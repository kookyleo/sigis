// Derived from pyhanko-certvalidator `fetchers/requests_fetchers/*.py`,
// `fetchers/aiohttp_fetchers/*.py` and `fetchers/common_utils.py`
// (MIT, see LICENSE-pyHanko).

//! HTTP fetchers for issuer certificates, CRLs and OCSP responses, with
//! result caching, a shared request budget and multi-URL fallback.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use der::Encode;

use hanko_core::cert::Cert;
use hanko_core::errors::{FetchError, FetchErrorKind};
use hanko_core::fetch::{CertificateFetcher, CrlFetcher, Fetchers, OcspFetcher};

use crate::budget::{cap_aia_urls, FetchBudget, FetchKind, FetchLimits};
use crate::common::{
    enumerate_delivery_point_urls, format_ocsp_request, gather_aia_issuer_urls,
    get_ocsp_urls, get_relevant_crl_dps, pem_detect, pem_unarmor, process_ocsp_response_data,
    random_bytes, unpack_cert_content, CertIdHash, OcspResponseError,
    ACCEPTABLE_CERT_DER_ALIASES, ACCEPTABLE_CERT_PEM_ALIASES, ACCEPTABLE_PKCS7_DER_ALIASES,
    ACCEPTABLE_STRICT_CERT_CONTENT_TYPES,
};
use crate::transport::{
    HttpRequest, HttpResponse, HttpTransport, ReqwestTransport, TransportError, DEFAULT_USER_AGENT,
};

/// Which fetch failed, for error messages and kinds.
fn fetch_error(kind: FetchErrorKind, message: impl Into<String>) -> FetchError {
    FetchError::new(kind, message)
}

fn transport_kind(e: &TransportError) -> FetchErrorKind {
    match e {
        TransportError::Network(_) => FetchErrorKind::Network,
        TransportError::Timeout(_) => FetchErrorKind::Timeout,
        TransportError::TooLarge(_) => FetchErrorKind::TooLarge,
    }
}

type Cache<K, V> = Mutex<HashMap<K, Result<V, FetchError>>>;

/// Settings of [`HttpFetchers`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetcherSettings {
    /// Request limits and budget.
    pub limits: FetchLimits,
    /// `User-Agent` header.
    pub user_agent: String,
    /// Accept PEM payloads for issuer certificates (`permit_pem`).
    pub permit_pem: bool,
    /// CertID hash for OCSP requests (`certid_hash_algo`).
    pub certid_hash: CertIdHash,
    /// Send OCSP nonces (`request_nonces`).
    pub request_nonces: bool,
}

impl Default for FetcherSettings {
    fn default() -> Self {
        Self {
            limits: FetchLimits::default(),
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            permit_pem: true,
            certid_hash: CertIdHash::Sha1,
            request_nonces: true,
        }
    }
}

#[derive(Debug)]
struct Inner {
    transport: Arc<dyn HttpTransport>,
    settings: FetcherSettings,
    budget: FetchBudget,
    certs_by_url: Cache<String, Vec<Cert>>,
    crls_by_url: Cache<String, Vec<u8>>,
    crls_by_cert: Mutex<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
    ocsp_by_cert: Cache<(Vec<u8>, Vec<u8>), Vec<u8>>,
}

/// HTTP fetchers with caching, size limits, timeouts and multi-URL
/// fallback (`RequestsFetcherBackend.get_fetchers()`). Clones share the
/// caches and the request budget; a new instance starts a fresh budget.
#[derive(Clone, Debug)]
pub struct HttpFetchers {
    inner: Arc<Inner>,
}

impl Default for HttpFetchers {
    fn default() -> Self {
        Self::new(FetcherSettings::default())
    }
}

/// A transport that always fails, used when the HTTP client cannot be built.
#[derive(Debug)]
struct BrokenTransport(String);

impl HttpTransport for BrokenTransport {
    fn send(&self, _request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        Err(TransportError::Network(self.0.clone()))
    }
}

impl HttpFetchers {
    /// Fetchers over HTTP (reqwest) with the given settings.
    pub fn new(settings: FetcherSettings) -> Self {
        let transport: Arc<dyn HttpTransport> = match ReqwestTransport::new(
            settings.limits.timeout,
            settings.limits.max_response_bytes,
        ) {
            Ok(t) => Arc::new(t),
            Err(e) => Arc::new(BrokenTransport(e.to_string())),
        };
        Self::with_transport(transport, settings)
    }

    /// Fetchers over a custom transport (tests, proxies).
    pub fn with_transport(transport: Arc<dyn HttpTransport>, settings: FetcherSettings) -> Self {
        let budget = FetchBudget::new(settings.limits.clone());
        Self {
            inner: Arc::new(Inner {
                transport,
                settings,
                budget,
                certs_by_url: Mutex::default(),
                crls_by_url: Mutex::default(),
                crls_by_cert: Mutex::default(),
                ocsp_by_cert: Mutex::default(),
            }),
        }
    }

    /// The shared request budget.
    pub fn budget(&self) -> &FetchBudget {
        &self.inner.budget
    }

    /// The settings.
    pub fn settings(&self) -> &FetcherSettings {
        &self.inner.settings
    }

    /// The three fetchers as a [`Fetchers`] set for a validation context.
    pub fn as_fetchers(&self) -> Fetchers {
        let me = Arc::new(self.clone());
        Fetchers {
            ocsp: Some(me.clone()),
            crl: Some(me.clone()),
            cert: Some(me),
        }
    }

    fn charge(&self, kind: FetchKind) -> Result<(), FetchError> {
        self.inner
            .budget
            .charge(kind)
            .map_err(|e| fetch_error(FetchErrorKind::Disabled, e.message))
    }

    fn request(
        &self,
        method: &'static str,
        url: &str,
        accept: &[&str],
        body: Option<(&str, &[u8])>,
    ) -> Result<HttpResponse, TransportError> {
        let mut headers = vec![
            ("Accept".to_owned(), accept.join(",")),
            ("User-Agent".to_owned(), self.inner.settings.user_agent.clone()),
        ];
        if let Some((ct, _)) = body {
            headers.push(("Content-Type".to_owned(), ct.to_owned()));
        }
        let response = self.inner.transport.send(&HttpRequest {
            method,
            url,
            headers,
            body: body.map(|(_, b)| b),
        })?;
        if response.status != 200 {
            return Err(TransportError::Network(format!(
                "status code {}",
                response.status
            )));
        }
        Ok(response)
    }

    /// Look up `key` in `cache`, or run `fetch` and cache its result
    /// (`queue_fetch_task`; errors are cached too).
    fn cached<K, V>(
        cache: &Cache<K, V>,
        key: K,
        fetch: impl FnOnce() -> Result<V, FetchError>,
    ) -> Result<V, FetchError>
    where
        K: std::hash::Hash + Eq + Clone,
        V: Clone,
    {
        if let Some(r) = lock(cache).get(&key) {
            return r.clone();
        }
        let r = fetch();
        lock(cache).insert(key, r.clone());
        r
    }

    /// `fetch_certs(url, url_origin_type)`: certificates served at `url`.
    pub fn fetch_certs(&self, url: &str, url_origin_type: &str) -> Result<Vec<Cert>, FetchError> {
        Self::cached(&self.inner.certs_by_url, url.to_owned(), || {
            self.charge(FetchKind::Cert)?;
            self.grab_certs(url, url_origin_type).map_err(|(kind, detail)| {
                fetch_error(
                    kind,
                    format!("Failed to fetch certificate(s) from url {url}. ({detail})"),
                )
            })
        })
    }

    fn grab_certs(
        &self,
        url: &str,
        url_origin_type: &str,
    ) -> Result<Vec<Cert>, (FetchErrorKind, String)> {
        let permit_pem = self.inner.settings.permit_pem;
        let acceptable: Vec<&str> = if permit_pem {
            let mut v: Vec<&str> = ACCEPTABLE_STRICT_CERT_CONTENT_TYPES.to_vec();
            for ct in ACCEPTABLE_CERT_PEM_ALIASES
                .iter()
                .chain(ACCEPTABLE_CERT_DER_ALIASES)
                .chain(ACCEPTABLE_PKCS7_DER_ALIASES)
            {
                if !v.contains(ct) {
                    v.push(ct);
                }
            }
            v
        } else {
            ACCEPTABLE_STRICT_CERT_CONTENT_TYPES.to_vec()
        };
        let response = self
            .request("GET", url, &acceptable, None)
            .map_err(|e| (transport_kind(&e), e.to_string()))?;
        if let Some(ct) = response.content_type.as_deref() {
            if !acceptable.contains(&ct) {
                return Err((
                    FetchErrorKind::BadResponse,
                    format!(
                        "Unacceptable content type '{ct:?}' when fetching issuer certificate for {url_origin_type} from URL {url}."
                    ),
                ));
            }
        }
        unpack_cert_content(&response.body, response.content_type.as_deref(), url, permit_pem)
            .map_err(|e| (FetchErrorKind::BadResponse, e.0))
    }

    /// Fetch issuer certificates from a list of `caIssuers` URLs; failing
    /// URLs are skipped (`complete_certificate_fetch_jobs`).
    pub fn fetch_issuers_from_urls(&self, urls: Vec<String>, origin: &str) -> Vec<Cert> {
        cap_aia_urls(Some(&self.inner.budget), urls)
            .iter()
            .filter_map(|u| self.fetch_certs(u, origin).ok())
            .flatten()
            .collect()
    }

    /// `_fetch_single` of the CRL fetcher: the DER CRL at `url`.
    pub fn fetch_crl_url(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        Self::cached(&self.inner.crls_by_url, url.to_owned(), || {
            self.charge(FetchKind::Crl)?;
            let response = self
                .request("GET", url, &["application/pkix-crl"], None)
                .map_err(|e| {
                    fetch_error(
                        transport_kind(&e),
                        format!("Failure to fetch CRL from URL {url} ({e})"),
                    )
                })?;
            let mut data = response.body;
            if pem_detect(&data) {
                data = pem_unarmor(&data)
                    .ok()
                    .and_then(|v| v.into_iter().next())
                    .map(|(_, der)| der)
                    .ok_or_else(|| {
                        fetch_error(
                            FetchErrorKind::BadResponse,
                            format!("Failure to fetch CRL from URL {url} (bad PEM)"),
                        )
                    })?;
            }
            if !looks_like_crl(&data) {
                return Err(fetch_error(
                    FetchErrorKind::BadResponse,
                    format!("Failure to fetch CRL from URL {url} (not a CRL)"),
                ));
            }
            Ok(data)
        })
    }

    /// OCSP response for `cert` from the responders in its AIA extension;
    /// the first successful response wins (`ocsp_job_get_earliest`).
    pub fn fetch_ocsp_response(&self, cert: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        let key = (issuer_serial(cert), issuer.der().to_vec());
        Self::cached(&self.inner.ocsp_by_cert, key, || {
            let nonce = self
                .inner
                .settings
                .request_nonces
                .then(random_bytes::<16>);
            let request = format_ocsp_request(cert, issuer, self.inner.settings.certid_hash, nonce)
                .map_err(|e| fetch_error(FetchErrorKind::BadResponse, e.to_string()))?;
            let body = request
                .to_der()
                .map_err(|e| fetch_error(FetchErrorKind::BadResponse, e.to_string()))?;
            let urls = get_ocsp_urls(cert);
            if urls.is_empty() {
                return Err(fetch_error(
                    FetchErrorKind::NotFound,
                    "No URLs to fetch OCSP responses from",
                ));
            }
            let mut last = None;
            for url in &urls {
                let r = self.charge(FetchKind::Ocsp).and_then(|()| {
                    let response = self
                        .request(
                            "POST",
                            url,
                            &["application/ocsp-response"],
                            Some(("application/ocsp-request", &body)),
                        )
                        .map_err(|e| {
                            fetch_error(
                                transport_kind(&e),
                                format!("Failed to fetch OCSP response from {url} ({e})"),
                            )
                        })?;
                    process_ocsp_response_data(&response.body, &request, url)
                        .map(|_| response.body)
                        .map_err(|e| match e {
                            OcspResponseError::Unparseable => fetch_error(
                                FetchErrorKind::BadResponse,
                                format!("Failed to fetch OCSP response from {url} ({e})"),
                            ),
                            OcspResponseError::Validation(m) => {
                                fetch_error(FetchErrorKind::BadResponse, m)
                            }
                        })
                });
                match r {
                    Ok(data) => return Ok(data),
                    Err(e) if e.message.starts_with("Fetch limit") => return Err(e),
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| fetch_error(FetchErrorKind::NotFound, "No OCSP results")))
        })
    }

    /// The CRLs fetched for `cert`, if it was processed.
    pub fn fetched_crls_for_cert(&self, cert: &Cert) -> Option<Vec<Vec<u8>>> {
        lock(&self.inner.crls_by_cert)
            .get(&issuer_serial(cert))
            .cloned()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Issuer and serial number of a certificate, as a cache key.
fn issuer_serial(cert: &Cert) -> Vec<u8> {
    let mut key = cert.issuer().to_der().unwrap_or_default();
    key.extend_from_slice(cert.serial_bytes());
    key
}

/// `crl.CertificateList.load` succeeds lazily on any SEQUENCE; require the
/// three top-level fields. The validator decodes CRLs fully later.
fn looks_like_crl(data: &[u8]) -> bool {
    hanko_core::asn1::tlv::Tlv::parse_exact(data).is_ok_and(|t| {
        t.is_universal(hanko_core::asn1::tlv::tag::SEQUENCE)
            && t.children().is_ok_and(|c| c.len() == 3)
    })
}

impl OcspFetcher for HttpFetchers {
    fn fetch_ocsp(&self, cert: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        self.fetch_ocsp_response(cert, issuer)
    }
}

impl CrlFetcher for HttpFetchers {
    /// CRLs from every HTTP distribution point (and freshest-CRL point);
    /// fails only if every URL failed (`crl_job_results_as_completed`).
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        let key = issuer_serial(cert);
        if let Some(r) = lock(&self.inner.crls_by_cert).get(&key) {
            return Ok(r.clone());
        }
        let mut results = Vec::new();
        let mut last = None;
        for dp in get_relevant_crl_dps(cert, true) {
            for url in enumerate_delivery_point_urls(&dp) {
                match self.fetch_crl_url(&url) {
                    Ok(crl) => {
                        if !results.contains(&crl) {
                            results.push(crl);
                        }
                    }
                    Err(e) => last = Some(e),
                }
            }
        }
        if results.is_empty() {
            if let Some(e) = last {
                return Err(e);
            }
        }
        lock(&self.inner.crls_by_cert).insert(key, results.clone());
        Ok(results)
    }
}

impl CertificateFetcher for HttpFetchers {
    fn fetch_issuers(&self, cert: &Cert) -> Result<Vec<Cert>, FetchError> {
        Ok(self.fetch_issuers_from_urls(gather_aia_issuer_urls(cert), "certificate"))
    }
}
