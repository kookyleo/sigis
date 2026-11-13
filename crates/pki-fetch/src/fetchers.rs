// Derived from pyhanko-certvalidator `fetchers/requests_fetchers/*.py`,
// `fetchers/aiohttp_fetchers/*.py` and `fetchers/common_utils.py`
// (MIT, see LICENSE-pyHanko).

//! HTTP fetchers for issuer certificates, CRLs and OCSP responses, with
//! result caching, a shared request budget and multi-URL fallback.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use der::Encode;

use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{FetchError, FetchErrorKind};
use sigis_pki_core::fetch::{CertificateFetcher, CrlFetcher, Fetchers, OcspFetcher};

use crate::budget::{cap_aia_urls, FetchBudget, FetchKind, FetchLimits};
use crate::common::{
    ac_fetch_info, check_ac_response_id, enumerate_delivery_point_urls,
    format_ocsp_request_for_serial, gather_aia_issuer_urls, get_ocsp_urls, get_relevant_crl_dps,
    pem_detect, pem_unarmor, process_ocsp_response_data, random_bytes, unpack_cert_content,
    CertIdHash, OcspResponseError, ACCEPTABLE_CERT_DER_ALIASES, ACCEPTABLE_CERT_PEM_ALIASES,
    ACCEPTABLE_PKCS7_DER_ALIASES, ACCEPTABLE_STRICT_CERT_CONTENT_TYPES,
};
use crate::transport::{
    HttpRequest, HttpResponse, HttpTransport, LazyTransport, TransportError, DEFAULT_USER_AGENT,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TargetKind {
    X509,
    Attribute,
}

/// Field boundaries and target namespace are part of the identity. CRL URL
/// caching is separate: sharing retrieved bytes never shares a trust verdict.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TargetKey {
    kind: TargetKind,
    issuer_name: Vec<u8>,
    serial: Vec<u8>,
}

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
    crls_by_cert: Mutex<HashMap<TargetKey, Vec<Vec<u8>>>>,
    ocsp_by_cert: Cache<(TargetKey, Vec<u8>), Vec<u8>>,
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

impl HttpFetchers {
    /// Fetchers over HTTP (reqwest) with the given settings.
    pub fn new(settings: FetcherSettings) -> Self {
        let transport: Arc<dyn HttpTransport> = Arc::new(LazyTransport::new(
            settings.limits.timeout,
            settings.limits.max_response_bytes,
        ));
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
            (
                "User-Agent".to_owned(),
                self.inner.settings.user_agent.clone(),
            ),
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
            self.grab_certs(url, url_origin_type)
                .map_err(|(kind, detail)| {
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
        unpack_cert_content(
            &response.body,
            response.content_type.as_deref(),
            url,
            permit_pem,
        )
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
        let key = (issuer_serial(cert)?, issuer.der().to_vec());
        Self::cached(&self.inner.ocsp_by_cert, key, || {
            self.fetch_ocsp_job(cert.serial_bytes(), issuer, get_ocsp_urls(cert), false)
        })
    }

    fn fetch_ac_ocsp_response(&self, ac_der: &[u8], issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        let info = ac_fetch_info(ac_der)
            .map_err(|e| fetch_error(FetchErrorKind::BadResponse, e.to_string()))?;
        let key = TargetKey {
            kind: TargetKind::Attribute,
            issuer_name: info
                .issuer_name
                .to_der()
                .map_err(|e| fetch_error(FetchErrorKind::BadResponse, e.to_string()))?,
            serial: info.serial.clone(),
        };
        Self::cached(
            &self.inner.ocsp_by_cert,
            (key, issuer.der().to_vec()),
            || self.fetch_ocsp_job(&info.serial, issuer, info.ocsp_urls(), true),
        )
    }

    fn fetch_ocsp_job(
        &self,
        serial: &[u8],
        issuer: &Cert,
        urls: Vec<String>,
        is_ac: bool,
    ) -> Result<Vec<u8>, FetchError> {
        let nonce = self.inner.settings.request_nonces.then(random_bytes::<16>);
        let request =
            format_ocsp_request_for_serial(serial, issuer, self.inner.settings.certid_hash, nonce)
                .map_err(|e| fetch_error(FetchErrorKind::BadResponse, e.to_string()))?;
        let body = request
            .to_der()
            .map_err(|e| fetch_error(FetchErrorKind::BadResponse, e.to_string()))?;
        if urls.is_empty() {
            return Err(fetch_error(
                FetchErrorKind::NotFound,
                "No URLs to fetch OCSP responses from",
            ));
        }
        let mut last = None;
        for url in &urls {
            let result = self.charge(FetchKind::Ocsp).and_then(|()| {
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
                let parsed = process_ocsp_response_data(&response.body, &request, url).map_err(
                    |e| match e {
                        OcspResponseError::Unparseable => fetch_error(
                            FetchErrorKind::BadResponse,
                            format!("Failed to fetch OCSP response from {url} ({e})"),
                        ),
                        OcspResponseError::Validation(m) => {
                            fetch_error(FetchErrorKind::BadResponse, m)
                        }
                    },
                )?;
                if is_ac {
                    check_ac_response_id(&parsed, serial, issuer)
                        .map_err(|e| fetch_error(FetchErrorKind::BadResponse, e.to_string()))?;
                }
                Ok(response.body)
            });
            match result {
                Ok(data) => return Ok(data),
                Err(e) if e.message.starts_with("Fetch limit") => return Err(e),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| fetch_error(FetchErrorKind::NotFound, "No OCSP results")))
    }

    fn fetch_crl_points(
        &self,
        key: TargetKey,
        points: Vec<x509_cert::ext::pkix::crl::dp::DistributionPoint>,
    ) -> Result<Vec<Vec<u8>>, FetchError> {
        if let Some(result) = lock(&self.inner.crls_by_cert).get(&key) {
            return Ok(result.clone());
        }
        let mut results = Vec::new();
        let mut last = None;
        for point in points {
            for url in enumerate_delivery_point_urls(&point) {
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
            if let Some(error) = last {
                return Err(error);
            }
        }
        lock(&self.inner.crls_by_cert).insert(key, results.clone());
        Ok(results)
    }

    /// The CRLs fetched for `cert`, if it was processed.
    pub fn fetched_crls_for_cert(&self, cert: &Cert) -> Option<Vec<Vec<u8>>> {
        lock(&self.inner.crls_by_cert)
            .get(&issuer_serial(cert).ok()?)
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
fn issuer_serial(cert: &Cert) -> Result<TargetKey, FetchError> {
    Ok(TargetKey {
        kind: TargetKind::X509,
        issuer_name: cert
            .issuer()
            .to_der()
            .map_err(|e| fetch_error(FetchErrorKind::BadResponse, e.to_string()))?,
        serial: cert.serial_bytes().to_vec(),
    })
}

/// `crl.CertificateList.load` succeeds lazily on any SEQUENCE; require the
/// three top-level fields. The validator decodes CRLs fully later.
fn looks_like_crl(data: &[u8]) -> bool {
    sigis_pki_core::asn1::tlv::Tlv::parse_exact(data).is_ok_and(|t| {
        t.is_universal(sigis_pki_core::asn1::tlv::tag::SEQUENCE)
            && t.children().is_ok_and(|c| c.len() == 3)
    })
}

impl OcspFetcher for HttpFetchers {
    fn fetch_ocsp(&self, cert: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        self.fetch_ocsp_response(cert, issuer)
    }

    fn fetch_ac_ocsp(&self, ac_der: &[u8], issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        self.fetch_ac_ocsp_response(ac_der, issuer)
    }
}

impl CrlFetcher for HttpFetchers {
    /// CRLs from all HTTP distribution points, retaining URL cache/error behavior.
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        self.fetch_crl_points(issuer_serial(cert)?, get_relevant_crl_dps(cert, true))
    }

    fn fetch_ac_crls(&self, ac_der: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        let info = ac_fetch_info(ac_der)
            .map_err(|e| fetch_error(FetchErrorKind::BadResponse, e.to_string()))?;
        let key = TargetKey {
            kind: TargetKind::Attribute,
            issuer_name: info
                .issuer_name
                .to_der()
                .map_err(|e| fetch_error(FetchErrorKind::BadResponse, e.to_string()))?,
            serial: info.serial.clone(),
        };
        self.fetch_crl_points(key, info.crl_dps())
    }
}

impl CertificateFetcher for HttpFetchers {
    fn fetch_issuers(&self, cert: &Cert) -> Result<Vec<Cert>, FetchError> {
        Ok(self.fetch_issuers_from_urls(gather_aia_issuer_urls(cert), "certificate"))
    }
}

#[cfg(test)]
mod backend_lifecycle_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use sigis_pki_core::fetch::FetcherBackend;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Session {
        number: usize,
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for Session {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl HttpTransport for Session {
        fn send(&self, _: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
            Ok(HttpResponse {
                status: 200,
                content_type: None,
                body: self.number.to_be_bytes().to_vec(),
            })
        }
    }

    #[test]
    fn backend_new_and_default_own_only_their_exact_managed_transport() {
        for backend in [
            HttpFetchers::default(),
            HttpFetchers::new(FetcherSettings::default()),
        ] {
            let pool = backend.managed_transport.as_ref().unwrap();
            let erased: Arc<dyn HttpTransport> = pool.clone();
            assert!(Arc::ptr_eq(&backend.inner.transport, &erased));
            assert!(Arc::ptr_eq(
                backend.managed_transport.as_ref().unwrap(),
                backend.clone().managed_transport.as_ref().unwrap()
            ));
            backend.close().unwrap();
            backend.close().unwrap();
            let external = HttpFetchers::with_transport(pool.clone(), backend.settings().clone());
            assert!(external.managed_transport.is_none());
        }
    }

    #[test]
    fn backend_managed_close_recreates_real_lazy_session_without_resetting_state() {
        let created = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let pool = Arc::new(LazyTransport::with_factory({
            let created = created.clone();
            let dropped = dropped.clone();
            move || {
                Ok(Arc::new(Session {
                    number: created.fetch_add(1, Ordering::SeqCst),
                    dropped: dropped.clone(),
                }))
            }
        }));
        let settings = FetcherSettings {
            limits: FetchLimits {
                max_requests: Some(1),
                ..Default::default()
            },
            user_agent: "owned-lifecycle".into(),
            ..Default::default()
        };
        let mut backend = HttpFetchers::with_transport(pool.clone(), settings.clone());
        // Inject an observable factory into the same private managed-pool slot.
        // Public with_transport itself never adopts this caller's pool.
        backend.managed_transport = Some(pool);
        let view = backend.clone();
        let request = HttpRequest {
            method: "GET",
            url: "https://example.invalid",
            headers: Vec::new(),
            body: None,
        };
        assert_eq!(created.load(Ordering::SeqCst), 0);
        let first = backend.inner.transport.send(&request).unwrap();
        assert_eq!(first, view.inner.transport.send(&request).unwrap());
        assert_eq!(created.load(Ordering::SeqCst), 1);
        backend.charge(FetchKind::Ocsp).unwrap();
        let cached = FetchError::new(FetchErrorKind::Timeout, "retained cached failure");
        lock(&backend.inner.crls_by_url)
            .insert("https://cache.invalid".into(), Err(cached.clone()));
        backend.close().unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(backend.settings(), &settings);
        assert!(Arc::ptr_eq(&backend.inner, &view.inner));
        assert_eq!(view.fetch_crl_url("https://cache.invalid"), Err(cached));
        assert_eq!(
            view.charge(FetchKind::Crl).unwrap_err().kind,
            FetchErrorKind::Disabled
        );
        let second = view.inner.transport.send(&request).unwrap();
        assert_ne!(first.body, second.body);
        assert_eq!(created.load(Ordering::SeqCst), 2);
        view.close().unwrap();
        view.close().unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        assert_eq!(created.load(Ordering::SeqCst), 2);
    }
}
