// Derived from pyHanko `pyhanko/sign/signers/csc_signer.py` (MIT, see
// LICENSE-pyHanko).

//! Remote signing through a Cloud Signature Consortium (CSC) API v1 service
//! (`pyhanko.sign.signers.csc_signer`), based on version 1.0.4.0 of the CSC
//! API specification.
//!
//! [`CscSigner`] calls the `signatures/signHash` endpoint and handles batch
//! control. Authentication to the service (usually OAuth2) and obtaining
//! signature activation data (SAD) are delegated to a
//! [`CscAuthorizationManager`]; [`fetch_certs_in_csc_credential`] reads the
//! certificates from `credentials/info`.
//!
//! The port is blocking. pyHanko's concurrent coroutines that share a batch
//! become threads that call [`KeySigner::sign_raw`] on the same signer; a
//! call waits until its batch is committed, either automatically when the
//! batch is full or by [`CscSigner::commit`] from another thread. Waiting is
//! bounded by the signing timeout.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding};
use der::asn1::ObjectIdentifier;
use der::{Encode, Tagged};
use serde_json::{json, Map, Value};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};
use sigis_pki_core::sign::KeySigner;
use sigis_pki_core::time::Moment;
use spki::AlgorithmIdentifierOwned;

use crate::signer::default_signature_mechanism;

fn signing_error(msg: impl Into<String>) -> HankoError {
    HankoError::Signing(msg.into())
}

/// Information about the CSC service and the credential, with the
/// authentication data (`CSCServiceSessionInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CscServiceSessionInfo {
    /// Base URL of the service: the part before `/csc/<version>/...`.
    pub service_url: String,
    /// Identifier of the credential to sign with (vendor-specific format).
    pub credential_id: String,
    /// OAuth token for the `Authorization: Bearer` header.
    pub oauth_token: Option<String>,
    /// API version in the endpoint URLs.
    pub api_ver: String,
}

impl CscServiceSessionInfo {
    /// Session information without an OAuth token, for API version `v1`.
    pub fn new(service_url: impl Into<String>, credential_id: impl Into<String>) -> Self {
        Self {
            service_url: service_url.into(),
            credential_id: credential_id.into(),
            oauth_token: None,
            api_ver: "v1".into(),
        }
    }

    /// The full URL of an endpoint such as `credentials/info`.
    pub fn endpoint_url(&self, endpoint_name: &str) -> String {
        format!("{}/csc/{}/{endpoint_name}", self.service_url, self.api_ver)
    }

    /// HTTP headers for authentication: `Authorization: Bearer <token>` if
    /// a token is set.
    pub fn auth_headers(&self) -> Vec<(String, String)> {
        match &self.oauth_token {
            Some(tok) if !tok.is_empty() => {
                vec![("Authorization".into(), format!("Bearer {tok}"))]
            }
            _ => Vec::new(),
        }
    }
}

/// Information about a CSC credential (`CSCCredentialInfo`), usually from
/// `credentials/info`.
#[derive(Clone, Debug, PartialEq)]
pub struct CscCredentialInfo {
    /// The signer's certificate.
    pub signing_cert: Cert,
    /// Other relevant CA certificates.
    pub chain: Vec<Cert>,
    /// Signature mechanisms the credential supports, as asn1crypto names
    /// (`sha256_rsa`, `rsassa_pss`, ...; dotted OIDs for unnamed ones).
    pub supported_mechanisms: BTreeSet<String>,
    /// Maximal batch size of the credential.
    pub max_batch_size: i64,
    /// Whether SAD must be bound to specific hashes (`SCAL` 2).
    pub hash_pinning_required: bool,
    /// The raw response.
    pub response_data: Value,
}

impl CscCredentialInfo {
    /// The signing certificate followed by the chain (`as_cert_store`).
    pub fn as_cert_store(&self) -> Vec<Cert> {
        let mut out = vec![self.signing_cert.clone()];
        for c in &self.chain {
            if !out.contains(c) {
                out.push(c.clone());
            }
        }
        out
    }
}

/// asn1crypto's names for signature algorithm OIDs
/// (`algos.SignedDigestAlgorithmId`).
const SIGNED_DIGEST_ALGORITHM_NAMES: &[(&str, &str)] = &[
    ("1.3.14.3.2.3", "md5_rsa"),
    ("1.3.14.3.2.29", "sha1_rsa"),
    ("1.3.14.7.2.3.1", "md2_rsa"),
    ("1.2.840.113549.1.1.2", "md2_rsa"),
    ("1.2.840.113549.1.1.4", "md5_rsa"),
    ("1.2.840.113549.1.1.5", "sha1_rsa"),
    ("1.2.840.113549.1.1.14", "sha224_rsa"),
    ("1.2.840.113549.1.1.11", "sha256_rsa"),
    ("1.2.840.113549.1.1.12", "sha384_rsa"),
    ("1.2.840.113549.1.1.13", "sha512_rsa"),
    ("1.2.840.113549.1.1.10", "rsassa_pss"),
    ("1.2.840.10040.4.3", "sha1_dsa"),
    ("1.3.14.3.2.13", "sha1_dsa"),
    ("1.3.14.3.2.27", "sha1_dsa"),
    ("2.16.840.1.101.3.4.3.1", "sha224_dsa"),
    ("2.16.840.1.101.3.4.3.2", "sha256_dsa"),
    ("1.2.840.10045.4.1", "sha1_ecdsa"),
    ("1.2.840.10045.4.3.1", "sha224_ecdsa"),
    ("1.2.840.10045.4.3.2", "sha256_ecdsa"),
    ("1.2.840.10045.4.3.3", "sha384_ecdsa"),
    ("1.2.840.10045.4.3.4", "sha512_ecdsa"),
    ("2.16.840.1.101.3.4.3.9", "sha3_224_ecdsa"),
    ("2.16.840.1.101.3.4.3.10", "sha3_256_ecdsa"),
    ("2.16.840.1.101.3.4.3.11", "sha3_384_ecdsa"),
    ("2.16.840.1.101.3.4.3.12", "sha3_512_ecdsa"),
    ("1.2.840.113549.1.1.1", "rsassa_pkcs1v15"),
    ("1.2.840.10040.4.1", "dsa"),
    ("1.2.840.10045.4", "ecdsa"),
    ("1.3.101.112", "ed25519"),
    ("1.3.101.113", "ed448"),
];

/// The asn1crypto name of a signature algorithm OID; the dotted form if it
/// has no name (`SignedDigestAlgorithmId(oid).native`).
pub fn signed_digest_algorithm_name(oid: &ObjectIdentifier) -> String {
    let dotted = oid.to_string();
    SIGNED_DIGEST_ALGORITHM_NAMES
        .iter()
        .find(|(o, _)| *o == dotted)
        .map_or(dotted, |(_, n)| (*n).to_owned())
}

/// Parse an entry of `key/algo`: a dotted OID, or an asn1crypto name.
fn parse_algorithm_name(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    if SIGNED_DIGEST_ALGORITHM_NAMES.iter().any(|(_, n)| *n == s) {
        return Some(s.to_owned());
    }
    ObjectIdentifier::new(s)
        .ok()
        .map(|oid| signed_digest_algorithm_name(&oid))
}

/// Python's `int(x)` on a JSON value: integers, integral floats and decimal
/// strings.
fn py_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| {
            n.as_f64()
                .filter(|f| f.is_finite() && f.abs() < 9.0e18)
                .map(|f| f.trunc() as i64)
        }),
        Value::String(s) => s.trim().replace('_', "").parse().ok(),
        Value::Bool(b) => Some(i64::from(*b)),
        _ => None,
    }
}

/// Decode base64 the way Python's `base64.b64decode` does by default:
/// characters outside the alphabet are discarded.
fn lenient_b64decode(s: &str) -> Option<Vec<u8>> {
    let filtered: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        .collect();
    Base64::decode_vec(&filtered).ok()
}

/// Process a `credentials/info` response (`_process_certificate_info_response`).
pub fn process_certificate_info_response(response_data: &Value) -> Result<CscCredentialInfo> {
    let b64_certs = response_data
        .get("cert")
        .and_then(|c| c.get("certificates"))
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| signing_error("Could not retrieve certificates from response"))?;
    let mut certs = Vec::new();
    for c in b64_certs {
        let cert = c
            .as_str()
            .and_then(lenient_b64decode)
            .and_then(|der| Cert::from_der(&der).ok())
            .ok_or_else(|| signing_error("Could not decode certificates in response"))?;
        certs.push(cert);
    }
    let supported_mechanisms = response_data
        .get("key")
        .and_then(|k| k.get("algo"))
        .and_then(Value::as_array)
        .and_then(|algos| {
            algos
                .iter()
                .map(parse_algorithm_name)
                .collect::<Option<BTreeSet<_>>>()
        })
        .ok_or_else(|| {
            signing_error("Could not retrieve supported signing mechanisms from response")
        })?;
    let max_batch_size = response_data
        .get("multisign")
        .and_then(py_int)
        .ok_or_else(|| signing_error("Could not retrieve max batch size from response"))?;
    let scal = match response_data.get("SCAL") {
        None => Some(1),
        Some(v) => py_int(v).filter(|s| *s == 1 || *s == 2),
    }
    .ok_or_else(|| signing_error("SCAL value must be \"1\" or \"2\"."))?;
    // The CSC spec requires the signer's certificate to come first.
    let signing_cert = certs.remove(0);
    Ok(CscCredentialInfo {
        signing_cert,
        chain: certs,
        supported_mechanisms,
        max_batch_size,
        hash_pinning_required: scal == 2,
        response_data: response_data.clone(),
    })
}

/// A blocking HTTP client for CSC requests.
pub fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .build()
        .map_err(|e| signing_error(format!("could not create HTTP client: {e}")))
}

/// POST `body` as JSON and decode a JSON response.
fn post_json(
    client: &reqwest::blocking::Client,
    url: &str,
    headers: &[(String, String)],
    body: &Value,
    timeout: Duration,
) -> std::result::Result<Value, String> {
    let mut req = client.post(url).json(body).timeout(timeout);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| e.to_string())?;
    resp.json::<Value>().map_err(|e| e.to_string())
}

/// Call `credentials/info` for the credential and process the result
/// (`fetch_certs_in_csc_credential`).
pub fn fetch_certs_in_csc_credential(
    client: &reqwest::blocking::Client,
    session_info: &CscServiceSessionInfo,
    timeout: Duration,
) -> Result<CscCredentialInfo> {
    let req = json!({
        "credentialID": session_info.credential_id,
        "certificates": "chain",
        "certInfo": false,
    });
    let resp = post_json(
        client,
        &session_info.endpoint_url("credentials/info"),
        &session_info.auth_headers(),
        &req,
        timeout,
    )
    .map_err(|e| signing_error(format!("Credential info request failed: {e}")))?;
    process_certificate_info_response(&resp)
}

/// Digest `data` and encode it in base64 (`base64_digest`).
pub fn base64_digest(data: &[u8], digest: DigestAlgorithm) -> String {
    Base64::encode_string(&digest.digest(data))
}

/// Authorization to make a signing request: the result of
/// `credentials/authorize` (`CSCAuthorizationInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CscAuthorizationInfo {
    /// Signature activation data; opaque to the client.
    pub sad: String,
    /// Expiry of the SAD.
    pub expires_at: Option<Moment>,
}

impl CscAuthorizationInfo {
    /// SAD without expiry information.
    pub fn new(sad: impl Into<String>) -> Self {
        Self {
            sad: sad.into(),
            expires_at: None,
        }
    }
}

/// Parameters of a `credentials/authorize` request
/// (`format_csc_auth_request`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CscAuthRequest {
    /// Number of signatures to authorise; replaced by the number of hashes
    /// if `hash_b64s` is set.
    pub num_signatures: usize,
    /// The user's PIN.
    pub pin: Option<String>,
    /// One-time password.
    pub otp: Option<String>,
    /// Base64-encoded hashes to bind the SAD to (required for SCAL 2).
    pub hash_b64s: Option<Vec<String>>,
    /// Free-form description.
    pub description: Option<String>,
    /// Vendor-specific client data.
    pub client_data: Option<String>,
}

impl Default for CscAuthRequest {
    fn default() -> Self {
        Self {
            num_signatures: 1,
            pin: None,
            otp: None,
            hash_b64s: None,
            description: None,
            client_data: None,
        }
    }
}

/// Format a `credentials/authorize` request body
/// (`CSCAuthorizationManager.format_csc_auth_request`).
pub fn format_csc_auth_request(
    session_info: &CscServiceSessionInfo,
    req: &CscAuthRequest,
) -> Value {
    let mut m = Map::new();
    m.insert("credentialID".into(), json!(session_info.credential_id));
    let mut num = req.num_signatures;
    if let Some(h) = &req.hash_b64s {
        // make numSignatures congruent with the number of hashes
        num = h.len();
        m.insert("hash".into(), json!(h));
    }
    m.insert("numSignatures".into(), json!(num));
    if let Some(p) = &req.pin {
        m.insert("PIN".into(), json!(p));
    }
    if let Some(o) = &req.otp {
        m.insert("OTP".into(), json!(o));
    }
    if let Some(d) = &req.description {
        m.insert("description".into(), json!(d));
    }
    if let Some(c) = &req.client_data {
        m.insert("clientData".into(), json!(c));
    }
    Value::Object(m)
}

/// Parse a `credentials/authorize` response
/// (`CSCAuthorizationManager.parse_csc_auth_response`); the expiry is
/// relative to the current time.
pub fn parse_csc_auth_response(response_data: &Value) -> Result<CscAuthorizationInfo> {
    parse_csc_auth_response_at(response_data, Moment::now())
}

/// [`parse_csc_auth_response`] with an explicit current time.
pub fn parse_csc_auth_response_at(
    response_data: &Value,
    now: Moment,
) -> Result<CscAuthorizationInfo> {
    let sad = match response_data.get("SAD") {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => {
            return Err(signing_error(
                "Could not extract SAD value from auth response",
            ))
        }
    };
    let lifetime = match response_data.get("expiresIn") {
        None => 3600,
        Some(v) => py_int(v)
            .ok_or_else(|| signing_error("Could not process expiresIn value in auth response"))?,
    };
    let expires_at = if lifetime >= 0 {
        now.plus(Duration::from_secs(lifetime.unsigned_abs()))
    } else {
        now.minus(Duration::from_secs(lifetime.unsigned_abs()))
    };
    Ok(CscAuthorizationInfo {
        sad,
        expires_at: Some(expires_at),
    })
}

/// Procures signature activation data from the service
/// (`CSCAuthorizationManager`).
pub trait CscAuthorizationManager: Send + Sync + fmt::Debug {
    /// The service and credential.
    fn session_info(&self) -> &CscServiceSessionInfo;

    /// Details about the credential.
    fn credential_info(&self) -> &CscCredentialInfo;

    /// Request SAD for the given base64-encoded hashes, freshly or by
    /// extending the current transaction.
    fn authorize_signature(&self, hash_b64s: &[String]) -> Result<CscAuthorizationInfo>;

    /// HTTP headers for authentication; by default those of the session
    /// information.
    fn auth_headers(&self) -> Vec<(String, String)> {
        self.session_info().auth_headers()
    }

    /// Format a `credentials/authorize` request for this credential.
    fn format_csc_auth_request(&self, req: &CscAuthRequest) -> Value {
        format_csc_auth_request(self.session_info(), req)
    }
}

/// Uses SAD fetched before signing, once (`PrefetchedSADAuthorizationManager`).
///
/// Only useful for services that do not bind SAD to hashes.
#[derive(Debug)]
pub struct PrefetchedSadAuthorizationManager {
    session_info: CscServiceSessionInfo,
    credential_info: CscCredentialInfo,
    auth_info: CscAuthorizationInfo,
    used: AtomicBool,
}

impl PrefetchedSadAuthorizationManager {
    /// Wrap pre-fetched SAD.
    pub fn new(
        session_info: CscServiceSessionInfo,
        credential_info: CscCredentialInfo,
        auth_info: CscAuthorizationInfo,
    ) -> Self {
        Self {
            session_info,
            credential_info,
            auth_info,
            used: AtomicBool::new(false),
        }
    }
}

impl CscAuthorizationManager for PrefetchedSadAuthorizationManager {
    fn session_info(&self) -> &CscServiceSessionInfo {
        &self.session_info
    }

    fn credential_info(&self) -> &CscCredentialInfo {
        &self.credential_info
    }

    /// Return the pre-fetched SAD, or fail if called twice.
    fn authorize_signature(&self, _hash_b64s: &[String]) -> Result<CscAuthorizationInfo> {
        if self.used.swap(true, Ordering::SeqCst) {
            return Err(signing_error("Prefetched SAD token is stale"));
        }
        Ok(self.auth_info.clone())
    }
}

/// Options of a [`CscSigner`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CscSignerOptions {
    /// Timeout of signing requests, and the longest a signature waits for
    /// its batch to be committed (default 300 s).
    pub sign_timeout: Duration,
    /// Prefer RSASSA-PSS for RSA keys.
    pub prefer_pss: bool,
    /// CSC client data to add to signing requests.
    pub client_data: Option<String>,
    /// Commit a batch as soon as it is full (default `true`); otherwise the
    /// caller must call [`CscSigner::commit`].
    pub batch_autocommit: bool,
    /// Number of signatures per `signatures/signHash` call (default 1).
    pub batch_size: usize,
    /// Size of the dry-run placeholder signature (default 512 bytes).
    pub est_raw_signature_size: usize,
    /// Explicit signature mechanism; bypasses the check against the
    /// credential's supported mechanisms.
    pub signature_mechanism: Option<AlgorithmIdentifierOwned>,
}

impl Default for CscSignerOptions {
    fn default() -> Self {
        Self {
            sign_timeout: Duration::from_secs(300),
            prefer_pss: false,
            client_data: None,
            batch_autocommit: true,
            batch_size: 1,
            est_raw_signature_size: 512,
            signature_mechanism: None,
        }
    }
}

#[derive(Debug)]
struct Batch {
    md: DigestAlgorithm,
    hashes: Vec<String>,
    initiated: bool,
    done: bool,
    results: Option<Vec<Vec<u8>>>,
    error: Option<String>,
    waiters: usize,
}

#[derive(Debug, Default)]
struct BatchState {
    current: Option<u64>,
    next_id: u64,
    batches: HashMap<u64, Batch>,
}

/// A [`KeySigner`] for a remote CSC signing service (`CSCSigner`).
pub struct CscSigner {
    client: reqwest::blocking::Client,
    auth_manager: Arc<dyn CscAuthorizationManager>,
    options: CscSignerOptions,
    signing_cert: Cert,
    chain: Vec<Cert>,
    state: Mutex<BatchState>,
    cv: Condvar,
}

impl fmt::Debug for CscSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CscSigner")
            .field("auth_manager", &self.auth_manager)
            .field("options", &self.options)
            .finish()
    }
}

impl CscSigner {
    /// A signer for the credential of `auth_manager`, using `client` for
    /// signing requests.
    pub fn new(
        client: reqwest::blocking::Client,
        auth_manager: Arc<dyn CscAuthorizationManager>,
        options: CscSignerOptions,
    ) -> Self {
        let info = auth_manager.credential_info();
        let signing_cert = info.signing_cert.clone();
        let chain = info.as_cert_store();
        Self {
            client,
            auth_manager,
            options: CscSignerOptions {
                batch_size: options.batch_size.max(1),
                ..options
            },
            signing_cert,
            chain,
            state: Mutex::new(BatchState::default()),
            cv: Condvar::new(),
        }
    }

    /// The authorization manager.
    pub fn auth_manager(&self) -> &Arc<dyn CscAuthorizationManager> {
        &self.auth_manager
    }

    /// The placeholder signature of a dry run (`async_sign_raw(...,
    /// dry_run=True)`): `est_raw_signature_size` zero bytes.
    pub fn dry_run_signature(&self) -> Vec<u8> {
        vec![0u8; self.options.est_raw_signature_size]
    }

    /// Number of hashes in the batch being collected.
    pub fn current_batch_len(&self) -> usize {
        let st = self.lock();
        st.current
            .and_then(|id| st.batches.get(&id))
            .map_or(0, |b| b.hashes.len())
    }

    fn lock(&self) -> MutexGuard<'_, BatchState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wait on the condition variable until `deadline`; `None` on timeout.
    fn wait_until<'a>(
        &self,
        guard: MutexGuard<'a, BatchState>,
        deadline: Instant,
    ) -> Option<MutexGuard<'a, BatchState>> {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let (g, _) = self
            .cv
            .wait_timeout(guard, deadline - now)
            .unwrap_or_else(|e| e.into_inner());
        Some(g)
    }

    /// The signature mechanism for `digest`, checked against the
    /// credential's supported mechanisms unless set explicitly
    /// (`get_signature_mechanism_for_digest`).
    pub fn signature_mechanism_for_digest(
        &self,
        digest: DigestAlgorithm,
    ) -> Result<AlgorithmIdentifierOwned> {
        if let Some(m) = &self.options.signature_mechanism {
            return Ok(m.clone());
        }
        let result =
            default_signature_mechanism(&self.signing_cert, digest, self.options.prefer_pss)?;
        let name = signed_digest_algorithm_name(&result.oid);
        let supported = &self.auth_manager.credential_info().supported_mechanisms;
        if !supported.contains(&name) {
            return Err(signing_error(format!(
                "Signature mechanism {name} is not supported, must be one of {}.",
                supported.iter().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
        Ok(result)
    }

    /// The request body of a `signatures/signHash` call
    /// (`format_csc_signing_req`); obtains SAD from the authorization
    /// manager.
    pub fn format_csc_signing_req(
        &self,
        tbs_hashes: &[String],
        digest: DigestAlgorithm,
    ) -> Result<Value> {
        let mechanism = self.signature_mechanism_for_digest(digest)?;
        let session_info = self.auth_manager.session_info();
        let auth_info = self.auth_manager.authorize_signature(tbs_hashes)?;
        let mut m = Map::new();
        m.insert("credentialID".into(), json!(session_info.credential_id));
        m.insert("SAD".into(), json!(auth_info.sad));
        m.insert("hashAlgo".into(), json!(digest.oid().to_string()));
        m.insert("signAlgo".into(), json!(mechanism.oid.to_string()));
        m.insert("hash".into(), json!(tbs_hashes));
        if let Some(p) = &mechanism.parameters {
            let is_null = p.tag() == der::Tag::Null;
            if !is_null {
                m.insert(
                    "signAlgoParams".into(),
                    json!(Base64::encode_string(&p.to_der()?)),
                );
            }
        }
        if let Some(c) = &self.options.client_data {
            m.insert("clientData".into(), json!(c));
        }
        Ok(Value::Object(m))
    }

    /// Commit the current batch by calling `signatures/signHash`
    /// (`commit`). Signers waiting on the batch are woken up.
    pub fn commit(&self) -> Result<()> {
        self.commit_batch(None)
    }

    // Automatic commits stay bound to the batch that triggered them. Public
    // commits select the current batch while holding the same state lock.
    fn commit_batch(&self, batch_id: Option<u64>) -> Result<()> {
        let deadline = Instant::now() + self.options.sign_timeout;
        let mut st = self.lock();
        let Some(id) = batch_id.or(st.current) else {
            return Ok(());
        };
        let mut waiting = false;
        loop {
            let Some(b) = st.batches.get_mut(&id) else {
                return Ok(());
            };
            if b.done {
                let ok = b.results.is_some();
                if waiting {
                    // this commit held the batch open while waiting
                    b.waiters = b.waiters.saturating_sub(1);
                    if b.waiters == 0 {
                        st.batches.remove(&id);
                    }
                }
                return if ok {
                    Ok(())
                } else {
                    Err(signing_error("Commit failed"))
                };
            }
            if !b.initiated {
                break;
            }
            // wait for the other commit to finish; count as a waiter so the
            // batch outcome stays readable
            if !waiting {
                b.waiters += 1;
                waiting = true;
            }
            st = match self.wait_until(st, deadline) {
                Some(g) => g,
                None => {
                    let mut g = self.lock();
                    if let Some(b) = g.batches.get_mut(&id) {
                        b.waiters = b.waiters.saturating_sub(1);
                    }
                    return Err(signing_error("Commit failed"));
                }
            };
        }
        let (hashes, md) = match st.batches.get_mut(&id) {
            Some(b) => {
                b.initiated = true;
                (b.hashes.clone(), b.md)
            }
            None => return Ok(()),
        };
        drop(st);
        let result = self.do_commit(&hashes, md);
        let mut st = self.lock();
        if st.current == Some(id) {
            st.current = None;
        }
        if let Some(b) = st.batches.get_mut(&id) {
            b.done = true;
            match &result {
                Ok(sigs) => b.results = Some(sigs.clone()),
                Err(e) => b.error = Some(e.to_string()),
            }
            if b.waiters == 0 {
                st.batches.remove(&id);
            }
        }
        drop(st);
        self.cv.notify_all();
        result.map(|_| ())
    }

    /// Call `signatures/signHash` for a batch (`_do_commit`).
    fn do_commit(&self, hashes: &[String], md: DigestAlgorithm) -> Result<Vec<Vec<u8>>> {
        let req = self.format_csc_signing_req(hashes, md)?;
        let url = self
            .auth_manager
            .session_info()
            .endpoint_url("signatures/signHash");
        let resp = post_json(
            &self.client,
            &url,
            &self.auth_manager.auth_headers(),
            &req,
            self.options.sign_timeout,
        )
        .map_err(|e| signing_error(format!("Signature request failed: {e}")))?;
        let malformed = || signing_error("Expected response with b64-encoded signature values");
        let sig_b64s = resp
            .get("signatures")
            .and_then(Value::as_array)
            .ok_or_else(malformed)?;
        if sig_b64s.len() != hashes.len() {
            return Err(signing_error(format!(
                "Expected {} signatures, got {}",
                hashes.len(),
                sig_b64s.len()
            )));
        }
        sig_b64s
            .iter()
            .map(|s| {
                s.as_str()
                    .and_then(|s| Base64::decode_vec(s).ok())
                    .ok_or_else(malformed)
            })
            .collect()
    }
}

impl KeySigner for CscSigner {
    fn signing_cert(&self) -> &Cert {
        &self.signing_cert
    }

    fn cert_chain(&self) -> &[Cert] {
        &self.chain
    }

    fn signature_algorithm(&self, digest: DigestAlgorithm) -> Result<AlgorithmIdentifierOwned> {
        self.signature_mechanism_for_digest(digest)
    }

    /// Queue the hash of `data` in the current batch and wait for the batch
    /// to be committed (`async_sign_raw`).
    fn sign_raw(&self, data: &[u8], digest: DigestAlgorithm) -> Result<Vec<u8>> {
        let deadline = Instant::now() + self.options.sign_timeout;
        let no_results = |err: Option<&str>| {
            signing_error(match err {
                Some(e) => format!("No signing results available ({e})"),
                None => "No signing results available".to_owned(),
            })
        };
        let tbs_hash = base64_digest(data, digest);
        let mut st = self.lock();
        // A full automatic batch is sealed even before its committing thread
        // reacquires the lock. Wait for that batch, then start or join another.
        while let Some(b) = st.current.and_then(|id| st.batches.get(&id)) {
            if !b.initiated
                && (!self.options.batch_autocommit || b.hashes.len() < self.options.batch_size)
            {
                break;
            }
            st = self
                .wait_until(st, deadline)
                .ok_or_else(|| no_results(None))?;
        }
        let id = match st.current {
            Some(id) => {
                let Some(b) = st.batches.get(&id) else {
                    return Err(no_results(None));
                };
                if b.md != digest {
                    return Err(signing_error(format!(
                        "All signatures in the same batch must use the same digest function; \
                         encountered both {} and {}.",
                        b.md.name(),
                        digest.name()
                    )));
                }
                id
            }
            None => {
                let id = st.next_id;
                st.next_id += 1;
                st.batches.insert(
                    id,
                    Batch {
                        md: digest,
                        hashes: Vec::new(),
                        initiated: false,
                        done: false,
                        results: None,
                        error: None,
                        waiters: 0,
                    },
                );
                st.current = Some(id);
                id
            }
        };
        let ix = match st.batches.get_mut(&id) {
            Some(b) => {
                b.hashes.push(tbs_hash);
                b.waiters += 1;
                b.hashes.len() - 1
            }
            None => return Err(no_results(None)),
        };
        if self.options.batch_autocommit && ix + 1 == self.options.batch_size {
            drop(st);
            // failures are reported through the batch below
            let _ = self.commit_batch(Some(id));
            st = self.lock();
        }
        // wait until a commit goes through
        loop {
            match st.batches.get(&id) {
                Some(b) if b.done => break,
                Some(_) => {}
                None => return Err(no_results(None)),
            }
            match self.wait_until(st, deadline) {
                Some(g) => st = g,
                None => {
                    let mut st = self.lock();
                    if let Some(b) = st.batches.get_mut(&id) {
                        b.waiters = b.waiters.saturating_sub(1);
                    }
                    return Err(no_results(Some(
                        "timed out waiting for the batch to be committed",
                    )));
                }
            }
        }
        let outcome = match st.batches.get_mut(&id) {
            Some(b) => {
                b.waiters = b.waiters.saturating_sub(1);
                let r = b.results.as_ref().and_then(|r| r.get(ix).cloned());
                let err = b.error.clone();
                let remove = b.waiters == 0;
                (r, err, remove)
            }
            None => (None, None, false),
        };
        if outcome.2 {
            st.batches.remove(&id);
        }
        outcome.0.ok_or_else(|| no_results(outcome.1.as_deref()))
    }
}

#[cfg(test)]
#[path = "csc_batch_race_tests.rs"]
mod batch_race_tests;
