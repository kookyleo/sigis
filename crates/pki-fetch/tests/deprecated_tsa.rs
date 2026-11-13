// Exact caller/session/error assertions from pyHanko 0.38.1
// test_deprecated_aiohttp_timestamper_forwards (MIT, see LICENSE-pyHanko).
#![deny(deprecated)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use der::Decode;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::errors::{FetchErrorKind, HankoError};
use sigis_pki_core::sign::TimeStamper;
use sigis_pki_fetch::transport::HttpRequest;
#[allow(deprecated)]
use sigis_pki_fetch::tsa::AioHttpTimeStamper;
use sigis_pki_fetch::{
    HttpResponse, HttpTransport, ReqwestTransport, TimestampRequestError, TransportError,
};
use x509_tsp::TimeStampReq;

#[derive(Debug)]
struct FailedSession {
    requests: Mutex<Vec<(String, Vec<u8>)>>,
    released: Arc<AtomicUsize>,
}

impl HttpTransport for FailedSession {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        assert_eq!(request.method, "POST");
        for (name, value) in [
            ("Content-Type", "application/timestamp-query"),
            ("Accept", "application/timestamp-reply"),
        ] {
            assert!(request
                .headers
                .iter()
                .any(|(key, val)| key == name && val == value));
        }
        self.requests.lock().unwrap().push((
            request.url.to_owned(),
            request.body.expect("actual encoded TimeStampReq").to_vec(),
        ));
        Err(TransportError::Network(
            "caller session cannot connect".into(),
        ))
    }
}

impl Drop for FailedSession {
    fn drop(&mut self) {
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
#[allow(deprecated)]
fn test_deprecated_aiohttp_timestamper_forwards() {
    let released = Arc::new(AtomicUsize::new(0));
    let session = Arc::new(FailedSession {
        requests: Mutex::new(Vec::new()),
        released: released.clone(),
    });
    let transport: Arc<dyn HttpTransport> = session.clone();
    // The deny(deprecated) doctest calls this constructor; this allowed
    // runtime use independently proves the constructor and arguments are valid.
    let client = AioHttpTimeStamper::new(
        "http://example.invalid",
        transport.clone(),
        Duration::from_secs(30),
    );
    assert!(Arc::ptr_eq(client.transport().unwrap(), &transport));
    assert_eq!(client.url, "http://example.invalid");
    assert_eq!(client.limits.timeout, Duration::from_secs(30));
    let digest = DigestAlgorithm::Sha256.digest(b"Hello world!");
    assert_eq!(
        client.timestamp_token(&digest, DigestAlgorithm::Sha256),
        Err(TimestampRequestError(
            "Error while contacting timestamp service".into()
        ))
    );
    assert!(Arc::ptr_eq(client.transport().unwrap(), &transport));
    let requests = session.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "http://example.invalid");
    let request = TimeStampReq::from_der(&requests[0].1).unwrap();
    assert_eq!(
        request.message_imprint.hash_algorithm.oid,
        DigestAlgorithm::Sha256.oid()
    );
    assert_eq!(request.message_imprint.hashed_message.as_bytes(), digest);
    assert!(request.cert_req);
    assert!(request.nonce.is_some());
    drop(requests);
    drop(client);
    assert_eq!(released.load(Ordering::SeqCst), 0);
    drop(transport);
    assert_eq!(released.load(Ordering::SeqCst), 0);
    drop(session);
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

#[test]
#[allow(deprecated)]
fn deprecated_constructor_uses_the_actual_reqwest_session() {
    let url =
        std::env::var("SIGIS_TSA_ALIAS_FAILURE_URL").unwrap_or_else(|_| common::closed_port_url());
    assert!(url.starts_with("http://127.0.0.1:"));
    let transport: Arc<dyn HttpTransport> =
        Arc::new(ReqwestTransport::new(Duration::from_secs(30), 1024).unwrap());
    let client = AioHttpTimeStamper::new(url.clone(), transport.clone(), Duration::from_secs(30));
    assert!(Arc::ptr_eq(client.transport().unwrap(), &transport));
    let error = client
        .timestamp_token(
            &DigestAlgorithm::Sha256.digest(b"Hello world!"),
            DigestAlgorithm::Sha256,
        )
        .unwrap_err();
    assert_eq!(error.0, "Error while contacting timestamp service");
    assert!(Arc::ptr_eq(client.transport().unwrap(), &transport));
    // A failed timestamp does not consume or replace the caller's session.
    assert!(client
        .timestamp_token(
            &DigestAlgorithm::Sha256.digest(b"Hello world!"),
            DigestAlgorithm::Sha256,
        )
        .is_err());
    println!(
        "TSA_ALIAS_NATIVE_FAILURE {}",
        serde_json::json!({
            "url": url,
            "message_digest": DigestAlgorithm::Sha256.digest(b"Hello world!"),
            "digest_algorithm": "sha256",
            "configured_client_timeout_seconds": client.limits.timeout.as_secs(),
            "supplied_reqwest_timeout_seconds": 30,
            "supplied_transport_identity": Arc::ptr_eq(client.transport().unwrap(), &transport),
            "timestamp_attempts": 2,
            "error_class": "TimestampRequestError",
            "error": error.0,
        })
    );
}

#[test]
#[allow(deprecated)]
fn core_trait_and_modern_migration_keep_the_same_transport() {
    let released = Arc::new(AtomicUsize::new(0));
    let session = Arc::new(FailedSession {
        requests: Mutex::new(Vec::new()),
        released: released.clone(),
    });
    let transport: Arc<dyn HttpTransport> = session.clone();
    let legacy = AioHttpTimeStamper::new(
        "http://example.invalid",
        transport.clone(),
        Duration::from_secs(30),
    );
    let digest = DigestAlgorithm::Sha256.digest(b"Hello world!");
    let error = TimeStamper::timestamp(&legacy, &digest, DigestAlgorithm::Sha256).unwrap_err();
    assert!(matches!(error, HankoError::Fetch(ref e) if e.kind == FetchErrorKind::BadResponse));
    let modern = legacy.into_http();
    assert!(Arc::ptr_eq(modern.transport().unwrap(), &transport));
    assert_eq!(modern.limits.timeout, Duration::from_secs(30));
    assert_eq!(modern.url, "http://example.invalid");
    assert!(modern
        .timestamp_token(&digest, DigestAlgorithm::Sha256)
        .is_err());
    assert_eq!(session.requests.lock().unwrap().len(), 2);
    drop(modern);
    assert_eq!(released.load(Ordering::SeqCst), 0);
}

#[test]
fn modern_constructor_compiles_under_deny_deprecated() {
    // This function inherits deny(deprecated), without a local allowance or
    // legacy import. The standalone modern doctest checks the same boundary.
    use sigis_pki_fetch::{FetchLimits, HttpTimeStamper};

    let timeout = Duration::from_secs(30);
    let transport: Arc<dyn HttpTransport> = Arc::new(ReqwestTransport::new(timeout, 1024).unwrap());
    let client = HttpTimeStamper::new("http://example.invalid")
        .with_transport(transport.clone())
        .with_limits(FetchLimits {
            timeout,
            ..FetchLimits::default()
        });
    assert!(Arc::ptr_eq(client.transport().unwrap(), &transport));
    assert_eq!(client.limits.timeout, timeout);
    assert_eq!(client.url, "http://example.invalid");
}
