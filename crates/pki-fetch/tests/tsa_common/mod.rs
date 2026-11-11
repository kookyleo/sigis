//! Shared parts of the two TSA test modules.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_fetch::{HttpTimeStamper, NonceMode};

use crate::common::{read_lane, LocalServer, Reply};

pub const FIXED_NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

pub fn message_digest() -> Vec<u8> {
    DigestAlgorithm::Sha256.digest(b"Hello world!")
}

pub fn tsa_reply(content_type: Option<&str>) -> LocalServer {
    LocalServer::start(Reply {
        status: 200,
        content_type: content_type.map(str::to_owned),
        body: read_lane(&["tsa", "granted-fixed-nonce.der"]),
    })
}

/// `test_http_timestamp`: the client obtains a token from a local TSA and
/// the token validates as trusted at the test time (2020-11-01).
pub fn http_timestamp_round_trip() {
    let server = tsa_reply(Some("application/timestamp-reply"));
    let ts = HttpTimeStamper::new(format!("{}/testing-ca/tsa/tsa", server.url))
        .with_nonce(NonceMode::Fixed(FIXED_NONCE.to_vec()));
    let token = ts
        .timestamp_token(&message_digest(), DigestAlgorithm::Sha256)
        .expect("token");
    let received = server.received.lock().unwrap();
    assert_eq!(received.len(), 1);
    let r = &received[0];
    assert_eq!(r.method, "POST");
    let header = |n: &str| {
        r.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(
        header("content-type").as_deref(),
        Some("application/timestamp-query")
    );
    assert_eq!(
        header("accept").as_deref(),
        Some("application/timestamp-reply")
    );

    let root = sigis_pki_core::cert::Cert::from_der(&read_lane(&["tsa", "root.der"])).unwrap();
    let ctx = sigis_pki_certvalidator::ValidationContext::builder()
        .trust_root(root)
        .moment(sigis_pki_core::time::Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap())
        .build()
        .unwrap();
    let status = sigis_cms::validate_timestamp_token(&token, &message_digest(), &ctx).unwrap();
    assert!(status.trusted(), "{:?}", status.signature.trust_problem);
    assert_eq!(
        status.timestamp,
        sigis_pki_core::time::Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap()
    );
}

/// `test_http_timestamp_bad_content_type`.
pub fn http_timestamp_bad_content_type() {
    let server = tsa_reply(None);
    let ts = HttpTimeStamper::new(format!("{}/testing-ca/tsa/tsa", server.url))
        .with_nonce(NonceMode::Fixed(FIXED_NONCE.to_vec()));
    let e = ts
        .timestamp_token(&message_digest(), DigestAlgorithm::Sha256)
        .expect_err("bad content type");
    assert!(e.0.contains("timestamp service"), "{e}");
}

/// `test_ts_fetch_error`: nothing answers at the URL.
pub fn ts_fetch_error() {
    let ts = HttpTimeStamper::new(crate::common::closed_port_url());
    assert!(ts
        .timestamp_token(&message_digest(), DigestAlgorithm::Sha256)
        .is_err());
}
