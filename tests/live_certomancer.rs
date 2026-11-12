// Ported from pyHanko v0.38.1 internal/integration-tests (MIT).
//! Real loopback HTTP integrations, rather than recorded transport replays.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/live_pki.rs"]
mod live_pki;

use std::sync::Arc;
use std::time::Duration;

use live_pki::{LivePki, TIME};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::ades::{AdesIndeterminate, AdesSubIndic};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::time::Moment;
use sigis_pki_fetch::{HttpTimeStamper, ReqwestTransport};

fn check_timestamp(explicit_session: bool) {
    let live = LivePki::start();
    let mut client = HttpTimeStamper::new(format!("{}/testing-ca/tsa/tsa", live.url));
    if explicit_session {
        client = client.with_transport(Arc::new(
            ReqwestTransport::new(Duration::from_secs(30), 1024 * 1024).unwrap(),
        ));
    }
    // SHA-256(b"Hello world!"), the exact upstream message imprint.
    let imprint = DigestAlgorithm::Sha256.digest(b"Hello world!");
    let token = client
        .timestamp_token(&imprint, DigestAlgorithm::Sha256)
        .unwrap();
    let ctx = ValidationContext::builder()
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .build()
        .unwrap();
    let status = sigis_cms::validate_timestamp_token(&token, &imprint, &ctx).unwrap();
    assert!(status.signature.valid && status.signature.intact);
    assert!(!status.signature.trusted());
    assert_eq!(
        status.signature.trust_problem_indic,
        Some(AdesSubIndic::Indeterminate(
            AdesIndeterminate::NO_CERTIFICATE_CHAIN_FOUND,
        ))
    );
    let mut wrong = imprint.clone();
    wrong[0] ^= 1;
    let bad = sigis_cms::validate_timestamp_token(&token, &wrong, &ctx).unwrap();
    assert!(!bad.signature.intact && !bad.signature.trusted());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("timestamp.der");
    std::fs::write(&path, token).unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let expected = hex(&imprint);
    let script =
        sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/live_timestamp_verdict.py");
    let verdict =
        sigis_testdata::oracle::run_json(&script, &[path.to_str().unwrap(), &expected, TIME])
            .expect("live oracle required");
    assert_eq!(verdict["correct"]["valid"], true);
    assert_eq!(verdict["correct"]["intact"], true);
    assert_eq!(
        verdict["correct"]["trust_problem_indic"],
        "NO_CERTIFICATE_CHAIN_FOUND"
    );
    assert_eq!(verdict["wrong"]["intact"], false);
}

#[test]
fn test_ts_fetch_default_session() {
    check_timestamp(false);
}

#[test]
fn test_ts_fetch_aiohttp() {
    check_timestamp(true);
}
