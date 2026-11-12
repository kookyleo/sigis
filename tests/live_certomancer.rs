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

// Native fixture acceptance, not an additional upstream function.
#[test]
fn live_pki_download_and_issuer_routes_support_native_validation() {
    use sigis_pades_sign::SimpleSigner;
    use sigis_pki_certvalidator::CertificateValidator;
    use sigis_pki_core::algorithms::{validate_signature, SignatureValidationContext};
    use sigis_pki_core::cert::Cert;
    use sigis_pki_core::sign::KeySigner;
    use sigis_pki_fetch::{FetcherSettings, HttpFetchers};

    let live = LivePki::start();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let pfx = client
        .post(format!("{}/_certomancer/pfx-download/testing-ca", live.url))
        .form(&[("cert", "signer1-long"), ("passphrase", "secret")])
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .unwrap();
    assert!(SimpleSigner::from_pkcs12(&pfx, Some(b"wrong")).is_err());
    let signer = SimpleSigner::from_pkcs12(&pfx, Some(b"secret")).unwrap();
    assert_eq!(signer.cert_chain().len(), 2);
    let root_der = client
        .get(format!(
            "{}/_certomancer/any-cert/testing-ca/root.crt",
            live.url
        ))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .unwrap();
    let issuer_der = client
        .get(format!("{}/testing-ca/certs/interm/ca.crt", live.url))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .unwrap();
    let root = Cert::from_der(&root_der).unwrap();
    let issuer = Cert::from_der(&issuer_der).unwrap();
    assert!(signer.cert_chain().contains(&root));
    assert!(signer.cert_chain().contains(&issuer));
    assert_eq!(signer.signing_cert().issuer(), issuer.subject());

    let data = b"native key imported from the live PKCS12 route";
    let signature = signer.sign_raw(data, DigestAlgorithm::Sha256).unwrap();
    validate_signature(
        &signature,
        data,
        &signer.signing_cert().public_key(),
        &signer.signature_algorithm(DigestAlgorithm::Sha256).unwrap(),
        &SignatureValidationContext {
            contextual_digest: Some(DigestAlgorithm::Sha256),
            prehashed: false,
        },
    )
    .unwrap();

    let http = HttpFetchers::new(FetcherSettings {
        permit_pem: false,
        ..Default::default()
    });
    let fetchers = http.as_fetchers();
    let fetched = fetchers
        .cert
        .as_ref()
        .unwrap()
        .fetch_issuers(signer.signing_cert())
        .unwrap();
    assert!(fetched.contains(&issuer));
    let context = ValidationContext::builder()
        .trust_root(root.clone())
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .revocation_mode("require")
        .fetchers(fetchers)
        .build()
        .unwrap();
    // No intermediate is supplied: native path construction must use the
    // configured AIA fetcher, with mandatory live revocation evidence.
    CertificateValidator::new(&context, signer.signing_cert().clone())
        .validate()
        .unwrap();
    let missing_evidence = ValidationContext::builder()
        .trust_root(root)
        .other_cert(issuer.clone())
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .revocation_mode("require")
        .build()
        .unwrap();
    assert!(
        CertificateValidator::new(&missing_evidence, signer.signing_cert().clone())
            .validate()
            .is_err()
    );
    let no_roots = ValidationContext::builder()
        .other_cert(issuer)
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .build()
        .unwrap();
    assert!(
        CertificateValidator::new(&no_roots, signer.signing_cert().clone())
            .validate()
            .is_err()
    );

    let metrics: serde_json::Value = client
        .get(format!("{}/_sigis/requests", live.url))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert!(metrics["requests"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["path"] == "/testing-ca/certs/interm/ca.crt" && entry["status"] == 200));
}
