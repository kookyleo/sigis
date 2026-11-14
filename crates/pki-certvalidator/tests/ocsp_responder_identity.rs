//! Supplemental ordinary OCSP authority regressions; zero upstream-function credit.
//! CV 0.33.0 also accepts the copied-signature attack. Its refusal expectation
//! deliberately requires fail-closed hardening, not pinned-oracle parity.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use der::{Decode, Encode};
use sigis_pki_certvalidator::{
    find_valid_path, validate_path_detailed, Cert, CertRevTrustPolicy, FreshnessReqType,
    PathFailure, RevocationCheckingPolicy, RevocationCheckingRule, TrustAnchor, ValidationContext,
    ValidationPath,
};
use sigis_pki_core::{
    algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext},
    asn1::{oids, tlv::Tlv},
    errors::ValidationError,
    time::Moment,
};
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};

const NOW: &str = "2020-12-25T00:00:00Z";
const DIRECT: &str = "actual-direct-issuer-good.ocsp.der";
const DIRECT_BAD: &str = "actual-direct-issuer-bad-raw-signature.ocsp.der";
const DELEGATED: &str = "real-delegated-good.ocsp.der";
const FAKE: &str = "fake-issuer-signed-good.ocsp.der";
const FAKE_BAD: &str = "fake-issuer-bad-raw-signature.ocsp.der";
const INPUTS: &[(&str, usize, &str)] = &[
    (
        "cert-root.der",
        976,
        "2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa",
    ),
    (
        "cert-interm.der",
        987,
        "0e8fa78719fdd97ac8f9a531fa32929462d65306b9c58a63881ef21ca1a9509f",
    ),
    (
        "cert-signer1.der",
        1140,
        "449ecb59122767b13cbfbb6e75feb98bac90a4e1f782b4da43c071af94329aa5",
    ),
    (
        "root-good.crl.der",
        542,
        "5b8a25d50da418ce93b9f73ea14e590c18fcba684be79e30bb2e8cc650ed7a80",
    ),
    (
        "fake-issuer-copied-signature.der",
        987,
        "d007ef09a56f26992e5bd8f6bdcf8d4fd3a2630d6fd8caea6f17b1af668fbbf5",
    ),
    (
        FAKE,
        1521,
        "0fb99ca22290cad9dee7f27a836a3cba06fb6b532620bf432c3cf4eb8d67c3a6",
    ),
    (
        FAKE_BAD,
        1521,
        "09c42dc3561eaf6c0cba14b37545fc37c05504a4a1dcdb5cf5a2487d78889aff",
    ),
    (
        DELEGATED,
        1407,
        "7835d257a48a82c6a115735ce8665bdac5560646d43bc8e82736268133b185b3",
    ),
    (
        DIRECT,
        1521,
        "29a4fde76ae82b52f83a9c99417a06dc9a8d1e9aac5664d7edcdd9cb6f4e8f39",
    ),
    (
        DIRECT_BAD,
        1521,
        "75305ffe85b85df85734f96f3ed1c33f63867eeeb0f43662f654b5fc2dec27a6",
    ),
];

fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn read(name: &str) -> Vec<u8> {
    let (_, length, expected) = INPUTS
        .iter()
        .find(|(file, _, _)| *file == name)
        .expect("pinned input");
    let path = sigis_testdata::data_dir()
        .join("lanes/r3-l/ocsp-issuer-identity")
        .join(name);
    let bytes = std::fs::read(&path).expect("immutable DER fixture");
    let hash = sha(&bytes);
    eprintln!(
        "ORDINARY_OCSP_IDENTITY_INPUT {}",
        serde_json::json!({
            "path": path.canonicalize().unwrap(), "length": bytes.len(), "sha256": hash
        })
    );
    assert_eq!(bytes.len(), *length, "{name}");
    assert_eq!(hash, *expected, "{name}");
    bytes
}

fn cert(name: &str) -> Cert {
    Cert::from_der(&read(&format!("cert-{name}.der"))).expect("certificate")
}

// Keep the original signed octets, independently of the OCSP/certificate
// decoder's encoding. No test response or certificate is re-signed or altered.
fn signed_part(der: &[u8]) -> &[u8] {
    Tlv::parse_exact(der)
        .unwrap()
        .children()
        .unwrap()
        .first()
        .unwrap()
        .raw
}

struct Response {
    basic: BasicOcspResponse,
    tbs: Vec<u8>,
}

fn response(name: &str) -> Response {
    let outer = OcspResponse::from_der(&read(name)).expect("OCSPResponse");
    assert_eq!(outer.response_status, OcspResponseStatus::Successful);
    let bytes = outer.response_bytes.expect("successful response bytes");
    assert_eq!(bytes.response_type, oids::OCSP_BASIC);
    let inner = bytes.response.as_bytes();
    Response {
        basic: BasicOcspResponse::from_der(inner).expect("BasicOCSPResponse"),
        tbs: signed_part(inner).to_vec(),
    }
}

fn embedded_responder(response: &Response) -> Cert {
    let embedded = response.basic.certs.as_ref().expect("embedded responder");
    assert_eq!(embedded.len(), 1, "one explicit responder candidate");
    Cert::from_der(&embedded[0].to_der().unwrap()).unwrap()
}

fn check_responder_id(response: &Response, responder: &Cert) {
    match &response.basic.tbs_response_data.responder_id {
        ResponderId::ByName(name) => assert_eq!(name, responder.subject()),
        ResponderId::ByKey(hash) => assert_eq!(
            hash.as_bytes(),
            DigestAlgorithm::Sha1
                .digest(responder.public_key().subject_public_key.raw_bytes())
                .as_slice()
        ),
    }
}

fn check_full_cert_id(actual: &Response) {
    let singles = &actual.basic.tbs_response_data.responses;
    assert_eq!(singles.len(), 1);
    let single = &singles[0];
    assert!(matches!(&single.cert_status, CertStatus::Good(_)));
    let issuer = cert("interm");
    let leaf = cert("signer1");
    let digest = DigestAlgorithm::from_oid(&single.cert_id.hash_algorithm.oid).unwrap();
    assert_eq!(single.cert_id.serial_number.as_bytes(), leaf.serial_bytes());
    assert_eq!(
        single.cert_id.issuer_name_hash.as_bytes(),
        digest.digest(&leaf.issuer().to_der().unwrap()).as_slice()
    );
    assert_eq!(
        single.cert_id.issuer_key_hash.as_bytes(),
        digest
            .digest(issuer.public_key().subject_public_key.raw_bytes())
            .as_slice()
    );
    assert_eq!(
        single.cert_id,
        response(DELEGATED).basic.tbs_response_data.responses[0].cert_id
    );
}

fn verify_response(response: &Response, signer: &Cert) -> bool {
    validate_signature(
        response.basic.signature.raw_bytes(),
        &response.tbs,
        &signer.public_key(),
        &response.basic.signature_algorithm,
        &SignatureValidationContext::default(),
    )
    .is_ok()
}

fn verify_certificate(certificate: &Cert, issuer: &Cert) -> bool {
    validate_signature(
        certificate.decoded().signature().raw_bytes(),
        signed_part(certificate.der()),
        &issuer.public_key(),
        certificate.decoded().signature_algorithm(),
        &SignatureValidationContext::default(),
    )
    .is_ok()
}

fn context(response: &str) -> ValidationContext {
    let mut policy = CertRevTrustPolicy::new(RevocationCheckingPolicy {
        ee_certificate_rule: RevocationCheckingRule::OcspRequired,
        intermediate_ca_cert_rule: RevocationCheckingRule::CrlRequired,
    });
    policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    ValidationContext::builder()
        .trust_root(cert("root"))
        .other_cert(cert("interm"))
        .moment(Moment::parse_rfc3339(NOW).unwrap())
        .point_in_time_validation(false)
        .revinfo_policy(policy)
        .crl(read("root-good.crl.der"))
        .ocsp_response(read(response))
        .build()
        .expect("ordinary current context")
}

fn expected_path() -> ValidationPath {
    ValidationPath::new(
        TrustAnchor::new(cert("root")),
        vec![cert("interm")],
        Some(cert("signer1")),
    )
}

fn path_hashes(path: &ValidationPath) -> Vec<String> {
    path.certs()
        .iter()
        .map(|certificate| sha(certificate.der()))
        .collect()
}

fn assert_positive(input: &str) {
    let ctx = context(input);
    let leaf = cert("signer1");
    let expected = expected_path();
    // Exercise both ordinary public boundaries before either assertion.
    let found = find_valid_path(&ctx, &leaf, None);
    let checked = validate_path_detailed(&ctx, &expected, None);
    eprintln!(
        "ORDINARY_OCSP_IDENTITY_CASE {}",
        serde_json::json!({
            "input": input, "find_accepted": found.is_ok(), "validate_accepted": checked.is_ok(),
            "find_error": found.as_ref().err().map(|failure| failure.error.to_string()),
            "validate_error": checked.as_ref().err().map(|failure| failure.error.to_string())
        })
    );
    let actual = found.expect("genuine authorized responder must retain ordinary trust");
    checked.expect("genuine authorized responder must validate the supplied real path");
    assert_eq!(path_hashes(&actual), path_hashes(&expected));
    assert_eq!(actual.leaf(), Some(&leaf));
}

fn assert_mandatory_failure(failure: &PathFailure, expected: &ValidationPath, reason: &str) {
    let ValidationError::InsufficientRevinfo(message) = &failure.error else {
        panic!(
            "expected typed mandatory OCSP refusal, got {}",
            failure.error
        );
    };
    assert!(
        message.contains("mandatory OCSP check(s) for the end-entity certificate failed"),
        "{message}"
    );
    assert!(message.contains(reason), "{message}");
    assert_eq!(
        path_hashes(failure.path.as_ref().expect("actual checked path")),
        path_hashes(expected)
    );
    assert!(!failure.is_side_validation);
}

fn assert_refused(input: &str, reason: &str) {
    let ctx = context(input);
    let leaf = cert("signer1");
    let expected = expected_path();
    let found = find_valid_path(&ctx, &leaf, None);
    let checked = validate_path_detailed(&ctx, &expected, None);
    eprintln!(
        "ORDINARY_OCSP_IDENTITY_CASE {}",
        serde_json::json!({
            "input": input, "find_accepted": found.is_ok(), "validate_accepted": checked.is_ok(),
            "find_error": found.as_ref().err().map(|failure| failure.error.to_string()),
            "validate_error": checked.as_ref().err().map(|failure| failure.error.to_string())
        })
    );
    let found_failure =
        found.expect_err("ordinary path search must refuse unauthorized OCSP evidence");
    let checked_failure =
        checked.expect_err("ordinary path validation must refuse unauthorized OCSP evidence");
    assert_mandatory_failure(&found_failure, &expected, reason);
    assert_mandatory_failure(&checked_failure, &expected, reason);
}

fn check_signature_only_control(good: &str, bad: &str) {
    let genuine = response(good);
    let damaged = response(bad);
    assert_eq!(genuine.tbs, damaged.tbs);
    assert_eq!(genuine.basic.certs, damaged.basic.certs);
    assert_eq!(
        genuine.basic.signature_algorithm,
        damaged.basic.signature_algorithm
    );
    let signer = embedded_responder(&genuine);
    check_responder_id(&genuine, &signer);
    check_full_cert_id(&damaged);
    let good_signature = genuine.basic.signature.raw_bytes();
    let bad_signature = damaged.basic.signature.raw_bytes();
    assert_eq!(good_signature.len(), bad_signature.len());
    assert_eq!(good_signature[0] ^ bad_signature[0], 1);
    assert_eq!(&good_signature[1..], &bad_signature[1..]);
    assert!(verify_response(&genuine, &signer));
    assert!(!verify_response(&damaged, &signer));
}

#[test]
fn genuine_exact_issuer_response_preserves_ordinary_trust() {
    let actual = response(DIRECT);
    let issuer = cert("interm");
    assert_eq!(embedded_responder(&actual).der(), issuer.der());
    assert!(
        matches!(&actual.basic.tbs_response_data.responder_id, ResponderId::ByName(name) if name == issuer.subject())
    );
    check_full_cert_id(&actual);
    assert!(verify_response(&actual, &issuer));
    assert_positive(DIRECT);
}

#[test]
fn genuine_delegated_response_preserves_ordinary_trust() {
    let actual = response(DELEGATED);
    let responder = embedded_responder(&actual);
    let issuer = cert("interm");
    assert_ne!(responder.der(), issuer.der());
    assert_eq!(responder.issuer(), issuer.subject());
    assert!(responder
        .extended_key_usage()
        .unwrap()
        .contains(&oids::KP_OCSP_SIGNING));
    assert!(verify_certificate(&responder, &issuer));
    check_responder_id(&actual, &responder);
    check_full_cert_id(&actual);
    assert!(verify_response(&actual, &responder));
    assert_positive(DELEGATED);
}

#[test]
fn copied_issuer_signature_cannot_authorize_a_different_ocsp_key() {
    let issuer = cert("interm");
    let fake = Cert::from_der(&read("fake-issuer-copied-signature.der")).unwrap();
    assert_eq!(fake.issuer(), issuer.issuer());
    assert_eq!(fake.subject(), issuer.subject());
    assert_eq!(fake.serial_bytes(), issuer.serial_bytes());
    assert_eq!(fake.decoded().signature(), issuer.decoded().signature());
    assert_eq!(
        fake.decoded().signature_algorithm(),
        issuer.decoded().signature_algorithm()
    );
    assert_ne!(signed_part(fake.der()), signed_part(issuer.der()));
    assert_ne!(fake.der(), issuer.der());
    assert_ne!(fake.public_key(), issuer.public_key());
    assert_eq!(fake.public_key(), cert("signer1").public_key());
    let root = cert("root");
    assert!(verify_certificate(&issuer, &root));
    assert!(!verify_certificate(&fake, &root));
    let forged = response(FAKE);
    assert_eq!(embedded_responder(&forged).der(), fake.der());
    assert!(
        matches!(&forged.basic.tbs_response_data.responder_id, ResponderId::ByName(name) if name == issuer.subject() && name == fake.subject())
    );
    check_full_cert_id(&forged);
    assert!(verify_response(&forged, &fake));
    assert!(!verify_response(&forged, &issuer));
    assert_refused(FAKE, "response was signed by an unauthorized certificate");
}

#[test]
fn fake_issuer_does_not_mask_a_bad_raw_response_signature() {
    check_signature_only_control(FAKE, FAKE_BAD);
    assert_refused(FAKE_BAD, "Unable to verify OCSP response signature");
}

#[test]
fn exact_issuer_does_not_mask_a_bad_raw_response_signature() {
    check_signature_only_control(DIRECT, DIRECT_BAD);
    assert_refused(DIRECT_BAD, "Unable to verify OCSP response signature");
}
