//! Actual exact-DER direct issuer authority remains valid under the bounded proof guard.
//! Supplemental cryptographic controls; no immutable upstream-function credit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use sigis_pki_certvalidator::{
    validate::{find_current_leaf_revocation_evaluation, find_valid_path},
    CertRevTrustPolicy, FreshnessReqType, RevocationCheckingPolicy, RevocationCheckingRule,
    ValidationContext,
};
use sigis_pki_core::{algorithms::DigestAlgorithm, cert::Cert, time::Moment};
const NOW: &str = "2020-12-25T00:00:00Z";
fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn read(name: &str) -> Vec<u8> {
    let path = sigis_testdata::data_dir()
        .join("lanes/r3-v/leaf-revoked-completion/metadata-direct-issuer")
        .join(name);
    let b = std::fs::read(&path).unwrap();
    eprintln!(
        "LEAF_COMPLETION_DIRECT_ISSUER_INPUT {}",
        serde_json::json!({"path":path.canonicalize().unwrap(),"length":b.len(),"sha256":sha(&b)})
    );
    b
}
fn manifest() {
    let m: serde_json::Value = serde_json::from_slice(&read("manifest.json")).unwrap();
    assert_eq!(m["current_time"], NOW);
    for row in m["files"].as_array().unwrap() {
        let b = read(row["file"].as_str().unwrap());
        assert_eq!(sha(&b), row["sha256"].as_str().unwrap());
        assert_eq!(b.len() as u64, row["length"].as_u64().unwrap());
        assert_eq!(sha(&b), row["sha256"].as_str().unwrap());
    }
}
fn cert(name: &str) -> Cert {
    Cert::from_der(&read(&format!("cert-{name}.der"))).unwrap()
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
        .unwrap()
}
#[test]
fn genuine_exact_actual_issuer_ocsp_remains_an_ordinary_and_complete_current_positive() {
    manifest();
    let ctx = context("actual-direct-issuer-good.ocsp.der");
    let leaf = cert("signer1");
    let ordinary = find_valid_path(&ctx, &leaf, None)
        .expect("actual issuer signed its genuine Good full-CertID response");
    let evaluation = find_current_leaf_revocation_evaluation(&ctx, &leaf, None)
        .expect("exact actual issuer guard cannot blanket-refuse genuine issuer authority");
    assert_eq!(evaluation.path(), &ordinary);
    assert!(evaluation.unresolved_failure().is_none());
    assert!(evaluation.leaf_events().is_empty());
    eprintln!(
        "LEAF_COMPLETION_DIRECT_ISSUER_CASE {}",
        serde_json::json!({"id":"genuine-direct-issuer","ordinary_path":ordinary.certs().iter().map(|c|sha(c.der())).collect::<Vec<_>>(),"new_complete_current":true,"events":0})
    );
}
#[test]
fn actual_issuer_certificate_presence_never_masks_bad_raw_ocsp_signature() {
    manifest();
    let ctx = context("actual-direct-issuer-bad-raw-signature.ocsp.der");
    let leaf = cert("signer1");
    let ordinary = find_valid_path(&ctx, &leaf, None);
    let evaluation = find_current_leaf_revocation_evaluation(&ctx, &leaf, None);
    eprintln!(
        "LEAF_COMPLETION_DIRECT_ISSUER_CASE {}",
        serde_json::json!({"id":"bad-direct-issuer-raw-signature","ordinary_refused":ordinary.is_err(),"ordinary":format!("{ordinary:?}"),"new_refused":evaluation.is_err(),"new":format!("{evaluation:?}")})
    );
    assert!(
        ordinary.is_err(),
        "real issuer identity cannot bypass cryptographic response verification"
    );
    assert!(
        evaluation.is_err(),
        "new complete evaluation must retain mandatory raw signature verification"
    );
}
