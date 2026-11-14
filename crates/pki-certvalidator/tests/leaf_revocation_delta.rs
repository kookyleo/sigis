//! A genuine base and selected delta must retain ordinary status but not recovery authority.
//! Tests-first supplemental scope; zero immutable upstream-function credit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use sigis_pki_certvalidator::{
    validate::{find_current_leaf_revocation_evaluation, find_valid_path},
    CertRevTrustPolicy, FreshnessReqType, RevocationCheckingPolicy, RevocationCheckingRule,
    ValidationContext,
};
use sigis_pki_core::{
    algorithms::DigestAlgorithm, cert::Cert, errors::ValidationError, time::Moment,
};
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
        .join("lanes/r3-v/leaf-revoked-completion/metadata-delta")
        .join(name);
    let bytes = std::fs::read(&path).unwrap();
    eprintln!(
        "LEAF_COMPLETION_DELTA_INPUT {}",
        serde_json::json!({"path":path.canonicalize().unwrap(),"length":bytes.len(),"sha256":sha(&bytes)})
    );
    bytes
}
fn manifest() {
    let m: serde_json::Value = serde_json::from_slice(&read("manifest.json")).unwrap();
    assert_eq!(m["current_time"], NOW);
    for row in m["files"].as_array().unwrap() {
        let b = read(row["file"].as_str().unwrap());
        assert_eq!(b.len() as u64, row["length"].as_u64().unwrap());
        assert_eq!(sha(&b), row["sha256"].as_str().unwrap());
    }
}
fn cert(name: &str) -> Cert {
    Cert::from_der(&read(&format!("cert-{name}.der"))).unwrap()
}
fn context(delta: Option<&str>) -> ValidationContext {
    let mut policy = CertRevTrustPolicy::new(RevocationCheckingPolicy {
        ee_certificate_rule: RevocationCheckingRule::CrlRequired,
        intermediate_ca_cert_rule: RevocationCheckingRule::CrlRequired,
    });
    policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    let mut b = ValidationContext::builder()
        .trust_root(cert("root"))
        .other_cert(cert("interm"))
        .moment(Moment::parse_rfc3339(NOW).unwrap())
        .point_in_time_validation(false)
        .revinfo_policy(policy)
        .crl(read("root-good.crl.der"))
        .crl(read("base-number100-before-revocation.crl.der"));
    if let Some(delta) = delta {
        b = b.crl(read(delta));
    }
    b.build().unwrap()
}
#[test]
fn actual_base_freshest_extension_requires_its_selected_delta() {
    manifest();
    let ctx = context(None);
    let leaf = cert("signer2");
    let failure = find_valid_path(&ctx, &leaf, None)
        .expect_err("real FreshestCRL base cannot complete without required delta");
    assert!(failure.error.is_insufficient_revinfo(), "{failure:?}");
    assert!(find_current_leaf_revocation_evaluation(&ctx, &leaf, None).is_err());
}
#[test]
fn selected_delta_real_key_compromise_is_not_base_only_recovery_evidence() {
    manifest();
    let ctx = context(Some("selected-delta-number101-key-compromise.crl.der"));
    let leaf = cert("signer2");
    let ordinary = find_valid_path(&ctx, &leaf, None)
        .expect_err("base has no entry; real selected delta must supply revocation");
    assert!(
        matches!(ordinary.error,ValidationError::Revoked { revocation_time:Some(t),reason:Some("key_compromise"),.. }
        if t==Moment::parse_rfc3339("2020-12-01T00:00:00Z").unwrap()),
        "{ordinary:?}"
    );
    let completion_refused = find_current_leaf_revocation_evaluation(&ctx, &leaf, None).is_err();
    eprintln!(
        "LEAF_COMPLETION_DELTA_CASE {}",
        serde_json::json!({"id":"selected-delta-revoked","ordinary":format!("{ordinary:?}"),"completion_refused":completion_refused})
    );
    assert!(
        completion_refused,
        "authenticated selected delta dependence is outside initial recovery profile"
    );
}
#[test]
fn genuinely_good_current_leaf_keeps_ordinary_success_with_selected_delta() {
    manifest();
    let ctx = context(Some("selected-delta-number101-key-compromise.crl.der"));
    let leaf = cert("signer1");
    let ordinary = find_valid_path(&ctx, &leaf, None)
        .expect("real signer1 is not revoked by base or selected delta");
    let evaluated = find_current_leaf_revocation_evaluation(&ctx, &leaf, None)
        .expect("ordinary fully valid current path remains ordinary success");
    assert_eq!(evaluated.path(), &ordinary);
    assert!(evaluated.unresolved_failure().is_none());
    assert!(evaluated.leaf_events().is_empty());
}
#[test]
fn selected_delta_signature_cannot_be_bypassed_by_authentic_base() {
    manifest();
    let ctx = context(Some("selected-delta-bad-raw-signature.crl.der"));
    let leaf = cert("signer2");
    let ordinary = find_valid_path(&ctx, &leaf, None)
        .expect_err("actual selected delta signature bitflip refuses mandatory CRL");
    assert!(ordinary.error.is_insufficient_revinfo(), "{ordinary:?}");
    assert!(find_current_leaf_revocation_evaluation(&ctx, &leaf, None).is_err());
}
