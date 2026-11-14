//! Tests-first authority/role boundaries for current leaf-revocation completion.
//! Zero immutable upstream ID credit. No public validation-status injection.
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
        .join("lanes/r3-v/leaf-revoked-completion/metadata-authority")
        .join(name);
    let bytes = std::fs::read(&path).unwrap();
    eprintln!(
        "LEAF_COMPLETION_AUTHORITY_INPUT {}",
        serde_json::json!({
            "path":path.canonicalize().unwrap(),"length":bytes.len(),"sha256":sha(&bytes)
        })
    );
    bytes
}
fn manifest() {
    let manifest: serde_json::Value = serde_json::from_slice(&read("manifest.json")).unwrap();
    assert_eq!(manifest["current_time"], NOW);
    for row in manifest["files"].as_array().unwrap() {
        let bytes = read(row["file"].as_str().unwrap());
        assert_eq!(bytes.len() as u64, row["length"].as_u64().unwrap());
        assert_eq!(sha(&bytes), row["sha256"].as_str().unwrap());
    }
}
fn cert(name: &str) -> Cert {
    Cert::from_der(&read(&format!("cert-{name}.der"))).unwrap()
}
fn context(ocsp: Option<&str>, crl: &str) -> ValidationContext {
    let mut policy = CertRevTrustPolicy::new(RevocationCheckingPolicy {
        ee_certificate_rule: if ocsp.is_some() {
            RevocationCheckingRule::OcspRequired
        } else {
            RevocationCheckingRule::CrlRequired
        },
        intermediate_ca_cert_rule: RevocationCheckingRule::CrlRequired,
    });
    policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    let mut builder = ValidationContext::builder()
        .moment(Moment::parse_rfc3339(NOW).unwrap())
        .point_in_time_validation(false)
        .revinfo_policy(policy)
        .trust_root(cert("root"))
        .other_cert(cert("interm"))
        .crl(read(crl));
    if crl != "root-good.crl.der" && crl != "root-revokes-intermediate.crl.der" {
        builder = builder.crl(read("root-good.crl.der"));
    }
    if let Some(file) = ocsp {
        builder = builder.ocsp_response(read(file));
    }
    builder.build().unwrap()
}

#[test]
fn currently_revoked_ca_target_is_not_the_recoverable_main_leaf_profile() {
    manifest();
    let intermediate = cert("interm");
    assert!(intermediate.is_ca());
    let good = context(None, "root-good.crl.der");
    let good_path = find_valid_path(&good, &intermediate, None)
        .expect("genuine current CA path and authentic unrevoked root CRL control");
    assert_eq!(good_path.leaf(), Some(&intermediate));
    let revoked = context(None, "root-revokes-intermediate.crl.der");
    let ordinary = find_valid_path(&revoked, &intermediate, None)
        .expect_err("actual root-signed CA revocation stays an ordinary refusal");
    assert!(
        matches!(ordinary.error, ValidationError::Revoked { revocation_time: Some(t), reason: Some("key_compromise"), .. }
        if t == Moment::parse_rfc3339("2020-12-01T00:00:00Z").unwrap())
    );
    let completion_refused =
        find_current_leaf_revocation_evaluation(&revoked, &intermediate, None).is_err();
    eprintln!(
        "LEAF_COMPLETION_AUTHORITY_CASE {}",
        serde_json::json!({"id":"revoked-ca-as-main",
        "ordinary_failure":format!("{ordinary:?}"),"new_completion_refused":completion_refused})
    );
    assert!(completion_refused,"current-valid CA with a real KeyCompromise event cannot become eligible MAIN-leaf recovery");
}

#[test]
fn actual_delegated_ocsp_positive_completes_ordinary_and_new_current_paths() {
    manifest();
    let leaf = cert("signer1");
    let ctx = context(Some("real-delegated-good.ocsp.der"), "root-good.crl.der");
    let ordinary =
        find_valid_path(&ctx, &leaf, None).expect("genuine actual delegated OCSP positive");
    let evaluated = find_current_leaf_revocation_evaluation(&ctx, &leaf, None)
        .expect("new evaluation retains normal current-valid behaviour");
    assert!(evaluated.unresolved_failure().is_none());
    assert!(evaluated.leaf_events().is_empty());
    assert_eq!(evaluated.path(), &ordinary);
}

#[test]
fn copied_issuer_signature_bits_do_not_authorize_a_different_ocsp_key() {
    manifest();
    let real = cert("interm");
    let fake = Cert::from_der(&read("fake-issuer-copied-signature.der")).unwrap();
    assert_eq!(fake.issuer(), real.issuer());
    assert_eq!(fake.subject(), real.subject());
    assert_eq!(fake.serial_bytes(), real.serial_bytes());
    assert_eq!(fake.decoded().signature(), real.decoded().signature());
    assert_ne!(fake.public_key(), real.public_key());
    let leaf = cert("signer1");
    let mut failures = Vec::new();
    for input in [
        "fake-issuer-signed-good.ocsp.der",
        "fake-issuer-bad-raw-signature.ocsp.der",
    ] {
        let ctx = context(Some(input), "root-good.crl.der");
        // Execute BOTH actual boundaries before asserting, so an ordinary
        // failure does not hide the result of the new operation (or vice versa).
        let ordinary = find_valid_path(&ctx, &leaf, None);
        let completion = find_current_leaf_revocation_evaluation(&ctx, &leaf, None);
        let ordinary_refused = ordinary.is_err();
        let completion_refused = completion.is_err();
        eprintln!(
            "LEAF_COMPLETION_AUTHORITY_CASE {}",
            serde_json::json!({"id":input,
            "ordinary_refused":ordinary_refused,"ordinary":format!("{ordinary:?}"),
            "new_completion_refused":completion_refused,"new_completion":format!("{completion:?}")})
        );
        if !ordinary_refused {
            failures.push(format!(
                "ordinary accepted unauthorized copied-signature responder: {input}"
            ));
        }
        if !completion_refused {
            failures.push(format!(
                "new evaluation accepted unauthorized copied-signature responder: {input}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn crl_signed_inner_and_outer_algorithm_identifiers_must_agree_for_completion() {
    manifest();
    let leaf = cert("signer2");
    let baseline = context(None, "leaf-real-key-compromise.crl.der");
    let baseline_evaluation = find_current_leaf_revocation_evaluation(&baseline, &leaf, None)
        .expect("actual correctly encoded and signed KeyCompromise CRL control");
    assert_eq!(baseline_evaluation.leaf_events().len(), 1);
    assert!(baseline_evaluation.unresolved_failure().is_some());
    let mismatch = context(None, "leaf-crl-inner-sha384-outer-sha256.der");
    let ordinary = find_valid_path(&mismatch, &leaf, None);
    let completion_refused =
        find_current_leaf_revocation_evaluation(&mismatch, &leaf, None).is_err();
    eprintln!(
        "LEAF_COMPLETION_AUTHORITY_CASE {}",
        serde_json::json!({"id":"crl-inner-outer-mismatch",
        "ordinary_refused":ordinary.is_err(),"ordinary":format!("{ordinary:?}"),"new_completion_refused":completion_refused})
    );
    // Record the real ordinary error independently; the new proof must not
    // treat outer-only signature verification as a complete signed CRL profile.
    assert!(
        ordinary.is_err(),
        "ordinary current revocation cannot become trust"
    );
    assert!(
        completion_refused,
        "signed TBS SHA384/outer SHA256 mismatch is unsupported completion evidence"
    );
}
