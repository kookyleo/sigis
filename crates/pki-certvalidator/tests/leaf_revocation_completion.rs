//! Tests-first opaque current-leaf evaluation contract; no upstream ID credit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use der::Decode;
use sigis_pki_certvalidator::{
    validate::{find_current_leaf_revocation_evaluation, LeafRevocationChannel},
    CertRevTrustPolicy, FreshnessReqType, RevocationCheckingPolicy, RevocationCheckingRule,
    ValidationContext, REQUIRE_REVINFO,
};
use sigis_pki_core::{cert::Cert, time::Moment};

fn bytes(name: &str) -> Vec<u8> {
    let path = sigis_testdata::data_dir()
        .join("lanes/r3-v/leaf-revoked-completion")
        .join(name);
    let b = std::fs::read(&path).unwrap();
    eprintln!(
        "LEAF_COMPLETION_CV_INPUT {}",
        serde_json::json!({"path":path.canonicalize().unwrap(),"length":b.len(),"sha256":sigis_pki_core::algorithms::DigestAlgorithm::Sha256.digest(&b).iter().map(|b|format!("{b:02x}")).collect::<String>()})
    );
    b
}
fn cert(name: &str) -> Cert {
    Cert::from_der(&bytes(&format!("cert-{name}.der"))).unwrap()
}
fn context(roots: bool, at: &str, both: bool, leaf_crl: bool) -> ValidationContext {
    let mut policy = CertRevTrustPolicy::new(if both {
        RevocationCheckingPolicy {
            ee_certificate_rule: RevocationCheckingRule::CrlAndOcspRequired,
            intermediate_ca_cert_rule: RevocationCheckingRule::CrlOrOcspRequired,
        }
    } else {
        REQUIRE_REVINFO
    });
    policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    let mut b = ValidationContext::builder()
        .moment(Moment::parse_rfc3339(at).unwrap())
        .point_in_time_validation(false)
        .revinfo_policy(policy)
        .other_cert(cert("interm"))
        .crl(bytes("2020-12-25/crl-root.der"))
        .ocsp_response(bytes("2020-12-25/ocsp-signer2.der"));
    if roots {
        b = b.trust_root(cert("root"));
    }
    if leaf_crl {
        b = b.crl(bytes("2020-12-25/crl-interm.der"));
    }
    b.build().unwrap()
}
#[test]
fn selected_ocsp_revocation_retains_authenticated_bound_after_full_current_checks() {
    let ctx = context(true, "2020-12-25T00:00:00Z", false, false);
    let leaf = cert("signer2");
    let checked = find_current_leaf_revocation_evaluation(&ctx, &leaf, None).unwrap();
    assert_eq!(checked.path().leaf(), Some(&leaf));
    assert!(
        checked.unresolved_failure().is_some(),
        "currently revoked remains unresolved"
    );
    assert_eq!(checked.leaf_events().len(), 1);
    let event = &checked.leaf_events()[0];
    assert_eq!(event.target(), &leaf);
    assert_eq!(event.issuer(), &cert("interm"));
    assert_eq!(event.evidence_der(), bytes("2020-12-25/ocsp-signer2.der"));
    assert_eq!(
        event.effective_time(),
        Moment::parse_rfc3339("2020-12-01T00:00:00Z").unwrap()
    );
    assert_eq!(event.channel(), LeafRevocationChannel::Ocsp);
    assert_eq!(event.rule(), RevocationCheckingRule::CrlOrOcspRequired);
}
#[test]
fn required_independent_crl_cannot_be_skipped_after_authenticated_ocsp_revocation() {
    let ctx = context(true, "2020-12-25T00:00:00Z", true, false);
    assert!(find_current_leaf_revocation_evaluation(&ctx, &cert("signer2"), None).is_err());
}
#[test]
fn both_selected_channels_must_complete_and_preserve_both_authenticated_events() {
    let ctx = context(true, "2020-12-25T00:00:00Z", true, true);
    let checked = find_current_leaf_revocation_evaluation(&ctx, &cert("signer2"), None).unwrap();
    assert_eq!(checked.leaf_events().len(), 2);
    assert!(checked
        .leaf_events()
        .iter()
        .any(|e| e.channel() == LeafRevocationChannel::Ocsp));
    assert!(checked
        .leaf_events()
        .iter()
        .any(|e| e.channel() == LeafRevocationChannel::Crl));
    assert!(checked
        .leaf_events()
        .iter()
        .all(|e| e.effective_time() == Moment::parse_rfc3339("2020-12-01T00:00:00Z").unwrap()));
}
#[test]
fn unknown_anchor_never_becomes_an_evaluated_completion_path() {
    let ctx = context(false, "2020-12-25T00:00:00Z", false, false);
    assert!(find_current_leaf_revocation_evaluation(&ctx, &cert("signer2"), None).is_err());
}
#[test]
fn expiry_barriers_remain_in_force() {
    let ctx = context(true, "2025-12-25T00:00:00Z", false, false);
    assert!(find_current_leaf_revocation_evaluation(&ctx, &cert("signer2"), None).is_err());
}

#[test]
fn ordinary_path_validation_retains_current_revoked_error_and_time() {
    use sigis_pki_certvalidator::validate::find_valid_path;
    use sigis_pki_core::errors::ValidationError;
    let ctx = context(true, "2020-12-25T00:00:00Z", false, false);
    let failure = find_valid_path(&ctx, &cert("signer2"), None).unwrap_err();
    assert!(failure.is_ee_cert);
    assert_eq!(
        failure.time_horizon,
        Some(Moment::parse_rfc3339("2020-12-01T00:00:00Z").unwrap())
    );
    assert!(matches!(
        failure.error,
        ValidationError::Revoked {
            reason: Some("key_compromise"),
            ..
        }
    ));
    assert_eq!(
        failure.path.as_ref().and_then(|p| p.leaf()),
        Some(&cert("signer2"))
    );
}

#[test]
fn authenticated_leaf_event_does_not_turn_forged_ocsp_into_completion() {
    let mut forged = bytes("2020-12-25/ocsp-signer2.der");
    // Flip only the actual BasicOCSPResponse signature found by mature decode;
    // keep the signed response data and embedded certificates unchanged.
    let response = x509_ocsp::OcspResponse::from_der(&forged).unwrap();
    let basic_bytes = response.response_bytes.unwrap().response;
    let basic = x509_ocsp::BasicOcspResponse::from_der(basic_bytes.as_bytes()).unwrap();
    let signature = basic.signature.raw_bytes();
    let at = forged
        .windows(signature.len())
        .position(|window| window == signature)
        .unwrap();
    forged[at] ^= 1;
    let ctx = ValidationContext::builder()
        .moment(Moment::parse_rfc3339("2020-12-25T00:00:00Z").unwrap())
        .point_in_time_validation(false)
        .revinfo_policy(CertRevTrustPolicy::new(REQUIRE_REVINFO))
        .trust_root(cert("root"))
        .other_cert(cert("interm"))
        .crl(bytes("2020-12-25/crl-root.der"))
        .ocsp_response(forged)
        .build()
        .unwrap();
    assert!(find_current_leaf_revocation_evaluation(&ctx, &cert("signer2"), None).is_err());
}

#[test]
fn proof_only_metadata_limit_keeps_fully_current_valid_ordinary_path_semantics() {
    use sigis_pki_certvalidator::validate::find_valid_path;
    for root_crl in [
        "metadata/root-crl-duplicate-extension.der",
        "metadata/root-crl-this-update-fraction.der",
    ] {
        let mut policy = CertRevTrustPolicy::new(REQUIRE_REVINFO);
        policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
        let ctx = ValidationContext::builder()
            .moment(Moment::parse_rfc3339("2020-12-25T00:00:00Z").unwrap())
            .point_in_time_validation(false)
            .revinfo_policy(policy)
            .trust_root(cert("root"))
            .other_cert(cert("interm"))
            .crl(bytes(root_crl))
            .ocsp_response(bytes("metadata/ocsp-good.der"))
            .build()
            .unwrap();
        let leaf = cert("signer2");
        let ordinary =
            find_valid_path(&ctx, &leaf, None).expect("ordinary currently valid control");
        let evaluation = find_current_leaf_revocation_evaluation(&ctx, &leaf, None)
            .expect("no temporal recovery is required for a fully valid current MAIN");
        assert_eq!(evaluation.path(), &ordinary);
        assert!(evaluation.leaf_events().is_empty());
        assert!(evaluation.unresolved_failure().is_none());
    }
}

#[test]
fn unknown_self_issued_anchor_preserves_complete_ordinary_failure_mapping() {
    use sigis_pki_certvalidator::validate::find_valid_path;
    let ctx = context(false, "2020-12-25T00:00:00Z", false, false);
    let unknown_root = cert("root");
    let ordinary = find_valid_path(&ctx, &unknown_root, None).unwrap_err();
    assert!(ordinary.invalid_certificate);
    let evaluation =
        find_current_leaf_revocation_evaluation(&ctx, &unknown_root, None).unwrap_err();
    assert_eq!(
        evaluation, ordinary,
        "new entry retains the original typed payload/path/position/time"
    );
}

#[test]
fn provisional_partial_crl_event_cannot_survive_tolerated_fetch_failure() {
    use sigis_pki_certvalidator::validate::find_valid_path;
    use sigis_pki_core::{
        errors::{FetchError, FetchErrorKind, ValidationError},
        fetch::{CrlFetcher, Fetchers},
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Debug, Default)]
    struct FailedTransport(AtomicUsize);
    impl CrlFetcher for FailedTransport {
        fn fetch_crls(&self, _: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(FetchError::new(
                FetchErrorKind::Network,
                "required supplementary CRL transport failed",
            ))
        }
    }
    let fetcher = Arc::new(FailedTransport::default());
    let mut policy = CertRevTrustPolicy::new(RevocationCheckingPolicy {
        ee_certificate_rule: RevocationCheckingRule::CheckIfDeclaredSoft,
        intermediate_ca_cert_rule: RevocationCheckingRule::CrlRequired,
    });
    policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    let ctx = ValidationContext::builder()
        .moment(Moment::parse_rfc3339("2020-12-25T00:00:00Z").unwrap())
        .point_in_time_validation(false)
        .revinfo_policy(policy)
        .trust_root(cert("root"))
        .other_cert(cert("interm"))
        .crl(bytes("2020-12-25/crl-root.der"))
        .crl(bytes("metadata/crl-partial-reasons.der"))
        .fetchers(Fetchers {
            crl: Some(fetcher.clone()),
            ..Fetchers::none()
        })
        .build()
        .unwrap();
    let leaf = cert("signer2");
    let ordinary = find_valid_path(&ctx, &leaf, None).unwrap_err();
    assert!(matches!(
        ordinary.error,
        ValidationError::Revoked {
            reason: Some("key_compromise"),
            ..
        }
    ));
    assert_eq!(
        fetcher.0.load(Ordering::SeqCst),
        0,
        "ordinary authentic revocation returns before supplementary fetch"
    );
    let completion = find_current_leaf_revocation_evaluation(&ctx, &leaf, None);
    assert!(completion.is_err(), "incomplete selected CRL reason coverage cannot become opaque completed facts after tolerated fetch failure");
}
