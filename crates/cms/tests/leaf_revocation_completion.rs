//! Tests-first same-operation CMS completion; opaque value cannot take new inputs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use der::{Decode, Encode};
use sigis_cms::{
    validate::evaluate_cms_leaf_revocation, CmsValidationOptions, CmsValidationOrder, SignedContent,
};
use sigis_pki_certvalidator::{
    CertRevTrustPolicy, FreshnessReqType, ValidationContext, REQUIRE_REVINFO,
};
use sigis_pki_core::{cert::Cert, key_usage::KeyUsageConstraints, time::Moment};
fn bytes(name: &str) -> Vec<u8> {
    let p = sigis_testdata::data_dir()
        .join("lanes/r3-v/leaf-revoked-completion")
        .join(name);
    let b = std::fs::read(&p).unwrap();
    eprintln!(
        "LEAF_COMPLETION_CMS_INPUT {}",
        serde_json::json!({"path":p.canonicalize().unwrap(),"length":b.len(),"sha256":sigis_pki_core::algorithms::DigestAlgorithm::Sha256.digest(&b).iter().map(|b|format!("{b:02x}")).collect::<String>()})
    );
    b
}
fn context(roots: bool) -> ValidationContext {
    let mut policy = CertRevTrustPolicy::new(REQUIRE_REVINFO);
    policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    let mut b = ValidationContext::builder()
        .moment(Moment::parse_rfc3339("2020-12-25T00:00:00Z").unwrap())
        .point_in_time_validation(false)
        .revinfo_policy(policy)
        .crl(bytes("2020-12-25/crl-root.der"))
        .ocsp_response(bytes("2020-12-25/ocsp-signer2.der"));
    if roots {
        b = b.trust_root(Cert::from_der(&bytes("cert-root.der")).unwrap());
    }
    b.build().unwrap()
}
fn cms() -> Vec<u8> {
    // The original Python dump retains its existing explicit [0] wrapper.
    // Remove exactly that outer wrapper before ContentInfo applies it again;
    // the complete inner SignedData (including signed attributes/signature)
    // remains byte-identical. A double [0] is not a valid test input.
    let exported = bytes("fresh-original-signed-data.der");
    let explicit = der::Any::from_der(&exported).unwrap();
    assert_eq!(
        der::Tagged::tag(&explicit),
        der::Tag::ContextSpecific {
            constructed: true,
            number: der::TagNumber(0),
        }
    );
    let signed_data = der::Any::from_der(explicit.value()).unwrap();
    sigis_cms::SignedData::from_der(explicit.value()).unwrap();
    ::cms::content_info::ContentInfo {
        content_type: sigis_pki_core::asn1::oids::CT_SIGNED_DATA,
        content: signed_data,
    }
    .to_der()
    .unwrap()
}
#[test]
fn only_own_authenticated_signature_timestamp_resolves_current_leaf_obligation() {
    for order in [
        CmsValidationOrder::TimestampsFirst,
        CmsValidationOrder::SignerFirst,
    ] {
        let input = cms();
        let ctx = context(true);
        let options = CmsValidationOptions {
            validation_order: order,
            ..Default::default()
        };
        let evaluated =
            evaluate_cms_leaf_revocation(&input, SignedContent::Encapsulated, &ctx, &options)
                .unwrap();
        assert!(!evaluated.unresolved_status().signature.trusted());
        assert!(evaluated.unresolved_status().signature.revoked());
        let unresolved = evaluated.unresolved_status().clone();
        let revocation = unresolved.signature.revocation_details.as_ref().unwrap();
        assert!(!revocation.ca_revoked);
        assert_eq!(revocation.revocation_reason, Some("key_compromise"));
        assert_eq!(
            revocation.revocation_date,
            Some(Moment::parse_rfc3339("2020-12-01T00:00:00Z").unwrap())
        );
        assert_eq!(
            unresolved.signature.error_time_horizon,
            revocation.revocation_date
        );
        assert_eq!(
            unresolved.signature.validation_time,
            Some(ctx.timing().validation_time)
        );
        assert_eq!(
            unresolved
                .timestamp_validity
                .as_ref()
                .and_then(|ts| ts.signature.validation_time),
            Some(ctx.timing().validation_time)
        );
        let ts = evaluated
            .eligible_signature_timestamp()
            .expect("genuine bound signature TST");
        assert!(ts.trusted());
        assert_eq!(
            ts.timestamp,
            Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap()
        );
        let complete = evaluated.resolve_signature_timestamp();
        assert!(complete.signature.trusted(), "{complete:#?}");
        assert!(complete.bottom_line(), "{complete:#?}");
        assert!(
            complete.signature.revoked(),
            "temporal signature trust must not claim that its certificate is currently unrevoked"
        );
        assert_eq!(
            complete.signature.revocation_details,
            unresolved.signature.revocation_details
        );
        assert_eq!(
            complete.signature.error_time_horizon,
            unresolved.signature.error_time_horizon
        );
        assert_eq!(
            complete.signature.validation_path,
            unresolved.signature.validation_path
        );
        assert_eq!(
            complete.signature.signing_cert,
            unresolved.signature.signing_cert
        );
        assert_eq!(complete.signer_reported_dt, unresolved.signer_reported_dt);
        assert_eq!(
            complete
                .timestamp_validity
                .as_ref()
                .map(|ts| ts.signature.validation_time),
            unresolved
                .timestamp_validity
                .as_ref()
                .map(|ts| ts.signature.validation_time)
        );
        assert_eq!(
            complete.timestamp_validity.as_ref().map(|ts| ts.timestamp),
            unresolved
                .timestamp_validity
                .as_ref()
                .map(|ts| ts.timestamp)
        );
        assert_eq!(complete.ac_validation_errs, unresolved.ac_validation_errs);
        assert_eq!(
            complete.signature.validation_time,
            Some(ctx.timing().validation_time)
        );
    }
}
#[test]
fn unresolved_conversion_never_promotes_failed_main() {
    let input = cms();
    let ctx = context(true);
    let options = CmsValidationOptions::default();
    let evaluated =
        evaluate_cms_leaf_revocation(&input, SignedContent::Encapsulated, &ctx, &options).unwrap();
    let before = format!("{:#?}", evaluated.unresolved_status());
    let status = evaluated.into_unresolved_status();
    assert_eq!(
        format!("{status:#?}"),
        before,
        "unresolved conversion retains the complete typed error/path/API/time payload"
    );
    assert!(!status.signature.trusted());
    assert!(status.signature.trust_problem.is_some());
}
#[test]
fn required_main_predicate_is_completed_before_resolution_in_both_orders() {
    for order in [
        CmsValidationOrder::TimestampsFirst,
        CmsValidationOrder::SignerFirst,
    ] {
        let input = cms();
        let ctx = context(true);
        let options = CmsValidationOptions {
            validation_order: order,
            exact_key_usage_settings: Some(KeyUsageConstraints {
                key_usage_forbidden: Some(["non_repudiation".to_owned()].into_iter().collect()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let evaluated =
            evaluate_cms_leaf_revocation(&input, SignedContent::Encapsulated, &ctx, &options)
                .unwrap();
        let before = format!("{:#?}", evaluated.unresolved_status());
        let result = evaluated.resolve_signature_timestamp();
        assert!(!result.signature.trusted());
        assert_eq!(
            format!("{result:#?}"),
            before,
            "a mandatory-purpose denial cannot replace, clear or retime the frozen payload"
        );
    }
}
#[test]
fn unknown_roots_remain_terminal_even_with_authentic_timestamp_bytes() {
    let input = cms();
    let ctx = context(false);
    let options = CmsValidationOptions::default();
    let evaluated =
        evaluate_cms_leaf_revocation(&input, SignedContent::Encapsulated, &ctx, &options).unwrap();
    let before = format!("{:#?}", evaluated.unresolved_status());
    let result = evaluated.resolve_signature_timestamp();
    assert!(!result.signature.trusted());
    assert_eq!(
        format!("{result:#?}"),
        before,
        "unknown-root denial cannot substitute a path/status or reference time"
    );
}

#[test]
fn all_five_exact_main_predicate_fields_survive_both_operation_orders() {
    let names = |values: &[&str]| values.iter().map(|value| (*value).to_owned()).collect();
    let cases = [
        (
            "empty KU",
            KeyUsageConstraints {
                key_usage: Some(names(&[])),
                ..Default::default()
            },
            true,
        ),
        (
            "required NR",
            KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation"])),
                ..Default::default()
            },
            true,
        ),
        (
            "forbidden NR",
            KeyUsageConstraints {
                key_usage_forbidden: Some(names(&["non_repudiation"])),
                ..Default::default()
            },
            false,
        ),
        (
            "any KU",
            KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation", "key_agreement"])),
                match_all_key_usages: false,
                ..Default::default()
            },
            true,
        ),
        (
            "all KU",
            KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation", "key_agreement"])),
                match_all_key_usages: true,
                ..Default::default()
            },
            false,
        ),
        (
            "absent optional EKU",
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["time_stamping"])),
                explicit_extd_key_usage_required: false,
                ..Default::default()
            },
            true,
        ),
        (
            "absent mandatory EKU",
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["time_stamping"])),
                explicit_extd_key_usage_required: true,
                ..Default::default()
            },
            false,
        ),
        (
            "empty optional EKU",
            KeyUsageConstraints {
                extd_key_usage: Some(names(&[])),
                explicit_extd_key_usage_required: false,
                ..Default::default()
            },
            true,
        ),
        (
            "empty mandatory EKU",
            KeyUsageConstraints {
                extd_key_usage: Some(names(&[])),
                explicit_extd_key_usage_required: true,
                ..Default::default()
            },
            false,
        ),
    ];
    for order in [
        CmsValidationOrder::TimestampsFirst,
        CmsValidationOrder::SignerFirst,
    ] {
        let input = cms();
        let ctx = context(true);
        for (label, predicate, expected) in &cases {
            let options = CmsValidationOptions {
                validation_order: order,
                exact_key_usage_settings: Some(predicate.clone()),
                ..Default::default()
            };
            let evaluated =
                evaluate_cms_leaf_revocation(&input, SignedContent::Encapsulated, &ctx, &options)
                    .unwrap();
            assert!(
                !evaluated.unresolved_status().signature.trusted(),
                "still unresolved: {label}, {order:?}"
            );
            let result = evaluated.resolve_signature_timestamp();
            assert_eq!(
                result.signature.trusted(),
                *expected,
                "{label}, {order:?}: {result:#?}"
            );
            assert_eq!(
                result.bottom_line(),
                *expected,
                "{label}, {order:?}: {result:#?}"
            );
            assert_eq!(
                result.signature.validation_time,
                Some(ctx.timing().validation_time)
            );
        }
    }
}

#[test]
fn caller_supplied_path_cannot_authorize_the_temporal_exception() {
    use sigis_pki_certvalidator::{TrustAnchor, ValidationPath};
    let input = cms();
    let ctx = context(true);
    let cert = |label: &str| Cert::from_der(&bytes(&format!("cert-{label}.der"))).unwrap();
    let path = ValidationPath::new(
        TrustAnchor::new(cert("root")),
        vec![cert("interm")],
        Some(cert("signer2")),
    );
    for order in [
        CmsValidationOrder::TimestampsFirst,
        CmsValidationOrder::SignerFirst,
    ] {
        let options = CmsValidationOptions {
            validation_order: order,
            validation_path: Some(path.clone()),
            ..Default::default()
        };
        let evaluated =
            evaluate_cms_leaf_revocation(&input, SignedContent::Encapsulated, &ctx, &options)
                .unwrap();
        assert!(evaluated.unresolved_status().signature.revoked());
        assert!(
            !evaluated.resolve_signature_timestamp().signature.trusted(),
            "a correct supplied candidate path is still not this operation's discovery proof"
        );
    }
}

#[test]
fn ambiguous_selectors_reject_before_parsing_or_content_work() {
    let ctx = context(true);
    let options = CmsValidationOptions {
        key_usage_settings: Some(KeyUsageConstraints::default()),
        exact_key_usage_settings: Some(KeyUsageConstraints::default()),
        ..Default::default()
    };
    let error = evaluate_cms_leaf_revocation(
        b"not CMS",
        SignedContent::Data(b"not signed content"),
        &ctx,
        &options,
    )
    .unwrap_err();
    assert!(matches!(error, sigis_cms::CmsError::Malformed(ref message)
        if message == "key_usage_settings and exact_key_usage_settings are mutually exclusive"));
}

#[derive(Debug)]
struct OperationPolicyProbe {
    delegate: std::sync::Arc<dyn sigis_cms::policy::CmsAlgorithmUsagePolicy>,
    calls: std::sync::Mutex<Vec<(&'static str, Option<Moment>, const_oid::ObjectIdentifier)>>,
    deny_existence_only: bool,
}
impl sigis_pki_core::algorithms::AlgorithmUsagePolicy for OperationPolicyProbe {
    fn signature_algorithm_allowed(
        &self,
        algorithm: &spki::AlgorithmIdentifierOwned,
        moment: Option<Moment>,
        key: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        assert!(key.is_some());
        self.calls
            .lock()
            .unwrap()
            .push(("signature", moment, algorithm.oid));
        self.delegate
            .signature_algorithm_allowed(algorithm, moment, key)
    }
    fn digest_algorithm_allowed(
        &self,
        algorithm: &const_oid::ObjectIdentifier,
        moment: Option<Moment>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        let mut calls = self.calls.lock().unwrap();
        calls.push(("digest", moment, *algorithm));
        let digests = calls.iter().filter(|call| call.0 == "digest").count();
        if self.deny_existence_only && digests == 3 {
            sigis_pki_core::algorithms::AlgorithmUsageConstraint::denied(
                "third digest is the existence decision",
            )
        } else {
            self.delegate.digest_algorithm_allowed(algorithm, moment)
        }
    }
    fn min_rsa_key_size(&self) -> usize {
        self.delegate.min_rsa_key_size()
    }
}
impl sigis_cms::policy::CmsAlgorithmUsagePolicy for OperationPolicyProbe {
    fn digest_combination_allowed(
        &self,
        signature: &spki::AlgorithmIdentifierOwned,
        digest: &spki::AlgorithmIdentifierOwned,
        moment: Option<Moment>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        self.calls
            .lock()
            .unwrap()
            .push(("combination", moment, digest.oid));
        self.delegate
            .digest_combination_allowed(signature, digest, moment)
    }
}
#[test]
fn original_role_clocks_and_one_existence_gate_are_frozen_before_resolution() {
    use std::sync::{Arc, Mutex};
    let main_time = Moment::parse_rfc3339("2020-12-25T00:00:00Z").unwrap();
    let tsa_time = Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap();
    let mut revocation = CertRevTrustPolicy::new(REQUIRE_REVINFO);
    revocation.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    let tsa_context = ValidationContext::builder()
        .trust_root(Cert::from_der(&bytes("cert-root.der")).unwrap())
        .moment(tsa_time)
        .point_in_time_validation(false)
        .revinfo_policy(revocation)
        .crl(bytes("2020-11-01/crl-root.der"))
        .build()
        .unwrap();
    for order in [
        CmsValidationOrder::TimestampsFirst,
        CmsValidationOrder::SignerFirst,
    ] {
        for deny in [false, true] {
            let bytes = cms();
            let ctx = context(true);
            let policy = Arc::new(OperationPolicyProbe {
                delegate: sigis_cms::policy::default_policy(),
                calls: Mutex::new(Vec::new()),
                deny_existence_only: deny,
            });
            let options = CmsValidationOptions {
                validation_order: order,
                algorithm_policy: Some(policy.clone()),
                ts_validation_context: Some(&tsa_context),
                ..Default::default()
            };
            let evaluated =
                evaluate_cms_leaf_revocation(&bytes, SignedContent::Encapsulated, &ctx, &options)
                    .unwrap();
            let frozen = format!("{:#?}", evaluated.unresolved_status());
            assert!(evaluated
                .unresolved_status()
                .timestamp_validity
                .as_ref()
                .unwrap()
                .trusted());
            assert_eq!(
                evaluated.unresolved_status().signature.validation_time,
                Some(main_time)
            );
            assert_eq!(
                evaluated
                    .unresolved_status()
                    .timestamp_validity
                    .as_ref()
                    .unwrap()
                    .signature
                    .validation_time,
                Some(tsa_time)
            );
            assert_eq!(evaluated.eligible_signature_timestamp().is_some(), !deny);
            let calls = policy.calls.lock().unwrap().clone();
            let role_times = match order {
                CmsValidationOrder::SignerFirst => [main_time, tsa_time],
                CmsValidationOrder::TimestampsFirst => [tsa_time, main_time],
            };
            assert_eq!(
                calls.len(),
                7,
                "two complete ordinary CMS role decisions and ONE existence gate: {calls:?}"
            );
            for (role, expected) in role_times.into_iter().enumerate() {
                assert_eq!(calls[role * 3].0, "signature");
                assert_eq!(calls[role * 3].1, Some(expected));
                assert_eq!(calls[role * 3 + 1].0, "digest");
                assert_eq!(calls[role * 3 + 1].1, Some(expected));
                assert_eq!(calls[role * 3 + 2].0, "combination");
                assert_eq!(calls[role * 3 + 2].1, None);
            }
            assert_eq!(calls[6].0, "digest");
            assert_eq!(calls[6].1, Some(main_time));
            let result = evaluated.resolve_signature_timestamp();
            assert_eq!(
                *policy.calls.lock().unwrap(),
                calls,
                "consuming resolution cannot call a stateful policy"
            );
            assert_eq!(result.signature.trusted(), !deny);
            assert!(result.signature.revoked());
            if deny {
                assert_eq!(format!("{result:#?}"), frozen);
            }
        }
    }
}
