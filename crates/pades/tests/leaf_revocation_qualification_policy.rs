//! Tests-first reached content-qualification contract for narrow leaf completion.
//! New fixed-clock TEST construction, zero original IDs; not previously executed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use serde_json::Value;
use sigis_cms::{
    validate::evaluate_cms_leaf_revocation, CmsValidationOptions, CmsValidationOrder,
    SignedContent, StandardCmsSignatureStatus, TrustProblem,
};
use sigis_eutl::{
    assess::{enforce_requirements, QualificationRequirements, RequiredServiceType},
    parse::trust_list_to_registry,
    q_status::QualificationResult,
    tsp::{TspRegistry, QTST_URI},
};
use sigis_pades::ades::{
    basic::{qualification_analysis, QualificationSpec},
    with_time::{
        timestamp_subindication, with_time_result, with_time_validation,
        with_time_validation_with_options, WithTimeValidationResult,
    },
    AdesValidationOptions,
};
use sigis_pki_certvalidator::{
    CertRevTrustPolicy, FreshnessReqType, ValidationContext, REQUIRE_REVINFO,
};
use sigis_pki_core::{
    algorithms::DigestAlgorithm, cert::Cert, errors::ValidationError,
    fetch::Fetchers, key_usage::KeyUsageConstraints, time::Moment,
};

const ROOT: &str = "lanes/r3-v/leaf-revoked-qualification-policy";
const C: &str = "2020-10-31T23:59:59Z";
const T: &str = "2020-11-01T00:00:00Z";
const R: &str = "2020-12-01T00:00:00Z";
const V: &str = "2020-12-25T00:00:00Z";
const PROFILES: [&str; 2] = ["issued-ca-qualified", "direct-qtst-anchor"];

fn at(value: &str) -> Moment {
    Moment::parse_rfc3339(value).unwrap()
}

fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256.digest(bytes).iter()
        .map(|byte| format!("{byte:02x}")).collect()
}

fn opened(relative: &str) -> Vec<u8> {
    let path = sigis_testdata::data_dir().join(ROOT).join(relative);
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!("required finite fixture {}: {error}", path.display())
    });
    eprintln!("LEAF_QUALIFICATION_POLICY_INPUT {}", serde_json::json!({
        "path":path.canonicalize().unwrap(),"length":bytes.len(),"sha256":sha(&bytes)
    }));
    bytes
}

fn input(relative: &str) -> Vec<u8> {
    let origin: Value = serde_json::from_slice(&opened("origin.json")).unwrap();
    let row = origin["files"].as_array().unwrap().iter()
        .find(|row| row["path"] == relative).unwrap();
    let bytes = opened(relative);
    assert_eq!(bytes.len() as u64, row["length"].as_u64().unwrap());
    assert_eq!(sha(&bytes), row["sha256"].as_str().unwrap());
    bytes
}

fn cert(role: &str) -> Cert {
    Cert::from_der(&input(&format!("content/pki/{role}.der"))).unwrap()
}

fn options() -> AdesValidationOptions {
    let mut options = AdesValidationOptions::default();
    options.exact_key_usage_settings = Some(KeyUsageConstraints {
        key_usage: Some(["non_repudiation".to_owned()].into_iter().collect()),
        ..Default::default()
    });
    options
}

fn cms_options() -> CmsValidationOptions<'static> {
    CmsValidationOptions {
        validation_order: CmsValidationOrder::SignerFirst,
        exact_key_usage_settings: options().exact_key_usage_settings,
        ..Default::default()
    }
}

fn context(profile: &str, roots: bool) -> ValidationContext {
    assert!(PROFILES.contains(&profile));
    let trust: Value = serde_json::from_slice(
        &input(&format!("content/trust/{profile}.json")),
    ).unwrap();
    let mut policy = CertRevTrustPolicy::new(REQUIRE_REVINFO);
    policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    let mut builder = ValidationContext::builder()
        .moment(at(V)).point_in_time_validation(false)
        .revinfo_policy(policy).fetchers(Fetchers::none());
    if roots {
        for anchor in trust["anchors"].as_object().unwrap().values() {
            let bytes = input(&format!("content/{}", anchor["der_path"].as_str().unwrap()));
            assert_eq!(sha(&bytes), anchor["sha256"].as_str().unwrap());
            builder = builder.trust_root(Cert::from_der(&bytes).unwrap());
        }
    }
    // These are original explicit fixture trust inputs, identical across TL
    // variants. Do not derive a weaker context by stripping EUTL qualifiers.
    for name in ["main-current-revoked", "content-tsa-current-good", "signature-tsa-current-good"] {
        builder = builder
            .crl(input(&format!("content/revinfo/{name}.crl.der")))
            .ocsp_response(input(&format!("content/revinfo/{name}.ocsp.der")));
    }
    builder.build().unwrap()
}

fn registry(profile: &str, variant: &str) -> TspRegistry {
    let origin: Value = serde_json::from_slice(&opened("origin.json")).unwrap();
    let authentication_reference = at(
        origin["content_clocks"]["authentication_reference"].as_str().unwrap(),
    );
    assert!(authentication_reference > at(V));
    let xml = String::from_utf8(input(&format!("content/tls/{profile}/{variant}.xml"))).unwrap();
    // Authenticate actual signed list bytes. The observed authentication
    // reference is separate from MAIN v and is never earlier signature POE.
    let (registry, errors) = trust_list_to_registry(
        &xml, &[cert("tlso")], None, Some(authentication_reference),
    ).expect("genuine TL authentication prerequisite, never an unsafe parse fallback");
    assert!(errors.is_empty(), "actual TL service interpretation must succeed: {errors:?}");
    registry
}

fn requirements(profile: &str) -> QualificationRequirements {
    let mut requirements = QualificationRequirements::default();
    if profile == "direct-qtst-anchor" {
        requirements.require_service_type = Some(RequiredServiceType::Uri(QTST_URI.into()));
    }
    requirements
}

fn spec<'a>(registry: &'a TspRegistry, profile: &str) -> QualificationSpec<'a> {
    QualificationSpec {
        registry: Some(registry),
        requirements: Some(QualificationRequirements::default()),
        ts_requirements: Some(requirements(profile)),
    }
}

fn frozen(bytes: &[u8], ctx: &ValidationContext) -> StandardCmsSignatureStatus {
    let selected = cms_options();
    let operation = evaluate_cms_leaf_revocation(bytes, SignedContent::Encapsulated, ctx, &selected)
        .expect("actual current CMS producer, no injected facts");
    let status = operation.into_unresolved_status();
    assert!(status.signature.intact && status.signature.valid);
    assert!(!status.signature.trusted() && status.signature.revoked());
    assert!(matches!(status.signature.trust_problem.as_ref(),
        Some(TrustProblem::Path(ValidationError::Revoked {
            revocation_time: Some(time), reason: Some("key_compromise"), ..
        })) if *time == at(R)));
    assert_eq!(status.signature.validation_time, Some(at(V)));
    assert_eq!(status.signature.error_time_horizon, Some(at(R)));
    assert_eq!(status.signature.signing_cert.as_ref(), Some(&cert("main")));
    assert!(status.signature.validation_path.is_some());
    let ts = status.timestamp_validity.as_ref().expect("real selected signature TST");
    assert!(ts.signature.intact && ts.signature.valid && ts.trusted());
    assert_eq!(ts.timestamp, at(T));
    assert_eq!(ts.signature.validation_time, Some(at(V)));
    assert_eq!(ts.signature.signing_cert.as_ref(), Some(&cert("signature-tsa")));
    status
}

fn run(
    bytes: &[u8], ctx: &ValidationContext, qualification: &QualificationSpec<'_>,
) -> WithTimeValidationResult {
    let before = format!("{ctx:?}");
    let algorithm_policy = ctx.algorithm_policy_arc();
    let result = with_time_validation_with_options(
        bytes, None, ctx, qualification, None, &options(),
    ).unwrap();
    assert_eq!(format!("{ctx:?}"), before, "caller context retained");
    assert!(Arc::ptr_eq(&algorithm_policy, &ctx.algorithm_policy_arc()));
    result
}

fn require_success(result: &WithTimeValidationResult, original: &StandardCmsSignatureStatus) {
    assert_eq!(result.ades_subindic.standard_name(), "OK", "{result:#?}");
    assert_eq!(result.best_signature_time, Some(at(T)));
    assert!(result.failure_msg.is_none());
    let after = result.api_status.as_ref().unwrap();
    assert!(after.signature.intact && after.signature.valid);
    assert!(after.signature.trusted() && after.bottom_line());
    assert!(after.signature.revoked(), "no false currently-unrevoked claim");
    assert_eq!(after.signature.revocation_details, original.signature.revocation_details);
    assert_eq!(after.signature.validation_time, Some(at(V)));
    assert_eq!(after.signature.error_time_horizon, Some(at(R)));
    assert_eq!(after.signature.validation_path, original.signature.validation_path);
    assert_eq!(format!("{:?}", after.timestamp_validity), format!("{:?}", original.timestamp_validity));
    assert_eq!(format!("{:?}", after.content_timestamp_validity), format!("{:?}", original.content_timestamp_validity));
}

fn require_late_refusal(result: &WithTimeValidationResult, original: &StandardCmsSignatureStatus) {
    assert_eq!(result.ades_subindic.standard_name(), "REVOKED_NO_POE", "{result:#?}");
    assert_eq!(result.best_signature_time, Some(at(T)), "keep genuine reached signature bound");
    let after = result.api_status.as_ref().expect("available frozen CMS is mandatory");
    assert_eq!(format!("{after:#?}"), format!("{original:#?}"),
        "late content decision must move the WHOLE same frozen CMS payload");
    assert!(!after.signature.trusted() && after.signature.revoked());
    assert!(!after.bottom_line());
    assert_eq!(after.signature.validation_time, Some(at(V)));
    assert_eq!(after.signature.error_time_horizon, Some(at(R)));
}

// An independent public diagnostic assessment is a premise check, not the
// internal assessment or a witness supplied to the WithTime operation. Exact
// private reuse/no-extra-call observation is routed separately to L.
fn current_content_service(
    status: &StandardCmsSignatureStatus, registry: &TspRegistry, profile: &str,
    expected_c: Moment,
) -> QualificationResult {
    let content = status.content_timestamp_validity.as_ref().unwrap();
    assert!(content.signature.intact && content.signature.valid && content.trusted());
    assert_eq!(content.timestamp, expected_c);
    assert_eq!(content.signature.validation_time, Some(at(V)));
    assert_eq!(content.signature.signing_cert.as_ref(), Some(&cert("content-tsa")));
    let path = content.signature.validation_path.as_ref().unwrap();
    let assessment = qualification_analysis(registry, path, content.signature.validation_time).unwrap();
    enforce_requirements(&requirements(profile), &assessment, path)
        .expect("actual content qualification ALREADY passes at its original reference");
    assessment
}

#[test]
fn c0_no_content_preserves_old_default_none_and_the_pure_failed_status_guard() {
    let bytes = input("content/cms/no-content.der");
    for profile in PROFILES {
        let ctx = context(profile, true);
        let original = frozen(&bytes, &ctx);
        assert!(original.content_timestamp_validity.is_none());
        let default = with_time_validation(&bytes, None, &ctx, &QualificationSpec::default(), None).unwrap();
        let none = with_time_validation_with_options(
            &bytes, None, &ctx, &QualificationSpec::default(), None,
            &AdesValidationOptions::default(),
        ).unwrap();
        assert_eq!(format!("{default:#?}"), format!("{none:#?}"));
        require_success(&default, &original);
        let pure = with_time_result(original.clone(), &QualificationSpec::default(), None, None, at(V));
        assert_ne!(pure.ades_subindic.standard_name(), "OK");
        assert_eq!(format!("{:?}", pure.api_status.as_ref().unwrap().signature),
            format!("{:?}", original.signature));
        assert!(!pure.api_status.unwrap().signature.trusted());
    }
}

#[test]
fn c1_c4_c5_authentic_inclusive_windows_and_same_input_controls_complete() {
    let bytes = input("content/cms/distinct-role.der");
    for profile in PROFILES {
        let ctx = context(profile, true);
        let original = frozen(&bytes, &ctx);
        let trust_before = input(&format!("content/trust/{profile}.json"));
        for variant in ["broad", "start-at-c", "finite-end-at-v"] {
            let registry = registry(profile, variant);
            let assessment = current_content_service(&original, &registry, profile, at(C));
            let service = assessment.service_definition.as_ref().unwrap();
            assert!(service.base_info.valid_from <= at(C));
            assert!(service.base_info.valid_until.is_none_or(|end| at(V) <= end));
            if variant == "start-at-c" { assert_eq!(service.base_info.valid_from, at(C)); }
            if variant == "finite-end-at-v" { assert_eq!(service.base_info.valid_until, Some(at(V))); }
            let result = run(&bytes, &ctx, &spec(&registry, profile));
            require_success(&result, &original);
            assert!(result.qualification.as_ref().unwrap().status.qualified);
            assert!(result.timestamp_qualification.as_ref().unwrap().status.qualified);
            assert_eq!(input("content/cms/distinct-role.der"), bytes);
            assert_eq!(input(&format!("content/trust/{profile}.json")), trust_before);
        }
    }
}

#[test]
fn c2_c3_selected_current_content_service_must_cover_both_real_bounds() {
    let bytes = input("content/cms/distinct-role.der");
    for profile in PROFILES {
        let ctx = context(profile, true);
        let original = frozen(&bytes, &ctx);
        // A real allowed control is mandatory before any rejected variation.
        let broad = registry(profile, "broad");
        require_success(&run(&bytes, &ctx, &spec(&broad, profile)), &original);
        for variant in ["between-c-and-t", "after-t-before-v", "start-at-v"] {
            let registry = registry(profile, variant);
            let assessment = current_content_service(&original, &registry, profile, at(C));
            let selected = assessment.service_definition.as_ref().unwrap();
            assert!(selected.base_info.valid_from > at(C));
            assert!(selected.base_info.valid_from <= at(V));
            if variant == "between-c-and-t" { assert_eq!(selected.base_info.valid_from, at(T)); }
            let result = run(&bytes, &ctx, &spec(&registry, profile));
            require_late_refusal(&result, &original);
            assert_eq!(result.signature_not_before_time, Some(at(C)));
            assert!(result.qualification.as_ref().unwrap().status.qualified,
                "existing signer guard was actually reached and passed");
            assert!(result.timestamp_qualification.as_ref().unwrap().status.qualified,
                "signature TSA assessment remains its own reached role");
        }
    }
}

#[test]
fn c4_equal_content_and_signature_time_is_a_separate_genuine_inclusive_control() {
    let bytes = input("content/cms/equal-content-time.der");
    assert_ne!(bytes, input("content/cms/distinct-role.der"));
    for profile in PROFILES {
        let ctx = context(profile, true);
        let original = frozen(&bytes, &ctx);
        let registry = registry(profile, "between-c-and-t");
        let assessment = current_content_service(&original, &registry, profile, at(T));
        assert_eq!(assessment.service_definition.unwrap().base_info.valid_from, at(T));
        let result = run(&bytes, &ctx, &spec(&registry, profile));
        require_success(&result, &original);
        assert_eq!(result.signature_not_before_time, Some(at(T)));
    }
}

#[test]
fn c7_optional_absence_and_qfalse_are_not_rewritten_as_mandatory_or_qualified() {
    let bytes = input("content/cms/distinct-role.der");
    for profile in PROFILES {
        let ctx = context(profile, true);
        let original = frozen(&bytes, &ctx);
        let optional_absent = run(&bytes, &ctx, &QualificationSpec::default());
        require_success(&optional_absent, &original);
        assert!(optional_absent.qualification.is_none());
        assert!(optional_absent.timestamp_qualification.is_none());
        let conflicting = registry(profile, "multiple-conflicting");
        let content = original.content_timestamp_validity.as_ref().unwrap();
        let actual = qualification_analysis(&conflicting,
            content.signature.validation_path.as_ref().unwrap(), content.signature.validation_time).unwrap();
        assert!(!actual.status.qualified);
        assert!(actual.service_definition.is_none(), "real conflicting selection premise");
        let optional = QualificationSpec {
            registry: Some(&conflicting), requirements: None, ts_requirements: None,
        };
        require_success(&run(&bytes, &ctx, &optional), &original);
        // Private retention of this qfalse content assessment has no public
        // getter; that exact no-rewrite/no-extra-call assertion is not invented.
    }
}

#[test]
fn c8_no_favorable_service_retry_and_required_conflicts_stay_closed() {
    let bytes = input("content/cms/distinct-role.der");
    for profile in PROFILES {
        let ctx = context(profile, true);
        let original = frozen(&bytes, &ctx);
        let broad = registry(profile, "broad");
        require_success(&run(&bytes, &ctx, &spec(&broad, profile)), &original);
        let ordered = registry(profile, "multiple-first-late-second-favorable");
        let assessment = current_content_service(&original, &ordered, profile, at(C));
        assert!(assessment.service_definition.unwrap().base_info.valid_from > at(T),
            "actual first selected service, never a favorable earlier re-query");
        require_late_refusal(&run(&bytes, &ctx, &spec(&ordered, profile)), &original);
        let conflict = registry(profile, "multiple-conflicting");
        let result = run(&bytes, &ctx, &spec(&conflict, profile));
        require_late_refusal(&result, &original);
    }
}

#[test]
fn c9_real_current_reference_content_denial_preserves_frozen_main_after_old_role_guards() {
    let bytes = input("content/cms/distinct-role.der");
    for profile in PROFILES {
        let ctx = context(profile, true);
        let original = frozen(&bytes, &ctx);
        let broad = registry(profile, "broad");
        require_success(&run(&bytes, &ctx, &spec(&broad, profile)), &original);
        let registry = registry(profile, "outside-current-end");
        let qualification = spec(&registry, profile);
        let content = original.content_timestamp_validity.as_ref().unwrap();
        assert!(content.trusted());
        assert_eq!(content.signature.validation_time, Some(at(V)));
        assert_ne!(timestamp_subindication(content, &qualification,
            qualification.ts_requirements.as_ref()).0.standard_name(), "OK",
            "real current-v content qualification denial is a required premise");
        let signature = original.timestamp_validity.as_ref().unwrap();
        assert_eq!(timestamp_subindication(signature, &qualification,
            qualification.ts_requirements.as_ref()).0.standard_name(), "OK",
            "signature TSA stays qualified at its OWN original reference");
        let signer_path = original.signature.validation_path.as_ref().unwrap();
        let signer = qualification_analysis(&registry, signer_path, Some(at(T))).unwrap();
        enforce_requirements(qualification.requirements.as_ref().unwrap(), &signer, signer_path).unwrap();
        let result = run(&bytes, &ctx, &qualification);
        require_late_refusal(&result, &original);
        assert!(result.qualification.as_ref().unwrap().status.qualified);
        assert!(result.timestamp_qualification.as_ref().unwrap().status.qualified);
        assert!(result.signature_not_before_time.is_none(),
            "a denied content assessment never contributes the lower bound");
    }
}

#[test]
fn existing_signer_requirement_failure_precedes_new_content_admission() {
    let bytes = input("content/cms/distinct-role.der");
    let deny_signer = QualificationRequirements {
        permit_cert_types: Some(Default::default()), ..Default::default()
    };
    for profile in PROFILES {
        let ctx = context(profile, true);
        let original = frozen(&bytes, &ctx);
        let mut old_failure = None;
        for variant in ["broad", "after-t-before-v"] {
            let registry = registry(profile, variant);
            let qualification = QualificationSpec {
                registry: Some(&registry), requirements: Some(deny_signer.clone()),
                ts_requirements: Some(requirements(profile)),
            };
            let result = run(&bytes, &ctx, &qualification);
            assert_eq!(result.ades_subindic.standard_name(), "SIG_CONSTRAINTS_FAILURE");
            assert_eq!(format!("{:?}", result.api_status.as_ref().unwrap()), format!("{original:?}"));
            let error = enforce_requirements(&deny_signer,
                result.qualification.as_ref().unwrap(), original.signature.validation_path.as_ref().unwrap())
                .unwrap_err();
            assert_eq!(result.failure_msg.as_deref(), Some(error.failure_message.as_str()));
            if let Some(before) = &old_failure { assert_eq!(before, &result.failure_msg); }
            old_failure = Some(result.failure_msg);
        }
    }
}

#[test]
fn c7_real_bad_content_crypto_imprint_purpose_and_missing_registry_do_not_recover() {
    for profile in PROFILES {
        let ctx = context(profile, true);
        let allowed_bytes = input("content/cms/distinct-role.der");
        let original = frozen(&allowed_bytes, &ctx);
        let broad = registry(profile, "broad");
        require_success(&run(&allowed_bytes, &ctx, &spec(&broad, profile)), &original);
        for name in ["bad-content-signature", "wrong-content-imprint", "wrong-content-purpose"] {
            let bytes = input(&format!("content/cms/{name}.der"));
            let frozen_bad = frozen(&bytes, &ctx);
            let content = frozen_bad.content_timestamp_validity.as_ref().unwrap();
            assert!(!content.trusted(), "actual bad content-token premise: {name}");
            match name {
                "bad-content-signature" => assert!(!content.signature.valid),
                "wrong-content-imprint" => {
                    assert!(content.signature.valid);
                    assert!(!content.signature.intact);
                }
                "wrong-content-purpose" => {
                    // This authentic token uses the MAIN cert, which is also
                    // actually revoked at v. It is a COMBINED negative, not
                    // isolated evidence that the later TSA KU check ran.
                    assert_eq!(content.signature.signing_cert.as_ref(), Some(&cert("main")));
                    assert!(cert("main").extended_key_usage().is_none_or(|eku| {
                        !eku.contains(&sigis_pki_core::asn1::oids::KP_TIME_STAMPING)
                    }));
                }
                _ => unreachable!(),
            }
            let result = run(&bytes, &ctx, &QualificationSpec::default());
            assert_ne!(result.ades_subindic.standard_name(), "OK");
            assert_eq!(format!("{:?}", result.api_status.as_ref().unwrap()), format!("{frozen_bad:?}"));
            assert!(!result.api_status.as_ref().unwrap().signature.trusted());
        }
        let missing = QualificationSpec {
            registry: None, requirements: None, ts_requirements: Some(requirements(profile)),
        };
        let denied = run(&allowed_bytes, &ctx, &missing);
        assert_ne!(denied.ades_subindic.standard_name(), "OK");
        assert_eq!(format!("{:?}", denied.api_status.as_ref().unwrap()), format!("{original:?}"));
    }
}

#[test]
fn authenticated_list_and_root_guards_cannot_be_replaced_by_manual_service_mutation() {
    let origin: Value = serde_json::from_slice(&opened("origin.json")).unwrap();
    let auth = at(origin["content_clocks"]["authentication_reference"].as_str().unwrap());
    for profile in PROFILES {
        let xml = String::from_utf8(input(&format!("content/tls/{profile}/broad.xml"))).unwrap();
        assert!(trust_list_to_registry(&xml, &[cert("main-ca")], None, Some(auth)).is_err(),
            "wrong TL authentication key must refuse");
        let bytes = input("content/cms/distinct-role.der");
        let untrusted = context(profile, false);
        let result = run(&bytes, &untrusted, &QualificationSpec::default());
        assert_ne!(result.ades_subindic.standard_name(), "OK");
        assert!(!result.api_status.as_ref().unwrap().signature.trusted());
    }
}
