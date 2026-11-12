//! Exact qualification assertions from pyHanko 0.38.1
//! `test_ades_validation.py`, with fresh mandatory-policy rejection cases.

mod common;

use common::*;
use sigis_eutl::assess::{QualificationRequirements, RequiredServiceType};
use sigis_eutl::parse::trust_list_to_registry;
use sigis_eutl::tsp::{QcCertType, TspRegistry, TspTrustManager, CA_QC_URI, QTST_URI};
use sigis_pades::ades::basic::QualificationSpec;
use sigis_pades::ades::with_time::{with_time_validation, WithTimeValidationResult};
use sigis_pki_certvalidator::ValidationContext;

const MODULE: &str = "test_ades_validation";

fn recording() -> Recording {
    match std::env::var_os("HANKO_QUALIFICATION_RECORDING") {
        Some(path) => Recording(serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()),
        None => Recording::load(MODULE),
    }
}

fn registry(rec: &Recording, id: &str, keep_tsa: bool) -> TspRegistry {
    let tl = rec.0["generated_tls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tl| tl["nodeid"].as_str().unwrap().ends_with(id))
        .unwrap();
    let full = trust_list_to_registry(
        tl["xml"].as_str().unwrap(),
        &[rec.cert("testing-ca-qualified", "root")],
        None,
        None,
    )
    .unwrap()
    .0;
    if keep_tsa {
        full
    } else {
        // Mirrors clearing Python's `_tst_cert_to_si`, retaining every CA
        // registration rather than changing the input certificate or trust root.
        let mut ca_only = TspRegistry::new();
        for authority in full.known_certificate_authorities() {
            for service in full.applicable_service_definitions(authority, None) {
                if service.is_ca() {
                    ca_only.register_ca(service.clone());
                }
            }
        }
        assert!(ca_only.known_timestamp_authorities().is_empty());
        assert!(!ca_only.known_certificate_authorities().is_empty());
        ca_only
    }
}

fn context(registry: &TspRegistry, call: &Call) -> ValidationContext {
    let mut builder = ValidationContext::builder()
        .revinfo_policy(default_revinfo_policy())
        .moment(call.time())
        .fetchers(call.fetchers());
    for anchor in TspTrustManager::new(registry).trust_anchors_at(call.time()) {
        builder = builder.trust_anchor(anchor);
    }
    builder.build().unwrap()
}

fn validate(
    rec: &Recording,
    id: &str,
    registry: &TspRegistry,
    requirements: Option<QualificationRequirements>,
    ts_requirements: Option<QualificationRequirements>,
) -> WithTimeValidationResult {
    let calls = rec.calls(MODULE, id);
    assert_eq!(calls.len(), 1, "{id}");
    let call = &calls[0];
    assert_eq!(call.function(), "ades_with_time_validation");
    let result = with_time_validation(
        &call.content_info(),
        call.raw_digest().as_deref(),
        &context(registry, call),
        &QualificationSpec {
            registry: Some(registry),
            requirements,
            ts_requirements,
        },
        None,
    )
    .unwrap();
    assert_eq!(
        result.ades_subindic.standard_name(),
        call.expected_subindic(),
        "{id}: {:?}",
        result.failure_msg
    );
    assert_eq!(
        result.best_signature_time,
        sigis_eutl::util::parse_xsd_datetime(
            call.0["result"]["best_signature_time"].as_str().unwrap()
        ),
        "{id}"
    );
    let status = result.api_status.as_ref().unwrap();
    assert!(status.signature.intact, "{id}");
    assert!(status.signature.valid, "{id}");
    for (name, actual) in [
        ("trusted", status.signature.trusted()),
        ("revoked", status.signature.revoked()),
        ("bottom_line", status.bottom_line()),
    ] {
        assert_eq!(
            actual,
            call.0["result"][format!("api_status.{name}")]
                .as_bool()
                .unwrap(),
            "{id}: api_status.{name}"
        );
    }
    result
}

#[test]
fn test_embedded_cades_with_time_happy_path_with_tl() {
    let rec = recording();
    for with_requirements in [true, false] {
        let id = format!(
            "test_embedded_cades_with_time_happy_path_with_tl[{}]",
            if with_requirements { "True" } else { "False" }
        );
        let registry = registry(&rec, &id, true);
        let result = validate(
            &rec,
            &id,
            &registry,
            with_requirements.then(QualificationRequirements::default),
            None,
        );
        assert_eq!(result.ades_subindic.standard_name(), "OK");
        assert_eq!(
            result.best_signature_time,
            sigis_eutl::util::parse_xsd_datetime("2020-11-01T00:00:00Z")
        );
        let signer = result.qualification.unwrap();
        assert!(signer.status.qualified);
        assert_eq!(signer.status.qc_type, QcCertType::QcEseal);
        assert_eq!(
            signer.service_definition.unwrap().base_info.service_type,
            CA_QC_URI
        );
        let tsa = result.timestamp_qualification.unwrap();
        assert!(tsa.status.qualified);
        assert_eq!(tsa.status.qc_type, QcCertType::QcEseal);
        assert_eq!(
            tsa.service_definition.unwrap().base_info.service_type,
            QTST_URI
        );
    }
}

#[test]
fn test_embedded_cades_with_time_fail_qualification_requirements() {
    let rec = recording();
    for i in 0..3 {
        let ts_param = if i == 2 {
            "None".into()
        } else {
            format!("ts_requirements{i}")
        };
        let id = format!(
            "test_embedded_cades_with_time_fail_qualification_requirements[cert_label{i}-tsa_label{i}-requirements{i}-{ts_param}]"
        );
        let registry = registry(&rec, &id, true);
        let result = validate(
            &rec,
            &id,
            &registry,
            Some(QualificationRequirements::default()),
            (i != 2).then(QualificationRequirements::default),
        );
        assert_eq!(
            result.ades_subindic.standard_name(),
            "SIG_CONSTRAINTS_FAILURE"
        );
        if i == 0 {
            assert!(!result.api_status.as_ref().unwrap().signature.trusted());
        }
    }
}

#[test]
fn test_embedded_cades_with_time_non_qtst_tsa_fail() {
    let rec = recording();
    let id = "test_embedded_cades_with_time_non_qtst_tsa_fail";
    let registry = registry(&rec, id, false);
    let result = validate(
        &rec,
        id,
        &registry,
        Some(QualificationRequirements::default()),
        Some(QualificationRequirements {
            require_service_type: Some(RequiredServiceType::Uri(QTST_URI.into())),
            ..Default::default()
        }),
    );
    assert_eq!(
        result.ades_subindic.standard_name(),
        "SIG_CONSTRAINTS_FAILURE"
    );
}

#[test]
fn test_embedded_cades_with_time_non_qtst_tsa_pass() {
    let rec = recording();
    let id = "test_embedded_cades_with_time_non_qtst_tsa_pass";
    let registry = registry(&rec, id, false);
    let result = validate(
        &rec,
        id,
        &registry,
        Some(QualificationRequirements::default()),
        Some(QualificationRequirements::default()),
    );
    assert_eq!(result.ades_subindic.standard_name(), "OK");
}

#[test]
fn mandatory_qualification_without_registry_rejects() {
    let rec = Recording::load(MODULE);
    let call = &rec.calls(MODULE, "test_embedded_cades_with_time_happy_path")[0];
    let ctx = default_context(&rec, call);
    for (requirements, ts_requirements) in [
        (Some(QualificationRequirements::default()), None),
        (None, Some(QualificationRequirements::default())),
    ] {
        let signer_qualification_required = requirements.is_some();
        let result = with_time_validation(
            &call.content_info(),
            None,
            &ctx,
            &QualificationSpec {
                registry: None,
                requirements,
                ts_requirements,
            },
            None,
        )
        .unwrap();
        assert_eq!(
            result.ades_subindic.standard_name(),
            "SIG_CONSTRAINTS_FAILURE"
        );
        if signer_qualification_required {
            assert!(!result.api_status.as_ref().unwrap().signature.trusted());
        }
    }
}

#[test]
fn pre_revocation_poe_restores_api_trust() {
    let rec = Recording::load(MODULE);
    let call = &rec.calls(MODULE, "test_embedded_cades_pre_revoke_with_poe")[0];
    let result = with_time_validation(
        &call.content_info(),
        None,
        &default_context(&rec, call),
        &QualificationSpec::default(),
        None,
    )
    .unwrap();
    assert_eq!(result.ades_subindic.standard_name(), "OK");
    let status = result.api_status.unwrap();
    assert!(status.signature.revoked());
    assert!(status.signature.trusted());
    assert!(status.bottom_line());
}

#[test]
fn basic_mandatory_qualification_without_registry_rejects_trust() {
    let rec = Recording::load(MODULE);
    let call = &rec.calls(MODULE, "test_embedded_cades_happy_path")[0];
    let result = sigis_pades::ades::basic::basic_validation(
        &call.content_info(),
        None,
        &default_context(&rec, call),
        &QualificationSpec {
            registry: None,
            requirements: Some(QualificationRequirements::default()),
            ts_requirements: None,
        },
    )
    .unwrap();
    assert_eq!(
        result.ades_subindic.standard_name(),
        "SIG_CONSTRAINTS_FAILURE"
    );
    let status = result.api_status.unwrap();
    assert!(!status.signature.trusted());
    assert!(!status.bottom_line());
}

#[test]
fn tampered_content_cannot_acquire_qualified_status() {
    let rec = recording();
    let id = "test_embedded_cades_with_time_happy_path_with_tl[True]";
    let registry = registry(&rec, id, true);
    let call = &rec.calls(MODULE, id)[0];
    let mut content_info = call.content_info();
    let offset = content_info
        .windows(b"Hello world!".len())
        .position(|window| window == b"Hello world!")
        .expect("encapsulated original content");
    content_info[offset] ^= 1;
    let result = with_time_validation(
        &content_info,
        None,
        &context(&registry, call),
        &QualificationSpec {
            registry: Some(&registry),
            requirements: Some(QualificationRequirements::default()),
            ts_requirements: None,
        },
        None,
    )
    .unwrap();
    assert_eq!(result.ades_subindic.standard_name(), "HASH_FAILURE");
    assert!(result.qualification.is_none());
    assert!(result.timestamp_qualification.is_none());
}

#[test]
fn timestamp_qualification_does_not_use_its_own_unproven_generation_time() {
    let rec = recording();
    let id = "test_embedded_cades_with_time_happy_path_with_tl[True]";
    let original = registry(&rec, id, true);
    let call = &rec.calls(MODULE, id)[0];
    let mut historical = TspRegistry::new();
    for authority in original.known_certificate_authorities() {
        for service in original.applicable_service_definitions(authority, None) {
            if service.is_ca() {
                historical.register_ca(service.clone());
            }
        }
    }
    for authority in original.known_timestamp_authorities() {
        for service in original.applicable_service_definitions(authority, None) {
            if !service.is_ca() {
                let mut expired = service.clone();
                expired.base_info.valid_until =
                    sigis_eutl::util::parse_xsd_datetime("2020-11-02T00:00:00Z");
                historical.register_tst(expired);
            }
        }
    }
    // Keep cryptographic validation identical. Only the qualification service
    // window changes: it contains genTime, but not the token's known POE.
    let result = with_time_validation(
        &call.content_info(),
        None,
        &context(&original, call),
        &QualificationSpec {
            registry: Some(&historical),
            requirements: None,
            ts_requirements: Some(QualificationRequirements {
                require_service_type: Some(RequiredServiceType::Uri(QTST_URI.into())),
                ..Default::default()
            }),
        },
        None,
    )
    .unwrap();
    assert_eq!(
        result.ades_subindic.standard_name(),
        "SIG_CONSTRAINTS_FAILURE"
    );
    assert_eq!(result.best_signature_time, Some(call.time()));
}
