// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_ades_validation.py`
// (MIT, see LICENSE-pyHanko), replaying the oracle recordings.
//
// The tests are ignored until `hanko_cms::validate_cms_signature` (lane A)
// is implemented; run them with `cargo test -- --ignored`.

#![allow(non_snake_case)]

mod common;

use common::*;
use hanko_ades::basic::{basic_validation, QualificationSpec};
use hanko_eutl::assess::{QualificationRequirements, RequiredServiceType};
use hanko_eutl::parse::trust_list_to_registry;
use hanko_eutl::q_status::QcPrivateKeyManagementType;
use hanko_eutl::tsp::{QcCertType, TrustedServiceType, TspTrustManager, QTST_URI};

const MODULE: &str = "test_ades_validation";

fn run_basic(test: &str, qual: &QualificationSpec<'_>, ctx_for: impl Fn(&Recording, &Call) -> hanko_certvalidator::ValidationContext) {
    let rec = Recording::load(MODULE);
    let calls = rec.calls(MODULE, test);
    assert!(!calls.is_empty());
    for call in calls {
        assert_eq!(call.function(), "ades_basic_validation");
        let ctx = ctx_for(&rec, &call);
        let ci = call.content_info();
        let result = basic_validation(&ci, call.raw_digest().as_deref(), &ctx, qual).unwrap();
        assert_eq!(result.ades_subindic.standard_name(), call.expected_subindic(), "{test}");
    }
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A)"]
fn test_pades_basic_happy_path() {
    run_basic("test_pades_basic_happy_path", &QualificationSpec::default(), default_context);
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A)"]
fn test_embedded_cades_happy_path() {
    run_basic("test_embedded_cades_happy_path", &QualificationSpec::default(), default_context);
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A)"]
fn test_embedded_cades_basic_tampered() {
    run_basic("test_embedded_cades_basic_tampered", &QualificationSpec::default(), default_context);
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A)"]
fn test_embedded_cades_sig_tampered() {
    run_basic("test_embedded_cades_sig_tampered", &QualificationSpec::default(), default_context);
}

/// The trusted list `_testing_ca_registry` generated in the recorded run.
fn testing_ca_registry(rec: &Recording, test_id: &str) -> hanko_eutl::tsp::TspRegistry {
    let tls = rec.0["generated_tls"].as_array().unwrap();
    let tl = tls
        .iter()
        .find(|t| t["nodeid"].as_str().unwrap().ends_with(test_id))
        .unwrap_or_else(|| panic!("no generated TL for {test_id}"));
    let root = rec.cert("testing-ca-qualified", "root");
    trust_list_to_registry(tl["xml"].as_str().unwrap(), &[root], None, None).unwrap().0
}

fn tl_context(registry: &hanko_eutl::tsp::TspRegistry) -> impl Fn(&Recording, &Call) -> hanko_certvalidator::ValidationContext + '_ {
    move |_rec, call| {
        let mut b = hanko_certvalidator::ValidationContext::builder()
            .revinfo_policy(default_revinfo_policy())
            .moment(call.time())
            .fetchers(call.fetchers());
        for a in TspTrustManager::new(registry).trust_anchors_at(call.time()) {
            b = b.trust_anchor(a);
        }
        b.build().unwrap()
    }
}

fn with_tl(case: &str, requirements: Option<QualificationRequirements>) {
    let rec = Recording::load(MODULE);
    let id = format!("test_pades_basic_happy_path_with_tl[{case}]");
    let registry = testing_ca_registry(&rec, &id);
    let qual = QualificationSpec {
        registry: Some(&registry),
        requirements,
        ts_requirements: None,
    };
    for call in rec.calls(MODULE, &id) {
        let ctx = tl_context(&registry)(&rec, &call);
        let result = basic_validation(&call.content_info(), call.raw_digest().as_deref(), &ctx, &qual).unwrap();
        assert_eq!(result.ades_subindic.standard_name(), call.expected_subindic());
        let q = result.qualification.expect("qualification result");
        assert!(q.status.qualified);
        assert!(q.service_definition.is_some());
        assert_eq!(q.status.qc_type, QcCertType::QcEseal);
    }
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A); const-oid (R-E5)"]
fn test_pades_basic_happy_path_with_tl__true() {
    with_tl("True", Some(QualificationRequirements::default()));
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A); const-oid (R-E5)"]
fn test_pades_basic_happy_path_with_tl__false() {
    with_tl("False", None);
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A); const-oid (R-E5)"]
fn test_pades_fail_qualification_requirements() {
    let reqs = [
        QualificationRequirements::default(),
        QualificationRequirements {
            permit_cert_types: Some([QcCertType::QcEseal].into_iter().collect()),
            ..Default::default()
        },
        QualificationRequirements {
            permit_key_mgmt_types: Some([QcPrivateKeyManagementType::Qscd].into_iter().collect()),
            ..Default::default()
        },
        QualificationRequirements {
            require_service_type: Some(RequiredServiceType::Uri(QTST_URI.into())),
            ..Default::default()
        },
        QualificationRequirements {
            require_service_type: Some(RequiredServiceType::Type(TrustedServiceType::TimeStampingAuthority)),
            ..Default::default()
        },
    ];
    let rec = Recording::load(MODULE);
    for (i, req) in reqs.into_iter().enumerate() {
        let id = format!("test_pades_fail_qualification_requirements[cert_label{i}-requirements{i}]");
        let registry = testing_ca_registry(&rec, &id);
        let qual = QualificationSpec {
            registry: Some(&registry),
            requirements: Some(req),
            ts_requirements: None,
        };
        for call in rec.calls(MODULE, &id) {
            let ctx = tl_context(&registry)(&rec, &call);
            let result = basic_validation(&call.content_info(), call.raw_digest().as_deref(), &ctx, &qual).unwrap();
            assert_eq!(result.ades_subindic.standard_name(), "SIG_CONSTRAINTS_FAILURE", "{id}");
            assert_eq!(call.expected_subindic(), "SIG_CONSTRAINTS_FAILURE");
        }
    }
}

/// The recordings are complete: every upstream case passed under pyHanko
/// and recorded at least one validation call (not blocked).
#[test]
fn recordings_are_complete() {
    let rec = Recording::load(MODULE);
    let tests = rec.0["tests"].as_object().unwrap();
    assert_eq!(tests.len(), 69);
    for (id, t) in tests {
        assert_eq!(t["outcome"], "passed", "{id}");
    }
}

fn run_with_time(test: &str, expect_best_time: Option<&str>) {
    let rec = Recording::load(MODULE);
    for call in rec.calls(MODULE, test) {
        let ctx = default_context(&rec, &call);
        let result = match call.function() {
            "ades_with_time_validation" => hanko_ades::with_time::with_time_validation(
                &call.content_info(),
                call.raw_digest().as_deref(),
                &ctx,
                &QualificationSpec::default(),
                None,
            )
            .unwrap(),
            other => panic!("unexpected call {other}"),
        };
        assert_eq!(result.ades_subindic.standard_name(), call.expected_subindic(), "{test}");
        if let Some(t) = expect_best_time {
            assert_eq!(result.best_signature_time, hanko_eutl::util::parse_xsd_datetime(t));
        }
    }
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A)"]
fn test_embedded_cades_with_time_happy_path() {
    run_with_time("test_embedded_cades_with_time_happy_path", Some("2020-11-01T00:00:00Z"));
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A)"]
fn test_embedded_cades_with_time_tampered_timestamp() {
    run_with_time("test_embedded_cades_with_time_tampered_timestamp", None);
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A)"]
fn test_embedded_cades_with_time_sig_tampered_timestamp() {
    run_with_time("test_embedded_cades_with_time_sig_tampered_timestamp", None);
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A)"]
fn test_embedded_cades_pre_revoke_with_poe() {
    run_with_time("test_embedded_cades_pre_revoke_with_poe", Some("2020-11-01T00:00:00Z"));
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A)"]
fn test_embedded_cades_provably_revoked() {
    run_basic("test_embedded_cades_provably_revoked", &QualificationSpec::default(), default_context);
}

#[test]
#[ignore = "blocked: hanko_cms::validate_cms_signature (lane A)"]
fn test_embedded_cades_revoked_no_poe() {
    run_basic("test_embedded_cades_revoked_no_poe", &QualificationSpec::default(), default_context);
}
