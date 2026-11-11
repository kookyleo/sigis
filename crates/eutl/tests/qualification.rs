// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_trusted_list.py`, the tests
// that need the Certomancer test PKIs (MIT, see LICENSE-pyHanko).

#![allow(non_snake_case)]

mod common;

use std::collections::BTreeSet;

use common::*;
use sigis_eutl::assess::{QualificationAssessor, UNQUALIFIED};
use sigis_eutl::q_status::{QcPrivateKeyManagementType as K, QualifiedStatus};
use sigis_eutl::tsp::{
    Authority, BaseServiceInformation, CriteriaCombination as CC, CriteriaList, Criterion,
    QcCertType, Qualification, QualifiedServiceInformation, Qualifier, TspRegistry, CA_QC_URI,
};
use sigis_pki_certvalidator::{
    CertRevTrustPolicy, CertificateValidator, ValidationContext, ValidationPath, NO_REVOCATION,
};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::key_usage::KeyUsageConstraints;
use sigis_pki_core::time::Moment;

fn ku(names: &[&str]) -> Criterion {
    Criterion::KeyUsage(KeyUsageConstraints {
        key_usage: Some(set(names)),
        ..KeyUsageConstraints::new()
    })
}

fn from_ca_signing_cert() -> Cert {
    pki_cert("testing-ca", "signer1")
}

#[test]
fn test_criteria_accept() {
    let cases = [
        CriteriaList::new(CC::All, []),
        CriteriaList::new(CC::None, []),
        CriteriaList::new(
            CC::All,
            [
                Criterion::CertSubjectDn(set(&["2.5.4.3"])),
                Criterion::CertSubjectDn(set(&["2.5.4.10"])),
                ku(&["non_repudiation"]),
            ],
        ),
        CriteriaList::new(
            CC::AtLeastOne,
            [
                Criterion::CertSubjectDn(set(&["2.5.4.3"])),
                Criterion::PolicySet(set(&["2.999"])),
            ],
        ),
        CriteriaList::new(CC::None, [ku(&["key_encipherment"])]),
    ];
    let cert = from_ca_signing_cert();
    for (i, c) in cases.iter().enumerate() {
        assert!(c.matches(&cert), "case {i}");
    }
}

#[test]
fn test_criteria_reject() {
    let cases = [
        CriteriaList::new(
            CC::All,
            [
                Criterion::CertSubjectDn(set(&["2.5.4.3"])),
                Criterion::PolicySet(set(&["2.999"])),
            ],
        ),
        CriteriaList::new(
            CC::None,
            [
                Criterion::CertSubjectDn(set(&["2.5.4.3"])),
                Criterion::PolicySet(set(&["2.999"])),
            ],
        ),
    ];
    let cert = from_ca_signing_cert();
    for (i, c) in cases.iter().enumerate() {
        assert!(!c.matches(&cert), "case {i}");
    }
}

fn interm_cert() -> Cert {
    pki_cert("testing-ca", "interm")
}

fn ecc_interm_cert() -> Cert {
    pki_cert("testing-ca-ecdsa", "interm")
}

fn base(name: &str, certs: Vec<Cert>) -> BaseServiceInformation {
    BaseServiceInformation {
        service_type: String::new(),
        service_name: name.to_owned(),
        valid_from: moment("2020-11-01T00:00:00Z"),
        valid_until: None,
        provider_certs: certs,
        additional_info_certificate_type: BTreeSet::new(),
        other_additional_info: BTreeSet::new(),
    }
}

fn dummy_service_definition(extra: &[Cert]) -> QualifiedServiceInformation {
    let mut certs = vec![interm_cert()];
    certs.extend(extra.iter().cloned());
    QualifiedServiceInformation::ca(base("test1", certs), [], None)
}

#[test]
fn test_tsp_registry() {
    let mut r = TspRegistry::new();
    r.register_ca(dummy_service_definition(&[]));
    let res = r.applicable_service_definitions(&Authority::of_cert(&interm_cert()), None);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].base_info.service_name, "test1");
}

#[test]
fn test_tsp_registry_by_name() {
    let mut r = TspRegistry::new();
    r.register_ca(dummy_service_definition(&[]));
    let c = interm_cert();
    let res =
        r.applicable_service_definitions(&Authority::named_key(c.subject(), &c.public_key()), None);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].base_info.service_name, "test1");
}

#[test]
fn test_tsp_registry_alternative_cert() {
    let mut r = TspRegistry::new();
    r.register_ca(dummy_service_definition(&[ecc_interm_cert()]));
    let res = r.applicable_service_definitions(&Authority::of_cert(&interm_cert()), None);
    let res2 = r.applicable_service_definitions(&Authority::of_cert(&ecc_interm_cert()), None);
    assert_eq!(res, res2);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].base_info.service_name, "test1");
}

#[test]
fn test_tsp_registry_multiple_sds() {
    let mut r = TspRegistry::new();
    r.register_ca(QualifiedServiceInformation::ca(
        base("test1", vec![interm_cert()]),
        [],
        None,
    ));
    r.register_ca(QualifiedServiceInformation::ca(
        base("test2", vec![interm_cert()]),
        [],
        None,
    ));
    let res = r.applicable_service_definitions(&Authority::of_cert(&interm_cert()), None);
    assert_eq!(res.len(), 2);
    let names: BTreeSet<&str> = res
        .iter()
        .map(|r| r.base_info.service_name.as_str())
        .collect();
    assert_eq!(names, ["test1", "test2"].into_iter().collect());
}

fn q(label: &str) -> Cert {
    pki_cert("testing-ca-qualified", label)
}

#[test]
fn test_qcstatements_processing() {
    let st = |qualified, qc_type, qc_key_security| QualifiedStatus {
        qualified,
        qc_type,
        qc_key_security,
    };
    let cases = [
        ("esig-qualified", st(true, QcCertType::QcEsign, K::Qscd)),
        ("eseal-qualified", st(true, QcCertType::QcEseal, K::Qscd)),
        (
            "esig-qualified-no-qscd",
            st(true, QcCertType::QcEsign, K::Unknown),
        ),
        ("not-qualified", UNQUALIFIED),
        ("not-qualified-nonsense-qcsd", UNQUALIFIED),
    ];
    for (label, expected) in cases {
        assert_eq!(
            QualificationAssessor::process_qc_statements(&q(label)).unwrap(),
            expected,
            "{label}"
        );
    }
}

fn dummy_base_info() -> BaseServiceInformation {
    BaseServiceInformation {
        service_type: CA_QC_URI.to_owned(),
        service_name: "Dummy".to_owned(),
        valid_from: moment("2015-11-01T00:00:00Z"),
        valid_until: None,
        provider_certs: vec![q("root")],
        additional_info_certificate_type: [QcCertType::QcEsign].into_iter().collect(),
        other_additional_info: BTreeSet::new(),
    }
}

fn policy(oid: &str) -> CriteriaList {
    CriteriaList::new(CC::All, [Criterion::PolicySet(set(&[oid]))])
}

fn must_have_policy0() -> CriteriaList {
    policy("2.999.31337.0")
}

fn must_have_policy1() -> CriteriaList {
    policy("2.999.31337.1")
}

fn must_have_nonrepud() -> CriteriaList {
    CriteriaList::new(CC::All, [ku(&["non_repudiation"])])
}

fn qual(quals: &[Qualifier], criteria: CriteriaList) -> Qualification {
    Qualification {
        qualifiers: quals.iter().copied().collect(),
        criteria_list: criteria,
    }
}

fn sd(quals: Vec<Qualification>) -> QualifiedServiceInformation {
    QualifiedServiceInformation::ca(dummy_base_info(), quals, None)
}

/// Upstream builds the path with `CertificateValidator` (no revocation
/// checks). `sigis-pki-certvalidator` cannot validate this PKI yet: `const-oid`
/// rejects the `2.999.31337.*` policy OIDs (request R-E5). Until then the
/// path root -> interm-qualified -> leaf is assembled directly;
/// `path_validation_of_qualified_pki` tracks the blocked part.
/// The paths contain the same certificates (validation also records the
/// qualified policies, which the expected path does not carry).
fn assert_same_certs(actual: &ValidationPath, expected: &ValidationPath) {
    assert_eq!(actual.trust_anchor(), expected.trust_anchor());
    assert_eq!(actual.intermediates(), expected.intermediates());
    assert_eq!(actual.leaf(), expected.leaf());
}

fn validated_path(label: &str, _at: Moment) -> ValidationPath {
    ValidationPath::new(
        sigis_pki_certvalidator::TrustAnchor::new(q("root")),
        vec![q("interm-qualified")],
        Some(q(label)),
    )
}

#[test]
fn path_validation_of_qualified_pki() {
    let at = t2020();
    let ctx = ValidationContext::builder()
        .trust_root(q("root"))
        .other_cert(q("interm-qualified"))
        .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
        .moment(at)
        .build()
        .unwrap();
    for label in [
        "esig-qualified",
        "eseal-qualified",
        "not-qualified",
        "esig-qualified-no-qscd",
    ] {
        let path = CertificateValidator::new(&ctx, q(label))
            .validate()
            .unwrap();
        assert_same_certs(&path, &validated_path(label, at));
    }
    let ctx15 = ValidationContext::builder()
        .trust_root(q("root"))
        .other_cert(q("interm-qualified"))
        .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
        .moment(t2015())
        .build()
        .unwrap();
    for label in [
        "esig-qualified-legacy-policy",
        "esig-qualified-legacy-policy-qscd",
        "not-qualified-legacy",
    ] {
        CertificateValidator::new(&ctx15, q(label))
            .validate()
            .unwrap();
    }
}

fn assess(label: &str, sds: Vec<QualifiedServiceInformation>, at: Moment) -> QualifiedStatus {
    let path = validated_path(label, at);
    let mut registry = TspRegistry::new();
    for s in sds {
        registry.register_ca(s);
    }
    QualificationAssessor::new(&registry)
        .check_entity_cert_qualified(&path, Some(at))
        .unwrap()
        .status
}

fn t2020() -> Moment {
    moment("2020-11-01T00:00:00Z")
}

fn t2015() -> Moment {
    moment("2015-11-01T00:00:00Z")
}

#[test]
fn test_conclude_qualified_qcsd() {
    let cases: Vec<(&str, QualifiedServiceInformation)> = vec![
        ("esig-qualified", sd(vec![])),
        (
            "esig-qualified-no-qscd",
            sd(vec![qual(&[Qualifier::WithQscd], must_have_policy0())]),
        ),
        (
            "not-qualified",
            sd(vec![qual(
                &[Qualifier::QcStatement, Qualifier::WithQscd],
                must_have_policy0(),
            )]),
        ),
        (
            "not-qualified",
            sd(vec![
                qual(&[Qualifier::QcStatement], must_have_policy0()),
                qual(&[Qualifier::WithQscd], must_have_nonrepud()),
            ]),
        ),
        (
            "esig-qualified",
            sd(vec![qual(&[Qualifier::NoQscd], must_have_policy1())]),
        ),
        (
            "esig-qualified",
            sd(vec![qual(&[Qualifier::NotQualified], must_have_policy1())]),
        ),
    ];
    assert_eq!(cases.len(), 6);
    for (i, (label, s)) in cases.into_iter().enumerate() {
        let status = assess(label, vec![s], t2020());
        assert!(status.qualified, "case {i}");
        assert_eq!(status.qc_key_security, K::Qscd, "case {i}");
    }
}

#[test]
fn test_conclude_qualified_pre_eidas() {
    for (label, expect_qscd) in [
        ("esig-qualified-legacy-policy", false),
        ("esig-qualified-legacy-policy-qscd", true),
    ] {
        let status = assess(label, vec![sd(vec![])], t2015());
        assert!(status.qualified, "{label}");
        let want = if expect_qscd {
            K::QscdByPolicy
        } else {
            K::Unknown
        };
        assert_eq!(status.qc_key_security, want, "{label}");
    }
}

#[test]
fn test_conclude_not_qualified_pre_eidas() {
    let status = assess("not-qualified-legacy", vec![sd(vec![])], t2015());
    assert!(!status.qualified);
}

#[test]
fn test_conclude_not_qualified() {
    let cases: Vec<(&str, QualifiedServiceInformation)> = vec![
        ("not-qualified", sd(vec![])),
        (
            "esig-qualified",
            sd(vec![qual(&[Qualifier::NotQualified], must_have_policy0())]),
        ),
        // out of scope of this service definition
        ("eseal-qualified", sd(vec![])),
        ("esig-qualified-legacy-policy", sd(vec![])),
    ];
    for (i, (label, s)) in cases.into_iter().enumerate() {
        let status = assess(label, vec![s], t2020());
        assert!(!status.qualified, "case {i}");
    }
}

#[test]
fn test_conclude_not_qualified_contradictory() {
    let sd1 = sd(vec![]);
    let mut b2 = dummy_base_info();
    b2.service_name = "Dummy2".into();
    let sd2 = QualifiedServiceInformation::ca(
        b2,
        [qual(&[Qualifier::NoQscd], must_have_policy0())],
        None,
    );
    let status = assess("esig-qualified", vec![sd1, sd2], t2020());
    assert!(!status.qualified);
}

#[test]
fn test_conclude_qualified_convergence() {
    let sd1 = sd(vec![]);
    let mut b2 = dummy_base_info();
    b2.service_name = "Dummy2".into();
    let sd2 = QualifiedServiceInformation::ca(b2, [], None);
    let status = assess("esig-qualified", vec![sd1, sd2], t2020());
    assert!(status.qualified);
}

#[test]
fn test_parse_generated_lotl() {
    // Generated by oracle/gen_lists.py with pyHanko's `certomancer_lotl`.
    let xml = std::fs::read_to_string(common::data(&["lanes", "e", "tl", "certomancer-lotl.xml"]))
        .unwrap();
    let result =
        sigis_eutl::parse::validate_and_parse_lotl(&xml, Some(&[q("root")]), None).unwrap();
    assert!(result.errors.is_empty());
    let urls: Vec<&str> = result
        .references
        .iter()
        .map(|r| r.location_uri.as_str())
        .collect();
    assert_eq!(urls, vec!["https://example.com/"]);
}

#[test]
fn generated_qualified_tl_validates() {
    // The trusted list `_testing_ca_registry` builds in test_ades_validation.py.
    let xml = std::fs::read_to_string(common::data(&[
        "lanes",
        "e",
        "tl",
        "certomancer-qualified-tl.xml",
    ]))
    .unwrap();
    let (registry, errors) =
        sigis_eutl::parse::trust_list_to_registry(&xml, &[q("root")], None, None).unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    assert!(!registry.known_certificate_authorities().is_empty());
    assert!(!registry.known_timestamp_authorities().is_empty());
}
