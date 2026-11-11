// Port of pyhanko-certvalidator `tests/test_policy_proc.py` (MIT, see
// LICENSE-pyHanko). Name subtrees are expressed with `x509-cert`'s
// `GeneralSubtree` instead of pyhanko-certvalidator's `name_trees` module.

mod common;

use std::str::FromStr;

use common::{load_nist_cert, moment};
use der::asn1::Ia5String;
use sigis_pki_certvalidator::authority::TrustQualifiers;
use sigis_pki_certvalidator::{
    build_paths, validate_path, PkixValidationParams, TrustAnchor, ValidationContext,
    ValidationPath,
};
use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;

fn ctx_with(anchor: TrustAnchor, others: &[&str]) -> ValidationContext {
    let mut b = ValidationContext::builder()
        .trust_anchor(anchor)
        .moment(moment("2022-05-01T00:00:00Z"))
        .revocation_mode("soft-fail");
    for o in others {
        b = b.other_cert(load_nist_cert(o));
    }
    b.build().expect("context")
}

fn only_path(ctx: &ValidationContext, ee: &str) -> ValidationPath {
    let mut paths = build_paths(ctx, &load_nist_cert(ee)).expect("paths");
    assert_eq!(paths.len(), 1);
    paths.remove(0)
}

fn dn_subtree(s: &str) -> GeneralSubtree {
    GeneralSubtree {
        base: GeneralName::DirectoryName(Name::from_str(s).expect("name")),
        minimum: 0,
        maximum: None,
    }
}

fn assert_err(r: Result<(), sigis_pki_core::errors::ValidationError>, a: &str, b: &str) {
    let e = r.expect_err("error");
    assert!(e.is_path_validation_error(), "{e:?}");
    let m = e.to_string();
    assert!(m.find(a).is_some_and(|i| m[i..].contains(b)), "{m}");
}

#[test]
fn test_extract_policy() {
    let anchor =
        TrustAnchor::with_enforced_validity(load_nist_cert("ValidCertificatePathTest1EE.crt"));
    let params = anchor
        .qualifiers()
        .standard_parameters
        .as_ref()
        .expect("params");
    assert_eq!(
        params.user_initial_policy_set,
        vec![const_oid::ObjectIdentifier::new_unwrap(
            "2.16.840.1.101.3.2.1.48.1"
        )]
    );
}

#[test]
fn test_extract_permitted_subtrees() {
    let anchor =
        TrustAnchor::with_enforced_validity(load_nist_cert("nameConstraintsDN1CACert.crt"));
    let params = anchor
        .qualifiers()
        .standard_parameters
        .as_ref()
        .expect("params");
    let permitted = params
        .initial_permitted_subtrees
        .as_ref()
        .expect("permitted");
    let dirnames: Vec<_> = permitted
        .iter()
        .filter(|s| matches!(s.base, GeneralName::DirectoryName(_)))
        .collect();
    assert_eq!(dirnames.len(), 1);
    let expected =
        Name::from_str("OU=permittedSubtree1,O=Test Certificates 2011,C=US").expect("name");
    match &dirnames[0].base {
        GeneralName::DirectoryName(n) => assert!(certval::compare_names(n, &expected)),
        _ => unreachable!(),
    }
}

#[test]
fn test_validate_with_derived() {
    let anchor =
        TrustAnchor::with_enforced_validity(load_nist_cert("nameConstraintsDN1CACert.crt"));
    let ctx = ctx_with(anchor, &[]);
    let path = only_path(&ctx, "InvalidDNnameConstraintsTest2EE.crt");
    assert_eq!(path.pkix_len(), 1);
    assert_err(
        validate_path(&ctx, &path, None),
        "not all names",
        "permitted",
    );
}

#[test]
fn test_validate_with_merged_permitted_subtrees() {
    let anchor =
        TrustAnchor::with_enforced_validity(load_nist_cert("nameConstraintsDN1CACert.crt"));
    let ctx = ctx_with(anchor, &[]);
    let path = only_path(&ctx, "ValidDNnameConstraintsTest1EE.crt");
    assert_eq!(path.pkix_len(), 1);
    validate_path(&ctx, &path, None).expect("valid");
    let extra = PkixValidationParams {
        initial_permitted_subtrees: Some(vec![dn_subtree(
            "OU=someNameYouDontHave,O=Test Certificates 2011,C=US",
        )]),
        ..PkixValidationParams::default()
    };
    assert_err(
        validate_path(&ctx, &path, Some(&extra)),
        "not all names",
        "permitted",
    );
}

#[test]
fn test_validate_with_merged_excluded_subtrees() {
    let anchor =
        TrustAnchor::with_enforced_validity(load_nist_cert("nameConstraintsDN3CACert.crt"));
    let ctx = ctx_with(anchor, &[]);
    let path = only_path(&ctx, "ValidDNnameConstraintsTest6EE.crt");
    assert_eq!(path.pkix_len(), 1);
    validate_path(&ctx, &path, None).expect("valid");
    let extra = PkixValidationParams {
        initial_excluded_subtrees: Some(vec![dn_subtree(
            "OU=permittedSubtree1,O=Test Certificates 2011,C=US",
        )]),
        ..PkixValidationParams::default()
    };
    assert_err(
        validate_path(&ctx, &path, Some(&extra)),
        "some names",
        "excluded",
    );
}

fn certless(permitted: &str) -> (TrustAnchor, PkixValidationParams) {
    let crt = load_nist_cert("nameConstraintsDN1CACert.crt");
    let params = PkixValidationParams {
        initial_permitted_subtrees: Some(vec![dn_subtree(permitted)]),
        ..PkixValidationParams::default()
    };
    let anchor = TrustAnchor::from_name_and_key(
        crt.subject().clone(),
        crt.public_key(),
        TrustQualifiers {
            standard_parameters: Some(params.clone()),
            ..TrustQualifiers::default()
        },
    )
    .expect("anchor");
    (anchor, params)
}

#[test]
fn test_validate_with_certless_root() {
    let (anchor, params) = certless("OU=permittedSubtree1,O=Test Certificates 2011,C=US");
    let ctx = ctx_with(anchor.clone(), &[]);
    let path = only_path(&ctx, "ValidDNnameConstraintsTest1EE.crt");
    assert_eq!(path.pkix_len(), 1);
    assert_eq!(path.trust_anchor(), &anchor);
    validate_path(&ctx, &path, Some(&params)).expect("valid");
}

#[test]
fn test_validate_with_certless_root_failure() {
    let (anchor, params) = certless("OU=someNameYouDontHave,O=Test Certificates 2011,C=US");
    let ctx = ctx_with(anchor.clone(), &[]);
    let path = only_path(&ctx, "ValidDNnameConstraintsTest1EE.crt");
    assert_eq!(path.pkix_len(), 1);
    assert_eq!(path.trust_anchor(), &anchor);
    assert_err(
        validate_path(&ctx, &path, Some(&params)),
        "not all names",
        "permitted",
    );
}

#[test]
fn test_validate_empty_path_certless_root() {
    let crt = load_nist_cert("nameConstraintsDN1CACert.crt");
    let anchor = TrustAnchor::from_name_and_key(
        crt.subject().clone(),
        crt.public_key(),
        TrustQualifiers::default(),
    )
    .expect("anchor");
    let ctx = ctx_with(anchor.clone(), &[]);
    validate_path(&ctx, &ValidationPath::new(anchor, Vec::new(), None), None).expect("valid");
}

#[test]
fn test_trust_anchor_authority_consistency() {
    let crt = load_nist_cert("nameConstraintsDN1CACert.crt");
    let anchor = TrustAnchor::new(crt.clone());
    let without_cert = TrustAnchor::from_name_and_key(
        crt.subject().clone(),
        crt.public_key(),
        TrustQualifiers::default(),
    )
    .expect("anchor");
    assert_eq!(anchor.authority(), without_cert.authority());
}

fn nist_ee_path(ca: &str, ee: &str) -> (ValidationContext, ValidationPath) {
    let ctx = ctx_with(
        TrustAnchor::new(load_nist_cert("TrustAnchorRootCertificate.crt")),
        &[ca],
    );
    let path = only_path(&ctx, ee);
    assert_eq!(path.pkix_len(), 2);
    (ctx, path)
}

const NC_DNS: (&str, &str) = (
    "nameConstraintsDNS1CACert.crt",
    "ValidDNSnameConstraintsTest30EE.crt",
);
const NC_EMAIL: (&str, &str) = (
    "nameConstraintsRFC822CA1Cert.crt",
    "ValidRFC822nameConstraintsTest21EE.crt",
);
const NC_URI: (&str, &str) = (
    "nameConstraintsURI1CACert.crt",
    "ValidURInameConstraintsTest34EE.crt",
);

#[derive(Clone, Copy)]
enum Kind {
    Dns,
    Email,
    Uri,
}

fn excluded(kind: Kind, base: &str) -> PkixValidationParams {
    let ia5 = Ia5String::new(base).expect("ia5");
    let base = match kind {
        Kind::Dns => GeneralName::DnsName(ia5),
        Kind::Email => GeneralName::Rfc822Name(ia5),
        Kind::Uri => GeneralName::UniformResourceIdentifier(ia5),
    };
    PkixValidationParams {
        initial_excluded_subtrees: Some(vec![GeneralSubtree {
            base,
            minimum: 0,
            maximum: None,
        }]),
        ..PkixValidationParams::default()
    }
}

#[test]
fn test_excluded_subtree_catches_differently_cased_name() {
    for (certs, kind, base) in [
        (NC_DNS, Kind::Dns, "TESTSERVER.TESTCERTIFICATES.GOV"),
        (NC_DNS, Kind::Dns, "TestCertificates.GOV"),
        (NC_DNS, Kind::Dns, "testserver.testcertificates.gov."),
        (NC_DNS, Kind::Dns, "TESTCERTIFICATES.GOV."),
        (
            NC_EMAIL,
            Kind::Email,
            "Test21EE@MAILSERVER.TESTCERTIFICATES.GOV",
        ),
        (
            NC_EMAIL,
            Kind::Email,
            "Test21EE@mailserver.testcertificates.gov.",
        ),
        (NC_EMAIL, Kind::Email, ".TESTCERTIFICATES.GOV"),
        (NC_EMAIL, Kind::Email, "MAILSERVER.TESTCERTIFICATES.GOV"),
        (NC_URI, Kind::Uri, "TESTSERVER.TESTCERTIFICATES.GOV"),
        (NC_URI, Kind::Uri, ".TESTCERTIFICATES.GOV"),
        (NC_URI, Kind::Uri, "testserver.testcertificates.gov."),
    ] {
        let (ctx, path) = nist_ee_path(certs.0, certs.1);
        validate_path(&ctx, &path, None).expect("valid without the constraint");
        let r = validate_path(&ctx, &path, Some(&excluded(kind, base)));
        assert!(r.is_err(), "{base} should be excluded");
        assert_err(r, "some names", "excluded");
    }
}

#[test]
fn test_excluded_subtree_does_not_overmatch() {
    for (certs, kind, base) in [
        (NC_DNS, Kind::Dns, "OTHER.TESTCERTIFICATES.GOV"),
        (NC_DNS, Kind::Dns, "ESTCERTIFICATES.GOV"),
        (
            NC_EMAIL,
            Kind::Email,
            "test21ee@mailserver.testcertificates.gov",
        ),
        (NC_URI, Kind::Uri, "OTHER.TESTCERTIFICATES.GOV"),
    ] {
        let (ctx, path) = nist_ee_path(certs.0, certs.1);
        validate_path(&ctx, &path, Some(&excluded(kind, base)))
            .unwrap_or_else(|e| panic!("{base}: {e}"));
    }
}

#[test]
fn test_policy_graph_size_limit() {
    let p = |n: Option<usize>| PkixValidationParams {
        max_policy_graph_nodes: n,
        ..PkixValidationParams::default()
    };
    for (anchor_params, params, valid) in [
        (None, p(Some(3)), true),
        (None, p(Some(2)), false),
        (Some(p(Some(2))), p(None), false),
        (Some(p(None)), p(Some(2)), false),
        (Some(p(Some(3))), p(Some(4)), true),
    ] {
        let anchor = TrustAnchor::with_qualifiers(
            load_nist_cert("TrustAnchorRootCertificate.crt"),
            TrustQualifiers {
                standard_parameters: anchor_params,
                ..TrustQualifiers::default()
            },
        );
        let ctx = ctx_with(anchor, &["GoodCACert.crt"]);
        let path = only_path(&ctx, "ValidCertificatePathTest1EE.crt");
        let r = validate_path(&ctx, &path, Some(&params));
        if valid {
            r.expect("valid");
        } else {
            assert_err(r, "policy graph", "");
        }
    }
}

#[test]
fn test_merge_takes_the_stricter_policy_graph_limit() {
    for (a, b, expected) in [
        (None, None, None),
        (None, Some(5), Some(5)),
        (Some(5), None, Some(5)),
        (Some(5), Some(3), Some(3)),
        (Some(3), Some(5), Some(3)),
    ] {
        let pa = PkixValidationParams {
            max_policy_graph_nodes: a,
            ..PkixValidationParams::default()
        };
        let pb = PkixValidationParams {
            max_policy_graph_nodes: b,
            ..PkixValidationParams::default()
        };
        assert_eq!(pa.merge(&pb).max_policy_graph_nodes, expected);
    }
}
