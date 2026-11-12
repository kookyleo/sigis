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

// Supplemental trust-constraint regressions: an empty intersection must not
// become the public empty-Vec wildcard convention during anchor combination.
fn policy_input(name: &str) -> sigis_pki_certvalidator::Cert {
    use std::fmt::Write;
    let path = common::fixture(&["nist_pkits", "certs", name]);
    let cert = sigis_pki_certvalidator::Cert::from_pem_or_der(
        &std::fs::read(&path).expect("opened policy fixture"),
    )
    .expect("policy fixture certificate");
    let mut hash = String::new();
    for byte in cert.sha256() {
        write!(&mut hash, "{byte:02x}").unwrap();
    }
    eprintln!("POLICY_INPUT path={} sha256={hash}", path.display());
    cert
}

fn policy_verdict(
    result: &Result<ValidationPath, Box<sigis_pki_certvalidator::PathFailure>>,
) -> serde_json::Value {
    match result {
        Ok(path) => serde_json::json!({
            "outcome": "accept",
            "qualified_policies": path.qualified_policies().unwrap().iter().map(|p| {
                assert!(p.qualifiers.is_empty());
                serde_json::json!({
                    "user_policy": p.user_domain_policy_id.to_string(),
                    "issuer_policy": p.issuer_domain_policy_id.to_string(),
                    "qualifiers_der_hex": []
                })
            }).collect::<Vec<_>>()
        }),
        Err(failure) => serde_json::json!({
            "outcome": "reject",
            "error_class": failure.error.class_name(),
            "message": failure.error.to_string(),
            "is_ee_cert": failure.is_ee_cert
        }),
    }
}

fn anchor_policy_case(
    anchor_policies: &[const_oid::ObjectIdentifier],
    caller_policies: &[const_oid::ObjectIdentifier],
    anchor_explicit: bool,
    caller_explicit: bool,
) -> Result<ValidationPath, Box<sigis_pki_certvalidator::PathFailure>> {
    let anchor = TrustAnchor::with_qualifiers(
        policy_input("TrustAnchorRootCertificate.crt"),
        TrustQualifiers {
            standard_parameters: Some(PkixValidationParams {
                user_initial_policy_set: anchor_policies.to_vec(),
                initial_explicit_policy: anchor_explicit,
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let ctx = ValidationContext::builder()
        .trust_anchor(anchor)
        .other_cert(policy_input("GoodCACert.crt"))
        .moment(moment("2022-05-01T00:00:00Z"))
        .revocation_mode("soft-fail")
        .build()
        .expect("policy context");
    let mut paths =
        build_paths(&ctx, &policy_input("ValidCertificatePathTest1EE.crt")).expect("policy paths");
    assert_eq!(paths.len(), 1);
    let path = paths.remove(0);
    let result = sigis_pki_certvalidator::validate_path_qualified(
        &ctx,
        &path,
        Some(&PkixValidationParams {
            user_initial_policy_set: caller_policies.to_vec(),
            initial_explicit_policy: caller_explicit,
            ..Default::default()
        }),
    );
    eprintln!(
        "POLICY_INTERSECTION {}",
        serde_json::json!({
            "anchor_policies": anchor_policies.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "caller_policies": caller_policies.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "anchor_explicit": anchor_explicit,
            "caller_explicit": caller_explicit,
            "verdict": policy_verdict(&result)
        })
    );
    result
}

const NIST_POLICY_ONE: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.1");
const NIST_POLICY_TWO: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.2");

#[test]
fn disjoint_anchor_policy_intersection_retains_explicit_requirement() {
    for (anchor, caller) in [
        (NIST_POLICY_ONE, NIST_POLICY_TWO),
        (NIST_POLICY_TWO, NIST_POLICY_ONE),
    ] {
        for (anchor_explicit, caller_explicit) in [(true, false), (false, true), (true, true)] {
            let failure =
                anchor_policy_case(&[anchor], &[caller], anchor_explicit, caller_explicit)
                    .expect_err("disjoint mandatory policy sets must reject");
            assert!(failure.error.is_path_validation_error(), "{failure:?}");
            assert!(
                failure
                    .error
                    .to_string()
                    .contains("no valid set of policies"),
                "{failure:?}"
            );
            assert!(failure.is_ee_cert);
            let original = failure.path.expect("original failed path");
            assert_eq!(original.pkix_len(), 2);
            assert_eq!(
                original.leaf().unwrap(),
                &load_nist_cert("ValidCertificatePathTest1EE.crt")
            );
        }
    }
}

#[test]
fn disjoint_anchor_policy_intersection_without_explicit_requirement_is_empty() {
    for (anchor, caller) in [
        (NIST_POLICY_ONE, NIST_POLICY_TWO),
        (NIST_POLICY_TWO, NIST_POLICY_ONE),
    ] {
        let path = anchor_policy_case(&[anchor], &[caller], false, false)
            .expect("explicit policy is optional");
        assert_eq!(path.qualified_policies(), Some([].as_slice()));
    }
}

#[test]
fn anchor_policy_intersection_preserves_wildcards_and_nonempty_overlap() {
    let any = const_oid::db::rfc5280::ANY_POLICY;
    for (anchor, caller) in [
        (vec![NIST_POLICY_ONE], vec![NIST_POLICY_ONE]),
        (vec![], vec![NIST_POLICY_ONE]),
        (vec![NIST_POLICY_ONE], vec![]),
        (vec![any], vec![NIST_POLICY_ONE]),
        (vec![NIST_POLICY_ONE], vec![any]),
        (
            vec![NIST_POLICY_ONE, NIST_POLICY_TWO],
            vec![NIST_POLICY_ONE],
        ),
        (
            vec![NIST_POLICY_ONE],
            vec![NIST_POLICY_ONE, NIST_POLICY_TWO],
        ),
    ] {
        let path = anchor_policy_case(&anchor, &caller, true, true)
            .expect("wildcard or overlapping mandatory policy");
        let policies = path.qualified_policies().expect("qualified policy output");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].user_domain_policy_id, NIST_POLICY_ONE);
        assert_eq!(policies[0].issuer_domain_policy_id, NIST_POLICY_ONE);
    }
}

#[test]
fn policy_graph_limit_enforces_transient_nodes_before_pruning() {
    let ctx = ValidationContext::builder()
        .trust_root(policy_input("TrustAnchorRootCertificate.crt"))
        .other_cert(policy_input("PoliciesP123CACert.crt"))
        .moment(moment("2022-05-01T00:00:00Z"))
        .revocation_mode("soft-fail")
        .build()
        .expect("policy graph context");
    let target = policy_input("PoliciesP123subCAP12Cert.crt");
    let paths = build_paths(&ctx, &target).expect("policy graph path");
    assert_eq!(paths.len(), 1);
    let path = &paths[0];
    assert_eq!(path.pkix_len(), 2);
    for limit in [None, Some(6), Some(7), Some(8)] {
        let result = sigis_pki_certvalidator::validate_path_qualified(
            &ctx,
            path,
            Some(&PkixValidationParams {
                max_policy_graph_nodes: limit,
                ..Default::default()
            }),
        )
        .expect("limit covers the transient six-node graph");
        eprintln!(
            "POLICY_LIMIT {}",
            serde_json::json!({
                "limit": limit,
                "verdict": policy_verdict(&Ok(result.clone()))
            })
        );
        let policies = result.qualified_policies().expect("qualified policies");
        assert_eq!(policies.len(), 2);
        assert!(policies
            .iter()
            .all(|p| p.user_domain_policy_id == p.issuer_domain_policy_id));
        assert_eq!(
            policies
                .iter()
                .map(|p| p.user_domain_policy_id)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([NIST_POLICY_ONE, NIST_POLICY_TWO])
        );
    }
    for limit in (0..=5).rev() {
        let failure = sigis_pki_certvalidator::validate_path_qualified(
            &ctx,
            path,
            Some(&PkixValidationParams {
                max_policy_graph_nodes: Some(limit),
                ..Default::default()
            }),
        )
        .expect_err("transient allocation must obey the node limit");
        eprintln!(
            "POLICY_LIMIT {}",
            serde_json::json!({
                "limit": limit,
                "verdict": {
                    "outcome": "reject",
                    "error_class": failure.error.class_name(),
                    "message": failure.error.to_string(),
                    "is_ee_cert": failure.is_ee_cert
                }
            })
        );
        let who = if limit < 4 {
            "intermediate certificate 1"
        } else {
            "the end-entity certificate"
        };
        assert_eq!(failure.error.to_string(), format!(
            "The path could not be validated because policy processing for {who} exceeds the size limit on the policy graph"
        ));
        assert_eq!(failure.is_ee_cert, limit >= 4);
        assert!(!failure.is_side_validation);
        assert_eq!(failure.time_horizon, None);
        assert_eq!(failure.path.as_ref(), Some(path));
    }
}
