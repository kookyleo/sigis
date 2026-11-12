//! Supplemental public policy-composition regressions; no new upstream IDs.

mod common;

use std::collections::BTreeSet;

use common::{load_nist_cert, moment};
use const_oid::ObjectIdentifier;
use sigis_pki_certvalidator::authority::TrustQualifiers;
use sigis_pki_certvalidator::validate::validate_path_qualified;
use sigis_pki_certvalidator::{
    CertificateValidator, PkixValidationParams, TrustAnchor, ValidationContext, ValidationPath,
};

const P: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.1");
const Q: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.2");
const ANY: ObjectIdentifier = const_oid::db::rfc5280::ANY_POLICY;

fn params(policies: &[ObjectIdentifier], explicit: bool) -> PkixValidationParams {
    PkixValidationParams {
        user_initial_policy_set: policies.to_vec(),
        initial_explicit_policy: explicit,
        ..Default::default()
    }
}

fn environment(
    anchor_params: Option<PkixValidationParams>,
    zero: bool,
) -> (ValidationContext, ValidationPath) {
    let anchor = TrustAnchor::with_qualifiers(
        load_nist_cert("TrustAnchorRootCertificate.crt"),
        TrustQualifiers {
            standard_parameters: anchor_params,
            ..Default::default()
        },
    );
    let ctx = ValidationContext::builder()
        .trust_anchor(anchor.clone())
        .other_cert(load_nist_cert("GoodCACert.crt"))
        .moment(moment("2022-05-01T00:00:00Z"))
        .revocation_mode("soft-fail")
        .build()
        .expect("context");
    let (intermediates, leaf) = if zero {
        (Vec::new(), None)
    } else {
        (
            vec![load_nist_cert("GoodCACert.crt")],
            Some(load_nist_cert("ValidCertificatePathTest1EE.crt")),
        )
    };
    (ctx, ValidationPath::new(anchor, intermediates, leaf))
}

fn policy_pairs(path: &ValidationPath) -> Vec<(ObjectIdentifier, ObjectIdentifier)> {
    path.qualified_policies()
        .expect("qualified output")
        .iter()
        .map(|p| (p.user_domain_policy_id, p.issuer_domain_policy_id))
        .collect()
}

#[test]
fn materialized_disjoint_merge_rejects_before_accepting_a_certificate() {
    let empty = params(&[P], true).merge(&params(&[Q], true));
    for anchor in [None, Some(params(&[], true)), Some(params(&[P], true))] {
        let (ctx, path) = environment(anchor, false);
        let error = validate_path_qualified(&ctx, &path, Some(&empty))
            .expect_err("a materialized empty intersection cannot become anyPolicy");
        assert!(error.error.is_path_validation_error(), "{error:?}");
        assert_eq!(error.path.as_ref(), Some(&path));
    }
}

#[test]
fn materialized_anchor_combination_retains_a_disjoint_restriction() {
    let empty = params(&[P], true).combine_with_anchor(&params(&[Q], true));
    let (ctx, path) = environment(None, false);
    assert!(validate_path_qualified(&ctx, &path, Some(&empty)).is_err());
}

#[test]
fn repeated_materialized_merge_cannot_resurrect_a_policy() {
    let a = params(&[P], true);
    let b = params(&[Q], true);
    let (ctx, path) = environment(None, false);
    for merged in [a.merge(&b).merge(&b), a.merge(&b.merge(&b))] {
        assert!(validate_path_qualified(&ctx, &path, Some(&merged)).is_err());
    }
}

#[test]
fn optional_empty_policy_set_does_not_report_a_matched_policy() {
    let empty = params(&[P], false).merge(&params(&[Q], false));
    for anchor in [None, Some(params(&[ANY], false)), Some(params(&[P], false))] {
        let (ctx, path) = environment(anchor, false);
        let validated =
            validate_path_qualified(&ctx, &path, Some(&empty)).expect("optional policy");
        assert!(policy_pairs(&validated).is_empty());
    }
}

#[test]
fn legacy_default_and_matching_finite_policies_still_validate() {
    let (ctx, path) = environment(None, false);
    for parameters in [params(&[], false), params(&[ANY], true), params(&[P], true)] {
        let validated = validate_path_qualified(&ctx, &path, Some(&parameters)).expect("control");
        assert_eq!(policy_pairs(&validated), vec![(P, P)]);
    }
}

#[test]
fn zero_issued_path_honors_finite_policy_projection() {
    let (ctx, path) = environment(None, true);
    for explicit in [false, true] {
        let validated = validate_path_qualified(&ctx, &path, Some(&params(&[P], explicit)))
            .expect("finite zero-length policy");
        assert_eq!(policy_pairs(&validated), vec![(P, P)]);
    }
}

#[test]
fn zero_issued_path_rejects_empty_policy_and_retains_anchor_context() {
    for explicit in [false, true] {
        let empty = params(&[P], explicit).merge(&params(&[Q], explicit));
        for (caller, anchor) in [
            (Some(empty.clone()), None),
            (None, Some(empty.clone())),
            (Some(params(&[ANY], explicit)), Some(empty.clone())),
        ] {
            let (ctx, path) = environment(anchor, true);
            let error = validate_path_qualified(&ctx, &path, caller.as_ref())
                .expect_err("zero-issued wrap-up must honor the empty set");
            assert_eq!(
                error.error.to_string(),
                "The path could not be validated because there is no valid set of policies for the trust anchor."
            );
            assert_eq!(error.path.as_ref(), Some(&path));
            assert!(!error.is_ee_cert);
            assert!(!error.is_side_validation);
            assert_eq!(error.time_horizon, None);
        }
    }
}

#[test]
fn zero_issued_default_wildcard_control_is_unchanged() {
    let (ctx, path) = environment(None, true);
    for parameters in [None, Some(params(&[], false)), Some(params(&[ANY], true))] {
        let validated =
            validate_path_qualified(&ctx, &path, parameters.as_ref()).expect("wildcard");
        assert_eq!(policy_pairs(&validated), vec![(ANY, ANY)]);
    }
}

#[test]
fn policy_constraint_composition_is_associative_and_empty_is_absorbing() {
    let mut empty = PkixValidationParams::default();
    empty.replace_user_initial_policy_set(Some(BTreeSet::new()));
    let cases = [
        params(&[], false),
        params(&[ANY], true),
        params(&[P], true),
        params(&[Q], false),
        params(&[Q, P, P], true),
        empty.clone(),
    ];
    for a in &cases {
        for b in &cases {
            assert_eq!(
                a.merge(b).effective_user_initial_policy_set(),
                b.merge(a).effective_user_initial_policy_set()
            );
            for c in &cases {
                assert_eq!(
                    a.merge(b).merge(c).effective_user_initial_policy_set(),
                    a.merge(&b.merge(c)).effective_user_initial_policy_set()
                );
                assert_eq!(
                    a.combine_with_anchor(b)
                        .combine_with_anchor(c)
                        .effective_user_initial_policy_set(),
                    a.combine_with_anchor(&b.combine_with_anchor(c))
                        .effective_user_initial_policy_set()
                );
            }
        }
        for merged in [
            empty.merge(a),
            a.merge(&empty),
            empty.combine_with_anchor(a),
            a.combine_with_anchor(&empty),
        ] {
            assert_eq!(
                merged.effective_user_initial_policy_set(),
                Some(BTreeSet::new())
            );
        }
    }
}

#[test]
fn legacy_mutation_cannot_erase_a_computed_constraint_but_explicit_replacement_can() {
    let empty = params(&[P], true).merge(&params(&[Q], true));
    let (ctx, path) = environment(None, false);
    for legacy in [vec![], vec![P], vec![ANY], vec![P, Q]] {
        let mut changed = empty.clone();
        changed.user_initial_policy_set = legacy;
        assert_eq!(
            changed.effective_user_initial_policy_set(),
            Some(BTreeSet::new())
        );
        assert!(validate_path_qualified(&ctx, &path, Some(&changed)).is_err());
    }
    let mut replaced = empty;
    replaced.replace_user_initial_policy_set(Some(BTreeSet::from([P])));
    let validated =
        validate_path_qualified(&ctx, &path, Some(&replaced)).expect("explicit replacement");
    assert_eq!(policy_pairs(&validated), vec![(P, P)]);
    replaced.replace_user_initial_policy_set(None);
    assert_eq!(replaced.effective_user_initial_policy_set(), None);
    assert!(validate_path_qualified(&ctx, &path, Some(&replaced)).is_ok());

    let mut finite = params(&[P], true).merge(&params(&[P, Q], true));
    finite.user_initial_policy_set.clear();
    assert_eq!(
        finite.effective_user_initial_policy_set(),
        Some(BTreeSet::from([P]))
    );
}

#[test]
fn explicit_constraint_input_retains_empty_and_normalizes_any_policy() {
    for explicit in [false, true] {
        let empty = PkixValidationParams {
            user_initial_policy_constraint: Some(BTreeSet::new()),
            initial_explicit_policy: explicit,
            ..Default::default()
        };
        let (ctx, path) = environment(None, true);
        assert!(validate_path_qualified(&ctx, &path, Some(&empty)).is_err());
    }
    let mut constrained = params(&[P], false);
    constrained.user_initial_policy_constraint = Some(BTreeSet::from([ANY, Q]));
    assert_eq!(
        constrained.effective_user_initial_policy_set(),
        Some(BTreeSet::from([P]))
    );
    constrained.user_initial_policy_constraint = Some(BTreeSet::from([Q]));
    assert_eq!(
        constrained.effective_user_initial_policy_set(),
        Some(BTreeSet::new())
    );
}

#[test]
fn certificate_validator_and_anchor_only_paths_retain_the_full_constraint() {
    let empty = params(&[P], true).merge(&params(&[Q], true));
    let (ctx, _) = environment(None, false);
    let cert = load_nist_cert("ValidCertificatePathTest1EE.crt");
    let error = CertificateValidator::new(&ctx, cert.clone())
        .with_params(empty.clone())
        .validate()
        .expect_err("high-level validation must retain the empty constraint");
    assert!(error.is_path_validation_error());
    let mut replaced = empty.clone();
    replaced.replace_user_initial_policy_set(Some(BTreeSet::from([P])));
    let valid = CertificateValidator::new(&ctx, cert)
        .with_params(replaced)
        .validate()
        .expect("explicit finite replacement permits the matching certificate");
    assert_eq!(policy_pairs(&valid), vec![(P, P)]);

    let (ctx, path) = environment(Some(empty), false);
    assert!(validate_path_qualified(&ctx, &path, None).is_err());
}
