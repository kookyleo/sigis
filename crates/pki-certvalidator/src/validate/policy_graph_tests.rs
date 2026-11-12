// Exact output assertions from pyhanko-certvalidator 0.33.0
// tests/test_policy_graph.py::TestUserConstrainedPolicies (MIT).
// Synthetic final graph rows exercise the production certval graph adapter.
use super::*;
use const_oid::ObjectIdentifier;
use der::{asn1::{Any, Ia5String, SequenceOf}, Encode};
use std::collections::BTreeSet;
use x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo;

const GOLD: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.999.1");
const SILVER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.999.2");
const WHITE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.999.3");
const YELLOW: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.999.4");
const ANY: ObjectIdentifier = const_oid::db::rfc5280::ANY_POLICY;

fn cps(url: &str) -> PolicyQualifierInfo {
    PolicyQualifierInfo {
        policy_qualifier_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.2.1"),
        qualifier: Any::encode_from(&Ia5String::new(url).unwrap()).unwrap(),
    }
}

fn node(policy: ObjectIdentifier, expected: &[ObjectIdentifier], qs: &[PolicyQualifierInfo]) -> certval::ValidPolicyTreeNode {
    let qualifier_set = if qs.is_empty() { None } else {
        let mut seq = SequenceOf::<PolicyQualifierInfo, 8>::new();
        for q in qs { seq.add(q.clone()).unwrap(); }
        Some(seq.to_der().unwrap())
    };
    certval::ValidPolicyTreeNode {valid_policy: policy, qualifier_set, expected_policy_set: expected.iter().copied().collect()}
}

fn root() -> Vec<certval::ValidPolicyTreeNode> { vec![node(ANY, &[ANY], &[])] }

fn policies(graph: certval::FinalValidPolicyTree, user: &[ObjectIdentifier]) -> Vec<crate::path::QualifiedPolicy> {
    let mut results = CertificationPathResults::new();
    results.set_final_valid_policy_graph(graph);
    qualified_policies(&results, Some(&PkixValidationParams { user_initial_policy_set: user.to_vec(), ..Default::default() }))
}

#[test]
fn test_null_graph() {
    let results = CertificationPathResults::new();
    assert!(qualified_policies(&results, Some(&PkixValidationParams {user_initial_policy_set: vec![GOLD], ..Default::default()})).is_empty());
}

#[test]
fn test_zero_length_path() {
    let result = policies(vec![root()], &[ANY]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].user_domain_policy_id, ANY);
    assert_eq!(result[0].issuer_domain_policy_id, ANY);
    assert!(result[0].qualifiers.is_empty());
}

#[test]
fn test_qualifiers_are_gathered_across_the_path() {
    let gold = cps("http://gold.example.com");
    let white = cps("http://white.example.com");
    let result = policies(vec![root(), vec![node(GOLD, &[WHITE], &[gold.clone()])], vec![node(WHITE, &[WHITE], &[white.clone()])]], &[ANY]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].user_domain_policy_id, GOLD);
    assert_eq!(result[0].issuer_domain_policy_id, WHITE);
    let actual: BTreeSet<_> = result[0].qualifiers.iter().map(|q|q.to_der().unwrap()).collect();
    assert_eq!(actual, BTreeSet::from([gold.to_der().unwrap(), white.to_der().unwrap()]));
}

#[test]
fn test_identical_qualifiers_are_deduplicated() {
    let q = cps("http://gold.example.com");
    let result = policies(vec![root(), vec![node(GOLD, &[GOLD], &[q.clone()])], vec![node(GOLD, &[GOLD], &[q])]], &[ANY]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].qualifiers.len(), 1);
}

#[test]
fn test_only_policies_in_the_root_domain_are_reported() {
    let result = policies(vec![root(), vec![node(GOLD, &[WHITE, YELLOW], &[])], vec![node(WHITE, &[WHITE], &[]), node(YELLOW, &[YELLOW], &[])]], &[ANY]);
    // Projection by user policy is the authority-constrained map asserted upstream.
    assert_eq!(result.iter().map(|q|q.user_domain_policy_id).collect::<BTreeSet<_>>(), BTreeSet::from([GOLD]));
    assert_eq!(result.iter().map(|q|q.issuer_domain_policy_id).collect::<BTreeSet<_>>(), BTreeSet::from([WHITE, YELLOW]));
}

fn two_policies() -> certval::FinalValidPolicyTree {
    vec![root(), vec![node(GOLD, &[GOLD], &[]), node(SILVER, &[SILVER], &[])], vec![node(GOLD, &[GOLD], &[]), node(SILVER, &[SILVER], &[])]]
}

#[test]
fn test_unacceptable_policies_are_filtered_out() {
    let result = policies(two_policies(), &[GOLD]);
    assert_eq!(result.iter().map(|q|q.user_domain_policy_id).collect::<BTreeSet<_>>(), BTreeSet::from([GOLD]));
}

#[test]
fn test_no_acceptable_policies() {
    assert!(policies(vec![root(), vec![node(GOLD, &[GOLD], &[])], vec![node(GOLD, &[GOLD], &[])]], &[SILVER]).is_empty());
}

#[test]
fn test_trailing_any_policy_expands_to_user_initial_policy_set() {
    let q = cps("http://any.example.com");
    let result = policies(vec![root(), vec![node(ANY, &[ANY], &[q.clone()]), node(GOLD, &[GOLD], &[])], vec![node(ANY, &[ANY], &[q.clone()]), node(GOLD, &[GOLD], &[])]], &[GOLD, SILVER]);
    assert_eq!(result.iter().map(|p|(p.user_domain_policy_id,p.issuer_domain_policy_id)).collect::<BTreeSet<_>>(), BTreeSet::from([(GOLD,GOLD),(SILVER,SILVER)]));
    assert!(result.iter().find(|p|p.user_domain_policy_id==GOLD).unwrap().qualifiers.is_empty());
    assert_eq!(result.iter().find(|p|p.user_domain_policy_id==SILVER).unwrap().qualifiers, vec![q]);
}
