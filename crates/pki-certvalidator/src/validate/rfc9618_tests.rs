// Port of pyhanko-certvalidator 0.33.0 tests/test_policy_graph.py (MIT,
// see LICENSE-pyHanko). These tests build and mutate the production graph;
// final certval rows or recorded Python outcomes are not substitutes.

use super::rfc9618::{
    apply_mapping, authority_constrained, update, user_constrained, Graph, GraphError, NodeId,
};
use crate::path::QualifiedPolicy;
use const_oid::ObjectIdentifier;
use der::{
    asn1::{Any, Ia5String},
    Encode,
};
use std::collections::{BTreeMap, BTreeSet};
use x509_cert::ext::pkix::certpolicy::{PolicyInformation, PolicyQualifierInfo};

const GOLD: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.999.1");
const SILVER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.999.2");
const WHITE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.999.3");
const YELLOW: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.999.4");
const RED: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.999.5");
const BLUE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.999.6");
const ANY: ObjectIdentifier = const_oid::db::rfc5280::ANY_POLICY;

fn cps(url: &str) -> PolicyQualifierInfo {
    let qualifier = PolicyQualifierInfo {
        policy_qualifier_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.2.1"),
        qualifier: Some(Any::encode_from(&Ia5String::new(url).expect("IA5 URL")).expect("CPS DER")),
    };
    eprintln!(
        "POLICY_QUALIFIER {}",
        serde_json::json!({
            "url": url,
            "der": qualifier.to_der().expect("qualifier input DER")
        })
    );
    qualifier
}

fn policy(oid: ObjectIdentifier, qualifiers: &[PolicyQualifierInfo]) -> PolicyInformation {
    PolicyInformation {
        policy_identifier: oid,
        policy_qualifiers: (!qualifiers.is_empty()).then(|| qualifiers.to_vec()),
    }
}

fn set(policies: &[ObjectIdentifier]) -> BTreeSet<ObjectIdentifier> {
    policies.iter().copied().collect()
}

fn mappings(
    pairs: &[(ObjectIdentifier, ObjectIdentifier)],
) -> BTreeMap<ObjectIdentifier, BTreeSet<ObjectIdentifier>> {
    let mut result = BTreeMap::<_, BTreeSet<_>>::new();
    for &(issuer, subject) in pairs {
        result.entry(issuer).or_default().insert(subject);
    }
    result
}

type Description = BTreeMap<ObjectIdentifier, (BTreeSet<ObjectIdentifier>, Vec<ObjectIdentifier>)>;

fn describe(graph: &Graph) -> Vec<Description> {
    (0..=graph.depth())
        .map(|depth| {
            graph
                .nodes_at_depth(depth as isize)
                .into_iter()
                .map(|id| {
                    let node = graph.node(id);
                    let mut parents: Vec<_> = node
                        .parents
                        .iter()
                        .map(|&parent| graph.node(parent).policy)
                        .collect();
                    parents.sort();
                    (node.policy, (node.expected.clone(), parents))
                })
                .collect()
        })
        .collect()
}

fn level(rows: &[(ObjectIdentifier, &[ObjectIdentifier], &[ObjectIdentifier])]) -> Description {
    rows.iter()
        .map(|(oid, expected, parents)| {
            let mut parents = parents.to_vec();
            parents.sort();
            (*oid, (set(expected), parents))
        })
        .collect()
}

fn id(graph: &Graph, depth: isize, policy: ObjectIdentifier) -> NodeId {
    graph.node_at(depth, policy).expect("policy node")
}

fn expect_next(
    graph: &mut Graph,
    depth: isize,
    policy: ObjectIdentifier,
    expected: &[ObjectIdentifier],
) {
    let node = id(graph, depth, policy);
    graph.node_mut(node).expect("live policy node").expected = set(expected);
}

fn qualifiers(graph: &Graph, node: NodeId) -> BTreeSet<Vec<u8>> {
    graph
        .node(node)
        .qualifiers
        .iter()
        .map(|q| q.to_der().expect("qualifier DER"))
        .collect()
}

fn process(graph: &mut Graph, depth: usize, policies: &[PolicyInformation]) -> bool {
    update(graph, depth, policies, true).expect("policy update")
}

fn count(graph: &Graph) -> usize {
    let by_levels = (0..=graph.depth())
        .map(|depth| graph.nodes_at_depth(depth as isize).len())
        .sum();
    assert_eq!(graph.node_count(), by_levels);
    by_levels
}

#[test]
fn test_initial_graph() {
    let graph = Graph::new(None);
    assert_eq!(describe(&graph), vec![level(&[(ANY, &[ANY], &[])])]);
    assert_eq!(graph.depth(), 0);
}

#[test]
fn test_figure4_exact_match_shares_a_single_node() {
    let mut graph = Graph::new(None);
    assert!(process(
        &mut graph,
        1,
        &[policy(RED, &[]), policy(BLUE, &[])]
    ));
    expect_next(&mut graph, 1, RED, &[GOLD, WHITE]);
    expect_next(&mut graph, 1, BLUE, &[GOLD, YELLOW]);
    assert!(process(
        &mut graph,
        2,
        &[policy(GOLD, &[]), policy(SILVER, &[])]
    ));
    assert_eq!(describe(&graph)[2], level(&[(GOLD, &[GOLD], &[RED, BLUE])]));
}

#[test]
fn test_figure5_unmatched_policies_under_any_policy() {
    let mut graph = Graph::new(None);
    let silver = cps("http://silver.example.com");
    assert!(process(
        &mut graph,
        1,
        &[
            policy(GOLD, &[]),
            policy(SILVER, std::slice::from_ref(&silver))
        ],
    ));
    assert_eq!(
        describe(&graph)[1],
        level(&[(GOLD, &[GOLD], &[ANY]), (SILVER, &[SILVER], &[ANY])]),
    );
    assert!(qualifiers(&graph, id(&graph, 1, GOLD)).is_empty());
    assert_eq!(
        qualifiers(&graph, id(&graph, 1, SILVER)),
        BTreeSet::from([silver.to_der().expect("CPS DER")]),
    );
}

#[test]
fn test_figure6_any_policy_in_certificate() {
    let mut graph = Graph::new(None);
    assert!(process(
        &mut graph,
        1,
        &[policy(RED, &[]), policy(BLUE, &[])]
    ));
    expect_next(&mut graph, 1, RED, &[GOLD, SILVER]);
    expect_next(&mut graph, 1, BLUE, &[GOLD]);
    let any = cps("http://any.example.com");
    assert!(process(
        &mut graph,
        2,
        &[policy(ANY, std::slice::from_ref(&any))]
    ));
    assert_eq!(
        describe(&graph)[2],
        level(&[(GOLD, &[GOLD], &[RED, BLUE]), (SILVER, &[SILVER], &[RED])]),
    );
    assert_eq!(
        qualifiers(&graph, id(&graph, 2, GOLD)),
        BTreeSet::from([any.to_der().expect("CPS DER")]),
    );
}

#[test]
fn test_any_policy_inhibited() {
    let mut graph = Graph::new(None);
    assert!(process(&mut graph, 1, &[policy(GOLD, &[])]));
    assert!(!update(&mut graph, 2, &[policy(ANY, &[])], false).expect("policy update"));
}

#[test]
fn test_figure7_pruning_cascades() {
    let mut graph = Graph::new(None);
    assert!(process(
        &mut graph,
        1,
        &[policy(RED, &[]), policy(BLUE, &[])]
    ));
    expect_next(&mut graph, 1, RED, &[GOLD]);
    expect_next(&mut graph, 1, BLUE, &[SILVER]);
    assert!(process(
        &mut graph,
        2,
        &[policy(GOLD, &[]), policy(SILVER, &[])]
    ));
    expect_next(&mut graph, 2, GOLD, &[WHITE]);
    expect_next(&mut graph, 2, SILVER, &[YELLOW]);
    assert!(process(&mut graph, 3, &[policy(WHITE, &[])]));
    assert_eq!(
        describe(&graph),
        vec![
            level(&[(ANY, &[ANY], &[])]),
            level(&[(RED, &[GOLD], &[ANY])]),
            level(&[(GOLD, &[WHITE], &[RED])]),
            level(&[(WHITE, &[WHITE], &[GOLD])]),
        ],
    );
}

#[test]
fn test_pruning_to_null_graph() {
    let mut graph = Graph::new(None);
    assert!(process(&mut graph, 1, &[policy(GOLD, &[])]));
    assert!(!process(&mut graph, 2, &[policy(SILVER, &[])]));
}

#[test]
fn test_duplicate_policy_oid_is_ignored() {
    let mut graph = Graph::new(None);
    let first = cps("http://first.example.com");
    assert!(process(
        &mut graph,
        1,
        &[
            policy(GOLD, std::slice::from_ref(&first)),
            policy(GOLD, &[cps("http://second.example")]),
        ],
    ));
    assert_eq!(describe(&graph)[1], level(&[(GOLD, &[GOLD], &[ANY])]));
    assert_eq!(
        qualifiers(&graph, id(&graph, 1, GOLD)),
        BTreeSet::from([first.to_der().expect("CPS DER")]),
    );
}

#[test]
fn test_no_any_policy_parent_to_fall_back_on() {
    let mut graph = Graph::new(None);
    assert!(process(
        &mut graph,
        1,
        &[policy(GOLD, &[]), policy(SILVER, &[])]
    ));
    assert!(process(
        &mut graph,
        2,
        &[policy(GOLD, &[]), policy(WHITE, &[])]
    ));
    assert_eq!(describe(&graph)[2], level(&[(GOLD, &[GOLD], &[GOLD])]));
}

#[test]
fn test_no_exponential_blowup() {
    let depth_target = 25;
    let mut graph = Graph::new(None);
    for depth in 1..=depth_target {
        assert!(process(
            &mut graph,
            depth,
            &[policy(GOLD, &[]), policy(SILVER, &[])]
        ));
        assert!(apply_mapping(
            &mut graph,
            depth,
            &mappings(&[
                (GOLD, GOLD),
                (GOLD, SILVER),
                (SILVER, GOLD),
                (SILVER, SILVER)
            ]),
            true,
        )
        .expect("mapping"));
    }
    assert_eq!(count(&graph), 2 * depth_target + 1);
}

mod test_policy_mapping {
    use super::*;

    #[test]
    fn test_mapped_node_expects_subject_domain_policies() {
        let mut graph = Graph::new(None);
        assert!(process(&mut graph, 1, &[policy(GOLD, &[])]));
        assert!(apply_mapping(
            &mut graph,
            1,
            &mappings(&[(GOLD, WHITE), (GOLD, YELLOW)]),
            true
        )
        .expect("mapping"));
        assert_eq!(
            describe(&graph)[1],
            level(&[(GOLD, &[WHITE, YELLOW], &[ANY])])
        );
    }

    #[test]
    fn test_mapping_under_any_policy() {
        let any = cps("http://any.example.com");
        let mut graph = Graph::new(None);
        assert!(process(
            &mut graph,
            1,
            &[policy(ANY, std::slice::from_ref(&any))]
        ));
        assert!(apply_mapping(&mut graph, 1, &mappings(&[(GOLD, WHITE)]), true).expect("mapping"));
        assert_eq!(
            describe(&graph)[1],
            level(&[(ANY, &[ANY], &[ANY]), (GOLD, &[WHITE], &[ANY])]),
        );
        assert_eq!(
            qualifiers(&graph, id(&graph, 1, GOLD)),
            BTreeSet::from([any.to_der().expect("CPS DER")]),
        );
    }

    #[test]
    fn test_no_mapping_without_any_policy() {
        let mut graph = Graph::new(None);
        assert!(process(&mut graph, 1, &[policy(SILVER, &[])]));
        assert!(apply_mapping(&mut graph, 1, &mappings(&[(GOLD, WHITE)]), true).expect("mapping"));
        assert_eq!(describe(&graph)[1], level(&[(SILVER, &[SILVER], &[ANY])]));
    }

    #[test]
    fn test_inhibited_mapping_deletes_node() {
        let mut graph = Graph::new(None);
        assert!(process(
            &mut graph,
            1,
            &[policy(GOLD, &[]), policy(SILVER, &[])]
        ));
        assert!(apply_mapping(&mut graph, 1, &mappings(&[(GOLD, WHITE)]), false).expect("mapping"));
        assert_eq!(describe(&graph)[1], level(&[(SILVER, &[SILVER], &[ANY])]));
    }

    #[test]
    fn test_inhibited_mapping_of_absent_policy() {
        let mut graph = Graph::new(None);
        assert!(process(&mut graph, 1, &[policy(SILVER, &[])]));
        assert!(apply_mapping(&mut graph, 1, &mappings(&[(GOLD, WHITE)]), false).expect("mapping"));
        assert_eq!(describe(&graph)[1], level(&[(SILVER, &[SILVER], &[ANY])]));
    }

    #[test]
    fn test_inhibited_mapping_can_null_out_the_graph() {
        let mut graph = Graph::new(None);
        assert!(process(
            &mut graph,
            1,
            &[policy(GOLD, &[]), policy(SILVER, &[])]
        ));
        assert!(!apply_mapping(
            &mut graph,
            1,
            &mappings(&[(GOLD, WHITE), (SILVER, YELLOW), (RED, BLUE)]),
            false,
        )
        .expect("mapping"));
    }

    #[test]
    fn test_inhibited_mapping_prunes_once() {
        let policies: Vec<_> = (0..50)
            .map(|ix| {
                format!("2.999.100.{ix}")
                    .parse::<ObjectIdentifier>()
                    .expect("policy OID")
            })
            .collect();
        let mut graph = Graph::new(None);
        let certificates: Vec<_> = policies.iter().map(|&oid| policy(oid, &[])).collect();
        assert!(process(&mut graph, 1, &certificates));
        graph.prune_calls.clear();
        let pairs: Vec<_> = policies[1..].iter().map(|&oid| (oid, WHITE)).collect();
        assert!(apply_mapping(&mut graph, 1, &mappings(&pairs), false).expect("mapping"));
        assert_eq!(graph.prune_calls, vec![0]);
        assert_eq!(
            describe(&graph)[1],
            level(&[(policies[0], &[policies[0]], &[ANY])])
        );
    }
}

mod test_graph_operations {
    use super::*;

    #[test]
    fn test_nodes_outside_the_graph() {
        let graph = Graph::new(None);
        assert!(graph.nodes_at_depth(-1).is_empty());
        assert!(graph.nodes_at_depth(1).is_empty());
        assert_eq!(graph.node_at(1, ANY), None);
        assert_eq!(graph.node_at(-1, ANY), None);
    }

    #[test]
    fn test_duplicate_node_rejected() {
        let mut graph = Graph::new(None);
        let error = graph
            .add_node(0, ANY, vec![], set(&[ANY]), &[])
            .expect_err("duplicate node");
        assert!(error.to_string().contains("already occurs"), "{error}");
        assert!(matches!(error, GraphError::Duplicate { .. }));
    }

    #[test]
    fn test_size_limit_rejects_surplus_nodes() {
        let mut graph = Graph::new(Some(2));
        let error = update(
            &mut graph,
            1,
            &[policy(GOLD, &[]), policy(SILVER, &[])],
            true,
        )
        .expect_err("surplus node");
        assert!(error.to_string().contains("2 nodes"), "{error}");
        assert!(matches!(error, GraphError::SizeLimit(2)));
    }

    #[test]
    fn test_deleted_nodes_free_up_space() {
        let mut graph = Graph::new(Some(3));
        assert!(process(
            &mut graph,
            1,
            &[policy(GOLD, &[]), policy(SILVER, &[])]
        ));
        let silver = id(&graph, 1, SILVER);
        graph.delete_node(silver);
        assert!(process(&mut graph, 2, &[policy(GOLD, &[])]));
        assert_eq!(count(&graph), 3);
    }

    #[test]
    fn test_delete_unknown_node_is_a_noop() {
        let mut graph = Graph::new(None);
        let root = id(&graph, 0, ANY);
        graph.delete_node(root);
        graph.delete_node(root);
        assert_eq!(describe(&graph), vec![BTreeMap::new()]);
    }

    #[test]
    fn test_delete_node_takes_orphans_with_it() {
        let mut graph = Graph::new(None);
        assert!(process(
            &mut graph,
            1,
            &[policy(GOLD, &[]), policy(SILVER, &[])]
        ));
        expect_next(&mut graph, 1, GOLD, &[WHITE]);
        expect_next(&mut graph, 1, SILVER, &[WHITE, YELLOW]);
        assert!(process(
            &mut graph,
            2,
            &[policy(WHITE, &[]), policy(YELLOW, &[])]
        ));
        let silver = id(&graph, 1, SILVER);
        graph.delete_node(silver);
        assert_eq!(
            describe(&graph),
            vec![
                level(&[(ANY, &[ANY], &[])]),
                level(&[(GOLD, &[WHITE], &[ANY])]),
                level(&[(WHITE, &[WHITE], &[GOLD])]),
            ],
        );
        assert_eq!(
            graph.node(id(&graph, 0, ANY)).children,
            BTreeSet::from([id(&graph, 1, GOLD)])
        );
        assert!(graph.node(silver).parents.is_empty());
        assert!(graph.node(silver).children.is_empty());
    }

    #[test]
    fn test_prune_is_not_limited_to_deepest_level() {
        let mut graph = Graph::new(None);
        for depth in 1..=3 {
            assert!(process(
                &mut graph,
                depth,
                &[policy(GOLD, &[]), policy(SILVER, &[])]
            ));
        }
        let silver = id(&graph, 2, SILVER);
        graph.delete_node(silver);
        assert!(graph.prune(2));
        assert_eq!(
            describe(&graph),
            vec![
                level(&[(ANY, &[ANY], &[])]),
                level(&[(GOLD, &[GOLD], &[ANY])]),
                level(&[(GOLD, &[GOLD], &[GOLD])]),
                level(&[(GOLD, &[GOLD], &[GOLD])]),
            ],
        );
    }

    #[test]
    fn test_ancestors_and_descendants_of_a_diamond() {
        let mut graph = Graph::new(None);
        assert!(process(
            &mut graph,
            1,
            &[policy(GOLD, &[]), policy(SILVER, &[])]
        ));
        expect_next(&mut graph, 1, GOLD, &[WHITE]);
        expect_next(&mut graph, 1, SILVER, &[WHITE]);
        assert!(process(&mut graph, 2, &[policy(WHITE, &[])]));
        expect_next(&mut graph, 2, WHITE, &[YELLOW]);
        assert!(process(&mut graph, 3, &[policy(YELLOW, &[])]));
        let white = id(&graph, 2, WHITE);
        let ancestors: BTreeSet<_> = graph
            .ancestors(white)
            .iter()
            .map(|&node| graph.node(node).policy)
            .collect();
        assert_eq!(ancestors, set(&[GOLD, SILVER, ANY]));
        assert_eq!(graph.ancestors(white).len(), 3);
        let root = id(&graph, 0, ANY);
        let descendants: BTreeSet<_> = graph
            .descendants(root)
            .iter()
            .map(|&node| graph.node(node).policy)
            .collect();
        assert_eq!(descendants, set(&[GOLD, SILVER, WHITE, YELLOW]));
        assert_eq!(graph.descendants(root).len(), 4);
    }
}

mod test_user_constrained_policies {
    use super::*;

    #[test]
    fn test_null_graph() {
        assert!(user_constrained(None, 3, &set(&[GOLD])).is_empty());
        assert!(authority_constrained(None, 3).is_empty());
    }

    #[test]
    fn test_zero_length_path() {
        let graph = Graph::new(None);
        assert_eq!(
            user_constrained(Some(&graph), 0, &set(&[ANY])),
            vec![QualifiedPolicy {
                user_domain_policy_id: ANY,
                issuer_domain_policy_id: ANY,
                qualifiers: vec![],
            }],
        );
    }

    #[test]
    fn test_qualifiers_are_gathered_across_the_path() {
        let gold = cps("http://gold.example.com");
        let white = cps("http://white.example.com");
        let mut graph = Graph::new(None);
        assert!(process(
            &mut graph,
            1,
            &[policy(GOLD, std::slice::from_ref(&gold))]
        ));
        assert!(apply_mapping(&mut graph, 1, &mappings(&[(GOLD, WHITE)]), true).expect("mapping"));
        assert!(process(
            &mut graph,
            2,
            &[policy(WHITE, std::slice::from_ref(&white))]
        ));
        let result = user_constrained(Some(&graph), 2, &set(&[ANY]));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].user_domain_policy_id, GOLD);
        assert_eq!(result[0].issuer_domain_policy_id, WHITE);
        let qualifiers: BTreeSet<_> = result[0]
            .qualifiers
            .iter()
            .map(|q| q.to_der().expect("CPS DER"))
            .collect();
        assert_eq!(
            qualifiers,
            BTreeSet::from([
                gold.to_der().expect("CPS DER"),
                white.to_der().expect("CPS DER")
            ])
        );
    }

    #[test]
    fn test_identical_qualifiers_are_deduplicated() {
        let mut graph = Graph::new(None);
        assert!(process(
            &mut graph,
            1,
            &[policy(GOLD, &[cps("http://gold.example.com")])]
        ));
        assert!(process(
            &mut graph,
            2,
            &[policy(GOLD, &[cps("http://gold.example.com")])]
        ));
        let result = user_constrained(Some(&graph), 2, &set(&[ANY]));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].qualifiers.len(), 1);
    }

    #[test]
    fn test_only_policies_in_the_root_domain_are_reported() {
        let mut graph = Graph::new(None);
        assert!(process(&mut graph, 1, &[policy(GOLD, &[])]));
        assert!(apply_mapping(
            &mut graph,
            1,
            &mappings(&[(GOLD, WHITE), (GOLD, YELLOW)]),
            true
        )
        .expect("mapping"));
        assert!(process(
            &mut graph,
            2,
            &[policy(WHITE, &[]), policy(YELLOW, &[])]
        ));
        let authority = authority_constrained(Some(&graph), 2);
        assert_eq!(
            authority.keys().copied().collect::<BTreeSet<_>>(),
            set(&[GOLD])
        );
        assert_eq!(authority[&GOLD].issuer_policies, set(&[WHITE, YELLOW]));
    }

    #[test]
    fn test_unacceptable_policies_are_filtered_out() {
        let mut graph = Graph::new(None);
        for depth in 1..=2 {
            assert!(process(
                &mut graph,
                depth,
                &[policy(GOLD, &[]), policy(SILVER, &[])]
            ));
        }
        let result = user_constrained(Some(&graph), 2, &set(&[GOLD]));
        assert_eq!(
            result
                .iter()
                .map(|q| q.user_domain_policy_id)
                .collect::<BTreeSet<_>>(),
            set(&[GOLD])
        );
    }

    #[test]
    fn test_no_acceptable_policies() {
        let mut graph = Graph::new(None);
        for depth in 1..=2 {
            assert!(process(&mut graph, depth, &[policy(GOLD, &[])]));
        }
        assert!(user_constrained(Some(&graph), 2, &set(&[SILVER])).is_empty());
    }

    #[test]
    fn test_trailing_any_policy_expands_to_user_initial_policy_set() {
        let any = cps("http://any.example.com");
        let mut graph = Graph::new(None);
        for depth in 1..=2 {
            assert!(process(
                &mut graph,
                depth,
                &[policy(ANY, std::slice::from_ref(&any)), policy(GOLD, &[])]
            ));
        }
        let result = user_constrained(Some(&graph), 2, &set(&[GOLD, SILVER]));
        assert_eq!(
            result
                .iter()
                .map(|q| (q.user_domain_policy_id, q.issuer_domain_policy_id))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([(GOLD, GOLD), (SILVER, SILVER)]),
        );
        let gold = result
            .iter()
            .find(|q| q.user_domain_policy_id == GOLD)
            .expect("Gold");
        assert!(gold.qualifiers.is_empty());
        let silver = result
            .iter()
            .find(|q| q.user_domain_policy_id == SILVER)
            .expect("Silver");
        assert_eq!(
            silver
                .qualifiers
                .iter()
                .map(|q| q.to_der().expect("CPS DER"))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([any.to_der().expect("CPS DER")]),
        );
    }
}
