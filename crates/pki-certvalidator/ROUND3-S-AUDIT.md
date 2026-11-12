# Round 3 S inherited skip audit

Baseline: pyhanko-certvalidator 0.33.0, pinned source commit `b48999514cb4`.
The assigned crate denominator remains 133 unique upstream test functions.
The baseline is 92 passed, 41 skipped and zero pending.
After targeted Rust verification, the lane result is **133 total / 98 passed /
35 skipped / zero pending**, pending lead integration acceptance. Exactly the
six name-predicate functions move from skipped to passed.

## Name predicates

`src/validate/name_constraints_tests.rs` translates every exact upstream
assertion and parameter in `test_name_trees.py`. The fixture is extracted
from the pinned AST, preserving the Unicode DNS negative case, local-part
case sensitivity, boundary labels, trailing root dots and URI failures.

| Upstream function | Rust test | Parameters |
| --- | --- | ---: |
| `test_dns_tree_contains` | `validate::name_constraints_tests::test_dns_tree_contains` | 15 |
| `test_host_tree_contains` | `validate::name_constraints_tests::test_host_tree_contains` | 14 |
| `test_host_tree_contains_rejects_empty_base` | `validate::name_constraints_tests::test_host_tree_contains_rejects_empty_base` | 1 |
| `test_email_tree_contains` | `validate::name_constraints_tests::test_email_tree_contains` | 15 |
| `test_uri_tree_contains` | `validate::name_constraints_tests::test_uri_tree_contains` | 7 |
| `test_uri_tree_contains_requires_fqdn` | `validate::name_constraints_tests::test_uri_tree_contains_requires_fqdn` | 2 |

These predicates are consumed by production excluded-name validation.
Constraint errors are propagated as explicit path validation failures.
They are not disconnected compatibility helpers.

## User-constrained policy results

`src/validate/policy_graph_tests.rs` exercises the production
`qualified_policies` adapter with the exact final graph rows specified by
the eight `TestUserConstrainedPolicies` examples. Setup uses actual
`certval::FinalValidPolicyTree` rows rather than reimplementing the graph
mutation engine. The tests preserve all output assertions, including DER
qualifier identity. The authority-constrained map in the root-domain test
is checked by projecting qualified results to user and issuer policy IDs.

| Upstream method | Exact assertion |
| --- | --- |
| `test_null_graph` | Null graph produces an empty policy result |
| `test_zero_length_path` | Root graph produces exactly anyPolicy/anyPolicy with no qualifiers |
| `test_qualifiers_are_gathered_across_the_path` | Gold-to-White mapping reports both exact CPS qualifier encodings |
| `test_identical_qualifiers_are_deduplicated` | Identical CPS qualifiers across two levels appear once |
| `test_only_policies_in_the_root_domain_are_reported` | Authority domain is exactly Gold; issuer domain is exactly White and Yellow |
| `test_unacceptable_policies_are_filtered_out` | Restriction to Gold filters Silver |
| `test_no_acceptable_policies` | A Silver-only initial set produces no Gold result |
| `test_trailing_any_policy_expands_to_user_initial_policy_set` | Gold/Gold and Silver/Silver only; Gold has no qualifier and Silver has the exact wildcard CPS qualifier |

The zero-length assertion exposed a real adapter bug: a graph containing
only the root was discarded. The adapter now discards only an empty graph.
The setup substitutions do not establish coverage of certval's internal
mutation operations. All eight functions remain skipped with partial
coverage: their upstream setup calls process and/or apply_policy_mapping,
which the synthetic final graph bypasses. Exact adapter output assertions
alone do not complete those upstream functions. The other 25 graph
functions remain skipped below as well.

## Remaining graph feature gaps

Every row below is an inherited skipped function from
`pyhanko-certvalidator/test_policy_graph.py`. The Rust port exposes no
equivalent direct mutable graph API. The existing PKITS corpus and policy
tests are useful regression coverage, but do not establish these exact
node/edge/allocation/complexity assertions.

| Upstream function or method | Remaining exact assertion gap |
| --- | --- |
| `test_initial_graph` | Root-node structure and depth introspection |
| `test_figure4_exact_match_shares_a_single_node` | One Gold node with both Red and Blue parents |
| `test_figure5_unmatched_policies_under_any_policy` | Explicit Gold/Silver nodes under anyPolicy and per-node CPS qualifiers |
| `test_figure6_any_policy_in_certificate` | Gold has two parents, Silver has one, and wildcard qualifiers are copied |
| `test_any_policy_inhibited` | Inhibited wildcard update collapses graph to null |
| `test_figure7_pruning_cascades` | Exact four-level surviving chain after cascading pruning |
| `test_pruning_to_null_graph` | Unmatched next-level update collapses the entire graph |
| `test_duplicate_policy_oid_is_ignored` | First duplicate OID qualifier wins with exactly one node |
| `test_no_any_policy_parent_to_fall_back_on` | Unexpected White is absent and matched Gold remains |
| `test_no_exponential_blowup` | 25-level adversarial mapping chain contains exactly 51 nodes |
| `TestPolicyMapping.test_mapped_node_expects_subject_domain_policies` | Gold node expected set becomes exactly White and Yellow |
| `TestPolicyMapping.test_mapping_under_any_policy` | New mapped Gold node inherits exact wildcard qualifiers and parent |
| `TestPolicyMapping.test_no_mapping_without_any_policy` | Absent issuer policy does not create a node without a wildcard parent |
| `TestPolicyMapping.test_inhibited_mapping_deletes_node` | Inhibited mapping removes Gold and preserves Silver |
| `TestPolicyMapping.test_inhibited_mapping_of_absent_policy` | Inhibited absent mapping preserves existing graph |
| `TestPolicyMapping.test_inhibited_mapping_can_null_out_the_graph` | Null graph after second removal tolerates the third mapping |
| `TestPolicyMapping.test_inhibited_mapping_prunes_once` | Exactly one prune call for 49 inhibited mappings, preserving the first of 50 policies |
| `TestGraphOperations.test_nodes_outside_the_graph` | Negative and excessive-depth lookup yields no nodes |
| `TestGraphOperations.test_duplicate_node_rejected` | Duplicate explicit insertion raises the specified error |
| `TestGraphOperations.test_size_limit_rejects_surplus_nodes` | Allocation rejects at exactly two live nodes; existing policy_proc size-limit coverage checks a completed graph instead |
| `TestGraphOperations.test_deleted_nodes_free_up_space` | Removing Silver frees a live-node allocation slot |
| `TestGraphOperations.test_delete_unknown_node_is_a_noop` | Repeated root removal is safe and leaves an empty root level |
| `TestGraphOperations.test_delete_node_takes_orphans_with_it` | Orphan Yellow is removed, shared White survives, and detached node edges are cleared |
| `TestGraphOperations.test_prune_is_not_limited_to_deepest_level` | Pruning removes childless nodes above the requested deepest level |
| `TestGraphOperations.test_ancestors_and_descendants_of_a_diamond` | Diamond traversal returns each ancestor/descendant once |

## Deprecated registry entry points

| Upstream function | Remaining feature gap |
| --- | --- |
| `pyhanko-certvalidator/test_registry.py::test_system_trust_fallback_deprecated` | There is no implicit OS trust loader or Python DeprecationWarning API; a mocked loader returning no certificates and the exact warning cannot be asserted through a Rust equivalent |
| `pyhanko-certvalidator/test_registry.py::test_extra_trust_roots_deprecated` | There is no extra_trust_roots alias or deprecation warning; explicit trust roots are covered elsewhere, but that does not port the warning assertion |

No deprecated compatibility alias was added merely to manufacture a pass.
No blanket equivalence claim is retained for any of the 41 baseline skips.
Six name functions now pass all 54 upstream cases in Rust. All 33 graph functions remain
skipped, including eight with partial adapter coverage; two deprecated
registry functions remain skipped.

## Verification

No provider-dependent early return is present in the new tests. The six
name tests always execute all 54 parameter cases and the eight policy
tests always execute their assertions. Live oracle evidence and final
build/test logs are recorded in the lane artifact handoff. A fresh pinned-AST
comparison confirms the fixture exactly preserves all six functions and 54
cases, including the non-parametrized empty-host error assertion.

All Cargo commands used `tools/cargo-locked.sh` with normal configured
compiler wrappers, features and profiles. Check passed on vm2064 slot0 in
0.91s. Formatting completed successfully. The final full library unit suite
passed 25/25 tests and `policy_proc` passed 13/13 on vm2065 slot0, both with
zero failures and zero ignored tests. Library tests include the six name
functions, eight partial graph adapter tests and both context-preservation
regressions. The graph fixture encodes qualifiers through alloc-backed
`Vec<PolicyQualifierInfo>` without enabling heapless features; exact DER
qualifier assertions are retained. Invalid-name errors are mapped to a
path-bearing `PathFailure` at the production caller.

The verified lane result is 133 total / 98 passed / 35 skipped / zero pending.
Eight synthetic policy adapter tests earn no upstream-function passes; the
two context regressions also earn none. Fresh oracle calls remain a separate
measurement: 54 name invocations and eight graph invocations passed. Lead
acceptance and the complete workspace gate are outside this targeted result.
