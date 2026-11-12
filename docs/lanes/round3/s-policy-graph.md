# Lead acceptance: native RFC 9618 graph

Source d1e38df passed build, tests, strict clippy, strict docs, layer and fmt:
1359 discovered / 1351 passed / 8 ignored / 0 failed,
across 109 reports. Only the33 exact immutable S policy-graph IDs change
skipped -> passed. Production path validation uses the same native RFC9618
graph; certval remains mandatory. All source assertions were independently
reviewed, and the lead freshly reran all33 pinned Python tests successfully.
Eight partial final-row adapters were replaced by real mutation/mapping tests.
Oracle calls and native helpers earn no additional upstream-function credit.

Accepted certvalidator133/131/2/0; S824/787/30/7; overall1431/1085/33/313.
The two deprecated registry entry points remain skipped. The six-file curated
source includes d79ee62 empty-intersection protection and68a1ae7 native graph,
preserving accepted typed algorithm horizons. Actual transient node limits
reject a six-node peak even when only five nodes survive. Disjoint caller and
anchor policy sets retain their empty intersection during path validation.
Already-materialized public merge empty-set provenance remains a separate API
gap. Native limits apply after certval, not to whole-validator memory use.
No universal fail-closed parity claim follows from this increment.

Existing S comparisons cover21 public policy/limit results, five actual DER
hashes and four qualifier encodings; the lead's separate33-function Python run
is fresh execution. Logs: round3-launch/s-policy-graph-gate/ artifacts.

The following original candidate report is retained as source/test provenance.
Its pre-acceptance tables describe that earlier snapshot.

# Native RFC 9618 graph: independent S review candidate

Accepted accounting remains **S824/754/63/7**, overall **1431/1052/66/313**.
This increment requests L review of exactly33 inherited graph skips. It does
not update the accepted ledger or claim that main's gate ran this source.

| Owned crate | Accepted total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| sigis-cms | 78 | 74 | 2 | 2 |
| sigis-eutl | 53 | 53 | 0 | 0 |
| sigis-pdf | 406 | 390 | 11 | 5 |
| sigis-pdf-diff | 94 | 92 | 2 | 0 |
| sigis-pki-certvalidator | 133 | 98 | 35 | 0 |
| sigis-pki-core | 4 | 4 | 0 | 0 |
| sigis-pki-fetch | 56 | 43 | 13 | 0 |
| Total | 824 | 754 | 63 | 7 |

If L accepts this candidate, only the33 listed certificate graph functions
change classification. The two deprecated registry gaps remain. The separate
CMS selector candidate is not included. Native helper tests and oracle calls
add no unique upstream functions.

## Production change and tests first

The private production graph replaces approximate edge reconstruction from
certval's final rows. Its nodes retain actual parent/child identities, one node
per policy/depth, expected policy sets and opaque qualifiers. Update, mapping,
cascading deletion/pruning, authority projection and user projection follow
pinned policy_graph.py. Shared descendants survive until their last parent is
removed. Deleted nodes release production storage and active-node capacity;
identities are never reused. Test-only detached snapshots preserve Python's
external-reference observation that deleted node edges are cleared.

All33 exact upstream tests were translated before implementation. Their first
native run failed because the graph API was missing. They include the complete
25-depth/four-mapping-per-level/51-node growth assertion,50policies with49
inhibited mappings and exactly one prune, max2 rejection, max3 delete/reuse,
all shared-parent/orphan/diamond assertions, duplicate first-qualifier retention,
and every qualifier/authority/user policy assertion. Eight historical synthetic
final-row adapters are replaced by these complete graph mutation tests; none
of their substantive output assertions is dropped. Distinct native error
variants preserve duplicate-node versus size-limit errors.

The same graph is used by production path validation. Native replay handles
missing CertificatePolicies, anyPolicy inhibition and the self-issued exception,
policy mappings (including forbidden anyPolicy even after NULL), restriction
counters, final wrap-up and explicit-policy rejection. Certval's complete
signature/name/CA/path/extension validation remains mandatory. Native success
cannot override certval failure. Existing algorithm and revocation enforcement
remain mandatory afterwards. There are no new dependencies, public exports,
core/context changes or cross-layer dev-dependency edges.

## Real-path allocation and failure context

A genuine existing NIST path uses TrustAnchorRootCertificate -> PoliciesP123CA
-> PoliciesP123subCAP12 (the second CA is validated as the target; no signing
usage is implied). Its graph peaks at6 active nodes and prunes to5. The previous
final-only check wrongly accepted limit5; the new native test first reproduced
that acceptance. The new replay rejects during construction. None/6/7/8 accept;
0..3 reject at intermediate1 and4/5 at the target, with exact pinned messages,
original path, leaf/side-validation flags and no invented time horizon.
A strengthened context assertion first exposed the missing leaf flag; the
producer now returns contextual PathFailure rather than stripping the position.
An initial test expected an extra English article before intermediate1; fresh
oracle proved the correct wording and the assertion was corrected. That earlier
wording failure is retained separately from the observed limit5 acceptance.

The active-node limit constrains native graph construction after mandatory
certval validation. It is not a preflight bound on certval's preceding work.
No claim of a whole-validator memory bound is made.

The preceding bounded empty caller/anchor intersection repair d79ee62 is retained:
mandatory empty intersection rejects; optional returns no qualified policies.
Default empty Vec and anyPolicy remain wildcards. The current real-path tests
cover six disjoint explicit refusals, two optional empty results and seven
matched/wildcard/overlap controls. An already materialized public merge result
still loses empty-intersection provenance under the existing public Vec contract;
that separate L-routed representation issue remains explicit. Existing stricter
symmetric Rust wildcard intersection is retained; a known asymmetric Python
branch is not used to relax caller constraints.

## Exact function mapping

Every row is one unique upstream function, irrespective of loops or graph calls.
There are no new provider exclusions, runtime skips or empty re-enable stubs.

| Exact upstream function ID | Native test |
| --- | --- |
| `pyhanko-certvalidator/test_policy_graph.py::test_initial_graph` | `validate::rfc9618_tests::test_initial_graph` |
| `pyhanko-certvalidator/test_policy_graph.py::test_figure4_exact_match_shares_a_single_node` | `validate::rfc9618_tests::test_figure4_exact_match_shares_a_single_node` |
| `pyhanko-certvalidator/test_policy_graph.py::test_figure5_unmatched_policies_under_any_policy` | `validate::rfc9618_tests::test_figure5_unmatched_policies_under_any_policy` |
| `pyhanko-certvalidator/test_policy_graph.py::test_figure6_any_policy_in_certificate` | `validate::rfc9618_tests::test_figure6_any_policy_in_certificate` |
| `pyhanko-certvalidator/test_policy_graph.py::test_any_policy_inhibited` | `validate::rfc9618_tests::test_any_policy_inhibited` |
| `pyhanko-certvalidator/test_policy_graph.py::test_figure7_pruning_cascades` | `validate::rfc9618_tests::test_figure7_pruning_cascades` |
| `pyhanko-certvalidator/test_policy_graph.py::test_pruning_to_null_graph` | `validate::rfc9618_tests::test_pruning_to_null_graph` |
| `pyhanko-certvalidator/test_policy_graph.py::test_duplicate_policy_oid_is_ignored` | `validate::rfc9618_tests::test_duplicate_policy_oid_is_ignored` |
| `pyhanko-certvalidator/test_policy_graph.py::test_no_any_policy_parent_to_fall_back_on` | `validate::rfc9618_tests::test_no_any_policy_parent_to_fall_back_on` |
| `pyhanko-certvalidator/test_policy_graph.py::test_no_exponential_blowup` | `validate::rfc9618_tests::test_no_exponential_blowup` |
| `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_mapped_node_expects_subject_domain_policies` | `validate::rfc9618_tests::test_policy_mapping::test_mapped_node_expects_subject_domain_policies` |
| `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_mapping_under_any_policy` | `validate::rfc9618_tests::test_policy_mapping::test_mapping_under_any_policy` |
| `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_no_mapping_without_any_policy` | `validate::rfc9618_tests::test_policy_mapping::test_no_mapping_without_any_policy` |
| `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_inhibited_mapping_deletes_node` | `validate::rfc9618_tests::test_policy_mapping::test_inhibited_mapping_deletes_node` |
| `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_inhibited_mapping_of_absent_policy` | `validate::rfc9618_tests::test_policy_mapping::test_inhibited_mapping_of_absent_policy` |
| `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_inhibited_mapping_can_null_out_the_graph` | `validate::rfc9618_tests::test_policy_mapping::test_inhibited_mapping_can_null_out_the_graph` |
| `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_inhibited_mapping_prunes_once` | `validate::rfc9618_tests::test_policy_mapping::test_inhibited_mapping_prunes_once` |
| `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_nodes_outside_the_graph` | `validate::rfc9618_tests::test_graph_operations::test_nodes_outside_the_graph` |
| `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_duplicate_node_rejected` | `validate::rfc9618_tests::test_graph_operations::test_duplicate_node_rejected` |
| `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_size_limit_rejects_surplus_nodes` | `validate::rfc9618_tests::test_graph_operations::test_size_limit_rejects_surplus_nodes` |
| `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_deleted_nodes_free_up_space` | `validate::rfc9618_tests::test_graph_operations::test_deleted_nodes_free_up_space` |
| `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_delete_unknown_node_is_a_noop` | `validate::rfc9618_tests::test_graph_operations::test_delete_unknown_node_is_a_noop` |
| `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_delete_node_takes_orphans_with_it` | `validate::rfc9618_tests::test_graph_operations::test_delete_node_takes_orphans_with_it` |
| `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_prune_is_not_limited_to_deepest_level` | `validate::rfc9618_tests::test_graph_operations::test_prune_is_not_limited_to_deepest_level` |
| `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_ancestors_and_descendants_of_a_diamond` | `validate::rfc9618_tests::test_graph_operations::test_ancestors_and_descendants_of_a_diamond` |
| `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_null_graph` | `validate::rfc9618_tests::test_user_constrained_policies::test_null_graph` |
| `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_zero_length_path` | `validate::rfc9618_tests::test_user_constrained_policies::test_zero_length_path` |
| `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_qualifiers_are_gathered_across_the_path` | `validate::rfc9618_tests::test_user_constrained_policies::test_qualifiers_are_gathered_across_the_path` |
| `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_identical_qualifiers_are_deduplicated` | `validate::rfc9618_tests::test_user_constrained_policies::test_identical_qualifiers_are_deduplicated` |
| `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_only_policies_in_the_root_domain_are_reported` | `validate::rfc9618_tests::test_user_constrained_policies::test_only_policies_in_the_root_domain_are_reported` |
| `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_unacceptable_policies_are_filtered_out` | `validate::rfc9618_tests::test_user_constrained_policies::test_unacceptable_policies_are_filtered_out` |
| `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_no_acceptable_policies` | `validate::rfc9618_tests::test_user_constrained_policies::test_no_acceptable_policies` |
| `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_trailing_any_policy_expands_to_user_initial_policy_set` | `validate::rfc9618_tests::test_user_constrained_policies::test_trailing_any_policy_expands_to_user_initial_policy_set` |

## Verification and evidence

Artifacts: `/home/l/.codex/artifacts/sigis/round3/s/policy-graph/`.
The final full PKI run has185passed/0failed/0ignored across15reports, including
all33 graph functions, the real transient-limit regression, existing full PKITS
and OpenSSL OCSP corpora, context/AC/revocation/time-slide and typed-horizon
regressions. Existing PKITS is committed-fixture replay and retains its exact
known UTCTime1950 rejection guard; it is not described as fresh Python execution.
Affected CMS has90passed (9unit/77CMS/4KU), a selected scope distinct from the
preserved known-red strict MD5 signing suite. Strict all-target PKI Clippy passes.
Affected root signing controls4 and layer/devcycle1 also pass. Strict PKI docs
and formatting pass. Final source hashes and exact host/slot receipts are in
ready-receipt.json. Package/CMS/root/Clippy runs used vm2065 slot0; strict docs
used s7 slot0, all automatically placed by the normal wrapper.

Fresh Python evidence is separate: pinned exact test file33passed, plus12
structured graph probe records, eleven public intersection validations and ten
public transient-limit validations/ten path builds. Eighteen exploratory
transient-limit validation calls are separately labelled. The native JSON
outputs directly agree on all21 final public verdict/error/policy cases, actual
opened DER hashes for five distinct certificates, and four qualifier DER values.
`verify_native_oracle.py` reproduces those comparisons and writes
`graph-native-oracle-receipt.json`. The first parallel native log interleaved
qualifier stderr with test progress; a serial-runtime33-test rerun supplies
intact encoding receipts. It changes no compiler/job/profile/feature settings.

Reproducible commands (serial normal scheduler wrapper, HANKO_ORACLE pinned):

```sh
tools/cargo-locked.sh check -p sigis-pki-certvalidator
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python \
  tools/cargo-locked.sh test -p sigis-pki-certvalidator -- --nocapture
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python \
  tools/cargo-locked.sh test -p sigis-cms --lib --test test_cms \
  --test test_key_usage_constraints
tools/cargo-locked.sh clippy -p sigis-pki-certvalidator --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' tools/cargo-locked.sh doc -p sigis-pki-certvalidator --no-deps
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python \
  tools/cargo-locked.sh test --test pdf_diff_signing --test layering
tools/cargo-locked.sh fmt -p sigis-pki-certvalidator -- --check
```

No main/other-lane source was edited, no history rewritten, no pushes or service
operations performed. Generated Cargo.lock stays uncommitted. This graph
increment is delivered separately from the full historical S branch, preserving
all earlier typed CMS/path/time-slide and ByteRange checkpoints for L selection.

## Independent clean delivery

`graph-main8fb.patch` contains only six owned source/test files (including
replacement of the obsolete partial test file) and the bounded intersection
repair. It excludes prior CMS/horizon edits, root tests, manifests and shared
files. Artifact-only zero-fuzz application to main8fb succeeds. Applying the
separate prior horizon-consumers patch afterwards also succeeds with zero fuzz;
all thirteen composed source files equal the verified S bytes. Those application
checks establish applicability/composition, not an additional isolated native
run. L owns the merged-source gate and upstream acceptance.
