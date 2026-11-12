# Round 3 lane S: Structure, PKI and skip review

Session: `sigis-r3-s`. Branch: `hanko/r3-s`. Worktree: `/home/l/D/kooky/sigis-wt/r3-s`.
Baseline: main `34482bf`, pyHanko 0.38.1 / certvalidator 0.33.0.
Assigned unique functions: **824 total / 738 passed / 80 skipped / 6 pending**.
The exact full ownership set is every `functions[]` entry with `lane == "S"`
in [ownership.json](ownership.json): each entry has the package, module,
qualified function, pinned source line, crate and baseline status. This is
an exhaustive function list, not a glob or a count of Rust wrappers.

## Allowed paths and interfaces

Own `crates/{pdf,pdf-diff,pki-certvalidator,pki-fetch,cms,eutl}/**` and
`crates/pki-core/src/{algorithms.rs,asn1/,key_usage.rs}`; own A/B/C lane docs
and new fixtures under `crates/testdata/data/lanes/r3-s/**`. Other pki-core
files, module exports and all shared type changes go through L. V owns
pades/ades-model and its E lane doc; P owns pades-sign. Finish the five PDF
and one CMS pending functions below. Coordinate decode-limit propagation,
PDF MAC signer attributes and complete AdES-LTA callers with P/V through L.

Centrally audit all 93 inherited skipped function IDs: 80 in S-owned crates
and 13 P-owned signing functions. Implement within S-owned crates; send
P-owned implementation requests through L without touching signing files.
For every skip give an exact equivalent assertion/test or a remaining
feature gap. The two PDF-diff coverage-only skips require V validator
coverage, not empty re-enable stubs. Four PDF layout/resource skips require
P-owned assertions. Audit runtime parameter skips separately. Also audit
historically partial passed CMS functions `test_overspecify_cms_digest_algo`
and `test_direct_pdfcmsembedder_usage`; report count corrections with proof.

## Operating contract

Read `AGENTS.md` if present, `docs/status.md`, `docs/crates.md`, the owning
crate's `PORTING.md`, and `docs/lanes/round3/README.md`. This is an execution
task: continue implementing and checking owned work; do not stop after a
plan or a recording-only test. Work in the assigned worktree and branch.
Use the Codex backend. Communicate in Chinese; code, documents, reports and
commit messages are English. Never mention AI tool names in commit messages.
Local commits only: no push, service restart, `pkill`, other-session kills,
or changes to old `sigis-a..e` sessions. Do not restart `aoa.service` or
`sigis.service`. Keep all unrelated work and existing services intact.

**Port tests first.** Translate the exact upstream assertions and negative
cases before implementing missing behaviour. Preserve parameter coverage;
count each upstream function once, even if split into Rust wrappers.
Recorded Python outcomes/completeness checks alone do not establish a
passing Rust port. Use mature Rust crates and the existing lower-layer APIs.
Do not weaken tests or classify an unimplemented feature as a harmless skip.

The reference is pyHanko **0.38.1** + certvalidator **0.33.0**, interpreter
`/tmp/pyhanko-oracle/venv/bin/python`; set `HANKO_ORACLE` to that path.
Pinned source trees are `/tmp/pyhanko-oracle/src/v0.38.1` and
`/tmp/pyhanko-oracle/src/cv-0.33.0`. Differentially compare meaningful
status/output/error assertions with the oracle and distinguish fresh live
oracle comparisons from committed-fixture replay. For trust decisions,
unsupported mandatory requirements reject explicitly; no verdict may be
more trusting than the oracle. Keep adversarial rejection assertions.
Report semantic/encoding compatibility differences separately; do not
claim all differences universally fail closed.

**Every Cargo invocation uses `tools/cargo-locked.sh`, including metadata,
formatting and the gate.** It holds `$(git rev-parse --git-common-dir)/round3-cargo.lock`
with `flock` across all lanes and L, then evaluates `/usr/local/bin/rust-target-env`
in the caller's worktree. All lanes share its canonical `/build/sigis/target`;
never set another target, `RUST_TARGET_OWNER`, or `--target-dir`. The wrapper
uses two build jobs and one doc job, selects the existing local slot queue,
and consistently bypasses the broken sccache probe with empty `RUSTC_WRAPPER`.
It keeps the workspace compiler wrapper and Rust flags. Do not change
`RUSTFLAGS`, `CARGO_INCREMENTAL`, profiles or feature combinations for speed.
Do not run raw Cargo, remote Cargo, `cargo clean`, or a background build.
Do not hold this lock while editing or waiting for another lane. Start with:

```sh
tools/cargo-locked.sh check -p PACKAGE
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test -p PACKAGE --test SUITE
```

The wrapper supplies job flags; do not add `-j`. Restrict checks/tests to
changed packages and affected callers. L owns the full workspace gate on
each integration. Cargo metadata spawned internally by the layer test is
already covered by the parent lock and must not re-enter the wrapper.

Root `Cargo.toml`, `Cargo.lock`, `tools/`, facades, `docs/status.md`, the
ownership manifest and other lanes' briefs are L-owned. Crate-local
manifests may use existing shared dependencies or pinned mature crates;
report new dependencies to L. A local Cargo.lock regeneration is allowed
under the wrapper, but leave it out of lane commits; L regenerates the
merged lockfile. Shared type/API changes outside the allowed paths go
through a concrete request in the lane report; do not edit the other lane.
Never relax `tools/layers.json`. Dev-dependency integration checks are
allowed if acyclic; production dependencies obey `docs/crates.md`.

## Checkpoints and handoff

Write `docs/lanes/round3/s-report.md` early and keep it current. Commit
only owned files in coherent English local commits. Preserve detailed logs
under `~/.codex/artifacts/sigis/round3/s/` and include reproducible commands.
For every owned crate report `total / passed / skipped / pending` in unique
upstream functions (the sum must match the fixed assigned total), then list
changed function IDs -> Rust test names, parameters exercised and runtime
provider skips. List oracle cases/calls and verdict agreements separately
from function counts. Review inherited partial assertions honestly; report
any downgrade with evidence instead of preserving an inflated pass count.
Include divergences, exact dependency requests, commit heads and cleanliness.

For requests and a ready milestone, write the report first, then notify
only the lead with `aoa send - -s sigis-cx < docs/lanes/round3/s-report.md`.
The lead is responsible for integration; do not merge into main or rewrite
another worktree. Continue independent owned work while an interface request
is pending. On readiness, ensure owned files are committed, report any
uncommitted generated lockfile, and wait for lead rebase/acceptance feedback.

## Exact pending upstream functions

- `pyhanko/test_cms.py::test_embed_ac_revinfo_adobe_style`
- `pyhanko/test_decode_limits.py::test_post_sign_reopen_keeps_limits`
- `pyhanko/test_decode_limits.py::test_archival_timestamp_update_keeps_limits`
- `pyhanko/test_decode_limits.py::test_add_dss_keeps_limits`
- `pyhanko/test_pdfmac.py::test_pdf_mac_pades`
- `pyhanko/test_pdfmac.py::test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel`

## Exact inherited skip review

P owns implementation for the 13 IDs marked P below; S owns the other 80.

- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_provisions_and_owns_a_backend`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_leaves_a_supplied_backend_alone`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_leaves_supplied_fetchers_alone`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_context_adopts_an_owned_backend`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_no_backend_without_fetching`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_no_backend_when_fetchers_are_unreachable`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_unreachable_fetchers_still_adopt_an_owned_backend`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_owns_the_default_backend`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_owns_the_default_backend_explicitly`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_without_fetching_owns_nothing`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_leaves_a_supplied_backend_alone`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_bootstrap_leaves_supplied_fetchers_alone`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_policy_hands_ownership_to_the_context`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_policy_without_handlers_hands_over_nothing`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_lazy_session_is_reusable_after_closing`
- [S] `pyhanko-certvalidator/test_fetcher_lifecycle.py::test_lazy_session_close_without_a_session`
- [S] `pyhanko-certvalidator/test_name_trees.py::test_dns_tree_contains`
- [S] `pyhanko-certvalidator/test_name_trees.py::test_host_tree_contains`
- [S] `pyhanko-certvalidator/test_name_trees.py::test_host_tree_contains_rejects_empty_base`
- [S] `pyhanko-certvalidator/test_name_trees.py::test_email_tree_contains`
- [S] `pyhanko-certvalidator/test_name_trees.py::test_uri_tree_contains`
- [S] `pyhanko-certvalidator/test_name_trees.py::test_uri_tree_contains_requires_fqdn`
- [S] `pyhanko-certvalidator/test_policy_graph.py::test_initial_graph`
- [S] `pyhanko-certvalidator/test_policy_graph.py::test_figure4_exact_match_shares_a_single_node`
- [S] `pyhanko-certvalidator/test_policy_graph.py::test_figure5_unmatched_policies_under_any_policy`
- [S] `pyhanko-certvalidator/test_policy_graph.py::test_figure6_any_policy_in_certificate`
- [S] `pyhanko-certvalidator/test_policy_graph.py::test_any_policy_inhibited`
- [S] `pyhanko-certvalidator/test_policy_graph.py::test_figure7_pruning_cascades`
- [S] `pyhanko-certvalidator/test_policy_graph.py::test_pruning_to_null_graph`
- [S] `pyhanko-certvalidator/test_policy_graph.py::test_duplicate_policy_oid_is_ignored`
- [S] `pyhanko-certvalidator/test_policy_graph.py::test_no_any_policy_parent_to_fall_back_on`
- [S] `pyhanko-certvalidator/test_policy_graph.py::test_no_exponential_blowup`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_mapped_node_expects_subject_domain_policies`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_mapping_under_any_policy`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_no_mapping_without_any_policy`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_inhibited_mapping_deletes_node`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_inhibited_mapping_of_absent_policy`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_inhibited_mapping_can_null_out_the_graph`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestPolicyMapping.test_inhibited_mapping_prunes_once`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_nodes_outside_the_graph`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_duplicate_node_rejected`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_size_limit_rejects_surplus_nodes`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_deleted_nodes_free_up_space`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_delete_unknown_node_is_a_noop`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_delete_node_takes_orphans_with_it`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_prune_is_not_limited_to_deepest_level`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestGraphOperations.test_ancestors_and_descendants_of_a_diamond`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_null_graph`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_zero_length_path`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_qualifiers_are_gathered_across_the_path`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_identical_qualifiers_are_deduplicated`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_only_policies_in_the_root_domain_are_reported`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_unacceptable_policies_are_filtered_out`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_no_acceptable_policies`
- [S] `pyhanko-certvalidator/test_policy_graph.py::TestUserConstrainedPolicies.test_trailing_any_policy_expands_to_user_initial_policy_set`
- [S] `pyhanko-certvalidator/test_registry.py::test_system_trust_fallback_deprecated`
- [S] `pyhanko-certvalidator/test_registry.py::test_extra_trust_roots_deprecated`
- [S] `pyhanko/test_cms.py::test_sign_weak_digest_prevention`
- [S] `pyhanko/test_cms.py::test_key_based_digest_selection`
- [S] `pyhanko/test_tsa_fetcher.py::test_deprecated_aiohttp_timestamper_forwards`
- [S] `pyhanko/test_tsa_fetcher.py::test_auth_coercion_rejects_nonsense`
- [S] `pyhanko/test_internal_utils.py::test_box_constraint_over_underspecify`
- [S] `pyhanko/test_internal_utils.py::test_box_constraint_recalc`
- [S] `pyhanko/test_internal_utils.py::test_resource_add_test`
- [S] `pyhanko/test_internal_utils.py::test_duplicate_resource`
- [S] `pyhanko/test_internal_utils.py::test_bool_dunders`
- [S] `pyhanko/test_internal_utils.py::test_ordered_enum`
- [S] `pyhanko/test_internal_utils.py::test_version_enum`
- [S] `pyhanko/test_internal_utils.py::test_name_encode_fail`
- [S] `pyhanko/test_internal_utils.py::test_pdfstring_typing`
- [S] `pyhanko/test_internal_utils.py::test_text_string_no_bytes_available`
- [S] `pyhanko/test_internal_utils.py::test_stream_pathological_encode_decode`
- [S] `pyhanko/test_internal_utils.py::test_dictionary_setvalue_guard`
- [S] `pyhanko/test_internal_utils.py::test_all_nulls_same_hash`
- [S] `pyhanko/test_internal_utils.py::test_unbound_reference`
- [S] `pyhanko/test_internal_utils.py::test_assign_non_name_to_dict`
- [S] `pyhanko/test_internal_utils.py::test_operator_literal_hash`
- [S] `pyhanko/test_xref.py::test_trailer_refs`
- [S] `pyhanko/test_diff_analysis.py::test_tamper_sig_obj`
- [S] `pyhanko/test_diff_analysis.py::test_anomalous_coverage`
- [P] `pyhanko/test_pades.py::test_cades_signer_attrs_multivalued`
- [P] `pyhanko/test_pkcs11.py::test_simple_sign_from_config_with_signing_pin`
- [P] `pyhanko/test_pkcs11.py::test_simple_sign_with_raw_dsa`
- [P] `pyhanko/test_seed_values.py::test_sign_with_sv_missing_cert`
- [P] `pyhanko/test_signing.py::test_default_validation_context_deprecated`
- [P] `pyhanko/test_signing.py::test_interrupted_with_delayed_signing_cert_mech`
- [P] `pyhanko/test_signing.py::test_interrupted_with_delayed_signing_cert_directly_specify_md`
- [P] `pyhanko/test_signing.py::test_interrupted_could_not_determine_digest_algo`
- [P] `pyhanko/test_signing.py::test_interrupted_no_estimation`
- [P] `pyhanko/test_signing.py::test_interrupted_with_delayed_signing_no_prevalidation`
- [P] `pyhanko/test_signing.py::test_determine_mechanism_no_signing_cert`
- [P] `pyhanko/test_signing.py::test_signer_info_no_signing_cert`
- [P] `pyhanko/test_signing.py::test_sign_reject_econtent_if_detached`

## Baseline by assigned crate

| Crate | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `sigis-cms` | 78 | 75 | 2 | 1 |
| `sigis-eutl` | 53 | 53 | 0 | 0 |
| `sigis-pdf` | 406 | 384 | 17 | 5 |
| `sigis-pdf-diff` | 94 | 92 | 2 | 0 |
| `sigis-pki-certvalidator` | 133 | 92 | 41 | 0 |
| `sigis-pki-core` | 4 | 4 | 0 | 0 |
| `sigis-pki-fetch` | 56 | 38 | 18 | 0 |
