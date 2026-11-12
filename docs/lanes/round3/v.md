# Round 3 lane V: AdES and validation

Session: `sigis-r3-v`. Branch: `hanko/r3-v`. Worktree: `/home/l/D/kooky/sigis-wt/r3-v`.
Baseline: main `34482bf`, pyHanko 0.38.1 / certvalidator 0.33.0.
Assigned unique functions: **47 total / 12 passed / 0 skipped / 35 pending**.
The exact full ownership set is every `functions[]` entry with `lane == "V"`
in [ownership.json](ownership.json): each entry has the package, module,
qualified function, pinned source line, crate and baseline status. This is
an exhaustive function list, not a glob or a count of Rust wrappers.

## Allowed paths and interfaces

Own `crates/pades/**`, `crates/ades-model/**`, `docs/lanes/e.md`, and new
fixtures under `crates/testdata/data/lanes/r3-v/**`. Existing E fixtures are
read-only. S owns `crates/eutl`; all pki-core shared types (including
`pki-core/src/ades.rs`) and public type changes outside these two crates
are requested through L. Finish past/time/LTA/POE/revinfo, qualification,
seed values, reports and validation requests using A/B/C/D interfaces.
P owns signer/timestamp generation and S owns structural/PKI primitives.
Start with the existing recordings but add substantive Rust calls and all
upstream assertions, fresh mutation/rejection cases and necessary local
HTTP services. Keep the 12 already covered functions as regressions; the
13 Rust wrappers are not 13 unique upstream functions.

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
formatting and the gate.** It evaluates `/usr/local/bin/rust-target-env` in
its caller's worktree and delegates concurrency, per-host worktree locking
and placement to the system `rust-slots` Cargo wrapper. Check/test/clippy
may run on vm2064/vm2065 through automatic `rust-remote` dispatch. Do not
invoke remote Cargo directly or force local placement. The repository adds
no global flock or job limit. Keep canonical target selection: never set
another target, `RUST_TARGET_OWNER`, or `--target-dir`. System worker target
selection is owned by `rust-remote`; do not override it. Preserve configured
sccache, workspace compiler flags, profiles and features. Do not run raw
Cargo, clean the shared target, or start an unmanaged background build.
See [cargo-scheduling.md](cargo-scheduling.md) for the cache probe repair.
Start with:

```sh
tools/cargo-locked.sh check -p PACKAGE
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test -p PACKAGE --test SUITE
```

Let rust-slots supply concurrency; do not add job flags for speed. Restrict
checks/tests to changed packages and affected callers. L owns the full
workspace gate on each integration. Internal Cargo metadata children are
non-compiling scheduler pass-throughs; no repository lock is needed.

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

Write `docs/lanes/round3/v-report.md` early and keep it current. Commit
only owned files in coherent English local commits. Preserve detailed logs
under `~/.codex/artifacts/sigis/round3/v/` and include reproducible commands.
For every owned crate report `total / passed / skipped / pending` in unique
upstream functions (the sum must match the fixed assigned total), then list
changed function IDs -> Rust test names, parameters exercised and runtime
provider skips. List oracle cases/calls and verdict agreements separately
from function counts. Review inherited partial assertions honestly; report
any downgrade with evidence instead of preserving an inflated pass count.
Include divergences, exact dependency requests, commit heads and cleanliness.

For requests and a ready milestone, write the report first, then notify
only the lead with `aoa send - -s sigis-cx < docs/lanes/round3/v-report.md`.
The lead is responsible for integration; do not merge into main or rewrite
another worktree. Continue independent owned work while an interface request
is pending. On readiness, ensure owned files are committed, report any
uncommitted generated lockfile, and wait for lead rebase/acceptance feedback.

## Exact pending upstream functions

- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_happy_path_with_tl`
- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_fail_qualification_requirements`
- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_non_qtst_tsa_fail`
- `pyhanko/test_ades_validation.py::test_embedded_cades_with_time_non_qtst_tsa_pass`
- `pyhanko/test_ades_validation.py::test_pades_lta_happy_path_current_time`
- `pyhanko/test_ades_validation.py::test_pades_lta_happy_path_past_time`
- `pyhanko/test_ades_validation.py::test_simulate_future_lta_happy_path`
- `pyhanko/test_ades_validation.py::test_simulate_future_lta_happy_path_eseal`
- `pyhanko/test_ades_validation.py::test_pades_lta_fail_qualification_requirements`
- `pyhanko/test_ades_validation.py::test_simulate_future_lta_happy_path_with_ts_chain`
- `pyhanko/test_ades_validation.py::test_simulate_future_lta_no_revinfo_fail`
- `pyhanko/test_ades_validation.py::test_simulate_future_lta_with_broken_ts_chain`
- `pyhanko/test_ades_validation.py::test_pades_lta_expired_timestamp`
- `pyhanko/test_ades_validation.py::test_pades_missing_dts`
- `pyhanko/test_ades_validation.py::test_pades_lta_happy_path_past_time_with_chain`
- `pyhanko/test_ades_validation.py::test_pades_hash_algorithm_banned_but_poe_ok`
- `pyhanko/test_ades_validation.py::test_pades_lta_hash_algorithm_banned_and_no_poe`
- `pyhanko/test_ades_validation.py::test_pades_lta_algo_permaban`
- `pyhanko/test_ades_validation.py::test_pades_lta_live_ac_validation`
- `pyhanko/test_ades_validation.py::test_nontraditional_hybrid_lta`
- `pyhanko/test_ades_validation.py::test_nontraditional_hybrid_lta_with_failed_timestamp`
- `pyhanko/test_ades_validation.py::test_pades_multi_sig_timestamp_algo_hedge_ok`
- `pyhanko/test_ades_validation.py::test_pades_multi_doc_timestamp_algo_hedge_ok`
- `pyhanko/test_ades_validation.py::test_pades_multi_sig_timestamp_with_unknown_digest`
- `pyhanko/test_ades_validation.py::test_content_ts_with_different_digest_not_supported`
- `pyhanko/test_ades_validation.py::test_bootstrap_handlers_default_backend`
- `pyhanko/test_ades_validation.py::test_certificate_fetching_rule_matrix`
- `pyhanko/test_ades_validation.py::test_never_fetch_certs_keeps_revinfo_fetching`
- `pyhanko/test_ades_validation_report.py::test_pades_basic_report_smoke_test`
- `pyhanko/test_ades_validation_report.py::test_pades_basic_failing_report_smoke_test`
- `pyhanko/test_ades_validation_report.py::test_pades_basic_indeteriminate_report_smoke_test`
- `pyhanko/test_ades_validation_report.py::test_pades_lta_report_smoke_test`
- `pyhanko/test_ades_validation_report.py::test_pades_with_attributes_report_smoke_test`
- `pyhanko/test_ades_validation_requests.py::test_pades_basic_happy_path_requests`
- `pyhanko/test_ades_validation_requests.py::test_pades_lta_happy_path_current_time_requests`

## Baseline by assigned crate

| Crate | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `sigis-pades` | 47 | 12 | 0 | 35 |
