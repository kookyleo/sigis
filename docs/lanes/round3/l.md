# Round 3 lane L: Integration and final acceptance

Session: `sigis-cx`. Branch: `main`. Worktree: `/home/l/D/kooky/sigis`.
Baseline: main `34482bf`, pyHanko 0.38.1 / certvalidator 0.33.0.
Assigned unique functions: **11 total / 0 passed / 0 skipped / 11 pending**.
The exact full ownership set is every `functions[]` entry with `lane == "L"`
in [ownership.json](ownership.json): each entry has the package, module,
qualified function, pinned source line, crate and baseline status. This is
an exhaustive function list, not a glob or a count of Rust wrappers.

## Allowed paths and interfaces

Owner is the current lead `sigis-cx`; no separate L session or worktree.
Own root application/manifests/lockfile, `tools/**`, facades (`hanko`, `xsig`,
`sign`), testdata support and central fixtures, consolidated status and the
round-3 baseline/briefs. P/V/S/C exclusively own their listed implementation
paths; apply cross-lane type/export changes centrally and publish concise
interface contracts. Own the 11 exact live integration functions below.
Build a repeatable central Certomancer export/pytest collected-case inventory
and fresh local-service integrations; preserve upstream assertions and both
backend/parameter variants. Do not switch or restart the running services.
Any future backend switch remains an acceptance milestone, not a restart.

Merge small ready changes in dependency order: S primitives/limits first,
P signer hooks next, V complete LTA/report consumers next, C command paths
last; independent commits may arrive earlier if their dependencies already
exist. Rebase the lane onto current main, resolve shared files as lead,
run targeted checks, then `git merge --ff-only` locally. After each merge
run the full gate below and update exact counts in `docs/status.md`;
coordinate rebase/lockfile updates and notify consumers. Never cherry-pick
uncommitted work or hide a test regression behind a skip. Keep lane reports,
Python/Rust fixture-vs-live evidence and final all-worktree state reviewable.

```sh
tools/cargo-locked.sh build --workspace
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test --workspace
tools/cargo-locked.sh clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' tools/cargo-locked.sh doc --workspace --no-deps
tools/cargo-locked.sh test --test layering
tools/cargo-locked.sh fmt --all -- --check
```

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

Write `docs/lanes/round3/l-report.md` early and keep it current. Commit
only owned files in coherent English local commits. Preserve detailed logs
under `~/.codex/artifacts/sigis/round3/l/` and include reproducible commands.
For every owned crate report `total / passed / skipped / pending` in unique
upstream functions (the sum must match the fixed assigned total), then list
changed function IDs -> Rust test names, parameters exercised and runtime
provider skips. List oracle cases/calls and verdict agreements separately
from function counts. Review inherited partial assertions honestly; report
any downgrade with evidence instead of preserving an inflated pass count.
Include divergences, exact dependency requests, commit heads and cleanliness.

For requests and a ready milestone, write the report first, then notify
only the lead with `aoa send - -s sigis-cx < docs/lanes/round3/l-report.md`.
The lead is responsible for integration; do not merge into main or rewrite
another worktree. Continue independent owned work while an interface request
is pending. On readiness, ensure owned files are committed, report any
uncommitted generated lockfile, and wait for lead rebase/acceptance feedback.

## Exact pending upstream functions

- `integration-tests/test_live_certomancer.py::test_pades_lta_live`
- `integration-tests/test_live_certomancer.py::test_async_sign_many_concurrent`
- `integration-tests/test_live_certomancer.py::test_async_lazy_session`
- `integration-tests/test_live_certomancer.py::test_async_strict_cert_fetchers_happy_path`
- `integration-tests/test_live_certomancer.py::test_requests_fetchers_happy_path`
- `integration-tests/test_live_certomancer.py::test_requests_fetcher_backend_happy_path`
- `integration-tests/test_live_certomancer.py::test_pades_lta_live_with_cli`
- `integration-tests/test_live_certomancer.py::test_ts_fetch_default_session`
- `integration-tests/test_live_certomancer.py::test_ts_fetch_aiohttp`
- `integration-tests/test_live_csc_dummy.py::test_simple_sign_with_dummy`
- `integration-tests/test_live_csc_dummy.py::test_implicit_batch_sign_with_dummy`

## Baseline by assigned crate

| Crate | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `sigis` | 11 | 0 | 0 | 11 |
