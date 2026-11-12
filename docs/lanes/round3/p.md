# Round 3 lane P: Signing completion

Session: `sigis-r3-p`. Branch: `hanko/r3-p`. Worktree: `/home/l/D/kooky/sigis-wt/r3-p`.
Baseline: main `34482bf`, pyHanko 0.38.1 / certvalidator 0.33.0.
Assigned unique functions: **297 total / 271 passed / 13 skipped / 13 pending**.
The exact full ownership set is every `functions[]` entry with `lane == "P"`
in [ownership.json](ownership.json): each entry has the package, module,
qualified function, pinned source line, crate and baseline status. This is
an exhaustive function list, not a glob or a count of Rust wrappers.

## Allowed paths and interfaces

Own `crates/pades-sign/**`, `docs/lanes/d.md`, and new fixtures only under
`crates/testdata/data/lanes/r3-p/**`. Retain existing D fixtures as read-only.
Own implementation review of all 13 signing skips listed below, including
certificate-less signing, duplicate attributes and provider exclusions.
S centrally records the skip review, but must request P's signing changes
through L. Audit raw DSA using current core capabilities (the old core
verification limitation is stale). Finish HTTP TSA/seed URL, AC presign/DSS,
public-key encrypted signing and attachments by consuming existing APIs.
PDF MAC signing is P-owned; S owns PDF MAC structural assertions. Expose
small stable signer hooks to L so S/V/C can consume them. V owns validation,
past/LTA and reports; coordinate those interfaces through L. Keep
`test_overspecify_cms_digest_algo` signer refusal and CMS embedder/DSS parity
in view; their baseline pass counts do not justify omitting half an assertion.

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

Write `docs/lanes/round3/p-report.md` early and keep it current. Commit
only owned files in coherent English local commits. Preserve detailed logs
under `~/.codex/artifacts/sigis/round3/p/` and include reproducible commands.
For every owned crate report `total / passed / skipped / pending` in unique
upstream functions (the sum must match the fixed assigned total), then list
changed function IDs -> Rust test names, parameters exercised and runtime
provider skips. List oracle cases/calls and verdict agreements separately
from function counts. Review inherited partial assertions honestly; report
any downgrade with evidence instead of preserving an inflated pass count.
Include divergences, exact dependency requests, commit heads and cleanliness.

For requests and a ready milestone, write the report first, then notify
only the lead with `aoa send - -s sigis-cx < docs/lanes/round3/p-report.md`.
The lead is responsible for integration; do not merge into main or rewrite
another worktree. Continue independent owned work while an interface request
is pending. On readiness, ensure owned files are committed, report any
uncommitted generated lockfile, and wait for lead rebase/acceptance feedback.

## Exact pending upstream functions

- `pyhanko/test_pades.py::test_pades_revinfo_http_ts_dummydata`
- `pyhanko/test_pades.py::test_pades_live_ac_presign_validation`
- `pyhanko/test_pades.py::test_pades_lta_live_ac_presign_validation`
- `pyhanko/test_pades.py::test_cades_signer_attrs_autofill_dss`
- `pyhanko/test_pades.py::test_cades_signer_attrs_validate_acs`
- `pyhanko/test_pades.py::test_cades_signer_attrs_validate_acs_no_claimed`
- `pyhanko/test_pades.py::test_cades_signer_attrs_validate_acs_wrong_vc`
- `pyhanko/test_pades.py::test_cades_signer_attrs_validate_acs_missing_vc`
- `pyhanko/test_seed_values.py::test_sv_timestamp_url`
- `pyhanko/test_sign_encrypted.py::test_sign_crypt_pubkey_aes256`
- `pyhanko/test_sign_encrypted.py::test_sign_crypt_pubkey_rc4`
- `pyhanko/test_sign_encrypted.py::test_copy_file_with_mdp_signature_and_backref`
- `pyhanko/test_signing.py::test_embed_signed_attachment`

## Exact inherited skip review

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
| `sigis-pades-sign` | 297 | 271 | 13 | 13 |
