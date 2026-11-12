# Round 3 L interface coordination contract

Status: approved implementation requests and the shared API acceptance below; no new upstream-function pass count.
L owns integration, merged manifests/lockfile, shared APIs and final acceptance.
This contract does not transfer exclusive file or upstream-function ownership.

## P: decode limits and reopen state

L approves caller-selected `DecodeLimits` with existing defaults. Preserve the
selected limits, remaining document decode budget, authentication and strictness
through every signing, timestamp, archival-chain and DSS reopen. A fresh default
reader or a reset budget during a reopen is not acceptable. Port exact upstream
assertions before implementation and compare against pyHanko 0.38.1.

Before implementing the public surface, P must publish exact proposed Rust
signatures and defaults in `p-report.md` and notify L early: the added
`SignOptions` and `TimestampOptions` fields, the limit-aware archival-chain API,
the limit-aware DSS API, and how callers transfer remaining budget,
authentication and strictness between them. Show all argument and return types,
export paths, compatibility wrappers and a concrete signing -> archival -> DSS
caller example. No specific new P signature is represented here as delivered.
L routes any necessary shared API change; P edits only its owned paths.

S owns these exact three caller tests, confirmed in its assigned brief:

- `pyhanko/test_decode_limits.py::test_post_sign_reopen_keeps_limits`
- `pyhanko/test_decode_limits.py::test_archival_timestamp_update_keeps_limits`
- `pyhanko/test_decode_limits.py::test_add_dss_keeps_limits`

S must exercise the real P operations and limit/budget rejection assertions.
If its current report lacks the IDs, add the exact IDs above after checking the
pinned source; report discrepancies rather than inventing substitutes. Route
necessary acyclic test-only dependency requests through L.

## P, V and S: PDF MAC and inherited signing skips

P supplies PDF MAC attributes scoped to each individual signing session and
upstream-equivalent concurrent reuse rejection. S owns:

- `pyhanko/test_pdfmac.py::test_pdf_mac_pades`
- `pyhanko/test_pdfmac.py::test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel`

V supplies full LTA validation for `test_pdf_mac_pades`. P must publish concrete
session/attribute and concurrency interfaces plus negative-test evidence to L
for S/V consumption; a shared signer must not leak per-document MAC state.

P supplies complete assertions and parameter coverage for these S-owned IDs:

- `pyhanko/test_internal_utils.py::test_box_constraint_over_underspecify`
- `pyhanko/test_internal_utils.py::test_box_constraint_recalc`
- `pyhanko/test_internal_utils.py::test_resource_add_test`
- `pyhanko/test_internal_utils.py::test_duplicate_resource`

P audits all 13 inherited signing skips listed in `p.md`: exact upstream IDs,
Rust equivalent assertions or remaining gaps, provider/runtime exclusions,
parameter coverage and reproducible proof. S records the central audit; signing
implementation remains P-owned. Do not infer passing ports from source inventory.

## V: validator integrity and context preservation

V supplies substantive validator integrity and coverage proof for S-owned:

- `pyhanko/test_diff_analysis.py::test_tamper_sig_obj`
- `pyhanko/test_diff_analysis.py::test_anomalous_coverage`

Preserve every upstream mutation, coverage and rejection assertion. Removing
ignore markers from empty wrappers is not acceptance. Route the proof and exact
Rust test mapping through L to S; these functions remain S-owned.

V's existing workspace dependency `sigis-pki-fetch` in `sigis-pades` is approved
(L2 -> L0, no new version). L retains merged manifest/lockfile ownership.

The following exact V-requested signatures are available on main in `940e04d`:

```rust
impl ValidationContext {
    pub fn with_timing(&self, timing: ValidationTimingParams) -> Self;
    pub fn with_fetchers(&self, fetchers: Fetchers) -> Self;
}
```

`Fetchers` is `sigis_pki_core::fetch::Fetchers`; `ValidationTimingParams` is
`sigis_pki_certvalidator::policy::ValidationTimingParams`. S supplied an
uncommitted prototype and initial regressions. L integrated the equivalent
clone-and-replace methods with stronger regression assertions for non-default
freshness judges, nonempty assertions, custom trust managers, AC restrictions,
qualified anchors, algorithm/revocation policy, revocation material and fetchers.
Both native regression tests, crate all-target clippy with -D warnings,
strict crate documentation and formatting checks passed. These helper tests
do not add upstream function passes.

They clone the current context and replace only the named field. Preserve trust
material, freshness judges, algorithm/revocation policies, assertions, AC target
restrictions and every other caller requirement; retain unaffected handle
identity and source immutability. V may consume these accepted methods after
updating its worktree; validation feature acceptance remains separate.

V's additional `AlgorithmUsageConstraint::not_allowed_after: Option<Moment>`
request, error-horizon propagation and distinction between time-limited
`CRYPTO_CONSTRAINTS_FAILURE_NO_POE` and permanent `CRYPTO_CONSTRAINTS_FAILURE`
remain pending L triage. Do not infer a cutoff from diagnostic strings, weaken
mandatory policy tests, or claim this additional API is approved/delivered.

## Scheduling, accounting and handoff

Main `db8a75c` uses system rust-slots through `tools/cargo-locked.sh`; it has no
repository-wide flock, forced local placement or repository job cap. All four
lane worktrees were synced previously. V's shared-repository-lock wording is
stale and must be corrected. Existing old jobs/sessions stay unchanged; L owns
the fresh old-lock audit. No service restart or process killing is authorized.

Accepted unique-function counts remain P 297/271/13/13, V 47/12/0/35 and
S 824/738/80/6 (total/passed/skipped/pending). Cross-lane assistance does not add
S-owned functions to P/V counts. Python's 14 cases across three functions are
oracle evidence, not passing Rust ports. Publish exact IDs -> Rust tests,
parameters, exclusions, commands/results and evidence paths in each lane report.
Keep fixtures/replays separate from fresh live comparisons. All trust decisions
fail closed. Notify L with concrete signatures and committed, verified increments;
continue independent owned work while shared interfaces are pending.
