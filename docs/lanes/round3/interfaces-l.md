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

The same requirement applies to `PdfUpdate::{new,fresh}`, field additions and
standalone text/QR stamp APIs requested by C. A bounded CLI preflight does not
make an unbounded internal parser safe; every real downstream read must inherit
the selected policy/state. Compatibility entry points keep existing defaults.
C owns its eight remaining decode-function assertions; S retains the three
caller IDs below. P owns signing/stamp/update implementations. L owns the
shared reader primitive and coordinates its acceptance with S.

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

The shared `AlgorithmUsageConstraint::not_allowed_after: Option<Moment>` API
and `ValidationError::DisallowedAlgorithm { msg, banned_since }` are accepted
in main33bc368 after the complete workspace gate. Both existing constraint
constructors default to None. Error display/class/hierarchy remain unchanged;
certificate/AC/time-slide producers retain actual typed cutoffs and still reject.
Five native regressions and seven constraint/three Python error property cases
cover this helper API; they are not full algorithm-validation function ports.

S owns typed CMS enforcement, path/AC/context horizon propagation, preserving
original failure paths, horizon-sensitive status mapping and actual time-slide
min(control_time, cutoff) behavior. V owns typed error matching, _NO_POE versus
permanent mapping and LTA/hedging recovery with authenticated POE. Existing
string-based CMS enforcement/permanent mappings and rejecting time-slide
semantics remain pending consumer work. Never infer cutoff dates from reason
strings, create POE from a cutoff, or weaken mandatory checks. Exact audit:
/home/l/.codex/artifacts/sigis/round3-launch/algorithm-horizon/audit.md.

## Scheduling, accounting and handoff

Main `db8a75c` uses system rust-slots through `tools/cargo-locked.sh`; it has no
repository-wide flock, forced local placement or repository job cap. All four
lane worktrees were synced previously. V's shared-repository-lock wording is
stale and must be corrected. Existing old jobs/sessions stay unchanged; L owns
the fresh old-lock audit. No service restart or process killing is authorized.

Accepted unique-function counts at main62a72a2 are P 297/271/13/13,
V 47/12/0/35, S 824/753/63/8, C 252/0/0/252 and L 11/2/0/9
(total/passed/skipped/pending). The acceptance ledger is authoritative; lane
working-copy counts are proposals until review and the workspace gate pass. Cross-lane assistance does not add
S-owned functions to P/V counts. Python's 14 cases across three functions are
oracle evidence, not passing Rust ports. Publish exact IDs -> Rust tests,
parameters, exclusions, commands/results and evidence paths in each lane report.
Keep fixtures/replays separate from fresh live comparisons. All trust decisions
fail closed. Notify L with concrete signatures and committed, verified increments;
continue independent owned work while shared interfaces are pending.


## C: caller policy and independently reviewable increments

C reports 202/252 functions locally verified; no C implementation is accepted
yet. L retains merged manifests/lockfile ownership. Existing workspace CMS,
PDF-diff and EUTL dependencies are permitted in the CLI layer; no dependency
layer change is approved. Submit coherent owned commits, exact function IDs,
parameter/provider exclusions and fresh same-output oracle evidence before
claiming accepted counts. CLI subprocess tests must use their Cargo-produced
executable, protected from another worktree overwriting the shared binary.

C reports a forbidden-only KU constraint gap in the shared validator. S owns
the lower-layer investigation and substantive regression/repair, preserving
None versus explicit-empty usage semantics. CLI must continue enforcing
mandatory negative policies until the shared implementation is accepted. V
owns qualified AdES/LTA results; unsupported mandatory qualification must
reject before network or output, rather than silently run basic validation.
