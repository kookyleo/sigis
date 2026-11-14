# Accepted compatibility increment: opt-in exact main-signer AdES validation

Candidate source: `3a7737ec4d882dd1620d0e4d6be852e818d19920`, based on
accepted main `7d4012b8ef6a876808c822e282cb5c0021379961`.
Root branch: `hanko/r3-l-ades-exact`; worktree: `r3-l-algorithm-api`.
The Root-only full six-stage source-specific gate and final independent
current-source/runtime review are complete. Focused results remain a separate
measurement from the full workspace test counts below.

Full workspace measurements: **2087 discovered /2084 passed /3 ignored /0 failed /212 reports**
(discovered/passed/ignored/failed/reports).
Final gate receipt/hash: **/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/gate/gate.json SHA256 1ab71f911bca89a9b1a1651bcb89944d462c7c0950fd03e4cc0d13f8cfe86291**.
Final source/runtime/review receipts and hashes:
**/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/final-gate-review.json SHA256 cf2069f0c53fca7dd3b0a5c498f2b507d3be03b609d010d4580d1947185b8b4d**.

The immutable inventory remains **1431 total /1350 passed /17 skipped
/64 pending**. C252/188/0/64, P297/296/1/0, S824/808/16/0,
V47/47/0/0, L11/11/0/0 and library1168/1151/17/0 retain prior counts.
The feature, controls, parameters, exports and oracle calls earn zero new IDs.
All331 existing acceptance overrides and immutable ownership are unchanged.
The next C qualification packet remains source planning, with zero newly
accepted originals here; current bounded default-appearance work is separate.

## Behavior and public surface

A non-exhaustive defaultable `AdesValidationOptions` exposes one optional
complete `exact_key_usage_settings` predicate. New entries are
`basic_validation_with_options`, `with_time_validation_with_options`,
`lta_validation_with_ades_options`,
`simulate_future_lta_validation_with_ades_options`, and
`validate_pdf_ades_with_options`.

Existing APIs delegate with Default/None and preserve their signatures,
individual ordinary predicate defaults, result order and status behavior.
Some forwards the five `KeyUsageConstraints` fields verbatim:
`key_usage`, `key_usage_forbidden`, `extd_key_usage`,
`explicit_extd_key_usage_required`, and `match_all_key_usages`.
None and empty KU/EKU remain distinct; no implicit NR is inserted into Some.
Only MAIN receives the exact selector. Fixed TSA purpose remains intact.
The PDF dispatcher keeps TimestampsFirst while detailed AdES paths retain
SignerFirst. Exact MAIN settings reach initial CMS/PDF validation, actual
algorithm recovery/discovery, the final historical MAIN recheck, and future
simulation. `LtaOptions`, `QualificationSpec`, trust/context/handler ownership,
revocation, freshness, algorithm and AC requirements remain unchanged.
Reports consume the same result; there is no automatic CLI opt-in.

The curated production projection changes only
`crates/pades/src/ades/{mod.rs,basic.rs,with_time.rs,lta.rs,options.rs}`.
It adds no crate edge, manifest/lock change, shared CLI provider, TSA context
or lifecycle policy. Existing mandatory qualification, crypto, coverage,
DocMDP, seed, AC, missing-POE and corrupt-imprint refusals remain constraints.
No timestamp presence, DSS membership, token genTime or algorithm cutoff
alone creates POE. An unsupported mandatory stage must reject.

## Tests first and Root current evidence

Root tests/fixtures commit `7bc621a4e8bc8ca5308387177b6fc253e5b7ffde`
precedes production commit `3a7737ec4d882dd1620d0e4d6be852e818d19920`.
The actual pre-implementation check exited101 with E0432 for the six missing
public symbols. This is genuine API unavailability, not an executed behavioral
RED. Owner d1e40fce projections and prior owner executions remain provenance;
they are not relabelled as this Root execution.

On the current Root source, the focused pades test suite passed15/15 and the
real signer caller suite passed3/3. Both input audits report zero errors.
The runs cover Default/None whole-result equality; real DS-only/empty/NR,
forbidden/any-all/EKU predicates; wrong-purpose TSA and raw signature denial;
current and historical/future validation; actual MAIN-SPKI bounded algorithm
discovery and final recheck; required qualification/revinfo/crypto/AC;
context/owner handles, missing POE, denied/corrupt timestamp imprint, and
PDF coverage/modification/seed controls. Focused tests supplement accepted
original regressions; they do not establish the full workspace gate.

Root emitted69 actual case exports. A new Root comparison of those exported
native bytes executed207 pinned validation API calls:69 exact low-level MAIN,
69 ordinary normalizing CMS, and69 public AdES. The interpreter has assertions
enabled, optimize0, pinned pyHanko0.38.1/certvalidator0.33.0 distribution
versions and module-byte receipts. There are zero exclusions and zero network
attempts in this comparison. This207-call run is distinct from the owner's
older207-call evidence. Reused older recording fixtures retain their origin;
fresh reference calls over current native exports are identified separately.

Current Root CLI product SHA256:
`479946d1f3435f26ae7c6f2d3f8d1bfe43e9315d9ad05487a0e8a3907fa61be1`,
123881832bytes, produced from this source with13 selected local units and235
input records. Both vm2064/vm2065 copies match path/hash/length/version;
distribution receipts alone do not establish VM test execution. Focused test
ELFs are retained with their explicit post-run/pre-next-build capture timing,
not claimed as run-instant identity. Root owns current full-gate execution,
measurement, retained executable/input audits and final review.

## Differential results and limits

The69 public final comparisons include68 Some-exact profiles and one
legacy-default far-future counterfactual. The68 matched Some-exact profiles have56 agreeing final results
and12 stricter native refusals. The one legacy-None control compares native
ordinary NR with unrestricted Python AdES defaults and has a different-default
result; it is not a matched exact-profile divergence. The aggregate across69
is56 agreements/13 differences, with no more-trusting native final verdict in
this measured cohort. Only the12 matched-profile refusals support the bounded
same-profile fail-closed statement; the thirteenth is a counterfactual between
different defaults. Neither establishes universal fail-closed behavior.

Ten historical and one near-future mandatory KU/EKU profiles retain native
final predicate refusals where Python recovery differs. Two far-future
profiles retain TRY_LATER: Python's simulator supplies extra last-TSA
nonrevocation/knowledge assumptions; native does not invent them. The genuine
near-future success uses collected2024 evidence and a2024-11-21 target with an
actual2020 final control context. These explicit profile/POE assumptions must
remain attached to the comparison.

Component comparisons have different stage/time/evidence and are not final
archival equivalence. Exact low-level MAIN has15 flag differences: native
trusted higher13/lower2. Ordinary normalizing CMS has33: higher27/lower6.
The ordinary facade changes the predicate, so it cannot prove exact MAIN
parity. All best signature times agree, while21 returned API-status clocks
differ. Algorithm best-signature clock and final reported control clock are
separate values; request-count or clock differences are not hidden as parity.
Optional EKU, ordinary/raw predicate and broader historical/provider profiles
remain bounded by actual evidence. These results do not establish universal
fail-closed behavior, full raw policy parity or a complete port.

## Qualified CLI interface decision and final gate

The separate [qualified CLI interface decision](c-qualified-interface-decision.md)
uses existing public detailed APIs and assigns no shared API work. Full PDF
structural metadata and final TSA qualification are not retained by the LTA
result; read-only assessment from its trusted returned path/time is available.
C must test raw API bottom line versus archival subindication explicitly.
No eight-original qualification acceptance, whole22-function suite import,
Basic fallback or ordinary revalidation is included in this cohort.

Evidence root:
`/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/`.
Stable focused receipts: `api-before-implementation-receipt.json`,
`exact-main-native-focus-receipt.json`,
`exact-main-signer-callers-receipt.json`, `oracle/fresh-comparison.json` and
its execution receipt, `executable-current-receipt.json`,
`worker-cli-copies.json`, and `focus-native-executables.json`.
Full gate and final independent review receipts are sealed below. Previous
accepted status/history and all331 override bytes remain intact.

## Sealed current receipts

- `/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/gate/gate.json`: SHA256 `1ab71f911bca89a9b1a1651bcb89944d462c7c0950fd03e4cc0d13f8cfe86291`, 957 bytes.
- `/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/gate/test.log`: SHA256 `935cb7851fbb049960bd1979c78a40753e9147459b2695e1460d9a4d2be1d129`, 9300590 bytes.
- `/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/oracle/fresh-comparison.json`: SHA256 `207edcb205775b672cd97f989843c00621097fcc9d6ff7607d3a7c14a2bb0518`, 21098202 bytes.
- `/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/oracle/fresh-comparison-receipt.json`: SHA256 `b5052b2112a93d204b0d74f73b5c8dc5f8b55c3fa80ecbbc0b18a202fd3d53eb`, 906 bytes.
- `/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/executable-current-receipt.json`: SHA256 `601f3c0a2ca2aaff4ea7d47118cd14311e40932612af79ec859b8f71ece40e3f`, 748 bytes.
- `/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/worker-cli-copies.json`: SHA256 `745167c0a8c27bf25fc5fb7fed540b1662928b6c9d8be14996972195f5e6d16a`, 755 bytes.
- `/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/focus-native-executables.json`: SHA256 `d10184803ed258b1ee952b8b86a585bcd4df6adb8dfdbc1898da9357eaf9800e`, 1130 bytes.
- `/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/exact-main-native-focus-receipt.json`: SHA256 `a54df3b53e0041a419b553306cf65bd8baf534efb01d1ed81e0624e88a80f0b6`, 819 bytes.
- `/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/exact-main-signer-callers-receipt.json`: SHA256 `45468431e2ea10df4f9c8d75fea6cbb37a5502fcf5d01dc676daa7565cfcab83`, 608 bytes.
- `/home/l/.codex/artifacts/sigis/round3-launch/ades-exact-integration/final-gate-review.json`: SHA256 `cf2069f0c53fca7dd3b0a5c498f2b507d3be03b609d010d4580d1947185b8b4d`, 5948874 bytes.

Measured stage receipts: build return0 (4.04s); test return0 (1118.92s); clippy return0 (15.3s); doc return0 (84.58s); layer return0 (3.87s); fmt return0 (3.23s).
