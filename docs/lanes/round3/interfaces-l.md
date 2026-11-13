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

### Accepted shared reader primitive

Main8a1568c passes the complete workspace gate and delivers:

```rust
impl sigis_pdf::PdfFile {
    pub fn reopen(&self, bytes: &[u8]) -> sigis_pdf::PdfResult<Self>;
}
impl sigis_pdf::crypt::SecurityHandler {
    pub fn mac_token_handler(&self)
        -> Option<std::sync::Arc<dyn sigis_pdf::crypt::pdfmac::PdfMacTokenHandlerFactory>>;
}
```

Ten native regressions cover remaining allowance before eager xref parsing,
file growth, precision/strictness/cache isolation, actual password/public-key
authentication, nested Encrypt identity/permanent ID guards, plaintext key
removal and factory handle identity. Continue sequential operations with the
returned reader; sibling reopens hold independent snapshots. Reusing keys
does not establish output integrity or a valid PDF MAC. Unsupported identity
graphs reject within bounded traversal. These helpers earn no upstream credit.
P's operation/state/sign/stamp consumers and S/C exact callers still need
implementation and complete real-operation assertions; the helper alone does
not fix the reproduced default DSS writer limit bypass.

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

S's typed CMS enforcement, path/AC/context horizon propagation, preserved
original paths, horizon-sensitive status mapping and actual time-slide
min(control_time, cutoff) behavior are accepted on mainc4158bd after all gates. V owns typed error matching, _NO_POE versus
permanent mapping and LTA/hedging recovery with authenticated POE. The former string-based enforcement and unconditional time-slide rejection
are superseded by that accepted consumer increment; full V LTA proof handling
remains pending. Never infer cutoff dates from reason
strings, create POE from a cutoff, or weaken mandatory checks. Exact audit:
/home/l/.codex/artifacts/sigis/round3-launch/algorithm-horizon/audit.md.

## Scheduling, accounting and handoff

Main `db8a75c` uses system rust-slots through `tools/cargo-locked.sh`; it has no
repository-wide flock, forced local placement or repository job cap. All four
lane worktrees were synced previously. V's shared-repository-lock wording is
stale and must be corrected. Existing old jobs/sessions stay unchanged; L owns
the fresh old-lock audit. No service restart or process killing is authorized.

Accepted unique-function counts at main8a1568c are P 297/282/3/12,
V 47/12/0/35, S 824/754/63/7, C 252/0/0/252 and L 11/4/0/7
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


## Acyclic integration callers and remaining live flows

Root tests now host the four round3_signing cross-validator suites and four
previously accepted PDF-diff signer callers. Original function owners/counts
are unchanged. Package cycles, including dev edges, are rejected by the layer
gate. Deliver cross-layer caller patches to L for central integration when
adding the equivalent dev edge would form a cycle. Do not weaken layer rules.

All seven remaining L Certomancer functions require real V LTA results and
exact LTA_UPDATES. P must collect missing issuer certificates through the
configured fetchers for the five affected leaf-only flows; preloading the
intermediate would bypass their assertion. L owns loopback PFX and strict
DER/PEM certificate-repo fixtures and CLI harness. Exact dependencies:
/home/l/.codex/artifacts/sigis/round3/l-certomancer-next/DEPENDENCY_MAP.md.

C now proposes230/252 locally; all remain unaccepted until coherent source
review and integration. Quoted policy booleans have a confirmed configuration
object interpretation difference. Eight preserved-binary CLI comparisons did
not reproduce a more-trusting native CLI verdict (upstream CLI drops a flag
and another default rejects); do not claim a proved final CLI fail-open.
Still repair/test mandatory policy interpretation and stop labelling it only
semantic encoding. S's forbidden-only KU fix is intentionally stricter than
Python's same early-return bug and remains unaccepted until its commit/gate.


C configuration acceptance is blocked by a confirmed unknown-key fail-open:
three unknown/misspelled nested signer policy keys lead the preserved native
CLI to exit0/INTACT:TRUSTED while Python rejects exit1. Current C source drops
those keys. C must port rejection tests first, validate nested policy keys and
alias conflicts, and reject before trust evaluation. Exact reproduction and
routing: c-config-review/unknown-policy-native-cli-differential.json and
c-config-fail-open-routing.json under round3-launch artifacts. The quoted-
boolean object discrepancy is separate; its eight tested final CLI verdicts
did not demonstrate more native trust. Keep both evidence scopes explicit.


## Accepted bounded S follow-up and approved ByteRange interface

Mainb81c254 passed all six gate stages. The algorithm-failure producer now
retains actual certificate position and original path; explicit forbidden KU
is enforced independently of positive None/empty KU. Default/core EKU rules
remain unchanged. Five KU plus three path-context regressions earn no upstream
credit. Six of26 oracle cases intentionally reject more strictly than Python.
C can consume this accepted shared fix; its unknown nested policy-key hold
remains a separate mandatory configuration rejection requirement.

The bounded S signatures below are delivered and accepted on maincef64d3
after the complete workspace gate:

```rust
// sigis_pdf::signatures
pub byte_range: Vec<u64>; // EmbeddedSignature field
pub fn byte_range_data(bytes: &[u8], br: &[u64]) -> PdfResult<Vec<u8>>;
```

S owns parser/digestion and exact two-entry/bounds/odd/noninteger/negative/
overflow/resource tests. V owns coverage/status consumers; P owns signer
consumers. Do not silently truncate incomplete pairs or permit unbounded
repeated-range allocation. Nonstandard cardinality must preserve oracle
UNCLEAR/NONSTANDARD_COVERAGE and false bottom line, not gain standard coverage.
The complete caller remains centrally integrated to avoid dev cycles; IDs
stay S-owned and no pass follows from signature approval.

Fresh fixture selection on VM jobs must use explicit Cargo --config env args,
replicated exact fixture files and native actual opened-path/hash receipts.
Ambient HANKO_* selection variables are not forwarded by rust-remote. Do not
change global scheduling, force local, bypass the wrapper or equate parent
shell exports with native fresh-input proof.


## Accepted typed consumers and live fixture checkpoint

Sourcec4158bd passed the complete workspace gate:1321discovered/1313passed/
8ignored/0failed/109reports. Sourcee476da8 previously passed all gates for
PFX/AIA loopback routes and one native environment helper. No upstream count
changes: overall1431/1052/66/313, S824/754/63/7, L11/4/0/7.

Typed errors carry real cutoffs through CMS/path/AC/status. Time sliding uses
the actual cutoff minimum for timed denial and rejects permanent policies.
OCSP_NOCHECK no longer bypasses the mandatory responder certificate algorithm
query; its other prior gates remain.28 native helpers and oracle exception-
shape limitations are documented in s-algorithm-horizons.md. V/C can consume
these accepted shared changes, but V's timestamp-POE guards, fresh-native
provenance and ByteRange failure remain separate acceptance holds.


## Runtime-input syntax and report compatibility follow-up

Actual Cargo rejected inline-table CLI values (`--config env.KEY={...}`).
Use separate verified leaf arguments, for example:

```sh
tools/cargo-locked.sh test -p sigis-pades --test ades_validation \
  --config 'env.HANKO_ADES_RECORDING_DIR.value="/path/to/fresh"' \
  --config 'env.HANKO_ADES_RECORDING_DIR.force=true' -- --nocapture
```

The nonexistent-path negative and native snapshot/hash receipts established
effective input selection; see v-candidate-review/. This supersedes the earlier
unverified inline-table suggestion. It changes functional runtime inputs,
not targets/compiler flags/profiles/features or scheduler placement.

V's unmerged report constructor still assigns Vec to a fixed-array attribute.
Adapt the report field/renderer/tests to preserve every actual pair, or prove
and explicitly reject an upstream-required standard-only format. Never pad,
truncate or invent four values for a nonstandard input. V owns this consumer;
source088e78d and its new contract regression also need a complete actual
package rerun against the accepted S range interface. No V pass is accepted
from the compile-failed attempt.


## Accepted AC fetch defaults and verified V report compatibility

Sourceeb0e43a passed build/test/strict clippy/strict docs/layer/fmt, with
1330discovered/1322passed/8ignored/0failed/109reports. The raw-DER methods
OcspFetcher::fetch_ac_ocsp(&self, ac_der: &[u8], issuer: &Cert) and
CrlFetcher::fetch_ac_crls(&self, ac_der: &[u8]) default to NotFound; they never
silently dispatch AC input to legacy PKC methods. Two new compatibility
helpers earn zero upstream credit. S owns pki-fetch common/fetchers and
certvalidator revinfo OCSP/CRL routing per the AC handoff; core fetch traits
remain L-owned. Retrieval still requires strict identity, shared limits,
separate AC cache keys and authenticated/authorized/fresh revocation evidence.

The independent V rerun on610806a (including088e78d, accepted S ranges and
20ea444 report adaptation) passed101 native tests,0failed/ignored,15reports.
174 native read/hash receipts cover87 distinct frozen inputs; files exist on
both workers, with no final executing host claimed. This supersedes the
historical compile-failed rerun above. The source-level POE policy/chain
controls, two AC functions and full merged workspace gate remain separate
requirements. No V or overall upstream count change. Use verified separate
Cargo env.KEY.value/env.KEY.force leaf arguments for runtime selectors.


## Native graph accepted after full integration

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


## Caller digest policy accepted

Source c69886c passed all six workspace stages: 1363 discovered,
1355 passed, 8 ignored, zero failed, 110 reports. The one exact
S/CMS-owned test_sign_weak_digest_prevention changes skipped -> passed. P's
function count is unchanged. Digest selection now asks a supplied caller
policy at current signing time before explicit-digest mechanism resolution.
Tests require actual MD5 Signing refusal, zero mechanism calls under explicit
denial, a permitted intact native signature and preserved no-VC preparation.
All four native tests require fresh pinned Python operation probes. The three
additional controls add no upstream IDs; no-VC MD5 preparation is not a claim
that full weak signing is permitted by a supplied policy.

Accepted CMS78/75/1/2; S824/788/29/7; overall1431/1086/32/313.
Key-based digest selection remains skipped pending its full assertion port.
Direct embedder remains pending until the coherent borrowed-buffer runtime
and callers pass integration; the independent borrowed API review alone
earns no pass. Larger P reader/MAC consumers and V LTA remain unaccepted.
Logs: round3-launch/p-digest-policy-gate/; independent source review:
round3-launch/p-borrowed-buffer-review.md.


## Explicit policy composition accepted

Source f91dccd passed all six workspace gates: 1375 discovered,
1367 passed, 8 ignored, zero failed, 111 suite reports. The
lead first reproduced six actual failures with two positive controls using
the existing public API: a materialized empty policy intersection validated
successfully, and a zero-issued path returned wildcard instead of its finite
policy. The repaired12-test suite passes, including high-level validation,
clone/mutation/replacement, composition algebra and caller/anchor controls.
Related library/policy tests also pass. These are supplemental regressions,
not new immutable upstream functions; overall stays1431/1086/32/313.

PkixValidationParams retains its legacy Vec input (empty means wildcard) and
adds user_initial_policy_constraint: Option<BTreeSet<ObjectIdentifier>> as
an additional conjunction. None/anyPolicy means wildcard; Some(empty) permits
no policies. effective_user_initial_policy_set() returns the combined meaning.
replace_user_initial_policy_set(&mut self, Option<BTreeSet<ObjectIdentifier>>)
deliberately replaces both inputs. Legacy field mutation alone cannot erase
a computed merged restriction. Public merge/anchor composition preserve empty
sets; zero-issued paths still apply final policy wrap-up with anchor context.
Certval policy denial remains denial, including when native replay succeeds.

Existing Default/struct-update callers remain compatible. Adding a public
field can break external exhaustive struct literals; this source compatibility
limit is explicit. No dependency, layer exception or build setting changed.

The lead freshly executed10 pinned Python public validations over the same
three NIST certificate files with SHA256 receipts. Python's asymmetric empty
set plus anyPolicy helper can restore P1: the native fix intentionally retains
empty constraints instead. In the mandatory case native rejects more strictly;
in the optional case it returns no qualified policy. Other finite/default and
zero-issued controls retain their assertions. Do not label all10 calls exact
agreements or infer universal fail-closed parity. Evidence and independent
source review are under round3-launch/policy-merge-api/.


## Archival validation and reports accepted

Source df25c79 passed all six workspace gates: 1462 discovered /
1454 passed / 8 ignored / zero failed, across126 reports.
V is now47/45/0/2:33 originally pending unique functions are accepted once.
All47 immutable IDs and76 source parameters were audited; two AC-dependent
functions remain pending authenticated fetched evidence. S foreign caller
wrappers and additional security helpers earn no V function credit.

The actual lead workspace run used explicit Cargo env leaf arguments, not
ambient selection. All212 native read receipts match lengths/SHA256 for102
actual files:87 selected frozen inputs (three AdES recordings,78 seed files,
six PDF-MAC files) and15 committed repository inputs. Receipts identify s7 /
s7.0 for this run; owner vm2064.1 and the earlier isolated101-test result
are different runs. The pinned Python recordings were freshly regenerated
earlier; replaying them here is not another fresh Python execution.

Atomic document-timestamp candidate evidence publishes only when the entire
chain passes. A forbidden signature-timestamp imprint cannot add POE, lower
best time or lower qualification time through a retained report token. The
previous source/provenance/ByteRange holds are closed by reviewed fixes and
this actual merged gate. Independent review of owner810d417 is recorded in
v-proof-policy-fix-review.md; all133 owned source/test/fixture bytes match it.
The lockfile adds only two existing workspace edges, with no version changes.

Three supplemental denied-imprint cases reject more strictly than pinned
Python's final OK. A corrupt chain agrees on final NO_POE but reports native
best time2024 versus Python2020. Report encoding/layout and complete XML schema
identity remain outside smoke assertions. Do not call all differences either
identical or universally fail closed. Accepted overall1431/1119/32/280;
P/S/C/L counts unchanged. Exact evidence: round3-launch/v-integration/.


## Stateful signing and core CRL repair accepted

The coherent P runtime source0054aee passed all six gates, then source03a156c
passed the combined gate after closing a newly reproduced shared CRL defect:
1535 discovered / 1527 passed / 8 ignored / zero failed,
across136 reports. Five P functions become passed (seed HTTP URL,
HTTP TSA/revinfo, two public-key signing modes and the signed plaintext copy).
The exact borrowed-buffer CMS function becomes passed once under S/CMS, with
original Vec identity retained through both signing and DSS continuation.
No renderer/state/MAC helper or oracle call adds an upstream-function count.
P297/287/3/7; CMS78/76/1/1; S824/791/27/6; overall1431/1127/30/274.

Caller-selected reader options, decode snapshots and authentication now flow
through signing/DSS/timestamps/stamps and borrowed operations. Session-local
MAC state rejects concurrent shared-signer reuse; caller-buffer failure paths
are staged atomically. The legacy post-parse set_strict method is still a
separate declared compatibility gap. Complete five S PDF callers and seven
P AC functions remain pending; component MAC proof is not whole-function LTA
acceptance. The lockfile adds one existing pki-fetch edge, no version change.

The shared CRL failure was real: a stack shortcut accepted an invalid signature.
L's independent direct verify_ac_crl/full validate_ac tests first failed twice
while the genuine control passed, using a different existing fixture from P's
original ambiguous loop. Actual AC/AA/good/bad/TBS/algorithm SHA receipts match
fresh pinned Python bytes. The fix exempts only issuer certificate path recursion;
every current CRL still requires signed_by. Existing nonrecursive path/signature
order, scope, key usage, freshness, reasons, delta and later policies remain.
Three fixed tests exercise require and soft-fail; eight fresh same-input public
Python decisions and197 existing CV tests pass. Helpers earn zero unique credit.
The prior reference also has a narrower active-path shortcut; this bounded
repair is not a universal claim of lexical equivalence or all-input trust parity.
Evidence: round3-launch/ac-crl-recursion/ and p-integration/.


## AC retrieval and live archival acceptance

Source 7500fc7 passes all six workspace gates: 1578 discovered,
1570 passed, 8 ignored, zero failed, 142 reports.
The two earlier gate failures remain recorded: stale V AC replay/cache controls
and a real CSC batching race. Neither was hidden by a skip or weaker assertion.
Current counts: V47/47/0/0, L11/6/0/5; overall1431/1131/30/270.

AC retrieval now shares production transport limits, caches and actual-AA
request identity with PKC retrieval, and routes actual AC DER to its methods.
Strict metadata envelope checks reject nonminimal headers before I/O. Serial
INTEGER contents remain capped at20 encoded bytes; arbitrary-length serials
are not supported. The response matcher uses the signed AC issuer Name DER
and actual AA key hash. Eight genuinely signed Name variants agree with the
pinned public validator, including three positive controls. A proposed matcher
first accepted an oracle rejection; that candidate was corrected before merge.
Fetched/cached CRLs still require the accepted03 signature guard. Required and
hard-fail policies reject forged signatures; explicit soft-fail can tolerate a
separate unavailable provider as the pinned policy does. It is not evidence
that a forged CRL is authenticated or that all modes reject every bad response.

V's complete remaining two original functions pass after its recorded AC
adapter gains actual AC request binding. The adapter uses production fetchers
over frozen responses with full CertID selection; it is not new live HTTP.
The signature-mutation control creates a new fetcher from changed records,
so an earlier cached genuine response cannot mask the intended negative input.
S's real loopback HTTP composition and its repeated-cache rejection controls
are separate evidence. No helper, recording, parameter or oracle call earns
an extra immutable function.

The context non_revoked_status_assertions getter returns an immutable borrowed
view of existing caller state. Six tests and two compile-fail doctests retain
order/hash/time/clone/security requirements and actual strict revocation
matching. Successful optional validation does not invent an assertion. The
accessor changes no default, policy, field or trust verdict and earns no ID.

L completes strict live issuer fetching and both full-chain/leaf-only base
cases. Their three new PDFs receive real native LTA, exact LtaUpdates and fresh
same-output Python LTA; empty roots reject. Leaf-only signing requests the
exact downloaded leaf through a forwarding real certificate fetcher before
validation, rather than relying only on a shared TSA issuer-URL count. The
two exact upstream functions independently pass all three original executions.
CSC automatic batches now stop admitting jobs when full and bind commit to
their original batch; retained-result/public-commit semantics remain tested.
The existing three batch/authorization-count parameters remain unchanged.

All divergences cannot be labelled fail-closed. Bounded serial/metadata refusals
are stricter, but explicit optional-revocation policy, report/time metadata and
other declared semantic/encoding gaps are not universal trust proofs. A separate
combined ECC/RSA test context has a retained native/Python validation discrepancy
under colliding synthetic issuer/serial identities. Using role-specific contexts
for the exact upstream test does not repair that registry/path-selection gap.
It remains under independent diagnosis, rather than being relabelled fail-closed.
Unmerged CLI code remains outside acceptance; three configuration loader functions still
need their exact CMS intact/valid assertions despite a raw-signature control.
Detailed red/green logs, oracle outputs, public byte hashes and independent
reviews are retained under round3-launch/s-ac-combined and round3/l-certomancer-next.


## Scoped CLI prefix acceptance

Source 09ec130 passes all six workspace gates: 1706 discovered,
1698 passed, 8 ignored, zero failed, 150 reports.
Only the reviewed standalone prefix is integrated: configuration57, native
plugin registration/identity11, encryption/decryption23 (including two exact
decode-limit functions), and field management7. The98 immutable IDs and original
parameters are in crates/cli/INCREMENT_PARAMETERS.md and PORTING.md. Other154
CLI functions stay pending; later full-source restoration and its known runtime
or trust-result failures are not imported by this acceptance. No function was
ignored, removed from its inventory, or counted from an empty wrapper.

Three configuration loader functions previously had only raw-signature checks.
They now sign the independent SHA256 digest of Hello world! through the actual
production CMS builder and verify its unique SignerInfo with the loaded
certificate, expected data OID and original digest. Intact and valid must both
hold; a changed expected digest must fail integrity. The focused44 native
configuration tests pass. Four retained native CMS/certificate output cases
received eight fresh pinned Python integrity decisions with matching actual
input hashes. The fourth missing-passphrase function is not counted twice;
it already had complete original loading/refusal assertions. CMS integrity
does not establish certificate trust or CLI signing-command coverage.

The scoped CLI package has128 passed native tests, zero failures/ignores.
Cargo copied its actual ELF into an immutable artifact directory while holding
the build lock. Producer source 09ec130, ELF SHA256 ffc61fff25eacf12cd8f57b67fb6767e9729a6a7efaa5cffd36b22e064738c69,
88102784bytes. Same-path copies on both workers match SHA/version.
Explicit test-only Cargo env selectors chose that executable for every actual
CLI subprocess; its hash is unchanged before/after the full gate. Canonical
targets, compiler flags/profiles/features, sccache and automatic placement are
unchanged. Artifact copy uses the existing nightly Cargo artifact-dir facility.

The existing scoped tests freshly execute17 configuration oracle cases,
36 crypt CLI comparisons plus18 artifact checks, and10 field oracle calls.
The independent loader output comparison adds eight integrity decisions;
these are separate measurements, not new unique functions. Plugin reference
evidence is historical source execution; native11 tests exercise registry/help
and typed identity behavior, using native endpoint interfaces rather than
importing Python modules. They do not execute a signing engine. Field tests
use real lower-layer signing to check occupied fields; they do not establish
a trusted PDF signature. No runtime provider exclusion was added.

PKCS11 commands, other signing/stamping/runtime/validation/LTV functions,
complete reader-state callers and final CLI LTA integration remain pending.
Unsupported commands and mandatory requirements reject explicitly. Known
unmerged CLI trust failures and the retained combined-PKI registry discrepancy
still prevent any universal all-divergences-fail-closed claim. This is a scoped
98-function acceptance, not completion of the252-function CLI or full port.

Accepted C252/98/0/154; overall1431/1229/30/172. Detailed source/binary/fixture
hashes, independent assertion reviews, actual test selectors and full logs:
round3-launch/c-prefix-integration/ and round3-launch/c-prefix-review/.

## Accepted operation-local certificate registration

Source dc90dce passes all six workspace gates. The additive API
`ValidationContext::with_registered_other_certs` clones complete security state
and registers caller candidates, explicit roots and incoming candidates with the
existing first-issuer/serial-wins store. All trust anchors remain configured.
General `with_other_certs` and `with_revinfo` retain their existing behavior.

CMS private helpers carry this owned state through actually visited timestamp
validation into main validation only for the same original context identity.
Explicit independent contexts, including equal-valued clones, stay independent;
callers are never mutated. Registration remains after raw validity/algorithm
checks and before path/imprint trust, and never creates POE or trust anchors.
Eight frozen-input profiles and seven security/registration guards are gated.

This is not a cross-call mutable validation session or an AC-alias/fetched-store
parity claim. See [acceptance](l-s-callers.md) and [counterexample](l-mixed-context.md).


## Accepted AC capture and complete callers

Source ac1bdbc passed the complete workspace gate with root P7 and Adobe CMS callers. Native AC outcome capture delegates one validation and publishes an operation-local evidence journal only after the complete batch succeeds. Full caller context/security requirements, NoCheck/OCSP-CRL rules and issuer-name guards are preserved. Root tests retain separate main/AC trust, exact typed attributes and the2028 current/stale provider controls. Adobe finalNO_POE versus PythonOK remains a separate RIA/POE consumer feature gap, not a reason to weaken status classification. No new shared dependency or layer exemption was added. Details: l-ac-stamps.md.


## Source-correct main revalidation

The current source45a8b44 and both local vendor dependencies pass the complete repeated workspace gate with content-based source checking. The two-key Cargo configuration and wrapper downgrade guard preserve the canonical target, system scheduler and sccache. Prior mtime reuse and the first retry's dependency-hash failure are preserved;391 compiler-unit observations/2411 input records/381 source files independently match Git main45. This restores the existing inventory only, with no new function credit. See l-source-freshness.md; future cache races and build-script mtime inputs are not universally proven safe.
