# Round 3 lane L progress

Status: active; lead sigis-cx. Launch commit b5bb72f.

## Counts

| Crate / assigned suite | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| root live integrations | 11 | 10 | 0 | 1 |

The four Codex aoa sessions were created in dedicated worktrees and all
reported busy at launch. Their scope and exact ownership are in the briefs.
At launch the repository flock was tested for blocking and release; the
subsequent FD audit found it unsuitable across the scheduler boundary. Main
now delegates to the absolute system rust-slots Cargo entry point, without
that repository lock or forced local/job settings. CLI skeleton, metadata,
formatting and dependency layering passed at launch. Logs and session
snapshots: ~/.codex/artifacts/sigis/round3-launch/.

## Current work

Complete the final live function: actual CLI LTA with complete C commands.
Lazy lifetime, concurrent signing and both requests backend flows are accepted. Strict fetchers and both
full/leaf-chain cases are accepted, alongside TSA and CSC. Continue scoped
P/S/C/V integration, caller assertions and trust/registry compatibility audits.
Actual tests/gates and immutable function ownership remain authoritative.

## Integration contract

Accept S primitive increments, then P signer hooks, V LTA/report consumers,
and complete C commands. Independent increments may merge sooner. Rebase
and fast-forward only; run the full locked workspace gate after each merge
and reconcile unique-function status centrally. Keep old sessions and
services unchanged. No push or service restart.

## Shared historical validation API

ValidationContext::with_timing and with_fetchers clone the complete context
and replace only the requested field. L integrated S's initial design and
strengthened its native regressions to use non-default security state.
Both context tests, crate all-target clippy -D warnings, strict crate docs
and package formatting passed. No upstream function count is added.

The old wrapper's FD 9 could be replaced by rust-slots slot acquisition.
Other bypass paths could retain it; a lane PATH putting rustup Cargo first
was found. The launcher now uses the absolute system scheduler entry point.
See cargo-lock-audit.md and context-clone-api artifacts. No build was killed.
The immutable live baseline was 11/0/0/11; accepted main is now 11/2/0/9.
Earlier queued runs and unvalidated drafts were not used as passing evidence.

## Live TSA acceptance

Main0823cef passes the full serial build/test/clippy/strict-doc/layer/fmt gate.
The exact upstream default-session and explicit-session functions exercise
actual loopback HTTP and compare correct/wrong imprint verdicts against the
pinned oracle. Accepted2, pending9; four Python validation calls are not four
functions. Worker oracle replicas passed real loopback smoke checks.

The accepted ledger also downgrades two historically partial CMS passes;
overall counts therefore remain1431/1021/93/317 until further lane acceptance.
The immutable ownership baseline is unchanged. See acceptance.json and
python3 tools/port-status.py for reproducible counts.

## S primitive acceptance

Main6dc97bb integrates only the reviewed fetch/name-policy/PDF subset and
passes the complete serial workspace gate. Accepted13 formerly skipped
functions, no CMS source known-red suite. Policy graph8 adapters remain
partial and count0; stronger main context tests remain intact. Accepted
S824/749/67/8, overall1431/1034/80/317. See acceptance.json for exact IDs.

## Shared algorithm API and P layout acceptance

Main33bc368 passed all six workspace gates. Five native cutoff/error API
regressions retain typed metadata, permanent defaults and error identity;
actual timed-policy CMS/LTA recovery remains S/V-owned and pending. Four
S-owned layout/resource functions pass all28 exact assertions in P's test
crate and count once. Accepted S824/753/63/8, overall1431/1038/76/317.
Latest Rust1249 discovered/1241 passed/8ignored/0failed across99 reports.


## C caller requests and independent L work

C reports a local202/252 checkpoint; none is accepted before committed source,
assertion review and the full gate. L extended the interface contract to
PdfUpdate construction, field additions and standalone stamps: preflight is
insufficient, and remaining budget/authentication/strictness must reach real
reads. P received the consumer request. S received the forbidden-only key
usage investigation/repair request and a reservation for L's minimal shared
reader primitive and MAC factory getter. Receipts:
round3-launch/c-interface-routing-20261113.json.

L is reviewing P's external PdfFile::reopen proposal, adding independent
central regressions before implementation. The snapshot model supports
sequential state transfer; it does not promise a global budget across sibling
operations. Independent CSC live integrations are being ported against the
actual pinned Python CSC service, with isolated test dependencies and actual
Rust PDF signing/trust verification. No helper, draft or oracle call adds an
upstream pass before acceptance. No new Cargo gate has started yet.


## Accepted reader, CSC and independent P increment

Main8a1568c passed build/test/clippy-Dwarnings/strictdocs/layer/fmt. Latest
Rust1284discovered/1276passed/8ignored/0failed/107reports. A preceding full
test run passed but clippy rejected a CSC helper fixed-size chunk lint; the
corrected source then passed all stages again. Logs: reader-csc-p-gate-final/.
Accepted unique functions: overall1431/1052/66/313; P297/282/3/12;
S824/754/63/7; L11/4/0/7. V/C acceptance unchanged. Exact14function overrides
are in acceptance.json; native helpers earn0.

The two CSC functions preserve every original batch tuple and authorization
count, use the actual pinned Python CSC service, generate16PDFs per language,
validate both origins in both implementations, and reject empty-root trust.
Optional CSC0.4.2/PAE0.1.0 dependencies are isolated and verified on all hosts;
shared oracle venv unchanged. Four P cross-validator suites and four old
PDF-diff signers now run centrally; all assertions/owners retained. The complete
package graph is acyclic and the layer gate checks dev cycles too.

PdfFile::reopen and the public MAC factory getter pass10native regressions.
The remaining-budget snapshot reaches eager xref parsing; key reuse checks
raw nested Encrypt identity and permanent ID; plaintext copies drop keys.
Real password/pubkey updates retain access. This does not create shared
sibling allowance or a MAC verdict. P/C real-operation consumers are pending.

All seven remaining Certomancer functions require complete V LTA. Exact
AST/assertion/dependency preparation is in round3/l-certomancer-next/. P must
fetch missing issuers for leaf-only inputs; L still needs PFX/AIA routes.
C now proposes230local passes but is unaccepted. Independent quoted-policy
configuration review found an object interpretation risk; eight real CLI
comparisons did not show more native trust. Fix and review remain C-owned.
S metadata/KU follow-up is independently reviewed, not yet integrated.


Independent C review also reproduced a distinct actual fail-open: three
unknown nested policy keys are ignored by native CLI (exit0/INTACT:TRUSTED)
but rejected by fresh Python CLI (exit1). C source remains unmerged and
accepted0/252; exact evidence/routing are recorded. C must reject unknown keys
and alias conflicts before trust. No claim that all differences fail closed.


## S bounded shared follow-up acceptance

Mainb81c254 passed the complete six-stage workspace gate:1292discovered,
1284passed,8ignored,0failed,108reports. Certificate-position rejection retains
leaf/intermediate context/full path/typed cutoff; forbidden-only KU now checks
explicit bans before the positive None/empty early return. Core defaults/EKU
remain unchanged. The six stricter Python-vs-Rust cases among26 fresh controls
are documented; zero new upstream credit, counts1431/1052/66/313 unchanged.

S's old baseline report was treated as historical. No unverified candidate,
dirty CMS/time-slide source or archived known-red caller was merged. FD/slot
lifetime audit was already complete; no historical build was killed/restarted.
V45/47 remains provisional: retained package failure, fresh native provenance
gap and source-level POE policy findings were routed for tests-first repairs.
L prepared loopback PFX/AIA fixtures with eight Python smoke groups only in
artifacts; no new live-function credit or main fixture change yet.


## L PFX/AIA environment acceptance

Sourcee476da8 passed all six workspace gates:1293discovered/1285passed/
8ignored/0failed,108reports. PFX firstfailed404, then nativeproduction
PKCS12keyimport/signverify/AIAissuerlookup/requiredlivepath+negativecontrols
passed with both existing TSA variants. Eight separatePythonpreflightgroups
are environment evidence. Zero upstream credit; L4/7and overallcountsunchanged.
ActualPFX/DER/PEMfixturesbindonlyloopback; requestmetricsbounded; no shared
venvorservicesmodified. Logs round3-launch/l-pki-routes/.


## S typed-consumer acceptance

Sourcec4158bd passed all six gates:1321discovered/1313passed/8ignored/0failed,
109reports. Independent28nativehelpers add0upstreamcredit; overall and per-
lane accepted function counts are unchanged. Typedcutoffs/status/context,
actualmin(control,cutoff) sliding, best_signature_time andmandatoryNOCHECK
responderpolicyquery are delivered. Oracle15timeSlideagree;22path/ACcalls
19agree/3PythonTypeErrors are reported explicitly. Old bareLtvErrorcontextgap
and fullVproof-policy work remain. No ancestorredCMS/caller source imported.

C is preparing policy-schema/CMSsanity fixes but has no accepted CLI pass.
Both workers now have exact CLI source + isolated platformdirs/pkcs11 extras;
sharedvenvunchanged. AmbientHANKO/PYTHONPATHmustuseexplicitCargo--configenv
forVM testselection, with actual nativepath/hashreceipts, not parentexports.


## Bounded range acceptance and verified V candidate inputs

Sourcecef64d3 passed all6gates:1328discovered/1320passed/8ignored/0failed,
109reports; seven structural helpers0upstreamcredit. Main coverage already
accepts slices and refuses standard coverage for cardinality!=4. Exact bounds,
order, empty/even pairs and capped repeated-range allocation are documented
in s-byte-range-report.md; both S validator functions remain unaccepted.

Isolated V review3348da0 on V0d95fd6 verified90frozen source files on both
workers, negative missing-path selection and173nativehashreceipts/87unique
opened files. Actualpackage99pass/2fail; class mismatch and range parser were
reported without weakening assertions. After V088e78d and Scef64d3, the review
candidate failed at report ByteRange type compilation; V owns compatibility
repair. No V integration/count change. All inputs remain preserved in the
v-candidate-review artifact directory; main worktree stays clean.


## AC default-interface acceptance and corrected V package rerun

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


## Complete validator coverage callers accepted

The lead independently reviewed both exact pinned validator functions against
validator_integrity.rs. test_tamper_sig_obj retains all three default/no-changes/
skip-diff assertions, including suspicious/absent diff and OTHER coverage result.
test_anomalous_coverage retains all four real-file parameters, native valid/
intact/distrust, exact coverage, false bottom line and NONSTANDARD_COVERAGE.
Positive and explicitly trusted-CMS facade controls prevent vacuous distrust.
The lead freshly revalidated the same committed/native input bytes in pinned
Python: nine validation calls, seven original parameter cases, two functions.
This is fresh oracle execution over existing inputs, not new signature creation.
The existing complete workspace gate on df25c79 passed all these native wrappers;
no source changed for this accounting increment and no gate repeat is needed.
Only two immutable S/PDF-diff skips become passed; no V credit or wrapper count.
PDF-diff94/94/0/0; S824/790/27/7; overall1431/1121/30/280.
The five PDF integration functions, including real MAC signing callers, remain
pending. Logs: round3-launch/s-coverage-acceptance/ and v-integration/gate/.


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
At that historical checkpoint the CLI was outside acceptance. The later scoped
CLI prefix below supplies the exact CMS intact/valid and changed-digest assertions.
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


## Live backend acceptance

Source `8819a77c424f1d5b0f40a423d8d5191fae3824e0` passes build, workspace tests, clippy with -D warnings,
strict documentation, dependency layering/cycles and formatting. Native gate:
1710 discovered / 1702 passed / 8 ignored /
0 failed, 152 reports. The four new immutable IDs are:

| Exact upstream function | Rust target / test | Original executions | Produced PDFs |
| --- | --- | ---: | ---: |
| test_requests_fetchers_happy_path | live_pades / requests::test_requests_fetchers_happy_path | 2 (strict True/False) | 2 |
| test_requests_fetcher_backend_happy_path | live_pades / requests::test_requests_fetcher_backend_happy_path | 2 (strict True/False) | 2 |
| test_async_lazy_session | live_pades_lazy / test_async_lazy_session | 1 | 1 |
| test_async_sign_many_concurrent | live_pades_concurrent / test_async_sign_many_concurrent | 1 | 10 |

All IDs belong to integration-tests/test_live_certomancer.py. Unique functions
count once. The focused three-target run passes six native tests, including
the previously accepted strict/base functions. Its eighteen real output PDFs
have independently recomputed native/Python PDF/root hashes; fifteen PDFs
belong to the four new functions. Every produced output receives real native
AdES LTA OK, intact/valid/trusted, exact StandardDiffPolicy LtaUpdates, fresh
pinned Python0.38.1/CV0.33.0 same-output LTA and empty-root distrust.
The complete workspace gate separately repeats these checks and retains its
own eighteen PDF outputs and actual hashes. Nothing is counted from replayed
verdicts, a reader-only test or an unavailable provider.

Requests explicit construction retains three independent blocking production
HTTP fetchers with ten-second request limits and literal permit_pem=strict.
Backend construction ignores the original strict parameter exactly as upstream
does. Its close method is a pinned upstream no-op; dropping only the facade
while retained real fetcher handles remain usable preserves that contract.
The unique eager setup client is out of scope before signing. Leaf-only flows
must forward the exact downloaded signer-leaf DER and perform actual AIA HTTP
before native/Python validation; no static issuer or manual prefetch substitutes.

The lazy case drops the unique real setup client before publishing closure.
Independent real production LazyTransport factories for fetchers and TSA each
remain uncreated before closure, then create exactly one actual Reqwest client
during signing. Default async-backend timeout10 and setup/TSA/new validation
timeout5 are retained. A fresh eager validation session is opened after signing.
This establishes resource-owner release, not immediate kernel socket teardown.

Concurrency uses one sidecar/session and the same Arc signer, context/fetchers
and production TSA across ten distinct PdfSigners/readers/writers/outputs.
A start barrier launches the jobs; the completion channel retains the original
index and the actual Sig1 Reason suffix for every completed output. It does
not wait for ten callbacks at one TSA/cache stage or impose a completion order.
Nonblocking telemetry measured ten actual sign calls in flight in the focused
run; the full gate measured 10. Each output independently
passes the full native/Python checker and empty-root controls.

The exact pinned original Python functions independently pass six parameter
executions and their original checker validates all fifteen generated PDFs.
Actual outputs/root DER, source/function hashes and original completion/index
assertions are preserved. The original lazy path emits four unclosed aiohttp
warning headers; run.log retains them. They are not hidden or relabelled as
native failures. No oracle venv package, source function or trust policy changed.

The gate selects a Cargo-produced immutable CLI ELF from this exact source:
SHA256 b7ac8de6226a30d0800510bbc72169b07088fa64da1640b282c015a9e2d7a24c. Its before/after hash and three actual
selection records agree, including identical worker copies. The213 actual V
fixture-open receipts are independently checked against bytes/lengths on their
recorded paths. Canonical target, sccache and system placement are unchanged;
no other job/session, service, target flag, profile or feature was changed.

Accepted root11/10/0/1; overall1431/1233/30/168. Remaining L function is
test_pades_lta_live_with_cli and requires complete real C signing/LTV commands.
Library counts, C98/252 and existing skips are unchanged. Known combined-PKI
registry/path-selection and encoding/model compatibility limitations remain
open; these successful controls do not establish universal fail-closed parity.

Evidence: /home/l/.codex/artifacts/sigis/round3/l-next/ (all-native-v1/, upstream-v1/, independent audits,
executable-v1-receipt.json, gate/gate.json and runtime-verification.json).

## PDF caller and registry acceptance

Source `dc90dceee5f0ce7d8287019e1b15eae923ea8ee2` passes build, workspace tests, clippy -D warnings, strict docs,
dependency layering/cycles and formatting. Native gate: 1724 discovered,
1720 passed, 4 ignored, zero failed, 156 reports.
Actual immutable CLI SHA256 2ea48b6911c1d2b4fa57d433aeeb5bfbc84e453cec64735dab05f277ca86f153; three selected
paths and before/after hashes agree, including both worker copies. The213 actual
V file opens and 69 S input reads are independently
recomputed against bytes/lengths. Compiler flags/profiles/features, canonical
target and configured sccache remain unchanged. All Cargo uses system slots.

Six immutable S-owned IDs are completed, counted under their original crates:

| Function | Crate | Original parameter executions |
| --- | --- | ---: |
| test_key_based_digest_selection | sigis-cms | 4 |
| test_post_sign_reopen_keeps_limits | sigis-pdf | 2 |
| test_archival_timestamp_update_keeps_limits | sigis-pdf | 1 |
| test_add_dss_keeps_limits | sigis-pdf | 1 |
| test_pdf_mac_pades | sigis-pdf | 1 |
| test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel | sigis-pdf | 1 |

The selector uses real decoded RSA2048/P384/Ed25519/Ed448 public keys and all four
expected digests; the exact original function independently passes four reference
executions, plus four same-SPKI public API comparisons. It does not require or
claim CMS signature generation. The ten focused caller tests include meaningful
supplemental controls, not ten upstream functions.

Three decode originals use the valid same oversized stream fixture through real
signing, archival-chain and DSS operations. Both post-sign timestamp placements,
exact timestamp/certificate/no-VRI assertions and unchanged original input are
retained. Default/finite limits reject inside each operation. Public operation
errors are typed HankoError::Malformed with the exact PdfDecodeLimitError prefix;
the downstream reader rejects with PdfError::DecodeLimit directly. This error
representation distinction is not falsely described as a typed Hanko DecodeLimit.
An authenticated lenient sign->archive->DSS continuation preserves password access,
strictness and a decreasing shared budget, then rejects the final oversized read.

MAC PAdES uses actual encrypted signing, real HTTP TSA tokens bound to the session,
MAC Successful/ISO32004 and full native V AdES LTA with the original policy. Exact
native/Python outcome is NO_POE with API bottom_line=true, not final AdES OK.
Concurrent reuse leaves bytes_reserved=None: the real estimator holds the MAC
lease while a second actual operation on the same PdfSigner refuses with the
original conflict text; the first operation and subsequent reuse succeed.

All six actual gated ordinary/MAC output PDFs receive fresh pinned Python checks
with actual fixed native root DER hashes recorded before parsing. Regenerating an
ECDSA fixture can change DER signature bytes; the initial root-pin preparation
failure is preserved and earns no success. The fixed original native roots are
used by the final comparisons. A seventh encrypted state output receives fresh
plaintext/two-timestamp readback. Six real Python default/finite operation denials
are PdfDecodeLimitError. The unchanged L suites independently validate eighteen
actual gated PDFs in native/Python, including empty-root denials and concurrency.

The actual retained29b shared-context more-trusting counterexample is repaired
in this source. Eight profiles match pinned Python: implicit/explicit shared
context refuses main trust; distinct equal-valued/separate-root contexts remain
trusted, under both timing flags. Main integrity/validity and TSA trust remain.
CMS carries an owned operation-local registry through visited timestamps then
main validation; first issuer/serial registration wins. Caller contexts remain
unchanged; independent role contexts and operations stay isolated. All original
anchors/policies/assertions/freshness/timing/AC restrictions/fetcher identities
survive. General with_other_certs remains a separate DER-deduplicating API.

Four real-token private CMS tests prove raw-invalid and algorithm-denied tokens
do not register, raw-valid wrong-imprint tokens register without trust, and a
later unvisited raw-valid token cannot register an extra genuine public cert.
The latter has a direct trusted/registered positive. Three context tests preserve
restrictive nondefault security state, collision order/independent operations and
both qualified anchors/custom-manager identity. These add zero upstream IDs.

Four stale empty ignored placeholders are removed with references to the actual
root MAC/V coverage tests; no empty wrapper is enabled or counted. Existing
diagnostic/provider/documentation ignores remain distinct from function counts.

Accepted S824/797/26/1: CMS78/77/0/1, PDF406/395/11/0. Overall1431/1239/29/163;
P297/287/3/7, V47/47/0/0, C252/98/0/154, L11/10/0/1 unchanged.
Remaining S function is Adobe AC revinfo with complete producer/full-LTA RoleSyntax
assertions; P must publish genuinely fetched AC material, without a fixture preload
shortcut. The separate offline Adobe RIA consumer is a production feature gap,
not an invented original-function offline requirement. The26 S skips remain.

The29b fix does not prove universal registry or fail-closed parity: AC-context
aliasing, persistent mutation across separate public calls, independently fetched
candidate registration and custom-manager root enumeration/order retain explicit
scope limits. Old overwritten7075 is not retroactively recovered. Other model,
encoding, resource and provider differences remain documented; no complete-port
or all-divergences-fail-closed claim is made. Evidence: /home/l/.codex/artifacts/sigis/round3-launch/s-caller-integration/ and
round3/l-next/mixed-*/ (actual pre-fix RED, fresh profiles, source reviews and units).