# Round 3 lane L progress

Status: active; lead sigis-cx. Launch commit b5bb72f.

## Counts

| Crate / assigned suite | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| root live integrations | 11 | 4 | 0 | 7 |

The four Codex aoa sessions were created in dedicated worktrees and all
reported busy at launch. Their scope and exact ownership are in the briefs.
At launch the repository flock was tested for blocking and release; the
subsequent FD audit found it unsuitable across the scheduler boundary. Main
now delegates to the absolute system rust-slots Cargo entry point, without
that repository lock or forced local/job settings. CLI skeleton, metadata,
formatting and dependency layering passed at launch. Logs and session
snapshots: ~/.codex/artifacts/sigis/round3-launch/.

## Current work

Port the two live HTTP timestamp functions first, with Rust CMS integrity
and empty-trust-root assertions plus live oracle comparisons. Build a
loopback-only Certomancer sidecar and a repeatable collected-case inventory.
The six live PAdES/backend flows depend on P/V accepted signing/LTA APIs;
the CLI live LTA case also depends on C. CSC batching is next independent
integration work. The two live timestamp functions are now accepted after the complete main gate.

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
