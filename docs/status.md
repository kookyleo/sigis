# Rust port status

Updated: 2026-11-13. Baseline: **pyHanko 0.38.1** (`v0.38.1`,
`580f49498f76`) and **pyhanko-certvalidator 0.33.0**
(`pyhanko-certvalidator/v0.33.0`, `b48999514cb4`).

Lane D is integrated. The complete port remains unfinished.

## Round 3 execution

The five remaining lanes are assigned in [round3/README.md](lanes/round3/README.md).
The exact immutable baseline is [ownership.json](lanes/round3/ownership.json),
with all 1,431 function IDs, owners and statuses. P/V/S/C use dedicated
`hanko/r3-*` branches and `sigis-r3-*` Codex sessions; `sigis-cx` owns L on
main. All Cargo commands use `tools/cargo-locked.sh`, which selects the
canonical target and invokes system rust-slots by absolute path. The system
owns placement/concurrency; there is no repository flock, local pin or job cap.
Automatic worker tests use the same pinned oracle runtime, now replicated and
live-smoke-verified on vm2064/vm2065. See [lock audit](lanes/round3/cargo-lock-audit.md).
At launch, the L6 `sigis-cli` shell earned no passes. The accepted scoped110
includes configuration57/plugins11/crypt23/fields7/stamps12; this20function
integration passed the complete ac1bdbc gate. The complete CLI
and port remain unfinished.
Lane reports remain provisional until the lead accepts their commits,
runs the full workspace gate and updates this document. The D gate and
worktree evidence below describe the preceding accepted snapshot.

## Accepted round 3 increments

Current accepted source: **ac1bdbc**. The full gate passed **1,760 native tests,
4 ignored, zero failed**. The immutable inventory is **1,431 total /1,259
passed /29 skipped /143 pending**. This adds P7, S/CMS1 and C/stamps12 once
each. The final section records this acceptance; prior source-specific counts
below are historical checkpoints. Complete porting and all-divergences-fail-closed
claims remain unsupported.

Main `940e04d` adds context-preserving historical timing/fetcher clones.
Two native regression tests retain non-default freshness judges, assertions,
AC targets, custom trust manager, trust/revocation material, algorithm policy
and fetcher identity. They earn no upstream function credit.

Main `0823cef` ports the two exact live TSA functions (default and explicit
HTTP session). Each fetches an actual loopback Certomancer token, verifies
integrity and no-root distrust in Rust and the fresh pinned Python oracle,
and rejects a changed imprint. This is two functions/four Python validation
calls; there are no oracle/provider early returns. The full serial workspace
build/test/clippy/strict-doc/layer/fmt gate passed. Logs and exact test counts:
`/home/l/.codex/artifacts/sigis/round3-launch/l-live-gate/`.

The accepted CMS count corrects two historical partial-pass claims to pending:
`test_overspecify_cms_digest_algo` lacked actual signer/refusal assertions;
`test_direct_pdfcmsembedder_usage` lacked low-level/buffer/DSS assertions.
The later P increment restores the overspecify function with actual signing
and refusal assertions. Direct embedder is now accepted after caller-buffer
identity, low-level, DocMDP and DSS assertions passed the combined gate. The two
earlier L completions and CMS corrections were separate accounting changes.
V now has47 accepted unique functions after the coherent AC-routing and
archival acceptance gate. Earlier provisional12/35 and intermediate45/2
snapshots below are historical evidence; both AC-dependent functions are accepted.

Main `6dc97bb` accepts the independently reviewed S primitive subset after a
second complete serial workspace gate: six name functions, five fetcher/auth
functions and two PDF typing functions, 13 unique completions from inherited
skips. No CMS known-red suite or weaker duplicate context helper was imported.
That checkpoint had accepted S824/749/67/8; eight policy-graph adapter tests
remain partial. Main33bc368 subsequently passed another complete workspace
gate. It adds P's four complete layout/resource assertion ports, credited only
to S/PDF, giving accepted S824/753/63/8. The shared algorithm-cutoff metadata
API has five native regressions but earns no upstream-function credit.

The preceding accepted gate on main dc90dce found **1,724 Rust tests: 1,720 passed, 4
ignored, zero failed**, across156 reports. Build, workspace tests, strict
clippy, strict documentation, layer/cycle checking and formatting all passed.
Logs: `/home/l/.codex/artifacts/sigis/round3-launch/s-caller-integration/gate/`.
The previous reader/CSC/P source8a1568c, S sourceb81c254 and live-fixture
sourcee476da8 also passed the complete gate.
The preceding attempt passed all tests but failed one CSC helper lint; the
fixed source then passed the complete gate again. Algorithm constraints now expose not_allowed_after;
structured policy errors preserve banned_since without parsing reason strings.
Mainc4158bd now implements and gates typed CMS enforcement, contextual path/AC
horizons, status mapping and timed-policy min(control_time, cutoff) sliding.
Permanent denial and mandatory POE/revocation remain enforced. Complete LTA
proof handling and timestamp-imprint policy remain V acceptance work; these
shared consumers alone do not establish complete timed-algorithm parity.

Main8a1568c additionally accepts P's attachment function and ten inherited
signing skips, one restored S/CMS function and L's two live CSC functions.
The CSC tests preserve all four original parameter executions, use the real
pinned Python service and production Rust automatic batches, compare 16 new
PDFs per implementation in both validators and reject empty-root trust. The
isolated CSC0.4.2/PAE0.1.0 dependencies are verified on both workers; the
shared oracle venv is unchanged. Native helpers add no upstream credit.

The shared PdfFile::reopen and MAC factory getter pass ten native regressions:
eager xref decode uses the remaining allowance before parsing, file growth
does not replenish it, strict/lossless policy and fresh caches survive, and
reused keys require unchanged Encrypt settings and permanent ID. Real password
and public-key incremental outputs retain access. Plaintext copies discard
keys. This is sequential snapshot transfer, not a global sibling budget or
a PDF MAC/integrity verdict; P/C operation consumers remain pending.

Cross-layer signer/validator callers now run in root integration tests. Four
new P suites and four previously accepted PDF-diff signing functions moved
without losing assertions or changing function ownership. Both new and old
package cycles were removed; the layer gate now also checks dev-dependency
cycles. No layer-map exemption was added.

Mainb81c254 accepts two independent S fixes with zero new upstream-function
credit. Algorithm-policy rejection now retains the actual leaf/intermediate
position and complete original path while preserving typed cutoff metadata.
Forbidden key usages are checked even when positive KU requirements are
None/empty; core defaults and EKU semantics remain unchanged. Three path-context
and five KU regressions passed, along with the complete workspace gate.
Pinned Python has the same forbidden-only early-return bug: six of26 fresh
policy cases intentionally become stricter native rejections, while20 controls
agree. This bounded difference is fail closed; it does not establish universal
conservatism for other inputs.

## Integration and verification

Lane D source is `hanko/d-sign`, original head `56af66c`. The integration
migrates the crate layout, rebases onto main while preserving both lane D
handoff sections, resolves the lockfile from main's version, verifies the
exhaustive digest matches, fixes runtime paths and aligns PNG rejection with
Pillow. It adds PDF decimal precision and trusted-list XML schema guards.
Main fast-forwarded from `1610639` to integration commit `b23462f`; the
preceding integration commit is `4648962`. Original D is preserved on
`backup/d-sign-56af66c`.

Four lane C tests now exercise Rust signing: deep fields, multiple deep
fields, non-signature field refusal and separate widget annotations.
Previously they were skipped because they never performed difference
analysis. They now pass with both Rust and live oracle validation.
Integration also fixes signature coverage to use padded `/Contents`, keeps
historical `/Encrypt` dictionaries raw, and enables Ed448 in the existing
SoftHSM signing matrix.

| Final evidence | Result |
| --- | --- |
| Workspace build and tests | Passed on D and again on main (`b23462f`) |
| Rust discovered / passed / ignored | **1,214 / 1,206 / 8**, zero failures; 95 suite reports |
| Clippy with `-D warnings` | Passed, `--workspace --all-targets` |
| Documentation with `-D warnings` | Passed, `--workspace --no-deps`, final main run `-j 1` |
| Formatting and dependency-layer check | Passed, `cargo fmt --all -- --check` and `cargo test --test layering` |
| Final integration commit and main fast-forward | `b23462f`, fast-forward from `1610639`; documentation committed afterward |
| Worktrees at D acceptance | Five old `hanko/*` lanes and `lead/d-sign-merge` synchronized to `34482bf`; clean |
| Actual oracle, SoftHSM and rendering-tool availability | pyHanko 0.38.1, certvalidator 0.33.0, Pillow 13.0.0, SoftHSM 2.6.1, `pdftoppm` and ImageMagick available |

Cargo uses the canonical target selected by `rust-target-env`. Round3 uses
system rust-slots for per-host worktree locks and automatic placement; the
old repository-wide serialization is superseded. Dependency layers follow
[crates.md](crates.md), with `cargo test --test layering` in the gate.
The integration uses local commits without pushing or restarting services.

Final main documentation and the explicit layer check used a command-scoped
empty `RUSTC_WRAPPER` to bypass a failing sccache compiler probe. The
workspace compiler wrapper, target selection, Rust flags, features and
profiles stayed unchanged; no global configuration was edited. The
existing Cargo dispatcher ran the final explicit layer check on vm2065.
Full local logs and machine-readable count audits are saved under
`/home/l/.codex/artifacts/sigis/d-integration/` (`main-*.log`,
`main-counts.json`, `upstream-counts.json`, `differential-evidence.md`).

The extra `lead-d-merge` helper had divergent history and dirty files, so
it could not literally fast-forward. Its complete history and edits were
preserved at `archive/lead-d-sign-merge-4788cac` (`6aa0043`); a fresh
`lead/d-sign-merge` branch now tracks main in that worktree. The five
regular lane branches were fast-forwarded normally.

## Upstream function counts

The release inventory contains **1,431 test functions in 55 modules**.
Parametrized functions count once. Rust test results, oracle calls,
recorded Python cases and fuzz iterations are separate measurements.
The accepted tables are computed from immutable ownership.json plus
[acceptance.json](lanes/round3/acceptance.json), using
`python3 tools/port-status.py`. Lane reports remain provisional until source
integration and the lead gate; their claimed passes are not accepted early.

| Crate / assigned test owner | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `sigis-pki-core` | 4 | 4 | 0 | 0 |
| `sigis-pki-certvalidator` | 133 | 131 | 2 | 0 |
| `sigis-pki-fetch` | 56 | 43 | 13 | 0 |
| `sigis-cms` | 78 | 78 | 0 | 0 |
| `sigis-pdf` | 406 | 395 | 11 | 0 |
| `sigis-pdf-diff` | 94 | 94 | 0 | 0 |
| `sigis-pades-sign` | 297 | 294 | 3 | 0 |
| `sigis-pades` (including `ades`) | 47 | 47 | 0 | 0 |
| `sigis-eutl` | 53 | 53 | 0 | 0 |
| **Library lanes A–E** | **1,168** | **1,139** | **29** | **0** |
| `sigis-cli`: CLI/configuration (round-3 C) | 252 | 110 | 0 | 142 |
| Lead: live integration (round-3 L) | 11 | 10 | 0 | 1 |
| **Overall** | **1,431** | **1,259** | **29** | **143** |

E's earlier 13-pass report counted two Rust wrappers for the single
parametrized upstream function `test_pades_basic_happy_path_with_tl` twice.
There are **12 unique upstream functions**, covered by 13 Rust test wrappers
and 17 recorded cases/calls. This corrects the old 1,022/316 totals to
**1,021 passed / 317 pending** without changing executed Rust results.

The four `test_key_usage_constraints.py` functions belong to `pki-core`.
Of certvalidator's 175 functions, 42 common-utils/fetch-budget/lifecycle
functions belong to `pki-fetch`, leaving 133 in `pki-certvalidator`.
The fetch crate also owns 14 TSA functions. Shared algorithms are counted
once at their owning test suite.

`sigis-ades-model`, `sigis-hanko`, `sigis-testdata`, `sigis-sign` and the
root service outside the 11 L-owned live functions have no separately assigned
upstream module in this inventory. Their shared code is covered by the owning suites or awaits
lead integration. `sigis-xmldsig`, `sigis-xades`, `sigis-cades`,
`sigis-asic`, `sigis-ooxml`, `sigis-odf` and `sigis-xsig` are XML-plan
skeletons; pyHanko baseline coverage is N/A for those crates.

### Pending work

| Owner | Pending | Functions or missing flow |
| --- | ---: | --- |
| C / CLI and configuration | 142 | Remaining signing, validation/LTV, runtime/provider and complete reader-state commands; config57/plugins11/crypt23/fields7/stamps12 are in the accepted prefix |
| Lead / live integration | 1 | Actual CLI LTA after complete C signing/LTV commands; other ten live functions are accepted |
| **Total** | **143** | |

The accepted20functions close the last eight pending library-owned callers:
seven complete P AC/signing flows and the S-owned Adobe CMS caller. Their
source-backed root tests exercise real P outputs and native V consumers with
original trust/revocation policies, plus fresh same-output pinned Python.
This does not remove the29library skips, provider parameter gaps or unassigned
feature limitations. Mandatory unsupported requirements still reject. The
separate offline Adobe RIA consumer feature is not claimed implemented.


### Skip accounting and limitations

The 29 skipped functions comprise certvalidator two, fetchers 13,
CMS zero, PDF 11 and signing three. Skip reasons remain in the
owning `PORTING.md` and lane files:

- Certvalidator retains two deprecated registry entries as skipped. All33
  exact policy-graph functions pass using actual native graph operations;
  eight former partial adapters were replaced. All six name-predicate functions
  exercise their54 exact pinned cases. Fetchers retain12 ownership/
  bootstrap gaps and one deprecated TSA alias; four lifecycle functions and
  nonsensical auth rejection are accepted.
- All four key-based digest selection parameters are accepted; CMS has no remaining skip. Weak-digest
  prevention now requires the actual MD5 signer refusal under a caller policy;
  validation replay alone does not satisfy signing assertions.
- PDF skips retain object-model/trailer gaps. The four layout/resource
  functions now execute all exact upstream assertions in the P test crate;
  they are credited once to S/PDF ownership, not again to signing.
- Both former PDF-diff skips now execute their complete native validator
  assertions and exact parameters, credited once to S/PDF-diff. No empty
  extraction wrapper or extra V function is counted.
- Signing retains three skipped functions: the deprecated Python warning
  entry point, SafeNet signing-PIN hardware and raw DSA token signing. Eight
  certificate-less flows, duplicate SET values and detached-econtent rejection
  now have complete accepted assertions. DSA binding/import work remains.

A complete functional port must revisit these exclusions, especially
provider behaviour and remaining validator compatibility; the143 pending
functions alone do not describe all remaining work.

Function-level pass counts do not prove every parameter ran. The local
SoftHSM run now covers Ed448 (the stale exclusion was removed). Providers
may lack ML-DSA, DSA or particular ECDSA mechanisms; missing SoftHSM can
cause early returns. Appearance comparisons need `pdftoppm` and
ImageMagick. Differential helpers can return early without the oracle.
The acceptance environment below had both rendering tools and the oracle;
no missing-tool early return was reported. Actual parameter exclusions
were DSA, ML-DSA and three combined ECDSA mechanism cases.

## Differential results

Reference interpreter: `/tmp/pyhanko-oracle/venv/bin/python`. Historical
committed corpus results and fresh integration runs are distinguished
below. A Python recording alone is not a passing Rust port.

| Area | Historical lane evidence | Limits |
| --- | --- | --- |
| NIST PKITS | 245/246 verdicts agree | One stricter rejection, UTCTime year 1950 (`4.2.3`); 91 path-validation diagnostic strings differ |
| OpenSSL OCSP | 29/29 agree | Includes rejection messages |
| CMS | 161/161 committed-call replays agree; a historical lane-A run reported 77 Rust tests | Calls and upstream functions are different denominators |
| PDF modification analysis | 165 recorded reviews, 982 sweep reviews, 1,308 seeded mutation verdicts agree | Extra historical seeds reported about 10,400 verdicts |
| Trusted lists | Original 18 cases agree | Signature, parsing and registry outcomes; expanded for this integration |
| AdES | 76 Python cases recorded, 144 validation calls, 98 HTTP exchanges | Historical snapshot only; current accepted assignment is47/47 |
| PDF encryption | PyHanko opens Rust-produced password/public-key encrypted files, including MAC/incremental cases | Live encryption interop requires `HANKO_ORACLE` |
| Signing | Test outputs receive Rust integrity checks and oracle PDF/CMS verification when available | No stable aggregate output count was recorded |

This integration expands trusted-list differential coverage to **22
cases**, adding four schema-invalid variants of a valid signature.
The fresh workspace run reports **22/22 agreement**, including the
original valid signature and four schema-invalid variants.

The PNG mode suite covers **eight cases**, including Pillow's rejection
of grayscale 1-bit/16-bit images and acceptance of supported indexed/RGB(A)
modes. The live Rust-versus-Pillow regression passes **8/8 cases**.

Fresh acceptance evidence (replay and oracle regeneration are separate):

| Check | Fresh result | Scope |
| --- | --- | --- |
| PDF reviews and mutation corpus | 165 recorded reviews and 1,308 seeded mutations pass | Fixed fixtures; mutations contain 518 jointly accepted verdicts |
| Production PDF parser / source | 982/982 agree, zero precision or rejection-kind differences | Actual PDF bytes and native xref history, strict and lenient |
| Generic derived source | 980 agree, two rejection-kind differences | All 982 verdicts reject/accept consistently; no fail-open |
| Live PDF oracle sweep | Matches all 982 recorded verdicts | Regenerates Python decisions for existing inputs |
| PKITS | 245/246 verdicts agree; one known stricter rejection | 73 agreeing verdicts have different diagnostic text |
| OpenSSL OCSP | 29/29 agree | Zero verdict or diagnostic differences |
| PNG/Pillow and trusted-list XML | 8/8 and 22/22 agree | Live oracle; includes newly added rejection cases |
| CMS / AdES replay | 161 CMS calls; 12 AdES functions / 17 cases / 17 calls pass | Recorded inputs; CMS replay includes the partially ported function retained as pending |
| Four unblocked C signing functions | All four pass, including their input variants | Rust integrity/trust/coverage and live pyHanko validation |
| PKCS#11 | 34 passed, two ignored; Ed448 enabled | DSA/ML-DSA and combined ECDSA parameter exclusions remain explicit |

Decimal collision and equality positive controls pass through the actual
PDF parser; normal-reader rounded caches cannot bypass the checked view.
Live PDF encryption interoperability checks 13 newly produced PDFs.
D's oracle signing assertions run
with `HANKO_ORACLE` explicitly set. Historical extra-seed fuzz results are
not relabelled as fresh regenerated runs.

Lane B's six historical fuzz targets completed 305,620 / 5,786,728 /
367,360 / 367,769 / 3,409,534 / 4,151,324 executions. Four earlier findings
were fixed or pinned by regression inputs. This integration does not
claim to repeat that fuzz campaign.

## Divergences and fail-closed scope

A historical unmerged C configuration review reproduced a real fail-open for
three unknown/misspelled policy keys: key-usage-forbiden,
require-qualified-signature and match-all-key-usage. The preserved executable
returned exit0/INTACT:TRUSTED while the fresh pinned Python CLI rejected them.
Evidence remains at
`round3-launch/c-config-review/unknown-policy-native-cli-differential.json`.
The accepted configuration prefix now rejects unknown keys and conflicting
aliases. It does not import the affected full CLI validation commands, which
remain pending under their separate trust-result holds.

The historical quoted-YAML truth discrepancy is also repaired in the accepted
configuration object: nonempty quoted no/off strings retain Python truthiness.
The earlier eight full-CLI comparisons did not prove end-to-end conservatism:
Python drops one flag and another shared default rejects the EKU adversary.
The complete validation consumers still require separate acceptance. The
accepted scoped110 prefix is independently gated; the old230/full-source proposals are not thereby
accepted, and no configuration-only assertion earns signing/validation credit.

S previously reproduced the default DSS operation accepting an oversized
object stream that Python rejects. Accepted stateful operation callers now
cover default/finite refusals and trusted-input sign/archive/DSS updates,
including encrypted continuation. These bounded resource-policy checks do not
prove every remaining-budget combination or universal trust-verdict parity.


Round-3 primitive compatibility boundaries are explicit: Rust typing rejects
the exact invalid PDF/auth inputs at compilation rather than Python runtime
exceptions. Lazy transport close releases its idle session while in-flight
requests retain an Arc until completion. The hand-written URI predicate is
used for normalized exclusions only: it rejects scheme-less references that
Python accepts and may match a malformed port that Python does not; the two
reviewed exclusion cases are stricter. Permitted subtrees still use certval.
These observations do not prove universal URI-parser conservatism or turn
resource/type-model differences into trust-verdict proofs. See the PKI audit.


The integration removes the known decimal-collision, image-mode and
schema-content leniency. Known trust-verdict differences require individual
evidence. A physically retained29b input exposed the combined-PKI discrepancy:
pre-fix native trusted/bottom_line=true versus pinned Python false under both matched
timing flags; separate-role positives pass in both. Actual input/root/binary
hashes and fresh registration traces are in [the open finding](lanes/round3/l-mixed-context.md).
That matched29b profile is repaired by the gated shared-operation registry fix;
other explicit registry scopes remain unproven, so universal parity is not claimed. The final
gate verifies exercised corpus behaviour; it does not establish safety for
every possible input. **All differences cannot be labelled fail-closed**:
semantic decoding and artifact compatibility differences below are not
trust verdicts, and have no universal conservatism proof.

- **PDF reals:** modification analysis uses an independent checked reader,
  retaining strictness, decode limits and authentication. It requires the
  exact source decimal value to
  equal the shortest decimal rendering of its `f32`; higher precision,
  collisions and overflow/underflow reject instead of rounding. Mixed
  integer/real equality uses exact decimal values. This supersedes the
  earlier acceptance of a potentially lenient modification verdict. General
  reading/encryption retain f32 compatibility; rounded caches are not reused.
  Custom `RevisionSource` implementations creating floats directly must
  enforce the same convention; lost source precision cannot be recovered.
- **XML schema:** a conservative profile checks the supported signature
  subtree's attributes, required attributes, child namespace/order/count,
  scalar/base64 content, XML whitespace, ASCII IDs/uniqueness, key values
  and consumed XAdES properties. Unsupported extensions, algorithm
  parameters, unsigned properties and Unicode IDs reject. This is narrower
  than a general XSD engine; full XML conformance remains X1 work.
- **PNG images:** Pillow-rejected grayscale 1-bit/16-bit input now rejects;
  accepted indexed 1-bit and RGB(A) 16-bit modes remain supported.
- **PKI/algorithms:** UTCTime-1950 decoding, non-FIPS DSA sizes, unsupported
  ML-DSA verification and no implicit OS trust fallback reject or reduce
  trust. ML-DSA signing checked only by the oracle is not Rust verification
  parity. Unsupported requirements must remain explicit errors.
- **Parsing/difference analysis:** bounds on nesting, references and
  integers, DER-only recipient material, stricter raw-string/type equality,
  malformed XML/certificate rejection and additional encrypted reverse
  references are conservative differences.
- **Qualification:** E's conservative policy-subset and trust-window
  workarounds remain stricter. A's full APIs now exist and E still needs
  to consume them. The `2.999` OID patch already resolves the old blocker.
- **Artifact compatibility:** producer strings, UTC timestamps,
  font/subsetting choices, narrower formats, eager key lookup and missing
  XMP signing updates are compatibility or missing-feature differences,
  not independent claims about trust. PDF PNG Sub prediction follows the
  specification where pyHanko decodes differently; name escaping and string
  serialization also differ. These are semantic/encoding differences, not
  proven conservative trust decisions. PDF key loading has a narrower
  PKCS#12/PEM scope than pyHanko (distinct from D's signing key loader).
  Mandatory timestamp seed values fail
  without a usable timestamper instead of silently losing the requirement.

Keep fail-open assertions enabled and extend adversarial oracle cases as
new algorithms, profiles and inputs become supported. No known lenient
trust-verdict exception should be silently reintroduced.

## Next parallel lanes

Root manifests, `tools/layers.json`, shared type changes, shared fixture
allocation and facade wiring remain lead-owned. Each lane owns only its
listed paths; cross-lane API changes go through L. Agents can work in
parallel with system per-host worktree locks and automatic worker placement.

| Lane | Exclusive file scope | Work and dependencies | Acceptance |
| --- | --- | --- | --- |
| P — Signing completion | `crates/pades-sign/`, D/P fixtures and owned reports | Original pending0; resolve3 documented skips (deprecated warning, SafeNet PIN, raw DSA) and audit provider parameters/evidence/state compatibility beyond original assertions | Preserve original/current caller policies, native negative controls and mandatory rejection; new helpers add0IDs |
| V — Validation / AdES | `crates/pades/`, `crates/ades-model/`, V fixtures and owned reports | All47 assigned functions accepted; implement separately tested offline Adobe RIA ingestion and audit final archival/POE, registry alias/persistence and independent trust-domain compatibility | Adobe API bottom_line=true with finalNO_POE is not final archival OK; no POE/imprint/algorithm/revocation waiver |
| S — Structural / PKI parity | Owned PDF/diff/PKI/fetch/CMS/EUTL paths and fixtures | Original pending0; review26skips (PDF11/CV2/fetch13), runtime exclusions, parser/serial/issuer and trust-boundary coverage | Port exact substantive assertions before changing skip status; no empty wrappers or universal parity claim |
| C — CLI / configuration | `crates/cli/` and C tests/fixtures | Finish142 pending unique functions, including real signing/validation/LTV, runtime, provider and complete reader-state commands; stamp12 does not import full CLI | Preserve both knownNO_POE failures and qualification trust holds; available provider wrappers do not complete18excluded parameters across6functions |
| L — Lead / integration | Root, tools, shared APIs, lockfile, central fixtures/status | Final1CLI live LTA function after accepted real C commands; coherent lane integration, parameter/skip/provenance audits, complete gates and final service replacement decision | Actual CLI/PFX/config/DSS/LTA flow, source-specific full gates, immutable counts; no service restart or early acceptance |

P, V, S and C can work concurrently within these exclusive scopes; L owns
cross-lane coordination and final acceptance. Library pending0 refers to the
assigned function inventory and does not make29skips or unassigned features
complete. State/HTTP/TSA infrastructure must not substitute for actual pending
CLI commands. The service switch from `underskrift` remains a final parity
milestone after functional/trust acceptance, not a consequence of count totals.

## Separate XML programme

The XML skeletons are outside the 1,431-function pyHanko baseline. Follow
[xml-lanes.md](xml-lanes.md): X0 imports pinned, licensed corpora and
external oracles; X1 targets zero failures on libxmlsec1/Santuario/XSW;
X2 adds XAdES/CAdES/ASiC; X3 handles OOXML/ODF. X0 can run independently;
X1 depends on its corpus, then X2/X3 follow the declared interfaces.
Upper-layer production Rust stays within the 12k-line cap. Each Office
format needs at least 50 positive and 50 negative samples plus external
POI/LibreOffice differentials before signing is enabled. The EUTL guard
added here does not claim these broader XML milestones.


## Historical unaccepted validation checkpoints

V's committed implementation proposes45/47, with two AC-fetch-dependent
functions explicitly pending. The complete package actually ran88 passes and
one retained anomalous-coverage failure; its assigned64-test run passed.
These are different scopes. The purported fresh-native runs dispatched to a
worker without the fixture-selection environment or fresh files, so they do
not yet prove native agreement with the regenerated inputs. Fresh Python
regeneration itself is valid. L supplied a supported Cargo --config env path,
worker fixture replication and native opened-path/hash receipts for a rerun.

Source review also identified a missing signature-timestamp messageImprint
policy gate before POE registration, and differing handling of a failed
document-timestamp chain. These are concrete source review findings requiring
negative oracle/native tests; no final native trust verdict is claimed from
source inspection alone. V remains unmerged. The bounded variable ByteRange
API is approved for S, with V coverage consumers and central caller tests;
nonstandard ranges must never acquire standard coverage or a trusting bottom
line. No pending function earns a pass from that approval.


The L loopback fixture now serves synthetic signer PFX and strict DER/PEM
issuer routes with bounded request counters and pinned oracle version checks.
Tests first reproduced404 for PFX; native verification then downloaded/imported
the real PFX, rejected a wrong password, signed/verified with its key, fetched
the issuer and built a path with mandatory live OCSP/CRL. Missing evidence and
empty roots reject. Both existing TSA tests still pass; the full gate passed
on e476da8. This is one native environment helper and zero upstream functions.
P's presign missing-issuer collection and V's complete LTA acceptance still
block the seven remaining live functions; the fixture alone does not close them.


Mainc4158bd additionally accepts the independently reviewed S algorithm
consumer delta, without its ancestor known-red caller suites.28 new native
regressions cover typed CMS error/cutoff propagation, original path/leaf
context, best-signature-time policy checks, timed/permanent time sliding and
OCSP_NOCHECK responder algorithm enforcement. This adds zero upstream passes.
Public time-slide comparisons agree in15 same-fixture calls;22 path/AC
validations yield19 agreements and three pinned Python AC TypeErrors caused
by unsupported denial-constructor arguments. Rust still rejects with the
typed policy error; this is exception-shape divergence, not exact AC error
parity. The bare LTV time-slide error interface retains an older path-context
limitation. CMS fresh Python signing and native harvest-fixture semantic
probes are separate inputs, not a same-fresh-bytes differential claim.


## Accepted bounded ByteRange and independent validation rerun

Maincef64d3 passed the complete workspace gate for S's Vec/slice ByteRange
interface and seven structural regressions. Complete even pairs are retained;
negative/noninteger/odd entries, overflow and out-of-file ranges reject. Total
output is capped by input length before fallible allocation, preventing repeated
range amplification. Python accepts some inputs rejected by these explicit
resource/bounds restrictions; universal helper parity is not claimed. Existing
coverage returns UNCLEAR for nonstandard cardinality and bottom line stays
false. The two S-owned complete validator functions remain skipped pending
their full consumer assertions; zero new upstream-function credit.

L independently reran V's rebased candidate on an isolated review branch with
verified frozen fresh inputs. Cargo command-line inline tables were rejected;
the corrected separate env.KEY.value/env.KEY.force arguments were verified
by an expected nonexistent-input failure, then173 native read/hash receipts
for87 unique files. The package ran99passed/2failed/0ignored. Besides the
known ByteRange case, the in_cert hash-ban case returned NO_POE instead of
CRYPTO_CONSTRAINTS_FAILURE_NO_POE. Both reject, but the original assertion
was retained. V subsequently supplied088e78d for that cause/horizon mapping.
The rerun with that fix plus accepted S ranges reached an ETSI report compile
error (fixed-array report attribute versus Vec); it is not a successful
post-fix package run. V was asked to preserve the actual range in its report
consumer. Main V12/35 acceptance remains unchanged, and the timestamp-POE
policy/control-flow review holds remain distinct. Detailed native source and
hashes are in round3-launch/v-candidate-review/.


## AC fetch extension and corrected validation evidence

Sourceeb0e43a adds backward-compatible raw-DER attribute-certificate OCSP/CRL
fetch trait methods. Defaults explicitly reject NotFound without delegating
an AC request to a certificate-only implementation. Two tests first failed
for missing methods, then verified default rejection and unchanged legacy
trait-object dispatch; the full workspace gate passed. This is an interface
extension, not completed HTTP retrieval or authenticated AC validation, and
adds zero upstream-function credit. S owns strict HTTP metadata/request/cache
and validator routing; P/V own their exact caller acceptance tests.

The isolated V candidate610806a now passes101/101 native tests, zero failures
or ignores, over verified fresh/seed/PDF-MAC inputs. Actual native receipts
check174 reads against87 distinct frozen file hashes; inputs were staged on
both workers, but the final executing host was not captured. This supersedes
the earlier99/2 result and report compile failure. Explicit Cargo runtime env
leaf arguments select these inputs; ambient-only exports were insufficient
on dispatched jobs. This is candidate-package evidence, not a main workspace
acceptance or33 additional accepted functions. V's timestamp-imprint/POE-chain
controls and two AC functions remain acceptance work. Artifacts are under
round3-launch/v-candidate-review/.

The accepted ledger remains1431/1052/66/313. Universal fail-closed parity is
not established: the independently reproduced C unknown-policy-key trusting
verdict remains a mandatory repair in unmerged source. Known accepted bounds
and forbidden-only KU differences reject more strictly; encoding/diagnostic
and source-only review findings have separate, narrower evidence.


## Accepted native policy graph

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


## Accepted caller digest policy

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


## Accepted explicit policy composition

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

The earlier C unknown-policy-key trusting verdict now has a candidate rejection
fix e19d2db with ten saved-binary fresh CLI controls. It remains unmerged;
three key-loader functions still need actual CMS integrity assertions, and
the complete CLI/qualified-validation package has not passed acceptance.
V supplied new archival-proof controls for review; the earlier independent
101-test result predates those controls. No V/C completion is booked early.


## Accepted archival validation and reports

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


## Accepted S validator coverage callers

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


## Accepted stateful signing and shared CRL trust repair

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

At the preceding03a156c checkpoint, AC HTTP source45a04d5 was unmerged,
and its DER/Name concerns were unresolved. The subsequent accepted AC retrieval
section below records their actual red/green repairs and full gate. The20-byte
serial boundary and report/time metadata limitations remain explicit; this
history must not be read as a current unmerged-HTTP or source-only Name claim.


## Accepted AC retrieval and live archival acceptance

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


## Accepted scoped CLI configuration and operations

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


## Accepted live backend lifetimes and concurrency

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


## Accepted operation callers and registry-order repair

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


## Accepted complete AC callers and standalone CLI stamps

Source `ac1bdbc404fa9ddca0a872a3bebccb0d4d2f66b4` passed all six gate
steps: build, complete workspace tests, strict Clippy, strict docs, layer/cycle
checking and formatting. Actual native totals: **1,764 discovered /1,760 passed
/4 ignored /0 failed**, across163 reports. The source-specific CLI executable
SHA-256 is `8834a8e12e68c1a0853da42bd29cddaee606e9c1def4784b4fab570d60cb97cf`;
all four actual subprocess selections use it. In-process dispatcher regressions
are separate. Both workers have byte-identical executable copies.

Accepted increment:20immutable functions/25original parameter executions,
counted once at original owners: P7/9cases, S-CMS1/2cases, C12/14cases.
The artifact `acceptance-additions.json` enumerates every exact ID and native
test. Accepted totals are:

| Owner | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| P | 297 | 294 | 3 | 0 |
| V | 47 | 47 | 0 | 0 |
| S | 824 | 798 | 26 | 0 |
| C | 252 | 110 | 0 | 142 |
| L | 11 | 10 | 0 | 1 |
| Overall | 1431 | 1259 | 29 | 143 |

The V row is its assigned AdES scope47; EUTL53/core4 retain their original S
ownership and are already included in the S824row. Do not add them again.

P's original factories sign actual AC/CAdES/PAdES outputs; root native tails
preserve all59original post-sign assertions across nine cases. The two live
functions keep both source backend variants and separate mandatory main/AC
trust. The historical LTA function validates at2028-02-01, not the signing
epoch; a genuine current2028AC response is used, and stale2020AC evidence must
not authenticate a role while the main historical signature can still recover.
Claimed group IetfAttrSyntax, certified RoleSyntax, wrong-context refusals,
missing-context None semantics and exact DSS counts remain explicit.

The producer repair captures actual lower-validator retrieval outcomes in an
operation-local adapter and publishes AC evidence atomically after successful
validation, without repeating native validation or supplying fixture responses
as context-preloaded revinfo. Configured replay responses remain labelled as
replay; fresh same-output Python calls are separate validation evidence. No
live-HTTP revocation claim follows from shared Services fixture adapters.

The Adobe original uses the real GenericPdf profile, signed RIA with the actual
AC OCSP response, five other certificates/one AC/seven total choices and full
native V LTA API status with authenticated typed RoleSyntax under separate
REQUIREpolicies. Both source backend cases require fresh same-PDF pinned
Python and real wrong-holder/untrusted-AA controls. Its original default online
capability is retained. FinalNO_POE with api_status.bottom_line=true is an
original-assertion success, not final archival OK or an offline RIA consumer
implementation. The latter remains a separate zero-ID feature/test increment.

C adds only standalone stamp implementation/dispatch plus exact12functions,
preserving all14source cases, original URL argument positions, meaningful
errors and genuine native/reference outputs. The selected executable must be
built from the coherent source. Historical141tests over owner19e4de6 lower
sources are preserved but not reused as proof of this exact candidate tree.
No runtime/validation/provider/full-CLI engine or decode-function credit is
imported by stamps12; accepted reader-state APIs already suffice.

Verified runtime evidence includes all213 V fixture opens,69 S public-input
reads,18 L live outputs, eight shared/distinct registry-context profiles, six
fresh S output verdicts, six resource-operation refusals and encrypted state
readback. P contributes nine retained outputs for seven original functions;
Adobe contributes two actual outputs for one original function. Their PDF,
root, AA and AC identities match fresh same-output Python checks. Separate
complete original Python runs passed9 P parameters and2 Adobe parameters;
source/conftest hashes remain unchanged. Fourteen standalone stamp parameter
cases also compare fresh pinned Python. Parameter cases and oracle calls earn
no additional function credit.

Evidence and machine-readable verification:
`/home/l/.codex/artifacts/sigis/round3-launch/p-c-stamp-integration/gate/`.
The earlier failed/stale-response attempts and the owner projection are
preserved separately. Native Adobe final `NO_POE` versus Python `OK` remains
an explicit stricter status/feature gap; original API bottom-line and typed
role assertions pass. No universal fail-closed or full-port claim follows.
