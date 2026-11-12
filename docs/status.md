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
The launch adds the L6 `sigis-cli` application shell; it earns no new passes.
Lane reports remain provisional until the lead accepts their commits,
runs the full workspace gate and updates this document. The D gate and
worktree evidence below describe the preceding accepted snapshot.

## Accepted round 3 increments

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
and refusal assertions. Direct embedder now has low-level/DocMDP/DSS coverage
but remains pending because caller-buffer identity is still absent. The two
earlier L completions and CMS corrections were separate accounting changes.
The 12 inherited V functions remain the accepted baseline. V's proposed45/47
checkpoint remains unaccepted. The independent corrected-input rerun now
passes101 native tests after the range/report and policy-classification fixes;
LTA proof-policy controls and coherent workspace integration remain required.

Main `6dc97bb` accepts the independently reviewed S primitive subset after a
second complete serial workspace gate: six name functions, five fetcher/auth
functions and two PDF typing functions, 13 unique completions from inherited
skips. No CMS known-red suite or weaker duplicate context helper was imported.
That checkpoint had accepted S824/749/67/8; eight policy-graph adapter tests
remain partial. Main33bc368 subsequently passed another complete workspace
gate. It adds P's four complete layout/resource assertion ports, credited only
to S/PDF, giving accepted S824/753/63/8. The shared algorithm-cutoff metadata
API has five native regressions but earns no upstream-function credit.

The latest gate on main c69886c found **1,363 Rust tests: 1,355 passed, 8
ignored, zero failed**, across 110 reports. Build, workspace tests, strict
clippy, strict documentation, layer/cycle checking and formatting all passed.
Logs: `/home/l/.codex/artifacts/sigis/round3-launch/p-digest-policy-gate/`.
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
| `sigis-cms` | 78 | 75 | 1 | 2 |
| `sigis-pdf` | 406 | 390 | 11 | 5 |
| `sigis-pdf-diff` | 94 | 92 | 2 | 0 |
| `sigis-pades-sign` | 297 | 282 | 3 | 12 |
| `sigis-pades` (including `ades`) | 47 | 12 | 0 | 35 |
| `sigis-eutl` | 53 | 53 | 0 | 0 |
| **Library lanes A–E** | **1,168** | **1,082** | **32** | **54** |
| `sigis-cli`: CLI/configuration (round-3 C) | 252 | 0 | 0 | 252 |
| Lead: live integration (round-3 L) | 11 | 4 | 0 | 7 |
| **Overall** | **1,431** | **1,086** | **32** | **313** |

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
| A / CMS | 2 | `test_embed_ac_revinfo_adobe_style`; borrowed-buffer identity for `test_direct_pdfcmsembedder_usage` (low-level/DSS assertions now execute) |
| B / PDF | 5 | Three decode-limit propagation tests after signing, archival timestamp and DSS updates; two PDF MAC/PAdES signer integration tests |
| D / signing | 12 | Eight PAdES HTTP-TSA/AC presign/DSS-attribute tests; one seed-value TSA URL; three public-key encrypted-signing/copy tests |
| E / AdES | 35 | 28 validation functions, five report functions and two request functions; past/LTA/POE/revinfo and report integration |
| Lead / CLI and configuration | 252 | Signing, validation, encryption, fields, stamps, plugins, configuration and runtime suites |
| Lead / live integration | 7 | Seven Certomancer functions, all requiring actual LTA validation; missing-issuer fetching and loopback PFX/AIA routes also remain |
| **Total** | **313** | |

D integration makes the signer and seed model available to dependent
callers. A already supplies HTTP TSA, AC validation, trust qualifiers,
qualified policies and LTV primitives; B supplies DSS, embedded files,
encryption and incremental writing. These dependencies now exist, but
pending callers still need implementation, error mapping and substantive
upstream assertions. PDF MAC signing and complete AdES-LTA are remaining
implementation gaps rather than tests to simply unignore.

### Skip accounting and limitations

The 32 skipped functions comprise certvalidator two, fetchers 13,
CMS one, PDF 11, PDF-diff two and signing three. Skip reasons remain in the
owning `PORTING.md` and lane files:

- Certvalidator retains two deprecated registry entries as skipped. All33
  exact policy-graph functions pass using actual native graph operations;
  eight former partial adapters were replaced. All six name-predicate functions
  exercise their54 exact pinned cases. Fetchers retain12 ownership/
  bootstrap gaps and one deprecated TSA alias; four lifecycle functions and
  nonsensical auth rejection are accepted.
- The remaining CMS skip is key-based digest selection. Weak-digest
  prevention now requires the actual MD5 signer refusal under a caller policy;
  validation replay alone does not satisfy signing assertions.
- PDF skips retain object-model/trailer gaps. The four layout/resource
  functions now execute all exact upstream assertions in the P test crate;
  they are credited once to S/PDF ownership, not again to signing.
- The two retained PDF-diff skips concern anomalous coverage and in-place
  signature-object tampering, checked before modification analysis.
  Validator coverage must retain those behaviours.
- Signing retains three skipped functions: the deprecated Python warning
  entry point, SafeNet signing-PIN hardware and raw DSA token signing. Eight
  certificate-less flows, duplicate SET values and detached-econtent rejection
  now have complete accepted assertions. DSA binding/import work remains.

A complete functional port must revisit these exclusions, especially
provider behaviour and shared policy-merge semantics; the313 pending
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
| AdES | 76 Python cases recorded, 144 validation calls, 98 HTTP exchanges | Only 12 unique assigned AdES functions currently ported in Rust |
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

An unmerged C configuration review reproduced a real fail-open for three
unknown/misspelled nested signer policy keys: key-usage-forbiden,
require-qualified-signature and match-all-key-usage. A preserved Cargo-produced
CLI executable returned exit0/INTACT:TRUSTED for the signed PDF; the fresh
pinned Python CLI rejected each configuration (exit1). The reviewed C commit/executable
silently ignored the unknown keys. C is preparing a source/test repair; it
remains unaccepted. L blocked CLI integration and routed
tests-first unknown-key/alias rejection before trust evaluation. Evidence:
`round3-launch/c-config-review/unknown-policy-native-cli-differential.json`.
These unmerged divergences are not fail closed; no CLI pass is accepted.

A separate configuration risk: quoted nonempty
YAML strings such as no/off can be coerced to false, weakening match-all KU
or explicit-EKU requirements relative to Python truthiness. Fresh pinned
oracle cases and the native source consumption path establish the discrepancy;
Eight comparisons using C's preserved Cargo-produced CLI executable did
not show a more trusting native CLI verdict: the Python CLI itself drops
one policy flag and another shared default rejects the EKU adversary. This
does not repair the configuration-object discrepancy. L blocked CLI acceptance
and routed the policy interpretation/regressions to C. The proposed230 CLI passes remain
unaccepted; this is not merely an encoding difference.

S also reproduced the current default DSS operation accepting an oversized
object-stream input that Python rejects. The native default reader rejects,
but a CLI preflight or shared reopen helper does not fix P's internal writer.
This observed resource-policy gap remains P-owned and is not a trust-verdict
parity proof. Selected-limit/budget/authentication operation callers stay pending.


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
schema-content leniency. Retained known trust-verdict divergences are
intended to reject or grant less trust where the oracle accepts. The final
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
| P — Signing completion | `crates/pades-sign/`, D fixtures, `docs/lanes/d.md` | Finish D's 12 pending functions; consume B writer/encryption/embedding and A TSA/AC APIs; PDF MAC signing, AC/DSS autofill, metadata and provider gaps | Every assigned function passing or explicitly justified; oracle verifies produced PDF/CMS; unsupported mandatory requirements reject |
| V — Validation / AdES | `crates/pades/`, `crates/ades-model/`, E AdES fixtures, `docs/lanes/e.md` | Finish 35 pending functions; seed values/status, DSS, past/LTA/POE, revinfo/local knowledge and full reports/requests using A/B/C/D interfaces | Complete assigned function accounting; tampered, expired and revoked replays agree with oracle; no fail-open verdict |
| S — Structural / PKI parity | `crates/pdf/`, `crates/pdf-diff/`, `crates/pki-core/src/{algorithms.rs,asn1/,key_usage.rs}`, `crates/pki-certvalidator/`, `crates/pki-fetch/`, `crates/cms/`, `crates/eutl/`, their fixtures and A/B/C status files | Finish B's five pending integration tests, consume qualified policies/trust-manager APIs, audit runtime skips, numeric/schema bounds and algorithm gaps; close A's three pending CMS functions with P/V | Corpus and fresh adversarial differential verdicts remain fail closed; five PDF and three CMS pending functions become substantive assertions; exceptions explicit |
| C — CLI / configuration | New lead-assigned CLI crate and its tests/configuration fixtures | Port 252 functions through current APIs; begin config/runtime/fields immediately, complete LTV commands after P/V | Match upstream output, error and exit behaviour; complete function accounting with local transport doubles |
| L — Lead / integration | Root, `tools/`, facades/service, central fixtures and consolidated status docs | Central Certomancer export and collected-case inventory; seven remaining live integrations; merge lanes, final gates and service switch after parity | Repeatable oracle setup, skip audit, full gate and layer check; service backend switch only after acceptance |

P, V, S and C can start concurrently. S starts decode-limit assertions and
independent parity work while coordinating PDF MAC/PAdES acceptance with
P/V. Available dependencies do not substitute for completed caller tests.
The service switch from `underskrift` remains a final parity milestone.

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


## Current unaccepted validation checkpoint

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
