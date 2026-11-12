# Rust port status

Updated: 2026-11-12. Baseline: **pyHanko 0.38.1** (`v0.38.1`,
`580f49498f76`) and **pyhanko-certvalidator 0.33.0**
(`pyhanko-certvalidator/v0.33.0`, `b48999514cb4`).

Lane D is integrated. The complete port remains unfinished.

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
| All lane worktree heads and cleanliness | Five `hanko/*` lanes and `lead/d-sign-merge` synchronized to final main; clean |
| Actual oracle, SoftHSM and rendering-tool availability | pyHanko 0.38.1, certvalidator 0.33.0, Pillow 13.0.0, SoftHSM 2.6.1, `pdftoppm` and ImageMagick available |

Cargo uses the shared target selected by `rust-target-env`; only one
Cargo build runs at a time for this repository. Dependency layers follow
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
The tables consolidate the latest lane reports rather than obsolete
introductory summaries in some `PORTING.md` files.

| Crate / assigned test owner | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `sigis-pki-core` | 4 | 4 | 0 | 0 |
| `sigis-pki-certvalidator` | 133 | 92 | 41 | 0 |
| `sigis-pki-fetch` | 56 | 38 | 18 | 0 |
| `sigis-cms` | 78 | 75 | 2 | 1 |
| `sigis-pdf` | 406 | 384 | 17 | 5 |
| `sigis-pdf-diff` | 94 | 92 | 2 | 0 |
| `sigis-pades-sign` | 297 | 271 | 13 | 13 |
| `sigis-pades` (including `ades`) | 47 | 12 | 0 | 35 |
| `sigis-eutl` | 53 | 53 | 0 | 0 |
| **Library lanes A–E** | **1,168** | **1,021** | **93** | **54** |
| Lead: CLI/configuration and live integration | 263 | 0 | 0 | 263 |
| **Overall** | **1,431** | **1,021** | **93** | **317** |

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
root service have no separately assigned upstream module in this
inventory. Their shared code is covered by the owning suites or awaits
lead integration. `sigis-xmldsig`, `sigis-xades`, `sigis-cades`,
`sigis-asic`, `sigis-ooxml`, `sigis-odf` and `sigis-xsig` are XML-plan
skeletons; pyHanko baseline coverage is N/A for those crates.

### Pending work

| Owner | Pending | Functions or missing flow |
| --- | ---: | --- |
| A / CMS | 1 | `test_embed_ac_revinfo_adobe_style`, blocked on complete AdES-LTA validation |
| B / PDF | 5 | Three decode-limit propagation tests after signing, archival timestamp and DSS updates; two PDF MAC/PAdES signer integration tests |
| D / signing | 13 | One signed attachment; eight PAdES HTTP-TSA/AC presign/DSS-attribute tests; one seed-value TSA URL; three public-key encrypted-signing/copy tests |
| E / AdES | 35 | 28 validation functions, five report functions and two request functions; past/LTA/POE/revinfo and report integration |
| Lead / CLI and configuration | 252 | Signing, validation, encryption, fields, stamps, plugins, configuration and runtime suites |
| Lead / live integration | 11 | Nine Certomancer and two CSC dummy-service functions |
| **Total** | **317** | |

D integration makes the signer and seed model available to dependent
callers. A already supplies HTTP TSA, AC validation, trust qualifiers,
qualified policies and LTV primitives; B supplies DSS, embedded files,
encryption and incremental writing. These dependencies now exist, but
pending callers still need implementation, error mapping and substantive
upstream assertions. PDF MAC signing and complete AdES-LTA are remaining
implementation gaps rather than tests to simply unignore.

### Skip accounting and limitations

The 93 skipped functions comprise certvalidator 41, fetchers 18,
CMS two, PDF 17, PDF-diff two and signing 13. Skip reasons remain in the
owning `PORTING.md` and lane files:

- Certvalidator replaces 39 internal name-tree/policy-graph tests with
  `certval` and equivalent PKITS/policy coverage; two deprecated trust-store
  entry points have no Rust counterpart. Fetcher skips cover asyncio
  session lifecycle, a deprecated alias and a Python runtime type check.
- The two CMS skips concern signer-side weak-digest prevention and
  key-based digest selection. Signing completion must revisit their
  assertions rather than count validation replays as full signing tests.
- PDF skips cover Python object-model/trailer mechanics and four
  layout/resource functions assigned to D modules. These are not
  automatically counted a second time as passed appearance tests.
- The two retained PDF-diff skips concern anomalous coverage and in-place
  signature-object tampering, checked before modification analysis.
  Validator coverage must retain those behaviours.
- Signing skips include certificate-less `ExternalSigner` flows excluded
  by `KeySigner`, duplicate SET values unsupported by the DER model,
  validation-only fixtures, deprecated entry points and provider-specific
  SafeNet/DSA behaviour.

A complete functional port must revisit these exclusions, especially
certificate-less signing, duplicate attributes and provider behaviour; the
317 pending functions alone do not describe all remaining parity work.

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
parallel while Cargo builds remain serialized on the shared target.

| Lane | Exclusive file scope | Work and dependencies | Acceptance |
| --- | --- | --- | --- |
| P — Signing completion | `crates/pades-sign/`, D fixtures, `docs/lanes/d.md` | Finish D's 13 pending functions; consume B writer/encryption/embedding and A TSA/AC APIs; PDF MAC signing, AC/DSS autofill, metadata and provider gaps | Every assigned function passing or explicitly justified; oracle verifies produced PDF/CMS; unsupported mandatory requirements reject |
| V — Validation / AdES | `crates/pades/`, `crates/ades-model/`, E AdES fixtures, `docs/lanes/e.md` | Finish 35 pending functions; seed values/status, DSS, past/LTA/POE, revinfo/local knowledge and full reports/requests using A/B/C/D interfaces | Complete assigned function accounting; tampered, expired and revoked replays agree with oracle; no fail-open verdict |
| S — Structural / PKI parity | `crates/pdf/`, `crates/pdf-diff/`, `crates/pki-core/src/{algorithms.rs,asn1/,key_usage.rs}`, `crates/pki-certvalidator/`, `crates/pki-fetch/`, `crates/cms/`, `crates/eutl/`, their fixtures and A/B/C status files | Finish B's five pending integration tests, consume qualified policies/trust-manager APIs, audit runtime skips, numeric/schema bounds and algorithm gaps; close A's one CMS test when V provides LTA | Corpus and fresh adversarial differential verdicts remain fail closed; five PDF and one CMS pending functions become substantive assertions; exceptions explicit |
| C — CLI / configuration | New lead-assigned CLI crate and its tests/configuration fixtures | Port 252 functions through current APIs; begin config/runtime/fields immediately, complete LTV commands after P/V | Match upstream output, error and exit behaviour; complete function accounting with local transport doubles |
| L — Lead / integration | Root, `tools/`, facades/service, central fixtures and consolidated status docs | Central Certomancer export and collected-case inventory; 11 live integrations; merge lanes, final gates and service switch after parity | Repeatable oracle setup, skip audit, full gate and layer check; service backend switch only after acceptance |

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
