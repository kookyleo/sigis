# Round 3 WithTime containment acceptance transaction

This entry takes effect with L's metadata transaction that applies it. It supersedes the older V47/47 status below without rewriting historical evidence. The executable proof source is the frozen9d candidate identified here, not a later documentation commit.

The accepted V assignment remains **47 total /46 passed /0 skipped /1 pending**, with **no new V upstream IDs**. All46 passing original mappings have actual current native results, including the existing LTA, historical-validation and future-positive routes. The only Pending original is `pyhanko/test_ades_validation.py::test_embedded_cades_pre_revoke_with_poe` (native `ades_validation::test_embedded_cades_pre_revoke_with_poe`). Its complete body and helpers remain unchanged. The sole authorized annotation is:

```rust
#[ignore = "Pending complete same-policy MAIN validation after fail-closed WithTime hardening"]
```

This is a functionality Pending item, not a pass or a provider/runtime exclusion. The explicit current `--ignored --exact` run actually returned101 in6.43s with0 passed,1 failed and13 filtered: the hardened result remains `REVOKED_NO_POE` where the unchanged original requires `OK`. Complete same-policy MAIN historical validation must restore that positive contract and re-enable the original. The supplemental `pre_revocation_poe_preserves_incomplete_main_refusal` is reasserted against the strict containment contract, remains enabled and passes; it creates no upstream-function credit.

The production change is confined to `crates/pades/src/ades/with_time.rs`. The reducer returns an incomplete or untrusted MAIN result before qualification whenever its typed subindication is not `OK` **or** the actual `status.signature.trusted()` predicate is false. A stale cached outer `OK` becomes `GENERIC`; it does not authorize clearing the typed MAIN error. The retained API payload, validation path, failure details and existence/time bounds are returned intact, and refused MAIN results gain no positive signer qualification (`None`). An existence bound alone does not complete certificate signatures, path length, names, critical extensions, policies or MAIN key usage. Actual adversarial path-length and bad-certificate-signature trust-promotion paths are contained.

Already fully checked and trusted current positives remain eligible for the existing qualification path. Current native controls preserve TSA purpose/trust, cryptographic signature and imprint binding, timestamp ordering and bounds. Genuine final historical/LTA validation remains a separate route that performs the required checks; the pure WithTime reducer does not supply historical rescue. No clock, public API, POE mechanism, certificate-validation/CMS/policy/LTA production file or shared framework is changed by this V repair.

Current source evidence is pinned to `9d921382ea837819b2ad5dda2b9546adc83dba03`. Root's genuine tests-first source `296c6cfd` produced4 passed/1 failed for qualified completion in37.43s and2 passed/2 failed for containment in13.26s; these were behavioral trust failures, not missing APIs. The sole production guard is `cb4945d3`; the authorized Pending/supplemental follow-up is `9d921382`. The current whole PAdES package actually returned0 in207.82s with22 reports,157 passed,0 failed and1 ignored. Its22 post-run private ELF archives are retained as lossless gzip with separately verified compressed and raw SHA256/lengths. The independent original map verifies46 genuine passing originals and the single explicit Pending item; an old owner's source/run is not relabelled current.

The actual current full workspace gate returned0/audit0 for build7.14s, test1354.13s, clippy25.50s, doc212.45s, layer4.74s and fmt3.38s. The completed log contains **2147 discovered /2143 passed /4 ignored /0 failed across219 reports**, derived from actual summaries rather than predictions or upstream counts. The full compiler audit covers508 selected phase units,3068 input records and505 unique full-gate source files. Across the current producer/focus/full packet,586 actual source locators were checked using literal paths, own-origin HEAD, the same common repository, exact candidate-relative Git bytes, SHA256/BLAKE3, stable fingerprints and binary/text dep-info; no manifest/hash waiver is used. All58 package-qualified completed native ELF snapshots verify actual Running paths and summaries. Eight storage hardlinks reuse only immutable byte-identical gzip archives, never a prior source identity or verdict.

Root additionally executed127 fresh reference API calls using pinned pyHanko0.38.1:63CMS (27 direct CMS,27 public WithTime and9 fixed-TSA controls) plus64PDF (32 exact AdES WithTime and32 ordinary PDF diagnostics). Independent offline comparison partitions the current results precisely:

| Surface | Comparable profiles | Result |
| --- | ---: | --- |
| Direct CMS | 27 | Trust and bottom-line flags agree in all27;4 error/horizon field profiles differ. |
| Public WithTime, same complete policy | 24 | 12 agree;12 native stricter refusals. |
| Public WithTime, explicit independent PKIX params | 3 | Excluded: native public wrapper cannot carry that complete policy profile. |
| Actual PDF exact AdES WithTime | 32 | 24 agree;8 native stricter refusals. |
| Ordinary normalized PDF facade | 32 | Diagnostic only; never counted as exact-policy parity. |

No matched native more-trusting decision was observed in these bounded matrices. Native stricter refusals remain compatibility gaps, not pyHanko rejections or full-port successes. Root receipts bind actual stdout/stderr, interpreter/modules, immutable signed input bytes and script/manifest hashes before/after. The independent Python socket audit recorded0 covered observable events; this is not kernel syscall or network-namespace attestation. The guard covers untrusted CA-revoked states by its actual trust/subindication predicates, but there is no independently named newly executed dynamic CA-revoked case in this packet. Field/path/error/time differences, three explicit-PKIX exclusions and the Pending positive prevent blanket parity, universal fail-closed or complete historical-rescue claims.

The independent final read-only checker completed its first attempt with exit0 in49.017s and58038 checks. Evidence is under `/home/l/.codex/artifacts/sigis/round3-launch/styled-context-integration/`: `final-review/review.json` SHA256 `0fe33202d9be8c59a0b1b77b6e5c429190b4516cbdf7e22d47ee45612705230e`; `v-focus-review/review.json` SHA256 `700cba98bef8cad7e9b8c4aa852960a2bff67a7eb040986d121b7da31b4424ff`; `v-focus-review/fresh-reference-review.json` SHA256 `6bfedb79569134ad096053afef4dd56c186f9a67ae6c825744905051cb55c0d9`. The final seal rehashed8039 proof paths and retained586 exact current-source postimages. Post-run snapshots do not attest run-instant identity; selected local compiler provenance is not a complete external toolchain attestation.

The central ledger must preserve its341 historical raw overrides verbatim. This original previously inherited the baseline Passed status; it had no existing override row to edit. The transaction appends one new V Pending override and four C/S Passed overrides, yielding346 overrides. Overall conditional totals are1363 passed /11 skipped /57 pending; the library aggregate is1156 passed /11 skipped /1 pending. The ART review and draft generation themselves change no ledger or acceptance count.

---

## Historical PORTING record (verbatim preimage)

# Lead acceptance update

Accepted assigned counts: **47 total /47 passed /0 skipped /0 pending** on source 7500fc7. The two AC-dependent functions now pass complete original assertions after production AC retrieval binding, exact fresh-input native verification and all six workspace gates. The owner narrative below remains historical provenance; unrelated followups are not imported by this acceptance. See docs/lanes/round3/l-ac-http-and-live-lta.md for recording/live evidence boundaries and remaining compatibility limitations.

# Porting status: sigis-pades (crates/pades)

Owner: E. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`.

## Module mapping

| pyHanko module | Rust file | Status (ported / replaced by crate X / skipped: reason) |
| --- | --- | --- |
| `sign/validation/settings.py` | `src/settings.rs` | ported (`KeyUsageConstraints`; config parsing is lead/CLI scope) |
| `sign/validation/errors.py` | `src/errors.rs` | ported |
| `sign/ades/report.py` | `src/report.rs` | ported (re-exported by `sigis-pades`) |
| `sign/validation/pdf_embedded.py` | `src/lib.rs`, `src/coverage.rs`, `src/integrity.rs` | ported against the lane A/B/C stubs: subfilter checks, coverage levels (incl. `process_data_at_eof`), DocMDP / FieldMDP / `/Lock` reading, modification review, `docmdp_ok`, CMS and timestamp validation calls. Pending: seed value checks (`_validate_sv_constraints`, needs lane D's `SigSeedValueSpec`), signer attribute status, key usage settings (needs lane A parameters) |
| `sign/validation/__init__.py` (`validate_pdf_signature`, `validate_pdf_timestamp`) | `src/lib.rs` | ported (synchronous) |
| `validate_pdf_ltv_signature` (pyHanko < 0.21) | `src/lib.rs` | not in the 0.38.1 baseline; kept as a stub, superseded by `sigis-pades` LTA validation |
| `sign/validation/status.py` | `src/lib.rs` | partly: `SignatureCoverageLevel`, `PdfSignatureStatus` (+ `docmdp_ok`, `bottom_line`), `DocumentTimestampStatus`; the CMS-level statuses live in `sigis-cms` (lane A) |
| `sign/validation/dss.py` (validation side), `utils.py`, `policy_decl.py` | — | pending |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| (no assigned upstream module; unit tests for coverage, DocMDP and subfilter rules) | `src/coverage.rs`, `src/integrity.rs` | — | — | — | — |

Interface addition: `PdfSignatureStatus::docmdp_ok` (field) and
`PdfSignatureStatus::bottom_line` (method).

## Module `ades` (formerly crate hanko-ades)


Owner: E. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`.

## Module mapping

| pyHanko module | Rust file | Status |
| --- | --- | --- |
| `sign/ades/report.py` | `hanko-validate/src/report.rs` (re-exported) | ported |
| `sign/validation/generic_cms.py` (`handle_certvalidator_errors`) | `src/ades/basic.rs` | ported (needs `is_ee_cert` from lane A, R-E7; defaults fail closed) |
| `sign/validation/ades.py` — basic validation (§5.3) incl. content-timestamp POE handling, qualification analysis and requirement enforcement | `src/ades/basic.rs`, `src/ades/with_time.rs`, `src/ades/lib.rs` | ported on top of `sigis_cms::validate_cms_signature` |
| `sign/validation/ades.py` — validation with time (§5.5), timestamp qualification requirements | `src/ades/with_time.rs` | ported (signature POE supplied by the caller until a POE manager is wired) |
| `sign/validation/ades.py` — past signature validation, LTA (§5.6), POE extraction from DSS / document timestamps, `simulate_future_ades_lta_validation` | — | pending (needs lane A `ltv`: POE manager, time slide, past validation; lane B DSS) |
| `sign/validation/policy_decl.py` | `src/ades/basic.rs` (`QualificationSpec`) | partly (qualification settings); revocation gathering and local knowledge pending |
| `sign/validation/report/tools.py` | `src/ades/etsi_report.rs` | ported (writer for the elements pyHanko fills; `quick-xml`) |
| `generated/etsi/ts_11910202.py` (xsdata) | — | skipped: replaced by the writer in `src/ades/etsi_report.rs` |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_ades_validation.py` | `tests/ades_validation.rs` | 40 | 12 | 0 | 28 |
| `test_ades_validation_report.py` | — | 5 | 0 | 0 | 5 |
| `test_ades_validation_requests.py` | — | 2 | 0 | 0 | 2 |

Oracle recordings for all three modules (76 collected cases, all passing
under pyHanko) are in `crates/testdata/data/lanes/e/ades/`, produced
by `oracle/run_oracle.sh` with `oracle/record_plugin.py`. The Rust ports
replay them once `sigis-cms` (lane A), `sigis-pdf` (lane B) and
`sigis-pdf-diff` (lane C) are implemented.

`tests/ades_validation.rs` replays the recordings (`tests/common/mod.rs`:
recorded PKI, frozen validation times, OCSP / CRL / certificate fetchers
answering from the recorded HTTP exchanges). Written so far, ignored until
`sigis_cms::validate_cms_signature` lands: `test_pades_basic_happy_path`,
`test_embedded_cades_happy_path`, `test_embedded_cades_basic_tampered`,
`test_embedded_cades_sig_tampered`, `test_pades_basic_happy_path_with_tl`
(2 cases), `test_pades_fail_qualification_requirements` (5 cases),
`test_embedded_cades_with_time_happy_path`,
`test_embedded_cades_with_time_tampered_timestamp`,
`test_embedded_cades_with_time_sig_tampered_timestamp`,
`test_embedded_cades_pre_revoke_with_poe`,
`test_embedded_cades_provably_revoked`, `test_embedded_cades_revoked_no_poe`.
`recordings_are_complete` checks the fixture (69 cases, all passed).

Unit tests: `src/ades/basic.rs` (error and status mapping), `src/ades/with_time.rs`
(§5.5 rules: POE, revocation, ordering, timestamp failures), `src/ades/etsi_report.rs`
(report content), `src/ades/lib.rs` (JSON / status-only XML).

## Known divergences

- `to_etsi_xml(&AdesValidationResult)` (§4 interface) only has the
  indications, so it emits a status-only report;
  `etsi_report::generate_report` writes the full report from a
  `ReportInput`.
- XML layout: element order follows TS 119 102-2; namespace prefixes are
  the ones pyHanko passes (`vr`, `XAdES`, `ds`, `xs`); date-times are
  written in UTC with `Z`.

## Integrated count correction (2026-11-12)

The 13 replay wrappers run and pass, but the two
`test_pades_basic_happy_path_with_tl` parameter wrappers represent one
upstream function. The strict upstream-function accounting is therefore
47 total / 12 passed / 0 skipped / 35 pending (28 validation, five report,
two requests). The wrappers replay 17 recorded cases/calls. See
`docs/status.md` for the final workspace and differential evidence.


## Round 3 validation milestone (2026-11-13)

Unique assigned accounting: **47 total / 45 passed / 0 skipped / 2 pending**,
local candidate results only. Root-accepted counts remain 47/12/0/35.
The latest L confirmation accepts context clones in 940e04d; cutoff/horizon
is accepted by the consolidated main62a72a2 handoff. V feature acceptance remains separate. The inherited 12 functions remain regressions;
the two TL wrappers still count once. All 76 source parameter IDs are mapped in
`docs/lanes/round3/v-report.md` and the final-function-audit.json artifact.

All 64 assigned-function Rust assertion wrappers and extra regressions passed
against freshly regenerated primary Python oracle inputs. The exact native
output assertions for all 47 functions pass, but live AC validation and the
attributes report remain conservatively pending because tests supply raw current
OCSP responses through with_revinfo until the shared AC fetch interface arrives.
That adapter validates original DER cryptographically; it supplies no trust or
verdict. Native AC HTTP fetching parity is not claimed.

The exported LTA implementation authenticates timestamp/DSS POEs, validates past
paths with preserved caller context, applies typed algorithm cutoffs and permanent
bans, rejects broken timestamp chains/missing proof, enforces qualification and
checks seed constraints at the final validated time. The facade now checks PDF
coverage, modifications and seed constraints. CMS/AC/key-usage options are exposed
through validate_pdf_signature_with_options. Actual request tests use loopback HTTP
and assert internal successful OCSP requests, full CertID and rejection controls.

Supplemental seed tests passed eight wrappers over 75 original parameter cases
plus a fresh trusted dangling-reference mutation. Twelve native unit tests pass.
These supplemental tests add no V function counts. The S-owned anomalous coverage
fixture with two ByteRange integers still fails the lower four-entry parser;
that original assertion is kept, with four of five supplemental integrity tests
passing. No harmless skip is substituted.

Targeted check, strict Clippy and formatting pass under the updated scheduler.
Every Cargo invocation uses tools/cargo-locked.sh, preserves compiler caching and
lets system rust-slots choose host/slot/concurrency. Detailed commands, oracle
case/call counts, scheduler receipts, dependency requests and compatibility
limitations are in the lane report and
/home/l/.codex/artifacts/sigis/round3/v/.

## PDF MAC and S validator assistance follow-up

The latest authoritative L notice confirms context-clone acceptance in
940e04d; the shared cutoff/horizon API is now accepted. Local candidate proof does not increase the accepted V
47/12/0/35 baseline. The existing workspace sigis-pki-fetch dependency is approved.

S-owned test_pdf_mac_pades now has full native LTA execution in pdfmac_lta.rs,
with all original body/decorator assertions and six fresh differential cases
across four Rust wrappers. A real more-trusting AdES result was fixed: past
validation now runs even when current CMS passed, matching the oracle's
NO_POE with true API bottom_line under its NO_REVOCATION policy. Failed PDF
MAC authentication and retained-key/CMS diagnostic results remain separately
labelled. This is validator proof on freshly Python-generated input, not a
claim that P's native MAC signing/session/concurrency interface is delivered.

S-owned test_tamper_sig_obj retains all three modes. test_anomalous_coverage
now runs its four parameters independently: tail/gap/weird pass; the exact
two-integer ByteRange parameter remains red in the shared parser. No ignore
or harmless skip is used and the whole function remains pending.

Latest fresh-input package result: 100 native tests / 99 passed / 1 failed /
0 ignored. Assigned V local candidate counts remain 47/45/0/2; all S assistance
adds zero V functions. See v-report.md for exact IDs, native mappings, independent
fresh oracle versus fixed-byte replay, actual host/slot receipts and L requests.

## Accepted context-clone consumer regression

L confirms the exact with_timing/with_fetchers methods in 940e04d. Local
context.rs and the absolute scheduler match the accepted source; the reported
fast-forward refusal did not require rewriting the lane branch. not_allowed_after
and error horizons are accepted shared APIs; V feature acceptance remains separate.

Five LTA contract wrappers now pass on fresh primary input. The additional
freshness-judge regression verifies a caller policy that accepts current-time
revinfo but rejects it during actual historical validation: current CMS remains
trusted while AdES returns NO_POE. This directly exercises the consumer's retained
policy across context timing/fetcher changes and adds no upstream-function credit.

The phase-specific custom hook test is Rust-specific consumer proof. A separate
four-call pinned Python audit shows the lower context sets its point-in-time flag
true even for outer current-time validation; the same flag predicate therefore
rejects both Python phases. That is an explicit timing-model compatibility gap,
not a claim of equivalent phase-specific oracle agreement. Full JSON/log and
reproduction are under artifacts/context-consumer; no upstream credit is added.

## Safe rebase verification

Rebased onto main 9c4436c with 14 owned commits replayed and five equivalent
shared commits skipped. A backup branch and complete dirty-lock recovery
artifacts were saved; Cargo.lock was reapplied as the same two dependency
additions and remains uncommitted. Owned trees matched before the necessary
post-rebase adaptation. Other branches/worktrees were not rewritten.

Actual time sliding on the new base exposed a certificate-algorithm failure
classification regression. Exact original tests remain unchanged in meaning,
with additional exact horizon assertions. The AdES adapter now retains typed
constraints from the actual certificate path and issuer keys, choosing the
earliest denied horizon with permanent bans taking precedence. It does not
parse reason strings or replace unrelated mandatory path failures.

Post-fix package verification: 101 Rust tests / 100 passed / 1 failed / 0 ignored;
only the known S-owned two-integer ByteRange parameter remains red. Native
execution replays saved fresh oracle exports, not new live Python calls.
Context clones and cutoff/horizon metadata are accepted; all V upstream-function
acceptance remains L-owned. Local V counts remain
47/45/0/2; root-accepted counts remain 47/12/0/35.

## Variable ByteRange consumer checkpoint

On frozen maincef64d3, SignatureAttributes::byte_range retains a Vec<u64>
cloned from the complete parsed signature range. Real two/four-integer
coverage-anomaly inputs preserve every oracle offset-length pair and report
ordering. All original integrity/coverage/rejection assertions and the trusted
CMS facade controls remain in validator_integrity.rs. Fresh pinned generation
covers seven S-owned source parameter cases and nine validation calls; all
eight native integrity wrappers pass. This grants zero V function credit and
does not claim XML schema identity or final L/S function acceptance.

The candidate package passes 103/103 tests with zero ignored after this source
integration. Prior red fixed-cardinality evidence above is historical. Shared
algorithm metadata is accepted by the consolidated main62a72a2 handoff;
V feature readiness remains separate from shared helper acceptance.
Root V counts remain 47/12/0/35 and local candidate counts remain 47/45/0/2;
both AC fetching-dependent functions still require the shared transport API.

## Explicit native fixture provenance

The consolidated main62a72a2 handoff resolves shared API delivery status. It is
already an ancestor of the V branch; no duplicate shared rebase was needed.
The interface contract requires Cargo --config env selection for automatic VM
jobs because rust-remote does not forward ambient HANKO_* exports. Earlier VM
logs using only parent-shell selection prove successful fixture replay, not
the claimed external fresh-input selection. That attribution is corrected.

Test inputs now emit native actual-opened-path, SHA-256, length, host/slot and
runtime-selection receipts. All94 exported fixture files were replicated and
hash-verified on both workers. Explicit env.KEY.value and env.KEY.force Cargo
configuration produced103/103 passing tests on vm2064slot0, with190 native
receipts:91 distinct external paths and6 repository paths, every hash matching
the local inputs, including all75 seed PDFs. This replays previously generated
fresh pinned exports; it is not a new Python execution or upstream credit.
Artifacts and exact arguments: accepted-api-followup/ under the lane artifacts.

## Authenticated archival POE follow-up

Accepted main62a72a2 is already included; shared metadata/context/wrapper
delivery is resolved. A fresh corrupt newest-DTS control proved nativeOK where
the pinned oracle rejectsNO_POE. Test-first repair stages the full candidate
evidence chain atomically and discards its derived POEs on any invalid member.
Explicit caller POEs survive. Timestamp messageImprint policy is queried at the
current reference time before registering signature POE; denied/fallback-now
values create no Timestamp entry. Independent Provided signature POE and
permanent target algorithm rejection remain intact.

The imprint denial invariant is deliberately stricter than Python's final LTA
acceptance; it is not a fabricated matching Python rejection. The original
helper's positional genTime/poe_type behavior is recorded unchanged. Native
corrupt-chain best-time2024 versus Python preliminary2020 is also separate
compatibility evidence, while both final indications rejectNO_POE.

LTA's internal time processor now uses exactly the POE selected by archival
validation for both timing and qualification. A real trusted-token/strong
revinfo test first demonstrated2020 genTime replacing selected2029. The internal
bounded path retains2029; ordinary public with-time keeps its original behavior.
No timestamp metadata is fabricated and no final qualification fail-open is
claimed from the intermediate-time regression.

Final candidate run:112/112 native tests,0ignored,212 native path/hash receipts,
96external paths plus6repository paths, explicit Cargo env selection and exact
replication to both workers. New live POE exports total22validation calls and
39loopback HTTP exchanges, not upstream function credit. Local candidate
chain downgrade44/0/3 is restored to45/0/2 after repair; accepted V47/12/0/35
remains provisional and the two AC fetching-dependent functions stay pending.
See v-report.md and artifacts/accepted-api-followup/ for exact cases and logs.
