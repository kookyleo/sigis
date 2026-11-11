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
| `test_ades_validation.py` | `tests/ades_validation.rs` | 40 | 0 | 0 | 40 (13 written, ignored until lane A) |
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
