# Porting status: hanko-ades

Owner: E. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`.

## Module mapping

| pyHanko module | Rust file | Status |
| --- | --- | --- |
| `sign/ades/report.py` | `hanko-validate/src/report.rs` (re-exported) | ported |
| `sign/validation/generic_cms.py` (`handle_certvalidator_errors`) | `src/basic.rs` | ported (needs `is_ee_cert` from lane A, R-E7; defaults fail closed) |
| `sign/validation/ades.py` — basic validation (§5.3), qualification analysis and requirement enforcement | `src/basic.rs`, `src/lib.rs` | ported on top of `hanko_cms::validate_cms_signature`; content-timestamp POE handling of `_process_basic_validation` pending |
| `sign/validation/ades.py` — validation with time (§5.5), past signature validation, LTA (§5.6), POE extraction, `simulate_future_ades_lta_validation` | — | pending (needs lane A `ltv`: POE manager, time slide, past validation) |
| `sign/validation/policy_decl.py` | `src/basic.rs` (`QualificationSpec`) | partly (qualification settings); revocation gathering and local knowledge pending |
| `sign/validation/report/tools.py` | `src/etsi_report.rs` | ported (writer for the elements pyHanko fills; `quick-xml`) |
| `generated/etsi/ts_11910202.py` (xsdata) | — | skipped: replaced by the writer in `src/etsi_report.rs` |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_ades_validation.py` | `tests/ades_validation.rs` | 40 | 0 | 0 | 40 (7 written, ignored until lane A) |
| `test_ades_validation_report.py` | — | 5 | 0 | 0 | 5 |
| `test_ades_validation_requests.py` | — | 2 | 0 | 0 | 2 |

Oracle recordings for all three modules (76 collected cases, all passing
under pyHanko) are in `crates/hanko-testdata/data/lanes/e/ades/`, produced
by `oracle/run_oracle.sh` with `oracle/record_plugin.py`. The Rust ports
replay them once `hanko-cms` (lane A), `hanko-pdf` (lane B) and
`hanko-diff` (lane C) are implemented.

`tests/ades_validation.rs` replays the recordings (`tests/common/mod.rs`:
recorded PKI, frozen validation times, OCSP / CRL / certificate fetchers
answering from the recorded HTTP exchanges). Written so far, ignored until
`hanko_cms::validate_cms_signature` lands: `test_pades_basic_happy_path`,
`test_embedded_cades_happy_path`, `test_embedded_cades_basic_tampered`,
`test_embedded_cades_sig_tampered`, `test_pades_basic_happy_path_with_tl`
(2 cases), `test_pades_fail_qualification_requirements` (5 cases).
`recordings_are_complete` checks the fixture (69 cases, all passed).

Unit tests: `src/basic.rs` (error and status mapping), `src/etsi_report.rs`
(report content), `src/lib.rs` (JSON / status-only XML).

## Known divergences

- `to_etsi_xml(&AdesValidationResult)` (§4 interface) only has the
  indications, so it emits a status-only report;
  `etsi_report::generate_report` writes the full report from a
  `ReportInput`.
- XML layout: element order follows TS 119 102-2; namespace prefixes are
  the ones pyHanko passes (`vr`, `XAdES`, `ds`, `xs`); date-times are
  written in UTC with `Z`.
