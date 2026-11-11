# Porting status: hanko-validate

Owner: E. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`.

## Module mapping

| pyHanko module | Rust file | Status (ported / replaced by crate X / skipped: reason) |
| --- | --- | --- |
| `sign/validation/settings.py` | `src/settings.rs` | ported (`KeyUsageConstraints`; config parsing is lead/CLI scope) |
| `sign/validation/errors.py` | `src/errors.rs` | ported |
| `sign/ades/report.py` | `src/report.rs` | ported (re-exported by `hanko-ades`) |
| `sign/validation/pdf_embedded.py` | `src/lib.rs`, `src/coverage.rs`, `src/integrity.rs` | ported against the lane A/B/C stubs: subfilter checks, coverage levels (incl. `process_data_at_eof`), DocMDP / FieldMDP / `/Lock` reading, modification review, `docmdp_ok`, CMS and timestamp validation calls. Pending: seed value checks (`_validate_sv_constraints`, needs lane D's `SigSeedValueSpec`), signer attribute status, key usage settings (needs lane A parameters) |
| `sign/validation/__init__.py` (`validate_pdf_signature`, `validate_pdf_timestamp`) | `src/lib.rs` | ported (synchronous) |
| `validate_pdf_ltv_signature` (pyHanko < 0.21) | `src/lib.rs` | not in the 0.38.1 baseline; kept as a stub, superseded by `hanko-ades` LTA validation |
| `sign/validation/status.py` | `src/lib.rs` | partly: `SignatureCoverageLevel`, `PdfSignatureStatus` (+ `docmdp_ok`, `bottom_line`), `DocumentTimestampStatus`; the CMS-level statuses live in `hanko-cms` (lane A) |
| `sign/validation/dss.py` (validation side), `utils.py`, `policy_decl.py` | — | pending |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| (no assigned upstream module; unit tests for coverage, DocMDP and subfilter rules) | `src/coverage.rs`, `src/integrity.rs` | — | — | — | — |

Interface addition: `PdfSignatureStatus::docmdp_ok` (field) and
`PdfSignatureStatus::bottom_line` (method).
