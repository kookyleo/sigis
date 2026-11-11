# Porting status: hanko-validate

Owner: E. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`.

## Module mapping

| pyHanko module | Rust file | Status (ported / replaced by crate X / skipped: reason) |
| --- | --- | --- |
| `sign/validation/settings.py` | `src/settings.rs` | ported (`KeyUsageConstraints`; config parsing is lead/CLI scope) |
| `sign/validation/errors.py` | `src/errors.rs` | ported |
| `sign/ades/report.py` | `src/report.rs` | ported (re-exported by `hanko-ades`) |
| `sign/validation/pdf_embedded.py`, `status.py`, `dss.py`, `utils.py`, `policy_decl.py` | `src/lib.rs` | pending (stubs return `HankoError::NotImplemented`) |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
