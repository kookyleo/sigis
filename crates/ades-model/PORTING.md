# Porting status: sigis-ades-model

Owner: lane E. Baseline: pyHanko 0.38.1.

| pyHanko module | Rust file | Status |
| --- | --- | --- |
| `sign/validation/errors.py` | `src/errors.rs` | Ported (moved from `sigis-pades` on 2026-11-12) |
| `sign/ades/report.py` | `sigis-pki-core/src/ades.rs`, re-exported | Ported |

Tests: covered by the suites of `sigis-pades` and `sigis-eutl`.
