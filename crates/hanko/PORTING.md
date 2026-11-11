# Porting status: pyHanko → sigis-hanko (index)

Baseline: pyHanko **0.38.1** (tag `v0.38.1`) and pyhanko-certvalidator
**0.33.0** (tag `pyhanko-certvalidator/v0.33.0`). The port runs in parallel
lanes; plan, ownership and the full test assignment are in
[`docs/hanko-lanes.md`](../../docs/hanko-lanes.md).

| Crate (directory) | Lane | Detailed status |
| --- | --- | --- |
| `sigis-pki-core` (`pki-core`) | Lead (+ A, E) | [PORTING.md](../pki-core/PORTING.md) |
| `sigis-pki-certvalidator` (`pki-certvalidator`) | A | [PORTING.md](../pki-certvalidator/PORTING.md) |
| `sigis-pki-fetch` (`pki-fetch`) | A | [PORTING.md](../pki-fetch/PORTING.md) |
| `sigis-cms` (`cms`) | A | [PORTING.md](../cms/PORTING.md) |
| `sigis-pdf` (`pdf`) | B | [PORTING.md](../pdf/PORTING.md) |
| `sigis-pdf-diff` (`pdf-diff`) | C | [PORTING.md](../pdf-diff/PORTING.md) |
| `sigis-pades-sign` (`pades-sign`) | D | [PORTING.md](../pades-sign/PORTING.md) |
| `sigis-pades` (`pades`, incl. `ades`) | E | [PORTING.md](../pades/PORTING.md) |
| `sigis-ades-model` (`ades-model`) | E | [PORTING.md](../ades-model/PORTING.md) |
| `sigis-eutl` (`eutl`) | E | [PORTING.md](../eutl/PORTING.md) |

Crate layout and layers: [`docs/crates.md`](../../docs/crates.md).

## Test baseline summary (2026-11-12, lead round 2)

Test functions at the release tags. "On `main`" excludes lane D, whose
work is not merged yet (its branch reports 266 / 13 / 18).

| Lane (suites) | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| A (certvalidator, CMS, TSA) | 271 | 209 | 61 | 1 |
| B (PDF layer) | 406 | 384 | 17 | 5 |
| C (diff analysis) | 94 | 88 | 6 | 0 |
| D (signing), on its branch | 297 | 266 | 13 | 18 |
| E (AdES, trusted lists) | 100 | 66 | 0 | 34 |
| **Lanes A–E** | **1,168** | **1,013** | **97** | **58** |
| L (pyhanko-cli, live integration) | 263 | 0 | 0 | 263 |
| **All suites** | **1,431** | **1,013** | **97** | **321** |
