# Porting status: pyHanko → sigis-hanko (index)

Baseline: pyHanko **0.38.1** (tag `v0.38.1`) and pyhanko-certvalidator
**0.33.0** (tag `pyhanko-certvalidator/v0.33.0`). The port runs in parallel
lanes; plan, ownership and the full test assignment are in
[`docs/hanko-lanes.md`](../../docs/hanko-lanes.md).

| Crate | Lane | Detailed status |
| --- | --- | --- |
| `hanko-core` | Lead (+ A) | [PORTING.md](../hanko-core/PORTING.md) |
| `hanko-certvalidator` | A | [PORTING.md](../hanko-certvalidator/PORTING.md) |
| `hanko-cms` | A | [PORTING.md](../hanko-cms/PORTING.md) |
| `hanko-fetch` | A | [PORTING.md](../hanko-fetch/PORTING.md) |
| `hanko-pdf` | B | [PORTING.md](../hanko-pdf/PORTING.md) |
| `hanko-diff` | C | [PORTING.md](../hanko-diff/PORTING.md) |
| `hanko-sign` | D | [PORTING.md](../hanko-sign/PORTING.md) |
| `hanko-validate` | E | [PORTING.md](../hanko-validate/PORTING.md) |
| `hanko-ades` | E | [PORTING.md](../hanko-ades/PORTING.md) |
| `hanko-eutl` | E | [PORTING.md](../hanko-eutl/PORTING.md) |

## Test baseline summary (2026-11-11)

| Package | Test functions | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| pyhanko-certvalidator 0.33.0 | 175 | 25 | 0 | 150 (39 proposed for skipping) |
| pyHanko 0.38.1 | 993 | 0 | 0 | 993 |
| pyhanko-cli (0.38.1 tag) | 252 | 0 | 0 | 252 |
| live integration tests | 11 | 0 | 0 | 11 |
