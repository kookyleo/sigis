# Port status

| Lane | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| P | 297 | 296 | 1 | 0 |
| C | 252 | 248 | 4 | 0 |
| V | 47 | 47 | 0 | 0 |
| S | 824 | 819 | 5 | 0 |
| L | 11 | 11 | 0 | 0 |
| **Total** | **1431** | **1421** | **10** | **0** |

No originals remain pending. Ten explicit exclusions remain: three SafeNet hardware cases, two raw-ECDSA reference-fixture cases and five S language/model contracts. Revisiting them requires actual providers or separately scoped compatibility work. Historical CLI acceptance retains raw NO_POE limitations. The latest workspace gate passed 2436 tests with 0 failures; all-target clippy/fmt pass. SDK paths are normal test inputs; no provenance selectors are required. [Ledger](lanes/round3/acceptance.json), [workflow](lanes/round3/README.md), [V coverage](lanes/round3/v-final-batch-acceptance.md), [history](history/round3-status-before-batch-process.md).
