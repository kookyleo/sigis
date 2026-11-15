# Port status

| Lane | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| P | 297 | 296 | 1 | 0 |
| C | 252 | 248 | 4 | 0 |
| V | 47 | 47 | 0 | 0 |
| S | 824 | 819 | 5 | 0 |
| L | 11 | 11 | 0 | 0 |
| **Total** | **1431** | **1421** | **10** | **0** |

No originals remain pending. Ten explicit exclusions remain: three SafeNet hardware cases, two raw-ECDSA reference-fixture exclusions and five S language/model contracts. Revisiting them requires the actual provider or a separately scoped compatibility contract; software controls do not establish hardware passes. Both historical CLI originals pass while retaining raw full-LTA NO_POE limitations. The final current-main workspace gate passed 2435 tests with 0 failures; clippy/fmt and applicable pinned pyHanko differentials pass. Counts come from [the ledger](lanes/round3/acceptance.json); parameters and helpers add no functions. [Signing-PIN acceptance and limits](lanes/round3/signing-pin-callback-acceptance.md). [Historical CLI acceptance](lanes/round3/cli-historical-acceptance.md). [History](history/round3-status-before-batch-process.md).
