# Port status

| Lane | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| P | 297 | 296 | 1 | 0 |
| C | 252 | 246 | 2 | 4 |
| V | 47 | 46 | 0 | 1 |
| S | 824 | 819 | 5 | 0 |
| L | 11 | 11 | 0 | 0 |
| **Total** | **1431** | **1418** | **8** | **5** |

Remaining pending work is two CLI context-specific signing-PIN originals (P), two CLI historical-validation cases (S) and the later-revoked leaf original (V). Eight skips remain for review: two genuine raw-ECDSA fixture exclusions, one P SafeNet hardware case and five S registry/PDF model exclusions. C/P batches completed 38 CLI originals; USER-PIN is counted only once. Four lanes continue in useful batches. Acceptance is current main, normal-wrapper workspace tests with zero failures, clean clippy/fmt and applicable pinned pyHanko differential checks. Counts come from [the ledger](lanes/round3/acceptance.json); parameters and helper controls add no functions. [Latest batch](lanes/round3/p-provider-batch-acceptance.md). [Historical status](history/round3-status-before-batch-process.md).
