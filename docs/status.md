# Port status

| Lane | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| P | 297 | 296 | 1 | 0 |
| C | 252 | 246 | 2 | 4 |
| V | 47 | 47 | 0 | 0 |
| S | 824 | 819 | 5 | 0 |
| L | 11 | 11 | 0 | 0 |
| **Total** | **1431** | **1419** | **8** | **4** |

Remaining pending work is two CLI context-specific signing-PIN originals (P) and two CLI historical-validation cases (S). V completed all47 owned originals; its final recovery is limited to currently valid later-KeyCompromise cases, with pure failed-status and unsupported historical recovery still refused. Eight skips remain: two raw-ECDSA fixture exclusions, one P SafeNet case and five S registry/PDF model exclusions. L alone runs the combined current-main workspace/clippy/fmt gate; lanes provide focused tests and applicable pinned pyHanko differentials. Counts come from [the ledger](lanes/round3/acceptance.json); helper controls add no functions. [Latest batch](lanes/round3/v-final-batch-acceptance.md). [Historical status](history/round3-status-before-batch-process.md).
