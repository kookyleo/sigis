# Port status

| Lane | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| P | 297 | 296 | 1 | 0 |
| C | 252 | 248 | 2 | 2 |
| V | 47 | 47 | 0 | 0 |
| S | 824 | 819 | 5 | 0 |
| L | 11 | 11 | 0 | 0 |
| **Total** | **1431** | **1421** | **8** | **2** |

Two CLI context-specific signing-PIN originals remain pending with P. Both CLI historical-validation originals now pass; historical trusted/qualified API status preserves the raw full-LTA NO_POE limitation. V completed all47 owned originals. Eight skips remain: two raw-ECDSA fixture exclusions, one P SafeNet case and five S registry/PDF model exclusions. L runs the combined workspace/clippy/fmt gate; lanes provide focused tests and pinned pyHanko differentials. Counts come from [the ledger](lanes/round3/acceptance.json); helper controls add no functions. [Historical CLI acceptance](lanes/round3/cli-historical-acceptance.md). [Historical status](history/round3-status-before-batch-process.md).
