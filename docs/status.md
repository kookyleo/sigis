# Port status

| Lane | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| P | 297 | 296 | 1 | 0 |
| C | 252 | 242 | 0 | 10 |
| V | 47 | 46 | 0 | 1 |
| S | 824 | 819 | 5 | 0 |
| L | 11 | 11 | 0 | 0 |
| **Total** | **1431** | **1414** | **6** | **11** |

Remaining work is 11 pending originals plus 6 skips to revisit: P handles eight CLI PKCS#11 originals and its SafeNet skip; S handles two CLI historical-validation gaps and five registry/PDF exclusions; V completes the later-revoked leaf original. C's batch completed 34 originals; the two ignored implementation gaps remain pending. Four lanes work concurrently and deliver useful batches. Acceptance requires current main, normal-wrapper workspace tests with zero failures, clean clippy/fmt and applicable original pyHanko differential checks. Counts come from [the ledger](lanes/round3/acceptance.json); parameters and helper tests add no functions. [Current batch](lanes/round3/c-batch-acceptance.md). [Historical status](history/round3-status-before-batch-process.md).
