# Port status

| Lane | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| P | 297 | 296 | 1 | 0 |
| C | 252 | 208 | 0 | 44 |
| V | 47 | 46 | 0 | 1 |
| S | 824 | 819 | 5 | 0 |
| L | 11 | 11 | 0 | 0 |
| **Total** | **1431** | **1380** | **6** | **45** |

Remaining work is 45 pending originals plus 6 skips to revisit: P owns the eight remaining CLI PKCS#11 originals and reviews its SafeNet skip; C owns the other 36 CLI originals; V completes the later-revoked leaf original; S reviews five remaining registry/PDF exclusions. Four lanes work concurrently and deliver batches, normally 5–15 originals. The lead rebases and merges each batch after workspace tests pass, clippy/fmt are clean and applicable original pyHanko differential checks pass, then updates these counts. Counts come from [the acceptance ledger](lanes/round3/acceptance.json); parameters and helper tests do not add functions. [Historical status](history/round3-status-before-batch-process.md).
