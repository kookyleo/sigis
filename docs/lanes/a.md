# Lane A — Certificates & CMS

Owner: lane A (branch `hanko/a-cms-cert`). See `docs/hanko-lanes.md`.

## Status

Phase 0 done before the lane split: certvalidator foundation (25 test functions ported, see `crates/hanko-certvalidator/PORTING.md`).

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_ac_validate.py` | 27 | 0 | 0 | 27 |
| `test_ades_time_slide.py` | 13 | 0 | 0 | 13 |
| `test_certificate_validator.py` | 2 | 2 | 0 | 0 |
| `test_common_utils.py` | 15 | 0 | 0 | 15 |
| `test_fetch_limits.py` | 11 | 0 | 0 | 11 |
| `test_fetcher_lifecycle.py` | 16 | 0 | 0 | 16 |
| `test_freshness.py` | 6 | 6 | 0 | 0 |
| `test_name_trees.py` | 6 | 0 | 0 | 6 |
| `test_policy_graph.py` | 33 | 0 | 0 | 33 |
| `test_policy_proc.py` | 13 | 0 | 0 | 13 |
| `test_registry.py` | 9 | 0 | 0 | 9 |
| `test_sig_validate.py` | 3 | 3 | 0 | 0 |
| `test_validate.py` | 21 | 14 | 0 | 7 |
| `test_cms.py` | 78 | 0 | 0 | 78 |
| `test_key_usage_constraints.py` | 4 | 0 | 0 | 4 |
| `test_tsa_fetcher.py` | 10 | 0 | 0 | 10 |
| `test_tsa_fetcher_requests.py` | 4 | 0 | 0 | 4 |

## Known divergences

None yet.

## Requests to the lead

None yet.
