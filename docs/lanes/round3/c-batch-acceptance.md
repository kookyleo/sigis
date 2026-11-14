# C batch acceptance

Accepted34unique CLI originals on current-main source `e2a0ef837a767e36fc3b9e63846f2f88ca168d4b`.

| Batch | Newly passed originals |
| --- | ---: |
| Software signing |7|
| LTV and decode limits |6|
| Qualified AdES |7|
| Ordinary EUTL |14|
| Total |34|

Normal repository wrapper gate: workspace tests2283passed/0failed/6ignored; workspace all-target clippy-Dwarnings clean; fmt check clean. Pinned original parameterized reference checks passed, and applicable native outputs have fresh differential checks. Parameters and supplemental wrappers add no IDs.

Two ignored originals remain Pending: pyhanko-cli/test_cli_decode_limits.py::test_validate and pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_point_in_time_no_revinfo. Native historical proof/API-status handling still differs. Their assertions remain; no weaker trust fallback or invented POE is accepted.

The ledger becomes1431/1414/6/11; CLI252/242/0/10. Other lane counts are unchanged. Ordinary test logs are under `/home/l/.codex/artifacts/sigis/round3-launch/simple-gate/`. The obsolete immutable CLI/source/ELF/evidence prerequisites were removed while preserving semantic, refusal and differential assertions. [Exact mappings and parameter coverage](../../../crates/cli/REMAINING_PORTING.md).
