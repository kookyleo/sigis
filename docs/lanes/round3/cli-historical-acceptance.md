# Historical CLI validation acceptance

Source `5b24e817` is based on accepted main `8b393619` and completes exactly two
C-owned originals: `pyhanko-cli/test_cli_decode_limits.py::test_validate`
(validate/adesverify) and
`pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_point_in_time_no_revinfo`.
S supplied CLI behavior and V supplied the private PAdES preliminary validation.
Supplemental guards add no original IDs.

The normal wrapper workspace gate passed2414 tests,0 failed,23 inherited ignored
across252 reports. Workspace all-target clippy-Dwarnings and fmt pass. Root's
fresh unchanged pinned originals passed3 parameter rows; the author current-base
focus passed24 native tests with fresh same-byte peers. The first Root original
attempt lacked platformdirs and failed before validation; the successful rerun
uses the existing isolated C dependency directory without modifying the venv.
Plain logs are in `~/.codex/artifacts/sigis/round3-launch/cli-historical-integration/`.

The historical MAIN conclusion requires actual authenticated signature/certificate
POEs and complete same-path, same-anchor, same-policy validation. Caller/TSA2025
remain distinct from the genuine MAIN2020 reference. Raw full-LTA NO_POE and
control-time failure remain visible. PDF, seed, integrity, mandatory TSA/MAIN,
algorithm and qualification refusals remain; two stronger current-TSA differences
from pinned CLI are disclosed. There is no Basic fallback, fabricated POE, failed
status mutation, generic expired recovery, public API or dependency change.
Counts are1431/1421/8/2; only the two signing-PIN CLI originals remain pending.
