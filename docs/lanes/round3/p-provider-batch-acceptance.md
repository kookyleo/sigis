# P provider batch acceptance

Current-main source `659201037d8185eeabed89853763533fd4c03633` passes the simple gate: workspace2297passed/0failed/26ignored, workspace all-target clippy-Dwarnings clean, fmt check clean. Focused provider suites35passed/0failed/20ignored. Unchanged original Python reports17passed/18genuine mechanism skips; actual native PDFs pass same-output trust, empty-root and mutation checks.

Four C-owned originals are newly passed:

- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_pull_interm`.
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_read_interm_from_file`.
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_pull_certs`.
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_read_certs_from_file`.

The USER-PIN prompt original was already accepted and adds no new credit. Ordinary ECDSA/ML-DSA parameter exclusions remain explicit and match the actual unchanged upstream fixture.

Two original raw-ECDSA functions are skipped because their unchanged fixture requires the unavailable combined ECDSA_SHA256 mechanism. The required_mechanism/require_mech marker mismatch is retained. Two actual native raw-signing controls pass but add zero original credit.

The two SafeNet CLI signing-PIN originals remain Pending: hardware is unavailable, and the current CLI explicitly rejects the context-specific signing credential while their native bodies are ignored stubs. Hardware absence does not hide that implementation gap. P is implementing the separate signing-PIN role. The P-owned existing SafeNet skip remains unchanged.

Inventory:1431/1418passed/8skipped/5pending; CLI252/246/2/4. Only fixture/test/direct-route commits were integrated; duplicate USER-PIN and superseded054 proof-harness changes were not imported. No extra tempfile dependency was needed. Ordinary gate logs are under `/home/l/.codex/artifacts/sigis/round3-launch/simple-gate/` (p-workspace-test.log, p-clippy.log, p-fmt.log).
