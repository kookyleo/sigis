# Remaining CLI LTV commands

Ports five original functions from pyHanko0.38.1: LTA update3architectures,
LTV fix3architectures×2timestamp settings, unsigned-field refusal1 and oversized
LTA/LTV flag pairs1each:12original parameters. Decode-limit assertions retain
both default refusal/rerun text and explicit trusted success.

The separate decode_limits_signing target ports two more original functions:
PAdES/PAdES-LTA signing2rows and ordinary/AdES validation2rows. Validation adds
the exact extra Sig2 field revision before both flag calls, forcing the original
signed object stream to be consumed during diff analysis. All four source rows
retain both the finite-default refusal and explicit trusted success assertions.
The complete two-parameter `test_validate` remains skipped: native full-LTA
requires historical revocation proof while upstream accepts B-T API-only status.
Its full body is retained; a zero-ID ordinary-validation control does not grant
half-function credit or relax the archival gate into Basic/NO_POE acceptance.

The current-time local Certomancer server uses the unchanged accepted long-lived
signer1-long certificate; it does not extend validity or relax trust/revocation.
This is an explicit adaptation of the original fixture frozen at2020. Python
executes the original function bodies with those supplied current-time fixtures;
decorators are replaced by the complete Rust parameter loops. Native output
bytes receive independent integrity/trust validation and empty-root denial.
Native commands use the accepted top-level `run_with_runtime` interface with
real default NOW, absolute config/known fixture operands and no global cwd change;
this is a CliRunner adaptation rather than subprocess-binary coverage.
No provenance, ELF, fingerprint or JSON evidence collection is added.

Derived source/fixtures are covered by the upstream pyHanko MIT license.
`upstream/test_cli_ltv.py` and `upstream/test_cli_decode_limits.py` are exact
unmodified copies from pyHanko0.38.1 `pkgs/pyhanko-cli/tests/`. The helper reads
these fixture-relative files so automatic workers need no separate upstream test
checkout. Original AST bodies and all parameter assertions remain unchanged;
only decorators are replaced by Rust's complete parameter loops. The actual CLI
implementation remains the pinned installed/source runtime, not these test files.
