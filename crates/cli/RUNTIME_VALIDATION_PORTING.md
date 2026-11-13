# Accepted CLI runtime-validation functions

Source: `05f46f46708f120a613683439e55e96ef0a6017a`. Accepted CLI counts:
**252 total /180 passed /0 skipped /72 pending**. Exactly these five original
functions/five parameters are credited once. The previously accepted runtime
`test_fail_read` remains credited once and is excluded from this increment.

| Immutable upstream function | Rust function | Original cases | Required exit | Required diagnostic destination |
| --- | --- | ---: | ---: | --- |
| `pyhanko-cli/test_runtime.py::test_fail_strict_mildly_broken` | `runtime_validation::test_fail_strict_mildly_broken` | 1 | 1 | combined output |
| `pyhanko-cli/test_runtime.py::test_succeed_strict_mildly_broken_nonstrict` | `runtime_validation::test_succeed_strict_mildly_broken_nonstrict` | 1 | 0 | No error required |
| `pyhanko-cli/test_runtime.py::test_log_stdout` | `runtime_validation::test_log_stdout` | 1 | 1 | stdout |
| `pyhanko-cli/test_runtime.py::test_log_stderr_default` | `runtime_validation::test_log_stderr_default` | 1 | 1 | stderr |
| `pyhanko-cli/test_runtime.py::test_log_file` | `runtime_validation::test_log_file` | 1 | 1 | pyhanko.log |

Pinned source: pyHanko0.38.1, `pyhanko-cli/test_runtime.py`, source SHA256
`e4a61fdeb60b2819e6cb2257fd96b28f3f833e30070f5b9c202daea922566ee4`.
The exact source bodies, parameters and immutable function IDs are recorded in
`owner-RUNTIME_VALIDATION_FUNCTIONS.json` in the integration artifact packet.
That inventory's owner historical execution is not substituted for ROOT's
current-source producer and fullgate executions.

ROOT uses current CLI SHA256
`791b1611abe143a0aa683f203acd21de2f4ad533d0fa86e990ae3f845445bbcb`
(length123701680), frozen per-case subprocess cwd/input/configuration, actual
stdout/stderr/log files frozen before starting each fresh pinned CliRunner
reference, and assertions-enabled optimization0 metadata. Both workers receive
the same actual product. The reference profile makes zero network calls.
Strict malformed-xref input must fail; explicit nonstrict mode succeeds on the
same actual PDF. The three logging functions verify the real selected output
stream/file, not a stored Python verdict or inferred logging configuration.

Current Click8.5.1 executes the stderr assertion. The original old-Click skip
condition is recorded; no provider/runtime skip occurred in these five cases.
These controls do not implement or certify arbitrary logging/runtime settings,
qualification/LTV/provider flows, or all remaining72 C originals.

The coherent current workspace gate measured **2,010 discovered /
2,007 passed /3 ignored /0 failed**,199 reports.
All six gates, current ELF/source/producer checks, actual current runtime review
and separate serial mandatory-policy controls precede this acceptance.
Shared TSA request-binding12 tests and raw malicious-probe3 tests add **0IDs**.
The known more-permissive legacy missing-KU signing case is not repaired by
these runtime assertions. No complete-port or universal fail-closed claim.
