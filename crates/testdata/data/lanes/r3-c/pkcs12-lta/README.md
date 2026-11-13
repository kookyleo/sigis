# Actual-process PKCS12/LTA current-clock fixtures

These test helpers support eight new P12 original functions (28 parameters),
two strict/non-strict LTA originals (six parameters), and one missing-TSA
negative: eleven new unique functions and 35 parameters. The previously accepted
basic P12 function and its four parameters are excluded from this slice. They implement no Rust signing/validation code and earn no
unique-function credit. Parent tests must use a newly produced immutable native
CLI and keep actual executable/input/output/source hashes.

## Clock and certificate scope

The original CLI unit fixtures freeze 2020 and use signer1, which expires in
2022. An actual current-clock native process cannot reuse that expired credential
for presign validation without an inappropriate clock/validity/policy override.
`live_server.py` uses the existing pinned signer1-long template (valid until
2030), inherited by RSA, ECDSA and Ed25519. No interval or tolerance is extended.
This is an explicit certificate/clock fixture adaptation, not the identical
frozen original input and not proof that original pytest was rerun.

The server constructs the selected architecture from the accepted crypto fixture
with the actual ephemeral loopback listener as external URL prefix. It uses
`AsyncIllusionist(..., at_time=None)`, the library's real current-time mode.
Actual certificates advertise the real HTTP AIA/OCSP/CRL routes; no redirect
transport, replay verdict, preloaded revocation evidence or fake clock is used.
The caller owns only this child process and must leave existing services alone.

## Server invocation

```text
PYTHON live_server.py --crypto ACCEPTED_CRYPTO_DIRECTORY \
  --architecture rsa|ecdsa|ed25519 --artifacts NEW_CASE_DIRECTORY
```

Read exactly one JSON readiness line. It records actual URL, TSA/PFX/root/metrics
URLs, actual source/interpreter/module/config/key-file hashes and current time.
The fresh synthetic encrypted `credential.p12` (test password secret), root DER,
signer/intermediate/TSA DER and `server-ready.json` are exported in the requested
directory. HTTP PFX download may generate a different PKCS12 envelope: record the
actual downloaded bytes separately rather than assuming the startup-export hash.

The metrics endpoint is `/_sigis/requests`, with bounded cardinality and no form
body/passphrase logging. Snapshot it **after the native CLI and before the oracle
CLI or validation helpers**. Later reference/check requests must not be presented
as native signing traffic. SIGTERM/SIGINT allow the test-owned server to clean up
and write final metrics; stopping another process/service is never required.

## Fresh native-output full-LTA verification

```text
PYTHON oracle_lta_verify.py --input INPUT.pdf --output NATIVE.pdf --root root.der \
  [--allow-hybrid] [--require-lta-updates] [--record RECEIPT.json]
```

This helper performs no signing or CLI invocation. It parses the actual native
PDF, requires a regular signature/document timestamp/DSS and invokes pinned
production `ades_lta_validation` with `REQUIRE_REVINFO`. The original unit
`post_validate` assertion is `api_status.bottom_line`; it does **not** explicitly
assert LTA_UPDATES or DSS1CRL/1OCSP. This helper retains that original assertion,
also asserts intact/valid/trusted, and records status/modification/DSS counts.
`--require-lta-updates` adds that stronger supplemental predicate only when the
caller asks for it. Do not claim it was an original unit assertion.

Independent supplemental controls require full-LTA empty-root distrust and
incorrect-digest `(intact=false, valid=true)` using the actual native CMS, loaded
signer certificate and actual ByteRange digest. Positive original failure cannot
be replaced by a successful supplemental refusal. Each failure returns process
status1 with an explicit failure receipt; successful output is one JSON record.
The current clock is not overridden. `--allow-hybrid` explicitly selects
nonstrict input/output parsing for the source's nonstrict LTA case.

## Fresh reference CLI on the current inputs

```text
PYTHON oracle_cli_current.py --input INPUT.pdf --output REFERENCE.pdf \
  --root root.der --record RECEIPT.json [--password-file PROMPT_FILE] \
  -- sign addsig ... pkcs12 ... INPUT.pdf REFERENCE.pdf ...
```

The script imports the pinned CLI source subtree and asserts pyHanko0.38.1 and
certvalidator0.33.0. It runs the complete argv through real CliRunner with the
source-style password prompter and current time. It installs no HTTP mocking or
time freezer. The output path must be separate from the native artifact, which
the caller archives first. Caller observations hash input/root/PFX/config/
passfile candidates before use and assert they remain unchanged; they are not a
production file-open trace. Config PFX/trust/other-cert paths are observed too.

The helper process may exit0 while the recorded inner `exit_code` is1. Tests
must check both the helper process result and the inner CLI result/exception.
For positive originals require inner exit_code0/exceptionNone and run the fresh
output verifier on the actual native artifact. Fresh same-input CLI comparison
and fresh native-output validation are separate oracle calls, not extra IDs.

The parent supplies isolated dependency overlay/runtime selection, including on
workers. Ambient parent variables alone are not evidence of worker selection;
normal Cargo uses the verified separate env.KEY.value/env.KEY.force leaf args.
Use the pinned interpreter path, not an unrelated system Python. No dependency
installation, shared venv replacement, Cargo or system/service change is needed.

## Status

Only AST parsing and pinned-Python import/`--help` smoke checks were executed
while preparing these files. No server was started, PFX/certificate generated,
HTTP request/signing/CLI invocation or output validation was run by that smoke.
Runtime behavior and native source-correct proof remain parent/root obligations.
The exact receipts/file hashes are saved in the lane's `pkcs12-lta-slice`
artifacts. Neither source-only preparation nor import smoke establishes a pass.
