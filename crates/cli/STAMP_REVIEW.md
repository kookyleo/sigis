## Verification basis correction

The reported141 tests are real,but they ran the projected CLI code in the
assigned owner's lower-layer snapshot19e4de6. Candidate parent e1e916a has22
different lower-layer files,including7 production sources. The projection
replaced C-owned files only,so it did not test the full147578e candidate tree.
The previous wording calling this independent candidate validation was too
broad. Keep147578e as a reviewable source patch; exact-base verification is
pending safe synchronization or L's independent candidate-tree gate. No
behavioral/trust divergence is inferred merely from a source diff. The12
functions remain unaccepted; accepted C98 is unaffected because its actual
L gate ran independently on09ec130. The published147578e ref is preserved.
Exact lower-source hashes are in verification-basis-correction.json under
the stamp-increment artifacts. The historical result below describes that
projected CLI execution only,and must not be promoted to complete-tree proof.

# Standalone stamp review increment

Base e1e916a has accepted98 C functions. This candidate proposes only12 exact
standalone stamp functions/14 source parameters; accepted C stays252/98/0/154
until L review and the complete workspace gate. The fixed assignment is252.
No signing/validation/LTV/runtime or decode-function credit is requested.

The same12 test functions first failed on the accepted explicit-unsupported
CLI artifact SHAffc61fff... (0 passed/12 failed; no filters/ignores). Then
the candidate added the stamp module and one dispatch arm,using existing
configuration and stateful lower stamp APIs. It independently built its own
ELF SHA9c3106dba97e9e2da2d75c8f8aecf330b8d05f961b3da23e3555e30709c96024
on s7.1. Identical copied artifacts/version probes exist on vm2064/vm2065;
the actual vm2065.0 tests explicitly select that new binary through Cargo
env value+force leaves,never the full unmerged CLI. No dependency/version or
layer/root manifest change. Native production src/stamp.rs is inherited
byte-exact from the owner implementation; the accepted prefix's other
production modules and tests remain intact. src/lib.rs adds only stamp
registration/dispatch and documentation. Shared main refs are unchanged.

Candidate all-target results:141 passed/0 failed/0 ignored/0 filtered:
128 accepted prefix tests+12 stamp originals+1 supplemental test. This141
is a different source scope from the earlier full-C config/policy/validation141.
Check and all-target clippy -D warnings pass on vm2065.0; strict docs pass on
s7.1 and fmt passes. These are package checks,not L workspace/layer gate.
All Cargo uses tools/cargo-locked.sh and normal absolute scheduler dispatch;
no local pin,remote Cargo,job/target/compiler/profile/feature override or kill.

Pinned upstream pytest freshly passes14 parameters/12 functions. Native tests
freshly invoke the pinned Python CLI for all14 cases,comparing status and
meaningful negative substrings. Positive Python exception is explicitly None.
The three original trailing --stamp-url positions after x/y are preserved.
Every negative checks no output file. Four positive native and oracle PDFs
retain the exact input prefix and revision2; native outputs contain XObjects.
The native test process,selected ELF and actual temporary inputs/outputs have
path/length/SHA256 records in STAMP_REVIEW.json and the matching runtime log.
These are before-use snapshots,not all lower file-read traces. No pixel or
layout identity is claimed (upstream itself has TODO layout checks); output
encoding/font metadata and nonasserted diagnostic quoting may differ. No
universal compatibility or fail-closed claim follows.

The single supplemental test covers text/QR default-limit rejection with
rerun hint/no output,and explicit --no-decode-limits success producing a real
incremental PDF. Production passes the same parsed reader through
PdfReopenState into text/qr_stamp_pdf_with_state. This does not establish all
finite custom remaining-budget,authentication or strictness combinations.
The two upstream decode stamp functions remain outside this12-function
proposal,and the field update helper is not imported or credited.

Exact runtime selector example:

```sh
tools/cargo-locked.sh test -p sigis-cli --all-targets \
  --config 'env.PYTHONPATH.value="/home/l/.codex/artifacts/sigis/round3/c/oracle-deps"' \
  --config 'env.PYTHONPATH.force=true' \
  --config 'env.HANKO_ORACLE.value="/tmp/pyhanko-oracle/venv/bin/python"' \
  --config 'env.HANKO_ORACLE.force=true' \
  --config 'env.SIGIS_CLI_TEST_BIN.value="/home/l/.codex/artifacts/sigis/round3/c/executable-stamp-increment/pyhanko"' \
  --config 'env.SIGIS_CLI_TEST_BIN.force=true' -- --nocapture
```

Receipt prefixes stamp-red-baseline/check/build/tests/clippy/docs/fmt-check
are under ~/.codex/artifacts/sigis/round3/c/. Detailed audit,source snapshot,
immutable-artifact receipt,upstream pytest log and runtime provenance are
in stamp-increment/. The complete owner source and original dirty lock are
archived byte-exact before projection and restored afterward. No full source
restoration or known-red CLI test is imported into this candidate.

## Exact upstream mapping

| Upstream ID | Rust test | Source cases |
| --- | --- | ---: |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_with_style | stamp::test_cli_stamp_with_style | 1 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_with_qr_style | stamp::test_cli_stamp_with_qr_style | 1 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_no_config | stamp::test_cli_stamp_style_no_config | 1 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_stamp_url_unnecessary | stamp::test_cli_stamp_style_stamp_url_unnecessary | 1 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_stamp_url_mandatory | stamp::test_cli_stamp_style_stamp_url_mandatory | 1 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_undefined | stamp::test_cli_stamp_style_undefined | 1 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_text_param_missing | stamp::test_cli_stamp_text_param_missing | 1 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_text_param_formatting_wrong | stamp::test_cli_stamp_text_param_formatting_wrong | 3 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_text_param_multiple_substitution | stamp::test_cli_stamp_text_param_multiple_substitution | 1 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_text_param_fail_partial_substitution | stamp::test_cli_stamp_text_param_fail_partial_substitution | 1 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_unspecified | stamp::test_cli_stamp_style_unspecified | 1 |
| pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_malformed | stamp::test_cli_stamp_style_malformed | 1 |
