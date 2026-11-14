# Decode limits for simple commands: three originals, six parameters

Source `14d6c6a3340714e14fe1d1798e047227b0442dc5`; current accepted parent6b35096d
(C252/190/0/62, overall1431/1356/13/62). The completed current-source Root acceptance records C result: **252/193/0/59**. Combined with the separately
reviewed S1 cohort, Root's accepted overall is **1431/1360/12/59**.
Full workspace Rust results: **2118 discovered /2115 passed /3 ignored /0 failed /215 reports**.
Final independent gate review SHA256: **25fa11d1ab703d58c5c0ca450b9afbd35a35cb6a8fac55f15ea67178e9d0ea58**.
All six returned gates/audit0 and final independent review precede this acceptance.
Gate: All six returned0 with audit0 (build 3.2s; test 1113.47s; clippy 9.75s; doc 64.23s; layer 3.7s; fmt 3.57s).

## Exact original mapping

| pyhanko-cli/test_cli_decode_limits.py original | Rust test | Parameters |
| --- | --- | --- |
| test_simple_commands | decode_limits_simple::test_simple_commands | encrypt/list/addfields/addfields-resave:4 |
| test_text_stamp | decode_limits_simple::test_text_stamp | configured text:1 |
| test_qr_stamp | decode_limits_simple::test_qr_stamp | configured QR:1 |

The QR nosmoke marker is not an ignored/provider case. Previously accepted
`test_decrypt_password`, `test_decrypt_pubkey` and `test_timestamp` are excluded;
addsig/validate/LTA update/LTV fix remain pending. Supplemental tests, parameters,
reference calls and output parsers add zero unique IDs.

## Measured baseline and minimal implementation

Tests-first16efb59c executes the complete integration target against accepted
A2 CLIa2cea192:3passed/1failed/0ignored/0filtered,37.53s wall and29.53s harness.
All six default attempts reject with the original rerun diagnostic. Trusted
encrypt/list/text/QR already pass; only trusted addfields and addfields-resave
fail from the field writer's default-reader reopen. The single four-parameter
simple function is incomplete at that baseline. No missing-helper compilation
or invented text/QR RED substitutes for these actual command failures.

Production14d changes ONLY crates/cli/src/fields.rs:25diff lines,
16insertions/9deletions. It transfers the actual selected parsed PdfFile into
PdfReopenState::from_reader -> PdfUpdate::open_with_state and calls make_fresh
only for --resave. It removes the second default PdfUpdate::new/fresh parse and
writer-only set_strict(false). Existing lenient/default-finite or explicitly
trusted policy and remaining budget survive. Command grammar, field/page/box
routing, encrypted-document refusal, field append and final write remain.
No top-level route, shared API/dependency/manifest/lock or alternate PDF engine
is introduced. Existing fs::write is not a new atomic replacement guarantee.

## Actual current producer and focused results

Actual source14d immutable CLI SHA256
34d4a7de82ba69ecf125b4bf708651402bee8d83124e2b83a2cc3f8bd9dd581d,
124035704bytes; producer13units/236records. Both vm2064/vm2065 copies record
that same path/hash/length/version. Copies do not imply worker test execution;
actual focus process receipts identify s7.

Current integration target:4passed/0failed/0ignored/0filtered,
36.18s wall and33.11s harness. Those four tests are the three originals plus
one2-case encrypted-field refusal supplemental. Reader-state units:
2passed/0failed/0ignored/0filtered,6.65s wall and2.39s harness.
Six passing Rust tests are not six upstream original functions.

The private integration raw ELF hash43521582/29624456bytes is independently
checked after decompressing gzip archive14abfae5/7939554bytes. Private reader
unit raw ELF0ae6b443/59812784bytes decompresses from archive0fefdc68/15780470bytes.
Archive identity is never substituted for raw ELF identity. Post-run/pre-later-
Cargo capture is explicit, not run-instant copying; runtime process hashes bind
actual execution. Baseline and green driver ELF may be identical because the
external immutable product changes from A2 to34d4. Owner905ec334 results are
historical and are not relabelled as source14d.

## Complete fixture and input binding

Fresh reference calls load hash-pinned actual original functions and _check_flag,
with manually entered original cli_runner and oversized_input fixtures. This is
not full pytest scheduling. Every peer invokes real CliRunner twice, asserting
default exit1, exact `rerun with --no-decode-limits`, and flagged no exception.
No PKI, architecture multiplier, timestamp, trust clock or inherited
post_validate fixture applies to these unsigned operations.

The real fixture copies MINIMAL, moves EVERY non-stream object into ObjStm,
and pads with a3MiB ByteString serialized as6MiB hexadecimal zeros. Offline
inspection of all six freshly prepared actual6937-byte native inputs verifies
one6291718-byte decoded ObjStm and that full padding. The committed compact
fixture is replay only in the separate reader-state test. Independent original
fixture generations retain separate input hashes; same-input helper peers use
the actual native bytes/config in disjoint directories. No smaller/catalog-only
fixture or independently generated reference PDF substitutes for native output.

## Actual complete process and output observations

Current37process records are exactly:

- 6fresh native fixture prepares;
- 12native original commands:6default exit1/diagnostic/sentinel,6flagged exit0;
- 6fresh unchanged original-body calls, each2real CLI invokes;
- 6fresh same-native-input helper calls, each2real CLI invokes;
- 5fresh actual native output inspections;
- 2native encrypted-field refusal supplements, resavefalse/true.

All131archive length/SHA checks and26actual Python-read bindings pass. Native
input hashes match same-input peers; text/QR config hashes match actual reads.
Both native attempts freeze before references. Original fixture inner input/
output/config artifacts copy before teardown and remain durably archived.
The actual signing_record helper asserts input bytes unchanged.

Five actual trusted output PDFs receive compiled native structure checks and
fresh same-native-output reference parsing. Explicit opened-file hashes equal
native frozen outputs, not samples: encrypt owner authentication with secret,
one page/one revision; empty Sig1 with correct Rect/Widget/page0 P/Annots,
incremental2/resave1 revisions; text/QR one page/two revisions/actual Form objects.
List produces empty stdout and retains sentinel; it invents no PDF parse call.
These unsigned checks prove stated structure/authentication, not signer trust,
QR payload decoding or full visual rendering. No irrelevant empty-root trust
scenario is introduced.

Both encrypted-field commands use actual isolated cwd, exit1 with unchanged
authentication-required refusal and retain inputs/sentinel. They establish no
encrypted field editing or new authenticated/MAC success path.

## Finite-state versus trusted-state limits

Actual field unit1 covers strictfalse/true x resavefalse/true: spend800 of1000,
retain200 with exact limits and reader/writer strictness, append field, then
refuse late300 decode. It does **not** prove finite-budget final serialization.
Unit2 uses compact trusted replay, writes CompactField and reopens actual output
while retaining lenient/unbounded trusted limits and incremental2/fresh1
revisions. These are different claims and neither earns an original ID.

Independent C focus report/checker/receipt is under
`/home/l/.codex/artifacts/sigis/round3-launch/decode-disabled-integration/c-focus-review`.
It binds714current source records plus241baseline records,57saved fingerprint
objects, binary checksum bindings, actual process/output archives and decompressed
ELF identities. Independent source recomputation here uses SHA256; recorded
BLAKE3 fields are cross-bound, not described as independently recomputed.
Completed source/gate verification and measured aggregate Rust results above
remain separate from the focused C evidence. No universal fail-closed, trust parity,
complete-port, encrypted-field, atomic-I/O or all-appearance claim follows.
