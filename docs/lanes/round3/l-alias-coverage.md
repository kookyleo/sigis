# Deprecated timestamp session forwarding and checked coverage boundaries

Accepted source: `7232e9c0d80c435cf29035053577ca87badb79a2`.
Evidence root: `/home/l/.codex/artifacts/sigis/round3-launch/alias-coverage-integration/`.
Only three source files change from accepted main e0416a2: pades/coverage.rs,
pki-fetch/tsa.rs and pki-fetch/tests/deprecated_tsa.rs. Their postimages match
reviewed V7efb68d and S6913910 exactly. No manifest/lock/dependency/layer change.

## One exact function and explicit language adaptation

`pyhanko/test_tsa_fetcher.py::test_deprecated_aiohttp_timestamper_forwards`
ports to `deprecated_tsa::test_deprecated_aiohttp_timestamper_forwards`.
One original function, one scenario, no parameter/provider exclusions. It checks
supplied-session identity and TimestampRequestError on the actual digest/request.
The wrapper delegates to the existing client, retains the same Arc and does
not close the caller's transport. Actual request DER, digest/algorithm, nonce,
transport identity and caller lifetime have native assertions.

Lead accepts an explicit language-phase adaptation: standard Rust #[deprecated]
produces a compile-time diagnostic instead of Python's runtime DeprecationWarning.
The compile-fail test permits only the import; the actual constructor expression
must fail under deny(deprecated). An independent modern constructor compiles and
runs under the same deny setting without local allowances. This excludes a
missing-symbol/import false-red. Four runtime tests and two new doctests cover
one original ID, not six; the third fetch doctest is the existing auth guard.
No runtime warning or complete optional legacy async API is claimed.

Explicit transports enforce their own deadline/body configuration. Setting the
client's timeout metadata does not reconfigure a supplied transport. The paired
Reqwest instance is also configured30seconds; immediate refusal measures no
actual deadline expiration. Arc lifetime is distinct from the remaining generic
async/backend/context-close/bootstrap exclusions. These limitations remain part
of the full-port work even after this original function is completed.

Inventory after acceptance:1431 total/1264 passed/25 skipped/142 pending.
S824/802/22/0; fetch56/44/12/0; library1168/1143/25/0. Other owners unchanged:
P297/294/3/0, V47/47/0/0, C252/111/0/141 and L11/10/0/1.

## Checked numeric helper behavior

V changes checked encoded Contents length and EOF cursor arithmetic. Genuine
root tests-first source44ed4c3 ran seven coverage tests: four passed, three
panicked with overflow. The alias target failed compilation with the required
missing type/getter errors, also before production. Both emitted-input audits
had zero errors. After the minimal production patches, coverage7/7, alias4/4
and fetch doctests3/3 pass with zero input-audit errors.

Original entire-file, entire-revision and contiguous controls remain. Four new
coverage tests add zero original IDs. Unrepresentable Contents lengths return
Unclear; unrepresentable EOF cursors return a typed error, retaining the existing
contiguous fallback rather than complete coverage. The independently reviewed
checked total bounds the subsequent additions. Python may raise OverflowError
at stream seek before scanning huge positions. Empty/numeric helper calls are
not actual signed PDF or trusted-verdict comparisons.

V's separate worker evidence contains two real RED runs and final7/0/0 on
vm2064.0/server64, using sealed actual executables. Independent review rehashed
three archived ELF files and their13 emitted source inputs against Git/BLAKE3.
That evidence is separate from older unit-fingerprint observations and from
this exact integrated source's measured gate.

## Fresh actual transport and oracle evidence

The root freshly executes the exact pinned original pytest function:1 passed,
zero failures. Three unrelated BasicAuth collection warnings are retained.
This is an actual original function execution, separate from additional probes.

The integrated alias native target is frozen from the selected focused compiler
artifact. Its current FP/dep-info equal immediate captured snapshots; emitted
test-source inputs match Git7232, and the binary is stable before/after copying.
SHA256 `b49937060a7e6676a2ff0f93d03adcebbd0be09fd078a04dea4c0bd6417437e3`,
36809136bytes. Linked local inputs are covered by the separate compiler graph
audit; this statement does not claim OS-level tracing of every linker read.

That actual frozen executable makes two failed HTTP requests to one held bound
nonlistening loopback endpoint. Fresh Python makes two public legacy/modern
requests to the same still-held endpoint with identical digest/algorithm and
30-second configuration. Both error classes/messages and supplied-session
identity agree. Python's actual runtime warning is recorded separately from
Rust's compile-time diagnostic. Endpoint control creates neither a server nor
fresh PKI evidence; there is no generated signature/token or trust verdict.
The supplemental native process has no Cargo slot because it performs no build.

## Measured complete gate

| Step | Result | Seconds |
| --- | --- | ---: |
| Workspace build | Passed | 7.69 |
| Workspace tests | Passed | 478.62 |
| All-target clippy, -D warnings | Passed | 16.77 |
| Documentation, -D warnings | Passed | 202.06 |
| Layer and cycle check | Passed | 13.83 |
| Formatting | Passed | 2.75 |

Measured1811 discovered/1807 passed/4 ignored/0 failed,172 reports.
Immediate source checking captured409 phase/unit observations,2485 emitted
records and395 actual source files, including both local vendor packages.
Independent final review rehashes frozen FP/dep-info and actual Git bytes.
Selected source auditing is not OS-level tracing, arbitrary external build-
script coverage or a guarantee about every future concurrent artifact race.

A new private CLI is built from exact7232: seven local units/133 input records,
SHA256 `7ca7425d0fdf7e4add3438a8edacda114699d3f367dc4aad5355c0315808716e`,
96311048bytes, version0.0.1. Same-path copies on both VMs match hash/length/version;
all five actual CLI selectors use this producer. Canonical targets, sccache,
system placement, compiler flags/profiles/features and services remain unchanged.
Root Cargo commands were sequential; there was no shared-target cleanup or push.

Retained runtime proof rechecks213 V opens,69 S inputs,18 live outputs, six S
outputs freshly validated by Python, six resource-operation refusals, encrypted
continuation, P7's nine outputs/two stale2028 controls, two current/two old Adobe
PDFs, HTTP2/four controls and runtime-read1. Adobe stays native/Python finalOK;
Full-LTA29b stays NO_POE with API trusted=true; BASIC8 retains independent refusals
and positives. CV's six tolerance regressions also pass. Its29 fresh Python
reference calls were made for prior sourcef0ed26a and remain retained evidence,
not new7232 oracle executions; both CV source/test bytes are unchanged. A
single full-gate CV JSON line interleaved with independent harness stdout;
that raw log and the initial checker failure are retained. A source-unchanged,
wrapper-controlled serial rerun passes all six CV tests and yields22 intact
input records, with five selected compiler units/49 emitted inputs verified.
Final review uses those actual serial records, not reconstructed JSON. This
supplemental rerun changes neither full-gate totals nor original-function credit.

## Evidence and limits

- `red-receipts.json`, `v-red.log`, `s-red.log`, frozen red inputs.
- `focused.json`, `coverage.log`, `alias.log`, `alias-doc.log`, focused inputs.
- `s-alias-review.md/json`, `v-coverage-review.md/json`, pinned owner evidence.
- `fresh-original/`, `frozen-build-receipt.json`, `alias-native-frozen`,
  `paired-root-v1/`, source-pinned paired probe.
- Private CLI producer, worker copies, complete gate, actual runtime verifier
  receipts, frozen compiler inputs and durable HTTP outputs/test ELF/source.
- Independent `final-review.md/json`, checker and exact artifact receipts.

Only the single S original is added. Reused verifier labels new_ids/exact_new_ids
refer to four retained live IDs already accepted earlier. Numeric helpers,
transport probes, runtime guards and oracle calls never create extra IDs.
All25 remaining skips,141 CLI pending functions and the final real CLI-LTA
function remain. C's obsolete unsupported-time-tolerance restriction and removed
positive tests were rejected; the accepted shared fix must be consumed with the
original controls restored. No complete-port or universal fail-closed claim is
made from this bounded increment.
