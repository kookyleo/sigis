# Adobe evidence, processing order and exact function acceptance

Accepted source: `e353d42d2cbfa5e0c4be13ddaf2641bd2ba30d81`.
Evidence root: `/home/l/.codex/artifacts/sigis/round3-launch/ria-http-pdf-integration/`.
Previous accepted source45a8b44 and its source-freshness repair remain unchanged.
All implementation, assertion and oracle changes preceded this metadata acceptance.

## Measured workspace gate

| Step | Result | Seconds |
| --- | --- | ---: |
| Workspace build | Passed | 9.99 |
| Workspace tests | Passed | 475.47 |
| All-target clippy, -D warnings | Passed | 19.32 |
| Documentation, -D warnings | Passed | 189.55 |
| Layer and dependency-cycle gate | Passed | 3.53 |
| Formatting | Passed | 2.65 |

Rust results:1795 discovered,1791 passed,4 ignored,0 failed,170 reports.
These are runtime tests, not unique upstream functions. All Cargo invocations
used the repository wrapper and ordinary system placement; no shared-target
cleaning, compiler wrapper bypass, local pin or flag/profile/feature change.

The immediate compiler-artifact audit froze405 phase/unit observations and2475
emitted input records. Independent review rehashed393 actual unique source
files against BLAKE3, length, SHA256 and committed e353 Git blobs, including
both local vendor packages. This covers the selected compiler graph, not every
OS-level read, arbitrary external build-script input or every future cache race.
The earlier mtime false-green, initial dependency-hash failure and first absent-
fingerprint event remain preserved. The auditor retries only a first absent
fingerprint for one second; absence or non-content mode cannot pass.

The private CLI was built from exact e353 and copied at the same absolute path
on both workers. SHA256:
`800182f5bb8de95b285ce64d89f1b327d3db6096c12a701dcf6cd50a1158a073`,
96308888bytes, version0.0.1. Its producer has seven selected local units/133
input records. Five actual CLI selectors (config, crypt, fields, stamp,
runtime_read) use this executable; plugin/state dispatcher tests are in-process.
Private CLI receipts, worker hashes and actual test ELF identities are separate
from library compiler-input verification.

## Four unique functions

| Owner | Exact upstream ID | Native test | Transition |
| --- | --- | --- | --- |
| S/PDF | pyhanko/test_internal_utils.py::test_ordered_enum | ordered_enums::test_ordered_enum | skipped -> passed |
| S/PDF | pyhanko/test_internal_utils.py::test_version_enum | ordered_enums::test_version_enum | skipped -> passed |
| S/PDF | pyhanko/test_internal_utils.py::test_unbound_reference | reference_resolution::test_unbound_reference | skipped -> passed |
| C/CLI | pyhanko-cli/test_runtime.py::test_fail_read | runtime_read::test_fail_read | pending -> passed |

Each original has one execution, with six,14,one and two original assertions
respectively. There are no provider exclusions in this increment. Extra PDF
controls, CMS order tests, RIA fixtures, HTTP calls, old-input regressions and
oracle invocations add zero IDs. Inventory:1431/1263/26/142. S824/801/23/0,
C252/111/0/141; P297/294/3/0, V47/47/0/0 and L11/10/0/1 are unchanged.

The resolver's unbound reference returns Null. Bound references delegate to the
exact borrowed handler, retaining strictness, authentication, historical view,
cache and decode context. Five bound controls are supplemental. Source delegation
is not a directly executed remaining-budget assertion.

The runtime original executes the actual encrypted addfields command on the
same MINIMAL_AES256 input as fresh pinned Python: exit1 and Failed to read.
Input SHA256: `eda8c19fae7b63e715f0936d0359b698bc81ab69107e159507842f08dce8b69a`.
Both leave no output in this run. File side effects are supplemental observations;
this function establishes no signing, decryption or trusted-validation success.

## Trust and differential boundaries

AdES explicitly selects `CmsValidationOrder::SignerFirst`, validating main once
before processing timestamps. The default remains TimestampsFirst for existing
BASIC/CMS callers. The operation-owned registry and role-context identity retain
first-issuer/serial behavior; raw-invalid or algorithm-denied tokens cannot
register candidates. Invalid/nonintact signer-first main validation returns
before timestamp/AC processing. No caller mutation, preseeded trust, algorithm
cutoff, POE, imprint or revocation waiver is introduced. Exhaustive external
`CmsValidationOptions` struct literals must add `validation_order`; Default
and struct-update callers retain their default. Blanket source compatibility
is not claimed.

The signed Adobe RIA consumer reads the signed attribute evidence and passes it
to real validation. On two retained old native PDFs and two newly produced
Adobe outputs, actual native and fresh same-input Python now agree on finalOK.
Original counts, API bottom_line and typed RoleSyntax remain asserted; finalOK
is an extra regression assertion. Wrong-AA roots still deny trust. The old
NO_POE/native-versus-OK/Python receipts remain historical evidence; they are
not rewritten. This closes the exact observed profile discrepancy only.

The fixed29b Full-LTA profile under two requested timing flags remains NO_POE
with API trusted/bottom_line=true in both implementations. Fresh Python's
explicit-moment builder internally selects point-in-time behavior; the requested
flags do not prove two independent upstream timing semantics. Eight legacy
BASIC context-identity profiles retain four refusals/four positives. Full-LTA
API status is not final archival OK; separate roles and independent contexts
remain separate. Registration/persistent aliases, independent fetches and
unassigned profiles retain explicit coverage limits.

P HTTP coverage uses real loopback Reqwest transport over replayed PKI evidence;
it is not fresh PKI generation. Two actual outputs and four fresh reference
controls are retained durably, with test ELF/source/input hashes. P7's nine
actual outputs and two stale2028 AC denials remain enabled. The prior complete
Python9 P7 and2 Adobe parameter executions are distinct from same-output tails.
Additional source inputs verified213 V opens,69 S reads,18 live outputs,
six fresh S PDFs, six resource-operation refusals and encrypted continuation.

The full port is unfinished:26 skips,141 CLI pending functions and one real
CLI-LTA function remain. C's supplemental one-hour-tolerance reds and unaccepted
validation/qualification trust fixes are excluded. Fail-closed evidence is
bounded to exercised adversaries; all differences cannot be called fail-closed.

## Durable review artifacts

- `gate/gate.json`, `test-counts.json`, `compiler-inputs/compiler-input-audit.json`.
- `gate/runtime-verification.json`, `p-runtime-verification.json`,
  `added-runtime-verification.json`, and retained actual HTTP artifacts.
- `executable-v2-receipt.json`, `worker-v2-copies.json`, producer content inputs.
- `composition-review.md/json`, `final-review.md/json`, exact-source verifier.
- Final independent review Markdown SHA256:
  `eab4fd03ae0482d774b65eb5fa27d0f1b711da64e7007551652a9a445786b30a`;
  JSON `d8114e9167ae95406cbbc493a464f2ec19f9c57c158f158f19ef320acba261a7`.
