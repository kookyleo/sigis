# Explicit certificate time tolerance acceptance

Accepted source: `f0ed26a4df08edd7d32c4f6dd9a660e1e45db279`.
Evidence: `/home/l/.codex/artifacts/sigis/round3-launch/tolerance-integration/`.
This shared repair adds **zero unique upstream functions**. The inventory stays
1431 total/1263 passed/26 skipped/142 pending. C's separate ordinary/qualified
validation engine and the final live CLI-LTA function are not accepted by it.

## Problem and bounded repair

C's supplemental real-process and direct public PDF tests reproduced the same
problem: a certificate expired by30minutes was correctly rejected with30seconds
tolerance, but still rejected with the explicitly selected3600seconds. The
context retained the correct value. The native issued-certificate preflight
already used moment±tolerance; certval then repeated strict single-time validity
and undid that decision.

The private settings helper now selects certval's disabled validity sentinel
only for nonzero tolerance after every issued certificate has passed the native
window check. Zero tolerance retains the actual certval TimeOfInterest. No
context clock changes: algorithm policy, revocation and freshness still use the
actual caller-selected time. Strict anchor qualifier bounds are checked first,
without tolerance, including direct-anchor paths. The existing issued-path DER
time range guard remains intact. All three primary/additional-permitted/relaxed-
excluded settings calls share this adapter. There are no new APIs, dependencies,
features, profile/flag changes, layer exemptions or status overrides.

Pinned certval's direct RFC5280 validator consumes its settings time only in
check_validity. Its other time consumers belong to builder/source/revocation
routes that this direct adapter does not use; certval network/revocation are
already disabled in favor of native checks. Existing key, signature, critical-
extension, name, policy, KU and EKU checks still execute. Enforced anchor
construction derives immutable strict qualifier dates from the certificate.
This justification is specific to the current pinned dependency/call graph,
not an unreviewed guarantee for future versions.

## Tests first and differential evidence

The final test-only source54be34e ran before the exact production patch:
1 passed/5 failed, exit101, zero input-audit errors. After productionf0ed26a,
6 passed/0 failed/0 ignored; a serial evidence run also passed. Independent
review confirmed identical test bytes across corrected RED/GREEN and production
bytes identical to the initial minimalf547 patch.

Six supplemental functions exercise29 actual path-validation calls:

| Control | Calls | Required result |
| --- | ---: | --- |
| Leaf notBefore and notAfter,30-minute offset | 10 | 0/30/1799seconds reject;1800/3600 accept, including equality |
| Intermediate notBefore and notAfter, independently valid EE | 4 | 30 rejects with intermediate position/horizon;3600 accepts |
| Default versus enforced root, both boundaries | 8 | Default anchor remains unbounded; enforced qualifiers always reject |
| Additional permitted namespace sets | 3 | Tolerated validity does not remove independent caller/anchor restrictions |
| Excluded-name diagnostic retry | 2 | Disjoint namespace accepts; actual SAN exclusion remains a name denial |
| Actual-time typed algorithm cutoff | 2 | Allow control accepts; deny retains cutoff, EE position and horizon |

Fresh pinned Python0.38.1/certvalidator0.33.0 made29 real public
async_validate_path calls. All29 decisions match the native matrix; ten raw/DER
inputs and three primary source files were rehashed. All22 emitted native input
records match actual certificate DER/time/tolerance. Seven other invocations
share recording sites;22 is neither the number of path calls nor function IDs.
The typed policy callbacks observe actual2022-01-01T00:30Z, including rejection
after the00:15Z cutoff. No revocation differential is claimed for this focused
suite; existing complete-workspace revocation controls remain mandatory.

The first intermediate fixture had a1950 UTCTime outside the current native
model and failed during parsing. It was replaced by the already accepted
PKITS40204 GeneralizedTime leaf, with actual matching issuer/signature and an
independently valid EE at the CA boundary. Production parsing was not broadened.
The old failure is retained. An initial Python namespace mapping incorrectly
replaced all name-type defaults; corrected V2 retains other defaults and changes
only DNS. V1 is retained and contributes no parity evidence.

## Measured full gate and provenance

| Step | Result | Seconds |
| --- | --- | ---: |
| Workspace build | Passed | 8.76 |
| Workspace tests | Passed | 487.54 |
| All-target clippy, -D warnings | Passed | 20.87 |
| Documentation, -D warnings | Passed | 194.98 |
| Layer and cycle check | Passed | 6.76 |
| Formatting | Passed | 2.70 |

Measured1801 discovered/1797 passed/4 ignored/0 failed,171 reports. The six new
runtime tests add no original IDs. Immediate content verification captured407
phase/unit observations,2480 emitted input records and394 actual source files,
including both local vendor dependencies. The independent final review rehashes
frozen fingerprints/dep-info against actual source and committed Git blobs.
Selected input checks are not OS tracing of every read or an arbitrary external
build-script/future-cache-race guarantee.

A new private CLI was built from exactf0ed26a with seven local units/133 input
records. SHA256 `2d951dd058784ece6d6a84632e354ddd0cc8774b2dfe6f2c1ff3b3ebd3a3e085`,
96309912bytes, version0.0.1. Both VM copies at the same absolute path match hash,
length and version. All five actual CLI selections use that artifact. Shared
canonical targets, system placement and configured sccache remain unchanged;
no second root Cargo, shared-target clean or service action was used.

Retained source-specific runtime proof includes213 V opens,69 S reads,18 live
outputs, six newly validated S PDFs, six resource-operation refusals, encrypted
continuation, nine P7 outputs/two stale2028 AC denials, two current/two old Adobe
PDF profiles, two real HTTP outputs/four controls and the exact runtime-read
case. Adobe stays finalOK in both implementations. Full-LTA29b stays NO_POE with
API trusted=true; eight BASIC role-context profiles retain their refusals and
positive controls. These are retained regressions, not new acceptance IDs.
The reused verifier's historical new_ids/exact_new_ids label denotes four
already-accepted live function IDs; evidence-scope.json records zero new credit.

## Durable evidence and limitations

- Corrected `red-v3-correct-fixture/`, `green-v2-correct-fixture/`,
  `green-v3-serial-evidence/`; old fixture/setup failures remain preserved.
- `oracle-v2/`, `verify-reference.py`, `reference-review.json`, `handoff.md/json`.
- `production-review.md/json`, the exact pinned certval/adapter call-graph audit.
- `gate/gate.json`, `test-counts.json`, frozen compiler inputs, sidecar/runtime
  verifier receipts, actual HTTP outputs and executable/source snapshots.
- `executable-v2-receipt.json`, `worker-v2-copies.json`, producer content inputs.
- Independent `final-review.md/json` and the checker with any initial artifact-
  schema adaptation failure preserved separately.

This fixes the exercised tolerance discrepancy and preserves tested security
controls. It does not prove universal temporal/trust parity, eliminate the
pre1970 model limitation or accept C's separate engine. Python CLI's automatic
revocation disable for explicit/claimed time is also distinct: the native
force-revinfo negative is a mandatory-policy supplement, not proof of the exact
Python CLI rejecting that same case. No all-divergences-fail-closed or complete-
port claim follows.
