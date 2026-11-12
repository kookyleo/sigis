# Round 3 S inherited skip audit

Baseline: pyhanko-certvalidator 0.33.0, pinned source commit `b48999514cb4`.
The assigned crate denominator remains 133 unique upstream test functions.
The baseline is 92 passed, 41 skipped and zero pending.
After targeted Rust verification, the lane result is **133 total / 98 passed /
35 skipped / zero pending**, pending lead integration acceptance. Exactly the
six name-predicate functions move from skipped to passed.

## Name predicates

`src/validate/name_constraints_tests.rs` translates every exact upstream
assertion and parameter in `test_name_trees.py`. The fixture is extracted
from the pinned AST, preserving the Unicode DNS negative case, local-part
case sensitivity, boundary labels, trailing root dots and URI failures.

| Upstream function | Rust test | Parameters |
| --- | --- | ---: |
| `test_dns_tree_contains` | `validate::name_constraints_tests::test_dns_tree_contains` | 15 |
| `test_host_tree_contains` | `validate::name_constraints_tests::test_host_tree_contains` | 14 |
| `test_host_tree_contains_rejects_empty_base` | `validate::name_constraints_tests::test_host_tree_contains_rejects_empty_base` | 1 |
| `test_email_tree_contains` | `validate::name_constraints_tests::test_email_tree_contains` | 15 |
| `test_uri_tree_contains` | `validate::name_constraints_tests::test_uri_tree_contains` | 7 |
| `test_uri_tree_contains_requires_fqdn` | `validate::name_constraints_tests::test_uri_tree_contains_requires_fqdn` | 2 |

These predicates are consumed by production excluded-name validation.
Constraint errors are propagated as explicit path validation failures.
They are not disconnected compatibility helpers.

## Native graph operations and policy results

Source d1e38df passed build, tests, strict clippy, strict docs, layer and fmt:
1359 discovered / 1351 passed / 8 ignored / 0 failed,
across 109 reports. Only the33 exact immutable S policy-graph IDs change
skipped -> passed. Production path validation uses the same native RFC9618
graph; certval remains mandatory. All source assertions were independently
reviewed, and the lead freshly reran all33 pinned Python tests successfully.
Eight partial final-row adapters were replaced by real mutation/mapping tests.
Oracle calls and native helpers earn no additional upstream-function credit.

Accepted certvalidator133/131/2/0; S824/787/30/7; overall1431/1085/33/313.
The two deprecated registry entry points remain skipped. The six-file curated
source includes d79ee62 empty-intersection protection and68a1ae7 native graph,
preserving accepted typed algorithm horizons. Actual transient node limits
reject a six-node peak even when only five nodes survive. Disjoint caller and
anchor policy sets retain their empty intersection during path validation.
Already-materialized public merge empty-set provenance remains a separate API
gap. Native limits apply after certval, not to whole-validator memory use.
No universal fail-closed parity claim follows from this increment.

Existing S comparisons cover21 public policy/limit results, five actual DER
hashes and four qualifier encodings; the lead's separate33-function Python run
is fresh execution. Logs: round3-launch/s-policy-graph-gate/ artifacts.

## Deprecated registry entry points

| Upstream function | Remaining feature gap |
| --- | --- |
| `pyhanko-certvalidator/test_registry.py::test_system_trust_fallback_deprecated` | There is no implicit OS trust loader or Python DeprecationWarning API; a mocked loader returning no certificates and the exact warning cannot be asserted through a Rust equivalent |
| `pyhanko-certvalidator/test_registry.py::test_extra_trust_roots_deprecated` | There is no extra_trust_roots alias or deprecation warning; explicit trust roots are covered elsewhere, but that does not port the warning assertion |

No deprecated compatibility alias was added merely to manufacture a pass.
No blanket equivalence claim is retained for any of the 41 baseline skips.
Six name functions now pass all 54 upstream cases in Rust. All 33 graph functions remain
skipped, including eight with partial adapter coverage; two deprecated
registry functions remain skipped.

## Verification

No provider-dependent early return is present in the new tests. The six
name tests always execute all 54 parameter cases and the eight policy
tests always execute their assertions. Live oracle evidence and final
build/test logs are recorded in the lane artifact handoff. A fresh pinned-AST
comparison confirms the fixture exactly preserves all six functions and 54
cases, including the non-parametrized empty-host error assertion.

All Cargo commands used `tools/cargo-locked.sh` with normal configured
compiler wrappers, features and profiles. Check passed on vm2064 slot0 in
0.91s. Formatting completed successfully. The final full library unit suite
passed 25/25 tests and `policy_proc` passed 13/13 on vm2065 slot0, both with
zero failures and zero ignored tests. Library tests include the six name
functions, eight partial graph adapter tests and both context-preservation
regressions. The graph fixture encodes qualifiers through alloc-backed
`Vec<PolicyQualifierInfo>` without enabling heapless features; exact DER
qualifier assertions are retained. Invalid-name errors are mapped to a
path-bearing `PathFailure` at the production caller.

The verified lane result is 133 total / 98 passed / 35 skipped / zero pending.
Eight synthetic policy adapter tests earn no upstream-function passes; the
two context regressions also earn none. Fresh oracle calls remain a separate
measurement: 54 name invocations and eight graph invocations passed. Lead
acceptance and the complete workspace gate are outside this targeted result.

The targeted `pkits` integration suite subsequently passed 2/2 on vm2065
slot0 (compile 0.72s, tests 1.89s), with zero ignored tests. It exercises
the existing 246-case corpus and simulated CRL fetches after the production
name-predicate change. The exact known-divergence guard still permits only
case 40203 (the Rust DER decoder rejects UTCTime year 1950); no newly
accepted oracle rejection or additional divergence was introduced. This
is committed-fixture replay, not a fresh Python comparison, and earns no
additional upstream-function count. Log: `slots-pki-pkits.log`.


The lead acceptance above supersedes the historical targeted verification:133/131/2/0.
