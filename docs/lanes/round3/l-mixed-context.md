# Matched-input counterexample and accepted registry repair

Status: **the matched29b more-trusting profile is repaired and fully gated**.
Historical pre-fix evidence is retained below; the current gate includes and
passes its regression. See [accepted repair](l-s-callers.md). The supplemental
regression adds no upstream IDs. Current counts are1431/1239/29/163.

This is a new, physically retained29b reproduction. It does not recover or
retroactively prove the earlier overwritten7075 PDF/binary sequence. The frozen
native executable is b9a854e1245d3201e4afa833223f11734f5a2da154ed120c199eb03e91200166,
built from09ec130 plus one explicit supplemental test. That production source
matched then-accepted6a33a07; current repaired source differs. The old test executes four profiles,
records every result, then fails with exit101 on the expected refusals.
The PDF and both root DER hashes are asserted before parsing:

| Actual input | SHA256 |
| --- | --- |
| encrypted PDF | 29b0a8a97e32bb220c96ac34d9906bcadf2d38dc7a13eb77336b63eaa6cdc4b2 |
| ECC root | ccc409838b97b5c04b18f889fa39b9b123868ff685751f58956206fb86d5ba90 |
| RSA root | 2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa |

The lead independently executes pinned public Python validation with these
exact files, logging their hashes before parsing. Time is fixed to
2020-11-01T00:00:00Z, tolerance1second, no fetching, NO_REVOCATION and default
weak-algorithm constraints. Both point-in-time settings are exercised. Native
and Python both verify actual signature integrity/validity and timestamp trust.

| Pre-fix profile, for each timing flag false/true | Native trusted / bottom_line | Python trusted / bottom_line |
| --- | --- | --- |
| combined signer/TSA context, ECC then RSA roots | true / true | false / false |
| separate ECC signer and RSA TSA contexts | true / true | true / true |

The native successful paths have valid signatures to explicitly trusted ECC
and RSA roots. This demonstrates a compatibility/trust-result discrepancy;
it is not evidence of forged signatures or an untrusted root bypass.
The pre-fix result violated the required no-more-trusting oracle boundary;
the accepted repair below closes this specific finding.

Fresh Python registration diagnostics preserve the unwrapped primary verdicts.
They record timestamp-first RSA registration, followed by rejection of the ECC
intermediate563435c97dca8ee1ba43f084d9330e66f0dee1b83bac98d03ff181b37ea00b5e
because the same issuer/serial identity already retains a different RSA
certificate with SHA prefix0e8fa78719fd. The pinned registry keys uniqueness on
issuer/serial before AKI/SKI issuer filtering. Native certificate augmentation
clones the context and deduplicates complete DER, leaving both valid chains
available. Separate-role controls do not fix production shared-context behavior.

Repair requires exact registration/order compatibility or an explicitly
bounded fail-closed treatment, with both timing flags and separate-role
positive controls. Do not add global cross-domain collision rejection without
showing its effect on valid independent contexts. Keep context-clone policies,
assertions, historical constraints and actual cryptographic checks intact.

Evidence:

- round3/s/pdf-callers/mixed-context-fresh/: preserved source archive,
  native-frozen, native-receipt.json, native-red.log and actual inputs.
- round3/l-next/mixed-profile-fresh/: lead fresh preparse receipts, four
  unwrapped profiles and four separately traced registration diagnostics.
- round3/l-next/combined-profile-oracle.py: the executed helper, exact inputs,
  pinned versions, current policy and registry snapshots.

No source fixture, root, timing policy or original function is weakened to
obtain a green result. This supplemental regression now runs automatically.


## Accepted bounded repair

Sourcedc90dceee5f0ce7d8287019e1b15eae923ea8ee2 passes the full workspace gate. All eight actual profiles match
the fresh pinned oracle, with raw-invalid/denied/wrong-imprint/unvisited-token
and nondefault context-state guards. The pre-fix violation is not an accepted
exception. AC aliases, cross-public-call persistence, fetched-candidate insertion
and custom-manager seed-order parity are separately scoped; no universal
all-divergences-fail-closed claim follows.
