# Provider defaults and historical OCSP precision

P's `768ca9b5` was curated as `73e42a5f`: the existing test SDK module, utility
and0.9.5 overlay are discovered in shared/private installations when worker HOME
differs. Explicit overrides retain precedence; absent real dependencies still
fail mandatory tests. No fake provider, algorithm exclusion/default-policy,
manifest or lock change was introduced. Default RootDSA3 and import2 passed
without resource or provenance selectors.

The first plain combined run exposed an independent functional difference: native
full LTA returned OK while pinned pyHanko returned NO_POE for the same native CLI
PDF. The equality was not removed. Its original TempDir was unavailable after
panic; failure-time input retention captured a second real reproduction. That
unchanged PDF/root are finite public fixtures in `r3-l/lta-subsecond` (no private
credential was committed). OCSP thisUpdate was04:48:36.125430Z while the declared
whole-second validation reference was04:48:36Z. Native lenient decoding had lost
the fractional issuance precision before strict historical filtering.

Fresh pinned public full-LTA checks with LOCAL_ONLY/NEVER_FETCH return NO_POE at
36Z, retaining intact/valid/trusted API status, and OK at37Z on identical bytes.
The signed native regression first failed the36Z assertion while its37Z positive
passed. After the fix both pass and require fresh same-input pinned peers. Three
metadata-only tests separately cover integral/fractional/zero/trailing-zero
bounds, response index and unavailable/malformed original time; they do not
claim authenticated decisions.

The private `OcspContainer::issued_by` reads the original signed TBS time by
SingleResponse index and compares it exactly to whole-second control time. Both
strict time-slide eligibility checks use it; unrecoverable original time is
ineligible. Public whole-second metadata, ordinary freshness, nextUpdate,
revocationTime and verification over original signed bytes remain unchanged.
This is a bounded historical-evidence fix, not a global subsecond clock API.
No context weakening, retiming, Basic fallback or manufactured POE is used.

On source `7d15f8c7`, the plain normal-wrapper workspace passed **2441 tests /
0 failed / 31 inherited native ignored**, across257 reports; workspace all-target
clippy-Dwarnings and fmt passed. No provider/oracle/proof selector arguments were
supplied. AffectedCV/CMS/PAdES tests passed585/0failed/1existingignore. The original
live CLI test still executes its full original baseline and mandatory same-byte
LTA equality; the retained-case negative and next-second positive run in the gate.
Earlier failed whole/RED logs remain under
`~/.codex/artifacts/sigis/round3-launch/provider-default-discovery/`.
Counts remain1431total/1421passed/10skipped/0pending; five native regression
functions add no upstream IDs and no hardware claim.
