# CRL signature verification across issuer recursion

The coherent P runtime source0054aee passed all six gates, then source03a156c
passed the combined gate after closing a newly reproduced shared CRL defect:
1535 discovered / 1527 passed / 8 ignored / zero failed,
across136 reports. Five P functions become passed (seed HTTP URL,
HTTP TSA/revinfo, two public-key signing modes and the signed plaintext copy).
The exact borrowed-buffer CMS function becomes passed once under S/CMS, with
original Vec identity retained through both signing and DSS continuation.
No renderer/state/MAC helper or oracle call adds an upstream-function count.
P297/287/3/7; CMS78/76/1/1; S824/791/27/6; overall1431/1127/30/274.

Caller-selected reader options, decode snapshots and authentication now flow
through signing/DSS/timestamps/stamps and borrowed operations. Session-local
MAC state rejects concurrent shared-signer reuse; caller-buffer failure paths
are staged atomically. The legacy post-parse set_strict method is still a
separate declared compatibility gap. Complete five S PDF callers and seven
P AC functions remain pending; component MAC proof is not whole-function LTA
acceptance. The lockfile adds one existing pki-fetch edge, no version change.

The shared CRL failure was real: a stack shortcut accepted an invalid signature.
L's independent direct verify_ac_crl/full validate_ac tests first failed twice
while the genuine control passed, using a different existing fixture from P's
original ambiguous loop. Actual AC/AA/good/bad/TBS/algorithm SHA receipts match
fresh pinned Python bytes. The fix exempts only issuer certificate path recursion;
every current CRL still requires signed_by. Existing nonrecursive path/signature
order, scope, key usage, freshness, reasons, delta and later policies remain.
Three fixed tests exercise require and soft-fail; eight fresh same-input public
Python decisions and197 existing CV tests pass. Helpers earn zero unique credit.
The prior reference also has a narrower active-path shortcut; this bounded
repair is not a universal claim of lexical equivalence or all-input trust parity.
Evidence: round3-launch/ac-crl-recursion/ and p-integration/.
