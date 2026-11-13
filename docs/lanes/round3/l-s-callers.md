# Accepted PDF operation callers and shared CMS registry repair

Source `dc90dceee5f0ce7d8287019e1b15eae923ea8ee2` passes build, workspace tests, clippy -D warnings, strict docs,
dependency layering/cycles and formatting. Native gate: 1724 discovered,
1720 passed, 4 ignored, zero failed, 156 reports.
Actual immutable CLI SHA256 2ea48b6911c1d2b4fa57d433aeeb5bfbc84e453cec64735dab05f277ca86f153; three selected
paths and before/after hashes agree, including both worker copies. The213 actual
V file opens and 69 S input reads are independently
recomputed against bytes/lengths. Compiler flags/profiles/features, canonical
target and configured sccache remain unchanged. All Cargo uses system slots.

Six immutable S-owned IDs are completed, counted under their original crates:

| Function | Crate | Original parameter executions |
| --- | --- | ---: |
| test_key_based_digest_selection | sigis-cms | 4 |
| test_post_sign_reopen_keeps_limits | sigis-pdf | 2 |
| test_archival_timestamp_update_keeps_limits | sigis-pdf | 1 |
| test_add_dss_keeps_limits | sigis-pdf | 1 |
| test_pdf_mac_pades | sigis-pdf | 1 |
| test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel | sigis-pdf | 1 |

The selector uses real decoded RSA2048/P384/Ed25519/Ed448 public keys and all four
expected digests; the exact original function independently passes four reference
executions, plus four same-SPKI public API comparisons. It does not require or
claim CMS signature generation. The ten focused caller tests include meaningful
supplemental controls, not ten upstream functions.

Three decode originals use the valid same oversized stream fixture through real
signing, archival-chain and DSS operations. Both post-sign timestamp placements,
exact timestamp/certificate/no-VRI assertions and unchanged original input are
retained. Default/finite limits reject inside each operation. Public operation
errors are typed HankoError::Malformed with the exact PdfDecodeLimitError prefix;
the downstream reader rejects with PdfError::DecodeLimit directly. This error
representation distinction is not falsely described as a typed Hanko DecodeLimit.
An authenticated lenient sign->archive->DSS continuation preserves password access,
strictness and a decreasing shared budget, then rejects the final oversized read.

MAC PAdES uses actual encrypted signing, real HTTP TSA tokens bound to the session,
MAC Successful/ISO32004 and full native V AdES LTA with the original policy. Exact
native/Python outcome is NO_POE with API bottom_line=true, not final AdES OK.
Concurrent reuse leaves bytes_reserved=None: the real estimator holds the MAC
lease while a second actual operation on the same PdfSigner refuses with the
original conflict text; the first operation and subsequent reuse succeed.

All six actual gated ordinary/MAC output PDFs receive fresh pinned Python checks
with actual fixed native root DER hashes recorded before parsing. Regenerating an
ECDSA fixture can change DER signature bytes; the initial root-pin preparation
failure is preserved and earns no success. The fixed original native roots are
used by the final comparisons. A seventh encrypted state output receives fresh
plaintext/two-timestamp readback. Six real Python default/finite operation denials
are PdfDecodeLimitError. The unchanged L suites independently validate eighteen
actual gated PDFs in native/Python, including empty-root denials and concurrency.

The actual retained29b shared-context more-trusting counterexample is repaired
in this source. Eight profiles match pinned Python: implicit/explicit shared
context refuses main trust; distinct equal-valued/separate-root contexts remain
trusted, under both timing flags. Main integrity/validity and TSA trust remain.
CMS carries an owned operation-local registry through visited timestamps then
main validation; first issuer/serial registration wins. Caller contexts remain
unchanged; independent role contexts and operations stay isolated. All original
anchors/policies/assertions/freshness/timing/AC restrictions/fetcher identities
survive. General with_other_certs remains a separate DER-deduplicating API.

Four real-token private CMS tests prove raw-invalid and algorithm-denied tokens
do not register, raw-valid wrong-imprint tokens register without trust, and a
later unvisited raw-valid token cannot register an extra genuine public cert.
The latter has a direct trusted/registered positive. Three context tests preserve
restrictive nondefault security state, collision order/independent operations and
both qualified anchors/custom-manager identity. These add zero upstream IDs.

Four stale empty ignored placeholders are removed with references to the actual
root MAC/V coverage tests; no empty wrapper is enabled or counted. Existing
diagnostic/provider/documentation ignores remain distinct from function counts.

Accepted S824/797/26/1: CMS78/77/0/1, PDF406/395/11/0. Overall1431/1239/29/163;
P297/287/3/7, V47/47/0/0, C252/98/0/154, L11/10/0/1 unchanged.
Remaining S function is Adobe AC revinfo with complete producer/full-LTA RoleSyntax
assertions; P must publish genuinely fetched AC material, without a fixture preload
shortcut. The separate offline Adobe RIA consumer is a production feature gap,
not an invented original-function offline requirement. The26 S skips remain.

The29b fix does not prove universal registry or fail-closed parity: AC-context
aliasing, persistent mutation across separate public calls, independently fetched
candidate registration and custom-manager root enumeration/order retain explicit
scope limits. Old overwritten7075 is not retroactively recovered. Other model,
encoding, resource and provider differences remain documented; no complete-port
or all-divergences-fail-closed claim is made. Evidence: /home/l/.codex/artifacts/sigis/round3-launch/s-caller-integration/ and
round3/l-next/mixed-*/ (actual pre-fix RED, fresh profiles, source reviews and units).
