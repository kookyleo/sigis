# Additional signed RIA OCSP and archival proof inputs

The original nine-case snapshot and `oracle.json` are unchanged. Additional
inputs have a separate `additional-oracle.json` hash/length manifest.
`generate_additional.py` imports the original generator definitions but does
not execute its guarded main or rewrite any original fixture. Five fresh
public Python LTA calls and five separate authenticated ER-validation calls
establish these outcomes. No native P operation or new V function is credited.

| Case | Relevant signed evidence | Pinned result |
| --- | --- | --- |
| ocsp-good | Four valid CRLs and actual AC OCSPResponse in signed RIA [1]; AC-target CRL excluded | Main LTA OK, bottom line true, authenticated bigboss RoleSyntax |
| ocsp-forged | Same, with only inner BasicOCSP signature bit flipped before genuine outer CMS signing | Main LTA OK and main bottom line true, but AC rejects with OCSP-signature error and no certified role |
| enclosing-good | Genuine later DocTS enclosing the exact original good PDF, no DSS | Main LTA OK, all five original RIA CRLs have authenticated 2020-11-02 POE |
| enclosing-bad | Only that DocTS signature bit flipped; original main PDF/CMS preserved exactly | Main LTA still OK at current time, authenticated ER validation rejects SIG_CRYPTO_FAILURE and publishes no RIA POEs |
| original-no-doc-ts | Original good PDF at 2020-11-02, no appended timestamp | Main LTA OK, no RIA CRL POEs |

Original signed data and response authentication remain separate requirements.
An invalid AC OCSP does not automatically invalidate the independently trusted
main signer. A corrupt later archival timestamp does not make current-valid
original CMS cryptographically invalid. Tests must retain explicit failed AC
role/authentication and zero published chain-POE assertions instead of claiming
that the pinned final main bottom line rejects in these two scoped cases.

`ocsp-good` and `ocsp-forged` exclude the leaf-AA AC-target CRL, so they cannot
obtain AC revocation authentication by falling back to that genuine CRL.
`ac-request.der` uses the actual AC serial and actual AA identity. There is
no online fetcher, injected status, trust-anchor promotion or fabricated POE.

The appended document timestamp is generated at 2020-11-02; original signatures
and responses are at 2020-11-01. Both appended PDFs retain the original good
PDF as an exact byte prefix and have no DSS. The original signature timestamp
alone publishes no POE for its signed RIA. Proof receipts come from the actual
pinned `_validate_prima_facie_poe` procedure; the manifest does not infer trust
from a prima-facie timestamp or access the manager's side-effecting item getter.

The OCSP response type is the full OCSPResponse wrapper. Its BasicOCSPResponse
signature mutation is independently visible in DER, while its signed CertID
and payload remain unchanged. Fresh serial/nonce/PDF IDs are frozen after this
run; do not regenerate between native red and green checks.
