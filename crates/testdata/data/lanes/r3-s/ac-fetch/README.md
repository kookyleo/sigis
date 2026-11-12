# AC HTTP revocation controls

These two public OCSP responses extend the existing `basic-aa` fixture without
changing any certificate, AC, issuer identity or response CertID. They are
supplemental native security controls and add no upstream-function credit.

- `unknown-signed.ors`: the existing `alice-all-good.ors` status is changed to
  `unknown`, then its exact response data is signed with the matching pinned
  fixture AA RSA key and SHA-256. The signature verifies with the public
  `basic-aa/interm/role-aa.crt`; a valid signature is insufficient evidence of
  non-revocation when status is unknown.
- `bad-signature.ors`: the first signature byte of `alice-all-good.ors` is XORed
  with1. Its status remains good, but its signature fails with the actual AA.

Both retain the target AC serial4096, SHA-256 issuer hashes, 2019-12-12 timestamps
and the original absent response nonce. Full metadata, DER hashes and the
independently checked signature outcomes are in `manifest.json`.

Generation and fresh pinned validation proof are saved outside the repository
at `/home/l/.codex/artifacts/sigis/round3/s/ac-fetch/oracle/validate_http.py` and
`validate-http-results.json`. The private key comes from the pinned upstream
fixture tree and is not copied into this directory or any lane commit. Replaying
these committed bytes through real HTTP is transport/evidence replay; it is not
freshly generated native PKI or a new live Python comparison by itself.

Additional identity and scope controls are signed with the same actual AA key:

- `alice-role-other-serial.attr.crt` has serial4098, distinct from AA4096 and
  holder4097. `other-serial-good.ors` is its matching good response. Returning
  the original serial4096 response for this AC must reject.
- `wrong-issuer-name-hash.ors` and `wrong-issuer-key-hash.ors` retain a valid AA
  signature but intentionally bind to the wrong issuer hash. Signature validity
  alone cannot satisfy complete CertID matching.
- `valid-aa-pkc-only.crl` retains actual AA issuer/signature and the declared DP,
  but its IDP covers only public-key certificates. It cannot establish AC status,
  even when raw CRL bytes are fetched from the expected URL.

Generation artifacts `generate_identity_controls.py` and `generate_crl_scope.py`
plus independent fresh HTTP validator comparisons are retained alongside the
original oracle artifacts. All seven evidence files are public; no private key
is copied. Cryptographic signatures of every additional control were separately
verified against the actual AA public certificate before curation.
