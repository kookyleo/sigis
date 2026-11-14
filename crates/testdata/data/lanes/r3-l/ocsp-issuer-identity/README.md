# Ordinary OCSP responder identity regressions

These ten DER files are byte-identical copies of the minimal relevant inputs
from V's eighteen authority/direct-issuer fixture rows. Shared certificates and
the root CRL are deduplicated; unrelated CA-revocation and CRL-algorithm inputs
are excluded. `ORIGIN.json` pins each copied source path, length and SHA256,
the original generators/manifests, recorded public Python comparisons and the
isolated V native source receipts. No generator was rerun and no private key
was copied. These inputs require no completion API, network or fixture creation.

The ordinary integration target is
`crates/pki-certvalidator/tests/ocsp_responder_identity.rs`. Its five independent
tests use the existing public `find_valid_path` and `validate_path_detailed`
operations with mandatory leaf OCSP, mandatory intermediate CRL, current
2020-12-25 validation, original default algorithm policy/tolerance and no
fetchers. Both public results are recorded before either is asserted.

The genuine exact issuer and genuine delegated responder remain positive
controls. The forged issuer copies the true intermediate's issuer DN, subject,
serial and certificate signature while replacing its SPKI with the signer's
key. Its certificate signature is invalid; its actual OCSP response signature
is valid under that replacement key and invalid under the true issuer key.
The full actual issuer/target CertID is unchanged. ResponderID.byName selects
the embedded fake certificate. Separate one-bit raw-response-signature controls
preserve all signed TBS and embedded certificate bytes for both fake and actual
issuer responses. Tests independently verify these structural and cryptographic
preconditions before requiring typed mandatory-OCSP authorization/signature
refusals through the ordinary public APIs.

Pinned pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0 accepts the forged issuer
response in the preserved same-byte public reference result. The new negative
expectation intentionally requires fail-closed security hardening. It does not
claim exact upstream parity, a newly ported upstream function, accepted-main
native reproduction, or completed TSA/CMS protection. Tests were prepared first;
compilation and behavioral baseline/fix execution remain the lead's next step.
The proposed production hunk is kept unapplied outside the repository.
