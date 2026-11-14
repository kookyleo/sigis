# Genuine signed PDF controls for WithTime trust containment

These supplemental inputs add zero immutable upstream function IDs. They are
new actual PDF outputs from pinned pyHanko0.38.1 PdfSigner, SimpleSigner and
DummyTimeStamper. They do not replace the frozen d56 CMS diagnostic evidence.

`generate.py` creates ephemeral RSA2048 test keys and cryptography-signed root,
CA, signer and TSA certificates, signs the existing read-only `minimal.pdf`,
and persists only public DER/PDF inputs. The root/CA/TSA validity is2000–2035;
MAIN leaves are valid2020–2022. The real timestamp generation time is2020-08-01.
The manifest binds the source PDF, every output, intended defects and clocks.

Eight cases retain actual MAIN signatures and detached PDF digest bindings:

- `good`: NR signer and valid path/TSA, current2021 positive control.
- `path_length`: a pathLen0 CA actually issues a subordinate CA.
- `bad_cert_signature`: the MAIN certificate claims the actual issuer but is
  genuinely signed by a different private key; the MAIN CMS signature under
  that certificate's public key remains cryptographically valid.
- `ds_only`: actual digitalSignature-only signer under required NR.
- `name_constraints`: issuing CA permits allowed.example; leaf is outside.example.
- `unknown_critical`: genuinely signed unsupported critical extension1.2.3.4.500.
- `wrong_tsa_purpose`: genuine token signed by a codeSigning-only certificate.
- `corrupt_imprint`: a DummyTimeStamper override signs a token over an XOR1
  changed message digest; the token's own signature stays valid.

`oracle.py` freshly reads these same PDF bytes, independently verifies eight
MAIN signatures, eight PDF digest bindings, eight timestamp signatures and
imprint expectations, then calls the exact AdES WithTime surface and the
ordinary normalized PDF surface separately. Each actual PDF runs current2021
and expired2025, each with current best time and counterfactual earlier best.
An earlier requested best clock is never claimed to be authenticated material
POE or full historical completion. No online requests/provider exclusions occur.

Actual selected run:32profiles/64APIcalls, no exceptions. The fresh raw result
and logs are under lane artifacts `withtime-containment/pdf-inputs/`. Existing
Python expiry recovery accepts some unchecked name/critical/purpose cases;
this does not excuse the native hardening defect. Ordinary PDF status and
AdES final indication are reported separately, not treated as equivalent APIs.

Regeneration changes ephemeral keys and outputs: do not regenerate to reproduce
an existing proof identity. `oracle.py --output PATH` can revalidate immutable
manifest-bound inputs without generating new signatures.
