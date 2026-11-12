# Signed AC issuer Name encoding controls

Public certificates/ACs/OCSPs derive from the MIT-licensed pinned
pyhanko-certvalidator0.33.0 basic-AA test PKI. The controlled AC changes only
CN encoding UTF8String -> PrintableString, then is genuinely re-signed with
that public test PKI's known AA key. No private key is copied into this directory.
Both Name forms are semantically equal and have different DER. The response
variants are genuinely signed by the same AA; the bad-signature response is a
negative control. results.json records eight actual pinned public validations,
three positive calls and five rejections, over seven distinct input triples.
Source/byte/signature checks are in source-pin.json and verification.json.
These supplemental controls earn zero immutable upstream-function credit.

The root ac_name_der test loads and hashes these actual DERs, applies mandatory
OCSP at both levels with the AA explicitly anchored and no CRL/fetch fallback,
and compares all eight native outcomes. A proposed AA-subject-only name matcher
accepted one oracle rejection; the accepted matcher instead uses the signed
AC issuer Name encoding, while key hashes always bind the actual AA. Request
construction separately follows the actual-AA name/key rule. Report/diagnostic
wording differences are outside this verdict control.

Regenerate to an external directory with the pinned venv and public test key:

```sh
/tmp/pyhanko-oracle/venv/bin/python -I crates/pki-fetch/oracle/ac_name_der.py --output /tmp/sigis-ac-name-der
```

The generator requires the pinned CV source tree's licensed test key at
/tmp/pyhanko-oracle/src/cv-0.33.0/pkgs/pyhanko-certvalidator/tests/fixtures/attribute-certs/keys/aa.key.pem.
Do not regenerate over committed bytes. The original fresh run and isolated
native red/green logs are under round3-launch/ac-name-der/ in lead artifacts.
