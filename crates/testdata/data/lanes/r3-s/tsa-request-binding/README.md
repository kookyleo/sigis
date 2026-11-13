# Signed RFC 3161 request-binding fixtures

Generated with pyHanko0.38.1/certvalidator0.33.0 from the existing public testing
CA and its existing test TSA key. Only public DER is exported; no key is copied.
The preimage is exactly `b'HTTP TSA request binding\x00probe\xff'`. Time is fixed
at2020-11-01T00:00:00Z; requested nonce, when present, is0102030405060708. All
TSTInfo values use the same fixed serial0102030405060709, time and TSA Name.
These controlled fixtures are test inputs, not a production TSA issuance log.

Each case contains:

- request.der: exact original/native-compatible TimeStampReq. SHA2 request
  AlgorithmIdentifiers have NULL parameters, including the absent-response case.
- modified-request.der: the copied TimeStampReq with only the case's intended
  imprint/nonce/response-parameter modifications, supplied to DummyTimeStamper
  **before signing**. A request-binding negative is not a corrupted signature.
- signer-input.der: exact TSTInfo DER encapsulated and signed by CMS.
- response.der: granted TimeStampResp containing the freshly signed token.
- token.der: the identical CMS ContentInfo extracted from that response.

The manifest's cases object is keyed by the twelve case names. All file metadata
is relative to this directory and includes SHA-256 and length. It records exact
request/token OIDs and digest bytes, request/response nonce, CMS digest, source
hashes, interpreter and versions. Only independent-cms-sha512 changes the CMS
signer's digest to SHA512. All other CMS signatures use SHA256, including the
matching SHA384 imprint control. MessageImprint and CMS digest are distinct.

| Case | Signed response change relative to original request |
| --- | --- |
| matching-sha256-null | Matching SHA256 imprint, NULL parameters |
| matching-sha256-absent | Matching SHA256 imprint, response parameters absent; request retains NULL |
| matching-sha384 | Matching SHA384 request/imprint and48byte digest |
| independent-cms-sha512 | Matching SHA256 imprint; only CMS signer digest is SHA512 |
| algorithm-only | SHA384 imprint OID with unchanged original SHA25632bytes |
| digest-only | SHA256 imprint OID; first digest byte XOR1 |
| both | SHA384 imprint OID plus first digest byte XOR1 |
| wrong-nonce | SHA384 imprint with original SHA25632bytes plus nonce0102030405060709 |
| missing-nonce | SHA384 imprint with original SHA25632bytes; response nonce absent |
| no-nonce-valid | Request/response nonce absent, matching SHA256 imprint |
| no-nonce-algorithm | Request/response nonce absent, SHA384 imprint with original SHA25632bytes |
| no-nonce-digest | Request/response nonce absent, SHA256 imprint with first digest byte XOR1 |

root.der and tsa.der form the actual direct TSA certification path. The supplied
root-crl.der is generated from the existing testing CA CRL service at the fixed
time; thisUpdate2020-09-12 and nextUpdate2020-12-11. Validation uses explicit
revocation_mode=require, these trust roots and CRL, and allow_fetching=False.
There is no soft-fail waiver or externally supplied AC/POE result.

Reproduce generation and fresh same-file public Python validation:

```sh
/tmp/pyhanko-oracle/venv/bin/python crates/testdata/data/lanes/r3-s/tsa-request-binding/generate.py
/tmp/pyhanko-oracle/venv/bin/python crates/testdata/data/lanes/r3-s/tsa-request-binding/validate.py --output /tmp/tsa-request-binding-results.json
```

The validation driver performs two public validate_tst_signed_data calls per
case. The declared-imprint callback returns the token's declared digest: this
isolates genuine CMS signature, TSA path and mandatory revocation checks. The
actual-preimage callback computes the requested hash over the exact original
preimage using the token's declared algorithm. The two scopes are separately
recorded with raw status fields, paths, input hashes and callbacks; success of
the declared-digest component is not proof of request/preimage binding.

The driver also records existing handle_tsp_response status/nonce behavior
against the original request nonce. This is component evidence, not HTTP. Its
production integer-nonce mismatch currently raises AttributeError in the pinned
Python formatter; that exception-shape boundary is recorded, not hidden. No
HTTP request, native test, root CLI or full LTA acceptance follows from fixture
generation/Python validation, and unique upstream-function credit is zero.

The first generated corpus was corrected during source review, before any native
baseline: an absent response must not cause the original native request to omit
NULL, and no-nonce corecases use absent response nonce. Initial bytes/scripts/
manifest and their actual Python24call receipts remain archived separately in
`~/.codex/artifacts/sigis/round3/s/tsa-request-binding-implementation/oracle/attempt-1-parameter-fixture-before-native/`.
That review correction is not a native RED or a native pass. Final results and
actual commands are stored alongside that archive under the oracle directory.
