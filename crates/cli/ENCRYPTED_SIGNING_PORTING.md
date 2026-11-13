# Accepted encrypted PEM software-command originals

Accepted source: `73d9c14c236a8cd96b4831505a1f87be4783a3ad`.
CLI assignment: **252 total /183 passed /0 skipped /69 pending**. Exactly the
following three immutable functions/six original parameters complete; no
provider exclusions, supplemental caller/oracle wrappers or P tests add IDs.

| Immutable source under pyhanko-cli/test_cli_signing.py:: | Rust encrypted_signing function | Cases |
| --- | --- | ---: |
| test_cli_addsig_pemder_encrypted_file | test_cli_addsig_pemder_encrypted_file |RSA/ECDSA/Ed25519/Ed448:4|
| test_cli_addsig_no_pubkey_encryption | test_cli_addsig_no_pubkey_encryption |RSA:1|
| test_cli_addsig_wrong_password | test_cli_addsig_wrong_password |RSA:1|

Pinned pyHanko0.38.1 source SHA256 is
`363e41f063048edd4b922db1d51a3b3713cd017f2ca7b437ff6e671f0ca45877`.
The encrypted input bytes match original AES256(1403B) and public-key AES256
(2743B) fixtures. Positive setups use DER signer leaf and PEM intermediate/root;
negative setups retain original PEM cert.pem and no added chain. Actual CLI
uses document password ownersecret/wrong through stdin; --no-pass only governs
the signing key. Public-key handler is refused before password/material use.

Canonical command success performs real PDF signing/authentication. Actual
Sig1/one signature/encryption/wrong-password refusal/owner authentication,
ByteRange/CMS and supplied-root trust are checked. Same actual output PDFs
receive fresh pinned public Python and native public hard-fail validation with
explicit signed CRLs; identical PDF/time/evidence without roots denies trust.
Negative commands require exit1 and the original Public-key document encryption
is not supported /Invalid password diagnostic, retaining existing output sentinels.

Current C3 scope has16process receipts and4in-process validation receipts,
20total; four same-native-output checks are not four extra unique functions.
Actual current CLI5683 is bound to source73d/13producerunits232inputs/bothworker
copies; the focused test ELF e278 is legitimately byte-identical to the RED test ELF,
while the selected product changes791b→5683. The separate actual fullgate ELF
is SHA256 `be0c341030e51d82a9c823f3ae07341f0151f5853b9c8519d9d926d31a6ad3ab`. All current fullgate outputs and
ELFs are separately retained; no old owner/full-engine report supplies credit.

The new internal entry shares the previous whole configuration/context/full
usage/effective-alias/schema checks. Public direct adapter remains plaintext-
only. Authentication uses the continuing strict reader and transfers its spent
budget/authentication through PdfReopenState; no plaintext reopening/default
context/mandatory option discard or fallback. Default/no-context/optional-policy
semantics beyond the exact approved legacy repair are not redefined.

Reference/post-validation uses recorded historical local-midnight2020, while
native signing uses current product time. Signed CRL fixtures are explicit
native evidence, not HTTP acquisition. Generic original post_validate lenient/
trusted-decode/LTA branches and arbitrary reader/handler/multi-prompt/MAC/
current-time trust/byte equality/atomic output are not universally covered.

Actual workspace gate: **2,014 discovered /2,011 passed /
3 ignored /0 failed**,200 reports; all six gates,
current product/source/runtime/retained proofs and independent final review
precede promotion. All clean mandatory-policy evidence comes solely from actual same-source serial37. Original parallel raw data retain12 strict anomalies:11 unparseable fragments plus1 JSON-decodable but semantically polluted thread; no field/identity reconstruction or repair is claimed.
The original12 strict raw anomalies include11 unparseable fragments and one
JSON-decodable object whose thread contains harness pollution. Its original
parsed value, raw span SHA and line SHA are preserved exactly. It is **not**
a clean source/thread/identity/policy row; syntactic decoding counts are only
framing observations. All clean policy proof comes solely from serial37.
Two auxiliary unavailable records(ad828/62e4 prefixes) remain unavailable;
the driving-before-start observation was lost. Source/ready checks are
independent guarantees and do not recover those raw observations. No field
repair, reconstruction or recovered-before-start observation is claimed.


P's measured legacy missing-KU closure adds0IDs and retains two raw optional-EKU
facade differences, two stricter Core refusals and provider exclusions. No
complete-port/universal fail-closed assertion. See docs/lanes/round3/l-ku-encrypted.md.
