# Signed CRL snapshot adversary

This supplemental fixture adds zero unique upstream-function credit. The input
PDF,leaf/intermediate/root certificates and original good CRLs are the existing
pinned pyHanko0.38.1 validation fixtures in this directory.

snapshot-revoked-leaf.crl.der is genuinely signed by the pinned Certomancer
TESTING_CA intermediate's existing private test key. The key is loaded only in
memory;no private key or PIN is copied. The issuer and authority-key identifier
match crl-interm.der. All original CRL extensions,including its issuing
distribution point,are preserved;the CRL number is incremented. The actual leaf
serial1001 is revoked for key_compromise before the fixed fixture clock. This
is signed adversarial evidence,not a signature-byte corruption or fabricated
"revoked" status. Its signature was independently checked with cryptography.

snapshot-provenance.json records the public input/output hashes,dates,issuer
SPKI identity,extension identities and generation versions. The generator is
preserved outside the repository under round3/c/ordinary-validation-content/
snapshot-audit/generate_snapshot_fixture.py and bound by its SHA-256 receipt.
The existing public test material and derived fixture follow the repository's
pyHanko MIT fixture provenance.

snapshot-oracle.py performs fresh public Python PDF validation with the actual
signed PDF/root/CRLs at the same fixed clock,allow_fetching=False and required
revocation information. It requires good evidence to trust the intact/valid
signature,and revoked evidence to preserve integrity/validity while denying
trust. Any socket connection attempt fails the control. Actual interpreter,
versions,API paths and loaded input hashes are printed as JSON.

The Rust validation_snapshot target uses the same data through a leaf-certificate
SHA-256 keyed CRL provider. It checks always-good and always-revoked controls,
then requires denial when evidence changes from revoked to good between calls.
It records actual fetch counts without asserting a specific call count. This
exercises an injected noncached runtime provider;it does not establish a default
HttpFetchers cache failure. The native RED/green outcome must be recorded by the
parent's normal scheduled Cargo run;fixture construction alone proves no native
trust result or CLI readiness.
