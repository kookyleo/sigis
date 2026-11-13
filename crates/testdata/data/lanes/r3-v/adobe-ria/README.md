# Signed Adobe revocation archival evidence

These are V-owned consumer regression inputs generated with pinned pyHanko0.38.1
and certvalidator0.33.0 at `2020-11-01T00:00:00Z`. They exercise consumption of
`adobe_revocation_info_archival` in genuinely signed PDF CMS attributes. They
are not evidence that the native P signer performs the original signing test.
The S-owned original function is
`pyhanko/test_cms.py::test_embed_ac_revinfo_adobe_style` (aiohttp/requests);
its native real-operation assertions and credit remain with central integration.

The original test's validation spec defaults to NO_HISTORICAL_FETCH with
backend=None, which provisions a current online backend when needed. Its
explicit assertions do not require offline/root-only success. Equivalent
Services remain permitted in the exact root integration. Historical fetching
is still disallowed by that rule.

This fixture generator deliberately selects LOCAL_ONLY to isolate the RIA
consumer, beyond the original assertions. The no-fetcher/no-DSS positive and
negative results below are supplemental feature checks. Their red/green does
not invalidate accepted V47 baseline assertions or add a new requirement to the
S-owned original. Frozen input bytes, manifests and outcomes are unchanged.

`generate.py` creates a signature with the original AC-aware signer material:
five other embedded PKCs, one embedded AC, the signer certificate and a genuine
signature timestamp. The signed RIA contains all five genuine Certomancer CRLs.
No DSS is written. Local revocation knowledge is the only allowed source for
validation; PKC and AC trust roots remain separate and both policies use
REQUIRE_REVINFO. No issuer certificate is promoted to an anchor by ingestion.

The generator's clock is fixed, while fresh PDF IDs and timestamp randomness
are frozen after generation. Re-running it creates a new snapshot; do not
regenerate inputs between native red/green runs. `oracle.json` pins each final
input length/SHA256, the exact full-LTA outcome and certified role assertions.
The final nine full-LTA calls used the same bytes now committed here, without
network fetchers. Earlier interrupted setup attempts are not their evidence.

| Case | Construction | Pinned full-LTA result |
| --- | --- | --- |
| good | Genuine signed RIA and five valid CRLs | OK, bottom line true, RoleSyntax bigboss@example.com |
| missing | Genuinely signed CMS with no RIA | CERTIFICATE_CHAIN_GENERAL_FAILURE |
| empty | Genuinely signed empty RIA SEQUENCE | CERTIFICATE_CHAIN_GENERAL_FAILURE |
| duplicate | Genuinely signed duplicated RIA attribute | CERTIFICATE_CHAIN_GENERAL_FAILURE |
| unsigned-only | RIA only in unsigned attributes | CERTIFICATE_CHAIN_GENERAL_FAILURE |
| malformed | Genuinely signed RIA value encoded as INTEGER | ValueError during RIA decoding |
| forged-crl | Each embedded CRL signature bit flipped before genuine CMS signing | CERTIFICATE_CHAIN_GENERAL_FAILURE |
| bad-signature | Outer CMS signature bit flipped in good PDF | SIG_CRYPTO_FAILURE |
| tampered-content | Signed PDF header version byte changed | HASH_FAILURE |

The no-evidence cases all retain intact/valid CMS but untrusted status, false
bottom line and no certified role. Forged inner CRLs retain intact/valid outer
CMS but are not authenticated revocation evidence. The good signature timestamp
alone does not establish earlier POE for the signed RIA: the pinned archival
algorithm only publishes those evidence-object POEs through a later enclosing
content/document timestamp or caller-provided proof. There are no invented POEs
in these fixtures.

`good-ria.der`, `good.cms.der` and `good-content.bin` expose the exact attribute,
ContentInfo and PDF ByteRange content for narrow public API checks. `crl-N.der`
are the original genuine CRLs. Root DER files are `root.der` and `root-aa.der`;
other public certificates are input material for independent inspection, not
additional trust roots. The test generator uses local Python fixture keys; no
private key is added here. All fixture/oracle/helper calls earn zero new V IDs.
