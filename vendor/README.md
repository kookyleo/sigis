# Vendored crates

## underskrift 0.1.4

- Source: crates.io `underskrift` 0.1.4 (upstream git commit `17bca3c4ac49af475772678f1e9ccd35bfaaa3af`, <https://github.com/kushaldas/underskrift>).
- License: BSD-2-Clause (see `underskrift/Cargo.toml`).
- Used through `[patch.crates-io]` in the root `Cargo.toml`.

The first commit that adds this directory contains the unmodified crate. Later
commits that touch `vendor/underskrift/` hold the Sigis patch, so `git diff`
against that commit shows exactly what to upstream.

Patch (three changes, all in `vendor/underskrift/src/`):

1. `signer.rs`, `cms/builder.rs`: `PdfSigner::sign` uses
   `SigningOptions::tsa_url`. When it is set, the signer requests an RFC 3161
   timestamp over the CMS `SignerInfo.signature` value (SHA-256 imprint) and
   embeds the token as the `id-aa-signatureTimeStampToken` unsigned attribute
   (PAdES B-T). Before the patch, `tsa_url` was accepted but ignored.
2. `verify/cms_verify.rs`: accept `rsaEncryption` as the SignerInfo signature
   algorithm and combine it with the SignerInfo digest algorithm. DigiCert and
   Sectigo timestamp tokens use it; before the patch, their TSA signature
   failed with "unsupported signature algorithm".
3. `verify/cms_verify.rs`: when the TSA chain built from the token does not end
   at a trust anchor, also try shorter prefixes of that chain. DigiCert tokens
   embed a "DigiCert Trusted Root G4" cross-certificate issued by an older root;
   before the patch, a trust store with only the G4 root rejected the chain.

Remove this directory and the `[patch.crates-io]` entry when upstream ships an
equivalent change.
