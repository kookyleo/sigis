# Sigis

**Signature Integrity Service**

Open-source PDF signing and verification.

## Status

This is an early test service. It provides a browser interface and HTTP endpoints for basic PAdES PDF signing with a local demo certificate or an uploaded PKCS#12 certificate, and offline signature verification. Signed files and uploaded keys are processed in memory. Signature integrity and certificate trust are reported separately; a cryptographically valid signature is not necessarily trusted.

**This test service has no authentication. Use test documents and test certificates only.** Do not expose it to untrusted networks or use production keys. Timestamping, revocation checking, long-term validation, PKCS#11, and identity integration are not yet implemented. This implementation is not independently certified for PAdES conformance.

## Run

```sh
cargo run
```

The default address is `127.0.0.1:38882`. Set `SIGIS_LISTEN` to change it. Set `SIGIS_TRUST_ROOTS` to a PEM file containing trusted certificate authorities for signature verification; with no configured roots, signatures may be cryptographically valid but untrusted.

On first start, the service generates a self-signed demo signing certificate and key at `<temp dir>/sigis-demo/demo-signer.p12` (for example `/tmp/sigis-demo/demo-signer.p12`) and reuses it on later starts. Signing uses this certificate when no PKCS#12 is uploaded. Verification always trusts it as a demo trust anchor, so demo-signed PDFs verify as valid in this service only. Delete the file to generate a new certificate. On a shared machine, another local user could create the `sigis-demo` directory first and plant their own certificate; do not rely on the demo certificate for anything but testing.

## HTTP API

- `GET /health`: health check.
- `GET /api/demo-certificate`: subject, SHA-256 fingerprint, and path of the local demo certificate.
- `POST /api/sign`: multipart field `pdf`, and optional fields `pkcs12` and `password`; returns the signed PDF. Without `pkcs12` (or with an empty file), the service signs with the demo certificate. The signature is invisible and uses the basic PAdES profile.
- `POST /api/verify`: multipart field `pdf`; returns per-signature verification details as JSON. Signing times in the PDF are claims, not trusted timestamps.

Maximum PDF size is 20 MiB and maximum PKCS#12 size is 2 MiB. An uploaded private key is used only to sign the requested document; the service does not store uploads.

## Design

- [Storage design](docs/storage.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
