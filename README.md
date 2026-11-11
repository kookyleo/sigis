# Sigis

**Signature Integrity Service**

Open-source PDF signing and verification.

## Status

This is an early test service. It provides a browser interface and HTTP endpoints for basic PAdES PDF signing with an uploaded PKCS#12 certificate and offline signature verification. Signed files and uploaded keys are processed in memory. Signature integrity and certificate trust are reported separately; a cryptographically valid signature is not necessarily trusted.

**This test service has no authentication. Use test documents and test certificates only.** Do not expose it to untrusted networks or use production keys. Timestamping, revocation checking, long-term validation, PKCS#11, and identity integration are not yet implemented. This implementation is not independently certified for PAdES conformance.

## Run

```sh
cargo run
```

The default address is `127.0.0.1:38882`. Set `SIGIS_LISTEN` to change it. Set `SIGIS_TRUST_ROOTS` to a PEM file containing trusted certificate authorities for signature verification; with no configured roots, signatures may be cryptographically valid but untrusted.

## HTTP API

- `GET /health`: health check.
- `POST /api/sign`: multipart fields `pdf`, `pkcs12`, and `password`; returns the signed PDF. The signature is invisible and uses the basic PAdES profile.
- `POST /api/verify`: multipart field `pdf`; returns per-signature verification details as JSON. Signing times in the PDF are claims, not trusted timestamps.

Maximum PDF size is 20 MiB and maximum PKCS#12 size is 2 MiB. The uploaded private key is used only to sign the requested document; the service does not store uploads.

## Design

- [Storage design](docs/storage.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
