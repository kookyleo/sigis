# sigis-hanko

Signature validation foundation for Sigis: a Rust port of the validation core
of [pyHanko](https://github.com/MatthiasValvekens/pyHanko) and
pyhanko-certvalidator. This crate is not wired into the Sigis service yet.

## What it does

- **Algorithms** (`algorithms`): verify RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA
  (P-256, P-384, P-521) and Ed25519 signatures from an `AlgorithmIdentifier`
  and a `SubjectPublicKeyInfo`, including the CMS convention of
  `rsaEncryption` with a digest from context. An `AlgorithmUsagePolicy` hook
  decides which algorithms and key sizes are acceptable.
- **ASN.1** (`asn1`): ESS `SigningCertificate` / `SigningCertificateV2`,
  `SignaturePolicyIdentifier`, `CommitmentTypeIndication`, which the RustCrypto
  `cms` crate does not define.
- **Path validation** (`certvalidator`): build paths to trust anchors and
  validate them at a time of interest. RFC 5280 processing is done by
  [`certval`](https://github.com/carl-wallace/rust-pki).
- **Revocation** (`certvalidator::revinfo`): offline checks against
  caller-supplied CRLs (including delta CRLs and separate CRL signing keys) and
  OCSP responses, under pyHanko's revocation checking rules (`soft-fail`,
  `hard-fail`, `require`, ETSI check types) and freshness policies. Freshness
  rules can be replaced through the `FreshnessJudge` trait.

No network access happens anywhere in this crate.

```rust,no_run
use sigis_hanko::certvalidator::{Cert, CertificateValidator, ValidationContext};
use sigis_hanko::time::Moment;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let root = Cert::from_pem_or_der(&std::fs::read("root.pem")?)?;
let interm = Cert::from_pem_or_der(&std::fs::read("interm.pem")?)?;
let leaf = Cert::from_pem_or_der(&std::fs::read("leaf.pem")?)?;
let ctx = ValidationContext::builder()
    .trust_root(root)
    .other_cert(interm)
    .crl(std::fs::read("interm.crl")?)
    .moment(Moment::parse_rfc3339("2026-11-11T00:00:00Z").ok_or("time")?)
    .revocation_mode("require")
    .build()?;
let path = CertificateValidator::new(&ctx, leaf).validate()?;
println!("valid path of length {}", path.len());
# Ok(())
# }
```

## Dependencies

The RustCrypto format crates are pinned to the exact versions that
`certval =0.2.0-rc.2` uses, so that types are shared: `cms =0.3.0-rc.1`,
`x509-ocsp =0.3.0-rc.0`, `x509-tsp =0.2.0-rc.0` (with `der` 0.8, `x509-cert`
0.3, `spki` 0.8). Signature verification uses the RustCrypto crates that
certval also uses (`rsa =0.10.0-rc.21`, `p256`/`p384`/`p521` 0.14,
`ed25519-dalek` 3). `certval` has not been independently audited; treat it as
part of the audit scope.

## Status and tests

See [PORTING.md](PORTING.md) for the module and test mapping. In short: NIST
PKITS 230/246 agree with pyhanko-certvalidator (the 16 divergences all fail
closed), OpenSSL OCSP vectors 29/29.

## License

Original code: Apache-2.0. Files derived from pyHanko / pyhanko-certvalidator:
MIT, see [LICENSE-pyHanko](LICENSE-pyHanko) and [NOTICE](NOTICE) for the list.
