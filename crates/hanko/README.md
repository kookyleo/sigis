# sigis-hanko

Signature validation and signing for Sigis: a Rust port of
[pyHanko](https://github.com/MatthiasValvekens/pyHanko) 0.38.1 and
pyhanko-certvalidator 0.33.0, built on mature Rust crates (RustCrypto,
certval, lopdf). Not wired into the Sigis service yet.

## Structure

`sigis-hanko` is the layer-L4 facade of the PDF and CMS stack
(`docs/crates.md`); the XML stack has its own facade, `sigis-xsig`, and the
service uses `sigis-sign`.

| Module | Crate | Content |
| --- | --- | --- |
| `algorithms`, `asn1`, `cert`, `errors`, `fetch`, `keys`, `time` | `sigis-pki-core` | Shared types and traits |
| `certvalidator` | `sigis-pki-certvalidator` | Path validation, revocation, LTV building blocks |
| `fetchers` | `sigis-pki-fetch` | HTTP fetchers and TSA client |
| `cms` | `sigis-cms` | CMS and RFC 3161 timestamp validation |
| `pdf` | `sigis-pdf` | PDF reading, revisions, incremental writing, encryption |
| `diff` | `sigis-pdf-diff` | DocMDP / FieldMDP analysis |
| `validate`, `ades` | `sigis-pades` | PDF signature validation, AdES validation and reports |
| `sign` | `sigis-pades-sign` | PDF and CMS signing (PAdES B-B to B-LTA) |
| `ades_model` | `sigis-ades-model` | Shared AdES verdict model |
| `eutl` | `sigis-eutl` | EU trusted lists, qualified status |
| `cades` | `sigis-cades` | CAdES outside PDF (skeleton) |

Status per crate: [PORTING.md](PORTING.md).

## License

Original code: Apache-2.0. Files derived from pyHanko / pyhanko-certvalidator:
MIT, see [LICENSE-pyHanko](LICENSE-pyHanko) and [NOTICE](NOTICE) (index of the per-crate NOTICE files).
