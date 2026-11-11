# sigis-hanko

Signature validation and signing for Sigis: a Rust port of
[pyHanko](https://github.com/MatthiasValvekens/pyHanko) 0.38.1 and
pyhanko-certvalidator 0.33.0, built on mature Rust crates (RustCrypto,
certval, lopdf). Not wired into the Sigis service yet.

## Structure

`sigis-hanko` is a facade over the `hanko-*` workspace crates:

| Module | Crate | Content |
| --- | --- | --- |
| `algorithms`, `asn1`, `cert`, `errors`, `fetch`, `keys`, `time` | `hanko-core` | Shared types and traits |
| `certvalidator` | `hanko-certvalidator` | Path validation, revocation, LTV building blocks |
| `cms` | `hanko-cms` | CMS and RFC 3161 timestamp validation |
| `fetchers` | `hanko-fetch` | HTTP fetchers and TSA client |
| `pdf` | `hanko-pdf` | PDF reading, revisions, incremental writing |
| `diff` | `hanko-diff` | DocMDP / FieldMDP analysis |
| `sign` | `hanko-sign` | Signing (PAdES B-B to B-LTA) |
| `validate` | `hanko-validate` | PDF signature validation |
| `ades` | `hanko-ades` | AdES validation and reports |
| `eutl` | `hanko-eutl` | EU trusted lists, qualified status |

Only certificate path validation and offline revocation checking work today;
the other crates are interface skeletons that return
`HankoError::NotImplemented`. See [PORTING.md](PORTING.md) and
`docs/hanko-lanes.md`.

## License

Original code: Apache-2.0. Files derived from pyHanko / pyhanko-certvalidator:
MIT, see [LICENSE-pyHanko](LICENSE-pyHanko) and [NOTICE](NOTICE) (index of the per-crate NOTICE files).
