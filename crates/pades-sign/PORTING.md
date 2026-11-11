# Porting status: sigis-pades-sign (crates/pades-sign)

Owner: D. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`; lane status and per-suite
counts: `docs/lanes/d.md`.

## Module mapping

| pyHanko module | Rust file | Status |
| --- | --- | --- |
| `keys/pemder.py`, `keys/internal.py` | `src/keys.rs` | ported (RSA, ECDSA P-256/384/521, Ed25519, ML-DSA; PKCS#8 incl. PBES1/PBES2, PKCS#1/SEC1 with legacy PEM encryption) |
| PKCS#12 loading (`cryptography` `pkcs12`, used by `SimpleSigner.load_pkcs12_data`) | `src/pkcs12.rs` | ported (no maintained crate for the RustCrypto 0.8/0.11 stack) |
| `sign/signers/pdf_cms.py` (`Signer`, `SimpleSigner`, `ExternalSigner`, attribute provider specs, `select_suitable_signing_md`) | `src/signer.rs`, `src/cms.rs` | ported; containers built from `cms` crate types (the `cms` builder needs an in-process key) |
| `sign/general.py` (signing parts: ESS helpers, `optimal_pss_params`, `get_cms_hash_algo_for_mechanism`) | `src/attributes.rs`, `src/signer.rs` | ported |
| `sign/attributes.py` | `src/attributes.rs`, `src/cms.rs` | ported |
| `sign/ades/api.py`, `sign/ades/cades_asn1.py` | `src/attributes.rs` (+ `hanko-core::asn1` types) | ported |
| `sign/timestamps/dummy_client.py`, `common_utils.py` | `src/timestamps.rs` | ported |
| `sign/timestamps/api.py` (`TimeStamper`) | `hanko_core::sign::TimeStamper` + `src/pdf/timestamp.rs` (`tsa_validation_info`) | ported |
| `sign/timestamps/requests_client.py`, `aiohttp_client.py` | — | lane A (`hanko-fetch::HttpTimeStamper`) |
| `sign/signers/pdf_signer.py` | `src/pdf/signer.rs`, `src/pdf/timestamp.rs`, `src/ltv.rs` | ported (PdfSigner, signing session, locking rules, seed value enforcement, size estimation, interrupted signing, post-sign DSS/LTA, PdfTimeStamper) except PDF MAC (ISO 32004, pending lane B `pdfmac`) |
| `sign/signers/cms_embedder.py` | `src/pdf/signer.rs` (`SigMdpSetup`, `write_and_digest`, `PdfTbsDocument`) | ported |
| `sign/signers/pdf_byterange.py` | `src/pdf/signer.rs` (`SignatureObjectSpec`, `BuildProps`, `PreparedDocument`), `src/pdf/writer.rs` (placeholders) | ported |
| `sign/signers/functions.py` (`sign_pdf`, `embed_payload_with_cms`) | `src/lib.rs` (`PdfSigner::sign_pdf`) | `sign_pdf` ported; `embed_payload_with_cms` pending (embedded files, lane B) |
| `sign/signers/constants.py` | `src/pdf/signer.rs` | ported (extensions, defaults) |
| `sign/fields.py` | `src/pdf/fields.rs`, `src/pdf/seed.rs` | ported |
| `sign/validation/dss.py` (writing: `supply_dss_in_writer`, `add_dss`, `add_validation_info`, `collect_validation_info`) | `src/pdf/dss.rs`, `src/pdf/timestamp.rs`, `src/ltv.rs` | ported |
| `pdf_utils/incremental_writer.py`, writing parts of `writer.py`, `xref.py` (`write_xref_table`, `XRefStream`) | `src/pdf/writer.rs` | ported on `lopdf`, temporary until lane B's `hanko_pdf::IncrementalWriter` |
| `pdf_utils/form_tools.py` (`enumerate_fields_in`, `get_single_field_annot`, `annot_width_height`) | `src/pdf/fields.rs` | ported |
| `pdf_utils/generic.py` (`pdf_date`, `pdf_string`) | `src/pdf/util.rs` | ported |
| Encryption for updates of encrypted files (`crypt/` standard handler) | `src/pdf/writer.rs` via `lopdf::encryption` | standard handler supported; public-key handler pending (lane B) |
| `sign/pkcs11.py` | `src/pkcs11.rs` | ported (`cryptoki`) |
| `sign/signers/csc_signer.py` | `src/csc.rs` | ported (blocking `reqwest`) |
| `stamp/`, `pdf_utils/{layout,text,content,images,qr,barcodes}.py`, `pdf_utils/font/` | `src/stamp/`, `src/layout.rs`, `src/text.rs`, `src/content/`, `src/images.rs`, `src/qr.rs`, `src/barcodes.rs`, `src/font/` | in progress (sub-slice) |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_signing.py` | `tests/test_signing.rs` | 78 | 58 | 9 | 11 |
| `test_pades.py` | `tests/test_pades.rs` | 48 | 39 | 1 | 8 |
| `test_fields.py` | `tests/test_fields.rs` | 27 | 25 | 0 | 2 |
| `test_seed_values.py` | `tests/test_seed_values.rs` | 36 | 34 | 1 | 1 |
| `test_sign_encrypted.py` | `tests/test_sign_encrypted.rs` | 11 | 8 | 0 | 3 |
| `test_pkcs11.py` | `tests/test_pkcs11.rs` | 36 | 34 | 2 | 0 |
| `test_csc.py` | `tests/test_csc.rs` | 17 | 17 | 0 | 0 |
| `test_stamp.py` | `tests/test_stamp.rs` | 25 | — | — | in progress |
| `test_text.py` | `tests/test_text.rs` | 15 | — | — | in progress |
| `test_images.py` | `tests/test_images.rs` | 2 | — | — | in progress |
| `test_barcode.py` | `tests/test_barcode.rs` | 2 | — | — | in progress |

Skip reasons and pending dependencies per test: `docs/lanes/d.md`.
Infrastructure tests (key loading, CMS, TSA): `tests/keys_and_cms.rs`.

## Verification

Every signed output in the tests is checked twice: a Rust-side integrity
check (`tests/support/pdfcheck.rs`: byte range, digest, signature value)
and pyHanko's own verdict through `oracle/validate_pdf.py` (pinned clock,
Certomancer services where pyHanko's tests use `pki_services`). Without an
oracle the differential checks are skipped with a message.
