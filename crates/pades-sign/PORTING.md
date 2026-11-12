# Porting status: sigis-pades-sign (crates/pades-sign)

Owner: D. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`; lane status and per-suite
counts: `docs/lanes/d.md`.

## Module mapping

| pyHanko module | Rust file | Status |
| --- | --- | --- |
| `keys/pemder.py`, `keys/internal.py` | `src/keys.rs` | ported (RSA, ECDSA P-256/384/521, Ed25519, Ed448, ML-DSA; PKCS#8 incl. PBES1/PBES2, PKCS#1/SEC1 with legacy PEM encryption) |
| PKCS#12 loading (`cryptography` `pkcs12`, used by `SimpleSigner.load_pkcs12_data`) | `src/pkcs12.rs` | ported (no maintained crate for the RustCrypto 0.8/0.11 stack) |
| `sign/signers/pdf_cms.py` (`Signer`, `SimpleSigner`, `ExternalSigner`, attribute provider specs, `select_suitable_signing_md`) | `src/signer.rs`, `src/cms.rs` | ported; containers built from `cms` crate types (the `cms` builder needs an in-process key) |
| `sign/general.py` (signing parts: ESS helpers, `optimal_pss_params`, `get_cms_hash_algo_for_mechanism`) | `src/attributes.rs`, `src/signer.rs` | ported |
| `sign/attributes.py` | `src/attributes.rs`, `src/cms.rs` | ported |
| `sign/ades/api.py`, `sign/ades/cades_asn1.py` | `src/attributes.rs` (+ `sigis_pki_core::asn1` types) | ported |
| `sign/timestamps/dummy_client.py`, `common_utils.py` | `src/timestamps.rs` | ported |
| `sign/timestamps/api.py` (`TimeStamper`) | `sigis_pki_core::sign::TimeStamper` + `src/pdf/timestamp.rs` (`tsa_validation_info`) | ported |
| `sign/timestamps/requests_client.py`, `aiohttp_client.py` | — | lane A (`sigis_pki_fetch::HttpTimeStamper`) |
| `sign/signers/pdf_signer.py` | `src/pdf/signer.rs`, `src/pdf/timestamp.rs`, `src/ltv.rs` | ported (PdfSigner, signing session, locking rules, seed value enforcement, size estimation, interrupted signing, post-sign DSS/LTA, PdfTimeStamper) except PDF MAC (ISO 32004, pending lane B `pdfmac`) |
| `sign/signers/cms_embedder.py` | `src/pdf/signer.rs` (`SigMdpSetup`, `write_and_digest`, `PdfTbsDocument`) | ported |
| `sign/signers/pdf_byterange.py` | `src/pdf/signer.rs` (`SignatureObjectSpec`, `BuildProps`, `PreparedDocument`), `src/pdf/writer.rs` (placeholders) | ported |
| `sign/signers/functions.py` (`sign_pdf`, `embed_payload_with_cms`) | `src/lib.rs` (`PdfSigner::sign_pdf`) | `sign_pdf` ported; `embed_payload_with_cms` pending (embedded files, lane B) |
| `sign/signers/constants.py` | `src/pdf/signer.rs` | ported (extensions, defaults) |
| `sign/fields.py` | `src/pdf/fields.rs`, `src/pdf/seed.rs` | ported |
| `sign/validation/dss.py` (writing: `supply_dss_in_writer`, `add_dss`, `add_validation_info`, `collect_validation_info`) | `src/pdf/dss.rs`, `src/pdf/timestamp.rs`, `src/ltv.rs` | ported |
| `pdf_utils/incremental_writer.py`, writing parts of `writer.py`, `xref.py` (`write_xref_table`, `XRefStream`) | `src/pdf/writer.rs` | ported on `lopdf`, temporary until lane B's `sigis_pdf::IncrementalWriter` |
| `pdf_utils/form_tools.py` (`enumerate_fields_in`, `get_single_field_annot`, `annot_width_height`) | `src/pdf/fields.rs` | ported |
| `pdf_utils/generic.py` (`pdf_date`, `pdf_string`) | `src/pdf/util.rs` | ported |
| Encryption for updates of encrypted files (`crypt/` standard handler) | `src/pdf/writer.rs` via `lopdf::encryption` | standard handler supported; public-key handler pending (lane B) |
| `sign/pkcs11.py` | `src/pkcs11.rs` | ported (`cryptoki`) |
| `sign/signers/csc_signer.py` | `src/csc.rs` | ported (blocking `reqwest`) |
| `stamp/` (`base`, `text`, `qr`, `static`, `functions`, `art`), stamp config | `src/stamp/` | ported |
| `pdf_utils/{layout,text,content,images,qr,barcodes,form_tools}.py` | `src/layout.rs`, `src/text.rs`, `src/content/`, `src/images.rs`, `src/qr.rs`, `src/barcodes.rs`, `src/form_tools.rs` | ported (`png`/`zune-jpeg`, `qrcode` with python-qrcode segmentation, Code 128 only) |
| `pdf_utils/font/` | `src/font/` | ported (`ttf-parser`, `rustybuzz`, `subsetter`; CFF subsets rebuilt in fontTools' layout) |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_signing.py` | `tests/test_signing.rs`, `tests/test_signing_appearance.rs` | 78 | 68 | 9 | 1 |
| `test_pades.py` | `tests/test_pades.rs` | 48 | 39 | 1 | 8 |
| `test_fields.py` | `tests/test_fields.rs` | 27 | 27 | 0 | 0 |
| `test_seed_values.py` | `tests/test_seed_values.rs` | 36 | 34 | 1 | 1 |
| `test_sign_encrypted.py` | `tests/test_sign_encrypted.rs` | 11 | 8 | 0 | 3 |
| `test_pkcs11.py` | `tests/test_pkcs11.rs` | 36 | 34 | 2 | 0 |
| `test_csc.py` | `tests/test_csc.rs` | 17 | 17 | 0 | 0 |
| `test_stamp.py` | `tests/test_stamp.rs` | 25 | 25 | 0 | 0 |
| `test_text.py` | `tests/test_text.rs` | 15 | 15 | 0 | 0 |
| `test_images.py` | `tests/test_images.rs` | 2 | 2 | 0 | 0 |
| `test_barcode.py` | `tests/test_barcode.rs` | 2 | 2 | 0 | 0 |

Skip reasons and pending dependencies per test: `docs/lanes/d.md`.
Infrastructure tests (key loading, CMS, TSA): `tests/keys_and_cms.rs`.

## Verification

Every signed output in the tests is checked twice: a Rust-side integrity
check (`tests/support/pdfcheck.rs`: byte range, digest, signature value)
and pyHanko's own verdict through `oracle/validate_pdf.py` (pinned clock,
Certomancer services where pyHanko's tests use `pki_services`). Without an
oracle the differential checks are skipped with a message.

## Integration restrictions (2026-11-12)

Runtime test and oracle paths use `sigis_testdata`; the shared oracle is
`/tmp/pyhanko-oracle/venv`. Grayscale PNG modes `1` and `I;16` are rejected
like Pillow (eight-mode live differential regression). Layout, configuration
and form errors use the dedicated core variants. See `docs/status.md` for
remaining signing/validation integration gaps and the final workspace gate.

## Round 3 independent increment (2026-11-13)

Lane P's last accepted baseline remains 297/271/13/13. Ready local commits
3a0a2ad, 21ac460 and 8e2107b propose **297/282/2/13** after eleven completed
functions and an honest raw-DSA reclassification to pending; L owns acceptance.
Eight certificate-less functions, duplicate signer-attribute rejection,
detached-eContent rejection and signed attachments pass substantive Rust and
mandatory fresh oracle assertions. The nine affected suites pass 172 Rust tests.
Two S-owned CMS partial ports and three inherited PAdES matrices have complete
extra native assertions without double counting.

A real presign algorithm-policy bypass was reproduced and fixed by extending
a clone of the caller context. Deny/allow controls agree with pinned pyHanko.
Core KeySigner remains unchanged; the optional-certificate SigningProvider,
DeferredSigner and legacy constructor adapter expose the new signing flow.

Native bounded writer/state/MAC/HTTP/AC work is preserved outside the active
source while shared APIs are pending, as detailed in the P report. Raw DSA
verification is available in core; token signing still needs a safe cryptoki
mechanism constructor and native token import. SafeNet and the Python warning
remain explicit exclusions. Existing old D fixtures stay read-only.

Exact interfaces, function mappings, runtime exclusions, commands/results and
recovery evidence: `docs/lanes/round3/p-report.md`.
