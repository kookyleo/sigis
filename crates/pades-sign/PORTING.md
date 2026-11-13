# Current lead acceptance

Accepted: **297 total /295 passed /2 skipped /0 pending** on source724d078d.
Root round3_raw_dsa covers the exact original with actual native token/PDF/full
trust/SHA256/Sig1 and mandatory fresh same-output oracle. Default3192 rejects;
the original local1024fixture policy trusts. Generic provider matrix parameters
remain separately excluded pending proof; SafeNet and deprecated Python warning
remain. Earlier complete AC and other histories below retain their real sources.
See docs/lanes/round3/l-signing-structure.md and the central ledger.

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
| `sign/signers/pdf_signer.py` | `src/pdf/signer.rs`, `src/pdf/timestamp.rs`, `src/ltv.rs` | ported (PdfSigner, signing session, locking rules, seed value enforcement, size estimation, interrupted signing, post-sign DSS/LTA, PdfTimeStamper) including per-session PDF MAC (ISO 32004), pending S/V caller acceptance |
| `sign/signers/cms_embedder.py` | `src/pdf/signer.rs` (`SigMdpSetup`, `write_and_digest`, `PdfTbsDocument`) | ported |
| `sign/signers/pdf_byterange.py` | `src/pdf/signer.rs` (`SignatureObjectSpec`, `BuildProps`, `PreparedDocument`), `src/pdf/writer.rs` (placeholders) | ported |
| `sign/signers/functions.py` (`sign_pdf`, `embed_payload_with_cms`) | `src/lib.rs` (`PdfSigner::sign_pdf`) | `sign_pdf` and `embed_payload_with_cms` ported; attachment accepted in round 3 |
| `sign/signers/constants.py` | `src/pdf/signer.rs` | ported (extensions, defaults) |
| `sign/fields.py` | `src/pdf/fields.rs`, `src/pdf/seed.rs` | ported |
| `sign/validation/dss.py` (writing: `supply_dss_in_writer`, `add_dss`, `add_validation_info`, `collect_validation_info`) | `src/pdf/dss.rs`, `src/pdf/timestamp.rs`, `src/ltv.rs` | ported |
| `pdf_utils/incremental_writer.py`, writing parts of `writer.py`, `xref.py` (`write_xref_table`, `XRefStream`) | `src/pdf/writer.rs` | native bounded reader and native encrypted object serialization; lopdf compatibility object storage |
| `pdf_utils/form_tools.py` (`enumerate_fields_in`, `get_single_field_annot`, `annot_width_height`) | `src/pdf/fields.rs` | ported |
| `pdf_utils/generic.py` (`pdf_date`, `pdf_string`) | `src/pdf/util.rs` | ported |
| Encryption for updates of encrypted files (`crypt/` standard handler) | `src/pdf/writer.rs` via `lopdf::encryption` | native password/public-key updates with authenticated reopen state (round 3 candidate) |
| `sign/pkcs11.py` | `src/pkcs11.rs` | ported (`cryptoki`) |
| `sign/signers/csc_signer.py` | `src/csc.rs` | ported (blocking `reqwest`) |
| `stamp/` (`base`, `text`, `qr`, `static`, `functions`, `art`), stamp config | `src/stamp/` | ported |
| `pdf_utils/{layout,text,content,images,qr,barcodes,form_tools}.py` | `src/layout.rs`, `src/text.rs`, `src/content/`, `src/images.rs`, `src/qr.rs`, `src/barcodes.rs`, `src/form_tools.rs` | ported (`png`/`zune-jpeg`, `qrcode` with python-qrcode segmentation, Code 128 only) |
| `pdf_utils/font/` | `src/font/` | ported (`ttf-parser`, `rustybuzz`, `subsetter`; CFF subsets rebuilt in fontTools' layout) |

## Historical baseline test mapping

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

## Round 3 consumer increment (2026-11-13)

L accepted the earlier optional-certificate, attachment and rejection increment:
**297 total / 282 passed / 3 skipped / 12 pending**. The three central exclusions
are SafeNet signing PIN hardware, raw DSA token integration and a Python
DeprecationWarning API. Raw DSA verification exists in core; the provider binding
and token importer remain gaps, not a verification limitation.

Five additional exact HTTP/seed URL and public-key signing/copy functions are
candidates for **297/287/3/7**, subject to L review and the workspace gate. Seven
AC functions remain pending: supplied-evidence native presign tests and fresh
Python status assertions do not replace automatic AC fetching or native V status
assertions. No helper test or cross-lane assistance adds P function credit.

Presign AC collection retains fetched AA intermediates as native validation
candidates without adding trust anchors or repeating the issuer request.
Supplemental one-fetch regressions preserve holder/algorithm rejection and
atomic evidence collection. Real signing tests check the exact AA DER emitted
in DSS and fresh Python validation using contexts built from that actual DSS,
including empty-AA-root rejection. This earns no additional function credit.

The active writer parses through bounded native readers and carries selected
limits, remaining budget, authentication and strictness across signing, DSS,
timestamps, archival updates and standalone stamps. Returned state is bound to
the actual output bytes. Native page imports retain the source reader policy;
separate background files use independent default limits. Compatibility wrappers
keep default untrusted policies; explicit state is authoritative.

PDF MAC keys live in each signing session, with a shared lease registry that
rejects overlapping MAC sessions on one reusable PdfSigner. The inherited
custom factory survives reopen state. S owns structural caller acceptance and
V owns full native LTA validation. Their functions are never double counted.

The four cross-validator suites live in root integration tests
round3_signing_{certless,skips,context_policy,partial_assertions}.rs. The package
has no validator dev-dependency cycle. The new normal dependency is the existing
workspace sigis-pki-fetch; L owns merged manifests and Cargo.lock.

Exact signatures/defaults, function mappings, provider exclusions, live oracle
versus fixture evidence, compatibility divergences and reproducible checks are
in docs/lanes/round3/p-report.md. Earlier detailed evidence is preserved under
/home/l/.codex/artifacts/sigis/round3/p/. Existing old D fixtures stay read-only.

## S-owned CMS signing prerequisites (2026-11-13)

The strict weak-digest prevention assertion now rejects through the caller's
algorithm policy at actual current time during digest selection, before MAC
setup and post-selection mechanism resolution. The MD5 error is Signing and
contains `md5 is not allowed`; an unrelated unsupported mechanism is not counted
as that policy refusal. Native spy controls prove zero operation mechanism calls
for an explicitly denied digest and a real positive signature when allowed.

Low-level CMS embedding now has a real borrowed caller-buffer API:
`pdf::signer::{write_and_digest_in_place, PreparedInPlaceDocument}` and
`pdf::dss::{add_dss_in_place, add_dss_in_place_with_state}`. Completion returns
the original caller-owned Vec by mutable reference; its allocation may grow.
The stateful completion/DSS forms carry remaining allowance, strictness and
authentication. All fallible work completes before caller bytes are committed;
bounds, reservation, malformed DSS, exhausted budget and authorization failures
preserve the buffer. These are byte transactions, not rollback of reader work.

The exact direct-embedder assistance retains field Signature,8192 reservation,
SHA256,NO_CHANGES, pointer identity after signing and DSS,3cert/1OCSP, and fresh
upstream val_trusted assertions before/after. Extra AES256/MAC controls retain
authentication and document-scoped session ownership. No root/S/V files or
shared types/dependencies changed. Both upstream function IDs remain S-owned
and add no P function credit; final S acceptance belongs to S/L.


## Accepted round 3 stateful producer increment

The coherent producer source0054aee and combined trust-repair source03a156c
passed all six workspace gates. Current assigned counts:297/287/3/7.
Five exact HTTP/seed/public-key/copy functions are newly accepted; all seven
AC functions remain pending their complete native evidence/attribute/LTA flows.
The borrowed CMS embedder is credited only once to S/CMS, never again here.
State snapshots preserve options, remaining allowance and authentication;
this is not a global sibling budget. The old post-parse set_strict setter
remains a separate compatibility gap. Component MAC/session tests do not alone
complete the two S-owned PDF MAC functions. Detailed source and oracle proof:
[lead P report](../../docs/lanes/round3/p-report.md).
