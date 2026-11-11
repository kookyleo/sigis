# Lane D — Signing

Owner: lane D (branch `hanko/d-sign`). See `docs/hanko-lanes.md`.

## Status

In progress. Landed on the lane branch:

- Key loading (PKCS#8 incl. PBES1/PBES2, PKCS#1/SEC1 with OpenSSL legacy PEM
  encryption, PKCS#12), `SimpleSigner` / `ExternalSigner` (RSA PKCS#1 v1.5
  and PSS, ECDSA P-256/384/521, Ed25519).
- CMS assembly with pyHanko's attribute profiles (generic, PDF, CAdES/PAdES):
  signing certificate v2, CMS algorithm protection, signature policy,
  commitment type, signer attributes v2, content and signature timestamps,
  Adobe revocation info archival. `DummyTimeStamper` (local TSA).
- PDF signing: incremental writer (`pdf::writer::PdfUpdate`, on `lopdf`,
  until lane B's `IncrementalWriter` lands), signature fields, field locks,
  seed values (parsing, writing, enforcement), certification (DocMDP),
  ESIC / ISO 32002 extensions, size estimation, ByteRange digest.
- PAdES B-B / B-T / B-LT / B-LTA: revocation info collection through the
  context's fetchers, DSS writing (VRI, dedup), document timestamps,
  archival timestamp chain renewal, `add_validation_info`; interrupted /
  remote signing (`digest_doc_for_signing`, `PdfTbsDocument::finish_signing`).
- Signing encrypted documents (standard security handler), ML-DSA keys.
- Key providers: PKCS#11 (`cryptoki`, SoftHSM tests), CSC remote signing.
- Visible appearances: stamps (text, QR, static), layout, fonts (OpenType
  embedding and subsetting), images, QR codes, Code 128 barcodes.

Validation of produced files: Rust-side integrity checks plus pyHanko's own
verdict through the oracle (`crates/hanko-sign/oracle/validate_pdf.py`,
with Certomancer's live services for AdES-LTA checks), until lane E lands.

## Per-suite counts

Totals are test functions at the v0.38.1 tag (§5.1).

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_signing.py` | 78 | 68 | 9 | 1 |
| `test_pades.py` | 48 | 39 | 1 | 8 |
| `test_fields.py` | 27 | 27 | 0 | 0 |
| `test_seed_values.py` | 36 | 34 | 1 | 1 |
| `test_pkcs11.py` | 36 | 34 | 2 | 0 |
| `test_csc.py` | 17 | 17 | 0 | 0 |
| `test_sign_encrypted.py` | 11 | 8 | 0 | 3 |
| `test_stamp.py` | 25 | 25 | 0 | 0 |
| `test_text.py` | 15 | 15 | 0 | 0 |
| `test_images.py` | 2 | 2 | 0 | 0 |
| `test_barcode.py` | 2 | 2 | 0 | 0 |

Infrastructure tests (key loading, CMS, TSA): `tests/keys_and_cms.rs`, 10.

## Oracle

The shared venv (`/tmp/pyhanko-oracle`) has no pyHanko yet (L1). Lane D
runs its own venv at `/tmp/hanko-lane-d/venv` (pyHanko 0.38.1, Certomancer
0.16.0, pyhanko_testing_commons from the v0.38.1 tag). PyPI was unreachable
directly; `pip install -i https://mirrors.aliyun.com/pypi/simple/` worked.
Tests find the oracle via `HANKO_ORACLE`, then `/tmp/pyhanko-oracle`, then
the lane venv, and skip differential checks when none imports pyHanko.

Lane D exported the Certomancer PKI and revocation data locally into
`crates/hanko-testdata/data/lanes/d/{pki,revinfo}` (§5.4 allows this before
L1); see the README there.

### `test_signing.py` details

- Skipped (9): `test_default_validation_context_deprecated` (deprecation
  warning of pyHanko's validator API; no counterpart);
  `test_sign_reject_econtent_if_detached` (validates a fixture only; no
  signing code involved, lane E); seven tests that sign with
  `ExternalSigner(signing_cert=None)`: `test_interrupted_with_delayed_signing_cert_mech`,
  `..._cert_directly_specify_md`, `test_interrupted_could_not_determine_digest_algo`,
  `test_interrupted_no_estimation`, `test_interrupted_with_delayed_signing_no_prevalidation`,
  `test_determine_mechanism_no_signing_cert`, `test_signer_info_no_signing_cert`
  (the `KeySigner` interface always has a signing certificate).
- The five appearance tests (`test_simple_qr_sign`,
  `test_qr_sign_enforce_url_param`, `test_no_email`,
  `test_sign_appearance_noop`, `test_sign_visible_with_separate_annot`) are in
  `tests/test_signing_appearance.rs`.
- Pending (1): `test_embed_signed_attachment` (embedded files, lane B).
- SHA-3, SHAKE256 (`id-shake256-len` for Ed448, RFC 8419) and Ed448 sign
  with lane A's new `DigestAlgorithm` variants, `sha3` and
  `ed448-goldilocks`; ISO 32001 / 32002 extensions as pyHanko registers
  them.
- ML-DSA (`test_mldsa44`) signs with the `ml-dsa` crate; the Rust-side
  signature check is skipped for it (lane A's verifier lacks ML-DSA), the
  oracle verifies.
- `test_sign_prescribed_attrs` uses the local TSA instead of pyHanko's HTTP
  timestamp client against the mocked TSA (HTTP client: lane A).

### Appearance suites (`test_stamp.py`, `test_text.py`, `test_images.py`, `test_barcode.py`)

- All ported; layout tests render with `pdftoppm` and compare with ImageMagick
  `compare -metric ae` against pyHanko's expected outputs
  (`tests/support/layout.rs`), skipping only if a tool is missing.
- Divergences: layout / form-filling / configuration errors are
  `HankoError::Malformed` with a message prefix (a dedicated variant would
  need `hanko-core`); stamp timestamps render in UTC (pyHanko: local zone for
  standalone stamps); `rustybuzz` instead of HarfBuzz (language tags via the
  `x-hbot` private-use form); `subsetter` instead of fontTools (CFF subsets
  desubroutinized and rebuilt in fontTools' layout; TrueType subsets use a
  `/CIDToGIDMap` stream); one object stream per update; images: PNG and JPEG
  only (1-bit and 16-bit accepted where Pillow rejects); barcodes: Code 128
  only; QR symbols from the `qrcode` crate with python-qrcode's segmentation,
  version and mask choice; standalone stamping takes no decode limits;
  inherited `/DecodeParms` are kept when importing pages.
- Signing a visible field without a style renders pyHanko's default stamp.

### `test_pkcs11.py` / `test_csc.py` details

- PKCS#11 via `cryptoki` 0.12 against SoftHSM2 tokens created per test
  process (`tests/support/softhsm.rs`; module `/usr/lib/softhsm/libsofthsm2.so`
  or `PKCS11_TEST_MODULE`; tests print a reason and pass if SoftHSM is
  absent). Skipped (2): `test_simple_sign_from_config_with_signing_pin`
  (pyHanko runs it on SafeNet only; SoftHSM cannot require per-signature
  login), `test_simple_sign_with_raw_dsa` (no DSA in `cryptoki` 0.12 /
  `hanko-core`). Inside passing parametrized tests, Ed448 / ML-DSA / DSA
  cases and three `CKM_ECDSA_SHA256` cases are skipped at run time (not
  supported by SoftHSM 2.6.1 or the core); raw `CKM_ECDSA` covers ECDSA.
- Divergences: `Pkcs11Signer::new` loads the certificate and key handles
  eagerly (pyHanko: on first use), so lookup errors surface earlier.
- CSC via blocking `reqwest` against a local port of certomancer-csc-dummy
  (`tests/support/csc_server.rs`, `127.0.0.1:0`). pyHanko's coroutines are
  threads; `SlowCommitter` becomes a server-side delay; the network-failure
  test connects to a closed local port. Extra test
  `test_csc_sign_pdf_end_to_end` signs a PDF through the fake service.

### `test_fields.py` / `test_seed_values.py` details

- `test_seed_values.py` skipped (1): `test_sign_with_sv_missing_cert`
  (`ExternalSigner(signing_cert=None)`, see above); pending (1):
  `test_sv_timestamp_url` (HTTP TSA client from the seed value URL, lane A).

### `test_sign_encrypted.py` details

- Standard security handler (RC4, AES-256; user and owner passwords):
  `PdfUpdate::with_password` decrypts with `lopdf` and encrypts every object
  the update writes with the file key (`lopdf::encryption::encrypt_object`);
  `/Contents` stays unencrypted, as pyHanko does.
- Pending (3): `test_sign_crypt_pubkey_aes256`, `test_sign_crypt_pubkey_rc4`,
  `test_copy_file_with_mdp_signature_and_backref` (public-key security
  handler, lane B `crypt/pubkey.py`).
- `test_copy_encrypted_signed_file` rewrites the decrypted document with
  `lopdf` in place of `copy_into_new_writer`.

### `test_pades.py` details

- Skipped: `test_cades_signer_attrs_multivalued` (signs an attribute with
  two identical values; the `der` SET OF types cannot represent it; it tests
  the validator's rejection, lane E).
- Pending: `test_pades_revinfo_http_ts_dummydata` (HTTP TSA client, lane A
  `hanko-fetch::HttpTimeStamper`); `test_pades_live_ac_presign_validation`,
  `test_pades_lta_live_ac_presign_validation`,
  `test_cades_signer_attrs_autofill_dss`, `..._validate_acs`,
  `..._validate_acs_no_claimed`, `..._validate_acs_wrong_vc`,
  `..._validate_acs_missing_vc` (attribute certificate validation, lane A).
- `dummy_ocsp_vc` is emulated by serving `FIXED_OCSP` through an OCSP fetcher.
- pyHanko's I/O variants (`in_place`, `direct_flush`, `to_disk`) run the
  same flow through files, since the Rust API takes and returns bytes.

## Known divergences

- VRI keys: pyHanko hashes the binary `/Contents` in the signing flow but
  the hex text of `/Contents` in `add_validation_info`; the port mirrors both.
- XMP metadata is not updated on signing (pyHanko updates `/ModDate` and
  producer in XMP when the document has `/Metadata`); `/Info` is updated.
- Producer string is `sigis-hanko`, not `pyHanko 0.38.1`.
- A seed value dictionary that requires a timestamp without a configured
  timestamper fails (pyHanko builds an HTTP timestamper from `/TimeStamp
  /URL`; pending `hanko-fetch`).
- `test_sign_with_policy` uses policy OID `1.3.6.1.4.1.99999.1` instead of
  `2.999`: `const-oid` cannot encode a first subidentifier above 127.
- Revocation information is fetched before validation (OCSP first, CRLs if
  no OCSP response), since `hanko-certvalidator` does not fetch during
  validation; pyHanko's validator records what it fetched.

## Service switch (final step, through the lead)

Not yet at parity. What the Sigis service would call instead of
`underskrift`: `SimpleSigner::from_pkcs12` (or `SimpleSigner::load` /
`from_pkcs8_der`), `PdfSigner::new(PdfSignatureMetadata::new(field), signer)`
(PAdES by default) with `.with_timestamper(..)` for B-T and
`validation_context` + `embed_validation_info` / `use_pades_lta` for
B-LT / B-LTA. A network timestamper (`hanko-fetch::HttpTimeStamper`, lane A)
is required first.

## Requests to the lead

1. **Interface (hanko-sign, applied on the lane branch, needs approval):**
   `PdfSignatureMetadata::md_algorithm` is now `Option<DigestAlgorithm>` and
   `subfilter` is `Option<SubFilter>` (pyHanko selects both from the signer,
   seed values or key when unset). New fields on `PdfSignatureMetadata`
   (`docmdp_permissions`, `app_build_props`, `prop_auth_time`,
   `prop_auth_type`, `cades_signed_attr_spec`, `tight_size_estimates`,
   `timestamp_field_name`, `signer_key_usage`, `dss_settings`) and
   `PdfSigner` (`new_field_spec`, `stamp_style`, `appearance_text_params`,
   `cms_options`, `signing_time`, `ignore_sv`, constructor `PdfSigner::new`).
   `SimpleSigner` moved to `hanko_sign::signer` (re-exported at the root).
   `SubFilter` gained `PbadPades`. `pkcs11::Pkcs11Config` gained fields.
2. **Shared target directory breaks lane fixtures:** `hanko_testdata::data_dir()`
   uses compile-time `env!("CARGO_MANIFEST_DIR")`; with the shared
   `/build/sigis/target`, the linked `hanko-testdata` can come from another
   worktree (observed: `sigis-wt/e-validate`, `sigis`), so lane-specific
   fixtures are not found. Lane D resolves paths at run time from the test
   process's `CARGO_MANIFEST_DIR`. Suggest the same in `hanko-testdata`
   (or a `HANKO_TESTDATA` override).
3. **Lane A (`hanko-core::algorithms`):** done on `main` (SHA-3, SHAKE256,
   Ed448, DSA); lane D signs SHA-3 / SHAKE256 / Ed448 / ML-DSA now.
   `validate_signature` cannot verify ML-DSA yet (Rust-side test check skipped
   for it; the oracle verifies).
4. **Lane A (`hanko-certvalidator`):** a getter for the CRLs / OCSP responses
   supplied to a `ValidationContext` (pyHanko embeds `vc.ocsps` / `vc.crls`,
   e.g. `dummy_ocsp_vc` in `test_ocsp_embed`, `test_pades_revinfo_dummydata`).
5. **Lane B:** signing needs from `hanko-pdf` an incremental writer with
   object get/put/add, a way to locate placeholder offsets in the output
   (or a hook to serialize one object with placeholders), xref-stream
   output when the previous revision used one, and encryption of new
   objects (standard handler done on `lopdf` in lane D; the public-key
   handler is missing for `test_sign_encrypted.py`).
6. **hanko-core:** a `HankoError::Layout` (and ideally `Configuration`,
   `FormFilling`) variant, to replace the message-prefix workaround.
## Requests from other lanes (relayed by the lead, 2026-11-12)

When rebasing onto `main`, keep this section in your version of this file.

- **D-1 (from lane E).** Seed value validation in `hanko-validate` is pending
  on `SigSeedValueSpec` (pyHanko `sign/fields.py`). Please expose the seed
  value model with parsing from a PDF dictionary
  (`SigSeedValueSpec::from_pdf_object`, including `/MDP`, `/LockDocument`,
  `/Cert` constraints, `/Reasons`, `/SubFilter`, `/DigestMethod`, `/TimeStamp`,
  `/AppearanceFilter`, `/Ff`) as public API of `hanko-sign`. `hanko-validate`
  may depend on `hanko-sign` (no cycle: `hanko-sign` must not depend on
  `hanko-validate`; dev-dependencies may).
  *Lane D answer:* done. `SigSeedValueSpec::from_pdf_object`,
  `SigCertConstraints::from_pdf_object` and `FieldMdpSpec::from_pdf_object`
  take any `hanko_sign::pdf::util::ObjectResolver`, implemented for
  `lopdf::Document` and for the signing writer; `SigCertConstraints::satisfied_by`
  checks a certificate. `hanko-sign` does not depend on `hanko-validate`.
- **D-2 (from the lead).** `crates/hanko-sign/tests/support/mod.rs` uses
  `env!("CARGO_MANIFEST_DIR")`; switch to `hanko_testdata::manifest_dir()` /
  `hanko_testdata::data_dir()` (run-time paths, see `docs/hanko-lanes.md`
  §5.2).
  *Lane D answer:* done (`tests/support` uses `hanko_testdata::data_dir()`).
- **Lead answers to your requests:** 1 approved (recorded in
  `docs/hanko-lanes.md` §8). 2 done on `main` (run-time fixture paths).
  3 and 4 relayed to lane A (A-5, A-6). 5 relayed to lane B (B-4). The
  standard oracle venv is `/tmp/pyhanko-oracle/venv`.
