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
  archival timestamp chain renewal, `add_validation_info`.

Validation of produced files: Rust-side integrity checks plus pyHanko's own
verdict through the oracle (`crates/hanko-sign/oracle/validate_pdf.py`,
with Certomancer's live services for AdES-LTA checks), until lane E lands.

## Per-suite counts

Totals are test functions at the v0.38.1 tag (§5.1).

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_signing.py` | 78 | 14 | 0 | 64 |
| `test_pades.py` | 48 | 15 | 0 | 33 |
| `test_fields.py` | 27 | 0 | 0 | 27 |
| `test_seed_values.py` | 36 | 0 | 0 | 36 |
| `test_pkcs11.py` | 36 | 0 | 0 | 36 |
| `test_csc.py` | 17 | 0 | 0 | 17 |
| `test_sign_encrypted.py` | 11 | 0 | 0 | 11 |
| `test_stamp.py` | 25 | 0 | 0 | 25 |
| `test_text.py` | 15 | 0 | 0 | 15 |
| `test_images.py` | 2 | 0 | 0 | 2 |
| `test_barcode.py` | 2 | 0 | 0 | 2 |

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

## Known divergences

- VRI keys: pyHanko hashes the binary `/Contents` in the signing flow but
  the hex text of `/Contents` in `add_validation_info`; the port mirrors both.
- XMP metadata is not updated on signing (pyHanko updates `/ModDate` and
  producer in XMP when the document has `/Metadata`); `/Info` is updated.
- Producer string is `sigis-hanko`, not `pyHanko 0.38.1`.
- A seed value dictionary that requires a timestamp without a configured
  timestamper fails (pyHanko builds an HTTP timestamper from `/TimeStamp
  /URL`; pending `hanko-fetch`).
- Revocation information is fetched before validation (OCSP first, CRLs if
  no OCSP response), since `hanko-certvalidator` does not fetch during
  validation; pyHanko's validator records what it fetched.

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
2. **Shared target directory breaks lane fixtures:** `hanko_testdata::data_dir()`
   uses compile-time `env!("CARGO_MANIFEST_DIR")`; with the shared
   `/build/sigis/target`, the linked `hanko-testdata` can come from another
   worktree (observed: `sigis-wt/e-validate`, `sigis`), so lane-specific
   fixtures are not found. Lane D resolves paths at run time from the test
   process's `CARGO_MANIFEST_DIR`. Suggest the same in `hanko-testdata`
   (or a `HANKO_TESTDATA` override).
3. **Lane A (`hanko-core::algorithms`):** `DigestAlgorithm` lacks SHA3-256/384/512
   and SHAKE256; needed for `test_ecdsa_with_sha3`, `test_rsa_with_sha3`,
   Ed448 (`shake256_len`). Signing support for Ed448, DSA and ML-DSA would
   need RustCrypto `ed448-goldilocks`, `dsa`, `ml-dsa` (not in the lock file).
4. **Lane A (`hanko-certvalidator`):** a getter for the CRLs / OCSP responses
   supplied to a `ValidationContext` (pyHanko embeds `vc.ocsps` / `vc.crls`,
   e.g. `dummy_ocsp_vc` in `test_ocsp_embed`, `test_pades_revinfo_dummydata`).
5. **Lane B:** signing needs from `hanko-pdf` an incremental writer with
   object get/put/add, a way to locate placeholder offsets in the output
   (or a hook to serialize one object with placeholders), xref-stream
   output when the previous revision used one, and encryption of new
   objects for signing encrypted documents (`test_sign_encrypted.py`).
