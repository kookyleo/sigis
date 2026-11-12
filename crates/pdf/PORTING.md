# Porting status: sigis-pdf (crates/pdf)

Owner: B. Baseline: pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0.
Plan and test assignment: `docs/hanko-lanes.md`.

## Decisions

- **Object model: `lopdf` 0.47** (`lopdf::Object`), as required by the lane
  interface. Names and strings are kept as raw bytes; pyHanko's text/byte
  string classification is available through `generic::pdf_string`.
  Reals are `f32` (pyHanko: `Decimal`).
- **Parser, xref machinery, reader and writer: ported, not taken from
  lopdf.** lopdf's parser is private and its `Document`/`Reader` merge all
  revisions into one object table, without per-revision history, strict-mode
  consistency checks or pyHanko's error behaviour. The tests assert those
  behaviours (exact error classes and messages, off-by-one `startxref`
  recovery, hybrid files, free/reuse generation rules), so `reader.py`,
  `xref.py` and the parsing half of `generic.py` are ported directly on top
  of the lopdf types. lopdf is used for the object model only.
- **XML (XMP)**: `quick-xml` (namespace-aware reader) builds a minimal
  element tree that mirrors what pyHanko uses of lxml. `roxmltree` was
  evaluated first and rejected: it refuses elements with the predefined
  `xml:` prefix (e.g. `<xml:lang>` qualifiers), which XMP uses. DTDs and
  non-predefined entities are rejected (pyHanko rejects entities; a DTD
  without entities is rejected here as well, which is stricter).
- **Filters**: `flate2` for Flate; ASCIIHex/ASCII85 are small and ported.
  As in pyHanko, LZW, RunLength and image filters are not supported
  (`NotImplemented`), so files pyHanko rejects are rejected here too.

## Module mapping

| pyHanko module | Rust file | Status |
| --- | --- | --- |
| `pdf_utils/misc.py` (tokenizer helpers, errors) | `src/misc.rs`, `src/error.rs` | ported (`ConsList`, `chunked_*`, async helpers: not needed in Rust) |
| `pdf_utils/generic.py` | `src/generic.rs`, `src/stream.rs` | ported (object classes replaced by `lopdf::Object`; `DecryptedObjectProxy` replaced by eager decryption in the reader) |
| `pdf_utils/filters.py` | `src/filters.rs` | ported (Flate via `flate2`) |
| `pdf_utils/decode_limits.py` | `src/decode_limits.rs` | ported |
| `pdf_utils/xref.py` | `src/xref.rs` | ported |
| `pdf_utils/reader.py` | `src/reader.rs` | ported (decryption via `src/crypt/`) |
| `pdf_utils/rw_common.py` | `src/rw_common.rs` | ported |
| `pdf_utils/writer.py` | `src/writer.rs` | ported (`encrypt`/`encrypt_pubkey` in `src/crypt/mod.rs`) |
| `pdf_utils/incremental_writer.py` | `src/writer.rs` (`IncrementalWriter`) | ported |
| `pdf_utils/metadata/info.py`, `model.py` | `src/metadata/{info,model}.rs` | ported |
| `pdf_utils/metadata/xmp_xml.py` | `src/metadata/xmp_xml.rs` | ported (XML via `quick-xml`, see Decisions) |
| `pdf_utils/form_tools.py` (`enumerate_fields_in`) | `src/signatures.rs` | ported in part |
| `sign/validation/pdf_embedded.py` (discovery), `dss.py` (`read_dss`) | `src/signatures.rs` | ported (structural part) |
| `pdf_utils/extensions.py` | `src/extensions.rs` | ported |
| `pdf_utils/content_stream_parser.py` | `src/content_stream_parser.rs` | ported |
| `pdf_utils/embed.py` | `src/embed.rs` | ported |
| `pdf_utils/crypt/api.py`, `filter_mixins.py` | `src/crypt/api.rs` | ported (class hierarchy flattened: `CryptFilter` is a value, `SecurityHandler` a shared handle; handler and crypt-filter registries are explicit values) |
| `pdf_utils/crypt/standard.py` | `src/crypt/standard.rs` | ported |
| `pdf_utils/crypt/pubkey.py` | `src/crypt/pubkey.rs`, `src/crypt/keys.rs`, `src/crypt/x448.rs` | ported |
| `pdf_utils/crypt/_legacy.py` | `src/crypt/legacy.rs` | ported |
| `pdf_utils/crypt/_util.py` | `src/crypt/util.rs`, `src/crypt/rc4.rs` | ported on RustCrypto; RC4 is a small local module (no `rc4` crate in the offline registry) |
| `pdf_utils/crypt/_saslprep.py` | `src/crypt/saslprep.rs` | replaced by crate `stringprep` |
| `pdf_utils/crypt/permissions.py` | `src/crypt/permissions.rs` | ported |
| `pdf_utils/crypt/cred_ser.py` | `src/crypt/cred_ser.rs` | ported |
| `pdf_utils/crypt/__init__.py` (+ encryption parts of reader, writer, incremental_writer, generic) | `src/crypt/mod.rs` | ported |
| `pdf_utils/crypt/pdfmac.py` | `src/crypt/pdfmac.rs` | ported |
| `pdf_utils/crypt/_iso32004_asn1.py` | `src/crypt/iso32004_asn1.rs` | ported |
| `pdf_utils/{layout,text,content,images,qr,barcodes}.py`, `pdf_utils/font/` | — | lane D (see `docs/hanko-lanes.md`) |
| `pdf_utils/form_tools.py` (appearance helpers) | — | lane D (only `enumerate_fields_in` is needed here) |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_xref.py` | `tests/xref.rs` | 60 | 59 | 1 | 0 |
| `test_internal_utils.py` | `tests/internal_utils.rs` | 127 | 111 | 16 | 0 |
| `test_decode_limits.py` | `tests/decode_limits.rs` | 29 | 26 | 0 | 3 |
| `test_content_stream_parser.py` | `tests/content_stream_parser.rs` | 8 | 8 | 0 | 0 |
| `test_embed.py` | `tests/embed.rs` | 9 | 9 | 0 | 0 |
| `test_meta.py` | `tests/meta.rs` | 39 | 39 | 0 | 0 |
| `test_crypt.py` | `tests/crypt.rs` | 84 | 84 | 0 | 0 |
| `test_pdfmac.py` | `tests/pdfmac.rs` | 50 | 48 | 0 | 2 |

Skipped tests:

- `test_internal_utils.py`, tests of lane D modules (`layout.py`,
  `content.py`; lane D ports those modules): `test_box_constraint_over_underspecify`,
  `test_box_constraint_recalc`, `test_resource_add_test`,
  `test_duplicate_resource`.
- `test_internal_utils.py`, tests of Python object-model behaviour with no
  Rust counterpart (dunder methods, hashing, runtime type guards, enum
  helpers): `test_bool_dunders`, `test_ordered_enum`, `test_version_enum`,
  `test_name_encode_fail` (names never carry the slash in Rust),
  `test_pdfstring_typing`, `test_text_string_no_bytes_available` (strings
  always keep their bytes), `test_stream_pathological_encode_decode`
  (streams always have data), `test_dictionary_setvalue_guard`,
  `test_all_nulls_same_hash`, `test_unbound_reference`,
  `test_assign_non_name_to_dict`, `test_operator_literal_hash`.

- `test_xref.py::test_trailer_refs`: exercises `container_ref` /
  `TrailerReference`, internals of pyHanko's mutable object model that have no
  Rust counterpart (objects are values; updates go through
  `PdfWriter::update_object`).

Pending tests (other lanes):

- `test_decode_limits.py::{test_post_sign_reopen_keeps_limits,
  test_archival_timestamp_update_keeps_limits, test_add_dss_keeps_limits}`:
  lane D signing, archival timestamps and DSS updates.
- `test_pdfmac.py::test_pdf_mac_pades` (lane D PAdES signing with a TSA and
  lane E AdES validation), `test_pdfmac.py::test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel`
  (lane D `PdfSigner`).

Adapted tests:

- `test_pdfmac.py`: documents with a MAC inside a signature are produced by
  pyHanko 0.38.1 (`oracle/gen_pdfmac_sig_fixtures.py`, 64 PDFs in
  `hanko-testdata/data/lanes/b/pdfmac-sig/`, each checked against pyHanko's
  own verdict) until lane D's signer exists; the signature validation half
  of `test_sign_crypt_aes256_with_mac` waits for lane E.
- `test_crypt.py`: `test_encrypt_skipping_metadata(_pubkey)` read the
  catalog raw before authenticating (eager decryption);
  `test_invalid_originator_key` patches the recipient DER instead of
  monkeypatching; `test_custom_crypt_filter_type` uses an explicit
  `SecurityHandlerRegistry`.
- Encryption interop: pyHanko 0.38.1 opens files written by the port
  (R3, R4, R6 + MAC, GCM, MAC'd incremental update; RSA PKCS#1 v1.5, OAEP,
  RC4 `adbe.pkcs7.s4`; ECDH P-256/384/521, X25519, X448), checked with
  `oracle/check_decrypt.py`; `tests/crypt.rs::differential_pyhanko_reads_our_encryption`
  runs when `HANKO_ORACLE` is set.

## Known divergences

All fail closed (the port never accepts what pyHanko rejects):

- PNG predictor "Sub" (filter type 1) follows the PNG/ISO 32000 definition;
  pyHanko adds the previous *encoded* byte, which decodes multi-byte rows
  incorrectly.
- Names with bytes below 0x10 are written as `#0X` (two hex digits);
  pyHanko writes a single digit, producing an unreadable name.
- Strings are written from their original bytes: text strings as escaped
  literals, byte strings (and strings marked hexadecimal) in hex. pyHanko
  re-encodes text strings (PDFDocEncoding, else UTF-16BE) on output.
- Integers beyond 64 bits, object numbers beyond 32 bits and generations
  beyond 16 bits are rejected (pyHanko has arbitrary-precision integers).
- Decimal literals must equal the shortest decimal rendering of their
  `f32` representation after removing redundant sign and zero formatting.
  Higher-precision decimals that would round to another value, overflow or
  underflow are rejected, even in lenient mode. This preserves common
  decimals such as `0.1` and `595.28`, and prevents distinct decimal values
  from collapsing during difference analysis. This is a stricter rejection
  than pyHanko's arbitrary-precision `Decimal` parser.
- Nesting of arrays/dictionaries is limited to 256 levels and reference
  chains to 64 (pyHanko: Python recursion limit).
- Text vs. byte strings are classified by their bytes (`pdf_string`), not
  by object class: a byte string whose bytes decode as text counts as text.
- Decoded stream data is cached per handler and stream object (identified by
  the data offset recorded in `Stream::start_position`), like pyHanko's
  per-object cache; streams parsed from a file therefore carry
  `start_position`, so compare streams by `dict` and `content`.
- `wrap_encrypted_payload`'s explanation page uses a plain standard-14
  Courier font resource (pyHanko uses lane D's font engine, which adds
  `/Widths` and a font descriptor).
- XMP: an XML declaration with an `encoding` attribute after the xpacket
  header is rejected (lxml refuses such decoded text, as pyHanko does).
- Incremental writers number new objects above every object number the
  file uses (pyHanko: from `/Size`), so files whose `/Size` does not cover
  their own xref stream are not clobbered (found by fuzzing; pyHanko would
  produce an update that its own strict reader rejects).
- Integral reals beyond 1e15 are written with a trailing `.0` (pyHanko
  writes them as integers, which only works with arbitrary-precision ints).
- Encryption: objects are decrypted whole when read (pyHanko decrypts each
  string or stream lazily). Before authenticating, an object that contains
  an encrypted string or stream cannot be read; a string that fails to
  decrypt makes its whole object unreadable.
- Signature `/Contents` stays raw in dictionaries with `/ByteRange` or
  `/Type /Sig`/`/DocTimeStamp` (ISO 32000 exempts it), matching what
  pyHanko's validation reads.
- Public-key recipient matching compares issuer names by exact DER bytes
  (asn1crypto normalises); CMS recipients and MAC tokens must be DER (BER
  indefinite lengths are rejected).
- Key loading is narrower: PKCS#12 through the `p12` crate (legacy SHA-1
  3DES/RC2 only, no PBES2); encrypted PEM keys: PKCS#8 PBES2/PBES1-3DES and
  OpenSSL traditional AES-CBC / DES-EDE3 only.
- Error mapping: `PdfKeyNotAvailableError` → `PdfError::KeyNotAvailable`
  (a read error); `InappropriateCredentialError` and the PDF MAC
  `DisallowedAlgorithmError` → `PdfError::Value` with that name as prefix.
- X448 is implemented locally on `crypto-bigint` (checked against RFC 7748
  vectors): the `ed448-goldilocks` pre-release did not reproduce them.
- `wrap_encrypted_payload` takes an enum (password, certificates or
  handler), so pyHanko's "exactly one of password/certs" `ValueError`
  cannot occur; an empty certificate list yields a file nobody can open.
- Producer string: `sigis-hanko <version>` instead of `pyHanko <version>`;
  modification dates are written in UTC (pyHanko: local time zone).
