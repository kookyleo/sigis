# Porting status: hanko-pdf

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
| `pdf_utils/reader.py` | `src/reader.rs` | ported (encryption hooks: see `crypt/`) |
| `pdf_utils/rw_common.py` | `src/rw_common.rs` | ported |
| `pdf_utils/writer.py` | `src/writer.rs` | ported (encryption setup pending: `encrypt`, `encrypt_pubkey`) |
| `pdf_utils/incremental_writer.py` | `src/writer.rs` (`IncrementalWriter`) | ported (encryption updates pending) |
| `pdf_utils/metadata/info.py`, `model.py` | `src/metadata/{info,model}.rs` | ported |
| `pdf_utils/metadata/xmp_xml.py` | `src/metadata/xmp_xml.rs` | ported (XML via `quick-xml`, see Decisions) |
| `pdf_utils/form_tools.py` (`enumerate_fields_in`) | `src/signatures.rs` | ported in part |
| `sign/validation/pdf_embedded.py` (discovery), `dss.py` (`read_dss`) | `src/signatures.rs` | ported (structural part) |
| `pdf_utils/extensions.py` | `src/extensions.rs` | ported |
| `pdf_utils/content_stream_parser.py` | `src/content_stream_parser.rs` | ported |
| `pdf_utils/embed.py` | `src/embed.rs` | ported (`wrap_encrypted_payload` with the crypt module) |
| `pdf_utils/crypt/` | — | pending |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_xref.py` | `tests/xref.rs` | 60 | 59 | 1 | 0 |
| `test_internal_utils.py` | `tests/internal_utils.rs` | 127 | 110 | 16 | 1 |
| `test_decode_limits.py` | `tests/decode_limits.rs` | 29 | 26 | 0 | 3 |
| `test_content_stream_parser.py` | `tests/content_stream_parser.rs` | 8 | 8 | 0 | 0 |
| `test_embed.py` | `tests/embed.rs` | 9 | 4 | 0 | 5 |
| `test_meta.py` | `tests/meta.rs` | 39 | 37 | 0 | 2 |
| `test_crypt.py` | — | 84 | 0 | 0 | 84 |
| `test_pdfmac.py` | — | 50 | 0 | 0 | 50 |

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

Pending tests:

- `test_meta.py::{test_encrypt_skipping_managed_metadata,
  test_encrypt_with_managed_metadata}`, `test_embed.py::{test_encrypt_efs,
  test_decrypt_ef_without_explicit_crypt_filter,
  test_wrapper_doc_underspecified, test_wrapper_doc, test_wrapper_doc_pubkey}`
  (need the crypt module).

- `test_internal_utils.py::test_page_tree_import` (needs encryption).
- `test_decode_limits.py::test_post_sign_reopen_keeps_limits`,
  `test_archival_timestamp_update_keeps_limits`, `test_add_dss_keeps_limits`
  (need lane D signing / DSS updates).

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
- Producer string: `sigis-hanko <version>` instead of `pyHanko <version>`;
  modification dates are written in UTC (pyHanko: local time zone).
