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
| `pdf_utils/writer.py` | `src/writer.rs` | ported in part: base writer, `PdfFileWriter`, object streams, page insertion, resources, import, `copy_into_new_writer`; pending: `register_extension`, `import_page_as_xobject`, encryption setup |
| `pdf_utils/incremental_writer.py` | `src/writer.rs` (`IncrementalWriter`) | ported (encryption updates pending) |
| `pdf_utils/metadata/info.py`, `model.py` (subset) | `src/metadata/` | ported in part (XMP pending) |
| `pdf_utils/form_tools.py` (`enumerate_fields_in`) | `src/signatures.rs` | ported in part |
| `sign/validation/pdf_embedded.py` (discovery), `dss.py` (`read_dss`) | `src/signatures.rs` | ported (structural part) |
| `pdf_utils/metadata/xmp_xml.py` | — | pending |
| `pdf_utils/embed.py`, `extensions.py`, `content_stream_parser.py` | — | pending |
| `pdf_utils/crypt/` | — | pending |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_xref.py` | `tests/xref.rs` | 60 | 59 | 1 | 0 |
| `test_internal_utils.py` | — | 127 | 0 | 0 | 127 |
| `test_decode_limits.py` | — | 29 | 0 | 0 | 29 |
| `test_content_stream_parser.py` | — | 8 | 0 | 0 | 8 |
| `test_embed.py` | — | 9 | 0 | 0 | 9 |
| `test_meta.py` | — | 39 | 0 | 0 | 39 |
| `test_crypt.py` | — | 84 | 0 | 0 | 84 |
| `test_pdfmac.py` | — | 50 | 0 | 0 | 50 |

Skipped tests:

- `test_xref.py::test_trailer_refs`: exercises `container_ref` /
  `TrailerReference`, internals of pyHanko's mutable object model that have no
  Rust counterpart (objects are values; updates go through
  `PdfWriter::update_object`).

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
- Producer string: `sigis-hanko <version>` instead of `pyHanko <version>`;
  modification dates are written in UTC (pyHanko: local time zone).
