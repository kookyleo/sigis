# Lane B — PDF layer

Owner: lane B (branch `hanko/b-pdf`). See `docs/hanko-lanes.md`.

## Status

Phase 1 (core) landed on `hanko/b-pdf`: reader with revision history
(xref tables and streams, object streams, hybrid files, strict/lenient
modes, `startxref` recovery), decoding limits, filters, historical
resolution (`HistoricalResolver`, reverse path index for lane C),
base/new-file/incremental writer, signature field enumeration, embedded
signature discovery, DSS reading. All §4 `hanko-pdf` interface functions are
implemented (no `NotImplemented` stubs left).

Next: `test_internal_utils.py`, `test_decode_limits.py`, content stream
parser, extensions, embedded files, XMP metadata, encryption, PDF MAC,
fuzz targets.

Notes for lanes C, D, E:

- `PdfFile::parse` reads in strict mode; `PdfFile::parse_with(bytes,
  ReaderOptions::lenient())` for lenient mode.
- `PdfHandler` / `PdfHandlerExt` (`get_object`, `resolve`, `root`, `get`
  with pyHanko's `dict[key]` semantics, `find_page_for_modification`, ...)
  are implemented by `PdfFile`, `HistoricalResolver` and `PdfWriter`.
- `PdfFile::historical_resolver(rev)` gives `object`, `explicit_refs_in_revision`,
  `refs_freed_in_revision`, `collect_dependencies`, `usages_of_ref`
  (pyHanko's `_get_usages_of_ref`), `is_ref_unassignable`.
- Writers: modify an object by fetching it, changing it and calling
  `update_object(id, obj)` (pyHanko's `mark_update`/`update_container`).
  `IncrementalWriter` derefs to `PdfWriter`. Set `fixed_time` and
  `set_document_id` for reproducible output.
- `RevisionInfo::end_offset` is the end of the `%%EOF` line that follows
  the `startxref` pointing at the revision's xref section (linearized
  originals: both sections end at the first `%%EOF` after the main xref).

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_xref.py` | 60 | 59 | 1 | 0 |
| `test_internal_utils.py` | 127 | 0 | 0 | 127 |
| `test_decode_limits.py` | 29 | 0 | 0 | 29 |
| `test_content_stream_parser.py` | 8 | 0 | 0 | 8 |
| `test_embed.py` | 9 | 0 | 0 | 9 |
| `test_meta.py` | 39 | 0 | 0 | 39 |
| `test_crypt.py` | 84 | 0 | 0 | 84 |
| `test_pdfmac.py` | 50 | 0 | 0 | 50 |

Skipped: `test_xref.py::test_trailer_refs` (Python `container_ref`
internals; see `crates/hanko-pdf/PORTING.md`).

## Known divergences

See `crates/hanko-pdf/PORTING.md` ("Known divergences"). All fail closed.

## Requests to the lead

1. `crates/hanko-core/Cargo.toml`: `cargo check -p hanko-core` (and `-p` of
   any crate depending on it alone) fails with "no `Raw` in `certificate`":
   `hanko-core` uses `x509_cert::certificate::Raw`, which needs the
   `x509-cert` feature `hazmat`. It only builds today through feature
   unification with `certval`. Please add `features = ["hazmat"]` to
   hanko-core's `x509-cert` dependency (or to the workspace entry). Lane B
   runs its checks with `--workspace` meanwhile.
2. pyHanko oracle (L1): not installed yet on this host; lane B has no
   differential tests so far.
