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

Phase 2 landed: developer extensions, page import, XMP metadata
(read/update/serialise), embedded files, content stream parser.
In progress: encryption and PDF MAC (on helper branch
`hanko/b-pdf-crypt`, to be merged into `hanko/b-pdf`), then fuzz targets.

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
- Streams parsed from a file carry `Stream::start_position` (data offset);
  compare streams by `dict` and `content`, not with `==` on `Stream`.
- `RevisionInfo::end_offset` is the end of the `%%EOF` line that follows
  the `startxref` pointing at the revision's xref section (linearized
  originals: both sections end at the first `%%EOF` after the main xref).

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_xref.py` | 60 | 59 | 1 | 0 |
| `test_internal_utils.py` | 127 | 110 | 16 | 1 |
| `test_decode_limits.py` | 29 | 26 | 0 | 3 |
| `test_content_stream_parser.py` | 8 | 8 | 0 | 0 |
| `test_embed.py` | 9 | 4 | 0 | 5 |
| `test_meta.py` | 39 | 37 | 0 | 2 |
| `test_crypt.py` | 84 | 0 | 0 | 84 |
| `test_pdfmac.py` | 50 | 0 | 0 | 50 |

Skipped and pending tests are listed with reasons in
`crates/hanko-pdf/PORTING.md`. Pending tests that depend on other lanes:
`test_decode_limits.py::{test_post_sign_reopen_keeps_limits,
test_archival_timestamp_update_keeps_limits, test_add_dss_keeps_limits}`
(lane D signing and DSS updates). Skipped because the module belongs to
lane D: `test_internal_utils.py::{test_box_constraint_*,
test_resource_add_test, test_duplicate_resource}` (`layout.py`,
`content.py`).

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
2. pyHanko oracle (L1): PyPI became reachable on 2026-11-11 evening; lane B
   installed a lane-local venv at `/tmp/hanko-b/venv` (certomancer,
   pyhanko 0.38.1, pyhanko-certvalidator 0.33.0) to export the certificates
   it needs (§5.4 allows a lane-local export). `/tmp/pyhanko-oracle` was not
   touched.
