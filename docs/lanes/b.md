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
Phase 3 landed: encryption (standard and public-key handlers, crypt
filters, permissions, credential serialisation), PDF MAC (ISO 32004),
cargo-fuzz targets. All assigned suites are ported; the 5 pending tests
wait for lanes D/E (see below).

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
- Lane C request C1 is served by new items (no §4 change):
  `PdfFile::{xref_section, last_change, introducing_revision, resolves_in,
  strict}` and `hanko_pdf::XrefSectionInfo` (same fields as
  `hanko_diff::XrefSectionInfo`). `trailer_in_revision(rev)` now returns the
  section's own trailer, as lane C asked; the merged view is
  `effective_trailer_in_revision`.
- Lane E request R-E6 is served by new methods instead of new fields on §4
  structs: `PdfFile::xref_location(rev)` (`declared_startxref`, `start`,
  `end` = pyHanko `end_location`) and `PdfFile::signature_field_ref(sig_object)`.
  If the lead prefers fields on `RevisionInfo` / `EmbeddedSignature`, lane B
  can add them.
- `RevisionInfo::end_offset` is the end of the `%%EOF` line that follows
  the `startxref` pointing at the revision's xref section (linearized
  originals: both sections end at the first `%%EOF` after the main xref).

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_xref.py` | 60 | 59 | 1 | 0 |
| `test_internal_utils.py` | 127 | 111 | 16 | 0 |
| `test_decode_limits.py` | 29 | 26 | 0 | 3 |
| `test_content_stream_parser.py` | 8 | 8 | 0 | 0 |
| `test_embed.py` | 9 | 9 | 0 | 0 |
| `test_meta.py` | 39 | 39 | 0 | 0 |
| `test_crypt.py` | 84 | 84 | 0 | 0 |
| `test_pdfmac.py` | 50 | 48 | 0 | 2 |
| **Total** | **406** | **384** | **17** | **5** |

Skipped and pending tests are listed with reasons in
`crates/hanko-pdf/PORTING.md`. Pending tests that depend on other lanes:
`test_decode_limits.py::{test_post_sign_reopen_keeps_limits,
test_archival_timestamp_update_keeps_limits, test_add_dss_keeps_limits}`
(lane D signing and DSS updates), `test_pdfmac.py::{test_pdf_mac_pades,
test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel}` (lane D signer,
lane E AdES validation). PDF MAC tests with signatures use pyHanko-made
fixtures until lane D's signer lands. Skipped because the module belongs to
lane D: `test_internal_utils.py::{test_box_constraint_*,
test_resource_add_test, test_duplicate_resource}` (`layout.py`,
`content.py`).

## Fuzzing

Targets in `crates/hanko-pdf/fuzz` (see its README). Budget: 15 minutes per
target, single process each, seeds from pyHanko's test PDFs/XML, on
2026-11-12 (machine load ~60). Final run: all six clean —
`parse_pdf` 305,620 runs, `parse_object` 5,786,728, `xref_stream` 367,360,
`object_stream` 367,769, `incremental_roundtrip` 3,409,534, `xmp`
4,151,324. Earlier runs found four issues, all fixed or pinned with
regression inputs (`tests/fuzz_regressions.rs`): an integer overflow on
object stream offsets, large reals that did not reparse, update numbering
below objects the file uses, and catalog/xref-stream number sharing (pyHanko
parity, excluded from the round-trip invariant).

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
