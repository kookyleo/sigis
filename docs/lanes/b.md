# Lane B — PDF layer

Owner: lane B (branch `hanko/b-pdf`). See `docs/hanko-lanes.md`.

## Status

Phase 1 (core) landed on `hanko/b-pdf`: reader with revision history
(xref tables and streams, object streams, hybrid files, strict/lenient
modes, `startxref` recovery), decoding limits, filters, historical
resolution (`HistoricalResolver`, reverse path index for lane C),
base/new-file/incremental writer, signature field enumeration, embedded
signature discovery, DSS reading. All §4 `sigis-pdf` interface functions are
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
  strict}` and `sigis_pdf::XrefSectionInfo` (same fields as
  `sigis_pdf_diff::XrefSectionInfo`). `trailer_in_revision(rev)` now returns the
  section's own trailer, as lane C asked; the merged view is
  `effective_trailer_in_revision`.
- Lane E request R-E6 / B-2: `RevisionInfo::{startxref, xref_end}` and
  `EmbeddedSignature::field_object` (as relayed by the lead), plus
  `PdfFile::xref_location(rev)` and `PdfFile::signature_field_ref(sig_object)`.
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
`crates/pdf/PORTING.md`. Pending tests that depend on other lanes:
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

Targets in `crates/pdf/fuzz` (see its README). Budget: 15 minutes per
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

See `crates/pdf/PORTING.md` ("Known divergences"). All fail closed.

## Requests to the lead

None open. (Item 1, `hazmat`, is done on `main`. Item 2: lane B used the
lane-local venv `/tmp/hanko-b/venv` to export its crypt PKI and the PDF MAC
signature fixtures; scripts are committed under `crates/pdf/oracle/`
and run against `/tmp/pyhanko-oracle/venv` as well.)

## Requests from other lanes (relayed by the lead, 2026-11-12)

When rebasing onto `main`, keep this section in your version of this file.

- **B-1 (from lane C, C1; needed for an exact `PdfFileSource`).** Add to
  `sigis_pdf::PdfFile`:
  ```rust
  pub struct XrefSectionInfo {      // XRefSectionData + XRefSectionMetaInfo
      pub size: u32,                // /Size of the section
      pub stream_ref: Option<ObjectId>,         // xref stream of the section
      pub hybrid_stream_ref: Option<ObjectId>,  // /XRefStm stream, if any
      pub explicit_refs: BTreeSet<ObjectId>,    // incl. hybrid entries and freed (n, next_gen - 1)
      pub freed: BTreeSet<ObjectId>,            // refs_freed_in_revision
      pub object_streams_used: BTreeSet<u32>,   // obj_streams_used
  }
  impl PdfFile {
      pub fn xref_section(&self, revision: usize) -> Result<XrefSectionInfo>;
      pub fn last_change(&self, id: ObjectId) -> Result<Option<usize>>;          // get_last_change
      pub fn introducing_revision(&self, id: ObjectId) -> Result<Option<usize>>; // get_introducing_revision
      pub fn resolves_in(&self, id: ObjectId, revision: usize) -> Result<bool>;  // get_historical_ref(..) is not None
      pub fn strict(&self) -> bool;
  }
  ```
  `sigis_pdf_diff::XrefSectionInfo` has exactly these fields; define it in
  `sigis-pdf`, and the lead will switch `sigis-pdf-diff` to a re-export. Please
  also pin the semantics of the existing methods in their docs:
  `object_in_revision(id, rev)` returns what
  `HistoricalResolver(rev).get_object(id)` returns (`None` when the reference
  does not resolve: free or never defined), and `trailer_in_revision(rev)` is
  that section's own trailer (lane C merges older trailers itself, as
  `TrailerDictionary.flatten`).
- **B-2 (from lane E, R-E6).** For the coverage check and the DocMDP `/Lock`
  lookup: `RevisionInfo` gains `startxref: u64` and `xref_end: u64` (end of
  the revision's xref table or stream, pyHanko
  `get_xref_container_info(rev).end_location`), and `EmbeddedSignature` gains
  `field_object: ObjectId` (the signature field dictionary).
- **B-3 (from lane C, C4).** `lopdf::Object::Real` is `f32`; pyHanko compares
  numbers exactly (`Decimal`). If `PdfFile` can keep the original numeric
  text (or an `f64`), the diff rules will use it; otherwise this stays a
  listed low-risk divergence in lane C. Tell the lead which way you go.
- **B-4 (from lane D).** Signing needs from `sigis-pdf`: an incremental writer
  with object get / put / add; a way to locate placeholder offsets in the
  output (or a hook to serialize one object with placeholders); xref-stream
  output when the previous revision used one; and encryption of new objects
  (lane D did the standard handler on `lopdf`; the public-key handler is
  missing for `test_sign_encrypted.py`).
- **Lead answers to your requests:** item 1 (`hazmat`) done on `main`;
  item 2: the standard oracle venv is `/tmp/pyhanko-oracle/venv` now (see
  `docs/hanko-lanes.md` §5.4). Use `sigis_testdata::data_dir()` /
  `manifest_dir()` (run-time paths), never `env!("CARGO_MANIFEST_DIR")`.

### Lane B answers (2026-11-12)

- **B-1: done** (`sigis_pdf::XrefSectionInfo`, `PdfFile::{xref_section,
  last_change, introducing_revision, resolves_in, strict}`). Semantics are
  pinned in the docs: `object_in_revision` as `HistoricalResolver(rev).get_object`
  (`None` when the reference does not resolve), `trailer_in_revision` is the
  section's own trailer; the merged one is `effective_trailer_in_revision`.
- **B-2: done**: `RevisionInfo::{startxref, xref_end}` and
  `EmbeddedSignature::field_object`.
- **B-3: stays `f32`.** The interface fixes `lopdf::Object`, whose reals are
  `f32`, and keeping the original text would need a parallel object model.
  Both revisions of a compared object go through the same parser, so equal
  source text gives equal values; only distinct decimals that collide in
  `f32` (more than ~7 significant digits) compare equal where pyHanko's
  `Decimal` would not. Please keep it as a listed low-risk divergence in
  lane C. Numbers beyond 64-bit integers are rejected by the reader.
- **B-4: done.** `IncrementalWriter` (derefs to `PdfWriter`):
  `get_object` / `update_object` / `add_object` / `allocate_placeholder` +
  `add_object_ext(.., idnum)`; xref streams are written when the previous
  revision used one (`stream_xrefs`); placeholders: after `write()`,
  `PdfWriter::written_object_spans()` gives the byte range of every
  serialised object body in the output, so a signer can search the
  `/Contents` and `/ByteRange` placeholders inside its signature object's
  span; encryption of new objects works for standard and public-key
  handlers (`IncrementalWriter::{encrypt, encrypt_pubkey}`, `PdfWriter::{encrypt,
  encrypt_pubkey, assign_security_handler}`), and signature dictionaries
  (`/ByteRange` or `/Type /Sig|/DocTimeStamp`) keep `/Contents`
  unencrypted, as pyHanko's placeholders do. Fixed object time and ID for
  reproducible output: `fixed_time`, `set_document_id`.

## Lead round 2 (2026-11-12)

- Merged into `main` (rebased; no conflicts); `hanko-diff` re-exports your
  `XrefSectionInfo`, and lane C's duplicate-xref test passes on your reader.
- B-3 decided: reals stay `f32`; recorded as lane C's known divergence 7
  (the only one that can be more lenient than pyHanko).
- The merged code was formatted with rustfmt (separate commit); run
  `cargo fmt --all` before phase commits.
- Layout renamed (`docs/crates.md`): your crate is `crates/pdf`
  (`sigis-pdf`).
