# Lane B — PDF layer

Owner: lane B (branch `hanko/b-pdf`). See `docs/hanko-lanes.md`.

## Status

Not started (skeleton only).

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_xref.py` | 60 | 0 | 0 | 60 |
| `test_internal_utils.py` | 127 | 0 | 0 | 127 |
| `test_decode_limits.py` | 29 | 0 | 0 | 29 |
| `test_content_stream_parser.py` | 8 | 0 | 0 | 8 |
| `test_embed.py` | 9 | 0 | 0 | 9 |
| `test_meta.py` | 39 | 0 | 0 | 39 |
| `test_crypt.py` | 84 | 0 | 0 | 84 |
| `test_pdfmac.py` | 50 | 0 | 0 | 50 |

## Known divergences

None yet.

## Requests to the lead

None yet.

## Requests from other lanes (relayed by the lead, 2026-11-12)

When rebasing onto `main`, keep this section in your version of this file.

- **B-1 (from lane C, C1; needed for an exact `PdfFileSource`).** Add to
  `hanko_pdf::PdfFile`:
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
  `hanko_diff::XrefSectionInfo` has exactly these fields; define it in
  `hanko-pdf`, and the lead will switch `hanko-diff` to a re-export. Please
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
- **B-4 (from lane D).** Signing needs from `hanko-pdf`: an incremental writer
  with object get / put / add; a way to locate placeholder offsets in the
  output (or a hook to serialize one object with placeholders); xref-stream
  output when the previous revision used one; and encryption of new objects
  (lane D did the standard handler on `lopdf`; the public-key handler is
  missing for `test_sign_encrypted.py`).
- **Lead answers to your requests:** item 1 (`hazmat`) done on `main`;
  item 2: the standard oracle venv is `/tmp/pyhanko-oracle/venv` now (see
  `docs/hanko-lanes.md` §5.4). Use `hanko_testdata::data_dir()` /
  `manifest_dir()` (run-time paths), never `env!("CARGO_MANIFEST_DIR")`.
