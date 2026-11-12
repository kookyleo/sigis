# Lane C — Modification analysis

Owner: lane C (branch `hanko/c-diff`). See `docs/hanko-lanes.md`.

## Status

Phase 1 done (2026-11-11): `sign/diff_analysis/` of pyHanko 0.38.1 is
ported in `crates/pdf-diff` (rules, policy, form analysis, DSS, metadata,
historical resolver parts). Details: `crates/pdf-diff/PORTING.md`.

- `StandardDiffPolicy` (unit struct, `DEFAULT_DIFF_POLICY`) implements
  `DiffPolicy::review_file` on `sigis_pdf::PdfFile`. It works as soon as
  lane B fills `PdfFile::{revisions, objects_written_in, object_in_revision,
  trailer_in_revision}`; request C1 makes it exact.
- `ConfigurableDiffPolicy` is the configurable `StandardDiffPolicy` class
  (custom rules, flags, `no_changes()` = `NO_CHANGES_DIFF_POLICY`).
- `RevisionSource` is the read interface the rules use; `PdfFileSource`
  adapts `PdfFile`, the tests use a source built from pyHanko's own
  cross-reference model.
- Oracle: the shared venv `/tmp/pyhanko-oracle` has no pyHanko yet (L1). Lane
  C built a private one in `/tmp/c-diff-oracle/venv` (pyHanko 0.38.1,
  certvalidator 0.33.0, Python 3.14) and generated its fixtures with it
  (`HANKO_ORACLE=/tmp/c-diff-oracle/venv/bin/python` for the live check).

For lane E (`pdf_embedded.evaluate_modifications`): check coverage first
(coverage below `ENTIRE_REVISION` → suspicious without a diff, `ENTIRE_FILE`
→ `ModificationLevel::None`), then call
`StandardDiffPolicy.review_file(&file, signed_revision, field_mdp, doc_mdp)`.
`Ok(DiffOutcome::Suspicious(_))` is pyHanko's returned
`SuspiciousModification`; `Err(_)` is an exception pyHanko propagates
(`PdfReadError`, e.g. a strict-mode dangling reference).

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_diff_analysis.py` | 94 | 92 | 2 | 0 |

Skipped (no difference analysis runs; reasons in PORTING.md):
`test_anomalous_coverage`, `test_tamper_sig_obj` (coverage, lane E),
`test_create_deep_sig_field`, `test_create_multi_deep_sig_field`,
`test_deep_non_sig_field`, `test_simple_sign_with_separate_annot` (signer,
lane D). Pending: `test_duplicate_xref_table_entry_rejected` (reader, needs
lane B; test written and ignored).

Differential coverage: 165 recorded reviews from the 183 upstream test cases,
a sweep of 982 reviews (every recorded file × base revision × strict /
lenient) and 1,308 verdicts on a seeded mutation corpus (436 random
incremental updates; plain, DocMDP P=2, all fields locked) agree with
pyHanko, including the kind of rejection. Local runs with four more seeds
(about 10,400 verdicts) agree too. Every pyHanko rejection is asserted to be
a rejection in the port. The sweep and the mutations also run through the
`PdfFile` derivation (`DerivedSource`): no fail-open case; stricter only on
one deliberately broken hybrid file.

## Known divergences

See `crates/pdf-diff/PORTING.md` § Known divergences. All are stricter
than pyHanko except the `f32` reals of lopdf (C4).

## Requests to the lead

- **C1 (lane B interface, needed for exactness).** `PdfFileSource` currently
  derives the cross-reference details from `objects_written_in` /
  `object_in_revision`. Please add to `sigis_pdf::PdfFile` (stubs, lane B
  fills them):
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
  `sigis_pdf_diff::XrefSectionInfo` has exactly these fields; it can move to
  `sigis-pdf` and be re-exported. Please also pin the semantics of the
  existing methods in their docs: `object_in_revision(id, rev)` returns what
  `HistoricalResolver(rev).get_object(id)` returns (`None` when the
  reference does not resolve: free or never defined), and
  `trailer_in_revision(rev)` is that section's own trailer (lane C merges
  older trailers itself, as `TrailerDictionary.flatten`).
- **C2 (build).** `cargo check -p hanko-core` (and `-p hanko-diff` alone)
  fails: `hanko-core/src/cert.rs` uses `x509_cert::certificate::Raw`, which
  needs the `x509-cert` feature `hazmat`; it only compiles when another crate
  (certval) enables it. Please add `features = ["hazmat"]` to hanko-core's
  `x509-cert` dependency. Lane C builds with
  `-p hanko-diff -p hanko-certvalidator` meanwhile.
- **C3 (dependency).** `sigis-pdf-diff` depends on `quick-xml = "0.38.4"` (XMP
  check). Please hoist it into `[workspace.dependencies]` together with
  lane E's XML dependency (same version, to avoid two copies).
- **C4 (lane B, reals).** `lopdf::Object::Real` is `f32`; pyHanko compares
  numbers exactly (`Decimal`). If `PdfFile` can keep the original numeric
  text (or `f64`), the diff rules will use it; otherwise this stays a listed
  (low-risk) divergence.
- Note: `StandardDiffPolicy` stays the unit struct of the skeleton
  (`DEFAULT_DIFF_POLICY`); the configurable class is the new
  `ConfigurableDiffPolicy` (an addition, no interface change).

## Lead responses (2026-11-12)

Merged into `main` with the lead round recorded in `docs/hanko-lanes.md` §8.
- C1 relayed to lane B (B-1); C4 relayed to lane B (B-3). When B lands
  `XrefSectionInfo`, `sigis-pdf-diff` switches to a re-export.
- C2 done (`hazmat`). C3 done (`quick-xml` from the workspace).
- `tests/sweep.rs` now uses `sigis_testdata::manifest_dir()`; the committed
  `oracle/__pycache__` file was removed (`.gitignore` covers it).

## Lead round 2 (2026-11-12)

- `test_duplicate_xref_table_entry_rejected` runs and passes against lane
  B's reader (pending → ported).
- `hanko_diff::XrefSectionInfo` is lane B's type now (re-export).
- B-3: `f32` reals stay; listed below under Known divergences (low risk).
- Crate renamed: `crates/pdf-diff` (`sigis-pdf-diff`), see `docs/crates.md`.

## Lead D integration (2026-11-12)

Four signing-only cases now execute real lane D signing, verify the resulting
field/widget structure, and validate with both `sigis-pades` and the shared
pyHanko oracle: `test_create_deep_sig_field`,
`test_create_multi_deep_sig_field`, `test_deep_non_sig_field`, and
`test_simple_sign_with_separate_annot`. Only the two coverage-only cases
remain skipped in this suite. The four tests are implemented in
`tests/support/signing.rs`; signing and validation dependencies are dev-only.

The previously accepted f32 decimal-collision exception is superseded:
`PdfFileSource` now uses an independent checked reader that rejects decimal literals that would lose their source value
when represented by the shortest f32 decimal; mixed integer/real comparisons
also avoid f64 rounding. The restriction is conservative (fail closed).
Custom `RevisionSource` implementations must preserve this input invariant.
See `docs/status.md` for the final gate and remaining work.
