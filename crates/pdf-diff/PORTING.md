# Porting status: sigis-pdf-diff (crates/pdf-diff)

Owner: C. Baseline: pyHanko 0.38.1 (tag `v0.38.1`, commit `580f49498f76`).
Plan and test assignment: `docs/hanko-lanes.md`.

## Module mapping

| pyHanko module | Rust file | Status |
| --- | --- | --- |
| `sign/diff_analysis/__init__.py` | `src/lib.rs` | Ported (re-exports) |
| `sign/diff_analysis/policy_api.py` | `src/lib.rs` (`ModificationLevel`, `DiffResult`, `DiffOutcome`, `DiffPolicy`), `src/error.rs` (`SuspiciousModification` = `DiffError::Suspicious`) | Ported |
| `sign/diff_analysis/policies.py` | `src/policy.rs` (`ConfigurableDiffPolicy` = class `StandardDiffPolicy`; `StandardDiffPolicy` = `DEFAULT_DIFF_POLICY`; `ConfigurableDiffPolicy::no_changes` = `NO_CHANGES_DIFF_POLICY`) | Ported |
| `sign/diff_analysis/rules_api.py` | `src/context.rs` (`Context`, `ApprovalType`, `ReferenceUpdate`), `src/rules/mod.rs` (`WhitelistRule`, `QualifiedWhitelistRule`, `Qualified`) | Ported |
| `sign/diff_analysis/form_rules_api.py` | `src/form.rs` | Ported |
| `sign/diff_analysis/commons.py`, `constants.py` | `src/commons.rs` | Ported. `qualify` / `qualify_transforming` / `map_with_return` are replaced by rules that return `Vec<(level, update)>` (all rules run to completion or fail, so laziness does not change results) |
| `sign/diff_analysis/rules/file_structure_rules.py` | `src/rules/file_structure.rs` | Ported |
| `sign/diff_analysis/rules/metadata_rules.py` | `src/rules/metadata.rs` | Ported; `lxml` replaced by `quick-xml` (well-formedness, entity and root-element checks implemented on the event stream) |
| `sign/diff_analysis/rules/form_field_rules.py` | `src/rules/form_fields.rs`, `src/rules/dss.rs` | Ported |
| `pdf_utils/reader.py` (`HistoricalResolver.get_object`, `is_ref_unassignable`, `collect_dependencies`, `_load_reverse_xref_cache`; `RawPdfPath`) | `src/history.rs`, `src/path.rs` | Ported (the parts the analysis uses; the reader itself is lane B) |
| `pdf_utils/xref.py` (`XRefCache` queries used by the analysis) | `src/history.rs` (`RevisionSource`), `src/pdf_source.rs` (`PdfFileSource`) | Interface ported; `PdfFileSource` derives the data from `sigis_pdf::PdfFile` until request C1 lands |
| `pdf_utils/generic.py` (equality, `pdf_string` decoding) | `src/object.rs` | Ported (see divergences) |
| `sign/fields.py` (`FieldMDPSpec.is_locked`) | `src/lib.rs` (`FieldMdpAction::is_locked`) | Ported |

## Test mapping

| Upstream test module | Rust test file | Total | Ported-pass | Skipped | Pending |
| --- | --- | ---: | ---: | ---: | ---: |
| `test_diff_analysis.py` | `tests/test_diff_analysis.rs` (+ `tests/sweep.rs`, `tests/mutations.rs`, unit tests) | 94 | 92 | 2 | 0 |

pyHanko's tests build their inputs with pyHanko's signer and writer.
`oracle/capture.sh` ran the upstream test module (183 cases, all passing)
and recorded each difference analysis into
`crates/testdata/data/lanes/c/`; each Rust test of the same name
replays the recorded reviews and requires pyHanko's verdict (level and
changed fields, or rejection). It also compares the reverse
cross-reference cache with pyHanko's. `tests/sweep.rs` additionally replays
pyHanko's default policy on every recorded file for every base revision,
strict and lenient (982 reviews), and re-runs pyHanko on all of them when
the oracle is installed. `tests/mutations.rs` replays a seeded mutation
corpus (`oracle/mutate.py`: one random incremental update per input, 436
updates, each reviewed plain, under DocMDP P=2 and with all fields locked:
1,308 verdicts). Larger local runs (`HANKO_DIFF_MUTATIONS`, seeds 2–5, 8
updates per file, about 10,400 verdicts) agree as well. Both the sweep and
the mutations also run through `DerivedSource`, the derivation that
`PdfFileSource` uses on `sigis_pdf::PdfFile`.

The four signing-only cases now use `tests/support/signing.rs` and lane D's
signer, with Rust and live pyHanko validation plus field/widget assertions.
Only `test_anomalous_coverage` and `test_tamper_sig_obj` remain skipped here:
coverage is decided by lane E before difference analysis. The duplicate-xref
reader regression is active and passes; there are no pending functions.

## Known divergences

All divergences are stricter than pyHanko (fail closed) for PDF inputs
reviewed through the production `PdfFileSource` adapter.

1. **Reverse cross-reference cache in encrypted files.** pyHanko does not
   enter nested direct containers of encrypted objects (they are
   `DecryptedObjectProxy` instances, which its walk skips), so it records
   fewer paths. The port walks them: more paths must be cleared. The tests
   assert that the port's paths are a superset of pyHanko's.
2. **String equality** compares raw bytes. pyHanko compares decoded text, so
   two encodings of the same text are equal there (and a text string equal
   to a name). Byte-string field names that pyHanko cannot decode make
   pyHanko crash (`TypeError`); the port rejects them as suspicious.
3. **Identical-object check** (`_is_id`) requires matching types; pyHanko
   treats a stream as identical to a dictionary with the same keys when the
   old object is the dictionary.
4. **Bounds.** The reverse cross-reference cache stops at
   `MAX_USAGE_PATHS` (2,000,000) paths, field hierarchies at depth 256 and
   page trees at depth 512, with a read error. pyHanko has no bounds
   (memory exhaustion or `RecursionError`).
5. **Python runtime errors.** Where pyHanko fails with `TypeError`,
   `ValueError`, `AttributeError` or `AssertionError` on malformed input, the
   port returns a suspicious modification or a read error.
6. **XMP check.** `quick-xml` instead of `lxml`: the port rejects invalid
   UTF-8, XML-1.0-illegal characters, `--` in comments and non-predefined
   entity references in text and attributes; streams whose filters `lopdf`
   cannot decode are rejected.
7. **Reals** (fail closed): `lopdf` stores reals as `f32`, so modification
   analysis uses an independent precision-checked reader that rejects decimal literals whose value differs from the shortest
   decimal rendering of that float (see `pdf/PORTING.md`). This prevents
   source decimals with distinct values from comparing equal. Common
   decimals remain supported; higher precision is rejected rather than
   rounded. Mixed integer/real comparisons use the exact shortest decimal
   rendering, without rounding the integer through `f64`. This supersedes
   the lead round 2 decision to accept a potentially lenient divergence.
   Custom `RevisionSource` implementations constructing `Object::Real`
   directly are responsible for the same decimal-value convention; the
   original source precision cannot be recovered from an `f32`.
8. **`DerivedSource`** (legacy generic adapter): the cross-reference stream,
   object streams and freed references of a revision are derived from the
   objects it writes; hybrid-reference streams are not cleared (pyHanko only
   accepts hybrid files in lenient mode); the mode is strict. Deriving freed
   references reads every object a revision writes, including objects
   pyHanko never reads: on the deliberately broken hybrid file of
   `test_sign_with_hybrid_sneaky_edit` this gives read errors where pyHanko
   reports a suspicious modification or (for later updates) accepts. On all
   other inputs the derivation agrees with pyHanko's exact model.

The production `PdfFileSource` now uses lane B's exact cross-reference
accessors and an independent precision-checked reader. `DerivedSource`
remains available for custom models and tests. Normal reading/encryption
may round floats; those rounded caches are not used by the production adapter.

Recorded model verdicts otherwise: all 165 recorded reviews, all 982 sweep
reviews and all 1,308 mutation verdicts agree with pyHanko, including the
kind of rejection.


## Round 3 complete validator callers

The lead independently reviewed both exact pinned validator functions against
validator_integrity.rs. test_tamper_sig_obj retains all three default/no-changes/
skip-diff assertions, including suspicious/absent diff and OTHER coverage result.
test_anomalous_coverage retains all four real-file parameters, native valid/
intact/distrust, exact coverage, false bottom line and NONSTANDARD_COVERAGE.
Positive and explicitly trusted-CMS facade controls prevent vacuous distrust.
The lead freshly revalidated the same committed/native input bytes in pinned
Python: nine validation calls, seven original parameter cases, two functions.
This is fresh oracle execution over existing inputs, not new signature creation.
The existing complete workspace gate on df25c79 passed all these native wrappers;
no source changed for this accounting increment and no gate repeat is needed.
Only two immutable S/PDF-diff skips become passed; no V credit or wrapper count.
PDF-diff94/94/0/0; S824/790/27/7; overall1431/1121/30/280.
The five PDF integration functions, including real MAC signing callers, remain
pending. Logs: round3-launch/s-coverage-acceptance/ and v-integration/gate/.
