# Lane S: exact inherited PDF skip audit

Baseline: pyHanko 0.38.1, `test_internal_utils.py` and `test_xref.py`.
This is an assertion audit, not a claim of newly passing functions.
All 17 inherited PDF skips remain skipped until the listed assertions
are exercised through substantive Rust tests. Four belong to P-owned APIs.

| Upstream function | Exact assertion or remaining feature gap |
| --- | --- |
| `test_box_constraint_over_underspecify` | P request: reject width+height+ratio; infer 1600/900 and 16/9 from every two supplied dimensions; reject overwriting inferred dimensions; verify defined flags before and after sequential assignment. |
| `test_box_constraint_recalc` | P request: ratio-only has no width/height; reads reject until assignment; assigning either dimension infers the other; width-only has no ratio until height is assigned. |
| `test_resource_add_test` | P request: merge `/XObject`, `/Pattern`, `/Font`; preserve `/Bleh` and `/Blah`; do not emit absent `/Shading`. |
| `test_duplicate_resource` | P request: duplicate `/XObject /Bleh` rejects even when both values are null. |
| `test_bool_dunders` | Gap: Python boolean-object coercion, comparison with text, and `repr`/`str` returning `True`/`False` have no matching public Rust API. Enum storage alone does not prove the full assertion set. |
| `test_ordered_enum` | Gap: generic Python `OrderedEnum` helper is absent. A test-only Rust enum would merely test the Rust language and cannot establish a port of this public helper. |
| `test_version_enum` | Gap: generic version ordering with a future/unknown version greater than all known versions is absent. Requires all strict/non-strict, equal-future and reverse comparisons. |
| `test_name_encode_fail` | Compatibility gap: upstream rejects serializing a name created without a leading slash, matching `Could not serialise name object`. Rust stores the payload without a slash and cannot preserve this invalid construction state. |
| `test_pdfstring_typing` | Upstream rejects integer `-1` at runtime. Rust's byte-slice input excludes this at compilation, but no exact compile-failure assertion has yet been added. Remains skipped. |
| `test_text_string_no_bytes_available` | Compatibility gap: upstream raises `No information` for original bytes of newly constructed text. Rust retains bytes in every string; the missing-original-bytes state is absent. |
| `test_stream_pathological_encode_decode` | Compatibility gap: upstream permits a stream with neither encoded nor decoded data and rejects both accessors with `No data`. Rust stream content is always a vector, including valid empty content. |
| `test_dictionary_setvalue_guard` | Compatibility gap: upstream rejects raw integer values for assignment and `setdefault` because values must be `PdfObject`. `lopdf::Dictionary::set` accepts convertible values, so its convenience API intentionally differs. |
| `test_all_nulls_same_hash` | Gap: upstream requires separately created null objects to have equal hashes. The chosen `lopdf::Object` does not expose a corresponding public hashing contract. Equality alone is not this assertion. |
| `test_unbound_reference` | Compatibility gap: an unbound Python reference resolves to null. Rust object IDs require a handler for resolution and do not expose an unbound reference resolver. |
| `test_assign_non_name_to_dict` | Upstream rejects integer dictionary key `10`. Rust byte-string keys reject integers at compilation; no exact compile-failure assertion has yet been added. Remains skipped. |
| `test_operator_literal_hash` | Gap: upstream distinguishes the hash of text `aaa` from an operator literal `aaa`. Rust separates operators and objects without an equivalent shared hashing interface. |
| `test_trailer_refs` | Gap: upstream `/Root` reference retains a `TrailerReference` container and `update_container` updates its trailer. Rust uses explicit writer mutation and has no container-reference API; updating a catalog is not the same assertion. |

## PDF-diff validator requests

These two functions remain part of the fixed PDF-diff total of 94. They
must not be counted from empty wrappers or difference-analysis recordings.

- `test_tamper_sig_obj`: all three `(policy, skip_diff)` combinations
  `(default, false)`, `(no-changes, false)`, `(default, true)`; append an
  update setting signature dictionary `/Bleh false`; require contiguous
  coverage from the start and modification level OTHER. The first two
  require a suspicious difference result; the last requires no difference
  result. V owns validator API assertions.
- `test_anomalous_coverage`: all four files `tail-uncovered.pdf`,
  `signature-gap-too-big.pdf`, `one-byterange.pdf`, `weird-byterange.pdf`;
  respectively contiguous-from-start, unclear, unclear, unclear coverage;
  all retain valid/intact cryptography, reject trust and bottom line,
  and include NONSTANDARD_COVERAGE in the status summary. V owns these
  assertions; rejecting the complete file does not substitute for the
  upstream cryptographic/status assertions.

## Pending decode-limit acceptance

The source assertions require a real oversized compressed object stream
that default limits reject and explicitly trusted limits accept. Preserve
the same policy through every internal reopen, then require:

- `test_post_sign_reopen_keeps_limits`: both next-timestamp and separate
  DSS placements produce exactly one embedded document timestamp after
  actual B-LTA signing with validation information.
- `test_archival_timestamp_update_keeps_limits`: archival-chain update of
  the trusted oversized input produces exactly one document timestamp.
- `test_add_dss_keeps_limits`: add the signing certificate to the trusted
  oversized input and require a nonempty DSS certificate store.

Default-limit rejection remains an adversarial control. Reopening a
pre-existing fixture, or checking only a Python recording, cannot satisfy
these three functions.
