# Qualified CLI interface decision

Source-only decision for the next bounded C packet. Zero new original IDs
are accepted; overall1431/1350/17/64 and C252/188/0/64 remain unchanged.
Current appearance work stays separate. Existing qualification history and
proofs are preserved; unaccepted22-function tests/engine are not imported.

Use public `basic::QualificationSpec`, owned `TspRegistry`, and
`lta_validation_with_options`. Keep the SAME final LTA CMS/status and signer
qualification, with read-only `qualification_analysis` on its trusted
signature-TSA path and actual reference time. C owns the fetched registry
and lends a shared borrow. No new provider/getter, shared pades API, OS trust,
Basic fallback or independent ordinary revalidation is assigned.

The LTA result does not retain full PDF coverage/diff/DocMDP/seed metadata or
final TSA qualification. Document those limits; existing internal PDF guards
and public path/time assessment suffice to attempt these exact assertions.
The thin default-spec dispatcher and obsolete legacy LTV stub are unsuitable
for this detailed report.

Pinned CLI uses `result.api_status.bottom_line`; the unaccepted C adapter also
requires archival subindication OK. Before a verdict change, fresh-test the
2025/no-revinfo and no-POE cases, required signer/TSA qualification, unknown or
wrong-purpose TSA, and PDF coverage/DocMDP/seed negatives. Preserve actual
mandatory refusals; report raw status separately from CLI decision. Runtime
observation time, requested historical time and token genTime cannot supply
interchangeable POE. Escalate a lower-layer defect with same-byte evidence.

The bounded source/test projection is C-owned `crates/cli/**` and its fixtures.
There is no V phase-A production overlap. Propose the next exact eight-ID
packet and native/reference clock/server plan from then-current accepted main:

- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_qual_required`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_not_qualified`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_not_qualified_summary`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_qualified_summary`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_not_qualified_required`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_tsa_not_qualified`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_point_in_time_no_revinfo`

Only `test_validate_eutl_ades` has four overloaded-trust/PAdES combinations.
The eight do not inherit the regular/encrypted input fixture matrix. Preserve
all original output positives/negatives and the explicit2025 time. Source
closure and hashes are in the qualified-cli-interface-review report/JSON;
that read-only review claims no runtime parity or passing ports.
