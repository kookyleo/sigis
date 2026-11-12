# Fields independent port

Scope: signature-field listing and incremental/resave creation. Original tests were translated before implementation.
Unique functions: 7 total / 7 locally passed /0 skipped/0 pending. Accepted counts require L gate.

| Unique upstream function | Assertions retained |
| --- | --- |
| test_list_empty_fields_with_status | Exact Sig1/Sig2 EMPTY output |
| test_list_mixed_fields_with_status | Real Rust signing, exact FILLED/EMPTY output |
| test_list_empty_fields_without_status | Exact names without status |
| test_cli_add_field_incremental_update_by_default | Sig1 name, two revisions, original input prefix |
| test_cli_add_field_with_resave | Sig1 name, one revision |
| test_cli_add_field_to_last_page | Last page object identity equals field P reference |
| test_cli_field_spec_errors | Four upstream cases, exit 1, required diagnostic substring |

Mixed-field occupancy uses real lower-layer signing with the encrypted self-signed test key; this does not count as a CLI signing command. The current PdfUpdate loader reopens its input without preserving the complete ReaderOptions budget/auth/strictness contract. No field decode-limit function receives credit; L/P request remains pending.

Oracle evidence: 10 fresh pinned CLI calls:3 exact listing outputs,4 error status/message comparisons,3 generated-PDF field/revision checks. No trust-verdict claim.

No provider skips. Fresh native evidence: increment-fields-tests.log; current cumulative projection uses its own preserved Cargo-produced executable, not the full-source binary. Build/tests/clippy/fmt receipts record actual scheduler host/slot.
