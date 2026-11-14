# Remaining CLI batches, November15 continuation

Base main: cc1f4fb3. The old owner branch and frozen candidates remain separate.
The coordinator's simplified gate replaces provenance/capture/review pipelines.
All Cargo uses tools/cargo-locked.sh; logs are plain text under
`~/.codex/artifacts/sigis/round3/c/remaining-20261115/`.

The 34 completed originals in this batch are accepted after the simple current-main gate. The two ignored historical-validation implementation gaps remain Pending, not Skipped. Current CLI inventory is252/246/2/4: two context-specific signing-PIN originals remain with P and the two historical-validation cases with S/V; two genuine raw-ECDSA fixture exclusions are skipped. Executed original parameter rows pass the pinned Python reference; helper tests and parameters add no IDs.

## Batch1: field/hybrid/dictionary signing, seven originals /16 rows

Source: pyhanko-cli/test_cli_signing.py. Rust: tests/signing_remaining.rs.
Every positive output receives native full PDF/CMS/trust/diff validation and a
fresh same-byte Python validation; empty roots refuse. Injected2020 runtime is
the original fixture adaptation, not a product clock override.

| Original function and same Rust test name | Parameters |
| --- | --- |
| test_cli_sign_pkcs12_visible_while_creating_field | RSA/ECDSA/Ed25519/Ed448 |
| test_cli_add_field_then_sign | RSA/ECDSA/Ed25519/Ed448 |
| test_cli_sign_implied_field | RSA/ECDSA/Ed25519/Ed448 |
| test_cli_sign_field_param_required | fixed RSA |
| test_fail_strict_hybrid | fixed RSA |
| test_succeed_non_strict_hybrid | fixed RSA |
| test_cli_with_signature_dictionary_entries | fixed RSA |

## Batch2: LTV and signed-PDF decode limits, seven originals /16 rows

Current-time signer1-long/TSA services explicitly adapt the original frozen PKI.
Native top-level execution mirrors CliRunner, preserving real NOW and continuing
reader/authentication/strictness/decode state. DSS/timestamp updates complete
before replacing the input. Same-output Python verifies actual signatures and
empty-root denial; unchanged original bodies supply the separate reference.

| Original ID | Rust target::test | Parameters / status |
| --- | --- | --- |
| pyhanko-cli/test_cli_ltv.py::test_cli_lta_update | ltv::test_cli_lta_update |3algorithms, pass|
| pyhanko-cli/test_cli_ltv.py::test_cli_ltvfix | ltv::test_cli_ltvfix |3algorithms × timestamp bool, pass|
| pyhanko-cli/test_cli_ltv.py::test_cli_ltvfix_require_signed_field | ltv::test_cli_ltvfix_require_signed_field | fixed RSA, pass|
| pyhanko-cli/test_cli_decode_limits.py::test_ltaupdate | ltv::test_ltaupdate | default/trusted flag pair, pass|
| pyhanko-cli/test_cli_decode_limits.py::test_ltvfix | ltv::test_ltvfix | default/trusted flag pair, pass|
| pyhanko-cli/test_cli_decode_limits.py::test_addsig | decode_limits_signing::test_addsig | PAdES/PAdES-LTA, pass|
| pyhanko-cli/test_cli_decode_limits.py::test_validate | decode_limits_signing::test_validate | validate/adesverify, Pending (native test ignored)|

Pending implementation gap: native full-LTA requires historical revocation proof absent from
the upstream B-T API-only acceptance case. Both original parameter bodies remain;
a separate ordinary_validate_decode_control exercises the supported parameter
without awarding partial original-function credit.

## Batch3: qualified AdES, eight originals /11 rows

Source: pyhanko-cli/validation/test_cli_qualified_validation.py.
Rust: tests/qualified_validation.rs, identical original function names.
Uses authentic signed lists, whole queried-DER registries, service role/window
checks and real full-LTA results. Required signer/default and independent TSA
Uri(QTST) remain separate; optional requirements both remainNone. Normal AdES
uses the same full-LTA API with no registry, never a Basic fallback. Nondefault
mandatory MAIN settings reject explicitly. All original clocks are recorded in
fixture moment.txt; product execution remains NOW. Same-byte Python peers retain
the genuine original PKI retrieval fixture; acquisition traces are not identical.

| Original function | Parameters / status |
| --- | --- |
| test_validate_eutl_ades | overloaded_trust × pades_style,4rows, pass|
| test_validate_eutl_ades_qual_required |1row, pass|
| test_validate_eutl_ades_not_qualified |1row, pass|
| test_validate_eutl_ades_not_qualified_summary |1row, pass|
| test_validate_eutl_ades_qualified_summary |1row, pass|
| test_validate_eutl_ades_not_qualified_required |1row, pass; genuine positive contrasts run first|
| test_validate_eutl_ades_tsa_not_qualified |1row, pass|
| test_validate_eutl_ades_point_in_time_no_revinfo |1row, Pending (native test ignored)|

Pending implementation gap: native full-LTA lacks historical control-time proof for the expired
2025leaf, whereas the original CLI accepts its API status projection. The native
NO_POE verdict is preserved; no whitelist, invented POE or clock waiver is used.

## Batch4: ordinary EUTL, fourteen originals /51 rows

Source: pyhanko-cli/validation/test_cli_qualified_validation.py.
Rust: tests/eutl_validation.rs, identical function names. Complete regular/
encrypted, extra-root and territory parameters remain. Contexts are built once
with original effective policy, timing, usage and fetchers; no OS-root fallback
or getter-based context reconstruction. All14 pass focused native execution and
all51 unchanged source parameters pass the pinned Python reference.

| Original function | Rows |
| --- | ---: |
| test_validate_eutl |2|
| test_validate_eutl_bogus_tl |2|
| test_validate_eutl_bogus_lotl |2|
| test_validate_eutl_with_extra_roots_ca_is_extra |1|
| test_validate_eutl_with_extra_roots_ca_on_tl |2|
| test_validate_config_eutl_limited_territories |8|
| test_validate_eutl_config_limited_territories_not_included |6|
| test_validate_eutl_config_empty_territories |6|
| test_validate_eutl_config_limited_territories_overridden_in_cli |10|
| test_validate_arg_eutl_limited_territories |4|
| test_validate_territories_arg_empty |1|
| test_validate_inconsistent_eutl_args |1|
| test_validate_eutl_arg_limited_territories_not_included |4|
| test_force_attempt_eutl_download |2|

No original is credited for a supplemental wrapper, oracle call or constructor
premise. Cold transport/TLS details, general ambiguous service histories and the
two archival display differences are not universal compatibility claims.

## Verification

The combined new-target run passed35 native tests with2 explicit ignores; the
extra ordinary-only decode control adds no upstream ID. Pinned original Python parameter checks passed. Workspace all-target Clippy with-Dwarnings and
formatting passed. The simplified CLI preflight and real EnvPIN targets also
passed all8 retained native tests, including actual token signing on all five
fixture labels; these previously accepted IDs add no new credit.

The first full `tools/cargo-locked.sh test --workspace --no-fail-fast` completed
on vm2065/slot0 with2244passed/16failed/6ignored across233 summaries. Failures
were old mandatory evidence/immutable-executable selectors in four Root targets
and two CLI targets, plus two signing targets requiring a configured SoftHSM
path or persistent proof directory. This is a failed workspace gate, not a
successful porting claim. The CLI helper migration removes obsolete proof
requirements while retaining actual token, frontend and signed-PDF checks.
Root/signing harness adjustments are routed to their owners. Cargo.lock's one
new existing-workspace sigis-eutl dependency edge is generated and uncommitted.

Reproducible focused command (normal pinned oracle paths are the test defaults):

```sh
tools/cargo-locked.sh test -p sigis-cli --test signing_remaining --test ltv --test decode_limits_signing --test qualified_validation --test eutl_validation --test pkcs12_requirements
tools/cargo-locked.sh clippy --workspace --all-targets -- -D warnings
tools/cargo-locked.sh fmt --all -- --check
```

## Accepted integration

Current-main source `e2a0ef837a767e36fc3b9e63846f2f88ca168d4b` passed the normal-wrapper workspace gate:2283passed/0failed/6ignored. Workspace all-target clippy-Dwarnings and fmt check passed. The two newly ignored tests are still Pending originals. Root fixed the obsolete proof selectors and provider setup prerequisites; no immutable ELF, source provenance pipeline or independent final review was required.
