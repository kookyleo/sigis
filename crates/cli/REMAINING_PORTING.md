# Remaining CLI originals and historical batch results

## Current accepted inventory

After the historical CLI integration on source `5b24e817`, the [central ledger](../../docs/lanes/round3/acceptance.json)
and [status](../../docs/status.md) record CLI **252 total / 248 passed / 2 skipped /
2 pending**, and overall **1431 / 1421 / 8 / 2**. V's restored original adds no CLI
credit. The 34-original C batch and four subsequent provider originals remain
accepted once; parameters, helper controls and oracle calls add no functions.

| Original ID | Status | Operational owner / reason |
| --- | --- | --- |
| pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_signing_pin_prompt | Pending | P: incomplete SafeNet context-specific signing-PIN original |
| pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_env_signing_pin | Pending | P: incomplete SafeNet context-specific signing-PIN original |
| pyhanko-cli/test_cli_decode_limits.py::test_validate | Passed | Both validate/adesverify parameters retained; current-main full gate and original differential pass |
| pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_point_in_time_no_revinfo | Passed | Historical trusted/qualified API conclusion retained alongside raw NO_POE; full gate and original differential pass |
| pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_raw_ecdsa | Skipped | Genuine unchanged-upstream fixture exclusion: missing combined ECDSA_SHA256 mechanism |
| pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_raw_ecdsa | Skipped | Same genuine fixture exclusion |

The raw-ECDSA fixture's required_mechanism/require_mech marker mismatch causes all
original rows to skip. Successful supplemental raw-ECDSA signatures do not turn
either original into a pass. The two historical-validation originals now pass complete CLI bodies and original
differentials. The raw archival NO_POE/control-time failure remains explicit;
acceptance does not claim full-LTA success or generic expired-status recovery.

The accepted static configured/environment signing-PIN producer and five
AlwaysAuthenticate controls are supplemental coverage. They do not complete
either SafeNet CLI original or establish the missing hardware behavior. The S5
native-boundary supplement likewise does not promote S's five exclusions. No
original status changed in `8b393619`.

L alone runs the combined current-main workspace, clippy and formatting gate.
Lanes supply focused affected tests and applicable pinned pyHanko differentials.
Every Cargo invocation uses `tools/cargo-locked.sh`. Reference-fixture assistance
to P/S requires explicit file boundaries.

## Historical November15 batch record

The following scope and runtime results describe the earlier batch based on
`cc1f4fb3`, not new executions on `8b393619`. The old owner branch and frozen
candidates remain separate. Plain logs are under
`~/.codex/artifacts/sigis/round3/c/remaining-20261115/`. Pending-gap diagnoses below
are historical observations, not claims about current lower-layer behavior.

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

Historical pending-gap observation: native full-LTA required historical revocation proof absent from
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

Historical pending-gap observation: native full-LTA lacked historical control-time proof for the expired
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

## Historical verification

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
Root/signing harness adjustments were routed to their owners. At that checkpoint,
Cargo.lock's new existing-workspace sigis-eutl dependency edge was generated and
uncommitted; this is not a statement about the current worktree or merged lock.

Historical commands (not instructions to repeat the workspace gate in a lane;
normal pinned oracle paths were the test defaults):

```sh
tools/cargo-locked.sh test -p sigis-cli --test signing_remaining --test ltv --test decode_limits_signing --test qualified_validation --test eutl_validation --test pkcs12_requirements
tools/cargo-locked.sh clippy --workspace --all-targets -- -D warnings
tools/cargo-locked.sh fmt --all -- --check
```

## Integration history and latest gate

The C34 integration source `e2a0ef837a767e36fc3b9e63846f2f88ca168d4b`
historically passed the normal-wrapper workspace gate: 2283 passed / 0 failed /
6 ignored, with workspace all-target clippy-Dwarnings and fmt clean. Root fixed
the obsolete proof selectors and provider setup prerequisites. The two newly
ignored historical-validation originals remained Pending.

Accepted main `fb6cd010` subsequently passed the normal current-main workspace
gate: **2389 passed / 0 failed / 25 ignored**, across 248 reports; clippy and fmt
returned 0. Root's fresh pinned V original and the author's same-native-CMS peer
each passed. The initial E0460 attempt remains a failed attempt; the unchanged
source retry passed. These are L's reported integration results, not new lane
runs. Native ignore totals are not unique-original skip counts. No new skip or
helper credit was awarded, and the four CLI originals above remain Pending.

The latest combined gate, accepted as main `8b393619`, passed **2399 tests /
0 failed / 25 inherited ignored**, across 251 reports, with all-target clippy
and fmt returning 0. The new native targets passed 10/10; the existing
provider/USER-PIN focus reported 22 passed / 20 ignored. Root's five fresh S
originals passed and five PKI peers matched. These are L's reported results;
this documentation update does not rerun Cargo or award any original credit.

The historical CLI integration on source `5b24e817` passed **2414 tests /
0 failed / 23 inherited ignored**, across252 reports, plus workspace all-target
clippy and fmt. Root reran the unchanged pinned originals:3 parameter rows pass.
The author current-base focus passed24 tests including same-byte peers. Exactly
two C originals changed to Passed; CLI252/248/2/2 and overall1431/1421/8/2.
Earlier tables under the historical batch heading retain their original snapshot.
