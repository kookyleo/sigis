# Round 3 lane C: CLI and configuration

Session: `sigis-r3-c`. Branch: `hanko/r3-c`. Worktree: `/home/l/D/kooky/sigis-wt/r3-c`.
Baseline: main `34482bf`, pyHanko 0.38.1 / certvalidator 0.33.0.
Assigned unique functions: **252 total / 0 passed / 0 skipped / 252 pending**.
The exact full ownership set is every `functions[]` entry with `lane == "C"`
in [ownership.json](ownership.json): each entry has the package, module,
qualified function, pinned source line, crate and baseline status. This is
an exhaustive function list, not a glob or a count of Rust wrappers.

## Allowed paths and interfaces

Own `crates/cli/**` (package `sigis-cli`, L6, compatibility binary
`pyhanko`) and new fixtures under `crates/testdata/data/lanes/r3-c/**`.
L has registered the crate and layer before this branch was created.
You may replace the explicit-unimplemented entry point; do not touch the
HTTP service, root manifests, facade exports or other crates. Use existing
APIs directly through allowed lower-layer dependencies; request missing
exports or interfaces through L. P owns signing implementation, V validation
and S structural/PKI; consume their accepted interfaces after rebasing.

Port all 252 functions below, starting with configuration/runtime and field
management that can run now, then encryption, stamps, plugins, signing and
validation/LTV. Use mature CLI/config libraries and local HTTP/CSC/TSA
services. Preserve exit codes, messages and meaningful command output;
configuration-only coverage does not count signing command tests passed.
Add one documented Rust test mapping per unique upstream function. Keep
compatibility aliases/error text required by assertions, and explicitly
reject unsupported mandatory signing or validation requirements.

## Operating contract

Read `AGENTS.md` if present, `docs/status.md`, `docs/crates.md`, the owning
crate's `PORTING.md`, and `docs/lanes/round3/README.md`. This is an execution
task: continue implementing and checking owned work; do not stop after a
plan or a recording-only test. Work in the assigned worktree and branch.
Use the Codex backend. Communicate in Chinese; code, documents, reports and
commit messages are English. Never mention AI tool names in commit messages.
Local commits only: no push, service restart, `pkill`, other-session kills,
or changes to old `sigis-a..e` sessions. Do not restart `aoa.service` or
`sigis.service`. Keep all unrelated work and existing services intact.

**Port tests first.** Translate the exact upstream assertions and negative
cases before implementing missing behaviour. Preserve parameter coverage;
count each upstream function once, even if split into Rust wrappers.
Recorded Python outcomes/completeness checks alone do not establish a
passing Rust port. Use mature Rust crates and the existing lower-layer APIs.
Do not weaken tests or classify an unimplemented feature as a harmless skip.

The reference is pyHanko **0.38.1** + certvalidator **0.33.0**, interpreter
`/tmp/pyhanko-oracle/venv/bin/python`; set `HANKO_ORACLE` to that path.
Pinned source trees are `/tmp/pyhanko-oracle/src/v0.38.1` and
`/tmp/pyhanko-oracle/src/cv-0.33.0`. Differentially compare meaningful
status/output/error assertions with the oracle and distinguish fresh live
oracle comparisons from committed-fixture replay. For trust decisions,
unsupported mandatory requirements reject explicitly; no verdict may be
more trusting than the oracle. Keep adversarial rejection assertions.
Report semantic/encoding compatibility differences separately; do not
claim all differences universally fail closed.

**Every Cargo invocation uses `tools/cargo-locked.sh`, including metadata,
formatting and the gate.** It holds `$(git rev-parse --git-common-dir)/round3-cargo.lock`
with `flock` across all lanes and L, then evaluates `/usr/local/bin/rust-target-env`
in the caller's worktree. All lanes share its canonical `/build/sigis/target`;
never set another target, `RUST_TARGET_OWNER`, or `--target-dir`. The wrapper
uses two build jobs and one doc job, selects the existing local slot queue,
and consistently bypasses the broken sccache probe with empty `RUSTC_WRAPPER`.
It keeps the workspace compiler wrapper and Rust flags. Do not change
`RUSTFLAGS`, `CARGO_INCREMENTAL`, profiles or feature combinations for speed.
Do not run raw Cargo, remote Cargo, `cargo clean`, or a background build.
Do not hold this lock while editing or waiting for another lane. Start with:

```sh
tools/cargo-locked.sh check -p PACKAGE
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test -p PACKAGE --test SUITE
```

The wrapper supplies job flags; do not add `-j`. Restrict checks/tests to
changed packages and affected callers. L owns the full workspace gate on
each integration. Cargo metadata spawned internally by the layer test is
already covered by the parent lock and must not re-enter the wrapper.

Root `Cargo.toml`, `Cargo.lock`, `tools/`, facades, `docs/status.md`, the
ownership manifest and other lanes' briefs are L-owned. Crate-local
manifests may use existing shared dependencies or pinned mature crates;
report new dependencies to L. A local Cargo.lock regeneration is allowed
under the wrapper, but leave it out of lane commits; L regenerates the
merged lockfile. Shared type/API changes outside the allowed paths go
through a concrete request in the lane report; do not edit the other lane.
Never relax `tools/layers.json`. Dev-dependency integration checks are
allowed if acyclic; production dependencies obey `docs/crates.md`.

## Checkpoints and handoff

Write `docs/lanes/round3/c-report.md` early and keep it current. Commit
only owned files in coherent English local commits. Preserve detailed logs
under `~/.codex/artifacts/sigis/round3/c/` and include reproducible commands.
For every owned crate report `total / passed / skipped / pending` in unique
upstream functions (the sum must match the fixed assigned total), then list
changed function IDs -> Rust test names, parameters exercised and runtime
provider skips. List oracle cases/calls and verdict agreements separately
from function counts. Review inherited partial assertions honestly; report
any downgrade with evidence instead of preserving an inflated pass count.
Include divergences, exact dependency requests, commit heads and cleanliness.

For requests and a ready milestone, write the report first, then notify
only the lead with `aoa send - -s sigis-cx < docs/lanes/round3/c-report.md`.
The lead is responsible for integration; do not merge into main or rewrite
another worktree. Continue independent owned work while an interface request
is pending. On readiness, ensure owned files are committed, report any
uncommitted generated lockfile, and wait for lead rebase/acceptance feedback.

## Exact pending upstream functions

- `pyhanko-cli/test_cli_crypt.py::test_encrypt_file`
- `pyhanko-cli/test_cli_crypt.py::test_encrypt_file_with_stdin_pass`
- `pyhanko-cli/test_cli_crypt.py::test_encrypt_file_with_recipient_cert`
- `pyhanko-cli/test_cli_crypt.py::test_encrypt_not_both_pubkey_and_password`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_owner_password`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_owner_password_on_stdin`
- `pyhanko-cli/test_cli_crypt.py::test_force_decrypt_with_user_password`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_user_password_no_force`
- `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_unencrypted_file`
- `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_wrong_sh_type`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_wrong_password`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_wrong_key`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_no_force_change_of_encryption_forbidden`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_force_change_of_encryption_forbidden`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_and_passfile`
- `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_with_private_key_unencrypted_file`
- `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_with_private_key_sh_type_mismatch`
- `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_with_non_matching_key`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_no_pass`
- `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_empty_pass_on_stdin`
- `pyhanko-cli/test_cli_decode_limits.py::test_simple_commands`
- `pyhanko-cli/test_cli_decode_limits.py::test_text_stamp`
- `pyhanko-cli/test_cli_decode_limits.py::test_qr_stamp`
- `pyhanko-cli/test_cli_decode_limits.py::test_decrypt_password`
- `pyhanko-cli/test_cli_decode_limits.py::test_decrypt_pubkey`
- `pyhanko-cli/test_cli_decode_limits.py::test_addsig`
- `pyhanko-cli/test_cli_decode_limits.py::test_timestamp`
- `pyhanko-cli/test_cli_decode_limits.py::test_validate`
- `pyhanko-cli/test_cli_decode_limits.py::test_ltaupdate`
- `pyhanko-cli/test_cli_decode_limits.py::test_ltvfix`
- `pyhanko-cli/test_cli_field_mgmt.py::test_list_empty_fields_with_status`
- `pyhanko-cli/test_cli_field_mgmt.py::test_list_mixed_fields_with_status`
- `pyhanko-cli/test_cli_field_mgmt.py::test_list_empty_fields_without_status`
- `pyhanko-cli/test_cli_field_mgmt.py::test_cli_add_field_incremental_update_by_default`
- `pyhanko-cli/test_cli_field_mgmt.py::test_cli_add_field_with_resave`
- `pyhanko-cli/test_cli_field_mgmt.py::test_cli_add_field_to_last_page`
- `pyhanko-cli/test_cli_field_mgmt.py::test_cli_field_spec_errors`
- `pyhanko-cli/test_cli_ltv.py::test_cli_lta_update`
- `pyhanko-cli/test_cli_ltv.py::test_cli_ltvfix`
- `pyhanko-cli/test_cli_ltv.py::test_cli_ltvfix_require_signed_field`
- `pyhanko-cli/test_cli_plugins.py::test_load_plugins_from_config`
- `pyhanko-cli/test_cli_plugins.py::test_gracefully_handle_dupe_plugins`
- `pyhanko-cli/test_cli_plugins.py::test_plugin_must_be_class`
- `pyhanko-cli/test_cli_plugins.py::test_disable_non_default_plugins`
- `pyhanko-cli/test_cli_plugins.py::test_show_unavailable_plugins`
- `pyhanko-cli/test_cli_plugins.py::test_trigger_unavailable_plugin`
- `pyhanko-cli/test_cli_plugins.py::test_identity_setup_with_too_few_parameters`
- `pyhanko-cli/test_cli_plugins.py::test_identity_setup_with_unknown_parameters`
- `pyhanko-cli/test_cli_plugins.py::test_identity_setup_with_unknown_plugin`
- `pyhanko-cli/test_cli_plugins.py::test_unknown_identity`
- `pyhanko-cli/test_cli_plugins.py::test_identity_without_config`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_without_nopass`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_with_setup`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_with_identity_setup`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_with_wrong_key_usage`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_with_wrong_extd_key_usage`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_with_setup_in_custom_config_file`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_with_identity_programmatically`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_with_setup_encrypted_key`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_setup_requires_config`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_some_args_required`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_setup_does_not_exist`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_with_unreadable_additional_certs`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_detached`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_detached_no_field_arg`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_unencrypted_p12`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_unencrypted_p12_without_nopass`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_with_setup`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_setup_requires_config`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_setup_unreadable`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_setup_corrupted_keystore`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_setup_or_pfx_argument_required`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_p12_passfile`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_getpass`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_pkcs12_visible_while_creating_field`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_no_style`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_style`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_qr_style`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_qr_style_omit_stamp_url`
- `pyhanko-cli/test_cli_signing.py::test_cli_add_field_then_sign`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_implied_field`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_field_param_required`
- `pyhanko-cli/test_cli_signing.py::test_cli_pades_lta`
- `pyhanko-cli/test_cli_signing.py::test_cli_pades_lta_nonstrict`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_pemder_encrypted_file`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_no_pubkey_encryption`
- `pyhanko-cli/test_cli_signing.py::test_cli_addsig_wrong_password`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_custom_default_style`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_default_style_and_others_in_config`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_undefined_default_style`
- `pyhanko-cli/test_cli_signing.py::test_cli_sign_visible_with_style_but_no_config`
- `pyhanko-cli/test_cli_signing.py::test_cli_new_field_spec_bars_existing_only`
- `pyhanko-cli/test_cli_signing.py::test_cli_underspecified_visible_new_field`
- `pyhanko-cli/test_cli_signing.py::test_cli_underspecified_visible_new_field_no_name`
- `pyhanko-cli/test_cli_signing.py::test_cli_explicit_style_but_field_invisible`
- `pyhanko-cli/test_cli_signing.py::test_cli_pades_lta_no_timestamp_url`
- `pyhanko-cli/test_cli_signing.py::test_fail_strict_hybrid`
- `pyhanko-cli/test_cli_signing.py::test_succeed_non_strict_hybrid`
- `pyhanko-cli/test_cli_signing.py::test_cli_with_signature_dictionary_entries`
- `pyhanko-cli/test_cli_signing.py::test_cli_timestamp`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_pkcs11_args_required`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_pkcs11_setup_requires_config`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_pkcs11_setup_config_unreadable`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_pull_interm`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_read_interm_from_file`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_raw_ecdsa`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_pull_certs`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_read_certs_from_file`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_raw_ecdsa`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_signing_pin_prompt`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_env_pin`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_env_signing_pin`
- `pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_pin_prompt`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_with_style`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_with_qr_style`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_no_config`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_stamp_url_unnecessary`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_stamp_url_mandatory`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_undefined`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_text_param_missing`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_text_param_formatting_wrong`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_text_param_multiple_substitution`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_text_param_fail_partial_substitution`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_unspecified`
- `pyhanko-cli/test_cli_stamp.py::test_cli_stamp_style_malformed`
- `pyhanko-cli/test_config.py::test_read_vc_kwargs`
- `pyhanko-cli/test_config.py::test_os_trust_fallback_warning`
- `pyhanko-cli/test_config.py::test_no_os_trust_fallback_warning_with_trust_replace`
- `pyhanko-cli/test_config.py::test_read_qr_config`
- `pyhanko-cli/test_config.py::test_read_bad_config`
- `pyhanko-cli/test_config.py::test_read_bad_background_config`
- `pyhanko-cli/test_config.py::test_read_bad_config2`
- `pyhanko-cli/test_config.py::test_empty_config`
- `pyhanko-cli/test_config.py::test_read_logging_config`
- `pyhanko-cli/test_config.py::test_read_logging_config_defaults`
- `pyhanko-cli/test_config.py::test_read_logging_config_errors`
- `pyhanko-cli/test_config.py::test_read_key_usage`
- `pyhanko-cli/test_config.py::test_read_extd_key_usage`
- `pyhanko-cli/test_config.py::test_read_key_usage_policy_1`
- `pyhanko-cli/test_config.py::test_read_key_usage_policy_2`
- `pyhanko-cli/test_config.py::test_read_key_usage_policy_3`
- `pyhanko-cli/test_config.py::test_extd_key_usage_errors`
- `pyhanko-cli/test_config.py::test_key_usage_errors`
- `pyhanko-cli/test_config.py::test_read_time_tolerance`
- `pyhanko-cli/test_config.py::test_read_time_tolerance_input_issues`
- `pyhanko-cli/test_config.py::test_read_retroactive_revinfo`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_legacy`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_legacy_with_extra_criteria`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_slot_no`
- `pyhanko-cli/test_config.py::test_read_pkcs11_nothing_to_pull`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_ids`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_external_cert`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_bad_criteria_type`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_bad_serial`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_no_cert_spec_or_key_spec`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_cert_label_from_key_label`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_cert_id_from_key_id`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_id_from_cert_id`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_label_from_cert_label`
- `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_label_not_from_cert_label_if_key_id_defined`
- `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin`
- `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin_default`
- `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin_invalid`
- `pyhanko-cli/test_config.py::test_read_pkcs11_signing_pin_mode`
- `pyhanko-cli/test_config.py::test_read_pkcs11_signing_pin_invalid`
- `pyhanko-cli/test_config.py::test_read_pkcs12_config`
- `pyhanko-cli/test_config.py::test_read_pkcs12_config_null_pw`
- `pyhanko-cli/test_config.py::test_read_pemder_config`
- `pyhanko-cli/test_config.py::test_read_pemder_config_wrong_passphrase`
- `pyhanko-cli/test_config.py::test_read_pemder_config_missing_passphrase`
- `pyhanko-cli/test_config.py::test_read_pkcs12_config_wrong_passphrase`
- `pyhanko-cli/test_config.py::test_read_simple_layout_config`
- `pyhanko-cli/test_config.py::test_read_simple_layout_config_failures`
- `pyhanko-cli/test_config.py::test_configurable_recurse`
- `pyhanko-cli/test_config.py::test_enforce_required`
- `pyhanko-cli/test_config.py::test_enforce_required_recursive`
- `pyhanko-cli/test_config.py::test_configurable_recurse_optional_styles`
- `pyhanko-cli/test_config.py::test_default_stamp_style_fetch`
- `pyhanko-cli/test_config.py::test_cache_dir_config`
- `pyhanko-cli/test_config.py::test_fail_to_read_default_config`
- `pyhanko-cli/test_config.py::test_fail_to_read_nondefault_config`
- `pyhanko-cli/test_runtime.py::test_fail_read`
- `pyhanko-cli/test_runtime.py::test_fail_strict_mildly_broken`
- `pyhanko-cli/test_runtime.py::test_succeed_strict_mildly_broken_nonstrict`
- `pyhanko-cli/test_runtime.py::test_log_stdout`
- `pyhanko-cli/test_runtime.py::test_log_stderr_default`
- `pyhanko-cli/test_runtime.py::test_log_file`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_bogus_tl`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_bogus_lotl`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_with_extra_roots_ca_is_extra`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_with_extra_roots_ca_on_tl`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_config_eutl_limited_territories`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_config_limited_territories_not_included`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_config_empty_territories`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_config_limited_territories_overridden_in_cli`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_arg_eutl_limited_territories`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_territories_arg_empty`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_inconsistent_eutl_args`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_arg_limited_territories_not_included`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_force_attempt_eutl_download`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_qual_required`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_not_qualified`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_not_qualified_summary`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_qualified_summary`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_not_qualified_required`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_tsa_not_qualified`
- `pyhanko-cli/validation/test_cli_qualified_validation.py::test_validate_eutl_ades_point_in_time_no_revinfo`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_fail_without_revinfo`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_with_soft_revocation`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_with_required_revinfo`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_fail_without_required_revinfo`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_without_revinfo_check`
- `pyhanko-cli/validation/test_cli_validation.py::test_inconsistent_revo_settings`
- `pyhanko-cli/validation/test_cli_validation.py::test_validate_encrypted_wrong_password`
- `pyhanko-cli/validation/test_cli_validation.py::test_validate_encrypted_empty_user_password`
- `pyhanko-cli/validation/test_cli_validation.py::test_validate_encrypted_empty_user_password_wrong_explicit_password`
- `pyhanko-cli/validation/test_cli_validation.py::test_validate_encrypted_explicit_empty_password`
- `pyhanko-cli/validation/test_cli_validation.py::test_validate_encrypted_wrong_explicit_empty_password`
- `pyhanko-cli/validation/test_cli_validation.py::test_validate_unsupported_handler`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_summary`
- `pyhanko-cli/validation/test_cli_validation.py::test_validate_inconsistent_print_settings`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_pretty_print`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_with_validation_time`
- `pyhanko-cli/validation/test_cli_validation.py::test_validation_time_syntax_error`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_with_claimed_time`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_untrusted`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_with_weak_hash`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_with_unknown_hash`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_signed_with_wrong_key`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_with_default_context`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_with_system_trust`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_with_explicit_context`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_lacking_intermediate`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_lacking_intermediate_with_trust_arg`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_context_config_wrong`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_context_config_nonsensical_other_certs`
- `pyhanko-cli/validation/test_cli_validation.py::test_trust_replace_arg_applies_to_config_context`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_context_without_config_file`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_context_incompatible_args`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_context_file_not_found`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_validate_context_malformed_cert`
- `pyhanko-cli/validation/test_cli_validation.py::test_basic_detached_validate`
- `pyhanko-cli/validation/test_cli_validation.py::test_fail_detached_validate`
- `pyhanko-cli/validation/test_cli_validation.py::test_detached_validate_malformed_input`
- `pyhanko-cli/validation/test_cli_validation.py::test_detached_validate_bad_cms_type`

## Baseline by assigned crate

| Crate | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `sigis-cli` | 252 | 0 | 0 | 252 |
