# Independently verified CLI increments

Current projection: crypt. Fixed assignment252; local proposal **252 / 91 passed / 0 skipped / 161 pending**. Accepted C remains252/0/0/252 until L review and gate. All original parameters/assertions remain in the scoped suites; supplemental wrappers add zero IDs.

The complete implementation and every deferred original assertion are preserved
at `4d8c8b7a92a949d5ba4f36581916d39f6fbe02a9` / `backup/r3-c-full-before-module-increments` and will be restored
after all four independently buildable commits. Deferred commands explicitly
reject. No unavailable command is counted as passed.

Current cumulative native run: 121 passed, zero failed/ignored. Evidence
`~/.codex/artifacts/sigis/round3/c/increment-crypt-{build,tests,clippy,fmt}.log`
and corresponding scheduler receipts. Tests use the fresh Cargo artifact
`executable-increment-crypt/pyhanko`, copied/hash-checked on both workers.
Build, all-target tests, strict all-target clippy and formatting passed through
the normal wrapper. No compiler/cache/placement override, raw Cargo or job cap.

Module documents list exact parameter coverage and separate oracle calls.
No provider skips occurred. Full-source historical proposal237/0/15 is separate
from this projection. Compatibility limitations do not imply universal
fail-closed behavior. Root Cargo.lock is generated and excluded from commits.

| Exact upstream ID | Rust test |
| --- | --- |
| `pyhanko-cli/test_cli_crypt.py::test_encrypt_file` | `crypt::test_encrypt_file` |
| `pyhanko-cli/test_cli_crypt.py::test_encrypt_file_with_stdin_pass` | `crypt::test_encrypt_file_with_stdin_pass` |
| `pyhanko-cli/test_cli_crypt.py::test_encrypt_file_with_recipient_cert` | `crypt::test_encrypt_file_with_recipient_cert` |
| `pyhanko-cli/test_cli_crypt.py::test_encrypt_not_both_pubkey_and_password` | `crypt::test_encrypt_not_both_pubkey_and_password` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_owner_password` | `crypt::test_decrypt_with_owner_password` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_owner_password_on_stdin` | `crypt::test_decrypt_with_owner_password_on_stdin` |
| `pyhanko-cli/test_cli_crypt.py::test_force_decrypt_with_user_password` | `crypt::test_force_decrypt_with_user_password` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_user_password_no_force` | `crypt::test_decrypt_with_user_password_no_force` |
| `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_unencrypted_file` | `crypt::test_attempt_decrypt_unencrypted_file` |
| `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_wrong_sh_type` | `crypt::test_attempt_decrypt_wrong_sh_type` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_wrong_password` | `crypt::test_decrypt_with_wrong_password` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key` | `crypt::test_decrypt_with_private_key` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_wrong_key` | `crypt::test_decrypt_with_wrong_key` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_no_force_change_of_encryption_forbidden` | `crypt::test_decrypt_with_private_key_no_force_change_of_encryption_forbidden` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_force_change_of_encryption_forbidden` | `crypt::test_decrypt_with_private_key_force_change_of_encryption_forbidden` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_and_passfile` | `crypt::test_decrypt_with_private_key_and_passfile` |
| `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_with_private_key_unencrypted_file` | `crypt::test_attempt_decrypt_with_private_key_unencrypted_file` |
| `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_with_private_key_sh_type_mismatch` | `crypt::test_attempt_decrypt_with_private_key_sh_type_mismatch` |
| `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_with_non_matching_key` | `crypt::test_attempt_decrypt_with_non_matching_key` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_no_pass` | `crypt::test_decrypt_with_private_key_no_pass` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_empty_pass_on_stdin` | `crypt::test_decrypt_with_private_key_empty_pass_on_stdin` |
| `pyhanko-cli/test_cli_decode_limits.py::test_decrypt_password` | `crypt::test_decrypt_password` |
| `pyhanko-cli/test_cli_decode_limits.py::test_decrypt_pubkey` | `crypt::test_decrypt_pubkey` |
| `pyhanko-cli/test_cli_plugins.py::test_load_plugins_from_config` | `plugins::test_load_plugins_from_config` |
| `pyhanko-cli/test_cli_plugins.py::test_gracefully_handle_dupe_plugins` | `plugins::test_gracefully_handle_dupe_plugins` |
| `pyhanko-cli/test_cli_plugins.py::test_plugin_must_be_class` | `plugins::test_plugin_must_be_class` |
| `pyhanko-cli/test_cli_plugins.py::test_disable_non_default_plugins` | `plugins::test_disable_non_default_plugins` |
| `pyhanko-cli/test_cli_plugins.py::test_show_unavailable_plugins` | `plugins::test_show_unavailable_plugins` |
| `pyhanko-cli/test_cli_plugins.py::test_trigger_unavailable_plugin` | `plugins::test_trigger_unavailable_plugin` |
| `pyhanko-cli/test_cli_plugins.py::test_identity_setup_with_too_few_parameters` | `plugins::test_identity_setup_with_too_few_parameters` |
| `pyhanko-cli/test_cli_plugins.py::test_identity_setup_with_unknown_parameters` | `plugins::test_identity_setup_with_unknown_parameters` |
| `pyhanko-cli/test_cli_plugins.py::test_identity_setup_with_unknown_plugin` | `plugins::test_identity_setup_with_unknown_plugin` |
| `pyhanko-cli/test_cli_plugins.py::test_unknown_identity` | `plugins::test_unknown_identity` |
| `pyhanko-cli/test_cli_plugins.py::test_identity_without_config` | `plugins::test_identity_without_config` |
| `pyhanko-cli/test_config.py::test_read_vc_kwargs` | `config::test_read_vc_kwargs` |
| `pyhanko-cli/test_config.py::test_os_trust_fallback_warning` | `config::test_os_trust_fallback_warning` |
| `pyhanko-cli/test_config.py::test_no_os_trust_fallback_warning_with_trust_replace` | `config::test_no_os_trust_fallback_warning_with_trust_replace` |
| `pyhanko-cli/test_config.py::test_read_qr_config` | `config::test_read_qr_config` |
| `pyhanko-cli/test_config.py::test_read_bad_config` | `config::test_read_bad_config` |
| `pyhanko-cli/test_config.py::test_read_bad_background_config` | `config::test_read_bad_background_config` |
| `pyhanko-cli/test_config.py::test_read_bad_config2` | `config::test_read_bad_config2` |
| `pyhanko-cli/test_config.py::test_empty_config` | `config::test_empty_config` |
| `pyhanko-cli/test_config.py::test_read_logging_config` | `config::test_read_logging_config` |
| `pyhanko-cli/test_config.py::test_read_logging_config_defaults` | `config::test_read_logging_config_defaults` |
| `pyhanko-cli/test_config.py::test_read_logging_config_errors` | `config::test_read_logging_config_errors` |
| `pyhanko-cli/test_config.py::test_read_key_usage` | `config::test_read_key_usage` |
| `pyhanko-cli/test_config.py::test_read_extd_key_usage` | `config::test_read_extd_key_usage` |
| `pyhanko-cli/test_config.py::test_read_key_usage_policy_1` | `config::test_read_key_usage_policy_1` |
| `pyhanko-cli/test_config.py::test_read_key_usage_policy_2` | `config::test_read_key_usage_policy_2` |
| `pyhanko-cli/test_config.py::test_read_key_usage_policy_3` | `config::test_read_key_usage_policy_3` |
| `pyhanko-cli/test_config.py::test_extd_key_usage_errors` | `config::test_extd_key_usage_errors` |
| `pyhanko-cli/test_config.py::test_key_usage_errors` | `config::test_key_usage_errors` |
| `pyhanko-cli/test_config.py::test_read_time_tolerance` | `config::test_read_time_tolerance` |
| `pyhanko-cli/test_config.py::test_read_time_tolerance_input_issues` | `config::test_read_time_tolerance_input_issues` |
| `pyhanko-cli/test_config.py::test_read_retroactive_revinfo` | `config::test_read_retroactive_revinfo` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config` | `config::test_read_pkcs11_config` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_legacy` | `config::test_read_pkcs11_config_legacy` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_legacy_with_extra_criteria` | `config::test_read_pkcs11_config_legacy_with_extra_criteria` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_slot_no` | `config::test_read_pkcs11_config_slot_no` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_nothing_to_pull` | `config::test_read_pkcs11_nothing_to_pull` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_ids` | `config::test_read_pkcs11_config_ids` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_external_cert` | `config::test_read_pkcs11_config_external_cert` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_bad_criteria_type` | `config::test_read_pkcs11_config_bad_criteria_type` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_bad_serial` | `config::test_read_pkcs11_config_bad_serial` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_no_cert_spec_or_key_spec` | `config::test_read_pkcs11_config_no_cert_spec_or_key_spec` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_cert_label_from_key_label` | `config::test_read_pkcs11_config_cert_label_from_key_label` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_cert_id_from_key_id` | `config::test_read_pkcs11_config_cert_id_from_key_id` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_id_from_cert_id` | `config::test_read_pkcs11_config_key_id_from_cert_id` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_label_from_cert_label` | `config::test_read_pkcs11_config_key_label_from_cert_label` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_label_not_from_cert_label_if_key_id_defined` | `config::test_read_pkcs11_config_key_label_not_from_cert_label_if_key_id_defined` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin` | `config::test_read_pkcs11_prompt_pin` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin_default` | `config::test_read_pkcs11_prompt_pin_default` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin_invalid` | `config::test_read_pkcs11_prompt_pin_invalid` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_signing_pin_mode` | `config::test_read_pkcs11_signing_pin_mode` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_signing_pin_invalid` | `config::test_read_pkcs11_signing_pin_invalid` |
| `pyhanko-cli/test_config.py::test_read_pkcs12_config` | `config::test_read_pkcs12_config` |
| `pyhanko-cli/test_config.py::test_read_pkcs12_config_null_pw` | `config::test_read_pkcs12_config_null_pw` |
| `pyhanko-cli/test_config.py::test_read_pemder_config` | `config::test_read_pemder_config` |
| `pyhanko-cli/test_config.py::test_read_pemder_config_wrong_passphrase` | `config::test_read_pemder_config_wrong_passphrase` |
| `pyhanko-cli/test_config.py::test_read_pemder_config_missing_passphrase` | `config::test_read_pemder_config_missing_passphrase` |
| `pyhanko-cli/test_config.py::test_read_pkcs12_config_wrong_passphrase` | `config::test_read_pkcs12_config_wrong_passphrase` |
| `pyhanko-cli/test_config.py::test_read_simple_layout_config` | `config::test_read_simple_layout_config` |
| `pyhanko-cli/test_config.py::test_read_simple_layout_config_failures` | `config::test_read_simple_layout_config_failures` |
| `pyhanko-cli/test_config.py::test_configurable_recurse` | `config::test_configurable_recurse` |
| `pyhanko-cli/test_config.py::test_enforce_required` | `config::test_enforce_required` |
| `pyhanko-cli/test_config.py::test_enforce_required_recursive` | `config::test_enforce_required_recursive` |
| `pyhanko-cli/test_config.py::test_configurable_recurse_optional_styles` | `config::test_configurable_recurse_optional_styles` |
| `pyhanko-cli/test_config.py::test_default_stamp_style_fetch` | `config::test_default_stamp_style_fetch` |
| `pyhanko-cli/test_config.py::test_cache_dir_config` | `config::test_cache_dir_config` |
| `pyhanko-cli/test_config.py::test_fail_to_read_default_config` | `config::test_fail_to_read_default_config` |
| `pyhanko-cli/test_config.py::test_fail_to_read_nondefault_config` | `config::test_fail_to_read_nondefault_config` |
