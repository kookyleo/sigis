# Lead acceptance update

Accepted assigned counts: **252 total /163 passed /0 skipped /89 pending**.
Sourcef1cd5948 accepts exactly11new PKCS12/LTA originals/35parameters after
coherent final CLI/source/runtime and all-six-gate acceptance. The prior basic
PEM/P12 functions remain credited once. Configuration57/plugins11/crypt23/
fields7/stamps12/runtime-read1/ordinary39/basic2/P12-LTA11 comprise163.
See PKCS12_SIGNING_PORTING.md and docs/lanes/round3/l-cli-lta.md.
Other signing/LTV/qualified/provider/runtime/reader flows remain pending.
Historical owner projections below are not acceptance of the complete CLI.

# Historical independently verified CLI increments

Current projection: fields. Fixed assignment252; local proposal **252 / 98 passed / 0 skipped / 154 pending**. Accepted C remains252/0/0/252 until L review and gate. All original parameters/assertions remain in the scoped suites; supplemental wrappers add zero IDs.

The complete implementation and every deferred original assertion are preserved
at `4d8c8b7a92a949d5ba4f36581916d39f6fbe02a9` / `backup/r3-c-full-before-module-increments` and will be restored
after all four independently buildable commits. Deferred commands explicitly
reject. No unavailable command is counted as passed.

Current cumulative native run: 128 passed, zero failed/ignored. Evidence
`~/.codex/artifacts/sigis/round3/c/increment-fields-{build,tests,clippy,fmt}.log`
and corresponding scheduler receipts. Tests use the fresh Cargo artifact
`executable-increment-fields/pyhanko`, copied/hash-checked on both workers.
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
| `pyhanko-cli/test_cli_field_mgmt.py::test_list_empty_fields_with_status` | `fields::test_list_empty_fields_with_status` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_list_mixed_fields_with_status` | `fields::test_list_mixed_fields_with_status` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_list_empty_fields_without_status` | `fields::test_list_empty_fields_without_status` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_cli_add_field_incremental_update_by_default` | `fields::test_cli_add_field_incremental_update_by_default` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_cli_add_field_with_resave` | `fields::test_cli_add_field_with_resave` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_cli_add_field_to_last_page` | `fields::test_cli_add_field_to_last_page` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_cli_field_spec_errors` | `fields::test_cli_field_spec_errors` |
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

[Exact pinned parameter decorators and fixture arguments](INCREMENT_PARAMETERS.md).


## Scoped CLI prefix acceptance

Source 09ec130 passes all six workspace gates: 1706 discovered,
1698 passed, 8 ignored, zero failed, 150 reports.
Only the reviewed standalone prefix is integrated: configuration57, native
plugin registration/identity11, encryption/decryption23 (including two exact
decode-limit functions), and field management7. The98 immutable IDs and original
parameters are in crates/cli/INCREMENT_PARAMETERS.md and PORTING.md. Other154
CLI functions stay pending; later full-source restoration and its known runtime
or trust-result failures are not imported by this acceptance. No function was
ignored, removed from its inventory, or counted from an empty wrapper.

Three configuration loader functions previously had only raw-signature checks.
They now sign the independent SHA256 digest of Hello world! through the actual
production CMS builder and verify its unique SignerInfo with the loaded
certificate, expected data OID and original digest. Intact and valid must both
hold; a changed expected digest must fail integrity. The focused44 native
configuration tests pass. Four retained native CMS/certificate output cases
received eight fresh pinned Python integrity decisions with matching actual
input hashes. The fourth missing-passphrase function is not counted twice;
it already had complete original loading/refusal assertions. CMS integrity
does not establish certificate trust or CLI signing-command coverage.

The scoped CLI package has128 passed native tests, zero failures/ignores.
Cargo copied its actual ELF into an immutable artifact directory while holding
the build lock. Producer source 09ec130, ELF SHA256 ffc61fff25eacf12cd8f57b67fb6767e9729a6a7efaa5cffd36b22e064738c69,
88102784bytes. Same-path copies on both workers match SHA/version.
Explicit test-only Cargo env selectors chose that executable for every actual
CLI subprocess; its hash is unchanged before/after the full gate. Canonical
targets, compiler flags/profiles/features, sccache and automatic placement are
unchanged. Artifact copy uses the existing nightly Cargo artifact-dir facility.

The existing scoped tests freshly execute17 configuration oracle cases,
36 crypt CLI comparisons plus18 artifact checks, and10 field oracle calls.
The independent loader output comparison adds eight integrity decisions;
these are separate measurements, not new unique functions. Plugin reference
evidence is historical source execution; native11 tests exercise registry/help
and typed identity behavior, using native endpoint interfaces rather than
importing Python modules. They do not execute a signing engine. Field tests
use real lower-layer signing to check occupied fields; they do not establish
a trusted PDF signature. No runtime provider exclusion was added.

PKCS11 commands, other signing/stamping/runtime/validation/LTV functions,
complete reader-state callers and final CLI LTA integration remain pending.
Unsupported commands and mandatory requirements reject explicitly. Known
unmerged CLI trust failures and the retained combined-PKI registry discrepancy
still prevent any universal all-divergences-fail-closed claim. This is a scoped
98-function acceptance, not completion of the252-function CLI or full port.

Accepted C252/98/0/154; overall1431/1229/30/172. Detailed source/binary/fixture
hashes, independent assertion reviews, actual test selectors and full logs:
round3-launch/c-prefix-integration/ and round3-launch/c-prefix-review/.
