# Config independent port

Scope: configuration schema, certificate/key loading, logging, styles and strict YAML semantics. Original tests were translated before implementation.
Unique functions: 57 total / 57 locally passed /0 skipped/0 pending. Accepted counts require L gate.

## Exact function mapping

| Upstream ID | Rust test | Source parameter cases |
| --- | --- | ---: |
| `pyhanko-cli/test_config.py::test_read_vc_kwargs` | `config::test_read_vc_kwargs` | 2 |
| `pyhanko-cli/test_config.py::test_os_trust_fallback_warning` | `config::test_os_trust_fallback_warning` | 2 |
| `pyhanko-cli/test_config.py::test_no_os_trust_fallback_warning_with_trust_replace` | `config::test_no_os_trust_fallback_warning_with_trust_replace` | 1 |
| `pyhanko-cli/test_config.py::test_read_qr_config` | `config::test_read_qr_config` | 1 |
| `pyhanko-cli/test_config.py::test_read_bad_config` | `config::test_read_bad_config` | 1 |
| `pyhanko-cli/test_config.py::test_read_bad_background_config` | `config::test_read_bad_background_config` | 1 |
| `pyhanko-cli/test_config.py::test_read_bad_config2` | `config::test_read_bad_config2` | 2 |
| `pyhanko-cli/test_config.py::test_empty_config` | `config::test_empty_config` | 1 |
| `pyhanko-cli/test_config.py::test_read_logging_config` | `config::test_read_logging_config` | 1 |
| `pyhanko-cli/test_config.py::test_read_logging_config_defaults` | `config::test_read_logging_config_defaults` | 1 |
| `pyhanko-cli/test_config.py::test_read_logging_config_errors` | `config::test_read_logging_config_errors` | 7 |
| `pyhanko-cli/test_config.py::test_read_key_usage` | `config::test_read_key_usage` | 3 |
| `pyhanko-cli/test_config.py::test_read_extd_key_usage` | `config::test_read_extd_key_usage` | 7 |
| `pyhanko-cli/test_config.py::test_read_key_usage_policy_1` | `config::test_read_key_usage_policy_1` | 1 |
| `pyhanko-cli/test_config.py::test_read_key_usage_policy_2` | `config::test_read_key_usage_policy_2` | 1 |
| `pyhanko-cli/test_config.py::test_read_key_usage_policy_3` | `config::test_read_key_usage_policy_3` | 1 |
| `pyhanko-cli/test_config.py::test_extd_key_usage_errors` | `config::test_extd_key_usage_errors` | 5 |
| `pyhanko-cli/test_config.py::test_key_usage_errors` | `config::test_key_usage_errors` | 5 |
| `pyhanko-cli/test_config.py::test_read_time_tolerance` | `config::test_read_time_tolerance` | 4 |
| `pyhanko-cli/test_config.py::test_read_time_tolerance_input_issues` | `config::test_read_time_tolerance_input_issues` | 1 |
| `pyhanko-cli/test_config.py::test_read_retroactive_revinfo` | `config::test_read_retroactive_revinfo` | 6 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config` | `config::test_read_pkcs11_config` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_legacy` | `config::test_read_pkcs11_config_legacy` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_legacy_with_extra_criteria` | `config::test_read_pkcs11_config_legacy_with_extra_criteria` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_slot_no` | `config::test_read_pkcs11_config_slot_no` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_nothing_to_pull` | `config::test_read_pkcs11_nothing_to_pull` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_ids` | `config::test_read_pkcs11_config_ids` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_external_cert` | `config::test_read_pkcs11_config_external_cert` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_bad_criteria_type` | `config::test_read_pkcs11_config_bad_criteria_type` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_bad_serial` | `config::test_read_pkcs11_config_bad_serial` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_no_cert_spec_or_key_spec` | `config::test_read_pkcs11_config_no_cert_spec_or_key_spec` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_cert_label_from_key_label` | `config::test_read_pkcs11_config_cert_label_from_key_label` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_cert_id_from_key_id` | `config::test_read_pkcs11_config_cert_id_from_key_id` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_id_from_cert_id` | `config::test_read_pkcs11_config_key_id_from_cert_id` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_label_from_cert_label` | `config::test_read_pkcs11_config_key_label_from_cert_label` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_label_not_from_cert_label_if_key_id_defined` | `config::test_read_pkcs11_config_key_label_not_from_cert_label_if_key_id_defined` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin` | `config::test_read_pkcs11_prompt_pin` | 7 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin_default` | `config::test_read_pkcs11_prompt_pin_default` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin_invalid` | `config::test_read_pkcs11_prompt_pin_invalid` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_signing_pin_mode` | `config::test_read_pkcs11_signing_pin_mode` | 3 |
| `pyhanko-cli/test_config.py::test_read_pkcs11_signing_pin_invalid` | `config::test_read_pkcs11_signing_pin_invalid` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs12_config` | `config::test_read_pkcs12_config` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs12_config_null_pw` | `config::test_read_pkcs12_config_null_pw` | 1 |
| `pyhanko-cli/test_config.py::test_read_pemder_config` | `config::test_read_pemder_config` | 1 |
| `pyhanko-cli/test_config.py::test_read_pemder_config_wrong_passphrase` | `config::test_read_pemder_config_wrong_passphrase` | 1 |
| `pyhanko-cli/test_config.py::test_read_pemder_config_missing_passphrase` | `config::test_read_pemder_config_missing_passphrase` | 1 |
| `pyhanko-cli/test_config.py::test_read_pkcs12_config_wrong_passphrase` | `config::test_read_pkcs12_config_wrong_passphrase` | 1 |
| `pyhanko-cli/test_config.py::test_read_simple_layout_config` | `config::test_read_simple_layout_config` | 6 |
| `pyhanko-cli/test_config.py::test_read_simple_layout_config_failures` | `config::test_read_simple_layout_config_failures` | 3 |
| `pyhanko-cli/test_config.py::test_configurable_recurse` | `config::test_configurable_recurse` | 6 |
| `pyhanko-cli/test_config.py::test_enforce_required` | `config::test_enforce_required` | 4 |
| `pyhanko-cli/test_config.py::test_enforce_required_recursive` | `config::test_enforce_required_recursive` | 1 |
| `pyhanko-cli/test_config.py::test_configurable_recurse_optional_styles` | `config::test_configurable_recurse_optional_styles` | 3 |
| `pyhanko-cli/test_config.py::test_default_stamp_style_fetch` | `config::test_default_stamp_style_fetch` | 1 |
| `pyhanko-cli/test_config.py::test_cache_dir_config` | `config::test_cache_dir_config` | 1 |
| `pyhanko-cli/test_config.py::test_fail_to_read_default_config` | `config::test_fail_to_read_default_config` | 1 |
| `pyhanko-cli/test_config.py::test_fail_to_read_nondefault_config` | `config::test_fail_to_read_nondefault_config` | 1 |

The parameter counts above are source declarations, not claimed execution counts.
Detailed mappings are also saved to `~/.codex/artifacts/sigis/round3/c/config/mapping.json`.

Scope: strict YAML grammar rejects nonfinite/legacy numeric encodings, unsupported tags, ambiguous aliases and nonstring mapping keys. This is not full YAML 1.1 compatibility. Limits: 4MiB input,100k tokens/events,depth128,16MiB estimated alias expansion cost, not heap cap. Key-loader tests sign/verify messages; they do not establish PDF signing command coverage. Optional annotation spellings share Rust Option semantics.

Oracle evidence: 17 fresh live configuration status/settings comparisons in configuration_live_oracle_matrix; no fixture-only credit. Supplemental scalar/config assertions add zero IDs.

No provider skips. Fresh native evidence: increment-fields-tests.log; current cumulative projection uses its own preserved Cargo-produced executable, not the full-source binary. Build/tests/clippy/fmt receipts record actual scheduler host/slot.
