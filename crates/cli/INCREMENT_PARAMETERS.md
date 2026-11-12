# First four CLI increments: source parameters

Exact pinned source decorators/fixtures are recorded below. Literal config values and negative assertions remain in the same-named Rust tests; annotation-only Python syntax maps to Rust Option. pubkey_decryption covers PEM/DER and PKCS12 paths; crypt force covers both booleans. No runtime provider exclusions or ignored tests occurred. This table adds no unique-function credit.

| Upstream ID | Source parameter decorators and fixture arguments |
| --- | --- |
| `pyhanko-cli/test_cli_crypt.py::test_encrypt_file` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_encrypt_file_with_stdin_pass` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_encrypt_file_with_recipient_cert` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_encrypt_not_both_pubkey_and_password` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_owner_password` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_owner_password_on_stdin` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_force_decrypt_with_user_password` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_user_password_no_force` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_unencrypted_file` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_wrong_sh_type` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_wrong_password` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key` | `pytest.mark.parametrize('force', [True, False]); fixtures: cli_runner, pubkey_decryption, force` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_wrong_key` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_no_force_change_of_encryption_forbidden` | `fixtures: cli_runner, pubkey_decryption` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_force_change_of_encryption_forbidden` | `fixtures: cli_runner, pubkey_decryption` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_and_passfile` | `fixtures: cli_runner, pubkey_decryption` |
| `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_with_private_key_unencrypted_file` | `fixtures: cli_runner, pubkey_decryption` |
| `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_with_private_key_sh_type_mismatch` | `fixtures: cli_runner, pubkey_decryption` |
| `pyhanko-cli/test_cli_crypt.py::test_attempt_decrypt_with_non_matching_key` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_no_pass` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_crypt.py::test_decrypt_with_private_key_empty_pass_on_stdin` | `fixtures: cli_runner, pubkey_decryption` |
| `pyhanko-cli/test_cli_decode_limits.py::test_decrypt_password` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_decode_limits.py::test_decrypt_pubkey` | `pytest.mark.parametrize('method', ['pemder', 'pkcs12']); fixtures: cli_runner, method` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_list_empty_fields_with_status` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_list_mixed_fields_with_status` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_list_empty_fields_without_status` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_cli_add_field_incremental_update_by_default` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_cli_add_field_with_resave` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_cli_add_field_to_last_page` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_field_mgmt.py::test_cli_field_spec_errors` | `pytest.mark.parametrize('field_spec,expected_error_msg', [('0/0,0,100,100/Sig1', 'nonzero integer'), ('zzz/0,0,100,100/Sig1', 'nonzero integer'), ('Sig1', 'should be of the form'), ('1/0,z,100,100/Sig1', 'should be four integers')]); fixtures: cli_runner, field_spec, expected_error_msg` |
| `pyhanko-cli/test_cli_plugins.py::test_load_plugins_from_config` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_plugins.py::test_gracefully_handle_dupe_plugins` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_plugins.py::test_plugin_must_be_class` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_plugins.py::test_disable_non_default_plugins` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_plugins.py::test_show_unavailable_plugins` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_plugins.py::test_trigger_unavailable_plugin` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_plugins.py::test_identity_setup_with_too_few_parameters` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_plugins.py::test_identity_setup_with_unknown_parameters` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_plugins.py::test_identity_setup_with_unknown_plugin` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_plugins.py::test_unknown_identity` | `fixtures: cli_runner` |
| `pyhanko-cli/test_cli_plugins.py::test_identity_without_config` | `fixtures: cli_runner` |
| `pyhanko-cli/test_config.py::test_read_vc_kwargs` | `pytest.mark.parametrize('trust_replace', [True, False]); fixtures: trust_replace` |
| `pyhanko-cli/test_config.py::test_os_trust_fallback_warning` | `pytest.mark.parametrize('trust_setting,expected_msg', [(f"trust: '{TESTING_CA_DIR}/root/root.cert.pem'", 'being combined with the operating system'), ('other-certs: []', 'No trust roots were configured')]); fixtures: caplog, trust_setting, expected_msg` |
| `pyhanko-cli/test_config.py::test_no_os_trust_fallback_warning_with_trust_replace` | `fixtures: caplog` |
| `pyhanko-cli/test_config.py::test_read_qr_config` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_bad_config` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_bad_background_config` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_bad_config2` | `pytest.mark.parametrize('bad_type', ['5', '[1,2,3]']); fixtures: bad_type` |
| `pyhanko-cli/test_config.py::test_empty_config` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_logging_config` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_logging_config_defaults` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_logging_config_errors` | `pytest.mark.parametrize('config_str', WRONG_CONFIGS); fixtures: config_str` |
| `pyhanko-cli/test_config.py::test_read_key_usage` | `pytest.mark.parametrize('key_usage_str, key_usages', [('non_repudiation', {'non_repudiation'}), ('[non_repudiation, digital_signature]', {'non_repudiation', 'digital_signature'}), ('[]', set())]); fixtures: key_usage_str, key_usages` |
| `pyhanko-cli/test_config.py::test_read_extd_key_usage` | `pytest.mark.parametrize('key_usage_str, key_usages', [('piv_content_signing', {'piv_content_signing'}), ('[piv_content_signing, code_signing]', {'piv_content_signing', 'code_signing'}), ('[]', set()), ('[2.16.840.1.101.3.6.7, code_signing]', {'piv_content_signing', 'code_signing'}), ('[2.16.840.1.101.3.6.7, "2.999"]', {'piv_content_signing', '2.999'}), ('2.16.840.1.101.3.6.7', {'piv_content_signing'}), ('"2.999"', {'2.999'})]); fixtures: key_usage_str, key_usages` |
| `pyhanko-cli/test_config.py::test_read_key_usage_policy_1` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_key_usage_policy_2` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_key_usage_policy_3` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_extd_key_usage_errors` | `pytest.mark.parametrize('key_usage_str', ['0', '["non_repudiation", 2]', '[1, 2, 3]', 'abcdef', '["no_such_key_usage"]']); fixtures: key_usage_str` |
| `pyhanko-cli/test_config.py::test_key_usage_errors` | `pytest.mark.parametrize('key_usage_str', ['0', '["non_repudiation", 2]', '[1, 2, 3]', 'abcdef', '["no_such_key_usage"]']); fixtures: key_usage_str` |
| `pyhanko-cli/test_config.py::test_read_time_tolerance` | `pytest.mark.parametrize('config_string, result', [(f"\n    time-tolerance: 5\n    validation-contexts:\n        default:\n            trust: '{TESTING_CA_DIR}/root/root.cert.pem'\n            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'\n            trust-replace: true\n    ", 5), (f"\n    time-tolerance: 5\n    validation-contexts:\n        default:\n            time-tolerance: 7\n            trust: '{TESTING_CA_DIR}/root/root.cert.pem'\n            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'\n            trust-replace: true\n    ", 7), (f"\n    validation-contexts:\n        default:\n            time-tolerance: 7\n            trust: '{TESTING_CA_DIR}/root/root.cert.pem'\n            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'\n            trust-replace: true\n    ", 7), (f"\n    validation-contexts:\n        default:\n            trust: '{TESTING_CA_DIR}/root/root.cert.pem'\n            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'\n            trust-replace: true\n    ", DEFAULT_TIME_TOLERANCE.seconds)]); fixtures: config_string, result` |
| `pyhanko-cli/test_config.py::test_read_time_tolerance_input_issues` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_retroactive_revinfo` | `pytest.mark.parametrize('config_string, result', [(f"\n    retroactive-revinfo: true\n    validation-contexts:\n        default:\n            trust: '{TESTING_CA_DIR}/root/root.cert.pem'\n            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'\n            trust-replace: true\n    ", True), (f"\n    retroactive-revinfo: true\n    validation-contexts:\n        default:\n            retroactive-revinfo: false\n            trust: '{TESTING_CA_DIR}/root/root.cert.pem'\n            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'\n            trust-replace: true\n    ", False), (f"\n    retroactive-revinfo: false\n    validation-contexts:\n        default:\n            retroactive-revinfo: true\n            trust: '{TESTING_CA_DIR}/root/root.cert.pem'\n            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'\n            trust-replace: true\n    ", True), (f"\n    validation-contexts:\n        default:\n            retroactive-revinfo: true\n            trust: '{TESTING_CA_DIR}/root/root.cert.pem'\n            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'\n            trust-replace: true\n    ", True), (f"""\n    validation-contexts:\n        default:\n            retroactive-revinfo: "yes"\n            trust: '{TESTING_CA_DIR}/root/root.cert.pem'\n            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'\n            trust-replace: true\n    """, True), (f"\n    validation-contexts:\n        default:\n            trust: '{TESTING_CA_DIR}/root/root.cert.pem'\n            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'\n            trust-replace: true\n    ", False)]); fixtures: config_string, result` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_legacy` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_legacy_with_extra_criteria` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_slot_no` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_nothing_to_pull` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_ids` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_external_cert` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_bad_criteria_type` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_bad_serial` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_no_cert_spec_or_key_spec` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_cert_label_from_key_label` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_cert_id_from_key_id` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_id_from_cert_id` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_label_from_cert_label` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_config_key_label_not_from_cert_label_if_key_id_defined` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin` | `pytest.mark.parametrize('literal,exp_val', [('prompt', pkcs11_cfg.PKCS11PinEntryMode.PROMPT), ('skip', pkcs11_cfg.PKCS11PinEntryMode.SKIP), ('defer', pkcs11_cfg.PKCS11PinEntryMode.DEFER), ('true', pkcs11_cfg.PKCS11PinEntryMode.PROMPT), ('false', pkcs11_cfg.PKCS11PinEntryMode.SKIP), ('1', pkcs11_cfg.PKCS11PinEntryMode.PROMPT), ('0', pkcs11_cfg.PKCS11PinEntryMode.SKIP)]); fixtures: literal, exp_val` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin_default` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_prompt_pin_invalid` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_signing_pin_mode` | `pytest.mark.parametrize('literal,exp_val', [('prompt', pkcs11_cfg.PKCS11SigningPinEntryMode.PROMPT), ('reauthenticate', pkcs11_cfg.PKCS11SigningPinEntryMode.REAUTHENTICATE), ('skip', pkcs11_cfg.PKCS11SigningPinEntryMode.SKIP)]); fixtures: literal, exp_val` |
| `pyhanko-cli/test_config.py::test_read_pkcs11_signing_pin_invalid` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs12_config` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs12_config_null_pw` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pemder_config` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pemder_config_wrong_passphrase` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pemder_config_missing_passphrase` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_pkcs12_config_wrong_passphrase` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_read_simple_layout_config` | `pytest.mark.parametrize('cfg_str,expected_result', [('x-align: left', layout.SimpleBoxLayoutRule(x_align=layout.AxisAlignment.ALIGN_MIN, y_align=layout.AxisAlignment.ALIGN_MID)), ('y-align: bottom', layout.SimpleBoxLayoutRule(x_align=layout.AxisAlignment.ALIGN_MID, y_align=layout.AxisAlignment.ALIGN_MIN)), ('\n        y-align: bottom\n        x-align: mid\n        margins:\n            left: 10\n            right: 10\n        ', layout.SimpleBoxLayoutRule(x_align=layout.AxisAlignment.ALIGN_MID, y_align=layout.AxisAlignment.ALIGN_MIN, margins=layout.Margins(left=10, right=10))), ('\n        y-align: bottom\n        x-align: mid\n        margins: [10, 10, 0, 0]\n        ', layout.SimpleBoxLayoutRule(x_align=layout.AxisAlignment.ALIGN_MID, y_align=layout.AxisAlignment.ALIGN_MIN, margins=layout.Margins(left=10, right=10))), ('\n        y-align: bottom\n        x-align: mid\n        inner-content-scaling: none\n        ', layout.SimpleBoxLayoutRule(x_align=layout.AxisAlignment.ALIGN_MID, y_align=layout.AxisAlignment.ALIGN_MIN, inner_content_scaling=layout.InnerScaling.NO_SCALING)), ('inner-content-scaling: stretch-to-fit', layout.SimpleBoxLayoutRule(x_align=layout.AxisAlignment.ALIGN_MID, y_align=layout.AxisAlignment.ALIGN_MID, inner_content_scaling=layout.InnerScaling.STRETCH_TO_FIT))]); fixtures: cfg_str, expected_result` |
| `pyhanko-cli/test_config.py::test_read_simple_layout_config_failures` | `pytest.mark.parametrize('cfg_str,error', [('x-align: bottom', 'is not a valid horizontal'), ('y-align: right', 'is not a valid vertical'), ('inner-content-scaling: foobar', 'is not a valid inner scaling')]); fixtures: cfg_str, error` |
| `pyhanko-cli/test_config.py::test_configurable_recurse` | `pytest.mark.parametrize('cfg_str, expected_field_val', [('\n            some_field:\n                field1: 1\n                field2: [1,2]\n            ', DemoConfigurableA(field1=1, field2=[1, 2])), ('\n            some_field:\n                field1: 1\n                field2: [1,2]\n                field3: 5\n            ', DemoConfigurableA(field1=1, field2=[1, 2], field3=5)), ('\n            some_field:\n                field1: 1\n                field2: [1,2]\n                field3: 5\n                field4: [6,7,8]\n            ', DemoConfigurableA(field1=1, field2=[1, 2], field3=5, field4=[6, 7, 8])), ('\n            some_field:\n                field1: 1\n                field2: [1,2]\n                field5: xyz\n            ', DemoConfigurableA(field1=1, field2=[1, 2], field5='xyz')), ('\n            some_field:\n                field1: 1\n                field2: [1,2]\n                field5: 8\n                field6: xyz\n            ', DemoConfigurableA(field1=1, field2=[1, 2], field5=8, field6='xyz')), ('{}', None)]); fixtures: cfg_str, expected_field_val` |
| `pyhanko-cli/test_config.py::test_enforce_required` | `pytest.mark.parametrize('cfg_str', ['\n    field2: [1,2]\n    field3: 5\n    ', '\n    field1: 1\n    field3: 5\n    ', '\n    field3: 5\n    ', '{}']); fixtures: cfg_str` |
| `pyhanko-cli/test_config.py::test_enforce_required_recursive` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_configurable_recurse_optional_styles` | `pytest.mark.parametrize('configurable_cls', [DemoConfigurableOldStyleOptional, DemoConfigurableOldStyleUnion, DemoConfigurableB]); fixtures: configurable_cls` |
| `pyhanko-cli/test_config.py::test_default_stamp_style_fetch` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_cache_dir_config` | `fixtures: ` |
| `pyhanko-cli/test_config.py::test_fail_to_read_default_config` | `fixtures: cli_runner` |
| `pyhanko-cli/test_config.py::test_fail_to_read_nondefault_config` | `fixtures: cli_runner` |
