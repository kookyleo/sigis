# Plugins independent port

Scope: native plugin registry, availability and typed identity validation. Original tests were translated before implementation.
Unique functions: 11 total / 11 locally passed /0 skipped/0 pending. Accepted counts require L gate.

## Function mapping

Every entry below maps to `tests/plugins.rs::<same test name>`.

- `test_load_plugins_from_config`: configured and manually registered command help, configured command resolution.
- `test_gracefully_handle_dupe_plugins`: duplicate endpoint, one command registration.
- `test_plugin_must_be_class`: invalid endpoint diagnostic and absent command.
- `test_disable_non_default_plugins`: manual command retained, configured command suppressed.
- `test_show_unavailable_plugins`: unavailable command remains in help.
- `test_trigger_unavailable_plugin`: exit 1 and exact unavailability reason.
- `test_identity_setup_with_too_few_parameters`: exit 1 and required option error.
- `test_identity_setup_with_unknown_parameters`: typed boolean and exact unknown parameter error.
- `test_identity_setup_with_unknown_plugin`: exit 1 and plugin name in error.
- `test_unknown_identity`: exit 1 and exact missing identity error.
- `test_identity_without_config`: exit 1 and exact config requirement error.

Python modules are not imported/executed. Native registered endpoint ABI is an extension compatibility difference. Command help/typed identity failures do not establish signing-engine execution.

Oracle evidence: Historical fresh pinned Python source-only suite:11 cases in config/upstream-plugins-pytest.log. The native11 tests execute the actual registry entry point, independently of that oracle result.

No provider skips. Fresh native evidence: increment-plugins-tests.log; current cumulative projection uses its own preserved Cargo-produced executable, not the full-source binary. Build/tests/clippy/fmt receipts record actual scheduler host/slot.
