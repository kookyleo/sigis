//! One exact no-provider pyHanko0.38.1 original and supplemental phase guards.
//! Only test_cli_pkcs11_setup_config_unreadable maps an immutable function ID.

#[path = "common/pkcs11_config_negative_one/mod.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;

use cases::{Case, CANARY};

const CONFIG_ERROR: &str = "Error while reading PKCS#11 config";
const UNSUPPORTED: &str = "Unsupported PKCS#11 signing requirement: User PIN prompt";

/// pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_pkcs11_setup_config_unreadable.
/// Valid YAML and an empty setup map; the named profile is missing.
#[test]
fn test_cli_pkcs11_setup_config_unreadable() {
    let case = Case::new(Some("pkcs11-setups: {}\n"));
    case.reject(&["--p11-setup", "test"], CONFIG_ERROR);
}

#[test]
fn absent_configuration_and_missing_direct_arguments_have_distinct_errors() {
    let case = Case::new(None);
    case.reject(
        &["--p11-setup", "test"],
        "--p11-setup option requires a configuration file",
    );
    for extra in [vec![], vec!["--lib", CANARY], vec!["--cert-label", "leaf"]] {
        case.reject(&extra, "--lib and --cert-label are required");
    }
}

#[test]
fn named_lookup_parses_real_profiles_before_refusing_unsupported_signing() {
    let config = format!(
        "pkcs11-setups:\n  selected-profile:\n    module-path: {CANARY}\n    cert-label: leaf\n"
    );
    let case = Case::new(Some(&config));
    case.canary();
    for name in ["test", "different-profile"] {
        let result = case.reject(&["--p11-setup", name], CONFIG_ERROR);
        assert!(!result.contains(UNSUPPORTED));
    }
    let result = case.reject(&["--p11-setup", "selected-profile"], UNSUPPORTED);
    assert!(!result.contains(CONFIG_ERROR));
    let invalid = Case::new(Some(
        "pkcs11-setups:\n  invalid-profile:\n    module-path: provider-canary.not-a-library\n    cert-label: [not, a, label]\n",
    ));
    invalid.canary();
    invalid.reject(&["--p11-setup", "invalid-profile"], CONFIG_ERROR);
}

#[test]
fn rejected_lookup_preserves_preexisting_output_and_all_inputs() {
    let case = Case::new(Some("pkcs11-setups: {}\n"));
    case.existing_output();
    case.canary();
    case.reject(&["--p11-setup", "test"], CONFIG_ERROR);
}

#[test]
fn provider_shaped_option_values_and_inline_setup_do_not_change_lookup_phase() {
    let case = Case::new(Some("pkcs11-setups: {}\n"));
    for value in ["pkcs11", "--p11-setup"] {
        let args = [
            "sign",
            "addsig",
            "--field",
            "Sig1",
            "--reason",
            value,
            "pkcs11",
            "--p11-setup",
            "test",
            "input.pdf",
            "output.pdf",
        ]
        .map(str::to_owned)
        .to_vec();
        case.reject_args(args, CONFIG_ERROR);
    }
    case.reject(&["--p11-setup=test"], CONFIG_ERROR);
}
