//! Two exact PKCS11 frontend originals through the actual top-level runtime.
//! No provider initialization is needed for missing-argument/configuration errors.

#[path = "common/pkcs11_preflight_two/mod.rs"]
mod cases;

/// pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_pkcs11_args_required.
#[test]
fn test_cli_pkcs11_args_required() {
    cases::run(
        "test_cli_pkcs11_args_required",
        &[],
        "--lib and --cert-label are required",
    );
}

/// pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_pkcs11_setup_requires_config.
#[test]
fn test_cli_pkcs11_setup_requires_config() {
    cases::run(
        "test_cli_pkcs11_setup_requires_config",
        &["--p11-setup", "test"],
        "requires a configuration file",
    );
}
