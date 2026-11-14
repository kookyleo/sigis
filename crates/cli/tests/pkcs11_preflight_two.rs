//! Two complete PKCS11 preflight originals with a genuine certificate-only fixture.
//! Each provider fixture runs in its own process before the real CLI command.

#[path = "common/pkcs11_preflight_two/mod.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;

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
