//! ONE complete upstream PKCS11 environment-user-PIN original, FIVE fixture rows.
//! The function marker selects Ed25519 for every retained root_cert_data label.

#[path = "common/pkcs11_signing_env_pin/mod.rs"]
mod cases;

/// pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_env_pin; root_cert_data label rsa.
#[test]
fn test_cli_addsig_pkcs11_with_setup_and_env_pin_rsa() {
    cases::run("test_cli_addsig_pkcs11_with_setup_and_env_pin_rsa", "rsa");
}

/// The same immutable original's ecdsa fixture label, effective Ed25519.
#[test]
fn test_cli_addsig_pkcs11_with_setup_and_env_pin_ecdsa() {
    cases::run(
        "test_cli_addsig_pkcs11_with_setup_and_env_pin_ecdsa",
        "ecdsa",
    );
}

/// The same immutable original's ed25519 fixture label.
#[test]
fn test_cli_addsig_pkcs11_with_setup_and_env_pin_ed25519() {
    cases::run(
        "test_cli_addsig_pkcs11_with_setup_and_env_pin_ed25519",
        "ed25519",
    );
}

/// The same immutable original's ed448 fixture label, effective Ed25519.
#[test]
fn test_cli_addsig_pkcs11_with_setup_and_env_pin_ed448() {
    cases::run(
        "test_cli_addsig_pkcs11_with_setup_and_env_pin_ed448",
        "ed448",
    );
}

/// The same immutable original's mldsa fixture label, effective Ed25519.
#[test]
fn test_cli_addsig_pkcs11_with_setup_and_env_pin_mldsa() {
    cases::run(
        "test_cli_addsig_pkcs11_with_setup_and_env_pin_mldsa",
        "mldsa",
    );
}

/// A selected token constraint must not disappear before native module loading.
#[test]
fn unsupported_token_criteria_rejects_before_module_loading() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.pdf");
    std::fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &input).unwrap();
    let output = dir.path().join("output.pdf");
    std::fs::write(&output, b"Preserve output on a selected-policy refusal.\n").unwrap();
    let config = dir.path().join("pyhanko.yml");
    std::fs::write(&config, "pkcs11-setups:\n  test:\n    module-path: /nonexistent-sigis-policy-guard-provider.so\n    cert-label: signer1\n    user-pin: fixture-only-value\n    token-criteria:\n      label: tested25519\n      manufacturer-id: required\n").unwrap();
    let before = std::fs::read(&input).unwrap();
    let args = [
        "--config",
        config.to_str().unwrap(),
        "sign",
        "addsig",
        "--field",
        "Sig1",
        "pkcs11",
        "--p11-setup",
        "test",
        input.to_str().unwrap(),
        output.to_str().unwrap(),
    ]
    .map(str::to_owned);
    let result = sigis_cli::run(&args);
    assert_eq!(result.code, 1);
    assert!(
        result
            .stderr
            .contains("Unsupported PKCS#11 token-criteria setting"),
        "Required selected constraint was lost: {}",
        result.stderr
    );
    assert!(!result.stderr.contains("fixture-only-value"));
    assert_eq!(std::fs::read(&input).unwrap(), before);
    assert_eq!(
        std::fs::read(&output).unwrap(),
        b"Preserve output on a selected-policy refusal.\n"
    );
}
