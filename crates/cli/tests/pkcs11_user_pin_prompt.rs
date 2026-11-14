//! ONE upstream USER-PIN prompt original, five retained effective Ed25519 labels.
#[path = "common/pkcs11_user_pin_prompt/mod.rs"]
mod cases;

#[test]
fn test_cli_addsig_pkcs11_with_setup_and_pin_prompt_rsa() {
    cases::run(
        "test_cli_addsig_pkcs11_with_setup_and_pin_prompt_rsa",
        &["positive-rsa"],
    );
}
#[test]
fn test_cli_addsig_pkcs11_with_setup_and_pin_prompt_ecdsa() {
    cases::run(
        "test_cli_addsig_pkcs11_with_setup_and_pin_prompt_ecdsa",
        &["positive-ecdsa"],
    );
}
#[test]
fn test_cli_addsig_pkcs11_with_setup_and_pin_prompt_ed25519() {
    cases::run(
        "test_cli_addsig_pkcs11_with_setup_and_pin_prompt_ed25519",
        &["positive-ed25519"],
    );
}
#[test]
fn test_cli_addsig_pkcs11_with_setup_and_pin_prompt_ed448() {
    cases::run(
        "test_cli_addsig_pkcs11_with_setup_and_pin_prompt_ed448",
        &["positive-ed448"],
    );
}
#[test]
fn test_cli_addsig_pkcs11_with_setup_and_pin_prompt_mldsa() {
    cases::run(
        "test_cli_addsig_pkcs11_with_setup_and_pin_prompt_mldsa",
        &["positive-mldsa"],
    );
}

/// Supplemental zero-ID role/error/authentication controls, fresh child per case.
#[test]
fn supplemental_user_pin_authority_errors_and_authentication_are_isolated() {
    cases::run(
        "supplemental_user_pin_authority_errors_and_authentication_are_isolated",
        &[
            "missing-capability",
            "unavailable",
            "cancelled",
            "wrong-pin",
            "generic-password-is-not-user-pin",
            "signing-pin-mode",
            "configured-signing-pin",
            "environment-signing-pin",
            "configured-pin-correct",
            "configured-pin-wrong",
            "environment-pin-correct",
            "environment-pin-wrong",
            "configured-pin-env-ignored",
        ],
    );
}

#[test]
fn supplemental_selected_requirements_and_certificate_sources_are_preserved() {
    cases::run(
        "supplemental_selected_requirements_and_certificate_sources_are_preserved",
        &[
            "unknown-profile",
            "unknown-token-criterion",
            "nonboolean-requirement",
            "signature-mechanism",
            "missing-resident-intermediate",
            "missing-file-intermediate",
        ],
    );
}

#[test]
fn supplemental_document_credentials_reader_and_usage_policy_remain_independent() {
    cases::run(
        "supplemental_document_credentials_reader_and_usage_policy_remain_independent",
        &[
            "decode-limit",
            "strict-reader",
            "pdf-password-missing",
            "pdf-password-wrong",
            "pdf-password-correct",
            "pdf-correct-user-pin-wrong",
            "pdf-mac-correct",
            "policy-positive",
            "policy-match-any",
            "policy-match-all",
            "policy-forbidden",
            "policy-explicit-eku",
            "policy-empty-roots",
            "policy-missing-revinfo",
            "policy-bad-crl",
            "unsupported-required-revinfo-policy",
        ],
    );
}
