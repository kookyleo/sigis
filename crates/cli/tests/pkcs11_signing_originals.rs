//! SafeNet-only original bodies: explicit availability exclusions, not empty stubs.
//! Run manually only with authorized real PKCS11_CONFIG and its credential envs.
#[path = "common/pkcs11_signing_originals/mod.rs"]
mod cases;

macro_rules! originals {
    ($prompt:ident, $environment:ident, $algorithm:literal) => {
        /// pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_signing_pin_prompt.
        #[test]
        #[ignore = "SafeNet provider not configured; explicit actual PKCS11_CONFIG and credentials required"]
        fn $prompt() {
            cases::run(stringify!($prompt), $algorithm, false);
        }

        /// pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_env_signing_pin.
        #[test]
        #[ignore = "SafeNet provider not configured; explicit actual PKCS11_CONFIG and credentials required"]
        fn $environment() {
            cases::run(stringify!($environment), $algorithm, true);
        }
    };
}

originals!(
    test_cli_addsig_pkcs11_with_setup_and_signing_pin_prompt_rsa,
    test_cli_addsig_pkcs11_with_setup_and_env_signing_pin_rsa,
    "rsa"
);
originals!(
    test_cli_addsig_pkcs11_with_setup_and_signing_pin_prompt_ecdsa,
    test_cli_addsig_pkcs11_with_setup_and_env_signing_pin_ecdsa,
    "ecdsa"
);
originals!(
    test_cli_addsig_pkcs11_with_setup_and_signing_pin_prompt_ed25519,
    test_cli_addsig_pkcs11_with_setup_and_env_signing_pin_ed25519,
    "ed25519"
);
originals!(
    test_cli_addsig_pkcs11_with_setup_and_signing_pin_prompt_ed448,
    test_cli_addsig_pkcs11_with_setup_and_env_signing_pin_ed448,
    "ed448"
);
originals!(
    test_cli_addsig_pkcs11_with_setup_and_signing_pin_prompt_mldsa,
    test_cli_addsig_pkcs11_with_setup_and_env_signing_pin_mldsa,
    "mldsa"
);
