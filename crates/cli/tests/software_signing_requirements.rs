//! Mandatory refusals for the deliberately bounded software-signing entry point.
//! These supplemental tests add no unique upstream-function credit.

use sigis_cli::{
    config::CliConfig, runtime::ValidationRuntime, software_signing::run_with_runtime,
};
use sigis_pki_core::{fetch::Fetchers, time::Moment};
use std::{fs, net::TcpListener, path::PathBuf};

const SENTINEL: &[u8] = b"Existing output must survive every rejected request.\n";
const EXTENDED: &str = "requires extended software signing";

struct Case {
    dir: tempfile::TempDir,
    input: PathBuf,
    output: PathBuf,
    listener: TcpListener,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.pdf");
        let output = dir.path().join("output.pdf");
        fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &input).unwrap();
        fs::write(&output, SENTINEL).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self {
            dir,
            input,
            output,
            listener,
        }
    }

    fn args(&self, common: &[&str]) -> Vec<String> {
        let mut args = vec!["--field".into(), "Sig1".into()];
        args.extend(common.iter().map(|value| value.to_string()));
        args.extend([
            "pemder".into(),
            "--no-pass".into(),
            "--key".into(),
            self.dir.path().join("missing.key").display().to_string(),
            "--cert".into(),
            self.dir.path().join("missing.cert").display().to_string(),
            self.input.display().to_string(),
            self.output.display().to_string(),
        ]);
        args
    }

    fn p12_args(&self) -> Vec<String> {
        vec![
            "--field".into(),
            "Sig1".into(),
            "pkcs12".into(),
            self.input.display().to_string(),
            self.output.display().to_string(),
            self.dir.path().join("missing.p12").display().to_string(),
        ]
    }

    fn rejects(&self, args: &[String], config: Option<&CliConfig>, expected: &str) {
        let input_before = fs::read(&self.input).unwrap();
        let runtime = ValidationRuntime {
            pkcs11_signing_pin_prompt: None,
            pkcs11_user_pin_prompt: None,
            now: Moment::parse_rfc3339("2020-08-01T00:00:00Z").unwrap(),
            fetchers: Fetchers::none(),
            password: Some("Injected password must not enable an unsupported request".into()),
            trusted_list_transport: None,
        };
        let error = run_with_runtime(args, config, &runtime)
            .expect_err("Unsupported mandatory requirements must reject");
        assert!(error.contains(expected), "{args:?}: {error}");
        assert_eq!(fs::read(&self.output).unwrap(), SENTINEL);
        assert_eq!(fs::read(&self.input).unwrap(), input_before);
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "Reject before contacting any timestamp/network endpoint"
        );
        eprintln!(
            "SOFTWARE_SIGNING_REQUIREMENT {}",
            serde_json::json!({
                "thread":std::thread::current().name(),"argv_after_addsig":args,
                "input":self.input,"output":self.output,"error":error,
                "input_length":input_before.len(),"output_preserved":true,
                "network_connections":0,"unique_upstream_credit":0,
            })
        );
    }
}

#[test]
fn advanced_requirements_reject_before_key_loading_network_and_output() {
    let case = Case::new();
    let url = format!(
        "http://{}/must-not-be-contacted",
        case.listener.local_addr().unwrap()
    );
    let requirements: Vec<Vec<&str>> = vec![
        vec!["--with-validation-info"],
        vec!["--use-pades-lta", "--timestamp-url", &url],
        vec!["--timestamp-url", &url],
        vec!["--validation-context", "selected"],
        vec!["--trust", "missing-root.pem"],
        vec!["--trust-replace"],
        vec!["--other-certs", "missing-intermediate.pem"],
        vec!["--retroactive-revinfo"],
        vec!["--no-revocation-check"],
        vec!["--soft-revocation-check"],
        vec!["--force-revinfo"],
        vec!["--detach"],
        vec!["--detach-pem"],
        vec!["--certify"],
        vec!["--docmdp-permissions", "1"],
        vec!["--use-pades"],
        vec!["--md-algorithm", "sha512"],
        vec!["--prefer-pss"],
        vec!["--style-name", "default"],
        vec!["--stamp-url", &url],
        vec!["--reason", "A required reason"],
        vec!["--location", "A required location"],
        vec!["--contact-info", "A required contact"],
        vec!["--name", "A required signer name"],
        vec!["--password", "A document password"],
        vec!["--no-strict-syntax"],
        vec!["--no-decode-limits"],
        vec!["--existing-only"],
        vec!["--passfile", "missing-passphrase-file"],
        vec!["--pemder-setup", "selected"],
        vec!["--p12-setup", "selected"],
    ];
    for requirement in requirements {
        case.rejects(&case.args(&requirement), None, EXTENDED);
    }
}

#[test]
fn unknown_options_reject_before_missing_key_material() {
    let case = Case::new();
    for option in [
        "--require-qualified-signature",
        "--unrecognised-mandatory-setting",
    ] {
        case.rejects(&case.args(&[option]), None, "No such option");
    }
}

#[test]
fn configured_policies_and_styles_cannot_be_silently_discarded() {
    let configurations = [
        serde_json::json!({"validation-contexts":{"default":{"signer-key-usage-policy":{"key-usage-forbidden":["non_repudiation"]}}}}),
        serde_json::json!({"validation-contexts":{"default":{"signer-key-usage-policy":{"key-usage":["crl_sign"]}}}}),
        serde_json::json!({"validation-contexts":{"default":{"signer-key-usage-policy":{"key-usage-forbiden":["non_repudiation"]}}}}),
        serde_json::json!({"validation-contexts":{"default":{"signer-key-usage-policy":{"require-qualified-signature":true}}}}),
        serde_json::json!({"validation-contexts":{"default":{"signer-key-usage-policy":{"match-all-key-usage":true}}}}),
        serde_json::json!({"default-validation-context":"selected","validation-contexts":{"selected":{"signer-key-usage":["crl_sign"]}}}),
        serde_json::json!({"stamp-styles":{"default":{"type":"qr"}}}),
        serde_json::json!({"default-stamp-style":"selected","stamp-styles":{"selected":{"type":"text","stamp-text":"Required appearance"}}}),
    ];
    for value in configurations {
        let case = Case::new();
        let config = CliConfig::parse(&serde_yaml::to_string(&value).unwrap()).unwrap();
        case.rejects(&case.args(&[]), Some(&config), EXTENDED);
    }
}

#[test]
fn encrypted_input_requires_the_extended_authentication_pipeline() {
    let case = Case::new();
    fs::copy(
        sigis_testdata::path(&["lanes", "r3-c", "runtime", "minimal-aes256.pdf"]),
        &case.input,
    )
    .unwrap();
    assert!(sigis_pdf::PdfFile::parse(&fs::read(&case.input).unwrap())
        .unwrap()
        .encrypted());
    case.rejects(&case.args(&[]), None, EXTENDED);
}

#[test]
fn duplicate_options_and_provider_mismatches_reject() {
    let case = Case::new();
    for duplicate in [
        vec!["--field", "OtherField"],
        vec!["--key", "other-missing.key"],
        vec!["--cert", "other-missing.cert"],
        vec!["--no-pass"],
    ] {
        case.rejects(&case.args(&duplicate), None, EXTENDED);
    }
    for option in ["--key", "--cert", "--pemder-setup"] {
        let mut args = case.p12_args();
        args.splice(3..3, [option.into(), "missing-or-selected".into()]);
        case.rejects(&args, None, EXTENDED);
    }
    for provider in ["identity", "pkcs11", "beid", "csc"] {
        let mut args = case.args(&[]);
        let index = args.iter().position(|arg| arg == "pemder").unwrap();
        args[index] = provider.into();
        case.rejects(&args, None, EXTENDED);
    }
    let mut args = case.args(&[]);
    args[1] = "1/0,0,100,100/Sig1".into();
    case.rejects(&args, None, EXTENDED);
}

#[test]
fn invalid_positional_cardinality_rejects_before_loading_or_prompting() {
    let case = Case::new();
    for missing_input in [true, false] {
        let mut args = case.args(&[]);
        let index = args.len() - if missing_input { 2 } else { 1 };
        args.remove(index);
        case.rejects(&args, None, EXTENDED);
    }
    let mut args = case.args(&[]);
    args.push("unexpected-extra-pemder-position".into());
    case.rejects(&args, None, EXTENDED);
    let mut args = case.p12_args();
    args.pop();
    case.rejects(&args, None, EXTENDED);
    let mut args = case.p12_args();
    args.push("unexpected-extra-p12-position".into());
    case.rejects(&args, None, EXTENDED);
}

#[test]
fn effective_public_configuration_cannot_hide_behind_an_empty_raw_mapping() {
    let mut policy = CliConfig::parse("").unwrap();
    policy.validation_contexts.insert(
        "default".into(),
        serde_json::json!({"signer-key-usage-policy":{"key-usage-forbidden":["non_repudiation"]}}),
    );
    assert_eq!(policy.raw_config, serde_json::json!({}));
    let case = Case::new();
    case.rejects(&case.args(&[]), Some(&policy), EXTENDED);

    let mut style = CliConfig::parse("").unwrap();
    style.default_stamp_style = "mandatory-appearance".into();
    style.stamp_styles.insert(
        "mandatory-appearance".into(),
        serde_json::json!({"type":"qr"}),
    );
    assert_eq!(style.raw_config, serde_json::json!({}));
    let case = Case::new();
    case.rejects(&case.args(&[]), Some(&style), EXTENDED);
}
