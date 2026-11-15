//! Tests-first mandatory requirements for the bounded PKCS#12 command adapter.
//! All tests in this target are supplemental and add zero original-function credit.

use sigis_cli::{config::CliConfig, pkcs12_signing::run_with_runtime, runtime::ValidationRuntime};
use sigis_pki_core::{fetch::Fetchers, time::Moment};
use std::{fs, net::TcpListener, path::PathBuf};

const SENTINEL: &[u8] = b"A rejected PKCS12 request must preserve this existing output.\n";
const EXTENDED: &str = "requires extended PKCS12 signing";
const SCHEMA_ERRORS: &[&str] = &[
    "Unexpected key",
    "Unknown setting",
    "Conflicting aliases",
    "Conflicting configuration aliases",
];

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
            "pkcs12".into(),
            "--no-pass".into(),
            self.input.display().to_string(),
            self.output.display().to_string(),
            self.dir.path().join("missing.p12").display().to_string(),
        ]);
        args
    }

    fn setup_args(&self) -> Vec<String> {
        vec![
            "--field".into(),
            "Sig1".into(),
            "pkcs12".into(),
            "--no-pass".into(),
            "--p12-setup".into(),
            "selected".into(),
            self.input.display().to_string(),
            self.output.display().to_string(),
        ]
    }

    fn config(&self, setup: serde_json::Value) -> CliConfig {
        let mut selected = serde_json::json!({
            "pfx-file":self.dir.path().join("missing.p12"),
        });
        selected
            .as_object_mut()
            .unwrap()
            .extend(setup.as_object().unwrap().clone());
        let value = serde_json::json!({"pkcs12-setups":{"selected":selected}});
        CliConfig::parse(&serde_yaml::to_string(&value).unwrap()).unwrap()
    }

    fn rejects(&self, args: &[String], config: Option<&CliConfig>, expected: &[&str]) {
        let before = fs::read(&self.input).unwrap();
        let runtime = ValidationRuntime {
            pkcs11_signing_pin_prompt: None,
            pkcs11_user_pin_prompt: None,
            now: Moment::parse_rfc3339("2020-08-01T00:00:00Z").unwrap(),
            fetchers: Fetchers::none(),
            password: Some("Injected public test password prevents stdin waits".into()),
            trusted_list_transport: None,
        };
        let error = run_with_runtime(args, config, &runtime)
            .expect_err("Unsupported PKCS12 requirements must not sign");
        assert!(
            expected.iter().any(|message| error.contains(message)),
            "{args:?}: expected one of {expected:?}, got {error}"
        );
        assert_eq!(fs::read(&self.output).unwrap(), SENTINEL);
        assert_eq!(fs::read(&self.input).unwrap(), before);
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "Mandatory refusal must precede network access"
        );
        eprintln!(
            "PKCS12_REQUIREMENT {}",
            serde_json::json!({
                "thread":std::thread::current().name(),"argv_after_addsig":args,
                "error":error,"input":self.input,"output":self.output,
                "input_length":before.len(),"input_and_output_preserved":true,
                "network_connections":0,"unique_upstream_credit":0,
            })
        );
    }
}

#[test]
fn unsupported_signing_requirements_reject_before_missing_pfx() {
    let case = Case::new();
    let url = format!(
        "http://{}/must-not-be-contacted",
        case.listener.local_addr().unwrap()
    );
    let requirements = [
        vec!["--detach"],
        vec!["--detach-pem"],
        vec!["--md-algorithm", "sha512"],
        vec!["--prefer-pss"],
        vec!["--certify"],
        vec!["--docmdp-permissions", "1"],
        vec!["--reason", "A mandatory reason"],
        vec!["--location", "A mandatory location"],
        vec!["--contact-info", "A mandatory contact"],
        vec!["--name", "A mandatory signer name"],
        vec!["--style-name", "default"],
        vec!["--stamp-url", &url],
        vec!["--other-certs", "missing-intermediate.pem"],
        vec!["--trust", "missing-root.pem"],
        vec!["--trust-replace"],
        vec!["--no-revocation-check"],
        vec!["--soft-revocation-check"],
        vec!["--password", "A document password"],
    ];
    for requirement in requirements {
        case.rejects(&case.args(&requirement), None, &[EXTENDED]);
    }
    let mut args = case.args(&[]);
    args[1] = "1/0,0,100,100/Sig1".into();
    case.rejects(&args, None, &[EXTENDED]);
}

#[test]
fn unknown_options_and_other_providers_reject() {
    let case = Case::new();
    case.rejects(
        &case.args(&["--unknown-mandatory-requirement"]),
        None,
        &["No such option"],
    );
    for provider in ["pemder", "identity", "pkcs11", "beid", "csc"] {
        let mut args = case.args(&[]);
        let at = args.iter().position(|arg| arg == "pkcs12").unwrap();
        args[at] = provider.into();
        case.rejects(&args, None, &[EXTENDED]);
    }
}

#[test]
fn unknown_selected_setup_fields_reject_before_loading_pfx() {
    for key in [
        "require-qualified-signature",
        "require_qualified_signature",
        "use-pades-lta",
    ] {
        let case = Case::new();
        let mut setup = serde_json::json!({});
        setup[key] = true.into();
        let config = case.config(setup);
        case.rejects(&case.setup_args(), Some(&config), SCHEMA_ERRORS);
    }
    let case = Case::new();
    let config = case.config(serde_json::json!({"prefer-pss":true}));
    case.rejects(&case.setup_args(), Some(&config), &[EXTENDED]);
}

#[test]
fn selected_setup_alias_conflicts_reject_before_loading_pfx_or_certs() {
    let setups = [
        serde_json::json!({"pfx-file":"missing-a.p12","pfx_file":"missing-b.p12"}),
        serde_json::json!({"pfx-passphrase":"first","pfx_passphrase":"second"}),
        serde_json::json!({"other-certs":["missing-a.pem"],"other_certs":["missing-b.pem"]}),
        serde_json::json!({"prefer-pss":false,"prefer_pss":true}),
    ];
    for setup in setups {
        let case = Case::new();
        let config = case.config(setup);
        case.rejects(&case.setup_args(), Some(&config), SCHEMA_ERRORS);
    }
}

#[test]
fn effective_selected_policy_uses_the_full_configuration_getter() {
    for key in [
        "key-usage-forbiden",
        "key_usage_forbiden",
        "require-qualified-signature",
        "require_qualified_signature",
        "match-all-key-usage",
        "match_all_key_usage",
    ] {
        let case = Case::new();
        let mut config = case.config(serde_json::json!({}));
        let raw_before = config.raw_config.clone();
        let mut policy = serde_json::json!({});
        policy[key] = if key.starts_with("key") {
            serde_json::json!(["non_repudiation"])
        } else {
            true.into()
        };
        config.validation_contexts.insert(
            "selected".into(),
            serde_json::json!({"signer-key-usage-policy":policy}),
        );
        config.default_validation_context = "selected".into();
        assert_eq!(config.raw_config, raw_before);
        case.rejects(&case.setup_args(), Some(&config), SCHEMA_ERRORS);
    }
    let case = Case::new();
    let mut config = case.config(serde_json::json!({}));
    config.validation_contexts.insert(
        "default".into(),
        serde_json::json!({
            "signer-key-usage-policy":{
                "key-usage":["non_repudiation"],"key_usage":["digital_signature"],
            }
        }),
    );
    case.rejects(&case.setup_args(), Some(&config), SCHEMA_ERRORS);
}

#[test]
fn effective_mandatory_stamp_style_cannot_be_hidden_by_stale_raw_config() {
    let case = Case::new();
    let mut config = case.config(serde_json::json!({}));
    let raw_before = config.raw_config.clone();
    config.default_stamp_style = "mandatory-appearance".into();
    config.stamp_styles.insert(
        "mandatory-appearance".into(),
        serde_json::json!({"type":"qr"}),
    );
    assert_eq!(config.raw_config, raw_before);
    case.rejects(&case.setup_args(), Some(&config), &[EXTENDED]);
}

#[test]
fn missing_lta_timestamp_url_precedes_provider_and_key_errors() {
    let case = Case::new();
    let args = vec![
        "--field".into(),
        "Sig1".into(),
        "--use-pades-lta".into(),
        "pemder".into(),
        "--no-pass".into(),
        "--key".into(),
        case.dir.path().join("missing.key").display().to_string(),
        "--cert".into(),
        case.dir.path().join("missing.cert").display().to_string(),
        case.input.display().to_string(),
        case.output.display().to_string(),
    ];
    case.rejects(&args, None, &["--timestamp-url is required"]);
    case.rejects(
        &case.args(&["--use-pades-lta"]),
        None,
        &["--timestamp-url is required"],
    );
}

#[test]
fn selected_setup_container_aliases_cannot_hide_mandatory_settings() {
    let case = Case::new();
    let mut config = case.config(serde_json::json!({}));
    let pfx = case.dir.path().join("missing.p12");
    config.raw_config["pkcs12_setups"] = serde_json::json!({
        "selected":{"pfx-file":pfx,"prefer-pss":true}
    });
    case.rejects(&case.setup_args(), Some(&config), SCHEMA_ERRORS);
}
