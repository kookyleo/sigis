//! Supplemental guards for the detached adapter; zero upstream-function credit.
//! In-process runtime controls are separate from original actual-CLI cases.
use serde_json::json;
use sigis_cli::{
    config::CliConfig, detached_signing::run_with_runtime, runtime::ValidationRuntime,
};
use sigis_pki_core::{fetch::Fetchers, time::Moment};
use std::{fs, net::TcpListener, path::PathBuf};

struct Case {
    dir: tempfile::TempDir,
    input: PathBuf,
    output: PathBuf,
    listener: TcpListener,
}
impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.bin");
        let output = dir.path().join("output.sig");
        fs::write(
            &input,
            b"Detached signatures accept arbitrary bytes, not only PDFs.",
        )
        .unwrap();
        fs::write(&output, b"detached-mandatory-sentinel").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self {
            dir,
            input,
            output,
            listener,
        }
    }
    fn args(&self, extra: &[&str]) -> Vec<String> {
        let mut args = vec!["--detach".into()];
        args.extend(extra.iter().map(|v| (*v).into()));
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
    fn runtime() -> ValidationRuntime {
        ValidationRuntime {
            now: Moment::parse_rfc3339("2020-08-01T00:00:00Z").unwrap(),
            fetchers: Fetchers::none(),
            password: Some("guard must run before prompting".into()),
            trusted_list_transport: None,
        }
    }
    fn reject(&self, extra: &[&str], cfg: Option<&CliConfig>, expected: &str) {
        let before = fs::read(&self.input).unwrap();
        let error = run_with_runtime(&self.args(extra), cfg, &Self::runtime())
            .expect_err("Mandatory detached requirement cannot be discarded");
        assert!(
            error.contains(expected),
            "{extra:?}: {error}; expected {expected}"
        );
        assert!(
            !error.contains("Could not read"),
            "Guard must precede credential access: {error}"
        );
        assert_eq!(fs::read(&self.input).unwrap(), before);
        assert_eq!(
            fs::read(&self.output).unwrap(),
            b"detached-mandatory-sentinel"
        );
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        eprintln!(
            "DETACHED_REQUIREMENT {}",
            json!({"extra":extra,"error":error,"input_unchanged":true,"output_preserved":true,"TSA_listener_untouched":true})
        );
    }
}
#[test]
fn field_conflict_precedes_material_and_configuration() {
    let case = Case::new();
    let mut cfg = CliConfig::parse("").unwrap();
    cfg.raw_config = json!({"require-qualified-signature":true});
    case.reject(
        &["--field", "Sig1"],
        Some(&cfg),
        "--field is not compatible with --detach",
    );
}
#[test]
fn unsupported_options_never_reach_material_or_tsa() {
    let case = Case::new();
    let url = format!("http://{}/tsa", case.listener.local_addr().unwrap());
    for extra in [
        vec!["--trust", "missing-root"],
        vec!["--validation-context", "strict"],
        vec!["--md-algorithm", "sha1"],
        vec!["--with-validation-info"],
        vec!["--use-pades-lta"],
        vec!["--soft-revocation-check"],
        vec!["--no-revocation-check"],
        vec!["--force-revinfo"],
        vec!["--prefer-pss"],
        vec!["--existing-only"],
        vec!["--style-name", "pretty"],
        vec!["--no-decode-limits"],
        vec!["--no-strict-syntax"],
        vec!["--password", "secret"],
        vec!["--detach"],
    ] {
        let mut extra = extra;
        extra.extend(["--timestamp-url", &url]);
        case.reject(&extra, None, "Detached signing does not support");
    }
}
#[test]
fn raw_configuration_requirements_cannot_hide_behind_missing_keys() {
    let case = Case::new();
    for (key, value) in [
        (
            "validation-contexts",
            json!({"strict":{"require-qualified-signature":true}}),
        ),
        ("default-validation-context", json!("strict")),
        ("time-tolerance", json!(30)),
        ("retroactive-revinfo", json!(false)),
        ("stamp-styles", json!({})),
        ("default-stamp-style", json!("default")),
        ("identities", json!({})),
        ("plugins", json!([])),
        ("cache-dir", json!("cache")),
        ("require-qualified-signature", json!(true)),
        ("revocation-policy", json!("strict")),
    ] {
        let mut cfg = CliConfig::parse("").unwrap();
        cfg.raw_config = json!({key:value});
        case.reject(
            &[],
            Some(&cfg),
            "Detached signing does not support configuration setting",
        );
    }
}
#[test]
fn mutated_effective_context_and_policy_fields_are_not_discarded() {
    let case = Case::new();
    for selector in 0..10 {
        let mut cfg = CliConfig::parse("").unwrap();
        match selector {
            0 => {
                cfg.validation_contexts
                    .insert("default".into(), json!({"trust":"missing-root"}));
            }
            1 => cfg.default_validation_context = "strict".into(),
            2 => {
                cfg.stamp_styles
                    .insert("default".into(), json!({"stamp-text":"mandatory"}));
            }
            3 => cfg.default_stamp_style = "mandatory".into(),
            4 => cfg.time_tolerance = Some(3600),
            5 => cfg.retroactive_revinfo = true,
            6 => cfg.cache_dir = Some("cache".into()),
            7 => cfg.plugin_endpoints.push("mandatory.plugin".into()),
            8 => {
                cfg.identities.insert(
                    "strict".into(),
                    sigis_cli::config::Identity {
                        plugin: "pemder".into(),
                        parameters: Default::default(),
                    },
                );
            }
            _ => {
                cfg.validation_contexts.insert("default".into(),json!({"signer-key-usage-policy":{"key-usage":["non_repudiation"],"key-usage-forbidden":["digital_signature"],"extd-key-usage":["code_signing"],"match-all-key-usages":true,"explicit-extd-key-usage-required":true}}));
            }
        }
        case.reject(
            &[],
            Some(&cfg),
            "Detached signing does not support effective",
        );
    }
}
#[test]
fn setup_schema_precedes_loading_chain_or_key() {
    let case = Case::new();
    for extra in [
        json!({"require-qualified-signature":true}),
        json!({"prefer-pss":true}),
        json!({"prompt-passphrase":true}),
    ] {
        let mut setup = json!({"key-file":"missing.key","cert-file":"missing.cert","other-certs":["missing-chain"]});
        setup
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let cfg = CliConfig::parse(
            &serde_yaml::to_string(&json!({"pemder-setups":{"selected":setup}})).unwrap(),
        )
        .unwrap();
        // Remove raw credential options so the setup schema is the first invalid requirement.
        let mut args = vec![
            "--detach".into(),
            "pemder".into(),
            "--no-pass".into(),
            "--pemder-setup".into(),
            "selected".into(),
            case.input.display().to_string(),
            case.output.display().to_string(),
        ];
        let error = run_with_runtime(&args, Some(&cfg), &Case::runtime()).unwrap_err();
        assert!(
            error.contains("Unexpected key in PEM/DER setup")
                || error.contains("requires extended PEM/DER signing"),
            "{error}"
        );
        assert!(
            !error.contains("Could not read") && !error.contains("Could not load"),
            "{error}"
        );
        assert_eq!(
            fs::read(&case.output).unwrap(),
            b"detached-mandatory-sentinel"
        );
        args.clear();
    }
}
#[test]
fn default_and_logging_configs_produce_actual_cms_for_arbitrary_bytes() {
    use sigis_pki_core::{
        algorithms::DigestAlgorithm,
        asn1::{oids, raw_oid::RawOid},
        cert::Cert,
    };
    let case = Case::new();
    let key = sigis_testdata::path(&["lanes", "r3-c", "signing", "rsa", "key.pem"]);
    let cert = sigis_testdata::path(&["lanes", "r3-c", "signing", "rsa", "cert.pem"]);
    let loaded = Cert::from_pem_or_der(&fs::read(&cert).unwrap()).unwrap();
    for cfg in [
        None,
        Some(CliConfig::parse("").unwrap()),
        Some(CliConfig::parse("logging:\n  root-output: stdout\n").unwrap()),
    ] {
        let args = vec![
            "--detach".into(),
            "pemder".into(),
            "--no-pass".into(),
            "--key".into(),
            key.display().to_string(),
            "--cert".into(),
            cert.display().to_string(),
            case.input.display().to_string(),
            case.output.display().to_string(),
        ];
        run_with_runtime(&args, cfg.as_ref(), &Case::runtime()).unwrap();
        let sd =
            sigis_cms::SignedData::from_content_info_der(&fs::read(&case.output).unwrap()).unwrap();
        assert!(sd.econtent.is_none());
        assert_eq!(sd.signer_infos.len(), 1);
        let digest = DigestAlgorithm::Sha256.digest(&fs::read(&case.input).unwrap());
        let (intact, valid) = sigis_cms::validate::validate_sig_integrity(
            &sd.signer_infos[0],
            &loaded,
            &RawOid::from(oids::CT_DATA),
            &digest,
        )
        .unwrap();
        assert!(intact && valid);
        let (wrong_intact, _) = sigis_cms::validate::validate_sig_integrity(
            &sd.signer_infos[0],
            &loaded,
            &RawOid::from(oids::CT_DATA),
            &[0; 32],
        )
        .unwrap();
        assert!(!wrong_intact);
    }
}

#[test]
fn equal_credential_aliases_sign_and_conflicts_refuse_before_material() {
    let case = Case::new();
    let key = sigis_testdata::path(&["lanes", "r3-c", "signing", "rsa", "key.pem"]);
    let cert = sigis_testdata::path(&["lanes", "r3-c", "signing", "rsa", "cert.pem"]);
    let setup = json!({"selected":{"key-file":key,"cert-file":cert}});
    let cfg = CliConfig::parse(
        &serde_yaml::to_string(&json!({"pemder-setups":setup,"pemder_setups":setup})).unwrap(),
    )
    .unwrap();
    let args = vec![
        "--detach".into(),
        "pemder".into(),
        "--no-pass".into(),
        "--pemder-setup".into(),
        "selected".into(),
        case.input.display().to_string(),
        case.output.display().to_string(),
    ];
    run_with_runtime(&args, Some(&cfg), &Case::runtime()).unwrap();
    let sd =
        sigis_cms::SignedData::from_content_info_der(&fs::read(&case.output).unwrap()).unwrap();
    let cert = sigis_pki_core::cert::Cert::from_pem_or_der(&fs::read(cert).unwrap()).unwrap();
    let digest =
        sigis_pki_core::algorithms::DigestAlgorithm::Sha256.digest(&fs::read(&case.input).unwrap());
    let (intact, valid) = sigis_cms::validate::validate_sig_integrity(
        &sd.signer_infos[0],
        &cert,
        &sigis_pki_core::asn1::oids::CT_DATA.into(),
        &digest,
    )
    .unwrap();
    assert!(intact && valid);
    let mut conflicting = cfg.clone();
    conflicting.raw_config["pemder_setups"]["selected"]["key-file"] = json!("missing-other-key");
    fs::write(&case.output, b"detached-mandatory-sentinel").unwrap();
    let error = run_with_runtime(&args, Some(&conflicting), &Case::runtime()).unwrap_err();
    assert!(
        error.contains("Conflicting configuration aliases"),
        "{error}"
    );
    assert_eq!(
        fs::read(&case.output).unwrap(),
        b"detached-mandatory-sentinel"
    );
}
