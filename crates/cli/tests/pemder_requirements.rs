//! Supplemental mandatory-policy tests, zero unique upstream-function credit.
//! Direct module controls preserve effective public config; top-level clock is
//! injected in process and is never a product command clock override.
use sigis_cli::{
    config::CliConfig, pemder_signing::run_with_runtime, plugins::PluginRegistry,
    runtime::ValidationRuntime,
};
use sigis_pki_core::{fetch::Fetchers, time::Moment};
use std::{fs, net::TcpListener, path::PathBuf};
const SENTINEL: &[u8] = b"A mandatory PEM requirement must preserve this output.\n";
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
        args.extend(common.iter().map(|s| (*s).into()));
        args.extend([
            "pemder".into(),
            "--no-pass".into(),
            "--key".into(),
            self.dir.path().join("missing.key").display().to_string(),
            "--cert".into(),
            self.dir.path().join("missing.crt").display().to_string(),
            self.input.display().to_string(),
            self.output.display().to_string(),
        ]);
        args
    }
    fn setup_args(&self) -> Vec<String> {
        vec![
            "--field".into(),
            "Sig1".into(),
            "pemder".into(),
            "--no-pass".into(),
            "--pemder-setup".into(),
            "selected".into(),
            self.input.display().to_string(),
            self.output.display().to_string(),
        ]
    }
    fn config(&self, extra: serde_json::Value) -> CliConfig {
        let mut setup = serde_json::json!({"key-file":self.dir.path().join("missing.key"),"cert-file":self.dir.path().join("missing.crt")});
        setup
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        CliConfig::parse(
            &serde_yaml::to_string(&serde_json::json!({"pemder-setups":{"selected":setup}}))
                .unwrap(),
        )
        .unwrap()
    }
    fn runtime() -> ValidationRuntime {
        ValidationRuntime {
            pkcs11_user_pin_prompt: None,
            now: Moment::parse_rfc3339("2020-08-01T00:00:00Z").unwrap(),
            fetchers: Fetchers::none(),
            password: Some("Injected test password prevents stdin waits".into()),
            trusted_list_transport: None,
        }
    }
    fn rejects(&self, args: &[String], cfg: Option<&CliConfig>, expected: &[&str]) {
        let before = fs::read(&self.input).unwrap();
        let error = run_with_runtime(args, cfg, &Self::runtime())
            .expect_err("Mandatory settings cannot be ignored");
        assert!(
            expected.iter().any(|s| error.contains(s)),
            "{args:?}: {error}"
        );
        assert_eq!(fs::read(&self.input).unwrap(), before);
        assert_eq!(fs::read(&self.output).unwrap(), SENTINEL);
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        eprintln!(
            "PEMDER_REQUIREMENT {}",
            serde_json::json!({"thread":std::thread::current().name(),"argv_after_addsig":args,"error":error,"input":self.input,"output":self.output,"input_and_output_preserved":true,"network_connections":0,"unique_upstream_credit":0})
        );
    }
}
#[test]
fn unsupported_requirements_refuse_before_key_or_network_io() {
    let c = Case::new();
    let url = format!(
        "http://{}/must-not-be-used",
        c.listener.local_addr().unwrap()
    );
    for extra in [
        vec!["--detach"],
        vec!["--detach-pem"],
        vec!["--prefer-pss"],
        vec!["--md-algorithm", "sha512"],
        vec!["--certify"],
        vec!["--use-pades-lta"],
        vec!["--use-pades"],
        vec!["--timestamp-url", &url],
        vec!["--stamp-url", &url],
        vec!["--password", "document password"],
        vec!["--trust", "missing.pem"],
        vec!["--trust-replace"],
        vec!["--no-revocation-check"],
        vec!["--soft-revocation-check"],
        vec!["--no-decode-limits"],
    ] {
        c.rejects(
            &c.args(&extra),
            None,
            &["requires extended PEM/DER signing"],
        );
    }
    // Named styles require configuration before any key or network I/O.
    c.rejects(
        &c.args(&["--style-name", "default"]),
        None,
        &["Using named styles requires a configuration file."],
    );
    for field in ["", "1/0,0,100,100/Sig1"] {
        let mut args = c.args(&[]);
        args[1] = field.into();
        c.rejects(&args, None, &["requires extended PEM/DER signing"]);
    }
}
#[test]
fn selected_setup_unknowns_and_aliases_refuse_before_loading_certs() {
    for extra in [
        serde_json::json!({"require-qualified-signature":true}),
        serde_json::json!({"prompt-passphrase":false}),
        serde_json::json!({"prefer-pss":true}),
        serde_json::json!({"key-file":"missing-a","key_file":"missing-b"}),
        serde_json::json!({"cert-file":"missing-a","cert_file":"missing-b"}),
        serde_json::json!({"key-passphrase":"first","key_passphrase":"second"}),
        serde_json::json!({"other-certs":["a"],"other_certs":["b"]}),
    ] {
        let c = Case::new();
        let cfg = c.config(extra);
        c.rejects(
            &c.setup_args(),
            Some(&cfg),
            &[
                "Unexpected key",
                "Conflicting aliases",
                "requires extended PEM/DER signing",
            ],
        );
    }
}
#[test]
fn effective_unknown_policy_is_not_replaced_with_stale_raw_config() {
    for name in [
        "key-usage-forbiden",
        "key_usage_forbiden",
        "require-qualified-signature",
        "require_qualified_signature",
        "match-all-key-usage",
        "match_all_key_usage",
    ] {
        let c = Case::new();
        let mut cfg = c.config(serde_json::json!({}));
        let raw = cfg.raw_config.clone();
        let mut policy = serde_json::json!({});
        policy[name] = if name.starts_with("key") {
            serde_json::json!(["non_repudiation"])
        } else {
            true.into()
        };
        cfg.validation_contexts.insert(
            "effective".into(),
            serde_json::json!({"signer-key-usage-policy":policy}),
        );
        cfg.default_validation_context = "effective".into();
        assert_eq!(cfg.raw_config, raw);
        c.rejects(
            &c.setup_args(),
            Some(&cfg),
            &["Unexpected key", "Unknown setting"],
        );
    }
    let c = Case::new();
    let mut cfg = c.config(serde_json::json!({}));
    cfg.validation_contexts.insert("default".into(),serde_json::json!({"signer-key-usage-policy":{"key-usage":["non_repudiation"],"key_usage":["crl_sign"]}}));
    c.rejects(
        &c.setup_args(),
        Some(&cfg),
        &["Conflicting configuration aliases"],
    );
}
#[test]
fn raw_and_effective_unsupported_config_cannot_fall_back_to_basic() {
    for (key, value) in [
        ("require-qualified-signature", true.into()),
        ("cache-dir", serde_json::json!("unopened")),
        (
            "identities",
            serde_json::json!({"selected":{"plugin":"pemder","parameters":{}}}),
        ),
    ] {
        let c = Case::new();
        let mut cfg = c.config(serde_json::json!({}));
        cfg.raw_config[key] = value;
        c.rejects(
            &c.setup_args(),
            Some(&cfg),
            &["requires extended PEM/DER signing"],
        );
    }
    let c = Case::new();
    let mut cfg = c.config(serde_json::json!({}));
    cfg.cache_dir = Some("not-in-raw-config".into());
    c.rejects(
        &c.setup_args(),
        Some(&cfg),
        &["requires extended PEM/DER signing"],
    );
    cfg.cache_dir = None;
    cfg.default_stamp_style = "unimplemented appearance".into();
    c.rejects(
        &c.setup_args(),
        Some(&cfg),
        &["requires extended PEM/DER signing"],
    );
}
#[test]
fn top_level_selected_setup_preserves_injected_clock_and_denies_unknowns() {
    for unknown in [false, true] {
        let c = Case::new();
        let path = c.dir.path().join("config.yml");
        let mut cfg = serde_json::json!({"pemder-setups":{"selected":{"key-file":sigis_testdata::path(&["lanes","r3-c","signing","rsa","key.pem"]),"cert-file":sigis_testdata::path(&["lanes","r3-c","signing","rsa","cert.pem"]),"other-certs":[sigis_testdata::path(&["lanes","r3-c","signing","rsa","interm.pem"])]}}});
        if unknown {
            cfg["pemder-setups"]["selected"]["require-qualified-signature"] = true.into();
        }
        fs::write(&path, serde_yaml::to_string(&cfg).unwrap()).unwrap();
        let mut args = vec![
            "--config".into(),
            path.display().to_string(),
            "sign".into(),
            "addsig".into(),
        ];
        args.extend(c.setup_args());
        let result =
            sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &Case::runtime());
        if unknown {
            assert_eq!(result.code, 1, "{}", result.stderr);
            assert!(
                result.stderr.contains("Unexpected key"),
                "{}",
                result.stderr
            );
            assert_eq!(fs::read(&c.output).unwrap(), SENTINEL);
        } else {
            assert_eq!(result.code, 0, "{}", result.stderr);
            let pdf = sigis_pdf::PdfFile::parse(&fs::read(&c.output).unwrap()).unwrap();
            let signatures = pdf.embedded_signatures().unwrap();
            let dict = pdf.get_object_at(signatures[0].sig_object, None).unwrap();
            assert_eq!(
                dict.as_dict().unwrap().get(b"M").unwrap().as_str().unwrap(),
                b"D:20200801000000Z"
            );
        }
        eprintln!(
            "PEMDER_TOPLEVEL {}",
            serde_json::json!({"mode":"in-process TOPLEVEL injected runtime, not product CLI process clock","moment":Case::runtime().now.to_string(),"argv":args,"code":result.code,"stderr":result.stderr,"unknown_requirement":unknown,"unique_upstream_credit":0})
        );
    }
}
#[test]
fn all_five_usage_fields_and_forbidden_only_rules_are_enforced() {
    let policies = [
        (serde_json::json!({"key-usage":["non_repudiation"]}), true),
        (serde_json::json!({"key-usage":["crl_sign"]}), false),
        (
            serde_json::json!({"key-usage-forbidden":["non_repudiation"]}),
            false,
        ),
        (
            serde_json::json!({"key-usage":[],"key-usage-forbidden":["non_repudiation"]}),
            false,
        ),
        (
            serde_json::json!({"key-usage":["non_repudiation","crl_sign"],"match-all-key-usages":false}),
            true,
        ),
        (
            serde_json::json!({"key-usage":["non_repudiation","crl_sign"],"match-all-key-usages":true}),
            false,
        ),
        (
            serde_json::json!({"extd-key-usage":["2.999"],"explicit-extd-key-usage-required":true}),
            false,
        ),
        (
            serde_json::json!({"extd-key-usage":["2.999"],"explicit-extd-key-usage-required":false}),
            true,
        ),
    ];
    for (policy, allowed) in policies {
        let c = Case::new();
        let mut cfg = c.config(serde_json::json!({}));
        cfg.raw_config["pemder-setups"]["selected"]["key-file"] =
            serde_json::json!(sigis_testdata::path(&[
                "lanes", "r3-c", "signing", "rsa", "key.pem"
            ]));
        cfg.raw_config["pemder-setups"]["selected"]["cert-file"] =
            serde_json::json!(sigis_testdata::path(&[
                "lanes", "r3-c", "signing", "rsa", "cert.pem"
            ]));
        cfg.validation_contexts.insert(
            "effective".into(),
            serde_json::json!({"signer-key-usage-policy":policy}),
        );
        cfg.default_validation_context = "effective".into();
        let raw = cfg.raw_config.clone();
        let result = run_with_runtime(&c.setup_args(), Some(&cfg), &Case::runtime());
        assert_eq!(cfg.raw_config, raw);
        if allowed {
            assert!(result.is_ok(), "{result:?}");
            let pdf = sigis_pdf::PdfFile::parse(&fs::read(&c.output).unwrap()).unwrap();
            assert_eq!(pdf.embedded_signatures().unwrap().len(), 1);
        } else {
            let error = result.expect_err("The complete effective usage policy must hold");
            assert!(error.contains("not valid for the purpose"), "{error}");
            assert_eq!(fs::read(&c.output).unwrap(), SENTINEL);
        }
        eprintln!(
            "PEMDER_USAGE {}",
            serde_json::json!({"mode":"supplemental in-process effective five-field policy, not upstream argv","policy":policy,"allowed":allowed,"unique_upstream_credit":0})
        );
    }
}

#[test]
fn selected_setup_and_raw_material_conflict_refuses_before_io() {
    for flag in ["--key", "--cert", "--chain"] {
        let c = Case::new();
        let cfg = c.config(serde_json::json!({}));
        let mut args = c.setup_args();
        args.extend([flag.into(), "missing-and-ignored.pem".into()]);
        c.rejects(&args, Some(&cfg), &["requires extended PEM/DER signing"]);
    }
}

#[test]
fn effective_context_alias_conflicts_cannot_silently_drop_requirements() {
    for context in [
        serde_json::json!({"time-tolerance":30,"time_tolerance":0}),
        serde_json::json!({"trust-replace":false,"trust_replace":true}),
        serde_json::json!({"retroactive-revinfo":true,"retroactive_revinfo":false}),
        serde_json::json!({"other-certs":[],"other_certs":["mandatory-missing.pem"]}),
    ] {
        let c = Case::new();
        let mut cfg = c.config(serde_json::json!({}));
        let raw = cfg.raw_config.clone();
        cfg.validation_contexts.insert("effective".into(), context);
        cfg.default_validation_context = "effective".into();
        assert_eq!(cfg.raw_config, raw);
        c.rejects(
            &c.setup_args(),
            Some(&cfg),
            &["Conflicting configuration aliases"],
        );
    }
}

#[test]
fn encrypted_input_refuses_before_key_loading_or_prompt() {
    let c = Case::new();
    fs::copy(
        sigis_testdata::pyhanko(&["pdf", "minimal-aes256.pdf"]),
        &c.input,
    )
    .unwrap();
    c.rejects(
        &c.args(&[]),
        None,
        &["Encrypted PDF input requires extended PEM/DER signing"],
    );
}
