//! Supplemental identity policy guards; no unique upstream-function credit.
#[path = "common/identity_cases.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;
use serde_json::json;
use sigis_cli::{config::CliConfig, plugins::PluginRegistry, runtime::ValidationRuntime};
fn runtime() -> ValidationRuntime {
    ValidationRuntime {
        pkcs11_user_pin_prompt: None,
        now: sigis_pki_core::time::Moment::parse_rfc3339("2020-08-01T00:00:00+08:00").unwrap(),
        fetchers: sigis_pki_core::fetch::Fetchers::none(),
        password: None,
        trusted_list_transport: None,
    }
}
#[test]
fn selected_identity_schema_and_effective_parameters_refuse_silently_dropped_requirements() {
    for mode in 0..4 {
        let case = cases::Case::new("rsa", "programmatic");
        let mut cfg =
            CliConfig::parse(&serde_yaml::to_string(&case.config_value()).unwrap()).unwrap();
        let expected = match mode {
            0 => {
                cfg.raw_config["identities"]["test"]["require-qualified-signature"] = json!(true);
                "Unexpected key in selected identity"
            }
            1 => {
                cfg.identities
                    .get_mut("test")
                    .unwrap()
                    .parameters
                    .insert("key".into(), json!("different-effective-key"));
                "Conflicting raw and effective identity parameters"
            }
            2 => {
                cfg.validation_contexts.insert(
                    "default".into(),
                    json!({"signer-key-usage-policy":{"require-qualified-signature":true}}),
                );
                "require-qualified-signature"
            }
            _ => {
                cfg.validation_contexts.insert(
                    "default".into(),
                    json!({"time-tolerance":1,"time_tolerance":2}),
                );
                "Conflicting configuration aliases"
            }
        };
        case.record_programmatic_begin(&cfg);
        let result = sigis_cli::identity_signing::run_with_runtime(
            &case.args()[2..],
            Some(&cfg),
            &PluginRegistry::default(),
            &runtime(),
        );
        case.record_programmatic(&result, &cfg);
        let error = result.unwrap_err();
        assert!(error.contains(expected), "{error}; expected {expected}");
        assert_eq!(
            std::fs::read(case.path("output.pdf")).unwrap(),
            b"identity-getpass-output-sentinel"
        );
    }
}
#[test]
fn complete_identity_key_usage_policy_is_enforced() {
    for (policy, expected) in [
        (json!({"key-usage":["key_cert_sign"]}), "purpose"),
        (
            json!({"key-usage-forbidden":["non_repudiation"]}),
            "forbidden",
        ),
        (
            json!({"extd-key-usage":["email_protection"],"explicit-extd-key-usage-required":true}),
            "purpose",
        ),
        (
            json!({"key-usage":["non_repudiation","key_cert_sign"],"match-all-key-usages":true}),
            "purpose",
        ),
    ] {
        let case = cases::Case::new("rsa", "programmatic");
        let mut cfg =
            CliConfig::parse(&serde_yaml::to_string(&case.config_value()).unwrap()).unwrap();
        cfg.validation_contexts
            .insert("default".into(), json!({"signer-key-usage-policy":policy}));
        case.record_programmatic_begin(&cfg);
        let result = sigis_cli::identity_signing::run_with_runtime(
            &case.args()[2..],
            Some(&cfg),
            &PluginRegistry::default(),
            &runtime(),
        );
        case.record_programmatic(&result, &cfg);
        let error = result.unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert_eq!(
            std::fs::read(case.path("output.pdf")).unwrap(),
            b"identity-getpass-output-sentinel"
        );
    }
}

#[derive(Debug)]
struct SignedFixtureCrls {
    values: Vec<Vec<u8>>,
    calls: std::sync::atomic::AtomicUsize,
}
impl sigis_pki_core::fetch::CrlFetcher for SignedFixtureCrls {
    fn fetch_crls(
        &self,
        _cert: &sigis_pki_core::cert::Cert,
    ) -> Result<Vec<Vec<u8>>, sigis_pki_core::errors::FetchError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self.values.clone())
    }
}
#[test]
fn contextual_any_of_and_implicit_eku_use_the_complete_policy() {
    for policy in [
        json!({"key-usage":["non_repudiation","key_cert_sign"],"key-usage-forbidden":["key_encipherment"],"match-all-key-usages":false,"explicit-extd-key-usage-required":true}),
        json!({"key-usage":["non_repudiation"],"key-usage-forbidden":["key_cert_sign"],"extd-key-usage":["email_protection"],"match-all-key-usages":false,"explicit-extd-key-usage-required":false}),
    ] {
        let case = cases::Case::new("rsa", "programmatic");
        let driver = sigis_testdata::path(&["lanes", "r3-c", "identity-getpass", "oracle.py"]);
        let evidence = case.path("presign-revinfo");
        let output = std::process::Command::new(sigis_testdata::oracle::python().unwrap())
            .arg(&driver)
            .args([
                "--mode",
                "revinfo",
                "--kind",
                "programmatic",
                "--architecture",
                "rsa",
                "--export-revinfo",
            ])
            .arg(&evidence)
            .current_dir(case.dir.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", cases::text(&output));
        let metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(evidence.join("metadata.json")).unwrap())
                .unwrap();
        let values = metadata["crls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| std::fs::read(row["path"].as_str().unwrap()).unwrap())
            .collect();
        let provider = std::sync::Arc::new(SignedFixtureCrls {
            values,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut runtime = runtime();
        runtime.fetchers.crl = Some(provider.clone());
        let mut cfg =
            CliConfig::parse(&serde_yaml::to_string(&case.config_value()).unwrap()).unwrap();
        cfg.validation_contexts.insert("default".into(),json!({"trust":case.path("root.cert.pem"),"trust-replace":true,"signer-key-usage-policy":policy}));
        let mut args = vec!["--validation-context".into(), "default".into()];
        args.extend_from_slice(&case.args()[2..]);
        case.record_programmatic_begin(&cfg);
        let result = sigis_cli::identity_signing::run_with_runtime(
            &args,
            Some(&cfg),
            &PluginRegistry::default(),
            &runtime,
        );
        case.record_programmatic(&result, &cfg);
        result.unwrap();
        assert!(provider.calls.load(std::sync::atomic::Ordering::Relaxed) > 0);
        case.verify();
    }
}
