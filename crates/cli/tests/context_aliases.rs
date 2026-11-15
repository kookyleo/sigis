//! Mutated public configuration must not choose one of conflicting requirements.
//! Supplemental API/adapter regressions, zero unique upstream-function credit.
#[path = "common/mod.rs"]
#[allow(dead_code)]
mod common;

use serde_json::{json, Value};
use sigis_cli::{config::CliConfig, runtime::ValidationRuntime, validation::context_from_config};
use sigis_pki_core::{cert::Cert, fetch::Fetchers, time::Moment};
use std::{fs, path::PathBuf, time::Duration};

const SENTINEL: &[u8] = b"Conflicting requirements must preserve the existing output.\n";

fn runtime() -> ValidationRuntime {
    ValidationRuntime {
        pkcs11_signing_pin_prompt: None,
        pkcs11_user_pin_prompt: None,
        now: Moment::parse_rfc3339("2020-08-01T00:00:00Z").unwrap(),
        fetchers: Fetchers::none(),
        password: Some("secret".into()),
        trusted_list_transport: None,
    }
}
fn fixture(name: &str) -> PathBuf {
    let path = sigis_testdata::path(&["lanes", "r3-c", "signing", "rsa", name]);
    common::record_test_executable();
    common::record_file(&path, "context_alias_fixture_snapshot");
    path
}
fn cases() -> Vec<(&'static str, Value)> {
    let mut cases = vec![
        (
            "time-tolerance",
            json!({"time-tolerance":30,"time_tolerance":0}),
        ),
        (
            "trust-replace",
            json!({"trust-replace":false,"trust_replace":true}),
        ),
        (
            "retroactive-revinfo",
            json!({"retroactive-revinfo":true,"retroactive_revinfo":false}),
        ),
        (
            "other-certs",
            json!({"other-certs":[],"other_certs":["mandatory-missing.pem"]}),
        ),
    ];
    for key in [
        "time-tolerance",
        "trust-replace",
        "retroactive-revinfo",
        "other-certs",
    ] {
        let mut context = json!({});
        context[key.replace('-', "_")] = match key {
            "time-tolerance" => json!(3600),
            "other-certs" => json!(["mandatory-missing.pem"]),
            _ => json!(true),
        };
        cases.push((key, context));
    }
    cases
}
fn mutated(context: Value, named: bool) -> CliConfig {
    let mut config = CliConfig::parse("").unwrap();
    config
        .validation_contexts
        .insert("effective".into(), context);
    if !named {
        config.default_validation_context = "effective".into();
    }
    config
}
fn name(named: bool) -> Option<&'static str> {
    named.then_some("effective")
}
fn alias_result(result: &Result<(), String>, key: &str) -> bool {
    matches!(result, Err(error) if error.to_ascii_lowercase().contains("alias") && error.contains(key))
}

#[test]
fn direct_context_rejects_all_effective_alias_conflicts_before_material_loading() {
    let mut failures = Vec::new();
    for named in [false, true] {
        for (key, context) in cases() {
            let config = mutated(context.clone(), named);
            let before = config.raw_config.clone();
            let result = context_from_config(Some(&config), name(named), &runtime()).map(|_| ());
            assert_eq!(config.raw_config, before);
            assert_eq!(config.validation_contexts["effective"], context);
            eprintln!(
                "CONTEXT_ALIAS {}",
                json!({"entry":"context_from_config","named":named,"key":key,"context":context,"result":result,"new_credit":0})
            );
            if !alias_result(&result, key) {
                failures.push((key, named, result));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "Requirements cannot be silently selected: {failures:?}"
    );
}

fn adapter_conflicts(provider: &str) {
    let mut failures = Vec::new();
    for named in [false, true] {
        for (key, context) in cases() {
            let directory = tempfile::tempdir().unwrap();
            let input = directory.path().join("input.pdf");
            let output = directory.path().join("output.pdf");
            fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &input).unwrap();
            let before = fs::read(&input).unwrap();
            fs::write(&output, SENTINEL).unwrap();
            let config = mutated(context.clone(), named);
            let raw_before = config.raw_config.clone();
            let mut args = vec!["--field".into(), "Sig1".into()];
            if named {
                args.extend(["--validation-context".into(), "effective".into()]);
            }
            args.extend([provider.into(), "--no-pass".into()]);
            if provider == "pemder" {
                args.extend([
                    "--key".into(),
                    directory.path().join("missing.key").display().to_string(),
                    "--cert".into(),
                    directory.path().join("missing.crt").display().to_string(),
                ]);
            }
            args.extend([input.display().to_string(), output.display().to_string()]);
            if provider == "pkcs12" {
                args.push(directory.path().join("missing.p12").display().to_string());
            }
            let result = match provider {
                "pkcs12" => {
                    sigis_cli::pkcs12_signing::run_with_runtime(&args, Some(&config), &runtime())
                }
                "pemder" => {
                    sigis_cli::pemder_signing::run_with_runtime(&args, Some(&config), &runtime())
                }
                _ => unreachable!(),
            }
            .map(|_| ());
            assert_eq!(fs::read(&input).unwrap(), before);
            assert_eq!(fs::read(&output).unwrap(), SENTINEL);
            assert_eq!(config.raw_config, raw_before);
            assert_eq!(config.validation_contexts["effective"], context);
            eprintln!(
                "CONTEXT_ALIAS {}",
                json!({"entry":provider,"named":named,"key":key,"context":context,"result":result,"input_preserved":true,"output_preserved":true,"argv_after_addsig":args,"new_credit":0})
            );
            if !alias_result(&result, key) {
                failures.push((key, named, result));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "Alias refusal must precede missing private material: {failures:?}"
    );
}
#[test]
fn current_pkcs12_adapter_rejects_effective_aliases_before_missing_pfx() {
    adapter_conflicts("pkcs12");
}
#[test]
fn pemder_adapter_rejects_effective_aliases_before_missing_keys() {
    adapter_conflicts("pemder");
}

#[test]
fn equal_value_alias_pairs_parse_and_construct_the_same_context() {
    let mut failures = Vec::new();
    for key in [
        "trust-replace",
        "time-tolerance",
        "retroactive-revinfo",
        "other-certs",
        "signer-key-usage-policy",
        "signer-key-usage",
        "signer-extd-key-usage",
    ] {
        let value = match key {
            "time-tolerance" => json!(30),
            "other-certs" | "signer-key-usage" | "signer-extd-key-usage" => json!([]),
            "signer-key-usage-policy" => json!({}),
            _ => json!(false),
        };
        let mut context = json!({});
        context[key] = value.clone();
        context[key.replace('-', "_")] = value;
        let config =
            CliConfig::parse(&json!({"validation-contexts":{"default":context}}).to_string())
                .unwrap();
        let result = context_from_config(Some(&config), None, &runtime()).map(|_| ());
        eprintln!(
            "CONTEXT_ALIAS_EQUAL {}",
            json!({"key":key,"context":context,"result":result})
        );
        if result.is_err() {
            failures.push((key, result));
        }
    }
    assert!(
        failures.is_empty(),
        "Equal aliases retain the established parser/factory contract: {failures:?}"
    );
}

fn positive_context(equal_aliases: bool) -> Value {
    let mut context = json!({
        "trust":[fixture("root.pem")], "trust-replace":true,
        "other-certs":[fixture("interm.pem")], "time-tolerance":3600,
        "retroactive-revinfo":true,
        "signer-key-usage-policy":{
            "key-usage":["non_repudiation"],"key-usage-forbidden":["crl_sign"],
            "extd-key-usage":[],"match-all-key-usages":true,
            "explicit-extd-key-usage-required":false,
        }
    });
    if equal_aliases {
        for key in [
            "trust-replace",
            "other-certs",
            "time-tolerance",
            "retroactive-revinfo",
        ] {
            let value = context[key].clone();
            context[key.replace('-', "_")] = value;
        }
    }
    context
}
#[test]
fn canonical_and_equal_aliases_preserve_roots_material_clock_and_all_five_usage_fields() {
    for named in [false, true] {
        for equal_aliases in [false, true] {
            let mut config = mutated(positive_context(equal_aliases), named);
            config.validation_contexts.insert(
                "unselected".into(),
                json!({
                    "time-tolerance":30,"time_tolerance":0,"other-certs":["unselected-missing.pem"]
                }),
            );
            let mut runtime = runtime();
            runtime.fetchers = sigis_pki_fetch::HttpFetchers::default().as_fetchers();
            let context = context_from_config(Some(&config), name(named), &runtime).unwrap();
            assert_eq!(context.timing().validation_time, runtime.now);
            assert!(std::sync::Arc::ptr_eq(
                context.fetchers().cert.as_ref().unwrap(),
                runtime.fetchers.cert.as_ref().unwrap()
            ));
            assert!(std::sync::Arc::ptr_eq(
                context.fetchers().ocsp.as_ref().unwrap(),
                runtime.fetchers.ocsp.as_ref().unwrap()
            ));
            assert!(std::sync::Arc::ptr_eq(
                context.fetchers().crl.as_ref().unwrap(),
                runtime.fetchers.crl.as_ref().unwrap()
            ));
            assert_eq!(context.timing().time_tolerance, Duration::from_secs(3600));
            assert!(context.revinfo_policy().retroactive_revinfo);
            assert_eq!(
                context.revinfo_policy().revocation_checking_policy,
                sigis_pki_certvalidator::policy::RevocationCheckingPolicy::from_legacy("hard-fail")
                    .unwrap()
            );
            let cert = |path: PathBuf| {
                Cert::from_der(
                    &openssl::x509::X509::from_pem(&fs::read(path).unwrap())
                        .unwrap()
                        .to_der()
                        .unwrap(),
                )
                .unwrap()
            };
            assert!(context.is_trust_anchor(&cert(fixture("root.pem"))));
            assert_eq!(context.trust_anchors().len(), 1);
            assert_eq!(context.other_certs(), &[cert(fixture("interm.pem"))]);
            let policy = config.key_usages(name(named)).unwrap();
            assert_eq!(policy.key_usage, Some(["non_repudiation".into()].into()));
            assert_eq!(policy.key_usage_forbidden, Some(["crl_sign".into()].into()));
            assert_eq!(policy.extd_key_usage, Some(Default::default()));
            assert!(policy.match_all_key_usages);
            assert!(!policy.explicit_extd_key_usage_required);
        }
    }
}

#[test]
fn parse_time_alias_rejections_and_unknown_effective_settings_remain() {
    for (key, context) in cases() {
        let error =
            CliConfig::parse(&json!({"validation-contexts":{"default":context}}).to_string())
                .unwrap_err();
        assert!(error.contains("alias"), "{key}: {error}");
    }
    CliConfig::parse(
        &json!({"validation-contexts":{"default":{
            "time-tolerance":30,"time_tolerance":30
        }}})
        .to_string(),
    )
    .unwrap();
    for key in ["require-qualified-signature", "require_qualified_signature"] {
        let mut context = json!({});
        context[key] = true.into();
        let config = mutated(context, false);
        let error = context_from_config(Some(&config), None, &runtime()).unwrap_err();
        assert!(error.contains("Unknown setting"), "{error}");
    }
}

#[test]
fn both_adapters_still_sign_with_unambiguous_effective_context() {
    for provider in ["pkcs12", "pemder"] {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.pdf");
        let output = directory.path().join("output.pdf");
        fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &input).unwrap();
        let before = fs::read(&input).unwrap();
        // Exercise the established parse -> common factory -> actual adapter
        // path with equal aliases, not only a fabricated effective map.
        let config = CliConfig::parse(
            &json!({"validation-contexts":{"default":positive_context(true)}}).to_string(),
        )
        .unwrap();
        context_from_config(Some(&config), None, &runtime()).unwrap();
        let raw = config.raw_config.clone();
        let mut args = vec!["--field".into(), "Sig1".into(), provider.into()];
        if provider == "pemder" {
            args.extend([
                "--no-pass".into(),
                "--key".into(),
                fixture("key.pem").display().to_string(),
                "--cert".into(),
                fixture("cert.pem").display().to_string(),
                "--chain".into(),
                fixture("interm.pem").display().to_string(),
            ]);
        }
        args.extend([input.display().to_string(), output.display().to_string()]);
        if provider == "pkcs12" {
            args.push(fixture("signer.p12").display().to_string());
        }
        match provider {
            "pkcs12" => {
                sigis_cli::pkcs12_signing::run_with_runtime(&args, Some(&config), &runtime())
            }
            "pemder" => {
                sigis_cli::pemder_signing::run_with_runtime(&args, Some(&config), &runtime())
            }
            _ => unreachable!(),
        }
        .unwrap();
        assert_eq!(fs::read(&input).unwrap(), before);
        assert_eq!(config.raw_config, raw);
        let pdf = sigis_pdf::PdfFile::parse(&fs::read(&output).unwrap()).unwrap();
        let signatures = pdf.embedded_signatures().unwrap();
        assert_eq!(signatures.len(), 1);
        let validation = context_from_config(Some(&config), None, &runtime()).unwrap();
        // Independent historical output control only; the actual adapter's
        // configured hard-fail context above is unchanged and is not waived.
        let validation = sigis_pki_certvalidator::ValidationContext::builder()
            .moment(runtime().now)
            .trust_root(validation.trust_anchors()[0].cert().clone())
            .other_cert(validation.other_certs()[0].clone())
            .revocation_mode("none")
            .build()
            .unwrap();
        let status = sigis_pades::validate_pdf_signature(
            &pdf,
            &signatures[0],
            &validation,
            Some(&sigis_pdf_diff::StandardDiffPolicy),
        )
        .unwrap();
        assert!(
            status.cms.signature.intact
                && status.cms.signature.valid
                && status.cms.signature.trusted()
                && status.bottom_line(),
            "{provider}: {status:?}"
        );
    }
}
