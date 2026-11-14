//! Three exact named-style originals: four text, four QR, one Ed25519 rejection.
#[allow(dead_code)] // Reuse accepted fixture/trust methods; do not copy its engine.
#[path = "common/appearance_cases.rs"]
mod appearance_cases;
#[path = "common/styled_cases.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;
use cases::{Case, ARCHES};
fn attempt(label: &str, failures: &mut Vec<String>, action: impl FnOnce()) {
    if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        let message = e
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| e.downcast_ref::<&str>().copied())
            .unwrap_or("panic");
        failures.push(format!("{label}: {message}"));
    }
}
fn positive(kind: &'static str) {
    let mut failures = Vec::new();
    for arch in ARCHES {
        let case = Case::new(arch, kind);
        let output = case.native();
        attempt(
            &format!("{kind}/{arch} fresh unchanged original"),
            &mut failures,
            || case.reference(),
        );
        attempt(&format!("{kind}/{arch} native"), &mut failures, || {
            assert!(output.status.success(), "{}", cases::text(&output));
            case.verify();
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn test_cli_sign_visible_with_style() {
    positive("text");
}
#[test]
fn test_cli_sign_visible_with_qr_style() {
    positive("qr");
}
#[test]
fn test_cli_sign_visible_with_qr_style_omit_stamp_url() {
    let c = Case::new("ed25519", "missing-url");
    let output = c.native();
    let mut failures = Vec::new();
    attempt(
        "fresh original missing-url fixture/teardown",
        &mut failures,
        || c.reference(),
    );
    attempt("exact native missing-url refusal", &mut failures, || {
        assert_eq!(output.status.code(), Some(1), "{}", cases::text(&output));
        assert!(
            cases::text(&output).contains("QR stamp styles require the --stamp-url option"),
            "{}",
            cases::text(&output)
        );
        assert_eq!(
            std::fs::read(c.path("output.pdf")).unwrap(),
            appearance_cases::SENTINEL
        );
    });
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

use serde_json::{json, Value};
use sigis_cli::{config::CliConfig, runtime::ValidationRuntime};
fn runtime() -> ValidationRuntime {
    ValidationRuntime {
        pkcs11_user_pin_prompt: None,
        now: sigis_pki_core::time::Moment::parse_rfc3339("2020-08-01T00:00:00+08:00").unwrap(),
        fetchers: sigis_pki_core::fetch::Fetchers::none(),
        password: None,
        trusted_list_transport: None,
    }
}
fn config(case: &Case, policy: Value) -> CliConfig {
    let mut value = case.config();
    value["validation-contexts"] = json!({"default":{
        "trust":case.path("root.cert.pem"),"trust-replace":true,"other-certs":[case.path("interm.cert.pem")],
        "time-tolerance":1,"retroactive-revinfo":false,"signer-key-usage-policy":policy}});
    CliConfig::parse(&serde_yaml::to_string(&value).unwrap()).unwrap()
}
fn sentinel(c: &Case) {
    assert_eq!(
        std::fs::read(c.path("output.pdf")).unwrap(),
        appearance_cases::SENTINEL
    );
}
#[test]
fn supplemental_named_styles_preserve_all_five_usage_constraints() {
    let mut failures = Vec::new();
    for (policy, expected) in [
        (
            json!({"key-usage":["key_cert_sign"],"key-usage-forbidden":[],"extd-key-usage":[],"match-all-key-usages":false,"explicit-extd-key-usage-required":true}),
            "purpose",
        ),
        (
            json!({"key-usage":["non_repudiation"],"key-usage-forbidden":["non_repudiation"],"extd-key-usage":[],"match-all-key-usages":false,"explicit-extd-key-usage-required":true}),
            "forbidden",
        ),
        (
            json!({"key-usage":["non_repudiation"],"key-usage-forbidden":[],"extd-key-usage":["email_protection"],"match-all-key-usages":false,"explicit-extd-key-usage-required":true}),
            "purpose",
        ),
        (
            json!({"key-usage":["non_repudiation","key_cert_sign"],"key-usage-forbidden":[],"extd-key-usage":[],"match-all-key-usages":true,"explicit-extd-key-usage-required":true}),
            "purpose",
        ),
        (
            json!({"key-usage":["non_repudiation"],"extd-key-usage":[],"explicit-extd-key-usage-required":true}),
            "purpose",
        ),
    ] {
        let c = Case::new("rsa", "text");
        let cfg = config(&c, policy.clone());
        attempt(&policy.to_string(), &mut failures, || {
            let e = c.programmatic(&cfg, &runtime(), true).unwrap_err();
            assert!(e.contains(expected), "{e}");
            sentinel(&c);
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn supplemental_raw_effective_policy_alias_and_style_guards() {
    let mut failures = Vec::new();
    for mode in 0..7 {
        let c = Case::new("rsa", "text");
        let mut cfg = config(&c, json!({"key-usage":["non_repudiation"]}));
        let expected = match mode {
            0 => {
                cfg.raw_config["require-qualified-signature"] = json!(true);
                "require-qualified-signature"
            }
            1 => {
                cfg.raw_config["validation-contexts"]["default"]["signer-key-usage-policy"]
                    ["require-qualified-signature"] = json!(true);
                "require-qualified-signature"
            }
            2 => {
                cfg.validation_contexts.get_mut("default").unwrap()["signer-key-usage-policy"]
                    ["require-qualified-signature"] = json!(true);
                "require-qualified-signature"
            }
            3 => {
                cfg.validation_contexts.get_mut("default").unwrap()["time_tolerance"] = json!(2);
                "Conflicting configuration aliases"
            }
            4 => {
                cfg.raw_config["stamp-styles"]["test"]["require-qualified-signature"] = json!(true);
                "require-qualified-signature"
            }
            5 => {
                cfg.stamp_styles.get_mut("test").unwrap()["require-qualified-signature"] =
                    json!(true);
                "require-qualified-signature"
            }
            _ => {
                cfg.stamp_styles.remove("test");
                "There is no stamp style named 'test'"
            }
        };
        attempt(&format!("guard{mode}"), &mut failures, || {
            let e = c.programmatic(&cfg, &runtime(), true).unwrap_err();
            assert!(e.contains(expected), "{e}; expected{expected}");
            sentinel(&c);
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn supplemental_named_context_empty_roots_and_actual_clock_denials() {
    let mut failures = Vec::new();
    for expired in [false, true] {
        let c = Case::new("rsa", "text");
        let mut cfg = config(&c, json!({"key-usage":["non_repudiation"]}));
        let mut rt = runtime();
        if expired {
            rt.now = sigis_pki_core::time::Moment::parse_rfc3339("2035-01-01T00:00:00Z").unwrap();
        } else {
            cfg.validation_contexts.get_mut("default").unwrap()["trust"] = json!([]);
        }
        attempt(&format!("context{expired}"), &mut failures, || {
            let e = c.programmatic(&cfg, &rt, true).unwrap_err();
            assert!(e.contains("could not be validated"), "{e}");
            sentinel(&c);
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[derive(Debug)]
struct SignedFixtureCrls {
    values: Vec<Vec<u8>>,
    calls: std::sync::atomic::AtomicUsize,
}
impl sigis_pki_core::fetch::CrlFetcher for SignedFixtureCrls {
    fn fetch_crls(
        &self,
        _: &sigis_pki_core::cert::Cert,
    ) -> Result<Vec<Vec<u8>>, sigis_pki_core::errors::FetchError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self.values.clone())
    }
}
#[test]
fn supplemental_named_context_positive_match_any_and_implicit_eku() {
    let mut failures = Vec::new();
    for (kind, policy) in [
        (
            "text",
            json!({"key-usage":["non_repudiation","key_cert_sign"],"key-usage-forbidden":["key_encipherment"],"match-all-key-usages":false,"explicit-extd-key-usage-required":true}),
        ),
        (
            "qr",
            json!({"key-usage":["non_repudiation"],"key-usage-forbidden":["key_cert_sign"],"extd-key-usage":["email_protection"],"match-all-key-usages":false,"explicit-extd-key-usage-required":false}),
        ),
    ] {
        let c = Case::new("rsa", kind);
        attempt(kind, &mut failures, || {
            let meta = c.base.revinfo("presign-styled-revinfo");
            let values = meta["crls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| std::fs::read(row["path"].as_str().unwrap()).unwrap())
                .collect();
            let fetcher = std::sync::Arc::new(SignedFixtureCrls {
                values,
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let mut rt = runtime();
            rt.now = sigis_pki_core::time::Moment::parse_rfc3339(meta["moment"].as_str().unwrap())
                .unwrap();
            rt.fetchers.crl = Some(fetcher.clone());
            c.programmatic(&config(&c, policy), &rt, true).unwrap();
            assert!(fetcher.calls.load(std::sync::atomic::Ordering::Relaxed) > 0);
            std::fs::copy(c.path("output.pdf"), c.path("native-styled-frozen.pdf")).unwrap();
            c.verify();
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn supplemental_missing_url_precedes_unreadable_material() {
    let c = Case::new("ed25519", "missing-url");
    let mut args = c.args();
    let at = args.iter().position(|a| a == "--key").unwrap();
    args[at + 1] = "absent-key.pem".into();
    let before = signing_record::before(&c.inputs());
    let output = std::process::Command::new(common::cli())
        .args(&args)
        .current_dir(c.base.dir.path())
        .output()
        .unwrap();
    signing_record::process(
        "styled-missing-url-before-key",
        &args,
        c.base.dir.path(),
        b"",
        common::cli(),
        &output,
        &before,
        &[("unchanged-output-sentinel", &c.path("output.pdf"))],
    );
    assert_eq!(output.status.code(), Some(1), "{}", cases::text(&output));
    assert!(
        cases::text(&output).contains("QR stamp styles require the --stamp-url option"),
        "{}",
        cases::text(&output)
    );
    sentinel(&c);
}
