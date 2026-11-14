//! Three exact default-style originals, four inherited architectures each.
#[allow(dead_code)]
#[path = "common/appearance_cases.rs"]
mod appearance_cases;
#[allow(dead_code)]
#[path = "common/default_style_cases.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;
use cases::{Case, ARCHES};
fn attempt(label: &str, failures: &mut Vec<String>, action: impl FnOnce()) {
    if let Err(error) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        let message = error
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| error.downcast_ref::<&str>().copied())
            .unwrap_or("panic");
        failures.push(format!("{label}: {message}"));
    }
}
fn original(kind: &'static str) {
    let mut failures = Vec::new();
    for arch in ARCHES {
        let case = Case::new(arch, kind);
        let output = case.native();
        attempt(
            &format!("{kind}/{arch} fresh original"),
            &mut failures,
            || case.reference(),
        );
        attempt(&format!("{kind}/{arch} native"), &mut failures, || {
            if kind == "undefined" {
                assert_eq!(output.status.code(), Some(1), "{}", cases::text(&output));
                assert!(
                    cases::text(&output).contains("There is no stamp style named 'undefined'"),
                    "{}",
                    cases::text(&output)
                );
                assert_eq!(
                    std::fs::read(case.path("output.pdf")).unwrap(),
                    appearance_cases::SENTINEL
                );
            } else {
                assert!(output.status.success(), "{}", cases::text(&output));
                case.verify();
            }
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn test_cli_sign_visible_with_custom_default_style() {
    original("custom");
}
#[test]
fn test_cli_sign_visible_with_default_style_and_others_in_config() {
    original("others");
}
#[test]
fn test_cli_sign_visible_with_undefined_default_style() {
    original("undefined");
}
use serde_json::{json, Value};
use sigis_cli::{config::CliConfig, runtime::ValidationRuntime};
fn runtime() -> ValidationRuntime {
    ValidationRuntime {
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
fn supplemental_default_styles_preserve_all_five_usage_constraints() {
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
        let c = Case::new("rsa", "custom");
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
fn supplemental_default_context_empty_roots_and_actual_clock_denials() {
    let mut failures = Vec::new();
    for expired in [false, true] {
        let c = Case::new("rsa", "custom");
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
fn supplemental_default_context_positive_match_any_and_implicit_eku() {
    let mut failures = Vec::new();
    for (kind, policy) in [
        (
            "custom",
            json!({"key-usage":["non_repudiation","key_cert_sign"],"key-usage-forbidden":["key_encipherment"],"match-all-key-usages":false,"explicit-extd-key-usage-required":true}),
        ),
        (
            "others",
            json!({"key-usage":["non_repudiation"],"key-usage-forbidden":["key_cert_sign"],"extd-key-usage":["email_protection"],"match-all-key-usages":false,"explicit-extd-key-usage-required":false}),
        ),
    ] {
        let c = Case::new("rsa", kind);
        attempt(kind, &mut failures, || {
            let meta = c.base.revinfo("presign-default-style-revinfo");
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
            let mut cfg = config(&c, policy);
            if kind == "custom" {
                cfg.stamp_styles.get_mut("test").unwrap()["stamp_text"] = json!("Effective Blah");
            }
            c.programmatic(&cfg, &rt, true).unwrap();
            if kind == "custom" {
                assert!(c
                    .direct_ap()
                    .windows(b"Effective Blah".len())
                    .any(|w| w == b"Effective Blah"));
            }
            assert!(fetcher.calls.load(std::sync::atomic::Ordering::Relaxed) > 0);
            std::fs::copy(
                c.path("output.pdf"),
                c.path("native-default-style-frozen.pdf"),
            )
            .unwrap();
            c.verify();
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn supplemental_default_raw_effective_alias_and_selected_style_refusals() {
    let mut failures = Vec::new();
    for mode in 0..10 {
        let c = Case::new("rsa", "custom");
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
            6 => {
                cfg.default_stamp_style = "undefined".into();
                "There is no stamp style named 'undefined'"
            }
            7 => {
                cfg.stamp_styles.remove("test");
                "There is no stamp style named 'test'"
            }
            8 => {
                cfg.raw_config["default-stamp-style"] = json!({"required":true});
                "default-stamp-style"
            }
            _ => {
                cfg.raw_config["default_stamp_style"] = json!("undefined");
                "Conflicting aliases in PEM/DER configuration"
            }
        };
        attempt(&format!("default-guard{mode}"), &mut failures, || {
            let e = c.programmatic(&cfg, &runtime(), true).unwrap_err();
            assert!(e.contains(expected), "{e}; expected {expected}");
            sentinel(&c);
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn supplemental_undefined_default_precedes_unreadable_key() {
    let c = Case::new("rsa", "undefined");
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
        "undefined-default-before-key",
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
        cases::text(&output).contains("There is no stamp style named 'undefined'"),
        "{}",
        cases::text(&output)
    );
    sentinel(&c);
}
