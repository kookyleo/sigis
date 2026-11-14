//! Exact two default-appearance originals: four positive parameters and fixed RSA.
//! Supplemental checks receive no additional upstream-function credit.
#[path = "common/appearance_cases.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;

fn attempt<T>(label: &str, failures: &mut Vec<String>, action: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(value) => Some(value),
        Err(error) => {
            let message = error
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| error.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic");
            failures.push(format!("{label}: {message}"));
            None
        }
    }
}

#[test]
fn test_cli_sign_visible_no_style() {
    let mut failures = Vec::new();
    for arch in cases::ARCHES {
        let case = cases::Case::new(arch, "visible");
        let native = attempt(&format!("{arch} native attempt"), &mut failures, || {
            case.native()
        });
        // Always run a fresh unchanged Python original, even on a red native case.
        attempt(
            &format!("{arch} fresh Python original"),
            &mut failures,
            || case.reference(),
        );
        if let Some(native) = native {
            attempt(&format!("{arch} native assertions"), &mut failures, || {
                assert!(native.status.success(), "{}", cases::text(&native));
                case.verify();
            });
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn test_cli_new_field_spec_bars_existing_only() {
    let case = cases::Case::new("rsa", "conflict");
    let mut failures = Vec::new();
    let native = attempt("fixed RSA native attempt", &mut failures, || case.native());
    attempt("fixed RSA fresh Python original", &mut failures, || {
        case.reference()
    });
    if let Some(native) = native {
        attempt("fixed RSA exact native diagnostic", &mut failures, || {
            assert_eq!(native.status.code(), Some(1), "{}", cases::text(&native));
            assert!(
                cases::text(&native).contains("incompatible with --existing-only"),
                "{}",
                cases::text(&native)
            );
            // Supplemental preservation requirement, separate from original ID.
            assert_eq!(
                std::fs::read(case.path("output.pdf")).unwrap(),
                cases::SENTINEL
            );
            assert_eq!(
                std::fs::read(case.path("native-output-frozen.pdf")).unwrap(),
                cases::SENTINEL
            );
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// Append to appearance_default.rs after the exact two originals.
use lopdf::{dictionary, Object};
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
fn prepare_widget(case: &cases::Case, shape: &str) {
    let mut doc = lopdf::Document::load(case.path("input.pdf")).unwrap();
    let page = *doc.get_pages().values().next().unwrap();
    let rect: Vec<Object> = match shape {
        "malformed" => vec![Object::Null, 0.into(), 100.into(), 100.into()],
        "nonfinite" => vec![0.into(), 0.into(), Object::Real(f32::INFINITY), 100.into()],
        "invisible" => vec![0.into(), 0.into(), 0.into(), 100.into()],
        _ => vec![0.into(), 0.into(), 100.into(), 100.into()],
    };
    let widget =
        doc.add_object(dictionary! {"Type"=>"Annot","Subtype"=>"Widget","Rect"=>rect,"P"=>page});
    let mut widgets = vec![widget];
    if shape == "multiple" {
        widgets.push(doc.add_object(dictionary! {"Type"=>"Annot","Subtype"=>"Widget","Rect"=>vec![0.into(),0.into(),100.into(),100.into()],"P"=>page}));
    }
    let separate = shape == "separate" || shape == "multiple";
    let field = if separate {
        doc.add_object(dictionary! {"FT"=>"Sig","T"=>Object::string_literal("Sig1"),"Kids"=>widgets.iter().copied().map(Object::Reference).collect::<Vec<_>>()})
    } else {
        let dict = doc.get_object_mut(widget).unwrap().as_dict_mut().unwrap();
        dict.set("FT", "Sig");
        dict.set("T", Object::string_literal("Sig1"));
        widget
    };
    if separate {
        for id in &widgets {
            doc.get_object_mut(*id)
                .unwrap()
                .as_dict_mut()
                .unwrap()
                .set("Parent", field);
        }
    }
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set(
            "Annots",
            widgets
                .iter()
                .copied()
                .map(Object::Reference)
                .collect::<Vec<_>>(),
        );
    let form = doc.add_object(dictionary! {"Fields"=>vec![Object::Reference(field)]});
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    doc.get_object_mut(root)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("AcroForm", form);
    doc.save(case.path("input.pdf")).unwrap();
}
#[test]
fn supplemental_malformed_nonfinite_invisible_or_multiple_widgets_are_rejected() {
    let mut failures = Vec::new();
    for shape in ["malformed", "nonfinite", "invisible", "multiple"] {
        let case = cases::Case::new("rsa", "supplemental");
        prepare_widget(&case, shape);
        attempt(shape, &mut failures, || {
            let result = case.programmatic(&CliConfig::parse("").unwrap(), &runtime(), false);
            let error = result.unwrap_err();
            assert!(
                !error.contains("requires extended"),
                "{shape}: unrelated unsupported error: {error}"
            );
            match shape {
                "malformed" | "invisible" => {
                    assert!(error.contains("not a visible"), "{shape}: {error}")
                }
                "multiple" => assert!(error.contains("exactly one"), "{shape}: {error}"),
                _ => {}
            }
            assert_eq!(
                std::fs::read(case.path("output.pdf")).unwrap(),
                cases::SENTINEL
            );
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn supplemental_separate_single_widget_remains_a_valid_visible_field() {
    let case = cases::Case::new("rsa", "supplemental");
    prepare_widget(&case, "separate");
    case.programmatic(&CliConfig::parse("").unwrap(), &runtime(), false)
        .unwrap();
    case.verify();
}
fn policy_config(case: &cases::Case, policy: Value) -> CliConfig {
    CliConfig::parse(
        &serde_yaml::to_string(&json!({
            "validation-contexts":{"default":{
                "trust":case.path("root.cert.pem"),"trust-replace":true,
                "time-tolerance":1,"retroactive-revinfo":false,
                "signer-key-usage-policy":policy,
            }},
        }))
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn supplemental_all_five_key_usage_policy_fields_remain_authoritative() {
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
        let case = cases::Case::new("rsa", "supplemental");
        let cfg = policy_config(&case, policy.clone());
        attempt(&policy.to_string(), &mut failures, || {
            let error = case.programmatic(&cfg, &runtime(), false).unwrap_err();
            assert!(error.contains(expected), "{error}; expected {expected}");
            assert_eq!(
                std::fs::read(case.path("output.pdf")).unwrap(),
                cases::SENTINEL
            );
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn supplemental_unknown_raw_and_effective_requirements_and_alias_conflicts_fail_closed() {
    let mut failures = Vec::new();
    for mode in 0..4 {
        let case = cases::Case::new("rsa", "supplemental");
        let mut cfg = policy_config(&case, json!({"key-usage":["non_repudiation"]}));
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
            _ => {
                cfg.validation_contexts.get_mut("default").unwrap()["time_tolerance"] = json!(2);
                "Conflicting configuration aliases"
            }
        };
        attempt(&format!("mode {mode}"), &mut failures, || {
            let error = case.programmatic(&cfg, &runtime(), true).unwrap_err();
            assert!(error.contains(expected), "{error}; expected {expected}");
            assert_eq!(
                std::fs::read(case.path("output.pdf")).unwrap(),
                cases::SENTINEL
            );
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn supplemental_configured_presign_context_is_not_discarded() {
    let case = cases::Case::new("rsa", "supplemental");
    let cfg = CliConfig::parse("validation-contexts:\n  default:\n    trust: []\n    trust-replace: true\n    signer-key-usage-policy:\n      key-usage: [non_repudiation]\n").unwrap();
    let error = case.programmatic(&cfg, &runtime(), true).unwrap_err();
    assert!(error.contains("could not be validated"), "{error}");
    assert_eq!(
        std::fs::read(case.path("output.pdf")).unwrap(),
        cases::SENTINEL
    );
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
fn supplemental_match_any_and_implicit_eku_survive_complete_presign_validation() {
    let mut failures = Vec::new();
    for policy in [
        json!({"key-usage":["non_repudiation","key_cert_sign"],"key-usage-forbidden":["key_encipherment"],"match-all-key-usages":false,"explicit-extd-key-usage-required":true}),
        json!({"key-usage":["non_repudiation"],"key-usage-forbidden":["key_cert_sign"],"extd-key-usage":["email_protection"],"match-all-key-usages":false,"explicit-extd-key-usage-required":false}),
    ] {
        let case = cases::Case::new("rsa", "supplemental");
        attempt(&policy.to_string(), &mut failures, || {
            let metadata = case.revinfo("presign-revinfo");
            let values = metadata["crls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let data = std::fs::read(row["path"].as_str().unwrap()).unwrap();
                    assert_eq!(row["sha256"], cases::sha(&data));
                    data
                })
                .collect();
            let fetcher = std::sync::Arc::new(SignedFixtureCrls {
                values,
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let mut runtime = runtime();
            runtime.now =
                sigis_pki_core::time::Moment::parse_rfc3339(metadata["moment"].as_str().unwrap())
                    .unwrap();
            runtime.fetchers.crl = Some(fetcher.clone());
            let cfg = policy_config(&case, policy.clone());
            case.programmatic(&cfg, &runtime, true).unwrap();
            assert!(fetcher.calls.load(std::sync::atomic::Ordering::Relaxed) > 0);
            case.verify();
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
