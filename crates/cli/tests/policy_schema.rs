//! Supplemental mandatory-policy assertions; no additional upstream-function credit.
#[path = "common/mod.rs"]
mod common;
use serde_json::{json, Value};
use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime, Output};
use sigis_pki_core::{
    cert::Cert,
    errors::FetchError,
    fetch::{CertificateFetcher, CrlFetcher, Fetchers, OcspFetcher},
    time::Moment,
};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

#[derive(Debug, Default)]
struct CountedFetchers(AtomicUsize);
impl CertificateFetcher for CountedFetchers {
    fn fetch_issuers(&self, _: &Cert) -> Result<Vec<Cert>, FetchError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(FetchError::disabled("unexpected issuer retrieval"))
    }
}
impl CrlFetcher for CountedFetchers {
    fn fetch_crls(&self, _: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(FetchError::disabled("unexpected CRL retrieval"))
    }
}
impl OcspFetcher for CountedFetchers {
    fn fetch_ocsp(&self, _: &Cert, _: &Cert) -> Result<Vec<u8>, FetchError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(FetchError::disabled("unexpected OCSP retrieval"))
    }
}
fn fixture(name: &str) -> PathBuf {
    let path = sigis_testdata::path(&["lanes", "r3-c", "validation", "rsa", name]);
    common::record_test_executable();
    common::record_file(&path, "fixture_snapshot");
    path
}
fn configuration(policy: Value) -> Value {
    json!({"validation-contexts":{"default":{
        "trust":fixture("root.der"), "trust-replace":true,
        "signer-key-usage-policy":policy
    }}})
}
fn args(config: &Path) -> Vec<String> {
    [
        "--config".into(),
        config.to_string_lossy().into_owned(),
        "sign".into(),
        "validate".into(),
        "--no-revocation-check".into(),
        "--validation-time".into(),
        "2020-08-01T00:00:00Z".into(),
        fixture("regular.pdf").to_string_lossy().into_owned(),
    ]
    .into()
}
fn native(args: &[String]) -> Output {
    let calls = Arc::new(CountedFetchers::default());
    let runtime = ValidationRuntime {
        now: Moment::parse_rfc3339("2020-08-01T00:00:00Z").unwrap(),
        fetchers: Fetchers {
            cert: Some(calls.clone()),
            crl: Some(calls.clone()),
            ocsp: Some(calls.clone()),
        },
        password: None,
        trusted_list_transport: None,
    };
    let output = sigis_cli::run_with_runtime(args, &PluginRegistry::default(), &runtime);
    assert_eq!(calls.0.load(Ordering::SeqCst), 0);
    output
}
fn oracle(args: &[String]) -> Value {
    let script = r#"import json,logging,sys
import pyhanko
pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
from click.testing import CliRunner
from pyhanko.cli import cli_root
import pyhanko.sign.validation as validation
from unittest.mock import patch
logging.disable(logging.CRITICAL)
with patch.object(validation, 'validate_pdf_signature', wraps=validation.validate_pdf_signature) as verify:
 result=CliRunner().invoke(cli_root,sys.argv[1:])
print(json.dumps({'code':result.exit_code,'output':result.output,'exception':str(result.exception) if result.exception else None,'exception_type':type(result.exception).__name__ if result.exception else None,'validation_calls':verify.call_count}))
"#;
    let output = Command::new(sigis_testdata::oracle::python().unwrap())
        .args(["-c", script])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn write_config(dir: &Path, value: &Value) -> PathBuf {
    let path = dir.join("config.yml");
    std::fs::write(&path, value.to_string()).unwrap();
    path
}
fn assert_rejected(output: Output, diagnostic: &str) {
    assert_eq!(output.code, 1, "{}{}", output.stdout, output.stderr);
    assert!(!output.stdout.contains("TRUSTED"), "{}", output.stdout);
    assert!(output.stdout.is_empty(), "{}", output.stdout);
    assert!(output.stderr.contains(diagnostic), "{}", output.stderr);
}

#[test]
fn unknown_nested_signer_policy_keys_reject_before_trust() {
    let dir = tempfile::tempdir().unwrap();
    for (key, value) in [
        ("key-usage-forbiden", json!("non_repudiation")),
        ("require-qualified-signature", json!(true)),
        ("match-all-key-usage", json!(true)),
    ] {
        for underscore in [false, true] {
            let key = if underscore {
                key.replace('-', "_")
            } else {
                key.into()
            };
            let mut policy = json!({});
            if key.starts_with("match") {
                policy["key-usage"] = json!(["non_repudiation", "crl_sign"]);
            }
            policy[&key] = value.clone();
            let path = write_config(dir.path(), &configuration(policy));
            let args = args(&path);
            let reference = oracle(&args);
            assert_eq!(reference["code"], json!(1), "{reference}");
            assert_eq!(reference["validation_calls"], json!(0), "{reference}");
            assert!(reference["exception"]
                .as_str()
                .unwrap()
                .contains("Unexpected key"));
            assert_rejected(native(&args), "Unexpected key");
        }
    }
}

#[test]
fn conflicting_policy_aliases_reject_before_trust() {
    let dir = tempfile::tempdir().unwrap();
    let nested = configuration(json!({
        "key-usage-forbidden":[], "key_usage_forbidden":["non_repudiation"]
    }));
    let mut outer = configuration(json!({"key-usage":["non_repudiation"]}));
    outer["validation-contexts"]["default"]["signer_key_usage_policy"] =
        json!({"key-usage-forbidden":["non_repudiation"]});
    for value in [nested, outer] {
        let path = write_config(dir.path(), &value);
        // Conflicting aliases are explicitly rejected even if the reference
        // resolves one spelling by precedence; this is a stricter requirement.
        assert_rejected(native(&args(&path)), "Conflicting");
    }
}

#[test]
fn quoted_match_all_policy_is_enforced_on_actual_signatures() {
    let dir = tempfile::tempdir().unwrap();
    for value in [json!("no"), json!("off")] {
        let path = write_config(
            dir.path(),
            &configuration(json!({
                "key-usage":["non_repudiation","crl_sign"],
                "match-all-key-usages":value
            })),
        );
        let args = args(&path);
        let reference = oracle(&args);
        // The upstream CLI drops match-all while its policy object keeps the
        // truthy quoted value. The native command enforces the mandatory value.
        assert_eq!(reference["code"], json!(0), "{reference}");
        assert!(reference["output"]
            .as_str()
            .unwrap()
            .contains("INTACT:TRUSTED"));
        assert_rejected(native(&args), "key usage");
    }
}

#[test]
fn valid_policy_remains_trusted() {
    let dir = tempfile::tempdir().unwrap();
    for underscore in [false, true] {
        let key = if underscore { "key_usage" } else { "key-usage" };
        let mut policy = json!({});
        policy[key] = json!(["non_repudiation"]);
        let path = write_config(dir.path(), &configuration(policy));
        let args = args(&path);
        let reference = oracle(&args);
        assert_eq!(reference["code"], json!(0), "{reference}");
        assert!(reference["output"]
            .as_str()
            .unwrap()
            .contains("INTACT:TRUSTED"));
        let output = native(&args);
        assert_eq!(output.code, 0, "{}{}", output.stdout, output.stderr);
        assert!(
            output.stdout.contains("INTACT:TRUSTED"),
            "{}",
            output.stdout
        );
    }
    let mut value = configuration(json!({"key-usage":["non_repudiation"]}));
    value["validation-contexts"]["default"]["signer-key-usage"] = json!(["crl_sign"]);
    let path = write_config(dir.path(), &value);
    let reference = oracle(&args(&path));
    assert_eq!(reference["code"], json!(0), "{reference}");
    let output = native(&args(&path));
    assert_eq!(output.code, 0, "{}{}", output.stdout, output.stderr);
    assert!(output.stdout.contains("INTACT:TRUSTED"));
}

#[test]
fn ambiguous_legacy_policy_precedence_rejects_before_trust() {
    let dir = tempfile::tempdir().unwrap();
    let canonical = configuration(json!({"key_usage":["non_repudiation"]}));
    let mut underscore = configuration(json!({"key-usage":["non_repudiation"]}));
    let default = &mut underscore["validation-contexts"]["default"];
    let policy = default
        .as_object_mut()
        .unwrap()
        .remove("signer-key-usage-policy")
        .unwrap();
    default["signer_key_usage_policy"] = policy;
    for mut value in [canonical, underscore] {
        value["validation-contexts"]["default"]["signer-key-usage"] = json!(["crl_sign"]);
        let path = write_config(dir.path(), &value);
        let args = args(&path);
        let reference = oracle(&args);
        assert_eq!(reference["code"], json!(1), "{reference}");
        assert!(!reference["output"]
            .as_str()
            .unwrap()
            .contains("INTACT:TRUSTED"));
        let output = native(&args);
        assert_eq!(output.code, 1, "{}{}", output.stdout, output.stderr);
        assert!(output.stdout.is_empty());
        assert!(
            output.stderr.to_lowercase().contains("alias"),
            "{}",
            output.stderr
        );
    }
}

#[test]
fn unsupported_outer_policy_aliases_reject_before_trust() {
    let dir = tempfile::tempdir().unwrap();
    for (key, value) in [
        ("signer_key_usage_policy", json!({"key-usage":[]})),
        ("signer_key_usage", json!([])),
        ("signer_extd_key_usage", json!([])),
    ] {
        let mut config = configuration(json!({}));
        let default = config["validation-contexts"]["default"]
            .as_object_mut()
            .unwrap();
        default.remove("signer-key-usage-policy");
        default.insert(key.into(), value);
        let path = write_config(dir.path(), &config);
        let args = args(&path);
        // These outer spellings are ignored by the pinned CLI. Explicitly
        // rejecting them avoids accepting a policy weaker than its defaults.
        let reference = oracle(&args);
        assert_eq!(reference["code"], json!(0), "{reference}");
        let output = native(&args);
        assert_eq!(output.code, 1, "{}{}", output.stdout, output.stderr);
        assert!(output.stdout.is_empty());
        assert!(
            output.stderr.to_lowercase().contains("alias"),
            "{}",
            output.stderr
        );
    }
}

#[test]
fn unsupported_root_trust_aliases_reject_before_trust() {
    let dir = tempfile::tempdir().unwrap();
    let canonical = configuration(json!({"key-usage":["non_repudiation"]}));
    let aliased_contexts = json!({
        "validation_contexts":canonical["validation-contexts"]
    });
    let aliased_default = json!({
        "validation-contexts":{
            "default":{},
            "custom":canonical["validation-contexts"]["default"]
        },
        "default_validation_context":"custom"
    });
    for value in [aliased_contexts, aliased_default] {
        let path = write_config(dir.path(), &value);
        let args = args(&path);
        let reference = oracle(&args);
        assert_eq!(reference["code"], json!(1), "{reference}");
        assert_eq!(reference["validation_calls"], json!(1), "{reference}");
        assert!(reference["output"]
            .as_str()
            .unwrap()
            .contains("INTACT:UNTRUSTED"));
        let output = native(&args);
        assert_eq!(output.code, 1, "{}{}", output.stdout, output.stderr);
        assert!(output.stdout.is_empty());
        assert!(
            output.stderr.to_lowercase().contains("alias"),
            "{}",
            output.stderr
        );
    }
}

#[test]
fn unsupported_yaml_policy_numbers_reject_before_trust() {
    let dir = tempfile::tempdir().unwrap();
    for field in ["match-all-key-usages", "explicit-extd-key-usage-required"] {
        for literal in [".nan", ".inf", "0o0", "0e0"] {
            for underscore in [false, true] {
                let name = if underscore {
                    field.replace('-', "_")
                } else {
                    field.into()
                };
                let requirements = if field == "match-all-key-usages" {
                    "key-usage: [non_repudiation, crl_sign]"
                } else {
                    "extd-key-usage: code_signing"
                };
                let yaml = format!(
                    "validation-contexts:\n  default:\n    trust: {}\n    trust-replace: true\n    signer-key-usage-policy:\n      {requirements}\n      {name}: {literal}\n",
                    fixture("root.der").display()
                );
                let path = dir.path().join("numeric.yml");
                std::fs::write(&path, yaml).unwrap();
                let args = args(&path);
                let reference = oracle(&args);
                // Both numeric values and YAML-1.1 string interpretations are
                // truthy in the policy object. The CLI still drops match-all;
                // its default EKU requirement rejects the other cases.
                assert_eq!(
                    reference["code"],
                    json!(if field == "match-all-key-usages" {
                        0
                    } else {
                        1
                    }),
                    "{reference}"
                );
                let output = native(&args);
                assert_eq!(
                    output.code, 1,
                    "{field}/{literal}: {}{}",
                    output.stdout, output.stderr
                );
                assert!(output.stdout.is_empty());
                assert!(output.stderr.contains("YAML"), "{}", output.stderr);
            }
        }
    }
}

#[test]
fn unsupported_global_policy_aliases_reject_before_trust() {
    let dir = tempfile::tempdir().unwrap();
    for (name, value) in [
        ("time_tolerance", json!(3600)),
        ("retroactive_revinfo", json!(true)),
    ] {
        let mut config = configuration(json!({"key-usage":["non_repudiation"]}));
        config[name] = value;
        let path = write_config(dir.path(), &config);
        let args = args(&path);
        let reference = oracle(&args);
        // The oracle ignores these unsupported global spellings. This valid
        // fixture does not demonstrate an actual timing/revocation fail-open.
        assert_eq!(reference["code"], json!(0), "{reference}");
        let output = native(&args);
        assert_eq!(output.code, 1, "{}{}", output.stdout, output.stderr);
        assert!(output.stdout.is_empty());
        assert!(output.stderr.to_lowercase().contains("alias"));
    }
}

#[test]
fn unsupported_context_policy_aliases_reject_before_trust() {
    let dir = tempfile::tempdir().unwrap();
    for (name, value) in [
        ("time_tolerance", json!(3600)),
        ("retroactive_revinfo", json!(true)),
        ("other_certs", json!(fixture("interm.der"))),
    ] {
        let mut config = configuration(json!({"key-usage":["non_repudiation"]}));
        config["validation-contexts"]["default"][name] = value;
        let path = write_config(dir.path(), &config);
        let args = args(&path);
        let reference = oracle(&args);
        assert_eq!(reference["code"], json!(0), "{reference}");
        let output = native(&args);
        assert_eq!(output.code, 1, "{}{}", output.stdout, output.stderr);
        assert!(output.stdout.is_empty());
        assert!(output.stderr.to_lowercase().contains("alias"));
    }
}

#[test]
fn raw_trust_context_aliases_require_canonical_spelling() {
    for (name, value) in [
        ("trust-replace", json!(true)),
        ("other-certs", json!([])),
        ("time-tolerance", json!(3600)),
        ("retroactive-revinfo", json!(true)),
        ("eutl-force-redownload", json!(true)),
        ("eutl-lotl-url", json!("http://example.invalid/lotl")),
        ("lotl-tlso-certs", json!("unused.pem")),
        ("eutl-territories", json!("all")),
        ("revocation-policy", json!("none")),
    ] {
        let alias = name.replace('-', "_");
        let mut config = configuration(json!({"key-usage":["non_repudiation"]}));
        config["validation-contexts"]["default"]
            .as_object_mut()
            .unwrap()
            .remove(name);
        config["validation-contexts"]["default"][&alias] = value;
        let error = sigis_cli::config::CliConfig::parse(&config.to_string()).unwrap_err();
        assert!(error.to_lowercase().contains("alias"), "{name}: {error}");
    }
}

#[test]
fn nonstring_context_names_cannot_select_trusted_configuration() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["true", "7"] {
        for quoted in [false, true] {
            let key = if quoted {
                format!("\"{name}\"")
            } else {
                name.into()
            };
            let yaml = format!(
                "validation-contexts:\n  default: {{}}\n  {key}:\n    trust: {}\n    trust-replace: true\n",
                fixture("root.der").display()
            );
            let path = dir.path().join("names.yml");
            std::fs::write(&path, yaml).unwrap();
            let mut args = args(&path);
            let index = args.len() - 1;
            args.splice(index..index, ["--validation-context".into(), name.into()]);
            let reference = oracle(&args);
            let output = native(&args);
            if quoted {
                assert_eq!(reference["code"], json!(0), "{reference}");
                assert_eq!(reference["validation_calls"], json!(1));
                assert_eq!(output.code, 0, "{}{}", output.stdout, output.stderr);
                assert!(output.stdout.contains("INTACT:TRUSTED"));
            } else {
                assert_eq!(reference["code"], json!(1), "{reference}");
                assert_eq!(reference["validation_calls"], json!(0));
                assert_eq!(output.code, 1, "{}{}", output.stdout, output.stderr);
                assert!(output.stdout.is_empty());
                assert!(output.stderr.contains("mapping keys"), "{}", output.stderr);
            }
        }
    }
}

#[test]
fn implicit_legacy_names_cannot_select_trusted_configuration() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["007", "2020-01-01", "1:20"] {
        for quoted in [false, true] {
            let key = if quoted {
                format!("\"{name}\"")
            } else {
                name.into()
            };
            let yaml = format!(
                "validation-contexts:\n  default: {{}}\n  {key}:\n    trust: {}\n    trust-replace: true\n",
                fixture("root.der").display()
            );
            let path = dir.path().join("legacy-names.yml");
            std::fs::write(&path, yaml).unwrap();
            let mut args = args(&path);
            let index = args.len() - 1;
            args.splice(index..index, ["--validation-context".into(), name.into()]);
            let reference = oracle(&args);
            let output = native(&args);
            if quoted {
                assert_eq!(reference["code"], json!(0), "{reference}");
                assert_eq!(reference["validation_calls"], json!(1));
                assert_eq!(output.code, 0, "{}{}", output.stdout, output.stderr);
                assert!(output.stdout.contains("INTACT:TRUSTED"));
            } else {
                assert_eq!(reference["code"], json!(1), "{reference}");
                assert_eq!(reference["validation_calls"], json!(0));
                assert_eq!(output.code, 1, "{}{}", output.stdout, output.stderr);
                assert!(output.stdout.is_empty());
                assert!(output.stderr.contains("YAML"), "{}", output.stderr);
            }
        }
    }
}

#[test]
fn reserved_implicit_values_cannot_bypass_configuration_rejection() {
    let dir = tempfile::tempdir().unwrap();
    for value in ["<<", "="] {
        for quoted in [false, true] {
            let token = if quoted {
                format!("'{value}'")
            } else {
                value.into()
            };
            let yaml = format!(
                "metadata: {token}\nvalidation-contexts:\n  default:\n    trust: {}\n    trust-replace: true\n",
                fixture("root.der").display()
            );
            let path = dir.path().join("reserved.yml");
            std::fs::write(&path, yaml).unwrap();
            let args = args(&path);
            let reference = oracle(&args);
            let output = native(&args);
            if quoted {
                assert_eq!(reference["code"], json!(0), "{reference}");
                assert_eq!(output.code, 0, "{}{}", output.stdout, output.stderr);
                assert!(output.stdout.contains("INTACT:TRUSTED"));
            } else {
                assert_eq!(reference["code"], json!(1), "{reference}");
                assert_eq!(reference["validation_calls"], json!(0));
                assert_eq!(output.code, 1, "{}{}", output.stdout, output.stderr);
                assert!(output.stdout.is_empty());
                assert!(output.stderr.contains("YAML"), "{}", output.stderr);
            }
        }
    }
}

#[test]
fn quoted_usage_flags_reject_real_signature_in_preserved_cli() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = std::fs::read(fixture("regular.pdf")).unwrap();
    let pdf = sigis_pdf::PdfFile::parse(&bytes).unwrap();
    let signatures = pdf.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let cms = sigis_pades::cms_from_contents(&signatures[0].contents).unwrap();
    let signed = sigis_cms::SignedData::from_der(cms).unwrap();
    let cert = sigis_cms::signed_data::extract_certificate_info(&signed)
        .unwrap()
        .signer_cert;
    assert!(sigis_pki_core::key_usage::cert_extended_key_usages(&cert).is_none());
    assert_eq!(
        cert.sha256(),
        Cert::from_der(&std::fs::read(fixture("signer1.der")).unwrap())
            .unwrap()
            .sha256()
    );
    let subprocess = |values: &[String]| {
        let result = Command::new(common::cli()).args(values).output().unwrap();
        Output {
            code: result.status.code().expect("native CLI exited normally"),
            stdout: String::from_utf8(result.stdout).unwrap(),
            stderr: String::from_utf8(result.stderr).unwrap(),
        }
    };
    for flag in ["match-all-key-usages", "explicit-extd-key-usage-required"] {
        for literal in ["'no'", "'off'", "\"no\"", "\"off\""] {
            let requirements = if flag == "match-all-key-usages" {
                "key-usage: [non_repudiation, crl_sign]"
            } else {
                "key-usage: [non_repudiation]\n      extd-key-usage: [code_signing]"
            };
            let yaml = format!(
                "validation-contexts:\n  default:\n    trust: {}\n    trust-replace: true\n    signer-key-usage-policy:\n      {requirements}\n      {flag}: {literal}\n",
                json!(fixture("root.der"))
            );
            let path = dir.path().join("quoted-policy.yml");
            std::fs::write(&path, &yaml).unwrap();
            let policy = sigis_cli::config::CliConfig::parse(&yaml)
                .unwrap()
                .key_usages(None)
                .unwrap();
            let mut requirement = sigis_cli::usage::key_usage_constraints(&policy);
            assert!(requirement.validate(&cert).is_err(), "{yaml}");
            if flag == "match-all-key-usages" {
                assert!(requirement.match_all_key_usages, "{yaml}");
                requirement.match_all_key_usages = false;
            } else {
                assert!(requirement.explicit_extd_key_usage_required, "{yaml}");
                requirement.explicit_extd_key_usage_required = false;
            }
            // The same actual signer passes only after this mandatory flag is
            // explicitly relaxed. This control is a certificate-policy check,
            // not a claim about the final reference CLI's class-default merge.
            assert!(requirement.validate(&cert).is_ok(), "{yaml}");
            let values = args(&path);
            let reference = oracle(&values);
            assert_eq!(reference["validation_calls"], json!(1), "{reference}");
            if flag == "match-all-key-usages" {
                // The reference final CLI drops match-all; keep its actual
                // outcome rather than substituting its stricter policy object.
                assert_eq!(reference["code"], json!(0), "{reference}");
                assert!(reference["output"]
                    .as_str()
                    .unwrap()
                    .contains("INTACT:TRUSTED"));
            } else {
                assert_eq!(reference["code"], json!(1), "{reference}");
                assert!(!reference["output"]
                    .as_str()
                    .unwrap()
                    .contains("INTACT:TRUSTED"));
            }
            assert_rejected(native(&values), "key usage");
            assert_rejected(subprocess(&values), "key usage");
        }
    }
    // A real trusted control rules out blanket configuration or PDF rejection.
    let path = write_config(
        dir.path(),
        &configuration(json!({"key-usage":["non_repudiation"]})),
    );
    let values = args(&path);
    let reference = oracle(&values);
    assert_eq!(reference["validation_calls"], json!(1), "{reference}");
    assert_eq!(reference["code"], json!(0), "{reference}");
    assert!(reference["output"]
        .as_str()
        .unwrap()
        .contains("INTACT:TRUSTED"));
    for result in [native(&values), subprocess(&values)] {
        assert_eq!(result.code, 0, "{}{}", result.stdout, result.stderr);
        assert!(
            result.stdout.contains("INTACT:TRUSTED"),
            "{}",
            result.stdout
        );
    }
}

fn separator_spellings(key: &str) -> Vec<String> {
    let separators = key.bytes().filter(|&byte| byte == b'-').count();
    (0..1usize << separators)
        .map(|mask| {
            let mut index = 0;
            key.chars()
                .map(|character| {
                    if character != '-' {
                        return character;
                    }
                    let character = if mask & (1 << index) == 0 { '-' } else { '_' };
                    index += 1;
                    character
                })
                .collect()
        })
        .collect()
}

fn preserved_cli(values: &[String]) -> Output {
    let result = Command::new(common::cli()).args(values).output().unwrap();
    Output {
        code: result.status.code().expect("native CLI exited normally"),
        stdout: String::from_utf8(result.stdout).unwrap(),
        stderr: String::from_utf8(result.stderr).unwrap(),
    }
}

#[test]
fn unknown_policy_spellings_reject_before_fetch_and_preserved_cli_trust() {
    let dir = tempfile::tempdir().unwrap();
    let mut cases = 0;
    for (key, value) in [
        ("key-usage-forbiden", json!("non_repudiation")),
        ("require-qualified-signature", json!(true)),
        ("match-all-key-usage", json!(true)),
    ] {
        for spelling in separator_spellings(key) {
            cases += 1;
            let mut policy = json!({});
            if key == "match-all-key-usage" {
                policy["key-usage"] = json!(["non_repudiation", "crl_sign"]);
            }
            policy[&spelling] = value.clone();
            let path = write_config(dir.path(), &configuration(policy));
            let values = args(&path);
            let reference = oracle(&values);
            let expected =
                format!("Unexpected key in configuration for KeyUsageConstraints: {key}.");
            assert_eq!(reference["code"], json!(1), "{reference}");
            assert_eq!(
                reference["exception_type"], "ConfigurationError",
                "{reference}"
            );
            assert_eq!(reference["exception"], expected, "{reference}");
            assert_eq!(reference["validation_calls"], json!(0), "{reference}");
            assert!(!reference["output"]
                .as_str()
                .unwrap()
                .contains("INTACT:TRUSTED"));
            assert_rejected(native(&values), &expected);
            assert_rejected(preserved_cli(&values), &expected);

            // A missing intermediate and mandatory revocation would require
            // issuer/revinfo retrieval if the schema error were discarded.
            // The injected fetchers must remain untouched, and the exact
            // configuration error must win over any trust/network failure.
            let mut fetch_required = values.clone();
            let index = fetch_required
                .iter()
                .position(|argument| argument == "--no-revocation-check")
                .unwrap();
            fetch_required[index] = "--force-revinfo".into();
            *fetch_required.last_mut().unwrap() = fixture("missing-intermediate.pdf")
                .to_string_lossy()
                .into_owned();
            assert_rejected(native(&fetch_required), &expected);
        }
    }
    assert_eq!(cases, 16);
}

#[test]
fn normalized_policy_conflicts_reject_for_every_separator_and_source_order() {
    let dir = tempfile::tempdir().unwrap();
    let mut cases = 0;
    for (key, left, right) in [
        (
            "key-usage",
            json!(["non_repudiation"]),
            json!(["digital_signature"]),
        ),
        ("key-usage-forbidden", json!(["non_repudiation"]), json!([])),
        ("extd-key-usage", json!(["code_signing"]), json!([])),
        ("match-all-key-usages", json!(true), json!(false)),
        (
            "explicit-extd-key-usage-required",
            json!(true),
            json!(false),
        ),
    ] {
        for alias in separator_spellings(key).into_iter().skip(1) {
            // Equal aliases stay valid at the policy-object boundary. This
            // is not a claim that every such policy trusts this certificate.
            let mut identical = json!({});
            identical[key] = left.clone();
            identical[&alias] = left.clone();
            assert!(
                sigis_cli::config::CliConfig::parse(&configuration(identical).to_string())
                    .unwrap()
                    .key_usages(None)
                    .is_ok()
            );
            for reverse in [false, true] {
                cases += 1;
                let mut pairs = [(key, &left), (alias.as_str(), &right)];
                if reverse {
                    pairs.reverse();
                }
                let fragment = pairs
                    .iter()
                    .map(|(key, value)| format!("      {key}: {value}\n"))
                    .collect::<String>();
                let yaml = format!(
                    "validation-contexts:\n  default:\n    trust: {}\n    trust-replace: true\n    signer-key-usage-policy:\n{fragment}",
                    json!(fixture("root.der"))
                );
                let path = dir.path().join("alias-conflict.yml");
                std::fs::write(&path, &yaml).unwrap();
                let error = sigis_cli::config::CliConfig::parse(&yaml)
                    .unwrap()
                    .key_usages(None)
                    .unwrap_err();
                assert!(error.contains("Conflicting"), "{yaml}: {error}");
                assert!(error.contains(key) && error.contains(&alias), "{error}");
                let values = args(&path);
                assert_rejected(native(&values), "Conflicting");
                assert_rejected(preserved_cli(&values), "Conflicting");
                // Pinned Python sometimes chooses a conflicting alias by
                // precedence. This explicitly required native rejection is
                // stricter; it is not asserted as universal oracle parity.
            }
        }
    }
    assert_eq!(cases, 58);
}
