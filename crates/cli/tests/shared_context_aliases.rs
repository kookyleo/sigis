//! Supplemental effective-context alias regressions using accepted public APIs.
//! No original-function credit. Missing-material controls prove schema priority,
//! not signing success or a trusted certificate verdict.
use serde_json::{json, Value};
use sigis_cli::{config::CliConfig, pkcs12_signing, runtime::ValidationRuntime, validation};
use sigis_pki_certvalidator::policy::RevocationCheckingPolicy;
use sigis_pki_core::{fetch::Fetchers, time::Moment};
use std::{fs, io::ErrorKind, net::TcpListener, path::PathBuf, time::Duration};

const INPUT: &[u8] = b"Input sentinel: schema checks must precede PDF parsing.\n";
const OUTPUT: &[u8] = b"Output sentinel: refused requests must preserve this file.\n";
const CONFLICT: &str = "Conflicting configuration aliases";
const UNSUPPORTED: &str = "Unsupported configuration alias";

fn runtime() -> ValidationRuntime {
    ValidationRuntime {
        now: Moment::parse_rfc3339("2020-08-01T00:00:00Z").unwrap(),
        fetchers: Fetchers::none(),
        password: Some("Must not prompt before rejecting schema".into()),
        trusted_list_transport: None,
    }
}

fn conflicting() -> Vec<Value> {
    vec![
        json!({"time-tolerance":30,"time_tolerance":0}),
        json!({"trust-replace":false,"trust_replace":true}),
        json!({"retroactive-revinfo":true,"retroactive_revinfo":false}),
        json!({"other-certs":[],"other_certs":["mandatory-missing.pem"]}),
    ]
}

fn underscore_only() -> Vec<Value> {
    vec![
        json!({"time_tolerance":0}),
        json!({"trust_replace":true}),
        json!({"retroactive_revinfo":true}),
        json!({"other_certs":["mandatory-missing.pem"]}),
    ]
}

fn equal_aliases() -> Value {
    json!({
        "time-tolerance":30,"time_tolerance":30,
        "trust-replace":true,"trust_replace":true,
        "retroactive-revinfo":false,"retroactive_revinfo":false,
        "other-certs":[],"other_certs":[],
    })
}

fn selected_name(named: bool) -> Option<&'static str> {
    named.then_some("target")
}

fn mutated(context: Value, named: bool) -> CliConfig {
    let mut config = CliConfig::parse("{}").unwrap();
    let raw = config.raw_config.clone();
    config.validation_contexts.insert("target".into(), context);
    config
        .validation_contexts
        .insert("unselected".into(), json!({"time-tolerance":99}));
    config.default_validation_context = if named { "unselected" } else { "target" }.into();
    assert_eq!(config.raw_config, raw);
    assert!(config.raw_config.get("validation-contexts").is_none());
    config
}

fn parsed(context: Value, named: bool) -> CliConfig {
    let value = json!({
        "default-validation-context":if named { "unselected" } else { "target" },
        "validation-contexts":{
            "target":context,"unselected":{"time-tolerance":99},
        },
    });
    CliConfig::parse(&serde_yaml::to_string(&value).unwrap()).unwrap()
}

fn assert_schema_error(error: &str, expected: &str) {
    assert!(error.contains(expected), "expected {expected}, got {error}");
    for material_error in [
        "Could not read",
        "Could not load key material",
        "I/O problem while reading certificate",
        "Failed to read PDF",
    ] {
        assert!(
            !error.contains(material_error),
            "schema must precede I/O: {error}"
        );
    }
}

struct Case {
    dir: tempfile::TempDir,
    input: PathBuf,
    output: PathBuf,
    missing_pfx: PathBuf,
    explicit_trust: PathBuf,
    missing_pdf: PathBuf,
    endpoint: TcpListener,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.pdf");
        let output = dir.path().join("output.pdf");
        fs::write(&input, INPUT).unwrap();
        fs::write(&output, OUTPUT).unwrap();
        let endpoint = TcpListener::bind("127.0.0.1:0").unwrap();
        endpoint.set_nonblocking(true).unwrap();
        Self {
            missing_pfx: dir.path().join("missing.p12"),
            explicit_trust: dir.path().join("missing-explicit-trust.der"),
            missing_pdf: dir.path().join("missing.pdf"),
            dir,
            input,
            output,
            endpoint,
        }
    }

    fn p12_args(&self, named: bool) -> Vec<String> {
        let mut args = vec![
            "--field".into(),
            "Sig1".into(),
            "--no-pass".into(),
            "--timestamp-url".into(),
            format!(
                "http://{}/must-not-connect",
                self.endpoint.local_addr().unwrap()
            ),
        ];
        if named {
            args.extend(["--validation-context".into(), "target".into()]);
        }
        args.extend([
            "pkcs12".into(),
            self.input.display().to_string(),
            self.output.display().to_string(),
            self.missing_pfx.display().to_string(),
        ]);
        args
    }

    fn ordinary_args(&self) -> Vec<String> {
        // Explicit CLI trust selects its own profile. A named-context option
        // would be an illegal combination and mask the shared guard.
        vec![
            "--trust".into(),
            self.explicit_trust.display().to_string(),
            "--trust-replace".into(),
            self.missing_pdf.display().to_string(),
        ]
    }

    fn preserved(&self) {
        assert_eq!(fs::read(&self.input).unwrap().as_slice(), INPUT);
        assert_eq!(fs::read(&self.output).unwrap().as_slice(), OUTPUT);
        assert!(!self.missing_pfx.exists());
        assert!(!self.explicit_trust.exists());
        assert!(!self.missing_pdf.exists());
    }

    fn timestamp_endpoint_quiet(&self) {
        assert_eq!(
            self.endpoint.accept().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
    }
}

#[test]
fn factory_rejects_conflicting_effective_aliases_before_material_io() {
    for named in [false, true] {
        for context in conflicting() {
            let config = mutated(context, named);
            let raw = config.raw_config.clone();
            let error =
                validation::context_from_config(Some(&config), selected_name(named), &runtime())
                    .expect_err("Conflicting effective requirements must reject");
            assert_schema_error(&error, CONFLICT);
            assert_eq!(config.raw_config, raw);
        }
    }
}

#[test]
fn factory_rejects_underscore_only_effective_aliases_like_parse() {
    for named in [false, true] {
        for context in underscore_only() {
            let value = json!({"validation-contexts":{"target":context.clone()}});
            let parse_error =
                CliConfig::parse(&serde_yaml::to_string(&value).unwrap()).unwrap_err();
            assert_schema_error(&parse_error, UNSUPPORTED);
            let config = mutated(context, named);
            let raw = config.raw_config.clone();
            let error =
                validation::context_from_config(Some(&config), selected_name(named), &runtime())
                    .expect_err("Effective input must retain the accepted parser's alias rules");
            assert_schema_error(&error, UNSUPPORTED);
            assert_eq!(config.raw_config, raw);
        }
    }
}

#[test]
fn equal_aliases_accepted_by_parse_preserve_factory_state_and_selection() {
    for named in [false, true] {
        let config = parsed(equal_aliases(), named);
        let raw = config.raw_config.clone();
        let runtime = runtime();
        let context =
            validation::context_from_config(Some(&config), selected_name(named), &runtime)
                .expect("Identical parser-approved aliases are not conflicting requirements");
        assert_eq!(context.timing().validation_time, runtime.now);
        assert_eq!(context.timing().time_tolerance, Duration::from_secs(30));
        assert!(context.fetchers().is_empty());
        assert!(runtime.fetchers.is_empty());
        assert!(context.trust_anchors().is_empty());
        assert!(context.other_certs().is_empty());
        assert!(!context.revinfo_policy().retroactive_revinfo);
        assert_eq!(
            context.revinfo_policy().revocation_checking_policy,
            RevocationCheckingPolicy::from_legacy("hard-fail").unwrap(),
        );
        assert_eq!(config.raw_config, raw);
    }
}

#[test]
fn pkcs12_rejects_effective_aliases_before_missing_key_or_timestamp_io() {
    for named in [false, true] {
        for (expected, contexts) in [(CONFLICT, conflicting()), (UNSUPPORTED, underscore_only())] {
            for context in contexts {
                let case = Case::new();
                let config = mutated(context, named);
                let raw = config.raw_config.clone();
                let error = pkcs12_signing::run_with_runtime(
                    &case.p12_args(named),
                    Some(&config),
                    &runtime(),
                )
                .expect_err("Ambiguous/unsupported effective requirements must reject");
                assert_schema_error(&error, expected);
                assert_eq!(config.raw_config, raw);
                case.preserved();
                case.timestamp_endpoint_quiet();
            }
        }
    }
}

#[test]
fn ordinary_explicit_trust_rejects_default_context_aliases_before_cert_or_pdf_io() {
    for (expected, contexts) in [(CONFLICT, conflicting()), (UNSUPPORTED, underscore_only())] {
        for context in contexts {
            let case = Case::new();
            let config = mutated(context, false);
            let raw = config.raw_config.clone();
            let error = validation::run_with_runtime(
                &case.ordinary_args(),
                Some(&config),
                false,
                &runtime(),
            )
            .expect_err("Explicit trust must not bypass effective-context schema validation");
            assert_schema_error(&error, expected);
            assert_eq!(config.raw_config, raw);
            case.preserved();
        }
    }
}

#[test]
fn equal_aliases_advance_to_expected_material_io_without_claiming_trust() {
    for named in [false, true] {
        let case = Case::new();
        let config = parsed(equal_aliases(), named);
        let raw = config.raw_config.clone();
        let error =
            pkcs12_signing::run_with_runtime(&case.p12_args(named), Some(&config), &runtime())
                .expect_err("Missing PFX is an intentional positive-schema I/O control");
        assert!(error.contains("Could not read"), "{error}");
        assert!(
            error.contains(case.missing_pfx.to_str().unwrap()),
            "{error}"
        );
        assert!(
            !error.contains(CONFLICT) && !error.contains(UNSUPPORTED),
            "{error}"
        );
        assert_eq!(config.raw_config, raw);
        case.preserved();
        case.timestamp_endpoint_quiet();
    }
    let case = Case::new();
    let mut context = equal_aliases();
    let ignored = case.dir.path().join("ignored-default-other.der");
    context["other-certs"] = json!([ignored.display().to_string()]);
    context["other_certs"] = context["other-certs"].clone();
    let config = parsed(context, false);
    let raw = config.raw_config.clone();
    let error =
        validation::run_with_runtime(&case.ordinary_args(), Some(&config), false, &runtime())
            .expect_err(
                "Missing explicit trust cert is an intentional positive-schema I/O control",
            );
    assert!(
        error.contains("I/O problem while reading certificate"),
        "{error}"
    );
    assert!(
        error.contains(case.explicit_trust.to_str().unwrap()),
        "{error}"
    );
    assert!(!error.contains(ignored.to_str().unwrap()), "{error}");
    assert_eq!(config.raw_config, raw);
    case.preserved();
}
