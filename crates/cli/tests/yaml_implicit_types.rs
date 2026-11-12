//! Supplemental schema-type checks before the YAML-to-JSON boundary.
use sigis_cli::config::CliConfig;

#[test]
fn ambiguous_legacy_numeric_scalars_require_explicit_strings() {
    for value in ["00", "007", "0_0", "0:00.0", "1:20"] {
        let yaml = format!(
            "validation-contexts:\n  default:\n    signer-key-usage-policy:\n      match-all-key-usages: {value}\n"
        );
        let error = CliConfig::parse(&yaml).unwrap_err();
        assert!(error.contains("YAML"), "{value}: {error}");
        let quoted = CliConfig::parse(&yaml.replace(value, &format!("'{value}'"))).unwrap();
        assert!(quoted.key_usages(None).unwrap().match_all_key_usages);
    }
}

#[test]
fn implicit_timestamps_require_explicit_strings() {
    for value in ["2020-01-01", "2020-01-01T00:00:00Z"] {
        let yaml = format!("metadata: {value}\n");
        let error = CliConfig::parse(&yaml).unwrap_err();
        assert!(error.contains("YAML"), "{value}: {error}");
        assert!(CliConfig::parse(&format!("metadata: '{value}'\n")).is_ok());
    }
}

#[test]
fn reserved_implicit_values_require_explicit_strings() {
    for value in ["<<", "="] {
        assert!(CliConfig::parse(&format!("metadata: {value}\n")).is_err());
        assert!(CliConfig::parse(&format!("metadata: '{value}'\n")).is_ok());
    }
}
