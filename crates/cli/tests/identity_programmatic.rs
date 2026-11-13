//! Exact programmatic original callback, four architectures; same native dispatch.
#[path = "common/identity_cases.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;
use sigis_cli::{config::CliConfig, plugins::PluginRegistry, runtime::ValidationRuntime};
#[test]
fn test_cli_addsig_pemder_with_identity_programmatically() {
    for arch in cases::ARCHES {
        let case = cases::Case::new(arch, "programmatic");
        let cfg = CliConfig::parse(&serde_yaml::to_string(&case.config_value()).unwrap()).unwrap();
        let runtime = ValidationRuntime {
            now: sigis_pki_core::time::Moment::parse_rfc3339("2020-08-01T00:00:00+08:00").unwrap(),
            fetchers: sigis_pki_core::fetch::Fetchers::none(),
            password: None,
            trusted_list_transport: None,
        };
        case.record_programmatic_begin(&cfg);
        let result = sigis_cli::identity_signing::run_with_runtime(
            &case.args()[2..],
            Some(&cfg),
            &PluginRegistry::default(),
            &runtime,
        );
        case.record_programmatic(&result, &cfg);
        result.unwrap();
        let reference = case.reference();
        assert_eq!(reference["code"], 0);
        case.verify();
    }
}
