//! Exact CLI assertions from pyHanko 0.38.1 `test_cli_plugins.py` (MIT).
use sigis_cli::{plugins::*, run_with_registry, Output};

const DUMMY: &str = "tests.test_cli_plugins:DummyTestPlugin";
const UNAVAILABLE: &str = "tests.test_cli_plugins:UnavailablePlugin";
fn registry() -> PluginRegistry {
    let mut r = PluginRegistry::default();
    r.register(PluginDefinition::new(
        "manual-dummy",
        "manual test plugin",
        PluginHandler::Pkcs12,
    ));
    r.register_endpoint(
        DUMMY,
        PluginDefinition::new("test-dummy", "this is a test plugin", PluginHandler::Pkcs12),
    );
    r.register_endpoint(
        UNAVAILABLE,
        PluginDefinition::new(
            "unavailable-plugin",
            "unavailable plugin",
            PluginHandler::Pkcs12,
        )
        .unavailable("plugin always unavailable"),
    );
    r
}
fn invoke(config: Option<&str>, no_plugins: bool, command: &[&str]) -> Output {
    let d = tempfile::tempdir().unwrap();
    let mut args = vec![];
    if let Some(s) = config {
        let p = d.path().join("config.yml");
        std::fs::write(&p, s).unwrap();
        args.extend(["--config".into(), p.to_str().unwrap().into()]);
    }
    if no_plugins {
        args.push("--no-plugins".into());
    }
    args.extend(command.iter().map(|s| s.to_string()));
    run_with_registry(&args, &registry())
}
fn text(o: &Output) -> String {
    format!("{}{}", o.stdout, o.stderr)
}
fn identity(config: Option<&str>) -> Output {
    invoke(
        config,
        false,
        &[
            "sign",
            "addsig",
            "--field",
            "Sig1",
            "identity",
            "test",
            "input.pdf",
            "output.pdf",
        ],
    )
}

#[test]
fn test_load_plugins_from_config() {
    let c = format!("plugins: ['{DUMMY}']");
    let r = invoke(Some(&c), false, &["sign", "addsig", "--help"]);
    assert_eq!(r.code, 0, "{}", text(&r));
    assert!(text(&r).contains("test-dummy"));
    assert!(text(&r).contains("manual-dummy"));
    let r = invoke(Some(&c), false, &["sign", "addsig", "test-dummy", "--help"]);
    assert_eq!(r.code, 0, "{}", text(&r));
}
#[test]
fn test_gracefully_handle_dupe_plugins() {
    let c = format!("plugins: ['{DUMMY}','{DUMMY}']");
    let r = invoke(Some(&c), false, &["sign", "addsig", "test-dummy", "--help"]);
    assert_eq!(r.code, 0, "{}", text(&r));
}
#[test]
fn test_plugin_must_be_class() {
    let r = invoke(
        Some("plugins: [tests]"),
        false,
        &["sign", "addsig", "--help"],
    );
    assert_eq!(r.code, 0, "{}", text(&r));
    assert!(text(&r).contains("Plugins must be defined as"));
    assert!(!text(&r).contains("test-dummy"));
}
#[test]
fn test_disable_non_default_plugins() {
    let c = format!("plugins: ['{DUMMY}']");
    let r = invoke(Some(&c), true, &["sign", "addsig", "--help"]);
    assert_eq!(r.code, 0, "{}", text(&r));
    assert!(!text(&r).contains("test-dummy"));
    assert!(text(&r).contains("manual-dummy"));
}
#[test]
fn test_show_unavailable_plugins() {
    let c = format!("plugins: ['{UNAVAILABLE}']");
    let r = invoke(Some(&c), false, &["sign", "addsig", "--help"]);
    assert_eq!(r.code, 0, "{}", text(&r));
    assert!(text(&r).contains("[unavailable]"));
}
#[test]
fn test_trigger_unavailable_plugin() {
    let c = format!("plugins: ['{UNAVAILABLE}']");
    let r = invoke(Some(&c), false, &["sign", "addsig", "unavailable-plugin"]);
    assert_eq!(r.code, 1, "{}", text(&r));
    assert!(text(&r).contains("plugin always unavailable"));
}
#[test]
fn test_identity_setup_with_too_few_parameters() {
    let r = identity(Some(
        "identities:\n  test:\n    plugin: pemder\n    parameters: {}",
    ));
    assert_eq!(r.code, 1, "{}", text(&r));
    assert!(text(&r).contains("option must be provided"));
}
#[test]
fn test_identity_setup_with_unknown_parameters() {
    let r=identity(Some("identities:\n  test:\n    plugin: pemder\n    parameters:\n      key: blah.key\n      cert: blah.cert\n      no-pass: true\n      zzz: blah"));
    assert_eq!(r.code, 1, "{}", text(&r));
    assert!(text(&r).contains("Parameter 'zzz' defined by 'test' not known"));
}
#[test]
fn test_identity_setup_with_unknown_plugin() {
    let r = identity(Some(
        "identities:\n  test:\n    plugin: zzz\n    parameters: {}",
    ));
    assert_eq!(r.code, 1, "{}", text(&r));
    assert!(text(&r).contains("Plugin 'zzz'"));
}
#[test]
fn test_unknown_identity() {
    let r = identity(Some("identities: {}"));
    assert_eq!(r.code, 1, "{}", text(&r));
    assert!(text(&r).contains("Identity 'test' not found"));
}
#[test]
fn test_identity_without_config() {
    let r = identity(None);
    assert_eq!(r.code, 1, "{}", text(&r));
    assert!(text(&r).contains("Identity command requires a config file"));
}
