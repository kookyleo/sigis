//! Fourteen original ordinary EUTL CLI functions, including every parameter.
use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime};
use sigis_pki_core::{
    cert::Cert,
    errors::FetchError,
    fetch::{CrlFetcher, Fetchers},
    time::Moment,
};
use sigis_pki_fetch::{transport::HttpRequest, HttpResponse, HttpTransport, TransportError};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug)]
struct PkiReplay {
    crls: Vec<Vec<u8>>,
}
impl CrlFetcher for PkiReplay {
    fn fetch_crls(&self, _cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        Ok(self.crls.clone())
    }
}
#[derive(Debug)]
struct NoTlNetwork;
impl HttpTransport for NoTlNetwork {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        Err(TransportError::Network(format!(
            "offline original cache replay: {}",
            request.url
        )))
    }
}
fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target)
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
fn rewrite_material(value: &mut serde_json::Value, dir: &Path) {
    if let Some(name) = value.as_str() {
        *value = serde_json::json!(dir.join(name));
    } else if let Some(names) = value.as_array_mut() {
        for value in names {
            rewrite_material(value, dir);
        }
    }
}
fn run_function(function: &str, expected_code: i32, phrases: &[&str]) {
    let base = sigis_testdata::path(&["lanes", "r3-c", "eutl-basic"]);
    let cases = fs::read_to_string(base.join("cases.txt")).unwrap();
    let mut exercised = 0;
    for (index, name) in cases.lines().enumerate() {
        if name.split('[').next() != Some(function) {
            continue;
        }
        exercised += 1;
        let dir = tempfile::tempdir().unwrap();
        copy_dir(&base.join(format!("case-{index}")), dir.path());
        let config_path = dir.path().join("pyhanko.yml");
        if config_path.exists() {
            let mut config: serde_json::Value =
                serde_yaml::from_slice(&fs::read(&config_path).unwrap()).unwrap();
            config["cache-dir"] = serde_json::json!(dir.path().join("cache"));
            if let Some(contexts) = config["validation-contexts"].as_object_mut() {
                for context in contexts.values_mut() {
                    for key in ["trust", "other-certs", "lotl-tlso-certs"] {
                        if let Some(value) = context.get_mut(key) {
                            rewrite_material(value, dir.path());
                        }
                    }
                }
            }
            fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        }
        let mut argv: Vec<String> = fs::read_to_string(dir.path().join("argv.txt"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        for value in &mut argv {
            if !value.starts_with('-') && dir.path().join(&*value).is_file() {
                *value = dir.path().join(&*value).display().to_string();
            }
        }
        if config_path.exists() {
            argv.splice(0..0, ["-c".into(), config_path.display().to_string()]);
        }
        let protected: Vec<(PathBuf, Vec<u8>)> = fs::read_dir(dir.path())
            .unwrap()
            .map(Result::unwrap)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "pdf"))
            .map(|p| {
                let b = fs::read(&p).unwrap();
                (p, b)
            })
            .collect();
        let crls = dir.path().join("revinfo");
        let crls = if crls.is_dir() {
            fs::read_dir(crls)
                .unwrap()
                .map(Result::unwrap)
                .map(|e| fs::read(e.path()).unwrap())
                .collect()
        } else {
            vec![]
        };
        let runtime = ValidationRuntime {
            now: Moment::from_unix_secs(1_596_211_200),
            password: Some("ownersecret".into()),
            fetchers: Fetchers {
                crl: Some(Arc::new(PkiReplay { crls })),
                ..Fetchers::none()
            },
            trusted_list_transport: Some(Arc::new(NoTlNetwork)),
            pkcs11_signing_pin_prompt: None,
            pkcs11_user_pin_prompt: None,
        };
        let output = sigis_cli::run_with_runtime(&argv, &PluginRegistry::default(), &runtime);
        let text = format!("{}{}", output.stdout, output.stderr);
        assert_eq!(output.code, expected_code, "{name}: {text}");
        for phrase in phrases {
            assert!(text.contains(phrase), "{name}: missing {phrase:?}: {text}");
        }
        for (path, before) in protected {
            assert_eq!(fs::read(path).unwrap(), before, "{name}: modified input");
        }
    }
    assert!(exercised > 0, "original fixture rows missing: {function}");
}
macro_rules! original{($name:ident,$code:expr,$($phrase:expr),+)=>{#[test]fn $name(){run_function(stringify!($name),$code,&[$($phrase),+]);}};}
original!(test_validate_eutl, 0, "judged VALID");
original!(test_validate_eutl_bogus_tl, 1, "judged INVALID");
original!(
    test_validate_eutl_bogus_lotl,
    1,
    "Trust list processing failed"
);
original!(
    test_validate_eutl_with_extra_roots_ca_is_extra,
    0,
    "judged VALID"
);
original!(
    test_validate_eutl_with_extra_roots_ca_on_tl,
    0,
    "judged VALID"
);
original!(
    test_validate_config_eutl_limited_territories,
    0,
    "judged VALID"
);
original!(
    test_validate_eutl_config_limited_territories_not_included,
    1,
    "judged INVALID"
);
original!(
    test_validate_eutl_config_empty_territories,
    1,
    "validation context",
    "must be non-empty"
);
original!(
    test_validate_eutl_config_limited_territories_overridden_in_cli,
    0,
    "judged VALID"
);
original!(
    test_validate_arg_eutl_limited_territories,
    0,
    "judged VALID"
);
original!(test_validate_territories_arg_empty, 1, "must be non-empty");
original!(
    test_validate_inconsistent_eutl_args,
    1,
    "mutually exclusive"
);
original!(
    test_validate_eutl_arg_limited_territories_not_included,
    1,
    "judged INVALID"
);
original!(
    test_force_attempt_eutl_download,
    1,
    "Trust list processing failed"
);
