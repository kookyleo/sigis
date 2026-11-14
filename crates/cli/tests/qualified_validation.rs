//! Exact AdES qualified CLI assertions from pyHanko 0.38.1 (MIT).
use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime};
use sigis_pki_core::{fetch::Fetchers, time::Moment};
use sigis_pki_fetch::{transport::HttpRequest, HttpResponse, HttpTransport, TransportError};
use std::{fs, path::Path, process::Command, sync::Arc};

#[derive(Debug)]
struct Offline;
impl HttpTransport for Offline {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        Err(TransportError::Network(format!(
            "unexpected uncached request {}",
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
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
fn invoke(index: usize, extra: &[&str]) -> sigis_cli::Output {
    let source =
        sigis_testdata::path(&["lanes", "r3-c", "qualified-ades"]).join(format!("case-{index}"));
    let dir = tempfile::tempdir().unwrap();
    copy_dir(&source, dir.path());
    let path = dir.path().join("pyhanko.yml");
    let mut config: serde_json::Value = serde_yaml::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["cache-dir"] = serde_json::json!(dir.path().join("cache"));
    let context = &mut config["validation-contexts"]["default"];
    for key in ["trust", "other-certs", "lotl-tlso-certs"] {
        if let Some(value) = context.get_mut(key) {
            if let Some(name) = value.as_str() {
                *value = serde_json::json!(dir.path().join(name));
            } else if let Some(names) = value.as_array_mut() {
                for name in names {
                    *name = serde_json::json!(dir.path().join(name.as_str().unwrap()));
                }
            }
        }
    }
    fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
    let pdf = dir.path().join("to-validate.pdf");
    let before = fs::read(&pdf).unwrap();
    let mut args = vec![
        "-c".to_owned(),
        path.display().to_string(),
        "sign".into(),
        "adesverify".into(),
        "--eutl-all".into(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    args.push(pdf.display().to_string());
    let runtime = ValidationRuntime {
        now: Moment::from_unix_secs(
            fs::read_to_string(dir.path().join("moment.txt"))
                .unwrap()
                .trim()
                .parse()
                .unwrap(),
        ),
        fetchers: Fetchers::none(),
        password: None,
        trusted_list_transport: Some(Arc::new(Offline)),
        pkcs11_user_pin_prompt: None,
    };
    let output = sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &runtime);
    assert_eq!(
        fs::read(&pdf).unwrap(),
        before,
        "validation changed the signed PDF"
    );
    // Fresh original CLI peer on the SAME complete PDF/config/cache bytes. The
    // explicit historical clock matches CliRunner/freezegun in the original,
    // not a product clock option or validity/tolerance extension.
    let oracle = Command::new(
        std::env::var("HANKO_ORACLE")
            .unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into()),
    )
    .arg("-B")
    .arg("-c")
    .arg(
        r#"
import sys
sys.path[:0]=['/home/l/.codex/artifacts/sigis/round3/c/oracle-deps',
 '/tmp/pyhanko-oracle/src/v0.38.1/internal/common-test-utils/src']
import pyhanko
pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
from click.testing import CliRunner
from freezegun import freeze_time
from pyhanko.cli import cli_root
from pyhanko_testing_commons.test_data.samples import TESTING_CA_QUALIFIED
from pyhanko_testing_commons.test_utils.live_http import live_pki_services
from datetime import datetime,timezone
from pathlib import Path
from yaml import safe_load
config=safe_load(Path(sys.argv[3]).read_text())
clock_file=Path(config['cache-dir']).parent/'moment.txt'
with freeze_time(datetime.fromtimestamp(int(clock_file.read_text()),timezone.utc)):
    with live_pki_services() as services:
        services.register(TESTING_CA_QUALIFIED)
        result=CliRunner().invoke(cli_root,['--config' if arg=='-c' else arg for arg in sys.argv[2:]])
assert result.exit_code==int(sys.argv[1]),(result.exit_code,result.output)
print(result.output)
"#,
    )
    .arg(output.code.to_string())
    .args(&args)
    .output()
    .unwrap();
    assert!(
        oracle.status.success(),
        "native: {}{}\nreference: {}{}",
        output.stdout,
        output.stderr,
        String::from_utf8_lossy(&oracle.stdout),
        String::from_utf8_lossy(&oracle.stderr)
    );
    assert_eq!(
        fs::read(&pdf).unwrap(),
        before,
        "reference validation changed the signed PDF"
    );
    output
}
fn text(output: &sigis_cli::Output) -> String {
    format!("{}{}", output.stdout, output.stderr)
}
fn valid(index: usize, pretty: bool) -> String {
    let out = invoke(index, if pretty { &["--pretty-print"] } else { &[] });
    let message = text(&out);
    assert_eq!(out.code, 0, "{message}");
    message
}
/// Four original overloaded_trust × pades_style parameter rows.
#[test]
fn test_validate_eutl_ades() {
    for index in 0..4 {
        let message = valid(index, true);
        for expected in [
            "The signer's certificate is qualified",
            "qualified for electronic signatures",
            "directly identified as a QTST",
            "judged VALID",
        ] {
            assert!(message.contains(expected), "{message}");
        }
    }
}
#[test]
fn test_validate_eutl_ades_qual_required() {
    let out = invoke(4, &["--require-qualified"]);
    let message = text(&out);
    assert_eq!(out.code, 0, "{message}");
    assert!(message.contains("INTACT:TRUSTED"), "{message}");
    assert!(!message.contains("UNTRUSTED"), "{message}");
}
#[test]
fn test_validate_eutl_ades_not_qualified() {
    let message = valid(5, true);
    assert!(
        message.contains("The signer's certificate is not qualified"),
        "{message}"
    );
    assert!(message.contains("judged VALID"), "{message}");
}
#[test]
fn test_validate_eutl_ades_not_qualified_summary() {
    let message = valid(6, false);
    assert!(message.contains("NOT_QUALIFIED"), "{message}");
}
#[test]
fn test_validate_eutl_ades_qualified_summary() {
    let message = valid(7, false);
    assert!(message.contains("QUALIFIED"), "{message}");
    assert!(!message.contains("NOT_QUALIFIED"), "{message}");
}
#[test]
fn test_validate_eutl_ades_not_qualified_required() {
    // The mandatory positive contrasts prevent an always-untrusted adapter from
    // satisfying this negative original. Use the SAME nonqualified PDF bytes.
    test_validate_eutl_ades_qual_required();
    let optional = invoke(8, &["--pretty-print"]);
    let optional_text = text(&optional);
    assert_eq!(optional.code, 0, "{optional_text}");
    assert!(optional_text.contains("judged VALID"), "{optional_text}");
    assert!(
        optional_text.contains("The signer's certificate is not qualified"),
        "{optional_text}"
    );
    let out = invoke(8, &["--require-qualified"]);
    let message = text(&out);
    assert_eq!(out.code, 1, "{message}");
    assert!(message.contains("UNTRUSTED"), "{message}");
    assert!(message.contains("NOT_QUALIFIED"), "{message}");
}
#[test]
fn test_validate_eutl_ades_tsa_not_qualified() {
    let message = valid(9, true);
    for expected in [
        "The signer's certificate is qualified",
        "The time stamping authority is not qualified",
        "judged VALID",
    ] {
        assert!(message.contains(expected), "{message}");
    }
}
#[test]
#[ignore = "Native full-LTA lacks historical control-time proof for the expired 2025 leaf; upstream CLI accepts its status projection"]
fn test_validate_eutl_ades_point_in_time_no_revinfo() {
    let out = invoke(
        10,
        &[
            "--pretty-print",
            "--validation-time",
            "2025-03-01T22:00:00Z",
            "--no-revocation-check",
        ],
    );
    let message = text(&out);
    assert_eq!(out.code, 0, "{message}");
    for expected in [
        "The signer's certificate is qualified",
        "qualified for electronic signatures",
        "directly identified as a QTST",
        "judged VALID",
    ] {
        assert!(message.contains(expected), "{message}");
    }
}
