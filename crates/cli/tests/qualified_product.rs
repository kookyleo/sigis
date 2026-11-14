//! Current-time product companion to the frozen original CliRunner cases.
//! This exercises the Cargo CLI, without injecting a clock or a trust context.
#[path = "common/mod.rs"]
mod common;

use std::{fs, path::Path, process::Command};

fn copy(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn prepare(root: &Path, name: &str, index: usize) -> std::path::PathBuf {
    let dir = root.join(name);
    let source =
        sigis_testdata::path(&["lanes", "r3-c", "qualified-ades"]).join(format!("case-{index}"));
    copy(&source, &dir);
    let config = dir.join("pyhanko.yml");
    let mut settings: serde_json::Value =
        serde_yaml::from_slice(&fs::read(&config).unwrap()).unwrap();
    settings["cache-dir"] = serde_json::json!(dir.join("cache"));
    settings["validation-contexts"]["default"]["lotl-tlso-certs"] =
        serde_json::json!(dir.join("tlso.cert.pem"));
    fs::write(config, serde_yaml::to_string(&settings).unwrap()).unwrap();
    dir
}

fn invoke(dir: &Path, required: bool, pretty: bool) -> (i32, String) {
    let protected = ["to-validate.pdf", "pyhanko.yml", "tlso.cert.pem"]
        .map(|name| (dir.join(name), fs::read(dir.join(name)).unwrap()));
    let mut args = vec!["sign", "adesverify", "--eutl-all"];
    if required {
        args.push("--require-qualified");
    }
    if pretty {
        args.push("--pretty-print");
    }
    args.push("to-validate.pdf");
    let output = Command::new(common::cli())
        .current_dir(dir)
        .args(&args)
        .output()
        .unwrap();
    let code = output.status.code().expect("product terminated by signal");
    // Fresh pinned CLI on the SAME historical archival PDF/cache at actual NOW.
    // No freeze_time, API-only substitute, new signature or invented old POE.
    let peer = Command::new(
        std::env::var("HANKO_ORACLE")
            .unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into()),
    )
    .current_dir(dir)
    .args([
        "-B",
        "-c",
        r#"
import sys
assert __debug__ and sys.flags.optimize == 0
sys.path[:0]=['/home/l/.codex/artifacts/sigis/round3/c/oracle-deps',
 '/tmp/pyhanko-oracle/src/v0.38.1/internal/common-test-utils/src']
import pyhanko
pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
from click.testing import CliRunner
from pyhanko.cli import cli_root
from pyhanko_testing_commons.test_data.samples import TESTING_CA_QUALIFIED
from pyhanko_testing_commons.test_utils.live_http import live_pki_services
with live_pki_services() as services:
    services.register(TESTING_CA_QUALIFIED)
    result=CliRunner().invoke(cli_root,sys.argv[2:])
assert result.exit_code==int(sys.argv[1]),(result.exit_code,result.output)
if '--require-qualified' in sys.argv and int(sys.argv[1])==1:
    assert 'UNTRUSTED' in result.output and 'NOT_QUALIFIED' in result.output,result.output
elif '--require-qualified' in sys.argv:
    assert 'INTACT:TRUSTED' in result.output and 'UNTRUSTED' not in result.output,result.output
else:
    assert 'judged VALID' in result.output,result.output
    assert "The signer's certificate is not qualified" in result.output,result.output
"#,
    ])
    .arg(code.to_string())
    .args(&args)
    .output()
    .unwrap();
    assert!(
        peer.status.success(),
        "same-input current-time Python peer: {}{}",
        String::from_utf8_lossy(&peer.stdout),
        String::from_utf8_lossy(&peer.stderr)
    );
    for (path, before) in protected {
        assert_eq!(fs::read(path).unwrap(), before, "product changed input");
    }
    (
        code,
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[test]
fn product_now_qualified_and_nonqualified_positives_precede_required_refusal() {
    let temp = tempfile::tempdir().unwrap();
    let qualified = prepare(temp.path(), "qualified", 4);
    let nonqualified = prepare(temp.path(), "nonqualified", 8);
    let (code, text) = invoke(&qualified, true, false);
    assert_eq!(code, 0, "genuine product-NOW qualified positive: {text}");
    assert!(text.contains("INTACT:TRUSTED"), "{text}");
    assert!(
        !text.contains("UNTRUSTED") && !text.contains("NOT_QUALIFIED"),
        "{text}"
    );
    assert!(
        text.contains("TIMESTAMP_TOKEN<INTACT:TRUSTED|QUALIFIED>"),
        "{text}"
    );
    let (code, text) = invoke(&nonqualified, false, true);
    assert_eq!(code, 0, "genuine product-NOW optional positive: {text}");
    assert!(text.contains("judged VALID"), "{text}");
    assert!(
        text.contains("The signer's certificate is not qualified"),
        "{text}"
    );
    assert!(text.contains("directly identified as a QTST"), "{text}");
    let (code, text) = invoke(&nonqualified, true, false);
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("UNTRUSTED") && text.contains("NOT_QUALIFIED"),
        "{text}"
    );
}
