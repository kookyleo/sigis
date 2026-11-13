//! Assertions from pyhanko-cli/test_cli_stamp.py, pyHanko 0.38.1 (MIT).
#[path = "common/mod.rs"]
mod common;

use std::{fs, process::Command};
fn invoke(config: Option<&str>, args: &[&str]) -> (tempfile::TempDir, i32, String) {
    let d = tempfile::tempdir().unwrap();
    fs::copy(
        sigis_testdata::path(&["lanes", "r3-c", "runtime", "minimal.pdf"]),
        d.path().join("input.pdf"),
    )
    .unwrap();
    common::record_test_executable();
    common::record_file(&d.path().join("input.pdf"), "fixture_snapshot");
    if let Some(c) = config {
        fs::write(d.path().join("pyhanko.yml"), c).unwrap();
    }
    // Match upstream's trailing URL position after x/y in all three cases.
    let mut before = args.to_vec();
    let after = before
        .iter()
        .position(|arg| *arg == "--stamp-url")
        .map(|i| before.drain(i..i + 2).collect::<Vec<_>>())
        .unwrap_or_default();
    let o = Command::new(common::cli())
        .current_dir(d.path())
        .arg("stamp")
        .args(&before)
        .args(["input.pdf", "output.pdf", "0", "0"])
        .args(&after)
        .output()
        .unwrap();
    let oracle=Command::new(std::env::var("HANKO_ORACLE").unwrap_or_else(|_|"/tmp/pyhanko-oracle/venv/bin/python".into())).current_dir(d.path()).arg("-c").arg("import sys,json,pyhanko;pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko');from click.testing import CliRunner;from pyhanko.cli import cli_root;r=CliRunner().invoke(cli_root,['stamp',*sys.argv[1:]]);print(json.dumps({'code':r.exit_code,'output':r.output,'exception':None if r.exception is None else type(r.exception).__name__}))").args(&before).args(["input.pdf","oracle.pdf","0","0"]).args(&after).output().unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let reference: serde_json::Value = serde_json::from_slice(&oracle.stdout).unwrap();
    assert_eq!(
        reference["code"].as_i64(),
        o.status.code().map(i64::from),
        "{reference}"
    );
    fs::write(d.path().join("oracle.json"), oracle.stdout).unwrap();
    (
        d,
        o.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
    )
}
const TEXT: &str = "stamp-styles: {test: {type: text, background: __stamp__}}";
const QR: &str = "stamp-styles: {test: {type: qr, background: __stamp__}}";
fn valid(r: (tempfile::TempDir, i32, String)) {
    let (d, s, o) = r;
    assert_eq!(s, 0, "{o}");
    let reference: serde_json::Value =
        serde_json::from_slice(&fs::read(d.path().join("oracle.json")).unwrap()).unwrap();
    assert!(reference["exception"].is_null(), "{reference}");
    let b = fs::read(d.path().join("output.pdf")).unwrap();
    assert_eq!(sigis_pdf::PdfFile::parse(&b).unwrap().total_revisions(), 2);
    assert!(b.windows(8).any(|v| v == b"/XObject"));
    let input = fs::read(d.path().join("input.pdf")).unwrap();
    assert!(b.starts_with(&input));
    let oracle = fs::read(d.path().join("oracle.pdf")).unwrap();
    assert!(oracle.starts_with(&input));
    assert_eq!(
        sigis_pdf::PdfFile::parse(&oracle)
            .unwrap()
            .total_revisions(),
        2
    );
    common::record_file(&d.path().join("output.pdf"), "native_stamp_output");
    common::record_file(&d.path().join("oracle.pdf"), "oracle_stamp_output");
}
fn err(c: Option<&str>, a: &[&str], messages: &[&str]) {
    let (d, s, o) = invoke(c, a);
    assert_eq!(s, 1, "{o}");
    for m in messages {
        assert!(o.contains(m), "missing {m:?}: {o}");
        let reference: serde_json::Value =
            serde_json::from_slice(&fs::read(d.path().join("oracle.json")).unwrap()).unwrap();
        assert!(
            reference["output"].as_str().unwrap().contains(m),
            "{reference}"
        );
    }
    assert!(!d.path().join("output.pdf").exists());
}
#[test]
fn test_cli_stamp_with_style() {
    valid(invoke(Some(TEXT), &["--style-name", "test"]));
}
#[test]
fn test_cli_stamp_with_qr_style() {
    valid(invoke(
        Some(QR),
        &["--style-name", "test", "--stamp-url", "https://example.com"],
    ));
}
#[test]
fn test_cli_stamp_style_no_config() {
    err(
        None,
        &["--style-name", "test"],
        &["requires a configuration file"],
    );
}
#[test]
fn test_cli_stamp_style_stamp_url_unnecessary() {
    err(
        Some(TEXT),
        &["--style-name", "test", "--stamp-url", "blah"],
        &["only meaningful for QR"],
    );
}
#[test]
fn test_cli_stamp_style_stamp_url_mandatory() {
    err(
        Some(QR),
        &["--style-name", "test"],
        &["require the --stamp-url option"],
    );
}
#[test]
fn test_cli_stamp_style_undefined() {
    err(
        Some(TEXT),
        &["--style-name", "undefined"],
        &["no stamp style named"],
    );
}
#[test]
fn test_cli_stamp_text_param_missing() {
    err(Some("stamp-styles: {default: {type: text, stamp_text: '%(nonexistent)s', background: __stamp__}}"),&[],&["Error raised while producing signature layout","'nonexistent' is missing"]);
}
#[test]
fn test_cli_stamp_text_param_formatting_wrong() {
    for p in ["nonsense", "---:blah", "%:blah"] {
        err(
            Some("{}"),
            &["--text-param", p],
            &["must be of the form", p],
        );
    }
}
const PARAMS:&str="stamp-styles: {default: {type: text, stamp_text: \"Signing as %(my_name)s\\n%(something_else)s\", background: __stamp__}}";
#[test]
fn test_cli_stamp_text_param_multiple_substitution() {
    valid(invoke(
        Some(PARAMS),
        &[
            "--text-param",
            "my_name:John Doe",
            "--text-param",
            "something_else:Who knows",
        ],
    ));
}
#[test]
fn test_cli_stamp_text_param_fail_partial_substitution() {
    err(
        Some(PARAMS),
        &["--text-param", "my_name:John Doe"],
        &[
            "Error raised while producing signature layout",
            "'something_else' is missing",
        ],
    );
}
#[test]
fn test_cli_stamp_style_unspecified() {
    valid(invoke(
        Some("stamp-styles: {default: {type: qr, background: __stamp__, stamp-text: Blah}}"),
        &["--stamp-url", "https://example.com"],
    ));
}
#[test]
fn test_cli_stamp_style_malformed() {
    err(
        Some("stamp-styles: {default: nonsense}"),
        &[],
        &["Could not process"],
    );
}
