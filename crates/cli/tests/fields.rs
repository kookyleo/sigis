//! Assertion ports of pyHanko 0.38.1 `test_cli_field_mgmt.py`.
#[path = "common/mod.rs"]
mod common;

use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SimpleSigner};
use sigis_pdf::{signatures::enumerate_sig_fields, PdfFile};
use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::Arc,
};

fn sample(name: &str) -> Vec<u8> {
    std::fs::read(sigis_testdata::pyhanko(&["pdf", name])).unwrap()
}
fn cli(args: &[&str]) -> Output {
    Command::new(common::cli()).args(args).output().unwrap()
}
fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}
fn oracle(args: &[&str]) -> (i32, String) {
    let python = std::env::var_os("HANKO_ORACLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/pyhanko-oracle/venv/bin/python"));
    let out = Command::new(python).arg("-c").arg("import sys; from click.testing import CliRunner; import pyhanko; pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko'); from pyhanko.cli import cli_root; r=CliRunner().invoke(cli_root, sys.argv[1:]); print(r.exit_code); print(r.output, end='')").args(args).output().expect("the live pinned oracle is required");
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let (code, output) = stdout.split_once('\n').unwrap();
    (code.parse().unwrap(), output.to_owned())
}
fn list(bytes: &[u8], skip: bool, expected: &str) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.pdf");
    std::fs::write(&input, bytes).unwrap();
    let mut args = vec!["sign", "list"];
    if skip {
        args.push("--skip-status");
    }
    args.push(input.to_str().unwrap());
    let out = cli(&args);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), expected);
    assert_eq!(oracle(&args), (0, expected.to_owned()));
}
/// Upstream: `test_list_empty_fields_with_status`.
#[test]
fn test_list_empty_fields_with_status() {
    list(
        &sample("minimal-two-fields.pdf"),
        false,
        "Sig1:EMPTY\nSig2:EMPTY\n",
    );
}
/// Upstream: `test_list_mixed_fields_with_status`; a real Rust signature fills Sig1.
#[test]
fn test_list_mixed_fields_with_status() {
    let signer = SimpleSigner::load(
        &std::fs::read(sigis_testdata::pyhanko(&["crypto", "selfsigned.key.pem"])).unwrap(),
        &std::fs::read(sigis_testdata::pyhanko(&["crypto", "selfsigned.cert.pem"])).unwrap(),
        Some(b"secret"),
        vec![],
    )
    .unwrap();
    let bytes = PdfSigner::new(
        PdfSignatureMetadata::pyhanko_defaults("Sig1"),
        Arc::new(signer),
    )
    .sign_pdf(&sample("minimal-two-fields.pdf"))
    .unwrap();
    assert_eq!(
        PdfFile::parse(&bytes)
            .unwrap()
            .embedded_signatures()
            .unwrap()
            .len(),
        1
    );
    list(&bytes, false, "Sig1:FILLED\nSig2:EMPTY\n");
}
/// Upstream: `test_list_empty_fields_without_status`.
#[test]
fn test_list_empty_fields_without_status() {
    list(&sample("minimal-two-fields.pdf"), true, "Sig1\nSig2\n");
}
fn add(name: &str, spec: &str, resave: bool) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.pdf");
    let output = dir.path().join("output.pdf");
    let reference = dir.path().join("oracle.pdf");
    std::fs::write(&input, sample(name)).unwrap();
    let mut args = vec!["sign", "addfields"];
    if resave {
        args.push("--resave");
    }
    args.extend([
        "--field",
        spec,
        input.to_str().unwrap(),
        output.to_str().unwrap(),
    ]);
    let out = cli(&args);
    assert!(out.status.success(), "{}", text(&out));
    let bytes = std::fs::read(&output).unwrap();
    *args.last_mut().unwrap() = reference.to_str().unwrap();
    assert_eq!(oracle(&args).0, 0);
    let rust = PdfFile::parse(&bytes).unwrap();
    let py = PdfFile::parse(&std::fs::read(reference).unwrap()).unwrap();
    assert_eq!(rust.total_revisions(), py.total_revisions());
    assert_eq!(
        enumerate_sig_fields(&rust, None, None).unwrap()[0].fq_name,
        enumerate_sig_fields(&py, None, None).unwrap()[0].fq_name
    );
    bytes
}
/// Upstream: `test_cli_add_field_incremental_update_by_default`.
#[test]
fn test_cli_add_field_incremental_update_by_default() {
    let bytes = add("minimal.pdf", "1/0,0,100,100/Sig1", false);
    let pdf = PdfFile::parse(&bytes).unwrap();
    assert_eq!(
        enumerate_sig_fields(&pdf, None, None).unwrap()[0].fq_name,
        "Sig1"
    );
    assert_eq!(pdf.total_revisions(), 2);
    assert!(bytes.starts_with(&sample("minimal.pdf")));
}
/// Upstream: `test_cli_add_field_with_resave`.
#[test]
fn test_cli_add_field_with_resave() {
    let bytes = add("minimal.pdf", "1/0,0,100,100/Sig1", true);
    let pdf = PdfFile::parse(&bytes).unwrap();
    assert_eq!(
        enumerate_sig_fields(&pdf, None, None).unwrap()[0].fq_name,
        "Sig1"
    );
    assert_eq!(pdf.total_revisions(), 1);
}
/// Upstream: `test_cli_add_field_to_last_page`.
#[test]
fn test_cli_add_field_to_last_page() {
    let bytes = add("minimal-two-pages.pdf", "-1/0,0,100,100/Sig1", false);
    let pdf = PdfFile::parse(&bytes).unwrap();
    let field = enumerate_sig_fields(&pdf, None, None).unwrap()[0].field_ref;
    let doc = lopdf::Document::load_mem(&bytes).unwrap();
    let field_page = doc
        .get_dictionary(field)
        .unwrap()
        .get(b"P")
        .unwrap()
        .as_reference()
        .unwrap();
    assert_eq!(doc.get_pages().get(&2).copied().unwrap(), field_page);
}
/// Upstream: `test_cli_field_spec_errors`; all four upstream parameters.
#[test]
fn test_cli_field_spec_errors() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.pdf");
    let output = dir.path().join("output.pdf");
    std::fs::write(&input, sample("minimal.pdf")).unwrap();
    for (spec, expected) in [
        ("0/0,0,100,100/Sig1", "nonzero integer"),
        ("zzz/0,0,100,100/Sig1", "nonzero integer"),
        ("Sig1", "should be of the form"),
        ("1/0,z,100,100/Sig1", "should be four integers"),
    ] {
        let args = [
            "sign",
            "addfields",
            "--field",
            spec,
            input.to_str().unwrap(),
            output.to_str().unwrap(),
        ];
        let out = cli(&args);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        assert!(text(&out).contains(expected), "{}", text(&out));
        let (code, text) = oracle(&args);
        assert_eq!(code, 1);
        assert!(text.contains(expected), "{text}");
    }
}
