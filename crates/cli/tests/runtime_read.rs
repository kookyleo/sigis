//! Exact encrypted-read failure from pyHanko 0.38.1 test_runtime.py (MIT).
#[path = "common/mod.rs"]
mod common;

use std::{fs, io::Write, path::Path, process::Command};

const ARGS: &[&str] = &[
    "sign",
    "addfields",
    "--field",
    "1/0,0,100,100/Sig1",
    "input.pdf",
    "out.pdf",
];

fn sha256(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn export_file(directory: &Path, actual: &Path, name: &str) -> Option<serde_json::Value> {
    if !actual.exists() {
        return None;
    }
    let bytes = fs::read(actual).unwrap();
    let exported = directory.join(name);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&exported)
        .unwrap()
        .write_all(&bytes)
        .unwrap();
    Some(serde_json::json!({
        "actual_path": actual, "exported_path": exported,
        "sha256": sha256(&bytes), "length": bytes.len(),
    }))
}

#[test]
fn test_fail_read() {
    let fixture = sigis_testdata::path(&["lanes", "r3-c", "runtime", "minimal-aes256.pdf"]);
    let bytes = fs::read(&fixture).unwrap();
    assert_eq!(
        sha256(&bytes),
        "eda8c19fae7b63e715f0936d0359b698bc81ab69107e159507842f08dce8b69a"
    );
    assert!(sigis_pdf::PdfFile::parse(&bytes).unwrap().encrypted());

    // Separate directories prevent an oracle operation from creating native files.
    let native_dir = tempfile::tempdir().unwrap();
    let oracle_dir = tempfile::tempdir().unwrap();
    let native_input = native_dir.path().join("input.pdf");
    let oracle_input = oracle_dir.path().join("input.pdf");
    fs::write(&native_input, &bytes).unwrap();
    fs::write(&oracle_input, &bytes).unwrap();
    common::record_test_executable();
    common::record_file(&native_input, "native_runtime_read_input");
    common::record_file(&oracle_input, "oracle_runtime_read_input");
    let native = Command::new(common::cli())
        .current_dir(native_dir.path())
        .args(ARGS)
        .output()
        .unwrap();
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    // Both exact original assertions run against the actual native command.
    assert_eq!(native.status.code(), Some(1), "{output}");
    assert!(output.contains("Failed to read"), "{output}");

    let python = sigis_testdata::oracle::python().expect("pinned oracle is required");
    let script = r#"
import hashlib, json, os, sys, pyhanko
from importlib.metadata import version
pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
from click.testing import CliRunner
from pyhanko.cli import cli_root
before = hashlib.sha256(open('input.pdf', 'rb').read()).hexdigest()
result = CliRunner().invoke(cli_root, sys.argv[1:])
print(json.dumps({
    'code': result.exit_code, 'output': result.output,
    'exception': None if result.exception is None else type(result.exception).__name__,
    'input_sha256': before, 'argv': sys.argv[1:], 'cwd': os.getcwd(),
    'out_exists': os.path.exists('out.pdf'), 'executable': sys.executable,
    'cli_module': sys.modules['pyhanko.cli'].__file__,
    'pyhanko_version': version('pyHanko'),
    'certvalidator_version': version('pyhanko-certvalidator'),
}))
"#;
    let oracle = Command::new(&python)
        .current_dir(oracle_dir.path())
        .args(["-c", script])
        .args(ARGS)
        .output()
        .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let reference: serde_json::Value = serde_json::from_slice(&oracle.stdout).unwrap();
    assert_eq!(reference["code"], 1, "{reference}");
    assert!(reference["output"]
        .as_str()
        .unwrap()
        .contains("Failed to read"));
    assert_eq!(reference["input_sha256"], sha256(&bytes));
    assert_eq!(reference["argv"], serde_json::json!(ARGS));
    assert_eq!(reference["executable"], python.to_str().unwrap());
    assert_eq!(reference["pyhanko_version"], "0.38.1");
    assert_eq!(reference["certvalidator_version"], "0.33.0");
    assert!(reference["cli_module"]
        .as_str()
        .unwrap()
        .starts_with("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko/cli/"));

    let mut receipt = serde_json::json!({
        "id": "pyhanko-cli/test_runtime.py::test_fail_read",
        "argv": ARGS, "native_code": native.status.code(),
        "native_stdout": String::from_utf8_lossy(&native.stdout),
        "native_stderr": String::from_utf8_lossy(&native.stderr),
        "native_cwd": native_dir.path(), "oracle_cwd": oracle_dir.path(),
        "host": fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),
        "cli_executable": common::cli(),
        "native_test_executable": std::env::current_exe().unwrap(),
        "fresh_oracle": reference,
        "native_out_exists": native_dir.path().join("out.pdf").exists(),
        "output_side_effect_parity_is_not_an_original_assertion": true,
    });
    if let Some(root) = std::env::var_os("SIGIS_CLI_RUNTIME_READ_RECORD_DIR") {
        let root = std::path::PathBuf::from(root);
        fs::create_dir_all(&root).unwrap();
        let mut files = serde_json::Map::new();
        for (name, actual) in [
            ("native-input.pdf", native_input),
            ("oracle-input.pdf", oracle_input),
            ("native-out.pdf", native_dir.path().join("out.pdf")),
            ("oracle-out.pdf", oracle_dir.path().join("out.pdf")),
        ] {
            if let Some(file) = export_file(&root, &actual, name) {
                files.insert(name.into(), file);
            }
        }
        receipt["files"] = serde_json::Value::Object(files);
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("receipt.json"))
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&receipt).unwrap())
            .unwrap();
    }
    eprintln!("RUNTIME_READ_CASE {receipt}");
}
