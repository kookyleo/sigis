//! Five exact remaining runtime assertions from pyHanko 0.38.1 (MIT).
#[path = "common/mod.rs"]
mod common;

use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

const ORACLE: &str = r#"import hashlib,importlib.metadata,json,os,pathlib,socket,sys
from unittest.mock import patch
import pyhanko
pinned=pathlib.Path('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
pyhanko.__path__.append(str(pinned))
from click.testing import CliRunner
import pyhanko.cli
module=pathlib.Path(pyhanko.cli.__file__).resolve()
assert module.is_relative_to(pinned.resolve()),module
input_path=pathlib.Path('input.pdf').resolve()
input_bytes=input_path.read_bytes()
config_path=pathlib.Path('pyhanko.yml')
config_bytes=config_path.read_bytes() if config_path.exists() else None
network=[]
def deny_network(*args,**kwargs):
    network.append(repr(args[1:]));raise AssertionError('Network is forbidden in runtime syntax/logging controls')
with patch.object(socket.socket,'connect',deny_network),patch.object(socket.socket,'connect_ex',deny_network):
    result=CliRunner().invoke(pyhanko.cli.cli_root,sys.argv[1:])
assert input_path.read_bytes()==input_bytes
assert (config_path.read_bytes() if config_path.exists() else None)==config_bytes
assert not network,network
log=pathlib.Path('pyhanko.log')
def snap(path,data):
    return {'path':str(path.resolve()),'length':len(data),'sha256':hashlib.sha256(data).hexdigest()}
print(json.dumps({
    'argv':sys.argv[1:],'code':result.exit_code,'output':result.output,
    'stdout':result.stdout,'stderr':result.stderr,
    'exception':None if result.exception is None else {'type':type(result.exception).__name__,'text':str(result.exception)},
    'log':log.read_text() if log.exists() else None,'cwd':str(pathlib.Path.cwd()),
    'executable':sys.executable,'interpreter_sha256':hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
    'cli_source':str(module),'cli_source_sha256':hashlib.sha256(module.read_bytes()).hexdigest(),
    'input':snap(input_path,input_bytes),
    'config':None if config_bytes is None else snap(config_path,config_bytes),
    'python_optimize':sys.flags.optimize,'assertions_enabled':__debug__,
    'PYTHONOPTIMIZE_environment':os.environ.get('PYTHONOPTIMIZE'),
    'pyhanko_version':importlib.metadata.version('pyHanko'),
    'certvalidator_version':importlib.metadata.version('pyhanko-certvalidator'),
    'click_version':importlib.metadata.version('click'),'network_calls':network,
}))"#;

fn sha256(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn snapshot(path: &Path) -> Value {
    let path = path.canonicalize().unwrap();
    let bytes = fs::read(&path).unwrap();
    json!({"path":path,"length":bytes.len(),"sha256":sha256(&bytes)})
}

fn write_new(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn run(sample: &str, cfg: Option<&str>, args: &[&str]) -> (tempfile::TempDir, Output) {
    let d = tempfile::tempdir().unwrap();
    let oracle_dir = tempfile::tempdir().unwrap();
    assert_ne!(d.path(), oracle_dir.path());
    let sample_path = sigis_testdata::path(&["lanes", "r3-c", "runtime", sample]);
    common::record_file(&sample_path, "runtime_source_fixture");
    let sample_snapshot = snapshot(&sample_path);
    for directory in [d.path(), oracle_dir.path()] {
        let input = directory.join("input.pdf");
        fs::copy(&sample_path, &input).unwrap();
        common::record_file(&input, "runtime_input_before_use");
        assert_eq!(snapshot(&input)["sha256"], sample_snapshot["sha256"]);
        if let Some(c) = cfg {
            let config = directory.join("pyhanko.yml");
            fs::write(&config, c).unwrap();
            common::record_file(&config, "runtime_config_before_use");
        }
    }
    let executable = common::cli();
    let before_cli = snapshot(executable);
    let before_test = snapshot(&std::env::current_exe().unwrap());
    let input = d.path().join("input.pdf");
    let input_before = snapshot(&input);
    let config_before = cfg.map(|_| snapshot(&d.path().join("pyhanko.yml")));
    let o = Command::new(executable)
        .current_dir(d.path())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(snapshot(executable), before_cli, "CLI changed during use");
    assert_eq!(snapshot(&input), input_before);
    assert_eq!(
        cfg.map(|_| snapshot(&d.path().join("pyhanko.yml"))),
        config_before
    );
    // Freeze the native file before launching the separately rooted reference.
    let native_log = fs::read_to_string(d.path().join("pyhanko.log")).ok();
    let native_log_snapshot = native_log
        .as_ref()
        .map(|_| snapshot(&d.path().join("pyhanko.log")));
    let python = sigis_testdata::oracle::python().expect("pinned oracle is required");
    common::record_file(&python, "runtime_reference_interpreter_before_use");
    let oracle = Command::new(&python)
        .current_dir(oracle_dir.path())
        .args(["-c", ORACLE])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        oracle.status.success(),
        "reference driver failed: {}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let reference: Value = serde_json::from_slice(&oracle.stdout).unwrap();
    let receipt = json!({
        "case":std::thread::current().name().unwrap(),"argv":args,
        "native_test_executable":before_test,"native_cli_executable":before_cli,
        "host":fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),
        "source_fixture":sample_snapshot,"native_input":input_before,
        "native_config":config_before,"native_cwd":d.path(),
        "native_status":o.status.code(),
        "native_stdout":String::from_utf8_lossy(&o.stdout),
        "native_stderr":String::from_utf8_lossy(&o.stderr),
        "native_log_before_oracle":native_log,
        "native_log_snapshot_before_oracle":native_log_snapshot,
        "native_log_frozen_before_reference_started":true,
        "reference_driver_sha256":sha256(ORACLE.as_bytes()),"oracle":reference,
    });
    if let Some(directory) = std::env::var_os("SIGIS_CLI_RUNTIME_RECEIPT_DIR") {
        let directory = std::path::PathBuf::from(directory);
        fs::create_dir_all(&directory).unwrap();
        let destination = directory.join(std::thread::current().name().unwrap());
        fs::create_dir(&destination).unwrap();
        write_new(&destination.join("input.pdf"), &fs::read(&input).unwrap());
        if let Some(c) = cfg {
            write_new(&destination.join("pyhanko.yml"), c.as_bytes());
        }
        if let Some(log) = &native_log {
            write_new(&destination.join("native-pyhanko.log"), log.as_bytes());
        }
        if let Some(log) = reference["log"].as_str() {
            write_new(&destination.join("reference-pyhanko.log"), log.as_bytes());
        }
        write_new(
            &destination.join("receipt.json"),
            &serde_json::to_vec_pretty(&receipt).unwrap(),
        );
    }
    eprintln!("NATIVE_RUNTIME_CASE {receipt}");
    assert_eq!(reference["pyhanko_version"], "0.38.1");
    assert_eq!(reference["certvalidator_version"], "0.33.0");
    assert_eq!(reference["python_optimize"], 0);
    assert_eq!(reference["assertions_enabled"], true);
    assert_eq!(reference["executable"].as_str(), python.to_str());
    assert_eq!(reference["interpreter_sha256"], snapshot(&python)["sha256"]);
    assert!(reference["cli_source"]
        .as_str()
        .unwrap()
        .starts_with("/tmp/pyhanko-oracle/src/v0.38.1/"));
    assert_eq!(reference["cwd"], oracle_dir.path().to_str().unwrap());
    assert_eq!(reference["argv"], json!(args));
    assert_eq!(reference["input"]["sha256"], input_before["sha256"]);
    assert_eq!(reference["config"].is_null(), cfg.is_none());
    if let Some(c) = cfg {
        assert_eq!(reference["config"]["sha256"], sha256(c.as_bytes()));
    }
    assert_eq!(reference["network_calls"], json!([]));
    assert_eq!(reference["code"].as_i64(), o.status.code().map(i64::from));
    let case = std::thread::current().name().unwrap().to_owned();
    let reference_stream = match case.as_str() {
        "test_fail_strict_mildly_broken" => Some("output"),
        "test_succeed_strict_mildly_broken_nonstrict" => None,
        "test_log_stdout" => Some("stdout"),
        "test_log_stderr_default" => Some("stderr"),
        "test_log_file" => Some("log"),
        other => panic!("Unexpected runtime function: {other}"),
    };
    if let Some(stream) = reference_stream {
        assert!(reference[stream]
            .as_str()
            .unwrap()
            .contains("in strict mode; rerun"));
    }
    if case == "test_log_file" {
        assert!(native_log.unwrap().contains("in strict mode; rerun"));
    }
    (d, o)
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn test_fail_strict_mildly_broken() {
    let (_, o) = run(
        "minimal-slightly-broken.pdf",
        None,
        &["sign", "validate", "--trust-replace", "input.pdf"],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(text(&o).contains("in strict mode; rerun"), "{}", text(&o));
}
#[test]
fn test_succeed_strict_mildly_broken_nonstrict() {
    let (_, o) = run(
        "minimal-slightly-broken.pdf",
        None,
        &[
            "sign",
            "validate",
            "--no-strict-syntax",
            "--trust-replace",
            "input.pdf",
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
}
const LOG:&str="logging: {root-level: DEBUG, root-output: stdout}\nvalidation-contexts: {default: {trust-replace: true}}";
#[test]
fn test_log_stdout() {
    let (_, o) = run(
        "minimal-slightly-broken.pdf",
        Some(LOG),
        &["sign", "validate", "input.pdf"],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stdout).contains("in strict mode; rerun"));
}
#[test]
fn test_log_stderr_default() {
    let (_, o) = run(
        "minimal-slightly-broken.pdf",
        None,
        &["sign", "validate", "--trust-replace", "input.pdf"],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("in strict mode; rerun"));
}
#[test]
fn test_log_file() {
    let (d, o) = run(
        "minimal-slightly-broken.pdf",
        Some(&LOG.replace("stdout", "pyhanko.log")),
        &["sign", "validate", "input.pdf"],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(fs::read_to_string(d.path().join("pyhanko.log"))
        .unwrap()
        .contains("in strict mode; rerun"));
}
