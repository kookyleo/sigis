//! Supplemental actual-process validation controls; zero upstream-function credit.
#[path = "common/mod.rs"]
mod common;

use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const ORACLE: &str = r#"import hashlib,importlib.metadata,json,socket,sys
from pathlib import Path
from unittest.mock import patch
import pyhanko
pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
from click.testing import CliRunner
from pyhanko.cli import cli_root
request=json.load(sys.stdin)
input_path=Path(request['input']).resolve()
input_sha256=hashlib.sha256(input_path.read_bytes()).hexdigest()
detached=None
if '--detached' in sys.argv:
    detached_path=Path(sys.argv[sys.argv.index('--detached')+1]).resolve()
    detached_bytes=detached_path.read_bytes()
    detached={'path':str(detached_path),'length':len(detached_bytes),'sha256':hashlib.sha256(detached_bytes).hexdigest()}
network_calls=[]
def reject_network(*args,**kwargs):
    network_calls.append(repr(args[1:]));raise AssertionError('Network is forbidden in this ordinary validation control')
with patch.object(socket.socket,'connect',reject_network),patch.object(socket.socket,'connect_ex',reject_network):
    result=CliRunner().invoke(cli_root,sys.argv[1:])
assert not network_calls,network_calls
assert hashlib.sha256(input_path.read_bytes()).hexdigest()==input_sha256
if detached is not None:
    assert hashlib.sha256(detached_path.read_bytes()).hexdigest()==detached['sha256']
print(json.dumps({
    'python':sys.executable,'pyhanko_version':importlib.metadata.version('pyHanko'),
    'certvalidator_version':importlib.metadata.version('pyhanko-certvalidator'),
    'cli_module':str(Path(sys.modules['pyhanko.cli'].__file__).resolve()),
    'driver':'inline validation_process.rs ORACLE',
    'argv':sys.argv[1:],'cwd':str(Path.cwd()),
    'input_path':str(input_path),'input_sha256':input_sha256,'detached':detached,
    'code':result.exit_code,'output':result.output,
    'exception':None if result.exception is None else {'type':type(result.exception).__name__,'text':str(result.exception)},
    'network_calls':network_calls,
}))
"#;

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

struct Case {
    directory: tempfile::TempDir,
    label: String,
    input: PathBuf,
    root: PathBuf,
    moment: String,
    config: Option<PathBuf>,
    detached: Option<PathBuf>,
}

impl Case {
    fn new(architecture: &str, variant: &str, label: &str) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("sigis-r3-c-validation-process-")
            .tempdir()
            .unwrap();
        let fixture = |name: &str| {
            let path = sigis_testdata::path(&["lanes", "r3-c", "validation", architecture, name]);
            common::record_file(&path, "ordinary_validation_source_fixture");
            path
        };
        let input = directory.path().join("input.pdf");
        let root = directory.path().join("root.der");
        fs::copy(fixture(&format!("{variant}.pdf")), &input).unwrap();
        fs::copy(fixture("root.der"), &root).unwrap();
        let metadata = sigis_testdata::path(&["lanes", "r3-c", "validation", "metadata.json"]);
        common::record_file(&metadata, "ordinary_validation_fixture_metadata");
        let metadata: Value = serde_json::from_slice(&fs::read(metadata).unwrap()).unwrap();
        Self {
            directory,
            label: label.into(),
            input,
            root,
            moment: metadata["moment"].as_str().unwrap().into(),
            config: None,
            detached: None,
        }
    }

    fn detached_rsa(label: &str) -> Self {
        let mut case = Self::new("rsa", "regular", label);
        let input =
            sigis_testdata::path(&["lanes", "r3-c", "validation", "rsa", "claimed-input.bin"]);
        let cms =
            sigis_testdata::path(&["lanes", "r3-c", "validation", "rsa", "claimed-detached.der"]);
        let metadata = sigis_testdata::path(&[
            "lanes",
            "r3-c",
            "validation",
            "rsa",
            "claimed-detached.json",
        ]);
        common::record_file(&input, "ordinary_detached_plaintext_source");
        common::record_file(&cms, "ordinary_detached_cms_source");
        common::record_file(&metadata, "ordinary_detached_extraction_metadata");
        let metadata: Value = serde_json::from_slice(&fs::read(metadata).unwrap()).unwrap();
        assert_eq!(
            metadata["source_pdf_sha256"],
            json!(sha256(&fs::read(&case.input).unwrap()))
        );
        assert_eq!(
            metadata["input_sha256"],
            json!(sha256(&fs::read(&input).unwrap()))
        );
        assert_eq!(
            metadata["der_sha256"],
            json!(sha256(&fs::read(&cms).unwrap()))
        );
        assert!(metadata["signing_times"]
            .as_array()
            .unwrap()
            .contains(&json!("2020-07-31T16:00:00+00:00")));
        case.input = case.directory.path().join("claimed-input.bin");
        fs::copy(input, &case.input).unwrap();
        let destination = case.directory.path().join("claimed-detached.der");
        fs::copy(cms, &destination).unwrap();
        case.detached = Some(destination);
        case
    }

    fn configure(&mut self, policy: Value) {
        let config = json!({"validation-contexts":{"default":{
            "trust":self.root,"trust-replace":true,"signer-key-usage-policy":policy
        }}});
        self.configure_value(config);
    }

    fn configure_value(&mut self, config: Value) {
        let path = self.directory.path().join("config.json");
        write_new(&path, &serde_json::to_vec_pretty(&config).unwrap());
        self.config = Some(path);
    }

    fn args(&self, rooted: bool) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(config) = &self.config {
            args.extend(["--config".into(), config.to_string_lossy().into_owned()]);
        }
        args.extend(["sign".into(), "validate".into()]);
        if self.config.is_none() {
            if rooted {
                args.extend(["--trust".into(), self.root.to_string_lossy().into_owned()]);
            }
            args.push("--trust-replace".into());
        }
        args.extend([
            "--validation-time".into(),
            self.moment.clone(),
            "--no-revocation-check".into(),
            "--password".into(),
            "ownersecret".into(),
        ]);
        if let Some(detached) = &self.detached {
            args.extend(["--detached".into(), detached.to_string_lossy().into_owned()]);
        }
        args.push(self.input.to_string_lossy().into_owned());
        args
    }

    fn native(&self, args: &[String]) -> Value {
        common::record_file(&self.input, "ordinary_validation_process_input_before_use");
        common::record_file(&self.root, "ordinary_validation_process_root_before_use");
        if let Some(config) = &self.config {
            common::record_file(config, "ordinary_validation_process_config_before_use");
        }
        if let Some(detached) = &self.detached {
            common::record_file(detached, "ordinary_validation_detached_cms_before_use");
        }
        let executable = common::cli();
        let before = snapshot(executable);
        let input_before = snapshot(&self.input);
        let detached_before = self.detached.as_deref().map(snapshot);
        let result = Command::new(executable)
            .args(args)
            .current_dir(self.directory.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(
            before,
            snapshot(executable),
            "CLI artifact changed during use"
        );
        assert_eq!(
            input_before,
            snapshot(&self.input),
            "input changed during use"
        );
        assert_eq!(detached_before, self.detached.as_deref().map(snapshot));
        json!({
            "executable":before,"argv":args,"cwd":self.directory.path(),
            "code":result.status.code().expect("native CLI exited normally"),
            "stdout":String::from_utf8(result.stdout).unwrap(),
            "stderr":String::from_utf8(result.stderr).unwrap(),
            "input_before_use":input_before,
            "detached_before_use":detached_before,
        })
    }

    fn oracle(&self, args: &[String]) -> Value {
        let python = std::env::var_os("HANKO_ORACLE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp/pyhanko-oracle/venv/bin/python"));
        common::record_file(
            &python,
            "ordinary_validation_reference_interpreter_before_use",
        );
        let input_before = snapshot(&self.input);
        let mut child = Command::new(python)
            .args(["-c", ORACLE])
            .args(args)
            .current_dir(self.directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                serde_json::to_string(&json!({"input":self.input}))
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "reference driver failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let mut result: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(result["pyhanko_version"], "0.38.1", "{result}");
        assert_eq!(result["certvalidator_version"], "0.33.0", "{result}");
        assert!(
            result["cli_module"]
                .as_str()
                .unwrap()
                .starts_with("/tmp/pyhanko-oracle/src/v0.38.1/"),
            "{result}"
        );
        assert_eq!(result["argv"], json!(args), "{result}");
        assert_eq!(result["input_sha256"], input_before["sha256"], "{result}");
        assert_eq!(result["input_path"], input_before["path"], "{result}");
        assert_eq!(
            result["detached"],
            json!(self.detached.as_deref().map(snapshot))
        );
        assert_eq!(snapshot(&self.input), input_before);
        assert_eq!(result["network_calls"], json!([]), "{result}");
        result["driver_sha256"] = json!(sha256(ORACLE.as_bytes()));
        result
    }

    fn record(&self, native: &Value, oracle: Option<&Value>) {
        let receipt = json!({
            "label":self.label,"unique_upstream_credit":0,
            "scope":"actual ordinary CLI processes; no signing/provider/qualified or HTTP acquisition proof",
            "input":snapshot(&self.input),"root":snapshot(&self.root),
            "config":self.config.as_deref().map(snapshot),
            "detached":self.detached.as_deref().map(snapshot),
            "native":native,"fresh_oracle":oracle,
            "host":fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),
        });
        eprintln!("VALIDATION_PROCESS_CASE {receipt}");
        if let Some(base) = std::env::var_os("SIGIS_CLI_VALIDATION_RECORD_DIR") {
            let base = PathBuf::from(base);
            fs::create_dir_all(&base).unwrap();
            let destination = base.join(self.directory.path().file_name().unwrap());
            fs::create_dir(&destination).unwrap();
            write_new(
                &destination.join("input.pdf"),
                &fs::read(&self.input).unwrap(),
            );
            write_new(
                &destination.join("root.der"),
                &fs::read(&self.root).unwrap(),
            );
            if let Some(config) = &self.config {
                write_new(&destination.join("config.json"), &fs::read(config).unwrap());
            }
            if let Some(detached) = &self.detached {
                write_new(
                    &destination.join("detached.der"),
                    &fs::read(detached).unwrap(),
                );
            }
            write_new(
                &destination.join("receipt.json"),
                &serde_json::to_vec_pretty(&receipt).unwrap(),
            );
        }
    }
}

fn native_output(result: &Value) -> String {
    format!(
        "{}{}",
        result["stdout"].as_str().unwrap(),
        result["stderr"].as_str().unwrap()
    )
}

fn summary(output: &str) -> String {
    regex::Regex::new(r"Sig1:[0-9a-f]{64}:[A-Z:,<>|_]+")
        .unwrap()
        .find(output)
        .unwrap_or_else(|| panic!("Missing meaningful signature summary: {output}"))
        .as_str()
        .into()
}

#[test]
fn actual_process_rooted_and_empty_roots_match_fresh_oracle() {
    for architecture in ["rsa", "ecdsa", "ed25519", "ed448"] {
        for variant in ["regular", "encrypted"] {
            for rooted in [true, false] {
                let case = Case::new(
                    architecture,
                    variant,
                    &format!("roots-{architecture}-{variant}-{rooted}"),
                );
                let args = case.args(rooted);
                let native = case.native(&args);
                let oracle = case.oracle(&args);
                case.record(&native, Some(&oracle));
                let code = if rooted { 0 } else { 1 };
                assert_eq!(native["code"], code, "{native}");
                assert_eq!(oracle["code"], code, "{oracle}");
                let expected = if rooted {
                    "INTACT:TRUSTED,UNTOUCHED"
                } else {
                    "INTACT:UNTRUSTED,UNTOUCHED"
                };
                let native_output = native_output(&native);
                assert!(native_output.contains(expected), "{native_output}");
                let oracle_output = oracle["output"].as_str().unwrap();
                assert!(oracle_output.contains(expected), "{oracle_output}");
                assert_eq!(summary(&native_output), summary(oracle_output));
                if rooted {
                    assert!(oracle["exception"].is_null(), "{oracle}");
                }
            }
        }
    }
}

#[test]
fn actual_process_policy_rejections_and_trusted_controls_match_fresh_oracle() {
    let cases = [
        (
            "unknown-forbidden",
            json!({"key-usage-forbiden":"non_repudiation"}),
            false,
        ),
        (
            "unknown-qualification",
            json!({"require-qualified-signature":true}),
            false,
        ),
        (
            "unknown-match-all",
            json!({"match-all-key-usage":true}),
            false,
        ),
        ("empty-policy-control", json!({}), true),
        (
            "required-ku-control",
            json!({"key-usage":["non_repudiation"]}),
            true,
        ),
        (
            "forbidden-ku-control",
            json!({"key-usage-forbidden":["key_cert_sign"]}),
            true,
        ),
    ];
    for (label, policy, trusted) in cases {
        let mut case = Case::new("rsa", "regular", label);
        let rejected_key =
            (!trusted).then(|| policy.as_object().unwrap().keys().next().unwrap().clone());
        case.configure(policy);
        let args = case.args(true);
        let native = case.native(&args);
        let oracle = case.oracle(&args);
        case.record(&native, Some(&oracle));
        let code = if trusted { 0 } else { 1 };
        assert_eq!(native["code"], code, "{native}");
        assert_eq!(oracle["code"], code, "{oracle}");
        let native_output = native_output(&native);
        let oracle_output = oracle["output"].as_str().unwrap();
        if trusted {
            assert!(native_output.contains("INTACT:TRUSTED"), "{native_output}");
            assert!(oracle_output.contains("INTACT:TRUSTED"), "{oracle_output}");
            assert_eq!(summary(&native_output), summary(oracle_output));
            assert!(oracle["exception"].is_null(), "{oracle}");
        } else {
            let diagnostic = format!(
                "Unexpected key in configuration for KeyUsageConstraints: {}.",
                rejected_key.unwrap()
            );
            assert!(native_output.contains(&diagnostic), "{native_output}");
            assert_eq!(
                oracle["exception"]["type"], "ConfigurationError",
                "{oracle}"
            );
            assert_eq!(oracle["exception"]["text"], diagnostic, "{oracle}");
            assert!(native["stdout"].as_str().unwrap().is_empty(), "{native}");
            assert!(oracle_output.is_empty(), "{oracle_output}");
        }
    }
}

#[test]
fn actual_process_detached_claimed_time_rejects_expired_signer() {
    let control = Case::detached_rsa("detached-explicit-2020-control");
    let args = control.args(true);
    let native = control.native(&args);
    let oracle = control.oracle(&args);
    control.record(&native, Some(&oracle));
    assert_eq!(native["code"], 0, "{native}");
    assert_eq!(oracle["code"], 0, "{oracle}");
    assert!(oracle["exception"].is_null(), "{oracle}");
    assert!(
        native_output(&native).contains("INTACT:TRUSTED"),
        "{native}"
    );
    assert!(
        oracle["output"]
            .as_str()
            .unwrap()
            .contains("INTACT:TRUSTED"),
        "{oracle}"
    );

    // Pinned detached CLI does not use its untrusted signingTime for claimed
    // validation. An expired signer cannot become trusted through that switch.
    let case = Case::detached_rsa("detached-claimed-time-refusal");
    let mut args = case.args(true);
    let time = args
        .iter()
        .position(|arg| arg == "--validation-time")
        .unwrap();
    args[time + 1] = "claimed".into();
    let native = case.native(&args);
    let oracle = case.oracle(&args);
    case.record(&native, Some(&oracle));
    assert_eq!(native["code"], 1, "{native}");
    assert_eq!(oracle["code"], 1, "{oracle}");
    assert!(
        !native_output(&native).contains("INTACT:TRUSTED"),
        "{native}"
    );
    assert!(
        !oracle["output"]
            .as_str()
            .unwrap()
            .contains("INTACT:TRUSTED"),
        "{oracle}"
    );
}

#[test]
fn actual_process_cli_trust_profile_ignores_default_context_roots_and_tolerance() {
    let mut observations = Vec::new();
    let mut control = Case::new("rsa", "regular", "default-context-root-control");
    control.configure(json!({}));
    let args = control.args(true);
    let native = control.native(&args);
    let oracle = control.oracle(&args);
    control.record(&native, Some(&oracle));
    observations.push(("default-context-root-control", native, oracle, true));

    let mut empty_roots = Case::new("rsa", "regular", "cli-other-certs-empty-roots");
    empty_roots.configure(json!({}));
    let intermediate = sigis_testdata::path(&["lanes", "r3-c", "validation", "rsa", "interm.der"]);
    common::record_file(
        &intermediate,
        "ordinary_cli_profile_intermediate_before_use",
    );
    let mut args = empty_roots.args(true);
    let end = args.len() - 1;
    args.splice(
        end..end,
        [
            "--other-certs".into(),
            intermediate.to_string_lossy().into_owned(),
            "--trust-replace".into(),
        ],
    );
    let native = empty_roots.native(&args);
    let oracle = empty_roots.oracle(&args);
    empty_roots.record(&native, Some(&oracle));
    observations.push(("cli-other-certs-empty-roots", native, oracle, false));

    // The signer expires at 2022-01-01T00:00Z. CLI certificate arguments select
    // the CLI profile: an unselected default context's one-hour tolerance must
    // not extend that signer, whereas an explicit global tolerance still can.
    for global in [false, true] {
        let label = if global {
            "cli-root-global-tolerance-control"
        } else {
            "cli-root-must-ignore-default-context-tolerance"
        };
        let mut case = Case::new("rsa", "regular", label);
        let mut config = json!({"validation-contexts":{"default":{
            "trust":case.root,"trust-replace":true,"time-tolerance":3600
        }}});
        if global {
            config["time-tolerance"] = json!(3600);
        }
        case.configure_value(config);
        let mut args = case.args(true);
        let time = args
            .iter()
            .position(|arg| arg == "--validation-time")
            .unwrap();
        args[time + 1] = "2022-01-01T00:30:00Z".into();
        let end = args.len() - 1;
        args.splice(
            end..end,
            [
                "--trust".into(),
                case.root.to_string_lossy().into_owned(),
                "--trust-replace".into(),
            ],
        );
        let native = case.native(&args);
        let oracle = case.oracle(&args);
        case.record(&native, Some(&oracle));
        observations.push((label, native, oracle, global));
    }

    // Selecting CLI roots must not discard mandatory schema rejection. These
    // are native-only controls; no reference leniency/denial is presumed.
    for (key, value) in [
        ("key-usage-forbiden", json!("non_repudiation")),
        ("require-qualified-signature", json!(true)),
        ("match-all-key-usage", json!(true)),
    ] {
        let mut case = Case::new(
            "rsa",
            "regular",
            &format!("cli-root-mandatory-schema-{key}"),
        );
        let mut policy = json!({});
        policy[key] = value;
        case.configure(policy);
        let mut args = case.args(true);
        let end = args.len() - 1;
        args.splice(
            end..end,
            [
                "--trust".into(),
                case.root.to_string_lossy().into_owned(),
                "--trust-replace".into(),
            ],
        );
        let result = case.native(&args);
        case.record(&result, None);
        assert_eq!(result["code"], 1, "{key}: {result}");
        let output = native_output(&result);
        assert!(output.contains("Unexpected key"), "{key}: {output}");
        assert!(!output.contains("INTACT:TRUSTED"), "{key}: {output}");
    }

    // Run and freeze both suspected counterexamples before any final assertion,
    // so a red empty-root decision cannot conceal the tolerance observation.
    for (label, native, oracle, trusted) in observations {
        let code = if trusted { 0 } else { 1 };
        assert_eq!(native["code"], code, "{label}: {native}");
        assert_eq!(oracle["code"], code, "{label}: {oracle}");
        if trusted {
            assert!(oracle["exception"].is_null(), "{label}: {oracle}");
            assert!(
                native_output(&native).contains("INTACT:TRUSTED"),
                "{label}: {native}"
            );
            assert!(
                oracle["output"]
                    .as_str()
                    .unwrap()
                    .contains("INTACT:TRUSTED"),
                "{label}: {oracle}"
            );
        } else {
            assert!(
                !native_output(&native).contains("INTACT:TRUSTED"),
                "{label}: {native}"
            );
            assert!(
                !oracle["output"]
                    .as_str()
                    .unwrap()
                    .contains("INTACT:TRUSTED"),
                "{label}: {oracle}"
            );
        }
    }
}

#[test]
fn actual_process_rejects_unavailable_mandatory_validation_paths() {
    let control = Case::new("rsa", "regular", "mandatory-trusted-control");
    let result = control.native(&control.args(true));
    control.record(&result, None);
    assert_eq!(result["code"], 0, "{result}");
    assert!(
        native_output(&result).contains("INTACT:TRUSTED"),
        "{result}"
    );

    for flag in [
        "--require-qualified",
        "--eutl-all",
        "--eutl-territories=be",
        "--ltv-profile=pades-lta",
        "adesverify",
    ] {
        let case = Case::new("rsa", "regular", &format!("unsupported-{flag}"));
        let mut args = case.args(true);
        if flag == "adesverify" {
            args[1] = flag.into();
        } else {
            args.insert(args.len() - 1, flag.into());
        }
        let result = case.native(&args);
        case.record(&result, None);
        assert_eq!(result["code"], 1, "{result}");
        assert!(
            !result["stdout"].as_str().unwrap().contains("TRUSTED"),
            "{result}"
        );
        assert!(
            !native_output(&result).contains("INTACT:TRUSTED"),
            "{result}"
        );
    }
}
