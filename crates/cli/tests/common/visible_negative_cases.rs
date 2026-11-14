//! Exact original fixtures, live differential checks and frozen native evidence.
use crate::{appearance_cases::Case as BaseCase, common, signing_record};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

pub const ARCHES: [&str; 4] = ["rsa", "ecdsa", "ed25519", "ed448"];
pub const BOXES: [&str; 4] = ["none", "zero-zero", "zero-height", "zero-width"];

pub fn text(output: &Output) -> String {
    crate::appearance_cases::text(output)
}

pub fn sha(data: &[u8]) -> String {
    crate::appearance_cases::sha(data)
}

pub fn assert_negative(kind: &str, exit_code: Option<i32>, output: &str) {
    assert_eq!(exit_code, Some(1), "{output}");
    let fragments: &[&str] = match kind {
        "no-config" => &["requires a configuration file"],
        "missing" => &[
            "'Sig1' does not exist in the PDF file",
            "you did not specify a bounding box",
        ],
        "unnamed" => &[
            "did not contain any signature fields",
            "you did not specify a bounding box",
        ],
        "invisible" => &["the field 'Sig1' in the PDF is not a visible one"],
        _ => panic!("Unknown original kind: {kind}"),
    };
    for fragment in fragments {
        assert!(output.contains(fragment), "Missing {fragment:?}: {output}");
    }
}

pub fn helper() -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "visible-negative-four", "oracle.py"])
}

fn python() -> PathBuf {
    sigis_testdata::oracle::python().expect("Pinned reference interpreter is mandatory")
}

fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) {
    if !directory.exists() {
        return;
    }
    let mut entries = fs::read_dir(directory)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            collect_files(&path, files);
        } else {
            files.push(path);
        }
    }
}

pub struct Case {
    pub base: BaseCase,
    pub kind: &'static str,
    pub named: bool,
    pub box_key: &'static str,
    pub preparation: Value,
}

impl Case {
    pub fn new(arch: &'static str, kind: &'static str) -> Self {
        assert!(ARCHES.contains(&arch));
        assert!(["no-config", "missing", "unnamed"].contains(&kind));
        if kind != "no-config" {
            assert_eq!(arch, "rsa");
        }
        Self::prepare(arch, kind, kind == "missing", "none")
    }

    pub fn invisible(named: bool, box_key: &'static str) -> Self {
        assert!(BOXES.contains(&box_key));
        Self::prepare("rsa", "invisible", named, box_key)
    }

    fn prepare(arch: &'static str, kind: &'static str, named: bool, box_key: &'static str) -> Self {
        let mut case = Self {
            base: BaseCase::new(arch, "visible"),
            kind,
            named,
            box_key,
            preparation: Value::Null,
        };
        // Keep inherited archive ownership, but put the exact originals in a
        // fresh directory. Original negative outputs begin absent.
        assert!(!case.cwd().exists());
        case.preparation = case.oracle("prepare");
        let expected = case.args();
        assert_eq!(case.preparation["native_argv"], json!(expected));
        assert!(!case.path("output.pdf").exists());
        assert_eq!(case.path("pyhanko.yml").exists(), kind != "no-config");
        for row in case.preparation["fixture_inputs"].as_array().unwrap() {
            let path = Path::new(row["path"].as_str().unwrap());
            assert!(path.starts_with(case.cwd()));
            let data = fs::read(path).unwrap();
            assert_eq!(row["sha256"], sha(&data));
            assert_eq!(row["length"], data.len());
        }
        case
    }

    pub fn cwd(&self) -> PathBuf {
        self.base.path("prepared-native")
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.cwd().join(name)
    }

    pub fn label(&self) -> String {
        format!(
            "{}/{}/named={}/{}",
            self.kind, self.base.arch, self.named, self.box_key
        )
    }

    pub fn args(&self) -> Vec<String> {
        if self.kind == "no-config" {
            let mut args = self.base.args();
            args.splice(2..2, ["--style-name".into(), "test".into()]);
            return args;
        }
        let mut args = vec!["sign".into(), "addsig".into()];
        if self.named {
            args.extend(["--field".into(), "Sig1".into()]);
        }
        args.extend(
            [
                "--style-name",
                "test",
                "pemder",
                "--no-pass",
                "--cert",
                "cert.pem",
                "--key",
                "signer.key.pem",
                "input.pdf",
                "output.pdf",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        args
    }

    pub fn inputs(&self) -> Vec<PathBuf> {
        let names: &[&str] = if self.kind == "no-config" {
            &[
                "input.pdf",
                "root.cert.pem",
                "interm.cert.pem",
                "signer.crt",
                "signer.key.pem",
            ]
        } else {
            &["input.pdf", "pyhanko.yml", "cert.pem", "signer.key.pem"]
        };
        names.iter().map(|name| self.path(name)).collect()
    }

    pub fn native(&self) -> Output {
        assert!(!self.path("output.pdf").exists());
        self.native_with_args(&self.args(), b"")
    }

    /// Actual CLI evidence for originals or separately labelled supplemental calls.
    pub fn native_with_args(&self, args: &[String], stdin: &[u8]) -> Output {
        let before = signing_record::before(&self.inputs());
        let output_before = self.output_snapshot();
        let mut child = Command::new(common::cli())
            .args(args)
            .current_dir(self.cwd())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let output = child.wait_with_output().unwrap();
        let frozen = self.path("native-output-frozen.pdf");
        let output_after = self.output_snapshot();
        if self.path("output.pdf").exists() {
            fs::copy(self.path("output.pdf"), &frozen).unwrap();
        }
        let attempt = self.path("native-attempt.json");
        fs::write(
            &attempt,
            serde_json::to_vec_pretty(&json!({
                "kind":"actual native CLI attempt; not a passing original",
                "case_kind":self.kind,"architecture":self.base.arch,
                "field_name_passed":self.named,"box_key":self.box_key,
                "argv":args,"exit_code":output.status.code(),
                "stdout":String::from_utf8_lossy(&output.stdout),
                "stderr":String::from_utf8_lossy(&output.stderr),
                "output_before":output_before,"output_after":output_after,
                "output_absent_after":!self.path("output.pdf").exists(),
                "inputs_before_use":before,
                "fixture_preparation":self.preparation,
                "oracle_script":file_snapshot(&helper()),
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(self.path("native-stdout.bin"), &output.stdout).unwrap();
        fs::write(self.path("native-stderr.bin"), &output.stderr).unwrap();
        let mut artifacts = vec![("native-attempt-and-output-absence", attempt.as_path())];
        if frozen.exists() {
            artifacts.push((
                "actual-native-output-frozen-before-reference",
                frozen.as_path(),
            ));
        }
        signing_record::process(
            "native-visible-negative-CLI",
            args,
            &self.cwd(),
            stdin,
            common::cli(),
            &output,
            &before,
            &artifacts,
        );
        output
    }

    fn output_snapshot(&self) -> Value {
        let path = self.path("output.pdf");
        if path.exists() {
            file_snapshot(&path)
        } else {
            Value::Null
        }
    }

    pub fn oracle(&self, mode: &str) -> Value {
        let cwd = self
            .base
            .path(&format!("visible-negative-{mode}-reference"));
        fs::create_dir_all(&cwd).unwrap();
        let mut args = vec![
            helper().display().to_string(),
            "--mode".into(),
            mode.into(),
            "--kind".into(),
            self.kind.into(),
            "--arch".into(),
            self.base.arch.into(),
            "--native-fixtures".into(),
            self.cwd().display().to_string(),
        ];
        if self.kind == "invisible" {
            args.extend([
                "--named".into(),
                self.named.to_string(),
                "--box".into(),
                self.box_key.into(),
            ]);
        }
        let mut inputs = vec![helper()];
        for name in ["test_cli_signing.py", "conftest.py"] {
            inputs.push(
                PathBuf::from("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests").join(name),
            );
        }
        if mode != "prepare" {
            inputs.extend(self.inputs());
            if self.path("output.pdf").exists() {
                inputs.push(self.path("output.pdf"));
            }
        }
        let before = signing_record::before(&inputs);
        let output = Command::new(python())
            .args(&args)
            .env("PYTHONOPTIMIZE", "0")
            .current_dir(&cwd)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        fs::write(cwd.join("reference-stdout.bin"), &output.stdout).unwrap();
        fs::write(cwd.join("reference-stderr.bin"), &output.stderr).unwrap();
        fs::write(cwd.join("reference.json"), &output.stdout).unwrap();
        let mut paths = Vec::new();
        collect_files(&cwd, &mut paths);
        if mode == "prepare" {
            collect_files(&self.cwd(), &mut paths);
        }
        let artifacts: Vec<_> = paths
            .iter()
            .map(|path| ("actual-reference-fixture-or-output", path.as_path()))
            .collect();
        signing_record::process(
            &format!("visible-negative-reference-{mode}"),
            &args,
            &cwd,
            b"",
            &python(),
            &output,
            &before,
            &artifacts,
        );
        assert!(
            output.status.success(),
            "{mode}/{}: {}",
            self.label(),
            text(&output)
        );
        let record: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record["success"], true, "{record}");
        assert_eq!(record["versions"]["pyhanko"], "0.38.1");
        assert_eq!(record["versions"]["pyhanko-certvalidator"], "0.33.0");
        record
    }

    pub fn reference(&self) -> Value {
        let record = self.oracle("original");
        assert_eq!(record["original_body_completed"], true);
        assert_eq!(record["original_output_existed"], false);
        assert_eq!(
            record["original_teardown_applicable"],
            self.kind == "no-config"
        );
        if self.kind == "no-config" {
            assert_eq!(record["full_post_validate_teardown_completed"], true);
        }
        self.assert_reference_call(&record);
        record
    }

    pub fn inspect_negative(&self) -> Value {
        let record = self.oracle("inspect-negative");
        assert_eq!(record["same_native_input_negative_completed"], true);
        assert_eq!(record["native_state_before"], record["native_state_after"]);
        self.assert_reference_call(&record);
        record
    }

    fn assert_reference_call(&self, record: &Value) {
        let calls = record["calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_negative(
            self.kind,
            call["exit_code"].as_i64().map(|value| value as i32),
            call["output"].as_str().unwrap(),
        );
        assert!(call["output_before"].is_null(), "{record}");
        assert!(call["output_after"].is_null(), "{record}");
        assert_eq!(call["input_before"], call["input_after"]);
    }
}

fn file_snapshot(path: &Path) -> Value {
    let data = fs::read(path).unwrap();
    json!({"path":path.canonicalize().unwrap(),"length":data.len(),"sha256":sha(&data)})
}
