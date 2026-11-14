//! Complete exact decode-limit pairs and durable per-process evidence.
use crate::{common, signing_record};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

pub const FLAG: &str = "--no-decode-limits";
pub const SENTINEL: &[u8] = b"decode-limits-simple-output-sentinel";
pub const SIMPLE: [&str; 4] = ["encrypt", "list", "addfields", "addfields-resave"];
pub fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}
fn helper() -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "decode-limits-simple", "oracle.py"])
}
pub struct Case {
    pub dir: tempfile::TempDir,
    pub kind: &'static str,
}
impl Case {
    pub fn new(kind: &'static str) -> Self {
        let c = Self {
            dir: tempfile::tempdir().unwrap(),
            kind,
        };
        c.oracle("prepare", c.dir.path(), None);
        fs::write(c.path("out.pdf"), SENTINEL).unwrap();
        c
    }
    pub fn path(&self, n: &str) -> PathBuf {
        self.dir.path().join(n)
    }
    pub fn args(&self, trusted: bool) -> Vec<String> {
        let mut a: Vec<String> = match self.kind {
            "encrypt" => [
                "encrypt",
                FLAG,
                "--password",
                "secret",
                "input.pdf",
                "out.pdf",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            "list" => ["sign", "list", FLAG, "input.pdf"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            "addfields" | "addfields-resave" => {
                let mut a = vec!["sign".into(), "addfields".into(), FLAG.into()];
                if self.kind == "addfields-resave" {
                    a.push("--resave".into());
                }
                a.extend(
                    ["--field", "1/0,0,100,100/Sig1", "input.pdf", "out.pdf"]
                        .into_iter()
                        .map(str::to_owned),
                );
                a
            }
            "text" => [
                "stamp",
                FLAG,
                "--style-name",
                "test",
                "input.pdf",
                "out.pdf",
                "0",
                "0",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            "qr" => [
                "stamp",
                FLAG,
                "--style-name",
                "test",
                "--stamp-url",
                "https://example.com",
                "input.pdf",
                "out.pdf",
                "0",
                "0",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            _ => panic!("unexpected case"),
        };
        if !trusted {
            a.retain(|v| v != FLAG);
        }
        a
    }
    pub fn inputs(&self) -> Vec<PathBuf> {
        let mut p = vec![self.path("input.pdf")];
        if self.path("pyhanko.yml").exists() {
            p.push(self.path("pyhanko.yml"));
        }
        p
    }
    pub fn oracle(&self, mode: &str, cwd: &Path, file: Option<&Path>) -> Value {
        let python = sigis_testdata::oracle::python().expect("Pinned oracle is mandatory");
        let script = helper();
        let mut inputs = vec![script.clone()];
        if mode == "same-input" {
            inputs.push(cwd.join("input.pdf"));
        }
        if let Some(file) = file {
            inputs.push(file.to_path_buf());
        }
        let before = signing_record::before(&inputs);
        let mut args = vec![
            script.to_string_lossy().into_owned(),
            mode.into(),
            self.kind.into(),
        ];
        if let Some(file) = file {
            args.extend(["--file".into(), file.to_string_lossy().into_owned()]);
        }
        let result = Command::new(&python)
            .args(&args)
            .env("PYTHONOPTIMIZE", "0")
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let report_path = self.path(&format!("reference-{mode}.json"));
        fs::write(&report_path, &result.stdout).unwrap();
        let mut files = vec![("reference-json", report_path.as_path())];
        let reference_files: Vec<_> = ["input.pdf", "out.pdf", "pyhanko.yml"]
            .into_iter()
            .map(|name| cwd.join("original-artifacts").join(name))
            .chain(std::iter::once(cwd.join("out.pdf")))
            .filter(|path| path.is_file() && mode != "prepare")
            .collect();
        for file in &reference_files {
            files.push(("reference-artifact-or-sentinel", file.as_path()));
        }
        let fresh_input = self.path("input.pdf");
        if mode == "prepare" {
            files.push(("fresh-fixture-input", fresh_input.as_path()));
        }
        signing_record::process(
            &format!("decode-simple-oracle-{mode}-{}", self.kind),
            &args,
            cwd,
            b"",
            &python,
            &result,
            &before,
            &files,
        );
        assert!(
            result.status.success(),
            "oracle {mode}/{}: {}",
            self.kind,
            text(&result)
        );
        let parsed: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(parsed["success"], true);
        parsed
    }
    pub fn native(&self, trusted: bool) -> Output {
        let args = self.args(trusted);
        let before = signing_record::before(&self.inputs());
        let result = Command::new(common::cli())
            .args(&args)
            .current_dir(self.dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let frozen = self.path(if trusted {
            "native-trusted.pdf"
        } else {
            "native-default.pdf"
        });
        fs::copy(self.path("out.pdf"), &frozen).unwrap();
        let attempt = self.path(if trusted {
            "native-trusted.json"
        } else {
            "native-default.json"
        });
        fs::write(&attempt, serde_json::to_vec_pretty(&json!({"case":self.kind,"trusted":trusted,"argv":args,"code":result.status.code()})).unwrap()).unwrap();
        signing_record::process(
            &format!("decode-simple-native-{}-{}", self.kind, trusted),
            &args,
            self.dir.path(),
            b"",
            common::cli(),
            &result,
            &before,
            &[
                ("native-output-or-sentinel", &frozen),
                ("attempt", &attempt),
            ],
        );
        result
    }
    /// Run both reference modes after native bytes are frozen; these are distinct calls.
    pub fn references(&self) {
        let original = tempfile::tempdir().unwrap();
        let result = self.oracle("original", original.path(), None);
        assert_eq!(result["original_body_completed"], true);
        let same = tempfile::tempdir().unwrap();
        for file in self.inputs() {
            fs::copy(&file, same.path().join(file.file_name().unwrap())).unwrap();
        }
        fs::write(same.path().join("out.pdf"), SENTINEL).unwrap();
        let result = self.oracle("same-input", same.path(), None);
        assert_eq!(result["same_input_check_completed"], true);
    }
    pub fn check(&self) -> Result<(), String> {
        let default = self.native(false);
        let default_sentinel = fs::read(self.path("out.pdf")).unwrap() == SENTINEL;
        let trusted = self.native(true);
        // Keep all peers and parameters measured even if the native opt-out is broken.
        self.references();
        let mut errors = Vec::new();
        if default.status.code() != Some(1) {
            errors.push(format!("default exit: {}", text(&default)));
        }
        if !text(&default).contains("rerun with --no-decode-limits") {
            errors.push(format!("default diagnostic: {}", text(&default)));
        }
        if !default_sentinel {
            errors.push("default changed output sentinel".into());
        }
        if !trusted.status.success() {
            errors.push(format!("trusted exit: {}", text(&trusted)));
        }
        if trusted.status.success() {
            if self.kind == "list" {
                if !trusted.stdout.is_empty() {
                    errors.push(format!("empty fields listing: {}", text(&trusted)));
                }
                assert_eq!(fs::read(self.path("out.pdf")).unwrap(), SENTINEL);
            } else {
                self.check_native_pdf();
                self.oracle(
                    "inspect",
                    self.dir.path(),
                    Some(&self.path("native-trusted.pdf")),
                );
            }
        } else {
            assert_eq!(
                fs::read(self.path("out.pdf")).unwrap(),
                SENTINEL,
                "failed edit changed output"
            );
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!("{}: {}", self.kind, errors.join("\n")))
        }
    }
    fn check_native_pdf(&self) {
        use sigis_pdf::{
            crypt::AuthStatus, decode_limits::DecodeLimits, PdfFile, PdfHandlerExt, ReaderOptions,
        };
        let bytes = fs::read(self.path("native-trusted.pdf")).unwrap();
        let reader = PdfFile::parse_with(
            &bytes,
            ReaderOptions {
                strict: false,
                decode_limits: DecodeLimits::for_trusted_input(),
                ..Default::default()
            },
        )
        .unwrap();
        if self.kind == "encrypt" {
            assert!(reader.encrypted());
            assert_eq!(reader.decrypt("secret").unwrap().status, AuthStatus::Owner);
        } else {
            assert!(!reader.encrypted());
        }
        let pages = reader
            .get_dict(&reader.root().unwrap(), b"Pages")
            .unwrap()
            .unwrap();
        assert_eq!(pages.get(b"Count").unwrap().as_i64().unwrap(), 1);
        let fields = sigis_pdf::signatures::enumerate_sig_fields(&reader, None, None).unwrap();
        if self.kind.starts_with("addfields") {
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].fq_name, "Sig1");
            assert!(fields[0].value.is_none());
        } else {
            assert!(fields.is_empty());
        }
        assert_eq!(
            reader.total_revisions(),
            if self.kind == "encrypt" || self.kind.ends_with("resave") {
                1
            } else {
                2
            }
        );
    }
}
