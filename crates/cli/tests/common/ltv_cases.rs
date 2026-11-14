// The LTV and decode-signing integration targets exercise different helpers.
#![allow(dead_code)]
use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
};

fn helper() -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "ltv-remaining", "helper.py"])
}
fn python() -> PathBuf {
    std::env::var_os("HANKO_ORACLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/tmp/pyhanko-oracle/venv/bin/python".into())
}
fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
fn native_text(output: &sigis_cli::Output) -> String {
    format!("{}{}", output.stdout, output.stderr)
}

pub struct Case {
    directory: tempfile::TempDir,
    server: Child,
    url: String,
    oversized: bool,
}

impl Case {
    pub fn new(architecture: &str, oversized: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut server = Command::new(python())
            .arg("-B")
            .arg(helper())
            .arg("serve")
            .arg(architecture)
            .arg(directory.path())
            .arg(sigis_testdata::pyhanko(&["crypto"]))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(server.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(
            line.starts_with("http://127.0.0.1:"),
            "test-owned server readiness: {line}"
        );
        let url = line.trim().to_owned();
        fs::copy(
            if oversized {
                sigis_testdata::path(&["lanes", "r3-c", "decode-limits-simple", "oversized.pdf"])
            } else {
                sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])
            },
            directory.path().join("input.pdf"),
        )
        .unwrap();
        let case = Self {
            directory,
            server,
            url,
            oversized,
        };
        case.write_config();
        case
    }
    fn write_config(&self) {
        let config = serde_json::json!({
            "pkcs12-setups":{"test":{"pfx-file":self.directory.path().join("credential.p12"),"pfx-passphrase":"secret"}},
            "validation-contexts":{"test":{"trust":self.directory.path().join("root.der"),"trust-replace":true}},
        });
        fs::write(
            self.directory.path().join("pyhanko.yml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();
    }
    fn run(&self, args: &[String]) -> sigis_cli::Output {
        let mut absolute = vec![
            "-c".to_owned(),
            self.directory
                .path()
                .join("pyhanko.yml")
                .display()
                .to_string(),
        ];
        absolute.extend(args.iter().map(|arg| {
            if ["input.pdf", "signed.pdf", "out.pdf", "before-ltv.pdf"].contains(&arg.as_str()) {
                self.directory.path().join(arg).display().to_string()
            } else {
                arg.clone()
            }
        }));
        // The accepted top-level API mirrors upstream CliRunner. A real NOW
        // runtime keeps current HTTP/crypto behavior without a shared-bin alias.
        sigis_cli::run_with_runtime(
            &absolute,
            &sigis_cli::plugins::PluginRegistry::default(),
            &sigis_cli::runtime::ValidationRuntime::default(),
        )
    }
    pub fn sign(&self, embed_info: bool) {
        let mut args: Vec<String> = [
            "sign",
            "addsig",
            "--field",
            "Sig1",
            "--use-pades",
            "--timestamp-url",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        args.push(self.url.clone());
        if self.oversized {
            args.push("--no-decode-limits".into());
        }
        if embed_info {
            args.extend([
                "--validation-context".into(),
                "test".into(),
                "--with-validation-info".into(),
            ]);
        }
        args.extend(
            ["pkcs12", "--p12-setup", "test", "input.pdf", "signed.pdf"].map(str::to_owned),
        );
        let result = self.run(&args);
        assert_eq!(result.code, 0, "{}", native_text(&result));
        fs::copy(
            self.directory.path().join("signed.pdf"),
            self.directory.path().join("before-ltv.pdf"),
        )
        .unwrap();
    }
    pub fn sign_decode(&self, lta: bool) {
        assert!(self.oversized);
        let mut args: Vec<String> = [
            "sign",
            "addsig",
            "--no-decode-limits",
            "--field",
            "Sig1",
            "--use-pades",
            "--timestamp-url",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        args.push(self.url.clone());
        if lta {
            args.extend([
                "--validation-context".into(),
                "test".into(),
                "--use-pades-lta".into(),
            ]);
        }
        args.extend(
            ["pkcs12", "--p12-setup", "test", "input.pdf", "signed.pdf"].map(str::to_owned),
        );
        let input = fs::read(self.directory.path().join("input.pdf")).unwrap();
        let sentinel = b"decode-signing-output-sentinel";
        fs::write(self.directory.path().join("signed.pdf"), sentinel).unwrap();
        let default_args = args
            .iter()
            .filter(|arg| arg.as_str() != "--no-decode-limits")
            .cloned()
            .collect::<Vec<_>>();
        let rejected = self.run(&default_args);
        assert_eq!(rejected.code, 1, "{}", native_text(&rejected));
        assert!(
            native_text(&rejected).contains("rerun with --no-decode-limits"),
            "{}",
            native_text(&rejected)
        );
        assert_eq!(
            fs::read(self.directory.path().join("signed.pdf")).unwrap(),
            sentinel
        );
        assert_eq!(
            fs::read(self.directory.path().join("input.pdf")).unwrap(),
            input
        );
        let result = self.run(&args);
        assert_eq!(result.code, 0, "{}", native_text(&result));
        assert_eq!(
            fs::read(self.directory.path().join("input.pdf")).unwrap(),
            input
        );
        fs::copy(
            self.directory.path().join("signed.pdf"),
            self.directory.path().join("before-ltv.pdf"),
        )
        .unwrap();
    }
    pub fn validate_decode(&self, command: &str) {
        assert!(self.oversized);
        let signed = fs::read(self.directory.path().join("signed.pdf")).unwrap();
        let appended = self.run(
            &[
                "sign",
                "addfields",
                "--no-decode-limits",
                "--field",
                "1/0,0,100,100/Sig2",
                "signed.pdf",
                "out.pdf",
            ]
            .map(str::to_owned),
        );
        assert_eq!(appended.code, 0, "{}", native_text(&appended));
        assert_eq!(
            fs::read(self.directory.path().join("signed.pdf")).unwrap(),
            signed
        );
        let before = fs::read(self.directory.path().join("out.pdf")).unwrap();
        let args = [
            "sign",
            command,
            "--no-decode-limits",
            "--validation-context",
            "test",
            "--no-revocation-check",
            "out.pdf",
        ]
        .map(str::to_owned);
        let default_args = args
            .iter()
            .filter(|arg| arg.as_str() != "--no-decode-limits")
            .cloned()
            .collect::<Vec<_>>();
        let rejected = self.run(&default_args);
        assert_eq!(rejected.code, 1, "{}", native_text(&rejected));
        assert!(
            native_text(&rejected).contains("rerun with --no-decode-limits"),
            "{}",
            native_text(&rejected)
        );
        let result = self.run(&args);
        assert_eq!(result.code, 0, "{}", native_text(&result));
        assert_eq!(
            fs::read(self.directory.path().join("out.pdf")).unwrap(),
            before
        );
    }
    pub fn command(&self, command: &str, timestamp: bool, allow: bool) {
        let mut args = vec![
            "sign".into(),
            command.into(),
            "--validation-context".into(),
            "test".into(),
        ];
        if command == "ltvfix" {
            args.extend(["--field".into(), "Sig1".into()]);
        }
        if timestamp {
            args.extend(["--timestamp-url".into(), self.url.clone()]);
        }
        if self.oversized && allow {
            args.push("--no-decode-limits".into());
        }
        args.push("signed.pdf".into());
        let before = fs::read(self.directory.path().join("signed.pdf")).unwrap();
        let result = self.run(&args);
        if self.oversized && !allow {
            assert_eq!(result.code, 1, "{}", native_text(&result));
            assert!(
                native_text(&result).contains("rerun with --no-decode-limits"),
                "{}",
                native_text(&result)
            );
            assert_eq!(
                fs::read(self.directory.path().join("signed.pdf")).unwrap(),
                before
            );
        } else {
            assert_eq!(result.code, 0, "{}", native_text(&result));
        }
    }
    pub fn require_signed_field(&self) {
        let args = [
            "sign",
            "ltvfix",
            "--field",
            "Sig1",
            "--validation-context",
            "test",
            "input.pdf",
        ]
        .map(str::to_owned);
        let before = fs::read(self.directory.path().join("input.pdf")).unwrap();
        let result = self.run(&args);
        assert_eq!(result.code, 1);
        assert!(
            native_text(&result).contains("Could not find a PDF signature labelled Sig1"),
            "{}",
            native_text(&result)
        );
        assert_eq!(
            fs::read(self.directory.path().join("input.pdf")).unwrap(),
            before
        );
    }
    pub fn check(&self, timestamps: usize) {
        let bytes = fs::read(self.directory.path().join("signed.pdf")).unwrap();
        let mut options = sigis_pdf::ReaderOptions::default();
        if self.oversized {
            options.decode_limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input();
        }
        let pdf = sigis_pdf::PdfFile::parse_with(&bytes, options).unwrap();
        let sigs = pdf.embedded_signatures().unwrap();
        assert_eq!(
            sigs.iter()
                .filter(|s| s.kind == sigis_pdf::SignatureKind::DocTimeStamp)
                .count(),
            timestamps
        );
        assert_eq!(
            sigs.iter()
                .filter(|s| s.kind == sigis_pdf::SignatureKind::Signature)
                .count(),
            1
        );
        let result = Command::new(python())
            .arg("-B")
            .arg(helper())
            .arg("verify")
            .arg(self.directory.path())
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", text(&result));
    }
    pub fn reference(&self, kind: &str, timestamp: bool) {
        let result = Command::new(python())
            .arg("-B")
            .arg(helper())
            .arg("reference")
            .arg(self.directory.path())
            .arg(kind)
            .arg(if timestamp { "yes" } else { "no" })
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", text(&result));
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        // This child is created exclusively by this test, never an existing service.
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}
