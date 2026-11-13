//! Assertion ports of pyHanko 0.38.1 `test_cli_signing.py`.
//! Two unique original functions / eight architecture parameters.
//! Every success signs actual input and retains fresh oracle and native trust controls.
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;

use sigis_pdf::{signatures::enumerate_sig_fields, PdfFile};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

thread_local! { static ARCH:std::cell::Cell<&'static str> = const { std::cell::Cell::new("rsa") }; }
struct Case {
    dir: tempfile::TempDir,
    input: PathBuf,
    output: PathBuf,
}
fn fixture(name: &str) -> PathBuf {
    ARCH.with(|v| sigis_testdata::path(&["lanes", "r3-c", "signing", v.get(), name]))
}
fn python() -> PathBuf {
    std::env::var_os("HANKO_ORACLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/pyhanko-oracle/venv/bin/python"))
}
fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.pdf");
        let output = dir.path().join("output.pdf");
        std::fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &input).unwrap();
        Self { dir, input, output }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn args(&self, common: &[&str], provider: &str, provider_args: &[&str]) -> Vec<String> {
        let mut a = vec!["sign".into(), "addsig".into()];
        a.extend(common.iter().map(|s| s.to_string()));
        a.push(provider.into());
        a.extend(provider_args.iter().map(|s| s.to_string()));
        a.push(self.input.to_string_lossy().into_owned());
        a.push(self.output.to_string_lossy().into_owned());
        a
    }
    fn pem(&self, common: &[&str]) -> Vec<String> {
        let cert = self.path("signer.der");
        // The pinned cert_chain fixture writes the leaf as DER and the
        // intermediate as PEM. Preserve those actual original input encodings.
        let chain = fixture("interm.pem");
        let bytes = std::fs::read(fixture("cert.pem")).unwrap();
        let x509 = openssl::x509::X509::from_pem(&bytes).unwrap();
        std::fs::write(&cert, x509.to_der().unwrap()).unwrap();
        self.args(
            common,
            "pemder",
            &[
                "--no-pass",
                "--key",
                fixture("key.pem").to_str().unwrap(),
                "--cert",
                cert.to_str().unwrap(),
                "--chain",
                chain.to_str().unwrap(),
            ],
        )
    }
    fn run(&self, args: &[String], input: &str) -> Output {
        let inputs = self.inputs(args);
        let mut child = Command::new(common::cli())
            .args(args)
            .current_dir(self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let artifacts = if self.output.exists() {
            vec![("native_signed_output", self.output.as_path())]
        } else {
            Vec::new()
        };
        signing_record::process(
            "native-cli",
            args,
            self.dir.path(),
            input.as_bytes(),
            common::cli(),
            &output,
            &inputs,
            &artifacts,
        );
        output
    }
    fn inputs(&self, args: &[String]) -> Vec<serde_json::Value> {
        let mut paths = args
            .iter()
            .map(|arg| {
                let path = PathBuf::from(arg);
                if path.is_absolute() {
                    path
                } else {
                    self.dir.path().join(path)
                }
            })
            .filter(|path| {
                path.is_file() && path != &self.output && path != &self.path("oracle.pdf")
            })
            .collect::<Vec<_>>();
        paths.extend([self.input.clone(), fixture("root.pem")]);
        if self.path("pyhanko.yml").is_file() {
            paths.push(self.path("pyhanko.yml"));
        }
        paths.sort();
        paths.dedup();
        signing_record::before(&paths)
    }
    fn oracle(&self, args: &[String], input: &str) -> (i32, String) {
        let inputs = self.inputs(args);
        let script = sigis_testdata::path(&["lanes", "r3-c", "signing", "oracle_cli.py"]);
        common::record_file(&script, "signing_oracle_cli_driver");
        let out = Command::new(python())
            .arg(sigis_testdata::path(&[
                "lanes",
                "r3-c",
                "signing",
                "oracle_cli.py",
            ]))
            .arg(input)
            .arg(ARCH.with(|v| v.get()))
            .args(args)
            .current_dir(self.dir.path())
            .output()
            .expect("live pinned oracle required");
        let mut actual_args = vec![
            script.to_string_lossy().into_owned(),
            input.to_owned(),
            ARCH.with(|v| v.get()).into(),
        ];
        actual_args.extend_from_slice(args);
        let artifacts = [self.path("oracle.pdf"), self.output.clone()];
        let artifacts = artifacts
            .iter()
            .filter(|path| path.exists())
            .map(|path| ("reference_or_retained_native_output", path.as_path()))
            .collect::<Vec<_>>();
        signing_record::process(
            "reference-cli",
            &actual_args,
            self.dir.path(),
            b"",
            &python(),
            &out,
            &inputs,
            &artifacts,
        );
        assert!(out.status.success(), "{}", text(&out));
        let stdout = String::from_utf8(out.stdout).unwrap();
        let (code, text) = stdout.split_once('\n').unwrap();
        (code.parse().unwrap(), text.into())
    }
    fn success(&self, args: &[String], input: &str) {
        let out = self.run(args, input);
        assert!(out.status.success(), "{}", text(&out));
        let bytes = std::fs::read(&self.output).unwrap();
        let pdf = PdfFile::parse(&bytes).unwrap();
        if !pdf.encrypted() {
            assert_eq!(
                enumerate_sig_fields(&pdf, Some(true), None).unwrap().len(),
                1
            );
            assert_eq!(pdf.embedded_signatures().unwrap().len(), 1);
        }
        self.verify_with_options(
            &self.output,
            args.iter().any(|arg| arg == "--no-strict-syntax"),
        );
        if matches!(
            std::thread::current().name(),
            Some("test_cli_addsig_pemder" | "test_cli_addsig_p12")
        ) {
            self.native_trust_controls();
        }
        let mut other = args.to_vec();
        for value in &mut other {
            if value == self.output.to_str().unwrap() {
                *value = self.path("oracle.pdf").to_string_lossy().into_owned();
            }
        }
        let (code, message) = self.oracle(&other, input);
        assert_eq!(code, 0, "{message}");
    }
    fn native_trust_controls(&self) {
        let root = fixture("root.pem");
        for trusted in [true, false] {
            let mut args = vec![
                "sign".into(),
                "validate".into(),
                "--validation-time".into(),
                "2020-08-01T00:00:00Z".into(),
                "--no-revocation-check".into(),
                "--trust-replace".into(),
            ];
            if trusted {
                args.extend(["--trust".into(), root.to_string_lossy().into_owned()]);
            }
            args.push(self.output.to_string_lossy().into_owned());
            let inputs = signing_record::before(&[self.output.clone(), root.clone()]);
            let output = Command::new(common::cli())
                .args(&args)
                .current_dir(self.dir.path())
                .output()
                .unwrap();
            signing_record::process(
                if trusted {
                    "native-trusted-control"
                } else {
                    "native-no-roots-control"
                },
                &args,
                self.dir.path(),
                b"",
                common::cli(),
                &output,
                &inputs,
                &[],
            );
            assert_eq!(
                output.status.code(),
                Some(if trusted { 0 } else { 1 }),
                "{}",
                text(&output)
            );
            assert!(
                text(&output).contains(if trusted {
                    "INTACT:TRUSTED"
                } else {
                    "UNTRUSTED"
                }),
                "{}",
                text(&output)
            );
        }
    }
    fn verify_with_options(&self, path: &Path, allow_hybrid: bool) {
        let mut command = Command::new(python());
        command
            .arg(sigis_testdata::path(&[
                "lanes",
                "r3-c",
                "signing",
                "oracle_verify.py",
            ]))
            .arg(path)
            .arg(&self.input)
            .arg(fixture("root.pem"))
            .arg(ARCH.with(|v| v.get()));
        if allow_hybrid {
            command.arg("--allow-hybrid-xrefs");
        }
        let basic = matches!(
            std::thread::current().name(),
            Some("test_cli_addsig_pemder" | "test_cli_addsig_p12")
        );
        if basic {
            command.arg("--trust-controls");
        }
        let actual_args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let inputs = signing_record::before(&[
            path.to_path_buf(),
            self.input.clone(),
            fixture("root.pem"),
            PathBuf::from(&actual_args[0]),
        ]);
        let out = command.output().unwrap();
        signing_record::process(
            "reference-validation",
            &actual_args,
            &std::env::current_dir().unwrap(),
            b"",
            &python(),
            &out,
            &inputs,
            &[("validated_native_signed_output", path)],
        );
        assert!(out.status.success(), "{}", text(&out));
        if basic {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let line = stderr
                .lines()
                .find_map(|line| line.strip_prefix("SIGNING_ORACLE_VERIFY "))
                .expect("fresh oracle validation receipt required");
            let receipt: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(
                receipt["controls"]["original_integrity"],
                serde_json::json!([true, true])
            );
            assert_eq!(
                receipt["controls"]["wrong_digest_integrity"],
                serde_json::json!([false, true])
            );
            assert_eq!(receipt["controls"]["no_roots"]["bottom_line"], false);
            assert_eq!(receipt["bottom_line"], true);
        }
    }
}
macro_rules! basic {
    ($name:ident,$field:expr) => {
        #[test]
        fn $name() {
            for architecture in architectures(stringify!($name)) {
                ARCH.with(|v| v.set(architecture));
                let c = Case::new();
                c.success(&c.pem(&["--field", $field]), "");
            }
        }
    };
}
basic!(test_cli_addsig_pemder, "Sig1");
fn p12(c: &Case, no_pass: bool, plain: bool) -> Vec<String> {
    let mut a = c.args(
        &["--field", "Sig1"],
        "pkcs12",
        if no_pass { &["--no-pass"] } else { &[] },
    );
    a.push(
        fixture(if plain { "plain.p12" } else { "signer.p12" })
            .to_string_lossy()
            .into_owned(),
    );
    a
}
#[test]
fn test_cli_addsig_p12() {
    for architecture in architectures("test_cli_addsig_p12") {
        ARCH.with(|v| v.set(architecture));
        let c = Case::new();
        c.success(&p12(&c, false, false), "secret\n");
    }
}
/// Exact inherited architecture matrix for the two original functions.
fn architectures(name: &str) -> Vec<&'static str> {
    match name {
        "test_cli_addsig_pemder" | "test_cli_addsig_p12" => {
            vec!["rsa", "ecdsa", "ed25519", "ed448"]
        }
        _ => panic!("Unexpected software signing test: {name}"),
    }
}

/// Supplemental actual-process authentication refusal; zero extra upstream credit.
#[test]
fn wrong_p12_password_rejects_without_artifact() {
    for architecture in ["rsa", "ecdsa", "ed25519", "ed448"] {
        ARCH.with(|v| v.set(architecture));
        let c = Case::new();
        let args = p12(&c, false, false);
        let output = c.run(&args, "incorrect-fixture-passphrase\n");
        assert_eq!(output.status.code(), Some(1), "{}", text(&output));
        assert!(
            text(&output).contains("Could not load key material"),
            "{}",
            text(&output)
        );
        assert!(!c.output.exists());
        let (code, message) = c.oracle(&args, "incorrect-fixture-passphrase\n");
        assert_eq!(code, 1, "{message}");
        assert!(!c.output.exists());
    }
}
