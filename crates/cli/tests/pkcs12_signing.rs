//! Assertion ports of pyHanko 0.38.1 `test_cli_signing.py`.
//! Eight new PKCS#12 functions / 28 complete source parameters.
//! Four non-parametrised error functions run once each.
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
/// Collect actual files referenced indirectly by the configuration, before use.
fn collect_config_files(value: &serde_json::Value, cwd: &Path, paths: &mut Vec<PathBuf>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if matches!(
                    key.replace('_', "-").as_str(),
                    "pfx-file" | "trust" | "other-certs" | "key-file" | "cert-file" | "passfile"
                ) {
                    collect_file_values(value, cwd, paths);
                } else {
                    collect_config_files(value, cwd, paths);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_config_files(value, cwd, paths);
            }
        }
        _ => {}
    }
}
fn collect_file_values(value: &serde_json::Value, cwd: &Path, paths: &mut Vec<PathBuf>) {
    match value {
        serde_json::Value::String(name) => {
            let path = PathBuf::from(name);
            let path = if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            };
            if path.is_file() {
                paths.push(path);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_file_values(value, cwd, paths);
            }
        }
        _ => {}
    }
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
    fn config(&self, value: serde_json::Value) {
        std::fs::write(
            self.path("pyhanko.yml"),
            serde_yaml::to_string(&value).unwrap(),
        )
        .unwrap();
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
            let config_path = self.path("pyhanko.yml");
            let value: serde_json::Value =
                serde_yaml::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
            collect_config_files(&value, self.dir.path(), &mut paths);
            paths.push(config_path);
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
        self.native_trust_controls();
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
        command.arg("--trust-controls");
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
    fn error(&self, args: &[String], expected: &[&str]) {
        let out = self.run(args, "wrong\n");
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        for expected in expected {
            assert!(text(&out).contains(expected), "{}", text(&out));
        }
        assert!(
            !self.output.exists(),
            "Native failure must not leave a signed artifact"
        );
        let (code, message) = self.oracle(args, "wrong\n");
        assert_eq!(code, 1, "{message}");
        for expected in expected {
            assert!(message.contains(expected), "{message}");
        }
        assert!(
            !self.output.exists(),
            "Reference failure must not leave a signed artifact"
        );
    }
}
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
// Basic P12 remains in root C2 software_signing.rs; no duplicate original.

#[test]
fn test_cli_addsig_unencrypted_p12() {
    for architecture in architectures("test_cli_addsig_unencrypted_p12") {
        ARCH.with(|v| v.set(architecture));
        let c = Case::new();
        c.success(&p12(&c, true, true), "");
    }
}

#[test]
fn test_cli_addsig_unencrypted_p12_without_nopass() {
    for architecture in architectures("test_cli_addsig_unencrypted_p12_without_nopass") {
        ARCH.with(|v| v.set(architecture));
        let c = Case::new();
        c.success(&p12(&c, false, true), "\n");
    }
}

#[test]
fn test_cli_addsig_p12_with_setup() {
    for architecture in architectures("test_cli_addsig_p12_with_setup") {
        ARCH.with(|v| v.set(architecture));
        for location in ["config", "prompt", "file"] {
            let c = Case::new();
            let mut cfg =
                serde_json::json!({"pkcs12-setups":{"test":{"pfx-file":fixture("signer.p12")}}});
            if location == "config" {
                cfg["pkcs12-setups"]["test"]["pfx_passphrase"] = "secret".into();
            }
            c.config(cfg);
            let mut p = vec!["--p12-setup", "test"];
            if location == "file" {
                std::fs::write(c.path("passfile"), "secret").unwrap();
                p.extend(["--passfile", "passfile"]);
            }
            c.success(
                &c.args(&["--field", "Sig1"], "pkcs12", &p),
                if location == "prompt" { "secret\n" } else { "" },
            );
        }
    }
}

#[test]
fn test_cli_addsig_p12_setup_requires_config() {
    ARCH.with(|v| v.set("rsa"));
    let c = Case::new();
    c.error(
        &c.args(&["--field", "Sig1"], "pkcs12", &["--p12-setup", "blah"]),
        &["requires a configuration file"],
    );
}

#[test]
fn test_cli_addsig_p12_setup_unreadable() {
    ARCH.with(|v| v.set("rsa"));
    let c = Case::new();
    c.config(serde_json::json!({"p12-setup":{}}));
    c.error(
        &c.args(&["--field", "Sig1"], "pkcs12", &["--p12-setup", "blah"]),
        &["Error while reading PKCS#12 config"],
    );
}

#[test]
fn test_cli_addsig_p12_setup_corrupted_keystore() {
    ARCH.with(|v| v.set("rsa"));
    let c = Case::new();
    std::fs::write(c.path("bad.p12"), [0xde, 0xad, 0xbe, 0xef]).unwrap();
    c.config(serde_json::json!({"pkcs12-setups":{"blah":{"pfx-file":"bad.p12"}}}));
    c.error(
        &c.args(
            &["--field", "Sig1"],
            "pkcs12",
            &["--no-pass", "--p12-setup", "blah"],
        ),
        &["Could not load key material"],
    );
}

#[test]
fn test_cli_addsig_p12_setup_or_pfx_argument_required() {
    ARCH.with(|v| v.set("rsa"));
    let c = Case::new();
    c.config(serde_json::json!({"p12-setup":{}}));
    c.error(
        &c.args(&["--field", "Sig1"], "pkcs12", &[]),
        &["argument or the --p12-setup"],
    );
}

#[test]
fn test_cli_addsig_p12_passfile() {
    for architecture in architectures("test_cli_addsig_p12_passfile") {
        ARCH.with(|v| v.set(architecture));
        let c = Case::new();
        std::fs::write(c.path("passfile"), "secret").unwrap();
        let mut a = p12(&c, false, false);
        a.splice(5..5, ["--passfile".into(), "passfile".into()]);
        c.success(&a, "");
    }
}
/// Inherited architecture cases; the four error originals are not parametrised.
fn architectures(name: &str) -> Vec<&'static str> {
    match name {
        "test_cli_addsig_unencrypted_p12"
        | "test_cli_addsig_unencrypted_p12_without_nopass"
        | "test_cli_addsig_p12_with_setup"
        | "test_cli_addsig_p12_passfile" => vec!["rsa", "ecdsa", "ed25519", "ed448"],
        _ => panic!("Unexpected PKCS#12 signing test: {name}"),
    }
}

/// Supplemental actual-process password precedence; not another original ID.
#[test]
fn configured_password_precedes_passfile_and_passfile_precedes_no_pass() {
    ARCH.with(|value| value.set("rsa"));
    for (configured, file, no_pass, expected) in [
        (Some("incorrect-configured-password"), "secret", false, 1),
        (Some("secret"), "incorrect-file-password", false, 0),
        (None, "secret\nignored second line", true, 0),
        (None, "  secret  \nignored second line", false, 0),
    ] {
        let case = Case::new();
        let mut setup = serde_json::json!({"pfx-file":fixture("signer.p12")});
        if let Some(password) = configured {
            setup["pfx-passphrase"] = password.into();
        }
        case.config(serde_json::json!({"pkcs12-setups":{"test":setup}}));
        std::fs::write(case.path("passfile"), file).unwrap();
        let mut provider = vec!["--p12-setup", "test", "--passfile", "passfile"];
        if no_pass {
            provider.push("--no-pass");
        }
        let args = case.args(&["--field", "Sig1"], "pkcs12", &provider);
        let mut reference_args = args.clone();
        for value in &mut reference_args {
            if value == case.output.to_str().unwrap() {
                *value = case.path("oracle.pdf").display().to_string();
            }
        }
        // Preserve the pinned decision even when the old native assertion fails.
        let (code, message) = case.oracle(&reference_args, "");
        assert_eq!(code, expected, "{message}");
        let output = case.run(&args, "");
        assert_eq!(output.status.code(), Some(expected), "{}", text(&output));
        if expected == 0 {
            assert_eq!(
                PdfFile::parse(&std::fs::read(&case.output).unwrap())
                    .unwrap()
                    .embedded_signatures()
                    .unwrap()
                    .len(),
                1
            );
            case.verify_with_options(&case.output, false);
            case.native_trust_controls();
        } else {
            assert!(!case.output.exists());
        }
    }
}
