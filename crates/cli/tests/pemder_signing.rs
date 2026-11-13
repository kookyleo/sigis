//! Assertion ports of pyHanko 0.38.1 `test_cli_signing.py`.
//! Ten unique original PEM/DER functions / 30 complete source parameters.
//! Successes cover RSA, ECDSA, Ed25519 and Ed448; the two policy cases use Ed25519.
//! Native CLI uses its real clock; reference CLI freezes fixture time to 2020.
//! Fresh verification reads the actual native PDF under the historical fixture policy.
//! Trust controls and output preservation are supplementary safety assertions.
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
        // Upstream cert_chain writes signer.crt as DER, while its issuers are PEM.
        let cert =
            openssl::x509::X509::from_pem(&std::fs::read(fixture("cert.pem")).unwrap()).unwrap();
        std::fs::write(dir.path().join("signer.crt"), cert.to_der().unwrap()).unwrap();
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
    fn setup(&self, encrypted: bool, password: bool) -> serde_json::Value {
        let key = fixture(if encrypted {
            "encrypted-key.pem"
        } else {
            "key.pem"
        });
        let mut config = serde_json::json!({"pemder-setups":{"test":{
            "key-file":key,
            "cert-file":self.path("signer.crt"),
            "other-certs":[fixture("interm.pem"),fixture("root.pem")]
        }}});
        if password {
            config["pemder-setups"]["test"]["key-passphrase"] = "secret".into();
        }
        config
    }
    fn pem(&self, no_pass: bool) -> Vec<String> {
        let mut provider = Vec::new();
        if no_pass {
            provider.push("--no-pass".to_owned());
        }
        provider.extend([
            "--cert".to_owned(),
            self.path("signer.crt").display().to_string(),
            "--chain".to_owned(),
            fixture("interm.pem").display().to_string(),
            "--key".to_owned(),
            fixture("key.pem").display().to_string(),
        ]);
        self.args(
            &["--field", "Sig1"],
            "pemder",
            &provider.iter().map(String::as_str).collect::<Vec<_>>(),
        )
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
            vec![("native_output", self.output.as_path())]
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
        // Record the actual selected config, including every indirectly referenced file.
        // A custom --config replaces the default config rather than supplementing it.
        let configured = args
            .windows(2)
            .find_map(|pair| (pair[0] == "--config").then(|| PathBuf::from(&pair[1])))
            .or_else(|| {
                args.iter()
                    .find_map(|arg| arg.strip_prefix("--config=").map(PathBuf::from))
            });
        let config_path = configured.unwrap_or_else(|| PathBuf::from("pyhanko.yml"));
        let config_path = if config_path.is_absolute() {
            config_path
        } else {
            self.dir.path().join(config_path)
        };
        if config_path.is_file() {
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
        let (code, message) = self.oracle(&self.reference_args(args), input);
        assert_eq!(code, 0, "{message}");
    }
    /// Supplemental CLI validation controls use an explicit historical certificate time.
    /// They do not change the native signing subprocess clock.
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
        let native_output = path == self.output;
        signing_record::process(
            if native_output {
                "reference-validation"
            } else {
                "reference-output-validation"
            },
            &actual_args,
            &std::env::current_dir().unwrap(),
            b"",
            &python(),
            &out,
            &inputs,
            &[(
                if native_output {
                    "validated_native_signed_output"
                } else {
                    "validated_reference_signed_output"
                },
                path,
            )],
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
        for verdict in ["intact", "valid", "trusted"] {
            assert_eq!(receipt[verdict], true, "{receipt}");
        }
        let output_digest = openssl::sha::sha256(&std::fs::read(path).unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(receipt["output"]["sha256"], output_digest);
        assert_eq!(
            receipt["output"]["path"],
            path.canonicalize().unwrap().to_str().unwrap()
        );
    }
    fn reference_args(&self, args: &[String]) -> Vec<String> {
        args.iter()
            .map(|arg| {
                if arg == self.output.to_str().unwrap() {
                    self.path("oracle.pdf").display().to_string()
                } else {
                    arg.clone()
                }
            })
            .collect()
    }
    fn error(&self, args: &[String], expected: &[&str]) {
        // Keep a fresh differential result even if the native assertion fails.
        let (code, message) = self.oracle(&self.reference_args(args), "");
        assert_eq!(code, 1, "{message}");
        for expected in expected {
            assert!(message.contains(expected), "{message}");
        }
        assert!(
            !self.path("oracle.pdf").exists(),
            "Reference failure left an output"
        );
        self.native_error(args, expected);
    }
    fn native_error(&self, args: &[String], expected: &[&str]) {
        // Supplementary transactional-output guard; upstream only checks the error.
        const SENTINEL: &[u8] = b"existing output must survive failed signing\n";
        std::fs::write(&self.output, SENTINEL).unwrap();
        let out = self.run(args, "");
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        for expected in expected {
            assert!(text(&out).contains(expected), "{}", text(&out));
        }
        assert_eq!(
            std::fs::read(&self.output).unwrap(),
            SENTINEL,
            "Native failure replaced the existing output"
        );
    }
}

const ARCHITECTURES: [&str; 4] = ["rsa", "ecdsa", "ed25519", "ed448"];

#[test]
fn test_cli_addsig_pemder_without_nopass() {
    for architecture in ARCHITECTURES {
        ARCH.with(|value| value.set(architecture));
        let case = Case::new();
        // DummyPrompter("") becomes an actual empty line on native stdin.
        case.success(&case.pem(false), "\n");
    }
}

#[test]
fn test_cli_addsig_pemder_with_setup() {
    for architecture in ARCHITECTURES {
        ARCH.with(|value| value.set(architecture));
        let case = Case::new();
        case.config(case.setup(false, false));
        case.success(
            &case.args(
                &["--field", "Sig1"],
                "pemder",
                &["--no-pass", "--pemder-setup", "test"],
            ),
            "",
        );
    }
}

#[test]
fn test_cli_addsig_pemder_with_wrong_key_usage() {
    ARCH.with(|value| value.set("ed25519"));
    let case = Case::new();
    let mut config = case.setup(false, false);
    config["validation-contexts"] = serde_json::json!({"test":{
        "trust":fixture("root.pem"), "trust-replace":true, "signer-key-usage":"crl_sign"
    }});
    case.config(config);
    case.error(
        &case.args(
            &[
                "--field",
                "Sig1",
                "--validation-context",
                "test",
                "--with-validation-info",
            ],
            "pemder",
            &["--no-pass", "--pemder-setup", "test"],
        ),
        &["not valid for the purpose"],
    );
}

#[test]
fn test_cli_addsig_pemder_with_wrong_extd_key_usage() {
    ARCH.with(|value| value.set("ed25519"));
    let case = Case::new();
    let mut config = case.setup(false, false);
    config["validation-contexts"] = serde_json::json!({"test":{
        "trust":fixture("root.pem"), "trust-replace":true, "signer-extd-key-usage":"2.999"
    }});
    case.config(config);
    let args = case.args(
        &[
            "--field",
            "Sig1",
            "--validation-context",
            "test",
            "--with-validation-info",
        ],
        "pemder",
        &["--no-pass", "--pemder-setup", "test"],
    );
    // The pinned original is xfail: Python omits this EKU presign check and signs.
    // Preserve fresh evidence of that divergence before asserting native rejection.
    // This stricter safety assertion does not claim reference verdict agreement.
    let (code, message) = case.oracle(&case.reference_args(&args), "");
    assert_eq!(code, 0, "Pinned xfail behavior changed: {message}");
    assert!(case.path("oracle.pdf").is_file());
    // Preserve the xfail case's inherited post_validate obligation as well.
    case.verify_with_options(&case.path("oracle.pdf"), false);
    case.native_error(&args, &[]);
}

#[test]
fn test_cli_addsig_pemder_with_setup_in_custom_config_file() {
    for architecture in ARCHITECTURES {
        ARCH.with(|value| value.set(architecture));
        let case = Case::new();
        std::fs::write(
            case.path("pyhanko-config.yml"),
            serde_yaml::to_string(&case.setup(false, false)).unwrap(),
        )
        .unwrap();
        let mut args = vec!["--config".into(), "pyhanko-config.yml".into()];
        args.extend(case.args(
            &["--field", "Sig1"],
            "pemder",
            &["--no-pass", "--pemder-setup", "test"],
        ));
        case.success(&args, "");
    }
}

#[test]
fn test_cli_addsig_pemder_with_setup_encrypted_key() {
    for architecture in ARCHITECTURES {
        ARCH.with(|value| value.set(architecture));
        for location in ["config", "passfile", "prompt"] {
            let case = Case::new();
            case.config(case.setup(true, location == "config"));
            let mut provider = vec!["--pemder-setup", "test"];
            if location == "passfile" {
                std::fs::write(case.path("passfile"), "secret").unwrap();
                provider.extend(["--passfile", "passfile"]);
            }
            case.success(
                &case.args(&["--field", "Sig1"], "pemder", &provider),
                if location == "prompt" { "secret\n" } else { "" },
            );
        }
    }
}

#[test]
fn test_cli_addsig_pemder_setup_requires_config() {
    ARCH.with(|value| value.set("rsa"));
    let case = Case::new();
    case.error(
        &case.args(
            &["--field", "Sig1"],
            "pemder",
            &["--no-pass", "--pemder-setup", "test"],
        ),
        &["requires a configuration file"],
    );
}

#[test]
fn test_cli_addsig_pemder_some_args_required() {
    ARCH.with(|value| value.set("rsa"));
    let case = Case::new();
    case.error(
        &case.args(&["--field", "Sig1"], "pemder", &["--no-pass"]),
        &["option must be provided"],
    );
}

#[test]
fn test_cli_addsig_pemder_setup_does_not_exist() {
    ARCH.with(|value| value.set("rsa"));
    let case = Case::new();
    case.config(serde_json::json!({"pemder-setups":{}}));
    case.error(
        &case.args(
            &["--field", "Sig1"],
            "pemder",
            &["--no-pass", "--pemder-setup", "test"],
        ),
        &["Error while reading PEM/DER setup"],
    );
}

#[test]
fn test_cli_addsig_pemder_with_unreadable_additional_certs() {
    ARCH.with(|value| value.set("rsa"));
    let case = Case::new();
    std::fs::write(case.path("bad-cert.pem"), "blah").unwrap();
    // Unlike cert_chain users above, this original explicitly writes a PEM leaf.
    case.error(
        &case.args(
            &["--field", "Sig1"],
            "pemder",
            &[
                "--no-pass",
                "--key",
                fixture("key.pem").to_str().unwrap(),
                "--cert",
                fixture("cert.pem").to_str().unwrap(),
                "--chain",
                "bad-cert.pem",
            ],
        ),
        &["Could not load certificates"],
    );
}

/// Four supplemental password crossings; zero additional upstream function credit.
#[test]
fn supplemental_pemder_encrypted_setup_password_precedence() {
    ARCH.with(|value| value.set("rsa"));
    for (label, configured, passfile, no_pass) in [
        (
            "configured password precedes wrong passfile",
            true,
            Some("wrong"),
            false,
        ),
        ("configured password precedes no-pass", true, None, true),
        ("passfile precedes no-pass", false, Some("secret"), true),
        (
            "passfile uses trimmed first line",
            false,
            Some(" secret \nwrong second line"),
            false,
        ),
    ] {
        eprintln!("Supplemental PEM/DER password case: {label}");
        let case = Case::new();
        case.config(case.setup(true, configured));
        let mut provider = vec!["--pemder-setup", "test"];
        if let Some(password) = passfile {
            std::fs::write(case.path("passfile"), password).unwrap();
            provider.extend(["--passfile", "passfile"]);
        }
        if no_pass {
            provider.push("--no-pass");
        }
        case.success(&case.args(&["--field", "Sig1"], "pemder", &provider), "");
    }
}

/// Empty configured bytes remain a real password and cannot fall back to a file.
#[test]
fn supplemental_empty_configured_password_cannot_use_correct_passfile() {
    ARCH.with(|v| v.set("rsa"));
    let c = Case::new();
    let mut config = c.setup(true, false);
    config["pemder-setups"]["test"]["key-passphrase"] = "".into();
    c.config(config);
    std::fs::write(c.path("passfile"), "secret").unwrap();
    let args = c.args(
        &["--field", "Sig1"],
        "pemder",
        &["--pemder-setup", "test", "--passfile", "passfile"],
    );
    let (code, message) = c.oracle(&c.reference_args(&args), "");
    assert_eq!(code, 1, "{message}");
    assert!(message.contains("Error:"), "{message}");
    assert!(!c.path("oracle.pdf").exists());
    c.native_error(&args, &["Could not load key material"]);
}
