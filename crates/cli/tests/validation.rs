//! Exact negative assertions from pyHanko 0.38.1 test_cli_validation.py (MIT).
#[path = "common/mod.rs"]
mod common;

use std::{fs, process::Command};
fn check(config: Option<&str>, args: &[&str], expected: &str) {
    check_with_file(config, args, expected, None)
}
fn check_with_file(config: Option<&str>, args: &[&str], expected: &str, file_pdf: Option<&str>) {
    let dir = tempfile::tempdir().unwrap();
    if let Some(source) = file_pdf {
        fs::copy(
            sigis_testdata::path(&["pyhanko", "pdf", source]),
            dir.path().join("file.pdf"),
        )
        .unwrap();
    }
    fs::copy(
        sigis_testdata::path(&["lanes", "r3-c", "runtime", "minimal.pdf"]),
        dir.path().join("input.pdf"),
    )
    .unwrap();
    fs::write(dir.path().join("cert.crt"), [0xde, 0xad, 0xbe, 0xef]).unwrap();
    if let Some(c) = config {
        fs::write(dir.path().join("pyhanko.yml"), c).unwrap();
    }
    for path in ["input.pdf", "file.pdf", "cert.crt", "pyhanko.yml"] {
        let path = dir.path().join(path);
        if path.is_file() {
            common::record_file(&path, "ordinary_cli_negative_input");
        }
    }
    let out = Command::new(common::cli())
        .current_dir(dir.path())
        .args(["sign", "validate"])
        .args(args)
        .output()
        .unwrap();
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!(
        "ORDINARY_NATIVE_CASE {}",
        serde_json::json!({
            "test":std::thread::current().name(),"entry":"actual_cli_subprocess",
            "argv":std::iter::once("sign").chain(std::iter::once("validate")).chain(args.iter().copied()).collect::<Vec<_>>(),
            "cwd":dir.path(),"code":out.status.code(),
            "stdout":String::from_utf8_lossy(&out.stdout),"stderr":String::from_utf8_lossy(&out.stderr),
        })
    );
    assert_eq!(out.status.code(), Some(1), "{message}");
    assert!(message.contains(expected), "{message}");
    let oracle=Command::new(std::env::var("HANKO_ORACLE").unwrap_or_else(|_|"/tmp/pyhanko-oracle/venv/bin/python".into())).current_dir(dir.path()).arg("-c").arg("import sys;from click.testing import CliRunner;import pyhanko; pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko'); from pyhanko.cli import cli_root;r=CliRunner().invoke(cli_root,['sign','validate',*sys.argv[2:]]);assert r.exit_code==1,(r.exit_code,r.output);assert sys.argv[1] in r.output,r.output").arg(expected).args(args).output().unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
}
#[test]
fn test_inconsistent_revo_settings() {
    regular_encrypted(|mut c| {
        c.mocks = false;
        let r = c
            .option("--no-revocation-check", None)
            .option("--soft-revocation-check", None)
            .run();
        assert_eq!(r.code, 1, "{}", output(&r));
        assert!(output(&r).contains("incompatible"), "{}", output(&r));
    });
}
#[test]
fn test_validate_inconsistent_print_settings() {
    check_with_file(
        None,
        &["--executive-summary", "--pretty-print", "file.pdf"],
        "incompatible",
        Some("minimal.pdf"),
    );
}
#[test]
fn test_validation_time_syntax_error() {
    check_with_file(
        None,
        &[
            "--validation-time",
            "2020-99-99T99:99:99Z",
            "--trust-replace",
            "file.pdf",
        ],
        "could not be parsed",
        Some("minimal-with-field.pdf"),
    );
}
#[test]
fn test_basic_validate_context_without_config_file() {
    check(
        None,
        &["--validation-context", "test", "input.pdf"],
        "No config file",
    );
}
#[test]
fn test_basic_validate_context_incompatible_args() {
    check(
        None,
        &[
            "--validation-context",
            "test",
            "--trust",
            "input.pdf",
            "--trust-replace",
            "input.pdf",
        ],
        "--validation-context is incompatible with",
    );
}
#[test]
fn test_basic_validate_context_file_not_found() {
    check(
        Some("validation-contexts: {test: {trust: no-such-cert.crt, trust-replace: true}}"),
        &["--validation-context", "test", "input.pdf"],
        "I/O problem",
    );
}
#[test]
fn test_basic_validate_context_malformed_cert() {
    check(
        Some("validation-contexts: {test: {trust: cert.crt, trust-replace: true}}"),
        &["--validation-context", "test", "input.pdf"],
        "processing problem",
    );
}
#[test]
fn test_basic_validate_context_config_wrong() {
    for name in ["default", "explicit"] {
        let config = format!("validation-contexts: {{{name}: {{thismakesnosense: blah}}}}");
        let mut args = Vec::new();
        if name != "default" {
            args.extend(["--validation-context", name]);
        }
        args.push("input.pdf");
        check(Some(&config), &args, "validation context");
    }
}
#[test]
fn test_basic_validate_context_config_nonsensical_other_certs() {
    for name in ["default", "explicit"] {
        let config =
            format!("validation-contexts: {{{name}: {{other-certs: 1234, trust-replace: true}}}}");
        let mut args = Vec::new();
        if name != "default" {
            args.extend(["--validation-context", name]);
        }
        args.push("input.pdf");
        check(Some(&config), &args, "validation context");
    }
}
#[test]
fn test_detached_validate_malformed_input() {
    check(
        None,
        &["--trust-replace", "--detached", "cert.crt", "input.pdf"],
        "Could not parse CMS object",
    );
}
#[test]
fn test_detached_validate_bad_cms_type() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data.der");
    fs::write(
        &file,
        [
            0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
        ],
    )
    .unwrap();
    check(
        None,
        &[
            "--trust-replace",
            "--detached",
            file.to_str().unwrap(),
            "input.pdf",
        ],
        "CMS content type is not signedData",
    );
}

use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime, Output};
use sigis_pki_core::{
    cert::Cert,
    errors::FetchError,
    fetch::{CrlFetcher, Fetchers},
    time::Moment,
};
use std::{path::PathBuf, sync::Arc};

const ARCHITECTURES: [&str; 4] = ["rsa", "ecdsa", "ed25519", "ed448"];
fn fixture(path: &str) -> PathBuf {
    let path = sigis_testdata::path(&["lanes", "r3-c", "validation", path]);
    common::record_test_executable();
    if path.is_file() {
        common::record_file(&path, "fixture_snapshot");
    }
    path
}
fn fixture_time() -> Moment {
    let v: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture("metadata.json")).unwrap()).unwrap();
    Moment::parse_rfc3339(v["moment"].as_str().unwrap()).unwrap()
}

#[derive(Debug)]
struct NativePkiMock(Vec<Vec<u8>>);
impl CrlFetcher for NativePkiMock {
    fn fetch_crls(&self, _: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        Ok(self.0.clone())
    }
}
fn fetchers(arch: &str, enabled: bool) -> Fetchers {
    if !enabled {
        return Fetchers::none();
    }
    let crls = fs::read_dir(fixture(arch))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("crl-"))
        .map(|p| {
            common::record_file(&p, "ordinary_validation_crl");
            fs::read(p).unwrap()
        })
        .collect();
    Fetchers {
        crl: Some(Arc::new(NativePkiMock(crls))),
        ..Fetchers::none()
    }
}

struct Case {
    arch: String,
    infile: PathBuf,
    args: Vec<String>,
    config: Option<String>,
    mocks: bool,
    now: Moment,
    password: Option<String>,
    verbose: bool,
    trust: bool,
}
impl Case {
    fn new(arch: &str, variant: &str) -> Self {
        Self {
            arch: arch.into(),
            infile: fixture(&format!("{arch}/{variant}.pdf")),
            args: vec![],
            config: None,
            mocks: true,
            now: fixture_time(),
            password: Some("ownersecret".into()),
            verbose: false,
            trust: true,
        }
    }
    fn option(mut self, key: &str, value: Option<&str>) -> Self {
        self.args.push(key.into());
        if let Some(value) = value {
            self.args.push(value.into())
        }
        self
    }
    fn run(self) -> Output {
        let d = tempfile::tempdir().unwrap();
        let mut args = vec![];
        if let Some(config) = self.config {
            let p = d.path().join("config.yml");
            fs::write(&p, config).unwrap();
            common::record_file(&p, "ordinary_validation_configuration");
            args.extend(["--config".into(), p.to_str().unwrap().into()]);
        }
        if self.verbose {
            args.push("--verbose".into())
        }
        args.extend(["sign".into(), "validate".into()]);
        if self.trust {
            args.extend([
                "--trust".into(),
                fixture(&format!("{}/root.der", self.arch))
                    .to_str()
                    .unwrap()
                    .into(),
                "--trust-replace".into(),
            ]);
        }
        args.extend(self.args);
        args.push(self.infile.to_str().unwrap().into());
        let runtime = ValidationRuntime {
            pkcs11_user_pin_prompt: None,
            trusted_list_transport: None,
            now: self.now,
            fetchers: fetchers(&self.arch, self.mocks),
            password: self.password,
        };
        common::record_file(&self.infile, "ordinary_validation_input");
        let result = sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &runtime);
        eprintln!(
            "ORDINARY_NATIVE_CASE {}",
            serde_json::json!({
                "test":std::thread::current().name(),"architecture":self.arch,
                "argv":args,"input":self.infile,"moment":runtime.now.to_string(),
                "configured_crl_provider":self.mocks,
                "code":result.code,"stdout":result.stdout,"stderr":result.stderr,
            })
        );
        result
    }
}
fn output(r: &Output) -> String {
    format!("{}{}", r.stdout, r.stderr)
}
fn trusted(r: Output) {
    assert_eq!(r.code, 0, "{}", output(&r));
    assert!(
        output(&r).contains("INTACT:TRUSTED,UNTOUCHED"),
        "{}",
        output(&r)
    );
}
fn regular_encrypted(mut test: impl FnMut(Case)) {
    for arch in ARCHITECTURES {
        for mode in ["regular", "encrypted"] {
            test(Case::new(arch, mode));
        }
    }
}

#[test]
fn test_basic_validate() {
    regular_encrypted(|c| trusted(c.run()));
}
#[test]
fn test_basic_validate_fail_without_revinfo() {
    regular_encrypted(|mut c| {
        c.mocks = false;
        let r = c.run();
        assert_eq!(r.code, 1, "{}", output(&r));
        assert!(output(&r).contains("INTACT:UNTRUSTED"), "{}", output(&r));
    });
}
#[test]
fn test_basic_validate_with_soft_revocation() {
    for mocks in [true, false] {
        regular_encrypted(|mut c| {
            c.mocks = mocks;
            trusted(c.option("--soft-revocation-check", None).run());
        });
    }
}
#[test]
fn test_basic_validate_with_required_revinfo() {
    regular_encrypted(|c| trusted(c.option("--force-revinfo", None).run()));
}
#[test]
fn test_basic_validate_fail_without_required_revinfo() {
    regular_encrypted(|mut c| {
        c.mocks = false;
        let r = c.option("--force-revinfo", None).run();
        assert_eq!(r.code, 1, "{}", output(&r));
        assert!(output(&r).contains("UNTRUSTED"), "{}", output(&r));
    });
}
#[test]
fn test_basic_validate_without_revinfo_check() {
    regular_encrypted(|mut c| {
        c.mocks = false;
        trusted(c.option("--no-revocation-check", None).run());
    });
}

#[test]
fn test_validate_encrypted_wrong_password() {
    for arch in ARCHITECTURES {
        let mut c = Case::new(arch, "encrypted");
        c.password = Some("badpassword".into());
        let r = c.run();
        assert_eq!(r.code, 1);
        assert!(
            output(&r).contains("Password didn't match."),
            "{}",
            output(&r)
        );
    }
}
#[test]
fn test_validate_encrypted_empty_user_password() {
    for arch in ARCHITECTURES {
        trusted(Case::new(arch, "empty-password").run());
    }
}
#[test]
fn test_validate_encrypted_empty_user_password_wrong_explicit_password() {
    for arch in ARCHITECTURES {
        let r = Case::new(arch, "empty-password")
            .option("--password", Some("bogus"))
            .run();
        assert_eq!(r.code, 1);
        assert!(
            output(&r).contains("Password didn't match."),
            "{}",
            output(&r)
        );
    }
}
#[test]
fn test_validate_encrypted_explicit_empty_password() {
    for arch in ARCHITECTURES {
        trusted(
            Case::new(arch, "empty-password")
                .option("--password", Some(""))
                .run(),
        );
    }
}
#[test]
fn test_validate_encrypted_wrong_explicit_empty_password() {
    for arch in ARCHITECTURES {
        let r = Case::new(arch, "user-password")
            .option("--password", Some(""))
            .run();
        assert_eq!(r.code, 1);
        assert!(
            output(&r).contains("Password didn't match."),
            "{}",
            output(&r)
        );
    }
}
#[test]
fn test_validate_unsupported_handler() {
    for arch in ARCHITECTURES {
        let mut c = Case::new(arch, "regular");
        c.infile = fixture("pubkey.pdf");
        let r = c.run();
        assert_eq!(r.code, 1);
        assert!(
            output(&r).contains("only password-based encryption"),
            "{}",
            output(&r)
        );
    }
}

#[test]
fn test_basic_validate_summary() {
    regular_encrypted(|c| {
        let r = c.option("--executive-summary", None).run();
        assert_eq!(r.code, 0, "{}", output(&r));
        assert!(
            regex::Regex::new(r"^Sig1:.*:VALID\n?$")
                .unwrap()
                .is_match(&r.stdout),
            "{}",
            output(&r)
        );
    });
}
#[test]
fn test_basic_validate_pretty_print() {
    regular_encrypted(|c| {
        let r = c.option("--pretty-print", None).run();
        assert_eq!(r.code, 0, "{}", output(&r));
        assert!(output(&r).contains("judged VALID"), "{}", output(&r));
    });
}
#[test]
fn test_basic_validate_with_validation_time() {
    regular_encrypted(|mut c| {
        c.now = c.now.plus(std::time::Duration::from_secs(3650 * 86400));
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture("metadata.json")).unwrap()).unwrap();
        let date = metadata["moment"].as_str().unwrap();
        trusted(c.option("--validation-time", Some(&date[..10])).run());
    });
}
#[test]
fn test_basic_validate_with_claimed_time() {
    regular_encrypted(|mut c| {
        c.now = c.now.plus(std::time::Duration::from_secs(3650 * 86400));
        trusted(c.option("--validation-time", Some("claimed")).run());
    });
}
#[test]
fn test_basic_validate_untrusted() {
    regular_encrypted(|mut c| {
        c.now = c.now.plus(std::time::Duration::from_secs(3650 * 86400));
        assert_eq!(c.run().code, 1);
    });
}
#[test]
fn test_basic_validate_with_weak_hash() {
    for pretty in [true, false] {
        let mut c = Case::new("rsa", "regular");
        c.infile = fixture("weak-hash.pdf");
        if pretty {
            c = c.option("--pretty-print", None)
        }
        let r = c.run();
        assert_eq!(r.code, 1);
        assert!(
            output(&r).contains("sha1_rsa is not allowed"),
            "{}",
            output(&r)
        );
    }
}
#[test]
fn test_basic_validate_with_unknown_hash() {
    for pretty in [true, false] {
        let mut c = Case::new("rsa", "regular");
        c.infile = fixture("unknown-hash.pdf");
        if pretty {
            c = c.option("--pretty-print", None)
        }
        let r = c.run();
        assert_eq!(r.code, 1);
        assert!(output(&r).contains("An error occurred"), "{}", output(&r));
        assert!(
            output(&r).contains("Unknown hash function"),
            "{}",
            output(&r)
        );
    }
}
#[test]
fn test_basic_validate_signed_with_wrong_key() {
    for verbosity in ["default", "verbose", "pretty"] {
        let mut c = Case::new("rsa", "regular");
        c.infile = fixture("wrong-key.pdf");
        c.verbose = verbosity == "verbose";
        if verbosity == "pretty" {
            c = c.option("--pretty-print", None)
        }
        let r = c.run();
        assert_eq!(r.code, 1);
        assert!(output(&r).contains("INVALID"), "{}", output(&r));
        assert_eq!(
            output(&r).contains("unsound"),
            verbosity == "pretty",
            "{}",
            output(&r)
        );
        if verbosity == "verbose" {
            assert!(
                output(&r).contains("Running with --verbose"),
                "{}",
                output(&r)
            );
        }
    }
}

fn context_config(arch: &str, name: &str, intermediate: bool, replace: bool) -> String {
    format!(
        "validation-contexts:\n  {name}:\n    trust: '{}'\n    trust-replace: {replace}\n{}",
        fixture(&format!("{arch}/root.der")).display(),
        if intermediate {
            format!(
                "    other-certs: '{}'\n",
                fixture(&format!("{arch}/interm.der")).display()
            )
        } else {
            String::new()
        }
    )
}
#[test]
fn test_basic_validate_with_default_context() {
    regular_encrypted(|mut c| {
        c.config = Some(context_config(&c.arch, "default", false, true));
        c.trust = false;
        trusted(c.run());
    });
}
#[test]
fn test_basic_validate_with_system_trust() {
    regular_encrypted(|mut c| {
        c.trust = false;
        assert_eq!(c.run().code, 1);
    });
}
#[test]
fn test_basic_validate_with_explicit_context() {
    regular_encrypted(|mut c| {
        c.config = Some(context_config(&c.arch, "test", false, true));
        c.trust = false;
        trusted(c.option("--validation-context", Some("test")).run());
    });
}
#[test]
fn test_basic_validate_lacking_intermediate() {
    for arch in ARCHITECTURES {
        let mut c = Case::new(arch, "missing-intermediate");
        c.config = Some(context_config(arch, "default", true, true));
        c.trust = false;
        trusted(c.run());
    }
}
#[test]
fn test_basic_validate_lacking_intermediate_with_trust_arg() {
    for arch in ARCHITECTURES {
        let mut c = Case::new(arch, "missing-intermediate");
        c.config = Some("validation-contexts: {default: {}}".into());
        trusted(
            c.option(
                "--other-certs",
                Some(fixture(&format!("{arch}/interm.der")).to_str().unwrap()),
            )
            .run(),
        );
    }
}
#[test]
fn test_trust_replace_arg_applies_to_config_context() {
    for name in ["default", "explicit"] {
        for replace in [true, false] {
            regular_encrypted(|mut c| {
                c.config = Some(context_config(&c.arch, name, false, false));
                c.trust = false;
                if name != "default" {
                    c = c.option("--validation-context", Some(name))
                }
                if replace {
                    c = c.option("--trust-replace", None)
                }
                let r = c.run();
                assert_eq!(r.code, 0, "{}", output(&r));
                assert!(
                    output(&r).contains("INTACT:TRUSTED,UNTOUCHED"),
                    "{}",
                    output(&r)
                );
                assert_eq!(
                    r.stderr.contains("operating system"),
                    !replace,
                    "{}",
                    output(&r)
                );
            });
        }
    }
}

#[test]
fn test_basic_detached_validate() {
    for arch in ARCHITECTURES {
        for encoding in ["der", "pem"] {
            let mut c = Case::new(arch, "regular");
            c.infile = fixture("minimal.pdf");
            let r = c
                .option(
                    "--detached",
                    Some(
                        fixture(&format!("{arch}/detached.{encoding}"))
                            .to_str()
                            .unwrap(),
                    ),
                )
                .run();
            assert_eq!(r.code, 0, "{}", output(&r));
            assert!(output(&r).contains("INTACT:TRUSTED"), "{}", output(&r));
        }
    }
}
#[test]
fn test_fail_detached_validate() {
    for arch in ARCHITECTURES {
        let mut c = Case::new(arch, "regular");
        c.infile = fixture("minimal.pdf");
        let r = c
            .option(
                "--detached",
                Some(
                    fixture(&format!("{arch}/detached-bad.der"))
                        .to_str()
                        .unwrap(),
                ),
            )
            .run();
        assert_eq!(r.code, 1);
        assert!(output(&r).contains("Error: INVALID"), "{}", output(&r));
    }
}

/// Additional adversarial cases do not increase unique upstream coverage.
#[test]
fn validation_enforces_configured_mandatory_key_usage() {
    for arch in ARCHITECTURES {
        for detached in [false, true] {
            for policy in [
                "extd-key-usage: code_signing",
                "key-usage-forbidden: non_repudiation",
                "key-usage: key_cert_sign",
            ] {
                let mut c = Case::new(arch, "regular");
                c.trust = false;
                c.config = Some(format!(
                    "{}    signer-key-usage-policy:\n      {policy}\n",
                    context_config(arch, "default", false, true)
                ));
                if detached {
                    c.infile = fixture("minimal.pdf");
                    c = c.option(
                        "--detached",
                        Some(fixture(&format!("{arch}/detached.der")).to_str().unwrap()),
                    );
                }
                let r = c.run();
                assert_eq!(r.code, 1, "{arch} {policy}: {}", output(&r));
                assert!(output(&r).contains("key usage"), "{}", output(&r));
                assert!(!output(&r).contains("INTACT:TRUSTED"), "{}", output(&r));
            }
        }
    }
}

/// Fresh native-versus-oracle calls are not additional upstream functions.
#[test]
fn validation_live_oracle_matrix() {
    use std::{io::Write, process::Stdio};
    let mut cases = vec![];
    let mut native = vec![];
    for arch in ARCHITECTURES {
        for variant in ["regular", "encrypted"] {
            for (flag, mocks) in [
                (None, true),
                (Some("--soft-revocation-check"), false),
                (Some("--no-revocation-check"), false),
                (Some("--force-revinfo"), true),
                (None, false),
                (Some("--force-revinfo"), false),
            ] {
                let mut c = Case::new(arch, variant);
                c.mocks = mocks;
                if let Some(flag) = flag {
                    c = c.option(flag, None)
                }
                let mut args = vec![
                    "sign".to_owned(),
                    "validate".into(),
                    "--trust".into(),
                    fixture(&format!("{arch}/root.der"))
                        .to_str()
                        .unwrap()
                        .into(),
                    "--trust-replace".into(),
                ];
                args.extend(c.args.clone());
                args.push(c.infile.to_str().unwrap().into());
                let metadata: serde_json::Value =
                    serde_json::from_slice(&fs::read(fixture("metadata.json")).unwrap()).unwrap();
                cases.push(serde_json::json!({"arch":arch,"now":metadata["moment"],"mocks":mocks,"password":"ownersecret","args":args}));
                native.push(c.run());
            }
        }
    }
    let python = std::env::var("HANKO_ORACLE")
        .unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into());
    let mut child = Command::new(python)
        .arg(fixture("oracle.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the pinned oracle is required for validation differential tests");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&cases).unwrap().as_bytes())
        .unwrap();
    let oracle = child.wait_with_output().unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let expected: Vec<serde_json::Value> = serde_json::from_slice(&oracle.stdout).unwrap();
    assert_eq!(expected.len(), native.len());
    let summary = regex::Regex::new(r"Sig1:[0-9a-f]{64}:[A-Z:,<>|_]+(?:\n|$)").unwrap();
    for (index, (rust, python)) in native.iter().zip(expected).enumerate() {
        eprintln!("ORDINARY_ORACLE_CASE {python}");
        assert_eq!(
            rust.code,
            i32::try_from(python["code"].as_i64().unwrap()).unwrap(),
            "case {index}: Rust {} / oracle {}",
            output(rust),
            python["output"]
        );
        let rust_output = output(rust);
        let rust_summary = summary.find(&rust_output).map(|s| s.as_str().trim());
        let python_output = python["output"].as_str().unwrap();
        let python_summary = summary.find(python_output).map(|s| s.as_str().trim());
        assert!(python_summary.is_some(), "case {index}: {python_output}");
        assert_eq!(rust_summary, python_summary, "case {index}");
    }
}

/// PEM dearmoring must preserve malformed-input, label and CMS-type rejection.
#[test]
fn validation_rejects_malformed_detached_cms_pem() {
    fn pem(label: &str, der: &[u8]) -> String {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            openssl::base64::encode_block(der)
        )
    }
    let der = fs::read(fixture("rsa/detached.der")).unwrap();
    let valid = pem("CMS", &der);
    let data = [
        0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
    ];
    for (encoded, expected) in [
        (pem("CERTIFICATE", &der), "Could not parse CMS object"),
        (
            valid.replace("-----END CMS-----", ""),
            "Could not parse CMS object",
        ),
        (
            valid.replace("-----END CMS-----", "-----END PKCS7-----"),
            "Could not parse CMS object",
        ),
        (
            "-----BEGIN CMS-----\n%%%\n-----END CMS-----\n".into(),
            "Could not parse CMS object",
        ),
        (pem("CMS", &data), "CMS content type is not signedData"),
        (pem("PKCS7", &data), "CMS content type is not signedData"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signature.pem");
        fs::write(&path, encoded).unwrap();
        let mut c = Case::new("rsa", "regular");
        c.infile = fixture("minimal.pdf");
        let r = c.option("--detached", Some(path.to_str().unwrap())).run();
        assert_eq!(r.code, 1, "{}", output(&r));
        assert!(output(&r).contains(expected), "{}", output(&r));
    }
}
