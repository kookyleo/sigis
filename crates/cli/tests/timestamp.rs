//! Exact pyHanko0.38.1 timestamp originals and separate mandatory refusal controls.
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;
use sigis_pki_fetch::{transport::HttpRequest, HttpTransport, ReqwestTransport};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    time::Duration,
};
fn python() -> PathBuf {
    std::env::var_os("HANKO_ORACLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/pyhanko-oracle/venv/bin/python"))
}
fn live_driver(name: &str) -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "pkcs12-lta", name])
}
fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
struct Server {
    child: Child,
    ready: serde_json::Value,
    stderr: PathBuf,
    ready_path: PathBuf,
}
impl Server {
    fn start(architecture: &str, directory: &Path, wrong_eku: bool) -> Self {
        fs::create_dir_all(directory).unwrap();
        let stderr = directory.join("server.stderr");
        let script = if wrong_eku {
            sigis_testdata::path(&["lanes", "r3-c", "timestamp", "wrong_eku_server.py"])
        } else {
            live_driver("live_server.py")
        };
        common::record_file(&script, "live_server_driver_before_start");
        common::record_file(&python(), "live_server_interpreter_before_start");
        common::record_file(
            &sigis_testdata::pyhanko(&["crypto", "certomancer.yml"]),
            "live_server_config_before_start",
        );
        let keys = match architecture {
            "rsa" => "keys-rsa",
            "ecdsa" => "keys-ecdsa",
            "ed25519" => "keys-ed25519",
            _ => panic!("unknown upstream architecture"),
        };
        for entry in fs::read_dir(sigis_testdata::pyhanko(&["crypto", keys])).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                common::record_file(&path, "live_server_key_material_before_start");
            }
        }
        let mut child = Command::new(python())
            .arg(script)
            .arg("--crypto")
            .arg(sigis_testdata::pyhanko(&["crypto"]))
            .arg("--architecture")
            .arg(architecture)
            .arg("--artifacts")
            .arg(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(fs::File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut server = Self {
            child,
            ready: serde_json::Value::Null,
            ready_path: directory.join("test-observed-ready.json"),
            stderr,
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = tx.send(result);
        });
        let line = rx.recv_timeout(Duration::from_secs(30)).unwrap().unwrap();
        assert!(
            !line.is_empty(),
            "{}",
            fs::read_to_string(&server.stderr).unwrap()
        );
        server.ready = serde_json::from_str(&line).unwrap();
        fs::write(&server.ready_path, &line).unwrap();
        assert_eq!(server.ready["clock"], "current UTC");
        assert_eq!(server.ready["architecture"], architecture);
        assert_eq!(server.ready["pyhanko"], "0.38.1");
        assert_eq!(server.ready["certvalidator"], "0.33.0");
        server
    }
    fn metrics(&self) -> serde_json::Value {
        let transport = ReqwestTransport::new(Duration::from_secs(5), 1024 * 1024).unwrap();
        let response = transport
            .send(&HttpRequest {
                method: "GET",
                url: self.ready["metrics_url"].as_str().unwrap(),
                headers: Vec::new(),
                body: None,
            })
            .unwrap();
        assert_eq!(response.status, 200);
        serde_json::from_slice(&response.body).unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        // Only this unreaped test-owned child is stopped; no existing service.
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
struct Case {
    dir: tempfile::TempDir,
    server: Server,
    input: PathBuf,
    output: PathBuf,
    root: PathBuf,
    config: PathBuf,
}
impl Case {
    fn new(architecture: &str, oversized: bool) -> Self {
        Self::with_wrong_eku(architecture, oversized, false)
    }
    fn with_wrong_eku(architecture: &str, oversized: bool, wrong_eku: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::start(architecture, &dir.path().join("server"), wrong_eku);
        let input = dir.path().join("input.pdf");
        let output = dir.path().join("out.pdf");
        fs::copy(
            if oversized {
                sigis_testdata::path(&["lanes", "r3-c", "decode-limits", "oversized.pdf"])
            } else {
                sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])
            },
            &input,
        )
        .unwrap();
        let root = PathBuf::from(server.ready["exported_root"]["path"].as_str().unwrap());
        let config = dir.path().join("pyhanko.yml");
        let mut cfg =
            serde_json::json!({"validation-contexts":{"test":{"trust":root,"trust-replace":true}}});
        if oversized {
            cfg["pkcs12-setups"] = serde_json::json!({"test":{"pfx-file":server.ready["exported_pfx"]["path"],"pfx-passphrase":"secret"}});
        }
        fs::write(&config, serde_yaml::to_string(&cfg).unwrap()).unwrap();
        Self {
            dir,
            server,
            input,
            output,
            root,
            config,
        }
    }
    fn paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![
            self.input.clone(),
            self.root.clone(),
            self.config.clone(),
            if self.server.ready.get("good_tsa_cert").is_some() {
                sigis_testdata::path(&["lanes", "r3-c", "timestamp", "wrong_eku_server.py"])
            } else {
                live_driver("live_server.py")
            },
        ];
        if let Some(good) = self.server.ready["good_tsa_cert"].as_str() {
            paths.push(good.into());
        }
        if let Some(pfx) = self.server.ready["exported_pfx"]["path"].as_str() {
            paths.push(pfx.into());
        }
        paths
    }
    fn args(&self, extra: &[&str]) -> Vec<String> {
        let mut args = vec!["sign".into(), "timestamp".into()];
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        args.extend([
            "--validation-context".into(),
            "test".into(),
            "--timestamp-url".into(),
            self.server.ready["tsa_url"].as_str().unwrap().into(),
            self.input.display().to_string(),
            self.output.display().to_string(),
        ]);
        args
    }
    fn native(&self, args: &[String]) -> Output {
        let before = signing_record::before(&self.paths());
        let executable = signing_record::before(std::slice::from_ref(common::cli()));
        let output = Command::new(common::cli())
            .args(args)
            .current_dir(self.dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let metrics = self.server.metrics();
        let metrics_path = self.dir.path().join("native-only-metrics.json");
        fs::write(&metrics_path, serde_json::to_vec_pretty(&metrics).unwrap()).unwrap();
        assert_eq!(
            executable,
            signing_record::before(std::slice::from_ref(common::cli()))
        );
        let mut artifacts = vec![
            ("native_only_http_metrics", metrics_path.as_path()),
            ("server_stderr", self.server.stderr.as_path()),
            (
                "observed_server_readiness",
                self.server.ready_path.as_path(),
            ),
        ];
        if self.output.exists() {
            artifacts.push(("actual_native_output", self.output.as_path()));
        }
        signing_record::process(
            "native-timestamp-cli",
            args,
            self.dir.path(),
            b"",
            common::cli(),
            &output,
            &before,
            &artifacts,
        );
        output
    }
    fn reference(&self, args: &[String], expected: i32, error_text: Option<&str>) {
        let script = live_driver("oracle_cli_current.py");
        let output = self.dir.path().join("reference.pdf");
        let receipt = self.dir.path().join("reference-cli.json");
        let mut argv = vec![
            script.display().to_string(),
            "--input".into(),
            self.input.display().to_string(),
            "--output".into(),
            output.display().to_string(),
            "--root".into(),
            self.root.display().to_string(),
            "--record".into(),
            receipt.display().to_string(),
            "--".into(),
        ];
        argv.extend(args.iter().map(|v| {
            if v == self.output.to_str().unwrap() {
                output.display().to_string()
            } else {
                v.clone()
            }
        }));
        let mut paths = self.paths();
        paths.push(script);
        let before = signing_record::before(&paths);
        let result = Command::new(python())
            .args(&argv)
            .current_dir(self.dir.path())
            .output()
            .unwrap();
        let mut artifacts = vec![("fresh_reference_receipt", receipt.as_path())];
        if output.exists() {
            artifacts.push(("reference_output", output.as_path()));
        }
        signing_record::process(
            "reference-current-timestamp-cli",
            &argv,
            self.dir.path(),
            b"",
            &python(),
            &result,
            &before,
            &artifacts,
        );
        assert!(result.status.success(), "{}", text(&result));
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
        assert_eq!(record["exit_code"], expected, "{record}");
        if expected == 0 {
            assert!(record["exception"].is_null(), "{record}");
        } else {
            assert!(
                record["output"]
                    .as_str()
                    .unwrap()
                    .contains(error_text.expect("negative oracle diagnostic")),
                "{record}"
            );
        }
    }
    fn verify(&self) {
        let bytes = fs::read(&self.output).unwrap();
        let parse = |data: &[u8]| {
            sigis_pdf::PdfFile::parse_with(
                data,
                sigis_pdf::ReaderOptions {
                    decode_limits: sigis_pdf::decode_limits::DecodeLimits::for_trusted_input(),
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let pdf = parse(&bytes);
        let signatures = pdf.embedded_signatures().unwrap();
        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0].kind, sigis_pdf::SignatureKind::DocTimeStamp);
        let cfg = sigis_cli::config::CliConfig::parse(&fs::read_to_string(&self.config).unwrap())
            .unwrap();
        let ctx = sigis_cli::validation::context_from_config(
            Some(&cfg),
            Some("test"),
            &Default::default(),
        )
        .unwrap();
        let status = sigis_pades::validate_pdf_timestamp(&pdf, &signatures[0], &ctx).unwrap();
        assert!(status.timestamp.signature.bottom_line(), "{status:?}");
        let empty = sigis_pki_certvalidator::ValidationContext::builder()
            .moment(ctx.moment())
            .revocation_mode("hard-fail")
            .build()
            .unwrap();
        let no_roots = sigis_pades::validate_pdf_timestamp(&pdf, &signatures[0], &empty);
        assert!(!no_roots.is_ok_and(|s| s.timestamp.signature.bottom_line()));
        let mut changed = bytes.clone();
        changed[7] = if changed[7] == b'6' { b'7' } else { b'6' };
        let modified = parse(&changed);
        let sigs = modified.embedded_signatures().unwrap();
        assert!(
            !sigis_pades::validate_pdf_timestamp(&modified, &sigs[0], &ctx)
                .unwrap()
                .timestamp
                .signature
                .intact
        );
        let script = sigis_testdata::path(&["lanes", "r3-c", "timestamp", "oracle_verify.py"]);
        let receipt = self.dir.path().join("native-timestamp-verdict.json");
        let argv = vec![
            script.display().to_string(),
            "--output".into(),
            self.output.display().to_string(),
            "--root".into(),
            self.root.display().to_string(),
            "--record".into(),
            receipt.display().to_string(),
        ];
        let before = signing_record::before(&[self.output.clone(), self.root.clone(), script]);
        let result = Command::new(python())
            .args(&argv)
            .current_dir(self.dir.path())
            .output()
            .unwrap();
        let mut artifacts = vec![("actual_native_timestamp", self.output.as_path())];
        if receipt.exists() {
            artifacts.push(("fresh_timestamp_verdict", receipt.as_path()));
        }
        signing_record::process(
            "fresh-native-timestamp-verification",
            &argv,
            self.dir.path(),
            b"",
            &python(),
            &result,
            &before,
            &artifacts,
        );
        assert!(result.status.success(), "{}", text(&result));
    }
}
/// Exact original test_cli_signing.py::test_cli_timestamp, all three architectures.
#[test]
fn test_cli_timestamp() {
    for arch in ["rsa", "ecdsa", "ed25519"] {
        let c = Case::new(arch, false);
        let args = c.args(&[]);
        let result = c.native(&args);
        assert_eq!(result.status.code(), Some(0), "{}", text(&result));
        let requests = c.server.metrics();
        let tsa_calls: u64 = requests["requests"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == "POST" && r["path"].as_str().unwrap().contains("/tsa/"))
            .map(|r| r["count"].as_u64().unwrap())
            .sum();
        assert!(
            tsa_calls >= 3,
            "Native dummy/path/final requests must precede every oracle: {requests}"
        );
        c.verify();
        c.reference(&args, 0, None);
    }
}
/// Exact original decode-limits timestamp: one RSA parameter and both executions.
#[test]
fn test_timestamp() {
    let c = Case::new("rsa", true);
    fs::write(&c.output, b"sentinel").unwrap();
    let result = c.native(&c.args(&[]));
    assert_eq!(result.status.code(), Some(1), "{}", text(&result));
    assert!(
        text(&result).contains("rerun with --no-decode-limits"),
        "{}",
        text(&result)
    );
    assert_eq!(fs::read(&c.output).unwrap(), b"sentinel");
    c.reference(&c.args(&[]), 1, Some("rerun with --no-decode-limits"));
    let args = c.args(&["--no-decode-limits"]);
    let result = c.native(&args);
    assert_eq!(result.status.code(), Some(0), "{}", text(&result));
    c.verify();
    c.reference(&args, 0, None);
}
/// Supplementary actual CLI RED: accepted generic options must not be discarded.
#[test]
fn unsupported_timestamp_requirement_preserves_output() {
    let c = Case::new("rsa", false);
    fs::write(&c.output, b"sentinel").unwrap();
    let result = c.native(&c.args(&["--certify"]));
    assert_eq!(result.status.code(), Some(1), "{}", text(&result));
    assert!(
        text(&result).contains("not supported by the timestamp command"),
        "{}",
        text(&result)
    );
    assert_eq!(fs::read(&c.output).unwrap(), b"sentinel");
    assert!(c.server.metrics()["requests"]
        .as_array()
        .unwrap()
        .is_empty());
}
/// Supplementary schema/option refusals happen before opening the document.
#[test]
fn timestamp_scope_rejects_before_io() {
    for flag in [
        "--detach",
        "--prefer-pss",
        "--force-revinfo",
        "--no-strict-syntax",
        "--md-algorithm=sha512",
        "--trust-replace",
    ] {
        let d = tempfile::tempdir().unwrap();
        let output = d.path().join("out.pdf");
        fs::write(&output, b"sentinel").unwrap();
        let args = vec![
            "sign",
            "timestamp",
            flag,
            "--timestamp-url",
            "http://127.0.0.1:1/tsa",
            "missing.pdf",
            output.to_str().unwrap(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let result = sigis_cli::run(&args);
        assert_eq!(result.code, 1);
        assert!(
            result
                .stderr
                .contains("not supported by the timestamp command"),
            "{}",
            result.stderr
        );
        assert_eq!(fs::read(&output).unwrap(), b"sentinel");
    }
}

/// Supplementary: even a directly trusted non-TSA certificate cannot timestamp.
#[test]
fn timestamp_leaf_anchor_still_requires_tsa_eku() {
    let c = Case::with_wrong_eku("rsa", false, true);
    fs::write(&c.output, b"sentinel").unwrap();
    let args = c.args(&[]);
    let result = c.native(&args);
    assert_eq!(result.status.code(), Some(1), "{}", text(&result));
    assert!(text(&result).contains("time_stamping"), "{}", text(&result));
    assert_eq!(fs::read(&c.output).unwrap(), b"sentinel");
    c.reference(&args, 1, Some("Generic processing error."));
}

/// Supplementary: a valid dummy cannot authorize a later unsuitable TSA token.
#[test]
fn timestamp_rechecks_the_final_token() {
    let c = Case::with_wrong_eku("rsa", false, true);
    let cfg = serde_json::json!({"validation-contexts":{"test":{"trust":[c.root,c.server.ready["good_tsa_cert"]],"trust-replace":true}}});
    fs::write(&c.config, serde_yaml::to_string(&cfg).unwrap()).unwrap();
    fs::write(&c.output, b"sentinel").unwrap();
    let mut args = c.args(&[]);
    let index = args
        .iter()
        .position(|value| value == "--timestamp-url")
        .unwrap()
        + 1;
    args[index] = c.server.ready["switch_url"].as_str().unwrap().into();
    let result = c.native(&args);
    assert_eq!(result.status.code(), Some(1), "{}", text(&result));
    assert!(text(&result).contains("time_stamping"), "{}", text(&result));
    assert_eq!(fs::read(&c.output).unwrap(), b"sentinel");
    let count: u64 = c.server.metrics()["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["count"].as_u64().unwrap())
        .sum();
    assert_eq!(
        count, 3,
        "Both dummy checks must pass before the final token is refused"
    );
}

/// Supplementary: configuration requirements are not silently erased or rebuilt.
#[test]
fn timestamp_config_scope_rejects_before_io() {
    for config in [
        serde_json::json!({"require-qualified-signature":true}),
        serde_json::json!({"default-validation-context":"test", "default_validation_context":"other"}),
        serde_json::json!({"cache-dir":"unopened-cache"}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pyhanko.yml");
        fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();
        let output = dir.path().join("out.pdf");
        fs::write(&output, b"sentinel").unwrap();
        let args = vec![
            "--config",
            path.to_str().unwrap(),
            "sign",
            "timestamp",
            "--timestamp-url",
            "http://127.0.0.1:1/tsa",
            "missing.pdf",
            output.to_str().unwrap(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let result = sigis_cli::run(&args);
        assert_eq!(result.code, 1);
        assert!(
            result
                .stderr
                .contains("not supported by the timestamp command")
                || result.stderr.contains("Conflicting configuration aliases"),
            "{}",
            result.stderr
        );
        assert_eq!(fs::read(&output).unwrap(), b"sentinel");
    }
    let mut config = sigis_cli::config::CliConfig::parse("").unwrap();
    config.cache_dir = Some("effective-cache-not-in-raw-config".into());
    let result = sigis_cli::timestamp::run_with_runtime(
        &[
            "--timestamp-url",
            "http://127.0.0.1:1/tsa",
            "missing.pdf",
            "untouched.pdf",
        ]
        .map(str::to_owned),
        Some(&config),
        &Default::default(),
    );
    assert!(result
        .unwrap_err()
        .contains("not supported by the timestamp command"));
}

/// Supplementary actual command denial; output verification cannot replace it.
#[test]
fn timestamp_command_refuses_empty_roots() {
    let c = Case::new("rsa", false);
    fs::write(
        &c.config,
        "validation-contexts:\n  test:\n    trust: []\n    trust-replace: true\n",
    )
    .unwrap();
    fs::write(&c.output, b"sentinel").unwrap();
    let args = c.args(&[]);
    let result = c.native(&args);
    assert_eq!(result.status.code(), Some(1), "{}", text(&result));
    assert!(text(&result).contains("TSA token"), "{}", text(&result));
    assert_eq!(fs::read(&c.output).unwrap(), b"sentinel");
    c.reference(&args, 1, Some("Error:"));
}
