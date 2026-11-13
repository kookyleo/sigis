//! Three original CLI LTA functions / seven source parameters, using actual processes.
//! Current-clock signer1-long credentials are an explicit fixture adaptation.
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;

use sigis_pdf::{PdfFile, ReaderOptions, SignatureKind};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
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
fn driver(name: &str) -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "pkcs12-lta", name])
}
fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
fn write_json(path: &Path, value: &serde_json::Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

struct LiveServer {
    child: Child,
    ready: serde_json::Value,
    ready_path: PathBuf,
    stderr_path: PathBuf,
}
impl LiveServer {
    fn start(architecture: &str, directory: &Path) -> Self {
        fs::create_dir_all(directory).unwrap();
        let script = driver("live_server.py");
        common::record_file(&script, "current_live_server_driver");
        common::record_file(&python(), "current_live_server_python");
        let stderr_path = directory.join("server.stderr");
        let child = Command::new(python())
            .arg(&script)
            .arg("--crypto")
            .arg(sigis_testdata::pyhanko(&["crypto"]))
            .arg("--architecture")
            .arg(architecture)
            .arg("--artifacts")
            .arg(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            ready: serde_json::Value::Null,
            ready_path: directory.join("server-ready.json"),
            stderr_path,
        };
        let stdout = server.child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout)
                .read_line(&mut line)
                .map(|_| line)
                .map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        let line = receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("test-owned live server must become ready within30seconds")
            .expect("live-server readiness must be readable");
        assert!(
            !line.trim().is_empty(),
            "{}",
            fs::read_to_string(&server.stderr_path).unwrap()
        );
        server.ready = serde_json::from_str(&line).unwrap();
        assert_eq!(server.ready["architecture"], architecture);
        assert_eq!(server.ready["clock"], "current UTC");
        assert_eq!(server.ready["pyhanko"], "0.38.1");
        assert_eq!(server.ready["certvalidator"], "0.33.0");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&server.ready_path).unwrap())
                .unwrap(),
            server.ready
        );
        for key in ["exported_pfx", "exported_root", "python", "driver"] {
            let path = PathBuf::from(server.ready[key]["path"].as_str().unwrap());
            assert_eq!(signing_record::before(&[path])[0], server.ready[key]);
        }
        server
    }
    fn path(&self, key: &str) -> PathBuf {
        PathBuf::from(self.ready[key]["path"].as_str().unwrap())
    }
}
impl Drop for LiveServer {
    fn drop(&mut self) {
        // This unreaped Child belongs exclusively to this test. Never stop a
        // pre-existing server, build or another test's process.
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(self.child.id().to_string())
                .status();
            for _ in 0..50 {
                if !matches!(self.child.try_wait(), Ok(None)) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if matches!(self.child.try_wait(), Ok(None)) {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
    }
}

/// Read this test-owned loopback endpoint without an oracle or extra dependency.
fn metrics(url: &str) -> serde_json::Value {
    let target = url
        .strip_prefix("http://")
        .expect("loopback HTTP metrics URL");
    let (authority, path) = target.split_once('/').unwrap();
    let address: SocketAddr = authority.parse().unwrap();
    assert!(address.ip().is_loopback());
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET /{path} HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let separator = response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    let headers = String::from_utf8_lossy(&response[..separator]);
    assert!(
        headers.lines().next().unwrap().contains(" 200 "),
        "{headers}"
    );
    assert!(
        !headers
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked"),
        "HTTP/1.0 response framing must be explicit"
    );
    serde_json::from_slice(&response[separator + 4..]).unwrap()
}

fn native_metrics_counts(record: &serde_json::Value) -> (u64, u64, u64) {
    let mut tsa = 0;
    let mut ocsp = 0;
    let mut crl = 0;
    for request in record["requests"].as_array().unwrap() {
        if request["status"] != 200 {
            continue;
        }
        let path = request["path"].as_str().unwrap();
        let count = request["count"].as_u64().unwrap();
        if request["method"] == "POST" && path.contains("/tsa/") {
            tsa += count;
        }
        if path.contains("/ocsp/") {
            ocsp += count;
        }
        if path.contains("/crls/") || path.ends_with(".crl") {
            crl += count;
        }
    }
    (tsa, ocsp, crl)
}

fn verify_native_lta(directory: &Path, input: &Path, output: &Path, root: &Path, nonstrict: bool) {
    let script = driver("oracle_lta_verify.py");
    let record_path = directory.join("native-full-lta-validation.json");
    let mut args = vec![
        script.display().to_string(),
        "--input".into(),
        input.display().to_string(),
        "--output".into(),
        output.display().to_string(),
        "--root".into(),
        root.display().to_string(),
        "--record".into(),
        record_path.display().to_string(),
    ];
    if nonstrict {
        args.push("--allow-hybrid".into());
    }
    let inputs = signing_record::before(&[
        input.to_path_buf(),
        output.to_path_buf(),
        root.to_path_buf(),
        script,
    ]);
    let result = Command::new(python())
        .args(&args)
        .current_dir(directory)
        .output()
        .unwrap();
    let mut artifacts = vec![("actual_native_lta_pdf", output)];
    if record_path.is_file() {
        artifacts.push(("fresh_full_lta_reference_record", record_path.as_path()));
    }
    signing_record::process(
        "reference-full-lta-validation",
        &args,
        directory,
        b"",
        &python(),
        &result,
        &inputs,
        &artifacts,
    );
    assert!(result.status.success(), "{}", text(&result));
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(record_path).unwrap()).unwrap();
    assert_eq!(record["success"], true, "{record}");
    assert_eq!(
        record["result"]["positive"]["bottom_line"], true,
        "{record}"
    );
    assert_eq!(record["result"]["positive"]["intact"], true);
    assert_eq!(record["result"]["positive"]["valid"], true);
    assert_eq!(record["result"]["positive"]["trusted"], true);
    assert_eq!(
        record["result"]["original_integrity"],
        serde_json::json!([true, true])
    );
    assert_eq!(
        record["result"]["wrong_digest_integrity"],
        serde_json::json!([false, true])
    );
    assert_eq!(record["result"]["empty_roots"]["bottom_line"], false);
}

fn current_reference_cli(
    directory: &Path,
    input: &Path,
    native_output: &Path,
    root: &Path,
    args: &[String],
    native_inputs: &[serde_json::Value],
    required_inputs: &[PathBuf],
) {
    let script = driver("oracle_cli_current.py");
    let output = directory.join("oracle.pdf");
    let record_path = directory.join("reference-cli.json");
    let mut actual_args = vec![
        script.display().to_string(),
        "--input".into(),
        input.display().to_string(),
        "--output".into(),
        output.display().to_string(),
        "--root".into(),
        root.display().to_string(),
        "--record".into(),
        record_path.display().to_string(),
        "--".into(),
    ];
    actual_args.extend(args.iter().map(|value| {
        if value == native_output.to_str().unwrap() {
            output.display().to_string()
        } else {
            value.clone()
        }
    }));
    let mut paths = required_inputs.to_vec();
    paths.extend([script, native_output.to_path_buf()]);
    let before = signing_record::before(&paths);
    let result = Command::new(python())
        .args(&actual_args)
        .current_dir(directory)
        .output()
        .unwrap();
    let mut artifacts = vec![("retained_native_lta_pdf", native_output)];
    if output.is_file() {
        artifacts.push(("actual_reference_cli_pdf", output.as_path()));
    }
    if record_path.is_file() {
        artifacts.push(("actual_reference_cli_record", record_path.as_path()));
    }
    signing_record::process(
        "reference-current-clock-cli",
        &actual_args,
        directory,
        b"",
        &python(),
        &result,
        &before,
        &artifacts,
    );
    assert!(result.status.success(), "{}", text(&result));
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(record_path).unwrap()).unwrap();
    assert_eq!(record["exit_code"], 0, "{record}");
    assert!(record["exception"].is_null(), "{record}");
    assert!(output.is_file());
    for path in required_inputs {
        let path = path.canonicalize().unwrap();
        let key = path.to_str().unwrap();
        let native = native_inputs
            .iter()
            .find(|item| item["path"] == key)
            .unwrap();
        assert_eq!(
            record["input_candidates_before_use"][key], *native,
            "Same actual inputs must reach native and reference commands"
        );
    }
}

fn lta_case(architecture: &str, nonstrict: bool) {
    let directory = tempfile::tempdir().unwrap();
    let server = LiveServer::start(architecture, &directory.path().join("server"));
    let input = directory.path().join("input.pdf");
    let output = directory.path().join("output.pdf");
    let config_path = directory.path().join("pyhanko.yml");
    let pfx = server.path("exported_pfx");
    let root = server.path("exported_root");
    fs::copy(
        if nonstrict {
            sigis_testdata::path(&["lanes", "r3-c", "signing", "mildly-broken.pdf"])
        } else {
            sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])
        },
        &input,
    )
    .unwrap();
    let config = serde_json::json!({
        "pkcs12-setups":{"test":{"pfx-file":pfx,"pfx-passphrase":"secret"}},
        "validation-contexts":{"test":{"trust":root,"trust-replace":true}},
    });
    fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
    let mut args = vec![
        "sign".into(),
        "addsig".into(),
        "--field".into(),
        "Sig1".into(),
    ];
    if nonstrict {
        args.push("--no-strict-syntax".into());
    }
    args.extend([
        "--validation-context".into(),
        "test".into(),
        "--with-validation-info".into(),
        "--use-pades-lta".into(),
        "--timestamp-url".into(),
        server.ready["tsa_url"].as_str().unwrap().into(),
        "pkcs12".into(),
        "--p12-setup".into(),
        "test".into(),
        input.display().to_string(),
        output.display().to_string(),
    ]);
    let required = vec![input.clone(), config_path, pfx, root.clone()];
    let mut paths = required.clone();
    paths.extend([server.ready_path.clone(), driver("live_server.py")]);
    let before = signing_record::before(&paths);
    let binary_before = signing_record::before(std::slice::from_ref(common::cli()));
    let before_path = directory.path().join("native-cli-before.json");
    write_json(&before_path, &serde_json::json!(binary_before));
    let result = Command::new(common::cli())
        .args(&args)
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    // This is the native-only request snapshot. It MUST precede every oracle
    // command and verifier, whose traffic cannot prove native acquisition.
    let requests = metrics(server.ready["metrics_url"].as_str().unwrap());
    let metrics_path = directory.path().join("native-only-requests.json");
    write_json(&metrics_path, &requests);
    let binary_after = signing_record::before(std::slice::from_ref(common::cli()));
    let after_path = directory.path().join("native-cli-after.json");
    write_json(&after_path, &serde_json::json!(binary_after));
    let mut artifacts = vec![
        ("native_only_http_metrics", metrics_path.as_path()),
        ("server_ready", server.ready_path.as_path()),
        ("server_stderr", server.stderr_path.as_path()),
        ("actual_cli_before", before_path.as_path()),
        ("actual_cli_after", after_path.as_path()),
    ];
    if output.is_file() {
        artifacts.push(("actual_native_lta_pdf", output.as_path()));
    }
    signing_record::process(
        "native-current-clock-lta-cli",
        &args,
        directory.path(),
        b"",
        common::cli(),
        &result,
        &before,
        &artifacts,
    );
    assert_eq!(
        binary_before, binary_after,
        "Private CLI must stay immutable"
    );
    assert_eq!(result.status.code(), Some(0), "{}", text(&result));
    let (tsa, ocsp, crl) = native_metrics_counts(&requests);
    assert!(
        tsa >= 2,
        "At least signature and document TSA POSTs: {requests}"
    );
    assert!(
        ocsp > 0,
        "Native signing must acquire actual OCSP: {requests}"
    );
    assert!(
        crl > 0,
        "Native signing must acquire actual CRL: {requests}"
    );
    let bytes = fs::read(&output).unwrap();
    let pdf = PdfFile::parse_with(
        &bytes,
        ReaderOptions {
            strict: !nonstrict,
            ..Default::default()
        },
    )
    .unwrap();
    let signatures = pdf.embedded_signatures().unwrap();
    assert!(signatures
        .iter()
        .any(|signature| signature.kind == SignatureKind::Signature));
    assert!(signatures
        .iter()
        .any(|signature| signature.kind == SignatureKind::DocTimeStamp));
    let dss = pdf
        .dss()
        .unwrap()
        .expect("Real LTA output must embed its DSS");
    assert!(
        !dss.material.crls.is_empty(),
        "Supplemental real DSS CRL assertion"
    );
    assert!(
        !dss.material.ocsps.is_empty(),
        "Supplemental real DSS OCSP assertion"
    );
    verify_native_lta(directory.path(), &input, &output, &root, nonstrict);
    current_reference_cli(
        directory.path(),
        &input,
        &output,
        &root,
        &args,
        &before,
        &required,
    );
}

#[test]
fn test_cli_pades_lta() {
    for architecture in ["rsa", "ecdsa", "ed25519"] {
        lta_case(architecture, false);
    }
}

#[test]
fn test_cli_pades_lta_nonstrict() {
    for architecture in ["rsa", "ecdsa", "ed25519"] {
        lta_case(architecture, true);
    }
}

#[test]
fn test_cli_pades_lta_no_timestamp_url() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.pdf");
    let output = directory.path().join("output.pdf");
    let config_path = directory.path().join("pyhanko.yml");
    let root = sigis_testdata::path(&["lanes", "r3-c", "signing", "rsa", "root.pem"]);
    let key = sigis_testdata::path(&["lanes", "r3-c", "signing", "rsa", "key.pem"]);
    let cert = sigis_testdata::path(&["lanes", "r3-c", "signing", "rsa", "cert.pem"]);
    fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &input).unwrap();
    fs::write(
        &config_path,
        serde_yaml::to_string(&serde_json::json!({
            "validation-contexts":{"test":{"trust":root,"trust-replace":true}},
        }))
        .unwrap(),
    )
    .unwrap();
    let args = vec![
        "sign".into(),
        "addsig".into(),
        "--field".into(),
        "Sig1".into(),
        "--validation-context".into(),
        "test".into(),
        "--with-validation-info".into(),
        "--use-pades-lta".into(),
        "pemder".into(),
        "--key".into(),
        key.display().to_string(),
        "--cert".into(),
        cert.display().to_string(),
        input.display().to_string(),
        output.display().to_string(),
    ];
    let inputs = signing_record::before(&[input, config_path, root, key, cert]);
    let result = Command::new(common::cli())
        .args(&args)
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let artifacts = if output.is_file() {
        vec![("unexpected_native_output", output.as_path())]
    } else {
        Vec::new()
    };
    signing_record::process(
        "native-missing-lta-timestamp-url",
        &args,
        directory.path(),
        b"",
        common::cli(),
        &result,
        &inputs,
        &artifacts,
    );
    assert_eq!(result.status.code(), Some(1), "{}", text(&result));
    assert!(
        text(&result).contains("--timestamp-url is required"),
        "{}",
        text(&result)
    );
    assert!(!output.exists());
    let script = sigis_testdata::path(&["lanes", "r3-c", "signing", "oracle_cli.py"]);
    let mut oracle_inputs = inputs.clone();
    oracle_inputs.extend(signing_record::before(std::slice::from_ref(&script)));
    let mut oracle_args = vec![script.display().to_string(), "".into(), "rsa".into()];
    oracle_args.extend_from_slice(&args);
    let result = Command::new(python())
        .args(&oracle_args)
        .current_dir(directory.path())
        .output()
        .unwrap();
    let artifacts = if output.is_file() {
        vec![("unexpected_reference_output", output.as_path())]
    } else {
        Vec::new()
    };
    signing_record::process(
        "reference-missing-lta-timestamp-url",
        &oracle_args,
        directory.path(),
        b"",
        &python(),
        &result,
        &oracle_inputs,
        &artifacts,
    );
    assert!(result.status.success(), "{}", text(&result));
    let stdout = String::from_utf8(result.stdout).unwrap();
    let (code, message) = stdout.split_once('\n').unwrap();
    assert_eq!(code, "1", "{message}");
    assert!(message.contains("--timestamp-url is required"), "{message}");
    assert!(!output.exists());
}
