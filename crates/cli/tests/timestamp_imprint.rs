//! Supplemental real signed TSA algorithm-substitution guards; zero upstream IDs.
use serde_json::{json, Value};
use sigis_cli::{config::CliConfig, runtime::ValidationRuntime};
use sigis_pki_core::algorithms::DigestAlgorithm;
use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};
const PROBE: &[u8] = b"timestamp imprint algorithm binding probe";
const SENTINEL: &[u8] = b"Keep this output after timestamp algorithm refusal.\n";
fn python() -> PathBuf {
    std::env::var_os("HANKO_ORACLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/tmp/pyhanko-oracle/venv/bin/python".into())
}
fn fixture(name: &str) -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "timestamp", name])
}
struct Server {
    child: Child,
    ready: Value,
}
impl Server {
    fn start(mode: &str, directory: &Path) -> Self {
        fs::create_dir_all(directory).unwrap();
        let mut child = Command::new(python())
            .arg(fixture("imprint_server.py"))
            .args(["--imprint-mode", mode, "--architecture", "rsa", "--crypto"])
            .arg(sigis_testdata::pyhanko(&["crypto"]))
            .arg("--artifacts")
            .arg(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(
                fs::File::create(directory.join("server.stderr")).unwrap(),
            ))
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
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
            fs::read_to_string(directory.join("server.stderr")).unwrap()
        );
        let ready: Value = serde_json::from_str(&line).unwrap();
        let server = Self { child, ready };
        assert_eq!(server.ready["clock"], "current UTC");
        assert_eq!(server.ready["architecture"], "rsa");
        assert_eq!(server.ready["pyhanko"], "0.38.1");
        assert_eq!(server.ready["certvalidator"], "0.33.0");
        server
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
fn file_record(path: &Path) -> Value {
    let path = path.canonicalize().unwrap();
    let bytes = fs::read(&path).unwrap();
    let sha = openssl::sha::sha256(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    json!({"path":path,"length":bytes.len(),"sha256":sha})
}
fn events(directory: &Path) -> Vec<Value> {
    fs::read_to_string(directory.join("imprint-events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn copy_tree(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        let dst = target.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &dst)?;
        } else {
            fs::copy(path, dst)?;
        }
    }
    Ok(())
}
// Construct before server/oracle/CMS checks; Drop preserves evidence on every
// assertion/error unwind, including helper preconditions. No other process used.
struct Evidence {
    directory: tempfile::TempDir,
    retained: PathBuf,
}
impl Evidence {
    fn new(mode: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let base = std::env::var_os("SIGIS_TIMESTAMP_IMPRINT_RECORD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("sigis-timestamp-imprint-guard"));
        let retained = base.join(format!(
            "{}-{mode}-{}",
            std::process::id(),
            directory.path().file_name().unwrap().to_string_lossy()
        ));
        eprintln!(
            "TIMESTAMP_IMPRINT_EVIDENCE {}",
            json!({"retained":retained,"mode":mode})
        );
        Self {
            directory,
            retained,
        }
    }
    fn path(&self) -> &Path {
        self.directory.path()
    }
    fn capture(&self) {
        copy_tree(self.path(), &self.retained).expect("Retain actual timestamp imprint evidence");
    }
}
impl Drop for Evidence {
    fn drop(&mut self) {
        if let Err(error) = copy_tree(self.path(), &self.retained) {
            eprintln!("Timestamp imprint evidence capture failed: {error}");
        }
    }
}
fn check(mode: &str) {
    let directory = Evidence::new(mode);
    let server_dir = directory.path().join("server");
    let server = Server::start(mode, &server_dir);
    let root = PathBuf::from(server.ready["exported_root"]["path"].as_str().unwrap());
    let configuration = json!({"validation-contexts":{"test":{"trust":root,"trust-replace":true}}});
    let config = CliConfig::parse(&configuration.to_string()).unwrap();
    let config_before = config.raw_config.clone();
    let runtime = ValidationRuntime::default();
    let context =
        sigis_cli::validation::context_from_config(Some(&config), Some("test"), &runtime).unwrap();
    assert_eq!(context.trust_anchors().len(), 1);
    assert_eq!(context.moment(), runtime.now);
    let imprint = DigestAlgorithm::Sha256.digest(PROBE);
    // Separate control: nonce-correlated HTTP token is correctly CMS-signed by
    // the same genuinely trusted TSA; the public CMS helper is algorithm-agnostic.
    // Use raw transport plus status/nonce parsing for this deliberate malicious
    // control. The bound client must reject the substituted imprint instead.
    let nonce: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let request = sigis_pki_fetch::tsa::request_cms(
        &imprint,
        DigestAlgorithm::Sha256,
        Some(nonce.as_slice()),
    )
    .unwrap();
    assert_eq!(
        request.message_imprint.hash_algorithm.oid,
        DigestAlgorithm::Sha256.oid()
    );
    assert_eq!(
        request.message_imprint.hashed_message.as_bytes(),
        imprint.as_slice()
    );
    assert_eq!(request.nonce.as_ref().unwrap().as_bytes(), nonce.as_slice());
    assert!(request.cert_req);
    let request_der = der::Encode::to_der(&request).unwrap();
    let request_path = directory.path().join("actual-probe-request.der");
    fs::write(&request_path, &request_der).unwrap();
    let response = sigis_pki_fetch::HttpTimeStamper::new(server.ready["tsa_url"].as_str().unwrap())
        .request_tsa_response(&request_der)
        .unwrap();
    let response_path = directory.path().join("actual-probe-response.der");
    fs::write(&response_path, &response).unwrap();
    let token =
        sigis_pki_fetch::tsa::handle_tsp_response(&response, Some(nonce.as_slice())).unwrap();
    let token_path = directory.path().join("actual-probe-token.cms");
    fs::write(&token_path, &token).unwrap();
    let cms = sigis_cms::validate_timestamp_token(&token, &imprint, &context).unwrap();
    assert!(cms.signature.bottom_line(), "{cms:?}");
    sigis_pki_core::key_usage::KeyUsageConstraints::with_extd_key_usage(["time_stamping"])
        .validate(cms.signature.signing_cert.as_ref().unwrap())
        .unwrap();
    let info = sigis_pki_fetch::tsa::token_tst_info(&token).unwrap();
    assert_eq!(
        info.nonce.as_ref().map(|value| value.as_bytes()),
        Some(nonce.as_slice())
    );
    assert_eq!(
        info.message_imprint.hashed_message.as_bytes(),
        imprint.as_slice()
    );
    let wrong = mode != "valid";
    assert_eq!(
        info.message_imprint.hash_algorithm.oid,
        if wrong {
            DigestAlgorithm::Sha384.oid()
        } else {
            DigestAlgorithm::Sha256.oid()
        }
    );
    let oracle_path = directory.path().join("fresh-probe-verdict.json");
    let preimage_hex = PROBE.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let oracle = Command::new(python())
        .arg(fixture("oracle_imprint.py"))
        .arg("--token")
        .arg(&token_path)
        .arg("--root")
        .arg(&root)
        .arg("--preimage-hex")
        .arg(&preimage_hex)
        .arg("--expect-intact")
        .arg(if wrong { "false" } else { "true" })
        .arg("--record")
        .arg(&oracle_path)
        .output()
        .unwrap();
    fs::write(directory.path().join("oracle.stdout"), &oracle.stdout).unwrap();
    fs::write(directory.path().join("oracle.stderr"), &oracle.stderr).unwrap();
    directory.capture();
    assert!(
        oracle.status.success(),
        "{}{}",
        String::from_utf8_lossy(&oracle.stdout),
        String::from_utf8_lossy(&oracle.stderr)
    );
    let verdict: Value = serde_json::from_slice(&fs::read(&oracle_path).unwrap()).unwrap();
    assert_eq!(verdict["raw_preimage"]["intact"], !wrong);
    assert_eq!(verdict["raw_preimage"]["bottom_line"], !wrong);
    for field in ["intact", "valid", "trusted", "bottom_line"] {
        assert_eq!(verdict["signature_component"][field], true, "{verdict}");
    }
    assert_eq!(
        verdict["signature_component"]["algorithm_binding_checked"],
        false
    );
    if !wrong {
        assert_eq!(verdict["raw_preimage"]["valid"], true);
        assert_eq!(verdict["raw_preimage"]["trusted"], true);
    }
    let before_count = events(&server_dir).len();
    assert_eq!(before_count, 1);
    let input = directory.path().join("input.pdf");
    let output = directory.path().join("out.pdf");
    fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &input).unwrap();
    let original_input = fs::read(&input).unwrap();
    fs::write(&output, SENTINEL).unwrap();
    let args = vec![
        "--validation-context".into(),
        "test".into(),
        "--timestamp-url".into(),
        server.ready["tsa_url"].as_str().unwrap().into(),
        input.display().to_string(),
        output.display().to_string(),
    ];
    let result = sigis_cli::timestamp::run_with_runtime(&args, Some(&config), &runtime);
    let actual_events = events(&server_dir);
    let receipt = json!({"mode":mode,"kind":"in-process existing public timestamp API, not a CLI subprocess","result":result,"argv_after_sign_timestamp":args,"effective_configuration":config_before,"native_test_executable":file_record(&std::env::current_exe().unwrap()),"input":file_record(&input),"output":file_record(&output),"raw_probe":{"request":file_record(&request_path),"response":file_record(&response_path),"token":file_record(&token_path),"nonce_hex":nonce.iter().map(|byte|format!("{byte:02x}")).collect::<String>()},"before_command_TSA_tokens":before_count,"after_command_TSA_tokens":actual_events.len(),"events":actual_events,"oracle":verdict,"context_clock":format!("{:?}",runtime.now),"new_unique_credit":0});
    fs::write(
        directory.path().join("native-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    // Preserve the actual RED outputs before the assertion can unwind a TempDir.
    // Set the path with Cargo --config env.SIGIS_TIMESTAMP_IMPRINT_RECORD_DIR.*.
    directory.capture();
    let retained = directory.retained.clone();
    eprintln!(
        "TIMESTAMP_IMPRINT_GUARD {}",
        json!({"retained":retained,"receipt":receipt})
    );
    assert_eq!(config.raw_config, config_before);
    assert_eq!(fs::read(&input).unwrap(), original_input);
    if wrong {
        let error =
            result.expect_err("A signed response cannot substitute its declared imprint algorithm");
        assert!(
            error.to_ascii_lowercase().contains("imprint algorithm"),
            "{error}"
        );
        assert_eq!(fs::read(&output).unwrap(), SENTINEL);
        assert_eq!(
            actual_events.len() - before_count,
            if mode == "wrong-all" { 1 } else { 3 }
        );
    } else {
        result.unwrap();
        assert_eq!(actual_events.len() - before_count, 3);
        let pdf = sigis_pdf::PdfFile::parse(&fs::read(&output).unwrap()).unwrap();
        let signatures = pdf.embedded_signatures().unwrap();
        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0].kind, sigis_pdf::SignatureKind::DocTimeStamp);
        let status = sigis_pades::validate_pdf_timestamp(&pdf, &signatures[0], &context).unwrap();
        assert!(status.timestamp.signature.bottom_line(), "{status:?}");
    }
}
#[test]
fn requested_timestamp_imprint_algorithm_positive() {
    check("valid");
}
#[test]
fn signed_wrong_timestamp_imprint_algorithm_rejects_dummy() {
    check("wrong-all");
}
#[test]
fn signed_wrong_timestamp_imprint_algorithm_rejects_final() {
    check("wrong-final");
}
