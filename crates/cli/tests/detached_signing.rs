//! Exact tests-first ports of the two detached pyHanko 0.38.1 CLI functions.
//! Twelve positive parameters and one field-conflict case; receipts identify actual runs.
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;

use serde_json::{json, Value};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{cert::Cert, time::Moment};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::Duration,
};

fn fixture(arch: &str, name: &str) -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "signing", arch, name])
}
fn helper(name: &str) -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "detached-signing", name])
}
fn python() -> PathBuf {
    sigis_testdata::oracle::python().expect("pinned oracle is required")
}
fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
fn sha(data: &[u8]) -> String {
    openssl::sha::sha256(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
struct Case {
    dir: tempfile::TempDir,
    arch: &'static str,
    cert_name: &'static str,
}
impl Case {
    fn new(arch: &'static str, setup: bool) -> Self {
        let case = Self {
            dir: tempfile::tempdir().unwrap(),
            arch,
            cert_name: if setup { "signer.crt" } else { "cert.pem" },
        };
        fs::copy(
            sigis_testdata::path(&["lanes", "r3-c", "runtime", "minimal.pdf"]),
            case.path("input.pdf"),
        )
        .unwrap();
        let cert =
            openssl::x509::X509::from_pem(&fs::read(fixture(arch, "cert.pem")).unwrap()).unwrap();
        fs::write(
            case.path(case.cert_name),
            if setup {
                cert.to_der().unwrap()
            } else {
                cert.to_pem().unwrap()
            },
        )
        .unwrap();
        if setup {
            let config = json!({"pemder-setups":{"test":{
                "key-file":fixture(arch,"key.pem"),"cert-file":case.path(case.cert_name),
                "other-certs":[fixture(arch,"interm.pem"),fixture(arch,"root.pem")]
            }}});
            fs::write(
                case.path("pyhanko.yml"),
                serde_yaml::to_string(&config).unwrap(),
            )
            .unwrap();
        }
        fs::write(case.path("output.sig.pem"), b"detached-output-sentinel").unwrap();
        case
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn input_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![
            self.path("input.pdf"),
            self.path(self.cert_name),
            fixture(self.arch, "key.pem"),
            fixture(self.arch, "root.pem"),
            fixture(self.arch, "interm.pem"),
            helper("oracle.py"),
        ];
        if self.path("pyhanko.yml").exists() {
            paths.push(self.path("pyhanko.yml"));
        }
        paths
    }
    fn invoke(&self, argv: &[String]) -> Output {
        let inputs = signing_record::before(&self.input_paths());
        let output = Command::new(common::cli())
            .args(argv)
            .current_dir(self.dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        signing_record::process(
            "detached-native-cli",
            argv,
            self.dir.path(),
            b"",
            common::cli(),
            &output,
            &inputs,
            &[("native-cms-or-sentinel", &self.path("output.sig.pem"))],
        );
        output
    }
    fn reference(&self, original: &[String], timestamp: bool) -> Value {
        let mut argv = vec![
            helper("oracle.py").display().to_string(),
            "--input".into(),
            self.path("input.pdf").display().to_string(),
            "--output".into(),
            self.path("reference.sig.pem").display().to_string(),
            "--root".into(),
            fixture(self.arch, "root.pem").display().to_string(),
        ];
        if timestamp {
            argv.push("--timestamp".into());
        }
        argv.extend(["cli".into(), self.arch.into(), "--".into()]);
        let mut reference_args = original.to_vec();
        *reference_args.last_mut().unwrap() = "reference.sig.pem".into();
        argv.extend(reference_args);
        let inputs = signing_record::before(&self.input_paths());
        let output = Command::new(python())
            .args(&argv)
            .current_dir(self.dir.path())
            .output()
            .unwrap();
        let artifact = self.path("reference.sig.pem");
        let artifacts = if artifact.exists() {
            vec![("reference-cms", artifact.as_path())]
        } else {
            vec![]
        };
        signing_record::process(
            "detached-reference-cli",
            &argv,
            self.dir.path(),
            b"",
            &python(),
            &output,
            &inputs,
            &artifacts,
        );
        if timestamp {
            self.capture_tsa("reference-complete");
        }
        assert!(output.status.success(), "{}", text(&output));
        let record: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record["optimize"], 0);
        assert_eq!(record["pyhanko"], "0.38.1");
        assert_eq!(record["certvalidator"], "0.33.0");
        record
    }
    fn capture_tsa(&self, phase: &str) -> Vec<Value> {
        let mut files = fs::read_dir(self.path("tsa-http"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        files.sort();
        let proof = signing_record::before(&files);
        if let Some(base) = std::env::var_os("SIGIS_CLI_SIGNING_RECORD_DIR") {
            let target = PathBuf::from(base).join(format!(
                "tsa-{}-{phase}",
                self.dir.path().file_name().unwrap().to_str().unwrap()
            ));
            fs::create_dir(&target).unwrap();
            for path in files {
                fs::copy(&path, target.join(path.file_name().unwrap())).unwrap();
            }
            fs::write(target.join("phase.json"),serde_json::to_vec_pretty(&json!({
                "phase":phase,"architecture":self.arch,"files":proof,
                "scope":"snapshot at this boundary; later reference requests are not native requests"
            })).unwrap()).unwrap();
        }
        proof
    }
    fn verify(&self, timestamp: bool, is_pem: bool, native_tsa: &[Value]) {
        let signed = self.path("output.sig.pem");
        let root = fixture(self.arch, "root.pem");
        let evidence = self.path("revinfo");
        let mut argv = vec![
            helper("oracle.py").display().to_string(),
            "--input".into(),
            self.path("input.pdf").display().to_string(),
            "--output".into(),
            signed.display().to_string(),
            "--root".into(),
            root.display().to_string(),
            "--export-revinfo".into(),
            evidence.display().to_string(),
        ];
        if timestamp {
            argv.push("--timestamp".into());
        }
        for file in native_tsa.iter().filter(|file| {
            let path = Path::new(file["path"].as_str().unwrap());
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("response-")
                && path.extension().is_some_and(|ext| ext == "der")
        }) {
            argv.extend([
                "--native-response".into(),
                file["path"].as_str().unwrap().into(),
            ]);
        }
        argv.extend(["verify".into(), self.arch.into()]);
        let inputs = signing_record::before(&[
            signed.clone(),
            self.path("input.pdf"),
            root.clone(),
            helper("oracle.py"),
        ]);
        let output = Command::new(python())
            .args(&argv)
            .current_dir(self.dir.path())
            .output()
            .unwrap();
        signing_record::process(
            "detached-same-output-oracle",
            &argv,
            self.dir.path(),
            b"",
            &python(),
            &output,
            &inputs,
            &[("native-cms", &signed)],
        );
        assert!(output.status.success(), "{}", text(&output));
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["bottom_line"], true);
        assert_eq!(result["has_timestamp"], timestamp);
        assert_eq!(result["pem"], is_pem);
        assert_eq!(result["optimize"], 0);
        let raw = fs::read(&signed).unwrap();
        assert_eq!(result["signed_output"]["sha256"], sha(&raw));
        let der = if is_pem {
            let armor = String::from_utf8(raw.clone()).unwrap();
            // Supplemental format assertion: pinned plugin uses PKCS7 armor.
            assert!(armor.starts_with("-----BEGIN PKCS7-----"));
            let body: String = armor
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            openssl::base64::decode_block(&body).unwrap()
        } else {
            raw
        };
        let sd = sigis_cms::SignedData::from_content_info_der(&der).unwrap();
        assert!(sd.econtent.is_none());
        assert_eq!(sd.signer_infos.len(), 1);
        let metadata: Value =
            serde_json::from_slice(&fs::read(evidence.join("metadata.json")).unwrap()).unwrap();
        assert_eq!(metadata["architecture"], self.arch);
        assert!(!metadata["crls"].as_array().unwrap().is_empty());
        let moment = Moment::parse_rfc3339(metadata["moment"].as_str().unwrap()).unwrap();
        // Original direct ValidationContext semantics, not CLI context defaults.
        let mut trusted = ValidationContext::builder()
            .moment(moment)
            .point_in_time_validation(false)
            .time_tolerance(Duration::from_secs(1))
            .revocation_mode("soft-fail")
            .trust_root(Cert::from_pem_or_der(&fs::read(&root).unwrap()).unwrap());
        let mut no_roots = ValidationContext::builder()
            .moment(moment)
            .point_in_time_validation(false)
            .time_tolerance(Duration::from_secs(1))
            .revocation_mode("soft-fail");
        let mut proof_files = vec![
            signed.clone(),
            self.path("input.pdf"),
            root.clone(),
            evidence.join("metadata.json"),
        ];
        for crl in metadata["crls"].as_array().unwrap() {
            let path = Path::new(crl["path"].as_str().unwrap());
            assert!(path.starts_with(&evidence));
            let bytes = fs::read(path).unwrap();
            assert_eq!(crl["sha256"], sha(&bytes));
            proof_files.push(path.to_path_buf());
            trusted = trusted.crl(bytes.clone());
            no_roots = no_roots.crl(bytes);
        }
        let data = fs::read(self.path("input.pdf")).unwrap();
        let status =
            sigis_cms::validate_detached_cms(&data, &der, &trusted.build().unwrap()).unwrap();
        assert!(status.bottom_line(), "{status:?}");
        assert!(
            status.signature.intact && status.signature.valid && status.signature.trusted(),
            "{status:?}"
        );
        assert_eq!(status.timestamp_validity.is_some(), timestamp);
        // Supplemental claim-vs-TSA semantics and equal-evidence trust guard.
        assert_eq!(status.signer_reported_dt.is_some(), !timestamp);
        let denied = sigis_cms::validate_detached_cms(&data, &der, &no_roots.build().unwrap());
        let no_root_outcome = match denied {
            Ok(status) => {
                assert!(
                    !status.signature.trusted() && !status.bottom_line(),
                    "{status:?}"
                );
                json!({"result":"untrusted_status","trusted":status.signature.trusted(),"bottom_line":status.bottom_line()})
            }
            Err(error) => json!({"result":"validation_error","error":error.to_string()}),
        };
        if timestamp {
            assert!(native_tsa.iter().any(|file| file["path"].as_str().unwrap().ends_with(".der")),
                    "A successful native TSA command must have its own requests before reference execution");
            // Append-only summary changes after the reference; raw DER files do not.
            for file in native_tsa
                .iter()
                .filter(|file| file["path"].as_str().unwrap().ends_with(".der"))
            {
                assert_eq!(
                    file["sha256"],
                    sha(&fs::read(file["path"].as_str().unwrap()).unwrap())
                );
            }
            let mut captured = fs::read_dir(self.path("tsa-http"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            captured.sort();
            assert!(!captured.is_empty());
            proof_files.extend(captured);
        }
        let proof = signing_record::before(&proof_files);
        let record = json!({"kind":"in-process","architecture":self.arch,
            "has_timestamp":timestamp,"pem":is_pem,"signed_sha256":sha(&fs::read(&signed).unwrap()),
            "moment":metadata["moment"],"bottom_line":true,"empty_roots_denied":true,
            "native_tsa_before_reference":native_tsa,
            "empty_roots_outcome":no_root_outcome,"evidence_before_archive":proof});
        if let Some(directory) = std::env::var_os("SIGIS_CLI_SIGNING_RECORD_DIR") {
            let directory = PathBuf::from(directory).join(format!(
                "native-detached-{}-{}-ts{}-pem{}",
                self.dir.path().file_name().unwrap().to_str().unwrap(),
                self.arch,
                timestamp,
                is_pem
            ));
            fs::create_dir(&directory).unwrap();
            for (index, path) in proof_files.iter().enumerate() {
                fs::copy(path, directory.join(format!("evidence-{index:02}.bin"))).unwrap();
            }
            fs::write(
                directory.join("receipt.json"),
                serde_json::to_vec_pretty(&record).unwrap(),
            )
            .unwrap();
        }
        eprintln!("DETACHED_NATIVE_VALIDATION {record}");
    }
}

// Preserve the complete per-case bytes even when an assertion unwinds before
// successful native validation. Each tempfile identity is unique per attempt.
impl Drop for Case {
    fn drop(&mut self) {
        fn copy_tree(source: &Path, target: &Path, files: &mut Vec<Value>) -> std::io::Result<()> {
            fs::create_dir(target)?;
            let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|entry| entry.path());
            for entry in entries {
                let path = entry.path();
                let dest = target.join(entry.file_name());
                if entry.file_type()?.is_dir() {
                    copy_tree(&path, &dest, files)?;
                } else {
                    let data = fs::read(&path)?;
                    fs::write(&dest, &data)?;
                    files.push(json!({"path":path,"archive_path":dest,"length":data.len(),"sha256":sha(&data)}));
                }
            }
            Ok(())
        }
        let Some(base) = std::env::var_os("SIGIS_CLI_SIGNING_RECORD_DIR") else {
            return;
        };
        let target = PathBuf::from(base).join(format!(
            "case-{}",
            self.dir.path().file_name().unwrap().to_str().unwrap()
        ));
        let mut files = Vec::new();
        let result = copy_tree(self.dir.path(), &target, &mut files).and_then(|()| {
            fs::write(
                target.join("case-receipt.json"),
                serde_json::to_vec_pretty(&json!({
                    "architecture":self.arch,"unwinding":std::thread::panicking(),"files":files,
                    "scope":"attempt bytes, including failed assertions; not a passing verdict"
                }))?,
            )
        });
        if let Err(error) = result {
            eprintln!("DETACHED_CASE_ARCHIVE_ERROR {error}");
            if !std::thread::panicking() {
                panic!("Could not preserve detached case: {error}");
            }
        }
    }
}

struct Tsa {
    child: Child,
    url: String,
}
impl Tsa {
    fn new(case: &Case) -> Self {
        let script = helper("tsa_server.py");
        common::record_file(&script, "detached_test_owned_TSA_source");
        let mut child = Command::new(python())
            .arg(script)
            .arg(case.arch)
            .arg(case.path("tsa-http"))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let ready: Value =
            serde_json::from_str(&line).expect("test-owned TSA must publish its listener");
        Self {
            child,
            url: format!("http://127.0.0.1:{}/tsa", ready["port"].as_u64().unwrap()),
        }
    }
}
impl Drop for Tsa {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Exact 12 parameters: claimed/TSA × RSA/ECDSA/Ed25519 × PEM/DER.
#[test]
fn test_cli_addsig_pemder_detached() {
    let mut failures = Vec::new();
    for timestamp in [false, true] {
        for arch in ["rsa", "ecdsa", "ed25519"] {
            for is_pem in [true, false] {
                let case = Case::new(arch, true);
                let tsa = timestamp.then(|| Tsa::new(&case));
                let mut argv = vec!["sign".into(), "addsig".into()];
                if let Some(tsa) = &tsa {
                    argv.extend(["--timestamp-url".into(), tsa.url.clone()]);
                }
                argv.extend([
                    if is_pem { "--detach-pem" } else { "--detach" }.into(),
                    "pemder".into(),
                    "--no-pass".into(),
                    "--pemder-setup".into(),
                    "test".into(),
                    "input.pdf".into(),
                    "output.sig.pem".into(),
                ]);
                let native = case.invoke(&argv);
                let native_tsa = if timestamp {
                    case.capture_tsa("native-complete")
                } else {
                    vec![]
                };
                let reference = case.reference(&argv, timestamp);
                assert_eq!(reference["code"], 0, "{reference}");
                assert!(reference["exception"].is_null(), "{reference}");
                assert_eq!(reference["bottom_line"], true);
                assert_eq!(reference["has_timestamp"], timestamp);
                if native.status.success() {
                    case.verify(timestamp, is_pem, &native_tsa);
                } else {
                    assert_eq!(
                        fs::read(case.path("output.sig.pem")).unwrap(),
                        b"detached-output-sentinel"
                    );
                    failures.push(format!(
                        "{arch}/timestamp={timestamp}/pem={is_pem}: {}",
                        text(&native)
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn test_cli_addsig_pemder_detached_no_field_arg() {
    let case = Case::new("rsa", false);
    let argv = vec![
        "sign".into(),
        "addsig".into(),
        "--detach-pem".into(),
        "--field".into(),
        "Sig1".into(),
        "pemder".into(),
        "--cert".into(),
        case.path("cert.pem").display().to_string(),
        "--key".into(),
        fixture("rsa", "key.pem").display().to_string(),
        "input.pdf".into(),
        "output.sig.pem".into(),
    ];
    let native = case.invoke(&argv);
    let reference = case.reference(&argv, false);
    let required = "--field is not compatible with --detach";
    assert_eq!(reference["code"], 1);
    assert!(
        reference["output"].as_str().unwrap().contains(required),
        "{reference}"
    );
    assert_eq!(native.status.code(), Some(1));
    assert!(text(&native).contains(required), "{}", text(&native));
    assert_eq!(
        fs::read(case.path("output.sig.pem")).unwrap(),
        b"detached-output-sentinel"
    );
}
