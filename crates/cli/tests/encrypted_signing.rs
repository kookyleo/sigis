//! Exact three encrypted-input signing originals from pyHanko 0.38.1 (MIT).
//! Four architecture positives and two single RSA rejections; no provider skip.
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;

use serde_json::{json, Value};
use sigis_pdf::{crypt::AuthStatus, PdfFile};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{cert::Cert, time::Moment};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn fixture(arch: &str, name: &str) -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "signing", arch, name])
}
fn driver() -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "encrypted-signing", "oracle.py"])
}
fn python() -> PathBuf {
    sigis_testdata::oracle::python().expect("the pinned oracle is required")
}
fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
fn sha(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
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
    fn new(arch: &'static str, pubkey: bool, chain: bool) -> Self {
        let case = Self {
            dir: tempfile::tempdir().unwrap(),
            arch,
            cert_name: if chain { "signer.crt" } else { "cert.pem" },
        };
        let input = if pubkey {
            sigis_testdata::path(&["lanes", "r3-c", "encrypted-signing", "pubkey-encrypted.pdf"])
        } else {
            sigis_testdata::path(&["lanes", "r3-c", "runtime", "minimal-aes256.pdf"])
        };
        common::record_file(&input, "original_encrypted_input_fixture");
        fs::copy(input, case.path("input.pdf")).unwrap();
        let cert =
            openssl::x509::X509::from_pem(&fs::read(fixture(arch, "cert.pem")).unwrap()).unwrap();
        fs::write(
            case.path(case.cert_name),
            if chain {
                cert.to_der().unwrap()
            } else {
                cert.to_pem().unwrap()
            },
        )
        .unwrap();
        let mut setup =
            json!({"key-file":fixture(arch,"key.pem"),"cert-file":case.path(case.cert_name)});
        if chain {
            setup["other-certs"] = json!([fixture(arch, "interm.pem"), fixture(arch, "root.pem")]);
        }
        fs::write(
            case.path("pyhanko.yml"),
            serde_yaml::to_string(&json!({"pemder-setups":{"test":setup}})).unwrap(),
        )
        .unwrap();
        // Supplemental safety assertion: denials must leave an existing output intact.
        fs::write(case.path("output.pdf"), b"encrypted-output-sentinel").unwrap();
        case
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn inputs(&self) -> Vec<PathBuf> {
        vec![
            self.path("input.pdf"),
            self.path("pyhanko.yml"),
            self.path(self.cert_name),
            fixture(self.arch, "key.pem"),
            fixture(self.arch, "root.pem"),
            fixture(self.arch, "interm.pem"),
        ]
    }
    fn argv(&self, output: &str) -> Vec<String> {
        [
            "sign",
            "addsig",
            "--field",
            "Sig1",
            "pemder",
            "--no-pass",
            "--pemder-setup",
            "test",
            "input.pdf",
            output,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    fn native(&self, password: &str) -> Output {
        let argv = self.argv("output.pdf");
        let before = signing_record::before(&self.inputs());
        let mut child = Command::new(common::cli())
            .args(&argv)
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
            .write_all(format!("{password}\n").as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        signing_record::process(
            "encrypted-native-cli",
            &argv,
            self.dir.path(),
            format!("{password}\n").as_bytes(),
            common::cli(),
            &output,
            &before,
            &[("native-output", &self.path("output.pdf"))],
        );
        output
    }
    fn reference(&self, password: &str) -> Value {
        let mut argv = vec![
            driver().display().to_string(),
            "--password".into(),
            password.into(),
            "cli".into(),
            self.arch.into(),
            "--".into(),
        ];
        argv.extend(self.argv("reference.pdf"));
        let before = signing_record::before(&self.inputs());
        let output = Command::new(python())
            .args(&argv)
            .current_dir(self.dir.path())
            .output()
            .unwrap();
        let artifacts = self.path("reference.pdf");
        let artifacts = if artifacts.exists() {
            vec![("reference-output", artifacts.as_path())]
        } else {
            vec![]
        };
        signing_record::process(
            "encrypted-reference-cli",
            &argv,
            self.dir.path(),
            b"",
            &python(),
            &output,
            &before,
            &artifacts,
        );
        assert!(output.status.success(), "{}", text(&output));
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["pyhanko"], "0.38.1");
        assert_eq!(result["certvalidator"], "0.33.0");
        assert_eq!(result["optimize"], 0);
        result
    }
    fn verify(&self) {
        let output = self.path("output.pdf");
        let root = fixture(self.arch, "root.pem");
        let revinfo = self.path("revinfo");
        let argv = vec![
            driver().display().to_string(),
            "--root".into(),
            root.display().to_string(),
            "--output".into(),
            output.display().to_string(),
            "--export-revinfo".into(),
            revinfo.display().to_string(),
            "verify".into(),
            self.arch.into(),
        ];
        let before = signing_record::before(&[output.clone(), root.clone(), driver()]);
        let verified = Command::new(python())
            .args(&argv)
            .current_dir(self.dir.path())
            .output()
            .unwrap();
        signing_record::process(
            "encrypted-same-output-oracle",
            &argv,
            self.dir.path(),
            b"",
            &python(),
            &verified,
            &before,
            &[("native-output", &output)],
        );
        assert!(verified.status.success(), "{}", text(&verified));
        let reference: Value = serde_json::from_slice(&verified.stdout).unwrap();
        for flag in ["bottom_line", "intact", "valid", "trusted"] {
            assert_eq!(reference[flag], true, "{reference}");
        }
        assert_eq!(reference["optimize"], 0);
        let data = fs::read(&output).unwrap();
        let pdf = PdfFile::parse(&data).unwrap();
        assert!(pdf.encrypted(), "encryption must be retained");
        assert_eq!(pdf.decrypt("wrong").unwrap().status, AuthStatus::Failed);
        assert_eq!(
            pdf.decrypt("ownersecret").unwrap().status,
            AuthStatus::Owner
        );
        let signatures = pdf.embedded_signatures().unwrap();
        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0].field_name, "Sig1");
        let metadata: Value =
            serde_json::from_slice(&fs::read(revinfo.join("metadata.json")).unwrap()).unwrap();
        assert_eq!(metadata["architecture"], self.arch);
        assert!(!metadata["crls"].as_array().unwrap().is_empty());
        assert_eq!(metadata["output_sha256"], sha(&data));
        let root_data = fs::read(&root).unwrap();
        assert_eq!(metadata["root_sha256"], sha(&root_data));
        let moment = Moment::parse_rfc3339(metadata["moment"].as_str().unwrap()).unwrap();
        let mut trusted = ValidationContext::builder()
            .moment(moment)
            .revocation_mode("hard-fail")
            .trust_root(Cert::from_pem_or_der(&root_data).unwrap());
        let mut untrusted = ValidationContext::builder()
            .moment(moment)
            .revocation_mode("hard-fail");
        let mut evidence_paths = vec![output.clone(), root.clone(), revinfo.join("metadata.json")];
        for row in metadata["crls"].as_array().unwrap() {
            let name = row["path"].as_str().unwrap();
            assert_eq!(Path::new(name).file_name().unwrap(), name);
            let path = revinfo.join(name);
            let crl = fs::read(&path).unwrap();
            assert_eq!(row["sha256"], sha(&crl));
            assert_eq!(row["length"], crl.len());
            evidence_paths.push(path);
            trusted = trusted.crl(crl.clone());
            untrusted = untrusted.crl(crl);
        }
        let status = sigis_pades::validate_pdf_signature(
            &pdf,
            &signatures[0],
            &trusted.build().unwrap(),
            Some(&sigis_pdf_diff::StandardDiffPolicy),
        )
        .unwrap();
        assert!(
            status.cms.signature.intact
                && status.cms.signature.valid
                && status.cms.signature.trusted()
                && status.bottom_line(),
            "{status:?}"
        );
        let denied = sigis_pades::validate_pdf_signature(
            &pdf,
            &signatures[0],
            &untrusted.build().unwrap(),
            Some(&sigis_pdf_diff::StandardDiffPolicy),
        );
        let no_root = match denied {
            Ok(status) => {
                assert!(
                    !status.cms.signature.trusted() && !status.bottom_line(),
                    "{status:?}"
                );
                json!({"result":"untrusted_status","trusted":status.cms.signature.trusted(),
                       "bottom_line":status.bottom_line()})
            }
            Err(error) => json!({"result":"validation_error","error":error.to_string()}),
        };
        let inputs = signing_record::before(&evidence_paths);
        let record = json!({"kind":"in-process public PDF validation, not a subprocess",
                            "architecture":self.arch,"input_output_evidence":inputs,"moment":metadata["moment"],
                            "intact":true,"valid":true,"trusted":true,"bottom_line":true,
                            "empty_roots_denied":true,"empty_roots_outcome":no_root});
        if let Some(base) = std::env::var_os("SIGIS_CLI_SIGNING_RECORD_DIR") {
            let target = PathBuf::from(base).join(format!("native-validation-{}", self.arch));
            fs::create_dir(&target).unwrap();
            for (index, path) in evidence_paths.iter().enumerate() {
                fs::copy(path, target.join(format!("evidence-{index}.bin"))).unwrap();
            }
            fs::write(
                target.join("receipt.json"),
                serde_json::to_vec_pretty(&record).unwrap(),
            )
            .unwrap();
        }
        eprintln!("ENCRYPTED_NATIVE_VALIDATION {record}");
    }
}

/// All four cert_chain/user_key architecture parameters and post_validate assertions.
#[test]
fn test_cli_addsig_pemder_encrypted_file() {
    let mut failures = Vec::new();
    for arch in ["rsa", "ecdsa", "ed25519", "ed448"] {
        let case = Case::new(arch, false, true);
        let native = case.native("ownersecret");
        let reference = case.reference("ownersecret");
        assert_eq!(reference["code"], 0, "{reference}");
        assert!(reference["exception"].is_null(), "{reference}");
        if native.status.success() {
            case.verify();
        } else {
            assert_eq!(
                fs::read(case.path("output.pdf")).unwrap(),
                b"encrypted-output-sentinel"
            );
            failures.push(format!("{arch}: {}", text(&native)));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn test_cli_addsig_no_pubkey_encryption() {
    let case = Case::new("rsa", true, false);
    let native = case.native("");
    let reference = case.reference("");
    let required = "Public-key document encryption is not supported";
    assert_eq!(reference["code"], 1);
    assert!(
        reference["output"].as_str().unwrap().contains(required),
        "{reference}"
    );
    assert_eq!(native.status.code(), Some(1));
    assert!(text(&native).contains(required), "{}", text(&native));
    assert_eq!(
        fs::read(case.path("output.pdf")).unwrap(),
        b"encrypted-output-sentinel"
    );
}
#[test]
fn test_cli_addsig_wrong_password() {
    let case = Case::new("rsa", false, false);
    let native = case.native("wrong");
    let reference = case.reference("wrong");
    assert_eq!(reference["code"], 1);
    assert!(
        reference["output"]
            .as_str()
            .unwrap()
            .contains("Invalid password"),
        "{reference}"
    );
    assert_eq!(native.status.code(), Some(1));
    assert!(
        text(&native).contains("Invalid password"),
        "{}",
        text(&native)
    );
    assert_eq!(
        fs::read(case.path("output.pdf")).unwrap(),
        b"encrypted-output-sentinel"
    );
}
