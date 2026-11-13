//! Shared test mechanics for only the three identity/getpass originals.
use crate::{common, signing_record};
use serde_json::{json, Value};
use sigis_pdf::rw_common::PdfHandlerExt;
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{cert::Cert, time::Moment};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::Duration,
};
#[allow(dead_code)] // Policy and field regression targets intentionally use only RSA.
pub const ARCHES: [&str; 4] = ["rsa", "ecdsa", "ed25519", "ed448"];
pub fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
fn sha(data: &[u8]) -> String {
    openssl::sha::sha256(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn python() -> PathBuf {
    sigis_testdata::oracle::python().expect("pinned reference required")
}
fn fixture(arch: &str, name: &str) -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "signing", arch, name])
}
fn helper(name: &str) -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "identity-getpass", name])
}
pub struct Case {
    pub dir: tempfile::TempDir,
    pub arch: &'static str,
    pub kind: &'static str,
}
#[allow(dead_code)] // Different exact targets intentionally use different mechanics.
impl Case {
    pub fn new(arch: &'static str, kind: &'static str) -> Self {
        let case = Self {
            dir: tempfile::tempdir().unwrap(),
            arch,
            kind,
        };
        fs::copy(
            sigis_testdata::path(&["lanes", "r3-c", "runtime", "minimal.pdf"]),
            case.path("input.pdf"),
        )
        .unwrap();
        for (source, target) in [
            ("key.pem", "signer.key.pem"),
            ("root.pem", "root.cert.pem"),
            ("interm.pem", "interm.cert.pem"),
            ("signer.p12", "signer.p12"),
        ] {
            fs::copy(fixture(arch, source), case.path(target)).unwrap();
        }
        let cert =
            openssl::x509::X509::from_pem(&fs::read(fixture(arch, "cert.pem")).unwrap()).unwrap();
        fs::write(case.path("signer.crt"), cert.to_der().unwrap()).unwrap();
        if kind != "getpass" {
            fs::write(
                case.path("pyhanko.yml"),
                serde_yaml::to_string(&case.config_value()).unwrap(),
            )
            .unwrap();
        }
        fs::write(case.path("output.pdf"), b"identity-getpass-output-sentinel").unwrap();
        case
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    pub fn config_value(&self) -> Value {
        json!({"identities":{"test":{"plugin":"pemder","parameters":{"key":self.path("signer.key.pem"),"cert":self.path("signer.crt"),"chain":[self.path("interm.cert.pem"),self.path("root.cert.pem")],"no-pass":true}}}})
    }
    pub fn args(&self) -> Vec<String> {
        if self.kind == "getpass" {
            vec![
                "sign".into(),
                "addsig".into(),
                "--field".into(),
                "1/0,0,100,100/Sig1".into(),
                "pkcs12".into(),
                "input.pdf".into(),
                "output.pdf".into(),
                "signer.p12".into(),
            ]
        } else {
            vec![
                "sign".into(),
                "addsig".into(),
                "--field".into(),
                "Sig1".into(),
                "identity".into(),
                "test".into(),
                self.path("input.pdf").display().to_string(),
                self.path("output.pdf").display().to_string(),
            ]
        }
    }
    pub fn inputs(&self) -> Vec<PathBuf> {
        let mut v = [
            "input.pdf",
            "signer.key.pem",
            "signer.crt",
            "root.cert.pem",
            "interm.cert.pem",
            "signer.p12",
        ]
        .iter()
        .map(|n| self.path(n))
        .collect::<Vec<_>>();
        if self.path("pyhanko.yml").exists() {
            v.push(self.path("pyhanko.yml"));
        }
        v
    }
    pub fn native(&self) -> Value {
        let args = self.args();
        let mut paths = self.inputs();
        paths.push(helper("pty_driver.py"));
        let before = signing_record::before(&paths);
        if self.kind == "getpass" {
            let argv = vec![
                helper("pty_driver.py").display().to_string(),
                "--bin".into(),
                common::cli().display().to_string(),
                "--child-receipt".into(),
                self.path("pty-child.json").display().to_string(),
                "--".into(),
            ];
            let argv = argv.into_iter().chain(args).collect::<Vec<_>>();
            let output = Command::new(python())
                .args(&argv)
                .current_dir(self.dir.path())
                .output()
                .unwrap();
            signing_record::process(
                "native-terminal-driver",
                &argv,
                self.dir.path(),
                b"",
                &python(),
                &output,
                &before,
                &[
                    ("native-PDF-or-sentinel", &self.path("output.pdf")),
                    ("actual-PTY-child", &self.path("pty-child.json")),
                ],
            );
            assert!(output.status.success(), "{}", text(&output));
            let r: Value = serde_json::from_slice(&output.stdout).unwrap();
            if r["exit_code"] == 0 {
                assert_eq!(r["password_sent_after_echo_off"], true);
                assert_eq!(r["secret_present_in_transcript"], false);
                assert_eq!(r["child"]["stdin_isatty"], true);
                assert_eq!(r["child"]["stdout_isatty"], true);
                assert_eq!(r["child"]["stderr_isatty"], true);
                assert_eq!(
                    r["observed_executable"]["sha256"],
                    sha(&fs::read(common::cli()).unwrap())
                );
            }
            r
        } else {
            let out = Command::new(common::cli())
                .args(&args)
                .current_dir(self.dir.path())
                .stdin(Stdio::null())
                .output()
                .unwrap();
            signing_record::process(
                "native-identity-CLI",
                &args,
                self.dir.path(),
                b"",
                common::cli(),
                &out,
                &before,
                &[("native-PDF-or-sentinel", &self.path("output.pdf"))],
            );
            json!({"exit_code":out.status.code(),"stdout":String::from_utf8_lossy(&out.stdout),"stderr":String::from_utf8_lossy(&out.stderr)})
        }
    }
    pub fn reference(&self) -> Value {
        let cwd = self.path("reference");
        fs::create_dir(&cwd).unwrap();
        for name in [
            "input.pdf",
            "signer.key.pem",
            "signer.crt",
            "root.cert.pem",
            "interm.cert.pem",
            "signer.p12",
        ] {
            fs::copy(self.path(name), cwd.join(name)).unwrap();
        }
        let argv = vec![
            helper("oracle.py").display().to_string(),
            "--mode".into(),
            "original".into(),
            "--kind".into(),
            self.kind.into(),
            "--architecture".into(),
            self.arch.into(),
        ];
        let mut inputs = [
            "input.pdf",
            "signer.key.pem",
            "signer.crt",
            "root.cert.pem",
            "interm.cert.pem",
            "signer.p12",
        ]
        .iter()
        .map(|name| cwd.join(name))
        .collect::<Vec<_>>();
        inputs.push(helper("oracle.py"));
        let before = signing_record::before(&inputs);
        let output = Command::new(python())
            .args(&argv)
            .current_dir(&cwd)
            .output()
            .unwrap();
        let artifacts = if cwd.join("output.pdf").exists() {
            vec![("fresh-reference-PDF", cwd.join("output.pdf"))]
        } else {
            vec![]
        };
        let artifacts = artifacts
            .iter()
            .map(|(s, p)| (*s, p.as_path()))
            .collect::<Vec<_>>();
        signing_record::process(
            "reference-original-body",
            &argv,
            &cwd,
            b"",
            &python(),
            &output,
            &before,
            &artifacts,
        );
        assert!(output.status.success(), "{}", text(&output));
        let r: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(r["optimize"], 0);
        assert_eq!(r["original_function_completed"], true);
        assert_eq!(r["original_teardown_completed"], true);
        assert!(r["exception"].is_null());
        r
    }
    pub fn verify(&self) {
        let rev = self.path("revinfo");
        let file = self.path("output.pdf");
        let args = vec![
            helper("oracle.py").display().to_string(),
            "--mode".into(),
            "verify".into(),
            "--kind".into(),
            self.kind.into(),
            "--architecture".into(),
            self.arch.into(),
            "--file".into(),
            file.display().to_string(),
            "--export-revinfo".into(),
            rev.display().to_string(),
        ];
        let mut inputs = self.inputs();
        inputs.push(file.clone());
        inputs.push(helper("oracle.py"));
        let before = signing_record::before(&inputs);
        let output = Command::new(python())
            .args(&args)
            .current_dir(self.dir.path())
            .output()
            .unwrap();
        signing_record::process(
            "same-native-PDF-reference",
            &args,
            self.dir.path(),
            b"",
            &python(),
            &output,
            &before,
            &[("native-PDF", &file)],
        );
        assert!(output.status.success(), "{}", text(&output));
        let r: Value = serde_json::from_slice(&output.stdout).unwrap();
        for flag in ["bottom_line", "intact", "valid", "trusted"] {
            assert_eq!(r[flag], true, "{r}");
        }
        let meta: Value =
            serde_json::from_slice(&fs::read(rev.join("metadata.json")).unwrap()).unwrap();
        let moment = Moment::parse_rfc3339(meta["moment"].as_str().unwrap()).unwrap();
        let root = Cert::from_pem_or_der(&fs::read(self.path("root.cert.pem")).unwrap()).unwrap();
        let mut trusted = ValidationContext::builder()
            .moment(moment)
            .point_in_time_validation(false)
            .time_tolerance(Duration::from_secs(1))
            .revocation_mode("soft-fail")
            .trust_root(root);
        let mut denied = ValidationContext::builder()
            .moment(moment)
            .point_in_time_validation(false)
            .time_tolerance(Duration::from_secs(1))
            .revocation_mode("soft-fail");
        for row in meta["crls"].as_array().unwrap() {
            let p = Path::new(row["path"].as_str().unwrap());
            assert!(p.starts_with(&rev));
            let data = fs::read(p).unwrap();
            assert_eq!(row["sha256"], sha(&data));
            trusted = trusted.crl(data.clone());
            denied = denied.crl(data);
        }
        let pdf = sigis_pdf::PdfFile::parse(&fs::read(&file).unwrap()).unwrap();
        let signatures = pdf.embedded_signatures().unwrap();
        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0].field_name, "Sig1");
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
        let no_roots = sigis_pades::validate_pdf_signature(
            &pdf,
            &signatures[0],
            &denied.build().unwrap(),
            Some(&sigis_pdf_diff::StandardDiffPolicy),
        );
        let denial = match no_roots {
            Ok(s) => {
                assert!(!s.cms.signature.trusted() && !s.bottom_line(), "{s:?}");
                json!({"trusted":s.cms.signature.trusted(),"bottom_line":s.bottom_line()})
            }
            Err(e) => json!({"error":e.to_string()}),
        };
        if self.kind == "getpass" {
            let fields =
                sigis_pdf::signatures::enumerate_sig_fields(&pdf, Some(true), Some("Sig1"))
                    .unwrap();
            assert_eq!(fields.len(), 1);
            let widget = pdf.get_object_at(fields[0].field_ref, None).unwrap();
            let field = widget.as_dict().unwrap();
            let annotation = if let Ok(kids) = field.get(b"Kids") {
                let kids = pdf.resolve(kids).unwrap();
                pdf.resolve(&kids.as_array().unwrap()[0]).unwrap()
            } else {
                widget
            };
            let dict = annotation.as_dict().unwrap();
            let rect = dict.get(b"Rect").unwrap().as_array().unwrap();
            let number = |n: &lopdf::Object| match n {
                lopdf::Object::Integer(n) => *n as f64,
                lopdf::Object::Real(n) => *n as f64,
                _ => panic!("rectangle must be numeric"),
            };
            assert_eq!(
                rect.iter().map(number).collect::<Vec<_>>(),
                [0., 0., 100., 100.]
            );
            assert!(dict.has(b"AP"));
        }
        fs::write(self.path("native-validation.json"),serde_json::to_vec_pretty(&json!({"kind":"in-process public PDF validation","architecture":self.arch,"source_case":self.kind,"moment":meta["moment"],"native_output_sha256":sha(&fs::read(file).unwrap()),"bottom_line":true,"empty_roots_outcome":denial})).unwrap()).unwrap();
    }
    pub fn record_programmatic_begin(&self, cfg: &sigis_cli::config::CliConfig) {
        common::record_test_executable();
        let inputs = signing_record::before(&self.inputs());
        let before = json!({"kind":"in-process identity before dispatch","raw_config":cfg.raw_config,"effective_validation_contexts":cfg.validation_contexts,"inputs":inputs});
        fs::write(
            self.path("programmatic-before.json"),
            serde_json::to_vec_pretty(&before).unwrap(),
        )
        .unwrap();
    }
    pub fn record_programmatic(
        &self,
        result: &Result<String, String>,
        cfg: &sigis_cli::config::CliConfig,
    ) {
        let before: Value =
            serde_json::from_slice(&fs::read(self.path("programmatic-before.json")).unwrap())
                .unwrap();
        assert_eq!(before["raw_config"], cfg.raw_config);
        assert_eq!(
            before["effective_validation_contexts"],
            serde_json::to_value(&cfg.validation_contexts).unwrap()
        );
        for row in before["inputs"].as_array().unwrap() {
            let data = fs::read(row["path"].as_str().unwrap()).unwrap();
            assert_eq!(row["sha256"], sha(&data));
            assert_eq!(row["length"], data.len());
        }
        fs::write(self.path("programmatic-result.json"),serde_json::to_vec_pretty(&json!({"kind":"in-process identity callback, not CLI subprocess","result":result,"before":before})).unwrap()).unwrap();
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        fn copy(source: &Path, target: &Path, rows: &mut Vec<Value>) -> std::io::Result<()> {
            fs::create_dir(target)?;
            let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|e| e.path());
            for e in entries {
                let path = e.path();
                let dest = target.join(e.file_name());
                if e.file_type()?.is_dir() {
                    copy(&path, &dest, rows)?;
                } else {
                    let data = fs::read(&path)?;
                    fs::write(&dest, &data)?;
                    rows.push(json!({"path":path,"archive_path":dest,"length":data.len(),"sha256":sha(&data)}));
                }
            }
            Ok(())
        }
        let Some(base) = std::env::var_os("SIGIS_CLI_SIGNING_RECORD_DIR") else {
            return;
        };
        if let Err(error) = fs::create_dir_all(&base) {
            eprintln!("IDENTITY_CASE_ARCHIVE_ERROR {error}");
            if !std::thread::panicking() {
                panic!("Cannot create case archive base: {error}");
            }
            return;
        }
        let target = PathBuf::from(base).join(format!(
            "case-{}",
            self.dir.path().file_name().unwrap().to_str().unwrap()
        ));
        let mut rows = Vec::new();
        let result=copy(self.dir.path(),&target,&mut rows).and_then(|()|fs::write(target.join("case-receipt.json"),serde_json::to_vec_pretty(&json!({"architecture":self.arch,"case_kind":self.kind,"unwinding":std::thread::panicking(),"files":rows}))?));
        if let Err(e) = result {
            eprintln!("IDENTITY_CASE_ARCHIVE_ERROR {e}");
            if !std::thread::panicking() {
                panic!("Could not archive identity case: {e}");
            }
        }
    }
}
