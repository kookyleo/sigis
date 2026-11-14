//! Evidence mechanics scoped to the two default-appearance originals.
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
pub const ARCHES: [&str; 4] = ["rsa", "ecdsa", "ed25519", "ed448"];
pub const SENTINEL: &[u8] = b"appearance-default-output-sentinel";
pub fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
pub fn sha(data: &[u8]) -> String {
    openssl::sha::sha256(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn python() -> PathBuf {
    sigis_testdata::oracle::python().expect("Pinned reference interpreter is mandatory")
}
fn helper() -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "appearance-default", "oracle.py"])
}
fn fixture(arch: &str, name: &str) -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "signing", arch, name])
}
pub struct Case {
    pub dir: tempfile::TempDir,
    pub arch: &'static str,
    pub kind: &'static str,
}
impl Case {
    pub fn new(arch: &'static str, kind: &'static str) -> Self {
        assert!(ARCHES.contains(&arch));
        assert!(kind == "visible" || kind == "conflict" || kind == "supplemental");
        if kind == "conflict" {
            assert_eq!(arch, "rsa");
        }
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
            ("cert.pem", "cert.pem"),
        ] {
            fs::copy(fixture(arch, source), case.path(target)).unwrap();
        }
        let cert =
            openssl::x509::X509::from_pem(&fs::read(case.path("cert.pem")).unwrap()).unwrap();
        fs::write(case.path("signer.crt"), cert.to_der().unwrap()).unwrap();
        fs::write(case.path("output.pdf"), SENTINEL).unwrap();
        case
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    pub fn args(&self) -> Vec<String> {
        let mut args: Vec<String> = ["sign", "addsig", "--field", "1/0,0,100,100/Sig1"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        if self.kind == "conflict" {
            args.push("--existing-only".into());
        }
        args.extend(
            ["pemder", "--no-pass", "--cert"]
                .into_iter()
                .map(str::to_owned),
        );
        args.push(
            if self.kind == "conflict" {
                "cert.pem"
            } else {
                "signer.crt"
            }
            .into(),
        );
        if self.kind != "conflict" {
            args.extend(["--chain".into(), "interm.cert.pem".into()]);
        }
        args.extend(
            ["--key", "signer.key.pem", "input.pdf", "output.pdf"]
                .into_iter()
                .map(str::to_owned),
        );
        args
    }
    pub fn inputs(&self) -> Vec<PathBuf> {
        [
            "input.pdf",
            "signer.key.pem",
            "signer.crt",
            "cert.pem",
            "root.cert.pem",
            "interm.cert.pem",
        ]
        .into_iter()
        .map(|n| self.path(n))
        .collect()
    }
    pub fn native(&self) -> Output {
        let args = self.args();
        let before = signing_record::before(&self.inputs());
        let output = Command::new(common::cli())
            .args(&args)
            .current_dir(self.dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        // Freeze all native evidence before starting any reference process.
        fs::write(self.path("native-stdout.bin"), &output.stdout).unwrap();
        fs::write(self.path("native-stderr.bin"), &output.stderr).unwrap();
        fs::copy(
            self.path("output.pdf"),
            self.path("native-output-frozen.pdf"),
        )
        .unwrap();
        fs::write(self.path("native-attempt.json"), serde_json::to_vec_pretty(&json!({"kind":"native attempt; not a passing original","exit_code":output.status.code(),"argv":args,"output_sha256":sha(&fs::read(self.path("output.pdf")).unwrap())})).unwrap()).unwrap();
        signing_record::process(
            "native-default-appearance-CLI",
            &args,
            self.dir.path(),
            b"",
            common::cli(),
            &output,
            &before,
            &[
                (
                    "native-PDF-or-sentinel",
                    &self.path("native-output-frozen.pdf"),
                ),
                ("native-attempt", &self.path("native-attempt.json")),
            ],
        );
        output
    }
    pub fn oracle(
        &self,
        mode: &str,
        cwd: &Path,
        file: Option<&Path>,
        revinfo: Option<&Path>,
    ) -> Value {
        fs::create_dir_all(cwd).unwrap();
        let mut args = vec![
            helper().display().to_string(),
            "--mode".into(),
            mode.into(),
            "--kind".into(),
            self.kind.into(),
            "--architecture".into(),
            self.arch.into(),
            "--native-fixture-directory".into(),
            self.dir.path().display().to_string(),
        ];
        let mut inputs = self.inputs();
        inputs.push(helper());
        if let Some(file) = file {
            args.extend(["--file".into(), file.display().to_string()]);
            inputs.push(file.to_path_buf());
        }
        if let Some(revinfo) = revinfo {
            args.extend(["--export-revinfo".into(), revinfo.display().to_string()]);
        }
        // Original source and fixture definitions are pinned inputs too.
        for name in ["test_cli_signing.py", "conftest.py"] {
            inputs.push(
                PathBuf::from("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests").join(name),
            );
        }
        let before = signing_record::before(&inputs);
        let output = Command::new(python())
            .args(&args)
            .env("PYTHONOPTIMIZE", "0")
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let prefix = format!("oracle-{mode}");
        fs::write(cwd.join(format!("{prefix}-stdout.bin")), &output.stdout).unwrap();
        fs::write(cwd.join(format!("{prefix}-stderr.bin")), &output.stderr).unwrap();
        let artifact = if mode == "original" {
            cwd.join("output.pdf")
        } else {
            file.map(Path::to_path_buf)
                .unwrap_or_else(|| self.path("output.pdf"))
        };
        let mut artifacts = Vec::new();
        if artifact.exists() {
            artifacts.push(("actual-PDF-or-sentinel", artifact.as_path()));
        }
        signing_record::process(
            &format!("reference-{mode}-default-appearance"),
            &args,
            cwd,
            b"",
            &python(),
            &output,
            &before,
            &artifacts,
        );
        assert!(output.status.success(), "{}", text(&output));
        let record: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record["optimize"], 0);
        assert_eq!(record["PYTHONOPTIMIZE"], "0");
        assert_eq!(record["pyhanko"], "0.38.1");
        assert_eq!(record["certvalidator"], "0.33.0");
        fs::write(
            cwd.join(format!("{prefix}-receipt.json")),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        record
    }
    pub fn reference(&self) -> Value {
        let cwd = self.path("reference");
        let record = self.oracle("original", &cwd, None, None);
        assert_eq!(record["original_function_completed"], true);
        assert!(record["exception"].is_null());
        if self.kind == "visible" {
            assert_eq!(record["original_teardown_completed"], true);
            assert_eq!(record["original_input_strict"], true);
            assert_eq!(record["calls"][0]["code"], 0);
        } else {
            assert_eq!(record["original_teardown_applicable"], false);
            assert_eq!(record["calls"][0]["code"], 1);
            assert!(record["calls"][0]["output"]
                .as_str()
                .unwrap()
                .contains("incompatible with --existing-only"));
        }
        record
    }
    fn read_revinfo(&self, directory: &Path) -> Value {
        let metadata = directory.join("metadata.json");
        signing_record::before(std::slice::from_ref(&metadata));
        let record: Value = serde_json::from_slice(&fs::read(metadata).unwrap()).unwrap();
        assert_eq!(record["architecture"], self.arch);
        assert!(record["moment"]
            .as_str()
            .unwrap()
            .starts_with("2020-08-01T00:00:00"));
        for row in record["crls"].as_array().unwrap() {
            let path = Path::new(row["path"].as_str().unwrap());
            assert!(path.starts_with(directory));
            signing_record::before(&[path.to_path_buf()]);
            let data = fs::read(path).unwrap();
            assert_eq!(row["sha256"], sha(&data));
            assert_eq!(row["length"], data.len());
        }
        assert!(!record["crls"].as_array().unwrap().is_empty());
        record
    }
    pub fn verify(&self) {
        let file = self.path("output.pdf");
        let bytes = fs::read(&file).unwrap();
        assert_ne!(bytes, SENTINEL);
        let frozen = self.path("verified-native-output.pdf");
        fs::write(&frozen, &bytes).unwrap();
        let revinfo = self.path("revinfo");
        let record = self.oracle(
            "verify",
            &self.path("verify-reference"),
            Some(&frozen),
            Some(&revinfo),
        );
        for flag in ["bottom_line", "intact", "valid", "trusted"] {
            assert_eq!(record[flag], true, "{record}");
        }
        assert_eq!(record["input_before_use"]["sha256"], sha(&bytes));
        assert_eq!(fs::read(&file).unwrap(), bytes);
        let metadata = self.read_revinfo(&revinfo);
        let moment = Moment::parse_rfc3339(metadata["moment"].as_str().unwrap()).unwrap();
        let root_path = self.path("root.cert.pem");
        signing_record::before(std::slice::from_ref(&root_path));
        let root_bytes = fs::read(&root_path).unwrap();
        let root = Cert::from_pem_or_der(&root_bytes).unwrap();
        let builder = || {
            ValidationContext::builder()
                .moment(moment)
                .point_in_time_validation(false)
                .time_tolerance(Duration::from_secs(1))
                .revocation_mode("soft-fail")
        };
        let mut trusted = builder().trust_root(root);
        let mut denied = builder();
        for row in metadata["crls"].as_array().unwrap() {
            let data = fs::read(row["path"].as_str().unwrap()).unwrap();
            trusted = trusted.crl(data.clone());
            denied = denied.crl(data);
        }
        let pdf = sigis_pdf::PdfFile::parse(&bytes).unwrap();
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
        let denial = match sigis_pades::validate_pdf_signature(
            &pdf,
            &signatures[0],
            &denied.build().unwrap(),
            Some(&sigis_pdf_diff::StandardDiffPolicy),
        ) {
            Ok(status) => {
                assert!(
                    !status.cms.signature.trusted() && !status.bottom_line(),
                    "{status:?}"
                );
                json!({"trusted":status.cms.signature.trusted(), "bottom_line":status.bottom_line()})
            }
            Err(error) => json!({"error":error.to_string()}),
        };
        // Supplemental structure assertions do not replace cryptographic trust.
        let fields =
            sigis_pdf::signatures::enumerate_sig_fields(&pdf, Some(true), Some("Sig1")).unwrap();
        assert_eq!(fields.len(), 1);
        let field_object = pdf.get_object_at(fields[0].field_ref, None).unwrap();
        let field = field_object.as_dict().unwrap();
        let widget = if let Ok(kids) = field.get(b"Kids") {
            let kids = pdf.resolve(kids).unwrap();
            let kids = kids.as_array().unwrap();
            assert_eq!(kids.len(), 1);
            pdf.resolve(&kids[0]).unwrap()
        } else {
            field_object
        };
        let widget = widget.as_dict().unwrap();
        let rect = pdf.resolve(widget.get(b"Rect").unwrap()).unwrap();
        let coords = rect
            .as_array()
            .unwrap()
            .iter()
            .map(|value| match value {
                lopdf::Object::Integer(value) => *value as f64,
                lopdf::Object::Real(value) => *value as f64,
                _ => panic!("Widget rectangle must be numeric"),
            })
            .collect::<Vec<_>>();
        assert_eq!(coords, [0., 0., 100., 100.]);
        let appearance = pdf.resolve(widget.get(b"AP").unwrap()).unwrap();
        let normal = pdf
            .resolve(appearance.as_dict().unwrap().get(b"N").unwrap())
            .unwrap();
        let normal = normal.as_stream().unwrap();
        assert!(!normal.content.is_empty());
        assert_eq!(
            normal.dict.get(b"Subtype").unwrap().as_name().unwrap(),
            b"Form"
        );
        fs::write(self.path("native-validation.json"), serde_json::to_vec_pretty(&json!({"kind":"public native PDF validation of exact same bytes","architecture":self.arch,"native_output_sha256":sha(&bytes),"trust_anchor_pem_sha256":sha(&root_bytes),"moment":metadata["moment"],"time_tolerance_seconds":1,"revocation_mode":"soft-fail","point_in_time_validation":false,"bottom_line":true,"empty_roots_outcome":denial,"supplemental_rect":coords,"supplemental_normal_appearance_length":normal.content.len()})).unwrap()).unwrap();
    }
    pub fn revinfo(&self, name: &str) -> Value {
        let directory = self.path(name);
        self.oracle(
            "revinfo",
            &self.path("presign-reference"),
            None,
            Some(&directory),
        );
        self.read_revinfo(&directory)
    }
    pub fn programmatic(
        &self,
        cfg: &sigis_cli::config::CliConfig,
        runtime: &sigis_cli::runtime::ValidationRuntime,
        contextual: bool,
    ) -> Result<String, String> {
        let mut args = self.args()[2..].to_vec();
        for arg in &mut args {
            if [
                "signer.crt",
                "cert.pem",
                "interm.cert.pem",
                "signer.key.pem",
                "input.pdf",
                "output.pdf",
            ]
            .contains(&arg.as_str())
            {
                *arg = self.path(arg).display().to_string();
            }
        }
        if contextual {
            args.splice(0..0, ["--validation-context".into(), "default".into()]);
        }
        common::record_test_executable();
        let before = signing_record::before(&self.inputs());
        let config = || {
            json!({
                "complete_fixture_config_debug":format!("{cfg:?}"),
                "raw_config":cfg.raw_config,
                "effective_validation_contexts":cfg.validation_contexts,
                "effective_default_validation_context":cfg.default_validation_context,
                "effective_stamp_styles":cfg.stamp_styles,
                "effective_default_stamp_style":cfg.default_stamp_style,
                "effective_time_tolerance":cfg.time_tolerance,
                "effective_retroactive_revinfo":cfg.retroactive_revinfo,
            })
        };
        let config_before = config();
        fs::write(self.path("programmatic-before.json"), serde_json::to_vec_pretty(&json!({
            "kind":"same public visible PEM callback as canonical CLI; supplemental only",
            "argv":args,"config":config_before,"inputs":before,"runtime_now":runtime.now.to_string(),
        })).unwrap()).unwrap();
        let result = sigis_cli::signature_appearance::run_with_runtime(&args, Some(cfg), runtime);
        assert_eq!(config_before, config());
        for row in &before {
            let bytes = fs::read(row["path"].as_str().unwrap()).unwrap();
            assert_eq!(row["sha256"], sha(&bytes));
            assert_eq!(row["length"], bytes.len());
        }
        fs::write(
            self.path("programmatic-result.json"),
            serde_json::to_vec_pretty(&json!({
                "kind":"supplemental public visible PEM callback; zero original-function credit",
                "result":result,"output_sha256":sha(&fs::read(self.path("output.pdf")).unwrap()),
            }))
            .unwrap(),
        )
        .unwrap();
        result
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        fn copy(source: &Path, target: &Path, rows: &mut Vec<Value>) -> std::io::Result<()> {
            fs::create_dir_all(target)?;
            let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|entry| entry.path());
            for entry in entries {
                let path = entry.path();
                let dest = target.join(entry.file_name());
                if entry.file_type()?.is_dir() {
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
        let target = PathBuf::from(base).join(format!(
            "case-{}",
            self.dir.path().file_name().unwrap().to_str().unwrap()
        ));
        let mut rows = Vec::new();
        let result = copy(self.dir.path(), &target, &mut rows).and_then(|()| fs::write(target.join("case-receipt.json"), serde_json::to_vec_pretty(&json!({"architecture":self.arch,"case_kind":self.kind,"unwinding":std::thread::panicking(),"files":rows}))?));
        if let Err(error) = result {
            eprintln!("APPEARANCE_CASE_ARCHIVE_ERROR {error}");
            if !std::thread::panicking() {
                panic!("Cannot archive appearance case: {error}");
            }
        }
    }
}
