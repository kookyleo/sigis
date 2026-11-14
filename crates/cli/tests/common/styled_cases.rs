//! Named-style evidence, reusing the accepted fixture and full trust checker.
use crate::{appearance_cases::Case as BaseCase, common, signing_record};
use serde_json::{json, Value};
use sigis_pdf::rw_common::PdfHandlerExt;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
pub const ARCHES: [&str; 4] = ["rsa", "ecdsa", "ed25519", "ed448"];
pub const URL: &str = "https://example.com";
pub fn text(output: &Output) -> String {
    crate::appearance_cases::text(output)
}
pub fn sha(data: &[u8]) -> String {
    crate::appearance_cases::sha(data)
}
fn helper() -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "styled-three", "oracle.py"])
}
pub struct Case {
    pub base: BaseCase,
    pub kind: &'static str,
}
impl Case {
    pub fn new(arch: &'static str, kind: &'static str) -> Self {
        assert!(["text", "qr", "missing-url"].contains(&kind));
        assert!(kind != "missing-url" || arch == "ed25519");
        let case = Self {
            base: BaseCase::new(arch, "visible"),
            kind,
        };
        fs::write(
            case.path("pyhanko.yml"),
            serde_yaml::to_string(&case.config()).unwrap(),
        )
        .unwrap();
        case
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.base.path(name)
    }
    pub fn config(&self) -> Value {
        json!({"stamp-styles":{"test":{"type":if self.kind=="text" {"text"} else {"qr"},"background":"__stamp__"}}})
    }
    pub fn args(&self) -> Vec<String> {
        let mut args = vec!["sign".into(), "addsig".into()];
        if self.kind == "qr" {
            args.extend(["--stamp-url".into(), URL.into()]);
        }
        args.extend(["--style-name".into(), "test".into()]);
        args.extend(self.base.args().into_iter().skip(2));
        args
    }
    pub fn inputs(&self) -> Vec<PathBuf> {
        let mut p = self.base.inputs();
        p.push(self.path("pyhanko.yml"));
        p
    }
    pub fn native(&self) -> Output {
        let args = self.args();
        let before = signing_record::before(&self.inputs());
        let output = Command::new(common::cli())
            .args(&args)
            .current_dir(self.base.dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let frozen = self.path("native-styled-frozen.pdf");
        fs::copy(self.path("output.pdf"), &frozen).unwrap();
        let attempt = self.path("native-styled-attempt.json");
        fs::write(&attempt,serde_json::to_vec_pretty(&json!({"kind":self.kind,"architecture":self.base.arch,"argv":args,"exit_code":output.status.code(),"output_sha256":sha(&fs::read(&frozen).unwrap())})).unwrap()).unwrap();
        signing_record::process(
            "native-named-style-CLI",
            &args,
            self.base.dir.path(),
            b"",
            common::cli(),
            &output,
            &before,
            &[
                ("actual-native-PDF-or-sentinel", &frozen),
                ("native-attempt", &attempt),
            ],
        );
        output
    }
    pub fn oracle(&self, mode: &str, file: Option<&Path>) -> Value {
        let python = sigis_testdata::oracle::python().expect("Pinned reference is mandatory");
        let cwd = self.path(&format!("styled-{mode}-reference"));
        fs::create_dir_all(&cwd).unwrap();
        let mut args = vec![
            helper().display().to_string(),
            mode.into(),
            self.kind.into(),
            self.base.arch.into(),
            "--native-fixtures".into(),
            self.base.dir.path().display().to_string(),
        ];
        let mut inputs = self.inputs();
        inputs.push(helper());
        for name in ["test_cli_signing.py", "conftest.py"] {
            inputs.push(
                PathBuf::from("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests").join(name),
            );
        }
        if let Some(file) = file {
            args.extend(["--file".into(), file.display().to_string()]);
            inputs.push(file.to_path_buf());
        }
        let before = signing_record::before(&inputs);
        let result = Command::new(&python)
            .args(&args)
            .env("PYTHONOPTIMIZE", "0")
            .current_dir(&cwd)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let report = cwd.join("reference.json");
        fs::write(&report, &result.stdout).unwrap();
        let originals: Vec<_> = cwd
            .join("original-artifacts")
            .read_dir()
            .map(|entries| entries.map(|e| e.unwrap().path()).collect())
            .unwrap_or_default();
        let mut files = vec![("fresh-reference-json", report.as_path())];
        for f in &originals {
            files.push(("fresh-original-fixture-or-output", f.as_path()));
        }
        if let Some(f) = file {
            files.push(("same-native-output", f));
        }
        signing_record::process(
            &format!("styled-reference-{mode}"),
            &args,
            &cwd,
            b"",
            &python,
            &result,
            &before,
            &files,
        );
        assert!(
            result.status.success(),
            "{mode}/{}: {}",
            self.kind,
            text(&result)
        );
        let record: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(record["success"], true);
        record
    }
    pub fn reference(&self) {
        let r = self.oracle("original", None);
        assert_eq!(r["original_body_completed"], true);
        assert_eq!(r["full_post_validate_teardown_completed"], true);
        if self.kind == "missing-url" {
            assert_eq!(r["original_output_existed"], false);
            assert_eq!(r["calls"][0]["exit_code"], 1);
            assert!(r["calls"][0]["output"]
                .as_str()
                .unwrap()
                .contains("QR stamp styles require the --stamp-url option"));
        } else {
            assert_eq!(r["original_output_existed"], true);
            assert_eq!(r["calls"][0]["exit_code"], 0);
            assert!(r["calls"][0]["exception"].is_null());
        }
    }
    pub fn verify(&self) {
        // This executes the accepted full same-byte reference/native PDF checks,
        // explicit fixture-root validation and same-evidence empty-root refusal.
        self.base.verify();
        let file = self.path("native-styled-frozen.pdf");
        assert_eq!(
            fs::read(&file).unwrap(),
            fs::read(self.path("output.pdf")).unwrap()
        );
        let bytes = fs::read(&file).unwrap();
        let pdf = sigis_pdf::PdfFile::parse(&bytes).unwrap();
        let sigs = pdf.embedded_signatures().unwrap();
        assert_eq!(sigs.len(), 1);
        let coverage = sigis_pades::signature_coverage(&pdf, &sigs[0]).unwrap();
        assert_eq!(coverage, sigis_pades::SignatureCoverageLevel::EntireFile);
        let fields =
            sigis_pdf::signatures::enumerate_sig_fields(&pdf, Some(true), Some("Sig1")).unwrap();
        let field = pdf.get_object_at(fields[0].field_ref, None).unwrap();
        let ap = pdf
            .resolve(field.as_dict().unwrap().get(b"AP").unwrap())
            .unwrap();
        let normal = pdf
            .resolve(ap.as_dict().unwrap().get(b"N").unwrap())
            .unwrap();
        let data = pdf.stream_data(normal.as_stream().unwrap()).unwrap();
        let operations = lopdf::content::Content::decode(&data).unwrap();
        let qr_draws = operations
            .operations
            .iter()
            .filter(|op| {
                op.operator == "Do"
                    && op.operands.first().and_then(|v| v.as_name().ok()) == Some(b"QR".as_slice())
            })
            .count();
        assert_eq!(qr_draws, usize::from(self.kind == "qr"));
        let painted_text: Vec<u8> = operations
            .operations
            .iter()
            .filter(|op| op.operator == "Tj")
            .flat_map(|op| {
                op.operands
                    .iter()
                    .filter_map(|v| v.as_str().ok())
                    .flatten()
                    .copied()
            })
            .collect();
        if self.kind == "qr" {
            assert!(painted_text.windows(URL.len()).any(|w| w == URL.as_bytes()));
        } else {
            assert!(!painted_text.windows(URL.len()).any(|w| w == URL.as_bytes()));
        }
        let appearance = self.oracle("inspect", Some(&file));
        assert_eq!(
            appearance["normal_appearance"]["builtin_background_present"],
            true
        );
        assert_eq!(
            appearance["normal_appearance"]["text_paint_operators_present"],
            true
        );
        if self.kind == "qr" {
            assert_eq!(appearance["qr"]["matrix_matches_independent_qrcode"], true);
        } else {
            assert_eq!(appearance["no_qr_in_text_style"], true);
        }
        let status: Value =
            serde_json::from_slice(&fs::read(self.path("native-validation.json")).unwrap())
                .unwrap();
        assert_eq!(status["bottom_line"], true);
        let merged = json!({"kind":"actual public native full-PDF result and appearance checks; supplemental zero IDs","architecture":self.base.arch,"style":self.kind,"native_output_sha256":sha(&bytes),"coverage":format!("{coverage:?}"),"qr_do_operations":qr_draws,"parsed_text":String::from_utf8_lossy(&painted_text),"native_validation":status,"appearance":appearance,"limits":"Vector/QR matrix evidence, not raster rendering/scanning; actual CLI NOW versus fixture2020 verification."});
        self.archive_validation(&merged);
    }
    fn archive_validation(&self, record: &Value) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let data = serde_json::to_vec_pretty(record).unwrap();
        fs::write(self.path("styled-native-validation.json"), &data).unwrap();
        if let Some(dir) = std::env::var_os("SIGIS_CLI_SIGNING_RECORD_DIR") {
            let dst = PathBuf::from(dir).join(format!(
                "validation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dst).unwrap();
            let mut sources = vec![
                self.path("native-styled-frozen.pdf"),
                self.path("root.cert.pem"),
                self.path("native-validation.json"),
                self.path("styled-native-validation.json"),
                self.path("revinfo/metadata.json"),
            ];
            for e in self.path("revinfo").read_dir().unwrap() {
                let e = e.unwrap();
                if e.path().extension().is_some_and(|v| v == "der") {
                    sources.push(e.path());
                }
            }
            let mut rows = Vec::new();
            for (i, source) in sources.into_iter().enumerate() {
                let bytes = fs::read(&source).unwrap();
                let path = dst.join(format!("artifact-{i:02}.bin"));
                fs::write(&path, &bytes).unwrap();
                rows.push(json!({"source":source,"archive":path,"length":bytes.len(),"sha256":sha(&bytes)}));
            }
            fs::write(
                dst.join("validation-record.json"),
                serde_json::to_vec_pretty(&json!({"status":record,"files":rows})).unwrap(),
            )
            .unwrap();
        }
        eprintln!("STYLED_NATIVE_VALIDATION {record}");
    }
    pub fn programmatic(
        &self,
        cfg: &sigis_cli::config::CliConfig,
        runtime: &sigis_cli::runtime::ValidationRuntime,
        contextual: bool,
    ) -> Result<String, String> {
        let mut args: Vec<_> = self.args().into_iter().skip(2).collect();
        for arg in &mut args {
            if [
                "signer.crt",
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
        let config_before = format!("{cfg:?}");
        let result = sigis_cli::signature_appearance::run_with_runtime(&args, Some(cfg), runtime);
        assert_eq!(format!("{cfg:?}"), config_before);
        let record = json!({"kind":"public in-process visible PEM callback; supplemental only", "argv":args,
            "config":config_before,"runtime_now":runtime.now.to_string(),"input_before":before,
            "result":result,"output_sha256":sha(&fs::read(self.path("output.pdf")).unwrap()),
            "test_executable":std::env::current_exe().unwrap()});
        let report = self.path("styled-programmatic.json");
        fs::write(&report, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        if let Some(dir) = std::env::var_os("SIGIS_CLI_SIGNING_RECORD_DIR") {
            let dst = PathBuf::from(dir).join(format!(
                "programmatic-{}-{}-{}-{}",
                std::process::id(),
                self.base.arch,
                self.kind,
                before[0]["path"].as_str().unwrap().replace('/', "_")
            ));
            fs::create_dir_all(&dst).unwrap();
            fs::copy(&report, dst.join("record.json")).unwrap();
            fs::copy(self.path("output.pdf"), dst.join("output.pdf")).unwrap();
        }
        eprintln!("STYLED_PROGRAMMATIC_RECORD {record}");
        result
    }
}
