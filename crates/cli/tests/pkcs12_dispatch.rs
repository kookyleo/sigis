//! Supplemental top-level dispatch controls; no additional upstream credit.
//! Injected historical clocks here are in-process, never product CLI overrides.
use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime};
use sigis_pdf::PdfFile;
use sigis_pki_core::{fetch::Fetchers, time::Moment};
use std::{fs, path::PathBuf};

const SENTINEL: &[u8] = b"Mandatory PKCS12 refusals preserve the existing output.\n";

struct Case {
    directory: tempfile::TempDir,
    input: PathBuf,
    output: PathBuf,
}

impl Case {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.pdf");
        let output = directory.path().join("output.pdf");
        fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &input).unwrap();
        fs::write(&output, SENTINEL).unwrap();
        Self {
            directory,
            input,
            output,
        }
    }

    fn config(&self, extra: serde_json::Value) -> PathBuf {
        let mut setup = serde_json::json!({
            "pfx-file":sigis_testdata::path(&["lanes","r3-c","signing","rsa","signer.p12"]),
            "pfx-passphrase":"secret",
        });
        setup
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let path = self.directory.path().join("config.yml");
        fs::write(
            &path,
            serde_yaml::to_string(&serde_json::json!({
                "pkcs12-setups":{"selected":setup},
            }))
            .unwrap(),
        )
        .unwrap();
        path
    }

    fn run(&self, common: &[&str], config: Option<PathBuf>) -> sigis_cli::Output {
        self.run_with_field(common, config, true)
    }

    fn run_with_field(
        &self,
        common: &[&str],
        config: Option<PathBuf>,
        explicit_field: bool,
    ) -> sigis_cli::Output {
        let mut args = Vec::new();
        if let Some(config) = config {
            args.extend(["--config".into(), config.display().to_string()]);
        }
        args.extend(["sign".into(), "addsig".into()]);
        if explicit_field {
            args.extend(["--field".into(), "Sig1".into()]);
        }
        args.extend(common.iter().map(|arg| (*arg).into()));
        args.push("pkcs12".into());
        if args.iter().any(|arg| arg == "--config") {
            args.extend(["--p12-setup".into(), "selected".into()]);
        }
        args.extend([
            self.input.display().to_string(),
            self.output.display().to_string(),
        ]);
        if !args.iter().any(|arg| arg == "--config") {
            args.push(
                sigis_testdata::path(&["lanes", "r3-c", "signing", "rsa", "signer.p12"])
                    .display()
                    .to_string(),
            );
        }
        let runtime = ValidationRuntime {
            now: Moment::parse_rfc3339("2020-08-01T00:00:00Z").unwrap(),
            fetchers: Fetchers::none(),
            password: Some("secret".into()),
            trusted_list_transport: None,
        };
        let result = sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &runtime);
        eprintln!(
            "PKCS12_TOPLEVEL {}",
            serde_json::json!({
                "mode":"in-process TOPLEVEL injected runtime, not CLI subprocess",
                "argv":args,"moment":runtime.now.to_string(),"code":result.code,
                "stdout":result.stdout,"stderr":result.stderr,
                "output_preserved":fs::read(&self.output).unwrap()==SENTINEL,
                "native_test_executable":std::env::current_exe().unwrap(),
                "unique_upstream_credit":0,
            })
        );
        result
    }
}

#[test]
fn unsupported_algorithm_cannot_fall_back_to_legacy_signing() {
    let case = Case::new();
    let result = case.run(&["--md-algorithm", "sha512"], None);
    assert_eq!(result.code, 1, "{}{}", result.stdout, result.stderr);
    assert!(
        result.stderr.contains("requires extended"),
        "{}",
        result.stderr
    );
    assert_eq!(fs::read(&case.output).unwrap(), SENTINEL);
}

#[test]
fn selected_setup_preserves_top_level_injected_clock() {
    let case = Case::new();
    let result = case.run(&[], Some(case.config(serde_json::json!({}))));
    assert_eq!(result.code, 0, "{}{}", result.stdout, result.stderr);
    let bytes = fs::read(&case.output).unwrap();
    let pdf = PdfFile::parse(&bytes).unwrap();
    let signatures = pdf.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let signature = pdf.get_object_at(signatures[0].sig_object, None).unwrap();
    assert_eq!(
        signature
            .as_dict()
            .unwrap()
            .get(b"M")
            .unwrap()
            .as_str()
            .unwrap(),
        b"D:20200801000000Z"
    );
}

#[test]
fn unknown_setup_requirement_refuses_through_top_level() {
    let case = Case::new();
    let config = case.config(serde_json::json!({"require-qualified-signature":true}));
    let result = case.run(&[], Some(config));
    assert_eq!(result.code, 1, "{}{}", result.stdout, result.stderr);
    assert!(
        result.stderr.contains("Unexpected key"),
        "{}",
        result.stderr
    );
    assert_eq!(fs::read(&case.output).unwrap(), SENTINEL);
}

#[test]
fn implied_field_only_uses_an_existing_single_field() {
    for has_field in [true, false] {
        let case = Case::new();
        if has_field {
            fs::copy(
                sigis_testdata::pyhanko(&["pdf", "minimal-with-field.pdf"]),
                &case.input,
            )
            .unwrap();
        }
        let result = case.run_with_field(&[], Some(case.config(serde_json::json!({}))), false);
        if has_field {
            assert_eq!(result.code, 0, "{}{}", result.stdout, result.stderr);
            let bytes = fs::read(&case.output).unwrap();
            let pdf = PdfFile::parse(&bytes).unwrap();
            let signatures = pdf.embedded_signatures().unwrap();
            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].field_name, "Sig1");
        } else {
            assert_eq!(result.code, 1, "{}{}", result.stdout, result.stderr);
            assert!(result.stderr.contains("no empty signature fields"));
            assert_eq!(fs::read(&case.output).unwrap(), SENTINEL);
        }
    }
}
