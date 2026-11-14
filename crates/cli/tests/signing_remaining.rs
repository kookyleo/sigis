//! Exact remaining field/hybrid/dictionary signing assertions from pyHanko0.38.1.
use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime};
use sigis_pdf::{PdfFile, ReaderOptions};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{cert::Cert, fetch::Fetchers, time::Moment};
use std::{fs, path::PathBuf, process::Command};

const ARCHES: [&str; 4] = ["rsa", "ecdsa", "ed25519", "ed448"];
struct Case {
    dir: tempfile::TempDir,
    arch: &'static str,
}
impl Case {
    fn new(arch: &'static str, input: &str) -> Self {
        let case = Self {
            dir: tempfile::tempdir().unwrap(),
            arch,
        };
        fs::copy(
            sigis_testdata::pyhanko(&["pdf", input]),
            case.path("input.pdf"),
        )
        .unwrap();
        fs::write(case.path("output.pdf"), b"output sentinel").unwrap();
        case
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn fixture(&self, name: &str) -> PathBuf {
        sigis_testdata::path(&["lanes", "r3-c", "signing", self.arch, name])
    }
    fn run(&self, args: Vec<String>) -> sigis_cli::Output {
        let runtime = ValidationRuntime {
            now: Moment::from_unix_secs(1_596_211_200),
            fetchers: Fetchers::none(),
            password: Some("secret".into()),
            trusted_list_transport: None,
            pkcs11_user_pin_prompt: None,
        };
        sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &runtime)
    }
    fn pem(&self, before: &[&str]) -> Vec<String> {
        let mut args = vec!["sign".into(), "addsig".into()];
        args.extend(before.iter().map(|s| (*s).into()));
        args.extend([
            "pemder".into(),
            "--no-pass".into(),
            "--cert".into(),
            self.fixture("cert.pem").display().to_string(),
            "--chain".into(),
            self.fixture("interm.pem").display().to_string(),
            "--key".into(),
            self.fixture("key.pem").display().to_string(),
            self.path("input.pdf").display().to_string(),
            self.path("output.pdf").display().to_string(),
        ]);
        args
    }
    fn success(&self, output: sigis_cli::Output, strict: bool) {
        assert_eq!(output.code, 0, "{}{}", output.stdout, output.stderr);
        let bytes = fs::read(self.path("output.pdf")).unwrap();
        assert_ne!(bytes, b"output sentinel");
        let pdf = PdfFile::parse_with(
            &bytes,
            ReaderOptions {
                strict,
                ..Default::default()
            },
        )
        .unwrap();
        let signatures = pdf.embedded_signatures().unwrap();
        assert_eq!(signatures.len(), 1);
        let mut builder = ValidationContext::builder()
            .moment(Moment::from_unix_secs(1_596_211_200))
            .point_in_time_validation(false)
            .revocation_mode("hard-fail")
            .trust_root(
                Cert::from_pem_or_der(&fs::read(self.fixture("root.pem")).unwrap()).unwrap(),
            );
        for name in ["crl-root.der", "crl-interm.der"] {
            builder = builder.crl(
                fs::read(sigis_testdata::path(&[
                    "lanes",
                    "r3-c",
                    "validation",
                    self.arch,
                    name,
                ]))
                .unwrap(),
            );
        }
        let status = sigis_pades::validate_pdf_signature(
            &pdf,
            &signatures[0],
            &builder.build().unwrap(),
            Some(&sigis_pdf_diff::StandardDiffPolicy),
        )
        .unwrap();
        assert!(status.bottom_line(), "{status:?}");
        let denied = ValidationContext::builder()
            .moment(Moment::from_unix_secs(1_596_211_200))
            .revocation_mode("none")
            .build()
            .unwrap();
        if let Ok(status) = sigis_pades::validate_pdf_signature(
            &pdf,
            &signatures[0],
            &denied,
            Some(&sigis_pdf_diff::StandardDiffPolicy),
        ) {
            assert!(!status.bottom_line());
        }
        let python = sigis_testdata::oracle::python().expect("pinned pyHanko interpreter");
        let result = Command::new(python)
            .arg("-B")
            .arg(sigis_testdata::path(&[
                "lanes",
                "r3-c",
                "signing-remaining",
                "verify.py",
            ]))
            .args([
                self.path("output.pdf").display().to_string(),
                self.fixture("root.pem").display().to_string(),
                self.arch.into(),
                strict.to_string(),
            ])
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONOPTIMIZE", "0")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("VALID; empty roots refused"));
    }
}

#[test]
fn test_cli_sign_pkcs12_visible_while_creating_field() {
    for arch in ARCHES {
        let case = Case::new(arch, "minimal.pdf");
        let args = vec![
            "sign".into(),
            "addsig".into(),
            "--field".into(),
            "1/0,0,100,100/Sig1".into(),
            "pkcs12".into(),
            case.path("input.pdf").display().to_string(),
            case.path("output.pdf").display().to_string(),
            case.fixture("signer.p12").display().to_string(),
        ];
        case.success(case.run(args), true);
        let bytes = fs::read(case.path("output.pdf")).unwrap();
        let doc = lopdf::Document::load_mem(&bytes).unwrap();
        assert!(
            doc.objects
                .values()
                .any(|o| o.as_dict().is_ok_and(|d| d.has(b"AP"))),
            "missing real appearance"
        );
    }
}

#[test]
fn test_cli_add_field_then_sign() {
    for arch in ARCHES {
        let case = Case::new(arch, "minimal.pdf");
        let presign = case.path("presign.pdf");
        let added = case.run(vec![
            "sign".into(),
            "addfields".into(),
            "--field".into(),
            "1/0,0,100,100/Sig1".into(),
            case.path("input.pdf").display().to_string(),
            presign.display().to_string(),
        ]);
        assert_eq!(added.code, 0, "{}", added.stderr);
        fs::rename(presign, case.path("input.pdf")).unwrap();
        case.success(
            case.run(case.pem(&["--field", "Sig1", "--existing-only"])),
            true,
        );
    }
}

#[test]
fn test_cli_sign_implied_field() {
    for arch in ARCHES {
        let case = Case::new(arch, "minimal-with-field.pdf");
        case.success(case.run(case.pem(&["--existing-only"])), true);
    }
}

#[test]
fn test_cli_sign_field_param_required() {
    let case = Case::new("rsa", "minimal.pdf");
    let result = case.run(case.pem(&["--existing-only"]));
    assert_eq!(result.code, 1);
    assert!(
        format!("{}{}", result.stdout, result.stderr)
            .contains("There are no empty signature fields"),
        "{}",
        result.stderr
    );
    assert_eq!(
        fs::read(case.path("output.pdf")).unwrap(),
        b"output sentinel"
    );
}

#[test]
fn test_fail_strict_hybrid() {
    let case = Case::new("rsa", "minimal-hybrid-xref.pdf");
    let result = case.run(case.pem(&["--field", "Sig1"]));
    assert_eq!(result.code, 1);
    assert!(
        format!("{}{}", result.stdout, result.stderr).contains("hybrid cross-ref"),
        "{}",
        result.stderr
    );
    assert_eq!(
        fs::read(case.path("output.pdf")).unwrap(),
        b"output sentinel"
    );
}

#[test]
fn test_succeed_non_strict_hybrid() {
    let case = Case::new("rsa", "minimal-hybrid-xref.pdf");
    case.success(
        case.run(case.pem(&["--no-strict-syntax", "--field", "Sig1"])),
        false,
    );
}

#[test]
fn test_cli_with_signature_dictionary_entries() {
    let case = Case::new("rsa", "minimal.pdf");
    case.success(
        case.run(case.pem(&[
            "--field",
            "Sig1",
            "--reason",
            "I agree with this document",
            "--location",
            "THIS-COMPUTER",
            "--contact-info",
            "www.pyhanko.com/verify",
        ])),
        true,
    );
    let bytes = fs::read(case.path("output.pdf")).unwrap();
    let doc = lopdf::Document::load_mem(&bytes).unwrap();
    let signature = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .find(|d| d.has(b"ByteRange"))
        .unwrap();
    assert_eq!(
        signature.get(b"ContactInfo").unwrap().as_str().unwrap(),
        b"www.pyhanko.com/verify"
    );
    assert_eq!(
        signature.get(b"Location").unwrap().as_str().unwrap(),
        b"THIS-COMPUTER"
    );
    assert_eq!(
        signature.get(b"Reason").unwrap().as_str().unwrap(),
        b"I agree with this document"
    );
}
