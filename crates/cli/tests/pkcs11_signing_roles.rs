//! Dedicated USER and context-specific signing credential capabilities.
//! Real RSA AlwaysAuthenticate software controls only; zero upstream/hardware IDs.
use sigis_cli::{
    plugins::PluginRegistry,
    runtime::{
        Pkcs11SigningPinPrompt, Pkcs11SigningPinPromptError, Pkcs11UserPinPrompt, ValidationRuntime,
    },
};
use sigis_pki_certvalidator::context::ValidationContext;
use sigis_pki_core::{cert::Cert, fetch::Fetchers, time::Moment};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Copy, Debug)]
enum Case {
    BothPrompt,
    MissingSigning,
    SigningUnavailable,
    SigningCancelled,
    WrongSigning,
    WrongUser,
    GenericPassword,
    OnlyUserCapability,
    OnlySigningCapability,
    StaticSigning,
    EnvironmentSigning,
    EnvironmentOverridesStatic,
    MissingResidentCertificate,
    MissingCertificateFile,
}

impl Case {
    fn succeeds(self) -> bool {
        matches!(
            self,
            Self::BothPrompt
                | Self::StaticSigning
                | Self::EnvironmentSigning
                | Self::EnvironmentOverridesStatic
        )
    }
    fn has_signing_environment(self) -> bool {
        matches!(
            self,
            Self::EnvironmentSigning | Self::EnvironmentOverridesStatic
        )
    }
    fn has_user_capability(self) -> bool {
        matches!(self, Self::BothPrompt | Self::OnlyUserCapability)
    }
    fn configures_user(self) -> bool {
        !matches!(
            self,
            Self::BothPrompt | Self::OnlyUserCapability | Self::OnlySigningCapability
        )
    }
    fn has_signing_capability(self) -> bool {
        !matches!(
            self,
            Self::MissingSigning | Self::GenericPassword | Self::OnlyUserCapability
        )
    }
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/data/lanes/r3-c")
}
fn python() -> String {
    std::env::var("HANKO_ORACLE").unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into())
}
fn overlay() -> String {
    std::env::var("SIGIS_PKCS11_ORACLE_OVERLAY").unwrap_or_else(|_| {
        "/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5".into()
    })
}
fn module() -> String {
    std::env::var("SIGIS_PKCS11_SIGNING_MODULE")
        .unwrap_or_else(|_| "/tmp/sigis-p-softhsm-8453e1bde7da/libsofthsm2.so".into())
}

fn context(root: Option<Cert>) -> ValidationContext {
    let builder = ValidationContext::builder()
        .moment(Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap())
        .point_in_time_validation(false)
        .time_tolerance(Duration::from_secs(1))
        .revocation_mode("soft-fail");
    match root {
        Some(root) => builder.trust_root(root).build().unwrap(),
        None => builder.build().unwrap(),
    }
}

fn check_pdf(bytes: &[u8], cert_dir: &Path) {
    let root_der = fs::read(cert_dir.join("root.der")).unwrap();
    let interm_der = fs::read(cert_dir.join("interm.der")).unwrap();
    let signer_der = fs::read(cert_dir.join("signer1.der")).unwrap();
    let root = Cert::from_der(&root_der).unwrap();
    let pdf = sigis_pdf::PdfFile::parse(bytes).unwrap();
    let signatures = pdf.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let sig = &signatures[0];
    assert_eq!(sig.field_name, "Sig1");
    let status = sigis_pades::validate_pdf_signature(
        &pdf,
        sig,
        &context(Some(root.clone())),
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
    assert_eq!(
        status.coverage,
        sigis_pades::SignatureCoverageLevel::EntireFile
    );
    assert_eq!(
        status.cms.signature.signing_cert.as_ref().unwrap().der(),
        signer_der
    );
    let path = status.cms.signature.validation_path.as_ref().unwrap();
    assert_eq!(
        path.certs()
            .iter()
            .map(|c| c.der().to_vec())
            .collect::<Vec<_>>(),
        vec![root_der, interm_der, signer_der]
    );
    if let Ok(untrusted) = sigis_pades::validate_pdf_signature(
        &pdf,
        sig,
        &context(None),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    ) {
        assert!(!untrusted.cms.signature.trusted() && !untrusted.bottom_line());
    }
    let mut changed = bytes.to_vec();
    assert!(changed.starts_with(b"%PDF-"));
    changed[7] = if changed[7] == b'7' { b'6' } else { b'7' };
    let changed_pdf = sigis_pdf::PdfFile::parse(&changed).unwrap();
    let changed_sigs = changed_pdf.embedded_signatures().unwrap();
    if let Ok(tampered) = sigis_pades::validate_pdf_signature(
        &changed_pdf,
        &changed_sigs[0],
        &context(Some(root)),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    ) {
        assert!(!tampered.cms.signature.intact && !tampered.bottom_line());
    }
}

fn run(name: &str, case: Case) {
    if std::env::var("SIGIS_PKCS11_ROLES_CHILD").as_deref() == Ok(name) {
        body(
            &PathBuf::from(std::env::var("SIGIS_PKCS11_ROLES_ROOT").unwrap()),
            case,
        );
        eprintln!("Credential role control completed: {name}");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("fixture");
    let prepared = Command::new(python())
        .arg(fixture_dir().join("pkcs11-signing-credentials/prepare.py"))
        .arg(&root)
        .env("PYTHONPATH", overlay())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("SIGIS_PKCS11_SIGNING_MODULE", module())
        .env_remove("SOFTHSM2_CONF")
        .env_remove("PKCS11_CONFIG")
        .env_remove("PYHANKO_PKCS11_PIN")
        .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    fs::write(directory.path().join("prepare.stdout.log"), prepared.stdout).unwrap();
    fs::write(directory.path().join("prepare.stderr.log"), prepared.stderr).unwrap();
    if !prepared.status.success() {
        panic!(
            "Fixture provisioning failed; inspect {}",
            directory.keep().display()
        );
    }
    let executable = if cfg!(target_os = "linux") {
        PathBuf::from("/proc/self/exe")
    } else {
        std::env::current_exe().unwrap()
    };
    let mut child = Command::new(executable);
    child
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("SIGIS_PKCS11_ROLES_CHILD", name)
        .env("SIGIS_PKCS11_ROLES_ROOT", &root)
        .env("SOFTHSM2_CONF", root.join("provider/softhsm2.conf"))
        .env_remove("PKCS11_CONFIG")
        .env_remove("PYHANKO_PKCS11_PIN")
        .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .stdin(Stdio::null());
    if case.has_signing_environment() {
        child.env("PYHANKO_PKCS11_SIGNING_PIN", "1234");
    }
    let output = child.output().unwrap();
    let completed = format!("Credential role control completed: {name}");
    let ran = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| *line == completed)
        .count();
    fs::write(directory.path().join("child.stdout.log"), output.stdout).unwrap();
    fs::write(directory.path().join("child.stderr.log"), output.stderr).unwrap();
    if !output.status.success() || ran != 1 {
        panic!(
            "Credential role control failed; inspect {}",
            directory.keep().display()
        );
    }
}

fn body(root: &Path, case: Case) {
    let input_path = root.join("input.pdf");
    let output_path = root.join("output.pdf");
    let config_path = root.join("pyhanko.yml");
    let input = fs::read(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])).unwrap();
    fs::write(&input_path, &input).unwrap();
    let sentinel = b"Keep existing output on any credential or certificate refusal";
    if !case.succeeds() {
        fs::write(&output_path, sentinel).unwrap();
    }
    let certificate_file = if matches!(case, Case::MissingCertificateFile) {
        root.join("missing-intermediate.der")
    } else {
        root.join("rsa/interm.der")
    };
    let resident_label = if matches!(case, Case::MissingResidentCertificate) {
        "missing-resident-intermediate"
    } else {
        "interm"
    };
    let mut config = format!("pkcs11-setups:\n  test:\n    module-path: {}\n    token-criteria:\n      label: testrsa\n    cert-label: signer1\n    key-label: signer1\n    other-certs-to-pull: {resident_label}\n    other-certs: {}\n", module(), certificate_file.display());
    if case.configures_user() {
        config.push_str(if matches!(case, Case::WrongUser) {
            "    user-pin: 'wrong-user-role'\n"
        } else {
            "    user-pin: '1234'\n"
        });
    }
    if matches!(case, Case::StaticSigning | Case::EnvironmentOverridesStatic) {
        config.push_str("    signing-pin-mode: reauthenticate\n");
        config.push_str(if matches!(case, Case::EnvironmentOverridesStatic) {
            "    signing-pin: 'wrong-configured-signing'\n"
        } else {
            "    signing-pin: '1234'\n"
        });
    } else {
        config.push_str("    signing-pin-mode: prompt\n");
    }
    fs::write(&config_path, &config).unwrap();
    let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let user_events = events.clone();
    let signing_events = events.clone();
    let runtime = ValidationRuntime {
        now: Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap(),
        fetchers: Fetchers::none(),
        password: matches!(case, Case::GenericPassword).then(|| "1234".into()),
        pkcs11_user_pin_prompt: case.has_user_capability().then(|| {
            Pkcs11UserPinPrompt::new(move |label| {
                assert_eq!(label, "PKCS#11 user PIN: ");
                user_events.lock().unwrap().push("USER");
                Ok("1234".into())
            })
        }),
        pkcs11_signing_pin_prompt: case.has_signing_capability().then(|| {
            Pkcs11SigningPinPrompt::new(move |label| {
                assert_eq!(label, "PKCS#11 signing PIN: ");
                signing_events.lock().unwrap().push("SIGN");
                match case {
                    Case::SigningUnavailable => Err(Pkcs11SigningPinPromptError::Unavailable),
                    Case::SigningCancelled => Err(Pkcs11SigningPinPromptError::Cancelled),
                    Case::WrongSigning => Ok("wrong-signing-role".into()),
                    // A static or environment value must suppress this callback.
                    Case::StaticSigning
                    | Case::EnvironmentSigning
                    | Case::EnvironmentOverridesStatic => {
                        Err(Pkcs11SigningPinPromptError::Unavailable)
                    }
                    _ => Ok("1234".into()),
                }
            })
        }),
        ..Default::default()
    };
    assert!(events.lock().unwrap().is_empty());
    let args = vec![
        "--config".into(),
        config_path.display().to_string(),
        "sign".into(),
        "addsig".into(),
        "--field".into(),
        "Sig1".into(),
        "pkcs11".into(),
        "--p11-setup".into(),
        "test".into(),
        input_path.display().to_string(),
        output_path.display().to_string(),
    ];
    let result = sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &runtime);
    assert_eq!(fs::read(&input_path).unwrap(), input);
    assert_eq!(fs::read_to_string(&config_path).unwrap(), config);
    for secret in [
        "1234",
        "wrong-user-role",
        "wrong-signing-role",
        "wrong-configured-signing",
    ] {
        assert!(
            !result.stdout.contains(secret) && !result.stderr.contains(secret),
            "Diagnostics must not expose a credential"
        );
    }
    let observed = events.lock().unwrap().clone();
    let signing_calls = observed.iter().filter(|event| **event == "SIGN").count();
    if matches!(case, Case::BothPrompt) {
        assert_eq!(
            observed.first(),
            Some(&"USER"),
            "USER login must precede per-operation signing credential requests"
        );
        assert_eq!(observed.iter().filter(|event| **event == "USER").count(), 1);
        assert!(
            signing_calls >= 1,
            "At least one actual signing operation must request its credential"
        );
        assert!(observed[1..].iter().all(|event| *event == "SIGN"));
    }
    if matches!(
        case,
        Case::SigningUnavailable | Case::SigningCancelled | Case::WrongSigning
    ) {
        assert!(signing_calls >= 1);
    }
    if matches!(
        case,
        Case::WrongUser
            | Case::OnlySigningCapability
            | Case::StaticSigning
            | Case::EnvironmentSigning
            | Case::EnvironmentOverridesStatic
            | Case::MissingResidentCertificate
            | Case::MissingCertificateFile
    ) {
        assert_eq!(
            signing_calls, 0,
            "This phase must not request a signing credential"
        );
    }
    if !case.succeeds() {
        assert_eq!(result.code, 1, "{}{}", result.stdout, result.stderr);
        assert_eq!(fs::read(&output_path).unwrap(), sentinel);
        let diagnostic = result.stderr.to_ascii_lowercase();
        match case {
            Case::SigningUnavailable => {
                assert!(diagnostic.contains("signing pin") && diagnostic.contains("unavailable"))
            }
            Case::SigningCancelled => {
                assert!(diagnostic.contains("signing pin") && diagnostic.contains("cancelled"))
            }
            Case::MissingSigning | Case::GenericPassword | Case::OnlyUserCapability => {
                assert!(diagnostic.contains("signing pin"))
            }
            Case::OnlySigningCapability => assert!(diagnostic.contains("user pin")),
            _ => {}
        }
        return;
    }
    assert_eq!(result.code, 0, "{}{}", result.stdout, result.stderr);
    check_pdf(&fs::read(&output_path).unwrap(), &root.join("rsa"));
    let peer = Command::new(python())
        .args(["-B", "-s", "-P"])
        .arg(fixture_dir().join("pkcs11-completion/validate_output.py"))
        .arg(&output_path)
        .arg(root.join("rsa/root.der"))
        .env("PYTHONPATH", overlay())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    fs::write(root.join("peer.stdout.log"), peer.stdout).unwrap();
    fs::write(root.join("peer.stderr.log"), peer.stderr).unwrap();
    assert!(
        peer.status.success(),
        "Pinned same-output full PDF reference failed"
    );
}

macro_rules! cases {
    ($($name:ident => $case:ident),+ $(,)?) => {
        $(#[test] fn $name() { run(stringify!($name), Case::$case); })+
    };
}

cases! {
    distinct_user_and_signing_prompts_sign_real_pdf_in_role_order => BothPrompt,
    correct_user_pin_without_signing_capability_refuses => MissingSigning,
    unavailable_signing_pin_preserves_output => SigningUnavailable,
    cancelled_signing_pin_preserves_output => SigningCancelled,
    wrong_signing_pin_preserves_output => WrongSigning,
    wrong_user_pin_never_requests_a_signing_pin => WrongUser,
    generic_document_password_cannot_answer_signing_prompt => GenericPassword,
    user_pin_capability_cannot_answer_signing_prompt => OnlyUserCapability,
    signing_pin_capability_cannot_answer_user_prompt => OnlySigningCapability,
    configured_static_signing_pin_suppresses_prompt_capability => StaticSigning,
    signing_environment_suppresses_configured_prompt => EnvironmentSigning,
    signing_environment_overrides_wrong_static_signing_pin => EnvironmentOverridesStatic,
    missing_resident_certificate_does_not_fall_back_to_file => MissingResidentCertificate,
    missing_certificate_file_does_not_fall_back_to_resident => MissingCertificateFile,
}
