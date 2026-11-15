//! Static context-specific PIN supplements on a real RSA AlwaysAuthenticate key.
//! These are zero-ID software controls, not SafeNet hardware original ports.
use sigis_cli::{
    plugins::PluginRegistry,
    runtime::{Pkcs11UserPinPrompt, ValidationRuntime},
};
use sigis_pki_certvalidator::context::ValidationContext;
use sigis_pki_core::{cert::Cert, fetch::Fetchers, time::Moment};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/data/lanes/r3-c/pkcs11-signing-credentials")
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

fn python() -> String {
    std::env::var("HANKO_ORACLE").unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into())
}

fn overlay() -> String {
    std::env::var("SIGIS_PKCS11_ORACLE_OVERLAY").unwrap_or_else(|_| {
        "/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5".into()
    })
}

fn run(name: &str, case: &str) {
    if std::env::var("PKCS11_CREDENTIAL_CHILD").as_deref() == Ok(name) {
        body(
            &PathBuf::from(std::env::var("PKCS11_CREDENTIAL_ROOT").unwrap()),
            case,
        );
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let fixture = root.path().join("fixture");
    let prepared = Command::new(python())
        .arg(fixture_dir().join("prepare.py"))
        .arg(&fixture)
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
    fs::write(root.path().join("prepare.stdout.log"), &prepared.stdout).unwrap();
    fs::write(root.path().join("prepare.stderr.log"), &prepared.stderr).unwrap();
    if !prepared.status.success() {
        panic!(
            "Fixture provisioning failed; inspect {}",
            root.keep().display()
        );
    }
    let mut child = Command::new("/proc/self/exe");
    child
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("PKCS11_CREDENTIAL_CHILD", name)
        .env("PKCS11_CREDENTIAL_ROOT", &fixture)
        .env("SOFTHSM2_CONF", fixture.join("provider/softhsm2.conf"))
        .env_remove("PKCS11_CONFIG")
        .env_remove("PYHANKO_PKCS11_PIN")
        .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .stdin(Stdio::null());
    if case == "environment" {
        child.env("PYHANKO_PKCS11_SIGNING_PIN", "1234");
    }
    let output = child.output().unwrap();
    fs::write(root.path().join("child.stdout.log"), output.stdout).unwrap();
    fs::write(root.path().join("child.stderr.log"), output.stderr).unwrap();
    if !output.status.success() {
        panic!(
            "Credential control failed; inspect {}",
            root.keep().display()
        );
    }
}

fn body(root: &Path, case: &str) {
    let cert_dir = root.join("rsa");
    let input = root.join("input.pdf");
    let output = root.join("output.pdf");
    let config = root.join("pyhanko.yml");
    let input_bytes = fs::read(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])).unwrap();
    fs::write(&input, &input_bytes).unwrap();
    let positive = matches!(case, "configured" | "environment");
    let sentinel = b"Do not replace this output on a credential failure";
    if !positive {
        fs::write(&output, sentinel).unwrap();
    }
    let mut setup = format!("pkcs11-setups:\n  test:\n    module-path: {}\n    token-criteria:\n      label: testrsa\n    cert-label: signer1\n    key-label: signer1\n    other-certs: {}\n    signing-pin-mode: reauthenticate\n", module(), cert_dir.join("interm.der").display());
    if !matches!(case, "environment" | "generic-password") {
        setup.push_str(if case == "wrong-user" {
            "    user-pin: 'incorrect-user'\n"
        } else {
            "    user-pin: '1234'\n"
        });
    }
    if case != "environment" {
        setup.push_str(if case == "wrong-signing" {
            "    signing-pin: 'incorrect-signing'\n"
        } else {
            "    signing-pin: '1234'\n"
        });
    }
    fs::write(&config, &setup).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let runtime = ValidationRuntime {
        now: Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap(),
        fetchers: Fetchers::none(),
        password: (case == "generic-password").then(|| "1234".into()),
        pkcs11_user_pin_prompt: (case == "environment").then(|| {
            Pkcs11UserPinPrompt::new(move |label| {
                assert_eq!(label, "PKCS#11 user PIN: ");
                observed.fetch_add(1, Ordering::SeqCst);
                Ok("1234".into())
            })
        }),
        ..Default::default()
    };
    let args = vec![
        "--config".into(),
        config.display().to_string(),
        "sign".into(),
        "addsig".into(),
        "--field".into(),
        "Sig1".into(),
        "pkcs11".into(),
        "--p11-setup".into(),
        "test".into(),
        input.display().to_string(),
        output.display().to_string(),
    ];
    let result = sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &runtime);
    assert_eq!(fs::read(&input).unwrap(), input_bytes);
    assert_eq!(fs::read_to_string(&config).unwrap(), setup);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        usize::from(case == "environment")
    );
    for secret in ["1234", "incorrect-user", "incorrect-signing"] {
        assert!(!result.stdout.contains(secret) && !result.stderr.contains(secret));
    }
    if !positive {
        assert_eq!(result.code, 1, "{}{}", result.stdout, result.stderr);
        assert_eq!(fs::read(&output).unwrap(), sentinel);
        // Wrong credentials must reach the credential boundary, not the old
        // blanket rejection of every static signing PIN configuration.
        if case == "generic-password" {
            assert!(result.stderr.contains("User PIN prompt"));
        } else {
            assert!(!result
                .stderr
                .contains("Unsupported PKCS#11 signing requirement"));
        }
        return;
    }
    assert_eq!(result.code, 0, "{}{}", result.stdout, result.stderr);
    check_pdf(&fs::read(&output).unwrap(), &cert_dir);
    let peer = Command::new(python())
        .args(["-B", "-s", "-P"])
        .arg(fixture_dir().join("../pkcs11-completion/validate_output.py"))
        .arg(&output)
        .arg(cert_dir.join("root.der"))
        .env("PYTHONPATH", overlay())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    fs::write(root.join("peer.stdout.log"), &peer.stdout).unwrap();
    fs::write(root.join("peer.stderr.log"), &peer.stderr).unwrap();
    assert!(
        peer.status.success(),
        "Same-output pinned reference validation failed"
    );
}

#[test]
fn configured_signing_pin_authenticates_real_rsa_signature() {
    run(
        "configured_signing_pin_authenticates_real_rsa_signature",
        "configured",
    );
}

#[test]
fn environment_signing_pin_preserves_user_prompt_authority() {
    run(
        "environment_signing_pin_preserves_user_prompt_authority",
        "environment",
    );
}

#[test]
fn wrong_signing_pin_cannot_fall_back_to_correct_user_pin() {
    run(
        "wrong_signing_pin_cannot_fall_back_to_correct_user_pin",
        "wrong-signing",
    );
}

#[test]
fn wrong_user_pin_cannot_be_replaced_by_correct_signing_pin() {
    run(
        "wrong_user_pin_cannot_be_replaced_by_correct_signing_pin",
        "wrong-user",
    );
}

#[test]
fn generic_document_password_cannot_authorize_token_user_login() {
    run(
        "generic_document_password_cannot_authorize_token_user_login",
        "generic-password",
    );
}
