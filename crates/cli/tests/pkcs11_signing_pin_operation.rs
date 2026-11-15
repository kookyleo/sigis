//! Per-operation context-specific PIN controls on a real software token.
//! Supplemental tests only: no SafeNet original or native FFI-count claim.
use sigis_pades_sign::{
    pkcs11::{open_signer, Pkcs11Config, Pkcs11Signer, SigningPinEntryMode, TokenCriteria},
    PdfSignatureMetadata, PdfSigner,
};
use sigis_pki_certvalidator::context::ValidationContext;
use sigis_pki_core::{
    algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext},
    cert::Cert,
    sign::KeySigner,
    time::Moment,
};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

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

fn run(name: &str, operation: fn(&Path)) {
    if std::env::var("SIGIS_PKCS11_OPERATION_CHILD").as_deref() == Ok(name) {
        operation(&PathBuf::from(
            std::env::var("SIGIS_PKCS11_OPERATION_ROOT").unwrap(),
        ));
        eprintln!("Operation control completed: {name}");
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
    let child = Command::new(executable)
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("SIGIS_PKCS11_OPERATION_CHILD", name)
        .env("SIGIS_PKCS11_OPERATION_ROOT", &root)
        .env("SOFTHSM2_CONF", root.join("provider/softhsm2.conf"))
        .env_remove("PKCS11_CONFIG")
        .env_remove("PYHANKO_PKCS11_PIN")
        .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let completed = format!("Operation control completed: {name}");
    let ran = String::from_utf8_lossy(&child.stderr)
        .lines()
        .filter(|line| *line == completed)
        .count();
    fs::write(directory.path().join("child.stdout.log"), child.stdout).unwrap();
    fs::write(directory.path().join("child.stderr.log"), child.stderr).unwrap();
    if !child.status.success() || ran != 1 {
        panic!(
            "Operation control failed; inspect {}",
            directory.keep().display()
        );
    }
}

fn signer(static_pin: Option<&str>) -> Pkcs11Signer {
    open_signer(
        &Pkcs11Config {
            module_path: module(),
            token_criteria: Some(TokenCriteria::label("testrsa")),
            cert_label: Some("signer1".into()),
            key_label: Some("signer1".into()),
            user_pin: Some("1234".into()),
            other_certs_to_pull: Some(vec!["interm".into(), "root".into()]),
            signing_pin_mode: if static_pin.is_some() {
                SigningPinEntryMode::Reauthenticate
            } else {
                SigningPinEntryMode::Skip
            },
            signing_pin: static_pin.map(str::to_owned),
            ..Default::default()
        },
        None,
    )
    .unwrap()
}

fn verify(signer: &Pkcs11Signer, bytes: &[u8], signature: &[u8]) {
    validate_signature(
        signature,
        bytes,
        &signer.signing_cert().public_key(),
        &signer.signature_algorithm(DigestAlgorithm::Sha256).unwrap(),
        &SignatureValidationContext::default(),
    )
    .unwrap();
    let mut changed = bytes.to_vec();
    changed.push(0);
    assert!(validate_signature(
        signature,
        &changed,
        &signer.signing_cert().public_key(),
        &signer.signature_algorithm(DigestAlgorithm::Sha256).unwrap(),
        &SignatureValidationContext::default(),
    )
    .is_err());
}

fn assert_no_secret(error: &impl fmt::Display) {
    let text = error.to_string();
    for secret in ["1234", "wrong-operation-secret", "wrong-static-secret"] {
        assert!(
            !text.contains(secret),
            "Credential must not appear in error diagnostics"
        );
    }
}

fn callback_operations(_root: &Path) {
    let wrong = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_wrong = wrong.clone();
    let observed_calls = calls.clone();
    let base = signer(None);
    let session = base.session().clone();
    let signer = base.with_signing_pin_callback(move || {
        observed_calls.fetch_add(1, Ordering::SeqCst);
        Ok(if observed_wrong.load(Ordering::SeqCst) {
            "wrong-operation-secret".into()
        } else {
            "1234".into()
        })
    });
    assert!(Arc::ptr_eq(&session, signer.session()));
    for (index, bytes) in [
        b"First independent real token signature".as_slice(),
        b"Second different token signature".as_slice(),
    ].into_iter().enumerate() {
        let signature = signer.sign_raw(bytes, DigestAlgorithm::Sha256).unwrap();
        verify(&signer, bytes, &signature);
        assert_eq!(calls.load(Ordering::SeqCst), index + 1);
        assert!(Arc::ptr_eq(&session, signer.session()));
    }
    wrong.store(true, Ordering::SeqCst);
    let error = signer.sign_raw(b"Must not be signed", DigestAlgorithm::Sha256).unwrap_err();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_no_secret(&error);
}

fn callback_override(_root: &Path) {
    let base = signer(Some("wrong-static-secret"));
    let session = base.session().clone();
    let signer = base
        .with_signing_pin_callback(|| panic!("Replaced callback must not run"))
        .with_signing_pin_callback(|| Ok("1234".into()));
    let data = b"Callback overrides static PIN on the same selected session and key";
    let signature = signer.sign_raw(data, DigestAlgorithm::Sha256).unwrap();
    verify(&signer, data, &signature);
    assert!(Arc::ptr_eq(&session, signer.session()));
    let signer = signer.with_signing_pin_callback(|| Err(
        sigis_pki_core::errors::HankoError::Signing("New callback unavailable".into())
    ));
    let error = signer.sign_raw(data, DigestAlgorithm::Sha256).unwrap_err();
    assert!(error.to_string().contains("New callback unavailable"));
    assert_no_secret(&error);
}

fn callback_pdf(root: &Path) {
    let wrong = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_wrong = wrong.clone();
    let observed_calls = calls.clone();
    let callback_signer = signer(None).with_signing_pin_callback(
        move || -> sigis_pki_core::errors::Result<String> {
            observed_calls.fetch_add(1, Ordering::SeqCst);
            Ok(if observed_wrong.load(Ordering::SeqCst) {
                "wrong-operation-secret".into()
            } else {
                "1234".into()
            })
        },
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "Building a signer must not request a credential"
    );
    callback_signer
        .signature_algorithm(DigestAlgorithm::Sha256)
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "Mechanism selection must not request a credential"
    );
    let debug = format!("{callback_signer:?}");
    assert!(debug.contains("SigningPinCallback(<redacted>)"));
    assert!(!debug.contains("wrong-operation-secret"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "Debug formatting must not invoke the credential callback"
    );
    let pdf_signer = PdfSigner::new(PdfSignatureMetadata::new("Sig1"), Arc::new(callback_signer))
        .at(Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap());
    let input_path = root.join("input.pdf");
    let output = root.join("signed.pdf");
    let input = fs::read(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])).unwrap();
    fs::write(&input_path, &input).unwrap();
    let signed = pdf_signer.sign_pdf(&input).unwrap();
    fs::write(&output, &signed).unwrap();
    assert!(calls.load(Ordering::SeqCst) > 0);
    check_pdf(&signed, &root.join("rsa"));
    let peer = Command::new(python())
        .args(["-B", "-s", "-P"])
        .arg(fixture_dir().join("pkcs11-completion/validate_output.py"))
        .arg(&output)
        .arg(root.join("rsa/root.der"))
        .env("PYTHONPATH", overlay())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    fs::write(root.join("peer.stdout.log"), peer.stdout).unwrap();
    fs::write(root.join("peer.stderr.log"), peer.stderr).unwrap();
    assert!(
        peer.status.success(),
        "Pinned same-output PDF validation failed"
    );
    let original_signed = fs::read(&output).unwrap();
    let before_calls = calls.load(Ordering::SeqCst);
    wrong.store(true, Ordering::SeqCst);
    let failed = pdf_signer.sign_pdf(&input);
    assert!(calls.load(Ordering::SeqCst) > before_calls);
    let error = failed.unwrap_err();
    assert_no_secret(&error);
    assert_eq!(fs::read(&input_path).unwrap(), input);
    assert_eq!(fs::read(&output).unwrap(), original_signed);
    // This public API returns bytes and has no sink argument. The retained
    // output above is an untouched caller-owned sentinel, not a claim about a
    // product file writer's atomicity or a runtime/terminal callback feature.
}

#[test]
fn callback_is_fresh_for_each_signature_on_same_session() {
    run(
        "callback_is_fresh_for_each_signature_on_same_session",
        callback_operations,
    );
}

#[test]
fn callback_replacement_preserves_session_and_overrides_static_pin() {
    run(
        "callback_replacement_preserves_session_and_overrides_static_pin",
        callback_override,
    );
}

#[test]
fn per_sign_test_callback_produces_real_pdf_and_later_wrong_pin_denies() {
    run(
        "per_sign_test_callback_produces_real_pdf_and_later_wrong_pin_denies",
        callback_pdf,
    );
}

fn callback_error_then_recovery(_root: &Path) {
    let available = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_available = available.clone();
    let observed_calls = calls.clone();
    // A correct static PIN is deliberately present: callback failure must
    // propagate rather than falling back to this otherwise valid credential.
    let signer = signer(Some("1234")).with_signing_pin_callback(move || {
        observed_calls.fetch_add(1, Ordering::SeqCst);
        if observed_available.load(Ordering::SeqCst) {
            Ok("1234".into())
        } else {
            Err(sigis_pki_core::errors::HankoError::Signing(
                "Signing credential unavailable".into(),
            ))
        }
    });
    let data = b"Callback errors must not poison the provider sign operation";
    let error = signer.sign_raw(data, DigestAlgorithm::Sha256).unwrap_err();
    assert!(error.to_string().contains("Signing credential unavailable"));
    assert_no_secret(&error);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    available.store(true, Ordering::SeqCst);
    let signature = signer.sign_raw(data, DigestAlgorithm::Sha256).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    verify(&signer, data, &signature);
}

#[test]
fn callback_error_refuses_static_fallback_and_same_session_recovers() {
    run(
        "callback_error_refuses_static_fallback_and_same_session_recovers",
        callback_error_then_recovery,
    );
}
