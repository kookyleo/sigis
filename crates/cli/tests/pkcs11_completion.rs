//! Remaining provider originals: real token-backed CLI signing and explicit
//! upstream fixture availability exclusions. Parameters do not add function IDs.
use sigis_cli::{plugins::PluginRegistry, runtime::{Pkcs11UserPinPrompt, ValidationRuntime}};
use sigis_pki_certvalidator::context::ValidationContext;
use sigis_pki_core::{cert::Cert, fetch::Fetchers, time::Moment};
use std::{fs, path::{Path, PathBuf}, process::{Command, Stdio}, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/data/lanes/r3-c/pkcs11-completion")
}

fn module() -> String {
    std::env::var("SIGIS_PKCS11_SIGNING_MODULE").unwrap_or_else(|_| "/tmp/sigis-p-softhsm-8453e1bde7da/libsofthsm2.so".into())
}

fn context(root: Option<Cert>) -> ValidationContext {
    let builder = ValidationContext::builder()
        .moment(Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap())
        .point_in_time_validation(false)
        .time_tolerance(Duration::from_secs(1))
        .revocation_mode("soft-fail");
    match root { Some(root) => builder.trust_root(root).build().unwrap(), None => builder.build().unwrap() }
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
    let status = sigis_pades::validate_pdf_signature(&pdf, sig, &context(Some(root.clone())), Some(&sigis_pdf_diff::StandardDiffPolicy)).unwrap();
    assert!(status.cms.signature.intact && status.cms.signature.valid && status.cms.signature.trusted() && status.bottom_line(), "{status:?}");
    assert_eq!(status.coverage, sigis_pades::SignatureCoverageLevel::EntireFile);
    assert_eq!(status.cms.signature.signing_cert.as_ref().unwrap().der(), signer_der);
    let path = status.cms.signature.validation_path.as_ref().unwrap();
    assert_eq!(path.certs().iter().map(|c| c.der().to_vec()).collect::<Vec<_>>(), vec![root_der, interm_der, signer_der]);
    if let Ok(untrusted) = sigis_pades::validate_pdf_signature(&pdf, sig, &context(None), Some(&sigis_pdf_diff::StandardDiffPolicy)) {
        assert!(!untrusted.cms.signature.trusted() && !untrusted.bottom_line());
    }
    let mut changed = bytes.to_vec();
    assert!(changed.starts_with(b"%PDF-"));
    changed[7] = if changed[7] == b'7' { b'6' } else { b'7' };
    let changed_pdf = sigis_pdf::PdfFile::parse(&changed).unwrap();
    let changed_sigs = changed_pdf.embedded_signatures().unwrap();
    if let Ok(tampered) = sigis_pades::validate_pdf_signature(&changed_pdf, &changed_sigs[0], &context(Some(root)), Some(&sigis_pdf_diff::StandardDiffPolicy)) {
        assert!(!tampered.cms.signature.intact && !tampered.bottom_line());
    }
}

fn run(name: &str, algorithm: &str, route: &str, raw: bool) {
    if std::env::var("PKCS11_COMPLETION_CHILD").as_deref() == Ok(name) {
        let root = PathBuf::from(std::env::var("PKCS11_COMPLETION_ROOT").unwrap());
        body(&root, algorithm, route, raw);
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let python = std::env::var("HANKO_ORACLE").unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into());
    let overlay = std::env::var("SIGIS_PKCS11_ORACLE_OVERLAY").unwrap_or_else(|_| "/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5".into());
    let prepared = Command::new(python)
        .arg(fixture_dir().join("prepare.py")).arg(root.path().join("fixture"))
        .env("PYTHONPATH", overlay).env("PYTHONDONTWRITEBYTECODE", "1")
        .env("SIGIS_PKCS11_SIGNING_MODULE", module())
        .env_remove("SOFTHSM2_CONF").env_remove("PYHANKO_PKCS11_PIN").env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .output().unwrap();
    assert!(prepared.status.success(), "Fixture provisioning failed: {}", String::from_utf8_lossy(&prepared.stderr));
    let fixture = root.path().join("fixture");
    let output = Command::new("/proc/self/exe")
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("PKCS11_COMPLETION_CHILD", name).env("PKCS11_COMPLETION_ROOT", &fixture)
        .env("SOFTHSM2_CONF", fixture.join("provider/softhsm2.conf"))
        .env_remove("PKCS11_CONFIG").env_remove("PYHANKO_PKCS11_PIN").env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .stdin(Stdio::null()).output().unwrap();
    if !output.status.success() {
        let retained = root.keep();
        fs::write(retained.join("child.stdout.log"), output.stdout).unwrap();
        fs::write(retained.join("child.stderr.log"), output.stderr).unwrap();
        panic!("Actual provider signing failed; inspect {}", retained.display());
    }
}

fn body(root: &Path, algorithm: &str, route: &str, raw: bool) {
    let cert_dir = root.join(algorithm);
    let cwd = tempfile::tempdir().unwrap();
    let input = cwd.path().join("input.pdf");
    let output = cwd.path().join("output.pdf");
    let config = cwd.path().join("pyhanko.yml");
    let intermediate = cert_dir.join("interm.der");
    let input_bytes = fs::read(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])).unwrap();
    fs::write(&input, &input_bytes).unwrap();
    let direct = route.starts_with("direct-");
    let resident = route.ends_with("pull");
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let runtime = ValidationRuntime {
        now: Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap(),
        fetchers: Fetchers::none(),
        pkcs11_user_pin_prompt: direct.then(|| Pkcs11UserPinPrompt::new(move |label| {
            assert_eq!(label, "PKCS#11 user PIN: ");
            observed.fetch_add(1, Ordering::SeqCst);
            Ok("1234".into())
        })),
        ..Default::default()
    };
    let mut args = vec!["sign".into(), "addsig".into(), "--field".into(), "Sig1".into(), "pkcs11".into()];
    if direct {
        args.extend(["--lib".into(), module(), "--token-label".into(), format!("test{algorithm}"), "--cert-label".into(), "signer1".into()]);
        args.extend([if resident { "--other-cert" } else { "--other-cert-file" }.into(), if resident { "interm".into() } else { intermediate.display().to_string() }]);
        if raw { args.push("--raw-mechanism".into()); }
    } else {
        let mut setup = format!("pkcs11-setups:\n  test:\n    module-path: {}\n    token-criteria:\n      label: test{algorithm}\n    cert-label: signer1\n    key-label: signer1\n    user-pin: '1234'\n    other-certs: {}\n", module(), intermediate.display());
        if resident { setup.push_str("    other-certs-to-pull: interm\n"); }
        if raw { setup.push_str("    raw-mechanism: true\n"); }
        fs::write(&config, setup).unwrap();
        args.splice(0..0, ["--config".into(), config.display().to_string()]);
        args.extend(["--p11-setup".into(), "test".into()]);
    }
    args.extend([input.display().to_string(), output.display().to_string()]);
    let result = sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &runtime);
    assert_eq!(result.code, 0, "{}{}", result.stdout, result.stderr);
    assert_eq!(calls.load(Ordering::SeqCst), usize::from(direct));
    assert_eq!(fs::read(&input).unwrap(), input_bytes);
    assert!(output.is_file(), "Success must produce an actual signed PDF");
    assert!(!result.stdout.contains("1234") && !result.stderr.contains("1234"));
    check_pdf(&fs::read(&output).unwrap(), &cert_dir);
    let peer = Command::new(std::env::var("HANKO_ORACLE").unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into()))
        .args(["-B", "-s", "-P"])
        .arg(fixture_dir().join("validate_output.py"))
        .arg(&output).arg(cert_dir.join("root.der"))
        .env("PYTHONPATH", std::env::var("SIGIS_PKCS11_ORACLE_OVERLAY").unwrap_or_else(|_| "/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5".into()))
        .stdin(Stdio::null()).output().unwrap();
    assert!(peer.status.success(), "Same-output pinned Python validation failed: {}", String::from_utf8_lossy(&peer.stderr));
}

macro_rules! cases {
    ($rsa:ident, $ecdsa:ident, $ed25519:ident, $ed448:ident, $mldsa:ident, $route:literal) => {
        #[test] fn $rsa() { run(stringify!($rsa), "rsa", $route, false); }
        #[test] #[ignore = "Upstream fixture requires ECDSA_SHA256, absent from available SoftHSM"] fn $ecdsa() { run(stringify!($ecdsa), "ecdsa", $route, false); }
        #[test] fn $ed25519() { run(stringify!($ed25519), "ed25519", $route, false); }
        #[test] fn $ed448() { run(stringify!($ed448), "ed448", $route, false); }
        #[test] #[ignore = "Available SoftHSM has no ML_DSA mechanism"] fn $mldsa() { run(stringify!($mldsa), "mldsa", $route, false); }
    }
}

cases!(test_cli_addsig_pkcs11_pull_interm_rsa, test_cli_addsig_pkcs11_pull_interm_ecdsa, test_cli_addsig_pkcs11_pull_interm_ed25519, test_cli_addsig_pkcs11_pull_interm_ed448, test_cli_addsig_pkcs11_pull_interm_mldsa, "direct-pull");
cases!(test_cli_addsig_pkcs11_read_interm_from_file_rsa, test_cli_addsig_pkcs11_read_interm_from_file_ecdsa, test_cli_addsig_pkcs11_read_interm_from_file_ed25519, test_cli_addsig_pkcs11_read_interm_from_file_ed448, test_cli_addsig_pkcs11_read_interm_from_file_mldsa, "direct-file");
cases!(test_cli_addsig_pkcs11_with_setup_pull_certs_rsa, test_cli_addsig_pkcs11_with_setup_pull_certs_ecdsa, test_cli_addsig_pkcs11_with_setup_pull_certs_ed25519, test_cli_addsig_pkcs11_with_setup_pull_certs_ed448, test_cli_addsig_pkcs11_with_setup_pull_certs_mldsa, "setup-pull");
cases!(test_cli_addsig_pkcs11_with_setup_read_certs_from_file_rsa, test_cli_addsig_pkcs11_with_setup_read_certs_from_file_ecdsa, test_cli_addsig_pkcs11_with_setup_read_certs_from_file_ed25519, test_cli_addsig_pkcs11_with_setup_read_certs_from_file_ed448, test_cli_addsig_pkcs11_with_setup_read_certs_from_file_mldsa, "setup-file");

#[test]
fn supplemental_actual_raw_ecdsa_with_resident_key() {
    run("supplemental_actual_raw_ecdsa_with_resident_key", "ecdsa", "setup-file", true);
}

#[test]
fn supplemental_actual_direct_raw_ecdsa_with_resident_key() {
    run("supplemental_actual_direct_raw_ecdsa_with_resident_key", "ecdsa", "direct-file", true);
}

// Function-level ECDSA marks win over all five root-cert fixture labels.
// Keep each original row explicit even though its unchanged combined-mechanism
// fixture gate currently skips it before the raw-signing body can execute.
macro_rules! raw_cases {
    ($route:literal; $($name:ident),+ $(,)?) => {
        $(
            #[test]
            #[ignore = "Original raw-ECDSA fixture requires unavailable combined ECDSA_SHA256 (marker name differs)"]
            fn $name() { run(stringify!($name), "ecdsa", $route, true); }
        )+
    }
}

raw_cases!("direct-file";
    test_cli_addsig_raw_ecdsa_rsa,
    test_cli_addsig_raw_ecdsa_ecdsa,
    test_cli_addsig_raw_ecdsa_ed25519,
    test_cli_addsig_raw_ecdsa_ed448,
    test_cli_addsig_raw_ecdsa_mldsa,
);
raw_cases!("setup-file";
    test_cli_addsig_pkcs11_with_setup_raw_ecdsa_rsa,
    test_cli_addsig_pkcs11_with_setup_raw_ecdsa_ecdsa,
    test_cli_addsig_pkcs11_with_setup_raw_ecdsa_ed25519,
    test_cli_addsig_pkcs11_with_setup_raw_ecdsa_ed448,
    test_cli_addsig_pkcs11_with_setup_raw_ecdsa_mldsa,
);

#[test]
#[ignore = "Original requires SafeNet hardware and a separate context-specific signing PIN; no configured device is available"]
fn test_cli_addsig_pkcs11_with_setup_and_signing_pin_prompt() {
    panic!("No configured SafeNet device: the original signing-PIN fixture is unavailable");
}

#[test]
#[ignore = "Original requires SafeNet hardware and its separate environment signing PIN; no configured device is available"]
fn test_cli_addsig_pkcs11_with_setup_and_env_signing_pin() {
    panic!("No configured SafeNet device: the original environment signing-PIN fixture is unavailable");
}
