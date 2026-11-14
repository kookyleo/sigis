//! Real isolated Ed25519 token fixtures and functional full-PDF checks.
//! Every row uses its own child process/store; no persistent proof directory.

use sigis_pades::PdfSignatureStatus;
use sigis_pades_sign::pkcs11::{
    cryptoki::{
        mechanism::MechanismType,
        object::{Attribute, AttributeType, KeyType, ObjectClass},
        session::UserType,
        types::AuthPin,
    },
    load_module,
};
use sigis_pki_certvalidator::context::ValidationContext;
use sigis_pki_core::{cert::Cert, errors::Result as PkiResult, time::Moment};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    time::Duration,
};

const USER_PIN: &str = "1234";
const PROVIDER_RUNTIME: &str =
    "/home/l/.codex/artifacts/sigis/round3/p/cli-signing-env-pin/runtime";
const ORACLE_OVERLAY: &str =
    "/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5";

fn selected_path(name: &str, default: impl Into<PathBuf>) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| default.into())
}
fn required_path(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var_os(name)
            .unwrap_or_else(|| panic!("Required isolated child selector {name} is missing")),
    )
}
fn fixture_dir() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            sigis_testdata::path(&["lanes", "r3-c", "pkcs11-signing-env-pin"])
                .canonicalize()
                .unwrap()
        })
        .clone()
}
fn names(dir: &Path) -> Vec<String> {
    let mut result = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    result.sort();
    result
}

/// The parent does not initialize the module, mutate its environment or change
/// cwd. Its five test-owned children receive their PIN/store before exec.
pub fn run(test_name: &str, label: &str) {
    if let Ok(selected) = std::env::var("SIGIS_PKCS11_SIGNING_CHILD") {
        assert_eq!(selected, test_name);
        child(label);
        return;
    }
    let case = tempfile::Builder::new()
        .prefix(&format!("pkcs11-{label}-"))
        .tempdir()
        .unwrap();
    // Self-reexec is functional isolation, not an ELF capture/hash requirement.
    // Linux's proc link retains this running executable across path replacement.
    let executable = if cfg!(target_os = "linux") {
        PathBuf::from("/proc/self/exe")
    } else {
        std::env::current_exe().unwrap()
    };
    let output = Command::new(executable)
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env("SIGIS_PKCS11_SIGNING_CHILD", test_name)
        .env("SIGIS_PKCS11_SIGNING_CASE_DIR", case.path())
        .env("SOFTHSM2_CONF", case.path().join("provider/softhsm2.conf"))
        .env("PYHANKO_PKCS11_PIN", USER_PIN)
        .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .env_remove("PKCS11_CONFIG")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Real isolated {label} signing child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let completed = format!("PKCS11 functional row completed: {label}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .filter(|line| *line == completed)
            .count(),
        1,
        "An empty child test filter must not count as a signing success"
    );
    // Keep the temporary store alive until the child and every session finish.
    drop(case);
}

// Functional import only: no generated/replaced keys, ELF/DSO/source hashing,
// maps collection or JSON receipts. Native code independently reads it back.
const IMPORT_FIXTURE: &str = r#"
import importlib.metadata, os, sys
from pathlib import Path
assert __debug__ and sys.flags.optimize == 0
import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.util.x509 import decode_x509_certificate
from asn1crypto import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
module, fixture, overlay = sys.argv[1:]
fixture, overlay = Path(fixture), Path(overlay).resolve()
assert Path(pkcs11.__file__).resolve().is_relative_to(overlay), 'The real requested PKCS11 binding is required'
assert importlib.metadata.version('python-pkcs11') == '0.9.5'
key = serialization.load_pem_private_key((fixture / 'signer.key.pem').read_bytes(), password=None)
assert isinstance(key, Ed25519PrivateKey)
raw_signer = (fixture / 'signer1.der').read_bytes()
signer = x509.Certificate.load(raw_signer, strict=True)
public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
assert public == signer.public_key['public_key'].native
seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
lib = pkcs11.lib(module)
token = lib.get_token(token_label='tested25519')
assert Mechanism.EDDSA in token.slot.get_mechanisms()
with token.open(rw=True, user_pin='1234') as session:
    for label in ['root', 'interm', 'signer1']:
        raw = (fixture / (label + '.der')).read_bytes()
        x509.Certificate.load(raw, strict=True)
        attrs = decode_x509_certificate(raw)
        attrs.update({Attribute.TOKEN:True, Attribute.LABEL:label, Attribute.ID:label.encode('ascii')})
        cert = session.create_object(attrs)
        assert cert[Attribute.VALUE] == raw and cert[Attribute.TOKEN]
    attrs = {Attribute.CLASS:ObjectClass.PRIVATE_KEY, Attribute.KEY_TYPE:KeyType.EC_EDWARDS,
             Attribute.TOKEN:True, Attribute.PRIVATE:True, Attribute.SENSITIVE:True,
             Attribute.EXTRACTABLE:False, Attribute.SIGN:True, Attribute.LABEL:'signer1',
             Attribute.ID:b'signer1', Attribute.EC_PARAMS:bytes.fromhex('06032b6570'), Attribute.VALUE:seed}
    key_object = session.create_object(attrs)
    assert key_object[Attribute.CLASS] == ObjectClass.PRIVATE_KEY
    assert key_object[Attribute.KEY_TYPE] == KeyType.EC_EDWARDS and key_object[Attribute.SIGN]
    assert key_object[Attribute.TOKEN] and key_object[Attribute.PRIVATE]
    assert not key_object[Attribute.EXTRACTABLE] and key_object[Attribute.SENSITIVE]
    inventory = list(session.get_objects())
    classes = [obj[Attribute.CLASS] for obj in inventory]
    assert len(inventory) == 4 and classes.count(ObjectClass.CERTIFICATE) == 3 and classes.count(ObjectClass.PRIVATE_KEY) == 1
    for label in ['root', 'interm', 'signer1']:
        certs = list(session.get_objects({Attribute.CLASS:ObjectClass.CERTIFICATE, Attribute.LABEL:label}))
        assert len(certs) == 1 and certs[0][Attribute.TOKEN]
        assert certs[0][Attribute.VALUE] == (fixture / (label + '.der')).read_bytes()
    keys = list(session.get_objects({Attribute.CLASS:ObjectClass.PRIVATE_KEY, Attribute.SIGN:True, Attribute.LABEL:'signer1'}))
    assert len(keys) == 1
"#;

fn child(label: &str) {
    assert!(["rsa", "ecdsa", "ed25519", "ed448", "mldsa"].contains(&label));
    let case = required_path("SIGIS_PKCS11_SIGNING_CASE_DIR");
    assert!(
        case.is_absolute(),
        "The child store requires an absolute temporary directory"
    );
    let module = selected_path(
        "SIGIS_PKCS11_SIGNING_MODULE",
        Path::new(PROVIDER_RUNTIME).join("libsofthsm2.so"),
    );
    let utility = selected_path(
        "SIGIS_PKCS11_SIGNING_UTILITY",
        Path::new(PROVIDER_RUNTIME).join("softhsm2-util"),
    );
    let python = selected_path("HANKO_ORACLE", "/tmp/pyhanko-oracle/venv/bin/python");
    let overlay = selected_path("SIGIS_PKCS11_ORACLE_OVERLAY", ORACLE_OVERLAY);
    assert!(
        module.is_file(),
        "Required real SoftHSM module is unavailable: {}",
        module.display()
    );
    assert!(
        utility.is_file(),
        "Required real SoftHSM utility is unavailable: {}",
        utility.display()
    );
    assert!(
        python.is_file(),
        "Required pinned Python is unavailable: {}",
        python.display()
    );
    assert!(
        overlay.is_dir(),
        "Required real Python PKCS11 0.9.5 overlay is unavailable: {}",
        overlay.display()
    );
    // Preserve relative provider overrides when this private child changes cwd.
    // Do not canonicalize the Python venv entry point into a system interpreter.
    let module = module.canonicalize().unwrap();
    let utility = utility.canonicalize().unwrap();
    let overlay = overlay.canonicalize().unwrap();
    let provider = case.join("provider");
    assert!(!provider.exists(), "Never reuse an old token store");
    fs::create_dir(&provider).unwrap();
    let tokens = provider.join("tokens");
    fs::create_dir(&tokens).unwrap();
    let conf = provider.join("softhsm2.conf");
    fs::write(&conf, format!("directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n", tokens.display())).unwrap();
    assert_eq!(required_path("SOFTHSM2_CONF"), conf);
    assert_eq!(std::env::var("PYHANKO_PKCS11_PIN").unwrap(), USER_PIN);
    assert!(std::env::var_os("PYHANKO_PKCS11_SIGNING_PIN").is_none());
    let initialized = Command::new(&utility)
        .arg("--module")
        .arg(&module)
        .args([
            "--init-token",
            "--free",
            "--label",
            "tested25519",
            "--pin",
            USER_PIN,
            "--so-pin",
            "5678",
        ])
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "Real token initialization failed: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let imported = Command::new(&python)
        .args(["-B", "-s", "-P", "-c", IMPORT_FIXTURE])
        .arg(&module)
        .arg(fixture_dir())
        .arg(&overlay)
        .env("PYTHONPATH", &overlay)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONNOUSERSITE", "1")
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "Actual Ed25519 import failed:\n{}\n{}",
        String::from_utf8_lossy(&imported.stdout),
        String::from_utf8_lossy(&imported.stderr)
    );
    read_actual_fixture(&module);
    let cwd = case.join("cli-cwd");
    fs::create_dir(&cwd).unwrap();
    let input = cwd.join("input.pdf");
    fs::copy(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]), &input).unwrap();
    fs::copy(fixture_dir().join("interm.der"), cwd.join("interm.crt")).unwrap();
    let config = cwd.join("pyhanko.yml");
    fs::write(&config, format!("pkcs11-setups:\n  test:\n    module-path: {}\n    token-criteria:\n      label: tested25519\n    cert-label: signer1\n    key-label: null\n    other-certs-to-pull: interm\n    other-certs: interm.crt\n", serde_json::to_string(module.to_str().unwrap()).unwrap())).unwrap();
    let sentinel = cwd.join("unrelated-sentinel.bin");
    fs::write(
        &sentinel,
        b"Preserve unrelated files during token signing.\n",
    )
    .unwrap();
    let protected = [&input, &config, &cwd.join("interm.crt"), &sentinel]
        .map(|path| (path.to_path_buf(), fs::read(path).unwrap()));
    let entries_before = names(&cwd);
    // This is the selected private libtest child, not the parent Cargo process.
    // Its one exact test can use CliRunner-like relative paths without racing
    // another test's cwd or provider initialization.
    std::env::set_current_dir(&cwd).unwrap();
    let args = [
        "sign",
        "addsig",
        "--field",
        "Sig1",
        "pkcs11",
        "--p11-setup",
        "test",
        "input.pdf",
        "output.pdf",
    ]
    .map(str::to_owned);
    let before_now = Moment::now();
    let output = sigis_cli::run_with_runtime(
        &args,
        &sigis_cli::plugins::PluginRegistry::default(),
        &sigis_cli::runtime::ValidationRuntime::default(),
    );
    for (path, before) in protected {
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "Input changed: {}",
            path.display()
        );
    }
    if output.code != 0 {
        assert!(
            !cwd.join("output.pdf").exists(),
            "An error must not publish signature output"
        );
    }
    assert_eq!(
        output.code, 0,
        "Original positive must actually sign: {}{}",
        output.stdout, output.stderr
    );
    assert!(cwd.join("output.pdf").is_file());
    let mut expected_entries = entries_before;
    expected_entries.push("output.pdf".into());
    expected_entries.sort();
    assert_eq!(
        names(&cwd),
        expected_entries,
        "Successful signing may only add its output"
    );
    assert!(
        !output.stderr.contains("PKCS#11 user PIN:"),
        "Environment PIN must not fall back to a prompt"
    );
    assert!(
        !output.stderr.contains("pin=1234") && !output.stderr.contains("PIN: 1234"),
        "Diagnostics must not expose PIN"
    );
    verify_output(&fs::read(cwd.join("output.pdf")).unwrap(), before_now);
    // Plain functional completion after every assertion, not a provenance log.
    eprintln!("PKCS11 functional row completed: {label}");
}

fn read_actual_fixture(module: &Path) {
    let ctx = load_module(module.to_str().unwrap()).unwrap();
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).unwrap().label().trim_end() == "tested25519")
        .expect("Actual isolated Ed25519 token must exist");
    let mechanisms = ctx.get_mechanism_list(slot).unwrap();
    assert!(
        mechanisms.contains(&MechanismType::EDDSA),
        "The original fixture requires actual EDDSA support"
    );
    let session = ctx.open_ro_session(slot).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
        .unwrap();
    let keys = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(b"signer1".to_vec()),
            Attribute::Sign(true),
        ])
        .unwrap();
    assert_eq!(keys.len(), 1);
    let key_attrs = session
        .get_attributes(
            keys[0],
            &[
                AttributeType::Class,
                AttributeType::KeyType,
                AttributeType::Sign,
            ],
        )
        .unwrap();
    assert!(key_attrs
        .iter()
        .any(|a| matches!(a, Attribute::KeyType(KeyType::EC_EDWARDS))));
    assert!(key_attrs.iter().any(|a| matches!(a, Attribute::Sign(true))));
    for label in ["root", "interm", "signer1"] {
        let found = session
            .find_objects(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .unwrap();
        assert_eq!(found.len(), 1);
        let attrs = session
            .get_attributes(found[0], &[AttributeType::Value, AttributeType::Token])
            .unwrap();
        let raw = attrs
            .iter()
            .find_map(|a| match a {
                Attribute::Value(b) => Some(b),
                _ => None,
            })
            .unwrap();
        assert!(attrs.iter().any(|a| matches!(a, Attribute::Token(true))));
        let expected = fs::read(fixture_dir().join(format!("{label}.der"))).unwrap();
        assert_eq!(*raw, expected);
        let parsed = Cert::from_der(raw).unwrap();
        assert_eq!(parsed.der(), expected);
    }
    let inventory = session.find_objects(&[]).unwrap();
    assert_eq!(
        inventory.len(),
        4,
        "Only signer1 private key plus three actual certificates are provisioned"
    );
    session.logout().unwrap();
    session.close().unwrap();
}

fn validation_context(root: Option<&Cert>, moment: Moment) -> ValidationContext {
    let builder = ValidationContext::builder()
        .moment(moment)
        .point_in_time_validation(false)
        .time_tolerance(Duration::from_secs(1))
        .revocation_mode("soft-fail");
    match root {
        Some(root) => builder.trust_root(root.clone()).build().unwrap(),
        None => builder.build().unwrap(),
    }
}

fn assert_denied(result: &PkiResult<PdfSignatureStatus>) {
    if let Ok(status) = result {
        assert!(
            !status.cms.signature.trusted() && !status.bottom_line(),
            "Mandatory negative may not become trusted"
        );
    }
}

fn verify_output(bytes: &[u8], now: Moment) {
    let root_bytes = fs::read(fixture_dir().join("root.der")).unwrap();
    let interm_bytes = fs::read(fixture_dir().join("interm.der")).unwrap();
    let signer_bytes = fs::read(fixture_dir().join("signer1.der")).unwrap();
    let signer_not_after = Cert::from_der(&signer_bytes).unwrap().not_after();
    let root = Cert::from_der(&root_bytes).unwrap();
    let pdf = sigis_pdf::PdfFile::parse(bytes).unwrap();
    let signatures = pdf.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let sig = &signatures[0];
    assert_eq!(sig.field_name, "Sig1");
    assert_eq!(sig.kind, sigis_pdf::signatures::SignatureKind::Signature);
    assert_eq!(
        sigis_pades::signature_coverage(&pdf, sig).unwrap(),
        sigis_pades::SignatureCoverageLevel::EntireFile
    );
    let cms = sigis_cms::signed_data::SignedData::from_content_info_der(&sig.contents).unwrap();
    assert!(cms.certificates.contains(&signer_bytes));
    assert!(
        cms.certificates.contains(&interm_bytes),
        "The actual intermediate must be embedded, not preloaded into validation"
    );
    let moment = Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap();
    let trusted = validation_context(Some(&root), moment);
    let result = sigis_pades::validate_pdf_signature(
        &pdf,
        sig,
        &trusted,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    );
    let status = result
        .as_ref()
        .expect("Original frozen-clock full-path validation must succeed");
    assert!(
        status.cms.signature.intact
            && status.cms.signature.valid
            && status.cms.signature.trusted()
            && status.bottom_line(),
        "Actual full signature status must pass: {status:?}"
    );
    assert_eq!(
        status.coverage,
        sigis_pades::SignatureCoverageLevel::EntireFile
    );
    assert_eq!(
        status.cms.signature.signing_cert.as_ref().unwrap().der(),
        signer_bytes
    );
    let path = status.cms.signature.validation_path.as_ref().unwrap();
    assert_eq!(
        path.len(),
        3,
        "This is full validation path length, not a demand to embed root in CMS"
    );
    assert_eq!(
        path.certs()
            .iter()
            .map(|c| c.der().to_vec())
            .collect::<Vec<_>>(),
        vec![root_bytes, interm_bytes, signer_bytes]
    );
    let empty = sigis_pades::validate_pdf_signature(
        &pdf,
        sig,
        &validation_context(None, moment),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    );
    assert_denied(&empty);
    let actual_now = sigis_pades::validate_pdf_signature(
        &pdf,
        sig,
        &validation_context(Some(&root), now),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    );
    let now_empty = sigis_pades::validate_pdf_signature(
        &pdf,
        sig,
        &validation_context(None, now),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    );
    assert_denied(&now_empty);
    let mut modified = bytes.to_vec();
    assert!(modified.starts_with(b"%PDF-"));
    modified[7] = if modified[7] == b'7' { b'6' } else { b'7' };
    let changed_pdf = sigis_pdf::PdfFile::parse(&modified).unwrap();
    let changed = changed_pdf.embedded_signatures().unwrap();
    assert_eq!(changed.len(), 1);
    let mutation = sigis_pades::validate_pdf_signature(
        &changed_pdf,
        &changed[0],
        &trusted,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    );
    if let Ok(status) = &mutation {
        assert!(
            !status.cms.signature.intact && !status.bottom_line(),
            "A changed signed byte must break document integrity and acceptance"
        );
    }
    if now > signer_not_after {
        assert_denied(&actual_now);
    }
}
