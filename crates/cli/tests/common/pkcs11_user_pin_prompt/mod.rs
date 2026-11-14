//! Dedicated test-client authority and fresh provider processes, never fixture login in the body.
use serde_json::{json, Value};
use sigis_cli::{
    plugins::PluginRegistry,
    runtime::{Pkcs11UserPinPrompt, Pkcs11UserPinPromptError, ValidationRuntime},
};
use sigis_pades::PdfSignatureStatus;
use sigis_pdf::PdfHandlerExt;
use sigis_pki_certvalidator::context::ValidationContext;
use sigis_pki_core::{
    cert::Cert,
    errors::{FetchError, FetchErrorKind, Result as PkiResult},
    fetch::{CrlFetcher, Fetchers},
    time::Moment,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

const USER_PIN: &str = "1234";
const WRONG_USER_PIN: &str = "not-the-token-user-pin";
const USER_LABEL: &str = "PKCS#11 user PIN: ";
const PROVIDER_RUNTIME: &str =
    "/home/l/.codex/artifacts/sigis/round3/p/cli-user-pin-prompt/runtime";
const ORACLE_OVERLAY: &str =
    "/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5";

fn selected_path(name: &str, default: impl Into<PathBuf>) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| default.into())
}
fn module_path() -> PathBuf {
    selected_path(
        "SIGIS_PKCS11_SIGNING_MODULE",
        Path::new(PROVIDER_RUNTIME).join("libsofthsm2.so"),
    )
    .canonicalize()
    .expect("The real SoftHSM module is required")
}
fn oracle_python() -> PathBuf {
    selected_path("HANKO_ORACLE", "/tmp/pyhanko-oracle/venv/bin/python")
}
const SENTINEL: &[u8] = b"Preserve the existing output on every refusal.\n";
const UNRELATED: &[u8] = b"Do not alter unrelated test-client files.\n";

fn required(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("Required real prompt fixture selector {name} is missing"))
}
fn sha(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn write_oracle_request(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
fn names(dir: &Path) -> Vec<String> {
    let mut result: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    result.sort();
    result
}
fn fixture_dir() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            sigis_testdata::path(&["lanes", "r3-c", "pkcs11-user-pin-prompt"])
                .canonicalize()
                .unwrap()
        })
        .clone()
}
fn frozen_moment() -> Moment {
    Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap()
}

/// A test-client retrieval service, not trust material or a validation bypass.
/// Only exact original certificate DER can request its issuer's recorded CRL.
#[derive(Debug)]
struct RecordedCrlSource {
    leaf_der: Vec<u8>,
    interm_der: Vec<u8>,
    root_crl: Vec<u8>,
    interm_crl: Vec<u8>,
    requests: Mutex<Vec<Vec<u8>>>,
}

impl RecordedCrlSource {
    fn new(tampered: bool) -> Self {
        let load = |filename: &str| {
            let mut bytes = fs::read(fixture_dir().join(filename)).unwrap();
            if tampered {
                let last = bytes
                    .len()
                    .checked_sub(1)
                    .expect("Recorded CRL must not be empty");
                // Change only the final signature octet, preserving TBS and DER.
                bytes[last] ^= 1;
            }
            bytes
        };
        Self {
            leaf_der: fs::read(fixture_dir().join("signer1.der")).unwrap(),
            interm_der: fs::read(fixture_dir().join("interm.der")).unwrap(),
            root_crl: load("policy-root.crl.der"),
            interm_crl: load("policy-interm.crl.der"),
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl CrlFetcher for RecordedCrlSource {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        let returned = if cert.der() == self.leaf_der {
            Some(&self.interm_crl)
        } else if cert.der() == self.interm_der {
            Some(&self.root_crl)
        } else {
            None
        };
        // Functional request assertion only: retain the actual requested DER,
        // without a transport/provenance record or issuer/file fingerprints.
        self.requests.lock().unwrap().push(cert.der().to_vec());
        returned.map(|bytes| vec![bytes.clone()]).ok_or_else(|| {
            FetchError::new(
                FetchErrorKind::NotFound,
                "No recorded CRL for this exact certificate",
            )
        })
    }
}

/// Every body is a fresh exec AFTER separate provisioning/readback exits.
/// The parent never loads the provider and never mutates global env or cwd.
pub fn run(test_name: &str, selections: &[&str]) {
    if let Ok(selected_test) = std::env::var("SIGIS_PKCS11_PROMPT_CHILD") {
        assert_eq!(selected_test, test_name);
        let selected_case = required("SIGIS_PKCS11_PROMPT_CASE");
        assert!(selections.contains(&selected_case.as_str()));
        body(&selected_case);
        return;
    }
    for selected in selections {
        let case = tempfile::Builder::new()
            .prefix(&format!("pkcs11-prompt-{selected}-"))
            .tempdir()
            .unwrap();
        let cwd = case.path().join("cli-cwd");
        fs::create_dir(&cwd).unwrap();
        provision(case.path());
        // Reexec isolates provider sessions; it is not a source/ELF audit.
        let executable = if cfg!(target_os = "linux") {
            PathBuf::from("/proc/self/exe")
        } else {
            std::env::current_exe().unwrap()
        };
        let mut command = Command::new(executable);
        command
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .current_dir(&cwd)
            .env("SIGIS_PKCS11_PROMPT_CHILD", test_name)
            .env("SIGIS_PKCS11_PROMPT_CASE", selected)
            .env("SIGIS_PKCS11_PROMPT_CASE_DIR", case.path())
            .env("SIGIS_PKCS11_SIGNING_MODULE", module_path())
            .env("SOFTHSM2_CONF", case.path().join("provider/softhsm2.conf"))
            .env_remove("PKCS11_CONFIG")
            .env_remove("PYHANKO_PKCS11_PIN")
            .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
            .stdin(Stdio::null());
        // An explicit unsupported signing-role control, never a USER source.
        if *selected == "environment-signing-pin" {
            command.env("PYHANKO_PKCS11_SIGNING_PIN", " ");
        }
        if *selected == "environment-pin-correct" {
            command.env("PYHANKO_PKCS11_PIN", USER_PIN);
        } else if matches!(
            *selected,
            "environment-pin-wrong" | "configured-pin-env-ignored"
        ) {
            command.env("PYHANKO_PKCS11_PIN", WRONG_USER_PIN);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "Prompt case {selected} failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let completed = format!("PKCS11 prompt case completed: {selected}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| *line == completed)
                .count(),
            1,
            "An empty child filter must not count as a completed prompt case"
        );
        // Drop only after the real provider child and its sessions have exited.
        drop(case);
    }
}

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

fn provision(case: &Path) {
    let provider = case.join("provider");
    assert!(!provider.exists(), "Never reuse a provider store");
    fs::create_dir(&provider).unwrap();
    let tokens = provider.join("tokens");
    fs::create_dir(&tokens).unwrap();
    let conf = provider.join("softhsm2.conf");
    fs::write(&conf, format!("directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n", tokens.display())).unwrap();
    let module = module_path();
    let utility = selected_path(
        "SIGIS_PKCS11_SIGNING_UTILITY",
        Path::new(PROVIDER_RUNTIME).join("softhsm2-util"),
    )
    .canonicalize()
    .expect("The real SoftHSM utility is required");
    let overlay = selected_path("SIGIS_PKCS11_ORACLE_OVERLAY", ORACLE_OVERLAY)
        .canonicalize()
        .expect("The real PKCS11 Python overlay is required");
    let initialized = Command::new(utility)
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
        .env("SOFTHSM2_CONF", &conf)
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "Real token initialization failed: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    // Import and read back in a separate process; no fixture login is inherited
    // by the production signing body, and no keys are generated or exported.
    let imported = Command::new(oracle_python())
        .args(["-B", "-s", "-P", "-c", IMPORT_FIXTURE])
        .arg(&module)
        .arg(fixture_dir())
        .arg(&overlay)
        .env("SOFTHSM2_CONF", &conf)
        .env("PYTHONPATH", &overlay)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONNOUSERSITE", "1")
        .env_remove("PKCS11_CONFIG")
        .env_remove("PYHANKO_PKCS11_PIN")
        .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "Real Ed25519 provisioning/readback failed:\n{}\n{}",
        String::from_utf8_lossy(&imported.stdout),
        String::from_utf8_lossy(&imported.stderr)
    );
}

fn earlier_refusal(selected: &str) -> bool {
    matches!(
        selected,
        "unknown-profile"
            | "unknown-token-criterion"
            | "nonboolean-requirement"
            | "signature-mechanism"
            | "signing-pin-mode"
            | "configured-signing-pin"
            | "environment-signing-pin"
            | "missing-file-intermediate"
    )
}
fn before_provider_refusal(selected: &str) -> bool {
    earlier_refusal(selected)
        || matches!(
            selected,
            "missing-capability"
                | "generic-password-is-not-user-pin"
                | "unavailable"
                | "cancelled"
                | "decode-limit"
                | "strict-reader"
                | "pdf-password-missing"
                | "pdf-password-wrong"
                | "unsupported-required-revinfo-policy"
                | "missing-file-intermediate"
        )
}
fn positive(selected: &str) -> bool {
    selected.starts_with("positive-")
        || matches!(
            selected,
            "pdf-password-correct"
                | "pdf-mac-correct"
                | "policy-positive"
                | "policy-match-any"
                | "configured-pin-correct"
                | "environment-pin-correct"
                | "configured-pin-env-ignored"
        )
}
fn policy_case(selected: &str) -> bool {
    selected.starts_with("policy-")
}
fn credential_override(selected: &str) -> bool {
    matches!(
        selected,
        "configured-pin-correct"
            | "configured-pin-wrong"
            | "environment-pin-correct"
            | "environment-pin-wrong"
            | "configured-pin-env-ignored"
    )
}

fn body(selected: &str) {
    let environment_user_pin = matches!(
        selected,
        "environment-pin-correct" | "environment-pin-wrong" | "configured-pin-env-ignored"
    );
    assert_eq!(
        std::env::var_os("PYHANKO_PKCS11_PIN").is_some(),
        environment_user_pin
    );
    if selected != "environment-signing-pin" {
        assert!(std::env::var_os("PYHANKO_PKCS11_SIGNING_PIN").is_none());
    }
    let case = PathBuf::from(required("SIGIS_PKCS11_PROMPT_CASE_DIR"));
    let cwd = case.join("cli-cwd");
    assert_eq!(std::env::current_dir().unwrap(), cwd);
    let module = module_path();
    let conf = case.join("provider/softhsm2.conf");
    assert_eq!(PathBuf::from(required("SOFTHSM2_CONF")), conf);
    let initial_maps = fs::read_to_string("/proc/self/maps").unwrap();
    assert!(
        !initial_maps.contains(module.to_str().unwrap()),
        "Fresh body must not inherit fixture module/login state"
    );
    let input = cwd.join("input.pdf");
    let encrypted = selected.starts_with("pdf-");
    let expected_mac = selected == "pdf-mac-correct";
    let input_source = if expected_mac {
        let source = case.join("generated-pdf-mac-input.pdf");
        fs::write(&source, mac_document()).unwrap();
        source
    } else if encrypted {
        sigis_testdata::pyhanko(&["pdf", "minimal-aes256.pdf"])
    } else if selected == "decode-limit" {
        sigis_testdata::path(&["lanes", "r3-c", "decode-limits-simple", "oversized.pdf"])
    } else if selected == "strict-reader" {
        sigis_testdata::path(&["lanes", "r3-c", "runtime", "minimal-slightly-broken.pdf"])
    } else {
        sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])
    };
    fs::copy(&input_source, &input).unwrap();
    if expected_mac {
        let pdf = sigis_pdf::PdfFile::parse(&fs::read(&input).unwrap()).unwrap();
        assert_mac_good(&pdf, "ownersecret");
    }
    let interm = cwd.join("interm.crt");
    fs::copy(fixture_dir().join("interm.der"), &interm).unwrap();
    let output_path = cwd.join("output.pdf");
    if !positive(selected) {
        fs::write(&output_path, SENTINEL).unwrap();
    }
    let unrelated = cwd.join("unrelated-sentinel.bin");
    fs::write(&unrelated, UNRELATED).unwrap();
    let provider_path = if before_provider_refusal(selected) {
        cwd.join("must-not-load-provider.so")
    } else {
        module.clone()
    };
    assert!(!cwd.join("must-not-load-provider.so").exists());
    let mut config = json!({"pkcs11-setups":{"test":{
        "module-path":provider_path,"token-criteria":{"label":"tested25519"},"cert-label":"signer1","key-label":null,
        "other-certs-to-pull":"interm","other-certs":interm
    }}});
    let setup = &mut config["pkcs11-setups"]["test"];
    match selected {
        "unknown-token-criterion" => setup["token-criteria"]["manufacturer-id"] = json!("required"),
        "nonboolean-requirement" => setup["prefer-pss"] = json!("true"),
        "signature-mechanism" => setup["signature-mechanism"] = json!({"algorithm":"ed25519"}),
        "signing-pin-mode" => setup["signing-pin-mode"] = json!("prompt"),
        "configured-signing-pin" => {
            setup["signing-pin"] = json!("unsupported-context-specific-fixture")
        }
        "missing-resident-intermediate" => {
            setup["other-certs-to-pull"] = json!("absent-certificate-label")
        }
        "missing-file-intermediate" => {
            setup["other-certs"] = json!(cwd.join("absent-intermediate.crt"))
        }
        "configured-pin-correct" | "configured-pin-env-ignored" => {
            setup["user-pin"] = json!(USER_PIN)
        }
        "configured-pin-wrong" => setup["user-pin"] = json!(WRONG_USER_PIN),
        _ => {}
    }
    if policy_case(selected) || selected == "unsupported-required-revinfo-policy" {
        let roots = if selected == "policy-empty-roots" {
            json!([])
        } else {
            json!(fixture_dir().join("root.der"))
        };
        let mut context = json!({"trust":roots,"trust-replace":true,"time-tolerance":1});
        let policy = match selected {
            "policy-match-any" => {
                json!({"key-usage":["non_repudiation","crl_sign"],"match-all-key-usages":false})
            }
            "policy-match-all" => {
                json!({"key-usage":["non_repudiation","crl_sign"],"match-all-key-usages":true})
            }
            "policy-forbidden" => {
                json!({"key-usage":["non_repudiation"],"key-usage-forbidden":["non_repudiation"]})
            }
            "policy-explicit-eku" => {
                json!({"key-usage":["non_repudiation"],"extd-key-usage":["2.999"],"explicit-extd-key-usage-required":true})
            }
            _ => json!({"key-usage":["non_repudiation"]}),
        };
        context["signer-key-usage-policy"] = policy;
        if selected == "unsupported-required-revinfo-policy" {
            // Unsupported mandatory input must not disappear. This does NOT
            // claim an executable RequireRevinfo CLI context exists.
            context["revocation-policy"] = json!("require");
        }
        config["validation-contexts"] = json!({"effective":context});
    }
    let config_path = cwd.join("pyhanko.yml");
    fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let input_before = (input.canonicalize().unwrap(), fs::read(&input).unwrap());
    let config_before = (
        config_path.canonicalize().unwrap(),
        fs::read(&config_path).unwrap(),
    );
    let interm_before = (interm.canonicalize().unwrap(), fs::read(&interm).unwrap());
    let sentinel_before = (
        unrelated.canonicalize().unwrap(),
        fs::read(&unrelated).unwrap(),
    );
    let entries_before = names(&cwd);
    let callbacks = Arc::new(AtomicUsize::new(0));
    let labels = Arc::new(Mutex::new(Vec::<String>::new()));
    let count = callbacks.clone();
    let observed = labels.clone();
    let response_case = selected.to_owned();
    let capability = Pkcs11UserPinPrompt::new(move |label| {
        count.fetch_add(1, Ordering::SeqCst);
        observed.lock().unwrap().push(label.to_owned());
        assert_eq!(label, USER_LABEL);
        match response_case.as_str() {
            "unavailable" => Err(Pkcs11UserPinPromptError::Unavailable),
            "cancelled" => Err(Pkcs11UserPinPromptError::Cancelled),
            "wrong-pin" | "pdf-correct-user-pin-wrong" => Ok(WRONG_USER_PIN.to_owned()),
            _ => Ok(USER_PIN.to_owned()),
        }
    });
    let wall_now = Moment::now();
    let runtime_now = if policy_case(selected) {
        frozen_moment()
    } else {
        wall_now
    };
    let missing = matches!(
        selected,
        "missing-capability" | "generic-password-is-not-user-pin"
    );
    let password = match selected {
        "generic-password-is-not-user-pin" => Some(USER_PIN.to_owned()),
        "pdf-password-wrong" => Some(USER_PIN.to_owned()),
        "pdf-password-correct" | "pdf-correct-user-pin-wrong" | "pdf-mac-correct" => {
            Some("ownersecret".to_owned())
        }
        _ => None,
    };
    // Historical policy controls retain the real hard-fail context; provide
    // authenticated recorded retrieval instead of weakening that requirement.
    // The missing-evidence case deliberately preserves the measured prior RED.
    let policy_crls = (policy_case(selected) && selected != "policy-missing-revinfo")
        .then(|| Arc::new(RecordedCrlSource::new(selected == "policy-bad-crl")));
    let fetchers = match &policy_crls {
        Some(source) => Fetchers {
            crl: Some(source.clone()),
            ..Fetchers::none()
        },
        None => Fetchers::none(),
    };
    let runtime = ValidationRuntime {
        now: runtime_now,
        fetchers,
        password,
        trusted_list_transport: None,
        pkcs11_signing_pin_prompt: None,
        pkcs11_user_pin_prompt: (!missing).then_some(capability),
    };
    // Never log the full runtime: generic password Debug is outside this scope.
    let mut argv = vec![
        "--config".into(),
        config_path.to_str().unwrap().into(),
        "sign".into(),
        "addsig".into(),
        "--field".into(),
        "Sig1".into(),
    ];
    if policy_case(selected) || selected == "unsupported-required-revinfo-policy" {
        argv.extend(["--validation-context".into(), "effective".into()]);
    }
    argv.extend([
        "pkcs11".into(),
        "--p11-setup".into(),
        if selected == "unknown-profile" {
            "unknown".into()
        } else {
            "test".into()
        },
        input.to_str().unwrap().into(),
        output_path.to_str().unwrap().into(),
    ]);
    let result = sigis_cli::run_with_runtime(&argv, &PluginRegistry::default(), &runtime);
    let after_maps = fs::read_to_string("/proc/self/maps").unwrap();
    let expected_requests = if missing || earlier_refusal(selected) || credential_override(selected)
    {
        0
    } else {
        1
    };
    if matches!(selected, "policy-positive" | "policy-match-any") {
        let source = policy_crls.as_ref().unwrap();
        let requests = source.requests.lock().unwrap();
        for target in [&source.leaf_der, &source.interm_der] {
            assert!(
                requests.iter().any(|request| request == target),
                "The actual complete policy path must consume recorded revocation evidence"
            );
        }
    }
    if selected == "policy-bad-crl" {
        assert!(
            !policy_crls
                .as_ref()
                .unwrap()
                .requests
                .lock()
                .unwrap()
                .is_empty(),
            "Bad CRL must reach authenticated revocation validation, not a fixture failure"
        );
    }
    assert_eq!(
        callbacks.load(Ordering::SeqCst),
        expected_requests,
        "Unexpected prompt role/phase for {selected}"
    );
    assert!(labels
        .lock()
        .unwrap()
        .iter()
        .all(|label| label == USER_LABEL));
    for (path, before) in [
        (&input, input_before),
        (&config_path, config_before),
        (&interm, interm_before),
        (&unrelated, sentinel_before),
    ] {
        assert_eq!(
            (path.canonicalize().unwrap(), fs::read(path).unwrap()),
            before,
            "The CLI must preserve caller input/config/sentinel"
        );
    }
    for secret in [
        USER_PIN,
        WRONG_USER_PIN,
        "ownersecret",
        "unsupported-context-specific-fixture",
    ] {
        assert!(
            !result.stdout.contains(secret) && !result.stderr.contains(secret),
            "Product diagnostics exposed a fixture credential"
        );
    }
    if positive(selected) {
        assert_eq!(
            result.code,
            0,
            "Real prompt signing must succeed; inspect {}",
            case.display()
        );
        assert!(
            after_maps.contains(module.to_str().unwrap()),
            "Actual body must map the selected real software provider"
        );
        assert!(
            output_path.is_file(),
            "Successful original must publish an actual PDF"
        );
        let mut expected_entries = entries_before;
        expected_entries.push("output.pdf".into());
        expected_entries.sort();
        assert_eq!(names(&cwd), expected_entries);
        let signed = fs::read(&output_path).unwrap();
        let validation = verify_output(
            &case,
            &signed,
            wall_now,
            encrypted.then_some("ownersecret"),
            expected_mac,
        );
        differential_output(
            &case,
            wall_now,
            encrypted.then_some("ownersecret"),
            expected_mac,
            &validation,
        );
    } else {
        assert_eq!(
            result.code,
            1,
            "Mandatory negative must refuse; inspect {}",
            case.display()
        );
        assert_eq!(
            fs::read(&output_path).unwrap(),
            SENTINEL,
            "A refusal must preserve the caller-owned output"
        );
        assert_eq!(
            names(&cwd),
            entries_before,
            "A refusal must not create other output files"
        );
        let diagnostic = format!("{}{}", result.stdout, result.stderr);
        assert_component(selected, &diagnostic);
        if before_provider_refusal(selected) {
            assert!(
                !after_maps.contains(module.to_str().unwrap()),
                "Early failure must not map the real module"
            );
            assert!(
                !diagnostic.contains("must-not-load-provider"),
                "Earlier guard must win over module loading"
            );
        }
        if matches!(
            selected,
            "wrong-pin"
                | "pdf-correct-user-pin-wrong"
                | "configured-pin-wrong"
                | "environment-pin-wrong"
        ) {
            assert!(
                after_maps.contains(module.to_str().unwrap()),
                "Wrong nonempty PIN must reach fresh real provider authentication"
            );
        }
    }
    eprintln!("PKCS11 prompt case completed: {selected}");
}

fn assert_component(selected: &str, message: &str) {
    let lower = message.to_ascii_lowercase();
    let components: &[&str] = match selected {
        "missing-capability" | "generic-password-is-not-user-pin" => {
            &["unsupported pkcs#11 signing requirement", "user pin prompt"]
        }
        "unavailable" => &["pkcs#11 user pin is unavailable"],
        "cancelled" => &["pkcs#11 user pin request was cancelled"],
        "wrong-pin"
        | "pdf-correct-user-pin-wrong"
        | "configured-pin-wrong"
        | "environment-pin-wrong" => &["pin"],
        "signing-pin-mode" | "configured-signing-pin" | "environment-signing-pin" => {
            &["context-specific signing pin"]
        }
        "unknown-profile" => &["error while reading pkcs#11 config"],
        "unknown-token-criterion" => &["unsupported pkcs#11 token-criteria setting"],
        "nonboolean-requirement" => &["must be a boolean"],
        "signature-mechanism" => &["explicit asn.1 signature-mechanism"],
        "missing-resident-intermediate" => &["absent-certificate-label"],
        // Typed named lookup loads files before native_setup and preserves the
        // existing frontend's config-error component, not its internal path.
        "missing-file-intermediate" => &["error while reading pkcs#11 config"],
        "decode-limit" => &["decod", "limit"],
        "strict-reader" => &["xref"],
        "pdf-password-missing" => &["pdf decryption password prompt"],
        "pdf-password-wrong" => &["invalid password"],
        "policy-match-all" => &[
            "active key usage policy requires the key usage extensions",
            "crl sign",
            "non repudiation",
        ],
        "policy-forbidden" => &["active key usage policy explicitly bans", "non repudiation"],
        "policy-explicit-eku" => &["requires an extended key usage extension"],
        "policy-empty-roots" => &["validat"],
        "policy-missing-revinfo" => &["revocation information"],
        "policy-bad-crl" => &["crl signature could not be verified"],
        "unsupported-required-revinfo-policy" => &["unknown setting", "revocation-policy"],
        _ => panic!("No exact diagnostic component for {selected}"),
    };
    for component in components {
        assert!(
            lower.contains(component),
            "Wrong refusal phase for {selected}; required {component}; got {message}"
        );
    }
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

fn status_record(result: &PkiResult<PdfSignatureStatus>) -> Value {
    match result {
        Ok(status) => {
            json!({"outcome":"status","intact":status.cms.signature.intact,"valid":status.cms.signature.valid,"trusted":status.cms.signature.trusted(),"bottom_line":status.bottom_line(),"coverage":format!("{:?}",status.coverage),"signer_sha256":status.cms.signature.signing_cert.as_ref().map(|c|sha(c.der())),"path_sha256":status.cms.signature.validation_path.as_ref().map(|p|p.certs().into_iter().map(|c|sha(c.der())).collect::<Vec<_>>()),"path_length":status.cms.signature.validation_path.as_ref().map(|p|p.len()),"claimed_signing_time":status.cms.signer_reported_dt.map(|t|t.unix_secs()),"trust_problem":format!("{:?}",status.cms.signature.trust_problem),"trust_problem_indic":format!("{:?}",status.cms.signature.trust_problem_indic)})
        }
        Err(error) => json!({"outcome":"error","error":error.to_string()}),
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

fn mac_document() -> Vec<u8> {
    use sigis_pdf::lopdf::{Dictionary, Object};
    let mut writer = sigis_pdf::PdfFileWriter::new(false, true).unwrap();
    let mut page = Dictionary::new();
    page.set("Type", Object::Name(b"Page".to_vec()));
    page.set(
        "MediaBox",
        Object::Array(vec![0.into(), 0.into(), 595.into(), 842.into()]),
    );
    writer.insert_page(page, None).unwrap();
    writer
        .encrypt_with(
            "ownersecret",
            None,
            sigis_pdf::crypt::StandardEncryptOptions {
                compat_entries: false,
                ..Default::default()
            },
        )
        .unwrap();
    writer.write().unwrap()
}

fn assert_mac_good(pdf: &sigis_pdf::PdfFile, password: &str) -> Value {
    let authentication = pdf.decrypt(password).unwrap();
    assert_ne!(authentication.status, sigis_pdf::crypt::AuthStatus::Failed);
    assert_eq!(
        authentication.mac_status,
        sigis_pdf::crypt::PdfMacStatus::Successful
    );
    let root = pdf.root().unwrap();
    let extensions = pdf.get_dict(&root, b"Extensions").unwrap().unwrap();
    let iso = pdf.get_array(&extensions, b"ISO_").unwrap().unwrap();
    assert!(iso.iter().any(|extension| {
        pdf.resolve(extension)
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"ExtensionLevel")
            .unwrap()
            .as_i64()
            .unwrap()
            == 32004
    }));
    json!({"authentication":format!("{:?}", authentication.status),"mac_status":format!("{:?}",authentication.mac_status),"ISO_32004_extension":true})
}

fn mutation_record(bytes: &[u8], password: Option<&str>, trusted: &ValidationContext) -> Value {
    let pdf = match sigis_pdf::PdfFile::parse(bytes) {
        Ok(pdf) => pdf,
        Err(error) => return json!({"outcome":"parse_refusal","error":error.to_string()}),
    };
    let authentication = if let Some(password) = password {
        match pdf.decrypt(password) {
            Ok(authentication) => {
                let record = json!({"authentication":format!("{:?}",authentication.status),"mac_status":format!("{:?}",authentication.mac_status)});
                if authentication.status == sigis_pdf::crypt::AuthStatus::Failed
                    || authentication.mac_status == sigis_pdf::crypt::PdfMacStatus::Failed
                {
                    return json!({"outcome":"authentication_or_MAC_refusal","authentication":record});
                }
                Some(record)
            }
            Err(error) => {
                return json!({"outcome":"authentication_error","error":error.to_string()})
            }
        }
    } else {
        None
    };
    let changed = match pdf.embedded_signatures() {
        Ok(signatures) => signatures,
        Err(error) => {
            return json!({"outcome":"signature_parse_refusal","error":error.to_string(),"authentication":authentication})
        }
    };
    assert_eq!(changed.len(), 1);
    let mutation = sigis_pades::validate_pdf_signature(
        &pdf,
        &changed[0],
        trusted,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    );
    if let Ok(status) = &mutation {
        assert!(
            !status.cms.signature.intact && !status.bottom_line(),
            "A changed signed byte must break document integrity and acceptance"
        );
    }
    json!({"authentication":authentication,"validation":status_record(&mutation)})
}

fn verify_output(
    case: &Path,
    bytes: &[u8],
    now: Moment,
    password: Option<&str>,
    expected_mac: bool,
) -> Value {
    let root_bytes = fs::read(fixture_dir().join("root.der")).unwrap();
    let interm_bytes = fs::read(fixture_dir().join("interm.der")).unwrap();
    let signer_bytes = fs::read(fixture_dir().join("signer1.der")).unwrap();
    let root = Cert::from_der(&root_bytes).unwrap();
    let pdf = sigis_pdf::PdfFile::parse(bytes).unwrap();
    if let Some(password) = password {
        assert!(
            pdf.encrypted(),
            "Authenticated encrypted signing must retain document encryption"
        );
        assert_ne!(
            pdf.decrypt(password).unwrap().status,
            sigis_pdf::crypt::AuthStatus::Failed
        );
    }
    let output_mac = expected_mac.then(|| {
        assert_mac_good(
            &pdf,
            password.expect("MAC output needs its distinct document credential"),
        )
    });
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
    // Original immutable leaf expired in 2022: actual wall NOW must deny.
    assert_denied(&actual_now);
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
    fs::write(case.join("modified-signed-byte.pdf"), &modified).unwrap();
    let mutation = mutation_record(&modified, password, &trusted);
    json!({"original_clock":status_record(&result),"original_clock_moment":moment.unix_secs(),"original_clock_empty_roots":status_record(&empty),"actual_NOW_moment":now.unix_secs(),"actual_NOW":status_record(&actual_now),"actual_NOW_empty_roots":status_record(&now_empty),"modified_signed_byte":mutation,"cms_embedded_certificate_count":cms.certificates.len(),"full_validation_path_required_length":3,"output_pdf_mac":output_mac,"clock_scope":"Original fixture2020-11-01 and actual native CLI NOW are separate; NOW denial is preserved, never retimed away"})
}

/// Every successful real native output must pass a fresh pinned Python peer.
/// JSON is temporary test IPC and is removed with the private case directory.
fn differential_output(
    case: &Path,
    now: Moment,
    password: Option<&str>,
    expect_mac: bool,
    native: &Value,
) {
    let request = case.join("validation-request.json");
    write_oracle_request(
        &request,
        &json!({
            "cases":[{"label":"output","pdf":case.join("cli-cwd/output.pdf"),
                "modified_pdf":case.join("modified-signed-byte.pdf"),"password":password,"expect_mac":expect_mac}],
            "moments":[frozen_moment().to_string(),now.to_string()],"assert_frozen_positive":true
        }),
    );
    let output = Command::new(oracle_python())
        .args(["-B", "-s", "-P"])
        .arg(fixture_dir().join("validate_outputs.py"))
        .arg(&request)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONNOUSERSITE", "1")
        .env_remove("PYTHONPATH")
        .env_remove("PYHANKO_PKCS11_PIN")
        .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .stdin(Stdio::null())
        .output()
        .expect("The pinned pyHanko oracle is mandatory");
    assert!(
        output.status.success(),
        "Fresh same-output pyHanko validation failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let peer: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(peer["runtime"]["packages"]["pyhanko"], "0.38.1");
    assert_eq!(peer["runtime"]["assertions_enabled"], true);
    assert_eq!(peer["runtime"]["optimize"], 0);
    let rows = peer["statuses"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        8,
        "Both clocks, root selections and original/changed bytes are mandatory"
    );
    let output_sha = Value::String(sha(&fs::read(case.join("cli-cwd/output.pdf")).unwrap()));
    let modified_sha = Value::String(sha(
        &fs::read(case.join("modified-signed-byte.pdf")).unwrap()
    ));
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["label"], "output");
        assert_eq!(row["modified"], index % 4 >= 2);
        assert_eq!(row["explicit_root"], index % 2 == 0);
        assert_eq!(
            Moment::parse_rfc3339(row["moment"].as_str().unwrap()).unwrap(),
            if index < 4 { frozen_moment() } else { now }
        );
        assert_eq!(
            &row["pdf_sha256"],
            if index % 4 >= 2 {
                &modified_sha
            } else {
                &output_sha
            }
        );
        // Python-only changed-byte/NOW/empty-root rows remain refusals too.
        if !matches!(index, 0 | 4) {
            assert_ne!(row["status"]["bottom_line"], true);
        }
    }
    for (profile, index) in [
        ("original_clock", 0),
        ("original_clock_empty_roots", 1),
        ("actual_NOW", 4),
        ("actual_NOW_empty_roots", 5),
        ("modified_signed_byte", 2),
    ] {
        let value = &native[profile];
        let value = value.get("validation").unwrap_or(value);
        let status = &rows[index]["status"];
        assert_eq!(
            value["bottom_line"].as_bool().unwrap_or(false),
            status["bottom_line"].as_bool().unwrap_or(false),
            "Acceptance differs for {profile}"
        );
        for field in ["intact", "valid", "trusted", "bottom_line", "signer_sha256"] {
            if let (Some(actual), Some(expected)) = (value.get(field), status.get(field)) {
                assert_eq!(actual, expected, "Available {field} differs for {profile}");
            }
        }
        if profile == "original_clock" {
            assert_eq!(value["path_sha256"], status["path_sha256"]);
        }
    }
}
