//! Direct schema port of pinned pkcs11_utils/{config,fixtures}.py.
//! No provider or credential defaults, software substitution or token mutation.
//! Missing configured rows/mechanisms are explicit failures if manually selected,
//! rather than successful bodies; normal harness runs retain ten hardware ignores.
use serde::Deserialize;
use sigis_cli::{
    plugins::PluginRegistry,
    runtime::{Pkcs11SigningPinPrompt, Pkcs11UserPinPrompt, ValidationRuntime},
};
use sigis_pades_sign::pkcs11::{
    cryptoki::object::{Attribute, AttributeType, ObjectClass},
    open_pkcs11_session, Pkcs11Session, TokenCriteria, UserPin,
};
use sigis_pki_certvalidator::context::ValidationContext;
use sigis_pki_core::{
    algorithms::DisallowWeakAlgorithmsPolicy, cert::Cert, fetch::Fetchers, time::Moment,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

const CHILD: &str = "SIGIS_PKCS11_HARDWARE_ORIGINAL_CHILD";
const ROOT: &str = "SIGIS_PKCS11_HARDWARE_ORIGINAL_DIRECTORY";
const USER: &str = "SIGIS_PKCS11_HARDWARE_ORIGINAL_USER";
const SIGN: &str = "SIGIS_PKCS11_HARDWARE_ORIGINAL_SIGN";

#[derive(Deserialize)]
struct Platform {
    configs: BTreeMap<String, Profile>,
    default: String,
}

// Field names deliberately retain the underscore spelling of PKCS11_CONFIG,
// not the hyphenated spelling of the generated production CLI YAML.
#[derive(Deserialize)]
struct Profile {
    module: String,
    token_label: Option<String>,
    user_pin_env_var: String,
    signing_pin_env_var: Option<String>,
    cert_label: String,
    key_label: Option<String>,
    #[serde(default)]
    cert_chain: Vec<PathBuf>,
    #[serde(default)]
    cert_chain_labels: Vec<String>,
    freeze_time_spec: Option<String>,
}

struct Selected {
    profile: Profile,
    config_directory: PathBuf,
    user_pin: String,
    signing_pin: Option<String>,
}

fn selected(algorithm: &str) -> Selected {
    assert!(
        std::env::var("PKCS11_PLATFORMS")
            .unwrap_or_default()
            .split(',')
            .any(|platform| platform == "safenet"),
        "Set PKCS11_PLATFORMS=safenet as required by the original platform fixture"
    );
    let path = PathBuf::from(std::env::var_os("PKCS11_CONFIG").expect(
        "SafeNet provider not configured: explicit actual PKCS11_CONFIG and credential environment required",
    ));
    let path = path
        .canonicalize()
        .expect("PKCS11_CONFIG must name a readable real configuration");
    let mut platforms: BTreeMap<String, Platform> =
        serde_yaml::from_slice(&fs::read(&path).expect("Cannot read PKCS11_CONFIG"))
            .expect("PKCS11_CONFIG must use the original platform/configs schema");
    let mut platform = platforms
        .remove("safenet")
        .expect("PKCS11_CONFIG has no safenet platform; a software provider is not a substitute");
    assert!(
        platform.configs.contains_key(&platform.default),
        "Original default config alias is unresolved"
    );
    let profile = platform.configs.remove(algorithm).unwrap_or_else(|| {
        panic!(
            "Original availability exclusion: no safenet config for {algorithm}; no body executed"
        )
    });
    assert!(
        Path::new(&profile.module).is_absolute(),
        "An explicit absolute hardware module path is required for isolated test execution"
    );
    assert!(
        Path::new(&profile.module).is_file(),
        "Configured hardware module is unavailable"
    );
    assert!(
        !profile.module.to_ascii_lowercase().contains("softhsm"),
        "SafeNet original must not use the private SoftHSM fixture"
    );
    let child = std::env::var_os(CHILD).is_some();
    let user_pin = std::env::var(if child {
        USER
    } else {
        &profile.user_pin_env_var
    })
    .expect("Configured USER credential environment is missing");
    let signing_pin = profile.signing_pin_env_var.as_ref().map(|name| {
        std::env::var(if child { SIGN } else { name })
            .expect("Configured signing credential environment is missing")
    });
    Selected {
        profile,
        config_directory: path.parent().unwrap().to_path_buf(),
        user_pin,
        signing_pin,
    }
}

pub fn run(name: &str, algorithm: &str, environment: bool) {
    let selected = selected(algorithm); // Parsing only; no provider work in parent.
    if std::env::var(CHILD).as_deref() == Ok(name) {
        let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
        body(&root, algorithm, environment, selected);
        eprintln!("SafeNet original body completed: {name}");
        return;
    }
    assert!(
        std::env::var_os(CHILD).is_none(),
        "Unexpected selected hardware child"
    );
    let directory = tempfile::tempdir().unwrap();
    let executable = if cfg!(target_os = "linux") {
        PathBuf::from("/proc/self/exe")
    } else {
        std::env::current_exe().unwrap()
    };
    let mut command = Command::new(executable);
    command
        .args([
            "--exact",
            name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, name)
        .env(ROOT, directory.path())
        // Preserve already selected fixture credentials when a profile's input
        // env-var name happens to be one of the production vars cleared below.
        .env(USER, &selected.user_pin)
        .env_remove(SIGN)
        .env_remove("PYHANKO_PKCS11_PIN")
        .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .stdin(Stdio::null());
    if let Some(pin) = &selected.signing_pin {
        command.env(SIGN, pin);
    }
    if environment {
        command.env("PYHANKO_PKCS11_PIN", &selected.user_pin);
        if let Some(pin) = &selected.signing_pin {
            command.env("PYHANKO_PKCS11_SIGNING_PIN", pin);
        }
    }
    let output = command.output().unwrap();
    let marker = format!("SafeNet original body completed: {name}");
    let completed = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| *line == marker)
        .count();
    fs::write(directory.path().join("child.stdout.log"), output.stdout).unwrap();
    fs::write(directory.path().join("child.stderr.log"), output.stderr).unwrap();
    if !output.status.success() || completed != 1 {
        panic!(
            "Real SafeNet original failed; inspect {}",
            directory.keep().display()
        );
    }
}

fn certificate(session: &Pkcs11Session, label: &str) -> Cert {
    let objects = session
        .find_objects(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .unwrap();
    assert_eq!(
        objects.len(),
        1,
        "Actual certificate label must select exactly one object"
    );
    let attrs = session
        .with(|s| Ok(s.get_attributes(objects[0], &[AttributeType::Value])?))
        .unwrap();
    let der = attrs
        .into_iter()
        .find_map(|value| match value {
            Attribute::Value(bytes) => Some(bytes),
            _ => None,
        })
        .expect("Actual certificate object must expose its public DER");
    Cert::from_der(&der).expect("Token certificate DER must parse")
}

fn signing_moment(profile: &Profile) -> Moment {
    match profile.freeze_time_spec.as_deref() {
        None => Moment::now(), // Exactly the upstream non-frozen profile branch.
        Some(value) => {
            let value = if value.len() == 10 {
                format!("{value}T00:00:00Z")
            } else {
                value.into()
            };
            Moment::parse_rfc3339(&value)
                .expect("Unsupported explicit fixture freeze_time_spec; do not replace its clock")
        }
    }
}

fn body(root: &Path, algorithm: &str, environment: bool, selected: Selected) {
    let profile = &selected.profile;
    let criteria = profile.token_label.as_ref().map(TokenCriteria::label);
    let session = open_pkcs11_session(
        &profile.module,
        None,
        criteria.as_ref(),
        &UserPin::Pin(selected.user_pin.clone()),
    )
    .expect("Actual configured token USER authentication must succeed");
    let required = match algorithm {
        "rsa" => 0x40,
        "ecdsa" => 0x1044,
        "ed25519" | "ed448" => 0x1057,
        "mldsa" => 0x1d,
        _ => unreachable!("Only the original five fixture labels are collected"),
    };
    assert!(
        session.mechanisms().unwrap().contains(&required),
        "Original availability exclusion: selected token lacks the required mechanism; no signing body accepted"
    );
    let chain = if profile.cert_chain.is_empty() {
        profile
            .cert_chain_labels
            .iter()
            .map(|label| certificate(&session, label))
            .collect::<Vec<_>>()
    } else {
        profile
            .cert_chain
            .iter()
            .map(|path| {
                let path = if path.is_absolute() {
                    path.clone()
                } else {
                    selected.config_directory.join(path)
                };
                Cert::from_pem_or_der(
                    &fs::read(path)
                        .expect("Original configured certificate chain file must be readable"),
                )
                .expect("Original certificate chain file must parse")
            })
            .collect::<Vec<_>>()
    };
    assert!(
        chain.len() >= 2 && profile.cert_chain_labels.len() >= 2,
        "Original helper requires root/intermediate material and resident labels"
    );
    let signer = certificate(&session, &profile.cert_label);
    let key_label = profile.key_label.as_ref().unwrap_or(&profile.cert_label);
    assert_eq!(
        session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(key_label.as_bytes().to_vec()),
            ])
            .unwrap()
            .len(),
        1,
        "Actual original key selector must resolve a resident handle"
    );
    // The original fixture's authenticated readback closes before CLI execution.
    session
        .with(|s| {
            s.logout()?;
            Ok(())
        })
        .unwrap();
    drop(session);
    let root_der = chain[0].der().to_vec();
    let intermediate_der = chain[1].der().to_vec();
    let signer_der = signer.der().to_vec();
    let root_path = root.join("root.der");
    fs::write(&root_path, &root_der).unwrap();
    let intermediate = root.join("interm.crt");
    fs::write(&intermediate, &intermediate_der).unwrap();
    let input = root.join("input.pdf");
    let output = root.join("output.pdf");
    let config_path = root.join("pyhanko.yml");
    let input_bytes = fs::read(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])).unwrap();
    fs::write(&input, &input_bytes).unwrap();
    let mut setup = serde_json::json!({
        "module-path": profile.module,
        "token-criteria": {"label": profile.token_label},
        "cert-label": profile.cert_label,
        "key-label": profile.key_label,
        "other-certs-to-pull": profile.cert_chain_labels[1],
        "other-certs": intermediate,
    });
    // Exact original condition: absent configured signing PIN leaves the mode
    // unchanged. Environment signing PIN selection belongs to production.
    if !environment && selected.signing_pin.is_some() {
        setup["signing-pin-mode"] = serde_json::json!("prompt");
    }
    let config =
        serde_json::to_string(&serde_json::json!({"pkcs11-setups": {"test": setup}})).unwrap();
    fs::write(&config_path, &config).unwrap();
    let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let user_events = events.clone();
    let sign_events = events.clone();
    let user_pin = selected.user_pin.clone();
    let signing_pin = selected.signing_pin.clone();
    let now = signing_moment(profile);
    let runtime = ValidationRuntime {
        now,
        fetchers: Fetchers::none(),
        pkcs11_user_pin_prompt: (!environment).then(|| {
            Pkcs11UserPinPrompt::new(move |label| {
                assert_eq!(label, "PKCS#11 user PIN: ");
                user_events.lock().unwrap().push("USER");
                Ok(user_pin.clone())
            })
        }),
        pkcs11_signing_pin_prompt: (!environment).then(|| {
            Pkcs11SigningPinPrompt::new(move |label| {
                assert_eq!(label, "PKCS#11 signing PIN: ");
                sign_events.lock().unwrap().push("SIGN");
                Ok(signing_pin
                    .clone()
                    .expect("Original must not request a signing PIN when none is configured"))
            })
        }),
        ..Default::default()
    };
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
        input.display().to_string(),
        output.display().to_string(),
    ];
    let result = sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &runtime);
    assert_eq!(fs::read(&input).unwrap(), input_bytes);
    assert_eq!(fs::read_to_string(&config_path).unwrap(), config);
    assert_eq!(fs::read(&intermediate).unwrap(), intermediate_der);
    // Never include hardware credentials in a failure message or child transcript.
    for pin in std::iter::once(&selected.user_pin)
        .chain(selected.signing_pin.iter())
        .filter(|pin| !pin.is_empty())
    {
        assert!(
            !result.stdout.contains(pin.as_str()) && !result.stderr.contains(pin.as_str()),
            "CLI diagnostics must not expose credentials"
        );
    }
    if result.code != 0 {
        assert!(
            !output.exists(),
            "Failed hardware signing must not publish output"
        );
    }
    assert_eq!(
        result.code, 0,
        "Configured hardware original must sign; inspect nonsecret CLI status (exit {})",
        result.code
    );
    assert!(
        output.is_file(),
        "A successful original must publish an actual signed PDF"
    );
    let events = events.lock().unwrap();
    if environment {
        assert!(
            events.is_empty(),
            "Production environment PINs must not use prompt capabilities"
        );
    } else {
        assert_eq!(events.first(), Some(&"USER"));
        assert_eq!(events.iter().filter(|event| **event == "USER").count(), 1);
        let sign_calls = events.iter().filter(|event| **event == "SIGN").count();
        if selected.signing_pin.is_some() {
            assert!(sign_calls >= 1);
        } else {
            assert_eq!(sign_calls, 0);
        }
    }
    // Pinned P11TestConfig.validation_context has a distinct clock quirk:
    // ANY configured signing freeze selects 2020-11-01 for validation, even
    // when freeze_time_spec requested another signing date. Keep both clocks;
    // the absence of a freeze instead validates at the actual current time.
    let validation_now = if profile.freeze_time_spec.is_some() {
        Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap()
    } else {
        Moment::now()
    };
    verify_pdf(
        &fs::read(&output).unwrap(),
        &chain,
        &signer_der,
        validation_now,
    );
    let other_paths = chain
        .iter()
        .enumerate()
        .skip(1)
        .map(|(index, cert)| {
            let path = root.join(format!("validation-other-{index}.der"));
            fs::write(&path, cert.der()).unwrap();
            path
        })
        .collect::<Vec<_>>();
    peer(&output, &root_path, &other_paths, validation_now, root);
}

fn context(root: Option<Cert>, others: &[Cert], now: Moment) -> ValidationContext {
    let mut builder = ValidationContext::builder()
        .moment(now)
        .point_in_time_validation(false)
        .time_tolerance(Duration::from_secs(1))
        .revocation_mode("soft-fail")
        // This original fixture's local policy also applies to any DSA issuer
        // path. The global default threshold remains 3192.
        .algorithm_policy(Arc::new(DisallowWeakAlgorithmsPolicy {
            dsa_key_size_threshold: 1024,
            ..Default::default()
        }));
    for cert in others {
        builder = builder.other_cert(cert.clone());
    }
    match root {
        Some(root) => builder.trust_root(root).build().unwrap(),
        None => builder.build().unwrap(),
    }
}

fn verify_pdf(bytes: &[u8], chain: &[Cert], signer: &[u8], now: Moment) {
    let root = chain[0].clone();
    let others = &chain[1..];
    let pdf = sigis_pdf::PdfFile::parse(bytes).unwrap();
    let signatures = pdf.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let signature = &signatures[0];
    assert_eq!(signature.field_name, "Sig1");
    let status = sigis_pades::validate_pdf_signature(
        &pdf,
        signature,
        &context(Some(root.clone()), others, now),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    )
    .unwrap();
    assert!(
        status.cms.signature.intact
            && status.cms.signature.valid
            && status.cms.signature.trusted()
            && status.bottom_line(),
        "Full status must succeed"
    );
    assert_eq!(
        status.coverage,
        sigis_pades::SignatureCoverageLevel::EntireFile
    );
    assert_eq!(
        status.cms.signature.signing_cert.as_ref().unwrap().der(),
        signer
    );
    assert_eq!(
        status
            .cms
            .signature
            .validation_path
            .as_ref()
            .unwrap()
            .certs()
            .iter()
            .map(|cert| cert.der().to_vec())
            .collect::<Vec<_>>(),
        chain
            .iter()
            .map(|cert| cert.der().to_vec())
            .chain(std::iter::once(signer.to_vec()))
            .collect::<Vec<_>>()
    );
    if let Ok(empty) = sigis_pades::validate_pdf_signature(
        &pdf,
        signature,
        &context(None, others, now),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    ) {
        assert!(!empty.cms.signature.trusted() && !empty.bottom_line());
    }
    let mut changed = bytes.to_vec();
    changed[7] = if changed[7] == b'7' { b'6' } else { b'7' };
    let changed_pdf = sigis_pdf::PdfFile::parse(&changed).unwrap();
    let changed_signatures = changed_pdf.embedded_signatures().unwrap();
    if let Ok(tampered) = sigis_pades::validate_pdf_signature(
        &changed_pdf,
        &changed_signatures[0],
        &context(Some(root), others, now),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    ) {
        assert!(!tampered.cms.signature.intact && !tampered.bottom_line());
    }
}

const PEER: &str = r#"
from datetime import datetime
from io import BytesIO
from pathlib import Path
import sys
from asn1crypto import x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.policy_decl import DisallowWeakAlgorithmsPolicy
raw, root = Path(sys.argv[1]).read_bytes(), x509.Certificate.load(Path(sys.argv[2]).read_bytes(), strict=True)
now = datetime.fromisoformat(sys.argv[3].replace('Z', '+00:00'))
others = [x509.Certificate.load(Path(p).read_bytes(), strict=True) for p in sys.argv[4:]]
def vc(roots):
    return ValidationContext(trust_roots=roots, other_certs=others, moment=now, allow_fetching=False,
                             algorithm_usage_policy=DisallowWeakAlgorithmsPolicy(dsa_key_size_threshold=1024))
signature = PdfFileReader(BytesIO(raw)).embedded_signatures[0]
assert signature.field_name == 'Sig1'
status = validate_pdf_signature(signature, vc([root]))
assert status.intact and status.valid and status.trusted and status.bottom_line
assert status.coverage.name == 'ENTIRE_FILE'
assert [c.dump() for c in status.validation_path] == [root.dump(), *[c.dump() for c in others], signature.signer_cert.dump()]
empty = validate_pdf_signature(signature, vc([]))
assert not empty.trusted and not empty.bottom_line
changed = bytearray(raw)
changed[7] = ord('6') if changed[7] == ord('7') else ord('7')
status = validate_pdf_signature(PdfFileReader(BytesIO(changed)).embedded_signatures[0], vc([root]))
assert not status.intact and not status.bottom_line
"#;

fn peer(output: &Path, root_cert: &Path, others: &[PathBuf], now: Moment, directory: &Path) {
    let mut command = Command::new(
        std::env::var("HANKO_ORACLE")
            .unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into()),
    );
    // The software completion peer uses the default DSA threshold and must
    // not replace this hardware fixture's explicit local 1024-bit policy.
    command.args(["-B", "-s", "-P", "-c", PEER]);
    command
        .arg(output)
        .arg(root_cert)
        .arg(now.to_string())
        .args(others);
    let result = command
        .env(
            "PYTHONPATH",
            std::env::var("SIGIS_PKCS11_ORACLE_OVERLAY").unwrap_or_else(|_| {
                "/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5".into()
            }),
        )
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    fs::write(directory.join("peer.stdout.log"), result.stdout).unwrap();
    fs::write(directory.join("peer.stderr.log"), result.stderr).unwrap();
    assert!(
        result.status.success(),
        "Pinned same-output hardware PDF peer failed"
    );
}
