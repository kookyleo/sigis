//! Dedicated test-client authority and fresh provider processes, never fixture login in the body.
use der::Encode;
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
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

const USER_PIN: &str = "1234";
const WRONG_USER_PIN: &str = "not-the-token-user-pin";
const USER_LABEL: &str = "PKCS#11 user PIN: ";
const ORIGINAL: &str =
    "pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_pin_prompt";
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
fn file(path: &Path) -> Value {
    let data = fs::read(path).unwrap();
    json!({"path":path.canonicalize().unwrap(),"length":data.len(),"sha256":sha(&data)})
}
fn save(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
fn running_executable() -> Value {
    use std::os::unix::fs::MetadataExt;
    let data = fs::read("/proc/self/exe").unwrap();
    let metadata = fs::metadata("/proc/self/exe").unwrap();
    json!({"read_path":"/proc/self/exe","declared_path":std::env::current_exe().unwrap(),"kernel_link":fs::read_link("/proc/self/exe").unwrap(),"device":metadata.dev(),"inode":metadata.ino(),"length":data.len(),"sha256":sha(&data),"pid":std::process::id()})
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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/data/lanes/r3-c/pkcs11-user-pin-prompt")
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
    evidence: Value,
    requests: Mutex<Vec<Value>>,
}

impl RecordedCrlSource {
    fn new(case: &Path, tampered: bool) -> Self {
        let mut evidence = Vec::new();
        let mut load = |filename: &str| {
            let path = fixture_dir().join(filename);
            let original = fs::read(&path).unwrap();
            let mut returned = original.clone();
            let last = returned
                .len()
                .checked_sub(1)
                .expect("Recorded CRL must not be empty");
            if tampered {
                // Preserve DER/TBS/algorithm bytes; flip one bit of the final
                // signature octet, without re-encoding or supplying any fallback.
                returned[last] ^= 1;
                fs::write(case.join(format!("tampered-{filename}")), &returned).unwrap();
            }
            evidence.push(json!({
                "source":file(&path),"original_sha256":sha(&original),
                "returned_sha256":sha(&returned),"returned_length":returned.len(),
                "signature_last_byte_bit_flipped":tampered,
                "mutated_byte_offset":tampered.then_some(last),
                "mutation_xor_mask":tampered.then_some(1),
            }));
            returned
        };
        let root_crl = load("policy-root.crl.der");
        let interm_crl = load("policy-interm.crl.der");
        Self {
            leaf_der: fs::read(fixture_dir().join("signer1.der")).unwrap(),
            interm_der: fs::read(fixture_dir().join("interm.der")).unwrap(),
            root_crl,
            interm_crl,
            evidence: json!({
                "manifest":file(&fixture_dir().join("policy-revinfo-manifest.json")),
                "CRLs":evidence,"tampered":tampered,
                "authority":"retrieval only; unchanged native CV checks signatures, scope and freshness",
            }),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn record(&self) -> Value {
        let requests = self.requests.lock().unwrap();
        json!({
            "evidence":self.evidence,"request_count":requests.len(),"requests":*requests,
            "expected_leaf_sha256":sha(&self.leaf_der),
            "expected_intermediate_sha256":sha(&self.interm_der),
            "no_issuer_certificates_or_anchors_added":true,
        })
    }
}

impl CrlFetcher for RecordedCrlSource {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        let (returned, issuer_role) = if cert.der() == self.leaf_der {
            (Some(&self.interm_crl), "actual intermediate issuer")
        } else if cert.der() == self.interm_der {
            (Some(&self.root_crl), "actual root issuer")
        } else {
            (None, "unsupported exact certificate")
        };
        self.requests.lock().unwrap().push(json!({
            "certificate_sha256":sha(cert.der()),
            "certificate_issuer_Name_DER_sha256":sha(&cert.issuer().to_der().expect("Original certificate issuer DER")),
            "selected_crl_issuer_role":issuer_role,
            "returned_sha256":returned.map(|bytes|sha(bytes)),
            "returned_lengths":returned.map(|bytes|bytes.len()),
        }));
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
    let archive = PathBuf::from(required("SIGIS_PKCS11_PROMPT_RECORD_DIR"));
    fs::create_dir_all(&archive).unwrap();
    let parent_elf = running_executable();
    for selected in selections {
        let case = tempfile::Builder::new()
            .prefix(&format!("{selected}-"))
            .tempdir_in(&archive)
            .unwrap()
            .keep();
        let cwd = case.join("cli-cwd");
        fs::create_dir(&cwd).unwrap();
        provision(&case);
        let mut command = Command::new("/proc/self/exe");
        command
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .current_dir(&cwd)
            .env("SIGIS_PKCS11_PROMPT_CHILD", test_name)
            .env("SIGIS_PKCS11_PROMPT_CASE", selected)
            .env("SIGIS_PKCS11_PROMPT_CASE_DIR", &case)
            .env(
                "SIGIS_PKCS11_PROMPT_PARENT_ELF_SHA256",
                parent_elf["sha256"].as_str().unwrap(),
            )
            .env("SOFTHSM2_CONF", case.join("provider/softhsm2.conf"))
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
        let stdout = case.join("child.stdout.bin");
        let stderr = case.join("child.stderr.bin");
        fs::write(&stdout, &output.stdout).unwrap();
        fs::write(&stderr, &output.stderr).unwrap();
        let receipt = case.join("receipt.json");
        let record = json!({"original":ORIGINAL,"case":selected,"effective_algorithm":"ed25519","parent_running_elf":parent_elf,"child_exit_code":output.status.code(),"child_stdout":file(&stdout),"child_stderr":file(&stderr),"child_receipt":receipt.exists().then(||file(&receipt)),"fixture_provisioning_completed_before_body_exec":true,"nested_summary_not_emitted":true});
        save(&case.join("parent-receipt.json"), &record);
        // Only paths/hashes/metadata; never nested captured libtest output.
        eprintln!("PKCS11_USER_PROMPT_CHILD {record}");
        assert!(
            output.status.success(),
            "Prompt case {selected} failed; inspect {}",
            case.display()
        );
        let receipt: Value = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        assert_eq!(
            receipt["actual_running_elf"]["sha256"],
            parent_elf["sha256"]
        );
        assert_eq!(receipt["case"], *selected);
    }
}

fn provision(case: &Path) {
    let provider = case.join("provider");
    assert!(
        !provider.exists(),
        "A prompt case must never reuse a token store"
    );
    let script = fixture_dir().join("provision_signing.py");
    let result = Command::new(required("HANKO_ORACLE"))
        .args(["-B", "-s", "-P"])
        .arg(&script)
        .arg(&provider)
        .env("PYTHONPATH", required("SIGIS_PKCS11_ORACLE_OVERLAY"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONNOUSERSITE", "1")
        .env_remove("SOFTHSM2_CONF")
        .env_remove("PKCS11_CONFIG")
        .env_remove("PYHANKO_PKCS11_PIN")
        .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    fs::write(case.join("provision.stdout.bin"), &result.stdout).unwrap();
    fs::write(case.join("provision.stderr.bin"), &result.stderr).unwrap();
    save(
        &case.join("provision-process.json"),
        &json!({"script":file(&script),"exit_code":result.status.code(),"stdout":file(&case.join("provision.stdout.bin")),"stderr":file(&case.join("provision.stderr.bin")),"readback_process_completed":true,"receipt":provider.join("receipt.json")}),
    );
    assert!(
        result.status.success(),
        "Separate real provider provisioning/readback failed; inspect {}",
        case.display()
    );
    assert!(provider.join("receipt.json").is_file());
    assert!(provider.join("softhsm2.conf").is_file());
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
    let elf = running_executable();
    assert_eq!(
        elf["sha256"].as_str(),
        Some(required("SIGIS_PKCS11_PROMPT_PARENT_ELF_SHA256").as_str())
    );
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
    let module = PathBuf::from(required("SIGIS_PKCS11_SIGNING_MODULE"))
        .canonicalize()
        .unwrap();
    let utility = PathBuf::from(required("SIGIS_PKCS11_SIGNING_UTILITY"))
        .canonicalize()
        .unwrap();
    let module_before = file(&module);
    let utility_before = file(&utility);
    let conf = case.join("provider/softhsm2.conf");
    assert_eq!(PathBuf::from(required("SOFTHSM2_CONF")), conf);
    let fixture: Value =
        serde_json::from_slice(&fs::read(case.join("provider/receipt.json")).unwrap()).unwrap();
    let initial_maps = fs::read_to_string("/proc/self/maps").unwrap();
    assert!(
        !initial_maps.contains(module.to_str().unwrap()),
        "Fresh body must not inherit fixture module/login state"
    );
    fs::write(case.join("body-initial-maps.txt"), &initial_maps).unwrap();
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
    let input_mac = expected_mac.then(|| {
        let pdf = sigis_pdf::PdfFile::parse(&fs::read(&input).unwrap()).unwrap();
        assert_mac_good(&pdf, "ownersecret")
    });
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
    let input_before = file(&input);
    let config_before = file(&config_path);
    let interm_before = file(&interm);
    let sentinel_before = file(&unrelated);
    let entries_before = names(&cwd);
    let output_before = output_path.exists().then(|| file(&output_path));
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
        .then(|| Arc::new(RecordedCrlSource::new(&case, selected == "policy-bad-crl")));
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
    // Test-client phase markers delimit actual production reads for an
    // independent syscall trace; they are not a product hook or FFI counter.
    fs::write(
        case.join("product-entry.begin"),
        b"production run_with_runtime begins\n",
    )
    .unwrap();
    let result = sigis_cli::run_with_runtime(&argv, &PluginRegistry::default(), &runtime);
    fs::write(
        case.join("product-entry.end"),
        b"production run_with_runtime returned\n",
    )
    .unwrap();
    fs::write(case.join("cli.stdout.bin"), result.stdout.as_bytes()).unwrap();
    fs::write(case.join("cli.stderr.bin"), result.stderr.as_bytes()).unwrap();
    let after_maps = fs::read_to_string("/proc/self/maps").unwrap();
    fs::write(case.join("body-final-maps.txt"), &after_maps).unwrap();
    let dsos: Vec<_> = after_maps
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|p| p.starts_with('/') && p.contains(".so"))
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>()
        .iter()
        .filter(|p| p.is_file())
        .map(|p| file(p))
        .collect();
    let expected_requests = if missing || earlier_refusal(selected) || credential_override(selected)
    {
        0
    } else {
        1
    };
    let native_cli = json!({"entry":"real sigis_cli::run_with_runtime in actual test-host ELF","argv":argv,"exit_code":result.code,"stdout":file(&case.join("cli.stdout.bin")),"stderr":file(&case.join("cli.stderr.bin")),
        "input_source":file(&input_source),"input_before":input_before,"input_after":file(&input),"config_before":config_before,"config_after":file(&config_path),"file_intermediate_before":interm_before,"file_intermediate_after":file(&interm),
        "sentinel_before":sentinel_before,"sentinel_after":file(&unrelated),"output_before":output_before,"output_after":output_path.exists().then(||file(&output_path)),"entries_before":entries_before,"entries_after":names(&cwd)});
    let mut record = json!({
        "original":ORIGINAL,"original_credit_scope":if selected.starts_with("positive-") { "one original; one of five labels" } else { "supplemental zero-ID" },
        "case":selected,"fixture_label":selected.strip_prefix("positive-"),"effective_algorithm":"ed25519","actual_running_elf":elf,
        "source_commit":required("SIGIS_PKCS11_PROMPT_SOURCE_COMMIT"),"host":fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),"slot":std::env::var_os("RUST_SLOTS_HELD"),
        "provider_fixture_receipt":file(&case.join("provider/receipt.json")),"provider_fixture":fixture,"provision_process":file(&case.join("provision-process.json")),
        "private_conf":file(&conf),"module_before":module_before,"module_after":file(&module),"utility_before":utility_before,"utility_after":file(&utility),
    });
    let operation_record = json!({
        "loaded_dsos":dsos,"initial_module_mapped":false,"final_module_mapped":after_maps.contains(module.to_str().unwrap()),
        "credential_source":if credential_override(selected) { "explicit configured/environment precedence supplemental; callback must not run" } else { "typed test-client USER-PIN callback; returned credential deliberately omitted" },"user_pin_env_present":environment_user_pin,
        "signing_pin_env_present":std::env::var_os("PYHANKO_PKCS11_SIGNING_PIN").is_some(),"callback_count":callbacks.load(Ordering::SeqCst),"callback_labels":*labels.lock().unwrap(),
        "native_cli":native_cli,
        "runtime_clock":runtime_now.unix_secs(),"actual_wall_NOW":wall_now.unix_secs(),"clock_scope":if policy_case(selected) { "supplemental historical policy control ONLY; not original NOW output" } else { "actual native wall NOW; original2020 validation separate" },
        "C_Sign_FFI_count":null,"body_fixture_login_performed":false,"input_pdf_mac":input_mac,"expected_output_pdf_mac":expected_mac,
        "policy_crl_fetcher":policy_crls.as_ref().map(|source|source.record()),
        "product_entry_begin":file(&case.join("product-entry.begin")),
        "product_entry_end":file(&case.join("product-entry.end")),
    });
    record
        .as_object_mut()
        .unwrap()
        .extend(operation_record.as_object().unwrap().clone());
    save(&case.join("receipt.json"), &record);
    if matches!(selected, "policy-positive" | "policy-match-any") {
        let source = policy_crls.as_ref().unwrap();
        let requests = source.requests.lock().unwrap();
        for target in [&source.leaf_der, &source.interm_der] {
            assert!(
                requests
                    .iter()
                    .any(|request| request["certificate_sha256"] == sha(target)),
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
        "Unexpected prompt role/phase; inspect receipt"
    );
    assert!(labels
        .lock()
        .unwrap()
        .iter()
        .all(|label| label == USER_LABEL));
    assert_eq!(record["module_before"], record["module_after"]);
    assert_eq!(record["utility_before"], record["utility_after"]);
    for prefix in ["input", "config", "file_intermediate", "sentinel"] {
        assert_eq!(
            record["native_cli"][format!("{prefix}_before")],
            record["native_cli"][format!("{prefix}_after")]
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
        record["native_cli"]["output"] = file(&output_path);
        record["validation"] = verify_output(
            &case,
            &signed,
            wall_now,
            encrypted.then_some("ownersecret"),
            expected_mac,
        );
        save(&case.join("receipt.json"), &record);
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
            "Wrong refusal phase for {selected}; required {component}; inspect captured diagnostic"
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
    json!({"original_clock":status_record(&result),"original_clock_moment":moment.unix_secs(),"original_clock_empty_roots":status_record(&empty),"actual_NOW_moment":now.unix_secs(),"actual_NOW":status_record(&actual_now),"actual_NOW_empty_roots":status_record(&now_empty),"modified_signed_byte":mutation,"modified_file":file(&case.join("modified-signed-byte.pdf")),"cms_embedded_certificate_count":cms.certificates.len(),"full_validation_path_required_length":3,"output_pdf_mac":output_mac,"clock_scope":"Original fixture2020-11-01 and actual native CLI NOW are separate; NOW denial is preserved, never retimed away"})
}
