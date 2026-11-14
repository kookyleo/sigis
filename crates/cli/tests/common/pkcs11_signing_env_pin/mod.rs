//! Real isolated Ed25519 token fixture and full-PDF checks, without a software signer.

use serde_json::{json, Value};
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
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

const USER_PIN: &str = "1234";
const ORIGINAL: &str =
    "pyhanko-cli/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_env_pin";

fn required(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("Required real signing fixture selector {name} is missing"))
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

fn running_executable() -> Value {
    let data = fs::read("/proc/self/exe").unwrap();
    json!({"read_path":"/proc/self/exe","declared_path":std::env::current_exe().unwrap(),"kernel_link":fs::read_link("/proc/self/exe").unwrap(),"length":data.len(),"sha256":sha(&data)})
}

fn save(path: &Path, value: &Value) {
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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/data/lanes/r3-c/pkcs11-signing-env-pin")
}

/// The parent never initializes a provider or mutates its environment. Every
/// row owns a separate child/store; nested libtest output is archived, not emitted.
pub fn run(test_name: &str, label: &str) {
    if let Ok(selected) = std::env::var("SIGIS_PKCS11_SIGNING_CHILD") {
        assert_eq!(selected, test_name);
        child(label);
        return;
    }
    let archive = PathBuf::from(required("SIGIS_PKCS11_SIGNING_RECORD_DIR"));
    fs::create_dir_all(&archive).unwrap();
    let case = tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(archive)
        .unwrap()
        .keep();
    let parent_elf = running_executable();
    let output = Command::new("/proc/self/exe")
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env("SIGIS_PKCS11_SIGNING_CHILD", test_name)
        .env("SIGIS_PKCS11_SIGNING_CASE_DIR", &case)
        .env("SOFTHSM2_CONF", case.join("provider/softhsm2.conf"))
        .env_remove("PKCS11_CONFIG")
        .env(
            "SIGIS_PKCS11_SIGNING_PARENT_ELF_SHA256",
            parent_elf["sha256"].as_str().unwrap(),
        )
        .output()
        .unwrap();
    let stdout = case.join("child.stdout.bin");
    let stderr = case.join("child.stderr.bin");
    fs::write(&stdout, &output.stdout).unwrap();
    fs::write(&stderr, &output.stderr).unwrap();
    let receipt = case.join("receipt.json");
    let record = json!({"original":ORIGINAL,"fixture_label":label,"effective_algorithm":"ed25519","parent_running_elf":parent_elf,"child_exit_code":output.status.code(),"child_stdout":file(&stdout),"child_stderr":file(&stderr),"child_receipt":receipt.exists().then(||file(&receipt)),"nested_summary_not_emitted":true});
    save(&case.join("parent-receipt.json"), &record);
    eprintln!("PKCS11_SIGNING_CHILD {record}");
    assert!(
        output.status.success(),
        "Actual signing row failed; inspect {}",
        case.display()
    );
    let record: Value = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
    assert_eq!(record["actual_running_elf"]["sha256"], parent_elf["sha256"]);
    assert_eq!(record["fixture_label"], label);
    assert_eq!(record["native_cli"]["exit_code"], 0);
    assert_eq!(record["validation"]["original_clock"]["bottom_line"], true);
}

fn child(label: &str) {
    let current_elf = running_executable();
    assert_eq!(
        current_elf["sha256"].as_str(),
        Some(required("SIGIS_PKCS11_SIGNING_PARENT_ELF_SHA256").as_str())
    );
    let case = PathBuf::from(required("SIGIS_PKCS11_SIGNING_CASE_DIR"));
    let module = PathBuf::from(required("SIGIS_PKCS11_SIGNING_MODULE"));
    let utility = PathBuf::from(required("SIGIS_PKCS11_SIGNING_UTILITY"));
    let python = PathBuf::from(required("HANKO_ORACLE"));
    let overlay = required("SIGIS_PKCS11_ORACLE_OVERLAY");
    let source = required("SIGIS_PKCS11_SIGNING_SOURCE_COMMIT");
    let expected_cli = required("SIGIS_PKCS11_SIGNING_CLI_SHA256");
    let module_before = file(&module);
    let utility_before = file(&utility);
    let provider = case.join("provider");
    assert!(!provider.exists(), "Never reuse an old token store");
    let provisioner = fixture_dir().join("provision_signing.py");
    let result = Command::new(&python)
        .args(["-B", "-s", "-P"])
        .arg(&provisioner)
        .arg(&provider)
        .env("PYTHONPATH", &overlay)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONNOUSERSITE", "1")
        .env("SIGIS_PKCS11_ORACLE_OVERLAY", &overlay)
        .env("SIGIS_PKCS11_SIGNING_MODULE", &module)
        .env("SIGIS_PKCS11_SIGNING_UTILITY", &utility)
        .env_remove("SOFTHSM2_CONF")
        .env_remove("PKCS11_CONFIG")
        .output()
        .unwrap();
    fs::write(case.join("provision.stdout.bin"), &result.stdout).unwrap();
    fs::write(case.join("provision.stderr.bin"), &result.stderr).unwrap();
    assert!(
        result.status.success(),
        "Actual Ed25519 fixture provisioning failed; inspect case logs"
    );
    let conf = provider.join("softhsm2.conf");
    assert!(conf.is_file());
    // The parent supplied this setting before exec and before any module load.
    assert_eq!(PathBuf::from(required("SOFTHSM2_CONF")), conf);
    let fixture = read_actual_fixture(&module);
    let maps = fs::read_to_string("/proc/self/maps").unwrap();
    fs::write(case.join("native-loaded-maps.txt"), &maps).unwrap();
    assert!(
        maps.contains(module.to_str().unwrap()),
        "Actual software module must be mapped"
    );
    let dsos: Vec<_> = maps
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|p| p.starts_with('/') && p.contains(".so"))
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>()
        .iter()
        .filter(|p| p.is_file())
        .map(|p| file(p))
        .collect();
    let cwd = case.join("cli-cwd");
    fs::create_dir(&cwd).unwrap();
    let input_source = sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]);
    let input = cwd.join("input.pdf");
    fs::copy(&input_source, &input).unwrap();
    fs::copy(fixture_dir().join("interm.der"), cwd.join("interm.crt")).unwrap();
    let config = cwd.join("pyhanko.yml");
    let config_text = format!("pkcs11-setups:\n  test:\n    module-path: {}\n    token-criteria:\n      label: tested25519\n    cert-label: signer1\n    key-label: null\n    other-certs-to-pull: interm\n    other-certs: interm.crt\n", serde_json::to_string(module.to_str().unwrap()).unwrap());
    fs::write(&config, config_text).unwrap();
    let sentinel = cwd.join("unrelated-sentinel.bin");
    fs::write(
        &sentinel,
        b"Preserve unrelated files during token signing.\n",
    )
    .unwrap();
    let input_before = file(&input);
    let config_before = file(&config);
    let interm_before = file(&cwd.join("interm.crt"));
    let sentinel_before = file(&sentinel);
    let entries_before = names(&cwd);
    let cli = crate::common::cli();
    let cli_before = file(cli);
    assert_eq!(cli_before["sha256"].as_str(), Some(expected_cli.as_str()));
    let argv = [
        "sign",
        "addsig",
        "--field",
        "Sig1",
        "pkcs11",
        "--p11-setup",
        "test",
        "input.pdf",
        "output.pdf",
    ];
    let before_now = Moment::now();
    let output = Command::new(cli)
        .args(argv)
        .current_dir(&cwd)
        .env("PYHANKO_PKCS11_PIN", USER_PIN)
        .env("SOFTHSM2_CONF", &conf)
        .env_remove("PYHANKO_PKCS11_SIGNING_PIN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    fs::write(case.join("cli.stdout.bin"), &output.stdout).unwrap();
    fs::write(case.join("cli.stderr.bin"), &output.stderr).unwrap();
    let mut record = json!({"original":ORIGINAL,"fixture_label":label,"effective_algorithm":"ed25519","actual_running_elf":current_elf,"source_commit":source,"host":fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),"slot":std::env::var_os("RUST_SLOTS_HELD"),"provider_fixture":fixture,"provisioner":file(&provisioner),"provisioning_receipt":file(&provider.join("receipt.json")),"private_conf":file(&conf),"loaded_dsos":dsos,"module_before":module_before,"module_after":file(&module),"utility_before":utility_before,"utility_after":file(&utility),"native_cli":{"argv":argv,"before":cli_before,"after":file(cli),"exit_code":output.status.code(),"stdout":file(&case.join("cli.stdout.bin")),"stderr":file(&case.join("cli.stderr.bin")),"user_pin_source":"PYHANKO_PKCS11_PIN; actual value deliberately not logged","signing_pin_env_present":false,"input_before":input_before,"input_after":file(&input),"config_before":config_before,"config_after":file(&config),"file_intermediate_before":interm_before,"file_intermediate_after":file(&cwd.join("interm.crt")),"sentinel_before":sentinel_before,"sentinel_after":file(&sentinel),"entries_before":entries_before,"entries_after":names(&cwd),"output_exists":cwd.join("output.pdf").exists(),"native_start_NOW":before_now.unix_secs()}});
    save(&case.join("receipt.json"), &record);
    assert_eq!(record["module_before"], record["module_after"]);
    assert_eq!(record["utility_before"], record["utility_after"]);
    for prefix in ["input", "config", "file_intermediate", "sentinel"] {
        assert_eq!(
            record["native_cli"][format!("{prefix}_before")],
            record["native_cli"][format!("{prefix}_after")]
        );
    }
    if !output.status.success() {
        assert!(
            !cwd.join("output.pdf").exists(),
            "An error must not publish a signature output"
        );
    }
    assert_eq!(
        output.status.code(),
        Some(0),
        "Original positive must actually sign; inspect CLI logs"
    );
    assert!(
        cwd.join("output.pdf").is_file(),
        "Output existence is mandatory even though upstream teardown is conditional"
    );
    let mut expected_entries = entries_before;
    expected_entries.push("output.pdf".into());
    expected_entries.sort();
    assert_eq!(
        names(&cwd),
        expected_entries,
        "Successful signing may only add its output"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("PKCS#11 user PIN:"),
        "Environment PIN must not fall back to a prompt"
    );
    assert!(
        !stderr.contains("pin=1234") && !stderr.contains("PIN: 1234"),
        "Product diagnostics must not expose PIN"
    );
    let signed = fs::read(cwd.join("output.pdf")).unwrap();
    record["native_cli"]["output"] = file(&cwd.join("output.pdf"));
    record["validation"] = verify_output(&case, &signed, before_now);
    save(&case.join("receipt.json"), &record);
}

fn read_actual_fixture(module: &Path) -> Value {
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
    let mut certs = Vec::new();
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
        certs.push(json!({"label":label,"length":raw.len(),"sha256":sha(raw),"der_parse_success":true,"subject_der_sha256":sha(&parsed.subject_der().unwrap())}));
    }
    let inventory = session.find_objects(&[]).unwrap();
    assert_eq!(
        inventory.len(),
        4,
        "Only signer1 private key plus three actual certificates are provisioned"
    );
    session.logout().unwrap();
    session.close().unwrap();
    json!({"platform":"softhsm","token_label":"tested25519","effective_algorithm":"ed25519","actual_EDDSA_advertised":true,"mechanism":"EDDSA (0x1057)","actual_user_login":true,"private_key_handles_matched":keys.len(),"private_key_value_requested":false,"certificates":certs,"inventory_objects":inventory.len(),"fixture_cache_scope":"One independent authenticated fixture process/store per original label","native_observation_scope":"Real native API/attributes/readback and loaded module; no C-sign interposition is claimed"})
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

fn verify_output(case: &Path, bytes: &[u8], now: Moment) -> Value {
    let root_bytes = fs::read(fixture_dir().join("root.der")).unwrap();
    let interm_bytes = fs::read(fixture_dir().join("interm.der")).unwrap();
    let signer_bytes = fs::read(fixture_dir().join("signer1.der")).unwrap();
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
    fs::write(case.join("modified-signed-byte.pdf"), &modified).unwrap();
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
    json!({"original_clock":status_record(&result),"original_clock_moment":moment.unix_secs(),"original_clock_empty_roots":status_record(&empty),"actual_NOW_moment":now.unix_secs(),"actual_NOW":status_record(&actual_now),"actual_NOW_empty_roots":status_record(&now_empty),"modified_signed_byte":status_record(&mutation),"modified_file":file(&case.join("modified-signed-byte.pdf")),"cms_embedded_certificate_count":cms.certificates.len(),"full_validation_path_required_length":3,"clock_scope":"Original fixture2020-11-01 and actual native CLI NOW are separate; NOW denial is preserved, never retimed away"})
}
