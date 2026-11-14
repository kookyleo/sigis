//! Real certificate-only provider preconditions, isolated before initialization.

use der::Encode;
use serde_json::{json, Value};
use sigis_pades_sign::pkcs11::{
    cryptoki::{
        object::{Attribute, AttributeType, CertificateType, ObjectClass},
        session::UserType,
        types::AuthPin,
    },
    load_module,
};
use sigis_pki_core::cert::Cert;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const MODULE_SHA256: &str = "8453e1bde7dac7a24ed1bab11786fa8641a0ff2b4093c5f027ceaf368a7a438d";
const UTILITY_SHA256: &str = "dbe84fb38af1cbcaf58fcea71b0d00753b0eb8480b517a1a4dd98f9ee95dfdb3";
const USER_PIN: &str = "1234";
const SO_PIN: &str = "5678";

fn required(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("Required real-fixture selector {name} is missing"))
}

fn sha256(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn snapshot(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap();
    json!({"path":path.canonicalize().unwrap(),"length":bytes.len(),"sha256":sha256(&bytes)})
}

fn running_executable_snapshot() -> Value {
    let bytes = fs::read("/proc/self/exe").unwrap();
    json!({
        "read_path":"/proc/self/exe",
        "kernel_link":fs::read_link("/proc/self/exe").unwrap(),
        "declared_path":std::env::current_exe().unwrap(),
        "length":bytes.len(),"sha256":sha256(&bytes),
    })
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn entries(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// No provider environment is changed in the top-level, potentially parallel
/// harness. Child stdout/stderr are only files: never nest libtest summaries in
/// the parent's report stream.
pub fn run(name: &str, extra: &[&str], expected: &str) {
    if let Ok(selected) = std::env::var("SIGIS_PKCS11_PREFLIGHT_CHILD") {
        assert_eq!(selected, name, "Child must run its selected exact original");
        child(name, extra, expected);
        return;
    }
    let archive = PathBuf::from(required("SIGIS_PKCS11_PREFLIGHT_RECORD_DIR"));
    fs::create_dir_all(&archive).unwrap();
    let dir = tempfile::Builder::new()
        .prefix(&format!("{name}-"))
        .tempdir_in(archive)
        .unwrap()
        .keep();
    let tokens = dir.join("tokens");
    fs::create_dir(&tokens).unwrap();
    let conf = dir.join("softhsm2.conf");
    fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
            tokens.display()
        ),
    )
    .unwrap();
    let parent_executable = running_executable_snapshot();
    // Execute the already running inode, not a mutable shared-target pathname.
    let output = Command::new("/proc/self/exe")
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("SIGIS_PKCS11_PREFLIGHT_CHILD", name)
        .env(
            "SIGIS_PKCS11_PREFLIGHT_PARENT_ELF_SHA256",
            parent_executable["sha256"].as_str().unwrap(),
        )
        .env("SIGIS_PKCS11_PREFLIGHT_CASE_DIR", &dir)
        .env("SOFTHSM2_CONF", &conf)
        .env("PKCS11_PLATFORMS", "softhsm")
        .env_remove("PKCS11_CONFIG")
        .output()
        .unwrap();
    let stdout = dir.join("child.stdout.bin");
    let stderr = dir.join("child.stderr.bin");
    fs::write(&stdout, &output.stdout).unwrap();
    fs::write(&stderr, &output.stderr).unwrap();
    let receipt = dir.join("receipt.json");
    let observation = json!({
        "case":name,"child_exit_code":output.status.code(),
        "parent_native_test_executable":parent_executable,
        "stdout":snapshot(&stdout),"stderr":snapshot(&stderr),
        "receipt":receipt.exists().then(|| snapshot(&receipt)),
        "child_summary_is_not_emitted":true,
    });
    write_json(&dir.join("parent-receipt.json"), &observation);
    eprintln!("PKCS11_PREFLIGHT_CHILD {observation}");
    assert!(
        output.status.success(),
        "Child failed; inspect {}",
        dir.display()
    );
    assert!(
        receipt.exists(),
        "Real fixture and CLI receipt is mandatory"
    );
    let record: Value = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
    assert_eq!(record["original"], name);
    assert_eq!(
        record["native_test_executable"]["sha256"],
        parent_executable["sha256"]
    );
    assert_eq!(record["cli"]["exit_code"], 1);
    assert_eq!(
        record["fixture"]["retrieved_certificates"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

fn child(name: &str, extra: &[&str], expected: &str) {
    let actual_executable = running_executable_snapshot();
    let expected_parent = required("SIGIS_PKCS11_PREFLIGHT_PARENT_ELF_SHA256");
    assert_eq!(
        actual_executable["sha256"].as_str(),
        Some(expected_parent.as_str())
    );
    let dir = PathBuf::from(required("SIGIS_PKCS11_PREFLIGHT_CASE_DIR"));
    let module = PathBuf::from(required("PKCS11_TEST_MODULE"));
    let utility = PathBuf::from(required("PKCS11_TEST_SOFTHSM_UTIL"));
    let source_commit = required("SIGIS_PKCS11_PREFLIGHT_SOURCE_COMMIT");
    let expected_cli = required("SIGIS_PKCS11_PREFLIGHT_CLI_SHA256");
    let module_before = snapshot(&module);
    let utility_before = snapshot(&utility);
    assert_eq!(module_before["sha256"], MODULE_SHA256);
    assert_eq!(utility_before["sha256"], UTILITY_SHA256);
    let conf = PathBuf::from(required("SOFTHSM2_CONF"));
    let tokens = dir.join("tokens");
    assert_eq!(conf, dir.join("softhsm2.conf"));
    assert!(
        entries(&tokens).is_empty(),
        "Only a fresh private store is allowed"
    );
    let fixture = provision_and_read(&dir, &module, &utility);
    let fixture_maps = fs::read_to_string("/proc/self/maps").unwrap();
    fs::write(dir.join("fixture-loaded-maps.txt"), &fixture_maps).unwrap();
    let loaded_dsos: Vec<_> = fixture_maps
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|name| name.starts_with('/') && name.contains(".so"))
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>()
        .iter()
        .filter(|path| path.is_file())
        .map(|path| snapshot(path))
        .collect();
    assert!(
        fixture_maps.contains(module.to_str().unwrap()),
        "Actual module must be loaded"
    );
    let cwd = dir.join("cli-cwd");
    fs::create_dir(&cwd).unwrap();
    let input_fixture = sigis_testdata::pyhanko(&["pdf", "minimal.pdf"]);
    let input = cwd.join("input.pdf");
    fs::copy(&input_fixture, &input).unwrap();
    // A separate unrelated sentinel supplements the exact absent-output case.
    let sentinel = cwd.join("unrelated-sentinel.bin");
    fs::write(
        &sentinel,
        b"Preserve unrelated files during preflight refusal.\n",
    )
    .unwrap();
    let before_input = snapshot(&input);
    let before_sentinel = snapshot(&sentinel);
    let before_entries = entries(&cwd);
    assert!(!cwd.join("pyhanko.yml").exists());
    assert!(!cwd.join("output.pdf").exists());
    let executable = crate::common::cli();
    let cli_before = snapshot(executable);
    assert_eq!(cli_before["sha256"].as_str(), Some(expected_cli.as_str()));
    let mut args = ["sign", "addsig", "--field", "Sig1", "pkcs11"]
        .map(str::to_owned)
        .to_vec();
    args.extend(extra.iter().map(|value| (*value).to_owned()));
    args.extend(["input.pdf".to_owned(), "output.pdf".to_owned()]);
    let output = Command::new(executable)
        .args(&args)
        .current_dir(&cwd)
        .output()
        .unwrap();
    fs::write(dir.join("cli.stdout.bin"), &output.stdout).unwrap();
    fs::write(dir.join("cli.stderr.bin"), &output.stderr).unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let module_after = snapshot(&module);
    let utility_after = snapshot(&utility);
    assert_eq!(module_before, module_after);
    assert_eq!(utility_before, utility_after);
    let record = json!({
        "original":name,"native_process_id":std::process::id(),
        "source_commit":source_commit,"native_test_executable":actual_executable,
        "native_now_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        "python_original_fixture_clock":"2020-11-01; native preflight intentionally uses actual NOW",
        "host":fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),
        "slot":std::env::var_os("RUST_SLOTS_HELD"),
        "fixture":fixture,"loaded_dsos":loaded_dsos,
        "module_before":module_before,"module_after":module_after,
        "utility_before":utility_before,"utility_after":utility_after,"private_conf":snapshot(&conf),
        "native_cache_scope":"Fresh store and helper process per mapped original; two certificate reads each, no cross-original chain cache",
        "cli":{
            "argv":args,"cwd":cwd,"before":cli_before,"after":snapshot(executable),
            "exit_code":output.status.code(),"stdout":snapshot(&dir.join("cli.stdout.bin")),"stderr":snapshot(&dir.join("cli.stderr.bin")),
            "expected_component":expected,"component_present":combined.contains(expected),
            "input_fixture":snapshot(&input_fixture),"input_before":before_input,"input_after":snapshot(&input),
            "unrelated_sentinel_before":before_sentinel,"unrelated_sentinel_after":snapshot(&sentinel),
            "entries_before":before_entries,"entries_after":entries(&cwd),
            "config_exists":cwd.join("pyhanko.yml").exists(),"output_exists":cwd.join("output.pdf").exists(),
        },
        "no_signing_result_or_trust_claim":true,
        "provider_observation_scope":"Actual native API success/readback and loaded maps; no C interposition or CLI trace is claimed",
    });
    write_json(&dir.join("receipt.json"), &record);
    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected actual original refusal"
    );
    assert!(
        combined.contains(expected),
        "Missing exact original diagnostic; inspect CLI files"
    );
    assert_eq!(record["cli"]["before"], record["cli"]["after"]);
    assert_eq!(record["cli"]["input_before"], record["cli"]["input_after"]);
    assert_eq!(
        record["cli"]["unrelated_sentinel_before"],
        record["cli"]["unrelated_sentinel_after"]
    );
    assert_eq!(
        record["cli"]["entries_before"],
        record["cli"]["entries_after"]
    );
    assert_eq!(record["cli"]["config_exists"], false);
    assert_eq!(record["cli"]["output_exists"], false);
}

fn provision_and_read(dir: &Path, module: &Path, utility: &Path) -> Value {
    let output = Command::new(utility)
        .arg("--module")
        .arg(module)
        .args([
            "--init-token",
            "--free",
            "--label",
            "testrsa",
            "--pin",
            USER_PIN,
            "--so-pin",
            SO_PIN,
        ])
        .output()
        .unwrap();
    fs::write(dir.join("utility.stdout.bin"), &output.stdout).unwrap();
    fs::write(dir.join("utility.stderr.bin"), &output.stderr).unwrap();
    assert!(
        output.status.success(),
        "Real isolated token initialization is required"
    );
    let ctx = load_module(module.to_str().unwrap()).expect("Actual module initialization failed");
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|slot| ctx.get_token_info(*slot).unwrap().label().trim_end() == "testrsa")
        .expect("Actual token testrsa must exist");
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/data/lanes/r3-c/pkcs11-preflight-two");
    let session = ctx.open_rw_session(slot).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
        .unwrap();
    let mut imported = Vec::new();
    for label in ["root", "interm"] {
        let path = fixture_dir.join(format!("{label}.der"));
        let bytes = fs::read(&path).unwrap();
        let cert = Cert::from_der(&bytes).expect("Original certificate DER must parse");
        let template = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(label.as_bytes().to_vec()),
            Attribute::Subject(cert.subject_der().unwrap()),
            Attribute::Issuer(cert.issuer().to_der().unwrap()),
            Attribute::Value(bytes),
        ];
        session.create_object(&template).unwrap();
        imported.push(
            json!({"label":label,"input":snapshot(&path),"class":"CERTIFICATE","token":true}),
        );
    }
    assert_eq!(
        session.find_objects(&[]).unwrap().len(),
        2,
        "Only certificate objects may be provisioned"
    );
    session.logout().unwrap();
    session.close().unwrap();
    // Reopen/authenticate as the actual original p11_config precondition does.
    let session = ctx.open_ro_session(slot).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
        .unwrap();
    let mut retrieved = Vec::new();
    for label in ["root", "interm"] {
        let found = session
            .find_objects(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .unwrap();
        assert_eq!(
            found.len(),
            1,
            "Exact original certificate label must resolve once"
        );
        let attrs = session
            .get_attributes(found[0], &[AttributeType::Value, AttributeType::Token])
            .unwrap();
        let bytes = attrs
            .iter()
            .find_map(|a| match a {
                Attribute::Value(v) => Some(v),
                _ => None,
            })
            .unwrap();
        assert!(attrs.iter().any(|a| matches!(a, Attribute::Token(true))));
        assert_eq!(
            bytes,
            &fs::read(fixture_dir.join(format!("{label}.der"))).unwrap()
        );
        let cert = Cert::from_der(bytes).expect("Actual provider VALUE must parse as DER");
        retrieved.push(json!({"label":label,"length":bytes.len(),"sha256":sha256(bytes),"der_parse_success":true,"subject_der_sha256":sha256(&cert.subject_der().unwrap())}));
    }
    session.logout().unwrap();
    session.close().unwrap();
    json!({
        "platform":"softhsm","declared_algo":"default","selected_config_algo":"rsa",
        "token_label":"testrsa","user_authentication":"actual user PIN login",
        "utility_exit_code":output.status.code(),"utility_stdout":snapshot(&dir.join("utility.stdout.bin")),"utility_stderr":snapshot(&dir.join("utility.stderr.bin")),
        "imported_certificates":imported,"retrieved_certificates":retrieved,
        "actual_sessions":"one RW certificate provisioning session, then one separate RO fixture session; both authenticated and explicitly closed",
        "object_inventory_count":2,"private_key_objects_imported":0,"key_generation_calls":0,"signing_calls":0,"mechanism_enumeration_calls":0,
    })
}
