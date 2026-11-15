//! Supplemental revocation-snapshot controls; zero upstream-function credit.
#[path = "common/mod.rs"]
#[allow(dead_code)] // This target uses provenance helpers without a CLI process.
mod common;

use serde_json::{json, Value};
use sigis_cli::{plugins::PluginRegistry, runtime::ValidationRuntime, Output};
use sigis_pki_core::{
    cert::Cert,
    errors::FetchError,
    fetch::{CrlFetcher, Fetchers},
    time::Moment,
};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

fn fixture(name: &str) -> PathBuf {
    common::record_test_executable();
    let path = sigis_testdata::path(&["lanes", "r3-c", "validation", "rsa", name]);
    common::record_file(&path, "validation_snapshot_fixture");
    path
}

fn sha256(data: &[u8]) -> String {
    openssl::sha::sha256(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn metadata() -> Value {
    let value: Value =
        serde_json::from_slice(&fs::read(fixture("snapshot-provenance.json")).unwrap()).unwrap();
    assert_eq!(value["private_key_material_copied"], false);
    assert_eq!(value["signature_verifies"], true);
    for (name, expected) in value["files"].as_object().unwrap() {
        let bytes = fs::read(fixture(name)).unwrap();
        assert_eq!(expected["sha256"].as_str(), Some(sha256(&bytes).as_str()));
        assert_eq!(expected["length"].as_u64(), Some(bytes.len() as u64));
    }
    value
}

#[derive(Clone, Copy, Debug)]
enum Evidence {
    Good,
    Revoked,
    RevokedThenGood,
}

#[derive(Debug)]
struct SnapshotCrls {
    leaf_sha256: [u8; 32],
    good_leaf: Vec<u8>,
    revoked_leaf: Vec<u8>,
    root: Vec<u8>,
    evidence: Evidence,
    leaf_calls: AtomicUsize,
    other_calls: AtomicUsize,
}

impl CrlFetcher for SnapshotCrls {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        let bytes = if cert.sha256() == self.leaf_sha256 {
            let call = self.leaf_calls.fetch_add(1, Ordering::SeqCst);
            match self.evidence {
                Evidence::Good => &self.good_leaf,
                Evidence::Revoked => &self.revoked_leaf,
                Evidence::RevokedThenGood if call == 0 => &self.revoked_leaf,
                Evidence::RevokedThenGood => &self.good_leaf,
            }
        } else {
            self.other_calls.fetch_add(1, Ordering::SeqCst);
            &self.root
        };
        eprintln!(
            "VALIDATION_SNAPSHOT_FETCH {}",
            json!({
                "certificate_sha256":sha256(cert.der()),
                "evidence_sha256":sha256(bytes),"mode":format!("{:?}", self.evidence),
            })
        );
        Ok(vec![bytes.clone()])
    }
}

fn native(evidence: Evidence) -> Output {
    native_at_time(evidence, false)
}

fn native_at_time(evidence: Evidence, claimed: bool) -> Output {
    let metadata = metadata();
    let crls = Arc::new(SnapshotCrls {
        leaf_sha256: Cert::from_der(&fs::read(fixture("signer1.der")).unwrap())
            .unwrap()
            .sha256(),
        good_leaf: fs::read(fixture("crl-interm.der")).unwrap(),
        revoked_leaf: fs::read(fixture("snapshot-revoked-leaf.crl.der")).unwrap(),
        root: fs::read(fixture("crl-root.der")).unwrap(),
        evidence,
        leaf_calls: AtomicUsize::new(0),
        other_calls: AtomicUsize::new(0),
    });
    let mut args = vec![
        "sign".into(),
        "validate".into(),
        "--force-revinfo".into(),
        "--trust-replace".into(),
        "--trust".into(),
        fixture("root.der").to_string_lossy().into_owned(),
        fixture("regular.pdf").to_string_lossy().into_owned(),
    ];
    if claimed {
        let end = args.len() - 1;
        args.splice(end..end, ["--validation-time".into(), "claimed".into()]);
    }
    let runtime = ValidationRuntime {
        pkcs11_signing_pin_prompt: None,
        pkcs11_user_pin_prompt: None,
        now: Moment::parse_rfc3339(metadata["moment"].as_str().unwrap()).unwrap(),
        fetchers: Fetchers {
            crl: Some(crls.clone()),
            ..Fetchers::none()
        },
        password: None,
        trusted_list_transport: None,
    };
    let result = sigis_cli::run_with_runtime(&args, &PluginRegistry::default(), &runtime);
    eprintln!(
        "VALIDATION_SNAPSHOT_NATIVE {}",
        json!({
            "mode":format!("{evidence:?}"),"claimed":claimed,"argv":args,"moment":metadata["moment"],
            "leaf_calls":crls.leaf_calls.load(Ordering::SeqCst),
            "other_calls":crls.other_calls.load(Ordering::SeqCst),
            "code":result.code,"stdout":&result.stdout,"stderr":&result.stderr,
        })
    );
    result
}

fn message(result: &Output) -> String {
    format!("{}{}", result.stdout, result.stderr)
}

fn rejected(result: Output) {
    let text = message(&result);
    assert_eq!(result.code, 1, "{text}");
    assert!(!text.contains("INTACT:TRUSTED"), "{text}");
    assert!(text.to_ascii_lowercase().contains("revoked"), "{text}");
}

#[test]
fn always_good_signed_crls_are_trusted() {
    let result = native(Evidence::Good);
    assert_eq!(result.code, 0, "{}", message(&result));
    assert!(message(&result).contains("INTACT:TRUSTED"));
}

#[test]
fn always_revoked_signed_crls_are_rejected() {
    rejected(native(Evidence::Revoked));
}

#[test]
fn switching_crls_cannot_overwrite_a_revocation_denial() {
    rejected(native(Evidence::RevokedThenGood));
}

#[test]
fn claimed_time_cannot_overwrite_a_revocation_denial() {
    rejected(native_at_time(Evidence::RevokedThenGood, true));
}

#[test]
fn fresh_oracle_authenticates_good_and_revoked_snapshot_evidence() {
    let _metadata = metadata();
    let program = sigis_testdata::oracle::python().expect("pinned Python oracle required");
    let result = Command::new(program)
        .arg(fixture("snapshot-oracle.py"))
        .arg(fixture("regular.pdf").parent().unwrap())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let receipt: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(receipt["pyhanko_version"], "0.38.1");
    assert_eq!(receipt["certvalidator_version"], "0.33.0");
    assert_eq!(receipt["network_calls"], json!([]));
    let statuses = receipt["results"].as_array().unwrap();
    assert_eq!(statuses.len(), 2);
    for status in statuses {
        assert_eq!(status["intact"], true);
        assert_eq!(status["valid"], true);
        let trusted = status["label"] == "good";
        assert_eq!(status["trusted"], trusted);
        assert_eq!(status["bottom_line"], trusted);
    }
    eprintln!("VALIDATION_SNAPSHOT_ORACLE {receipt}");
}
