//! Type-phase adaptation of the deprecated implicit validation context.
//! Explicit roots and empty roots validate identical genuinely signed bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde_json::json;
use sigis_pades::{validate_pdf_signature, SignatureCoverageLevel};
use sigis_pades_sign::keys::load_private_key_from_pemder_data;
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SimpleSigner};
use sigis_pdf::PdfFile;
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::ades::{AdesIndeterminate, AdesSubIndic};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::time::Moment;

const TIME: &str = "2020-11-01T00:00:00Z";

fn hash(data: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(data)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}

fn read_input(path: &Path, opened: &mut Vec<serde_json::Value>) -> Vec<u8> {
    let path = path.canonicalize().unwrap();
    let data = std::fs::read(&path).unwrap();
    opened.push(json!({"path":path,"bytes":data.len(),"sha256":hash(&data)}));
    data
}

#[test]
fn explicit_context_validates_actual_signed_pdf_and_empty_roots_deny() {
    let evidence = PathBuf::from(
        std::env::var_os("HANKO_P_DEFAULT_CONTEXT_EVIDENCE_DIR")
            .expect("new persistent evidence directory required"),
    );
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence.join("default-context-native.started"))
        .unwrap();
    let data_dir = sigis_testdata::data_dir();
    let pki_dir = data_dir.join("lanes/d/pki/testing-ca");
    let mut opened_inputs = Vec::new();
    let manifest: serde_json::Value = serde_json::from_slice(&read_input(
        &pki_dir.join("manifest.json"),
        &mut opened_inputs,
    ))
    .unwrap();
    let mut load_cert = |label: &str| {
        Cert::from_der(&read_input(
            &pki_dir.join(manifest["certs"][label]["file"].as_str().unwrap()),
            &mut opened_inputs,
        ))
        .unwrap()
    };
    let root = load_cert("root");
    let intermediate = load_cert("interm");
    let leaf = load_cert("signer1");
    let key_label = manifest["certs"]["signer1"]["subject_key"]
        .as_str()
        .unwrap();
    let key_entry = &manifest["keys"][key_label];
    let key_bytes = read_input(
        &data_dir
            .join("pyhanko/crypto")
            .join(key_entry["path"].as_str().unwrap()),
        &mut opened_inputs,
    );
    let key = load_private_key_from_pemder_data(
        &key_bytes,
        key_entry["password"].as_str().map(str::as_bytes),
    )
    .unwrap();
    let signer =
        SimpleSigner::new(key, leaf.clone(), vec![root.clone(), intermediate.clone()]).unwrap();
    let input = read_input(
        &data_dir.join("pyhanko/pdf/minimal.pdf"),
        &mut opened_inputs,
    );
    std::fs::write(
        evidence.join("native-inputs.json"),
        serde_json::to_vec_pretty(&opened_inputs).unwrap(),
    )
    .unwrap();
    let original = input.clone();
    let metadata = PdfSignatureMetadata::pyhanko_defaults("Sig1");
    // This reproduces normal no-context SIGNING; implicit VALIDATION context
    // is the subject of the original Python warning and type-phase proposal.
    assert!(metadata.validation_context.is_none());
    let output = PdfSigner::new(metadata, Arc::new(signer))
        .at(Moment::parse_rfc3339(TIME).unwrap())
        .sign_pdf(&input)
        .unwrap();
    assert_eq!(input, original);
    let file = PdfFile::parse(&output).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0].field_name, "Sig1");
    let mut outcomes = Vec::new();
    for has_root in [true, false] {
        let mut builder = ValidationContext::builder()
            .other_cert(intermediate.clone())
            .other_cert(root.clone())
            .moment(Moment::parse_rfc3339(TIME).unwrap())
            .revocation_mode("soft-fail");
        if has_root {
            builder = builder.trust_root(root.clone());
        }
        let context = builder.build().unwrap();
        assert_eq!(context.trust_anchors().len(), usize::from(has_root));
        assert!(context.trust_manager().is_none());
        // Real existing public API, explicitly borrowed caller context.
        let status = validate_pdf_signature(&file, &signatures[0], &context, None).unwrap();
        assert!(status.cms.signature.intact && status.cms.signature.valid);
        assert_eq!(
            status.cms.signature.signing_cert.as_ref().unwrap().der(),
            leaf.der()
        );
        assert_eq!(
            status.cms.signature.md_algorithm,
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(status.coverage, SignatureCoverageLevel::EntireFile);
        assert_eq!(
            status.modification_level(),
            Some(sigis_pdf_diff::ModificationLevel::None)
        );
        assert_eq!(status.cms.signature.trusted(), has_root);
        assert_eq!(status.bottom_line(), has_root);
        if has_root {
            let path = status
                .cms
                .signature
                .validation_path
                .as_ref()
                .unwrap()
                .certs();
            assert_eq!(path.len(), 3);
            for (actual, expected) in path.iter().zip([&root, &intermediate, &leaf]) {
                assert_eq!(actual.der(), expected.der());
            }
            assert!(status.cms.signature.trust_problem_indic.is_none());
        } else {
            assert_eq!(
                status.cms.signature.trust_problem_indic,
                Some(AdesSubIndic::Indeterminate(
                    AdesIndeterminate::NO_CERTIFICATE_CHAIN_FOUND
                ))
            );
        }
        outcomes.push(
            json!({"explicit_root":has_root,"intact":status.cms.signature.intact,
            "valid":status.cms.signature.valid,"trusted":status.cms.signature.trusted(),
            "bottom_line":status.bottom_line(),"summary":status.summary(),
            "coverage":format!("{:?}",status.coverage),
            "modification_level":format!("{:?}",status.modification_level()),
            "trust_indication":format!("{:?}",status.cms.signature.trust_problem_indic),
            "signer_sha256":hash(status.cms.signature.signing_cert.as_ref().unwrap().der()),
            "path_sha256":status.cms.signature.validation_path.as_ref().map(|path|
                path.certs().iter().map(|cert|hash(cert.der())).collect::<Vec<_>>())}),
        );
    }
    for (name, bytes) in [
        ("input.pdf", input.as_slice()),
        ("native.pdf", output.as_slice()),
        ("root.der", root.der()),
        ("interm.der", intermediate.der()),
        ("signer.der", leaf.der()),
    ] {
        std::fs::write(evidence.join(name), bytes).unwrap();
    }
    let request = json!({"pdf":evidence.join("native.pdf"),"root":evidence.join("root.der"),
        "intermediate":evidence.join("interm.der"),"leaf":evidence.join("signer.der"),"time":TIME});
    let request_path = evidence.join("request.json");
    std::fs::write(&request_path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();
    let python = std::env::var_os("HANKO_ORACLE").expect("fresh pinned oracle required");
    let reference = Command::new(python)
        .args([
            "-I",
            "-B",
            "-c",
            include_str!(
                "../crates/testdata/data/lanes/r3-p/default-context/explicit_context_oracle.py"
            ),
        ])
        .arg(&request_path)
        .output()
        .unwrap();
    std::fs::write(evidence.join("oracle-stdout.json"), &reference.stdout).unwrap();
    std::fs::write(evidence.join("oracle-stderr.log"), &reference.stderr).unwrap();
    assert!(
        reference.status.success(),
        "{}",
        String::from_utf8_lossy(&reference.stderr)
    );
    let reference: serde_json::Value = serde_json::from_slice(&reference.stdout).unwrap();
    assert_eq!(
        reference["versions"],
        json!({"pyhanko":"0.38.1","certvalidator":"0.33.0"})
    );
    assert_eq!(reference["runtime"]["debug"], true);
    assert_eq!(reference["runtime"]["optimize"], 0);
    assert_eq!(reference["runtime"]["isolated"], 1);
    assert_eq!(reference["pdf_sha256"], hash(&output));
    assert_eq!(reference["signer_sha256"], hash(leaf.der()));
    let opened = reference["opened_inputs"].as_array().unwrap();
    for path in std::iter::once(request_path.as_path()).chain(
        ["pdf", "root", "intermediate", "leaf"]
            .into_iter()
            .map(|k| std::path::Path::new(request[k].as_str().unwrap())),
    ) {
        let path = path.canonicalize().unwrap();
        assert_eq!(
            opened
                .iter()
                .filter(|row| row["path"] == path.to_str().unwrap())
                .count(),
            1,
            "missing/duplicate opened input: {}",
            path.display()
        );
    }
    for row in reference["opened_inputs"].as_array().unwrap() {
        let bytes = std::fs::read(row["path"].as_str().unwrap()).unwrap();
        assert_eq!(row["bytes"], bytes.len());
        assert_eq!(row["sha256"], hash(&bytes));
    }
    for (row, root) in reference["statuses"]
        .as_array()
        .unwrap()
        .iter()
        .zip([true, false])
    {
        assert_eq!(row["explicit_root"], root);
        assert_eq!(row["intact"], true);
        assert_eq!(row["valid"], true);
        assert_eq!(row["trusted"], root);
        assert_eq!(row["bottom_line"], root);
        assert_eq!(row["coverage"], "ENTIRE_FILE");
        assert_eq!(row["modification_level"], "NONE");
    }
    assert_eq!(reference["statuses"].as_array().unwrap().len(), 2);
    let elf_path = std::env::current_exe().unwrap();
    let elf = std::fs::read(&elf_path).unwrap();
    std::fs::write(
        evidence.join("native-receipt.json"),
        serde_json::to_vec_pretty(&json!({
        "pdf_sha256":hash(&output),"pdf_bytes":output.len(),"native_statuses":outcomes,
        "elf_path":elf_path,"elf_sha256":hash(&elf),"elf_bytes":elf.len(),
        "source_identity":"independent emitted-content/compiler audit is mandatory",
        "opened_inputs":opened_inputs,"time":TIME,"field":"Sig1","digest":"sha256",
        "new_original_ids":0}))
        .unwrap(),
    )
    .unwrap();
}
