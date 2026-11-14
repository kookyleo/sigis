//! Type-phase adaptation of the deprecated implicit validation context.
//! Explicit roots and empty roots validate identical genuinely signed bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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

#[test]
fn explicit_context_validates_actual_signed_pdf_and_empty_roots_deny() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path();
    let data_dir = sigis_testdata::data_dir();
    let pki_dir = data_dir.join("lanes/d/pki/testing-ca");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pki_dir.join("manifest.json")).unwrap()).unwrap();
    let load_cert = |label: &str| {
        Cert::from_der(
            &std::fs::read(pki_dir.join(manifest["certs"][label]["file"].as_str().unwrap()))
                .unwrap(),
        )
        .unwrap()
    };
    let root = load_cert("root");
    let intermediate = load_cert("interm");
    let leaf = load_cert("signer1");
    let key_label = manifest["certs"]["signer1"]["subject_key"]
        .as_str()
        .unwrap();
    let key_entry = &manifest["keys"][key_label];
    let key_bytes = std::fs::read(
        data_dir
            .join("pyhanko/crypto")
            .join(key_entry["path"].as_str().unwrap()),
    )
    .unwrap();
    let key = load_private_key_from_pemder_data(
        &key_bytes,
        key_entry["password"].as_str().map(str::as_bytes),
    )
    .unwrap();
    let signer =
        SimpleSigner::new(key, leaf.clone(), vec![root.clone(), intermediate.clone()]).unwrap();
    let input = std::fs::read(data_dir.join("pyhanko/pdf/minimal.pdf")).unwrap();
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
    }
    for (name, bytes) in [
        ("input.pdf", input.as_slice()),
        ("native.pdf", output.as_slice()),
        ("root.der", root.der()),
        ("interm.der", intermediate.der()),
        ("signer.der", leaf.der()),
    ] {
        std::fs::write(directory.join(name), bytes).unwrap();
    }
    let request = json!({"pdf":directory.join("native.pdf"),"root":directory.join("root.der"),
        "intermediate":directory.join("interm.der"),"leaf":directory.join("signer.der"),"time":TIME});
    let request_path = directory.join("request.json");
    std::fs::write(&request_path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();
    let python = std::env::var_os("HANKO_ORACLE")
        .unwrap_or_else(|| "/tmp/pyhanko-oracle/venv/bin/python".into());
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
}
