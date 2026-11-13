//! Generic DSA parameter completion candidate for two existing upstream IDs.
//! Source-only candidate: UNCOMPILED / UNRUN until L integrates and verifies it.
//! Each actual native PDF requires a fresh mandatory pinned-reference verdict.
//! The original async config case uses the existing blocking Rust public API.
//! Three DSA parameters add zero new unique upstream-function credit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../crates/pades-sign/tests/support/softhsm.rs"]
mod softhsm;
#[path = "support/signing_integration.rs"]
mod support;

// The reused native fixture module resolves these from its parent.
use der::{Decode, Encode};
use sigis_pades_sign::pkcs11::{
    self, open_pkcs11_session, Pkcs11Config, Pkcs11Mechanism, Pkcs11Session, Pkcs11Signer,
    Pkcs11SignerOptions, PostSignTransform, TokenCriteria, UserPin,
};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::{
    dsa_key_size, validate_signature, DigestAlgorithm, DisallowWeakAlgorithmsPolicy,
    SignatureValidationContext,
};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::sign::KeySigner;
use std::{path::PathBuf, process::Command, sync::Arc};
use support::{pki, Pki};

const TIME: &str = "2020-11-01T00:00:00Z";

#[derive(der::Sequence)]
struct DsaSignature<'a> {
    r: der::asn1::UintRef<'a>,
    s: der::asn1::UintRef<'a>,
}

struct ReviewedProvider {
    module: String,
    module_bytes: Vec<u8>,
    utility: String,
    utility_bytes: Vec<u8>,
}

fn sha256(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn reviewed_provider() -> ReviewedProvider {
    let module = std::env::var("PKCS11_TEST_MODULE")
        .expect("explicit reviewed private module selector is mandatory");
    let utility = std::env::var("PKCS11_TEST_SOFTHSM_UTIL")
        .expect("explicit reviewed private utility selector is mandatory");
    let module_bytes = std::fs::read(&module).unwrap();
    let utility_bytes = std::fs::read(&utility).unwrap();
    assert_eq!(
        sha256(&module_bytes),
        "8453e1bde7dac7a24ed1bab11786fa8641a0ff2b4093c5f027ceaf368a7a438d"
    );
    assert_eq!(
        sha256(&utility_bytes),
        "dbe84fb38af1cbcaf58fcea71b0d00753b0eb8480b517a1a4dd98f9ee95dfdb3"
    );
    ReviewedProvider {
        module,
        module_bytes,
        utility,
        utility_bytes,
    }
}

fn fixture(provider: &ReviewedProvider) -> softhsm::P11Config {
    // Reuse the accepted acceptance-only provisioning opt-in. Its raw name
    // describes the original consumer, not the mechanism selected below.
    // Missing provider/config/capability fails; no generic ALL_ALGOS change.
    let cfg = softhsm::raw_dsa_config()
        .expect("PKCS11_TEST_RAW_DSA=1 must select the complete DSA fixture before initialization");
    assert_eq!(cfg.module, provider.module);
    assert_eq!(cfg.algo, "dsa");
    assert_eq!(cfg.arch, "testing-ca-dsa");
    assert_eq!(cfg.token_label, "testdsa");
    assert_eq!(cfg.cert_label, "signer1");
    assert!(cfg.key_label.is_none());
    assert_eq!(cfg.user_pin, "1234");
    assert_eq!(cfg.cert_chain_labels, ["root", "interm"]);
    assert!(softhsm::ALL_ALGOS
        .iter()
        .any(|(algo, _, exclusion)| *algo == "dsa" && exclusion.is_some()));
    cfg
}

fn checked_session(cfg: &softhsm::P11Config) -> (Arc<Pkcs11Session>, Vec<u64>) {
    let session = Arc::new(
        open_pkcs11_session(
            &cfg.module,
            None,
            Some(&TokenCriteria::label(&cfg.token_label)),
            &UserPin::Pin(cfg.user_pin.clone()),
        )
        .expect("actual configured DSA token session is mandatory"),
    );
    assert_eq!(session.token_label(), "testdsa");
    let mechanisms = session.mechanisms().expect("actual token enumeration");
    let required = Pkcs11Mechanism::DsaSha(DigestAlgorithm::Sha256);
    assert_eq!(required.mechanism_type(), 0x14);
    assert!(
        mechanisms.contains(&0x14),
        "original generic DSA fixture requires advertised CKM_DSA_SHA256 (0x14)"
    );
    // Generic signing has no extra CKM_DSA (0x11) prerequisite.
    (session, mechanisms)
}

fn context(root: &Cert, intermediate: &Cert, original_case: bool) -> ValidationContext {
    let builder = ValidationContext::builder()
        .trust_root(root.clone())
        .other_cert(intermediate.clone())
        .moment(support::at(TIME))
        // Original P11TestConfig creates its context at the frozen clock,
        // without an explicit historical moment or a revocation exemption.
        .point_in_time_validation(false);
    if original_case {
        builder
            .algorithm_policy(Arc::new(DisallowWeakAlgorithmsPolicy {
                dsa_key_size_threshold: 1024,
                ..Default::default()
            }))
            .build()
            .unwrap()
    } else {
        builder.build().unwrap()
    }
}

fn complete_case(
    case: &str,
    entrypoint: &str,
    cfg: &softhsm::P11Config,
    provider: &ReviewedProvider,
    advertised_mechanisms: &[u64],
    signer: Arc<dyn KeySigner>,
) {
    let evidence = PathBuf::from(
        std::env::var_os("HANKO_GENERIC_DSA_EVIDENCE_DIR")
            .expect("persistent evidence directory is mandatory for generic DSA acceptance"),
    )
    .join(case);
    std::fs::create_dir_all(&evidence).unwrap();
    // A second run must choose a fresh evidence parent, never replace a case.
    let _marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence.join("generic-dsa-native.started"))
        .unwrap();
    let token_signer = signer.signing_cert().clone();
    assert_eq!(token_signer, cfg.pki().cert("signer1"));
    assert_eq!(dsa_key_size(&token_signer.public_key()), Some(1024));
    // KeySigner::cert_chain is Pkcs11Signer's actual registry. Neither entry
    // path injects an external signing certificate or an external CA chain.
    assert_eq!(signer.cert_chain().len(), 2);
    let root = signer
        .cert_chain()
        .iter()
        .find(|cert| **cert == cfg.pki().cert("root"))
        .expect("actual token registry must contain the expected root")
        .clone();
    let intermediate = signer
        .cert_chain()
        .iter()
        .find(|cert| **cert == cfg.pki().cert("interm"))
        .expect("actual token registry must contain the expected intermediate")
        .clone();
    let algorithm = signer.signature_algorithm(DigestAlgorithm::Sha256).unwrap();
    assert_eq!(algorithm.oid.to_string(), "2.16.840.1.101.3.4.3.2");
    let operation =
        pkcs11::select_pkcs11_signing_params(&algorithm, DigestAlgorithm::Sha256, false, None)
            .unwrap();
    assert_eq!(
        operation.mechanism,
        Pkcs11Mechanism::DsaSha(DigestAlgorithm::Sha256)
    );
    assert_eq!(operation.mechanism.mechanism_type(), 0x14);
    assert!(advertised_mechanisms.contains(&operation.mechanism.mechanism_type()));
    assert_eq!(operation.pre_sign_transform, None);
    assert_eq!(
        operation.post_sign_transform,
        Some(PostSignTransform::EncodeDsa)
    );
    // Preserve the original generic default digest selection. Do not copy
    // the separate raw-DSA case's explicit SHA-256 metadata override.
    let metadata = PdfSignatureMetadata::pyhanko_defaults("Sig1");
    assert_eq!(metadata.md_algorithm, None);
    let output = PdfSigner::new(metadata, signer)
        .at(support::at(TIME))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .expect("actual native non-raw DSA signing of the original minimal PDF");
    for (name, bytes) in [
        ("native.pdf", output.as_slice()),
        ("root.der", root.der()),
        ("interm.der", intermediate.der()),
        ("signer.der", token_signer.der()),
    ] {
        std::fs::write(evidence.join(name), bytes).unwrap();
    }
    let file = sigis_pdf::PdfFile::parse(&output).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let signature = &signatures[0];
    assert_eq!(signature.field_name, "Sig1");
    let sd = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
    let si = sigis_cms::signed_data::extract_signer_info(&sd).unwrap();
    assert_eq!(si.digest().unwrap(), DigestAlgorithm::Sha256);
    let encoded_sd = sigis_pades_sign::cms::decode_signed_data(&signature.contents).unwrap();
    let encoded_si = encoded_sd.signer_infos.0.iter().next().unwrap();
    assert_eq!(encoded_si.signature_algorithm, algorithm);
    let der_signature = encoded_si.signature.as_bytes();
    let pair = DsaSignature::from_der(der_signature).expect("post-sign DER r,s");
    assert!(!pair.r.as_bytes().is_empty() && !pair.s.as_bytes().is_empty());
    let signed_attrs = encoded_si.signed_attrs.as_ref().unwrap().to_der().unwrap();
    validate_signature(
        der_signature,
        &signed_attrs,
        &token_signer.public_key(),
        &algorithm,
        &SignatureValidationContext::default(),
    )
    .unwrap();
    let mut changed = signed_attrs.clone();
    changed.push(b'!');
    assert!(validate_signature(
        der_signature,
        &changed,
        &token_signer.public_key(),
        &algorithm,
        &SignatureValidationContext::default(),
    )
    .is_err());
    let digest = DigestAlgorithm::Sha256.digest(&signature.signed_data(&file).unwrap());
    assert_eq!(
        sigis_cms::validate::validate_sig_integrity(si, &token_signer, &sd.econtent_type, &digest)
            .unwrap(),
        (true, true)
    );
    let status = sigis_pades::validate_pdf_signature(
        &file,
        signature,
        &context(&root, &intermediate, true),
        None,
    )
    .unwrap();
    assert_eq!(status.field_name, "Sig1");
    assert!(status.cms.signature.intact);
    assert!(status.cms.signature.valid);
    assert!(status.cms.signature.trusted());
    assert_eq!(
        status.cms.signature.signing_cert.as_ref(),
        Some(&token_signer)
    );
    assert_eq!(
        status
            .cms
            .signature
            .validation_path
            .as_ref()
            .unwrap()
            .certs()
            .len(),
        3
    );
    assert_eq!(
        status.coverage,
        sigis_pades::SignatureCoverageLevel::EntireFile
    );
    assert_eq!(
        status.modification_level(),
        Some(sigis_pdf_diff::ModificationLevel::None)
    );
    let summary = status.summary();
    assert!(
        summary.contains("INTACT") && summary.contains("TRUSTED"),
        "{summary}"
    );
    assert!(status.bottom_line());
    // The local original-fixture exception must never weaken global defaults.
    assert_eq!(
        DisallowWeakAlgorithmsPolicy::default().dsa_key_size_threshold,
        3192
    );
    let default_status = sigis_pades::validate_pdf_signature(
        &file,
        signature,
        &context(&root, &intermediate, false),
        None,
    )
    .unwrap();
    assert!(default_status.cms.signature.intact && default_status.cms.signature.valid);
    assert!(!default_status.cms.signature.trusted());
    assert!(!default_status.bottom_line());
    assert_eq!(
        default_status.cms.signature.trust_problem_indic,
        Some(sigis_pki_core::ades::AdesSubIndic::Indeterminate(
            sigis_pki_core::ades::AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE
        ))
    );
    assert!(default_status.cms.signature.error_time_horizon.is_none());
    let native_status = serde_json::json!({
        "case": case, "entrypoint": entrypoint,
        "field": status.field_name, "digest": "sha256", "metadata_md_algorithm": null,
        "mechanism": "CKM_DSA_SHA256", "mechanism_value": 0x14,
        "pre_sign_transform": null, "post_sign_transform": "EncodeDsa",
        "advertised_mechanisms": advertised_mechanisms, "policy_dsa_threshold": 1024,
        "intact": status.cms.signature.intact, "valid": status.cms.signature.valid,
        "trusted": status.cms.signature.trusted(), "bottom_line": status.bottom_line(),
        "summary": status.summary(), "path_len": 3,
        "coverage": "ENTIRE_FILE", "modification_level": "NONE",
        "default_policy_threshold": 3192,
        "default_trust_indication": "CRYPTO_CONSTRAINTS_FAILURE",
        "default_intact": default_status.cms.signature.intact,
        "default_valid": default_status.cms.signature.valid,
        "default_trusted": default_status.cms.signature.trusted(),
        "default_bottom_line": default_status.bottom_line()
    });
    let status_bytes = serde_json::to_vec_pretty(&native_status).unwrap();
    std::fs::write(evidence.join("native-status.json"), &status_bytes).unwrap();
    let executable = std::env::current_exe().unwrap();
    let executable_bytes = std::fs::read(&executable).unwrap();
    assert!(
        executable_bytes.starts_with(b"\x7fELF"),
        "current test executable must be ELF"
    );
    let native_receipt = serde_json::json!({
        "case": case,
        "provider": {"module": provider.module, "bytes": provider.module_bytes.len(),
            "sha256": sha256(&provider.module_bytes), "utility": provider.utility,
            "utility_bytes": provider.utility_bytes.len(),
            "utility_sha256": sha256(&provider.utility_bytes)},
        "binary": {"path": executable, "bytes": executable_bytes.len(),
            "sha256": sha256(&executable_bytes)},
        "outputs": [
            {"file": "native.pdf", "bytes": output.len(), "sha256": sha256(&output)},
            {"file": "root.der", "bytes": root.der().len(), "sha256": sha256(root.der())},
            {"file": "interm.der", "bytes": intermediate.der().len(), "sha256": sha256(intermediate.der())},
            {"file": "signer.der", "bytes": token_signer.der().len(), "sha256": sha256(token_signer.der())},
            {"file": "native-status.json", "bytes": status_bytes.len(), "sha256": sha256(&status_bytes)}
        ],
        "status": native_status,
        "compilation_source_proof": "requires independent L compiler-input audit"
    });
    std::fs::write(
        evidence.join("native-receipt.json"),
        serde_json::to_vec_pretty(&native_receipt).unwrap(),
    )
    .unwrap();
    println!("GENERIC_DSA_NATIVE_RECEIPT {native_receipt}");
    let python = std::env::var_os("HANKO_ORACLE")
        .unwrap_or_else(|| "/tmp/pyhanko-oracle/venv/bin/python".into());
    let mut command = Command::new(python);
    command
        .args([
            "-B",
            "-s",
            "-P",
            "-c",
            include_str!("support/raw_dsa_oracle.py"),
        ])
        .arg(&evidence);
    // Assertions and interpreter selection must not be altered by inherited
    // Python settings. The isolated python-pkcs11 0.9.5 overlay is mandatory.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("PYTHON") {
            command.env_remove(key);
        }
    }
    let overlay = std::env::var_os("HANKO_DSA_ORACLE_OVERLAY")
        .expect("reviewed python-pkcs11 0.9.5 isolated overlay is required");
    command.env("PYTHONPATH", overlay);
    command.env("PYTHONDONTWRITEBYTECODE", "1");
    command.env("PYTHONNOUSERSITE", "1");
    let oracle = command
        .output()
        .expect("mandatory pinned same-output oracle must start");
    std::fs::write(evidence.join("oracle.stdout.json"), &oracle.stdout).unwrap();
    std::fs::write(evidence.join("oracle.stderr.log"), &oracle.stderr).unwrap();
    assert!(
        oracle.status.success(),
        "mandatory oracle rejected: {}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let verdict: serde_json::Value = serde_json::from_slice(&oracle.stdout).unwrap();
    assert_eq!(verdict["pyhanko"], "0.38.1");
    assert_eq!(verdict["certvalidator"], "0.33.0");
    assert_eq!(verdict["python_pkcs11"], "0.9.5");
    assert_eq!(verdict["policy_dsa_threshold"], 1024);
    assert_eq!(verdict["count"], 1);
    assert_eq!(verdict["field"], "Sig1");
    assert_eq!(verdict["md_algorithm"], "sha256");
    for key in ["intact", "valid", "trusted", "bottom_line"] {
        assert_eq!(verdict[key], true, "{key}: {verdict}");
    }
    assert_eq!(verdict["coverage"], "ENTIRE_FILE");
    assert_eq!(verdict["modification_level"], "NONE");
    let summary = verdict["summary"].as_str().unwrap();
    assert!(summary.contains("INTACT") && summary.contains("TRUSTED"));
    assert_eq!(verdict["default_policy_rejected"], true);
    assert_eq!(verdict["default_policy"]["intact"], true);
    assert_eq!(verdict["default_policy"]["valid"], true);
    assert_eq!(verdict["default_policy"]["trusted"], false);
    assert_eq!(verdict["default_policy"]["bottom_line"], false);
    // Both implementations must validate the exact native bytes exported here.
    assert_eq!(verdict["pdf_sha256"], sha256(&output));
    assert_eq!(verdict["signer_sha256"], sha256(token_signer.der()));
    let opened = verdict["opened_inputs"].as_array().unwrap();
    assert_eq!(opened.len(), 4);
    for name in ["native.pdf", "root.der", "interm.der", "signer.der"] {
        let path = evidence.join(name).canonicalize().unwrap();
        let path_text = path.to_str().unwrap();
        let record = opened
            .iter()
            .find(|record| record["path"] == path_text)
            .unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(record["bytes"], bytes.len());
        assert_eq!(record["sha256"], sha256(&bytes));
    }
}

#[test]
fn test_simple_sign() {
    let _guard = softhsm::lock();
    let provider = reviewed_provider();
    let cfg = fixture(&provider);
    for (bulk_fetch, case) in [
        (true, "simple-sign-bulk-true"),
        (false, "simple-sign-bulk-false"),
    ] {
        let (session, advertised_mechanisms) = checked_session(&cfg);
        let options = Pkcs11SignerOptions {
            cert_label: Some(cfg.cert_label.clone()),
            key_label: cfg.key_label.clone(),
            other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
            bulk_fetch,
            ..Default::default()
        };
        assert!(!options.use_raw_mechanism);
        assert!(options.signing_cert.is_none());
        assert!(options.ca_chain.is_empty());
        assert!(
            options.signing_pin.is_none(),
            "original SoftHSM signing_kwargs is empty"
        );
        assert!(options.signature_mechanism.is_none());
        assert!(options.mechanism_override.is_none());
        let signer = Arc::new(Pkcs11Signer::new(session, options).unwrap());
        assert_eq!(signer.cert_registry(), signer.cert_chain());
        complete_case(
            case,
            "Pkcs11Signer::new",
            &cfg,
            &provider,
            &advertised_mechanisms,
            signer,
        );
    }
}

#[test]
fn test_simple_sign_from_config_async() {
    let _guard = softhsm::lock();
    let provider = reviewed_provider();
    let cfg = fixture(&provider);
    // Same configured actual token, same upstream gate; the signer itself
    // must still be opened through pkcs11::open, never substituted directly.
    let (gate_session, advertised_mechanisms) = checked_session(&cfg);
    drop(gate_session);
    let config = Pkcs11Config {
        module_path: cfg.module.clone(),
        token_criteria: Some(TokenCriteria::label(&cfg.token_label)),
        cert_label: Some(cfg.cert_label.clone()),
        key_label: cfg.key_label.clone(),
        user_pin: Some(cfg.user_pin.clone()),
        other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
        ..Default::default()
    };
    assert!(!config.raw_mechanism);
    assert!(
        config.bulk_fetch,
        "upstream config case has no bulk parameter"
    );
    assert!(config.signing_certificate.is_none());
    assert!(config.other_certs.is_empty());
    assert!(config.signature_mechanism.is_none());
    assert!(config.signing_pin.is_none());
    assert_eq!(config.signing_pin_mode, pkcs11::SigningPinEntryMode::Skip);
    // Public Rust adaptation of async context open + async_sign_pdf: blocking
    // pkcs11::open + PdfSigner::sign_pdf. No async scheduling claim is made.
    let signer = pkcs11::open(&config, None).unwrap();
    complete_case(
        "simple-sign-from-config-async",
        "pkcs11::open (blocking adaptation)",
        &cfg,
        &provider,
        &advertised_mechanisms,
        signer,
    );
}
