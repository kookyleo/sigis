//! Port of the single original SoftHSM raw-DSA function.
//! This root suite requires a real token and separate fresh oracle proofs.
//! Unique upstream credit requires the complete lead workspace gate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../crates/pades-sign/tests/support/softhsm.rs"]
mod softhsm;
#[path = "support/signing_integration.rs"]
mod support;

// The reused native fixture module resolves these from its parent.
use der::{Decode, Encode};
use sigis_pades_sign::pkcs11::{
    self, open_pkcs11_session, Pkcs11Mechanism, Pkcs11Signer, Pkcs11SignerOptions,
    PostSignTransform, PreSignTransform, TokenCriteria, UserPin,
};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::{
    dsa_key_size, validate_signature, DigestAlgorithm, DisallowWeakAlgorithmsPolicy,
    SignatureValidationContext,
};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::sign::KeySigner;
use std::{process::Command, sync::Arc};
use support::{pki, Pki};

const TIME: &str = "2020-11-01T00:00:00Z";

#[derive(der::Sequence)]
struct DsaSignature<'a> {
    r: der::asn1::UintRef<'a>,
    s: der::asn1::UintRef<'a>,
}

fn sha256(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn context(root: &Cert, intermediate: &Cert, original_case: bool) -> ValidationContext {
    let builder = ValidationContext::builder()
        .trust_root(root.clone())
        .other_cert(intermediate.clone())
        .moment(support::at(TIME))
        // P11TestConfig.validation_context is constructed at the frozen clock,
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

/// Supplemental actual CKM_DSA operation; zero additional upstream IDs.
/// The PDF below still goes through the real Pkcs11Signer implementation.
fn assert_actual_raw_token_signature(signer: &Pkcs11Signer, signed_attrs: &[u8]) {
    use pkcs11::cryptoki::mechanism::{
        vendor_defined::VendorDefinedMechanism, Mechanism, MechanismType,
    };
    use pkcs11::cryptoki::object::{Attribute, KeyType, ObjectClass};

    let keys = signer
        .session()
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::DSA),
            Attribute::Label(b"signer1".to_vec()),
        ])
        .unwrap();
    assert_eq!(keys.len(), 1);
    let mechanism = Mechanism::VendorDefined(VendorDefinedMechanism::new::<()>(
        MechanismType::try_from(0x11_u64).expect("standard CKM_DSA conversion is required"),
        None,
    ));
    let digest = DigestAlgorithm::Sha256.digest(signed_attrs);
    assert_eq!(digest.len(), 32, "SHA-256 prehash without DigestInfo");
    let raw = signer
        .session()
        .with(|session| Ok(session.sign(&mechanism, keys[0], &digest)?))
        .expect("actual native CKM_DSA C_Sign must succeed");
    let public_key = signer.signing_cert().public_key();
    let params = public_key
        .algorithm
        .parameters
        .as_ref()
        .unwrap()
        .decode_as::<softhsm::DsaParameters<'_>>()
        .unwrap();
    let width = params.subprime.as_bytes().len();
    assert_eq!(
        raw.len(),
        width * 2,
        "native DSA returns fixed-width r || s"
    );
    let encoded = DsaSignature {
        r: der::asn1::UintRef::new(&raw[..width]).unwrap(),
        s: der::asn1::UintRef::new(&raw[width..]).unwrap(),
    }
    .to_der()
    .unwrap();
    let algorithm = signer.signature_algorithm(DigestAlgorithm::Sha256).unwrap();
    validate_signature(
        &encoded,
        signed_attrs,
        &public_key,
        &algorithm,
        &SignatureValidationContext::default(),
    )
    .unwrap();
    let mut changed = signed_attrs.to_vec();
    changed.push(b'!');
    assert!(validate_signature(
        &encoded,
        &changed,
        &public_key,
        &algorithm,
        &SignatureValidationContext::default()
    )
    .is_err());
}

#[test]
fn test_simple_sign_with_raw_dsa() {
    let _guard = softhsm::lock();
    // A real provider/capability is required; no passing availability shortcut.
    // Generic ALL_ALGOS exclusions remain separate from this DSA operation.
    let cfg =
        softhsm::raw_dsa_config().expect("explicit complete raw DSA native fixture is required");
    assert_eq!(cfg.module, softhsm::module_path().unwrap());
    assert_eq!(cfg.algo, "dsa");
    assert_eq!(cfg.arch, "testing-ca-dsa");
    assert_eq!(cfg.token_label, "testdsa");
    assert_eq!(cfg.cert_chain_labels, ["root", "interm"]);
    let session = Arc::new(
        open_pkcs11_session(
            &cfg.module,
            None,
            Some(&TokenCriteria::label(&cfg.token_label)),
            &UserPin::Pin(cfg.user_pin.clone()),
        )
        .unwrap(),
    );
    let mechanisms = session.mechanisms().expect("actual token enumeration");
    // Exact upstream required_mechanism fixture gate precedes raw signing.
    assert!(
        mechanisms.contains(&Pkcs11Mechanism::DsaSha(DigestAlgorithm::Sha256).mechanism_type()),
        "upstream fixture requires DSA_SHA256 (0x14)"
    );
    assert!(
        mechanisms.contains(&Pkcs11Mechanism::Dsa.mechanism_type()),
        "actual raw CKM_DSA (0x11) is also required"
    );
    let options = Pkcs11SignerOptions {
        cert_label: Some(cfg.cert_label.clone()),
        key_label: cfg.key_label.clone(),
        other_certs_to_pull: Some(cfg.cert_chain_labels.clone()),
        use_raw_mechanism: true,
        ..Default::default()
    };
    assert!(options.signing_cert.is_none());
    assert!(options.ca_chain.is_empty());
    assert!(
        options.signing_pin.is_none(),
        "original SoftHSM signing_kwargs is empty"
    );
    let signer = Arc::new(Pkcs11Signer::new(session, options).unwrap());
    let token_signer = signer.signing_cert().clone();
    assert_eq!(token_signer, cfg.pki().cert("signer1"));
    assert_eq!(dsa_key_size(&token_signer.public_key()), Some(1024));
    assert_eq!(signer.cert_registry().len(), 2);
    let root = signer
        .cert_registry()
        .iter()
        .find(|cert| **cert == cfg.pki().cert("root"))
        .unwrap()
        .clone();
    let intermediate = signer
        .cert_registry()
        .iter()
        .find(|cert| **cert == cfg.pki().cert("interm"))
        .unwrap()
        .clone();
    // Native signer and both chain certificates above were pulled from token.
    let algorithm = signer.signature_algorithm(DigestAlgorithm::Sha256).unwrap();
    assert_eq!(algorithm.oid.to_string(), "2.16.840.1.101.3.4.3.2");
    let operation =
        pkcs11::select_pkcs11_signing_params(&algorithm, DigestAlgorithm::Sha256, true, None)
            .unwrap();
    assert_eq!(operation.mechanism, Pkcs11Mechanism::Dsa);
    assert_eq!(
        operation.pre_sign_transform,
        Some(PreSignTransform::HashFully {
            digest: DigestAlgorithm::Sha256,
            wrap_digest_info: false,
        })
    );
    assert_eq!(
        operation.post_sign_transform,
        Some(PostSignTransform::EncodeDsa)
    );
    let metadata = PdfSignatureMetadata {
        md_algorithm: Some(DigestAlgorithm::Sha256),
        ..PdfSignatureMetadata::pyhanko_defaults("Sig1")
    };
    let output = PdfSigner::new(metadata, signer.clone())
        .at(support::at(TIME))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .expect("actual native token signing of original minimal PDF");
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
    assert_actual_raw_token_signature(&signer, &signed_attrs);
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
    // Independent negative control: local fixture policy must not weaken defaults.
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
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path();
    for (name, bytes) in [
        ("native.pdf", output.as_slice()),
        ("root.der", root.der()),
        ("interm.der", intermediate.der()),
        ("signer.der", token_signer.der()),
    ] {
        std::fs::write(directory.join(name), bytes).unwrap();
    }
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
        .arg(directory);
    // Inherited PYTHONOPTIMIZE/PYTHONHOME must not disable assertions or
    // redirect the pinned interpreter.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("PYTHON") {
            command.env_remove(key);
        }
    }
    if let Some(overlay) = softhsm::oracle_overlay() {
        command.env("PYTHONPATH", overlay);
    }
    command.env("PYTHONDONTWRITEBYTECODE", "1");
    command.env("PYTHONNOUSERSITE", "1");
    let oracle = command
        .output()
        .expect("mandatory pinned same-output oracle must start");
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
    // Same bytes are exported above and hashed by both native and Python code.
    assert_eq!(verdict["pdf_sha256"], sha256(&output));
    assert_eq!(verdict["signer_sha256"], sha256(token_signer.der()));
}
