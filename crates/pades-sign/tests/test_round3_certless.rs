//! Exact certificate-less signing cases from pyHanko 0.38.1.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use sigis_pades_sign::cms::{AttrProfile, CmsSigner, CmsSignerOptions};
use sigis_pades_sign::pdf::seed::{SigCertConstraintFlags, SigCertConstraints};
use sigis_pades_sign::pdf::signer::{PdfTbsDocument, SignOptions};
use sigis_pades_sign::signer::{DeferredSignatureValue, DeferredSigner, SigningProvider};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SigFieldSpec, SigSeedValueSpec};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::errors::HankoError;
use spki::AlgorithmIdentifierOwned;

const TIME: &str = "2020-11-01T00:00:00Z";

fn rsa_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: sigis_pki_core::asn1::oids::SHA256_WITH_RSA,
        parameters: None,
    }
}

fn provider(
    value: DeferredSignatureValue,
    mechanism: Option<AlgorithmIdentifierOwned>,
) -> DeferredSigner {
    DeferredSigner::new(None, Vec::new(), value, mechanism)
}

fn pdf_signer(metadata: PdfSignatureMetadata, signer: DeferredSigner) -> PdfSigner {
    PdfSigner::with_signing_provider(metadata, Arc::new(signer)).at(support::at(TIME))
}

fn options() -> SignOptions {
    SignOptions {
        bytes_reserved: Some(8192),
        ..Default::default()
    }
}

fn assert_signing_error(error: HankoError, before: &str, after: &str) {
    assert!(matches!(error, HankoError::Signing(_)), "{error}");
    let message = error.to_string();
    let prefix = message.find(before).unwrap_or_else(|| panic!("{message}"));
    assert!(message[prefix..].contains(after), "{message}");
}

fn complete_and_validate(tbs: PdfTbsDocument, copy_output: bool) {
    assert_eq!(tbs.md_algorithm, DigestAlgorithm::Sha256);
    assert!(tbs.post_sign_instructions.is_none());
    let mut prepared = tbs.prepared;
    if copy_output {
        let copied = prepared.output.to_vec();
        assert_eq!(copied, prepared.output);
        prepared.output = copied;
    }
    let signer = support::pki("testing-ca").signer("signer1");
    let cms = CmsSigner {
        signer: &signer,
        options: &CmsSignerOptions::default(),
    }
    .sign(
        &prepared.document_digest,
        tbs.md_algorithm,
        &Default::default(),
        AttrProfile::GenericPdf,
        None,
        false,
        None,
    )
    .unwrap();
    let output = PdfTbsDocument::finish_signing(prepared, &cms, None, None).unwrap();
    let signatures = support::pdfcheck::embedded_signatures(&output);
    assert_eq!(signatures[0].field_name, "SigNew");
    support::pdfcheck::check_integrity(&output, &signatures[0]);
    let file = sigis_pdf::PdfFile::parse(&output).unwrap();
    let signature = &file.embedded_signatures().unwrap()[0];
    let context = support::services::simple_vc("testing-ca", TIME);
    let status = sigis_pades::validate_pdf_signature(&file, signature, &context, None).unwrap();
    assert!(status.bottom_line(), "{status:?}");
    let root = support::pki("testing-ca").cert_path("root");
    let verdicts = support::pdfcheck::oracle_verdicts(&output, &[&root], TIME, &[])
        .expect("the pinned live oracle is required for this exact port");
    assert_eq!(verdicts[0]["bottom_line"], true, "{}", verdicts[0]);
    eprintln!("live oracle delayed signing certificate: {}", verdicts[0]);
}

#[test]
fn test_interrupted_with_delayed_signing_cert_mech() {
    let signer = pdf_signer(
        PdfSignatureMetadata::pyhanko_defaults("SigNew"),
        provider(DeferredSignatureValue::Size(256), Some(rsa_sha256())),
    );
    let tbs = signer
        .digest_doc_for_signing(&support::pdf("minimal.pdf"), &options())
        .unwrap();
    complete_and_validate(tbs, true);
}

#[test]
fn test_interrupted_with_delayed_signing_cert_directly_specify_md() {
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults("SigNew");
    metadata.md_algorithm = Some(DigestAlgorithm::Sha256);
    let signer = pdf_signer(metadata, provider(DeferredSignatureValue::Size(256), None));
    let tbs = signer
        .digest_doc_for_signing(&support::pdf("minimal.pdf"), &options())
        .unwrap();
    complete_and_validate(tbs, false);
}

#[test]
fn test_interrupted_could_not_determine_digest_algo() {
    let signer = pdf_signer(
        PdfSignatureMetadata::pyhanko_defaults("SigNew"),
        provider(DeferredSignatureValue::Size(256), None),
    );
    let error = signer
        .digest_doc_for_signing(&support::pdf("minimal.pdf"), &Default::default())
        .unwrap_err();
    assert_signing_error(error, "Could not select", "digest algorithm");
}

#[test]
fn test_interrupted_no_estimation() {
    let signer = pdf_signer(
        PdfSignatureMetadata::pyhanko_defaults("SigNew"),
        provider(
            DeferredSignatureValue::Bytes(vec![0; 256]),
            Some(rsa_sha256()),
        ),
    );
    let error = signer
        .digest_doc_for_signing(&support::pdf("minimal.pdf"), &Default::default())
        .unwrap_err();
    assert_signing_error(error, "estimation", "bytes_reserved");
}

#[test]
fn test_interrupted_with_delayed_signing_no_prevalidation() {
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults("SigNew");
    metadata.embed_validation_info = true;
    metadata.validation_context = Some(Arc::new(support::services::simple_vc("testing-ca", TIME)));
    let signer = pdf_signer(
        metadata,
        provider(DeferredSignatureValue::Size(256), Some(rsa_sha256())),
    );
    let error = signer
        .digest_doc_for_signing(&support::pdf("minimal.pdf"), &options())
        .unwrap_err();
    assert_signing_error(
        error,
        "certificate must be provided",
        "certificate must be provided",
    );
}

#[test]
fn test_determine_mechanism_no_signing_cert() {
    let signer = provider(DeferredSignatureValue::Bytes(vec![0; 256]), None);
    assert!(signer.signing_cert().is_none());
    let error = signer
        .signature_algorithm(DigestAlgorithm::Sha256)
        .unwrap_err();
    assert_signing_error(error, "Could not set up", "mechanism");
}

#[test]
fn test_signer_info_no_signing_cert() {
    let signer = provider(DeferredSignatureValue::Size(256), Some(rsa_sha256()));
    let error = CmsSigner {
        signer: &signer,
        options: &CmsSignerOptions::default(),
    }
    .sign_general_data(
        b"Hello world",
        DigestAlgorithm::Sha256,
        true,
        false,
        None,
        &Default::default(),
    )
    .unwrap_err();
    assert_signing_error(error, "certificate must be available", "SignerInfo");
}

#[test]
fn test_sign_with_sv_missing_cert() {
    let seed = SigSeedValueSpec {
        cert: Some(SigCertConstraints {
            flags: SigCertConstraintFlags::SUBJECT_DN,
            subject_dn: Some(vec![("2.5.4.3".into(), "Alice".into())]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut field = SigFieldSpec::new("Sig");
    field.seed_value_dict = Some(seed);
    let mut update =
        sigis_pades_sign::pdf::writer::PdfUpdate::new(&support::pdf("minimal.pdf")).unwrap();
    sigis_pades_sign::pdf::fields::append_signature_field(&mut update, &field).unwrap();
    let input = update.write().unwrap().0;
    let signer = pdf_signer(
        PdfSignatureMetadata::pyhanko_defaults(""),
        provider(DeferredSignatureValue::Size(256), Some(rsa_sha256())),
    );
    let error = signer
        .sign_pdf_with(
            &input,
            &SignOptions {
                existing_fields_only: true,
                ..options()
            },
        )
        .unwrap_err();
    assert_signing_error(error, "Cannot verify seed value", "certificate");
}

#[test]
fn mechanism_conflict_precedes_missing_signer_info_certificate() {
    let signer = provider(
        DeferredSignatureValue::Size(256),
        Some(AlgorithmIdentifierOwned {
            oid: sigis_pki_core::asn1::oids::SHA512_WITH_RSA,
            parameters: None,
        }),
    );
    let error = CmsSigner {
        signer: &signer,
        options: &CmsSignerOptions::default(),
    }
    .sign_general_data(
        b"Hello world",
        DigestAlgorithm::Sha256,
        true,
        false,
        None,
        &Default::default(),
    )
    .unwrap_err();
    assert_signing_error(error, "Selected signature mechanism", "sha512");
}

#[test]
fn missing_presign_certificate_precedes_missing_validation_context() {
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults("SigNew");
    metadata.embed_validation_info = true;
    let signer = pdf_signer(
        metadata,
        provider(DeferredSignatureValue::Size(256), Some(rsa_sha256())),
    );
    let error = signer
        .digest_doc_for_signing(&support::pdf("minimal.pdf"), &options())
        .unwrap_err();
    assert_signing_error(
        error,
        "certificate must be provided",
        "certificate must be provided",
    );
}
