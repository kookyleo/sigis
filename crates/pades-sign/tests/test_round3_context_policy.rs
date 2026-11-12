//! Regression coverage for caller policy enforcement during PDF presigning.
//!
//! These are additional behavioral regressions, not new upstream function ports.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use const_oid::ObjectIdentifier;
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::errors::HankoError;
use sigis_pki_core::time::Moment;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const TIME: &str = "2020-11-01T00:00:00Z";
const DENIAL: &str = "Caller policy forbids SHA-256 RSA certificate signatures";

#[derive(Debug)]
struct CertificateSignaturePolicy {
    allow_sha256_rsa: bool,
}

impl AlgorithmUsagePolicy for CertificateSignaturePolicy {
    fn digest_algorithm_allowed(
        &self,
        _algorithm: &ObjectIdentifier,
        _moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::allowed()
    }

    fn signature_algorithm_allowed(
        &self,
        algorithm: &AlgorithmIdentifierOwned,
        _moment: Option<Moment>,
        _public_key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        if algorithm.oid == oids::SHA256_WITH_RSA && !self.allow_sha256_rsa {
            AlgorithmUsageConstraint::denied(DENIAL)
        } else {
            AlgorithmUsageConstraint::allowed()
        }
    }
}

fn pdf_signer(allow_sha256_rsa: bool) -> PdfSigner {
    let pki = support::pki("testing-ca");
    // Deny the actual certificate signature algorithm, rather than depending
    // on a policy callback that the certificate validator does not consume.
    assert_eq!(
        pki.cert("signer1").decoded().signature_algorithm().oid,
        oids::SHA256_WITH_RSA
    );
    let context = ValidationContext::builder()
        .trust_root(pki.cert("root"))
        .moment(support::at(TIME))
        .revocation_mode("soft-fail")
        .algorithm_policy(Arc::new(CertificateSignaturePolicy { allow_sha256_rsa }))
        .build()
        .unwrap();
    let mut metadata = PdfSignatureMetadata::new("SigPolicy");
    metadata.validation_context = Some(Arc::new(context));
    PdfSigner::new(metadata, Arc::new(pki.signer("signer1"))).at(support::at(TIME))
}

#[test]
fn presign_rejects_certificate_signature_forbidden_by_caller_policy() {
    // A complete signing request must stop during certificate prevalidation.
    // Rebuilding its context with default policies incorrectly signs this PDF.
    let Err(error) = pdf_signer(false).sign_pdf(&support::pdf("minimal.pdf")) else {
        panic!("PDF signing must enforce the caller's certificate algorithm policy");
    };
    assert!(matches!(error, HankoError::Signing(_)), "{error}");
    let message = error.to_string();
    assert!(message.contains("could not be validated"), "{message}");
    assert!(message.contains("disallowed algorithm"), "{message}");
    assert!(message.contains(DENIAL), "{message}");
}

#[test]
fn presign_allows_certificate_signature_permitted_by_caller_policy() {
    // The same native fixtures and operation must succeed when the caller
    // permits the algorithm, ruling out an unrelated preparation failure.
    let output = pdf_signer(true)
        .sign_pdf(&support::pdf("minimal.pdf"))
        .unwrap();
    let file = sigis_pdf::PdfFile::parse(&output).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0].field_name, "SigPolicy");
    let context = support::services::simple_vc("testing-ca", TIME);
    let status =
        sigis_pades::validate_pdf_signature(&file, &signatures[0], &context, None).unwrap();
    assert!(status.bottom_line(), "{status:?}");
}
