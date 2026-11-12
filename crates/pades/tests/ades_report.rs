// Port of pyHanko 0.38.1 tests/test_ades_validation_report.py (MIT).
// Assertions inspect reports derived from actual Rust validation results.

mod common;

use common::*;
use sigis_pades::ades::basic::{basic_validation, QualificationSpec};
use sigis_pades::ades::etsi_report::{
    generate_report, ReportInput, ReportValidation, ValidationProcess,
};
use sigis_pki_core::time::Moment;

const MODULE: &str = "test_ades_validation_report";

fn basic_report(test: &str) -> String {
    let recording = std::env::var("HANKO_REPORT_RECORDING")
        .map(|path| Recording(serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()))
        .unwrap_or_else(|_| Recording::load(MODULE));
    let calls = recording.calls(MODULE, test);
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    let content_info = call.content_info();
    let digest = call.raw_digest().expect("detached PDF digest");
    let result = basic_validation(
        &content_info,
        Some(&digest),
        &default_context(&recording, call),
        &QualificationSpec::default(),
    )
    .unwrap();
    assert_eq!(
        result.ades_subindic.standard_name(),
        call.expected_subindic()
    );
    let validation = ReportValidation {
        validation_time: call.time(),
        best_signature_time: None,
        process: ValidationProcess::Basic,
        subindication: result.ades_subindic,
        status: result.api_status.as_ref().unwrap(),
    };
    generate_report(&ReportInput::from_cms(&content_info, &digest, &validation).unwrap()).unwrap()
}

#[test]
fn test_pades_basic_report_smoke_test() {
    let report = basic_report("test_pades_basic_report_smoke_test");
    assert!(report.contains("urn:etsi:019102:mainindication:total-passed"));
}

#[test]
fn test_pades_basic_failing_report_smoke_test() {
    let report = basic_report("test_pades_basic_failing_report_smoke_test");
    assert!(report.contains("urn:etsi:019102:mainindication:total-failed"));
    assert!(report.contains("urn:etsi:019102:subindication:HASH_FAILURE"));
    assert!(!report.contains("urn:etsi:019102:mainindication:total-passed"));
}

#[test]
fn test_pades_basic_indeteriminate_report_smoke_test() {
    let report = basic_report("test_pades_basic_indeteriminate_report_smoke_test");
    assert!(report.contains("urn:etsi:019102:mainindication:indeterminate"));
    assert!(!report.contains("urn:etsi:019102:mainindication:total-passed"));
}

#[test]
fn report_uses_etsi_namespaces_and_certificate_reference_attributes() {
    let report = basic_report("test_pades_basic_report_smoke_test");
    assert!(report
        .split("<vr:SignatureIdentifier>")
        .nth(1)
        .unwrap()
        .trim_start()
        .starts_with("<vr:DigestAlgAndValue>"));
    assert!(!report.contains("<XAdES:DigestAlgAndValue>"));
    assert!(report.contains("<vr:SignerCertificate VOReference=\"vo-certificate-"));
    assert!(!report.contains("<vr:VOReference>"));
    let certificate_id = report.split("<vr:CertID>").nth(1).unwrap();
    if let Some(issuer_serial) = certificate_id.find("<vr:X509IssuerSerial>") {
        assert!(issuer_serial < certificate_id.find("<ds:DigestMethod").unwrap());
    }
    // Independent asn1crypto hashes of signed_attrs.dump() in the inherited
    // and fresh pinned-oracle recordings. The report hashes the original [0]
    // encoding; CMS cryptographic verification instead uses a SET tag.
    assert!(
        report.contains("yPv8Vb5iZRH0TfCh07as4gciQGii8u+HyBnF0JvHySc=")
            || report.contains("CD3Q1cVnm4g9XI3+k/BDn1Xw2leAPM/zmECOun6/4UY=")
    );
}

#[test]
fn report_pdf_metadata_comes_from_the_signed_dictionary() {
    let recording = Recording::load(MODULE);
    let call = recording
        .calls(MODULE, "test_pades_with_attributes_report_smoke_test")
        .into_iter()
        .find(|call| call.function() == "ades_lta_validation")
        .unwrap();
    let (bytes, name) = call.pdf();
    let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|signature| signature.field_name == name)
        .unwrap();
    // These deliberately absent CMS fields force the /M fallback. They make
    // no statement about signature trust; this checks report field sourcing.
    let status = sigis_cms::StandardCmsSignatureStatus::default();
    let validation = ReportValidation {
        validation_time: call.time(),
        best_signature_time: None,
        process: ValidationProcess::Basic,
        subindication: sigis_pades::ades::AdesIndeterminate::GENERIC.into(),
        status: &status,
    };
    let input = ReportInput::from_pdf(&file, &signature, &validation).unwrap();
    assert_eq!(input.attributes.name.as_deref(), Some("John Doe"));
    assert_eq!(input.attributes.reason.as_deref(), Some("Testing"));
    assert_eq!(
        input.attributes.contact_info.as_deref(),
        Some("john.doe@example.com")
    );
    assert_eq!(input.attributes.location.as_deref(), Some("Somewhere"));
    assert_eq!(
        input.attributes.signing_time,
        Moment::parse_rfc3339("2020-11-20T00:00:00Z")
    );
    assert_eq!(input.attributes.byte_range, signature.byte_range);
    assert_eq!(input.attributes.sub_filter, "ETSI.CAdES.detached");
    assert!(!input.attributes.message_digest.is_empty());
    assert!(input.attributes.signer_roles.is_empty());
    let report = generate_report(&input).unwrap();
    assert!(!report.contains("<vr:EndorsementType>certified</vr:EndorsementType>"));
}
