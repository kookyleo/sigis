// Exact LTA report assertions with native archival and attribute validation.
mod common;
use common::*;
use sigis_pades::ades::basic::QualificationSpec;
use sigis_pades::ades::etsi_report::{
    generate_report, ReportInput, ReportValidation, ValidationProcess,
};
const MODULE: &str = "test_ades_validation_report";
fn lta_report(test: &str) -> String {
    let recording = Recording::load(MODULE);
    let call = recording
        .calls(MODULE, test)
        .into_iter()
        .find(|c| c.function() == "ades_lta_validation")
        .unwrap();
    let (bytes, name) = call.pdf();
    let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    let signature = signatures.iter().find(|s| s.field_name == name).unwrap();
    let attributes = test == "test_pades_with_attributes_report_smoke_test";
    let ctx = if attributes {
        sigis_pki_certvalidator::ValidationContext::builder()
            .trust_root(recording.cert("testing-ca-with-aa", "root"))
            .moment(call.time())
            .revinfo_policy(default_revinfo_policy())
            .fetchers(call.fetchers())
            .build()
            .unwrap()
    } else {
        default_context(&recording, &call)
    };
    let ac = attributes.then(|| {
        sigis_pki_certvalidator::ValidationContext::builder()
            .trust_root(recording.cert("testing-ca-with-aa", "root-aa"))
            .moment(call.time())
            .revinfo_policy(default_revinfo_policy())
            .fetchers(call.fetchers())
            .build()
            .unwrap()
    });
    // Exact current-time AA HTTP responses are replayed as raw local
    // material; this is not a claim that the Cert-only transport fetches ACs.
    let ac = ac.map(|ctx| call.with_recorded_revinfo(&ctx));
    let result = sigis_pades::ades::lta::lta_validation_with_options(
        &file,
        signature,
        &ctx,
        &QualificationSpec::default(),
        &sigis_pades::ades::lta::LtaOptions {
            ac_validation_context: ac.as_ref(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        result.ades_subindic.standard_name(),
        call.expected_subindic()
    );
    if attributes {
        let status = result.api_status.as_ref().unwrap();
        assert!(
            status
                .cades_signer_attrs
                .as_ref()
                .and_then(|attrs| attrs.certified_attrs.as_ref())
                .is_some_and(|attrs| !attrs.0.is_empty()),
            "certified AC diagnostics: {:?}; aggregate: {:?}",
            status.cades_signer_attrs,
            status.ac_validation_errs
        );
    }
    let validation = ReportValidation {
        validation_time: call.time(),
        best_signature_time: result.best_signature_time,
        process: ValidationProcess::Lta,
        subindication: result.ades_subindic,
        status: result.api_status.as_ref().unwrap(),
    };
    generate_report(&ReportInput::from_pdf(&file, signature, &validation).unwrap()).unwrap()
}

#[test]
fn test_pades_lta_report_smoke_test() {
    let report = lta_report("test_pades_lta_report_smoke_test");
    assert!(report.contains("urn:etsi:019102:mainindication:total-passed"));
    assert!(report.contains("urn:etsi:019102:validationprocess:LTA"));
}

#[test]
fn test_pades_with_attributes_report_smoke_test() {
    let report = lta_report("test_pades_with_attributes_report_smoke_test");
    assert!(report.contains("urn:etsi:019102:mainindication:total-passed"));
    assert!(report.contains("claimed"));
    assert!(report.contains("certified"));
    assert!(report.contains("urn:etsi:019102:validationprocess:LTA"));
    assert!(report.contains("vr:CommitmentTypeIndication"));
    assert!(report.contains("vr:Name"));
    assert!(report.contains("vr:Reason"));
    assert!(report.contains("vr:ContactInfo"));
    assert!(report.contains("vr:SignatureProductionPlace"));
}

#[test]
fn certified_report_requires_authenticated_attribute_revocation_evidence() {
    use base64::Engine;
    let recording = Recording::load(MODULE);
    let mut call = recording
        .calls(MODULE, "test_pades_with_attributes_report_smoke_test")
        .into_iter()
        .find(|c| c.function() == "ades_lta_validation")
        .unwrap();
    let ctx = sigis_pki_certvalidator::ValidationContext::builder()
        .trust_root(recording.cert("testing-ca-with-aa", "root"))
        .moment(call.time())
        .revinfo_policy(default_revinfo_policy())
        .fetchers(call.fetchers())
        .build()
        .unwrap();
    let ac = sigis_pki_certvalidator::ValidationContext::builder()
        .trust_root(recording.cert("testing-ca-with-aa", "root-aa"))
        .moment(call.time())
        .revinfo_policy(default_revinfo_policy())
        .fetchers(call.fetchers())
        .build()
        .unwrap();
    let ac_ok = call.with_recorded_revinfo(&ac);
    let (bytes, name) = call.pdf();
    let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
    let sig = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.field_name == name)
        .unwrap();
    let signed = sig.signed_data(&file).unwrap();
    let valid = sigis_cms::validate_cms_signature_with(
        &sig.contents,
        sigis_cms::SignedContent::Data(&signed),
        &ctx,
        &sigis_cms::CmsValidationOptions {
            ac_validation_context: Some(&ac_ok),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(valid.signature.intact && valid.signature.valid);
    assert!(!valid
        .cades_signer_attrs
        .as_ref()
        .unwrap()
        .certified_attrs
        .as_ref()
        .unwrap()
        .0
        .is_empty());
    let mut changed = 0;
    for key in ["http", "case_http"] {
        if let Some(exchanges) = call.0[key].as_array_mut() {
            for exchange in exchanges {
                if exchange["path"] != "/testing-ca-with-aa/ocsp/leaf-aa" {
                    continue;
                }
                let mut bytes = b64(exchange["response_body"].as_str().unwrap());
                let response = sigis_pki_core::asn1::tlv::Tlv::parse_exact(&bytes)
                    .unwrap()
                    .children()
                    .unwrap();
                let response_bytes = response[1].children().unwrap()[0].children().unwrap();
                let basic = sigis_pki_core::asn1::tlv::Tlv::parse_exact(response_bytes[1].value)
                    .unwrap()
                    .children()
                    .unwrap();
                assert!(basic[2].is_universal(3));
                let signature = &basic[2].value[1..];
                let offset = bytes
                    .windows(signature.len())
                    .position(|w| w == signature)
                    .unwrap();
                bytes[offset] ^= 1;
                exchange["response_body"] = base64::engine::general_purpose::STANDARD
                    .encode(bytes)
                    .into();
                changed += 1;
            }
        }
    }
    assert!(changed > 0);
    let ac_bad = call.with_recorded_revinfo(&ac);
    let invalid = sigis_cms::validate_cms_signature_with(
        &sig.contents,
        sigis_cms::SignedContent::Data(&signed),
        &ctx,
        &sigis_cms::CmsValidationOptions {
            ac_validation_context: Some(&ac_bad),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(invalid.signature.intact && invalid.signature.valid);
    assert!(invalid
        .cades_signer_attrs
        .as_ref()
        .unwrap()
        .certified_attrs
        .as_ref()
        .unwrap()
        .0
        .is_empty());
    assert!(
        format!("{:?}", invalid.ac_validation_errs)
            .contains("Unable to verify OCSP response signature"),
        "{:?}",
        invalid.ac_validation_errs
    );
    let input = ReportInput::from_pdf(
        &file,
        &sig,
        &ReportValidation {
            validation_time: call.time(),
            best_signature_time: None,
            process: ValidationProcess::Lta,
            subindication: sigis_pades::ades::basic::basic_subindication(&invalid.signature),
            status: &invalid,
        },
    )
    .unwrap();
    assert!(input
        .attributes
        .signer_roles
        .iter()
        .all(|(certified, _)| !*certified));
    let xml = generate_report(&input).unwrap();
    assert!(xml.contains("claimed"));
    assert!(!xml.contains("certified"));
}
