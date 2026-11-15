//! Signed live CLI regression for subsecond OCSP issuance and historical control time.
use sigis_pades::ades::{basic::QualificationSpec, lta::lta_validation, AdesIndeterminate, AdesPassed};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{cert::Cert, fetch::Fetchers, time::Moment};

fn validate(at: &str) -> sigis_pades::ades::lta::LtaValidationResult {
    let directory = sigis_testdata::path(&["lanes", "r3-l", "lta-subsecond"]);
    let bytes = std::fs::read(directory.join("native.pdf")).unwrap();
    let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    let signature = signatures.iter().find(|sig| sig.field_name == "Sig1").unwrap();
    let context = ValidationContext::builder()
        .trust_root(Cert::from_der(&std::fs::read(directory.join("root.der")).unwrap()).unwrap())
        .moment(Moment::parse_rfc3339(at).unwrap())
        .point_in_time_validation(false)
        .revocation_mode("require")
        .fetchers(Fetchers::none())
        .build()
        .unwrap();
    let result = lta_validation(&file, signature, &context, &QualificationSpec::default()).unwrap();
    let status = result.api_status.as_ref().unwrap();
    assert!(status.signature.intact && status.signature.valid && status.signature.trusted());
    let dss = file.dss().unwrap().unwrap();
    assert_eq!(dss.material.ocsps.len(), 1);
    assert_eq!(dss.material.crls.len(), 1);
    result
}

#[test]
fn historical_control_cannot_backdate_fractional_ocsp_issuance() {
    let result = validate("2026-11-15T04:48:36Z");
    assert_eq!(result.ades_subindic, AdesIndeterminate::NO_POE.into(), "{result:?}");
}

#[test]
fn next_second_keeps_the_same_genuine_archival_proof_usable() {
    let result = validate("2026-11-15T04:48:37Z");
    assert_eq!(result.ades_subindic, AdesPassed::OK.into(), "{result:?}");
}
