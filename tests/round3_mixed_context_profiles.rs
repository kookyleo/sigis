//! Supplemental public-API replay of one frozen different-generation PDF.
//! Not an upstream-function port; every profile uses the same frozen bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use sigis_cms::validate::CmsValidationOptions;
use sigis_pdf::PdfFile;
use sigis_pki_certvalidator::{Cert, ValidationContext};
use sigis_pki_core::algorithms::DigestAlgorithm;

fn hash(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn frozen_mixed_context_profiles_match_pinned_refusals_and_positives() {
    let dir = sigis_testdata::path(&["lanes", "r3-s", "mixed-context"]);
    let pdf_path = dir.join("different-generation-reproducer.pdf");
    let bytes = std::fs::read(&pdf_path).unwrap();
    assert_eq!(
        hash(&bytes),
        "29b0a8a97e32bb220c96ac34d9906bcadf2d38dc7a13eb77336b63eaa6cdc4b2"
    );
    let ecc_der = std::fs::read(dir.join("testing-ca-ecdsa-root.der")).unwrap();
    let rsa_der = std::fs::read(dir.join("testing-ca-root.der")).unwrap();
    assert_eq!(
        hash(&ecc_der),
        "ccc409838b97b5c04b18f889fa39b9b123868ff685751f58956206fb86d5ba90"
    );
    assert_eq!(
        hash(&rsa_der),
        "2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa"
    );
    let ecc = Cert::from_der(&ecc_der).unwrap();
    let rsa = Cert::from_der(&rsa_der).unwrap();
    let mut rows = Vec::new();
    for historical in [false, true] {
        for separate in [false, true] {
            let file = PdfFile::parse(&bytes).unwrap();
            let auth = file.decrypt("secret").unwrap();
            assert_eq!(auth.mac_status, sigis_pdf::crypt::PdfMacStatus::Successful);
            let signature = file
                .embedded_signatures()
                .unwrap()
                .into_iter()
                .find(|s| s.field_name == "Sig")
                .unwrap();
            let mut builder = ValidationContext::builder().trust_root(ecc.clone());
            if !separate {
                builder = builder.trust_root(rsa.clone());
            }
            let context = builder
                .moment(
                    sigis_pki_core::time::Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap(),
                )
                .point_in_time_validation(historical)
                .revocation_mode("none")
                .build()
                .unwrap();
            let ts = ValidationContext::builder()
                .trust_root(rsa.clone())
                .moment(
                    sigis_pki_core::time::Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap(),
                )
                .point_in_time_validation(historical)
                .revocation_mode("none")
                .build()
                .unwrap();
            let options = CmsValidationOptions {
                ts_validation_context: if separate { Some(&ts) } else { None },
                ..Default::default()
            };
            let status = sigis_pades::validate_pdf_signature_with_options(
                &file,
                &signature,
                &context,
                Some(&sigis_pdf_diff::StandardDiffPolicy),
                &options,
            )
            .unwrap();
            let main_path: Vec<String> = status
                .cms
                .signature
                .validation_path
                .as_ref()
                .map(|p| p.certs().iter().map(|c| hash(c.der())).collect())
                .unwrap_or_default();
            let ts_path: Vec<String> = status
                .cms
                .timestamp_validity
                .as_ref()
                .and_then(|t| t.signature.validation_path.as_ref())
                .map(|p| p.certs().iter().map(|c| hash(c.der())).collect())
                .unwrap_or_default();
            rows.push(serde_json::json!({"pdf_path":pdf_path,"pdf_sha256":hash(&bytes),"point_in_time_validation":historical,"separate_role_contexts":separate,"bottom_line":status.bottom_line(),"expected_Python_bottom_line":separate,"intact":status.cms.signature.intact,"valid":status.cms.signature.valid,"trusted":status.cms.signature.trusted(),"timestamp_trusted":status.cms.timestamp_validity.as_ref().map(|t|t.trusted()),"summary":status.summary(),"main_path_sha256":main_path,"timestamp_path_sha256":ts_path,"time":"2020-11-01T00:00:00Z","tolerance_seconds":1,"revocation":"none","root_order":if separate{vec![hash(&ecc_der)]}else{vec![hash(&ecc_der),hash(&rsa_der)]},"timestamp_roots":if separate{vec![hash(&rsa_der)]}else{vec![hash(&ecc_der),hash(&rsa_der)]}}));
        }
    }
    eprintln!(
        "MIXED_CONTEXT_PROFILES_JSON {}",
        serde_json::to_string(&rows).unwrap()
    );
    assert!(rows.iter().all(|r|r["bottom_line"]==r["expected_Python_bottom_line"]),"one or more actual configured profiles differs from pinned refusals/positives; preserve full records");
}
