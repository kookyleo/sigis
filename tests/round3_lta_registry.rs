//! Supplemental full-LTA parity profiles of retained29b; zero upstream credit.
//! Tests-first full-LTA policy profiles; the independent BASIC suite keeps its own order.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use sigis_pades::ades::{
    basic::QualificationSpec,
    lta::{lta_validation_with_options, LtaOptions},
};
use sigis_pdf::PdfFile;
use sigis_pki_certvalidator::{Cert, ValidationContext};
use sigis_pki_core::{algorithms::DigestAlgorithm, time::Moment};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(&DigestAlgorithm::Sha256.digest(bytes))
}

#[test]
fn frozen_mixed_context_public_full_lta_matches_pinned_two_timing_profiles() {
    let dir = sigis_testdata::path(&["lanes", "r3-s", "mixed-context"]);
    let pdf_path = dir.join("different-generation-reproducer.pdf");
    let ecc_path = dir.join("testing-ca-ecdsa-root.der");
    let rsa_path = dir.join("testing-ca-root.der");
    let bytes = std::fs::read(&pdf_path).unwrap();
    let ecc_der = std::fs::read(&ecc_path).unwrap();
    let rsa_der = std::fs::read(&rsa_path).unwrap();
    let inputs = serde_json::json!({
        "pdf":{"path":pdf_path,"length":bytes.len(),"sha256":hash(&bytes)},
        "ecc_root":{"path":ecc_path,"length":ecc_der.len(),"sha256":hash(&ecc_der)},
        "rsa_root":{"path":rsa_path,"length":rsa_der.len(),"sha256":hash(&rsa_der)}
    });
    eprintln!("LTA_MIXED_NATIVE_INPUT {inputs}");
    // Check all three raw inputs before PDF/certificate parsing.
    assert_eq!(
        hash(&bytes),
        "29b0a8a97e32bb220c96ac34d9906bcadf2d38dc7a13eb77336b63eaa6cdc4b2"
    );
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
    let moment = Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap();
    let mut rows = Vec::new();
    for historical in [false, true] {
        let context = ValidationContext::builder()
            .trust_root(ecc.clone())
            .trust_root(rsa.clone())
            .moment(moment)
            .point_in_time_validation(historical)
            .revocation_mode("none")
            .build()
            .unwrap();
        assert_eq!(context.timing().time_tolerance.as_secs(), 1);
        assert!(context.fetchers().ocsp.is_none() && context.fetchers().crl.is_none());
        assert_eq!(context.crls().count() + context.ocsps().count(), 0);
        let before = format!("{context:?}");
        let file = PdfFile::parse(&bytes).unwrap();
        let auth = file.decrypt("secret").unwrap();
        assert_eq!(auth.mac_status, sigis_pdf::crypt::PdfMacStatus::Successful);
        let signatures = file.embedded_signatures().unwrap();
        assert_eq!(signatures.len(), 1);
        let signature = signatures.iter().find(|s| s.field_name == "Sig").unwrap();
        // This public API has no timestamp-role override. Do not add synthetic
        // explicit-shared/equal-distinct/separate-root LTA profiles.
        let result = lta_validation_with_options(
            &file,
            signature,
            &context,
            &QualificationSpec::default(),
            &LtaOptions::default(),
        );
        assert_eq!(
            format!("{context:?}"),
            before,
            "caller context must stay immutable"
        );
        let row = match result {
            Err(error) => serde_json::json!({
                "point_in_time_validation":historical,"error":format!("{error:?}"),
                "profile":"public full LTA; implicit timestamp policy; no role override"
            }),
            Ok(result) => {
                let api = result.api_status.as_ref();
                let main_path = api
                    .and_then(|s| s.signature.validation_path.as_ref())
                    .map(|p| p.certs().iter().map(|c| hash(c.der())).collect::<Vec<_>>())
                    .unwrap_or_default();
                let ts = api.and_then(|s| s.timestamp_validity.as_ref());
                let ts_path = ts
                    .and_then(|t| t.signature.validation_path.as_ref())
                    .map(|p| p.certs().iter().map(|c| hash(c.der())).collect::<Vec<_>>())
                    .unwrap_or_default();
                serde_json::json!({
                    "profile":"public full LTA; implicit timestamp policy; no role override",
                    "point_in_time_validation":historical,"error":null,
                    "validation_time":"2020-11-01T00:00:00Z","revocation":"none",
                    "root_order":[hash(&ecc_der),hash(&rsa_der)],
                    "preloaded_revinfo":false,"provided_poes":false,"separate_ac_context":false,
                    "ades_subindication":result.ades_subindic.standard_name(),
                    "failure_msg":result.failure_msg,
                    "best_signature_time":result.best_signature_time.map(|t|t.to_string()),
                    "api_intact":api.map(|s|s.signature.intact),
                    "api_valid":api.map(|s|s.signature.valid),
                    "api_trusted":api.map(|s|s.signature.trusted()),
                    "api_bottom_line":api.map(|s|s.bottom_line()),
                    "api_summary":api.map(|s|s.summary()),
                    "signer_sha256":api.and_then(|s|s.signature.signing_cert.as_ref()).map(|c|hash(c.der())),
                    "main_path_sha256":main_path,
                    "timestamp_intact":ts.map(|t|t.signature.intact),
                    "timestamp_valid":ts.map(|t|t.signature.valid),
                    "timestamp_trusted":ts.map(|t|t.trusted()),
                    "timestamp_time":ts.map(|t|t.timestamp.to_string()),
                    "timestamp_path_sha256":ts_path,
                    "timestamp_signer_sha256":ts.and_then(|t|t.signature.signing_cert.as_ref()).map(|c|hash(c.der())),
                    "main_error_time_horizon":api.and_then(|s|s.signature.error_time_horizon).map(|t|t.to_string()),
                    "main_trust_problem":api.map(|s|format!("{:?}",s.signature.trust_problem)),
                    "timestamp_trust_problem":ts.map(|t|format!("{:?}",t.signature.trust_problem)),
                    "poes":result.poe.iter().map(|p|serde_json::json!({"digest":hex(&p.digest),"time":p.poe_time.to_string(),"kind":format!("{:?}",p.poe_type)})).collect::<Vec<_>>(),
                    "complete_result_debug":format!("{result:#?}")
                })
            }
        };
        rows.push(row);
    }
    // Preserve both actual results before asserting reference expectations.
    eprintln!(
        "LTA_MIXED_NATIVE_PROFILES {}",
        serde_json::to_string(&rows).unwrap()
    );
    for row in &rows {
        assert!(row["error"].is_null(), "{row}");
        assert_eq!(row["ades_subindication"], "NO_POE", "{row}");
        for field in [
            "api_intact",
            "api_valid",
            "api_trusted",
            "api_bottom_line",
            "timestamp_intact",
            "timestamp_valid",
            "timestamp_trusted",
        ] {
            assert_eq!(row[field], true, "{field}: {row}");
        }
        assert_eq!(row["best_signature_time"], "2020-11-01T00:00:00Z");
        assert_eq!(row["timestamp_time"], "2020-11-01T00:00:00Z");
        assert_eq!(
            row["signer_sha256"],
            "899920fac432386b36a5a0cbccd5c681a215df2accf35e0280560fef8749555a"
        );
        assert_eq!(
            row["timestamp_signer_sha256"],
            "31d7cc1589f388928dec5e1c6ccd2f973d0881dfa9d4874ca3caf0926918a7a6"
        );
        assert_eq!(
            row["main_path_sha256"],
            serde_json::json!([
                "ccc409838b97b5c04b18f889fa39b9b123868ff685751f58956206fb86d5ba90",
                "563435c97dca8ee1ba43f084d9330e66f0dee1b83bac98d03ff181b37ea00b5e",
                "899920fac432386b36a5a0cbccd5c681a215df2accf35e0280560fef8749555a"
            ])
        );
        assert_eq!(
            row["timestamp_path_sha256"],
            serde_json::json!([
                "2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa",
                "31d7cc1589f388928dec5e1c6ccd2f973d0881dfa9d4874ca3caf0926918a7a6"
            ])
        );
        assert!(row["main_error_time_horizon"].is_null());
    }
}
