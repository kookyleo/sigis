//! Public native timing boundary; supplemental, zero upstream-function credit.
#[path = "common/mod.rs"]
#[allow(dead_code)] // This target probes the public validator, not a CLI process.
mod common;

use sigis_pki_core::{cert::Cert, time::Moment};
use std::{fs, time::Duration};

#[test]
fn explicit_time_tolerance_reaches_native_certificate_validation() {
    let fixture = |name: &str| {
        let path = sigis_testdata::path(&["lanes", "r3-c", "validation", "rsa", name]);
        common::record_test_executable();
        common::record_file(&path, "native_tolerance_fixture");
        path
    };
    let bytes = fs::read(fixture("regular.pdf")).unwrap();
    let root = Cert::from_der(&fs::read(fixture("root.der")).unwrap()).unwrap();
    let pdf = sigis_pdf::PdfFile::parse(&bytes).unwrap();
    let signatures = pdf.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let moment = Moment::parse_rfc3339("2022-01-01T00:30:00Z").unwrap();
    let mut decisions = Vec::new();
    for seconds in [30, 3600] {
        let context = sigis_pki_certvalidator::ValidationContext::builder()
            .trust_root(root.clone())
            .moment(moment)
            .time_tolerance(Duration::from_secs(seconds))
            .revocation_mode("none")
            .build()
            .unwrap();
        assert_eq!(
            context.timing().time_tolerance,
            Duration::from_secs(seconds)
        );
        let status = sigis_pades::validate_pdf_signature(
            &pdf,
            &signatures[0],
            &context,
            Some(&sigis_pdf_diff::StandardDiffPolicy),
        )
        .unwrap();
        let problem = status
            .cms
            .signature
            .trust_problem
            .as_ref()
            .map(|problem| match problem {
                sigis_cms::status::TrustProblem::Path(error) => error.to_string(),
                other => format!("{other:?}"),
            });
        eprintln!(
            "NATIVE_TOLERANCE_BOUNDARY {}",
            serde_json::json!({
                "seconds":seconds,"moment":moment.to_string(),
                "recorded_tolerance_seconds":context.timing().time_tolerance.as_secs(),
                "intact":status.cms.signature.intact,"valid":status.cms.signature.valid,
                "trusted":status.cms.signature.trusted(),"bottom_line":status.bottom_line(),
                "trust_problem":problem,
            })
        );
        assert!(status.cms.signature.intact, "{status:?}");
        assert!(status.cms.signature.valid, "{status:?}");
        decisions.push(status.bottom_line());
    }
    assert!(
        !decisions[0],
        "Thirty seconds cannot cover a thirty-minute expiry"
    );
    assert!(
        decisions[1],
        "Explicit one-hour tolerance must cover a thirty-minute expiry"
    );
}
