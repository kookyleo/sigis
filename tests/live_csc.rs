// Ported from pyHanko v0.38.1 internal/integration-tests (MIT).
//! Actual pinned CSC service, implicit batch commits and trusted PDF validation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/live_csc.rs"]
mod live_csc;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use live_csc::{LiveAuthorization, LiveCsc, TIME};
use sigis_pades::{validate_pdf_signature, SignatureCoverageLevel};
use sigis_pades_sign::csc::{
    fetch_certs_in_csc_credential, http_client, CscServiceSessionInfo, CscSigner, CscSignerOptions,
};
use sigis_pades_sign::pdf::signer::SignOptions;
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner};
use sigis_pdf::PdfFile;
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::time::Moment;

fn check_pdf(data: &[u8], root_der: &[u8], reason: Option<&str>) {
    let file = PdfFile::parse(data).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let signature = &signatures[0];
    if let Some(reason) = reason {
        let object = file
            .get_object_raw(signature.sig_object, Some(signature.signed_revision))
            .unwrap();
        let dictionary = object.as_dict().unwrap();
        assert!(dictionary
            .get(b"Reason")
            .unwrap()
            .as_str()
            .unwrap()
            .ends_with(reason.as_bytes()));
    }
    let ctx = ValidationContext::builder()
        .trust_root(Cert::from_der(root_der).unwrap())
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .build()
        .unwrap();
    let status = validate_pdf_signature(&file, signature, &ctx, None).unwrap();
    assert!(status.cms.signature.intact);
    assert!(status.cms.signature.valid);
    assert!(status.cms.signature.trusted());
    assert!(!status.cms.pretty_print_details().is_empty());
    let summary = status.cms.summary();
    assert!(summary.contains("INTACT"));
    assert!(summary.contains("TRUSTED"));
    assert_eq!(status.coverage, SignatureCoverageLevel::EntireFile);
    // With skip_diff=True, EntireFile has no later revision to modify it.
    assert!(status.diff_result.is_none());
    assert!(status.bottom_line());
    let no_roots = ValidationContext::builder()
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .build()
        .unwrap();
    let denied = validate_pdf_signature(&file, signature, &no_roots, None).unwrap();
    assert!(denied.cms.signature.intact && denied.cms.signature.valid);
    assert!(!denied.cms.signature.trusted() && !denied.bottom_line());
}

fn sign_case(number: usize, batch: usize, expected_auth: usize, waste: u64, reasons: bool) {
    let live = LiveCsc::start();
    let client = http_client().unwrap();
    let mut session = CscServiceSessionInfo::new(&live.url, "testing-ca/signer1-long");
    session.oauth_token = Some("deadbeef".into());
    let credential =
        fetch_certs_in_csc_credential(&client, &session, Duration::from_secs(10)).unwrap();
    let authorization = Arc::new(LiveAuthorization {
        client: client.clone(),
        session,
        credential,
        authorizations_requested: AtomicUsize::new(0),
        waste_time: Duration::from_secs(waste),
    });
    let signer = Arc::new(CscSigner::new(
        client,
        authorization.clone(),
        CscSignerOptions {
            batch_size: batch,
            sign_timeout: Duration::from_secs(10),
            ..Default::default()
        },
    ));
    let input = std::fs::read(sigis_testdata::pyhanko(&["pdf", "minimal-with-field.pdf"])).unwrap();
    let results = std::thread::scope(|scope| {
        let jobs = (1..=number)
            .map(|index| {
                let signer = signer.clone();
                let input = &input;
                scope.spawn(move || {
                    let mut metadata = PdfSignatureMetadata::new("Sig1");
                    if reasons {
                        metadata.reason = Some(format!("I'm number #{index}!"));
                    }
                    PdfSigner::new(metadata, signer)
                        .at(Moment::parse_rfc3339(TIME).unwrap())
                        .sign_pdf_with(
                            input,
                            &SignOptions {
                                existing_fields_only: true,
                                ..Default::default()
                            },
                        )
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        jobs.into_iter()
            .map(|job| job.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        authorization
            .authorizations_requested
            .load(Ordering::SeqCst),
        expected_auth
    );
    let directory = tempfile::tempdir().unwrap();
    for (index, data) in results.iter().enumerate() {
        let reason = reasons.then(|| format!("#{}!", index + 1));
        check_pdf(data, &live.root_der, reason.as_deref());
        std::fs::write(
            directory.path().join(format!("rust-{}.pdf", index + 1)),
            data,
        )
        .unwrap();
    }
    let hex = live
        .root_der
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let script = sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/live_csc_verdict.py");
    let number_arg = number.to_string();
    let batch_arg = batch.to_string();
    let waste_arg = waste.to_string();
    let mut args = vec![
        "--url",
        &live.url,
        "--root",
        &hex,
        "--directory",
        directory.path().to_str().unwrap(),
        "--time",
        TIME,
        "--number",
        &number_arg,
        "--batch",
        &batch_arg,
        "--waste",
        &waste_arg,
    ];
    if reasons {
        args.push("--reason");
    }
    let result =
        sigis_testdata::oracle::run_json(&script, &args).expect("fresh live oracle required");
    assert_eq!(result["authorizations_requested"], expected_auth);
    for origin in ["python", "rust"] {
        let statuses = result[origin].as_array().unwrap();
        assert_eq!(statuses.len(), number);
        for status in statuses {
            for field in ["intact", "valid", "trusted", "bottom_line"] {
                assert_eq!(status[field], true);
            }
            assert_eq!(status["coverage"], "ENTIRE_FILE");
            assert_eq!(status["modification_level"], "NONE");
            assert_eq!(status["empty_roots_trusted"], false);
        }
    }
    // Both validators check both implementations' fresh outputs.
    for index in 1..=number {
        let data = std::fs::read(directory.path().join(format!("python-{index}.pdf"))).unwrap();
        let reason = reasons.then(|| format!("#{index}!"));
        check_pdf(&data, &live.root_der, reason.as_deref());
    }
}

#[test]
fn test_simple_sign_with_dummy() {
    sign_case(1, 1, 1, 0, false);
}

#[test]
fn test_implicit_batch_sign_with_dummy() {
    for (number, batch, expected_auth, waste) in [(3, 3, 1, 0), (6, 3, 2, 0), (6, 3, 2, 1)] {
        sign_case(number, batch, expected_auth, waste, true);
    }
}
