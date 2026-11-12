//! Real-operation regressions for S-owned decode-limit caller assertions.
//! No lane P upstream-function credit is assigned to these tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use lopdf::dictionary;

use sigis_pades_sign::pdf::dss::{add_dss_with_state, DssContent};
use sigis_pades_sign::pdf::signer::{SigDssPlacement, SignOptions};
use sigis_pades_sign::pdf::timestamp::PdfTimeStamper;
use sigis_pades_sign::pdf::writer::{PdfReopenState, PdfUpdate};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner};
use sigis_pdf::decode_limits::{DecodeLimits, DecodePurpose, DocumentDecodeBudget};
use sigis_pdf::{PdfFile, ReaderOptions};
use sigis_pki_core::algorithms::DigestAlgorithm;
use support::*;

const TIME: &str = "2020-11-01T00:00:00+00:00";

fn oversized() -> Vec<u8> {
    let path = temp_file("round3-oversized.pdf", &[]);
    oracle("oversized_objstm.py", &[path_str(&path)])
        .expect("the pinned oracle is required to generate the exact upstream input");
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(path);
    bytes
}

fn trusted_state(pdf: &[u8], strict: bool) -> PdfReopenState {
    PdfReopenState::from_reader(
        PdfFile::parse_with(
            pdf,
            ReaderOptions {
                strict,
                decode_limits: DecodeLimits::for_trusted_input(),
                ..Default::default()
            },
        )
        .unwrap(),
    )
}

#[test]
fn post_sign_reopen_retains_trusted_limits_for_both_dss_placements() {
    let input = oversized();
    assert!(PdfUpdate::new(&input)
        .unwrap_err()
        .to_string()
        .contains("limit"));
    for placement in [
        SigDssPlacement::TogetherWithNextTs,
        SigDssPlacement::SeparateRevision,
    ] {
        let ca = pki("testing-ca");
        let mut meta = PdfSignatureMetadata::new("Sig1");
        meta.validation_context = Some(Arc::new(support::services::live_testing_vc(
            "testing-ca",
            TIME,
            &[],
        )));
        meta.embed_validation_info = true;
        meta.use_pades_lta = true;
        meta.dss_settings.placement = placement;
        let signer = PdfSigner::new(meta, Arc::new(ca.signer("signer1")))
            .at(at(TIME))
            .with_timestamper(Arc::new(ca.tsa("tsa", at(TIME))));
        let output = signer
            .sign_pdf_with_state(
                &input,
                &SignOptions {
                    reopen_state: Some(trusted_state(&input, false)),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(!output.state.strict());
        assert!(output.state.reader().bytes() == output.pdf);
        assert_eq!(
            output.state.decode_context().limits,
            DecodeLimits::for_trusted_input()
        );
        assert_eq!(output.state.decode_context().remaining_budget(), None);
        assert_eq!(support::pdfcheck::sig_kinds(&output.pdf), (1, 1));
        let update = PdfUpdate::open_with_state(&output.pdf, output.state).unwrap();
        assert_eq!(
            sigis_pades_sign::pdf::embedded::embedded_signatures(&update)
                .unwrap()
                .iter()
                .filter(|sig| sig.is_doc_timestamp)
                .count(),
            1
        );
    }
}

#[test]
fn archival_reopen_retains_trusted_limits() {
    let input = oversized();
    let ca = pki("testing-ca");
    let ctx = support::services::live_testing_vc("testing-ca", TIME, &[]);
    let tsa = PdfTimeStamper::new(Arc::new(ca.tsa("tsa", at(TIME))));
    let output = tsa
        .update_archival_timestamp_chain_with_state(
            &input,
            &ctx,
            DigestAlgorithm::Sha256,
            trusted_state(&input, false),
        )
        .unwrap();
    assert!(!output.state.strict());
    assert!(output.state.reader().bytes() == output.pdf);
    assert_eq!(
        output.state.decode_context().limits,
        DecodeLimits::for_trusted_input()
    );
    assert_eq!(support::pdfcheck::sig_kinds(&output.pdf), (0, 1));
}

#[test]
fn dss_reopen_retains_trusted_limits() {
    let input = oversized();
    let output = add_dss_with_state(
        &input,
        &DssContent {
            certs: vec![pki("testing-ca").cert("signer1")],
            ..Default::default()
        },
        false,
        trusted_state(&input, false),
    )
    .unwrap();
    assert!(!output.state.strict());
    assert!(output.state.reader().bytes() == output.pdf);
    assert_eq!(
        output.state.decode_context().limits,
        DecodeLimits::for_trusted_input()
    );
    assert_eq!(support::pdfcheck::dss_counts(&output.pdf).unwrap().0, 1);
}

#[test]
fn dss_reopen_cannot_reset_remaining_document_budget() {
    let mut doc = lopdf::Document::with_version("1.7");
    let mut stream = lopdf::Stream::new(lopdf::Dictionary::new(), vec![0u8; 800]);
    stream.compress().unwrap();
    let id = doc.add_object(stream);
    let root = doc.add_object(lopdf::dictionary! { "Type" => "Catalog" });
    doc.trailer.set("Root", root);
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    let limits = DecodeLimits {
        document_budget: Some(DocumentDecodeBudget {
            base_allowance: 1000,
            max_ratio: 0.0,
        }),
        ..Default::default()
    };
    let reader = PdfFile::parse_with(
        &bytes,
        ReaderOptions {
            decode_limits: limits,
            ..Default::default()
        },
    )
    .unwrap();
    let lopdf::Object::Stream(stream) = reader.get_object_at(id, None).unwrap() else {
        panic!("stream")
    };
    assert_eq!(
        reader
            .read_stream_data(&stream, DecodePurpose::Generic, None)
            .unwrap()
            .len(),
        800
    );
    assert_eq!(reader.remaining_decode_budget(), Some(200));
    let output = add_dss_with_state(
        &bytes,
        &DssContent::default(),
        false,
        PdfReopenState::from_reader(reader),
    )
    .unwrap();
    assert_eq!(output.state.decode_context().remaining_budget(), Some(200));
    let update = PdfUpdate::open_with_state(&output.pdf, output.state).unwrap();
    let lopdf::Object::Stream(stream) = update.get(id).unwrap() else {
        panic!("stream")
    };
    assert!(update
        .read_stream_data(stream, DecodePurpose::Generic)
        .unwrap_err()
        .to_string()
        .contains("limit"));
}

#[test]
fn whole_pipeline_cannot_reset_budget_between_signature_dss_updates() {
    let ca = pki("testing-ca");
    let mut base = PdfUpdate::new(&pdf("minimal.pdf")).unwrap();
    let mut compressed_cert =
        lopdf::Stream::new(lopdf::Dictionary::new(), ca.cert("signer1").der().to_vec());
    compressed_cert.compress().unwrap();
    let cert_id = base.add(lopdf::Object::Stream(compressed_cert));
    let dss_id = base.add(lopdf::Object::Dictionary(lopdf::dictionary! {
        "Certs" => vec![lopdf::Object::Reference(cert_id)],
    }));
    base.root_mut().unwrap().set("DSS", dss_id);
    let mut signed = base.write().unwrap().0;
    for field in ["First", "Second"] {
        signed = PdfSigner::new(
            PdfSignatureMetadata::new(field),
            Arc::new(ca.signer("signer1")),
        )
        .at(at(TIME))
        .sign_pdf(&signed)
        .unwrap();
    }
    let ctx = support::services::live_testing_vc("testing-ca", TIME, &[]);
    let limited_reader = |allowance| {
        let limits = DecodeLimits {
            document_budget: Some(DocumentDecodeBudget {
                base_allowance: allowance,
                max_ratio: 0.0,
            }),
            ..Default::default()
        };
        PdfReopenState::from_reader(
            PdfFile::parse_with(
                &signed,
                ReaderOptions {
                    strict: false,
                    decode_limits: limits,
                    ..Default::default()
                },
            )
            .unwrap(),
        )
    };
    // The first signature reads the compressed existing certificate. The
    // second signature must read that DSS under the remaining allowance.
    // Unfiltered DSS streams do not consume a decompression budget.
    let error = sigis_pades_sign::add_validation_info_with_state(
        &signed,
        &ctx,
        None,
        limited_reader(u64::try_from(ca.cert("signer1").der().len()).unwrap() + 100),
    )
    .map(|_| ())
    .expect_err("the second DSS read must not reset the decode budget");
    assert!(error.to_string().contains("limit"), "{error}");
    let output = sigis_pades_sign::add_validation_info_with_state(
        &signed,
        &ctx,
        Some(&ca.tsa("tsa", at(TIME))),
        limited_reader(1_000_000),
    )
    .unwrap();
    assert!(!output.state.strict());
    assert!(output.state.reader().bytes() == output.pdf);
    assert!(output.state.decode_context().remaining_budget().unwrap() < 1_000_000);
    assert_eq!(support::pdfcheck::sig_kinds(&output.pdf), (2, 1));
    assert!(support::pdfcheck::dss_counts(&output.pdf).unwrap().3 >= 2);
    let root = ca.cert_path("root");
    let statuses = support::pdfcheck::oracle_verdicts(
        &output.pdf,
        &[&root],
        TIME,
        &["--extd", "--live", "testing-ca"],
    )
    .expect("the fresh pinned oracle is required for the stateful pipeline");
    assert_eq!(statuses.len(), 3);
    for status in statuses {
        for key in ["intact", "valid", "trusted"] {
            assert_eq!(status[key], true, "{key}: {status}");
        }
        if status["type"] == "/Sig" {
            assert_eq!(status["bottom_line"], true, "{status}");
        }
    }
}

#[test]
fn unread_malformed_page_is_deferred_but_access_and_fresh_copy_reject() {
    // Upstream signs this preexisting invisible field without reading page 3.
    // Its latest xref points page 3 at an object whose actual ID is 6.
    let input = pdf("minimal-annotless.pdf");
    let mut update = PdfUpdate::new(&input).unwrap();
    assert!(update.is_strict());
    assert!(update
        .get((3, 0))
        .unwrap_err()
        .to_string()
        .contains("Expected object ID"));
    update.make_fresh();
    assert!(update
        .write()
        .unwrap_err()
        .to_string()
        .contains("Expected object ID"));
}
