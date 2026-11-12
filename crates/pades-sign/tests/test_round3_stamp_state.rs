//! Actual stamp operations retain caller-selected PDF reader state.
//! These native regressions earn no additional upstream-function credit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use lopdf::{dictionary, Dictionary, Document, Object, ObjectId, Stream};
use sigis_pades_sign::pdf::writer::{PdfOperationResult, PdfReopenState, PdfUpdate};
use sigis_pades_sign::stamp::{
    qr_stamp_pdf_with_state, text_stamp_pdf_with_state, QrStampStyle, TextStampStyle,
};
use sigis_pdf::crypt::AuthStatus;
use sigis_pdf::decode_limits::{DecodeLimits, DecodePurpose, DocumentDecodeBudget};
use sigis_pdf::{PdfFile, PdfHandlerExt, ReaderOptions};
use sigis_pki_core::errors::Result;

const STAMP_TEXT: &str = "Stateful secret stamp";
const STAMP_URL: &str = "https://example.invalid/state";

fn stamp(pdf: &[u8], state: PdfReopenState, qr: bool) -> Result<PdfOperationResult> {
    if qr {
        qr_stamp_pdf_with_state(
            pdf,
            &QrStampStyle::with_text(STAMP_TEXT),
            0,
            10.0,
            20.0,
            STAMP_URL,
            None,
            state,
        )
    } else {
        text_stamp_pdf_with_state(
            pdf,
            &TextStampStyle::with_text(STAMP_TEXT),
            0,
            10.0,
            20.0,
            None,
            state,
        )
    }
}

fn state(pdf: &[u8], limits: DecodeLimits, strict: bool) -> PdfReopenState {
    PdfReopenState::from_reader(
        PdfFile::parse_with(
            pdf,
            ReaderOptions {
                decode_limits: limits,
                strict,
                ..Default::default()
            },
        )
        .unwrap(),
    )
}

fn stamp_xobjects(reader: &PdfFile, qr: bool) -> Vec<Object> {
    let (page_id, _) = reader.find_page_for_modification(0).unwrap();
    let page = reader
        .get_object_at(page_id, None)
        .unwrap()
        .as_dict()
        .unwrap()
        .clone();
    let resources = reader.get_dict(&page, b"Resources").unwrap().unwrap();
    let xobjects = reader.get_dict(&resources, b"XObject").unwrap().unwrap();
    let stamps: Vec<_> = xobjects
        .iter()
        .filter(|(name, _)| name.starts_with(b"Stamp"))
        .map(|(_, object)| reader.resolve(object).unwrap())
        .collect();
    assert!(!stamps.is_empty(), "the output page must paint a stamp");
    let contents = reader.get_array(&page, b"Contents").unwrap().unwrap();
    assert!(
        contents.len() >= 4,
        "existing content must be wrapped and stamped"
    );
    if qr {
        let annotations = reader.get_array(&page, b"Annots").unwrap().unwrap();
        assert!(annotations.iter().any(|annotation| {
            let annotation = reader.resolve(annotation).unwrap();
            let action = reader
                .get_dict(annotation.as_dict().unwrap(), b"A")
                .unwrap();
            action.is_some_and(|action| {
                reader
                    .get(&action, b"URI")
                    .unwrap()
                    .is_some_and(|uri| uri.as_str().unwrap() == STAMP_URL.as_bytes())
            })
        }));
    }
    stamps
}

fn oversized() -> Vec<u8> {
    let path = support::temp_file("stamp-state-oversized.pdf", &[]);
    support::oracle("oversized_objstm.py", &[support::path_str(&path)])
        .expect("the pinned oracle is required to generate the exact oversized object stream");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    bytes
}

#[test]
fn text_and_qr_stamps_keep_trusted_oversized_input_and_final_state() {
    let input = oversized();
    assert!(PdfUpdate::new(&input)
        .unwrap_err()
        .to_string()
        .contains("limit"));
    for qr in [false, true] {
        let selected = state(&input, DecodeLimits::for_trusted_input(), false);
        let revisions = selected.reader().total_revisions();
        let output = stamp(&input, selected, qr).unwrap();
        assert!(output.pdf.starts_with(&input));
        assert_eq!(output.state.reader().bytes(), output.pdf);
        assert_eq!(output.state.reader().total_revisions(), revisions + 1);
        assert!(!output.state.strict());
        assert_eq!(
            output.state.decode_context().limits,
            DecodeLimits::for_trusted_input()
        );
        assert_eq!(output.state.decode_context().remaining_budget(), None);
        assert_eq!(stamp_xobjects(output.state.reader(), qr).len(), 1);

        // A second actual operation must continue from the returned revision,
        // preserving both the first stamp and the selected trusted policy.
        let second = stamp(&output.pdf, output.state, false).unwrap();
        assert_eq!(second.state.reader().bytes(), second.pdf);
        assert_eq!(second.state.reader().total_revisions(), revisions + 2);
        assert_eq!(stamp_xobjects(second.state.reader(), qr).len(), 2);
        assert!(!second.state.strict());
    }
}

fn budget_pdf() -> (Vec<u8>, ObjectId) {
    let mut document = Document::with_version("1.7");
    let mut stream = Stream::new(Dictionary::new(), vec![0u8; 800]);
    stream.compress().unwrap();
    let spare = document.add_object(stream);
    let content = document.add_object(Stream::new(Dictionary::new(), b"q Q".to_vec()));
    let pages = document.new_object_id();
    let page = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages,
        "MediaBox" => vec![0.into(), 0.into(), 300.into(), 300.into()],
        "Resources" => Dictionary::new(),
        "Contents" => content,
    });
    document.objects.insert(
        pages,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Count" => 1,
            "Kids" => vec![Object::Reference(page)],
        }),
    );
    let root = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages,
        "Missing" => Object::Reference((999, 0)),
    });
    document.trailer.set("Root", root);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes).unwrap();
    (bytes, spare)
}

#[test]
fn text_and_qr_stamps_preserve_remaining_allowance_and_lenient_reads() {
    let (input, spare) = budget_pdf();
    let limits = DecodeLimits {
        document_budget: Some(DocumentDecodeBudget {
            base_allowance: 1000,
            max_ratio: 0.0,
        }),
        ..Default::default()
    };
    for qr in [false, true] {
        let selected = state(&input, limits.clone(), false);
        let stream = selected.reader().get_object_at(spare, None).unwrap();
        assert_eq!(
            selected
                .reader()
                .read_stream_data(stream.as_stream().unwrap(), DecodePurpose::Generic, None)
                .unwrap()
                .len(),
            800
        );
        assert_eq!(selected.decode_context().remaining_budget(), Some(200));
        let output = stamp(&input, selected, qr).unwrap();
        assert_eq!(output.state.reader().bytes(), output.pdf);
        assert_eq!(output.state.decode_context().limits, limits);
        // Reopening may also charge the newly written xref stream; it must
        // never replenish the allowance already spent before stamping.
        let remaining = output.state.decode_context().remaining_budget().unwrap();
        assert!(remaining > 0 && remaining <= 200, "remaining: {remaining}");
        assert!(!output.state.strict());
        assert_eq!(
            output.state.reader().get_object_at((999, 0), None).unwrap(),
            Object::Null
        );
        stamp_xobjects(output.state.reader(), qr);

        // Reopening output resets caches, not the remaining allowance. The
        // previously decoded 800-byte stream no longer fits the at most 200 left.
        let stream = output.state.reader().get_object_at(spare, None).unwrap();
        let error = output
            .state
            .reader()
            .read_stream_data(stream.as_stream().unwrap(), DecodePurpose::Generic, None)
            .unwrap_err();
        assert!(error.to_string().contains("limit"), "{error}");
    }
}

#[test]
fn text_and_qr_stamps_keep_authenticated_encryption_without_repeating_credentials() {
    let input = support::pdf("minimal-with-field-aes256.pdf");
    assert!(PdfUpdate::new(&input).is_err());
    for qr in [false, true] {
        let selected = state(&input, DecodeLimits::for_trusted_input(), false);
        assert_ne!(
            selected.reader().decrypt("usersecret").unwrap().status,
            AuthStatus::Failed
        );
        let output = stamp(&input, selected, qr).unwrap();
        assert!(output.pdf.starts_with(&input));
        assert_eq!(output.state.reader().bytes(), output.pdf);
        assert!(output.state.reader().encrypted());
        assert!(output
            .state
            .reader()
            .security_handler()
            .unwrap()
            .unwrap()
            .is_authenticated());
        assert!(!output.state.strict());
        let forms = stamp_xobjects(output.state.reader(), qr);
        assert!(forms.iter().any(|form| {
            let data = output
                .state
                .reader()
                .read_stream_data(form.as_stream().unwrap(), DecodePurpose::Generic, None)
                .unwrap();
            data.windows(STAMP_TEXT.len())
                .any(|window| window == STAMP_TEXT.as_bytes())
        }));
        assert!(!output
            .pdf
            .windows(STAMP_TEXT.len())
            .any(|window| window == STAMP_TEXT.as_bytes()));

        let second = stamp(&output.pdf, output.state, false).unwrap();
        assert!(second.state.reader().encrypted());
        assert_eq!(stamp_xobjects(second.state.reader(), qr).len(), 2);
    }
}
