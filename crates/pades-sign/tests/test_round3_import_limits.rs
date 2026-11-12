//! Native bounded-reader regressions for actual PDF page imports.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use lopdf::{dictionary, Dictionary, Document, Object, ObjectId, Stream};
use sigis_pades_sign::content::import::{
    import_page_as_xobject, import_page_as_xobject_from_reader,
};
use sigis_pades_sign::content::{ContentWriter, ImportedPdfPage, PdfContent};
use sigis_pades_sign::pdf::writer::PdfUpdate;
use sigis_pdf::decode_limits::{DecodeLimits, DecodePurpose, DocumentDecodeBudget};
use sigis_pdf::{PdfFile, ReaderOptions};

fn flate(data: &[u8]) -> Stream {
    Stream::new(
        dictionary! { "Filter" => "FlateDecode" },
        sigis_pdf::filters::flate_compress(data),
    )
}

fn expansion_stream() -> Stream {
    let first = sigis_pdf::filters::flate_compress(&vec![b' '; 2 * 1024 * 1024]);
    Stream::new(
        dictionary! {
            "Filter" => Object::Array(vec![
                Object::Name(b"FlateDecode".to_vec()),
                Object::Name(b"FlateDecode".to_vec()),
            ])
        },
        sigis_pdf::filters::flate_compress(&first),
    )
}

fn source_pdf(streams: Vec<Stream>, missing_resources: bool) -> (Document, Vec<u8>, Vec<ObjectId>) {
    let mut document = Document::with_version("1.7");
    let pages = document.new_object_id();
    let contents: Vec<_> = streams
        .into_iter()
        .map(|stream| document.add_object(stream))
        .collect();
    let resources = if missing_resources {
        Object::Reference((999, 0))
    } else {
        Object::Dictionary(Dictionary::new())
    };
    let page = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages,
        "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
        "Resources" => resources,
        "Contents" => Object::Array(contents.iter().copied().map(Object::Reference).collect()),
    });
    document.objects.insert(
        pages,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page)],
            "Count" => 1,
        }),
    );
    let catalog = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
    document.trailer.set("Root", catalog);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes).unwrap();
    (document, bytes, contents)
}

fn oversized_object_stream_pdf() -> Vec<u8> {
    let mut body = b"3 0 << /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources <<>> /Contents 5 0 R >>".to_vec();
    body.resize(5 * 1024 * 1024, b' ');
    let encoded = sigis_pdf::filters::flate_compress(&body);
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let mut offsets = [0; 7];
    offsets[1] = bytes.len();
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets[2] = bytes.len();
    bytes.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    offsets[4] = bytes.len();
    writeln!(
        bytes,
        "4 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length {} >>\nstream",
        encoded.len()
    )
    .unwrap();
    bytes.extend_from_slice(&encoded);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");
    offsets[5] = bytes.len();
    bytes.extend_from_slice(b"5 0 obj\n<< /Length 3 >>\nstream\nq Q\nendstream\nendobj\n");
    offsets[6] = bytes.len();
    let mut xref = Vec::new();
    for (id, offset) in offsets.iter().enumerate() {
        let (kind, field, generation): (u8, u32, u16) = match id {
            0 => (0, 0, u16::MAX),
            3 => (2, 4, 0),
            _ => (1, u32::try_from(*offset).unwrap(), 0),
        };
        xref.push(kind);
        xref.extend_from_slice(&field.to_be_bytes());
        xref.extend_from_slice(&generation.to_be_bytes());
    }
    writeln!(
        bytes,
        "6 0 obj\n<< /Type /XRef /Size 7 /Root 1 0 R /W [1 4 2] /Length {} >>\nstream",
        xref.len()
    )
    .unwrap();
    bytes.extend_from_slice(&xref);
    write!(
        bytes,
        "\nendstream\nendobj\nstartxref\n{}\n%%EOF\n",
        offsets[6]
    )
    .unwrap();
    bytes
}

fn target() -> PdfUpdate {
    let (_, bytes, _) = source_pdf(vec![flate(b"q Q")], false);
    PdfUpdate::new(&bytes).unwrap()
}

fn assert_limit(error: impl std::fmt::Display) {
    assert!(error.to_string().contains("PdfDecodeLimitError"), "{error}");
}

struct TemporaryPdf(PathBuf);

impl TemporaryPdf {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "sigis-import-limits-{}-{}.pdf",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for TemporaryPdf {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn imported_pdf_page_keeps_independent_source_limits_with_trusted_destination() {
    let (_, bytes, _) = source_pdf(vec![expansion_stream(), flate(b"q Q")], false);
    let source = TemporaryPdf::new(&bytes);
    let (_, destination, _) = source_pdf(vec![flate(b"q Q")], false);
    let mut update =
        PdfUpdate::open_with_limits(&destination, None, DecodeLimits::for_trusted_input(), false)
            .unwrap();
    let mut page = ImportedPdfPage::new(&source.0, 0);
    let mut writer = ContentWriter::new(&mut update);
    assert_limit(page.render(&mut writer).unwrap_err());
}

#[test]
fn imported_pdf_page_bounds_object_stream_parsing() {
    let bytes = oversized_object_stream_pdf();
    let source = TemporaryPdf::new(&bytes);
    let mut update = target();
    let mut writer = ContentWriter::new(&mut update);
    assert_limit(
        ImportedPdfPage::new(&source.0, 0)
            .render(&mut writer)
            .unwrap_err(),
    );

    let trusted = PdfFile::parse_with(
        &bytes,
        ReaderOptions {
            decode_limits: DecodeLimits::for_trusted_input(),
            ..Default::default()
        },
    )
    .unwrap();
    let imported = import_page_as_xobject_from_reader(&mut update, &trusted, 0, false).unwrap();
    let stream = update.get(imported).unwrap().as_stream().unwrap();
    assert_eq!(
        trusted
            .read_stream_data(stream, DecodePurpose::Generic, None)
            .unwrap(),
        b"q Q"
    );
}

#[test]
fn legacy_page_import_applies_default_decode_limits() {
    let (document, _, _) = source_pdf(vec![expansion_stream(), flate(b"q Q")], false);
    assert_limit(import_page_as_xobject(&mut target(), &document, 0, true).unwrap_err());
}

#[test]
fn native_page_import_accepts_explicit_trusted_source() {
    let (_, bytes, _) = source_pdf(vec![expansion_stream(), flate(b"q Q")], false);
    let reader = PdfFile::parse_with(
        &bytes,
        ReaderOptions {
            decode_limits: DecodeLimits::for_trusted_input(),
            strict: false,
            ..Default::default()
        },
    )
    .unwrap();
    let mut update = target();
    let imported = import_page_as_xobject_from_reader(&mut update, &reader, 0, true).unwrap();
    let stream = update.get(imported).unwrap().as_stream().unwrap();
    let data = reader
        .read_stream_data(stream, DecodePurpose::Generic, None)
        .unwrap();
    assert_eq!(data.len(), 2 * 1024 * 1024 + 3);
    assert!(data[..2 * 1024 * 1024].iter().all(|byte| *byte == b' '));
    assert_eq!(&data[2 * 1024 * 1024..], b"q Q");
    assert!(!reader.strict());
    assert_eq!(reader.remaining_decode_budget(), None);
}

#[test]
fn same_document_page_import_uses_remaining_reader_budget() {
    // The third stream consumes budget before the import begins. The page's
    // first two streams require 32 more bytes, exceeding the 28 left over.
    let (_, bytes, streams) = source_pdf(
        vec![flate(&[b'A'; 16]), flate(&[b'B'; 16]), flate(&[b'C'; 20])],
        false,
    );
    let limits = DecodeLimits {
        document_budget: Some(DocumentDecodeBudget {
            base_allowance: 48,
            max_ratio: 0.0,
        }),
        ..Default::default()
    };
    let mut update = PdfUpdate::open_with_limits(&bytes, None, limits, false).unwrap();
    let state = update.state();
    let reader = state.reader();
    let spare = reader.get_object_at(streams[2], None).unwrap();
    reader
        .read_stream_data(spare.as_stream().unwrap(), DecodePurpose::Generic, None)
        .unwrap();
    assert_eq!(reader.remaining_decode_budget(), Some(28));
    assert_limit(import_page_as_xobject_from_reader(&mut update, reader, 0, false).unwrap_err());
    assert_eq!(reader.remaining_decode_budget(), Some(12));
    assert_eq!(update.state().reader().remaining_decode_budget(), Some(12));
    assert!(!reader.strict());
}

#[test]
fn native_page_import_preserves_source_strictness() {
    let (_, bytes, _) = source_pdf(vec![flate(b"q Q")], true);
    for strict in [true, false] {
        let mut update =
            PdfUpdate::open_with_limits(&bytes, None, DecodeLimits::default(), strict).unwrap();
        let state = update.state();
        let result = import_page_as_xobject_from_reader(&mut update, state.reader(), 0, false);
        if strict {
            let error = result.unwrap_err();
            assert!(error.to_string().contains("strict mode"), "{error}");
        } else {
            assert!(result.is_ok(), "{result:?}");
        }
        assert_eq!(state.reader().strict(), strict);
    }
}

#[test]
fn malformed_content_is_not_imported_as_raw_data() {
    let malformed = Stream::new(
        dictionary! { "Filter" => "FlateDecode" },
        b"not zlib".to_vec(),
    );
    let (document, _, _) = source_pdf(vec![malformed, flate(b"q Q")], false);
    let error = import_page_as_xobject(&mut target(), &document, 0, true).unwrap_err();
    assert!(error.to_string().contains("decompress"), "{error}");
}

#[test]
fn encrypted_page_import_decodes_explicit_crypt_under_source_budget() {
    use sigis_pdf::crypt::{
        add_crypt_filter, encode_stream_with, AuthStatus, StandardEncryptOptions, STD_CF,
    };
    use sigis_pdf::stream::DecodedStream;
    use sigis_pdf::PdfFileWriter;

    let mut writer = PdfFileWriter::new(false, true).unwrap();
    let handler = writer
        .encrypt_with(
            "secret",
            None,
            StandardEncryptOptions {
                pdf_mac: false,
                ..Default::default()
            },
        )
        .unwrap();
    let payload = b"q Q\n".repeat(128);
    let mut stream = DecodedStream::new(Dictionary::new(), payload.clone());
    add_crypt_filter(&mut stream, STD_CF, None, Some(&handler)).unwrap();
    let content = writer
        .add_object(Object::Stream(
            encode_stream_with(&stream, &handler).unwrap(),
        ))
        .unwrap();
    writer.insert_page(dictionary! {
        "Type" => "Page", "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
        "Contents" => content, "Resources" => dictionary! { "XObject" => dictionary! { "Nested" => content } },
    }, None).unwrap();
    let input = writer.write().unwrap();
    for inherit in [true, false] {
        let reader = PdfFile::parse(&input).unwrap();
        assert_ne!(reader.decrypt("secret").unwrap().status, AuthStatus::Failed);
        let mut target = target();
        let imported =
            import_page_as_xobject_from_reader(&mut target, &reader, 0, inherit).unwrap();
        let stream = target.get(imported).unwrap().as_stream().unwrap();
        assert!(
            !sigis_pdf::stream::has_crypt_filter(&stream.dict, &|object| {
                Ok(target.resolve(object).unwrap().clone())
            })
            .unwrap()
        );
        assert_eq!(
            target
                .read_stream_data(stream, DecodePurpose::Generic)
                .unwrap(),
            payload
        );
        let resources = target
            .dict_get(&stream.dict, b"Resources")
            .unwrap()
            .unwrap()
            .as_dict()
            .unwrap();
        let xobjects = target
            .dict_get(resources, b"XObject")
            .unwrap()
            .unwrap()
            .as_dict()
            .unwrap();
        let nested = target
            .dict_get(xobjects, b"Nested")
            .unwrap()
            .unwrap()
            .as_stream()
            .unwrap();
        assert!(
            !sigis_pdf::stream::has_crypt_filter(&nested.dict, &|object| {
                Ok(target.resolve(object).unwrap().clone())
            })
            .unwrap()
        );
        assert_eq!(
            target
                .read_stream_data(nested, DecodePurpose::Generic)
                .unwrap(),
            payload
        );

        let limits = DecodeLimits {
            document_budget: Some(DocumentDecodeBudget {
                base_allowance: u64::try_from(payload.len() - 1).unwrap(),
                max_ratio: 0.0,
            }),
            ..Default::default()
        };
        let limited = PdfFile::parse_with(
            &input,
            ReaderOptions {
                decode_limits: limits,
                ..Default::default()
            },
        )
        .unwrap();
        assert_ne!(
            limited.decrypt("secret").unwrap().status,
            AuthStatus::Failed
        );
        assert_limit(
            import_page_as_xobject_from_reader(&mut target, &limited, 0, inherit).unwrap_err(),
        );
    }
}
