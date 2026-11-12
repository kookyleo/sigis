//! Regressions for decimal collisions in lopdf's f32 object representation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pdf::generic::{read_object, ParseContext};
use sigis_pdf::misc::Cursor;

#[test]
fn common_decimals_and_equivalent_formatting_remain_supported() {
    for strict in [true, false] {
        let context = ParseContext {
            strict,
            lossless_reals: true,
            ..Default::default()
        };
        for raw in [
            "0.1",
            "+.1000",
            "000.1000",
            "595.28",
            "32.00001",
            ".5",
            "1.",
            "-0.000",
            "-.0",
            "0.00000000000000000001",
        ] {
            assert!(
                read_object(&mut Cursor::new(raw.as_bytes()), &context).is_ok(),
                "rejected {raw:?}, strict={strict}"
            );
        }
    }
}

#[test]
fn distinct_decimals_cannot_collapse_into_an_accepted_float() {
    for (canonical, colliding) in [
        ("1.0", "1.00000001"),
        ("1.0", "1.00000002"),
        ("-1.0", "-1.00000001"),
        ("0.1", ".1000000001"),
        ("595.28", "595.28000001"),
    ] {
        assert_eq!(canonical.parse::<f32>(), colliding.parse::<f32>());
        for strict in [true, false] {
            let context = ParseContext {
                strict,
                lossless_reals: true,
                ..Default::default()
            };
            assert!(read_object(&mut Cursor::new(canonical.as_bytes()), &context).is_ok());
            assert!(
                read_object(&mut Cursor::new(colliding.as_bytes()), &context).is_err(),
                "precision loss accepted for {colliding:?}, strict={strict}"
            );
        }
    }
}

#[test]
fn decimal_overflow_and_underflow_are_rejected() {
    for strict in [true, false] {
        let context = ParseContext {
            strict,
            lossless_reals: true,
            ..Default::default()
        };
        for raw in [
            "9999999999999999999999999999999999999999999999.0",
            "0.00000000000000000000000000000000000000000000000001",
            "-0.00000000000000000000000000000000000000000000000001",
        ] {
            assert!(
                read_object(&mut Cursor::new(raw.as_bytes()), &context).is_err(),
                "out-of-range decimal accepted for {raw:?}, strict={strict}"
            );
        }
    }
}

#[test]
fn ordinary_parsing_keeps_high_precision_pdf_dimensions_compatible() {
    let context = ParseContext::default();
    assert!(read_object(&mut Cursor::new(b"595.275574"), &context).is_ok());
    let checked = ParseContext {
        lossless_reals: true,
        ..Default::default()
    };
    assert!(read_object(&mut Cursor::new(b"595.275574"), &checked).is_err());
}

fn table_pdf(trailer_extra: &str) -> Vec<u8> {
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let root_offset = bytes.len();
    bytes.extend_from_slice(b"1 0 obj\n<</Type /Catalog>>\nendobj\n");
    let xref = bytes.len();
    bytes.extend_from_slice(
        format!(
            "xref\n0 2\n0000000000 65535 f \n{root_offset:010} 00000 n \n\
             trailer\n<</Size 2 /Root 1 0 R {trailer_extra}>>\n\
             startxref\n{xref}\n%%EOF\n"
        )
        .as_bytes(),
    );
    bytes
}

#[test]
fn precision_view_checks_trailers_in_both_reader_modes() {
    let bytes = table_pdf("/Probe 1.00000001");
    for strict in [true, false] {
        let file = sigis_pdf::PdfFile::parse_with(
            &bytes,
            sigis_pdf::ReaderOptions {
                strict,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(file.for_modification_analysis().is_err());
    }
}

#[derive(Debug)]
struct MarkerDecryptor;

impl sigis_pdf::reader::Decryptor for MarkerDecryptor {
    fn decrypt_object(
        &self,
        object: sigis_pdf::lopdf::Object,
        _: sigis_pdf::lopdf::ObjectId,
    ) -> sigis_pdf::PdfResult<sigis_pdf::lopdf::Object> {
        Ok(object)
    }

    fn crypt_filters(&self) -> Option<&dyn sigis_pdf::stream::CryptFilterDecode> {
        None
    }
}

#[test]
fn precision_view_preserves_reader_configuration_and_decryptor() {
    use std::sync::Arc;

    let bytes = table_pdf("");
    let limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input();
    let file = sigis_pdf::PdfFile::parse_with(
        &bytes,
        sigis_pdf::ReaderOptions {
            strict: false,
            decode_limits: limits.clone(),
            ..Default::default()
        },
    )
    .unwrap();
    let decryptor: Arc<dyn sigis_pdf::reader::Decryptor> = Arc::new(MarkerDecryptor);
    file.set_decryptor(Some(decryptor.clone()));
    let checked = file.for_modification_analysis().unwrap();
    assert!(!checked.strict());
    assert_eq!(checked.decode_context().limits, limits);
    assert!(Arc::ptr_eq(&file.bytes_arc(), &checked.bytes_arc()));
    assert!(Arc::ptr_eq(&decryptor, &checked.decryptor().unwrap()));
}

fn object_stream_pdf(value: &str, xref_extra: &str) -> Vec<u8> {
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let root_offset = bytes.len();
    bytes.extend_from_slice(b"1 0 obj\n<</Type /Catalog /Probe 3 0 R>>\nendobj\n");
    let stream_offset = bytes.len();
    let payload = format!("3 0 {value}");
    bytes.extend_from_slice(
        format!(
            "2 0 obj\n<</Type /ObjStm /N 1 /First 4 /Length {}>>\nstream\n{payload}\nendstream\nendobj\n",
            payload.len()
        )
        .as_bytes(),
    );
    let xref_offset = bytes.len();
    let mut entries = Vec::new();
    for (kind, offset, generation) in [
        (0u8, 0u32, 65535u16),
        (1, root_offset as u32, 0),
        (1, stream_offset as u32, 0),
        (2, 2, 0),
        (1, xref_offset as u32, 0),
    ] {
        entries.push(kind);
        entries.extend_from_slice(&offset.to_be_bytes());
        entries.extend_from_slice(&generation.to_be_bytes());
    }
    bytes.extend_from_slice(
        format!(
            "4 0 obj\n<</Type /XRef /Root 1 0 R /Size 5 /W [1 4 2] /Length {} {xref_extra}>>\nstream\n",
            entries.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(&entries);
    bytes.extend_from_slice(
        format!("\nendstream\nendobj\nstartxref\n{xref_offset}\n%%EOF\n").as_bytes(),
    );
    bytes
}

#[test]
fn precision_view_does_not_reuse_rounded_object_stream_caches() {
    for strict in [true, false] {
        let bytes = object_stream_pdf("1.00000001", "");
        let file = sigis_pdf::PdfFile::parse_with(
            &bytes,
            sigis_pdf::ReaderOptions {
                strict,
                ..Default::default()
            },
        )
        .unwrap();
        // Populate both the parsed-object and decoded-object-stream caches.
        assert!(file.get_object_at((3, 0), None).is_ok());
        let checked = file.for_modification_analysis().unwrap();
        assert!(checked.get_object_at((3, 0), None).is_err());
        assert!(checked.get_object_at((3, 0), Some(0)).is_err());
    }
}

#[test]
fn precision_view_checks_xref_stream_dictionaries() {
    for strict in [true, false] {
        let bytes = object_stream_pdf("1.0", "/Probe 1.00000001");
        let file = sigis_pdf::PdfFile::parse_with(
            &bytes,
            sigis_pdf::ReaderOptions {
                strict,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(file.for_modification_analysis().is_err());
    }
}
