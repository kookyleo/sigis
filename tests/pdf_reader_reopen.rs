//! Native state-transfer regressions. These helpers earn no upstream-function credit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use sigis_pdf::crypt::{
    AuthStatus, PubKeyEncryptOptions, SimpleEnvelopeKeyDecrypter, StandardEncryptOptions,
};
use sigis_pdf::decode_limits::{DecodeLimits, DecodePurpose, DocumentDecodeBudget};
use sigis_pdf::filters::flate_compress;
use sigis_pdf::lopdf::Object;
use sigis_pdf::reader::Decryptor;
use sigis_pdf::{IncrementalWriter, PdfError, PdfFile, PdfFileWriter, PdfHandler, ReaderOptions};

fn table_pdf(objects: &[Vec<u8>], trailer: &str, padding: usize) -> Vec<u8> {
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        offsets.push(bytes.len());
        bytes.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        bytes.extend_from_slice(object);
        bytes.extend_from_slice(b"\nendobj\n");
    }
    // Padding is a legal PDF comment, before the final cross-reference section.
    bytes.push(b'%');
    bytes.extend(std::iter::repeat_n(b'p', padding));
    bytes.push(b'\n');
    let xref = bytes.len();
    bytes.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in offsets {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(
        format!(
            "trailer\n<</Size {} /Root 1 0 R {trailer}>>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    bytes
}

fn encoded_stream(payload: &[u8]) -> Vec<u8> {
    let encoded = flate_compress(payload);
    let mut out = format!(
        "<</Length {} /Filter /FlateDecode>>\nstream\n",
        encoded.len()
    )
    .into_bytes();
    out.extend_from_slice(&encoded);
    out.extend_from_slice(b"\nendstream");
    out
}

// Exactly four seven-byte xref entries are decoded eagerly at reader creation.
fn xref_stream_pdf(payload: &[u8], padding: usize) -> Vec<u8> {
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let root_offset = bytes.len();
    bytes.extend_from_slice(b"1 0 obj\n<</Type /Catalog>>\nendobj\n");
    let stream_offset = bytes.len();
    bytes.extend_from_slice(b"2 0 obj\n");
    bytes.extend_from_slice(&encoded_stream(payload));
    bytes.extend_from_slice(b"\nendobj\n%");
    bytes.extend(std::iter::repeat_n(b'p', padding));
    bytes.push(b'\n');
    let xref_offset = bytes.len();
    let mut entries = Vec::new();
    for (kind, offset, generation) in [
        (0u8, 0usize, 65535u16),
        (1, root_offset, 0),
        (1, stream_offset, 0),
        (1, xref_offset, 0),
    ] {
        entries.push(kind);
        entries.extend_from_slice(&u32::try_from(offset).unwrap().to_be_bytes());
        entries.extend_from_slice(&generation.to_be_bytes());
    }
    assert_eq!(entries.len(), 28);
    let encoded = flate_compress(&entries);
    bytes.extend_from_slice(
        format!("3 0 obj\n<</Type /XRef /Root 1 0 R /Size 4 /W [1 4 2] /Filter /FlateDecode /Length {}>>\nstream\n", encoded.len()).as_bytes(),
    );
    bytes.extend_from_slice(&encoded);
    bytes.extend_from_slice(
        format!("\nendstream\nendobj\nstartxref\n{xref_offset}\n%%EOF\n").as_bytes(),
    );
    bytes
}

fn budget_options() -> ReaderOptions {
    ReaderOptions {
        decode_limits: DecodeLimits {
            document_budget: Some(DocumentDecodeBudget {
                base_allowance: 820,
                max_ratio: 1.0,
            }),
            ..DecodeLimits::default()
        },
        ..ReaderOptions::default()
    }
}

fn decode_payload(reader: &PdfFile) -> Vec<u8> {
    let Object::Stream(stream) = reader.get_object_at((2, 0), None).unwrap() else {
        panic!("payload must be a stream");
    };
    reader
        .read_stream_data(&stream, DecodePurpose::Generic, None)
        .unwrap()
}

#[test]
fn reopen_xref_uses_remaining_budget_before_parsing_larger_output() {
    let objects = vec![b"<</Type /Catalog>>".to_vec(), encoded_stream(&[0; 800])];
    let original = table_pdf(&objects, "", 0);
    assert!(original.len() < 820);
    let reader = PdfFile::parse_with(&original, budget_options()).unwrap();
    assert_eq!(decode_payload(&reader).len(), 800);
    assert_eq!(reader.remaining_decode_budget(), Some(20));
    let output = xref_stream_pdf(&[0; 800], 10_000);
    assert!(output.len() > original.len());
    // A constructor that recomputes from file size incorrectly grants >10KB.
    assert!(PdfFile::parse_with(&output, budget_options()).is_ok());
    assert!(matches!(
        reader.reopen(&output),
        Err(PdfError::DecodeLimit(_))
    ));
    assert_eq!(reader.remaining_decode_budget(), Some(20));
}

#[test]
fn modification_analysis_xref_uses_remaining_budget_before_parsing() {
    let bytes = xref_stream_pdf(&[0; 780], 0);
    assert!(bytes.len() < 820);
    let reader = PdfFile::parse_with(&bytes, budget_options()).unwrap();
    assert_eq!(reader.remaining_decode_budget(), Some(792));
    assert_eq!(decode_payload(&reader).len(), 780);
    assert_eq!(reader.remaining_decode_budget(), Some(12));
    assert!(matches!(
        reader.for_modification_analysis(),
        Err(PdfError::DecodeLimit(_))
    ));
}

#[test]
fn unchanged_reopen_shares_bytes_and_decoding_cache_without_new_allowance() {
    let bytes = table_pdf(
        &[b"<</Type /Catalog>>".to_vec(), encoded_stream(&[0; 800])],
        "",
        0,
    );
    let reader = PdfFile::parse_with(&bytes, budget_options()).unwrap();
    assert_eq!(decode_payload(&reader).len(), 800);
    let reopened = reader.reopen(&bytes).unwrap();
    assert!(Arc::ptr_eq(&reader.bytes_arc(), &reopened.bytes_arc()));
    assert_eq!(reopened.remaining_decode_budget(), Some(20));
    assert_eq!(decode_payload(&reopened).len(), 800);
    assert_eq!(reader.remaining_decode_budget(), Some(20));
    assert_eq!(reopened.remaining_decode_budget(), Some(20));
}

#[test]
fn changed_reopen_preserves_strictness_lossless_policy_and_rebuilds_object_cache() {
    let original = table_pdf(&[b"<</Type /Catalog>>".to_vec(), b"1.0".to_vec()], "", 0);
    let changed = table_pdf(
        &[b"<</Type /Catalog>>".to_vec(), b"1.00000001".to_vec()],
        "",
        0,
    );
    for strict in [false, true] {
        for lossless_reals in [false, true] {
            let reader = PdfFile::parse_with(
                &original,
                ReaderOptions {
                    strict,
                    lossless_reals,
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(reader.get_object_at((2, 0), None).is_ok());
            let reopened = reader.reopen(&changed).unwrap();
            assert_eq!(reopened.strict(), strict);
            assert_eq!(
                reopened.get_object_at((2, 0), None).is_err(),
                lossless_reals
            );
            assert_eq!(reopened.get_object_at((999, 0), None).is_err(), strict);
        }
    }
}

#[derive(Debug)]
struct MarkerDecryptor;

impl Decryptor for MarkerDecryptor {
    fn decrypt_object(&self, object: Object, _: (u32, u16)) -> sigis_pdf::PdfResult<Object> {
        Ok(object)
    }
    fn crypt_filters(&self) -> Option<&dyn sigis_pdf::stream::CryptFilterDecode> {
        None
    }
}

fn identity_pdf(encryption: &str, filters: &str, first_id: &str, second_id: &str) -> Vec<u8> {
    table_pdf(
        &[
            b"<</Type /Catalog>>".to_vec(),
            encryption.as_bytes().to_vec(),
            filters.as_bytes().to_vec(),
        ],
        &format!("/Encrypt 2 0 R /ID [({first_id}) ({second_id})]"),
        0,
    )
}

const ENCRYPTION: &str = "<</Filter /Standard /V 4 /CF 3 0 R>>";
const FILTERS: &str = "<</StdCF <</CFM /AESV2>>>>";

#[test]
fn encrypted_reopen_compares_indirect_settings_and_permanent_id_before_key_transfer() {
    // Synthetic raw graph isolates authentication-transfer checks from cipher correctness.
    let original = identity_pdf(ENCRYPTION, FILTERS, "permanent", "old");
    let reader = PdfFile::parse(&original).unwrap();
    let marker: Arc<dyn Decryptor> = Arc::new(MarkerDecryptor);
    reader.set_decryptor(Some(marker.clone()));
    let changed_second_id = identity_pdf(ENCRYPTION, FILTERS, "permanent", "new");
    let reopened = reader.reopen(&changed_second_id).unwrap();
    assert!(Arc::ptr_eq(&marker, &reopened.decryptor().unwrap()));
    for bytes in [
        identity_pdf(
            "<</Filter /Standard /V 5 /CF 3 0 R>>",
            FILTERS,
            "permanent",
            "new",
        ),
        identity_pdf(ENCRYPTION, "<</StdCF <</CFM /AESV3>>>>", "permanent", "new"),
        identity_pdf(ENCRYPTION, FILTERS, "different", "new"),
    ] {
        let error = reader.reopen(&bytes).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed encryption settings or document ID"),
            "{error}"
        );
        assert!(Arc::ptr_eq(&marker, &reader.decryptor().unwrap()));
    }
}

#[test]
fn encrypted_reopen_rejects_cyclic_or_excessive_identity_graphs() {
    let original = identity_pdf(ENCRYPTION, FILTERS, "permanent", "old");
    let reader = PdfFile::parse(&original).unwrap();
    reader.set_decryptor(Some(Arc::new(MarkerDecryptor)));
    let repeated = format!("<</Items [{}]>>", "0 ".repeat(4097));
    for filters in ["<</StdCF 3 0 R>>", repeated.as_str()] {
        let bytes = identity_pdf(ENCRYPTION, filters, "permanent", "new");
        let error = reader.reopen(&bytes).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Encryption settings graph exceeds reopen limits"),
            "{error}"
        );
    }
}

#[test]
fn plaintext_copy_clears_decryptor_without_resetting_budget() {
    let original = identity_pdf(ENCRYPTION, FILTERS, "permanent", "old");
    let reader = PdfFile::parse_with(&original, budget_options()).unwrap();
    reader.set_decryptor(Some(Arc::new(MarkerDecryptor)));
    let before = reader.remaining_decode_budget();
    let plaintext = table_pdf(
        &[b"<</Type /Catalog>>".to_vec()],
        "/ID [(fresh) (copy)]",
        10_000,
    );
    let reopened = reader.reopen(&plaintext).unwrap();
    assert!(!reopened.encrypted());
    assert!(reopened.decryptor().is_none());
    assert_eq!(reopened.remaining_decode_budget(), before);
    assert!(reopened.reopen(&original).is_err());
}

#[test]
fn password_encrypted_incremental_update_preserves_actual_authenticated_access() {
    let mut writer = PdfFileWriter::new(false, true).unwrap();
    writer
        .encrypt_with(
            "owner",
            Some("user"),
            StandardEncryptOptions {
                pdf_mac: false,
                ..Default::default()
            },
        )
        .unwrap();
    let input = writer.write().unwrap();
    let reader = PdfFile::parse(&input).unwrap();
    assert_eq!(reader.decrypt("user").unwrap().status, AuthStatus::User);
    assert_authenticated_update(&reader);
}

#[test]
fn public_key_encrypted_incremental_update_preserves_actual_authenticated_access() {
    let decrypter = SimpleEnvelopeKeyDecrypter::load(
        &sigis_testdata::read(&["pyhanko", "crypto", "keys-rsa", "signer.key.pem"]),
        &sigis_testdata::read(&[
            "pyhanko",
            "crypto",
            "testing-ca",
            "interm",
            "decrypter1.cert.pem",
        ]),
        Some(b"secret"),
    )
    .unwrap();
    let mut writer = PdfFileWriter::new(false, true).unwrap();
    writer
        .encrypt_pubkey_with(
            &[decrypter.cert_info().der().to_vec()],
            PubKeyEncryptOptions {
                pdf_mac: false,
                ..Default::default()
            },
        )
        .unwrap();
    let input = writer.write().unwrap();
    let reader = PdfFile::parse(&input).unwrap();
    assert_eq!(
        reader.decrypt_pubkey(&decrypter).unwrap().status,
        AuthStatus::User
    );
    assert_authenticated_update(&reader);
}

fn assert_authenticated_update(reader: &PdfFile) {
    let original_handler = reader.decryptor().unwrap();
    let mut writer = IncrementalWriter::new(reader.clone());
    let object = writer
        .add_object(Object::String(
            b"new encrypted secret".to_vec(),
            sigis_pdf::lopdf::StringFormat::Literal,
        ))
        .unwrap();
    let output = writer.write().unwrap();
    let reopened = reader.reopen(&output).unwrap();
    assert!(Arc::ptr_eq(
        &original_handler,
        &reopened.decryptor().unwrap()
    ));
    let Object::String(value, _) = reopened.get_object(object).unwrap() else {
        panic!("new encrypted string expected");
    };
    assert_eq!(value, b"new encrypted secret");
    let Object::String(raw, _) = reopened.get_object_raw(object, None).unwrap() else {
        panic!("raw encrypted string expected");
    };
    assert_ne!(raw, b"new encrypted secret");
}

#[derive(Debug)]
struct MarkerMacFactory;

impl sigis_pdf::crypt::pdfmac::PdfMacTokenHandlerFactory for MarkerMacFactory {}

#[test]
fn public_mac_factory_getter_preserves_custom_handle_and_default_none() {
    let handler = sigis_pdf::crypt::SecurityHandler::build_from_pw(
        "owner",
        Some("user".into()),
        StandardEncryptOptions {
            pdf_mac: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(handler.mac_token_handler().is_none());
    let factory: Arc<dyn sigis_pdf::crypt::pdfmac::PdfMacTokenHandlerFactory> =
        Arc::new(MarkerMacFactory);
    handler.set_mac_token_handler(Some(factory.clone()));
    assert!(Arc::ptr_eq(&factory, &handler.mac_token_handler().unwrap()));
    let cloned = handler.clone();
    assert!(Arc::ptr_eq(&factory, &cloned.mac_token_handler().unwrap()));
    handler.set_mac_token_handler(None);
    assert!(handler.mac_token_handler().is_none());
}
