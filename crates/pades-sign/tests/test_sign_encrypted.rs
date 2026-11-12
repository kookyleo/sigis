//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_sign_encrypted.py`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use sigis_pades_sign::pdf::writer::PdfUpdate;
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SignOptions, SubFilter};
use sigis_pdf::crypt::{AuthStatus, SimpleEnvelopeKeyDecrypter};
use sigis_pdf::{PdfFile, ReaderOptions};
use support::pdfcheck::*;
use support::*;

const T: &str = "2020-11-01T00:00:00+00:00";

fn signer() -> Arc<sigis_pades_sign::SimpleSigner> {
    Arc::new(pki("testing-ca").signer("signer1"))
}

fn sign(input: &[u8], field: &str, password: &[u8], existing_only: bool) -> Vec<u8> {
    PdfSigner::new(PdfSignatureMetadata::pyhanko_defaults(field), signer())
        .at(at(T))
        .sign_pdf_with(
            input,
            &SignOptions {
                existing_fields_only: existing_only,
                password: Some(password.to_vec()),
                ..Default::default()
            },
        )
        .unwrap()
}

/// `val_trusted` on a document opened with `password`.
fn val_trusted_pw(out: &[u8], password: &str, extd: bool) -> Option<serde_json::Value> {
    let root = pki("testing-ca").cert_path("root");
    let mut extra = vec!["--password", password];
    if extd {
        extra.push("--extd");
    }
    let v = oracle_verdicts(out, &[&root], T, &extra)?;
    let s = v[0].clone();
    assert!(
        s.get("error").is_none() && s.get("reader_error").is_none(),
        "{s}"
    );
    for k in ["intact", "valid", "trusted", "bottom_line"] {
        assert_eq!(s[k], true, "{k}: {s}");
    }
    if extd {
        assert_eq!(s["coverage"], "ENTIRE_REVISION", "{s}");
    } else {
        assert_eq!(s["coverage"], "ENTIRE_FILE", "{s}");
        assert_eq!(s["modification_level"], "NONE", "{s}");
    }
    Some(s)
}

#[test]
fn test_sign_crypt_rc4() {
    for pw in ["usersecret", "ownersecret"] {
        let out = sign(&pdf("minimal-with-field-rc4.pdf"), "", pw.as_bytes(), true);
        val_trusted_pw(&out, pw, false);
    }
}

#[test]
fn test_sign_crypt_aes256() {
    for pw in ["usersecret", "ownersecret"] {
        let out = sign(
            &pdf("minimal-with-field-aes256.pdf"),
            "",
            pw.as_bytes(),
            true,
        );
        val_trusted_pw(&out, pw, false);
    }
}

fn selfsigned_decrypter() -> Arc<SimpleEnvelopeKeyDecrypter> {
    Arc::new(
        SimpleEnvelopeKeyDecrypter::load(
            &pyhanko_data(&["crypto", "selfsigned.key.pem"]),
            &pyhanko_data(&["crypto", "selfsigned.cert.pem"]),
            Some(b"secret"),
        )
        .unwrap(),
    )
}

fn pubkey_oracle_output(output: &[u8], copied: bool) -> std::process::Output {
    let python = oracle_python().expect("the pinned pyHanko oracle is required");
    let output_file = temp_file("pubkey-signature.pdf", output);
    let root = pki("testing-ca").cert_path("root");
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("oracle/validate_pubkey_signature.py");
    let mut command = std::process::Command::new(python);
    command
        .arg("-I")
        .arg(script)
        .args([
            "--pdf",
            path_str(&output_file),
            "--trust",
            path_str(&root),
            "--time",
            T,
        ])
        .args([
            "--key",
            path_str(&data_path(&["pyhanko", "crypto", "selfsigned.key.pem"])),
        ])
        .args([
            "--cert",
            path_str(&data_path(&["pyhanko", "crypto", "selfsigned.cert.pem"])),
        ]);
    if copied {
        command.arg("--copied");
    }
    command.output().unwrap()
}

fn validate_pubkey_signature(output: &[u8], copied: bool) -> serde_json::Value {
    let result = pubkey_oracle_output(output, copied);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

fn sign_pubkey_native(input: &[u8]) -> Vec<u8> {
    let output = PdfSigner::new(PdfSignatureMetadata::pyhanko_defaults(""), signer())
        .at(at(T))
        .sign_pdf_with(
            input,
            &SignOptions {
                existing_fields_only: true,
                pubkey_credential: Some(selfsigned_decrypter()),
                ..Default::default()
            },
        )
        .unwrap();
    let reader = PdfFile::parse_with(&output, ReaderOptions::default()).unwrap();
    assert!(reader.encrypted());
    assert_ne!(
        reader
            .decrypt_pubkey(selfsigned_decrypter().as_ref())
            .unwrap()
            .status,
        AuthStatus::Failed
    );
    let signatures = reader.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let native = &signatures[0];
    let found = FoundSig {
        field_name: native.field_name.clone(),
        field: reader
            .get_object_at(native.field_object, None)
            .unwrap()
            .as_dict()
            .unwrap()
            .clone(),
        field_id: native.field_object,
        sig: reader
            .get_object_at(native.sig_object, None)
            .unwrap()
            .as_dict()
            .unwrap()
            .clone(),
        sig_id: Some(native.sig_object),
        byte_range: native
            .byte_range
            .iter()
            .map(|value| i64::try_from(*value).unwrap())
            .collect(),
        contents: native.contents.clone(),
    };
    check_integrity(&output, &found);
    output
}

fn sign_pubkey(input: &[u8]) -> Vec<u8> {
    let output = sign_pubkey_native(input);
    let status = validate_pubkey_signature(&output, false);
    for flag in ["intact", "valid", "trusted", "bottom_line"] {
        assert_eq!(status[flag], true, "{flag}: {status}");
    }
    assert_eq!(status["coverage"], "ENTIRE_FILE", "{status}");
    assert_eq!(status["modification_level"], "NONE", "{status}");
    output
}

#[test]
fn test_sign_crypt_pubkey_aes256() {
    sign_pubkey(&pdf("minimal-with-field-pubkey-aes256.pdf"));
}

#[test]
fn test_sign_crypt_pubkey_rc4() {
    sign_pubkey(&pdf("minimal-with-field-pubkey-rc4.pdf"));
}

/// Append a raw revision that changes representation, leaving all encrypted
/// document content and recipient key material byte-for-byte unchanged.
fn pubkey_input_with_indirect_settings(indirect_id: bool) -> Vec<u8> {
    use std::collections::BTreeMap;
    use std::io::Write;

    use lopdf::{Dictionary, Object};

    let mut output = pdf("minimal-with-field-pubkey-aes256.pdf");
    let reader = PdfFile::parse(&output).unwrap();
    let original_trailer = reader.trailer_view();
    let new_id = (
        u32::try_from(original_trailer.get(b"Size").unwrap().as_i64().unwrap()).unwrap(),
        0,
    );
    let encrypt_id = original_trailer
        .get(b"Encrypt")
        .unwrap()
        .as_reference()
        .unwrap();
    let mut objects = BTreeMap::new();
    let mut trailer = Dictionary::new();
    for key in [b"Root".as_slice(), b"Encrypt".as_slice(), b"ID".as_slice()] {
        trailer.set(key, original_trailer.get(key).unwrap().clone());
    }
    if indirect_id {
        objects.insert(new_id, original_trailer.get(b"ID").unwrap().clone());
        trailer.set("ID", Object::Reference(new_id));
    } else {
        let mut encryption = reader
            .get_object_raw(encrypt_id, None)
            .unwrap()
            .as_dict()
            .unwrap()
            .clone();
        let filter = encryption
            .get_mut(b"CF")
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .get_mut(b"DefaultCryptFilter")
            .unwrap()
            .as_dict_mut()
            .unwrap();
        objects.insert(new_id, filter.get(b"Recipients").unwrap().clone());
        filter.set("Recipients", Object::Reference(new_id));
        objects.insert(encrypt_id, Object::Dictionary(encryption));
    }
    output.push(b'\n');
    let mut positions = BTreeMap::new();
    for (id, object) in objects {
        positions.insert(id, output.len());
        writeln!(output, "{} {} obj", id.0, id.1).unwrap();
        sigis_pdf::writer::write_object_encrypted(&mut output, &object, None).unwrap();
        output.extend_from_slice(b"\nendobj\n");
    }
    let startxref = output.len();
    output.extend_from_slice(b"xref\n0 1\n0000000000 65535 f \n");
    for (id, offset) in positions {
        writeln!(output, "{} 1\n{offset:010} {:05} n ", id.0, id.1).unwrap();
    }
    trailer.set("Prev", Object::Integer(reader.last_startxref()));
    trailer.set("Size", Object::Integer(i64::from(new_id.0) + 1));
    output.extend_from_slice(b"trailer\n");
    sigis_pdf::writer::write_object_encrypted(&mut output, &Object::Dictionary(trailer), None)
        .unwrap();
    write!(output, "\nstartxref\n{startxref}\n%%EOF\n").unwrap();

    let reader = PdfFile::parse(&output).unwrap();
    assert_ne!(
        reader
            .decrypt_pubkey(selfsigned_decrypter().as_ref())
            .unwrap()
            .status,
        AuthStatus::Failed,
        "the raw representation change must preserve valid input authentication"
    );
    output
}

#[test]
fn pubkey_signing_preserves_indirect_permanent_document_id() {
    let input = pubkey_input_with_indirect_settings(true);
    let original = PdfFile::parse(&input).unwrap();
    let original_id = original.document_id().unwrap().0;
    let output = sign_pubkey(&input);
    let signed = PdfFile::parse(&output).unwrap();
    assert_eq!(signed.document_id().unwrap().0, original_id);
}

#[test]
fn pubkey_signing_reads_indirect_recipients_without_decrypting_key_material() {
    let input = pubkey_input_with_indirect_settings(false);
    let output = sign_pubkey_native(&input);
    // pyHanko recursively constructs its security handler when Recipients is
    // indirect. Pin that input/output interoperability limitation separately:
    // native authentication and cryptographic integrity above still execute.
    for document in [&input, &output] {
        let comparison = pubkey_oracle_output(document, false);
        assert!(!comparison.status.success());
        assert!(String::from_utf8_lossy(&comparison.stderr)
            .contains("RecursionError: maximum recursion depth exceeded"));
    }
}

fn lane_d(name: &str) -> Vec<u8> {
    std::fs::read(data_path(&["lanes", "d", "encrypted", name])).unwrap()
}

#[test]
fn test_sign_crypt_empty_user_pass() {
    let out = sign(&lane_d("minimal-with-field-owner-only.pdf"), "", b"", true);
    val_trusted_pw(&out, "", false);
}

#[test]
fn test_sign_encrypted_with_extensions() {
    let p = pki("testing-ca-ed25519");
    let out = PdfSigner::new(
        PdfSignatureMetadata::pyhanko_defaults(""),
        Arc::new(p.signer("signer1")),
    )
    .at(at(T))
    .sign_pdf_with(
        &lane_d("minimal-with-field-secret.pdf"),
        &SignOptions {
            existing_fields_only: true,
            password: Some(b"secret".to_vec()),
            ..Default::default()
        },
    )
    .unwrap();
    let root = p.cert_path("root");
    if let Some(v) = oracle_verdicts(&out, &[&root], T, &["--password", "secret"]) {
        assert_eq!(v[0]["bottom_line"], true, "{}", v[0]);
    }
}

const NEW_PARAMS: [(&str, usize); 4] = [
    ("usersecret", 0),
    ("usersecret", 1),
    ("ownersecret", 0),
    ("ownersecret", 1),
];

#[test]
fn test_sign_crypt_rc4_new() {
    let files = ["minimal-rc4.pdf", "minimal-with-field-rc4.pdf"];
    for (pw, f) in NEW_PARAMS {
        let out = sign(&pdf(files[f]), "SigNew", pw.as_bytes(), false);
        val_trusted_pw(&out, pw, false);
    }
}

#[test]
fn test_sign_crypt_aes256_new() {
    let files = ["minimal-aes256.pdf", "minimal-with-field-aes256.pdf"];
    for (pw, f) in NEW_PARAMS {
        let out = sign(&pdf(files[f]), "SigNew", pw.as_bytes(), false);
        val_trusted_pw(&out, pw, false);
    }
}

#[test]
fn test_sign_encrypted_with_post_sign() {
    use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
    let files = ["minimal-aes256.pdf", "minimal-with-field-aes256.pdf"];
    for (pw, f) in NEW_PARAMS {
        let mut m = PdfSignatureMetadata::pyhanko_defaults("Sig1");
        m.validation_context = Some(Arc::new(support::services::live_testing_vc(
            "testing-ca",
            T,
            &[],
        )));
        m.subfilter = Some(SubFilter::Pades);
        m.embed_validation_info = true;
        m.dss_settings = DssContentSettings {
            placement: SigDssPlacement::SeparateRevision,
            ..Default::default()
        };
        m.use_pades_lta = true;
        let out = PdfSigner::new(m, signer())
            .at(at(T))
            .with_timestamper(Arc::new(pki("testing-ca").tsa("tsa", at(T))))
            .sign_pdf_with(
                &pdf(files[f]),
                &SignOptions {
                    password: Some(pw.as_bytes().to_vec()),
                    ..Default::default()
                },
            )
            .unwrap();
        if let Some(s) = val_trusted_pw(&out, pw, true) {
            assert_eq!(s["modification_level"], "LTA_UPDATES", "{s}");
        }
        if let Some(v) = oracle_verdicts(&out, &[], T, &["--password", pw]) {
            let kinds: Vec<&str> = v.iter().map(|e| e["type"].as_str().unwrap()).collect();
            assert_eq!(kinds, ["/Sig", "/DocTimeStamp"]);
        }
    }
}

#[test]
fn test_copy_encrypted_signed_file() {
    let out = sign(
        &pdf("minimal-with-field-aes256.pdf"),
        "",
        b"ownersecret",
        true,
    );
    // copy_into_new_writer of the decrypted document: a fresh, unencrypted
    // single-revision file whose signature no longer matches
    let copied = fresh_copy_decrypted(&out, b"ownersecret");
    assert!(!PdfFile::parse_with(&copied, ReaderOptions::default())
        .unwrap()
        .encrypted());
    let root = pki("testing-ca").cert_path("root");
    if let Some(v) = oracle_verdicts(&copied, &[&root], T, &[]) {
        assert_eq!(v[0]["intact"], false, "{}", v[0]);
    }
}

/// Rewrite the decrypted contents of an encrypted file as a new document.
fn fresh_copy_decrypted(pdf_in: &[u8], password: &[u8]) -> Vec<u8> {
    let mut update = PdfUpdate::with_password(pdf_in, password).unwrap();
    update.make_fresh();
    update.write().unwrap().0
}

fn assert_catalog_backref(reader: &PdfFile) {
    use sigis_pdf::PdfHandlerExt;
    let root_id = reader
        .trailer_view()
        .get(b"Root")
        .unwrap()
        .as_reference()
        .unwrap();
    let signatures = reader.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let signature = reader
        .get_object_at(signatures[0].sig_object, None)
        .unwrap();
    let references = reader
        .resolve(signature.as_dict().unwrap().get(b"Reference").unwrap())
        .unwrap();
    assert!(references.as_array().unwrap().iter().any(|reference| {
        let dictionary = reader.resolve(reference).unwrap();
        dictionary
            .as_dict()
            .unwrap()
            .get(b"Data")
            .and_then(lopdf::Object::as_reference)
            .is_ok_and(|id| id == root_id)
    }));
}

#[test]
fn test_copy_file_with_mdp_signature_and_backref() {
    let input = pdf("signed-encrypted-pubkey-with-catalog-ref.pdf");
    let original = PdfFile::parse_with(&input, ReaderOptions::default()).unwrap();
    assert_ne!(
        original
            .decrypt_pubkey(selfsigned_decrypter().as_ref())
            .unwrap()
            .status,
        AuthStatus::Failed
    );
    assert_catalog_backref(&original);
    let mut update = PdfUpdate::with_pubkey(&input, selfsigned_decrypter().as_ref()).unwrap();
    update.make_fresh();
    let (copied, offsets) = update.write().unwrap();
    assert!(offsets.is_empty());
    let reader = PdfFile::parse_with(&copied, ReaderOptions::default()).unwrap();
    assert!(!reader.encrypted());
    assert!(reader.trailer_view().get(b"Encrypt").is_err());
    assert_catalog_backref(&reader);
    // The original signed byte range cannot authenticate a rewritten file.
    // Check that negative in Rust before asking the fresh Python validator.
    let signatures = reader.embedded_signatures().unwrap();
    let signature = &signatures[0];
    let cms_len = sigis_pades_sign::pdf::embedded::der_tlv_len(&signature.contents).unwrap();
    let data = sigis_pades_sign::cms::decode_signed_data(&signature.contents[..cms_len]).unwrap();
    let signer = data.signer_infos.0.iter().next().unwrap();
    let md = sigis_pki_core::algorithms::DigestAlgorithm::from_oid(&signer.digest_alg.oid).unwrap();
    let claimed = signer
        .signed_attrs
        .as_ref()
        .unwrap()
        .iter()
        .find(|attribute| attribute.oid == sigis_pki_core::asn1::oids::MESSAGE_DIGEST)
        .unwrap()
        .values
        .iter()
        .next()
        .unwrap()
        .decode_as::<der::asn1::OctetString>()
        .unwrap();
    let range = &signature.byte_range;
    let intact = if range.len() == 4 && range[0] == 0 {
        let end_first = usize::try_from(range[1]).unwrap();
        let start_second = usize::try_from(range[2]).unwrap();
        let end_second = start_second
            .checked_add(usize::try_from(range[3]).unwrap())
            .unwrap();
        if end_first <= start_second && end_second <= copied.len() {
            let mut bytes = copied[..end_first].to_vec();
            bytes.extend_from_slice(&copied[start_second..end_second]);
            md.digest(&bytes) == claimed.as_bytes()
        } else {
            false
        }
    } else {
        false
    };
    assert!(
        !intact,
        "a rewritten plaintext copy must not retain original signature integrity"
    );
    let status = validate_pubkey_signature(&copied, true);
    assert_eq!(status["intact"], false, "{status}");
    assert_eq!(status["skip_diff"], true, "{status}");
}

fn encrypted_explicit_crypt_stream() -> (Vec<u8>, lopdf::ObjectId, Vec<u8>) {
    use sigis_pdf::crypt::{add_crypt_filter, encode_stream_with, StandardEncryptOptions, STD_CF};
    use sigis_pdf::stream::DecodedStream;
    use sigis_pdf::{PdfFileWriter, PdfHandlerExt};

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
    let payload = b"Explicit crypt stream payload".repeat(16);
    let mut stream = DecodedStream::new(lopdf::Dictionary::new(), payload.clone());
    add_crypt_filter(&mut stream, STD_CF, None, Some(&handler)).unwrap();
    let id = writer
        .add_object(lopdf::Object::Stream(
            encode_stream_with(&stream, &handler).unwrap(),
        ))
        .unwrap();
    let mut root = writer.root().unwrap();
    root.set("Payload", lopdf::Object::Reference(id));
    let root_id = writer.root_id();
    writer.update_object(root_id, lopdf::Object::Dictionary(root));
    (writer.write().unwrap(), id, payload)
}

#[test]
fn fresh_copy_decrypts_explicit_crypt_stream_without_retaining_filter() {
    use sigis_pdf::decode_limits::DecodePurpose;

    let (input, stream_id, payload) = encrypted_explicit_crypt_stream();
    let original = PdfFile::parse(&input).unwrap();
    assert_ne!(
        original.decrypt("secret").unwrap().status,
        AuthStatus::Failed
    );
    let original_stream = original.get_object_at(stream_id, None).unwrap();
    assert_eq!(
        original
            .read_stream_data(
                original_stream.as_stream().unwrap(),
                DecodePurpose::Generic,
                None,
            )
            .unwrap(),
        payload
    );

    let mut update = PdfUpdate::with_password(&input, b"secret").unwrap();
    update.make_fresh();
    let copied = update.write().unwrap().0;
    let reader = PdfFile::parse(&copied).unwrap();
    assert!(!reader.encrypted());
    let stream = reader.get_object_at(stream_id, None).unwrap();
    let stream = stream.as_stream().unwrap();
    assert!(stream.dict.get(b"Filter").is_err());
    assert!(stream.dict.get(b"DecodeParms").is_err());
    assert_eq!(
        reader
            .read_stream_data(stream, DecodePurpose::Generic, None)
            .unwrap(),
        payload
    );
    let source_path = temp_file("explicit-crypt-source.pdf", &input);
    let copied_path = temp_file("explicit-crypt-copy.pdf", &copied);
    let hex: String = payload.iter().map(|byte| format!("{byte:02x}")).collect();
    let comparison = std::process::Command::new(
        oracle_python().expect("the fresh pinned oracle is required for explicit Crypt copying"),
    )
    .args([
        "-I",
        "-c",
        r#"
import importlib.metadata, sys
from pyhanko.pdf_utils.crypt import AuthStatus
from pyhanko.pdf_utils.reader import PdfFileReader
assert importlib.metadata.version('pyhanko') == '0.38.1'
for path, encrypted in [(sys.argv[1], True), (sys.argv[2], False)]:
    with open(path, 'rb') as source:
        reader = PdfFileReader(source)
        assert bool(reader.encrypted) == encrypted
        if encrypted:
            assert reader.decrypt('secret').status != AuthStatus.FAILED
        assert reader.root['/Payload'].data == bytes.fromhex(sys.argv[3])
print('PASS explicit Crypt plaintext copy bytes')
"#,
    ])
    .args([path_str(&source_path), path_str(&copied_path), &hex])
    .output()
    .unwrap();
    assert!(
        comparison.status.success(),
        "{}",
        String::from_utf8_lossy(&comparison.stderr)
    );
    assert!(String::from_utf8_lossy(&comparison.stdout)
        .contains("PASS explicit Crypt plaintext copy bytes"));
}

#[test]
fn fresh_copy_explicit_crypt_stream_cannot_reset_decode_budget() {
    use sigis_pades_sign::pdf::writer::PdfReopenState;
    use sigis_pdf::decode_limits::{DecodeLimits, DocumentDecodeBudget};

    let (input, _, payload) = encrypted_explicit_crypt_stream();
    let limits = DecodeLimits {
        document_budget: Some(DocumentDecodeBudget {
            base_allowance: u64::try_from(payload.len() - 1).unwrap(),
            max_ratio: 0.0,
        }),
        ..Default::default()
    };
    let reader = PdfFile::parse_with(
        &input,
        ReaderOptions {
            decode_limits: limits,
            ..Default::default()
        },
    )
    .unwrap();
    assert_ne!(reader.decrypt("secret").unwrap().status, AuthStatus::Failed);
    let mut update =
        PdfUpdate::open_with_state(&input, PdfReopenState::from_reader(reader)).unwrap();
    update.make_fresh();
    let error = update
        .write()
        .expect_err("a plaintext rewrite must charge explicit crypt decoding to the caller budget");
    assert!(error.to_string().contains("limit"), "{error}");
}
