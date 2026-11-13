//! Exact S-owned PDF MAC callers for the root integration test package.
//! Derived from pyHanko 0.38.1 tests/test_pdfmac.py (MIT).
//! Keep this test at root: P signing and V validation must not gain a dev-cycle.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/signing_integration.rs"]
mod support;

#[path = "support/round3_s_pdf_inputs.rs"]
mod provenance;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use der::{Decode, Encode};
use lopdf::{Dictionary, Object, Stream};
use sigis_pades::ades::{basic::QualificationSpec, lta::lta_validation};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SignOptions, SubFilter};
use sigis_pdf::crypt::{AuthStatus, PdfMacStatus, StandardEncryptOptions};
use sigis_pdf::{PdfFile, PdfFileWriter, PdfHandlerExt, SignatureKind};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::{
    oids,
    tlv::{self, tag, Tlv},
};
use sigis_pki_core::errors::{HankoError, Result};
use sigis_pki_core::sign::TimeStamper;

const TIME: &str = "2020-11-01T00:00:00Z";

fn encrypted_document() -> Vec<u8> {
    eprintln!(
        "S_PDFMAC_CALLER_RUNTIME {}",
        serde_json::json!({
            "host":std::fs::read_to_string("/etc/hostname").unwrap().trim(),
            "runtime_slot":std::env::var("RUST_SLOTS_HELD").ok(),
            "build_manifest":env!("CARGO_MANIFEST_DIR"),
            "testdata_selection":std::env::var("HANKO_TESTDATA").ok(),
        })
    );
    // init_sample_doc(STANDARD): same password, Courier text and page size.
    let mut writer = PdfFileWriter::new(false, true).unwrap();
    let mut courier = Dictionary::new();
    courier.set("Type", Object::Name(b"Font".to_vec()));
    courier.set("Subtype", Object::Name(b"Type1".to_vec()));
    courier.set("BaseFont", Object::Name(b"Courier".to_vec()));
    let font = writer.add_object(Object::Dictionary(courier)).unwrap();
    let mut fonts = Dictionary::new();
    fonts.set("F1", Object::Reference(font));
    let mut resources = Dictionary::new();
    resources.set("Font", Object::Dictionary(fonts));
    let stream = writer.add_object(Object::Stream(Stream::new(Dictionary::new(),
        b"\n    BT\n        /F1 12 Tf 40 700 Td 12 TL\n        (Hello ISO/TS 32004!) Tj\n    ET\n    ".to_vec()))).unwrap();
    let mut page = Dictionary::new();
    page.set("Type", Object::Name(b"Page".to_vec()));
    page.set("Contents", Object::Reference(stream));
    page.set("Resources", Object::Dictionary(resources));
    page.set(
        "MediaBox",
        Object::Array(vec![
            0.into(),
            0.into(),
            Object::Real(595.28),
            Object::Real(841.89),
        ]),
    );
    writer.insert_page(page, None).unwrap();
    writer
        .encrypt_with(
            "secret",
            None,
            StandardEncryptOptions {
                compat_entries: false,
                ..Default::default()
            },
        )
        .unwrap();
    writer.write().unwrap()
}

fn authenticated_file(bytes: &[u8]) -> PdfFile {
    let file = PdfFile::parse(bytes).unwrap();
    assert!(file.encrypted());
    let auth = file.decrypt("secret").unwrap();
    assert_ne!(auth.status, AuthStatus::Failed);
    assert_eq!(
        auth.mac_status,
        PdfMacStatus::Successful,
        "{:?}",
        auth.mac_failure_reason
    );
    let root = file.root().unwrap();
    let extensions = file.get_dict(&root, b"Extensions").unwrap().unwrap();
    let iso = file.get_array(&extensions, b"ISO_").unwrap().unwrap();
    assert!(iso.iter().any(|extension| {
        file.resolve(extension)
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"ExtensionLevel")
            .unwrap()
            .as_i64()
            .unwrap()
            == 32004
    }));
    file
}

fn persist(name: &str, bytes: &[u8]) {
    // Optional runtime handoff for a separate fresh oracle invocation.
    if let Some(dir) = std::env::var_os("SIGIS_MAC_CALLER_OUTPUT_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
        let saved = provenance::read(&dir.join(name));
        assert_eq!(saved, bytes);
    }
}

/// Local real HTTP TSA using the same exported ECDSA architecture as upstream.
/// The endpoint creates each token from the received imprint and nonce.
struct HttpTsa {
    address: std::net::SocketAddr,
    url: String,
    tokens: Arc<Mutex<Vec<Vec<u8>>>>,
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HttpTsa {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let tokens = Arc::new(Mutex::new(Vec::new()));
        let worker_stopped = stopped.clone();
        let worker_tokens = tokens.clone();
        let thread = std::thread::spawn(move || {
            let tsa = support::pki("testing-ca-ecdsa").tsa("tsa", support::at(TIME));
            loop {
                let (stream, _) = listener.accept().unwrap();
                if worker_stopped.load(Ordering::Acquire) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line.trim_end(), "POST /testing-ca-ecdsa/tsa/tsa HTTP/1.1");
                let mut content_length = None;
                let mut content_type = None;
                loop {
                    line.clear();
                    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap();
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = Some(value.trim().parse::<usize>().unwrap());
                    }
                    if name.eq_ignore_ascii_case("content-type") {
                        content_type = Some(value.trim().to_owned());
                    }
                }
                assert_eq!(content_type.as_deref(), Some("application/timestamp-query"));
                let length = content_length.unwrap();
                assert!(length < 65536);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                // Decode the request without adding a direct x509-tsp dependency.
                // request_cms returns that public type; retain its exact DER input.
                let fields = Tlv::parse_exact(&body).unwrap().children().unwrap();
                assert_eq!(fields.len(), 4);
                assert_eq!(fields[0].value, &[1]);
                let imprint = fields[1].children().unwrap();
                assert_eq!(imprint.len(), 2);
                let algorithm = spki::AlgorithmIdentifierOwned::from_der(imprint[0].raw).unwrap();
                let digest = DigestAlgorithm::from_oid(&algorithm.oid).unwrap();
                assert!(imprint[1].is_universal(tag::OCTET_STRING));
                assert!(fields[2].is_universal(tag::INTEGER));
                assert!(fields[3].is_universal(tag::BOOLEAN));
                assert_eq!(fields[3].value, &[0xff]);
                let query = sigis_pki_fetch::tsa::request_cms(
                    imprint[1].value,
                    digest,
                    Some(fields[2].value),
                )
                .unwrap();
                assert_eq!(query.to_der().unwrap(), body);
                let token = tsa
                    .respond(&query.message_imprint, query.nonce.clone())
                    .unwrap();
                let info = sigis_pades_sign::timestamps::tst_info(&token).unwrap();
                assert_eq!(info.message_imprint, query.message_imprint);
                assert_eq!(info.nonce, query.nonce);
                worker_tokens.lock().unwrap().push(token.clone());
                let response = tlv::encode(0x30, &[&b"\x30\x03\x02\x01\x00"[..], &token].concat());
                let mut stream = reader.into_inner();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                stream.write_all(&response).unwrap();
                stream.flush().unwrap();
            }
        });
        Self {
            address,
            url: format!("http://{address}/testing-ca-ecdsa/tsa/tsa"),
            tokens,
            stopped,
            thread: Some(thread),
        }
    }

    fn assert_embedded_token(&self, token: &[u8]) {
        let original = sigis_pades_sign::cms::decode_signed_data(token).unwrap();
        assert_eq!(original.signer_infos.0.len(), 1);
        let mut normalized = original.clone();
        let mut signer = original.signer_infos.0.iter().next().unwrap().clone();
        // A document timestamp receives its required pdfMacData unsigned
        // attribute AFTER the real HTTP response. Remove only that attribute
        // for the served-token comparison; all signed CMS bytes must match.
        let mut mac_count = 0;
        if let Some(attributes) = signer.unsigned_attrs.take() {
            let kept: Vec<_> = attributes
                .iter()
                .filter(|attribute| {
                    if attribute.oid == sigis_pades_sign::pdf::mac::PDF_MAC_DATA {
                        mac_count += 1;
                        false
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();
            if !kept.is_empty() {
                signer.unsigned_attrs = Some(kept.try_into().unwrap());
            }
        }
        assert!(mac_count <= 1);
        normalized.signer_infos.0 = vec![signer].try_into().unwrap();
        assert!(
            self.tokens
                .lock()
                .unwrap()
                .iter()
                .any(|served| sigis_pades_sign::cms::decode_signed_data(served).unwrap().to_der().unwrap()==normalized.to_der().unwrap()),
            "all timestamp CMS content other than the added pdfMacData must equal an actual HTTP response"
        );
    }
}

impl Drop for HttpTsa {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address); // Wake only this fixture's accept.
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}

#[test]
fn test_pdf_mac_pades() {
    provenance::trace_pki("testing-ca-ecdsa");
    let tsa = HttpTsa::new();
    let pki = support::pki("testing-ca-ecdsa");
    let mut metadata = PdfSignatureMetadata::new("Sig1");
    metadata.subfilter = Some(SubFilter::Pades);
    metadata.embed_validation_info = true;
    metadata.use_pades_lta = true;
    metadata.validation_context = Some(Arc::new(support::services::live_testing_vc(
        "testing-ca-ecdsa",
        TIME,
        &[],
    )));
    let output = PdfSigner::new(metadata, Arc::new(pki.signer("signer1")))
        .at(support::at(TIME))
        .with_timestamper(Arc::new(sigis_pki_fetch::HttpTimeStamper::new(&tsa.url)))
        .sign_pdf_with(
            &encrypted_document(),
            &SignOptions {
                password: Some(b"secret".to_vec()),
                ..Default::default()
            },
        )
        .unwrap();
    persist("p-generated-mac-pades.pdf", &output);
    let file = authenticated_file(&output);
    let signatures = file.embedded_signatures().unwrap();
    let signature = signatures
        .iter()
        .find(|sig| sig.kind == SignatureKind::Signature)
        .unwrap();
    assert_eq!(signature.field_name, "Sig1");
    assert_eq!(signature.sub_filter.as_deref(), Some("ETSI.CAdES.detached"));
    let sd = sigis_pades_sign::cms::decode_signed_data(&signature.contents).unwrap();
    let si = sd.signer_infos.0.iter().next().unwrap();
    let timestamp = si
        .unsigned_attrs
        .as_ref()
        .unwrap()
        .iter()
        .find(|attr| attr.oid == oids::AA_SIGNATURE_TIME_STAMP_TOKEN)
        .unwrap();
    let token = timestamp.values.iter().next().unwrap().to_der().unwrap();
    tsa.assert_embedded_token(&token);
    let doc_timestamp = signatures
        .iter()
        .find(|sig| sig.kind == SignatureKind::DocTimeStamp)
        .unwrap();
    tsa.assert_embedded_token(&doc_timestamp.contents);
    let dss = file.dss().unwrap().unwrap();
    assert!(!dss.material.certs.is_empty());
    assert!(!dss.material.ocsps.is_empty() || !dss.material.crls.is_empty());

    // Exact upstream post-signing policy: ECC root + NO_REVOCATION.
    let context = ValidationContext::builder()
        .trust_root(pki.cert("root"))
        .moment(support::at(TIME))
        .revocation_mode("none")
        .build()
        .unwrap();
    let result = lta_validation(&file, signature, &context, &QualificationSpec::default()).unwrap();
    let status = result.api_status.as_ref().unwrap();
    assert!(status.bottom_line(), "{:?}", result.failure_msg);
    assert!(status.signature.intact && status.signature.valid && status.signature.trusted());
    let signature_timestamp = status.timestamp_validity.as_ref().unwrap();
    assert!(
        signature_timestamp.signature.intact
            && signature_timestamp.signature.valid
            && signature_timestamp.signature.trusted()
    );
    let pdf_status = sigis_pades::validate_pdf_signature(
        &file,
        signature,
        &context,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    )
    .unwrap();
    assert!(pdf_status.bottom_line());
    assert_eq!(
        pdf_status.modification_level(),
        Some(sigis_pdf_diff::ModificationLevel::LtaUpdates)
    );
    eprintln!(
        "native PDF MAC PAdES LTA: subindication={}, bottom_line={}",
        result.ades_subindic.standard_name(),
        status.bottom_line()
    );

    // Preserve real-output refusal controls alongside the original positive.
    let untrusted = ValidationContext::builder()
        .moment(support::at(TIME))
        .revocation_mode("none")
        .build()
        .unwrap();
    let denied = lta_validation(&file, signature, &untrusted, &QualificationSpec::default());
    match denied {
        Ok(result) => assert!(!result
            .api_status
            .as_ref()
            .is_some_and(|status| status.bottom_line())),
        Err(error) => assert!(!error.to_string().is_empty()),
    }
    let unopened = PdfFile::parse(&output).unwrap();
    match unopened.decrypt("wrong-secret") {
        Ok(auth) => assert_eq!(auth.status, AuthStatus::Failed),
        Err(error) => assert!(!error.to_string().is_empty()),
    }
}

#[derive(Debug)]
struct BlockingTsa {
    delegate: sigis_pades_sign::DummyTimeStamper,
    first: AtomicBool,
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl TimeStamper for BlockingTsa {
    fn timestamp(&self, digest: &[u8], algorithm: DigestAlgorithm) -> Result<Vec<u8>> {
        // Produce the actual timestamp response before blocking the first call.
        let token = self.delegate.timestamp(digest, algorithm)?;
        if !self.first.swap(true, Ordering::SeqCst) {
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(30))
                .unwrap();
        }
        Ok(token)
    }
}

#[test]
fn test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel() {
    provenance::trace_pki("testing-ca-ecdsa");
    provenance::trace_pki("testing-ca");
    let first_document = encrypted_document();
    let second_document = encrypted_document();
    assert_ne!(
        first_document, second_document,
        "documents must use independently generated encryption state"
    );
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let signer = Arc::new(
        PdfSigner::new(
            PdfSignatureMetadata::pyhanko_defaults("Sig"),
            Arc::new(support::pki("testing-ca-ecdsa").signer("signer1")),
        )
        .at(support::at(TIME))
        .with_timestamper(Arc::new(BlockingTsa {
            // Exact upstream DUMMY_TS uses testing-ca, independently of ECC signer.
            delegate: support::pki("testing-ca").tsa("tsa", support::at(TIME)),
            first: AtomicBool::new(false),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        })),
    );
    let worker_signer = signer.clone();
    assert!(Arc::ptr_eq(&worker_signer, &signer));
    // Keep upstream default estimation. The first timestamp callback blocks
    // only after the actual signing operation holds its document MAC lease.
    let options = SignOptions {
        password: Some(b"secret".to_vec()),
        ..Default::default()
    };
    let worker_options = options.clone();
    let first =
        std::thread::spawn(move || worker_signer.sign_pdf_with(&first_document, &worker_options));
    let entered = entered_rx.recv_timeout(Duration::from_secs(30));
    if entered.is_err() {
        let _ = release_tx.send(());
        let completed = first.join().unwrap();
        panic!("first actual signing operation never reached its timestamp barrier: {entered:?}; result={completed:?}");
    }
    let second = signer.sign_pdf_with(&second_document, &options);
    // Always release and join the real first operation before assertions.
    release_tx.send(()).unwrap();
    let first_output = first.join().unwrap().unwrap();
    assert!(
        matches!(&second, Err(HankoError::Signing(message))
        if message.contains("Other PDF MAC attribute provider found")),
        "{second:?}"
    );
    persist("p-generated-mac-parallel-first.pdf", &first_output);
    let file = authenticated_file(&first_output);
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|sig| sig.kind == SignatureKind::Signature)
        .unwrap();
    assert_eq!(signature.field_name, "Sig");
    // The signer and DUMMY_TS belong to separate PKIs that reuse issuer
    // names/serials. Give each role its exact trust context; do not merge
    // unrelated certificate registries when comparing the pinned validator.
    let context = ValidationContext::builder()
        .trust_root(support::pki("testing-ca-ecdsa").cert("root"))
        .moment(support::at(TIME))
        .revocation_mode("none")
        .build()
        .unwrap();
    let timestamp_context = ValidationContext::builder()
        .trust_root(support::pki("testing-ca").cert("root"))
        .moment(support::at(TIME))
        .revocation_mode("none")
        .build()
        .unwrap();
    let validation_options = sigis_cms::CmsValidationOptions {
        ts_validation_context: Some(&timestamp_context),
        ..Default::default()
    };
    let verified = sigis_pades::validate_pdf_signature_with_options(
        &file,
        &signature,
        &context,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
        &validation_options,
    )
    .unwrap();
    assert!(verified.bottom_line());
    let timestamp = verified.cms.timestamp_validity.as_ref().unwrap();
    assert!(
        timestamp.signature.intact && timestamp.signature.valid && timestamp.signature.trusted()
    );
    // A completed real session releases its lease and accepts the other key.
    let next = signer.sign_pdf_with(&second_document, &options).unwrap();
    authenticated_file(&next);
}
