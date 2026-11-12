//! Signing-side coverage of pyHanko 0.38.1 PDF MAC workflows.
//!
//! The two named upstream functions belong to lane S; these tests provide
//! executable signing prerequisites and add no lane P function counts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use lopdf::{Dictionary, Object};
use sigis_pades_sign::pdf::mac::PdfMacSessions;
use sigis_pades_sign::pdf::writer::{PdfReopenState, PdfUpdate};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SignOptions};
use sigis_pdf::crypt::pdfmac::{
    default_build_auth_data, derive_mac_kek, PdfMacTokenHandler, PdfMacTokenHandlerFactory,
};
use sigis_pdf::crypt::{PdfMacStatus, SecurityHandler, StandardEncryptOptions};
use sigis_pdf::{PdfFile, PdfFileWriter, PdfHandlerExt, ReaderOptions};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::errors::{HankoError, Result};
use sigis_pki_core::sign::TimeStamper;
use support::*;

const T: &str = "2020-11-01T00:00:00+00:00";

fn encrypted_document() -> Vec<u8> {
    let mut writer = PdfFileWriter::new(false, true).unwrap();
    let mut page = Dictionary::new();
    page.set("Type", Object::Name(b"Page".to_vec()));
    page.set(
        "MediaBox",
        Object::Array(vec![0.into(), 0.into(), 595.into(), 842.into()]),
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

fn assert_mac_good(pdf: &[u8]) {
    let reader = PdfFile::parse_with(pdf, ReaderOptions::default()).unwrap();
    assert_eq!(
        reader.decrypt("secret").unwrap().mac_status,
        PdfMacStatus::Successful
    );
    let root = reader.root().unwrap();
    let extensions = reader.get_dict(&root, b"Extensions").unwrap().unwrap();
    let iso = reader.get_array(&extensions, b"ISO_").unwrap().unwrap();
    assert!(iso.iter().any(|extension| {
        reader
            .resolve(extension)
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"ExtensionLevel")
            .unwrap()
            .as_i64()
            .unwrap()
            == 32004
    }));
}

/// Exact upstream positive assertions: `pdf_mac_good` and AdES LTA bottom line.
#[test]
fn test_pdf_mac_pades_signing_prerequisite() {
    let mut metadata = PdfSignatureMetadata::new("Sig1");
    metadata.embed_validation_info = true;
    metadata.use_pades_lta = true;
    metadata.validation_context = Some(Arc::new(services::live_testing_vc(
        "testing-ca-ecdsa",
        T,
        &[],
    )));
    let pki = pki("testing-ca-ecdsa");
    let output = PdfSigner::new(metadata, Arc::new(pki.signer("signer1")))
        .at(at(T))
        .with_timestamper(Arc::new(pki.tsa("tsa", at(T))))
        .sign_pdf_with(
            &encrypted_document(),
            &SignOptions {
                password: Some(b"secret".to_vec()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_mac_good(&output);
    let root = pki.cert_path("root");
    let verdicts = support::pdfcheck::oracle_verdicts(
        &output,
        &[&root],
        T,
        &[
            "--password",
            "secret",
            "--ades-lta",
            "--norev",
            "--live",
            "testing-ca-ecdsa",
        ],
    )
    .expect("the fresh pinned oracle is required for the exact PDF MAC LTA assertions");
    assert_eq!(verdicts[0]["bottom_line"], true, "{}", verdicts[0]);
}

#[derive(Debug, Default)]
struct CountingMacFactory {
    derivations: AtomicUsize,
    dry_attached_tokens: AtomicUsize,
    real_attached_tokens: AtomicUsize,
    reject_derivation: AtomicBool,
}

impl PdfMacTokenHandlerFactory for CountingMacFactory {
    fn derive_key_material(
        &self,
        file_encryption_key: &[u8],
        kdf_salt: &[u8],
        md_algorithm: &str,
    ) -> sigis_pdf::PdfResult<(Vec<u8>, String)> {
        self.derivations.fetch_add(1, Ordering::SeqCst);
        if self.reject_derivation.load(Ordering::SeqCst) {
            return Err(sigis_pdf::PdfError::Value(
                "Custom MAC factory rejected key derivation".into(),
            ));
        }
        Ok((
            derive_mac_kek(file_encryption_key, kdf_salt)?,
            md_algorithm.to_owned(),
        ))
    }

    fn build_pdfmac_token(
        &self,
        handler: &PdfMacTokenHandler,
        document_digest: &[u8],
        signature_digest: Option<&[u8]>,
        dry_run: bool,
    ) -> sigis_pdf::PdfResult<Vec<u8>> {
        // Standalone metadata-update tokens do not establish that the PDF
        // signing session inherited this factory. Count signature-bound tokens.
        if signature_digest.is_some() {
            let counter = if dry_run {
                &self.dry_attached_tokens
            } else {
                &self.real_attached_tokens
            };
            counter.fetch_add(1, Ordering::SeqCst);
        }
        Ok(
            default_build_auth_data(self, handler, document_digest, signature_digest, dry_run)?
                .to_content_info(),
        )
    }
}

#[test]
fn signing_inherits_custom_mac_factory_through_reopened_reader_state() {
    let input = encrypted_document();
    let reader = PdfFile::parse(&input).unwrap();
    assert_eq!(
        reader.decrypt("secret").unwrap().mac_status,
        PdfMacStatus::Successful
    );
    let factory = Arc::new(CountingMacFactory::default());
    reader
        .security_handler()
        .unwrap()
        .unwrap()
        .set_mac_token_handler(Some(factory.clone()));

    // Produce genuinely different related bytes and reopen them with the
    // authenticated state, before asking a signer to consume that state.
    let mut update =
        PdfUpdate::open_with_state(&input, PdfReopenState::from_reader(reader)).unwrap();
    update
        .update_info("D:20201101000000Z", "Custom MAC factory regression")
        .unwrap();
    let (rewritten, offsets) = update.write().unwrap();
    assert!(offsets.is_empty());
    assert_ne!(rewritten, input);
    assert_mac_good(&rewritten);
    let state = update.state().reopen(&rewritten).unwrap();
    let derivations_before_signing = factory.derivations.load(Ordering::SeqCst);
    assert_eq!(factory.real_attached_tokens.load(Ordering::SeqCst), 0);

    let pki = pki("testing-ca-ecdsa");
    let signed = PdfSigner::new(
        PdfSignatureMetadata::pyhanko_defaults("CustomFactory"),
        Arc::new(pki.signer("signer1")),
    )
    .at(at(T))
    .sign_pdf_with_state(
        &rewritten,
        &SignOptions {
            reopen_state: Some(state),
            ..Default::default()
        },
    )
    .unwrap();
    // Input MAC verification also derives through the inherited factory.
    assert!(
        factory.derivations.load(Ordering::SeqCst) > derivations_before_signing,
        "the signing session must initialize the inherited factory"
    );
    assert!(factory.dry_attached_tokens.load(Ordering::SeqCst) > 0);
    assert_eq!(factory.real_attached_tokens.load(Ordering::SeqCst), 1);
    assert_mac_good(&signed.pdf);

    let python = oracle_python().expect("the fresh pinned oracle is required");
    let output = temp_file("custom-mac-factory.pdf", &signed.pdf);
    let root = pki.cert_path("root");
    let script = r#"
import importlib.metadata, json, sys
from freezegun import freeze_time
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.crypt.api import AuthStatus, PdfMacStatus
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
assert importlib.metadata.version('pyhanko') == '0.38.1'
assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
with freeze_time(sys.argv[3]), open(sys.argv[1], 'rb') as source:
    reader = PdfFileReader(source)
    authentication = reader.decrypt('secret')
    assert authentication.status != AuthStatus.FAILED
    assert authentication.mac_status == PdfMacStatus.SUCCESSFUL
    assert len(reader.embedded_signatures) == 1
    signature = reader.embedded_signatures[0]
    assert signature.field_name == 'CustomFactory'
    context = ValidationContext(trust_roots=[load_cert_from_pemder(sys.argv[2])])
    status = validate_pdf_signature(signature, context)
    assert status.intact and status.valid and status.trusted and status.bottom_line
    assert status.coverage.name == 'ENTIRE_FILE'
    assert status.modification_level.name == 'NONE'
    print(json.dumps({'mac_status': authentication.mac_status.name,
                      'bottom_line': status.bottom_line,
                      'coverage': status.coverage.name}))
"#;
    let result = Command::new(python)
        .args(["-I", "-c", script])
        .arg(output)
        .arg(root)
        .arg(T)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "custom factory oracle failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let verdict: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(verdict["mac_status"], "SUCCESSFUL");
    assert_eq!(verdict["bottom_line"], true);
    eprintln!("fresh custom MAC factory oracle: {verdict}");
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
        if !self.first.swap(true, Ordering::SeqCst) {
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(30))
                .unwrap();
        }
        self.delegate.timestamp(digest, algorithm)
    }
}

/// Exact upstream negative assertion with deterministic overlapping sessions.
#[test]
fn test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel_signing_prerequisite() {
    let first_pdf = encrypted_document();
    let second_pdf = encrypted_document();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let pki = pki("testing-ca-ecdsa");
    let signer = Arc::new(
        PdfSigner::new(
            PdfSignatureMetadata::pyhanko_defaults("Sig"),
            Arc::new(pki.signer("signer1")),
        )
        .at(at(T))
        .with_timestamper(Arc::new(BlockingTsa {
            delegate: pki.tsa("tsa", at(T)),
            first: AtomicBool::new(false),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        })),
    );
    let worker_signer = signer.clone();
    let options = SignOptions {
        password: Some(b"secret".to_vec()),
        ..Default::default()
    };
    let worker_options = options.clone();
    let first =
        std::thread::spawn(move || worker_signer.sign_pdf_with(&first_pdf, &worker_options));
    entered_rx.recv_timeout(Duration::from_secs(30)).unwrap();
    let second = signer.sign_pdf_with(&second_pdf, &options);
    release_tx.send(()).unwrap();
    let first_output = first.join().unwrap().unwrap();
    assert!(
        matches!(second, Err(HankoError::Signing(ref message))
        if message.contains("Other PDF MAC attribute provider found")),
        "{second:?}"
    );
    assert_mac_good(&first_output);
    // The completed session releases its lease, and the next document gets
    // its own encryption key rather than the previous session's key.
    let next_output = signer.sign_pdf_with(&second_pdf, &options).unwrap();
    assert_mac_good(&next_output);
}

fn handler() -> SecurityHandler {
    SecurityHandler::build_from_pw("secret", None, StandardEncryptOptions::default()).unwrap()
}

fn mac_token(cms: &[u8]) -> Vec<u8> {
    let ci = ContentInfo::from_der(cms).unwrap();
    let data = SignedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    let signer = data.signer_infos.0.iter().next().unwrap();
    let attrs = signer.unsigned_attrs.as_ref().unwrap();
    let mac = attrs
        .iter()
        .find(|attribute| attribute.oid.to_string() == "1.0.32004.1.2")
        .unwrap();
    assert_eq!(mac.values.len(), 1);
    mac.values.iter().next().unwrap().to_der().unwrap()
}

#[test]
fn test_mac_session_releases_after_error_and_rejects_duplicate_attributes() {
    let sessions = PdfMacSessions::default();
    let handler = handler();
    assert!(sessions.begin(&handler, "sha1").is_err());
    // Unlike a disallowed digest, a factory error happens after acquiring
    // the session lease. A later initialization must still be able to proceed.
    let failing_factory = Arc::new(CountingMacFactory::default());
    failing_factory
        .reject_derivation
        .store(true, Ordering::SeqCst);
    handler.set_mac_token_handler(Some(failing_factory));
    let error = sessions.begin(&handler, "sha256").unwrap_err();
    assert!(
        error.to_string().contains("Custom MAC factory rejected"),
        "{error}"
    );
    handler.set_mac_token_handler(None);
    let session = sessions.begin(&handler, "sha256").unwrap().unwrap();
    assert!(sessions.clone().begin(&handler, "sha256").is_err());
    let signer = pki("testing-ca-ecdsa").signer("signer1");
    let cms = sigis_pades_sign::sign_general_data(
        b"document",
        &signer,
        DigestAlgorithm::Sha256,
        true,
        None,
    )
    .unwrap();
    let digest = DigestAlgorithm::Sha256.digest(b"document");
    assert!(session.attach_to_cms(&[0; 31], &cms, false).is_err());
    let attached = session.attach_to_cms(&digest, &cms, false).unwrap();
    assert!(session.attach_to_cms(&digest, &attached, false).is_err());
    let dry = session.attach_to_cms(&digest, &cms, true).unwrap();
    assert_eq!(attached.len(), dry.len());
    assert_ne!(mac_token(&attached), mac_token(&dry));
    let retained_session = session.clone();
    drop(session);
    assert!(sessions.begin(&handler, "sha256").is_err());
    drop(retained_session);
    assert!(sessions.begin(&handler, "sha256").unwrap().is_some());
}

#[test]
fn test_mac_session_timestamp_uses_imprint_digest_with_independent_tsa_digest() {
    let sessions = PdfMacSessions::default();
    let session = sessions.begin(&handler(), "sha256").unwrap().unwrap();
    let digest = DigestAlgorithm::Sha256.digest(b"document");
    let mut tsa = pki("testing-ca-ecdsa").tsa("tsa", at(T));
    tsa.override_md = Some(DigestAlgorithm::Sha384);
    let token = tsa.timestamp(&digest, DigestAlgorithm::Sha256).unwrap();
    let attached = session.attach_to_cms(&digest, &token, false).unwrap();
    assert!(!mac_token(&attached).is_empty());
    assert!(session.attach_to_cms(&[0; 32], &token, false).is_err());
}

#[test]
fn test_non_signature_update_replaces_mac_with_standalone_token() {
    use sigis_pades_sign::pdf::writer::PdfUpdate;
    let input = encrypted_document();
    let mut update = PdfUpdate::with_password(&input, b"secret").unwrap();
    update
        .update_info("D:20201101000000Z", "MAC regression")
        .unwrap();
    let (output, offsets) = update.write().unwrap();
    assert!(offsets.is_empty());
    assert_mac_good(&output);
    let reader = PdfFile::parse_with(&output, ReaderOptions::default()).unwrap();
    let trailer = reader.trailer_view();
    let auth_code = trailer.get(b"AuthCode").unwrap().as_dict().unwrap();
    assert_eq!(
        auth_code.get(b"MACLocation").unwrap().as_name().unwrap(),
        b"Standalone"
    );
}

/// Live token validation proves interoperability and rejects another document's key.
#[test]
fn test_mac_session_token_matches_oracle_and_isolates_document_keys() {
    let python = oracle_python().expect("the fresh pinned oracle is required for PDF MAC tokens");
    let first = handler();
    let second = handler();
    let session = PdfMacSessions::default()
        .begin(&first, "sha256")
        .unwrap()
        .unwrap();
    let signer = pki("testing-ca-ecdsa").signer("signer1");
    let cms = sigis_pades_sign::sign_general_data(
        b"document",
        &signer,
        DigestAlgorithm::Sha256,
        true,
        None,
    )
    .unwrap();
    let digest = DigestAlgorithm::Sha256.digest(b"document");
    let attached = session.attach_to_cms(&digest, &cms, false).unwrap();
    let ci = ContentInfo::from_der(&attached).unwrap();
    let signed = SignedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    let signature = signed
        .signer_infos
        .0
        .iter()
        .next()
        .unwrap()
        .signature
        .as_bytes();
    let payload = serde_json::json!({
        "token": mac_token(&attached), "document_digest": digest,
        "signature_digest": DigestAlgorithm::Sha256.digest(signature),
        "key": first.get_file_encryption_key().unwrap(), "salt": first.get_kdf_salt().unwrap(),
        "wrong_key": second.get_file_encryption_key().unwrap(), "wrong_salt": second.get_kdf_salt().unwrap(),
    });
    let script = r#"
import importlib.metadata, json, sys
from asn1crypto import cms
from pyhanko.pdf_utils.crypt.pdfmac import PdfMacTokenHandler, PdfMacValidationError
p = json.load(sys.stdin)
assert importlib.metadata.version('pyhanko') == '0.38.1'
ad = cms.ContentInfo.load(bytes(p['token']))['content']
def validate(key, salt):
    h = PdfMacTokenHandler.for_validation(bytes(key), bytes(salt), ad)
    h.validate_pdfmac_token_cms(auth_data=ad, document_digest=bytes(p['document_digest']), signature_digest=bytes(p['signature_digest']))
validate(p['key'], p['salt'])
try:
    validate(p['wrong_key'], p['wrong_salt'])
except PdfMacValidationError:
    pass
else:
    raise AssertionError('MAC accepted another document key')
print('ok')
"#;
    let mut child = Command::new(python)
        .args(["-I", "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&payload).unwrap())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"ok\n");
}

fn authenticated_mac_input() -> (Vec<u8>, PdfReopenState) {
    let input = encrypted_document();
    let reader = PdfFile::parse(&input).unwrap();
    assert_eq!(
        reader.decrypt("secret").unwrap().mac_status,
        PdfMacStatus::Successful
    );
    (input, PdfReopenState::from_reader(reader))
}

fn continue_mac_operation(operation: &str, input: &[u8], state: PdfReopenState) -> Result<()> {
    match operation {
        "open" => {
            PdfUpdate::open_with_state(input, state)?;
        }
        "sign" => {
            let output = PdfSigner::new(
                PdfSignatureMetadata::pyhanko_defaults("BoundarySignature"),
                Arc::new(pki("testing-ca-ecdsa").signer("signer1")),
            )
            .at(at(T))
            .sign_pdf_with_state(
                input,
                &SignOptions {
                    reopen_state: Some(state),
                    ..Default::default()
                },
            )?;
            assert_mac_good(&output.pdf);
        }
        "dss" => {
            let output = sigis_pades_sign::pdf::dss::add_dss_with_state(
                input,
                &Default::default(),
                true,
                state,
            )?;
            assert_mac_good(&output.pdf);
        }
        "timestamp" => {
            use sigis_pades_sign::pdf::timestamp::{timestamp_pdf_with_state, TimestampOptions};
            let pki = pki("testing-ca-ecdsa");
            let output = timestamp_pdf_with_state(
                input,
                &pki.tsa("tsa", at(T)),
                Some("BoundaryTimestamp".into()),
                &TimestampOptions {
                    reopen_state: Some(state),
                    ..TimestampOptions::new(DigestAlgorithm::Sha256)
                },
            )?;
            assert_mac_good(&output.pdf);
        }
        _ => panic!("unknown MAC operation"),
    }
    Ok(())
}

#[test]
fn authenticated_state_accepts_valid_mac_input_for_continuing_operations() {
    let (input, state) = authenticated_mac_input();
    for operation in ["open", "sign", "dss", "timestamp"] {
        continue_mac_operation(operation, &input, state.clone())
            .unwrap_or_else(|error| panic!("{operation}: {error}"));
    }
}

#[test]
fn authenticated_state_rejects_same_identity_input_with_invalid_mac() {
    let (input, state) = authenticated_mac_input();
    let mut tampered = input.clone();
    let media_box = input
        .windows(b"/MediaBox".len())
        .position(|window| window == b"/MediaBox")
        .unwrap();
    let end = media_box
        + input[media_box..]
            .iter()
            .position(|byte| *byte == b']')
            .unwrap();
    let coordinate = media_box
        + input[media_box..end]
            .windows(3)
            .position(|window| window == b"595")
            .unwrap();
    tampered[coordinate + 2] = b'6';
    assert_eq!(tampered.len(), input.len());
    let original = PdfFile::parse(&input).unwrap();
    let invalid = PdfFile::parse(&tampered).unwrap();
    assert_eq!(
        original.document_id().unwrap(),
        invalid.document_id().unwrap()
    );
    assert_eq!(
        original.trailer_view().get(b"Encrypt").unwrap(),
        invalid.trailer_view().get(b"Encrypt").unwrap()
    );
    let authentication = invalid.decrypt("secret").unwrap();
    assert_eq!(authentication.status, sigis_pdf::crypt::AuthStatus::Failed);
    assert_eq!(authentication.mac_status, PdfMacStatus::Failed);

    let python = oracle_python().expect("the pinned oracle must reject the tampered input MAC");
    let source = temp_file("same-identity-invalid-mac.pdf", &tampered);
    let script = r#"
import importlib.metadata, sys
from pyhanko.pdf_utils.crypt.api import AuthStatus, PdfMacStatus
from pyhanko.pdf_utils.reader import PdfFileReader
assert importlib.metadata.version('pyhanko') == '0.38.1'
with open(sys.argv[1], 'rb') as source:
    reader = PdfFileReader(source)
    result = reader.decrypt('secret')
    assert result.status == AuthStatus.FAILED
    assert result.mac_status == PdfMacStatus.FAILED
print('MAC_REJECTED')
"#;
    let result = Command::new(python)
        .args(["-I", "-c", script])
        .arg(source)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "tampered input oracle failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"MAC_REJECTED\n");

    let results: Vec<_> = ["open", "sign", "dss", "timestamp"]
        .into_iter()
        .map(|operation| {
            (
                operation,
                continue_mac_operation(operation, &tampered, state.clone()).is_err(),
            )
        })
        .collect();
    assert!(
        results.iter().all(|(_, rejected)| *rejected),
        "authenticated keys must not authorize MAC-invalid bytes: {results:?}"
    );
}
