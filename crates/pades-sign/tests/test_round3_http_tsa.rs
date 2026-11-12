//! Exact HTTP timestamp ports from pyHanko 0.38.1.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use der::{Decode, Encode};
use sigis_pades_sign::pdf::seed::SigSeedValueSpec;
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SigFieldSpec};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::{oids, tlv};
use sigis_pki_core::sign::TimeStamper;
use support::pdfcheck::{check_integrity, dss_counts, embedded_signatures, oracle_verdicts};

const TIME: &str = "2020-11-01T00:00:00Z";

/// A real local HTTP endpoint: decode each RFC 3161 request and generate a
/// freshly signed response with that exact imprint and nonce.
struct HttpTsa {
    url: String,
    requests: Arc<Mutex<Vec<x509_tsp::TimeStampReq>>>,
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HttpTsa {
    fn new() -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}/timestamp", server.server_addr());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_requests = requests.clone();
        let thread_stopped = stopped.clone();
        let thread = std::thread::spawn(move || {
            let tsa = support::pki("testing-ca").tsa("tsa", support::at(TIME));
            while !thread_stopped.load(Ordering::Acquire) {
                let Some(mut request) = server.recv_timeout(Duration::from_millis(100)).unwrap()
                else {
                    continue;
                };
                assert_eq!(request.method(), &tiny_http::Method::Post);
                assert_eq!(request.url(), "/timestamp");
                assert!(request.headers().iter().any(|header| {
                    header.field.equiv("Content-Type")
                        && header.value.as_str() == "application/timestamp-query"
                }));
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).unwrap();
                let query = x509_tsp::TimeStampReq::from_der(&body).unwrap();
                assert!(query.nonce.is_some(), "the HTTP client must send a nonce");
                assert!(
                    query.cert_req,
                    "the HTTP client must request TSA certificates"
                );
                let token = tsa
                    .respond(&query.message_imprint, query.nonce.clone())
                    .unwrap();
                let info = sigis_pades_sign::timestamps::tst_info(&token).unwrap();
                assert_eq!(info.message_imprint, query.message_imprint);
                assert_eq!(info.nonce, query.nonce);
                thread_requests.lock().unwrap().push(query);
                // TimeStampResp ::= SEQUENCE { status Granted(0), token }.
                let response = tlv::encode(0x30, &[&b"\x30\x03\x02\x01\x00"[..], &token].concat());
                let decoded = x509_tsp::TimeStampResp::from_der(&response).unwrap();
                assert!(decoded.time_stamp_token.is_some());
                request
                    .respond(
                        tiny_http::Response::from_data(response).with_header(
                            tiny_http::Header::from_bytes(
                                b"Content-Type",
                                b"application/timestamp-reply",
                            )
                            .unwrap(),
                        ),
                    )
                    .unwrap();
            }
        });
        Self {
            url,
            requests,
            stopped,
            thread: Some(thread),
        }
    }

    fn assert_signature_timestamp_requested(&self, output: &[u8]) {
        let found = embedded_signatures(output);
        assert_eq!(found.len(), 1);
        let sd =
            sigis_pades_sign::cms::decode_signed_data(&support::pdfcheck::cms_bytes(&found[0]))
                .unwrap();
        let signer_info = sd.signer_infos.0.iter().next().unwrap();
        let md = DigestAlgorithm::from_oid(&signer_info.digest_alg.oid).unwrap();
        let signature_imprint = md.digest(signer_info.signature.as_bytes());
        let unsigned = signer_info.unsigned_attrs.as_ref().unwrap();
        let timestamp = unsigned
            .iter()
            .find(|attribute| attribute.oid == oids::AA_SIGNATURE_TIME_STAMP_TOKEN)
            .unwrap();
        let token = timestamp.values.iter().next().unwrap().to_der().unwrap();
        let info = sigis_pades_sign::timestamps::tst_info(&token).unwrap();
        assert_eq!(
            info.message_imprint.hashed_message.as_bytes(),
            signature_imprint
        );
        assert_eq!(
            info.message_imprint.hash_algorithm.oid,
            signer_info.digest_alg.oid
        );
        let requests = self.requests.lock().unwrap();
        assert!(!requests.is_empty(), "a real HTTP request is required");
        assert!(requests.iter().any(|request| {
            request.message_imprint == info.message_imprint && request.nonce == info.nonce
        }));
    }
}

impl Drop for HttpTsa {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}

/// Upstream also validates the seed dictionary through `sign_with_sv`.
#[test]
fn test_sv_timestamp_url() {
    let tsa = HttpTsa::new();
    let seed = SigSeedValueSpec {
        timestamp_server_url: Some(tsa.url.clone()),
        timestamp_required: true,
        ..Default::default()
    };
    let mut field = SigFieldSpec::new("Sig");
    field.seed_value_dict = Some(seed);
    let mut update =
        sigis_pades_sign::pdf::writer::PdfUpdate::new(&support::pdf("minimal.pdf")).unwrap();
    sigis_pades_sign::pdf::fields::append_signature_field(&mut update, &field).unwrap();
    let input = update.write().unwrap().0;
    // No with_timestamper: the PDF's seed URL must select the HTTP client.
    let signer = PdfSigner::new(
        PdfSignatureMetadata::pyhanko_defaults("Sig"),
        Arc::new(support::pki("testing-ca").signer("signer1")),
    )
    .at(support::at(TIME));
    assert!(signer.timestamper.is_none());
    let output = signer.sign_pdf(&input).unwrap();
    check_integrity(&output, &embedded_signatures(&output)[0]);
    tsa.assert_signature_timestamp_requested(&output);
    let root = support::pki("testing-ca").cert_path("root");
    let verdicts = oracle_verdicts(&output, &[&root], TIME, &[])
        .expect("the pinned live oracle is required for this exact port");
    let status = &verdicts[0];
    assert!(status.get("error").is_none(), "{status}");
    assert_eq!(status["seed_value_ok"], true, "{status}");
    assert_eq!(status["intact"], true, "{status}");
    assert_eq!(status["valid"], true, "{status}");
    assert!(status.get("timestamp_validity").is_some(), "{status}");
    assert_seed_value_details(&output);
    eprintln!("live oracle seed timestamp URL: {status}");
}

fn assert_seed_value_details(output: &[u8]) {
    // Preserve the exact assertions in upstream sign_with_sv, including the
    // human-readable detail string omitted by the generic verdict helper.
    let python = support::oracle_python().expect("the pinned oracle is required");
    let path = support::temp_file("seed-url-details.pdf", output);
    let result = std::process::Command::new(python)
        .args([
            "-I",
            "-c",
            r#"
import json
import sys
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_testing_commons.test_utils.signing_commons import dummy_ocsp_vc
with freeze_time('2020-11-01'):
    with open(sys.argv[1], 'rb') as source:
        signature = PdfFileReader(source).embedded_signatures[0]
        status = validate_pdf_signature(signature, dummy_ocsp_vc())
        print(json.dumps({'seed_value_ok': status.seed_value_ok, 'details': status.pretty_print_details()}))
"#,
        ])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["seed_value_ok"], true, "{result}");
    assert!(
        result["details"].as_str().unwrap().contains("no SV issues"),
        "{result}"
    );
    eprintln!("live oracle seed details: seed_value_ok=True, no SV issues");
}

#[test]
fn test_pades_revinfo_http_ts_dummydata() {
    let tsa = HttpTsa::new();
    let mut metadata = PdfSignatureMetadata::new("Sig1");
    metadata.validation_context = Some(Arc::new(support::services::dummy_ocsp_vc(TIME)));
    metadata.embed_validation_info = true;
    let output = PdfSigner::new(
        metadata,
        Arc::new(support::pki("testing-ca").signer("signer1")),
    )
    .at(support::at(TIME))
    .with_timestamper(Arc::new(sigis_pki_fetch::HttpTimeStamper::new(&tsa.url)))
    .sign_pdf(&support::pdf("minimal-with-field.pdf"))
    .unwrap();
    let signatures = embedded_signatures(&output);
    assert_eq!(signatures[0].field_name, "Sig1");
    assert_eq!(signatures[0].subfilter(), "ETSI.CAdES.detached");
    let (certificates, ocsps, _, _) = dss_counts(&output).expect("a DSS must be present");
    assert_eq!(certificates, 5);
    assert_eq!(ocsps, 1);
    check_integrity(&output, &signatures[0]);
    tsa.assert_signature_timestamp_requested(&output);
    let root = support::pki("testing-ca").cert_path("root");
    let verdicts = oracle_verdicts(&output, &[&root], TIME, &[])
        .expect("the pinned live oracle is required for this exact port");
    let status = &verdicts[0];
    assert!(status.get("error").is_none(), "{status}");
    assert_eq!(status["intact"], true, "{status}");
    assert_eq!(status["valid"], true, "{status}");
    assert!(status.get("timestamp_validity").is_some(), "{status}");
    eprintln!("live oracle HTTP TSA dummy revocation data: {status}");
}

#[test]
fn seed_timestamp_url_preserves_explicit_timestamper() {
    let explicit: Arc<dyn TimeStamper> =
        Arc::new(support::pki("testing-ca").tsa("tsa", support::at(TIME)));
    let seed = SigSeedValueSpec {
        timestamp_server_url: Some("http://127.0.0.1:1/unreachable".into()),
        timestamp_required: true,
        ..Default::default()
    };
    let resolved =
        sigis_pades_sign::http_tsa::resolve_timestamper(Some(explicit.clone()), Some(&seed))
            .unwrap();
    assert!(Arc::ptr_eq(&resolved, &explicit));
    assert!(sigis_pades_sign::http_tsa::resolve_timestamper(None, None).is_none());
}

#[test]
fn optional_seed_timestamp_url_does_not_request_a_timestamp() {
    let mut field = SigFieldSpec::new("SigOptional");
    field.seed_value_dict = Some(SigSeedValueSpec {
        timestamp_server_url: Some("http://127.0.0.1:1/unreachable".into()),
        timestamp_required: false,
        ..Default::default()
    });
    let mut update =
        sigis_pades_sign::pdf::writer::PdfUpdate::new(&support::pdf("minimal.pdf")).unwrap();
    sigis_pades_sign::pdf::fields::append_signature_field(&mut update, &field).unwrap();
    let input = update.write().unwrap().0;
    let signer = PdfSigner::new(
        PdfSignatureMetadata::pyhanko_defaults("SigOptional"),
        Arc::new(support::pki("testing-ca").signer("signer1")),
    )
    .at(support::at(TIME));
    let output = signer.sign_pdf(&input).unwrap();
    let signature = &embedded_signatures(&output)[0];
    check_integrity(&output, signature);
    let data = sigis_pades_sign::cms::decode_signed_data(&support::pdfcheck::cms_bytes(signature))
        .unwrap();
    let signer_info = data.signer_infos.0.iter().next().unwrap();
    assert!(!signer_info
        .unsigned_attrs
        .as_ref()
        .is_some_and(|attributes| {
            attributes
                .iter()
                .any(|attribute| attribute.oid == oids::AA_SIGNATURE_TIME_STAMP_TOKEN)
        }));
    let root = support::pki("testing-ca").cert_path("root");
    let status = oracle_verdicts(&output, &[&root], TIME, &[])
        .expect("the pinned oracle is required for this compatibility regression")
        .remove(0);
    assert_eq!(status["bottom_line"], true, "{status}");
    assert_eq!(status["seed_value_ok"], true, "{status}");
    assert!(status.get("timestamp_validity").is_none(), "{status}");
    eprintln!("live oracle optional timestamp URL: {status}");
}

#[test]
fn mandatory_empty_timestamp_url_is_rejected_without_a_client() {
    let mut field = SigFieldSpec::new("SigRequired");
    let seed = SigSeedValueSpec {
        timestamp_server_url: Some(String::new()),
        timestamp_required: true,
        ..Default::default()
    };
    assert!(sigis_pades_sign::http_tsa::resolve_timestamper(None, Some(&seed)).is_none());
    field.seed_value_dict = Some(seed);
    let signer = PdfSigner::new(
        PdfSignatureMetadata::pyhanko_defaults("SigRequired"),
        Arc::new(support::pki("testing-ca").signer("signer1")),
    )
    .with_field_spec(field)
    .at(support::at(TIME));
    let error = signer.sign_pdf(&support::pdf("minimal.pdf")).unwrap_err();
    assert!(
        error.to_string().contains("requires a timestamp"),
        "{error}"
    );
}

#[test]
fn mandatory_seed_tsa_is_retained_for_archival_timestamping() {
    let tsa = HttpTsa::new();
    let mut field = SigFieldSpec::new("SigLta");
    field.seed_value_dict = Some(SigSeedValueSpec {
        timestamp_server_url: Some(tsa.url.clone()),
        timestamp_required: true,
        ..Default::default()
    });
    let mut metadata = PdfSignatureMetadata::new("SigLta");
    metadata.embed_validation_info = true;
    metadata.use_pades_lta = true;
    metadata.validation_context = Some(Arc::new(support::services::live_testing_vc(
        "testing-ca",
        TIME,
        &[],
    )));
    let signer = PdfSigner::new(
        metadata,
        Arc::new(support::pki("testing-ca").signer("signer1")),
    )
    .with_field_spec(field)
    .at(support::at(TIME));
    let output = signer.sign_pdf(&support::pdf("minimal.pdf")).unwrap();
    assert!(
        signer.timestamper.is_none(),
        "seed TSA selection must stay session-local"
    );
    assert_eq!(support::pdfcheck::sig_kinds(&output), (1, 1));
    let signatures = embedded_signatures(&output);
    for signature in &signatures {
        check_integrity(&output, signature);
    }
    let timestamp = signatures
        .iter()
        .find(|signature| signature.sig_type() == "DocTimeStamp")
        .unwrap();
    let info =
        sigis_pades_sign::timestamps::tst_info(&support::pdfcheck::cms_bytes(timestamp)).unwrap();
    let md = DigestAlgorithm::from_oid(&info.message_imprint.hash_algorithm.oid).unwrap();
    let first_end = usize::try_from(timestamp.byte_range[1]).unwrap();
    let second_start = usize::try_from(timestamp.byte_range[2]).unwrap();
    let second_len = usize::try_from(timestamp.byte_range[3]).unwrap();
    let mut signed_bytes = output[..first_end].to_vec();
    signed_bytes.extend_from_slice(&output[second_start..second_start + second_len]);
    assert_eq!(
        info.message_imprint.hashed_message.as_bytes(),
        md.digest(&signed_bytes)
    );
    assert!(tsa.requests.lock().unwrap().iter().any(|query| {
        query.message_imprint == info.message_imprint && query.nonce == info.nonce
    }));
    let root = support::pki("testing-ca").cert_path("root");
    let verdicts = oracle_verdicts(
        &output,
        &[&root],
        TIME,
        &["--ades-lta", "--live", "testing-ca"],
    )
    .expect("the pinned oracle is required for archival TSA propagation");
    assert_eq!(verdicts[0]["bottom_line"], true, "{}", verdicts[0]);
    eprintln!("live oracle seed URL archival timestamp: {}", verdicts[0]);
}
