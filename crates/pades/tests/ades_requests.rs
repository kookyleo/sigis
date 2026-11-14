//! Exact requests-backend assertions over a real loopback HTTP connection.
//! HTTP response bytes are recorded fixtures; this is not a live PKI oracle.
mod common;
use common::*;
use der::Encode;
use serde_json::Value;
use sigis_pades::ades::{
    basic::{basic_validation, QualificationSpec},
    lta::lta_validation,
    policy::{
        basic_validation_with_handlers, bootstrap_validation_data_handlers, HandlerFetchSelection,
        RevocationInfoGatheringSpec, ValidationDataHandlers,
    },
};
use sigis_pdf::PdfFile;
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::asn1::tlv::Tlv;
use sigis_pki_fetch::{
    common::{format_ocsp_request, CertIdHash},
    transport::HttpRequest,
    FetcherSettings, HttpFetchers, HttpResponse, HttpTransport, ReqwestTransport, TransportError,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
const MODULE: &str = "test_ades_validation_requests";
fn recording() -> Recording {
    if std::env::var_os("HANKO_ADES_RECORDING_DIR").is_some() {
        return Recording::load(MODULE);
    }
    Recording(
        serde_json::from_slice(
            &std::fs::read(data(&[
                "lanes",
                "r3-v",
                "ades",
                "test_ades_validation_requests.json",
            ]))
            .unwrap(),
        )
        .unwrap(),
    )
}
fn http(call: &Call) -> Value {
    if call.0["http"].as_array().is_some_and(|a| !a.is_empty()) {
        call.0["http"].clone()
    } else {
        call.0["case_http"].clone()
    }
}
#[derive(Debug)]
struct LoopbackTransport {
    base: String,
    actual: ReqwestTransport,
}
impl HttpTransport for LoopbackTransport {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        let rest = request
            .url
            .split_once("://")
            .map_or(request.url, |(_, r)| r);
        let path = rest.find('/').map_or("/", |p| &rest[p..]);
        let url = format!("{}{path}", self.base);
        self.actual.send(&HttpRequest {
            method: request.method,
            url: &url,
            headers: request.headers.clone(),
            body: request.body,
        })
    }
}
struct Server {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<(String, u16)>>>,
    worker: Option<thread::JoinHandle<()>>,
}
#[derive(Debug, PartialEq, Eq)]
struct OcspCertId {
    algorithm: Vec<u8>,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    serial: Vec<u8>,
}

// Match the whole CertID rather than looking for serial bytes in a response.
// Nonces are intentionally excluded from the lookup key: committed responses
// retain their original signed nonce and cannot echo a newly generated nonce.
fn ocsp_cert_id(request: &[u8]) -> Option<OcspCertId> {
    let root = Tlv::parse_exact(request).ok()?;
    if !root.is_universal(16) {
        return None;
    }
    let root = root.children().ok()?;
    let tbs = root.first()?.children().ok()?;
    let list = tbs.iter().find(|v| v.is_universal(16))?.children().ok()?;
    if list.len() != 1 {
        return None;
    }
    let single = list[0].children().ok()?;
    let cert_id = single.first()?.children().ok()?;
    if cert_id.len() != 4
        || !cert_id[1].is_universal(4)
        || !cert_id[2].is_universal(4)
        || !cert_id[3].is_universal(2)
    {
        return None;
    }
    let algorithm = cert_id[0].children().ok()?;
    if !algorithm.first()?.is_universal(6)
        || algorithm.len() > 2
        || algorithm
            .get(1)
            .is_some_and(|value| !value.is_universal(5) || !value.value.is_empty())
    {
        return None;
    }
    let mut serial = cert_id[3].value;
    while serial.len() > 1 && serial[0] == 0 {
        serial = &serial[1..];
    }
    Some(OcspCertId {
        algorithm: algorithm[0].value.to_vec(),
        issuer_name_hash: cert_id[1].value.to_vec(),
        issuer_key_hash: cert_id[2].value.to_vec(),
        serial: serial.to_vec(),
    })
}

fn matching_exchange<'a>(
    exchanges: &'a Value,
    method: &str,
    path: &str,
    request_body: &[u8],
) -> Option<&'a Value> {
    exchanges.as_array()?.iter().find(|exchange| {
        if exchange["path"] != path || exchange["method"] != method {
            return false;
        }
        let recorded_body = exchange["request_body"]
            .as_str()
            .map(b64)
            .unwrap_or_default();
        if method == "POST" {
            match (ocsp_cert_id(request_body), ocsp_cert_id(&recorded_body)) {
                (Some(actual), Some(recorded)) => actual == recorded,
                _ => false,
            }
        } else {
            recorded_body == request_body
        }
    })
}
impl Server {
    fn new(exchanges: Value, deny: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopped = stop.clone();
        let seen = requests.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("HTTP accept: {e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buf = [0u8; 4096];
                let (header_end, length) = loop {
                    let n = match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break (None, 0),
                        Ok(n) => n,
                    };
                    bytes.extend_from_slice(&buf[..n]);
                    if bytes.len() > 1024 * 1024 {
                        break (None, 0);
                    }
                    if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..i]);
                        let length = header
                            .lines()
                            .find_map(|l| {
                                l.split_once(':')
                                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                    .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        break (Some(i + 4), length);
                    }
                };
                let Some(end) = header_end else {
                    continue;
                };
                if length > 1024 * 1024 {
                    continue;
                }
                while bytes.len() < end + length {
                    let n = match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    bytes.extend_from_slice(&buf[..n]);
                }
                if bytes.len() < end + length {
                    continue;
                }
                let header = String::from_utf8_lossy(&bytes[..end]);
                let first = header.lines().next().unwrap();
                let mut words = first.split_whitespace();
                let method = words.next().unwrap_or("");
                let path = words.next().unwrap_or("");
                let request_body = &bytes[end..end + length];
                let found = if deny {
                    None
                } else {
                    matching_exchange(&exchanges, method, path, request_body)
                };
                let (code, body) = found.map_or((404, Vec::new()), |e| {
                    (
                        e["status"].as_u64().unwrap() as u16,
                        b64(e["response_body"].as_str().unwrap()),
                    )
                });
                seen.lock()
                    .unwrap()
                    .push((format!("{method} {path}"), code));
                let mime = if path.contains("/ocsp/") {
                    "application/ocsp-response"
                } else if path.contains("/crl/") {
                    "application/pkix-crl"
                } else {
                    "application/pkix-cert"
                };
                let mime = found
                    .and_then(|e| e["content_type"].as_str())
                    .unwrap_or(mime);
                let header=format!("HTTP/1.1 {code} Response\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        Self {
            address,
            stop,
            requests,
            worker: Some(worker),
        }
    }
    fn backend_with_nonce(&self, request_nonces: bool) -> HttpFetchers {
        HttpFetchers::with_transport(
            Arc::new(LoopbackTransport {
                base: format!("http://{}", self.address),
                actual: ReqwestTransport::new(Duration::from_secs(2), 4 * 1024 * 1024).unwrap(),
            }),
            FetcherSettings {
                request_nonces,
                ..Default::default()
            },
        )
    }

    fn backend(&self) -> HttpFetchers {
        // Recorded OCSP responses cannot be re-signed for a fresh nonce.
        // A separate rejection test exercises the default nonce-enabled backend.
        self.backend_with_nonce(false)
    }

    fn request(&self, method: &'static str, path: &str, body: &[u8]) -> HttpResponse {
        ReqwestTransport::new(Duration::from_secs(2), 4 * 1024 * 1024)
            .unwrap()
            .send(&HttpRequest {
                method,
                url: &format!("http://{}{path}", self.address),
                headers: vec![("Content-Type".into(), "application/ocsp-request".into())],
                body: Some(body),
            })
            .unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            if let Err(error) = worker.join() {
                if !thread::panicking() {
                    std::panic::resume_unwind(error);
                }
            }
        }
    }
}
fn context(rec: &Recording, call: &Call, server: &Server) -> ValidationContext {
    let handlers = bootstrap_validation_data_handlers(
        &RevocationInfoGatheringSpec {
            fetcher_backend: Some(server.backend()),
            ..Default::default()
        },
        false,
    );
    assert!(handlers.owned_fetcher_backend.is_none());
    assert!(handlers.fetching_allowed());
    ValidationContext::builder()
        .trust_root(rec.cert("testing-ca", "root"))
        .moment(call.time())
        .revinfo_policy(default_revinfo_policy())
        .fetchers(handlers.fetchers)
        .build()
        .unwrap()
}

fn assert_recorded_status(status: &sigis_cms::StandardCmsSignatureStatus, call: &Call) {
    for (key, actual) in [
        ("api_status.intact", status.signature.intact),
        ("api_status.valid", status.signature.valid),
        ("api_status.trusted", status.signature.trusted()),
        ("api_status.revoked", status.signature.revoked()),
        ("api_status.bottom_line", status.bottom_line()),
    ] {
        assert_eq!(actual, call.0["result"][key].as_bool().unwrap(), "{key}");
    }
}
#[test]
fn test_pades_basic_happy_path_requests() {
    let rec = recording();
    let calls = rec.calls(MODULE, "test_pades_basic_happy_path_requests");
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.function(), "ades_basic_validation");
    assert_eq!(
        call.time(),
        sigis_pki_core::time::Moment::from_ymd_hms(2020, 11, 25, 0, 0, 0).unwrap()
    );
    assert!(
        call.raw_digest().is_some(),
        "the PDF digest is supplied explicitly"
    );
    let server = Server::new(http(call), false);
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Borrowed(
        Arc::new(server.backend()),
    ));
    assert!(handlers.owned_fetcher_backend.is_none());
    assert!(handlers.fetching_allowed());
    let ctx = ValidationContext::builder()
        .trust_root(rec.cert("testing-ca", "root"))
        .moment(call.time())
        .revinfo_policy(default_revinfo_policy())
        .build()
        .unwrap();
    let result = basic_validation_with_handlers(
        &call.content_info(),
        call.raw_digest().as_deref(),
        &ctx,
        &QualificationSpec::default(),
        &handlers,
    )
    .unwrap();
    assert_eq!(result.ades_subindic.standard_name(), "OK");
    assert_eq!(call.expected_subindic(), "OK");
    let status = result.api_status.as_ref().unwrap();
    assert_recorded_status(status, call);
    assert_eq!(
        status.signature.signing_cert,
        Some(rec.cert("testing-ca", "signer1"))
    );
    assert!(
        status.signer_reported_dt.is_none(),
        "PAdES omits CMS signingTime"
    );
    assert_eq!(
        status.timestamp_validity.as_ref().unwrap().timestamp,
        sigis_pki_core::time::Moment::from_ymd_hms(2020, 11, 20, 0, 0, 0).unwrap()
    );
    assert!(
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(request, status)| {
                request == "POST /testing-ca/ocsp/interm" && *status == 200
            }),
        "Rust must consume a matching OCSP response over the actual HTTP backend"
    );
}
#[test]
fn test_pades_lta_happy_path_current_time_requests() {
    let rec = recording();
    let call = rec
        .calls(MODULE, "test_pades_lta_happy_path_current_time_requests")
        .into_iter()
        .find(|c| c.function() == "ades_lta_validation")
        .unwrap();
    assert_eq!(
        call.time(),
        sigis_pki_core::time::Moment::from_ymd_hms(2020, 11, 20, 0, 0, 0).unwrap()
    );
    let server = Server::new(http(&call), false);
    let ctx = context(&rec, &call, &server);
    let (bytes, name) = call.pdf();
    assert_eq!(name, "Sig1");
    let file = PdfFile::parse(&bytes).unwrap();
    let sig = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.field_name == name)
        .unwrap();
    let result = lta_validation(&file, &sig, &ctx, &QualificationSpec::default()).unwrap();
    assert_eq!(result.ades_subindic.standard_name(), "OK");
    assert_eq!(call.expected_subindic(), "OK");
    assert_recorded_status(result.api_status.as_ref().unwrap(), &call);
    assert_eq!(result.best_signature_time, Some(call.time()));
    let requests = server.requests.lock().unwrap();
    assert!(
        requests.iter().any(|(request, status)| {
            request == "POST /testing-ca/ocsp/interm" && *status == 200
        }),
        "LTA itself must consume a matching OCSP response over HTTP: {requests:?}"
    );
}
#[test]
fn missing_http_evidence_cannot_establish_basic_trust() {
    let rec = recording();
    let call = rec
        .calls(MODULE, "test_pades_basic_happy_path_requests")
        .into_iter()
        .next()
        .unwrap();
    let server = Server::new(http(&call), true);
    let ctx = context(&rec, &call, &server);
    let result = basic_validation(
        &call.content_info(),
        call.raw_digest().as_deref(),
        &ctx,
        &QualificationSpec::default(),
    )
    .unwrap();
    assert_ne!(result.ades_subindic.standard_name(), "OK");
    assert!(!server.requests.lock().unwrap().is_empty());
}

#[test]
fn ocsp_replay_requires_the_entire_certificate_identifier() {
    let rec = recording();
    let call = rec
        .calls(MODULE, "test_pades_basic_happy_path_requests")
        .into_iter()
        .next()
        .unwrap();
    let server = Server::new(http(&call), false);
    let signer = rec.cert("testing-ca", "signer1");
    let issuer = rec.cert("testing-ca", "interm");
    let request = |cert, issuer, hash| {
        format_ocsp_request(cert, issuer, hash, None)
            .unwrap()
            .to_der()
            .unwrap()
    };
    let valid = request(&signer, &issuer, CertIdHash::Sha1);
    assert_eq!(
        server
            .request("POST", "/testing-ca/ocsp/interm", &valid)
            .status,
        200
    );

    let other_signer = rec.cert("testing-ca", "signer2");
    let other_issuer = rec.cert("testing-ca", "root");
    let wrong_serial = request(&other_signer, &issuer, CertIdHash::Sha1);
    let wrong_issuer = request(&signer, &other_issuer, CertIdHash::Sha1);
    let wrong_hash = request(&signer, &issuer, CertIdHash::Sha256);
    let key = ocsp_cert_id(&valid).unwrap();
    let mutate_hash = |hash: &[u8]| {
        let mut mutated = valid.clone();
        let offset = mutated
            .windows(hash.len())
            .position(|value| value == hash)
            .unwrap();
        mutated[offset] ^= 1;
        mutated
    };
    let wrong_name_hash = mutate_hash(&key.issuer_name_hash);
    let wrong_key_hash = mutate_hash(&key.issuer_key_hash);
    for body in [
        wrong_serial,
        wrong_issuer,
        wrong_hash,
        wrong_name_hash,
        wrong_key_hash,
        vec![0x30, 0],
    ] {
        assert_eq!(
            server
                .request("POST", "/testing-ca/ocsp/interm", &body)
                .status,
            404
        );
    }
    assert_eq!(
        server
            .request("GET", "/testing-ca/ocsp/interm", &valid)
            .status,
        404
    );
    assert_eq!(server.request("POST", "/unknown", &valid).status, 404);
}

#[test]
fn fresh_nonce_rejects_the_recorded_nonce_over_real_http() {
    let rec = recording();
    let call = rec
        .calls(MODULE, "test_pades_basic_happy_path_requests")
        .into_iter()
        .next()
        .unwrap();
    let server = Server::new(http(&call), false);
    let error = server
        .backend_with_nonce(true)
        .fetch_ocsp_response(
            &rec.cert("testing-ca", "signer1"),
            &rec.cert("testing-ca", "interm"),
        )
        .unwrap_err();
    assert!(error.message.contains("nonces do not match"), "{error}");
    assert!(server
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|(_, status)| *status == 200));
}

#[test]
fn lta_fixture_ocsp_response_is_replayed_over_real_http() {
    let rec = recording();
    let call = rec
        .calls(MODULE, "test_pades_lta_happy_path_current_time_requests")
        .into_iter()
        .find(|call| call.function() == "ades_lta_validation")
        .unwrap();
    let exchanges = http(&call);
    let expected = exchanges
        .as_array()
        .unwrap()
        .iter()
        .find(|exchange| {
            exchange["method"] == "POST" && exchange["path"] == "/testing-ca/ocsp/interm"
        })
        .unwrap();
    let server = Server::new(exchanges.clone(), false);
    let response = server
        .backend()
        .fetch_ocsp_response(
            &rec.cert("testing-ca", "signer1"),
            &rec.cert("testing-ca", "interm"),
        )
        .unwrap();
    assert_eq!(response, b64(expected["response_body"].as_str().unwrap()));
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        &[("POST /testing-ca/ocsp/interm".to_owned(), 200)]
    );
}

#[test]
fn malformed_http_evidence_cannot_establish_basic_trust() {
    let rec = recording();
    let call = rec
        .calls(MODULE, "test_pades_basic_happy_path_requests")
        .into_iter()
        .next()
        .unwrap();
    let mut exchanges = http(&call);
    for exchange in exchanges.as_array_mut().unwrap() {
        // A well-framed HTTP success carrying an invalid ASN.1 structure.
        exchange["response_body"] = Value::String("MAA=".into());
    }
    let server = Server::new(exchanges, false);
    let ctx = context(&rec, &call, &server);
    let result = basic_validation(
        &call.content_info(),
        call.raw_digest().as_deref(),
        &ctx,
        &QualificationSpec::default(),
    )
    .unwrap();
    assert_ne!(result.ades_subindic.standard_name(), "OK");
    let status = result.api_status.unwrap();
    assert!(status.signature.intact && status.signature.valid);
    assert!(!status.signature.trusted());
    assert!(server
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|(_, status)| *status == 200));
}
