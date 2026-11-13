//! Supplemental HTTP TSA request-binding regressions; no upstream-function credit.
//!
//! Every signed response is independently checked with required revocation under
//! its declared imprint before HTTP binding assertions. Client refusal is not a
//! substitute for CMS integrity, TSA authorization or caller trust constraints.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use der::{Decode, Encode};
use serde_json::{json, Value};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::tlv::{encode, tag, Tlv};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{FetchErrorKind, HankoError};
use sigis_pki_core::sign::TimeStamper;
use sigis_pki_core::time::Moment;
use sigis_pki_fetch::tsa::{handle_tsp_response, token_tst_info};
use sigis_pki_fetch::{FetchLimits, HttpTimeStamper, NonceMode, TimestampRequestError};
use x509_tsp::{TimeStampReq, TspVersion};

const PREIMAGE: &[u8] = b"HTTP TSA request binding\0probe\xff";
const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const VALIDATION_TIME: &str = "2020-11-01T00:00:00Z";
const ALGORITHM_ERROR: &str =
    "Timestamp server response does not match the requested message imprint algorithm.";
const DIGEST_ERROR: &str =
    "Timestamp server response does not match the requested message imprint digest.";
const COMMUNICATION_ERROR: &str = "Error while contacting timestamp service";
const CASES: [&str; 12] = [
    "matching-sha256-null",
    "matching-sha256-absent",
    "matching-sha384",
    "independent-cms-sha512",
    "algorithm-only",
    "digest-only",
    "both",
    "wrong-nonce",
    "missing-nonce",
    "no-nonce-valid",
    "no-nonce-algorithm",
    "no-nonce-digest",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&DigestAlgorithm::Sha256.digest(bytes))
}

fn emit(marker: &str, value: Value) {
    let line = format!("{marker} {value}\n");
    std::io::stderr().write_all(line.as_bytes()).unwrap();
}

fn fixture_root() -> PathBuf {
    sigis_testdata::path(&["lanes", "r3-s", "tsa-request-binding"])
        .canonicalize()
        .unwrap()
}

fn identity(label: &str) {
    static IMAGE: OnceLock<(PathBuf, String, usize)> = OnceLock::new();
    let (path, digest, length) = IMAGE.get_or_init(|| {
        let path = std::env::current_exe().unwrap().canonicalize().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        (path, sha256(&bytes), bytes.len())
    });
    emit(
        "TSA_TEST_IDENTITY",
        json!({
            "label":label, "self_exe":path, "self_sha256":digest, "self_length":length,
            "cwd":std::env::current_dir().unwrap(),
            "hostname":std::fs::read_to_string("/etc/hostname").ok().map(|s|s.trim().to_owned()),
            "unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "HANKO_TESTDATA":std::env::var("HANKO_TESTDATA").ok(),
            "HANKO_ORACLE":std::env::var("HANKO_ORACLE").ok(),
            "CARGO_MANIFEST_DIR":std::env::var("CARGO_MANIFEST_DIR").ok(),
        }),
    );
}

fn opened(path: &Path) -> Vec<u8> {
    let path = path.canonicalize().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    emit(
        "TSA_OPENED_INPUT",
        json!({"path":path,"sha256":sha256(&bytes),"length":bytes.len()}),
    );
    bytes
}

fn asset(root: &Path, metadata: &Value) -> Vec<u8> {
    let path = Path::new(metadata["path"].as_str().unwrap());
    assert!(path.is_relative(), "fixture metadata uses relative paths");
    let bytes = opened(&root.join(path));
    assert_eq!(sha256(&bytes), metadata["sha256"].as_str().unwrap());
    assert_eq!(bytes.len() as u64, metadata["length"].as_u64().unwrap());
    bytes
}

struct Fixture {
    name: String,
    request: Vec<u8>,
    signer_input: Vec<u8>,
    response: Vec<u8>,
    token: Vec<u8>,
    digest: DigestAlgorithm,
    expected_digest: Vec<u8>,
    root: Cert,
    tsa: Cert,
    crls: Vec<Vec<u8>>,
}

impl Fixture {
    fn load(name: &str) -> Self {
        identity(name);
        let root = fixture_root();
        let manifest: Value = serde_json::from_slice(&opened(&root.join("manifest.json"))).unwrap();
        assert_eq!(manifest["preimage_hex"].as_str().unwrap(), hex(PREIMAGE));
        assert_eq!(manifest["fixed_nonce_hex"].as_str().unwrap(), hex(&NONCE));
        assert_eq!(
            manifest["validation_time"].as_str().unwrap(),
            VALIDATION_TIME
        );
        assert_eq!(manifest["revocation_mode"].as_str().unwrap(), "require");
        let case = &manifest["cases"][name];
        let digest = if name == "matching-sha384" {
            DigestAlgorithm::Sha384
        } else {
            DigestAlgorithm::Sha256
        };
        let expected_digest = digest.digest(PREIMAGE);
        assert_eq!(
            case["request_algorithm_oid"].as_str().unwrap(),
            digest.oid().to_string()
        );
        assert_eq!(
            case["request_digest_hex"].as_str().unwrap(),
            hex(&expected_digest)
        );
        let out = Self {
            name: name.to_owned(),
            request: asset(&root, &case["request"]),
            signer_input: asset(&root, &case["signer_input"]),
            response: asset(&root, &case["response"]),
            token: asset(&root, &case["token"]),
            digest,
            expected_digest,
            root: Cert::from_der(&asset(&root, &manifest["trust_root"])).unwrap(),
            tsa: Cert::from_der(&asset(&root, &manifest["tsa_cert"])).unwrap(),
            crls: manifest["crls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| asset(&root, v))
                .collect(),
        };
        assert!(
            !out.crls.is_empty(),
            "required TSA revocation evidence is explicit"
        );
        let info = token_tst_info(&out.token).unwrap();
        assert_eq!(
            info.to_der().unwrap(),
            out.signer_input,
            "actual signed TSTInfo bytes"
        );
        let sd = sigis_cms::SignedData::from_content_info_der(&out.token).unwrap();
        assert_eq!(sd.econtent.as_deref(), Some(out.signer_input.as_slice()));
        assert_eq!(sd.signer_infos.len(), 1);
        let cms_digest = if name == "independent-cms-sha512" {
            DigestAlgorithm::Sha512
        } else {
            DigestAlgorithm::Sha256
        };
        assert_eq!(sd.signer_infos[0].digest_algorithm.oid, cms_digest.oid());
        assert_eq!(
            info.message_imprint.hash_algorithm.oid.to_string(),
            case["token_algorithm_oid"].as_str().unwrap()
        );
        assert_eq!(
            hex(info.message_imprint.hashed_message.as_bytes()),
            case["token_digest_hex"].as_str().unwrap()
        );
        assert_eq!(
            handle_tsp_response(&out.response, None).unwrap(),
            out.token,
            "raw parser retains its request-agnostic contract"
        );
        out.assert_declared_imprint_valid();
        out
    }

    fn nonce(&self) -> Option<&[u8]> {
        if self.name.starts_with("no-nonce-") {
            None
        } else {
            Some(&NONCE)
        }
    }

    fn context(&self, trusted: bool) -> ValidationContext {
        let mut builder = ValidationContext::builder()
            .moment(Moment::parse_rfc3339(VALIDATION_TIME).unwrap())
            .revocation_mode("require");
        if trusted {
            builder = builder.trust_root(self.root.clone());
        }
        for crl in &self.crls {
            builder = builder.crl(crl.clone());
        }
        let context = builder.build().unwrap();
        assert!(
            context.fetchers().is_empty(),
            "fixture cryptographic proof never fetches external data"
        );
        context
    }

    fn assert_declared_imprint_valid(&self) {
        let info = token_tst_info(&self.token).unwrap();
        let status = sigis_cms::validate_timestamp_token(
            &self.token,
            info.message_imprint.hashed_message.as_bytes(),
            &self.context(true),
        )
        .unwrap();
        assert!(status.signature.intact && status.signature.valid);
        assert!(
            status.trusted(),
            "{}: {:?}",
            self.name,
            status.signature.trust_problem
        );
        assert_eq!(status.signature.signing_cert.as_ref(), Some(&self.tsa));
        let path = status.signature.validation_path.as_ref().unwrap();
        assert_eq!(path.len(), 2, "direct root -> TSA fixture path");
        assert_eq!(path.leaf(), Some(&self.tsa));
        assert_eq!(
            status.timestamp,
            Moment::parse_rfc3339(VALIDATION_TIME).unwrap()
        );
        emit(
            "TSA_DECLARED_TOKEN_VALIDATION",
            json!({"case":self.name,"token_sha256":sha256(&self.token),"intact":status.signature.intact,"valid":status.signature.valid,"trusted":status.trusted(),"context_time":VALIDATION_TIME,"revocation_mode":"require","path_length":path.len(),"declared_algorithm_oid":info.message_imprint.hash_algorithm.oid.to_string(),"declared_imprint":hex(info.message_imprint.hashed_message.as_bytes())}),
        );
    }
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct Reply {
    status: u16,
    mime: Option<&'static str>,
    body: Vec<u8>,
    delay: Duration,
    close_without_reply: bool,
}

impl Reply {
    fn timestamp(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            mime: Some("application/timestamp-reply"),
            body,
            delay: Duration::ZERO,
            close_without_reply: false,
        }
    }
}

struct Server {
    address: SocketAddr,
    recorded: Arc<Mutex<Option<RecordedRequest>>>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Server {
    fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let recorded = Arc::new(Mutex::new(None));
        let capture = recorded.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            drop(listener);
            if stop.load(Ordering::SeqCst) {
                return;
            }
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut first = line.split_whitespace();
            let method = first.next().unwrap().to_owned();
            let path = first.next().unwrap().to_owned();
            assert_eq!(first.next(), Some("HTTP/1.1"));
            let mut headers = Vec::new();
            let mut length = None;
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.trim_end().split_once(':').unwrap();
                if name.eq_ignore_ascii_case("Content-Length") {
                    assert!(length.is_none());
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
                headers.push((name.to_owned(), value.trim().to_owned()));
            }
            let length = length.unwrap();
            assert!(length <= 65536, "bounded test request body");
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            *capture.lock().unwrap() = Some(RecordedRequest {
                method,
                path,
                headers,
                body,
            });
            if reply.close_without_reply {
                return;
            }
            thread::sleep(reply.delay);
            let mut headers = format!(
                "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
                reply.status,
                reply.body.len()
            );
            if let Some(mime) = reply.mime {
                headers.push_str(&format!("Content-Type: {mime}\r\n"));
            }
            headers.push_str("\r\n");
            if stream.write_all(headers.as_bytes()).is_ok() {
                let _ = stream.write_all(&reply.body);
            }
        });
        Self {
            address,
            recorded,
            stopped,
            worker: Some(worker),
        }
    }

    fn url(&self) -> String {
        format!("http://{}/tsa/request-binding", self.address)
    }

    fn captured(&self) -> RecordedRequest {
        self.recorded.lock().unwrap().as_ref().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

fn client(server: &Server, fixture: &Fixture) -> HttpTimeStamper {
    let nonce = fixture
        .nonce()
        .map_or(NonceMode::None, |n| NonceMode::Fixed(n.to_vec()));
    HttpTimeStamper::new(server.url())
        .with_nonce(nonce)
        .with_basic_auth("lane-s", "tsa-proof")
        .with_header("X-Request-Binding", "lane-s")
        .with_header("Content-Type", "must-be-replaced")
        .with_header("Accept", "must-be-replaced")
}

fn assert_request(server: &Server, fixture: &Fixture) {
    let received = server.captured();
    emit(
        "TSA_ACTUAL_HTTP_REQUEST",
        json!({"case":fixture.name,"url":server.url(),"method":received.method,"path":received.path,"headers":received.headers,"body_sha256":sha256(&received.body),"body_length":received.body.len(),"body_hex":hex(&received.body)}),
    );
    assert_eq!(received.method, "POST");
    assert_eq!(received.path, "/tsa/request-binding");
    assert_eq!(
        received.body, fixture.request,
        "actual outgoing DER equals independently generated fixed request"
    );
    for (name, value) in [
        ("Content-Type", "application/timestamp-query"),
        ("Accept", "application/timestamp-reply"),
        ("X-Request-Binding", "lane-s"),
        ("Authorization", "Basic bGFuZS1zOnRzYS1wcm9vZg=="),
    ] {
        let values: Vec<_> = received
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(values, vec![value], "{name}");
    }
    assert_eq!(
        received
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Host"))
            .unwrap()
            .1,
        server.address.to_string()
    );
    let request = TimeStampReq::from_der(&received.body).unwrap();
    assert_eq!(request.version, TspVersion::V1);
    assert!(request.cert_req);
    assert!(request.req_policy.is_none() && request.extensions.is_none());
    assert_eq!(
        request.message_imprint.hash_algorithm.oid,
        fixture.digest.oid()
    );
    assert_eq!(
        request.message_imprint.hashed_message.as_bytes(),
        fixture.expected_digest
    );
    assert_eq!(
        request.nonce.as_ref().map(|n| n.as_bytes()),
        fixture.nonce()
    );
}

fn bound_call(fixture: &Fixture) -> Result<Vec<u8>, TimestampRequestError> {
    let server = Server::start(Reply::timestamp(fixture.response.clone()));
    let result = client(&server, fixture).timestamp_token(&fixture.expected_digest, fixture.digest);
    assert_request(&server, fixture);
    emit(
        "TSA_BOUND_RESULT",
        json!({"case":fixture.name,"accepted":result.is_ok(),"error":result.as_ref().err().map(|e|&e.0),"returned_sha256":result.as_ref().ok().map(|b|sha256(b))}),
    );
    result
}

#[test]
fn signed_tsa_fixtures_have_genuine_cms_and_authorized_paths() {
    for name in CASES {
        let fixture = Fixture::load(name);
        if matches!(name, "algorithm-only" | "digest-only" | "both") {
            assert_eq!(
                handle_tsp_response(&fixture.response, Some(&NONCE)).unwrap(),
                fixture.token,
                "public raw handler has no requested imprint argument"
            );
        }
    }
    let algorithm = Fixture::load("algorithm-only");
    let status = sigis_cms::validate_timestamp_token(
        &algorithm.token,
        &algorithm.expected_digest,
        &algorithm.context(true),
    )
    .unwrap();
    assert!(
        status.signature.intact && status.signature.valid && status.trusted(),
        "precomputed CMS bytes contract remains unchanged"
    );
    let changed = Fixture::load("digest-only");
    let status = sigis_cms::validate_timestamp_token(
        &changed.token,
        &changed.expected_digest,
        &changed.context(true),
    )
    .unwrap();
    assert!(status.signature.valid && !status.signature.intact && !status.trusted());
}

#[test]
fn http_tsa_accepts_matching_imprints_parameters_and_independent_cms_digest() {
    for name in [
        "matching-sha256-null",
        "matching-sha256-absent",
        "matching-sha384",
        "independent-cms-sha512",
    ] {
        let fixture = Fixture::load(name);
        let info = token_tst_info(&fixture.token).unwrap();
        assert_eq!(
            info.message_imprint.hash_algorithm.oid,
            fixture.digest.oid()
        );
        assert_eq!(
            info.message_imprint.hashed_message.as_bytes(),
            fixture.expected_digest
        );
        if name == "matching-sha384" {
            assert_eq!(fixture.expected_digest.len(), 48);
        }
        if name == "matching-sha256-absent" {
            assert!(info.message_imprint.hash_algorithm.parameters.is_none());
        }
        if name == "matching-sha256-null" {
            assert!(info.message_imprint.hash_algorithm.parameters.is_some());
        }
        assert_eq!(
            bound_call(&fixture).unwrap(),
            fixture.token,
            "the original signed token is returned unchanged"
        );
    }
}

fn assert_imprint_refusal(name: &str, error: &str) {
    let fixture = Fixture::load(name);
    let info = token_tst_info(&fixture.token).unwrap();
    assert_eq!(fixture.expected_digest.len(), 32);
    assert_eq!(info.nonce.as_ref().unwrap().as_bytes(), NONCE);
    if name == "digest-only" {
        assert_eq!(
            info.message_imprint.hash_algorithm.oid,
            fixture.digest.oid()
        );
    } else {
        assert_eq!(
            info.message_imprint.hash_algorithm.oid,
            DigestAlgorithm::Sha384.oid()
        );
    }
    if name == "algorithm-only" {
        assert_eq!(
            info.message_imprint.hashed_message.as_bytes(),
            fixture.expected_digest
        );
    } else {
        assert_ne!(
            info.message_imprint.hashed_message.as_bytes(),
            fixture.expected_digest
        );
    }
    assert_eq!(
        bound_call(&fixture)
            .expect_err("request-mismatching signed response must reject")
            .0,
        error
    );
}

#[test]
fn http_tsa_rejects_algorithm_only_substitution() {
    assert_imprint_refusal("algorithm-only", ALGORITHM_ERROR);
}

#[test]
fn http_tsa_rejects_same_algorithm_wrong_digest_bytes() {
    assert_imprint_refusal("digest-only", DIGEST_ERROR);
}

#[test]
fn http_tsa_reports_algorithm_before_digest_when_both_differ() {
    assert_imprint_refusal("both", ALGORITHM_ERROR);
}

#[test]
fn http_tsa_keeps_nonce_refusal_before_imprint_binding() {
    for name in ["wrong-nonce", "missing-nonce"] {
        let fixture = Fixture::load(name);
        let info = token_tst_info(&fixture.token).unwrap();
        assert_eq!(
            info.message_imprint.hash_algorithm.oid,
            DigestAlgorithm::Sha384.oid()
        );
        assert_eq!(
            info.message_imprint.hashed_message.as_bytes(),
            fixture.expected_digest
        );
        let received = info.nonce.as_ref().map(|n| n.as_bytes());
        assert_ne!(received, Some(NONCE.as_slice()));
        let rendered = received.map_or_else(|| "None".to_owned(), |v| format!("0x{}", hex(v)));
        assert_eq!(bound_call(&fixture).unwrap_err().0,format!("Time stamping authority sent back bad nonce value. Expected {}, but got {rendered}.",hex(&NONCE)));
    }
}

fn assert_no_nonce_case(name: &str, error: Option<&str>) {
    let fixture = Fixture::load(name);
    assert!(fixture.nonce().is_none());
    assert!(TimeStampReq::from_der(&fixture.request)
        .unwrap()
        .nonce
        .is_none());
    let info = token_tst_info(&fixture.token).unwrap();
    assert!(
        info.nonce.is_none(),
        "standard no-nonce response remains nonce-free"
    );
    if name == "no-nonce-algorithm" {
        assert_eq!(
            info.message_imprint.hash_algorithm.oid,
            DigestAlgorithm::Sha384.oid()
        );
        assert_eq!(
            info.message_imprint.hashed_message.as_bytes(),
            fixture.expected_digest
        );
    } else {
        assert_eq!(
            info.message_imprint.hash_algorithm.oid,
            DigestAlgorithm::Sha256.oid()
        );
        if name == "no-nonce-digest" {
            assert_ne!(
                info.message_imprint.hashed_message.as_bytes(),
                fixture.expected_digest
            );
        } else {
            assert_eq!(
                info.message_imprint.hashed_message.as_bytes(),
                fixture.expected_digest
            );
        }
    }
    let result = bound_call(&fixture);
    if let Some(error) = error {
        assert_eq!(result.unwrap_err().0, error);
    } else {
        assert_eq!(result.unwrap(), fixture.token);
    }
}

#[test]
fn http_tsa_accepts_matching_imprint_without_a_nonce() {
    assert_no_nonce_case("no-nonce-valid", None);
}

#[test]
fn http_tsa_rejects_wrong_algorithm_without_a_nonce() {
    assert_no_nonce_case("no-nonce-algorithm", Some(ALGORITHM_ERROR));
}

#[test]
fn http_tsa_rejects_wrong_digest_without_a_nonce() {
    assert_no_nonce_case("no-nonce-digest", Some(DIGEST_ERROR));
}

#[test]
fn http_tsa_core_trait_maps_binding_refusals_to_bad_response() {
    let mut results = Vec::new();
    for (name, message) in [
        ("algorithm-only", ALGORITHM_ERROR),
        ("digest-only", DIGEST_ERROR),
    ] {
        let fixture = Fixture::load(name);
        let server = Server::start(Reply::timestamp(fixture.response.clone()));
        let result = TimeStamper::timestamp(
            &client(&server, &fixture),
            &fixture.expected_digest,
            fixture.digest,
        );
        assert_request(&server, &fixture);
        emit(
            "TSA_TRAIT_RESULT",
            json!({"case":name,"accepted":result.is_ok(),"error":result.as_ref().err().map(ToString::to_string)}),
        );
        results.push((name, message, result));
    }
    // Execute both network calls on the unchanged source before any refusal
    // assertion, so the first unexpected acceptance cannot hide the second.
    for (name, message, result) in results {
        let HankoError::Fetch(error) = result.expect_err(name) else {
            panic!("binding refusal must retain the Fetch error class");
        };
        assert_eq!(error.kind, FetchErrorKind::BadResponse);
        assert_eq!(error.message, message);
    }
}

#[test]
fn http_tsa_keeps_transport_status_and_malformed_response_precedence() {
    let fixture = Fixture::load("algorithm-only");
    let mut cases = Vec::new();
    for status in [400, 503] {
        cases.push((
            format!("http-{status}"),
            Reply {
                status,
                ..Reply::timestamp(fixture.response.clone())
            },
            COMMUNICATION_ERROR.to_owned(),
            false,
        ));
    }
    for mime in [None, Some("application/octet-stream")] {
        cases.push((
            format!("mime-{mime:?}"),
            Reply {
                mime,
                ..Reply::timestamp(fixture.response.clone())
            },
            COMMUNICATION_ERROR.to_owned(),
            false,
        ));
    }
    for status in [1, 2, 3] {
        let status = encode(0x30, &encode(0x02, &[status]));
        let body = encode(0x30, &[status, fixture.token.clone()].concat());
        cases.push((
            "tsp-refusal".to_owned(),
            Reply::timestamp(body),
            "Timestamp server refused our request: statusString \"\", failInfo \"\"".to_owned(),
            false,
        ));
    }
    for body in [
        b"not DER".to_vec(),
        encode(0x30, &encode(0x30, &encode(0x02, &[0]))),
        encode(
            0x30,
            &[encode(0x30, &encode(0x02, &[0])), encode(0x30, &[])].concat(),
        ),
    ] {
        cases.push((
            "malformed".to_owned(),
            Reply::timestamp(body),
            "Timestamp server response is malformed:".to_owned(),
            true,
        ));
    }
    cases.push((
        "closed-connection".to_owned(),
        Reply {
            close_without_reply: true,
            ..Reply::timestamp(Vec::new())
        },
        COMMUNICATION_ERROR.to_owned(),
        false,
    ));
    for (label, reply, expected, prefix) in cases {
        let server = Server::start(reply);
        let result =
            client(&server, &fixture).timestamp_token(&fixture.expected_digest, fixture.digest);
        assert_request(&server, &fixture);
        let error = result.unwrap_err();
        emit(
            "TSA_PRESERVED_ERROR",
            json!({"control":label,"error":error.0}),
        );
        if prefix {
            assert!(error.0.starts_with(&expected), "{}", error.0);
        } else {
            assert_eq!(error.0, expected);
        }
    }
    let slow = Server::start(Reply {
        delay: Duration::from_millis(1000),
        ..Reply::timestamp(fixture.response.clone())
    });
    let error = client(&slow, &fixture)
        .with_limits(FetchLimits {
            timeout: Duration::from_millis(500),
            ..Default::default()
        })
        .timestamp_token(&fixture.expected_digest, fixture.digest)
        .unwrap_err();
    assert_request(&slow, &fixture);
    assert_eq!(error.0, COMMUNICATION_ERROR);
    let large = Server::start(Reply::timestamp(vec![0x30; 4096]));
    let error = client(&large, &fixture)
        .with_limits(FetchLimits {
            max_response_bytes: 128,
            ..Default::default()
        })
        .timestamp_token(&fixture.expected_digest, fixture.digest)
        .unwrap_err();
    assert_request(&large, &fixture);
    assert_eq!(error.0, COMMUNICATION_ERROR);
}

#[test]
fn signed_tsa_token_still_requires_root_trust_and_a_valid_cms_signature() {
    let fixture = Fixture::load("matching-sha256-null");
    let untrusted = sigis_cms::validate_timestamp_token(
        &fixture.token,
        &fixture.expected_digest,
        &fixture.context(false),
    )
    .unwrap();
    assert!(untrusted.signature.intact && untrusted.signature.valid && !untrusted.trusted());
    assert!(
        untrusted.signature.trust_problem.is_some()
            || untrusted.signature.trust_problem_indic.is_some()
    );

    let ci = Tlv::parse_exact(&fixture.token)
        .unwrap()
        .children()
        .unwrap();
    let sd = Tlv::parse_exact(ci[1].value).unwrap().children().unwrap();
    let signer_set = sd.last().unwrap();
    assert!(signer_set.is_universal(tag::SET));
    let signers = signer_set.children().unwrap();
    assert_eq!(signers.len(), 1);
    let signer_fields = signers[0].children().unwrap();
    let signature = signer_fields
        .iter()
        .find(|field| field.is_universal(tag::OCTET_STRING))
        .unwrap();
    assert!(!signature.value.is_empty());
    let offset = signature.value.as_ptr() as usize - fixture.token.as_ptr() as usize;
    let mut changed = fixture.token.clone();
    changed[offset] ^= 1;
    assert_eq!(
        token_tst_info(&changed).unwrap().to_der().unwrap(),
        fixture.signer_input
    );
    let parsed = sigis_cms::SignedData::from_content_info_der(&changed).unwrap();
    assert_eq!(
        parsed.econtent.as_deref(),
        Some(fixture.signer_input.as_slice())
    );
    let invalid = sigis_cms::validate_timestamp_token(
        &changed,
        &fixture.expected_digest,
        &fixture.context(true),
    )
    .unwrap();
    assert!(
        !invalid.signature.valid && !invalid.trusted(),
        "a parsable token with only signature bytes changed cannot supply trust"
    );
    emit(
        "TSA_CRYPTO_NEGATIVE",
        json!({"original_sha256":sha256(&fixture.token),"changed_sha256":sha256(&changed),"empty_root_trusted":untrusted.trusted(),"changed_signature_valid":invalid.signature.valid,"changed_signature_trusted":invalid.trusted()}),
    );
}
