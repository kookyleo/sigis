//! Supplemental AC HTTP retrieval controls, not upstream-function credit.
//!
//! Retrieval-only ACs preserve an existing holder but replace retrieval metadata;
//! their signatures deliberately remain invalid. Unsigned OCSP envelopes exercise
//! request binding/nonce handling only. Actual validation is tested separately.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::Engine;
use der::asn1::{BitString, GeneralizedTime, OctetString};
use der::{Decode, Encode};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::oids;
use sigis_pki_core::asn1::tlv::{encode, Tlv};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::FetchErrorKind;
use sigis_pki_core::fetch::{CrlFetcher, OcspFetcher};
use sigis_pki_fetch::common::CertIdHash;
use sigis_pki_fetch::{FetchLimits, FetcherSettings, HttpFetchers};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_ocsp::{
    BasicOcspResponse, CertStatus, OcspGeneralizedTime, OcspResponse, ResponderId, ResponseData,
    SingleResponse,
};

type OcspRequest = x509_ocsp::OcspRequest<x509_cert::certificate::Rfc5280>;
type SerialNumber = x509_cert::serial_number::SerialNumber<x509_cert::certificate::Rfc5280>;

fn emit(marker: &str, value: serde_json::Value) {
    let line = format!("{marker} {value}\n");
    std::io::stderr().write_all(line.as_bytes()).unwrap();
}

#[derive(Clone, Debug)]
struct Received {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct Reply {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    delay: Duration,
}

impl Reply {
    fn ocsp(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            content_type: "application/ocsp-response",
            body,
            delay: Duration::ZERO,
        }
    }
}

struct Server {
    address: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Server {
    fn start(handler: impl Fn(&Received) -> Reply + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let recording = received.clone();
        let stop = stopped.clone();
        let worker = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let mut stream = stream.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or_default() == 0 {
                    continue;
                }
                let mut request = line.split_whitespace();
                let method = request.next().unwrap().to_owned();
                let path = request.next().unwrap().to_owned();
                let mut headers = Vec::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.trim_end().split_once(':').unwrap();
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                    headers.push((name.to_owned(), value.trim().to_owned()));
                }
                assert!(length <= 65536, "test server request bound");
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let request = Received {
                    method,
                    path,
                    headers,
                    body,
                };
                recording.lock().unwrap().push(request.clone());
                let reply = handler(&request);
                thread::sleep(reply.delay);
                let headers = format!(
                    "HTTP/1.1 {} Test\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.status, reply.content_type, reply.body.len()
                );
                if stream.write_all(headers.as_bytes()).is_ok() {
                    let _ = stream.write_all(&reply.body);
                }
            }
        });
        Self {
            address,
            received,
            stopped,
            worker: Some(worker),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    fn requests(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn fixture(parts: &[&str]) -> Vec<u8> {
    let path = sigis_testdata::certvalidator(parts).canonicalize().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let hash = DigestAlgorithm::Sha256.digest(&bytes);
    let hash: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!(
        "AC_FETCH_INPUT opened_path={} sha256={} length={}",
        path.display(),
        hash,
        bytes.len()
    );
    bytes
}

fn aa() -> Cert {
    Cert::from_pem_or_der(&fixture(&[
        "attribute-certs",
        "basic-aa",
        "interm",
        "role-aa.crt",
    ]))
    .unwrap()
}

fn template() -> Vec<u8> {
    fixture(&[
        "attribute-certs",
        "basic-aa",
        "aa",
        "alice-role-norev.attr.crt",
    ])
}

fn fields(bytes: &[u8]) -> Vec<Vec<u8>> {
    Tlv::parse_exact(bytes)
        .unwrap()
        .children()
        .unwrap()
        .iter()
        .map(|v| v.raw.to_vec())
        .collect()
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    encode(0x30, &parts.concat())
}

fn general_names(name: &Name) -> Vec<u8> {
    encode(0x30, &encode(0xa4, &name.to_der().unwrap()))
}

fn ext(oid: const_oid::ObjectIdentifier, value: Vec<u8>) -> Extension {
    Extension {
        extn_id: oid,
        critical: false,
        extn_value: OctetString::new(value).unwrap(),
    }
}

fn aia(urls: &[String]) -> Extension {
    let descriptions: Vec<Vec<u8>> = urls
        .iter()
        .map(|url| {
            sequence(&[
                oids::AD_OCSP.to_der().unwrap(),
                encode(0x86, url.as_bytes()),
            ])
        })
        .collect();
    ext(oids::PE_AUTHORITY_INFO_ACCESS, sequence(&descriptions))
}

fn crldp(urls: &[String], freshest: bool) -> Extension {
    let points: Vec<Vec<u8>> = urls
        .iter()
        .map(|url| {
            let full_name = encode(0xa0, &encode(0x86, url.as_bytes()));
            sequence(&[encode(0xa0, &full_name)])
        })
        .collect();
    ext(
        if freshest {
            oids::CE_FRESHEST_CRL
        } else {
            oids::CE_CRL_DISTRIBUTION_POINTS
        },
        sequence(&points),
    )
}

fn ac(serial_der: Vec<u8>, issuer: Vec<u8>, extensions: Vec<Extension>, version: u8) -> Vec<u8> {
    let mut outer = fields(&template());
    let mut info = fields(&outer[0]);
    info.truncate(7);
    info[0] = encode(0x02, &[version]);
    info[2] = issuer;
    info[4] = serial_der;
    if !extensions.is_empty() {
        info.push(extensions.to_der().unwrap());
    }
    outer[0] = sequence(&info);
    sequence(&outer)
}

fn ac_for(serial: &[u8], issuer: &Name, urls: &[String], version: u8) -> Vec<u8> {
    let names = general_names(issuer);
    let issuer = if version == 0 {
        names
    } else {
        encode(0xa0, &names)
    };
    ac(encode(0x02, serial), issuer, vec![aia(urls)], version)
}

fn pkc_at(cert: &Cert, extensions: Vec<Extension>) -> Cert {
    let mut outer = fields(cert.der());
    let mut tbs = fields(&outer[0]);
    tbs.retain(|field| !Tlv::parse_exact(field).unwrap().is_context(3));
    tbs.push(encode(0xa3, &extensions.to_der().unwrap()));
    outer[0] = sequence(&tbs);
    Cert::from_der(&sequence(&outer)).unwrap()
}

#[derive(Clone, Copy)]
enum ResponseChange {
    None,
    NoNonce,
    WrongNonce,
    WrongSerial,
    WrongNameHash,
    WrongKeyHash,
    WrongHashAlgorithm,
}

fn response(request: &Received, change: ResponseChange) -> Vec<u8> {
    let request = OcspRequest::from_der(&request.body).unwrap();
    let mut cert_id = request.tbs_request.request_list[0].req_cert.clone();
    let mut extensions = request.tbs_request.request_extensions.clone();
    match change {
        ResponseChange::None => {}
        ResponseChange::NoNonce => extensions = None,
        ResponseChange::WrongNonce => {
            extensions = Some(vec![ext(
                oids::OCSP_NONCE,
                OctetString::new([0xa5; 16]).unwrap().to_der().unwrap(),
            )])
        }
        ResponseChange::WrongSerial => cert_id.serial_number = SerialNumber::new(&[0x77]).unwrap(),
        ResponseChange::WrongNameHash => {
            cert_id.issuer_name_hash = OctetString::new([0u8; 20]).unwrap()
        }
        ResponseChange::WrongKeyHash => {
            cert_id.issuer_key_hash = OctetString::new([0u8; 20]).unwrap()
        }
        ResponseChange::WrongHashAlgorithm => cert_id.hash_algorithm.oid = oids::SHA256,
    }
    let time = OcspGeneralizedTime(GeneralizedTime::from_date_time(
        der::DateTime::new(2022, 5, 1, 0, 0, 0).unwrap(),
    ));
    let basic = BasicOcspResponse {
        tbs_response_data: ResponseData {
            version: Default::default(),
            responder_id: ResponderId::ByKey(OctetString::new([0x5a; 20]).unwrap()),
            produced_at: time,
            responses: vec![SingleResponse {
                cert_id,
                cert_status: CertStatus::good(),
                this_update: time,
                next_update: None,
                single_extensions: None,
            }],
            response_extensions: extensions,
        },
        signature_algorithm: spki::AlgorithmIdentifierOwned {
            oid: oids::SHA256_WITH_RSA,
            parameters: Some(der::asn1::Null.into()),
        },
        signature: BitString::from_bytes(&[1, 2, 3]).unwrap(),
        certs: None,
    };
    OcspResponse::successful(basic).unwrap().to_der().unwrap()
}

#[test]
fn ac_ocsp_uses_actual_authority_hashes_ac_serial_and_configured_nonce() {
    let issuer = aa();
    let ac_serial = [0x2a, 0x55];
    assert_ne!(issuer.serial_bytes(), ac_serial);
    for version in [0, 1] {
        for hash in [CertIdHash::Sha1, CertIdHash::Sha256] {
            let server =
                Server::start(|request| Reply::ocsp(response(request, ResponseChange::None)));
            let ac = ac_for(
                &ac_serial,
                issuer.subject(),
                &[server.url("/ac-ocsp")],
                version,
            );
            emit(
                "AC_FETCH_METADATA",
                serde_json::json!({
                    "ac_der_base64": base64::engine::general_purpose::STANDARD.encode(&ac),
                    "ac_sha256": DigestAlgorithm::Sha256.digest(&ac).iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "aa_der_base64": base64::engine::general_purpose::STANDARD.encode(issuer.der()),
                    "version": version,
                    "certid_hash": format!("{hash:?}"),
                }),
            );
            let ac_fields = fields(&fields(&ac)[0]);
            let holder = fields(&ac_fields[1]);
            assert!(!holder.is_empty(), "existing actual holder retained");
            let f = HttpFetchers::new(FetcherSettings {
                certid_hash: hash,
                ..Default::default()
            });
            let first = f.fetch_ac_ocsp(&ac, &issuer).unwrap();
            assert_eq!(f.fetch_ac_ocsp(&ac, &issuer).unwrap(), first);
            let requests = server.requests();
            assert_eq!(requests.len(), 1, "same AC/authority uses target cache");
            let got = &requests[0];
            assert_eq!(got.method, "POST");
            assert_eq!(got.path, "/ac-ocsp");
            assert!(got
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("content-type")
                    && v == "application/ocsp-request"));
            assert!(got
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("accept")
                    && v.contains("application/ocsp-response")));
            let request = OcspRequest::from_der(&got.body).unwrap();
            emit(
                "AC_FETCH_REQUEST",
                serde_json::json!({"ac_sha256":DigestAlgorithm::Sha256.digest(&ac).iter().map(|b|format!("{b:02x}")).collect::<String>(),"certid_der_base64":base64::engine::general_purpose::STANDARD.encode(request.tbs_request.request_list[0].req_cert.to_der().unwrap()),"request_der_base64":base64::engine::general_purpose::STANDARD.encode(&got.body)}),
            );
            assert_eq!(request.tbs_request.request_list.len(), 1);
            let id = &request.tbs_request.request_list[0].req_cert;
            let digest = if hash == CertIdHash::Sha1 {
                DigestAlgorithm::Sha1
            } else {
                DigestAlgorithm::Sha256
            };
            assert_eq!(id.hash_algorithm.oid, digest.oid());
            assert_eq!(id.serial_number.as_bytes(), ac_serial);
            assert_eq!(
                id.issuer_name_hash.as_bytes(),
                digest.digest(&issuer.subject_der().unwrap())
            );
            assert_eq!(
                id.issuer_key_hash.as_bytes(),
                digest.digest(issuer.public_key().subject_public_key.raw_bytes())
            );
            let exts = request.tbs_request.request_extensions.unwrap();
            let nonce = exts.iter().find(|e| e.extn_id == oids::OCSP_NONCE).unwrap();
            assert_eq!(
                OctetString::from_der(nonce.extn_value.as_bytes())
                    .unwrap()
                    .as_bytes()
                    .len(),
                16
            );
        }
    }
}

#[test]
fn ac_metadata_rejects_invalid_identity_serial_and_extensions_before_io() {
    let issuer = aa();
    let server = Server::start(|_| Reply {
        status: 503,
        ..Reply::ocsp(Vec::new())
    });
    let valid_extensions = vec![
        aia(&[server.url("/ocsp")]),
        crldp(&[server.url("/crl")], false),
    ];
    let valid_issuer = encode(0xa0, &general_names(issuer.subject()));
    let mut bad = Vec::new();
    for serial in [
        vec![],
        vec![0],
        vec![0x80],
        vec![0, 1],
        vec![0; 21],
        vec![1; 21],
        [vec![0], vec![0x80; 20]].concat(),
    ] {
        bad.push(ac(
            encode(0x02, &serial),
            valid_issuer.clone(),
            valid_extensions.clone(),
            1,
        ));
    }
    let issuer_serial = [
        general_names(issuer.issuer()),
        encode(0x02, issuer.serial_bytes()),
    ]
    .concat();
    let base_only = encode(0xa0, &encode(0xa0, &issuer_serial));
    bad.push(ac(
        encode(0x02, &[1]),
        base_only,
        valid_extensions.clone(),
        1,
    ));
    bad.push(ac(
        encode(0x02, &[1]),
        encode(
            0xa0,
            &encode(0x30, &encode(0x86, b"http://not-a-directory-name")),
        ),
        valid_extensions.clone(),
        1,
    ));
    bad.push(ac(
        encode(0x02, &[1]),
        valid_issuer.clone(),
        valid_extensions.clone(),
        2,
    ));
    let mut duplicate = valid_extensions.clone();
    duplicate.push(valid_extensions[0].clone());
    bad.push(ac(encode(0x02, &[1]), valid_issuer.clone(), duplicate, 1));
    for oid in [
        oids::PE_AUTHORITY_INFO_ACCESS,
        oids::CE_CRL_DISTRIBUTION_POINTS,
        oids::CE_FRESHEST_CRL,
    ] {
        bad.push(ac(
            encode(0x02, &[1]),
            valid_issuer.clone(),
            vec![ext(oid, vec![0x05, 0])],
            1,
        ));
    }
    bad.push(ac(
        encode(0x01, &[0xff]),
        valid_issuer.clone(),
        valid_extensions.clone(),
        1,
    ));
    let canonical = ac(encode(0x02, &[1]), valid_issuer, valid_extensions, 1);
    let mut trailing = canonical.clone();
    trailing.push(0);
    bad.push(trailing);
    bad.push(vec![0x30, 0]);

    // The generic TLV view intentionally accepts BER length/tag forms. AC
    // retrieval must reject nonminimal outer, acinfo and implicit v2 issuer
    // headers before either cache lookup or an actual HTTP request.
    fn padded_length(value: &[u8]) -> Vec<u8> {
        if value[1] < 0x80 {
            [vec![value[0], 0x81], value[1..].to_vec()].concat()
        } else {
            [vec![value[0], value[1] + 1, 0], value[2..].to_vec()].concat()
        }
    }
    fn long_tag(value: &[u8]) -> Vec<u8> {
        [
            vec![(value[0] & 0xe0) | 0x1f, value[0] & 0x1f],
            value[1..].to_vec(),
        ]
        .concat()
    }
    for mutate in [padded_length, long_tag] {
        bad.push(mutate(&canonical));
        let mut outer = fields(&canonical);
        outer[0] = mutate(&outer[0]);
        bad.push(sequence(&outer));
        let mut outer = fields(&canonical);
        let mut info = fields(&outer[0]);
        info[2] = mutate(&info[2]);
        outer[0] = sequence(&info);
        bad.push(sequence(&outer));
    }

    let envelope_variants = bad[17..].to_vec();
    assert_eq!(envelope_variants.len(), 6);
    let expected = vec![
        (
            Some(FetchErrorKind::BadResponse),
            Some(FetchErrorKind::BadResponse),
        );
        bad.len()
    ];
    let mut observed = Vec::new();
    for (index, malformed) in bad.into_iter().enumerate() {
        emit(
            "AC_FETCH_INVALID",
            serde_json::json!({"index":index,"ac_der_base64":base64::engine::general_purpose::STANDARD.encode(&malformed),"ac_sha256":DigestAlgorithm::Sha256.digest(&malformed).iter().map(|b|format!("{b:02x}")).collect::<String>()}),
        );
        let f = HttpFetchers::default();
        observed.push((
            f.fetch_ac_ocsp(&malformed, &issuer).err().map(|e| e.kind),
            f.fetch_ac_crls(&malformed).err().map(|e| e.kind),
        ));
    }
    assert_eq!(observed, expected);
    assert!(server.requests().is_empty());

    // A cached canonical failure is not an excuse to accept an invalid input
    // alias. Only these two well-formed requests may reach the server.
    let warm = HttpFetchers::default();
    assert_eq!(
        warm.fetch_ac_ocsp(&canonical, &issuer).unwrap_err().kind,
        FetchErrorKind::Network
    );
    assert_eq!(
        warm.fetch_ac_crls(&canonical).unwrap_err().kind,
        FetchErrorKind::Network
    );
    assert_eq!(server.requests().len(), 2);
    for malformed in envelope_variants {
        assert_eq!(
            warm.fetch_ac_ocsp(&malformed, &issuer).unwrap_err().kind,
            FetchErrorKind::BadResponse
        );
        assert_eq!(
            warm.fetch_ac_crls(&malformed).unwrap_err().kind,
            FetchErrorKind::BadResponse
        );
    }
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn ac_serial_boundaries_preserve_sign_padding_without_truncation() {
    // Raw affects decoding policy; its constructor still enforces the same
    // encoded INTEGER content bound. It cannot silently widen this producer.
    for magnitude in [vec![0x80; 19], vec![1; 20]] {
        let raw =
            x509_cert::serial_number::SerialNumber::<x509_cert::certificate::Raw>::new(&magnitude)
                .unwrap();
        let standard = SerialNumber::new(&magnitude).unwrap();
        assert_eq!(raw.to_der().unwrap(), standard.to_der().unwrap());
        let mut content = magnitude.clone();
        if magnitude[0] & 0x80 != 0 {
            content.insert(0, 0);
        }
        assert_eq!(content.len(), 20);
        assert_eq!(raw.to_der().unwrap(), encode(0x02, &content));
    }
    for magnitude in [vec![0x80; 20], vec![1; 21]] {
        assert!(
            x509_cert::serial_number::SerialNumber::<x509_cert::certificate::Raw>::new(&magnitude)
                .is_err()
        );
        assert!(SerialNumber::new(&magnitude).is_err());
    }
    let issuer = aa();
    let server = Server::start(|r| Reply::ocsp(response(r, ResponseChange::None)));
    let mut serials = vec![vec![1; 19], vec![1; 20], [vec![0], vec![0x80; 19]].concat()];
    for serial in serials.drain(..) {
        let ac = ac_for(&serial, issuer.subject(), &[server.url("/ocsp")], 1);
        let f = HttpFetchers::default();
        f.fetch_ac_ocsp(&ac, &issuer).unwrap();
        let requests = server.requests();
        let request = OcspRequest::from_der(&requests.last().unwrap().body).unwrap();
        assert_eq!(
            request.tbs_request.request_list[0]
                .req_cert
                .serial_number
                .to_der()
                .unwrap(),
            encode(0x02, &serial),
            "canonical positive INTEGER including any required sign padding is preserved exactly"
        );
    }
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn ac_ocsp_target_cache_is_namespaced_from_pkc_and_actual_authority() {
    let issuer = aa();
    let server = Server::start(|r| Reply::ocsp(response(r, ResponseChange::None)));
    let original = Cert::from_pem_or_der(&fixture(&["testing-aia", "with-ldap-urls.der"])).unwrap();
    let pkc = pkc_at(&original, vec![aia(&[server.url("/same")])]);
    let serial = SerialNumber::new(pkc.serial_bytes())
        .unwrap()
        .to_der()
        .unwrap();
    let ac = ac(
        serial,
        encode(0xa0, &general_names(pkc.issuer())),
        vec![aia(&[server.url("/same")])],
        1,
    );
    let f = HttpFetchers::new(FetcherSettings {
        request_nonces: false,
        ..Default::default()
    });
    f.fetch_ocsp(&pkc, &issuer).unwrap();
    f.fetch_ac_ocsp(&ac, &issuer).unwrap();
    f.fetch_ac_ocsp(&ac, &issuer).unwrap();
    assert_eq!(
        server.requests().len(),
        2,
        "same issuer/serial PKC and AC cannot share a target result"
    );
    let other =
        Cert::from_pem_or_der(&fixture(&["testing-ca-ed25519", "interm.cert.pem"])).unwrap();
    assert_ne!(issuer.public_key(), other.public_key());
    f.fetch_ac_ocsp(&ac, &other).unwrap();
    assert_eq!(
        server.requests().len(),
        3,
        "actual authority identity changes issuer hashes/cache key"
    );
}

#[test]
fn ac_ocsp_rejects_wrong_certid_or_nonce_and_caches_errors() {
    let issuer = aa();
    for change in [
        ResponseChange::WrongNonce,
        ResponseChange::WrongSerial,
        ResponseChange::WrongNameHash,
        ResponseChange::WrongKeyHash,
        ResponseChange::WrongHashAlgorithm,
    ] {
        let server = Server::start(move |r| Reply::ocsp(response(r, change)));
        let ac = ac_for(&[0x2a, 0x55], issuer.subject(), &[server.url("/ocsp")], 1);
        let f = HttpFetchers::default();
        for _ in 0..2 {
            assert_eq!(
                f.fetch_ac_ocsp(&ac, &issuer).unwrap_err().kind,
                FetchErrorKind::BadResponse
            );
        }
        assert_eq!(
            server.requests().len(),
            1,
            "failed target jobs remain cached"
        );
    }
    let server = Server::start(|r| Reply::ocsp(response(r, ResponseChange::NoNonce)));
    let ac = ac_for(&[0x2a, 0x55], issuer.subject(), &[server.url("/ocsp")], 1);
    assert!(
        HttpFetchers::default().fetch_ac_ocsp(&ac, &issuer).is_ok(),
        "missing response nonce follows upstream acceptance; it grants no trust"
    );
}

#[test]
fn ac_ocsp_preserves_url_order_fallback_and_disabled_nonce() {
    let issuer = aa();
    let server = Server::start(|r| {
        if r.path == "/bad" {
            Reply {
                status: 503,
                ..Reply::ocsp(Vec::new())
            }
        } else {
            Reply::ocsp(response(r, ResponseChange::None))
        }
    });
    let ac = ac_for(
        &[0x2a, 0x55],
        issuer.subject(),
        &[
            "ldap://ignored".into(),
            server.url("/bad"),
            server.url("/good"),
        ],
        1,
    );
    let f = HttpFetchers::new(FetcherSettings {
        request_nonces: false,
        ..Default::default()
    });
    f.fetch_ac_ocsp(&ac, &issuer).unwrap();
    let requests = server.requests();
    assert_eq!(
        requests.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        vec!["/bad", "/good"]
    );
    for r in requests {
        assert!(OcspRequest::from_der(&r.body)
            .unwrap()
            .tbs_request
            .request_extensions
            .is_none());
    }
}

#[test]
fn ac_crls_share_url_bytes_but_do_not_share_pkc_target_entries() {
    let first = fixture(&["nist_pkits", "crls", "GoodCACRL.crl"]);
    let second = fixture(&["nist_pkits", "crls", "NoPoliciesCACRL.crl"]);
    assert_ne!(first, second);
    let first_response = first.clone();
    let second_response = second.clone();
    let server = Server::start(move |r| Reply {
        status: 200,
        content_type: "application/pkix-crl",
        body: if r.path == "/pkc" {
            first_response.clone()
        } else {
            second_response.clone()
        },
        delay: Duration::ZERO,
    });
    let original = Cert::from_pem_or_der(&fixture(&["testing-aia", "with-ldap-urls.der"])).unwrap();
    let pkc = pkc_at(&original, vec![crldp(&[server.url("/pkc")], false)]);
    let serial = SerialNumber::new(pkc.serial_bytes())
        .unwrap()
        .to_der()
        .unwrap();
    let ac = ac(
        serial,
        encode(0xa0, &general_names(pkc.issuer())),
        vec![
            crldp(&[server.url("/ac")], false),
            crldp(&[server.url("/ac")], true),
        ],
        1,
    );
    let f = HttpFetchers::default();
    assert_eq!(f.fetch_crls(&pkc).unwrap(), vec![first]);
    assert_eq!(f.fetch_ac_crls(&ac).unwrap(), vec![second.clone()]);
    assert_eq!(f.fetch_ac_crls(&ac).unwrap(), vec![second.clone()]);
    let mut outer = fields(&ac);
    let mut info = fields(&outer[0]);
    info[4] = encode(0x02, &[0x2a, 0x56]);
    outer[0] = sequence(&info);
    assert_eq!(f.fetch_ac_crls(&sequence(&outer)).unwrap(), vec![second]);
    assert_eq!(
        server.requests().len(),
        2,
        "freshest/second target may reuse raw CRL URL bytes only"
    );
    assert!(server.requests().iter().all(|r| r.method == "GET"));
}

#[test]
fn ac_fetching_shares_body_time_and_total_request_limits() {
    let issuer = aa();
    let server = Server::start(|r| Reply::ocsp(response(r, ResponseChange::None)));
    let ac = ac_for(&[0x2a, 0x55], issuer.subject(), &[server.url("/ocsp")], 1);
    let f = HttpFetchers::new(FetcherSettings {
        limits: FetchLimits {
            max_requests: Some(1),
            ..Default::default()
        },
        ..Default::default()
    });
    f.fetch_ac_ocsp(&ac, &issuer).unwrap();
    let err = f.fetch_crl_url(&server.url("/unused")).unwrap_err();
    assert_eq!(err.kind, FetchErrorKind::Disabled);
    assert_eq!(server.requests().len(), 1);

    let big = Server::start(|_| Reply::ocsp(vec![0x30; 1024]));
    let ac = ac_for(&[0x2a, 0x55], issuer.subject(), &[big.url("/ocsp")], 1);
    let f = HttpFetchers::new(FetcherSettings {
        limits: FetchLimits {
            max_response_bytes: 128,
            ..Default::default()
        },
        ..Default::default()
    });
    assert_eq!(
        f.fetch_ac_ocsp(&ac, &issuer).unwrap_err().kind,
        FetchErrorKind::TooLarge
    );

    let slow = Server::start(|_| Reply {
        delay: Duration::from_millis(150),
        ..Reply::ocsp(Vec::new())
    });
    let ac = ac_for(&[0x2a, 0x55], issuer.subject(), &[slow.url("/ocsp")], 1);
    let f = HttpFetchers::new(FetcherSettings {
        limits: FetchLimits {
            timeout: Duration::from_millis(30),
            ..Default::default()
        },
        ..Default::default()
    });
    assert_eq!(
        f.fetch_ac_ocsp(&ac, &issuer).unwrap_err().kind,
        FetchErrorKind::Timeout
    );
}

#[test]
fn ac_absent_or_unsupported_locations_are_not_malformed_or_network_requests() {
    let issuer = aa();
    let f = HttpFetchers::default();
    for extensions in [
        Vec::new(),
        vec![
            aia(&["ldap://ignored".into()]),
            crldp(&["ldap://ignored".into()], false),
        ],
    ] {
        let ac = ac(
            encode(0x02, &[0x2a, 0x55]),
            encode(0xa0, &general_names(issuer.subject())),
            extensions,
            1,
        );
        assert_eq!(
            f.fetch_ac_ocsp(&ac, &issuer).unwrap_err().kind,
            FetchErrorKind::NotFound
        );
        assert!(f.fetch_ac_crls(&ac).unwrap().is_empty());
    }
    assert!(!f.budget().exhaustion_reported());
}

// Preserve the signed fixture URLs and bytes. Only the HTTP transport's socket
// destination is proxied to an ephemeral loopback server, avoiding global port9000.
#[derive(Debug)]
struct LoopbackProxy {
    base: String,
    delegate: sigis_pki_fetch::transport::ReqwestTransport,
}

impl sigis_pki_fetch::transport::HttpTransport for LoopbackProxy {
    fn send(
        &self,
        request: &sigis_pki_fetch::transport::HttpRequest<'_>,
    ) -> Result<sigis_pki_fetch::transport::HttpResponse, sigis_pki_fetch::transport::TransportError>
    {
        let path = request
            .url
            .strip_prefix("http://localhost:9000")
            .expect("signed fixture origin");
        let actual_url = format!("{}{path}", self.base);
        let forwarded = sigis_pki_fetch::transport::HttpRequest {
            method: request.method,
            url: &actual_url,
            headers: request.headers.clone(),
            body: request.body,
        };
        self.delegate.send(&forwarded)
    }
}

fn basic(parts: &[&str]) -> Vec<u8> {
    let mut all = vec!["attribute-certs", "basic-aa"];
    all.extend_from_slice(parts);
    fixture(&all)
}

fn lane(name: &str) -> Vec<u8> {
    let path = sigis_testdata::path(&["lanes", "r3-s", "ac-fetch", name])
        .canonicalize()
        .unwrap();
    let data = std::fs::read(&path).unwrap();
    eprintln!(
        "AC_FETCH_INPUT opened_path={} sha256={} length={}",
        path.display(),
        DigestAlgorithm::Sha256
            .digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        data.len()
    );
    data
}

fn basic_cert(parts: &[&str]) -> Cert {
    Cert::from_pem_or_der(&basic(parts)).unwrap()
}

fn http_fetchers(server: &Server) -> HttpFetchers {
    let settings = FetcherSettings::default();
    let proxy = LoopbackProxy {
        base: format!("http://{}", server.address),
        delegate: sigis_pki_fetch::transport::ReqwestTransport::new(
            settings.limits.timeout,
            settings.limits.max_response_bytes,
        )
        .unwrap(),
    };
    HttpFetchers::with_transport(Arc::new(proxy), settings)
}

fn http_context_builder(
    fetchers: &HttpFetchers,
    at: &str,
    trusted: bool,
) -> sigis_pki_certvalidator::context::ValidationContextBuilder {
    let mut builder = sigis_pki_certvalidator::ValidationContext::builder()
        .moment(sigis_pki_core::time::Moment::parse_rfc3339(at).unwrap())
        .revocation_mode("require")
        .other_cert(basic_cert(&["root", "interm-role.crt"]))
        .other_cert(aa())
        .fetchers(fetchers.as_fetchers());
    if trusted {
        builder = builder.trust_root(basic_cert(&["root", "root.crt"]));
    }
    // AA-path PKC CRLs are supplied; NO AC OCSP or AC CRL is supplied.
    let crl = if at.starts_with("2021") {
        "some-revoked"
    } else {
        "all-good"
    };
    builder = builder
        .crl(basic(&["root", &format!("root-{crl}.crl")]))
        .crl(basic(&["interm", &format!("interm-{crl}.crl")]));
    builder
}

fn http_context(
    fetchers: &HttpFetchers,
    at: &str,
    trusted: bool,
) -> sigis_pki_certvalidator::ValidationContext {
    http_context_builder(fetchers, at, trusted).build().unwrap()
}

fn evidence_server(kind: &str, evidence: Vec<u8>) -> Server {
    let kind = kind.to_owned();
    Server::start(move |request| {
        let selected = (kind == "ocsp"
            && request.method == "POST"
            && request.path == "/basic-aa/ocsp/role-aa")
            || (kind == "crl"
                && request.method == "GET"
                && request.path == "/basic-aa/crls/role-aa/latest.crl");
        if selected {
            Reply {
                status: 200,
                content_type: if kind == "ocsp" {
                    "application/ocsp-response"
                } else {
                    "application/pkix-crl"
                },
                body: evidence.clone(),
                delay: Duration::ZERO,
            }
        } else {
            Reply {
                status: 404,
                content_type: "text/plain",
                body: Vec::new(),
                delay: Duration::ZERO,
            }
        }
    })
}

fn report_validation(
    case: &str,
    result: &Result<
        sigis_pki_certvalidator::ac::AcValidationResult,
        sigis_pki_certvalidator::ac::AcError,
    >,
    server: &Server,
    ac: &[u8],
) {
    let requests: Vec<_> = server
        .requests()
        .iter()
        .map(|r| {
            let mut record = serde_json::json!({"method":r.method,"path":r.path});
            if r.method == "POST" {
                let request = OcspRequest::from_der(&r.body).unwrap();
                let id = &request.tbs_request.request_list[0].req_cert;
                record["serial_der_base64"] =
                    serde_json::json!(base64::engine::general_purpose::STANDARD
                        .encode(id.serial_number.to_der().unwrap()));
                record["certid_der_base64"] = serde_json::json!(
                    base64::engine::general_purpose::STANDARD.encode(id.to_der().unwrap())
                );
            }
            record
        })
        .collect();
    let (accepted, class, message) = match result {
        Ok(_) => (true, None, None),
        Err(e) => (false, Some(e.class_name()), Some(e.to_string())),
    };
    emit(
        "AC_HTTP_VALIDATION",
        serde_json::json!({"case":case,"ac_sha256":DigestAlgorithm::Sha256.digest(ac).iter().map(|b|format!("{b:02x}")).collect::<String>(),"accepted":accepted,"error_class":class,"message":message,"http_requests":requests,"AC_evidence_injected":false}),
    );
}

fn assert_valid_role(result: &sigis_pki_certvalidator::ac::AcValidationResult, ac: &[u8]) {
    assert_eq!(result.attr_cert, ac);
    assert_eq!(result.aa_cert, aa());
    let expected = sigis_pki_certvalidator::ValidationPath::new(
        sigis_pki_certvalidator::TrustAnchor::new(basic_cert(&["root", "root.crt"])),
        vec![basic_cert(&["root", "interm-role.crt"])],
        Some(aa()),
    );
    assert_eq!(result.aa_path, expected);
    assert_eq!(result.approved_attributes.len(), 1);
    let attr = Tlv::parse_exact(result.approved_attributes.get("role").unwrap()).unwrap();
    let fields = attr.children().unwrap();
    let values = fields[1].children().unwrap();
    assert_eq!(values.len(), 1);
    let role = values[0].children().unwrap();
    let name = role.iter().find(|v| v.is_context(1)).unwrap();
    let uri = Tlv::parse_exact(name.value).unwrap();
    assert!(
        uri.is_context(1),
        "roleName is the exact rfc822Name from the signed fixture"
    );
    assert_eq!(uri.value, b"bigboss@example.com");
}

#[test]
fn real_validate_ac_http_ocsp_enforces_status_signature_and_target_freshness() {
    let cases = [
        (
            "ocsp-good",
            basic(&["alice-all-good.ors"]),
            "2019-12-12T00:00:00Z",
            None,
        ),
        (
            "ocsp-revoked",
            basic(&["alice-revoked.ors"]),
            "2021-12-12T00:00:00Z",
            Some("RevokedError"),
        ),
        (
            "ocsp-unknown",
            lane("unknown-signed.ors"),
            "2019-12-12T00:00:00Z",
            Some("InsufficientRevinfoError"),
        ),
        (
            "ocsp-bad-signature",
            lane("bad-signature.ors"),
            "2019-12-12T00:00:00Z",
            Some("InsufficientRevinfoError"),
        ),
        (
            "ocsp-stale-target",
            basic(&["alice-all-good.ors"]),
            "2019-12-12T01:00:00Z",
            Some("StaleRevinfoError"),
        ),
        (
            "ocsp-missing",
            Vec::new(),
            "2019-12-12T00:00:00Z",
            Some("InsufficientRevinfoError"),
        ),
    ];
    for (name, evidence, at, expected) in cases {
        let server = evidence_server(
            if name == "ocsp-missing" {
                "missing"
            } else {
                "ocsp"
            },
            evidence,
        );
        let f = http_fetchers(&server);
        let context = http_context(&f, at, true);
        let ac = basic(&["aa", "alice-role-with-rev.attr.crt"]);
        let holder = basic_cert(&["people-ca", "alice.crt"]);
        let result = sigis_pki_certvalidator::ac::validate_ac(&context, &ac, Some(&holder));
        report_validation(name, &result, &server, &ac);
        if let Some(class) = expected {
            assert_eq!(result.unwrap_err().class_name(), class, "{name}");
        } else {
            assert_valid_role(&result.unwrap(), &ac);
        }
        let requests = server.requests();
        let requests: Vec<_> = requests.iter().filter(|r| r.method == "POST").collect();
        assert_eq!(requests.len(), 1, "{name}: actual HTTP AC request required");
        assert_eq!(requests[0].path, "/basic-aa/ocsp/role-aa");
        let request = OcspRequest::from_der(&requests[0].body).unwrap();
        let id = &request.tbs_request.request_list[0].req_cert;
        assert_eq!(id.serial_number.as_bytes(), &[0x10, 0]);
        assert_eq!(
            id.issuer_name_hash.as_bytes(),
            DigestAlgorithm::Sha1.digest(&aa().subject_der().unwrap())
        );
        assert_eq!(
            id.issuer_key_hash.as_bytes(),
            DigestAlgorithm::Sha1.digest(aa().public_key().subject_public_key.raw_bytes())
        );
    }
}

#[test]
fn real_validate_ac_http_crls_keep_scope_and_revocation_mandatory() {
    for (name, evidence, at, expected) in [
        (
            "crl-good",
            basic(&["role-aa-all-good.crl"]),
            "2019-12-12T00:00:00Z",
            None,
        ),
        (
            "crl-revoked",
            basic(&["role-aa-some-revoked.crl"]),
            "2021-12-12T00:00:00Z",
            Some("RevokedError"),
        ),
        (
            "crl-unrelated",
            basic(&["root", "root-all-good.crl"]),
            "2019-12-12T00:00:00Z",
            Some("InsufficientRevinfoError"),
        ),
        (
            "crl-pkc-only",
            lane("valid-aa-pkc-only.crl"),
            "2019-12-12T00:00:00Z",
            Some("InsufficientRevinfoError"),
        ),
    ] {
        let server = evidence_server("crl", evidence);
        let f = http_fetchers(&server);
        let context = http_context(&f, at, true);
        let ac = basic(&["aa", "alice-role-with-rev.attr.crt"]);
        let result = sigis_pki_certvalidator::ac::validate_ac(
            &context,
            &ac,
            Some(&basic_cert(&["people-ca", "alice.crt"])),
        );
        report_validation(name, &result, &server, &ac);
        if let Some(class) = expected {
            assert_eq!(result.unwrap_err().class_name(), class, "{name}");
        } else {
            assert_valid_role(&result.unwrap(), &ac);
        }
        assert!(
            server
                .requests()
                .iter()
                .any(|r| r.method == "GET" && r.path == "/basic-aa/crls/role-aa/latest.crl"),
            "{name}: actual AC CRL HTTP fetch required"
        );
    }
}

#[test]
fn real_validate_ac_http_crl_signature_and_cache_policy_controls() {
    let good = basic(&["role-aa-all-good.crl"]);
    let parsed = Tlv::parse_exact(&good).unwrap();
    let good_fields = parsed.children().unwrap();
    assert_eq!(good_fields.len(), 3);
    assert_eq!(good_fields[2].value[0], 0);
    let offset = good.len() - good_fields[2].value.len() + 1;
    let mut bad = good.clone();
    bad[offset] ^= 1;
    let bad_fields = fields(&bad);
    assert_eq!(good_fields[0].raw, bad_fields[0]);
    assert_eq!(good_fields[1].raw, bad_fields[1]);
    assert_ne!(good_fields[2].raw, bad_fields[2]);
    let aa = aa();
    for (label, bytes, valid) in [("good", &good, true), ("forged", &bad, false)] {
        let parts = fields(bytes);
        let algorithm = spki::AlgorithmIdentifierOwned::from_der(&parts[1]).unwrap();
        let signature = BitString::from_der(&parts[2]).unwrap();
        assert_eq!(
            sigis_pki_core::algorithms::validate_signature(
                signature.raw_bytes(),
                &parts[0],
                &aa.public_key(),
                &algorithm,
                &sigis_pki_core::algorithms::SignatureValidationContext::default(),
            )
            .is_ok(),
            valid
        );
        emit(
            "AC_FETCH_CRL_SIGNATURE",
            serde_json::json!({
                "label":label,
                "crl_der_base64":base64::engine::general_purpose::STANDARD.encode(bytes),
                "aa_der_base64":base64::engine::general_purpose::STANDARD.encode(aa.der()),
                "signature_valid":valid,
            }),
        );
    }
    let ac = basic(&["aa", "alice-role-with-rev.attr.crt"]);
    let holder = basic_cert(&["people-ca", "alice.crt"]);
    let mut outcomes = Vec::new();
    for mode in ["require", "hard-fail", "soft-fail"] {
        for (label, evidence) in [("good", &good), ("forged", &bad)] {
            // Pinned Python tolerates the failed OCSP fetch in soft-fail mode,
            // even when the separate CRL signature is invalid. Mandatory modes
            // must reject; cached bytes never relax those requirements.
            let allowed = label == "good" || mode == "soft-fail";
            let server = evidence_server("crl", evidence.clone());
            let fetchers = http_fetchers(&server);
            let context = http_context_builder(&fetchers, "2019-12-12T00:00:00Z", true)
                .revocation_mode(mode)
                .build()
                .unwrap();
            let case = format!("fetched-crl-signature-{label}-{mode}");
            for attempt in 0..2 {
                let result = sigis_pki_certvalidator::ac::validate_ac(&context, &ac, Some(&holder));
                report_validation(&case, &result, &server, &ac);
                if allowed {
                    assert_valid_role(result.as_ref().unwrap(), &ac);
                }
                if let Err(error) = &result {
                    assert!(
                        error
                            .to_string()
                            .contains("CRL signature could not be verified"),
                        "{case}: {error}"
                    );
                }
                outcomes.push((case.clone(), attempt, result.is_ok(), allowed));
            }
            let requests = server.requests();
            assert_eq!(
                requests
                    .iter()
                    .filter(|r| r.method == "GET"
                        && r.path == "/basic-aa/crls/role-aa/latest.crl")
                    .count(),
                1,
                "{case}: both full validations consume actual fetched bytes, then the shared URL cache"
            );
        }
    }
    assert!(
        outcomes
            .iter()
            .all(|(_, _, accepted, expected)| accepted == expected),
        "{outcomes:?}"
    );
}

#[test]
fn real_validate_ac_http_does_not_replace_holder_target_or_anchor_constraints() {
    for (name, trusted, holder_name, ac_name, expected) in [
        (
            "ocsp-untrusted-aa",
            false,
            "alice.crt",
            "alice-role-with-rev.attr.crt",
            "PathBuildingError",
        ),
        (
            "ocsp-holder-mismatch",
            true,
            "bob.crt",
            "alice-role-with-rev.attr.crt",
            "InvalidAttrCertificateError",
        ),
        (
            "ocsp-target-restriction",
            true,
            "alice.crt",
            "alice-norev-targeted.attr.crt",
            "InvalidAttrCertificateError",
        ),
    ] {
        let server = evidence_server("ocsp", basic(&["alice-all-good.ors"]));
        let f = http_fetchers(&server);
        let context = http_context(&f, "2019-12-12T00:00:00Z", trusted);
        let ac = basic(&["aa", ac_name]);
        let result = sigis_pki_certvalidator::ac::validate_ac(
            &context,
            &ac,
            Some(&basic_cert(&["people-ca", holder_name])),
        );
        report_validation(name, &result, &server, &ac);
        assert_eq!(result.unwrap_err().class_name(), expected, "{name}");
        assert!(
            server.requests().is_empty(),
            "{name}: HTTP must not bypass prerequisites"
        );
    }
}

#[test]
fn real_validate_ac_http_distinct_serial_and_full_authority_certid_are_mandatory() {
    let cases = [
        (
            "other-serial-good",
            lane("alice-role-other-serial.attr.crt"),
            lane("other-serial-good.ors"),
            true,
        ),
        (
            "wrong-serial",
            lane("alice-role-other-serial.attr.crt"),
            basic(&["alice-all-good.ors"]),
            false,
        ),
        (
            "wrong-issuer-name-hash",
            basic(&["aa", "alice-role-with-rev.attr.crt"]),
            lane("wrong-issuer-name-hash.ors"),
            false,
        ),
        (
            "wrong-issuer-key-hash",
            basic(&["aa", "alice-role-with-rev.attr.crt"]),
            lane("wrong-issuer-key-hash.ors"),
            false,
        ),
    ];
    for (name, ac, evidence, accepted) in cases {
        let server = evidence_server("ocsp", evidence);
        let f = http_fetchers(&server);
        let context = http_context(&f, "2019-12-12T00:00:00Z", true);
        let holder = basic_cert(&["people-ca", "alice.crt"]);
        let result = sigis_pki_certvalidator::ac::validate_ac(&context, &ac, Some(&holder));
        report_validation(name, &result, &server, &ac);
        if accepted {
            assert_valid_role(&result.unwrap(), &ac);
        } else {
            assert!(
                result
                    .unwrap_err()
                    .is_instance_of("InsufficientRevinfoError"),
                "{name}"
            );
        }
        let requests = server.requests();
        let request = requests.iter().find(|r| r.method == "POST").unwrap();
        let request = OcspRequest::from_der(&request.body).unwrap();
        let serial = request.tbs_request.request_list[0]
            .req_cert
            .serial_number
            .as_bytes();
        if name.starts_with("other") || name == "wrong-serial" {
            assert_eq!(serial, &[0x10, 2]);
            assert_ne!(serial, holder.serial_bytes());
            assert_ne!(serial, aa().serial_bytes());
        }
    }
}

#[test]
fn public_ac_controls_have_the_expected_actual_aa_signature_validity() {
    let manifest_path = sigis_testdata::path(&["lanes", "r3-s", "ac-fetch", "manifest.json"]);
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
    let key = aa().public_key();
    assert_eq!(manifest["files"].as_array().unwrap().len(), 7);
    for entry in manifest["files"].as_array().unwrap() {
        let name = entry["file"].as_str().unwrap();
        let bytes = lane(name);
        let actual_hash = DigestAlgorithm::Sha256
            .digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(actual_hash, entry["sha256"].as_str().unwrap(), "{name}");
        assert_eq!(
            bytes.len(),
            entry["length"].as_u64().unwrap() as usize,
            "{name}"
        );
        let signed = if name.ends_with(".ors") {
            OcspResponse::from_der(&bytes)
                .unwrap()
                .response_bytes
                .unwrap()
                .response
                .as_bytes()
                .to_vec()
        } else {
            bytes
        };
        let parts = fields(&signed);
        if name.ends_with(".ors") {
            let basic = BasicOcspResponse::from_der(&signed).unwrap();
            assert_eq!(
                parts.len(),
                4,
                "{name}: BasicOCSPResponse includes the original AA certificate"
            );
            assert!(Tlv::parse_exact(&parts[3]).unwrap().is_context(0));
            assert_eq!(basic.certs.as_ref().unwrap().len(), 1);
        } else {
            assert_eq!(parts.len(), 3, "{name}: AC/CRL signed envelope");
        }
        let algorithm = spki::AlgorithmIdentifierOwned::from_der(&parts[1]).unwrap();
        let signature = BitString::from_der(&parts[2]).unwrap();
        let result = sigis_pki_core::algorithms::validate_signature(
            signature.raw_bytes(),
            &parts[0],
            &key,
            &algorithm,
            &sigis_pki_core::algorithms::SignatureValidationContext::default(),
        );
        let expected = name != "bad-signature.ors";
        assert_eq!(
            result.is_ok(),
            expected,
            "{name}: actualAA cryptographic signature check {result:?}"
        );
        if !expected {
            assert!(matches!(
                result,
                Err(sigis_pki_core::errors::SignatureError::InvalidSignature)
            ));
        }
        emit(
            "AC_PUBLIC_SIGNATURE",
            serde_json::json!({"file":name,"sha256":actual_hash,"actual_aa_signature_valid":expected}),
        );
    }
}

#[derive(Debug)]
struct DenyAcSignature {
    key: spki::SubjectPublicKeyInfoOwned,
    called: Arc<AtomicBool>,
}

impl sigis_pki_core::algorithms::AlgorithmUsagePolicy for DenyAcSignature {
    fn digest_algorithm_allowed(
        &self,
        _: &const_oid::ObjectIdentifier,
        _: Option<sigis_pki_core::time::Moment>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        sigis_pki_core::algorithms::AlgorithmUsageConstraint::allowed()
    }

    fn signature_algorithm_allowed(
        &self,
        _: &spki::AlgorithmIdentifierOwned,
        _: Option<sigis_pki_core::time::Moment>,
        key: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        if key == Some(&self.key) {
            self.called.store(true, Ordering::SeqCst);
            sigis_pki_core::algorithms::AlgorithmUsageConstraint::denied(
                "The AC signature policy permanently refuses this AA key",
            )
        } else {
            sigis_pki_core::algorithms::AlgorithmUsageConstraint::allowed()
        }
    }
}

#[test]
fn real_validate_ac_http_cannot_bypass_attribute_algorithm_policy() {
    let server = evidence_server("ocsp", basic(&["alice-all-good.ors"]));
    let f = http_fetchers(&server);
    let ac = basic(&["aa", "alice-role-with-rev.attr.crt"]);
    let holder = basic_cert(&["people-ca", "alice.crt"]);
    let positive = sigis_pki_certvalidator::ac::validate_ac(
        &http_context(&f, "2019-12-12T00:00:00Z", true),
        &ac,
        Some(&holder),
    );
    report_validation("ocsp-policy-allowed-control", &positive, &server, &ac);
    assert_valid_role(&positive.unwrap(), &ac);
    assert_eq!(
        server.requests().len(),
        1,
        "positive control actually fetched the AC response"
    );

    let denied_server = evidence_server("ocsp", basic(&["alice-all-good.ors"]));
    let denied_fetchers = http_fetchers(&denied_server);
    let refused = Arc::new(AtomicBool::new(false));
    let context = http_context_builder(&denied_fetchers, "2019-12-12T00:00:00Z", true)
        .algorithm_policy(Arc::new(DenyAcSignature {
            key: aa().public_key(),
            called: refused.clone(),
        }))
        .build()
        .unwrap();
    let result = sigis_pki_certvalidator::ac::validate_ac(&context, &ac, Some(&holder));
    report_validation("ocsp-policy-denied", &result, &denied_server, &ac);
    let error = result.unwrap_err();
    assert_eq!(error.class_name(), "DisallowedAlgorithmError");
    assert!(
        refused.load(Ordering::SeqCst),
        "actual AA signature policy must be queried"
    );
    assert!(denied_server.requests().is_empty(),"actual AC policy denial occurs before HTTP; no response or cached evidence can grant trust");
}

#[test]
fn real_validate_ac_http_cached_crl_bytes_cannot_replace_attribute_scope() {
    let evidence = lane("valid-aa-pkc-only.crl");
    let server = evidence_server("crl", evidence.clone());
    let fetchers = http_fetchers(&server);
    let url = "http://localhost:9000/basic-aa/crls/role-aa/latest.crl";
    assert_eq!(fetchers.fetch_crl_url(url).unwrap(), evidence);
    assert_eq!(
        server.requests().len(),
        1,
        "the raw CRL was actually fetched over HTTP"
    );
    let context = http_context(&fetchers, "2019-12-12T00:00:00Z", true);
    let ac = basic(&["aa", "alice-role-with-rev.attr.crt"]);
    let holder = basic_cert(&["people-ca", "alice.crt"]);
    let result = sigis_pki_certvalidator::ac::validate_ac(&context, &ac, Some(&holder));
    report_validation("crl-pkc-only-cached", &result, &server, &ac);
    let error = result.unwrap_err();
    assert_eq!(error.class_name(), "InsufficientRevinfoError");
    assert!(error
        .to_string()
        .contains("CRL only contains public-key certificates"));
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|request| request.method == "GET"
                && request.path == "/basic-aa/crls/role-aa/latest.crl")
            .count(),
        1,
        "the validator reused cached raw bytes and still applied AC scope checks"
    );
}
