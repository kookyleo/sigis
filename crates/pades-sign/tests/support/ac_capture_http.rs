//! Real loopback HTTP for frozen AC signing evidence, using production fetchers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use der::{Decode, Encode};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_fetch::transport::HttpRequest;
use sigis_pki_fetch::{
    FetcherSettings, HttpFetchers, HttpResponse, HttpTransport, ReqwestTransport, TransportError,
};

use super::{data_path, pki};

pub fn hash(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug)]
struct Loopback {
    endpoint: String,
    transport: ReqwestTransport,
}

impl HttpTransport for Loopback {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        let path = request
            .url
            .strip_prefix("http://pyhanko.tests/")
            .expect("only the signed fixture host may reach the loopback server");
        self.transport.send(&HttpRequest {
            url: &format!("{}/{path}", self.endpoint),
            ..request.clone()
        })
    }
}

pub struct HttpPki {
    pub http: HttpFetchers,
    received: Arc<Mutex<Vec<serde_json::Value>>>,
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HttpPki {
    /// Adversarial modes change only AC evidence, preserving PKC path evidence.
    pub fn start(case: &'static str) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", server.server_addr());
        let received = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let recording = received.clone();
        let stopping = stopped.clone();
        let thread = std::thread::spawn(move || {
            let directory =
                data_path(&["lanes", "d", "revinfo", "testing-ca-with-aa", "2020-11-01"]);
            let mut ocsp_responses = Vec::new();
            for entry in std::fs::read_dir(&directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name().to_string_lossy().starts_with("ocsp-") {
                    ocsp_responses.push(std::fs::read(entry.path()).unwrap());
                }
            }
            let ac_ocsp = std::fs::read(data_path(&[
                "lanes",
                "r3-p",
                "ac",
                "ocsp-alice-role-with-rev.der",
            ]))
            .unwrap();
            ocsp_responses.push(ac_ocsp.clone());
            let architecture = pki("testing-ca-with-aa");
            while !stopping.load(Ordering::Acquire) {
                let Some(mut request) = server.recv_timeout(Duration::from_millis(50)).unwrap()
                else {
                    continue;
                };
                let path = request.url().to_owned();
                let method = request.method().as_str().to_owned();
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).unwrap();
                let mut status = 200;
                let mut cert_id = None;
                let (content_type, mut response) = if method == "POST" && path.contains("/ocsp/") {
                    let query =
                        x509_ocsp::OcspRequest::<x509_cert::certificate::Rfc5280>::from_der(&body)
                            .unwrap();
                    assert_eq!(query.tbs_request.request_list.len(), 1);
                    let target = &query.tbs_request.request_list[0].req_cert;
                    cert_id = Some(target.to_der().unwrap());
                    let matched = ocsp_responses.iter().find(|bytes| {
                        let response = x509_ocsp::OcspResponse::from_der(bytes).unwrap();
                        let response = response.response_bytes.unwrap();
                        let basic =
                            x509_ocsp::BasicOcspResponse::from_der(response.response.as_bytes())
                                .unwrap();
                        basic
                            .tbs_response_data
                            .responses
                            .iter()
                            .any(|single| single.cert_id == *target)
                    });
                    if let Some(matched) = matched {
                        ("application/ocsp-response", matched.clone())
                    } else {
                        status = 404;
                        ("application/ocsp-response", Vec::new())
                    }
                } else if method == "GET" && path.contains("/crls/") {
                    let parts: Vec<_> = path.split('/').collect();
                    let bytes =
                        std::fs::read(directory.join(format!("crl-{}.der", parts[3]))).unwrap();
                    ("application/pkix-crl", bytes)
                } else if method == "GET" && path.contains("/certs/") {
                    let parts: Vec<_> = path.split('/').collect();
                    (
                        "application/pkix-cert",
                        architecture.cert(parts[3]).der().to_vec(),
                    )
                } else {
                    panic!("unexpected fixture HTTP request {method} {path}")
                };
                if path == "/testing-ca-with-aa/ocsp/leaf-aa" {
                    assert_eq!(
                        response, ac_ocsp,
                        "entire CertID must match the actual AC response"
                    );
                    match case {
                        "missing" | "forged_crl" | "crl_fallback" => {
                            status = 404;
                            response.clear();
                        }
                        "tampered_ocsp" => {
                            let mut parsed = x509_ocsp::OcspResponse::from_der(&response).unwrap();
                            let envelope = parsed.response_bytes.as_mut().unwrap();
                            let mut basic = x509_ocsp::BasicOcspResponse::from_der(
                                envelope.response.as_bytes(),
                            )
                            .unwrap();
                            let mut signature = basic.signature.raw_bytes().to_vec();
                            signature[0] ^= 1;
                            basic.signature = der::asn1::BitString::from_bytes(&signature).unwrap();
                            envelope.response =
                                der::asn1::OctetString::new(basic.to_der().unwrap()).unwrap();
                            response = parsed.to_der().unwrap();
                        }
                        "good" => {}
                        _ => panic!("unknown HTTP AC control"),
                    }
                }
                if path == "/testing-ca-with-aa/crls/leaf-aa/latest.crl" {
                    match case {
                        "missing" | "tampered_ocsp" => {
                            status = 404;
                            response.clear();
                        }
                        "forged_crl" => {
                            let mut crl = x509_cert::crl::CertificateList::<
                                x509_cert::certificate::Rfc5280,
                            >::from_der(&response)
                            .unwrap();
                            let mut signature = crl.signature.raw_bytes().to_vec();
                            signature[0] ^= 1;
                            crl.signature = der::asn1::BitString::from_bytes(&signature).unwrap();
                            response = crl.to_der().unwrap();
                        }
                        "good" | "crl_fallback" => {}
                        _ => panic!("unknown HTTP AC control"),
                    }
                }
                recording.lock().unwrap().push(serde_json::json!({
                    "method": method, "path": path, "status": status,
                    "request_der": body, "request_sha256": hash(&body),
                    "cert_id_der": cert_id, "response_der": response,
                    "response_sha256": hash(&response),
                }));
                request
                    .respond(
                        tiny_http::Response::from_data(response)
                            .with_status_code(status)
                            .with_header(
                                tiny_http::Header::from_bytes(
                                    b"Content-Type",
                                    content_type.as_bytes(),
                                )
                                .unwrap(),
                            ),
                    )
                    .unwrap();
            }
        });
        Self {
            http: HttpFetchers::with_transport(
                Arc::new(Loopback {
                    endpoint,
                    transport: ReqwestTransport::new(Duration::from_secs(10), 4_000_000).unwrap(),
                }),
                FetcherSettings::default(),
            ),
            received,
            stopped,
            thread: Some(thread),
        }
    }

    pub fn trace(&self) -> Vec<serde_json::Value> {
        self.received.lock().unwrap().clone()
    }

    pub fn assert_ac_requested(&self) {
        assert!(
            self.trace()
                .iter()
                .any(|row| row["path"] == "/testing-ca-with-aa/ocsp/leaf-aa"),
            "real native HTTP AC dispatch must run before signing succeeds"
        );
    }
}

impl Drop for HttpPki {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap();
    }
}
