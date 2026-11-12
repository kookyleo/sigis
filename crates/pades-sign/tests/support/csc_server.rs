// Derived from certomancer-csc-dummy 0.4.2 `csc_dummy/csc_dummy_server.py`
// and pyHanko `pyhanko_testing_commons/test_utils/csc_utils/csc_dummy_client.py`
// (MIT, see LICENSE-pyHanko).

//! A local fake CSC service on `127.0.0.1:0` (`CSCWithCertomancer`), and
//! the dummy client authorization manager (`CSCDummyClientAuthManager`).
//!
//! Credentials are `<arch>/<cert label>` of the exported Certomancer PKI.
//! As in the Python dummy, SAD is an HMAC token over the credential id, the
//! number of signatures and the pinned hashes; it is not bound to a session
//! and not protected against replay.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use base64ct::{Base64, Encoding};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sigis_pades_sign::csc::{
    parse_csc_auth_response, CscAuthRequest, CscAuthorizationInfo, CscAuthorizationManager,
    CscCredentialInfo, CscServiceSessionInfo,
};
use sigis_pades_sign::keys::PrivateKey;
use sigis_pki_core::algorithms::{DigestAlgorithm, SignatureMechanism};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::errors::Result;

use super::pki;

/// A handler: `(path, JSON body) -> (status, JSON body)`.
pub type Handler = dyn Fn(&str, &Value) -> (u16, Value) + Send + Sync;

/// An HTTP server on `127.0.0.1:0` answering JSON POSTs.
pub struct FakeServer {
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    pub url: String,
}

impl FakeServer {
    pub fn start(handler: Arc<Handler>) -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = server.server_addr().to_ip().unwrap().port();
        let srv = server.clone();
        let thread = std::thread::spawn(move || {
            for mut req in srv.incoming_requests() {
                let handler = handler.clone();
                std::thread::spawn(move || {
                    let mut body = String::new();
                    let _ = req.as_reader().read_to_string(&mut body);
                    let json: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                    let path = req.url().to_owned();
                    let (status, out) = if *req.method() == tiny_http::Method::Post {
                        handler(&path, &json)
                    } else {
                        (405, json!({}))
                    };
                    let resp = tiny_http::Response::from_string(out.to_string())
                        .with_status_code(status)
                        .with_header(
                            tiny_http::Header::from_bytes("Content-Type", "application/json")
                                .unwrap(),
                        );
                    let _ = req.respond(resp);
                });
            }
        });
        Self {
            server,
            thread: Some(thread),
            url: format!("http://127.0.0.1:{port}"),
        }
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A URL on which nothing listens (for network failure tests).
pub fn closed_url() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    format!("http://127.0.0.1:{port}")
}

/// `DummyServiceParams`, plus artificial delays of `signatures/signHash`.
#[derive(Clone, Debug)]
pub struct DummyServiceParams {
    pub hash_pinning_required: bool,
    pub multisign: i64,
    pub sad_secret: Vec<u8>,
}

impl Default for DummyServiceParams {
    fn default() -> Self {
        Self {
            hash_pinning_required: true,
            multisign: 10,
            sad_secret: b"secret".to_vec(),
        }
    }
}

/// The dummy CSC service (`CSCWithCertomancer`).
pub struct CscDummy {
    pub params: DummyServiceParams,
    /// Delays applied to successive `signHash` requests (front first).
    pub sign_hash_delays: Mutex<VecDeque<Duration>>,
    pub sign_hash_calls: AtomicUsize,
}

fn bad() -> (u16, Value) {
    (400, json!({"error": "invalid_request"}))
}

fn mac(secret: &[u8], cred_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut h = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(secret).unwrap();
    h.update(cred_id.as_bytes());
    h.update(&[0]);
    h.update(payload);
    h.finalize().into_bytes().to_vec()
}

impl CscDummy {
    pub fn new(params: DummyServiceParams) -> Arc<Self> {
        Arc::new(Self {
            params,
            sign_hash_delays: Mutex::new(VecDeque::new()),
            sign_hash_calls: AtomicUsize::new(0),
        })
    }

    pub fn start(self: &Arc<Self>) -> FakeServer {
        let me = self.clone();
        FakeServer::start(Arc::new(move |path: &str, body: &Value| {
            me.handle(path, body)
        }))
    }

    fn handle(&self, path: &str, body: &Value) -> (u16, Value) {
        match path {
            "/csc/v1/credentials/info" => self.credentials_info(body),
            "/csc/v1/credentials/authorize" => self.credentials_authorize(body),
            "/csc/v1/signatures/signHash" => self.sign_hash(body),
            _ => (404, json!({})),
        }
    }

    fn parse_credential_id(cred_id: &str) -> Option<(super::Pki, String)> {
        let (arch, label) = cred_id.split_once('/')?;
        let dir = super::data_path(&["lanes", "d", "pki", arch]);
        if !dir.join("manifest.json").exists() {
            return None;
        }
        let p = pki(arch);
        if !p.labels().iter().any(|l| l == label) {
            return None;
        }
        Some((p, label.to_owned()))
    }

    fn credentials_info(&self, body: &Value) -> (u16, Value) {
        if body.get("certInfo").and_then(Value::as_bool) == Some(true) {
            return (501, json!({}));
        }
        let Some(cred_id) = body.get("credentialID").and_then(Value::as_str) else {
            return bad();
        };
        let Some((p, label)) = Self::parse_credential_id(cred_id) else {
            return (404, json!({}));
        };
        let cert = p.cert(&label);
        let spki = cert.public_key();
        let algos: Vec<&str> = match spki.algorithm.oid {
            oids::RSA_ENCRYPTION => vec![
                "1.2.840.113549.1.1.1",
                "1.2.840.113549.1.1.10",
                "1.2.840.113549.1.1.11",
                "1.2.840.113549.1.1.12",
                "1.2.840.113549.1.1.13",
            ],
            oids::EC_PUBLIC_KEY => vec![
                "1.2.840.10045.4.3.2",
                "1.2.840.10045.4.3.3",
                "1.2.840.10045.4.3.4",
            ],
            _ => vec![],
        };
        let certificates = body
            .get("certificates")
            .and_then(Value::as_str)
            .unwrap_or("single");
        let mut resp = json!({
            "key": {"status": "enabled", "algo": algos},
            "authMode": "implicit",
            "SCAL": if self.params.hash_pinning_required { "2" } else { "1" },
            "multisign": self.params.multisign,
        });
        let mut certs = vec![Base64::encode_string(cert.der())];
        match certificates {
            "none" => {}
            "single" | "chain" => {
                if certificates == "chain" {
                    // the issuer chain, up to the root
                    let manifest_issuer = |l: &str| -> String {
                        let m: Value = serde_json::from_slice(
                            &std::fs::read(super::data_path(&[
                                "lanes",
                                "d",
                                "pki",
                                &p.arch,
                                "manifest.json",
                            ]))
                            .unwrap(),
                        )
                        .unwrap();
                        m["certs"][l]["issuer"].as_str().unwrap().to_owned()
                    };
                    let mut cur = label.clone();
                    loop {
                        let iss = manifest_issuer(&cur);
                        if iss == cur {
                            break;
                        }
                        certs.push(Base64::encode_string(p.cert(&iss).der()));
                        cur = iss;
                    }
                }
                resp["cert"] = json!({"certificates": certs});
            }
            _ => return bad(),
        }
        (200, resp)
    }

    fn credentials_authorize(&self, body: &Value) -> (u16, Value) {
        let (Some(cred_id), Some(num)) = (
            body.get("credentialID").and_then(Value::as_str),
            body.get("numSignatures").and_then(Value::as_u64),
        ) else {
            return bad();
        };
        if Self::parse_credential_id(cred_id).is_none() {
            return (404, json!({}));
        }
        let hashes = match body.get("hash") {
            None | Some(Value::Null) => {
                if self.params.hash_pinning_required {
                    return bad();
                }
                Value::Null
            }
            Some(Value::Array(h)) => {
                if h.len() as u64 != num {
                    return bad();
                }
                Value::Array(h.clone())
            }
            Some(_) => return bad(),
        };
        let payload = json!({"n": num, "h": hashes}).to_string();
        let sad = format!(
            "{}.{}",
            Base64::encode_string(payload.as_bytes()),
            Base64::encode_string(&mac(&self.params.sad_secret, cred_id, payload.as_bytes()))
        );
        (200, json!({"SAD": sad}))
    }

    /// `CSCAuthorization.verify_sad`: `(num_signatures, pinned hashes)`.
    fn verify_sad(&self, sad: &str, cred_id: &str) -> Option<(u64, Option<Vec<String>>)> {
        let (payload_b64, mac_b64) = sad.split_once('.')?;
        let payload = Base64::decode_vec(payload_b64).ok()?;
        let tag = Base64::decode_vec(mac_b64).ok()?;
        if mac(&self.params.sad_secret, cred_id, &payload) != tag {
            return None;
        }
        let v: Value = serde_json::from_slice(&payload).ok()?;
        let n = v["n"].as_u64()?;
        let h = v["h"].as_array().map(|a| {
            a.iter()
                .map(|x| x.as_str().unwrap_or_default().to_owned())
                .collect()
        });
        Some((n, h))
    }

    fn sign_hash(&self, body: &Value) -> (u16, Value) {
        self.sign_hash_calls.fetch_add(1, Ordering::SeqCst);
        let delay = self.sign_hash_delays.lock().unwrap().pop_front();
        if let Some(d) = delay {
            std::thread::sleep(d);
        }
        let (Some(cred_id), Some(sad)) = (
            body.get("credentialID").and_then(Value::as_str),
            body.get("SAD").and_then(Value::as_str),
        ) else {
            return bad();
        };
        let Some((num, pinned)) = self.verify_sad(sad, cred_id) else {
            return bad();
        };
        let Some((p, label)) = Self::parse_credential_id(cred_id) else {
            return (404, json!({}));
        };
        let key = p.key(&p.key_label_of(&label));
        let Some(hashes) = body.get("hash").and_then(Value::as_array) else {
            return bad();
        };
        let hashes: Vec<String> = hashes
            .iter()
            .map(|h| h.as_str().unwrap_or_default().to_owned())
            .collect();
        match &pinned {
            Some(pinned) => {
                if !hashes.iter().all(|h| pinned.contains(h)) {
                    return bad();
                }
            }
            None => {
                if hashes.len() as u64 > num {
                    return bad();
                }
            }
        }
        let Some(sign_algo) = body
            .get("signAlgo")
            .and_then(Value::as_str)
            .and_then(|s| der::asn1::ObjectIdentifier::new(s).ok())
        else {
            return bad();
        };
        let params = match body.get("signAlgoParams").and_then(Value::as_str) {
            Some(b64) => {
                if sign_algo != oids::RSASSA_PSS {
                    return (501, json!({}));
                }
                let Ok(der) = Base64::decode_vec(b64) else {
                    return bad();
                };
                let Ok(any) = <der::Any as der::Decode>::from_der(&der) else {
                    return bad();
                };
                Some(any)
            }
            None => None,
        };
        let mech = spki::AlgorithmIdentifierOwned {
            oid: sign_algo,
            parameters: params,
        };
        let hash_algo = body
            .get("hashAlgo")
            .and_then(Value::as_str)
            .and_then(|s| der::asn1::ObjectIdentifier::new(s).ok())
            .and_then(|o| DigestAlgorithm::from_oid(&o));
        let Ok(resolved) = SignatureMechanism::from_algorithm_identifier(&mech, hash_algo) else {
            return bad();
        };
        let mut sigs = Vec::new();
        for h in &hashes {
            let Ok(digest) = Base64::decode_vec(h) else {
                return bad();
            };
            match sign_prehashed(&key, &resolved, &digest) {
                Some(s) => sigs.push(Base64::encode_string(&s)),
                None => return bad(),
            }
        }
        (200, json!({"signatures": sigs}))
    }
}

/// `generic_sign_prehashed` for RSA (PKCS#1 v1.5, PSS) and ECDSA.
fn sign_prehashed(key: &PrivateKey, mech: &SignatureMechanism, digest: &[u8]) -> Option<Vec<u8>> {
    use DigestAlgorithm::*;
    match (mech, key) {
        (SignatureMechanism::RsaPkcs1v15(md), PrivateKey::Rsa(k)) => {
            let scheme = match md {
                Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                Sha224 => rsa::Pkcs1v15Sign::new::<sha2::Sha224>(),
                Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                _ => return None,
            };
            k.sign(scheme, digest).ok()
        }
        (SignatureMechanism::RsaPss(p), PrivateKey::Rsa(k)) => {
            if p.mgf1_digest != p.digest {
                return None;
            }
            let s = p.salt_length;
            match p.digest {
                Sha1 => k.sign(rsa::Pss::<sha1::Sha1>::new_with_salt(s), digest),
                Sha224 => k.sign(rsa::Pss::<sha2::Sha224>::new_with_salt(s), digest),
                Sha256 => k.sign(rsa::Pss::<sha2::Sha256>::new_with_salt(s), digest),
                Sha384 => k.sign(rsa::Pss::<sha2::Sha384>::new_with_salt(s), digest),
                Sha512 => k.sign(rsa::Pss::<sha2::Sha512>::new_with_salt(s), digest),
                _ => return None,
            }
            .ok()
        }
        (SignatureMechanism::Ecdsa(_), _) => {
            use signature::hazmat::PrehashSigner;
            match key {
                PrivateKey::P256(k) => {
                    let s: p256::ecdsa::DerSignature = k.sign_prehash(digest).ok()?;
                    Some(s.as_bytes().to_vec())
                }
                PrivateKey::P384(k) => {
                    let s: p384::ecdsa::DerSignature = k.sign_prehash(digest).ok()?;
                    Some(s.as_bytes().to_vec())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// `CSCDummyClientAuthManager`: requests hash-bound SAD for every batch.
#[derive(Debug)]
pub struct DummyClientAuthManager {
    client: reqwest::blocking::Client,
    session_info: CscServiceSessionInfo,
    credential_info: CscCredentialInfo,
    pub authorizations_requested: AtomicUsize,
}

impl DummyClientAuthManager {
    pub fn new(session_info: CscServiceSessionInfo, credential_info: CscCredentialInfo) -> Self {
        Self {
            client: sigis_pades_sign::csc::http_client().unwrap(),
            session_info,
            credential_info,
            authorizations_requested: AtomicUsize::new(0),
        }
    }
}

impl CscAuthorizationManager for DummyClientAuthManager {
    fn session_info(&self) -> &CscServiceSessionInfo {
        &self.session_info
    }

    fn credential_info(&self) -> &CscCredentialInfo {
        &self.credential_info
    }

    fn authorize_signature(&self, hash_b64s: &[String]) -> Result<CscAuthorizationInfo> {
        self.authorizations_requested.fetch_add(1, Ordering::SeqCst);
        let req = self.format_csc_auth_request(&CscAuthRequest {
            hash_b64s: Some(hash_b64s.to_vec()),
            ..Default::default()
        });
        let resp = self
            .client
            .post(self.session_info.endpoint_url("credentials/authorize"))
            .json(&req)
            .timeout(Duration::from_secs(30))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(|r| r.json::<Value>())
            .map_err(|e| {
                sigis_pki_core::errors::HankoError::Signing(format!(
                    "Credential auth request failed: {e}"
                ))
            })?;
        parse_csc_auth_response(&resp)
    }
}
