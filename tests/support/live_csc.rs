//! Actual pinned Python CSC service and hash-bound authorization client.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::Value;
use sigis_pades_sign::csc::{
    parse_csc_auth_response, CscAuthRequest, CscAuthorizationInfo, CscAuthorizationManager,
    CscCredentialInfo, CscServiceSessionInfo,
};
use sigis_pki_core::errors::{HankoError, Result};

pub const TIME: &str = "2020-11-01T00:00:00Z";

pub struct LiveCsc {
    child: Child,
    pub url: String,
    pub root_der: Vec<u8>,
}

impl LiveCsc {
    pub fn start() -> Self {
        let python = sigis_testdata::oracle::python().expect("live CSC oracle is required");
        let script = sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/live_csc_server.py");
        let child = Command::new(python)
            .arg(script)
            .arg("--crypto")
            .arg(sigis_testdata::pyhanko(&["crypto"]))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start isolated pinned CSC service");
        // Establish ownership before parsing readiness, including failure paths.
        let mut service = Self {
            child,
            url: String::new(),
            root_der: Vec::new(),
        };
        let stdout = service.child.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = send.send(result);
        });
        let line = receive
            .recv_timeout(Duration::from_secs(30))
            .expect("CSC readiness timeout")
            .expect("read CSC readiness");
        let ready: Value = serde_json::from_str(&line).expect("CSC readiness JSON");
        service.url = ready["url"].as_str().unwrap().to_owned();
        assert!(service.url.starts_with("http://127.0.0.1:"));
        assert_eq!(ready["csc_version"], "0.4.2");
        assert_eq!(ready["pae_version"], "0.1.0");
        let root = ready["root_der"].as_str().unwrap();
        service.root_der = root
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        service
    }
}

impl Drop for LiveCsc {
    fn drop(&mut self) {
        // Signal only the child this test created; leave all sessions intact.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Mirrors CSCDummyClientAuthManager: fresh hash-bound SAD for every batch.
#[derive(Debug)]
pub struct LiveAuthorization {
    pub client: Client,
    pub session: CscServiceSessionInfo,
    pub credential: CscCredentialInfo,
    pub authorizations_requested: AtomicUsize,
    pub waste_time: Duration,
}

impl CscAuthorizationManager for LiveAuthorization {
    fn session_info(&self) -> &CscServiceSessionInfo {
        &self.session
    }
    fn credential_info(&self) -> &CscCredentialInfo {
        &self.credential
    }
    fn authorize_signature(&self, hashes: &[String]) -> Result<CscAuthorizationInfo> {
        self.authorizations_requested.fetch_add(1, Ordering::SeqCst);
        let body = self.format_csc_auth_request(&CscAuthRequest {
            hash_b64s: Some(hashes.to_vec()),
            ..Default::default()
        });
        let mut request = self
            .client
            .post(self.session.endpoint_url("credentials/authorize"))
            .json(&body)
            .timeout(Duration::from_secs(30));
        for (key, value) in self.auth_headers() {
            request = request.header(key, value);
        }
        let response = request
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(|response| response.json::<Value>())
            .map_err(|error| {
                HankoError::Signing(format!("Credential auth request failed: {error}"))
            })?;
        if !self.waste_time.is_zero() {
            std::thread::sleep(self.waste_time);
        }
        parse_csc_auth_response(&response)
    }
}
