//! Loopback-only Certomancer sidecar for the upstream live integrations.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

pub const TIME: &str = "2020-11-01T00:00:00Z";

pub struct LivePki {
    child: Child,
    pub url: String,
}

impl LivePki {
    pub fn start() -> Self {
        let python =
            sigis_testdata::oracle::python().expect("live integration requires the oracle");
        let script = sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/live_pki_server.py");
        let child = Command::new(python)
            .arg(script)
            .arg("--crypto")
            .arg(sigis_testdata::pyhanko(&["crypto"]))
            .args(["--time", TIME])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start the isolated Certomancer sidecar");
        let mut live = Self {
            child,
            url: String::new(),
        };
        let stdout = live.child.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = send.send(result);
        });
        let line = receive
            .recv_timeout(Duration::from_secs(30))
            .expect("Certomancer did not become ready within 30 seconds")
            .expect("read Certomancer readiness");
        let ready: serde_json::Value = serde_json::from_str(&line)
            .expect("Certomancer exited without a JSON readiness record");
        live.url = ready["url"].as_str().unwrap().to_owned();
        assert!(live.url.starts_with("http://127.0.0.1:"));
        live
    }
}

impl Drop for LivePki {
    fn drop(&mut self) {
        // This child belongs to this test; never signal another session.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
