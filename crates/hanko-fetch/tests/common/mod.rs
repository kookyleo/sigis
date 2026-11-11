//! Test helpers: transports that never touch the network, and a minimal
//! HTTP server on 127.0.0.1.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use hanko_core::cert::Cert;
use hanko_fetch::transport::{HttpRequest, HttpResponse, HttpTransport, TransportError};

/// A transport whose requests always fail, counting them (`FailingSession`).
#[derive(Debug, Default)]
pub struct FailingTransport {
    pub count: AtomicUsize,
}

impl HttpTransport for FailingTransport {
    fn send(&self, _request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        Err(TransportError::Network("no network".into()))
    }
}

/// Path of a pyhanko-certvalidator fixture.
pub fn cv_fixture(parts: &[&str]) -> std::path::PathBuf {
    hanko_testdata::certvalidator(parts)
}

pub fn read_cv(parts: &[&str]) -> Vec<u8> {
    let p = cv_fixture(parts);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

pub fn load_cert(parts: &[&str]) -> Cert {
    Cert::from_pem_or_der(&read_cv(parts)).expect("cert")
}

/// Path below `crates/hanko-testdata/data/lanes/a/`.
pub fn lane_data(parts: &[&str]) -> std::path::PathBuf {
    let mut all = vec!["lanes", "a"];
    all.extend_from_slice(parts);
    hanko_testdata::path(&all)
}

pub fn read_lane(parts: &[&str]) -> Vec<u8> {
    let p = lane_data(parts);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// What the local server answers.
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// A request received by the local server.
#[derive(Clone, Debug, Default)]
pub struct Received {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A local HTTP/1.1 server on 127.0.0.1 answering every request with
/// `reply`, until dropped.
pub struct LocalServer {
    pub url: String,
    pub received: Arc<Mutex<Vec<Received>>>,
}

impl LocalServer {
    pub fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let received = Arc::new(Mutex::new(Vec::new()));
        let rec = received.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let r = handle(stream, &reply);
                if let Some(r) = r {
                    rec.lock().unwrap().push(r);
                }
            }
        });
        Self {
            url: format!("http://{addr}"),
            received,
        }
    }
}

fn handle(mut stream: TcpStream, reply: &Reply) -> Option<Received> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = Vec::new();
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().ok()?;
            }
            headers.push((k.to_owned(), v.trim().to_owned()));
        }
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).ok()?;
    let mut out = format!(
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    if let Some(ct) = &reply.content_type {
        out.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    out.push_str("\r\n");
    stream.write_all(out.as_bytes()).ok()?;
    stream.write_all(&reply.body).ok()?;
    Some(Received {
        method,
        path,
        headers,
        body,
    })
}

/// A URL on 127.0.0.1 where nothing listens (connection refused).
pub fn closed_port_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    format!("http://{addr}/tsa")
}
