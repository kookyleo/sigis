// Derived from pyhanko-certvalidator `fetchers/requests_fetchers/util.py`
// (MIT, see LICENSE-pyHanko).

//! The HTTP layer used by the fetchers, behind a trait so that tests can
//! run without a network (in-memory fakes, or a server on 127.0.0.1).

use std::io::Read;
use std::time::Duration;

/// Default `User-Agent` (`DEFAULT_USER_AGENT`).
pub const DEFAULT_USER_AGENT: &str = concat!("sigis-hanko ", env!("CARGO_PKG_VERSION"));

/// An HTTP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// `Content-Type` header, trimmed, if present.
    pub content_type: Option<String>,
    /// Body.
    pub body: Vec<u8>,
}

/// Failure of an HTTP exchange.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// Connection, protocol or I/O failure.
    #[error("network error: {0}")]
    Network(String),
    /// The request timed out.
    #[error("request timed out: {0}")]
    Timeout(String),
    /// The response body exceeded the size limit.
    #[error("response larger than {0} bytes")]
    TooLarge(usize),
}

/// A request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest<'a> {
    /// `GET` or `POST`.
    pub method: &'static str,
    /// URL.
    pub url: &'a str,
    /// Headers (name, value).
    pub headers: Vec<(String, String)>,
    /// Body (`POST`).
    pub body: Option<&'a [u8]>,
}

/// Something that can perform HTTP requests.
pub trait HttpTransport: Send + Sync + std::fmt::Debug {
    /// Perform `request`.
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError>;
}

/// Blocking HTTP transport on `reqwest`, with a per-request timeout and a
/// response size limit.
#[derive(Clone, Debug)]
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
    max_response_bytes: usize,
}

impl ReqwestTransport {
    /// A transport with the given limits. Redirects are followed (at most
    /// 5), as `requests` and `aiohttp` do.
    pub fn new(timeout: Duration, max_response_bytes: usize) -> Result<Self, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| TransportError::Network(e.to_string()))?;
        Ok(Self {
            client,
            max_response_bytes,
        })
    }
}

impl HttpTransport for ReqwestTransport {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        let mut builder = match request.method {
            "POST" => self.client.post(request.url),
            _ => self.client.get(request.url),
        };
        for (k, v) in &request.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        if let Some(body) = request.body {
            builder = builder.body(body.to_vec());
        }
        let map_err = |e: reqwest::Error| {
            if e.is_timeout() {
                TransportError::Timeout(e.to_string())
            } else {
                TransportError::Network(e.to_string())
            }
        };
        let response = builder.send().map_err(map_err)?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_owned());
        if let Some(len) = response.content_length() {
            if usize::try_from(len).map_or(true, |l| l > self.max_response_bytes) {
                return Err(TransportError::TooLarge(self.max_response_bytes));
            }
        }
        let limit = u64::try_from(self.max_response_bytes).unwrap_or(u64::MAX);
        let mut body = Vec::new();
        response
            .take(limit.saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|e| TransportError::Network(e.to_string()))?;
        if body.len() > self.max_response_bytes {
            return Err(TransportError::TooLarge(self.max_response_bytes));
        }
        Ok(HttpResponse {
            status,
            content_type,
            body,
        })
    }
}
