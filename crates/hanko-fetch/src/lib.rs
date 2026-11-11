// Interfaces derived from pyhanko-certvalidator `fetchers/` and pyHanko
// `sign/timestamps/requests_client.py` (MIT, see LICENSE-pyHanko).

//! HTTP implementations of the retrieval traits in [`hanko_core::fetch`] and
//! of [`hanko_core::sign::TimeStamper`].
//!
//! Owned by lane A. Tests must not use these against the network; they use
//! in-memory fakes of the traits or a local HTTP server.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::time::Duration;

use hanko_core::algorithms::DigestAlgorithm;
use hanko_core::cert::Cert;
use hanko_core::errors::{not_implemented, FetchError, Result};
use hanko_core::fetch::{CertificateFetcher, CrlFetcher, OcspFetcher};
use hanko_core::sign::TimeStamper;

/// Limits applied to every request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchLimits {
    /// Per-request timeout.
    pub timeout: Duration,
    /// Maximum response size in bytes.
    pub max_response_bytes: usize,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_response_bytes: 10 * 1024 * 1024,
        }
    }
}

/// HTTP fetchers with caching, size limits, timeouts and multi-URL fallback.
#[derive(Clone, Debug, Default)]
pub struct HttpFetchers {
    /// Request limits.
    pub limits: FetchLimits,
}

impl OcspFetcher for HttpFetchers {
    fn fetch_ocsp(&self, _cert: &Cert, _issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        Err(FetchError::disabled(
            "HTTP OCSP fetcher not implemented yet",
        ))
    }
}

impl CrlFetcher for HttpFetchers {
    fn fetch_crls(&self, _cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        Err(FetchError::disabled("HTTP CRL fetcher not implemented yet"))
    }
}

impl CertificateFetcher for HttpFetchers {
    fn fetch_issuers(&self, _cert: &Cert) -> Result<Vec<Cert>, FetchError> {
        Err(FetchError::disabled(
            "HTTP certificate fetcher not implemented yet",
        ))
    }
}

/// RFC 3161 client over HTTP (`HTTPTimeStamper`).
#[derive(Clone, Debug)]
pub struct HttpTimeStamper {
    /// TSA URL.
    pub url: String,
    /// Request limits.
    pub limits: FetchLimits,
}

impl TimeStamper for HttpTimeStamper {
    fn timestamp(&self, _message_digest: &[u8], _digest: DigestAlgorithm) -> Result<Vec<u8>> {
        not_implemented("hanko_fetch::HttpTimeStamper::timestamp")
    }
}
