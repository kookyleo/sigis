//! Retrieval interfaces for revocation information and certificates
//! (`fetchers/api.py` in pyhanko-certvalidator).
//!
//! The traits are synchronous: validation code is synchronous, and async
//! callers (the Sigis service) run validation in a blocking task. Concrete
//! HTTP implementations live in `hanko-fetch`; tests use in-memory fakes, so
//! test suites never touch the network.

use std::sync::Arc;

use crate::cert::Cert;
use crate::errors::FetchError;

/// Retrieves OCSP responses (`OCSPFetcher`).
pub trait OcspFetcher: Send + Sync + std::fmt::Debug {
    /// Fetch a DER-encoded `OCSPResponse` for `cert`, issued by `issuer`.
    fn fetch_ocsp(&self, cert: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError>;
}

/// Retrieves CRLs (`CRLFetcher`).
pub trait CrlFetcher: Send + Sync + std::fmt::Debug {
    /// Fetch the DER-encoded CRLs from the distribution points of `cert`
    /// (including `freshestCRL`, for delta CRLs).
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError>;
}

/// Retrieves certificates, e.g. issuers via AIA `caIssuers` (`CertificateFetcher`).
pub trait CertificateFetcher: Send + Sync + std::fmt::Debug {
    /// Fetch candidate issuer certificates of `cert`.
    fn fetch_issuers(&self, cert: &Cert) -> Result<Vec<Cert>, FetchError>;
}

/// The set of fetchers a validation may use (`Fetchers`). Absent fetchers
/// mean "do not fetch".
#[derive(Clone, Debug, Default)]
pub struct Fetchers {
    /// OCSP fetcher.
    pub ocsp: Option<Arc<dyn OcspFetcher>>,
    /// CRL fetcher.
    pub crl: Option<Arc<dyn CrlFetcher>>,
    /// Certificate fetcher.
    pub cert: Option<Arc<dyn CertificateFetcher>>,
}

impl Fetchers {
    /// No fetching at all (the default; required in tests).
    pub fn none() -> Self {
        Self::default()
    }

    /// `true` if no fetcher is configured.
    pub fn is_empty(&self) -> bool {
        self.ocsp.is_none() && self.crl.is_none() && self.cert.is_none()
    }
}
