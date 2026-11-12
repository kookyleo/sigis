//! Retrieval interfaces for revocation information and certificates
//! (`fetchers/api.py` in pyhanko-certvalidator).
//!
//! The traits are synchronous: validation code is synchronous, and async
//! callers (the Sigis service) run validation in a blocking task. Concrete
//! HTTP implementations live in `sigis-pki-fetch`; tests use in-memory fakes, so
//! test suites never touch the network.

use std::sync::Arc;

use crate::cert::Cert;
use crate::errors::{FetchError, FetchErrorKind};

/// Retrieves OCSP responses (`OCSPFetcher`).
pub trait OcspFetcher: Send + Sync + std::fmt::Debug {
    /// Fetch a DER-encoded `OCSPResponse` for `cert`, issued by `issuer`.
    fn fetch_ocsp(&self, cert: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError>;

    /// Fetch OCSP evidence for a DER-encoded attribute certificate issued by
    /// the actual attribute authority `issuer`, not the holder certificate.
    /// The default reports an unsupported target without calling PKC retrieval.
    /// Implementations must preserve their configured transport and limits;
    /// successful retrieval alone does not establish trusted revocation evidence.
    fn fetch_ac_ocsp(&self, _ac_der: &[u8], _issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        Err(FetchError::new(
            FetchErrorKind::NotFound,
            "Attribute certificate OCSP fetching is not supported by this fetcher",
        ))
    }
}

/// Retrieves CRLs (`CRLFetcher`).
pub trait CrlFetcher: Send + Sync + std::fmt::Debug {
    /// Fetch the DER-encoded CRLs from the distribution points of `cert`
    /// (including `freshestCRL`, for delta CRLs).
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError>;

    /// Fetch DER CRLs declared by an attribute certificate, including deltas.
    /// The default reports an unsupported target without substituting a PKC.
    /// Implementations retain the existing request/body/time limits; callers
    /// must still authenticate and apply all target-specific scope checks.
    fn fetch_ac_crls(&self, _ac_der: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        Err(FetchError::new(
            FetchErrorKind::NotFound,
            "Attribute certificate CRL fetching is not supported by this fetcher",
        ))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::FetchErrorKind;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct CertificateOnlyFetcher {
        ocsp_calls: AtomicUsize,
        crl_calls: AtomicUsize,
    }

    impl OcspFetcher for CertificateOnlyFetcher {
        fn fetch_ocsp(&self, _cert: &Cert, _issuer: &Cert) -> Result<Vec<u8>, FetchError> {
            self.ocsp_calls.fetch_add(1, Ordering::SeqCst);
            Err(FetchError::disabled("legacy certificate OCSP retrieval"))
        }
    }

    impl CrlFetcher for CertificateOnlyFetcher {
        fn fetch_crls(&self, _cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
            self.crl_calls.fetch_add(1, Ordering::SeqCst);
            Err(FetchError::disabled("legacy certificate CRL retrieval"))
        }
    }

    fn certificate() -> Cert {
        Cert::from_pem_or_der(include_bytes!(
            "../../testdata/data/pyhanko-certvalidator/testing-ca-ed25519/signer.cert.pem"
        ))
        .unwrap()
    }

    #[test]
    fn legacy_ocsp_fetcher_rejects_ac_without_calling_certificate_method() {
        let legacy = CertificateOnlyFetcher::default();
        let fetcher: &dyn OcspFetcher = &legacy;
        let issuer = certificate();
        for ac_der in [&[][..], &[0x30, 0x00][..]] {
            assert_eq!(
                fetcher.fetch_ac_ocsp(ac_der, &issuer).unwrap_err().kind,
                FetchErrorKind::NotFound
            );
        }
        assert_eq!(legacy.ocsp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fetcher.fetch_ocsp(&issuer, &issuer).unwrap_err().kind,
            FetchErrorKind::Disabled
        );
        assert_eq!(legacy.ocsp_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn legacy_crl_fetcher_rejects_ac_without_calling_certificate_method() {
        let legacy = CertificateOnlyFetcher::default();
        let fetcher: &dyn CrlFetcher = &legacy;
        for ac_der in [&[][..], &[0x30, 0x00][..]] {
            assert_eq!(
                fetcher.fetch_ac_crls(ac_der).unwrap_err().kind,
                FetchErrorKind::NotFound
            );
        }
        assert_eq!(legacy.crl_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fetcher.fetch_crls(&certificate()).unwrap_err().kind,
            FetchErrorKind::Disabled
        );
        assert_eq!(legacy.crl_calls.load(Ordering::SeqCst), 1);
    }
}
