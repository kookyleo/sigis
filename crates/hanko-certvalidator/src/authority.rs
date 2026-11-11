// Partly derived from pyhanko-certvalidator `authority.py` (MIT, see LICENSE-pyHanko).

//! Trust anchors.

pub use hanko_core::cert::{Cert, RawCertificate};

/// A trust anchor expressed as a certificate (`CertTrustAnchor`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    cert: Cert,
    enforce_validity: bool,
}

impl TrustAnchor {
    /// A trust anchor whose own validity period is not enforced (the
    /// pyhanko-certvalidator default).
    pub fn new(cert: Cert) -> Self {
        Self {
            cert,
            enforce_validity: false,
        }
    }

    /// A trust anchor whose validity period is enforced
    /// (`derive_default_quals_from_cert=True` in pyhanko-certvalidator).
    pub fn with_enforced_validity(cert: Cert) -> Self {
        Self {
            cert,
            enforce_validity: true,
        }
    }

    /// The anchor certificate.
    pub fn cert(&self) -> &Cert {
        &self.cert
    }

    /// Whether the anchor's validity period is enforced.
    pub fn enforce_validity(&self) -> bool {
        self.enforce_validity
    }
}
