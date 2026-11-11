// Partly derived from pyhanko-certvalidator `authority.py` (MIT, see LICENSE-pyHanko).

//! Trust anchors and their qualifiers.

pub use hanko_core::cert::{Cert, RawCertificate};

use crate::policy::PkixValidationParams;
use hanko_core::time::Moment;

/// The service a trust anchor is trusted for (`TrustedServiceType`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TrustedServiceType {
    /// Trusted for any purpose.
    #[default]
    Unspecified,
    /// Trusted only to identify itself.
    Unsupported,
    /// A certificate authority: may issue certificates in a path.
    CertificateAuthority,
    /// A time stamping authority.
    TimeStampingAuthority,
}

/// Qualifiers of a trust anchor (`TrustQualifiers`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustQualifiers {
    /// Validation parameters that apply to paths from this anchor.
    pub standard_parameters: Option<PkixValidationParams>,
    /// Maximum path length (excluding self-issued intermediates).
    pub max_path_length: Option<usize>,
    /// Maximum path length for AA controls.
    pub max_aa_path_length: Option<usize>,
    /// Lower bound of the anchor's validity period (`valid_from`).
    pub valid_from: Option<Moment>,
    /// Upper bound of the anchor's validity period (`valid_until`).
    pub valid_until: Option<Moment>,
    /// The service the anchor is trusted for.
    pub trusted_service_type: TrustedServiceType,
}

/// A trust anchor expressed as a certificate (`CertTrustAnchor`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    cert: Cert,
    enforce_validity: bool,
    qualifiers: TrustQualifiers,
}

impl TrustAnchor {
    /// A trust anchor whose own validity period is not enforced (the
    /// pyhanko-certvalidator default).
    pub fn new(cert: Cert) -> Self {
        Self {
            cert,
            enforce_validity: false,
            qualifiers: TrustQualifiers::default(),
        }
    }

    /// A trust anchor with explicit qualifiers (`CertTrustAnchor(cert, quals)`).
    pub fn with_qualifiers(cert: Cert, qualifiers: TrustQualifiers) -> Self {
        Self {
            cert,
            enforce_validity: false,
            qualifiers,
        }
    }

    /// A trust anchor whose validity period is enforced and whose
    /// qualifiers are derived from the certificate
    /// (`derive_default_quals_from_cert=True`).
    pub fn with_enforced_validity(cert: Cert) -> Self {
        let qualifiers = crate::policy::derive_quals_from_cert(&cert);
        Self {
            cert,
            enforce_validity: true,
            qualifiers,
        }
    }

    /// A trust anchor given by name and public key only (`TrustAnchor(
    /// NamedKeyAuthority(name, key), quals)`). Internally it is carried by
    /// an unsigned self-issued certificate with that name and key and an
    /// unbounded validity period; anchors are trusted by fiat, so its
    /// signature is never checked.
    pub fn from_name_and_key(
        name: x509_cert::name::Name,
        key: spki::SubjectPublicKeyInfoOwned,
        qualifiers: TrustQualifiers,
    ) -> Result<Self, hanko_core::errors::ValidationError> {
        use der::Encode;
        use hanko_core::asn1::tlv::encode;
        let m = |e: der::Error| hanko_core::errors::ValidationError::Malformed(e.to_string());
        let alg = spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(der::asn1::Null.into()),
        }
        .to_der()
        .map_err(m)?;
        let name_der = name.to_der().map_err(m)?;
        let mut validity = encode(0x17, b"700101000000Z");
        validity.extend(encode(0x18, b"99991231235959Z"));
        let mut tbs = encode(0xa0, &encode(0x02, &[2]));
        tbs.extend(encode(0x02, &[1]));
        tbs.extend(&alg);
        tbs.extend(&name_der);
        tbs.extend(encode(0x30, &validity));
        tbs.extend(&name_der);
        tbs.extend(key.to_der().map_err(m)?);
        let mut cert = encode(0x30, &tbs);
        cert.extend(&alg);
        cert.extend(encode(0x03, &[0]));
        let cert = Cert::from_der(&encode(0x30, &cert))?;
        Ok(Self::with_qualifiers(cert, qualifiers))
    }

    /// The authority: name and public key (`authority`).
    pub fn authority(&self) -> Authority {
        Authority {
            name: self.cert.subject().clone(),
            public_key: self.cert.public_key(),
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

    /// The trust qualifiers (`trust_qualifiers`).
    pub fn qualifiers(&self) -> &TrustQualifiers {
        &self.qualifiers
    }

    /// May the anchor appear as issuer in a path (`find_potential_issuers`
    /// of `SimpleTrustManager`)?
    pub fn can_issue(&self) -> bool {
        matches!(
            self.qualifiers.trusted_service_type,
            TrustedServiceType::Unspecified | TrustedServiceType::CertificateAuthority
        )
    }
}

/// A dynamic source of trust anchors (`TrustManager`), consulted in
/// addition to the anchors supplied to the
/// [`ValidationContextBuilder`](crate::ValidationContextBuilder), for
/// example a trusted list registry.
///
/// Path building asks the manager for anchors that may have issued a
/// certificate and whether a certificate is itself an anchor. Revocation
/// checks look up CRL and OCSP issuers among the supplied anchors, the other
/// certificates and the path being validated.
pub trait TrustManager: Send + Sync + std::fmt::Debug {
    /// `as_trust_anchor`: `cert` as a trust anchor, if the manager trusts it.
    fn as_trust_anchor(&self, cert: &Cert) -> Option<TrustAnchor>;

    /// `find_potential_issuers`: trust anchors whose name matches the issuer
    /// of `cert`. Path building still checks names, key identifiers and
    /// [`TrustAnchor::can_issue`].
    fn find_potential_issuers(&self, cert: &Cert) -> Vec<TrustAnchor>;
}

/// A name and a public key (`Authority` / `NamedKeyAuthority`).
#[derive(Clone, Debug)]
pub struct Authority {
    /// The authority's name.
    pub name: x509_cert::name::Name,
    /// Its public key.
    pub public_key: spki::SubjectPublicKeyInfoOwned,
}

impl PartialEq for Authority {
    fn eq(&self, other: &Self) -> bool {
        certval::compare_names(&self.name, &other.name) && self.public_key == other.public_key
    }
}
