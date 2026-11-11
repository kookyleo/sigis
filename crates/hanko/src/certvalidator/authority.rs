// Partly derived from pyhanko-certvalidator `authority.py` (MIT, see LICENSE-pyHanko).

//! Certificates and trust anchors.

use std::sync::Arc;

use base64ct::Encoding;
use const_oid::AssociatedOid;
use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::certificate::{CertificateInner, Raw};
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage, KeyUsage,
};
use x509_cert::name::Name;

use crate::algorithms::DigestAlgorithm;
use crate::asn1::oids;
use crate::errors::ValidationError;
use crate::time::Moment;

/// A certificate decoded with the lenient `Raw` profile, which accepts
/// encodings that RFC 5280 forbids but real PKIs (and NIST PKITS) contain,
/// such as negative serial numbers.
pub type RawCertificate = CertificateInner<Raw>;

/// A parsed certificate together with its exact DER encoding.
#[derive(Clone, Debug)]
pub struct Cert {
    der: Arc<[u8]>,
    decoded: Arc<RawCertificate>,
}

impl PartialEq for Cert {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}

impl Eq for Cert {}

impl Cert {
    /// Parse a DER-encoded certificate.
    pub fn from_der(der: &[u8]) -> Result<Self, ValidationError> {
        let decoded = RawCertificate::from_der(der)
            .map_err(|e| ValidationError::Malformed(format!("certificate: {e}")))?;
        Ok(Self {
            der: der.into(),
            decoded: Arc::new(decoded),
        })
    }

    /// Parse a PEM or DER certificate.
    ///
    /// PEM parsing is lenient, as in asn1crypto: the first
    /// `CERTIFICATE` block is used, surrounding text is ignored, and base64
    /// lines may have any length.
    pub fn from_pem_or_der(bytes: &[u8]) -> Result<Self, ValidationError> {
        const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
        const END: &[u8] = b"-----END CERTIFICATE-----";
        let Some(start) = find(bytes, BEGIN) else {
            return Self::from_der(bytes);
        };
        let body = &bytes[start + BEGIN.len()..];
        let end = find(body, END)
            .ok_or_else(|| ValidationError::Malformed("certificate PEM: no END line".into()))?;
        let b64: Vec<u8> = body[..end]
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        let der = base64ct::Base64::decode_vec(core::str::from_utf8(&b64).unwrap_or(""))
            .map_err(|e| ValidationError::Malformed(format!("certificate PEM: {e}")))?;
        Self::from_der(&der)
    }

    /// The DER encoding.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The decoded certificate.
    pub fn decoded(&self) -> &RawCertificate {
        &self.decoded
    }

    /// Subject name.
    pub fn subject(&self) -> &Name {
        self.decoded.tbs_certificate().subject()
    }

    /// Issuer name.
    pub fn issuer(&self) -> &Name {
        self.decoded.tbs_certificate().issuer()
    }

    /// Serial number as encoded (big-endian two's complement).
    pub fn serial_bytes(&self) -> &[u8] {
        self.decoded.tbs_certificate().serial_number().as_bytes()
    }

    /// Subject public key info.
    pub fn public_key(&self) -> SubjectPublicKeyInfoOwned {
        self.decoded
            .tbs_certificate()
            .subject_public_key_info()
            .clone()
    }

    /// DER encoding of the subject name.
    pub fn subject_der(&self) -> Result<Vec<u8>, ValidationError> {
        Ok(self.subject().to_der()?)
    }

    /// SHA-256 digest of the DER encoding.
    pub fn sha256(&self) -> [u8; 32] {
        let digest = DigestAlgorithm::Sha256.digest(&self.der);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// `notBefore`.
    pub fn not_before(&self) -> Moment {
        Moment::from(self.decoded.tbs_certificate().validity().not_before)
    }

    /// `notAfter`.
    pub fn not_after(&self) -> Moment {
        Moment::from(self.decoded.tbs_certificate().validity().not_after)
    }

    /// Subject and issuer names are equal.
    pub fn is_self_issued(&self) -> bool {
        self.subject() == self.issuer()
    }

    /// Decode an extension. Malformed extensions are reported as errors.
    pub fn extension<'a, T>(&'a self) -> Result<Option<(bool, T)>, ValidationError>
    where
        T: Decode<'a, Error = der::Error> + AssociatedOid,
    {
        Ok(self.decoded.tbs_certificate().get_extension::<T>()?)
    }

    /// `basicConstraints` says this is a CA.
    pub fn is_ca(&self) -> bool {
        matches!(self.extension::<BasicConstraints>(), Ok(Some((_, bc))) if bc.ca)
    }

    /// Key usage, if present and well-formed.
    pub fn key_usage(&self) -> Option<KeyUsage> {
        self.extension::<KeyUsage>()
            .ok()
            .flatten()
            .map(|(_, ku)| ku)
    }

    /// Extended key usage OIDs, if present and well-formed.
    pub fn extended_key_usage(&self) -> Option<Vec<const_oid::ObjectIdentifier>> {
        self.extension::<ExtendedKeyUsage>()
            .ok()
            .flatten()
            .map(|(_, eku)| eku.0)
    }

    /// CRL distribution points, if present and well-formed.
    pub fn crl_distribution_points(&self) -> Option<CrlDistributionPoints> {
        self.extension::<CrlDistributionPoints>()
            .ok()
            .flatten()
            .map(|(_, dp)| dp)
    }

    /// The certificate names at least one OCSP responder in its AIA extension.
    pub fn declares_ocsp(&self) -> bool {
        matches!(
            self.extension::<AuthorityInfoAccessSyntax>(),
            Ok(Some((_, aia))) if aia.0.iter().any(|ad| ad.access_method == oids::AD_OCSP)
        )
    }

    /// The certificate has a CRL distribution points extension.
    pub fn declares_crl(&self) -> bool {
        self.crl_distribution_points()
            .is_some_and(|dps| !dps.0.is_empty())
    }

    /// The certificate has an extension with this OID.
    pub fn has_extension(&self, oid: &const_oid::ObjectIdentifier) -> bool {
        self.decoded
            .tbs_certificate()
            .extensions()
            .is_some_and(|exts| exts.iter().any(|e| e.extn_id == *oid))
    }

    /// `true` if `at` lies in `[notBefore - tolerance, notAfter + tolerance]`.
    pub fn valid_at(&self, at: Moment, tolerance: core::time::Duration) -> bool {
        at.plus(tolerance) >= self.not_before() && at.minus(tolerance) <= self.not_after()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

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
