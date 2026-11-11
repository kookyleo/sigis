//! Enhanced Security Services signing-certificate attributes.
//!
//! - `SigningCertificate` / `ESSCertID` (RFC 2634, SHA-1 only).
//! - `SigningCertificateV2` / `ESSCertIDv2` (RFC 5035).
//!
//! PAdES and CAdES baseline signatures carry `SigningCertificateV2` as a signed
//! attribute so that the signer certificate cannot be substituted.

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::OctetString;
use der::{Encode, Sequence};
use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::{CertificateInner, Profile};
use x509_cert::ext::pkix::certpolicy::PolicyInformation;
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::serial_number::SerialNumber;

use super::oids;
use crate::algorithms::DigestAlgorithm;

/// `IssuerSerial` (RFC 5035): the issuer name and serial number of a certificate.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct IssuerSerial {
    /// Issuer, as a list of general names (normally one directory name).
    pub issuer: GeneralNames,
    /// Serial number.
    pub serial_number: SerialNumber,
}

impl IssuerSerial {
    /// The issuer and serial number of `cert`.
    pub fn for_certificate<P: Profile>(cert: &CertificateInner<P>) -> der::Result<Self> {
        let tbs = cert.tbs_certificate();
        Ok(Self {
            issuer: vec![GeneralName::DirectoryName(tbs.issuer().clone())],
            serial_number: SerialNumber::new(tbs.serial_number().as_bytes())?,
        })
    }

    /// `true` if this names the issuer and serial number of `cert`.
    pub fn matches<P: Profile>(&self, cert: &CertificateInner<P>) -> bool {
        let tbs = cert.tbs_certificate();
        let issuer_matches = self
            .issuer
            .iter()
            .any(|name| matches!(name, GeneralName::DirectoryName(dn) if dn == tbs.issuer()));
        issuer_matches && self.serial_number.as_bytes() == tbs.serial_number().as_bytes()
    }
}

/// `ESSCertID` (RFC 2634): SHA-1 digest of a certificate.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EssCertId {
    /// SHA-1 digest of the DER-encoded certificate.
    pub cert_hash: OctetString,
    /// Issuer and serial number of the certificate.
    #[asn1(optional = "true")]
    pub issuer_serial: Option<IssuerSerial>,
}

/// `SigningCertificate` attribute value (RFC 2634).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SigningCertificate {
    /// The signer certificate first, then optionally certificates of its path.
    pub certs: Vec<EssCertId>,
    /// Certificate policies (rarely used).
    #[asn1(optional = "true")]
    pub policies: Option<Vec<PolicyInformation>>,
}

impl AssociatedOid for SigningCertificate {
    const OID: ObjectIdentifier = oids::AA_SIGNING_CERTIFICATE;
}

/// `ESSCertIDv2` (RFC 5035).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EssCertIdV2 {
    /// Digest algorithm. Absent means SHA-256 (the ASN.1 `DEFAULT`); use
    /// [`EssCertIdV2::digest_algorithm`] to read it.
    #[asn1(optional = "true")]
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    /// Digest of the DER-encoded certificate.
    pub cert_hash: OctetString,
    /// Issuer and serial number of the certificate.
    #[asn1(optional = "true")]
    pub issuer_serial: Option<IssuerSerial>,
}

impl EssCertIdV2 {
    /// Build an identifier for `cert` using `digest`. SHA-256 is encoded by
    /// omission, as DER requires for a `DEFAULT` value.
    pub fn for_certificate<P: Profile>(
        cert: &CertificateInner<P>,
        digest: DigestAlgorithm,
    ) -> der::Result<Self> {
        let der = cert.to_der()?;
        Ok(Self {
            hash_algorithm: (digest != DigestAlgorithm::Sha256)
                .then(|| digest.algorithm_identifier()),
            cert_hash: OctetString::new(digest.digest(&der))?,
            issuer_serial: Some(IssuerSerial::for_certificate(cert)?),
        })
    }

    /// The digest algorithm OID, applying the SHA-256 default.
    pub fn digest_algorithm_oid(&self) -> ObjectIdentifier {
        self.hash_algorithm
            .as_ref()
            .map_or(oids::SHA256, |alg| alg.oid)
    }

    /// The digest algorithm, if supported.
    pub fn digest_algorithm(&self) -> Option<DigestAlgorithm> {
        DigestAlgorithm::from_oid(&self.digest_algorithm_oid())
    }

    /// Check whether this identifier refers to the certificate with DER
    /// encoding `cert_der`. Returns `None` if the digest algorithm is not
    /// supported.
    pub fn matches_der(&self, cert_der: &[u8]) -> Option<bool> {
        let digest = self.digest_algorithm()?;
        Some(digest.digest(cert_der) == self.cert_hash.as_bytes())
    }
}

/// `SigningCertificateV2` attribute value (RFC 5035).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SigningCertificateV2 {
    /// The signer certificate first, then optionally certificates of its path.
    pub certs: Vec<EssCertIdV2>,
    /// Certificate policies (rarely used).
    #[asn1(optional = "true")]
    pub policies: Option<Vec<PolicyInformation>>,
}

impl AssociatedOid for SigningCertificateV2 {
    const OID: ObjectIdentifier = oids::AA_SIGNING_CERTIFICATE_V2;
}

impl SigningCertificateV2 {
    /// Build the attribute value for a single signer certificate.
    pub fn for_signer<P: Profile>(
        cert: &CertificateInner<P>,
        digest: DigestAlgorithm,
    ) -> der::Result<Self> {
        Ok(Self {
            certs: vec![EssCertIdV2::for_certificate(cert, digest)?],
            policies: None,
        })
    }

    /// Check that the first `ESSCertIDv2` refers to `cert` (by digest and, if
    /// present, by issuer and serial number), as RFC 5035 requires for the
    /// signer certificate.
    pub fn matches_signer<P: Profile>(
        &self,
        cert: &CertificateInner<P>,
    ) -> Result<bool, der::Error> {
        let Some(first) = self.certs.first() else {
            return Ok(false);
        };
        let der = cert.to_der()?;
        let hash_ok = first.matches_der(&der).unwrap_or(false);
        let issuer_ok = first
            .issuer_serial
            .as_ref()
            .is_none_or(|is| is.matches(cert));
        Ok(hash_ok && issuer_ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, DecodePem};
    use x509_cert::Certificate;

    const ROOT_PEM: &str =
        include_str!("../../../hanko-testdata/data/sigis-generated/rsa-sha256.cert.pem");
    const INTERM_PEM: &str =
        include_str!("../../../hanko-testdata/data/sigis-generated/ec-p256-sha256.cert.pem");

    #[test]
    fn signing_certificate_v2_round_trip_and_match() {
        let root = Certificate::from_pem(ROOT_PEM).expect("root");
        let interm = Certificate::from_pem(INTERM_PEM).expect("interm");
        for digest in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha384] {
            let attr = SigningCertificateV2::for_signer(&root, digest).expect("build");
            let der = attr.to_der().expect("encode");
            let decoded = SigningCertificateV2::from_der(&der).expect("decode");
            assert_eq!(decoded, attr);
            assert_eq!(decoded.certs[0].digest_algorithm(), Some(digest));
            assert!(decoded.matches_signer(&root).expect("match"));
            assert!(!decoded.matches_signer(&interm).expect("match"));
        }
    }

    #[test]
    fn sha256_default_is_omitted() {
        let root = Certificate::from_pem(ROOT_PEM).expect("root");
        let id = EssCertIdV2::for_certificate(&root, DigestAlgorithm::Sha256).expect("build");
        assert!(id.hash_algorithm.is_none());
        assert_eq!(id.digest_algorithm_oid(), oids::SHA256);
    }

    #[test]
    fn rejects_truncated_input() {
        let root = Certificate::from_pem(ROOT_PEM).expect("root");
        let der = SigningCertificateV2::for_signer(&root, DigestAlgorithm::Sha256)
            .and_then(|a| a.to_der())
            .expect("encode");
        for len in 0..der.len() {
            assert!(SigningCertificateV2::from_der(&der[..len]).is_err());
        }
    }
}
