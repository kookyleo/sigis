// Derived from pyHanko `sign/attributes.py`, `sign/ades/api.py`,
// `sign/ades/cades_asn1.py` and the attribute helpers of `sign/general.py`
// (MIT, see LICENSE-pyHanko).

//! CMS signed and unsigned attributes produced by the signers
//! (`pyhanko.sign.attributes`, `pyhanko.sign.ades`).

use const_oid::ObjectIdentifier as Oid;
use der::asn1::{OctetString, SetOfVec};
use der::{Any, Decode, Encode, Sequence};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::commitment::{CommitmentType, CommitmentTypeIndication};
use sigis_pki_core::asn1::ess::{EssCertId, IssuerSerial, SigningCertificate, SigningCertificateV2};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::asn1::sig_policy::SignaturePolicyIdentifier;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};
use sigis_pki_core::time::Moment;
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;

/// `id-aa-CMSAlgorithmProtection` (RFC 6211).
pub const CMS_ALGORITHM_PROTECTION: Oid = Oid::new_unwrap("1.2.840.113549.1.9.52");
/// Adobe `revocationInfoArchival`.
pub const ADOBE_REVOCATION_INFO_ARCHIVAL: Oid = Oid::new_unwrap("1.2.840.113583.1.1.8");
/// `id-aa-ets-contentTimestamp`.
pub const CONTENT_TIME_STAMP: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.20");
/// `id-aa-ets-signerAttrV2` (ETSI EN 319 122-1).
pub const SIGNER_ATTRIBUTES_V2: Oid = Oid::new_unwrap("0.4.0.19122.1.1");
/// `id-data`.
pub const ID_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
/// `id-signedData`.
pub const ID_SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
/// `id-ct-TSTInfo`.
pub const ID_CT_TST_INFO: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// Build a single-valued attribute (`simple_cms_attribute`).
pub fn simple_attribute<T: Encode>(oid: Oid, value: &T) -> Result<Attribute> {
    let mut values = SetOfVec::new();
    values.insert(Any::from_der(&value.to_der()?)?)?;
    Ok(Attribute { oid, values })
}

/// Build an attribute from an already DER-encoded value.
pub fn raw_attribute(oid: Oid, value_der: &[u8]) -> Result<Attribute> {
    let mut values = SetOfVec::new();
    values.insert(Any::from_der(value_der)?)?;
    Ok(Attribute { oid, values })
}

/// A `Time` value as pyHanko encodes `signingTime`: always `UTCTime`.
pub fn utc_time(at: Moment) -> Result<x509_cert::time::Time> {
    let dt = at
        .to_der_datetime()
        .ok_or_else(|| HankoError::Signing(format!("time {at} cannot be encoded")))?;
    Ok(x509_cert::time::Time::UtcTime(der::asn1::UtcTime::from_date_time(dt)?))
}

/// `SigningCertificate` (ESS v1, SHA-1) for `cert` (`as_signing_certificate`).
pub fn as_signing_certificate(cert: &Cert) -> Result<SigningCertificate> {
    Ok(SigningCertificate {
        certs: vec![EssCertId {
            cert_hash: OctetString::new(DigestAlgorithm::Sha1.digest(cert.der()))?,
            issuer_serial: Some(IssuerSerial::for_certificate(cert.decoded())?),
        }],
        policies: None,
    })
}

/// `SigningCertificateV2` for `cert` (`as_signing_certificate_v2`).
pub fn as_signing_certificate_v2(cert: &Cert, digest: DigestAlgorithm) -> Result<SigningCertificateV2> {
    let mut v2 = SigningCertificateV2::for_signer(cert.decoded(), digest)?;
    // `for_signer` re-encodes the certificate; hash the exact DER instead.
    if let Some(first) = v2.certs.first_mut() {
        first.cert_hash = OctetString::new(digest.digest(cert.der()))?;
    }
    Ok(v2)
}

/// `CMSAlgorithmProtection` (RFC 6211).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CmsAlgorithmProtection {
    /// Digest algorithm.
    pub digest_algorithm: AlgorithmIdentifierOwned,
    /// Signature algorithm.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub signature_algorithm: Option<AlgorithmIdentifierOwned>,
    /// MAC algorithm.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub mac_algorithm: Option<AlgorithmIdentifierOwned>,
}

/// Adobe `RevocationInfoArchival`; CRLs and OCSP responses are kept as DER.
#[derive(Clone, Debug, Default, Eq, PartialEq, Sequence)]
pub struct RevocationInfoArchival {
    /// CRLs.
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub crl: Option<Vec<Any>>,
    /// OCSP responses.
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub ocsp: Option<Vec<Any>>,
    /// Other revocation information.
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub other_rev_info: Option<Vec<Any>>,
}

impl RevocationInfoArchival {
    /// Build from DER-encoded OCSP responses and CRLs (`Signer.format_revinfo`).
    /// Returns `None` if both lists are empty.
    pub fn from_der_lists(ocsps: &[Vec<u8>], crls: &[Vec<u8>]) -> Result<Option<Self>> {
        if ocsps.is_empty() && crls.is_empty() {
            return Ok(None);
        }
        let conv = |items: &[Vec<u8>]| -> Result<Option<Vec<Any>>> {
            if items.is_empty() {
                return Ok(None);
            }
            Ok(Some(
                items
                    .iter()
                    .map(|d| Any::from_der(d))
                    .collect::<der::Result<Vec<_>>>()?,
            ))
        };
        Ok(Some(Self {
            crl: conv(crls)?,
            ocsp: conv(ocsps)?,
            other_rev_info: None,
        }))
    }
}

/// Generic commitment types (`GenericCommitment`).
pub type GenericCommitment = CommitmentType;

/// A `CommitmentTypeIndication` for a generic commitment type
/// (`GenericCommitment.asn1`).
pub fn commitment_indication(c: GenericCommitment) -> CommitmentTypeIndication {
    CommitmentTypeIndication {
        commitment_type_id: c.oid(),
        commitment_type_qualifier: None,
    }
}

/// `SignerAttributesV2` (ETSI EN 319 122-1); attribute certificates and
/// claimed attributes are kept as DER.
#[derive(Clone, Debug, Default, Eq, PartialEq, Sequence)]
pub struct SignerAttributesV2 {
    /// Claimed attributes (`SEQUENCE OF Attribute`).
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub claimed_attributes: Option<Vec<Any>>,
    /// Certified attributes (`SEQUENCE OF CertifiedAttributeChoices`).
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub certified_attributes_v2: Option<Vec<Any>>,
    /// Signed assertions.
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub signed_assertions: Option<Vec<Any>>,
}

/// Signer attributes for `signer-attributes-v2` (`SignerAttrSpec`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignerAttrSpec {
    /// DER-encoded `AttCertAttribute` values claimed by the signer.
    pub claimed_attrs: Vec<Vec<u8>>,
    /// DER-encoded `AttributeCertificateV2` values.
    pub certified_attrs: Vec<Vec<u8>>,
}

impl SignerAttrSpec {
    /// Build the attribute value (`SignerAttributesProvider`).
    pub fn to_asn1(&self) -> Result<SignerAttributesV2> {
        let mut out = SignerAttributesV2::default();
        if !self.claimed_attrs.is_empty() {
            out.claimed_attributes = Some(
                self.claimed_attrs
                    .iter()
                    .map(|d| Any::from_der(d))
                    .collect::<der::Result<_>>()?,
            );
        }
        if !self.certified_attrs.is_empty() {
            // CertifiedAttributeChoices: attr_cert [0] EXPLICIT.
            let mut items = Vec::new();
            for ac in &self.certified_attrs {
                let inner = Any::from_der(ac)?;
                let tagged = der::asn1::ContextSpecific {
                    tag_number: der::TagNumber(0),
                    tag_mode: der::TagMode::Explicit,
                    value: inner,
                };
                items.push(Any::encode_from(&tagged)?);
            }
            out.certified_attributes_v2 = Some(items);
        }
        Ok(out)
    }
}

/// CAdES signed attribute settings (`CAdESSignedAttrSpec`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CadesSignedAttrSpec {
    /// `commitment-type-indication`.
    pub commitment_type: Option<CommitmentTypeIndication>,
    /// Add a signed content timestamp (`content-time-stamp`).
    pub timestamp_content: bool,
    /// `signature-policy-identifier`.
    pub signature_policy_identifier: Option<SignaturePolicyIdentifier>,
    /// `signer-attributes-v2`.
    pub signer_attributes: Option<SignerAttrSpec>,
}

/// Signed attribute settings (`PdfCMSSignedAttributes`).
#[derive(Clone, Debug, Default)]
pub struct CmsSignedAttributes {
    /// `signingTime`; ignored for PAdES.
    pub signing_time: Option<Moment>,
    /// CAdES attributes.
    pub cades_signed_attrs: Option<CadesSignedAttrSpec>,
    /// Adobe-style revocation information (signed attribute).
    pub adobe_revinfo_attr: Option<RevocationInfoArchival>,
}

/// Decode attribute values of `oid` in `attrs` (helper for tests and
/// interrupted signing).
pub fn find_attribute<'a>(attrs: &'a [Attribute], oid: &Oid) -> Option<&'a Attribute> {
    attrs.iter().find(|a| a.oid == *oid)
}

/// Convenience: the `content-type` attribute.
pub fn content_type_attribute(content_type: Oid) -> Result<Attribute> {
    simple_attribute(oids::CONTENT_TYPE, &content_type)
}

/// Convenience: the `message-digest` attribute.
pub fn message_digest_attribute(digest: &[u8]) -> Result<Attribute> {
    simple_attribute(oids::MESSAGE_DIGEST, &OctetString::new(digest)?)
}
