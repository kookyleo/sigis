// Derived from pyHanko `sign/general.py` (MIT, see LICENSE-pyHanko).

//! Lenient parsing of CMS `SignedData` (RFC 5652) that keeps original
//! encodings, plus the certificate and attribute helpers of
//! `pyhanko.sign.general`.
//!
//! The RustCrypto `cms` crate decodes strictly and re-sorts `SET OF` values.
//! A signature over signed attributes must be checked against the bytes the
//! signer produced, and pyHanko tolerates harmless DER deviations there
//! (`test_tolerate_der_deviations`). Hence this module walks the structure
//! with [`sigis_pki_core::asn1::tlv`] and only decodes leaf values (algorithm
//! identifiers, names, attribute values) with `der`.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::name::Name;

use sigis_pki_certvalidator::names::check_name;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::ess::{EssCertId, EssCertIdV2, IssuerSerial};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::asn1::raw_oid::RawOid;
use sigis_pki_core::asn1::tlv::{self, tag, Tlv};
use sigis_pki_core::cert::Cert;

use crate::errors::{CmsError, CmsResult};

/// One CMS attribute (`CMSAttribute`): its type and the original encodings
/// of its values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmsAttribute {
    /// Attribute type.
    pub oid: RawOid,
    /// Original DER encoding of each value.
    pub values: Vec<Vec<u8>>,
}

/// Parse the contents octets of a `SET OF Attribute`, keeping the order and
/// duplicates as encoded.
pub fn parse_attributes(set_contents: &[u8]) -> CmsResult<Vec<CmsAttribute>> {
    tlv::parse_all(set_contents)?
        .into_iter()
        .map(|attr| {
            if !attr.is_universal(tag::SEQUENCE) {
                return Err(CmsError::Malformed("attribute is not a SEQUENCE".into()));
            }
            let parts = attr.children()?;
            let [oid, values] = parts.as_slice() else {
                return Err(CmsError::Malformed("attribute must have two fields".into()));
            };
            if !oid.is_universal(tag::OID) || !values.is_universal(tag::SET) {
                return Err(CmsError::Malformed("malformed attribute".into()));
            }
            let oid = RawOid::from_tlv(oid)?;
            let values = values
                .children()?
                .into_iter()
                .map(|v| v.raw.to_vec())
                .collect();
            Ok(CmsAttribute { oid, values })
        })
        .collect()
}

/// Failure of [`find_unique_cms_attribute`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AttributeLookupError {
    /// `NonexistentAttributeError`.
    #[error("Unable to locate attribute {0}.")]
    Nonexistent(String),
    /// `MultivaluedAttributeError`.
    #[error("Expected single-valued {0} attribute, but found multiple")]
    Multivalued(String),
}

/// All values of attributes of type `oid`, in order (`find_cms_attribute_iter`).
pub fn find_cms_attribute_iter<'a>(
    attrs: Option<&'a [CmsAttribute]>,
    oid: ObjectIdentifier,
) -> impl Iterator<Item = &'a [u8]> + 'a {
    attrs
        .unwrap_or_default()
        .iter()
        .filter(move |a| a.oid.is(&oid))
        .flat_map(|a| a.values.iter().map(Vec::as_slice))
}

/// The unique value of the attribute of type `oid`
/// (`find_unique_cms_attribute`): fails if there is none, or more than one
/// value across all attributes of that type.
pub fn find_unique_cms_attribute(
    attrs: Option<&[CmsAttribute]>,
    oid: ObjectIdentifier,
) -> Result<&[u8], AttributeLookupError> {
    let mut it = find_cms_attribute_iter(attrs, oid);
    let name = attribute_name(&RawOid::from(oid));
    let first = it
        .next()
        .ok_or_else(|| AttributeLookupError::Nonexistent(name.clone()))?;
    if it.next().is_some() {
        return Err(AttributeLookupError::Multivalued(name));
    }
    Ok(first)
}

/// The asn1crypto name of a CMS attribute type, or its dotted OID.
pub fn attribute_name(raw: &RawOid) -> String {
    let Some(oid) = raw.to_oid() else {
        return raw.dotted();
    };
    match oid {
        oids::CONTENT_TYPE => "content_type",
        oids::MESSAGE_DIGEST => "message_digest",
        oids::SIGNING_TIME => "signing_time",
        oids::COUNTER_SIGNATURE => "counter_signature",
        oids::CMS_ALGORITHM_PROTECTION => "cms_algorithm_protection",
        oids::AA_SIGNING_CERTIFICATE => "signing_certificate",
        oids::AA_SIGNING_CERTIFICATE_V2 => "signing_certificate_v2",
        oids::AA_SIGNATURE_TIME_STAMP_TOKEN => "signature_time_stamp_token",
        oids::AA_CONTENT_TIMESTAMP => "content_time_stamp",
        oids::AA_ETS_SIG_POLICY_ID => "signature_policy_identifier",
        oids::AA_ETS_COMMITMENT_TYPE => "commitment_type",
        oids::AA_SIGNER_ATTRIBUTES_V2 => "signer_attributes_v2",
        oids::ADBE_REVOCATION_INFO_ARCHIVAL => "adobe_revocation_info_archival",
        _ => return oid.to_string(),
    }
    .to_owned()
}

/// `SignerIdentifier`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerIdentifier {
    /// `issuerAndSerialNumber`, with the original encoding of the issuer name
    /// and the contents octets of the serial number.
    IssuerAndSerialNumber {
        /// Original DER of the issuer `Name`.
        issuer_der: Vec<u8>,
        /// Serial number contents octets.
        serial: Vec<u8>,
    },
    /// `subjectKeyIdentifier`.
    SubjectKeyIdentifier(Vec<u8>),
}

/// Signed attributes with their original encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAttributes {
    /// Contents octets of the `[0] IMPLICIT SET OF Attribute`, as encoded.
    pub contents: Vec<u8>,
    /// The parsed attributes.
    pub attrs: Vec<CmsAttribute>,
}

impl SignedAttributes {
    /// The bytes the signature covers: the attributes re-tagged as a
    /// universal `SET OF` (RFC 5652 §5.4), contents unchanged.
    pub fn signed_bytes(&self) -> Vec<u8> {
        tlv::encode(0x31, &self.contents)
    }
}

/// A `SignerInfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerInfo {
    /// `version` (1 or 3).
    pub version: u8,
    /// `sid`.
    pub sid: SignerIdentifier,
    /// `digestAlgorithm`.
    pub digest_algorithm: AlgorithmIdentifierOwned,
    /// `signedAttrs`.
    pub signed_attrs: Option<SignedAttributes>,
    /// `signatureAlgorithm`.
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// `signature`.
    pub signature: Vec<u8>,
    /// `unsignedAttrs`.
    pub unsigned_attrs: Option<Vec<CmsAttribute>>,
}

impl SignerInfo {
    /// Signed attributes, if any.
    pub fn signed_attr_list(&self) -> Option<&[CmsAttribute]> {
        self.signed_attrs.as_ref().map(|s| s.attrs.as_slice())
    }

    /// Unsigned attributes, if any.
    pub fn unsigned_attr_list(&self) -> Option<&[CmsAttribute]> {
        self.unsigned_attrs.as_deref()
    }

    /// The digest algorithm, if supported.
    pub fn digest(&self) -> Option<DigestAlgorithm> {
        DigestAlgorithm::from_oid(&self.digest_algorithm.oid)
    }
}

/// A parsed `SignedData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedData {
    /// `version`.
    pub version: u8,
    /// `digestAlgorithms`.
    pub digest_algorithms: Vec<AlgorithmIdentifierOwned>,
    /// `encapContentInfo.eContentType`.
    pub econtent_type: RawOid,
    /// `encapContentInfo.eContent` (the octets inside the OCTET STRING).
    pub econtent: Option<Vec<u8>>,
    /// Public-key certificates in `certificates`, as raw DER.
    pub certificates: Vec<Vec<u8>>,
    /// Version 2 attribute certificates in `certificates`, re-tagged as
    /// `SEQUENCE` (DER of `AttributeCertificate`).
    pub attribute_certificates: Vec<Vec<u8>>,
    /// `signerInfos`.
    pub signer_infos: Vec<SignerInfo>,
}

fn small_int(t: &Tlv<'_>) -> CmsResult<u8> {
    if !t.is_universal(tag::INTEGER) {
        return Err(CmsError::Malformed("expected INTEGER".into()));
    }
    match t.value {
        [v] => Ok(*v),
        _ => Err(CmsError::Malformed("version out of range".into())),
    }
}

fn alg_id(t: &Tlv<'_>) -> CmsResult<AlgorithmIdentifierOwned> {
    AlgorithmIdentifierOwned::from_der(t.raw)
        .map_err(|e| CmsError::Malformed(format!("algorithm identifier: {e}")))
}

/// The contents of an OCTET STRING, joining the segments of a constructed
/// (BER) encoding.
pub(crate) fn octet_string_contents(t: &Tlv<'_>) -> CmsResult<Vec<u8>> {
    if t.class != tlv::Class::Universal || t.number != tag::OCTET_STRING {
        return Err(CmsError::Malformed("expected OCTET STRING".into()));
    }
    if !t.constructed {
        return Ok(t.value.to_vec());
    }
    let mut out = Vec::new();
    for child in t.children()? {
        out.extend(octet_string_contents(&child)?);
    }
    Ok(out)
}

impl SignerInfo {
    /// Parse a DER `SignerInfo`.
    pub fn from_der(der: &[u8]) -> CmsResult<Self> {
        Self::from_tlv(&Tlv::parse_exact(der)?)
    }

    fn from_tlv(t: &Tlv<'_>) -> CmsResult<Self> {
        if !t.is_universal(tag::SEQUENCE) {
            return Err(CmsError::Malformed("SignerInfo is not a SEQUENCE".into()));
        }
        let fields = t.children()?;
        let mut it = fields.iter().peekable();
        let mut next = |what: &str| {
            it.next()
                .ok_or_else(|| CmsError::Malformed(format!("SignerInfo: missing {what}")))
        };
        let version = small_int(next("version")?)?;
        let sid_tlv = next("sid")?;
        let sid = if sid_tlv.is_universal(tag::SEQUENCE) {
            let parts = sid_tlv.children()?;
            let [issuer, serial] = parts.as_slice() else {
                return Err(CmsError::Malformed("IssuerAndSerialNumber".into()));
            };
            if !issuer.is_universal(tag::SEQUENCE) || !serial.is_universal(tag::INTEGER) {
                return Err(CmsError::Malformed("IssuerAndSerialNumber".into()));
            }
            SignerIdentifier::IssuerAndSerialNumber {
                issuer_der: issuer.raw.to_vec(),
                serial: serial.value.to_vec(),
            }
        } else if sid_tlv.is_context(0) && !sid_tlv.constructed {
            SignerIdentifier::SubjectKeyIdentifier(sid_tlv.value.to_vec())
        } else {
            return Err(CmsError::Malformed("unsupported SignerIdentifier".into()));
        };
        let digest_algorithm = alg_id(next("digestAlgorithm")?)?;
        let mut cur = next("signatureAlgorithm")?;
        let signed_attrs = if cur.is_context(0) && cur.constructed {
            let attrs = parse_attributes(cur.value)?;
            let sa = SignedAttributes {
                contents: cur.value.to_vec(),
                attrs,
            };
            cur = next("signatureAlgorithm")?;
            Some(sa)
        } else {
            None
        };
        let signature_algorithm = alg_id(cur)?;
        let signature = octet_string_contents(next("signature")?)?;
        let unsigned_attrs = match it.next() {
            Some(u) if u.is_context(1) && u.constructed => Some(parse_attributes(u.value)?),
            Some(_) => return Err(CmsError::Malformed("SignerInfo: unexpected field".into())),
            None => None,
        };
        if it.next().is_some() {
            return Err(CmsError::Malformed("SignerInfo: trailing fields".into()));
        }
        Ok(Self {
            version,
            sid,
            digest_algorithm,
            signed_attrs,
            signature_algorithm,
            signature,
            unsigned_attrs,
        })
    }
}

impl SignedData {
    /// Parse a DER `ContentInfo` whose content type is `signedData`.
    pub fn from_content_info_der(der: &[u8]) -> CmsResult<Self> {
        let ci = Tlv::parse_exact(der)?;
        if !ci.is_universal(tag::SEQUENCE) {
            return Err(CmsError::Malformed("ContentInfo is not a SEQUENCE".into()));
        }
        let parts = ci.children()?;
        let [ct, content] = parts.as_slice() else {
            return Err(CmsError::Malformed(
                "ContentInfo must have two fields".into(),
            ));
        };
        if !RawOid::from_tlv(ct)?.is(&oids::CT_SIGNED_DATA) {
            return Err(CmsError::Malformed(
                "ContentInfo does not contain SignedData".into(),
            ));
        }
        if !content.is_context(0) || !content.constructed {
            return Err(CmsError::Malformed(
                "ContentInfo content must be [0] EXPLICIT".into(),
            ));
        }
        let inner = Tlv::parse_exact(content.value)?;
        Self::from_tlv(&inner)
    }

    /// Parse either a `ContentInfo` wrapping `SignedData` or a bare
    /// `SignedData`.
    pub fn from_der(der: &[u8]) -> CmsResult<Self> {
        Self::from_content_info_der(der).or_else(|e| {
            let t = Tlv::parse_exact(der).map_err(|_| e.clone())?;
            // A bare SignedData starts with an INTEGER version; a ContentInfo
            // with an OID.
            match t.children().ok().and_then(|c| c.first().copied()) {
                Some(first) if first.is_universal(tag::INTEGER) => Self::from_tlv(&t),
                _ => Err(e),
            }
        })
    }

    fn from_tlv(t: &Tlv<'_>) -> CmsResult<Self> {
        if !t.is_universal(tag::SEQUENCE) {
            return Err(CmsError::Malformed("SignedData is not a SEQUENCE".into()));
        }
        let fields = t.children()?;
        let mut it = fields.iter();
        let mut next = |what: &str| {
            it.next()
                .ok_or_else(|| CmsError::Malformed(format!("SignedData: missing {what}")))
        };
        let version = small_int(next("version")?)?;
        let algs = next("digestAlgorithms")?;
        if !algs.is_universal(tag::SET) {
            return Err(CmsError::Malformed("digestAlgorithms is not a SET".into()));
        }
        let digest_algorithms = algs
            .children()?
            .iter()
            .map(alg_id)
            .collect::<CmsResult<Vec<_>>>()?;
        let eci = next("encapContentInfo")?;
        if !eci.is_universal(tag::SEQUENCE) {
            return Err(CmsError::Malformed(
                "encapContentInfo is not a SEQUENCE".into(),
            ));
        }
        let eci_parts = eci.children()?;
        let (econtent_type, econtent) = match eci_parts.as_slice() {
            [ct] => (RawOid::from_tlv(ct)?, None),
            [ct, c] if c.is_context(0) && c.constructed => {
                let octets = Tlv::parse_exact(c.value)?;
                (RawOid::from_tlv(ct)?, Some(octet_string_contents(&octets)?))
            }
            _ => return Err(CmsError::Malformed("malformed encapContentInfo".into())),
        };
        let mut certificates = Vec::new();
        let mut attribute_certificates = Vec::new();
        let mut cur = next("signerInfos")?;
        if cur.is_context(0) && cur.constructed {
            for choice in cur.children()? {
                if choice.is_universal(tag::SEQUENCE) {
                    certificates.push(choice.raw.to_vec());
                } else if choice.is_context(2) && choice.constructed {
                    attribute_certificates.push(tlv::retag(&choice, 0x30));
                }
                // v1 attribute certificates and other formats are ignored,
                // as in pyHanko.
            }
            cur = next("signerInfos")?;
        }
        if cur.is_context(1) && cur.constructed {
            // Revocation information choices: not used here.
            cur = next("signerInfos")?;
        }
        if !cur.is_universal(tag::SET) {
            return Err(CmsError::Malformed("signerInfos is not a SET".into()));
        }
        let signer_infos = cur
            .children()?
            .iter()
            .map(SignerInfo::from_tlv)
            .collect::<CmsResult<Vec<_>>>()?;
        Ok(Self {
            version,
            digest_algorithms,
            econtent_type,
            econtent,
            certificates,
            attribute_certificates,
            signer_infos,
        })
    }
}

/// Certificates embedded in a `SignedData` (`SignedDataCerts`).
#[derive(Clone, Debug)]
pub struct SignedDataCerts {
    /// The signer's certificate.
    pub signer_cert: Cert,
    /// Other public-key certificates.
    pub other_certs: Vec<Cert>,
    /// Attribute certificates (DER).
    pub attribute_certs: Vec<Vec<u8>>,
}

/// The unique `SignerInfo` (`extract_signer_info`).
pub fn extract_signer_info(sd: &SignedData) -> CmsResult<&SignerInfo> {
    match sd.signer_infos.as_slice() {
        [si] => Ok(si),
        _ => Err(CmsError::Extraction(
            "signer_infos should contain exactly one entry".into(),
        )),
    }
}

/// Strip redundant sign-extension octets of an INTEGER's contents.
fn normalize_int(bytes: &[u8]) -> &[u8] {
    let mut b = bytes;
    while b.len() > 1 && ((b[0] == 0 && b[1] & 0x80 == 0) || (b[0] == 0xff && b[1] & 0x80 != 0)) {
        b = &b[1..];
    }
    b
}

/// Issuer comparison as `match_issuer_serial` does it: byte equality, else
/// asn1crypto name equality, which fails (no match) for names that do not
/// survive string preparation.
fn names_match(expected_der: &[u8], cert: &Cert, allow_bytes: bool) -> bool {
    if allow_bytes && cert.issuer().to_der().is_ok_and(|d| d == expected_der) {
        return true;
    }
    match Name::from_der(expected_der) {
        Ok(name) => {
            check_name(&name).is_ok()
                && check_name(cert.issuer()).is_ok()
                && certval::compare_names(&name, cert.issuer())
        }
        Err(_) => false,
    }
}

/// `match_issuer_serial` for an `IssuerAndSerialNumber`.
pub fn match_issuer_and_serial(issuer_der: &[u8], serial: &[u8], cert: &Cert) -> bool {
    names_match(issuer_der, cert, true)
        && normalize_int(serial) == normalize_int(cert.serial_bytes())
}

/// `match_issuer_serial` for an ESS `IssuerSerial`: the issuer must be
/// exactly one directory name.
pub fn match_ess_issuer_serial(expected: &IssuerSerial, cert: &Cert) -> bool {
    let [GeneralName::DirectoryName(name)] = expected.issuer.as_slice() else {
        return false;
    };
    // pyHanko compares the encoding of the `[4]`-tagged general name with
    // the certificate's issuer, which never matches; only name equality
    // counts.
    let issuer_match = match name.to_der() {
        Ok(der) => names_match(&der, cert, false),
        Err(_) => false,
    };
    issuer_match
        && normalize_int(expected.serial_number.as_bytes()) == normalize_int(cert.serial_bytes())
}

/// An `ESSCertID` or `ESSCertIDv2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EssCertIdAny {
    /// `ESSCertID` (SHA-1).
    V1(EssCertId),
    /// `ESSCertIDv2`.
    V2(EssCertIdV2),
}

/// `check_ess_certid`: does the identifier refer to `cert`? Identifiers
/// with a digest algorithm that is not supported never match.
pub fn check_ess_certid(cert: &Cert, certid: &EssCertIdAny) -> bool {
    let (digest, hash, issuer_serial) = match certid {
        EssCertIdAny::V1(id) => (
            Some(DigestAlgorithm::Sha1),
            id.cert_hash.as_bytes(),
            id.issuer_serial.as_ref(),
        ),
        EssCertIdAny::V2(id) => (
            id.digest_algorithm(),
            id.cert_hash.as_bytes(),
            id.issuer_serial.as_ref(),
        ),
    };
    let Some(digest) = digest else {
        return false;
    };
    if digest.digest(cert.der()) != hash {
        return false;
    }
    issuer_serial.is_none_or(|is| match_ess_issuer_serial(is, cert))
}

fn signer_predicate(sid: &SignerIdentifier, cert: &Cert) -> bool {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber { issuer_der, serial } => {
            match_issuer_and_serial(issuer_der, serial, cert)
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => matches!(
            cert.extension::<SubjectKeyIdentifier>(),
            Ok(Some((_, k))) if k.0.as_bytes() == ski.as_slice()
        ),
    }
}

/// Classify the embedded certificates and find the signer's
/// (`extract_certificate_info`). Certificates that cannot be decoded are
/// skipped (they cannot take part in path building anyway).
pub fn extract_certificate_info(sd: &SignedData) -> CmsResult<SignedDataCerts> {
    let si = extract_signer_info(sd)?;
    let mut signer_cert = None;
    let mut other_certs = Vec::new();
    for der in &sd.certificates {
        let Ok(cert) = Cert::from_der(der) else {
            continue;
        };
        if signer_predicate(&si.sid, &cert) {
            signer_cert = Some(cert);
        } else {
            other_certs.push(cert);
        }
    }
    let signer_cert = signer_cert.ok_or_else(|| {
        CmsError::Extraction("signer certificate not included in signature".into())
    })?;
    Ok(SignedDataCerts {
        signer_cert,
        other_certs,
        attribute_certs: sd.attribute_certificates.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_lookup() {
        let a = CmsAttribute {
            oid: oids::CONTENT_TYPE.into(),
            values: vec![vec![1], vec![2]],
        };
        let b = CmsAttribute {
            oid: oids::MESSAGE_DIGEST.into(),
            values: vec![vec![3]],
        };
        let attrs = vec![a, b.clone(), b];
        let list = Some(attrs.as_slice());
        assert_eq!(
            find_cms_attribute_iter(list, oids::CONTENT_TYPE).collect::<Vec<_>>(),
            vec![&[1u8][..], &[2u8][..]]
        );
        assert_eq!(
            find_unique_cms_attribute(list, oids::MESSAGE_DIGEST),
            Err(AttributeLookupError::Multivalued("message_digest".into()))
        );
        assert_eq!(
            find_unique_cms_attribute(None, oids::SIGNING_TIME),
            Err(AttributeLookupError::Nonexistent("signing_time".into()))
        );
    }

    #[test]
    fn normalizes_integers() {
        assert_eq!(normalize_int(&[0, 0x7f]), &[0x7f]);
        assert_eq!(normalize_int(&[0, 0x80]), &[0, 0x80]);
        assert_eq!(normalize_int(&[0xff, 0xff, 0x80]), &[0x80]);
    }
}
