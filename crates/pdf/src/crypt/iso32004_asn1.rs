// Derived from pyHanko `pdf_utils/crypt/_iso32004_asn1.py` (MIT, see LICENSE-pyHanko).

//! ASN.1 definitions of ISO 32004 (PDF MAC).

use super::asn1::{self, tag, Tlv};
use crate::error::{PdfError, PdfResult};

/// `id-pdfMacIntegrityInfo`: content type of the MAC'd data.
pub const PDF_MAC_INTEGRITY_INFO: &str = "1.0.32004.1.0";
/// `id-pdfMacWrapKdf`: KDF deriving the MAC key encryption key.
pub const PDF_MAC_WRAP_KDF: &str = "1.0.32004.1.1";
/// `id-pdfMacData`: unsigned attribute carrying a MAC token in a signature.
pub const PDF_MAC_DATA: &str = "1.0.32004.1.2";

/// `PdfMacIntegrityInfo ::= SEQUENCE { version INTEGER, dataDigest OCTET
/// STRING, signatureDigest [0] IMPLICIT OCTET STRING OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdfMacIntegrityInfo {
    /// Version (0).
    pub version: i64,
    /// Digest of the document byte range.
    pub data_digest: Vec<u8>,
    /// Digest of the signature value, for MACs attached to signatures.
    pub signature_digest: Option<Vec<u8>>,
}

impl PdfMacIntegrityInfo {
    /// DER encoding.
    pub fn to_der(&self) -> Vec<u8> {
        let version = asn1::uint(u64::try_from(self.version).unwrap_or(0));
        let dd = asn1::octets(&self.data_digest);
        match &self.signature_digest {
            Some(sd) => asn1::seq(&[&version, &dd, &asn1::tlv(0x80, sd)]),
            None => asn1::seq(&[&version, &dd]),
        }
    }

    /// Decode.
    pub fn from_der(data: &[u8]) -> PdfResult<Self> {
        let bad = || PdfError::Value("Malformed PdfMacIntegrityInfo".into());
        let t = Tlv::parse_exact(data).map_err(|_| bad())?;
        if t.tag != tag::SEQUENCE {
            return Err(bad());
        }
        let ch = t.children()?;
        let (version, dd, sd) = match ch.as_slice() {
            [v, dd] => (v, dd, None),
            [v, dd, sd] if sd.tag == 0x80 => (v, dd, Some(sd.value.to_vec())),
            _ => return Err(bad()),
        };
        if dd.tag != tag::OCTET_STRING {
            return Err(bad());
        }
        Ok(Self {
            version: version.small_int()?,
            data_digest: dd.value.to_vec(),
            signature_digest: sd,
        })
    }
}
