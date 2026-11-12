// Derived from the discovery parts of pyHanko
// `sign/validation/pdf_embedded.py` (`EmbeddedPdfSignature`) (MIT, see
// LICENSE-pyHanko).

//! Signatures already embedded in a document, as needed by the signing
//! workflows (DSS updates, LTA renewal). Lane B's `PdfFile::
//! embedded_signatures` replaces this once it lands.

use sigis_pki_core::errors::{HankoError, Result};
use lopdf::{Object, ObjectId};

use crate::pdf::fields::enumerate_sig_fields;
use crate::pdf::writer::PdfUpdate;

/// A filled signature field.
#[derive(Clone, Debug)]
pub struct EmbeddedSig {
    /// Fully qualified field name.
    pub field_name: String,
    /// Field object.
    pub field_id: ObjectId,
    /// Signature dictionary, if indirect.
    pub sig_id: Option<ObjectId>,
    /// `/Contents` including padding.
    pub contents: Vec<u8>,
    /// `/ByteRange`.
    pub byte_range: Vec<i64>,
    /// `/Type` is `/DocTimeStamp`.
    pub is_doc_timestamp: bool,
}

impl EmbeddedSig {
    /// The DER CMS object without padding.
    pub fn cms(&self) -> &[u8] {
        let c = &self.contents;
        let len = der_tlv_len(c).unwrap_or(c.len()).min(c.len());
        &c[..len]
    }

    /// The end offset of the signed revision.
    pub fn signed_end(&self) -> Option<usize> {
        let br = &self.byte_range;
        (br.len() == 4).then(|| usize::try_from(br[2] + br[3]).ok()).flatten()
    }
}

/// Total length of the first DER TLV in `c`.
pub fn der_tlv_len(c: &[u8]) -> Option<usize> {
    let l0 = usize::from(*c.get(1)?);
    if l0 < 0x80 {
        return Some(2 + l0);
    }
    let n = l0 & 0x7f;
    if n > 4 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | usize::from(*c.get(2 + i)?);
    }
    Some(2 + n + len)
}

/// Filled signature fields of the latest revision, ordered by the end of
/// their byte range (i.e. by signing order).
pub fn embedded_signatures(update: &PdfUpdate) -> Result<Vec<EmbeddedSig>> {
    let mut out = Vec::new();
    for f in enumerate_sig_fields(update, Some(true), None)? {
        let field = update.get_dict(f.id)?;
        let sig_obj = field.get(b"V").map_err(|_| HankoError::Malformed("no /V".into()))?;
        let sig_id = sig_obj.as_reference().ok();
        let Object::Dictionary(sig) = update.resolve(sig_obj)? else {
            continue;
        };
        let contents = match update.dict_get(sig, b"Contents")? {
            Some(Object::String(s, _)) => s.clone(),
            _ => continue,
        };
        let byte_range = match update.dict_get(sig, b"ByteRange")? {
            Some(Object::Array(a)) => a.iter().filter_map(|o| o.as_i64().ok()).collect(),
            _ => continue,
        };
        let is_doc_timestamp = matches!(
            update.dict_get(sig, b"Type")?,
            Some(Object::Name(n)) if n == b"DocTimeStamp"
        );
        out.push(EmbeddedSig {
            field_name: f.name,
            field_id: f.id,
            sig_id,
            contents,
            byte_range,
            is_doc_timestamp,
        });
    }
    out.sort_by_key(|s| s.signed_end().unwrap_or(0));
    Ok(out)
}
