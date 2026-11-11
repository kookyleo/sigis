// Derived from pyHanko `sign/validation/pdf_embedded.py`, `status.py`,
// `__init__.py` (MIT, see LICENSE-pyHanko).

//! Validation of signatures embedded in PDF files
//! (`pyhanko.sign.validation`).
//!
//! Owned by lane E (see `docs/hanko-lanes.md`). Combines `sigis-pdf`
//! (structure), `sigis-cms` (CMS and timestamps), `sigis-pki-certvalidator`
//! (trust, revocation) and `sigis-pdf-diff` (modifications).
//!
//! | pyHanko module | Rust module |
//! | --- | --- |
//! | `sign/validation/pdf_embedded.py` | this file, [`coverage`], [`integrity`] |
//! | `sign/validation/settings.py` | [`settings`] |
//! | `sign/validation/errors.py` | [`errors`] (in `sigis-ades-model`) |
//! | `sign/validation/ades.py`, `sign/validation/report/tools.py` | [`ades`] |
//! | `sign/ades/report.py` | [`report`] |

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

/// Lets modules use `sigis_pades::..` paths (the former `sigis_pades::ades` code
/// referred to this crate as an external dependency).
extern crate self as sigis_pades;

pub mod ades;
pub mod coverage;
/// Validation errors; moved to [`sigis_ades_model::errors`] (re-exported here).
pub use sigis_ades_model::errors;
pub mod integrity;
/// AdES indications; moved to [`sigis_pki_core::ades`] (re-exported here).
pub use sigis_pki_core::ades as report;
/// Key usage settings; moved to [`sigis_pki_core::key_usage`] (re-exported here).
pub use sigis_pki_core::key_usage as settings;

use sigis_cms::{SignedContent, StandardCmsSignatureStatus, TimestampSignatureStatus};
use sigis_pdf::lopdf::{Dictionary, Object, ObjectId};
use sigis_pdf::{EmbeddedSignature, PdfFile, SignatureKind};
use sigis_pdf_diff::{DiffOutcome, DiffPolicy, MdpPerm};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::errors::{not_implemented, HankoError, Result};

use crate::coverage::{evaluate_signature_coverage, process_data_at_eof, XrefMeta};
use crate::errors::SignatureValidationError;
use crate::integrity::{
    docmdp_level, docmdp_ok, evaluate_modifications, fieldmdp, resolve, validate_subfilter,
};

/// How much of the file a signature covers (`SignatureCoverageLevel`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureCoverageLevel {
    /// The byte range is unusual.
    Unclear,
    /// A contiguous block from the start, ending mid-revision.
    ContiguousBlockFromStart,
    /// Exactly one complete revision.
    EntireRevision,
    /// The entire file.
    EntireFile,
}

/// How revocation information is used (`RevocationInfoValidationType`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RevocationInfoValidationType {
    /// Adobe-style: revocation information embedded in the CMS.
    AdobeStyle,
    /// PAdES-LT: revocation information in the DSS.
    #[default]
    PadesLt,
    /// PAdES-LTA: DSS plus a document timestamp chain.
    PadesLta,
}

/// Validation result of one PDF signature (`PdfSignatureStatus`).
#[derive(Clone, Debug)]
pub struct PdfSignatureStatus {
    /// Field name.
    pub field_name: String,
    /// CMS-level status.
    pub cms: StandardCmsSignatureStatus,
    /// Byte range coverage.
    pub coverage: SignatureCoverageLevel,
    /// Review of later revisions, if a diff policy was supplied.
    pub diff_result: Option<DiffOutcome>,
    /// DocMDP level the signature certifies, if any.
    pub docmdp_level: Option<MdpPerm>,
    /// Modifications are compatible with the DocMDP level (`docmdp_ok`).
    pub docmdp_ok: Option<bool>,
}

impl PdfSignatureStatus {
    /// `bottom_line`: intact, valid, trusted, sufficient coverage and no
    /// disallowed modifications.
    pub fn bottom_line(&self) -> bool {
        let coverage_ok = self.coverage >= SignatureCoverageLevel::EntireRevision;
        self.cms.signature.bottom_line() && coverage_ok && self.docmdp_ok.unwrap_or(true)
    }
}

/// Validation result of a document timestamp (`DocumentTimestampStatus`).
#[derive(Clone, Debug)]
pub struct DocumentTimestampStatus {
    /// Field name.
    pub field_name: String,
    /// Timestamp status.
    pub timestamp: TimestampSignatureStatus,
    /// Byte range coverage.
    pub coverage: SignatureCoverageLevel,
}

fn sv_error(e: SignatureValidationError) -> HankoError {
    HankoError::SignatureValidation {
        message: e.to_string(),
        ades_subindication: Some(e.ades_subindication),
    }
}

/// `startxref` and xref end of each revision.
///
/// `sigis-pdf` does not expose the xref container location yet (request
/// R-E6); the revision end offset is used as an upper bound for the xref
/// end, which can only lower the coverage level.
pub fn xref_meta(file: &PdfFile) -> Result<Vec<XrefMeta>> {
    let data = file.bytes();
    let mut out = Vec::new();
    for rev in file.revisions()? {
        let end = rev.end_offset.min(data.len());
        let startxref = process_data_at_eof(data, end.saturating_sub(1))
            .map_err(|e| HankoError::Malformed(e.0.to_owned()))?;
        out.push(XrefMeta {
            startxref,
            xref_end: rev.end_offset as u64,
        });
    }
    Ok(out)
}

fn sig_dictionary(file: &PdfFile, sig: &EmbeddedSignature) -> Result<Dictionary> {
    match file.object_in_revision(sig.sig_object, sig.signed_revision)? {
        Some(Object::Dictionary(d)) => Ok(d),
        _ => Err(HankoError::Malformed(
            "signature object is not a dictionary".into(),
        )),
    }
}

/// Find the signature field whose `/V` is `sig_object` in the AcroForm of
/// `revision` (fields are walked through `/Kids`).
pub fn find_sig_field(
    file: &PdfFile,
    sig_object: ObjectId,
    revision: usize,
) -> Result<Option<Dictionary>> {
    let trailer = file.trailer_in_revision(revision)?;
    let Ok(root) = trailer.get(b"Root") else {
        return Ok(None);
    };
    let Object::Dictionary(root) = resolve(file, root, revision)? else {
        return Ok(None);
    };
    let Ok(acroform) = root.get(b"AcroForm") else {
        return Ok(None);
    };
    let Object::Dictionary(acroform) = resolve(file, acroform, revision)? else {
        return Ok(None);
    };
    let Ok(fields) = acroform.get(b"Fields") else {
        return Ok(None);
    };
    let mut stack: Vec<Object> = match resolve(file, fields, revision)? {
        Object::Array(a) => a,
        _ => return Ok(None),
    };
    let mut seen = 0usize;
    while let Some(obj) = stack.pop() {
        seen += 1;
        if seen > 100_000 {
            return Err(HankoError::Malformed("form field tree too large".into()));
        }
        let Object::Dictionary(field) = resolve(file, &obj, revision)? else {
            continue;
        };
        if matches!(field.get(b"V"), Ok(Object::Reference(id)) if *id == sig_object) {
            return Ok(Some(field));
        }
        if let Ok(kids) = field.get(b"Kids") {
            if let Object::Array(k) = resolve(file, kids, revision)? {
                stack.extend(k);
            }
        }
    }
    Ok(None)
}

/// The DER `ContentInfo` at the start of `/Contents` (the zero padding after
/// it is dropped).
pub fn cms_from_contents(contents: &[u8]) -> Result<&[u8]> {
    let err = || HankoError::Malformed("/Contents does not hold a DER structure".into());
    let (&tag, rest) = contents.split_first().ok_or_else(err)?;
    if tag != 0x30 {
        return Err(err());
    }
    let (&l0, rest) = rest.split_first().ok_or_else(err)?;
    let (len, hdr) = if l0 < 0x80 {
        (usize::from(l0), 2)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return Err(err());
        }
        (
            rest[..n]
                .iter()
                .fold(0usize, |a, b| (a << 8) | usize::from(*b)),
            2 + n,
        )
    };
    contents.get(..hdr + len).ok_or_else(err)
}

/// Coverage of `signature` (`evaluate_signature_coverage`).
pub fn signature_coverage(
    file: &PdfFile,
    signature: &EmbeddedSignature,
) -> Result<SignatureCoverageLevel> {
    let xrefs = xref_meta(file)?;
    Ok(evaluate_signature_coverage(
        file.bytes(),
        &signature.byte_range,
        signature.contents.len(),
        signature.signed_revision,
        &xrefs,
    ))
}

/// Validate one embedded signature (`validate_pdf_signature`).
///
/// With `diff_policy` `None` the modification review is skipped
/// (`skip_diff=True`).
pub fn validate_pdf_signature(
    file: &PdfFile,
    signature: &EmbeddedSignature,
    ctx: &ValidationContext,
    diff_policy: Option<&dyn DiffPolicy>,
) -> Result<PdfSignatureStatus> {
    if signature.kind != SignatureKind::Signature {
        return Err(sv_error(SignatureValidationError::new(
            "Signature object type must be /Sig",
            None,
        )));
    }
    validate_subfilter(
        signature.sub_filter.as_deref(),
        &["adbe.pkcs7.detached", "ETSI.CAdES.detached", "PBAD.PAdES"],
        "%s is not a recognized SubFilter type in signatures.",
    )
    .map_err(sv_error)?;

    let coverage = signature_coverage(file, signature)?;
    let sig_dict = sig_dictionary(file, signature)?;
    let rev = signature.signed_revision;
    let latest = file.revisions()?.len().saturating_sub(1);
    let field = find_sig_field(file, signature.sig_object, latest)?;
    let docmdp = docmdp_level(file, &sig_dict, field.as_ref(), rev)?;
    let diff_result = match diff_policy {
        Some(policy) => {
            let fmdp = fieldmdp(file, &sig_dict, rev)?;
            Some(evaluate_modifications(
                file,
                coverage,
                rev,
                policy,
                fmdp.as_ref(),
                docmdp,
            )?)
        }
        None => None,
    };
    let ok = docmdp_ok(diff_result.as_ref(), docmdp, coverage);

    let signed = signature.signed_data(file)?;
    let cms_der = cms_from_contents(&signature.contents)?;
    let cms = sigis_cms::validate_cms_signature(cms_der, SignedContent::Data(&signed), ctx)?;

    Ok(PdfSignatureStatus {
        field_name: signature.field_name.clone(),
        cms,
        coverage,
        diff_result,
        docmdp_level: docmdp,
        docmdp_ok: ok,
    })
}

/// The message imprint digest algorithm of a `TimeStampToken`.
pub fn tst_imprint_algorithm(token: &[u8]) -> Result<DigestAlgorithm> {
    use der::Decode;
    let err = |m: String| HankoError::Malformed(format!("timestamp token: {m}"));
    let ci = cms::content_info::ContentInfo::from_der(token).map_err(|e| err(e.to_string()))?;
    let sd: cms::signed_data::SignedData = ci
        .content
        .decode_as()
        .map_err(|e: der::Error| err(e.to_string()))?;
    let econtent = sd
        .encap_content_info
        .econtent
        .ok_or_else(|| err("no TSTInfo".into()))?;
    let octets: der::asn1::OctetString = econtent
        .decode_as()
        .map_err(|e: der::Error| err(e.to_string()))?;
    let tst = x509_tsp::TstInfo::from_der(octets.as_bytes()).map_err(|e| err(e.to_string()))?;
    let oid = tst.message_imprint.hash_algorithm.oid;
    DigestAlgorithm::from_oid(&oid)
        .ok_or_else(|| err(format!("unsupported imprint algorithm {oid}")))
}

/// Validate one document timestamp (`validate_pdf_timestamp`).
pub fn validate_pdf_timestamp(
    file: &PdfFile,
    signature: &EmbeddedSignature,
    ctx: &ValidationContext,
) -> Result<DocumentTimestampStatus> {
    if signature.kind != SignatureKind::DocTimeStamp {
        return Err(sv_error(SignatureValidationError::new(
            "Signature object type must be /DocTimeStamp",
            None,
        )));
    }
    validate_subfilter(
        signature.sub_filter.as_deref(),
        &["ETSI.RFC3161"],
        "%s is not a recognized SubFilter type for timestamps.",
    )
    .map_err(sv_error)?;
    let coverage = signature_coverage(file, signature)?;
    let token = cms_from_contents(&signature.contents)?;
    let algo = tst_imprint_algorithm(token)?;
    let imprint = algo.digest(&signature.signed_data(file)?);
    let timestamp = sigis_cms::validate_timestamp_token(token, &imprint, ctx)?;
    Ok(DocumentTimestampStatus {
        field_name: signature.field_name.clone(),
        timestamp,
        coverage,
    })
}

/// Validate a signature for long-term validity using embedded material
/// (`validate_pdf_ltv_signature` of pyHanko < 0.21).
///
/// pyHanko 0.38.1 has no such function; long-term validation is
/// `sigis_pades::ades::validate_pdf_ades` with the long-term level. This
/// entry point stays unimplemented until `sigis-pki-certvalidator` lets a
/// validation context be extended with DSS material (request R-E6).
pub fn validate_pdf_ltv_signature(
    _file: &PdfFile,
    _signature: &EmbeddedSignature,
    _mode: RevocationInfoValidationType,
    _ctx: &ValidationContext,
) -> Result<PdfSignatureStatus> {
    not_implemented("sigis_pades::validate_pdf_ltv_signature")
}
