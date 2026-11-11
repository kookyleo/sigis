// Interfaces derived from pyHanko `sign/validation/pdf_embedded.py`,
// `status.py`, `dss.py`, `ltv.py` (MIT, see LICENSE-pyHanko).

//! Validation of signatures embedded in PDF files
//! (`pyhanko.sign.validation`).
//!
//! Owned by lane E (see `docs/hanko-lanes.md`). Combines `hanko-pdf`
//! (structure), `hanko-cms` (CMS and timestamps), `hanko-certvalidator`
//! (trust, revocation) and `hanko-diff` (modifications).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod errors;
pub mod report;
pub mod settings;

use hanko_certvalidator::ValidationContext;
use hanko_cms::{StandardCmsSignatureStatus, TimestampSignatureStatus};
use hanko_core::errors::{not_implemented, Result};
use hanko_diff::{DiffOutcome, DiffPolicy, MdpPerm};
use hanko_pdf::{EmbeddedSignature, PdfFile};

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

/// Validate one embedded signature (`validate_pdf_signature`).
pub fn validate_pdf_signature(
    _file: &PdfFile,
    _signature: &EmbeddedSignature,
    _ctx: &ValidationContext,
    _diff_policy: Option<&dyn DiffPolicy>,
) -> Result<PdfSignatureStatus> {
    not_implemented("hanko_validate::validate_pdf_signature")
}

/// Validate one document timestamp (`validate_pdf_timestamp`).
pub fn validate_pdf_timestamp(
    _file: &PdfFile,
    _signature: &EmbeddedSignature,
    _ctx: &ValidationContext,
) -> Result<DocumentTimestampStatus> {
    not_implemented("hanko_validate::validate_pdf_timestamp")
}

/// Validate a signature for long-term validity using embedded material
/// (`validate_pdf_ltv_signature`).
pub fn validate_pdf_ltv_signature(
    _file: &PdfFile,
    _signature: &EmbeddedSignature,
    _mode: RevocationInfoValidationType,
    _ctx: &ValidationContext,
) -> Result<PdfSignatureStatus> {
    not_implemented("hanko_validate::validate_pdf_ltv_signature")
}
