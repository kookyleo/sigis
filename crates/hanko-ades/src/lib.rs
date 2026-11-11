// Interfaces derived from pyHanko `sign/validation/ades.py` and
// `sign/validation/report/` (MIT, see LICENSE-pyHanko).

//! AdES validation per ETSI EN 319 102-1 (basic, with timestamps, long-term
//! with archival data) and validation reports (JSON and ETSI TS 119 102-2
//! XML) (`pyhanko.sign.validation.ades`).
//!
//! Owned by lane E (see `docs/hanko-lanes.md`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use hanko_certvalidator::ValidationContext;
use hanko_core::errors::{not_implemented, Result};
use hanko_pdf::{EmbeddedSignature, PdfFile};

/// Main indication (`AdESStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdesStatus {
    /// `TOTAL-PASSED` / `PASSED`.
    Passed,
    /// `INDETERMINATE`.
    Indeterminate,
    /// `TOTAL-FAILED` / `FAILED`.
    Failed,
}

/// Sub-indication (`AdESSubIndic`, EN 319 102-1 §5.1.3), named as in the
/// standard, e.g. `"OUT_OF_BOUNDS_NO_POE"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdesSubIndication(pub String);

/// Result of an AdES validation (`AdESBasicValidationResult` and variants).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdesValidationResult {
    /// Main indication.
    pub status: AdesStatus,
    /// Sub-indication, if not passed.
    pub sub_indication: Option<AdesSubIndication>,
}

/// Validation level requested (`ades_*_validation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdesLevel {
    /// Basic signature validation (§5.3).
    Basic,
    /// Validation with timestamps (§5.5).
    WithTimestamps,
    /// Long-term validation with archival data (§5.6).
    LongTerm,
}

/// Run AdES validation of a PDF signature (`ades_basic_validation`,
/// `ades_with_time_validation`, `ades_lta_validation`).
pub fn validate_pdf_ades(
    _file: &PdfFile,
    _signature: &EmbeddedSignature,
    _level: AdesLevel,
    _ctx: &ValidationContext,
) -> Result<AdesValidationResult> {
    not_implemented("hanko_ades::validate_pdf_ades")
}

/// Validation report output.
pub mod report {
    use hanko_core::errors::{not_implemented, Result};

    use super::AdesValidationResult;

    /// JSON report (pyHanko's validation summary).
    pub fn to_json(_result: &AdesValidationResult) -> Result<String> {
        not_implemented("hanko_ades::report::to_json")
    }

    /// ETSI TS 119 102-2 XML validation report.
    pub fn to_etsi_xml(_result: &AdesValidationResult) -> Result<String> {
        not_implemented("hanko_ades::report::to_etsi_xml")
    }
}
