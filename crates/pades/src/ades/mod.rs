// Derived from pyHanko `sign/validation/ades.py` and
// `sign/validation/report/` (MIT, see LICENSE-pyHanko).

//! AdES validation per ETSI EN 319 102-1 (basic, with timestamps, long-term
//! with archival data) and validation reports (JSON and ETSI TS 119 102-2
//! XML) (`pyhanko.sign.validation.ades`).
//!
//! Owned by lane E (see `docs/hanko-lanes.md`). Formerly the crate
//! `sigis-pades`; merged into `pades` on 2026-11-12 (`docs/crates.md`).
//!
//! | pyHanko module | Rust module |
//! | --- | --- |
//! | `sign/validation/ades.py` (basic validation) | [`basic`], [`validate_pdf_ades`] |
//! | `sign/validation/ades.py` (validation with time) | [`with_time`] |
//! | `sign/validation/report/tools.py` | [`etsi_report`] |
//! | `sign/ades/report.py` | re-exported from `sigis_pades::report` |

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod adobe_revinfo;
pub mod basic;
pub mod etsi_report;
pub mod lta;
mod options;
pub use options::AdesValidationOptions;
pub mod policy;
pub mod with_time;

use sigis_pdf::{EmbeddedSignature, PdfFile};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::errors::Result;

pub use sigis_pades::report::{
    AdesFailure, AdesIndeterminate, AdesPassed, AdesStatus, AdesSubIndic,
};

/// Sub-indication (`AdESSubIndic`, EN 319 102-1 §5.1.3), named as in the
/// standard, e.g. `"OUT_OF_BOUNDS_NO_POE"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdesSubIndication(pub String);

impl From<AdesSubIndic> for AdesSubIndication {
    fn from(s: AdesSubIndic) -> Self {
        Self(s.standard_name().to_owned())
    }
}

/// Result of an AdES validation (`AdESBasicValidationResult` and variants).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdesValidationResult {
    /// Main indication.
    pub status: AdesStatus,
    /// Sub-indication, if not passed.
    pub sub_indication: Option<AdesSubIndication>,
}

impl AdesValidationResult {
    /// Result for a sub-indication (`OK` gives `PASSED` without
    /// sub-indication).
    pub fn from_subindic(sub: AdesSubIndic) -> Self {
        Self {
            status: sub.status(),
            sub_indication: (sub.status() != AdesStatus::Passed).then(|| sub.into()),
        }
    }
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
///
/// Basic validation and validation with time are implemented on top of
/// `sigis_cms`; long-term validation authenticates archival evidence using
/// the POE and time-slide machinery of `sigis_pki_certvalidator::ltv`.
pub fn validate_pdf_ades(
    file: &PdfFile,
    signature: &EmbeddedSignature,
    level: AdesLevel,
    ctx: &ValidationContext,
) -> Result<AdesValidationResult> {
    validate_pdf_ades_with_options(
        file,
        signature,
        level,
        ctx,
        &AdesValidationOptions::default(),
    )
}

/// Run PDF AdES validation with an opt-in exact main-signer predicate.
///
/// Basic/time dispatcher branches retain their timestamp-first order; detailed
/// AdES APIs and long-term validation retain signer-first processing. PDF
/// coverage, modification and seed constraints are unchanged.
pub fn validate_pdf_ades_with_options(
    file: &PdfFile,
    signature: &EmbeddedSignature,
    level: AdesLevel,
    ctx: &ValidationContext,
    options: &AdesValidationOptions,
) -> Result<AdesValidationResult> {
    let cms_options = options.main_cms_options(sigis_cms::CmsValidationOrder::TimestampsFirst);
    match level {
        AdesLevel::Basic => {
            let pdf = crate::validate_pdf_signature_with_options(
                file,
                signature,
                ctx,
                Some(&sigis_pdf_diff::StandardDiffPolicy),
                &cms_options,
            )?;
            if pdf.seed_value_constraint_error.is_some()
                || pdf.docmdp_ok == Some(false)
                || pdf.coverage < crate::SignatureCoverageLevel::EntireRevision
            {
                return Ok(AdesValidationResult::from_subindic(
                    AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into(),
                ));
            }
            let status = pdf.cms;
            let result = basic::basic_result(status, &basic::QualificationSpec::default(), None);
            Ok(AdesValidationResult::from_subindic(result.ades_subindic))
        }
        AdesLevel::WithTimestamps => {
            let pdf = crate::validate_pdf_signature_with_options(
                file,
                signature,
                ctx,
                Some(&sigis_pdf_diff::StandardDiffPolicy),
                &cms_options,
            )?;
            if pdf.seed_value_constraint_error.is_some()
                || pdf.docmdp_ok == Some(false)
                || pdf.coverage < crate::SignatureCoverageLevel::EntireRevision
            {
                return Ok(AdesValidationResult::from_subindic(
                    AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into(),
                ));
            }
            let status = pdf.cms;
            let result = with_time::with_time_result(
                status,
                &basic::QualificationSpec::default(),
                None,
                None,
                ctx.timing().validation_time,
            );
            Ok(AdesValidationResult::from_subindic(result.ades_subindic))
        }
        AdesLevel::LongTerm => {
            let result = lta::lta_validation_with_ades_options(
                file,
                signature,
                ctx,
                &basic::QualificationSpec::default(),
                &lta::LtaOptions::default(),
                options,
            )?;
            Ok(AdesValidationResult::from_subindic(result.ades_subindic))
        }
    }
}

/// Validation report output.
pub mod report {
    use sigis_pki_core::errors::{HankoError, Result};

    use super::AdesValidationResult;

    /// JSON report (pyHanko's validation summary): the main indication and
    /// sub-indication.
    pub fn to_json(result: &AdesValidationResult) -> Result<String> {
        let v = serde_json::json!({
            "ades_status": result.status.name(),
            "ades_subindication": result.sub_indication.as_ref().map(|s| s.0.clone()),
        });
        serde_json::to_string_pretty(&v).map_err(|e| HankoError::Malformed(e.to_string()))
    }

    /// ETSI TS 119 102-2 XML validation report with the validation status
    /// only. The full report (signature identifier, attributes, validation
    /// objects) is [`crate::ades::etsi_report::generate_report`].
    pub fn to_etsi_xml(result: &AdesValidationResult) -> Result<String> {
        let sub = result
            .sub_indication
            .as_ref()
            .map(|s| s.0.as_str())
            .unwrap_or("OK");
        let main = super::etsi_report::main_indication_uri(result.status);
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vr:ValidationReport xmlns:vr=\"{}\">\n  <vr:SignatureValidationReport>\n    <vr:SignatureValidationStatus>\n      <vr:MainIndication>{main}</vr:MainIndication>\n      <vr:SubIndication>urn:etsi:019102:subindication:{sub}</vr:SubIndication>\n    </vr:SignatureValidationStatus>\n  </vr:SignatureValidationReport>\n</vr:ValidationReport>\n",
            super::etsi_report::VR_NS
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::ades::{AdesFailure, AdesPassed};

        #[test]
        fn json_and_xml() {
            let ok = AdesValidationResult::from_subindic(AdesPassed::OK.into());
            assert!(ok.sub_indication.is_none());
            assert!(to_json(&ok).unwrap().contains("\"PASSED\""));
            assert!(to_etsi_xml(&ok).unwrap().contains("total-passed"));
            let bad = AdesValidationResult::from_subindic(AdesFailure::HASH_FAILURE.into());
            assert_eq!(bad.sub_indication.as_ref().unwrap().0, "HASH_FAILURE");
            assert!(to_etsi_xml(&bad)
                .unwrap()
                .contains("subindication:HASH_FAILURE"));
        }
    }
}
