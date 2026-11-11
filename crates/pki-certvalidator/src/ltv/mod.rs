// Derived from pyhanko-certvalidator `ltv/` (MIT, see LICENSE-pyHanko).

//! Long-term validation building blocks (`ltv/` in pyhanko-certvalidator):
//! proof-of-existence management, time sliding and past certificate
//! validation (ETSI EN 319 102-1 §5.6.2.1–5.6.2.3).
//!
//! Owned by lane A, consumed by lane E (AdES).

pub mod poe;
pub mod time_slide;

use sigis_pki_core::errors::{HankoError, Result, ValidationError};
use sigis_pki_core::time::Moment;

use crate::policy::{CertRevTrustPolicy, NO_REVOCATION};
use crate::{ValidationContext, ValidationPath};

pub use time_slide::{time_slide_with, TimeSlideOptions};

/// Failures of the LTV algorithms.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LtvError {
    /// No proof of existence for a certificate at the control time
    /// (`InsufficientPOEError`).
    #[error("{0}")]
    InsufficientPoe(String),
    /// A validation error raised by the algorithm.
    #[error(transparent)]
    Validation(ValidationError),
    /// The time slide failed (`TimeSlideFailure`); the cause follows.
    #[error("{message}")]
    TimeSlideFailure {
        /// Description.
        message: String,
        /// The underlying failure.
        cause: Box<LtvError>,
    },
    /// The pre-check of past validation failed
    /// (`PastValidatePrecheckFailure`).
    #[error("{0}")]
    PrecheckFailure(String),
}

impl LtvError {
    /// The pyhanko-certvalidator class name.
    pub fn class_name(&self) -> &'static str {
        match self {
            Self::InsufficientPoe(_) => "InsufficientPOEError",
            Self::Validation(e) => e.class_name(),
            Self::TimeSlideFailure { .. } => "TimeSlideFailure",
            Self::PrecheckFailure(_) => "PastValidatePrecheckFailure",
        }
    }
}

impl From<ValidationError> for LtvError {
    fn from(e: ValidationError) -> Self {
        Self::Validation(e)
    }
}

impl From<LtvError> for HankoError {
    /// `ValidationError` has no POE / time-slide variants (lane A request
    /// R6); they map to `PathValidation`, keeping the message.
    fn from(e: LtvError) -> Self {
        match e {
            LtvError::Validation(v) => HankoError::Validation(v),
            other => HankoError::Validation(ValidationError::PathValidation(other.to_string())),
        }
    }
}

/// `_past_validate_precheck`: the certificates' validity periods must
/// intersect, and the path must validate at the end of the intersection
/// without revocation checks or algorithm constraints.
fn precheck(ctx: &ValidationContext, path: &ValidationPath) -> std::result::Result<(), LtvError> {
    let certs: Vec<_> = path.certs().into_iter().skip(1).collect();
    let lower = certs.iter().map(|c| c.not_before()).max();
    let upper = certs.iter().map(|c| c.not_after()).min();
    let (Some(lower), Some(upper)) = (lower, upper) else {
        return Ok(());
    };
    if lower >= upper {
        return Err(LtvError::PrecheckFailure(
            "The intersection of the validity periods of the certificates in the path is empty or degenerate."
                .into(),
        ));
    }
    let mut pre = ctx.clone();
    pre.timing.validation_time = upper;
    pre.timing.best_signature_time = upper;
    pre.timing.point_in_time_validation = true;
    pre.revinfo_policy = CertRevTrustPolicy::new(NO_REVOCATION);
    pre.algorithm_policy = std::sync::Arc::new(AcceptAllAlgorithms);
    crate::validate::validate_path(&pre, path, None).map_err(|_| {
        LtvError::PrecheckFailure(
            "Elementary path validation routine failed during pre-check for past point-in-time validation"
                .into(),
        )
    })
}

/// `AcceptAllAlgorithms`.
#[derive(Debug)]
struct AcceptAllAlgorithms;

impl sigis_pki_core::algorithms::AlgorithmUsagePolicy for AcceptAllAlgorithms {
    fn digest_algorithm_allowed(
        &self,
        _: &const_oid::ObjectIdentifier,
        _: Option<Moment>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        sigis_pki_core::algorithms::AlgorithmUsageConstraint::allowed()
    }

    fn signature_algorithm_allowed(
        &self,
        _: &spki::AlgorithmIdentifierOwned,
        _: Option<Moment>,
        _: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        sigis_pki_core::algorithms::AlgorithmUsageConstraint::allowed()
    }

    fn min_rsa_key_size(&self) -> usize {
        0
    }
}

/// Past certificate validation (`ades_past.past_validate`): validate `path`
/// at the latest moment for which its revocation status and POEs allow it,
/// returning that moment.
pub fn past_validate(
    ctx: &ValidationContext,
    path: &ValidationPath,
    poe: &poe::PoeManager,
    initial_validation_time: Moment,
) -> Result<Moment> {
    past_validate_with(ctx, path, poe, initial_validation_time, None).map_err(Into::into)
}

/// [`past_validate`] with the best signature time used for freshness, and
/// the detailed error type.
pub fn past_validate_with(
    ctx: &ValidationContext,
    path: &ValidationPath,
    poe: &poe::PoeManager,
    init_control_time: Moment,
    best_signature_time: Option<Moment>,
) -> std::result::Result<Moment, LtvError> {
    if path.pkix_len() > 0 {
        precheck(ctx, path)?;
    }
    let control_time = time_slide_with(
        path,
        init_control_time,
        ctx,
        poe,
        TimeSlideOptions::default(),
    )
    .map_err(|e| LtvError::TimeSlideFailure {
        message: format!(
            "Failed to get control time for point-in-time validation for path with leaf {}",
            path.leaf()
                .map(|c| crate::names::human_friendly(c.subject()))
                .unwrap_or_default()
        ),
        cause: Box::new(e),
    })?;
    let mut at = ctx.clone();
    at.timing.validation_time = control_time;
    at.timing.best_signature_time = best_signature_time.unwrap_or(control_time);
    at.timing.point_in_time_validation = true;
    crate::validate::validate_path(&at, path, None)?;
    Ok(control_time)
}
