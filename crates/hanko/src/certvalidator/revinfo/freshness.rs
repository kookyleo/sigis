// Derived from pyhanko-certvalidator `revinfo/archival.py` (MIT, see LICENSE-pyHanko).

//! Freshness of revocation information.
//!
//! [`judge_revinfo`] is a direct port of `_judge_revinfo`. The
//! [`FreshnessJudge`] trait is the hook through which callers can replace it.

use core::time::Duration;

use crate::certvalidator::policy::{
    CertRevTrustPolicy, FreshnessReqType, ValidationTimingParams,
    FRESHNESS_FALLBACK_VALIDITY_DEFAULT,
};
use crate::time::Moment;

/// Whether a piece of revocation information is usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevinfoUsabilityRating {
    /// Usable.
    Ok,
    /// Too old.
    Stale,
    /// Issued after the validation time (never an issue in the AdES model).
    TooNew,
    /// Usability could not be established.
    Unclear,
}

impl RevinfoUsabilityRating {
    /// The rating counts as "fresh" in AdES validation.
    pub fn usable_ades(self) -> bool {
        matches!(self, Self::Ok | Self::TooNew)
    }
}

/// Usability rating with the cutoff it was compared against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevinfoUsability {
    /// The rating.
    pub rating: RevinfoUsabilityRating,
    /// Last moment at which the information was usable, if applicable.
    pub last_usable_at: Option<Moment>,
    /// The moment `last_usable_at` was compared to.
    pub compared_to: Option<Moment>,
}

impl RevinfoUsability {
    fn rating(rating: RevinfoUsabilityRating) -> Self {
        Self {
            rating,
            last_usable_at: None,
            compared_to: None,
        }
    }

    fn stale(compared_to: Moment, last_usable_at: Moment) -> Self {
        Self {
            rating: RevinfoUsabilityRating::Stale,
            last_usable_at: Some(last_usable_at),
            compared_to: Some(compared_to),
        }
    }
}

/// Hook that decides whether revocation information is fresh enough.
pub trait FreshnessJudge: Send + Sync + std::fmt::Debug {
    /// Judge a CRL or OCSP response with the given `thisUpdate` and `nextUpdate`.
    fn judge(
        &self,
        this_update: Option<Moment>,
        next_update: Option<Moment>,
        policy: &CertRevTrustPolicy,
        timing: &ValidationTimingParams,
    ) -> RevinfoUsability;
}

/// The pyhanko-certvalidator freshness rules ([`judge_revinfo`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultFreshnessJudge;

impl FreshnessJudge for DefaultFreshnessJudge {
    fn judge(
        &self,
        this_update: Option<Moment>,
        next_update: Option<Moment>,
        policy: &CertRevTrustPolicy,
        timing: &ValidationTimingParams,
    ) -> RevinfoUsability {
        judge_revinfo(this_update, next_update, policy, timing)
    }
}

fn freshness_delta(
    policy: &CertRevTrustPolicy,
    this_update: Moment,
    next_update: Option<Moment>,
    time_tolerance: Duration,
) -> Option<Duration> {
    let delta = policy.freshness.or_else(|| {
        next_update
            .filter(|nu| *nu >= this_update)
            .map(|nu| nu.abs_diff(this_update))
    })?;
    Some(delta.saturating_add(time_tolerance))
}

/// Assess the usability of revocation information (port of `_judge_revinfo`).
pub fn judge_revinfo(
    this_update: Option<Moment>,
    next_update: Option<Moment>,
    policy: &CertRevTrustPolicy,
    timing: &ValidationTimingParams,
) -> RevinfoUsability {
    use RevinfoUsabilityRating as R;
    let Some(this_update) = this_update else {
        return RevinfoUsability::rating(R::Unclear);
    };
    let validation_time = timing.validation_time;
    let tolerance = timing.time_tolerance;

    match policy.freshness_req_type {
        FreshnessReqType::TimeAfterSignature => {
            // The revinfo must be issued sufficiently long after the signature.
            let Some(delta) = freshness_delta(policy, this_update, next_update, tolerance) else {
                return RevinfoUsability::rating(R::Unclear);
            };
            let signature_time = timing.best_signature_time;
            if this_update < signature_time.plus(delta).minus(tolerance) {
                return RevinfoUsability::stale(
                    signature_time,
                    this_update.minus(delta).plus(tolerance),
                );
            }
        }
        FreshnessReqType::MaxDiffRevocationValidation => {
            // ETSI EN 319 102-1 §5.2.5.4, item 2): pass/fail only.
            let Some(delta) = freshness_delta(policy, this_update, next_update, tolerance) else {
                return RevinfoUsability::rating(R::Unclear);
            };
            let cutoff = this_update.plus(delta).plus(tolerance);
            if validation_time > cutoff {
                return RevinfoUsability::stale(validation_time, cutoff);
            }
        }
        FreshnessReqType::Default => {
            // Usable within thisUpdate..nextUpdate (not an AdES rule). Without
            // nextUpdate, fall back to a short default window.
            let next_update = next_update
                .unwrap_or_else(|| this_update.plus(FRESHNESS_FALLBACK_VALIDITY_DEFAULT));
            if !policy.retroactive_revinfo && validation_time.plus(tolerance) < this_update {
                return RevinfoUsability::rating(R::TooNew);
            }
            if validation_time.minus(tolerance) > next_update {
                return RevinfoUsability::stale(validation_time, next_update.plus(tolerance));
            }
        }
    }
    RevinfoUsability::rating(R::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certvalidator::policy::{RevocationCheckingPolicy, REQUIRE_REVINFO};

    fn t(day: u8, hour: u8) -> Moment {
        Moment::from_ymd_hms(2020, 10, day, hour, 0, 0).expect("date")
    }

    fn timing(validation: Moment, signature: Moment) -> ValidationTimingParams {
        ValidationTimingParams {
            validation_time: validation,
            best_signature_time: signature,
            time_tolerance: Duration::from_secs(1),
        }
    }

    fn policy(req: FreshnessReqType, freshness: Option<Duration>) -> CertRevTrustPolicy {
        CertRevTrustPolicy {
            freshness,
            freshness_req_type: req,
            ..CertRevTrustPolicy::new(REQUIRE_REVINFO)
        }
    }

    #[test]
    fn default_window() {
        let p = CertRevTrustPolicy::new(
            RevocationCheckingPolicy::from_legacy("hard-fail").expect("mode"),
        );
        let judge = |v| judge_revinfo(Some(t(10, 0)), Some(t(17, 0)), &p, &timing(v, v)).rating;
        assert_eq!(judge(t(12, 0)), RevinfoUsabilityRating::Ok);
        assert_eq!(judge(t(9, 0)), RevinfoUsabilityRating::TooNew);
        assert_eq!(judge(t(18, 0)), RevinfoUsabilityRating::Stale);
        // Without nextUpdate the window is 30 minutes.
        let r = judge_revinfo(Some(t(10, 0)), None, &p, &timing(t(10, 1), t(10, 1)));
        assert_eq!(r.rating, RevinfoUsabilityRating::Stale);
    }

    #[test]
    fn retroactive_revinfo_is_never_too_new() {
        let p = CertRevTrustPolicy {
            retroactive_revinfo: true,
            ..CertRevTrustPolicy::default()
        };
        let r = judge_revinfo(
            Some(t(10, 0)),
            Some(t(17, 0)),
            &p,
            &timing(t(9, 0), t(9, 0)),
        );
        assert_eq!(r.rating, RevinfoUsabilityRating::Ok);
    }

    #[test]
    fn max_diff() {
        let p = policy(
            FreshnessReqType::MaxDiffRevocationValidation,
            Some(Duration::from_secs(3600)),
        );
        let ok = judge_revinfo(Some(t(10, 0)), None, &p, &timing(t(10, 1), t(10, 1)));
        assert_eq!(ok.rating, RevinfoUsabilityRating::Ok);
        let stale = judge_revinfo(Some(t(10, 0)), None, &p, &timing(t(10, 2), t(10, 2)));
        assert_eq!(stale.rating, RevinfoUsabilityRating::Stale);
        assert_eq!(
            stale.last_usable_at,
            Some(t(10, 1).plus(Duration::from_secs(2)))
        );
        // Revinfo after the validation time is fine under this policy.
        let later = judge_revinfo(Some(t(20, 0)), None, &p, &timing(t(10, 0), t(10, 0)));
        assert_eq!(later.rating, RevinfoUsabilityRating::Ok);
    }

    #[test]
    fn time_after_signature() {
        let p = policy(
            FreshnessReqType::TimeAfterSignature,
            Some(Duration::from_secs(3 * 86400)),
        );
        let ok = judge_revinfo(Some(t(10, 0)), None, &p, &timing(t(10, 0), t(5, 0)));
        assert_eq!(ok.rating, RevinfoUsabilityRating::Ok);
        let early = judge_revinfo(Some(t(10, 0)), None, &p, &timing(t(10, 0), t(9, 0)));
        assert_eq!(early.rating, RevinfoUsabilityRating::Stale);
        assert_eq!(early.compared_to, Some(t(9, 0)));
    }

    #[test]
    fn missing_this_update_is_unclear() {
        let p = CertRevTrustPolicy::default();
        assert_eq!(
            judge_revinfo(None, None, &p, &timing(t(1, 0), t(1, 0))).rating,
            RevinfoUsabilityRating::Unclear
        );
    }
}
