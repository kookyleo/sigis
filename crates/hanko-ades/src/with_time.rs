// Derived from pyHanko `sign/validation/ades.py`
// (`_process_basic_validation`, `_scoped_ades_with_time_validation`,
// `_ades_process_attached_ts`) (MIT, see LICENSE-pyHanko).

//! Validation process for signatures with time (EN 319 102-1, §5.5).

use hanko_cms::{StandardCmsSignatureStatus, TimestampSignatureStatus, TrustProblem};
use hanko_core::errors::ValidationError;
use hanko_core::time::Moment;
use hanko_eutl::assess::{enforce_requirements, QualificationRequirements};
use hanko_eutl::q_status::QualificationResult;
use hanko_validate::report::{AdesFailure, AdesIndeterminate, AdesPassed, AdesSubIndic};

use crate::basic::{basic_subindication, qualification_analysis, QualificationSpec};

/// Result of validation with time (`AdESWithTimeValidationResult`).
#[derive(Clone, Debug)]
pub struct WithTimeValidationResult {
    /// AdES sub-indication.
    pub ades_subindic: AdesSubIndic,
    /// CMS status.
    pub api_status: Option<StandardCmsSignatureStatus>,
    /// Failure message, if any.
    pub failure_msg: Option<String>,
    /// Best signature time (POE of the signature).
    pub best_signature_time: Option<Moment>,
    /// Lower bound for the signing time (content timestamp).
    pub signature_not_before_time: Option<Moment>,
    /// Qualification of the signer, if assessed.
    pub qualification: Option<QualificationResult>,
}

/// Sub-indications that validation with time processes further
/// (`_WITH_TIME_FURTHER_PROC`).
pub fn processed_further(sub: AdesSubIndic) -> bool {
    matches!(
        sub,
        AdesSubIndic::Passed(AdesPassed::OK)
            | AdesSubIndic::Indeterminate(
                AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE
                    | AdesIndeterminate::REVOKED_NO_POE
                    | AdesIndeterminate::REVOKED_CA_NO_POE
                    | AdesIndeterminate::TRY_LATER
                    | AdesIndeterminate::OUT_OF_BOUNDS_NO_POE
            )
    )
}

/// AdES evaluation of an attached timestamp (`_ades_process_attached_ts`):
/// basic validation of the token plus the timestamp qualification
/// requirements.
pub fn timestamp_subindication(
    ts: &TimestampSignatureStatus,
    qualification: &QualificationSpec<'_>,
    requirements: Option<&QualificationRequirements>,
) -> (AdesSubIndic, Option<String>) {
    let sub = basic_subindication(&ts.signature);
    if sub != AdesSubIndic::Passed(AdesPassed::OK) {
        return (sub, None);
    }
    if let (Some(registry), Some(req), Some(path)) = (
        qualification.registry,
        requirements,
        ts.signature.validation_path.as_ref(),
    ) {
        match qualification_analysis(registry, path, Some(ts.timestamp)) {
            Ok(qr) => {
                if let Err(e) = enforce_requirements(req, &qr, path) {
                    return (e.ades_subindication, Some(e.failure_message));
                }
            }
            Err(msg) => return (AdesIndeterminate::GENERIC.into(), Some(msg)),
        }
    }
    (sub, None)
}

fn revocation_date(status: &StandardCmsSignatureStatus) -> Option<Moment> {
    match &status.signature.trust_problem {
        Some(TrustProblem::Path(ValidationError::Revoked {
            revocation_time, ..
        })) => *revocation_time,
        _ => None,
    }
}

/// Basic validation including the content timestamp processing of
/// `_process_basic_validation`: returns the sub-indication and the
/// signature-not-before time.
pub fn basic_with_content_ts(
    status: &StandardCmsSignatureStatus,
    qualification: &QualificationSpec<'_>,
    mut signature_not_before: Option<Moment>,
) -> (AdesSubIndic, Option<Moment>) {
    let mut sub = basic_subindication(&status.signature);
    let revoked = sub == AdesSubIndic::Indeterminate(AdesIndeterminate::REVOKED_NO_POE);
    let expired = sub == AdesSubIndic::Indeterminate(AdesIndeterminate::OUT_OF_BOUNDS_NO_POE);
    if !(revoked || expired) {
        return (sub, signature_not_before);
    }
    let Some(ct) = &status.content_timestamp_validity else {
        return (sub, signature_not_before);
    };
    let ts_req = qualification
        .ts_requirements
        .as_ref()
        .or(qualification.requirements.as_ref());
    if timestamp_subindication(ct, qualification, ts_req).0 != AdesSubIndic::Passed(AdesPassed::OK)
    {
        return (sub, signature_not_before);
    }
    let snb = signature_not_before.map_or(ct.timestamp, |t| t.max(ct.timestamp));
    signature_not_before = Some(snb);
    let (cutoff, perm): (Option<Moment>, AdesSubIndic) = if revoked {
        (revocation_date(status), AdesFailure::REVOKED.into())
    } else {
        (
            status
                .signature
                .signing_cert
                .as_ref()
                .map(|c| c.not_after()),
            AdesIndeterminate::EXPIRED.into(),
        )
    };
    // pyHanko asserts the cut-off is known; without it nothing changes.
    if let Some(cutoff) = cutoff {
        if snb >= cutoff {
            sub = perm;
        }
    }
    (sub, signature_not_before)
}

/// Validation with time on top of a CMS validation status
/// (`_scoped_ades_with_time_validation`).
///
/// `signature_poe_time`: an earlier proof of existence of the signature
/// value, if known; `validation_time`: the time of validation (the best
/// signature time when no timestamp is present).
pub fn with_time_result(
    status: StandardCmsSignatureStatus,
    qualification: &QualificationSpec<'_>,
    signature_poe_time: Option<Moment>,
    signature_not_before: Option<Moment>,
    validation_time: Moment,
) -> WithTimeValidationResult {
    let (sub, snb) = basic_with_content_ts(&status, qualification, signature_not_before);
    let mut result = WithTimeValidationResult {
        ades_subindic: sub,
        api_status: None,
        failure_msg: None,
        best_signature_time: signature_poe_time,
        signature_not_before_time: snb,
        qualification: None,
    };
    if !processed_further(sub) {
        result.api_status = Some(status);
        return result;
    }
    let Some(ts) = status.timestamp_validity.clone() else {
        result.ades_subindic = AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into();
        result.failure_msg = Some("No signature timestamp present".into());
        result.best_signature_time = Some(validation_time);
        result.api_status = Some(status);
        return result;
    };
    let ts_req = qualification
        .ts_requirements
        .as_ref()
        .or(qualification.requirements.as_ref());
    let (ts_sub, ts_msg) = timestamp_subindication(&ts, qualification, ts_req);
    if ts_sub != AdesSubIndic::Passed(AdesPassed::OK) {
        result.ades_subindic = ts_sub;
        result.failure_msg = ts_msg;
        result.api_status = Some(status);
        return result;
    }
    let poe = signature_poe_time.map_or(ts.timestamp, |p| p.min(ts.timestamp));
    result.best_signature_time = Some(poe);
    match sub {
        AdesSubIndic::Indeterminate(AdesIndeterminate::REVOKED_NO_POE) => {
            // pyHanko asserts revocation details exist; fail closed if not.
            if revocation_date(&status).is_none_or(|d| poe >= d) {
                result.api_status = Some(status);
                return result;
            }
        }
        AdesSubIndic::Indeterminate(AdesIndeterminate::OUT_OF_BOUNDS_NO_POE) => {
            let not_before = status
                .signature
                .signing_cert
                .as_ref()
                .map(|c| c.not_before());
            if not_before.is_none_or(|nb| poe < nb) {
                result.ades_subindic = AdesIndeterminate::NOT_YET_VALID.into();
                result.api_status = Some(status);
                return result;
            }
        }
        AdesSubIndic::Indeterminate(
            AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE | AdesIndeterminate::TRY_LATER,
        ) => {
            result.api_status = Some(status);
            return result;
        }
        _ => {}
    }
    if snb.is_some_and(|t| t > poe) {
        result.ades_subindic = AdesIndeterminate::TIMESTAMP_ORDER_FAILURE.into();
        result.api_status = Some(status);
        return result;
    }
    if let (Some(registry), Some(path)) = (
        qualification.registry,
        status.signature.validation_path.as_ref(),
    ) {
        match qualification_analysis(registry, path, Some(poe)) {
            Ok(qr) => {
                if let Some(req) = &qualification.requirements {
                    if let Err(e) = enforce_requirements(req, &qr, path) {
                        result.ades_subindic = e.ades_subindication;
                        result.failure_msg = Some(e.failure_message);
                        result.qualification = Some(qr);
                        result.api_status = Some(status);
                        return result;
                    }
                }
                result.qualification = Some(qr);
            }
            Err(msg) => {
                result.ades_subindic = AdesIndeterminate::GENERIC.into();
                result.failure_msg = Some(msg);
                result.api_status = Some(status);
                return result;
            }
        }
    }
    result.ades_subindic = AdesPassed::OK.into();
    result.api_status = Some(status);
    result
}

/// Validation with time of a CMS signature (`ades_with_time_validation`).
/// See [`crate::basic::basic_validation`] for the arguments.
pub fn with_time_validation(
    content_info: &[u8],
    raw_digest: Option<&[u8]>,
    ctx: &hanko_certvalidator::ValidationContext,
    qualification: &QualificationSpec<'_>,
    signature_poe_time: Option<Moment>,
) -> Result<WithTimeValidationResult, hanko_core::errors::HankoError> {
    let validation_time = ctx.timing().validation_time;
    Ok(
        match crate::basic::cms_status(content_info, raw_digest, ctx)? {
            Ok(status) => with_time_result(
                status,
                qualification,
                signature_poe_time,
                None,
                validation_time,
            ),
            Err((sub, msg)) => WithTimeValidationResult {
                ades_subindic: sub,
                api_status: None,
                failure_msg: Some(msg),
                best_signature_time: signature_poe_time,
                signature_not_before_time: None,
                qualification: None,
            },
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hanko_certvalidator::{TrustAnchor, ValidationPath};
    use hanko_cms::SignatureStatus;
    use hanko_core::cert::Cert;

    fn cert() -> Cert {
        let p = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../hanko-testdata/data/lanes/e/pki/testing-ca/signer1.cert.pem");
        Cert::from_pem_or_der(&std::fs::read(p).unwrap()).unwrap()
    }

    fn sig(problem: Option<TrustProblem>) -> SignatureStatus {
        let c = cert();
        SignatureStatus {
            intact: true,
            valid: true,
            trust_problem: problem,
            signing_cert: Some(c.clone()),
            signature_mechanism: None,
            md_algorithm: None,
            validation_path: Some(ValidationPath::new(
                TrustAnchor::new(c.clone()),
                vec![],
                Some(c),
            )),

            ..Default::default()
        }
    }

    fn ts(at: Moment) -> TimestampSignatureStatus {
        TimestampSignatureStatus {
            signature: sig(None),
            timestamp: at,
        }
    }

    fn status(problem: Option<TrustProblem>, tst: Option<Moment>) -> StandardCmsSignatureStatus {
        StandardCmsSignatureStatus {
            signature: sig(problem),
            signer_reported_dt: None,
            timestamp_validity: tst.map(ts),
            content_timestamp_validity: None,

            ..Default::default()
        }
    }

    fn revoked(at: Moment) -> Option<TrustProblem> {
        Some(TrustProblem::Path(ValidationError::Revoked {
            msg: "revoked".into(),
            revocation_time: Some(at),
            reason: None,
        }))
    }

    fn name(r: &WithTimeValidationResult) -> &'static str {
        r.ades_subindic.standard_name()
    }

    #[test]
    fn with_time_rules() {
        let q = QualificationSpec::default();
        let now = Moment::from_unix_secs(2_000_000_000);
        let t = |s| Moment::from_unix_secs(s);
        // No timestamp.
        let r = with_time_result(status(None, None), &q, None, None, now);
        assert_eq!(name(&r), "SIG_CONSTRAINTS_FAILURE");
        assert_eq!(r.best_signature_time, Some(now));
        // Happy path: best signature time is the timestamp.
        let r = with_time_result(status(None, Some(t(1_600_000_000))), &q, None, None, now);
        assert_eq!(name(&r), "OK");
        assert_eq!(r.best_signature_time, Some(t(1_600_000_000)));
        // Revoked after the timestamp: the POE rescues the signature.
        let r = with_time_result(
            status(revoked(t(1_700_000_000)), Some(t(1_600_000_000))),
            &q,
            None,
            None,
            now,
        );
        assert_eq!(name(&r), "OK");
        // Revoked before the timestamp: stays REVOKED_NO_POE.
        let r = with_time_result(
            status(revoked(t(1_500_000_000)), Some(t(1_600_000_000))),
            &q,
            None,
            None,
            now,
        );
        assert_eq!(name(&r), "REVOKED_NO_POE");
        // Earlier POE wins.
        let r = with_time_result(
            status(revoked(t(1_550_000_000)), Some(t(1_600_000_000))),
            &q,
            Some(t(1_500_000_000)),
            None,
            now,
        );
        assert_eq!(name(&r), "OK");
        assert_eq!(r.best_signature_time, Some(t(1_500_000_000)));
        // Content timestamp later than the signature timestamp.
        let r = with_time_result(
            status(None, Some(t(1_600_000_000))),
            &q,
            None,
            Some(t(1_650_000_000)),
            now,
        );
        assert_eq!(name(&r), "TIMESTAMP_ORDER_FAILURE");
        // Not processed further.
        let mut s = status(None, Some(t(1_600_000_000)));
        s.signature.intact = false;
        assert_eq!(
            name(&with_time_result(s, &q, None, None, now)),
            "HASH_FAILURE"
        );
        // A failing timestamp propagates.
        let mut s = status(None, Some(t(1_600_000_000)));
        if let Some(tv) = s.timestamp_validity.as_mut() {
            tv.signature.valid = false;
        }
        assert_eq!(
            name(&with_time_result(s, &q, None, None, now)),
            "SIG_CRYPTO_FAILURE"
        );
        // TRY_LATER is not resolved by a timestamp.
        let stale = Some(TrustProblem::Path(ValidationError::StaleRevinfo {
            msg: "x".into(),
            time_cutoff: None,
        }));
        assert_eq!(
            name(&with_time_result(
                status(stale, Some(t(1_600_000_000))),
                &q,
                None,
                None,
                now
            )),
            "TRY_LATER"
        );
    }

    #[test]
    fn content_timestamp_turns_revocation_into_failure() {
        let q = QualificationSpec::default();
        let t = |s| Moment::from_unix_secs(s);
        let mut s = status(revoked(t(1_500_000_000)), None);
        s.content_timestamp_validity = Some(ts(t(1_600_000_000)));
        let (sub, snb) = basic_with_content_ts(&s, &q, None);
        assert_eq!(sub.standard_name(), "REVOKED");
        assert_eq!(snb, Some(t(1_600_000_000)));
    }
}
