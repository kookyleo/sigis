// Derived from pyHanko `sign/validation/ades.py`
// (`_process_basic_validation`, `_scoped_ades_with_time_validation`,
// `_ades_process_attached_ts`) (MIT, see LICENSE-pyHanko).

//! Validation process for signatures with time (EN 319 102-1, §5.5).

use sigis_cms::{StandardCmsSignatureStatus, TimestampSignatureStatus, TrustProblem};
use sigis_eutl::assess::{enforce_requirements, QualificationRequirements};
use sigis_eutl::q_status::QualificationResult;
use sigis_pades::report::{AdesFailure, AdesIndeterminate, AdesPassed, AdesSubIndic};
use sigis_pki_core::errors::ValidationError;
use sigis_pki_core::time::Moment;

use crate::ades::basic::{basic_subindication, qualification_analysis, QualificationSpec};

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
    /// Qualification of the signature timestamp, if assessed.
    pub timestamp_qualification: Option<QualificationResult>,
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
    let (sub, message, _) = timestamp_assessment(ts, qualification, requirements);
    (sub, message)
}

fn timestamp_assessment(
    ts: &TimestampSignatureStatus,
    qualification: &QualificationSpec<'_>,
    requirements: Option<&QualificationRequirements>,
) -> (AdesSubIndic, Option<String>, Option<QualificationResult>) {
    let sub = basic_subindication(&ts.signature);
    if sub != AdesSubIndic::Passed(AdesPassed::OK) {
        return (sub, None, None);
    }
    if let (Some(registry), Some(path)) = (
        qualification.registry,
        ts.signature.validation_path.as_ref(),
    ) {
        // A token cannot establish POE of its own signature using genTime.
        // Until external archival evidence supplies an earlier validation
        // context, qualification uses the token's validation reference time.
        match qualification_analysis(registry, path, ts.signature.validation_time) {
            Ok(qr) => {
                if let Some(req) = requirements {
                    if let Err(e) = enforce_requirements(req, &qr, path) {
                        return (e.ades_subindication, Some(e.failure_message), Some(qr));
                    }
                }
                return (sub, None, Some(qr));
            }
            Err(msg) => return (AdesIndeterminate::GENERIC.into(), Some(msg), None),
        }
    }
    if requirements.is_some() {
        return (
            AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into(),
            Some("Timestamp qualification requirements need a trusted-service registry and validated path".into()),
            None,
        );
    }
    (sub, None, None)
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
    process_with_time(
        status,
        qualification,
        signature_poe_time,
        signature_not_before,
        validation_time,
        true,
    )
}

/// Use precisely the signature time selected by archival POE processing.
/// A token retained for reporting cannot independently change that time or
/// the qualification reference time after its imprint was denied for POE.
pub(crate) fn with_time_result_at_poe(
    status: StandardCmsSignatureStatus,
    qualification: &QualificationSpec<'_>,
    signature_poe_time: Moment,
    signature_not_before: Option<Moment>,
    validation_time: Moment,
) -> WithTimeValidationResult {
    process_with_time(
        status,
        qualification,
        Some(signature_poe_time),
        signature_not_before,
        validation_time,
        false,
    )
}

fn process_with_time(
    mut status: StandardCmsSignatureStatus,
    qualification: &QualificationSpec<'_>,
    signature_poe_time: Option<Moment>,
    signature_not_before: Option<Moment>,
    validation_time: Moment,
    use_timestamp_poe: bool,
) -> WithTimeValidationResult {
    let (sub, snb) = basic_with_content_ts(&status, qualification, signature_not_before);
    let mut result = WithTimeValidationResult {
        ades_subindic: sub,
        api_status: None,
        failure_msg: None,
        best_signature_time: Some(signature_poe_time.unwrap_or(validation_time)),
        signature_not_before_time: snb,
        qualification: None,
        timestamp_qualification: None,
    };
    if !processed_further(sub) {
        result.api_status = Some(status);
        return result;
    }
    if qualification.requirements.is_some() && qualification.registry.is_none() {
        result.ades_subindic = AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into();
        result.failure_msg =
            Some("Signer qualification requirements need a trusted-service registry".into());
        status.signature.trust_problem_indic = Some(result.ades_subindic);
        status.timestamp_validity = None;
        status.content_timestamp_validity = None;
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
    let (ts_sub, ts_msg, ts_qualification) = timestamp_assessment(&ts, qualification, ts_req);
    result.timestamp_qualification = ts_qualification;
    if ts_sub != AdesSubIndic::Passed(AdesPassed::OK) {
        result.ades_subindic = ts_sub;
        result.failure_msg = ts_msg;
        status.timestamp_validity = None;
        status.content_timestamp_validity = None;
        result.api_status = Some(status);
        return result;
    }
    let poe = if use_timestamp_poe {
        signature_poe_time.map_or(ts.timestamp, |p| p.min(ts.timestamp))
    } else {
        signature_poe_time.unwrap_or(validation_time)
    };
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
    // An existence bound does not complete MAIN validation that stopped at
    // validity, revocation or an algorithm constraint. A retained error path
    // may not have passed certificate signatures, names, policies or MAIN
    // usage checks. This context-free reducer cannot run those checks.
    // Keep the typed failure and time bounds for genuine historical validation.
    if sub != AdesPassed::OK.into() || !status.signature.trusted() {
        if result.ades_subindic == AdesPassed::OK.into() {
            // A cached OK indication is not authority to clear a real failure.
            result.ades_subindic = AdesIndeterminate::GENERIC.into();
        }
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
                        status.signature.trust_problem_indic = Some(e.ades_subindication);
                        status.timestamp_validity = None;
                        status.content_timestamp_validity = None;
                        result.api_status = Some(status);
                        return result;
                    }
                }
                result.qualification = Some(qr);
            }
            Err(msg) => {
                result.ades_subindic = AdesIndeterminate::GENERIC.into();
                result.failure_msg = Some(msg);
                status.signature.trust_problem_indic = Some(result.ades_subindic);
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
/// See [`crate::ades::basic::basic_validation`] for the arguments.
pub fn with_time_validation(
    content_info: &[u8],
    raw_digest: Option<&[u8]>,
    ctx: &sigis_pki_certvalidator::ValidationContext,
    qualification: &QualificationSpec<'_>,
    signature_poe_time: Option<Moment>,
) -> Result<WithTimeValidationResult, sigis_pki_core::errors::HankoError> {
    with_time_validation_with_options(
        content_info,
        raw_digest,
        ctx,
        qualification,
        signature_poe_time,
        &super::AdesValidationOptions::default(),
    )
}

/// Validation with time and an opt-in exact main-signer usage predicate.
/// Caller-provided signature POE, timestamp purpose and qualification stay intact.
pub fn with_time_validation_with_options(
    content_info: &[u8],
    raw_digest: Option<&[u8]>,
    ctx: &sigis_pki_certvalidator::ValidationContext,
    qualification: &QualificationSpec<'_>,
    signature_poe_time: Option<Moment>,
    options: &super::AdesValidationOptions,
) -> Result<WithTimeValidationResult, sigis_pki_core::errors::HankoError> {
    use sigis_pki_core::errors::HankoError;

    let validation_time = ctx.timing().validation_time;
    crate::ades::basic::check_timestamp_digests(content_info)?;
    let content = match raw_digest {
        Some(digest) => {
            // Keep the existing strict detached-digest decoding contract. A
            // lenient CMS parse must not invent a digest for this caller.
            use der::Decode;
            let algorithm = (|| {
                let ci = cms::content_info::ContentInfo::from_der(content_info).ok()?;
                let sd: cms::signed_data::SignedData = ci.content.decode_as().ok()?;
                let si = sd.signer_infos.0.iter().next()?;
                sigis_pki_core::algorithms::DigestAlgorithm::from_oid(&si.digest_alg.oid)
            })()
            .ok_or_else(|| {
                HankoError::Malformed("cannot read the signer's digest algorithm".into())
            })?;
            sigis_cms::SignedContent::Digest(algorithm, digest)
        }
        None => sigis_cms::SignedContent::Encapsulated,
    };
    let cms_options = options.main_cms_options(sigis_cms::CmsValidationOrder::SignerFirst);
    match sigis_cms::validate::evaluate_cms_leaf_revocation(
        content_info,
        content,
        ctx,
        &cms_options,
    )
    .map_err(HankoError::from)
    {
        Ok(evaluated)
            if !matches!(
                evaluated
                    .unresolved_status()
                    .signature
                    .trust_problem
                    .as_ref(),
                Some(TrustProblem::Path(ValidationError::Revoked { .. }))
            ) || evaluated
                .unresolved_status()
                .signature
                .revocation_details
                .as_ref()
                .is_some_and(|details| details.ca_revoked) =>
        {
            // Only the leaf-revoked profile has new completion authority.
            // All ordinary success and other failure profiles retain the old
            // reducer once, including their existing diagnostic time bounds.
            Ok(with_time_result(
                evaluated.into_unresolved_status(),
                qualification,
                signature_poe_time,
                None,
                validation_time,
            ))
        }
        Ok(evaluated) => Ok(with_current_leaf_evaluation(
            evaluated,
            qualification,
            signature_poe_time,
            validation_time,
        )),
        Err(error @ HankoError::NotImplemented(_)) => Err(error),
        Err(error) => Ok(WithTimeValidationResult {
            ades_subindic: match error {
                HankoError::Malformed(_) => AdesFailure::FORMAT_FAILURE.into(),
                _ => AdesIndeterminate::GENERIC.into(),
            },
            api_status: None,
            failure_msg: Some(error.to_string()),
            best_signature_time: signature_poe_time,
            signature_not_before_time: None,
            qualification: None,
            timestamp_qualification: None,
        }),
    }
}

// An operation-bound completion cannot be reconstructed from a public status.
// This helper assesses each required role once, then consumes the original
// opaque CMS operation without supplying a clock, token or replacement status.
fn with_current_leaf_evaluation(
    evaluated: sigis_cms::validate::CmsLeafRevocationEvaluation<'_, '_>,
    qualification: &QualificationSpec<'_>,
    signature_poe_time: Option<Moment>,
    validation_time: Moment,
) -> WithTimeValidationResult {
    let status = evaluated.unresolved_status();
    let (sub, snb) = basic_with_content_ts(status, qualification, None);
    let mut result = WithTimeValidationResult {
        ades_subindic: sub,
        api_status: None,
        failure_msg: None,
        best_signature_time: Some(signature_poe_time.unwrap_or(validation_time)),
        signature_not_before_time: snb,
        qualification: None,
        timestamp_qualification: None,
    };
    // Every refusal moves the same frozen API payload. Qualification does not
    // strip tokens, replace the typed current failure or alter its reference.
    let refuse = |evaluated: sigis_cms::validate::CmsLeafRevocationEvaluation<'_, '_>,
                  mut result: WithTimeValidationResult| {
        result.api_status = Some(evaluated.into_unresolved_status());
        result
    };
    if !processed_further(sub) {
        return refuse(evaluated, result);
    }
    if qualification.requirements.is_some() && qualification.registry.is_none() {
        result.ades_subindic = AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into();
        result.failure_msg =
            Some("Signer qualification requirements need a trusted-service registry".into());
        return refuse(evaluated, result);
    }
    let Some(ts) = status.timestamp_validity.as_ref() else {
        result.ades_subindic = AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into();
        result.failure_msg = Some("No signature timestamp present".into());
        result.best_signature_time = Some(validation_time);
        return refuse(evaluated, result);
    };
    if ts.trusted() && ts.signature.validation_time.is_none() {
        result.failure_msg = Some("Timestamp validation reference is unavailable".into());
        return refuse(evaluated, result);
    }
    let ts_requirements = qualification
        .ts_requirements
        .as_ref()
        .or(qualification.requirements.as_ref());
    let (ts_sub, ts_message, ts_qualification) =
        timestamp_assessment(ts, qualification, ts_requirements);
    result.timestamp_qualification = ts_qualification;
    if ts_sub != AdesPassed::OK.into() {
        result.ades_subindic = ts_sub;
        result.failure_msg = ts_message;
        return refuse(evaluated, result);
    }
    let Some(eligible) = evaluated.eligible_signature_timestamp() else {
        // A diagnostic trusted token is not authority after a denied imprint
        // policy, incomplete MAIN, unsupported metadata or temporal bounds.
        return refuse(evaluated, result);
    };
    let bound = eligible.timestamp;
    if signature_poe_time.is_some_and(|external| external < bound) {
        result.failure_msg = Some(
            "An external earlier time cannot replace this operation's authenticated signature timestamp"
                .into(),
        );
        return refuse(evaluated, result);
    }
    result.best_signature_time = Some(bound);
    if snb.is_some_and(|not_before| not_before > bound) {
        result.ades_subindic = AdesIndeterminate::TIMESTAMP_ORDER_FAILURE.into();
        return refuse(evaluated, result);
    }
    if let Some(registry) = qualification.registry {
        let Some(path) = status.signature.validation_path.as_ref() else {
            result.failure_msg = Some("Completed MAIN path is unavailable".into());
            return refuse(evaluated, result);
        };
        match qualification_analysis(registry, path, Some(bound)) {
            Ok(assessment) => {
                if let Some(requirements) = &qualification.requirements {
                    if let Err(error) = enforce_requirements(requirements, &assessment, path) {
                        result.ades_subindic = error.ades_subindication;
                        result.failure_msg = Some(error.failure_message);
                        result.qualification = Some(assessment);
                        return refuse(evaluated, result);
                    }
                }
                result.qualification = Some(assessment);
            }
            Err(message) => {
                result.ades_subindic = AdesIndeterminate::GENERIC.into();
                result.failure_msg = Some(message);
                return refuse(evaluated, result);
            }
        }
    }
    // Reuse the actual frozen assessments. Never query the registry again to
    // choose a favourable service window or qualify a token at its own genTime.
    let outside_service_window = [
        result.qualification.as_ref(),
        result.timestamp_qualification.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|assessment| {
        assessment
            .service_definition
            .as_ref()
            .is_some_and(|service| {
                let window = &service.base_info;
                bound < window.valid_from || window.valid_until.is_some_and(|end| bound > end)
            })
    });
    if outside_service_window {
        result.ades_subindic = AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into();
        result.failure_msg =
            Some("The authenticated signature time is outside the assessed service window".into());
        return refuse(evaluated, result);
    }
    let resolved = evaluated.resolve_signature_timestamp();
    if resolved.signature.trusted() {
        result.ades_subindic = AdesPassed::OK.into();
    }
    // On success this still reports current revocation details at the original
    // MAIN reference. Only the signature's selected existence bound is earlier;
    // neither this result nor the CMS resolver claims full historical LTA.
    result.api_status = Some(resolved);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigis_cms::SignatureStatus;
    use sigis_pki_certvalidator::{TrustAnchor, ValidationPath};
    use sigis_pki_core::cert::Cert;

    #[test]
    fn archival_time_processing_uses_only_selected_signature_poe() {
        use crate::native_test_fixtures::{b64, data, default_revinfo_policy, read_fixture};
        use sigis_pki_certvalidator::ValidationContext;
        use sigis_pki_core::algorithms::DisallowWeakAlgorithmsPolicy;

        let root = std::env::var_os("HANKO_POE_POLICY_FIXTURE_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| data(&["lanes", "r3-v", "poe-policy"]));
        let manifest: serde_json::Value =
            serde_json::from_slice(&read_fixture(root.join("manifest.json"))).unwrap();
        let file =
            sigis_pdf::PdfFile::parse(&read_fixture(root.join(manifest["file"].as_str().unwrap())))
                .unwrap();
        let signature = file.embedded_signatures().unwrap().remove(0);
        let now = Moment::parse_rfc3339(manifest["validation_time"].as_str().unwrap()).unwrap();
        let signed_at = Moment::parse_rfc3339(manifest["signed_at"].as_str().unwrap()).unwrap();
        let ctx = ValidationContext::builder()
            .trust_root(Cert::from_der(&b64(manifest["trust_root"].as_str().unwrap())).unwrap())
            .moment(now)
            .revinfo_policy(default_revinfo_policy())
            .algorithm_policy(std::sync::Arc::new(
                DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&["sha512"]),
            ))
            .build()
            .unwrap();
        let dss = file.dss().unwrap().unwrap();
        let crls: Vec<_> = dss
            .material
            .crls
            .into_iter()
            .chain(
                manifest["current_crls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| b64(value.as_str().unwrap())),
            )
            .collect();
        let ocsps: Vec<_> = dss
            .material
            .ocsps
            .into_iter()
            .chain(
                manifest["current_ocsps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| b64(value.as_str().unwrap())),
            )
            .collect();
        let ctx = ctx
            .with_revinfo(
                std::iter::empty::<&Cert>(),
                crls.iter().map(Vec::as_slice),
                ocsps.iter().map(Vec::as_slice),
            )
            .unwrap();
        let status = sigis_cms::validate_cms_signature(
            &signature.contents,
            sigis_cms::SignedContent::Data(&signature.signed_data(&file).unwrap()),
            &ctx,
        )
        .unwrap();
        assert!(status.signature.intact && status.signature.valid);
        let timestamp = status.timestamp_validity.as_ref().unwrap();
        assert!(
            timestamp.signature.intact
                && timestamp.signature.valid
                && timestamp.signature.trusted()
        );
        assert_eq!(timestamp.timestamp, signed_at);
        assert!(
            !ctx.algorithm_policy()
                .digest_algorithm_allowed(
                    &sigis_pki_core::algorithms::DigestAlgorithm::Sha512.oid(),
                    Some(now)
                )
                .allowed
        );
        // The LTA caller selected only current-time observation after rejecting
        // this imprint for POE. Neither best time nor qualification may borrow
        // the token's old genTime from its still-valid CMS status.
        let ordinary = with_time_result(
            status.clone(),
            &QualificationSpec::default(),
            Some(now),
            None,
            now,
        );
        assert_eq!(ordinary.best_signature_time, Some(signed_at));
        let bounded =
            with_time_result_at_poe(status, &QualificationSpec::default(), now, None, now);
        assert_eq!(bounded.best_signature_time, Some(now));
    }

    fn cert() -> Cert {
        let p = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../testdata/data/lanes/e/pki/testing-ca/signer1.cert.pem");
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
        // Intentional hardening: an earlier timestamp does not complete the
        // MAIN checks skipped by the current revoked path. Keep the refusal.
        let r = with_time_result(
            status(revoked(t(1_700_000_000)), Some(t(1_600_000_000))),
            &q,
            None,
            None,
            now,
        );
        assert_eq!(name(&r), "REVOKED_NO_POE");
        assert!(!r.api_status.as_ref().unwrap().signature.trusted());
        // Revoked before the timestamp: stays REVOKED_NO_POE.
        let r = with_time_result(
            status(revoked(t(1_500_000_000)), Some(t(1_600_000_000))),
            &q,
            None,
            None,
            now,
        );
        assert_eq!(name(&r), "REVOKED_NO_POE");
        // Earlier POE remains a bound; it cannot upgrade incomplete MAIN trust.
        let r = with_time_result(
            status(revoked(t(1_550_000_000)), Some(t(1_600_000_000))),
            &q,
            Some(t(1_500_000_000)),
            None,
            now,
        );
        assert_eq!(name(&r), "REVOKED_NO_POE");
        assert!(!r.api_status.as_ref().unwrap().signature.trusted());
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
    fn cached_ok_does_not_authorize_clearing_a_real_main_failure() {
        let t = |s| Moment::from_unix_secs(s);
        let mut failed = status(revoked(t(1_700_000_000)), Some(t(1_600_000_000)));
        failed.signature.trust_problem_indic = Some(AdesPassed::OK.into());
        let before = format!("{:?}", failed.signature);
        let result = with_time_result(
            failed,
            &QualificationSpec::default(),
            None,
            None,
            t(2_000_000_000),
        );
        assert_ne!(name(&result), "OK");
        let after = result.api_status.unwrap();
        assert!(!after.signature.trusted());
        assert_eq!(format!("{:?}", after.signature), before);
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
