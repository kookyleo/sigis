// Derived from pyHanko `sign/validation/ades.py` (`_ades_basic_validation`,
// `_scoped_ades_basic_validation`) and `sign/validation/generic_cms.py`
// (`handle_certvalidator_errors`) (MIT, see LICENSE-pyHanko).

//! Basic signature validation (EN 319 102-1, §5.3) on top of the CMS
//! validation of `hanko-cms`.

use hanko_certvalidator::{ValidationContext, ValidationPath};
use hanko_cms::{SignatureStatus, SignedContent, StandardCmsSignatureStatus, TrustProblem};
use hanko_core::algorithms::DigestAlgorithm;
use hanko_core::errors::{HankoError, ValidationError};
use hanko_core::time::Moment;
use hanko_eutl::assess::{enforce_requirements, QualificationAssessor, QualificationRequirements};
use hanko_eutl::q_status::QualificationResult;
use hanko_eutl::tsp::TspRegistry;
use hanko_validate::report::{AdesFailure, AdesIndeterminate, AdesPassed, AdesSubIndic};

/// AdES sub-indication of a certificate validation error
/// (`handle_certvalidator_errors`).
///
/// `is_ee_cert`: the error concerns the end-entity certificate.
/// `hanko-certvalidator` does not report this yet (request R-E7); callers
/// that cannot tell pass `true`, which yields the `*_NO_POE` indications
/// that later POE processing may turn into `FAILED`, never into `PASSED`.
pub fn subindication_for_validation_error(err: &ValidationError, is_ee_cert: bool) -> AdesSubIndic {
    match err {
        ValidationError::StaleRevinfo { .. } => AdesIndeterminate::TRY_LATER.into(),
        ValidationError::DisallowedAlgorithm(_) => AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE.into(),
        ValidationError::Revoked { .. } => {
            if is_ee_cert {
                AdesIndeterminate::REVOKED_NO_POE.into()
            } else {
                AdesIndeterminate::REVOKED_CA_NO_POE.into()
            }
        }
        ValidationError::PathBuilding(_) => AdesIndeterminate::NO_CERTIFICATE_CHAIN_FOUND.into(),
        ValidationError::Expired { .. } => {
            if is_ee_cert {
                AdesIndeterminate::OUT_OF_BOUNDS_NO_POE.into()
            } else {
                AdesIndeterminate::CERTIFICATE_CHAIN_GENERAL_FAILURE.into()
            }
        }
        ValidationError::NotYetValid { .. }
        | ValidationError::PathValidation(_)
        | ValidationError::InsufficientRevinfo(_)
        | ValidationError::Malformed(_) => AdesIndeterminate::CERTIFICATE_CHAIN_GENERAL_FAILURE.into(),
    }
}

/// AdES sub-indication of a trust problem reported by `hanko-cms`.
pub fn subindication_for_trust_problem(problem: &TrustProblem) -> AdesSubIndic {
    match problem {
        TrustProblem::Path(e) => subindication_for_validation_error(e, true),
        // InvalidCertificateError (key usage) -> CHAIN_CONSTRAINTS_FAILURE
        TrustProblem::KeyUsage(_) => AdesIndeterminate::CHAIN_CONSTRAINTS_FAILURE.into(),
    }
}

/// Sub-indication of a CMS signature status before time-related processing
/// (`_ades_basic_validation` / `_process_basic_validation` without content
/// timestamps).
pub fn basic_subindication(status: &SignatureStatus) -> AdesSubIndic {
    if !status.intact {
        return AdesFailure::HASH_FAILURE.into();
    }
    if !status.valid {
        return AdesFailure::SIG_CRYPTO_FAILURE.into();
    }
    if let Some(p) = &status.trust_problem {
        return subindication_for_trust_problem(p);
    }
    if status.validation_path.is_none() {
        return AdesIndeterminate::NO_CERTIFICATE_CHAIN_FOUND.into();
    }
    AdesPassed::OK.into()
}

/// Qualification settings of a validation (`SignatureValidationSpec`
/// fields `qualification_requirements`, `ts_qualification_requirements`,
/// and the `TSPTrustManager`'s registry).
#[derive(Clone, Debug, Default)]
pub struct QualificationSpec<'a> {
    /// Registry the trust anchors come from, if qualification should be
    /// assessed.
    pub registry: Option<&'a TspRegistry>,
    /// Requirements for the signer.
    pub requirements: Option<QualificationRequirements>,
    /// Requirements for timestamps (defaults to `requirements`).
    pub ts_requirements: Option<QualificationRequirements>,
}

/// Result of basic validation (`AdESBasicValidationResult`).
#[derive(Clone, Debug)]
pub struct BasicValidationResult {
    /// AdES sub-indication.
    pub ades_subindic: AdesSubIndic,
    /// Status from the CMS validation, if it ran.
    pub api_status: Option<StandardCmsSignatureStatus>,
    /// Failure message, if any.
    pub failure_msg: Option<String>,
    /// Qualification of the signer, if a registry was supplied.
    pub qualification: Option<QualificationResult>,
}

/// Turn a CMS validation status into a basic validation result, including
/// the qualification analysis (`_scoped_ades_basic_validation`).
pub fn basic_result(
    status: StandardCmsSignatureStatus,
    qualification: &QualificationSpec<'_>,
    poe_time: Option<Moment>,
) -> BasicValidationResult {
    let (sub, _) = crate::with_time::basic_with_content_ts(&status, qualification, None);
    let mut result = BasicValidationResult {
        ades_subindic: sub,
        api_status: None,
        failure_msg: None,
        qualification: None,
    };
    if sub != AdesSubIndic::Passed(AdesPassed::OK) {
        result.api_status = Some(status);
        return result;
    }
    if let (Some(registry), Some(path)) = (qualification.registry, status.signature.validation_path.as_ref()) {
        match qualification_analysis(registry, path, poe_time) {
            Ok(qr) => {
                if let Some(req) = &qualification.requirements {
                    if let Err(e) = enforce_requirements(req, &qr, path) {
                        result.ades_subindic = e.ades_subindication;
                        result.failure_msg = Some(e.failure_message.clone());
                    }
                }
                result.qualification = Some(qr);
            }
            Err(msg) => {
                // pyHanko raises here; fail closed.
                result.ades_subindic = AdesIndeterminate::GENERIC.into();
                result.failure_msg = Some(msg);
            }
        }
    }
    result.api_status = Some(status);
    result
}

/// Digest algorithm of the first `SignerInfo` of a DER `ContentInfo`.
fn signer_digest_algorithm(content_info: &[u8]) -> Option<DigestAlgorithm> {
    use der::Decode;
    let ci = cms::content_info::ContentInfo::from_der(content_info).ok()?;
    let sd: cms::signed_data::SignedData = ci.content.decode_as().ok()?;
    let si = sd.signer_infos.0.iter().next()?;
    DigestAlgorithm::from_oid(&si.digest_alg.oid)
}

/// Basic validation of a CMS signature (`ades_basic_validation`).
///
/// `content_info` is the DER `ContentInfo`; `raw_digest` is the digest of
/// detached content (PDF byte ranges), computed with the signer's digest
/// algorithm. Errors other than [`HankoError::NotImplemented`] from the CMS
/// layer become failed / indeterminate results, as pyHanko's
/// `SignatureValidationError`s do.
pub fn basic_validation(
    content_info: &[u8],
    raw_digest: Option<&[u8]>,
    ctx: &ValidationContext,
    qualification: &QualificationSpec<'_>,
) -> Result<BasicValidationResult, HankoError> {
    match cms_status(content_info, raw_digest, ctx)? {
        Ok(status) => Ok(basic_result(status, qualification, Some(ctx.timing().validation_time))),
        Err((sub, msg)) => Ok(BasicValidationResult {
            ades_subindic: sub,
            api_status: None,
            failure_msg: Some(msg),
            qualification: None,
        }),
    }
}

/// Run the CMS validation; `Ok(Err(..))` carries the AdES sub-indication of
/// a validation error (pyHanko's `SignatureValidationError` path).
pub(crate) fn cms_status(
    content_info: &[u8],
    raw_digest: Option<&[u8]>,
    ctx: &ValidationContext,
) -> Result<Result<StandardCmsSignatureStatus, (AdesSubIndic, String)>, HankoError> {
    let content = match raw_digest {
        Some(d) => {
            let alg = signer_digest_algorithm(content_info)
                .ok_or_else(|| HankoError::Malformed("cannot read the signer's digest algorithm".into()))?;
            SignedContent::Digest(alg, d)
        }
        None => SignedContent::Encapsulated,
    };
    match hanko_cms::validate_cms_signature(content_info, content, ctx) {
        Ok(status) => Ok(Ok(status)),
        Err(e @ HankoError::NotImplemented(_)) => Err(e),
        Err(e) => {
            let sub: AdesSubIndic = match e {
                HankoError::Malformed(_) => AdesFailure::FORMAT_FAILURE.into(),
                _ => AdesIndeterminate::GENERIC.into(),
            };
            Ok(Err((sub, e.to_string())))
        }
    }
}

/// `_qualification_analysis`.
pub fn qualification_analysis(
    registry: &TspRegistry,
    path: &ValidationPath,
    moment: Option<Moment>,
) -> Result<QualificationResult, String> {
    QualificationAssessor::new(registry)
        .check_entity_cert_qualified(path, moment)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_mapping() {
        let s = |e: ValidationError, ee| subindication_for_validation_error(&e, ee).standard_name();
        assert_eq!(s(ValidationError::PathBuilding("x".into()), true), "NO_CERTIFICATE_CHAIN_FOUND");
        assert_eq!(
            s(
                ValidationError::Revoked {
                    msg: "x".into(),
                    revocation_time: None,
                    reason: None
                },
                true
            ),
            "REVOKED_NO_POE"
        );
        assert_eq!(
            s(
                ValidationError::Revoked {
                    msg: "x".into(),
                    revocation_time: None,
                    reason: None
                },
                false
            ),
            "REVOKED_CA_NO_POE"
        );
        assert_eq!(s(ValidationError::Expired { msg: "x".into() }, true), "OUT_OF_BOUNDS_NO_POE");
        assert_eq!(s(ValidationError::Expired { msg: "x".into() }, false), "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        assert_eq!(
            s(
                ValidationError::StaleRevinfo {
                    msg: "x".into(),
                    time_cutoff: None
                },
                true
            ),
            "TRY_LATER"
        );
        assert_eq!(s(ValidationError::DisallowedAlgorithm("x".into()), true), "CRYPTO_CONSTRAINTS_FAILURE");
        assert_eq!(s(ValidationError::InsufficientRevinfo("x".into()), true), "CERTIFICATE_CHAIN_GENERAL_FAILURE");
    }

    fn status(intact: bool, valid: bool, problem: Option<TrustProblem>, path: bool) -> SignatureStatus {
        let p = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../hanko-testdata/data/lanes/e/pki/testing-ca/root.cert.pem");
        let cert = hanko_core::cert::Cert::from_pem_or_der(
            &std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
        )
        .unwrap();
        SignatureStatus {
            intact,
            valid,
            trust_problem: problem,
            signing_cert: None,
            signature_mechanism: None,
            md_algorithm: None,
            validation_path: path.then(|| {
                ValidationPath::new(hanko_certvalidator::TrustAnchor::new(cert), vec![], None)
            }),
        }
    }

    #[test]
    fn basic_indications() {
        let n = |s: SignatureStatus| basic_subindication(&s).standard_name();
        assert_eq!(n(status(false, true, None, true)), "HASH_FAILURE");
        assert_eq!(n(status(true, false, None, true)), "SIG_CRYPTO_FAILURE");
        assert_eq!(n(status(true, true, Some(TrustProblem::KeyUsage("x".into())), false)), "CHAIN_CONSTRAINTS_FAILURE");
        assert_eq!(n(status(true, true, None, false)), "NO_CERTIFICATE_CHAIN_FOUND");
        assert_eq!(n(status(true, true, None, true)), "OK");
        assert_eq!(basic_subindication(&status(false, true, None, true)).status().name(), "FAILED");
    }
}
