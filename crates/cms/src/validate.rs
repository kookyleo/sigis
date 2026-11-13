// Derived from pyHanko `sign/validation/generic_cms.py` (MIT, see LICENSE-pyHanko).

//! CMS signature validation (`pyhanko.sign.validation.generic_cms`).
//!
//! The function names follow pyHanko:
//!
//! | pyHanko | here |
//! | --- | --- |
//! | `validate_sig_integrity` | [`validate_sig_integrity`] |
//! | `validate_algorithm_protection` | [`validate_algorithm_protection`] |
//! | `extract_certs_for_validation` | [`extract_certs_for_validation`] |
//! | `cms_basic_validation` | [`cms_basic_validation`] |
//! | `validate_cert_usage` + `handle_certvalidator_errors` | [`validate_cert_usage`] |
//! | `async_validate_cms_signature` | [`validate_cms_signature_basic`] |
//! | `extract_self_reported_ts` | [`extract_self_reported_ts`] |
//! | `extract_tst_data_iter` | [`extract_tst_data`] |
//! | `collect_timing_info` | [`collect_timing_info`] |
//! | `validate_tst_signed_data` | [`validate_tst_signed_data`] |
//! | `async_validate_detached_cms` | [`validate_detached_cms_with`] |

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;
use x509_tsp::TstInfo;

use sigis_pki_certvalidator::{
    find_valid_path, validate_path_detailed, PathFailure, PkixValidationParams, ValidationContext,
    ValidationPath,
};
use sigis_pki_core::algorithms::{
    validate_signature, DigestAlgorithm, SignatureMechanism, SignatureValidationContext,
};
use sigis_pki_core::asn1::ess::{SigningCertificate, SigningCertificateV2};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::asn1::raw_oid::RawOid;
use sigis_pki_core::asn1::tlv::Tlv;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::ValidationError;
use sigis_pki_core::time::Moment;

use crate::attributes::{collect_signer_attr_status, SignerAttrStatus};
use crate::errors::{CmsError, CmsResult};
use crate::policy::{digest_name, lift_policy, signature_algorithm_name, CmsAlgorithmUsagePolicy};
use crate::signed_data::{
    check_ess_certid, extract_certificate_info, extract_signer_info, find_cms_attribute_iter,
    find_unique_cms_attribute, AttributeLookupError, CmsAttribute, EssCertIdAny, SignedData,
    SignedDataCerts, SignerInfo,
};
use crate::status::{
    human_friendly, RevocationDetails, SignatureStatus, StandardCmsSignatureStatus,
    TimestampSignatureStatus, TrustProblem,
};
use sigis_pki_core::ades::{AdesFailure, AdesIndeterminate, AdesSubIndic};
use sigis_pki_core::key_usage::KeyUsageConstraints;

/// Which pyHanko status class a validation reports, which fixes the default
/// key usage requirements (`default_usage_constraints`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusKind {
    /// `SignatureStatus` / `StandardCMSSignatureStatus`: `non_repudiation`.
    Signature,
    /// `TimestampSignatureStatus`: extended key usage `time_stamping`.
    Timestamp,
}

impl StatusKind {
    /// `default_usage_constraints(key_usage_settings)`: start from the
    /// class defaults and override key usage and extended key usage with
    /// the settings given. Other settings are dropped, as in pyHanko.
    pub fn default_usage_constraints(
        self,
        settings: Option<&KeyUsageConstraints>,
    ) -> KeyUsageConstraints {
        let (ku, eku): (BTreeSet<String>, Option<BTreeSet<String>>) = match self {
            Self::Signature => (["non_repudiation".to_owned()].into(), None),
            Self::Timestamp => (BTreeSet::new(), Some(["time_stamping".to_owned()].into())),
        };
        let settings = settings.cloned().unwrap_or_default();
        KeyUsageConstraints {
            key_usage: Some(settings.key_usage.unwrap_or(ku)),
            extd_key_usage: settings.extd_key_usage.or(eku),
            ..KeyUsageConstraints::default()
        }
    }
}

/// Supplies digests of the signed content for any digest algorithm
/// (`raw_digest` callables in pyHanko).
pub trait ContentDigester {
    /// The digest of the content with `algorithm`.
    fn digest(&self, algorithm: &AlgorithmIdentifierOwned) -> CmsResult<Vec<u8>>;
}

/// Digests of in-memory data, cached per algorithm.
#[derive(Debug)]
pub struct DataDigester<'a> {
    data: &'a [u8],
    cache: RefCell<Vec<(ObjectIdentifier, Vec<u8>)>>,
}

impl<'a> DataDigester<'a> {
    /// Digest `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            cache: RefCell::new(Vec::new()),
        }
    }
}

/// `TSTDigestNotAvailableError` / unsupported digest algorithm.
pub(crate) fn digest_not_available(alg: &AlgorithmIdentifierOwned) -> CmsError {
    CmsError::validation_generic(format!("Unknown hash function '{}'", digest_name(&alg.oid)))
}

/// Resolve a digest algorithm identifier.
pub fn digest_algorithm(alg: &AlgorithmIdentifierOwned) -> CmsResult<DigestAlgorithm> {
    DigestAlgorithm::from_oid(&alg.oid).ok_or_else(|| digest_not_available(alg))
}

impl ContentDigester for DataDigester<'_> {
    fn digest(&self, algorithm: &AlgorithmIdentifierOwned) -> CmsResult<Vec<u8>> {
        if let Some((_, d)) = self
            .cache
            .borrow()
            .iter()
            .find(|(oid, _)| *oid == algorithm.oid)
        {
            return Ok(d.clone());
        }
        let d = digest_algorithm(algorithm)?.digest(self.data);
        self.cache.borrow_mut().push((algorithm.oid, d.clone()));
        Ok(d)
    }
}

/// A single precomputed digest (for example a PDF byte range digest). Other
/// algorithms are not available.
#[derive(Clone, Debug)]
pub struct PrecomputedDigest {
    /// The digest algorithm.
    pub algorithm: DigestAlgorithm,
    /// The digest value.
    pub digest: Vec<u8>,
}

impl ContentDigester for PrecomputedDigest {
    fn digest(&self, algorithm: &AlgorithmIdentifierOwned) -> CmsResult<Vec<u8>> {
        if DigestAlgorithm::from_oid(&algorithm.oid) == Some(self.algorithm) {
            Ok(self.digest.clone())
        } else {
            Err(digest_not_available(algorithm))
        }
    }
}

/// `CMSAlgorithmProtection` (RFC 6211).
#[derive(Clone, Debug, PartialEq, Eq, der::Sequence)]
struct CmsAlgorithmProtection {
    digest_algorithm: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    signature_algorithm: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    mac_algorithm: Option<AlgorithmIdentifierOwned>,
}

/// Compare algorithm identifiers as asn1crypto's `.native` does: absent
/// and NULL parameters are both `None`.
fn same_algorithm(a: &AlgorithmIdentifierOwned, b: &AlgorithmIdentifierOwned) -> bool {
    let norm = |p: &Option<der::Any>| -> Option<Vec<u8>> {
        p.as_ref()
            .filter(|any| !(der::Tagged::tag(*any) == der::Tag::Null && any.value().is_empty()))
            .and_then(|any| any.to_der().ok())
    };
    a.oid == b.oid && norm(&a.parameters) == norm(&b.parameters)
}

/// `validate_algorithm_protection`: check the RFC 6211 attribute, if present.
/// Errors are reported as pyHanko's `validate_sig_integrity` re-raises them.
pub fn validate_algorithm_protection(
    attrs: &[CmsAttribute],
    claimed_digest_algorithm: &AlgorithmIdentifierOwned,
    claimed_signature_algorithm: Option<&AlgorithmIdentifierOwned>,
    claimed_mac_algorithm: Option<&AlgorithmIdentifierOwned>,
) -> CmsResult<()> {
    let value = match find_unique_cms_attribute(Some(attrs), oids::CMS_ALGORITHM_PROTECTION) {
        Ok(v) => v,
        Err(AttributeLookupError::Nonexistent(_)) => return Ok(()),
        Err(AttributeLookupError::Multivalued(_)) => {
            return Err(CmsError::validation(
                "Multiple CMS algorithm protection attributes present",
                AdesSubIndic::Failure(AdesFailure::FORMAT_FAILURE),
            ))
        }
    };
    let prot = CmsAlgorithmProtection::from_der(value)
        .map_err(|e| CmsError::Malformed(format!("CMSAlgorithmProtection: {e}")))?;
    let generic =
        |m: &str| CmsError::validation(m, AdesSubIndic::Indeterminate(AdesIndeterminate::GENERIC));
    if !same_algorithm(&prot.digest_algorithm, claimed_digest_algorithm) {
        return Err(generic(
            "Digest algorithm does not match CMS algorithm protection attribute.",
        ));
    }
    if let Some(claimed) = claimed_signature_algorithm {
        match &prot.signature_algorithm {
            None => {
                return Err(generic(
                    "CMS algorithm protection attribute not valid for signed data",
                ))
            }
            Some(auth) if !same_algorithm(auth, claimed) => {
                return Err(generic(
                    "Signature mechanism does not match CMS algorithm protection attribute.",
                ))
            }
            Some(_) => {}
        }
    }
    if let Some(claimed) = claimed_mac_algorithm {
        match &prot.mac_algorithm {
            None => {
                return Err(generic(
                    "CMS algorithm protection attribute not valid for authenticated data",
                ))
            }
            Some(auth) if !same_algorithm(auth, claimed) => {
                return Err(generic(
                    "MAC mechanism does not match CMS algorithm protection attribute.",
                ))
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// The signing certificate attribute (`get_signing_cert_attr`): the first
/// `ESSCertID(v2)` of `signingCertificateV2`, else of `signingCertificate`.
/// `Ok(None)` if neither is present.
pub fn get_signing_cert_attr(
    attrs: Option<&[CmsAttribute]>,
) -> CmsResult<Option<Vec<EssCertIdAny>>> {
    let cardinality = || {
        CmsError::validation(
            "Wrong cardinality for signing certificate attribute",
            AdesSubIndic::Indeterminate(AdesIndeterminate::NO_SIGNING_CERTIFICATE_FOUND),
        )
    };
    match find_unique_cms_attribute(attrs, oids::AA_SIGNING_CERTIFICATE_V2) {
        Ok(v) => {
            let sc = SigningCertificateV2::from_der(v)
                .map_err(|e| CmsError::Malformed(format!("SigningCertificateV2: {e}")))?;
            return Ok(Some(sc.certs.into_iter().map(EssCertIdAny::V2).collect()));
        }
        Err(AttributeLookupError::Multivalued(_)) => return Err(cardinality()),
        Err(AttributeLookupError::Nonexistent(_)) => {}
    }
    match find_unique_cms_attribute(attrs, oids::AA_SIGNING_CERTIFICATE) {
        Ok(v) => {
            let sc = SigningCertificate::from_der(v)
                .map_err(|e| CmsError::Malformed(format!("SigningCertificate: {e}")))?;
            Ok(Some(sc.certs.into_iter().map(EssCertIdAny::V1).collect()))
        }
        Err(AttributeLookupError::Multivalued(_)) => Err(cardinality()),
        Err(AttributeLookupError::Nonexistent(_)) => Ok(None),
    }
}

/// `_check_signing_certificate`.
fn check_signing_certificate(cert: &Cert, attrs: Option<&[CmsAttribute]>) -> CmsResult<()> {
    let Some(ids) = get_signing_cert_attr(attrs)? else {
        return Ok(());
    };
    if ids.first().is_some_and(|id| check_ess_certid(cert, id)) {
        return Ok(());
    }
    Err(CmsError::validation(
        format!(
            "Signing certificate attribute does not match selected signer's certificate for subject\"{}\".",
            human_friendly(cert)
        ),
        AdesSubIndic::Indeterminate(AdesIndeterminate::NO_SIGNING_CERTIFICATE_FOUND),
    ))
}

/// `extract_message_digest`.
fn extract_message_digest(attrs: &[CmsAttribute]) -> CmsResult<Vec<u8>> {
    let err = || {
        CmsError::validation_generic(
            "Message digest not found in signature, or multiple message digest attributes present.",
        )
    };
    let value = find_unique_cms_attribute(Some(attrs), oids::MESSAGE_DIGEST).map_err(|_| err())?;
    let t = Tlv::parse_exact(value)?;
    crate::signed_data::octet_string_contents(&t)
}

/// `validate_sig_integrity`: returns `(intact, valid)`.
///
/// `intact` means the message digest attribute matches `actual_digest`
/// (without signed attributes: equal to `valid`); `valid` means the
/// signature verifies. No trust checks are made.
pub fn validate_sig_integrity(
    signer_info: &SignerInfo,
    cert: &Cert,
    expected_content_type: &RawOid,
    actual_digest: &[u8],
) -> CmsResult<(bool, bool)> {
    let md = signer_info.digest();
    let (signed_bytes, prehashed, embedded_digest) = match &signer_info.signed_attrs {
        None => (actual_digest.to_vec(), true, None),
        Some(sa) => {
            validate_algorithm_protection(
                &sa.attrs,
                &signer_info.digest_algorithm,
                Some(&signer_info.signature_algorithm),
                None,
            )?;
            check_signing_certificate(cert, Some(&sa.attrs))?;
            let content_type = find_unique_cms_attribute(Some(&sa.attrs), oids::CONTENT_TYPE)
                .map_err(|_| {
                    CmsError::validation(
                        "Content type not found in signature, or multiple content-type attributes present.",
                        AdesSubIndic::Failure(AdesFailure::FORMAT_FAILURE),
                    )
                })?;
            let content_type = RawOid::from_der(content_type)
                .map_err(|e| CmsError::Malformed(format!("content type: {e}")))?;
            if content_type != *expected_content_type {
                return Err(CmsError::validation(
                    format!(
                        "Content type {} did not match expected value {}",
                        content_type_name(&content_type),
                        content_type_name(expected_content_type)
                    ),
                    AdesSubIndic::Failure(AdesFailure::FORMAT_FAILURE),
                ));
            }
            let embedded = extract_message_digest(&sa.attrs)?;
            (sa.signed_bytes(), false, Some(embedded))
        }
    };
    let valid = validate_signature(
        &signer_info.signature,
        &signed_bytes,
        &cert.public_key(),
        &signer_info.signature_algorithm,
        &SignatureValidationContext {
            contextual_digest: md,
            prehashed,
        },
    )
    .is_ok();
    let intact = match embedded_digest {
        Some(d) => d == actual_digest,
        None => valid,
    };
    Ok((intact, valid))
}

/// The asn1crypto name of a content type.
pub fn content_type_name(raw: &RawOid) -> String {
    let Some(oid) = raw.to_oid() else {
        return raw.dotted();
    };
    match oid {
        oids::CT_DATA => "data",
        oids::CT_SIGNED_DATA => "signed_data",
        oids::CT_ENVELOPED_DATA => "enveloped_data",
        oids::CT_DIGESTED_DATA => "digested_data",
        oids::CT_ENCRYPTED_DATA => "encrypted_data",
        oids::CT_AUTHENTICATED_DATA => "authenticated_data",
        oids::CT_TST_INFO => "tst_info",
        _ => return oid.to_string(),
    }
    .to_owned()
}

/// `extract_certs_for_validation`: find the signer's certificate and check
/// it against the signing certificate attribute (ETSI EN 319 102-1 §5.2.3.4).
pub fn extract_certs_for_validation(sd: &SignedData) -> CmsResult<SignedDataCerts> {
    let info = extract_certificate_info(sd).map_err(|e| match e {
        CmsError::Extraction(_) if sd.signer_infos.len() == 1 => CmsError::validation(
            "signer certificate not included in signature",
            AdesSubIndic::Indeterminate(AdesIndeterminate::NO_SIGNING_CERTIFICATE_FOUND),
        ),
        other => other,
    })?;
    let si = extract_signer_info(sd)?;
    check_signing_certificate(&info.signer_cert, si.signed_attr_list())?;
    Ok(info)
}

/// `_enforce_algorithm_usage`; returns the failure as
/// `DisallowedAlgorithmError` would carry it.
fn enforce_algorithm_usage(
    si: &SignerInfo,
    cert: &Cert,
    policy: &dyn CmsAlgorithmUsagePolicy,
    time_indic: Option<Moment>,
) -> Result<(), ValidationError> {
    let sig_alg = &si.signature_algorithm;
    let allowed = policy.signature_algorithm_allowed(sig_alg, time_indic, Some(&cert.public_key()));
    if !allowed.allowed {
        let mut msg = format!(
            "The algorithm {} is not allowed by the current usage policy.",
            signature_algorithm_name(&sig_alg.oid)
        );
        if let Some(r) = allowed.failure_reason {
            msg.push_str(&format!(" Reason: {r}."));
        }
        return Err(ValidationError::DisallowedAlgorithm {
            msg,
            banned_since: allowed.not_allowed_after,
        });
    }
    let allowed = policy.digest_algorithm_allowed(&si.digest_algorithm.oid, time_indic);
    if !allowed.allowed {
        let mut msg = format!(
            "The algorithm {} is not allowed by the current usage policy.",
            digest_name(&si.digest_algorithm.oid)
        );
        if let Some(r) = allowed.failure_reason {
            msg.push_str(&format!(" Reason: {r}."));
        }
        return Err(ValidationError::DisallowedAlgorithm {
            msg,
            banned_since: allowed.not_allowed_after,
        });
    }
    let combo = policy.digest_combination_allowed(sig_alg, &si.digest_algorithm, None);
    if !combo.allowed {
        return Err(ValidationError::DisallowedAlgorithm {
            msg: combo.failure_reason.unwrap_or_default(),
            banned_since: combo.not_allowed_after,
        });
    }
    Ok(())
}

/// Result of [`validate_cert_usage`] (`CertvalidatorOperationResult`).
#[derive(Clone, Debug, Default)]
pub struct CertUsageResult {
    /// The valid path, on success.
    pub path: Option<ValidationPath>,
    /// On failure: the path on which validation failed, if pyHanko reports one.
    pub error_path: Option<ValidationPath>,
    /// On failure: the AdES sub-indication.
    pub error_subindic: Option<AdesSubIndic>,
    /// On failure: the underlying problem.
    pub trust_problem: Option<TrustProblem>,
    /// Revocation details.
    pub revo_details: Option<RevocationDetails>,
    /// Time horizon of the failure.
    pub error_time_horizon: Option<Moment>,
}

/// `handle_certvalidator_errors`: map a path failure to an AdES status.
pub fn handle_path_failure(f: PathFailure) -> CertUsageResult {
    let mut out = CertUsageResult::default();
    let (sub, path, horizon) = if f.invalid_certificate {
        (
            AdesSubIndic::Indeterminate(AdesIndeterminate::CHAIN_CONSTRAINTS_FAILURE),
            None,
            None,
        )
    } else {
        match &f.error {
            ValidationError::StaleRevinfo { time_cutoff, .. } => (
                AdesSubIndic::Indeterminate(AdesIndeterminate::TRY_LATER),
                None,
                *time_cutoff,
            ),
            ValidationError::DisallowedAlgorithm { banned_since, .. } => (
                AdesSubIndic::Indeterminate(if banned_since.is_some() {
                    AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE
                } else {
                    AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE
                }),
                f.path,
                *banned_since,
            ),
            ValidationError::Revoked {
                revocation_time,
                reason,
                ..
            } => {
                let sub = if f.is_side_validation {
                    AdesSubIndic::Indeterminate(
                        AdesIndeterminate::CERTIFICATE_CHAIN_GENERAL_FAILURE,
                    )
                } else {
                    out.revo_details = Some(RevocationDetails {
                        ca_revoked: !f.is_ee_cert,
                        revocation_date: *revocation_time,
                        revocation_reason: *reason,
                    });
                    if f.is_ee_cert {
                        AdesSubIndic::Indeterminate(AdesIndeterminate::REVOKED_NO_POE)
                    } else {
                        AdesSubIndic::Indeterminate(AdesIndeterminate::REVOKED_CA_NO_POE)
                    }
                };
                (sub, f.path, *revocation_time)
            }
            ValidationError::PathBuilding(_) => (
                AdesSubIndic::Indeterminate(AdesIndeterminate::NO_CERTIFICATE_CHAIN_FOUND),
                None,
                None,
            ),
            ValidationError::Expired { .. } => {
                let sub = if !f.is_side_validation && f.is_ee_cert {
                    AdesSubIndic::Indeterminate(AdesIndeterminate::OUT_OF_BOUNDS_NO_POE)
                } else {
                    AdesSubIndic::Indeterminate(
                        AdesIndeterminate::CERTIFICATE_CHAIN_GENERAL_FAILURE,
                    )
                };
                (sub, f.path, f.time_horizon)
            }
            ValidationError::Malformed(_) => (
                AdesSubIndic::Indeterminate(AdesIndeterminate::CERTIFICATE_CHAIN_GENERAL_FAILURE),
                None,
                None,
            ),
            _ => (
                AdesSubIndic::Indeterminate(AdesIndeterminate::CERTIFICATE_CHAIN_GENERAL_FAILURE),
                f.path,
                None,
            ),
        }
    };
    out.error_subindic = Some(sub);
    out.error_path = path;
    out.error_time_horizon = horizon;
    out.trust_problem = Some(if f.invalid_certificate {
        TrustProblem::KeyUsage(f.error.to_string())
    } else {
        TrustProblem::Path(f.error)
    });
    out
}

/// `validate_cert_usage`: find a valid path (or validate the given one) and
/// check the key usage requirements.
pub fn validate_cert_usage(
    cert: &Cert,
    ctx: &ValidationContext,
    key_usage_settings: &KeyUsageConstraints,
    path: Option<&ValidationPath>,
    params: Option<&PkixValidationParams>,
) -> CertUsageResult {
    let found = match path {
        Some(p) => validate_path_detailed(ctx, p, params).map(|()| p.clone()),
        None => find_valid_path(ctx, cert, params),
    };
    let path = match found {
        Ok(p) => p,
        Err(f) => return handle_path_failure(*f),
    };
    if path.pkix_len() > 0 {
        if let Err(e) = key_usage_settings.validate(cert) {
            return CertUsageResult {
                error_subindic: Some(AdesSubIndic::Indeterminate(
                    AdesIndeterminate::CHAIN_CONSTRAINTS_FAILURE,
                )),
                trust_problem: Some(TrustProblem::KeyUsage(e.0)),
                ..CertUsageResult::default()
            };
        }
    }
    // A trust anchor used directly as signer certificate: no key usage
    // checks (trusted service type qualifiers are not modelled yet, which
    // corresponds to `TrustedServiceType.UNSPECIFIED`).
    CertUsageResult {
        path: Some(path),
        ..CertUsageResult::default()
    }
}

/// Options shared by the validation entry points.
#[derive(Clone, Debug, Default)]
pub struct CmsValidationOptions<'a> {
    /// Context for timestamp tokens; defaults to the signer's context.
    pub ts_validation_context: Option<&'a ValidationContext>,
    /// Context for attribute certificates; without it, ACs are not validated.
    pub ac_validation_context: Option<&'a ValidationContext>,
    /// Key usage requirements for the signer.
    pub key_usage_settings: Option<KeyUsageConstraints>,
    /// CMS algorithm usage policy; defaults to the context's policy, lifted.
    pub algorithm_policy: Option<Arc<dyn CmsAlgorithmUsagePolicy>>,
    /// Validate this path instead of building one.
    pub validation_path: Option<ValidationPath>,
    /// RFC 5280 initial inputs.
    pub pkix_validation_params: Option<PkixValidationParams>,
}

fn empty_context() -> CmsResult<ValidationContext> {
    ValidationContext::builder()
        .build()
        .map_err(|e| CmsError::Malformed(e.to_string()))
}

/// `cms_basic_validation`: integrity and trust of one `SignedData`.
///
/// `raw_digest` is the digest of detached content with the signer's digest
/// algorithm; `None` means the content is encapsulated. Without a context,
/// nothing is trusted (pyHanko falls back to the system trust store; this
/// port does not, which can only be stricter).
pub fn cms_basic_validation(
    sd: &SignedData,
    raw_digest: Option<&[u8]>,
    ctx: Option<&ValidationContext>,
    key_usage_settings: &KeyUsageConstraints,
    algorithm_policy: Option<Arc<dyn CmsAlgorithmUsagePolicy>>,
    validation_path: Option<&ValidationPath>,
    params: Option<&PkixValidationParams>,
) -> CmsResult<SignatureStatus> {
    let mut operation_ctx = match ctx {
        Some(ctx) => ctx.clone(),
        None => empty_context()?,
    };
    cms_basic_validation_in_operation(
        sd,
        raw_digest,
        &mut operation_ctx,
        key_usage_settings,
        algorithm_policy,
        validation_path,
        params,
    )
}

// Only this private owned context accumulates registrations between stages.
// The public caller and independently supplied role contexts remain immutable.
fn cms_basic_validation_in_operation(
    sd: &SignedData,
    raw_digest: Option<&[u8]>,
    ctx: &mut ValidationContext,
    key_usage_settings: &KeyUsageConstraints,
    algorithm_policy: Option<Arc<dyn CmsAlgorithmUsagePolicy>>,
    validation_path: Option<&ValidationPath>,
    params: Option<&PkixValidationParams>,
) -> CmsResult<SignatureStatus> {
    let si = extract_signer_info(sd)?;
    let cert_info = extract_certs_for_validation(sd)?;
    let cert = &cert_info.signer_cert;
    let time_indic = Some(ctx.best_signature_time());
    let policy = algorithm_policy.unwrap_or_else(|| lift_policy(ctx.algorithm_policy_arc()));

    let md_name = digest_name(&si.digest_algorithm.oid);
    let mechanism_name = signature_algorithm_name(&si.signature_algorithm.oid);
    let raw_digest = match raw_digest {
        None => {
            let content = sd.econtent.as_deref().unwrap_or_default();
            digest_algorithm(&si.digest_algorithm)?.digest(content)
        }
        Some(d) => {
            if sd.econtent.is_some() {
                return Err(CmsError::validation(
                    "CMS structural error: detached signatures should not have encapsulated data",
                    AdesSubIndic::Failure(AdesFailure::FORMAT_FAILURE),
                ));
            }
            d.to_vec()
        }
    };

    let mut ades_status = None;
    let mut trust_problem = None;
    let mut error_time_horizon = None;
    if let Err(error) = enforce_algorithm_usage(si, cert, policy.as_ref(), time_indic) {
        // Preserve the typed cutoff; policy rejection does not establish POE.
        let banned_since = match &error {
            ValidationError::DisallowedAlgorithm { banned_since, .. } => *banned_since,
            _ => None,
        };
        ades_status = Some(AdesSubIndic::Indeterminate(if banned_since.is_some() {
            AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE
        } else {
            AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE
        }));
        error_time_horizon = banned_since;
        trust_problem = Some(TrustProblem::Path(error));
    }
    let (intact, valid) = validate_sig_integrity(si, cert, &sd.econtent_type, &raw_digest)?;

    let mut path = None;
    let mut revocation_details = None;
    if valid && ades_status.is_none() {
        // Registering the embedded certificates fails in pyHanko if one has
        // a subject asn1crypto cannot prepare (a `ValueError`).
        if let Some(e) = cert_info
            .other_certs
            .iter()
            .find_map(|c| sigis_pki_certvalidator::names::check_name(c.subject()).err())
        {
            return Ok(SignatureStatus {
                intact,
                valid,
                trust_problem: Some(TrustProblem::Path(ValidationError::Malformed(e))),
                signing_cert: Some(cert.clone()),
                signature_mechanism: SignatureMechanism::from_algorithm_identifier(
                    &si.signature_algorithm,
                    si.digest(),
                )
                .ok(),
                md_algorithm: si.digest(),
                validation_path: None,
                trust_problem_indic: Some(AdesSubIndic::Indeterminate(
                    AdesIndeterminate::CERTIFICATE_CHAIN_GENERAL_FAILURE,
                )),
                pkcs7_signature_mechanism: mechanism_name,
                md_algorithm_name: md_name,
                revocation_details: None,
                error_time_horizon: None,
                validation_time: Some(ctx.moment()),
            });
        }
        // Preserve the reference registration point: only a raw-valid CMS
        // signature with no algorithm denial reaches this block. Registration
        // precedes path trust and timestamp-imprint decisions.
        *ctx = ctx.with_registered_other_certs(&cert_info.other_certs);
        let r = validate_cert_usage(cert, ctx, key_usage_settings, validation_path, params);
        ades_status = r.error_subindic;
        trust_problem = r.trust_problem;
        revocation_details = r.revo_details;
        path = r.path.or(r.error_path);
        error_time_horizon = r.error_time_horizon;
    }

    Ok(SignatureStatus {
        intact,
        valid,
        trust_problem,
        signing_cert: Some(cert.clone()),
        signature_mechanism: SignatureMechanism::from_algorithm_identifier(
            &si.signature_algorithm,
            si.digest(),
        )
        .ok(),
        md_algorithm: si.digest(),
        validation_path: path,
        trust_problem_indic: ades_status,
        pkcs7_signature_mechanism: mechanism_name,
        md_algorithm_name: md_name,
        revocation_details,
        error_time_horizon,
        validation_time: Some(ctx.moment()),
    })
}

/// `async_validate_cms_signature` with `status_cls=SignatureStatus`.
pub fn validate_cms_signature_basic(
    sd: &SignedData,
    raw_digest: Option<&[u8]>,
    ctx: Option<&ValidationContext>,
    key_usage_settings: Option<&KeyUsageConstraints>,
    algorithm_policy: Option<Arc<dyn CmsAlgorithmUsagePolicy>>,
) -> CmsResult<SignatureStatus> {
    let ku = StatusKind::Signature.default_usage_constraints(key_usage_settings);
    cms_basic_validation(sd, raw_digest, ctx, &ku, algorithm_policy, None, None)
}

/// `extract_self_reported_ts`: the `signingTime` attribute, if present
/// exactly once and well-formed.
pub fn extract_self_reported_ts(si: &SignerInfo) -> Option<Moment> {
    let v = find_unique_cms_attribute(si.signed_attr_list(), oids::SIGNING_TIME).ok()?;
    Time::from_der(v).ok().map(Moment::from)
}

/// `extract_tst_data_iter`: the `SignedData` of each timestamp token in the
/// content timestamp (`signed = true`) or signature timestamp attributes.
pub fn extract_tst_data(si: &SignerInfo, signed: bool) -> CmsResult<Vec<SignedData>> {
    let (attrs, oid) = if signed {
        (si.signed_attr_list(), oids::AA_CONTENT_TIMESTAMP)
    } else {
        (si.unsigned_attr_list(), oids::AA_SIGNATURE_TIME_STAMP_TOKEN)
    };
    find_cms_attribute_iter(attrs, oid)
        .map(SignedData::from_content_info_der)
        .collect()
}

/// Parse the `TSTInfo` encapsulated in a timestamp token's `SignedData`.
pub fn tst_info(sd: &SignedData) -> CmsResult<TstInfo> {
    let not_tst = || {
        CmsError::validation(
            "SignedData does not encapsulate TSTInfo",
            AdesSubIndic::Failure(AdesFailure::FORMAT_FAILURE),
        )
    };
    if !sd.econtent_type.is(&oids::CT_TST_INFO) {
        return Err(not_tst());
    }
    let content = sd.econtent.as_deref().ok_or_else(not_tst)?;
    TstInfo::from_der(content).map_err(|_| not_tst())
}

/// `validate_tst_signed_data`: validate a timestamp token and compare its
/// message imprint with `expected_imprint(hash_algorithm)`.
pub fn validate_tst_signed_data(
    tst_sd: &SignedData,
    ctx: Option<&ValidationContext>,
    expected_imprint: &dyn Fn(&AlgorithmIdentifierOwned) -> CmsResult<Vec<u8>>,
    algorithm_policy: Option<Arc<dyn CmsAlgorithmUsagePolicy>>,
) -> CmsResult<TimestampSignatureStatus> {
    let mut operation_ctx = match ctx {
        Some(ctx) => ctx.clone(),
        None => empty_context()?,
    };
    validate_tst_signed_data_in_operation(
        tst_sd,
        &mut operation_ctx,
        expected_imprint,
        algorithm_policy,
    )
}

fn validate_tst_signed_data_in_operation(
    tst_sd: &SignedData,
    ctx: &mut ValidationContext,
    expected_imprint: &dyn Fn(&AlgorithmIdentifierOwned) -> CmsResult<Vec<u8>>,
    algorithm_policy: Option<Arc<dyn CmsAlgorithmUsagePolicy>>,
) -> CmsResult<TimestampSignatureStatus> {
    let info = tst_info(tst_sd)?;
    let timestamp = Moment::from(info.gen_time.to_date_time());
    let ku = StatusKind::Timestamp.default_usage_constraints(None);
    let mut signature =
        cms_basic_validation_in_operation(tst_sd, None, ctx, &ku, algorithm_policy, None, None)?;
    let mi = &info.message_imprint;
    let alg = AlgorithmIdentifierOwned {
        oid: mi.hash_algorithm.oid,
        parameters: mi.hash_algorithm.parameters.clone(),
    };
    let expected = expected_imprint(&alg)?;
    if expected != mi.hashed_message.as_bytes() {
        signature.intact = false;
    }
    Ok(TimestampSignatureStatus {
        signature,
        timestamp,
    })
}

/// Timing information of a signature (`collect_timing_info`).
#[derive(Clone, Debug, Default)]
pub struct TimingInfo {
    /// `signingTime`.
    pub signer_reported_dt: Option<Moment>,
    /// Signature timestamp status.
    pub timestamp_validity: Option<TimestampSignatureStatus>,
    /// Content timestamp status.
    pub content_timestamp_validity: Option<TimestampSignatureStatus>,
}

/// `collect_timing_info`: `signingTime`, and the signature and content
/// timestamps. Of several timestamps of one kind, the first trusted one is
/// reported, else the last one.
pub fn collect_timing_info(
    si: &SignerInfo,
    ts_ctx: Option<&ValidationContext>,
    content: &dyn ContentDigester,
    algorithm_policy: Option<Arc<dyn CmsAlgorithmUsagePolicy>>,
) -> CmsResult<TimingInfo> {
    let mut operation_ctx = match ts_ctx {
        Some(ctx) => ctx.clone(),
        None => empty_context()?,
    };
    collect_timing_info_in_operation(si, &mut operation_ctx, content, algorithm_policy)
}

fn collect_timing_info_in_operation(
    si: &SignerInfo,
    ts_ctx: &mut ValidationContext,
    content: &dyn ContentDigester,
    algorithm_policy: Option<Arc<dyn CmsAlgorithmUsagePolicy>>,
) -> CmsResult<TimingInfo> {
    let mut out = TimingInfo {
        signer_reported_dt: extract_self_reported_ts(si),
        ..TimingInfo::default()
    };
    let signature = si.signature.clone();
    let imprint = move |alg: &AlgorithmIdentifierOwned| -> CmsResult<Vec<u8>> {
        Ok(digest_algorithm(alg)?.digest(&signature))
    };
    for tst in extract_tst_data(si, false)? {
        let status = validate_tst_signed_data_in_operation(
            &tst,
            ts_ctx,
            &imprint,
            algorithm_policy.clone(),
        )?;
        let trusted = status.trusted();
        out.timestamp_validity = Some(status);
        if trusted {
            break;
        }
    }
    // pyHanko does not pass the algorithm policy for content timestamps.
    let content_imprint = |alg: &AlgorithmIdentifierOwned| content.digest(alg);
    for tst in extract_tst_data(si, true)? {
        let status = validate_tst_signed_data_in_operation(&tst, ts_ctx, &content_imprint, None)?;
        let trusted = status.trusted();
        out.content_timestamp_validity = Some(status);
        if trusted {
            break;
        }
    }
    Ok(out)
}

/// `async_validate_detached_cms`, generalized over how the content digest
/// is obtained. With `encapsulated = true` the content is the
/// `SignedData`'s own `eContent` and `content` must digest it.
pub fn validate_detached_cms_with(
    sd: &SignedData,
    content: &dyn ContentDigester,
    encapsulated: bool,
    signer_ctx: Option<&ValidationContext>,
    options: &CmsValidationOptions<'_>,
) -> CmsResult<StandardCmsSignatureStatus> {
    // Context identity determines whether the reference API shares a registry.
    // Equal-valued but separately supplied contexts must stay independent.
    let shared_roles = match (signer_ctx, options.ts_validation_context) {
        (_, None) => true,
        (Some(signer), Some(timestamp)) => core::ptr::eq(signer, timestamp),
        (None, Some(_)) => false,
    };
    let mut signer_operation_ctx = match signer_ctx {
        Some(ctx) => ctx.clone(),
        None => empty_context()?,
    };
    let si = extract_signer_info(sd)?;
    let digest_bytes = content.digest(&si.digest_algorithm)?;
    let timing = if shared_roles {
        collect_timing_info_in_operation(
            si,
            &mut signer_operation_ctx,
            content,
            options.algorithm_policy.clone(),
        )?
    } else {
        let mut timestamp_operation_ctx = options
            .ts_validation_context
            .ok_or_else(|| CmsError::Malformed("independent timestamp context is missing".into()))?
            .clone();
        collect_timing_info_in_operation(
            si,
            &mut timestamp_operation_ctx,
            content,
            options.algorithm_policy.clone(),
        )?
    };
    let ku = StatusKind::Signature.default_usage_constraints(options.key_usage_settings.as_ref());
    let signature = cms_basic_validation_in_operation(
        sd,
        (!encapsulated).then_some(digest_bytes.as_slice()),
        &mut signer_operation_ctx,
        &ku,
        options.algorithm_policy.clone(),
        options.validation_path.as_ref(),
        options.pkix_validation_params.as_ref(),
    )?;
    let cert_info = extract_certificate_info(sd)?;
    let SignerAttrStatus {
        cades_signer_attrs,
        ac_attrs,
        ac_validation_errs,
    } = collect_signer_attr_status(
        &cert_info.attribute_certs,
        &cert_info.signer_cert,
        &cert_info.other_certs,
        options.ac_validation_context,
        si.signed_attr_list(),
    )?;
    Ok(StandardCmsSignatureStatus {
        signature,
        signer_reported_dt: timing.signer_reported_dt,
        timestamp_validity: timing.timestamp_validity,
        content_timestamp_validity: timing.content_timestamp_validity,
        cades_signer_attrs,
        ac_attrs,
        ac_validation_errs,
    })
}

/// Validate a `TimeStampToken` (DER `ContentInfo`) whose message imprint
/// must equal `expected_imprint`, whatever its hash algorithm.
pub fn validate_timestamp_token_with(
    token: &[u8],
    expected_imprint: &[u8],
    ctx: Option<&ValidationContext>,
    algorithm_policy: Option<Arc<dyn CmsAlgorithmUsagePolicy>>,
) -> CmsResult<TimestampSignatureStatus> {
    let sd = SignedData::from_content_info_der(token)?;
    let expected = expected_imprint.to_vec();
    validate_tst_signed_data(&sd, ctx, &move |_| Ok(expected.clone()), algorithm_policy)
}

// Supplemental typed-algorithm regressions, not additional upstream ports.
// Tests were added before the consumer implementation.
#[cfg(test)]
mod algorithm_horizon_tests {
    use super::*;
    use std::sync::Mutex;

    use base64::Engine;
    use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
    use spki::SubjectPublicKeyInfoOwned;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Stage {
        Signature,
        Digest,
        Combination,
    }

    const STAGES: [Stage; 3] = [Stage::Signature, Stage::Digest, Stage::Combination];

    #[derive(Debug)]
    struct RecordingPolicy {
        constraints: [AlgorithmUsageConstraint; 3],
        calls: Mutex<Vec<(Stage, Option<Moment>)>>,
    }

    impl RecordingPolicy {
        fn new(denied: &[Stage], cutoff: Option<Moment>) -> Self {
            Self {
                constraints: STAGES.map(|stage| AlgorithmUsageConstraint {
                    allowed: !denied.contains(&stage),
                    failure_reason: denied.contains(&stage).then(|| format!("{stage:?} denied")),
                    not_allowed_after: cutoff,
                }),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn check(&self, stage: Stage, moment: Option<Moment>) -> AlgorithmUsageConstraint {
            self.calls.lock().unwrap().push((stage, moment));
            self.constraints[STAGES.iter().position(|s| *s == stage).unwrap()].clone()
        }

        fn assert_calls(&self, stages: &[Stage], time: Moment) {
            let expected: Vec<_> = stages
                .iter()
                .map(|stage| (*stage, (*stage != Stage::Combination).then_some(time)))
                .collect();
            assert_eq!(*self.calls.lock().unwrap(), expected);
        }
    }

    impl AlgorithmUsagePolicy for RecordingPolicy {
        fn signature_algorithm_allowed(
            &self,
            _algorithm: &AlgorithmIdentifierOwned,
            moment: Option<Moment>,
            public_key: Option<&SubjectPublicKeyInfoOwned>,
        ) -> AlgorithmUsageConstraint {
            assert!(public_key.is_some());
            self.check(Stage::Signature, moment)
        }

        fn digest_algorithm_allowed(
            &self,
            _algorithm: &ObjectIdentifier,
            moment: Option<Moment>,
        ) -> AlgorithmUsageConstraint {
            self.check(Stage::Digest, moment)
        }
    }

    impl CmsAlgorithmUsagePolicy for RecordingPolicy {
        fn digest_combination_allowed(
            &self,
            _signature_algorithm: &AlgorithmIdentifierOwned,
            _message_digest_algorithm: &AlgorithmIdentifierOwned,
            moment: Option<Moment>,
        ) -> AlgorithmUsageConstraint {
            self.check(Stage::Combination, moment)
        }
    }

    // Read actual CMS bytes and PDF byte-range digest from the committed
    // upstream forbidden-signature fixture. No recorded verdict is consumed.
    fn fixture() -> (SignedData, Vec<u8>, ValidationContext) {
        let bytes = std::fs::read(sigis_testdata::path(&[
            "lanes",
            "a",
            "harvest",
            "test_cms.json",
        ]))
        .unwrap();
        let harvest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let call = harvest["calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|call| {
                call["test"] == "test_forbidden_signature_algorithm"
                    && call["fn"] == "async_validate_pdf_signature"
            })
            .unwrap();
        let input = &call["inputs"];
        let decode = |value: &serde_json::Value| {
            base64::engine::general_purpose::STANDARD
                .decode(value.as_str().unwrap())
                .unwrap()
        };
        let sd = SignedData::from_der(&decode(&input["signed_data"])).unwrap();
        let hex = input["document_digest"].as_str().unwrap();
        let digest = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let vc = &input["vc"];
        let mut context = ValidationContext::builder()
            .moment(Moment::parse_rfc3339(vc["moment"].as_str().unwrap()).unwrap())
            .best_signature_time(
                Moment::parse_rfc3339(vc["best_signature_time"].as_str().unwrap()).unwrap(),
            )
            .revocation_mode("none");
        for root in vc["trust_roots"].as_array().unwrap() {
            let encoded = &harvest["certs"][root.as_str().unwrap()];
            context = context.trust_root(Cert::from_der(&decode(encoded)).unwrap());
        }
        (sd, digest, context.build().unwrap())
    }

    fn expected_message(stage: Stage, reason: &str) -> String {
        match stage {
            Stage::Signature => format!(
                "The algorithm sha256_rsa is not allowed by the current usage policy. Reason: {reason}."
            ),
            Stage::Digest => format!(
                "The algorithm sha256 is not allowed by the current usage policy. Reason: {reason}."
            ),
            Stage::Combination => reason.to_owned(),
        }
    }

    #[test]
    fn cms_constraint_constructor_defaults_do_not_infer_cutoffs() {
        assert_eq!(AlgorithmUsageConstraint::allowed().not_allowed_after, None);
        for reason in ["Denied", "Banned since 2019-12-31T23:59:59Z"] {
            let denied = AlgorithmUsageConstraint::denied(reason);
            assert!(!denied.allowed);
            assert_eq!(denied.failure_reason.as_deref(), Some(reason));
            assert_eq!(denied.not_allowed_after, None);
        }
    }

    #[test]
    fn cms_enforcement_preserves_typed_exact_cutoffs_and_short_circuits() {
        let (sd, _, ctx) = fixture();
        let si = extract_signer_info(&sd).unwrap();
        let certs = extract_certs_for_validation(&sd).unwrap();
        // Equality is intentional: do not round, subtract a second, or infer
        // policy permission from the cutoff. The policy's allowed bit governs.
        let cutoff = ctx.best_signature_time();
        for (i, stage) in STAGES.iter().copied().enumerate() {
            let policy = RecordingPolicy::new(&STAGES[i..], Some(cutoff));
            let error =
                enforce_algorithm_usage(si, &certs.signer_cert, &policy, Some(cutoff)).unwrap_err();
            assert_eq!(
                error,
                ValidationError::DisallowedAlgorithm {
                    msg: expected_message(stage, &format!("{stage:?} denied")),
                    banned_since: Some(cutoff),
                }
            );
            policy.assert_calls(&STAGES[..=i], cutoff);
        }
    }

    #[test]
    fn cms_status_preserves_timed_and_permanent_denials_at_every_stage() {
        let (sd, digest, ctx) = fixture();
        for stage in STAGES {
            for cutoff in [Some(ctx.best_signature_time()), None] {
                let policy = Arc::new(RecordingPolicy::new(&[stage], cutoff));
                let status = cms_basic_validation(
                    &sd,
                    Some(&digest),
                    Some(&ctx),
                    &KeyUsageConstraints::default(),
                    Some(policy.clone()),
                    None,
                    None,
                )
                .unwrap();
                assert!(status.intact);
                assert!(status.valid);
                assert!(!status.trusted());
                assert!(!status.bottom_line());
                assert!(status.validation_path.is_none());
                assert_eq!(status.error_time_horizon, cutoff);
                assert_eq!(
                    status.trust_problem_indic,
                    Some(AdesSubIndic::Indeterminate(if cutoff.is_some() {
                        AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE
                    } else {
                        AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE
                    }))
                );
                assert_eq!(
                    status.trust_problem,
                    Some(TrustProblem::Path(ValidationError::DisallowedAlgorithm {
                        msg: expected_message(stage, &format!("{stage:?} denied")),
                        banned_since: cutoff,
                    }))
                );
                let i = STAGES.iter().position(|s| *s == stage).unwrap();
                policy.assert_calls(&STAGES[..=i], ctx.best_signature_time());
            }
        }
    }

    #[test]
    fn cms_allowed_constraints_ignore_incidental_cutoffs() {
        let (sd, digest, ctx) = fixture();
        for cutoff in [None, Some(Moment::from_unix_secs(1))] {
            let policy = Arc::new(RecordingPolicy::new(&[], cutoff));
            let status = cms_basic_validation(
                &sd,
                Some(&digest),
                Some(&ctx),
                &KeyUsageConstraints::default(),
                Some(policy.clone()),
                None,
                None,
            )
            .unwrap();
            assert!(status.intact);
            assert!(status.valid);
            assert!(status.trusted());
            assert!(status.bottom_line());
            assert!(status.validation_path.is_some());
            assert!(status.trust_problem.is_none());
            assert!(status.trust_problem_indic.is_none());
            assert!(status.error_time_horizon.is_none());
            policy.assert_calls(&STAGES, ctx.best_signature_time());

            let untrusted_ctx = ValidationContext::builder()
                .moment(ctx.moment())
                .best_signature_time(ctx.best_signature_time())
                .revocation_mode("none")
                .build()
                .unwrap();
            let untrusted_policy = Arc::new(RecordingPolicy::new(&[], cutoff));
            let untrusted_status = cms_basic_validation(
                &sd,
                Some(&digest),
                Some(&untrusted_ctx),
                &KeyUsageConstraints::default(),
                Some(untrusted_policy.clone()),
                None,
                None,
            )
            .unwrap();
            assert!(untrusted_status.intact && untrusted_status.valid);
            assert!(!untrusted_status.trusted());
            assert!(!untrusted_status.bottom_line());
            assert!(untrusted_status.validation_path.is_none());
            assert!(untrusted_status.trust_problem.is_some());
            assert!(untrusted_status.trust_problem_indic.is_some());
            assert!(untrusted_status.error_time_horizon.is_none());
            untrusted_policy.assert_calls(&STAGES, ctx.best_signature_time());
        }
    }

    #[test]
    fn cms_date_like_reasons_do_not_create_cutoffs() {
        let (sd, digest, ctx) = fixture();
        let reason = "Banned since 2019-12-31T23:59:59Z";
        for (i, stage) in STAGES.iter().copied().enumerate() {
            let mut policy = RecordingPolicy::new(&[stage], None);
            policy.constraints[i].failure_reason = Some(reason.to_owned());
            let status = cms_basic_validation(
                &sd,
                Some(&digest),
                Some(&ctx),
                &KeyUsageConstraints::default(),
                Some(Arc::new(policy)),
                None,
                None,
            )
            .unwrap();
            assert!(status.intact && status.valid);
            assert!(!status.trusted());
            assert_eq!(status.error_time_horizon, None);
            assert_eq!(
                status.trust_problem_indic,
                Some(AdesSubIndic::Indeterminate(
                    AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE,
                ))
            );
            assert_eq!(
                status.trust_problem,
                Some(TrustProblem::Path(ValidationError::DisallowedAlgorithm {
                    msg: expected_message(stage, reason),
                    banned_since: None,
                }))
            );
        }
    }

    #[test]
    fn cms_path_mapping_preserves_original_path_typed_error_and_cutoff() {
        let (sd, digest, ctx) = fixture();
        let baseline = cms_basic_validation(
            &sd,
            Some(&digest),
            Some(&ctx),
            &KeyUsageConstraints::default(),
            Some(Arc::new(RecordingPolicy::new(&[], None))),
            None,
            None,
        )
        .unwrap();
        assert!(baseline.trusted());
        let path = baseline.validation_path.unwrap();
        for cutoff in [Some(ctx.best_signature_time()), None] {
            let error = ValidationError::DisallowedAlgorithm {
                msg: "Certificate signature denied".to_owned(),
                banned_since: cutoff,
            };
            let mapped = handle_path_failure(PathFailure {
                error: error.clone(),
                path: Some(path.clone()),
                is_ee_cert: true,
                is_side_validation: false,
                // Typed banned_since is authoritative even if legacy contextual
                // metadata is missing or contains an unrelated horizon.
                time_horizon: Some(Moment::from_unix_secs(1)),
                invalid_certificate: false,
            });
            assert!(mapped.path.is_none());
            assert_eq!(mapped.error_path, Some(path.clone()));
            assert_eq!(mapped.trust_problem, Some(TrustProblem::Path(error)));
            assert_eq!(mapped.error_time_horizon, cutoff);
            assert_eq!(
                mapped.error_subindic,
                Some(AdesSubIndic::Indeterminate(if cutoff.is_some() {
                    AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE
                } else {
                    AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE
                }))
            );
            assert!(mapped.revo_details.is_none());
        }
    }

    #[test]
    fn cms_cutoff_never_overrides_failed_integrity() {
        let (sd, mut digest, ctx) = fixture();
        digest[0] ^= 1;
        let cutoff = ctx.best_signature_time();
        for denied in [true, false] {
            let denied_stages: &[Stage] = if denied { &[Stage::Digest] } else { &[] };
            let status = cms_basic_validation(
                &sd,
                Some(&digest),
                Some(&ctx),
                &KeyUsageConstraints::default(),
                Some(Arc::new(RecordingPolicy::new(denied_stages, Some(cutoff)))),
                None,
                None,
            )
            .unwrap();
            assert!(!status.intact);
            assert!(status.valid);
            assert!(!status.trusted());
            assert!(!status.bottom_line());
            if denied {
                assert!(status.validation_path.is_none());
                assert_eq!(status.error_time_horizon, Some(cutoff));
                assert_eq!(
                    status.trust_problem_indic,
                    Some(AdesSubIndic::Indeterminate(
                        AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
                    ))
                );
            } else {
                // An otherwise valid certificate path cannot repair the
                // mismatching content digest, even with incidental metadata.
                assert!(status.validation_path.is_some());
                assert!(status.trust_problem.is_none());
                assert!(status.trust_problem_indic.is_none());
                assert!(status.error_time_horizon.is_none());
            }
        }
    }
}

#[cfg(test)]
#[path = "validate_registration_tests.rs"]
mod operation_registration_tests;

#[cfg(test)]
#[path = "validate_order_tests.rs"]
mod validation_order_tests;
