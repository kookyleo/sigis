// Derived from pyHanko 0.38.1 sign/validation/ades.py (MIT).
//! Archival validation with authenticated proofs of existence.
use super::{
    basic::{basic_subindication, QualificationSpec},
    with_time::{timestamp_subindication, with_time_result_at_poe},
    AdesIndeterminate, AdesPassed, AdesSubIndic,
};
use sigis_cms::{
    CmsValidationOptions, CmsValidationOrder, SignedContent, StandardCmsSignatureStatus,
    TimestampSignatureStatus,
};
use sigis_cms::{SignedData, SignerInfo, TrustProblem};
use sigis_eutl::q_status::QualificationResult;
use sigis_pdf::{EmbeddedSignature, PdfFile, SignatureKind};
use sigis_pki_certvalidator::ltv::LtvError;
use sigis_pki_certvalidator::{
    ltv::{
        past_validate_with,
        poe::{PoeManager, PoeType},
    },
    ValidationContext,
};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::{
    cert::Cert,
    errors::{HankoError, Result},
    fetch::Fetchers,
    time::Moment,
};
/// Outcome of validation using archival data.
#[derive(Clone, Debug)]
pub struct LtaValidationResult {
    /// Final ETSI sub-indication.
    pub ades_subindic: AdesSubIndic,
    /// Actual cryptographic validation status.
    pub api_status: Option<StandardCmsSignatureStatus>,
    /// Earliest proven existence of the signature.
    pub best_signature_time: Option<Moment>,
    /// Signer qualification at the proven signing time.
    pub qualification: Option<QualificationResult>,
    /// Diagnostic for unsuccessful validation.
    pub failure_msg: Option<String>,
    /// Authenticated and explicitly supplied proofs used by validation.
    pub poe: PoeManager,
}
/// Caller-provided knowledge and independent attribute-certificate trust.
#[derive(Default)]
pub struct LtaOptions<'a> {
    /// Explicit proofs, never inferred from DSS membership alone.
    pub known_poes: Option<&'a PoeManager>,
    /// Separate trust context for attribute certificates.
    pub ac_validation_context: Option<&'a ValidationContext>,
}
fn malformed(e: impl std::fmt::Display) -> HankoError {
    HankoError::Malformed(e.to_string())
}
fn signed_data(bytes: &[u8]) -> Result<SignedData> {
    Ok(SignedData::from_der(bytes)?)
}
fn signer(sd: &SignedData) -> Result<&SignerInfo> {
    if sd.signer_infos.len() != 1 {
        return Err(malformed("exactly one CMS signer is required"));
    }
    sd.signer_infos
        .first()
        .ok_or_else(|| malformed("missing CMS signer"))
}
fn certs(sd: &SignedData) -> Result<Vec<Cert>> {
    sd.certificates
        .iter()
        .map(|der| Cert::from_der(der).map_err(HankoError::from))
        .collect()
}
fn at(ctx: &ValidationContext, time: Moment, best: Moment, online: bool) -> ValidationContext {
    let mut timing = *ctx.timing();
    timing.validation_time = time;
    timing.best_signature_time = best;
    timing.point_in_time_validation = true;
    let out = ctx.with_timing(timing);
    if online {
        out
    } else {
        out.with_fetchers(Fetchers::default())
    }
}
fn dss_context(file: &PdfFile, ctx: &ValidationContext) -> Result<ValidationContext> {
    let Some(dss) = file.dss()? else {
        return Ok(ctx.clone());
    };
    let certs = dss
        .material
        .certs
        .iter()
        .map(|c| Cert::from_der(c).map_err(HankoError::from))
        .collect::<Result<Vec<_>>>()?;
    ctx.with_revinfo(
        &certs,
        dss.material.crls.iter().map(Vec::as_slice),
        dss.material.ocsps.iter().map(Vec::as_slice),
    )
    .map_err(Into::into)
}
fn register_cms(poe: &mut PoeManager, bytes: &[u8], time: Moment, kind: PoeType) -> Result<()> {
    register_cms_inner(poe, bytes, time, kind, 0)
}
fn register_cms_inner(
    poe: &mut PoeManager,
    bytes: &[u8],
    time: Moment,
    kind: PoeType,
    depth: usize,
) -> Result<()> {
    if depth > 16 {
        return Err(malformed(
            "nested timestamp proof objects exceed the validation depth limit",
        ));
    }
    let sd = signed_data(bytes)?;
    let si = signer(&sd)?;
    poe.register(bytes, time, kind);
    poe.register(&si.signature, time, kind);
    for cert in certs(&sd)? {
        poe.register(cert.der(), time, kind);
    }
    for cert in &sd.attribute_certificates {
        poe.register(cert, time, kind);
    }
    // Only this authenticated enclosing-material traversal proves archival
    // objects. A signature timestamp by itself never proves RIA evidence.
    let ria = super::adobe_revinfo::archival_material(si)?;
    for bytes in ria.crls.iter().chain(&ria.ocsps) {
        poe.register(bytes, time, kind);
    }
    // A proof of the containing CMS also proves every physically embedded
    // timestamp, including its signature and certificate material.
    for token in sigis_cms::signed_data::find_cms_attribute_iter(
        si.unsigned_attr_list(),
        oids::AA_SIGNATURE_TIME_STAMP_TOKEN,
    )
    .chain(sigis_cms::signed_data::find_cms_attribute_iter(
        si.signed_attr_list(),
        oids::AA_CONTENT_TIMESTAMP,
    )) {
        register_cms_inner(poe, token, time, kind, depth + 1)?;
    }
    Ok(())
}
fn register_material(
    file: &PdfFile,
    poe: &mut PoeManager,
    time: Moment,
    kind: PoeType,
) -> Result<()> {
    if let Some(dss) = file.dss()? {
        for bytes in dss
            .material
            .certs
            .iter()
            .chain(&dss.material.crls)
            .chain(&dss.material.ocsps)
        {
            poe.register(bytes, time, kind);
        }
    }
    for sig in file.embedded_signatures()? {
        register_cms(poe, &sig.contents, time, kind)?;
    }
    Ok(())
}
fn timestamp_tokens(sd: &SignedData) -> Result<Vec<Vec<u8>>> {
    Ok(sigis_cms::signed_data::find_cms_attribute_iter(
        signer(sd)?.unsigned_attr_list(),
        oids::AA_SIGNATURE_TIME_STAMP_TOKEN,
    )
    .map(<[u8]>::to_vec)
    .collect())
}
fn past_timestamp_failure(
    error: LtvError,
) -> (AdesSubIndic, sigis_pki_core::errors::ValidationError) {
    match error {
        LtvError::Validation(error) => (
            super::basic::subindication_for_validation_error(&error, true),
            error,
        ),
        LtvError::TimeSlideFailure { cause, .. } => past_timestamp_failure(*cause),
        other => (
            AdesIndeterminate::NO_POE.into(),
            sigis_pki_core::errors::ValidationError::PathValidation(other.to_string()),
        ),
    }
}
// AdES evaluates the actual caller policy, including its typed time cutoff.
// This adapter preserves metadata that a generic CMS status may not retain.
fn annotate_algorithm_constraint(
    sd: &SignedData,
    signature: &mut sigis_cms::SignatureStatus,
    ctx: &ValidationContext,
) -> Result<()> {
    let si = signer(sd)?;
    let certificate = signature
        .signing_cert
        .clone()
        .unwrap_or(sigis_cms::signed_data::extract_certificate_info(sd)?.signer_cert);
    let policy = ctx.algorithm_policy();
    let sig = policy.signature_algorithm_allowed(
        &si.signature_algorithm,
        Some(ctx.moment()),
        Some(&certificate.public_key()),
    );
    let mut constraints = vec![
        sig,
        policy.digest_algorithm_allowed(&si.digest_algorithm.oid, Some(ctx.moment())),
    ];
    // Validity may fail before certificate algorithm checks at the current
    // time. Retain the actual path's typed algorithm cutoff before time slide
    // rewinds to it and encounters an earlier certificate-validity boundary.
    // Other mandatory path/usage failures keep their existing classification.
    if matches!(
        &signature.trust_problem,
        None | Some(TrustProblem::Path(
            sigis_pki_core::errors::ValidationError::Expired { .. }
                | sigis_pki_core::errors::ValidationError::NotYetValid { .. }
                | sigis_pki_core::errors::ValidationError::DisallowedAlgorithm { .. }
        ))
    ) {
        if let Some(path) = &signature.validation_path {
            for pair in path.certs().windows(2) {
                constraints.push(policy.signature_algorithm_allowed(
                    pair[1].decoded().signature_algorithm(),
                    Some(ctx.moment()),
                    Some(&pair[0].public_key()),
                ));
            }
        }
    }
    // A permanent ban takes precedence; otherwise use the earliest exact
    // cutoff among all denied signature/digest/certificate requirements.
    let denied = constraints
        .into_iter()
        .filter(|c| !c.allowed)
        .min_by_key(|c| c.not_allowed_after);
    if let Some(denied) = denied {
        let message = match &signature.trust_problem {
            Some(TrustProblem::Path(
                error @ sigis_pki_core::errors::ValidationError::DisallowedAlgorithm { .. },
            )) => error.to_string(),
            _ => denied
                .failure_reason
                .unwrap_or_else(|| "Algorithm is not permitted at the validation time".into()),
        };
        signature.trust_problem = Some(TrustProblem::Path(
            sigis_pki_core::errors::ValidationError::DisallowedAlgorithm {
                msg: message,
                banned_since: denied.not_allowed_after,
            },
        ));
        signature.error_time_horizon = denied.not_allowed_after;
        signature.trust_problem_indic = Some(if denied.not_allowed_after.is_some() {
            AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE.into()
        } else {
            AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE.into()
        });
    } else if let Some(TrustProblem::Path(
        error @ sigis_pki_core::errors::ValidationError::DisallowedAlgorithm {
            banned_since, ..
        },
    )) = &signature.trust_problem
    {
        signature.error_time_horizon = *banned_since;
        signature.trust_problem_indic = Some(super::basic::subindication_for_validation_error(
            error, true,
        ));
    }
    Ok(())
}
fn may_recover_algorithm(signature: &sigis_cms::SignatureStatus, poe: Moment) -> bool {
    // This is only eligibility for historical path discovery. Actual trust
    // still requires authenticated signature/path POE and full revalidation.
    signature.intact
        && signature.valid
        && matches!(
            &signature.trust_problem,
            Some(TrustProblem::Path(
                sigis_pki_core::errors::ValidationError::DisallowedAlgorithm {
                    banned_since: Some(cutoff),
                    ..
                }
            )) if poe <= *cutoff
        )
}
fn path_has_poe(
    path: &sigis_pki_certvalidator::ValidationPath,
    poe: &PoeManager,
    control: Moment,
) -> bool {
    path.certs()
        .into_iter()
        .skip(1)
        .all(|cert| poe.poe_time(cert.der()) <= control)
}
fn ts_at(
    token: &[u8],
    expected: &[u8],
    ctx: &ValidationContext,
    poe: &PoeManager,
) -> Result<TimestampSignatureStatus> {
    let sd = signed_data(token)?;
    let mut status = sigis_cms::validate_timestamp_token(token, expected, ctx)?;
    annotate_algorithm_constraint(&sd, &mut status.signature, ctx)?;
    if status.signature.trusted() || !status.signature.intact || !status.signature.valid {
        return Ok(status);
    }
    let Some((known, _)) = poe.get(signer(&sd)?.signature.as_slice()) else {
        return Ok(status);
    };
    if status.signature.validation_path.is_none() && may_recover_algorithm(&status.signature, known)
    {
        let discovery = at(ctx, known, known, false);
        let recovered = sigis_cms::validate_timestamp_token(token, expected, &discovery)?;
        if !recovered.signature.intact || !recovered.signature.valid {
            return Ok(recovered);
        }
        status.signature.validation_path = recovered.signature.validation_path;
    }
    let Some(path) = status.signature.validation_path.as_ref() else {
        return Ok(status);
    };
    // Keep all currently known revocation evidence in scope while sliding.
    let historical = at(ctx, ctx.moment(), known, false);
    let control = match past_validate_with(&historical, path, poe, ctx.moment(), Some(known)) {
        Ok(control) => control,
        Err(error) => {
            let (sub, error) = past_timestamp_failure(error);
            status.signature.trust_problem_indic = Some(sub);
            status.signature.trust_problem = Some(TrustProblem::Path(error));
            status.signature.error_time_horizon = None;
            return Ok(status);
        }
    };
    if known > control || !path_has_poe(path, poe, control) {
        return Ok(status);
    }
    sigis_cms::validate_timestamp_token(token, expected, &at(ctx, control, known, false))
}
fn outcome(
    sub: AdesSubIndic,
    status: Option<StandardCmsSignatureStatus>,
    best: Moment,
    poe: PoeManager,
    msg: Option<String>,
) -> LtaValidationResult {
    LtaValidationResult {
        ades_subindic: sub,
        api_status: status,
        best_signature_time: Some(best),
        qualification: None,
        failure_msg: msg,
        poe,
    }
}
/// Validate a PDF signature using DSS and document timestamps.
pub fn lta_validation(
    file: &PdfFile,
    signature: &EmbeddedSignature,
    ctx: &ValidationContext,
    qual: &QualificationSpec<'_>,
) -> Result<LtaValidationResult> {
    lta_validation_with_options(file, signature, ctx, qual, &LtaOptions::default())
}
/// Validate using caller-provided POEs and independent AC trust.
pub fn lta_validation_with_options(
    file: &PdfFile,
    signature: &EmbeddedSignature,
    ctx: &ValidationContext,
    qual: &QualificationSpec<'_>,
    options: &LtaOptions<'_>,
) -> Result<LtaValidationResult> {
    super::basic::check_timestamp_digests(&signature.contents)?;
    let signed = signature.signed_data(file)?;
    let ctx = super::adobe_revinfo::with_signed_adobe_revinfo(
        &dss_context(file, ctx)?,
        &signature.contents,
        SignedContent::Data(&signed),
    )?;
    let now = ctx.moment();
    let mut poe = PoeManager::with_current_time(now);
    if let Some(known) = options.known_poes {
        poe.merge(known);
    }
    let sd = signed_data(crate::cms_from_contents(&signature.contents)?)?;
    let si = signer(&sd)?;
    let pdf_options = CmsValidationOptions {
        validation_order: CmsValidationOrder::SignerFirst,
        ..Default::default()
    };
    let pdf = crate::validate_pdf_signature_with_options(
        file,
        signature,
        &ctx,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
        &pdf_options,
    )?;
    if pdf.docmdp_ok == Some(false)
        || !matches!(
            pdf.coverage,
            crate::SignatureCoverageLevel::EntireFile
                | crate::SignatureCoverageLevel::EntireRevision
        )
    {
        return Ok(outcome(
            AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into(),
            Some(pdf.cms),
            now,
            poe,
            Some("PDF integrity or modification constraints failed".into()),
        ));
    }
    let ac = options
        .ac_validation_context
        .map(|ac| {
            super::adobe_revinfo::with_signed_adobe_revinfo(
                &dss_context(file, ac)?,
                &signature.contents,
                SignedContent::Data(&signed),
            )
        })
        .transpose()?;
    let cms_options = CmsValidationOptions {
        validation_order: CmsValidationOrder::SignerFirst,
        ac_validation_context: ac.as_ref(),
        ..Default::default()
    };
    let mut status = sigis_cms::validate_cms_signature_with(
        &signature.contents,
        SignedContent::Data(&signed),
        &ctx,
        &cms_options,
    )?;
    annotate_algorithm_constraint(&sd, &mut status.signature, &ctx)?;
    if !status.signature.intact || !status.signature.valid {
        return Ok(outcome(
            basic_subindication(&status.signature),
            Some(status),
            now,
            poe,
            None,
        ));
    }
    let signatures = file.embedded_signatures()?;
    // Evidence-record validation is atomic: one failed member invalidates
    // all POEs derived from this candidate chain. Explicit caller knowledge
    // stays available, but a valid sibling must not rescue a corrupt member.
    let mut candidate_poe = poe.clone();
    let mut chain_valid = true;
    let mut chain_failure = None;
    for dts in signatures.iter().rev().filter(|s| {
        s.kind == SignatureKind::DocTimeStamp && s.signed_revision > signature.signed_revision
    }) {
        let token = crate::cms_from_contents(&dts.contents)?;
        let alg = crate::tst_imprint_algorithm(token)?;
        let ts = ts_at(
            token,
            &alg.digest(&dts.signed_data(file)?),
            &ctx,
            &candidate_poe,
        )?;
        let req = qual.ts_requirements.as_ref().or(qual.requirements.as_ref());
        let ts_sub = timestamp_subindication(&ts, qual, req).0;
        if ts_sub != AdesPassed::OK.into() || ts.timestamp > now {
            chain_valid = false;
            chain_failure = Some(ts_sub);
            break;
        }
        if !matches!(
            crate::signature_coverage(file, dts)?,
            crate::SignatureCoverageLevel::EntireFile
                | crate::SignatureCoverageLevel::EntireRevision
        ) {
            chain_valid = false;
            break;
        }
        // Historical resolver preserves the caller's decoding limits and
        // authentication. The timestamp's own Contents is never proven here.
        let historical = file.historical_resolver(dts.signed_revision);
        if let Some(dss) = sigis_pdf::signatures::read_dss(&historical)? {
            for bytes in dss
                .material
                .certs
                .iter()
                .chain(&dss.material.crls)
                .chain(&dss.material.ocsps)
            {
                candidate_poe.register(bytes, ts.timestamp, PoeType::Timestamp);
            }
        }
        for previous in signatures
            .iter()
            .filter(|s| s.signed_revision < dts.signed_revision)
        {
            register_cms(
                &mut candidate_poe,
                &previous.contents,
                ts.timestamp,
                PoeType::Timestamp,
            )?;
        }
    }
    if chain_valid {
        poe = candidate_poe;
    }
    // A corrupt evidence record cannot supply a plausible historical path.
    // Keep the typed algorithm error/horizon in the API status, but report
    // the missing archival proof when that corruption prevents recovery.
    // Permanent main-signature bans remain permanent in the early return.
    let without_archival_proof = |sub| {
        if matches!(chain_failure, Some(AdesSubIndic::Failure(_)))
            && sub == AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE.into()
        {
            AdesIndeterminate::NO_POE.into()
        } else {
            sub
        }
    };
    let mut best = poe.poe_time(si.signature.as_slice());
    let mut ts_failure = None;
    let mut timestamp = None;
    for token in timestamp_tokens(&sd)? {
        let alg = crate::tst_imprint_algorithm(&token)?;
        let ts = ts_at(&token, &alg.digest(si.signature.as_slice()), &ctx, &poe)?;
        let req = qual.ts_requirements.as_ref().or(qual.requirements.as_ref());
        let (sub, msg) = timestamp_subindication(&ts, qual, req);
        if sub == AdesPassed::OK.into() && ts.timestamp <= now {
            // A cryptographically trusted token does not authorize its
            // independently selected imprint digest to create signature POE.
            // Query the actual imprint at the current reference time. A
            // cutoff alone grants no permission; independent authenticated
            // document/caller POE remains available for recovery.
            if !ctx
                .algorithm_policy()
                .digest_algorithm_allowed(&alg.oid(), Some(now))
                .allowed
            {
                status.timestamp_validity = Some(ts);
                continue;
            }
            best = best.min(ts.timestamp);
            poe.register(si.signature.as_slice(), ts.timestamp, PoeType::Timestamp);
            if timestamp
                .as_ref()
                .is_none_or(|t: &TimestampSignatureStatus| ts.timestamp < t.timestamp)
            {
                timestamp = Some(ts);
            }
        } else {
            ts_failure = Some((
                if ts.timestamp > now {
                    AdesIndeterminate::TIMESTAMP_ORDER_FAILURE.into()
                } else {
                    sub
                },
                msg,
            ));
            status.timestamp_validity = Some(ts);
        }
    }
    if let Some(ts) = timestamp {
        status.timestamp_validity = Some(ts);
    } else if let Some((sub, msg)) = ts_failure {
        let sub = if sub == AdesIndeterminate::OUT_OF_BOUNDS_NO_POE.into() && best == now {
            AdesIndeterminate::NO_POE.into()
        } else {
            sub
        };
        return Ok(outcome(sub, Some(status), best, poe, msg));
    }
    let mut current = with_time_result_at_poe(status.clone(), qual, best, None, now);
    let sub = current.ades_subindic;
    if matches!(sub, AdesSubIndic::Failure(_))
        || sub == AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE.into()
        || sub == AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into()
    {
        return Ok(LtaValidationResult {
            ades_subindic: sub,
            api_status: current.api_status,
            best_signature_time: Some(best),
            qualification: current.qualification,
            failure_msg: current.failure_msg,
            poe,
        });
    }
    // Archival validation still requires the past-validation block when
    // current-time CMS validation passes. In particular, NO_REVOCATION does
    // not itself provide historical revocation evidence or a valid control
    // time. Preserve a current trusted API status if archival proof fails.
    {
        if status.signature.validation_path.is_none()
            && may_recover_algorithm(&status.signature, best)
        {
            let discovery = at(&ctx, best, best, false);
            let candidate = sigis_cms::validate_cms_signature_with(
                &signature.contents,
                SignedContent::Data(&signed),
                &discovery,
                &cms_options,
            )?;
            if candidate.signature.intact && candidate.signature.valid {
                status.signature.validation_path = candidate.signature.validation_path;
            }
        }
        let Some(path) = status.signature.validation_path.as_ref() else {
            return Ok(outcome(
                without_archival_proof(sub),
                Some(status),
                best,
                poe,
                current.failure_msg,
            ));
        };
        // Historical validation uses the authenticated local evidence. Leaving
        // online fetchers enabled would replace a protected OCSP response with
        // a current response (or a failed current request) in the PKI backend.
        let past_ctx = ctx.with_fetchers(Fetchers::none());
        let control = match past_validate_with(&past_ctx, path, &poe, now, Some(best)) {
            Ok(t) => t,
            Err(e) => {
                let message = e.to_string();
                let (cause, _) = past_timestamp_failure(e);
                let failed = if sub == AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE.into() {
                    sub
                } else if cause == AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE.into()
                    || cause == AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE.into()
                {
                    cause
                } else {
                    AdesIndeterminate::NO_POE.into()
                };
                return Ok(outcome(
                    without_archival_proof(failed),
                    Some(status),
                    best,
                    poe,
                    Some(message),
                ));
            }
        };
        if best > control || !path_has_poe(path, &poe, control) {
            let failed = if sub == AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE.into() {
                sub
            } else {
                AdesIndeterminate::NO_POE.into()
            };
            return Ok(outcome(
                without_archival_proof(failed),
                Some(status),
                best,
                poe,
                Some(
                    "Signature or certificate proofs occur after the historical control time"
                        .into(),
                ),
            ));
        }
        let historical = at(&ctx, control, best, false);
        let historical_options = CmsValidationOptions {
            validation_order: CmsValidationOrder::SignerFirst,
            ac_validation_context: ac.as_ref(),
            ts_validation_context: Some(&historical),
            ..Default::default()
        };
        status = sigis_cms::validate_cms_signature_with(
            &signature.contents,
            SignedContent::Data(&signed),
            &historical,
            &historical_options,
        )?;
        current = with_time_result_at_poe(status.clone(), qual, best, None, now);
    }
    let signature_dictionary = crate::sig_dictionary(file, signature)?;
    let (_, seed_error) = crate::seed_values::validate(
        file,
        signature,
        &signature_dictionary,
        current.api_status.as_ref().unwrap_or(&status),
        pdf.docmdp_level,
    )?;
    if let Some(error) = seed_error {
        return Ok(outcome(
            AdesIndeterminate::SIG_CONSTRAINTS_FAILURE.into(),
            current.api_status,
            best,
            poe,
            Some(error.to_string()),
        ));
    }
    Ok(LtaValidationResult {
        ades_subindic: current.ades_subindic,
        api_status: current.api_status,
        best_signature_time: Some(best),
        qualification: current.qualification,
        failure_msg: current.failure_msg,
        poe,
    })
}
/// Assert the collected material exists now, then validate offline in the future.
pub fn simulate_future_lta_validation(
    file: &PdfFile,
    signature: &EmbeddedSignature,
    ctx: &ValidationContext,
    qual: &QualificationSpec<'_>,
    future: Moment,
) -> Result<LtaValidationResult> {
    if future < ctx.moment() {
        return Err(malformed("future validation precedes evidence collection"));
    }
    let mut known = PoeManager::with_current_time(future);
    register_material(file, &mut known, ctx.moment(), PoeType::Provided)?;
    lta_validation_with_options(
        file,
        signature,
        &at(ctx, future, ctx.moment(), false),
        qual,
        &LtaOptions {
            known_poes: Some(&known),
            ..Default::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigis_pki_core::errors::ValidationError;

    #[test]
    fn algorithm_recovery_requires_a_typed_timed_denial() {
        let cutoff = Moment::parse_rfc3339("2025-12-31T23:59:59Z").unwrap();
        let before = Moment::parse_rfc3339("2020-11-20T00:00:00Z").unwrap();
        let after = Moment::parse_rfc3339("2029-01-01T00:00:00Z").unwrap();
        let mut signature = sigis_cms::SignatureStatus {
            intact: true,
            valid: true,
            trust_problem_indic: Some(AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE.into()),
            error_time_horizon: Some(cutoff),
            ..Default::default()
        };
        // Cached status and a cutoff alone grant no recovery, even when a
        // caller has an earlier proof time. In particular they cannot turn
        // a permanent denial into a timed one.
        for problem in [
            None,
            Some(TrustProblem::KeyUsage("mandatory usage failed".into())),
            Some(TrustProblem::Path(ValidationError::DisallowedAlgorithm {
                msg: "ban from 2025-12-31T23:59:59Z".into(),
                banned_since: None,
            })),
        ] {
            signature.trust_problem = problem;
            assert!(!may_recover_algorithm(&signature, before));
        }
        signature.trust_problem = Some(TrustProblem::Path(ValidationError::DisallowedAlgorithm {
            msg: "no date in this diagnostic".into(),
            banned_since: Some(cutoff),
        }));
        assert!(may_recover_algorithm(&signature, before));
        assert!(may_recover_algorithm(&signature, cutoff));
        assert!(!may_recover_algorithm(&signature, after));
        // Redundant status metadata cannot extend or shorten the typed cutoff.
        signature.error_time_horizon = Some(after);
        assert!(!may_recover_algorithm(&signature, after));
        signature.error_time_horizon = None;
        assert!(may_recover_algorithm(&signature, before));
        signature.intact = false;
        assert!(!may_recover_algorithm(&signature, before));
        signature.intact = true;
        signature.valid = false;
        assert!(!may_recover_algorithm(&signature, before));
    }
}
