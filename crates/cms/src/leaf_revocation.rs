//! One-operation consumption of checked current leaf revocation facts.
//!
//! This is deliberately not a historical certificate validator. Current PKIX,
//! revocation freshness and algorithm decisions retain their original clocks.

use super::*;
use sigis_pki_certvalidator::validate::{
    find_current_leaf_revocation_evaluation, CurrentLeafRevocationFacts,
};
use sigis_pki_core::algorithms::AlgorithmUsageConstraint;

#[derive(Debug, Default)]
pub(super) struct MainLeafCompletion {
    facts: Option<CurrentLeafRevocationFacts>,
    pub(super) policy: Option<Arc<dyn CmsAlgorithmUsagePolicy>>,
}

#[derive(Debug, Default)]
pub(super) struct CmsLeafOperation {
    pub(super) main: MainLeafCompletion,
    pub(super) selected_timestamp: Option<SelectedTimestamp>,
    pub(super) selected_content_timestamp: Option<SelectedTimestamp>,
}

#[derive(Debug)]
pub(super) struct SelectedTimestamp {
    // Keep the actual selected encoding and covered signature, not a later
    // token chosen after a purpose, qualification or existence-policy denial.
    _token: Vec<u8>,
    // Signature tokens cover these actual MAIN octets. Content tokens instead
    // use the original operation's ContentDigester callback and keep no false
    // signature-byte binding here; the outer opaque value retains its input.
    _main_signature: Option<Vec<u8>>,
    bound: Option<Moment>,
    imprint_algorithm: Option<ObjectIdentifier>,
    status: TimestampSignatureStatus,
}

impl SelectedTimestamp {
    pub(super) fn from_selected(
        raw: &[u8],
        sd: &SignedData,
        main_signature: Option<&[u8]>,
        status: &TimestampSignatureStatus,
    ) -> Self {
        let info = tst_info(sd).ok();
        let bound = info.as_ref().and_then(|info| {
            // GeneralizedTimeNanos deliberately supports fractional values;
            // this first recovery profile must not truncate them to Moment.
            // Inspect the ORIGINAL signed eContent and use mature strict DER
            // time decoding only after the exact whole-second shape check.
            if info.accuracy.is_some() || info.extensions.is_some() {
                return None;
            }
            let fields = Tlv::parse_exact(sd.econtent.as_deref()?)
                .ok()?
                .children()
                .ok()?;
            let raw_time = fields.get(4)?;
            if !raw_time.is_universal(24)
                || raw_time.constructed
                || raw_time.value.len() != 15
                || raw_time.value.last() != Some(&b'Z')
                || !raw_time.value[..14].iter().all(u8::is_ascii_digit)
            {
                return None;
            }
            der::asn1::GeneralizedTime::from_der(raw_time.raw)
                .ok()
                .map(|time| Moment::from(time.to_date_time()))
        });
        Self {
            _token: raw.to_vec(),
            _main_signature: main_signature.map(<[u8]>::to_vec),
            bound,
            imprint_algorithm: info
                .as_ref()
                .map(|info| info.message_imprint.hash_algorithm.oid),
            status: status.clone(),
        }
    }
}

/// Evaluate the actual current path and all selected revocation obligations at
/// the existing MAIN slot. A supplied path never invokes this entry.
pub(super) fn validate_current_leaf_usage(
    cert: &Cert,
    ctx: &ValidationContext,
    key_usage_settings: &KeyUsageConstraints,
    params: Option<&PkixValidationParams>,
    state: &mut MainLeafCompletion,
) -> CertUsageResult {
    let checked = match find_current_leaf_revocation_evaluation(ctx, cert, params) {
        Ok(checked) => checked,
        Err(failure) => return handle_path_failure(*failure),
    };
    // Consume the producer itself while its real role context is still in
    // scope. This is not reconstruction from diagnostic getters. No context
    // or backend close authority is retained by this moving conversion.
    let facts = checked.into_owned_facts();
    if facts.path().pkix_len() > 0 {
        if let Err(error) = key_usage_settings.validate(cert) {
            return CertUsageResult {
                error_subindic: Some(AdesSubIndic::Indeterminate(
                    AdesIndeterminate::CHAIN_CONSTRAINTS_FAILURE,
                )),
                trust_problem: Some(TrustProblem::KeyUsage(error.0)),
                ..CertUsageResult::default()
            };
        }
    }
    let result = match facts.unresolved_failure() {
        Some(failure) => handle_path_failure(failure.clone()),
        None => CertUsageResult {
            path: Some(facts.path().clone()),
            ..CertUsageResult::default()
        },
    };
    state.facts = Some(facts);
    result
}

/// Frozen result of one CMS evaluation over its original content, contexts and
/// options. Only its own fully checked current leaf facts can be resolved.
///
/// A retained path or public status cannot construct a value of this type. The
/// type is not Clone/Copy/Default, and no API accepts a caller-supplied CV value.
/// Its borrowed inputs bind this operation; they do not freeze interior mutable
/// state behind a caller's Arc. All actual decisions are made by the producer
/// at their original references, before the no-argument consuming resolution.
///
/// Successful narrow resolution retains `revocation_details`, `revoked() ==
/// true`, and the original MAIN `validation_time`. It does not claim current
/// non-revocation or that checks were rerun at the selected TST time. The short
/// status summary prioritises trust; inspect those existing informational fields
/// when reporting this narrow signature conclusion.
#[derive(Debug)]
pub struct CmsLeafRevocationEvaluation<'operation, 'roles> {
    status: StandardCmsSignatureStatus,
    operation: CmsLeafOperation,
    eligible: bool,
    _existence_gate: Option<AlgorithmUsageConstraint>,
    _signed_data: &'operation [u8],
    _content: crate::SignedContent<'operation>,
    _context: &'operation ValidationContext,
    _options: &'operation CmsValidationOptions<'roles>,
}

impl CmsLeafRevocationEvaluation<'_, '_> {
    /// The complete frozen unresolved result, including its typed leaf error,
    /// checked path, actual revocation facts and original reference times.
    pub fn unresolved_status(&self) -> &StandardCmsSignatureStatus {
        &self.status
    }

    /// Consume without resolving anything. No payload, failure or clock changes.
    pub fn into_unresolved_status(self) -> StandardCmsSignatureStatus {
        self.status
    }

    /// The one genuine selected signature TST when ALL operation-local narrow
    /// completion gates passed. This is not a replaceable token or a witness
    /// constructor; qualifications still belong to the context-bearing caller.
    pub fn eligible_signature_timestamp(&self) -> Option<&TimestampSignatureStatus> {
        self.eligible
            .then_some(())
            .and(self.status.timestamp_validity.as_ref())
    }

    /// Consume once and discharge ONLY this operation's authenticated later
    /// MAIN leaf event. No validation, callback, fetch, policy, qualification or
    /// clock access occurs here, and callers cannot supply replacement inputs.
    /// Every refusal returns the complete frozen unresolved payload unchanged.
    pub fn resolve_signature_timestamp(mut self) -> StandardCmsSignatureStatus {
        // Retain ownership of the exact producer facts through consumption;
        // no diagnostic status/path can replace them.
        if self.eligible && self.operation.main.facts.is_some() {
            self.status.signature.trust_problem = None;
            self.status.signature.trust_problem_indic = None;
        }
        self.status
    }
}

fn path_covers_bound(path: &ValidationPath, bound: Moment) -> bool {
    // Check every issued certificate, including intermediate CAs. A trusted by
    // fiat anchor's own certificate is constrained only when requested by the
    // original anchor policy; its explicit service qualifiers always apply.
    if path
        .certs()
        .into_iter()
        .skip(1)
        .any(|cert| bound < cert.not_before() || bound > cert.not_after())
    {
        return false;
    }
    let anchor = path.trust_anchor();
    if anchor.enforce_validity()
        && (bound < anchor.cert().not_before() || bound > anchor.cert().not_after())
    {
        return false;
    }
    let qualifiers = anchor.qualifiers();
    qualifiers.valid_from.is_none_or(|from| bound >= from)
        && qualifiers.valid_until.is_none_or(|until| bound <= until)
}

fn selected_content_bound_is_eligible(
    status: &StandardCmsSignatureStatus,
    operation: &CmsLeafOperation,
    signature_bound: Moment,
) -> bool {
    match (
        status.content_timestamp_validity.as_ref(),
        operation.selected_content_timestamp.as_ref(),
    ) {
        (None, None) => true,
        (Some(public), Some(selected)) => {
            let Some(content_bound) = selected.bound else {
                // A rounded public Moment is not a proof of raw whole-second
                // ordering. Accuracy/extensions require a broader model.
                return false;
            };
            public.trusted()
                && selected.status.trusted()
                && public.timestamp == selected.status.timestamp
                && public.signature.validation_time == selected.status.signature.validation_time
                && public.signature.validation_path == selected.status.signature.validation_path
                && public.signature.signing_cert == selected.status.signature.signing_cert
                && content_bound == public.timestamp
                && content_bound <= signature_bound
                && public.signature.validation_time.is_some_and(|reference| {
                    content_bound <= reference && signature_bound <= reference
                })
                && public
                    .signature
                    .validation_path
                    .as_ref()
                    .is_some_and(|path| {
                        path_covers_bound(path, content_bound)
                            && path_covers_bound(path, signature_bound)
                    })
        }
        // Never infer a safe content bound from an unbound public status.
        _ => false,
    }
}

fn ready_for_signature_timestamp(
    status: &StandardCmsSignatureStatus,
    operation: &CmsLeafOperation,
    ctx: &ValidationContext,
    options: &CmsValidationOptions<'_>,
) -> bool {
    let Some(facts) = operation.main.facts.as_ref() else {
        return false;
    };
    if options.validation_path.is_some()
        || ctx.best_signature_time() != ctx.timing().validation_time
        || facts.leaf_events().is_empty()
        || !status.signature.intact
        || !status.signature.valid
        || status
            .ac_validation_errs
            .as_ref()
            .is_some_and(|errors| !errors.is_empty())
        || status.signature.validation_path.as_ref() != Some(facts.path())
    {
        return false;
    }
    let Some(failure) = facts.unresolved_failure() else {
        return false;
    };
    if failure.invalid_certificate || failure.is_side_validation || !failure.is_ee_cert {
        return false;
    }
    // Every status fact must still name the exact eligible unresolved leaf
    // failure produced in this operation. A stale OK indicator is not evidence.
    if status.signature.trust_problem != Some(TrustProblem::Path(failure.error.clone()))
        || status.signature.trust_problem_indic
            != Some(AdesSubIndic::Indeterminate(
                AdesIndeterminate::REVOKED_NO_POE,
            ))
    {
        return false;
    }
    let Some(details) = status.signature.revocation_details.as_ref() else {
        return false;
    };
    if details.ca_revoked || details.revocation_reason != Some("key_compromise") {
        return false;
    }
    let Some(selected) = operation.selected_timestamp.as_ref() else {
        return false;
    };
    let Some(bound) = selected.bound else {
        return false;
    };
    if !selected.status.trusted()
        || selected
            .status
            .signature
            .validation_time
            .is_none_or(|reference| bound > reference)
        || bound != selected.status.timestamp
        || bound > ctx.timing().validation_time
        || !path_covers_bound(facts.path(), bound)
        || !selected_content_bound_is_eligible(status, operation, bound)
        || selected
            .status
            .signature
            .validation_path
            .as_ref()
            .is_none_or(|path| !path_covers_bound(path, bound))
    {
        return false;
    }
    facts.leaf_events().iter().all(|event| {
        Some(event.target()) == status.signature.signing_cert.as_ref()
            && event.effective_time() > bound
            && event.effective_time() <= ctx.timing().validation_time
            && details.revocation_date == Some(event.effective_time())
    })
}

/// Evaluate a genuine CMS signature and freeze the one selected trusted
/// signature timestamp alongside its own complete current MAIN evaluation.
///
/// Existing ordinary entrypoints and ordering remain unchanged. This additive
/// producer never accepts externally supplied checked facts or substitutes a
/// weaker context. Invalidity, algorithms, constraints, application purpose,
/// AC errors, supplied-path or ambiguous-path recovery remain refusals.
/// The first supported profile is current-valid explicit KeyCompromise with
/// canonical whole-second evidence/TST and no declared TST Accuracy. It is not
/// generic historical or full LTA validation.
pub fn evaluate_cms_leaf_revocation<'operation, 'roles>(
    signed_data: &'operation [u8],
    content: crate::SignedContent<'operation>,
    ctx: &'operation ValidationContext,
    options: &'operation CmsValidationOptions<'roles>,
) -> CmsResult<CmsLeafRevocationEvaluation<'operation, 'roles>> {
    // Reject ambiguity at the direct entry BEFORE parsing/content work.
    if options.key_usage_settings.is_some() && options.exact_key_usage_settings.is_some() {
        return Err(CmsError::Malformed(
            "key_usage_settings and exact_key_usage_settings are mutually exclusive".into(),
        ));
    }
    let sd = SignedData::from_der(signed_data)?;
    let mut operation = CmsLeafOperation::default();
    let status = match content {
        crate::SignedContent::Data(data) => validate_detached_cms_operation(
            &sd,
            &DataDigester::new(data),
            false,
            Some(ctx),
            options,
            Some(&mut operation),
        )?,
        crate::SignedContent::Digest(algorithm, digest) => validate_detached_cms_operation(
            &sd,
            &PrecomputedDigest {
                algorithm,
                digest: digest.to_vec(),
            },
            false,
            Some(ctx),
            options,
            Some(&mut operation),
        )?,
        crate::SignedContent::Encapsulated => {
            let data = sd.econtent.as_deref().unwrap_or_default();
            validate_detached_cms_operation(
                &sd,
                &DataDigester::new(data),
                true,
                Some(ctx),
                options,
                Some(&mut operation),
            )?
        }
    };
    let preliminarily_eligible = ready_for_signature_timestamp(&status, &operation, ctx, options);
    // The selected token has already passed actual TSA CMS/path/purpose and
    // imprint validation at its original reference. Check its EXISTENCE hash
    // exactly once at the original MAIN validation time using the SAME effective
    // MAIN policy captured before any role-context mutation. Never retry tokens.
    let existence_gate = preliminarily_eligible.then(|| {
        let selected = operation.selected_timestamp.as_ref();
        let policy = operation.main.policy.as_ref();
        match (selected, policy) {
            (
                Some(SelectedTimestamp {
                    imprint_algorithm: Some(algorithm),
                    ..
                }),
                Some(policy),
            ) => policy.digest_algorithm_allowed(algorithm, Some(ctx.timing().validation_time)),
            _ => AlgorithmUsageConstraint::denied("missing operation-bound imprint policy"),
        }
    });
    let eligible = existence_gate.as_ref().is_some_and(|gate| gate.allowed);
    Ok(CmsLeafRevocationEvaluation {
        status,
        operation,
        eligible,
        _existence_gate: existence_gate,
        _signed_data: signed_data,
        _content: content,
        _context: ctx,
        _options: options,
    })
}
