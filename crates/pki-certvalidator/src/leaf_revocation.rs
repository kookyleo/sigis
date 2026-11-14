//! Private producer state for the current, explicitly key-compromised MAIN profile.

use super::{PathFailure, ValidationContext};
use crate::authority::Cert;
use crate::path::ValidationPath;
use crate::policy::RevocationCheckingRule;
use crate::revinfo::freshness::RevinfoUsability;
use crate::revinfo::{CrlContainer, OcspContainer, Subject};
use der::{Decode, Encode};
use sigis_pki_core::{errors::ValidationError, time::Moment};
use x509_cert::{certificate::Raw, crl::CertificateList, ext::Extension};
use x509_ocsp::{BasicOcspResponse, OcspResponse};

/// The selected revocation channel that authenticated an unresolved event.
#[derive(Debug, PartialEq, Eq)]
pub enum LeafRevocationChannel {
    /// An authenticated OCSP SingleResponse.
    Ocsp,
    /// An authenticated complete CRL and matching entry.
    Crl,
}

/// An authenticated key-compromise event produced only by the current checker.
///
/// A public error cannot construct an authenticated event:
/// ```compile_fail
/// use sigis_pki_certvalidator::validate::AuthenticatedLeafRevocation;
/// let event: AuthenticatedLeafRevocation = Default::default();
/// ```
#[derive(Debug)]
pub struct AuthenticatedLeafRevocation {
    target: Cert,
    issuer: Cert,
    evidence: Vec<u8>,
    effective: Moment,
    rule: RevocationCheckingRule,
    channel: LeafRevocationChannel,
    // The actual selected response/entry is retained, including its index.
    selected_index: usize,
    _reason: x509_cert::ext::pkix::CrlReason,
    _checked_evidence: CheckedEvidence,
}
impl AuthenticatedLeafRevocation {
    /// The actual MAIN certificate checked in this operation.
    pub fn target(&self) -> &Cert {
        &self.target
    }
    /// The actual issuer whose authority was checked.
    pub fn issuer(&self) -> &Cert {
        &self.issuer
    }
    /// The exact original authenticated response or CRL bytes.
    pub fn evidence_der(&self) -> &[u8] {
        &self.evidence
    }
    /// The canonical signed issuer-declared effective event time.
    pub fn effective_time(&self) -> Moment {
        self.effective
    }
    /// The original selected revocation rule.
    pub fn rule(&self) -> RevocationCheckingRule {
        self.rule
    }
    /// The channel that authenticated the event.
    pub fn channel(&self) -> LeafRevocationChannel {
        match self.channel {
            LeafRevocationChannel::Ocsp => LeafRevocationChannel::Ocsp,
            LeafRevocationChannel::Crl => LeafRevocationChannel::Crl,
        }
    }
    /// The selected response or entry index in the authenticated evidence.
    pub fn selected_index(&self) -> usize {
        self.selected_index
    }
}

/// A complete current PKIX evaluation with an unresolved authenticated leaf event.
///
/// This is not ordinary current validation success. Its fields and constructors
/// are private; a diagnostic path or public Revoked error cannot construct it.
/// A diagnostic path cannot be promoted by constructing this type:
/// ```compile_fail
/// use sigis_pki_certvalidator::{ValidationContext, ValidationPath};
/// use sigis_pki_certvalidator::validate::CurrentLeafRevocationEvaluation;
/// fn forge(ctx: &ValidationContext, path: ValidationPath) -> CurrentLeafRevocationEvaluation<'_> {
///     CurrentLeafRevocationEvaluation {
///         _context: ctx, path, failure: None, events: Vec::new(),
///         _selected_evidence: Vec::new(), _caller_params: None,
///         _completed_channels: Vec::new(), _reference_timing: *ctx.timing(),
///     }
/// }
/// ```
#[derive(Debug)]
pub struct CurrentLeafRevocationEvaluation<'ctx> {
    pub(super) _context: &'ctx ValidationContext,
    pub(super) path: ValidationPath,
    pub(super) failure: Option<Box<PathFailure>>,
    pub(super) events: Vec<AuthenticatedLeafRevocation>,
    pub(super) _selected_evidence: Vec<CheckedEvidence>,
    pub(super) _caller_params: Option<crate::policy::PkixValidationParams>,
    pub(super) _completed_channels: Vec<CompletedChannel>,
    pub(super) _reference_timing: crate::policy::ValidationTimingParams,
}
impl CurrentLeafRevocationEvaluation<'_> {
    /// The actual fully checked current path and its qualified policies.
    pub fn path(&self) -> &ValidationPath {
        &self.path
    }
    /// The retained current leaf failure, if the leaf is currently revoked.
    pub fn unresolved_failure(&self) -> Option<&PathFailure> {
        self.failure.as_deref()
    }
    /// Authenticated selected events; their presence is not temporal resolution.
    pub fn leaf_events(&self) -> &[AuthenticatedLeafRevocation] {
        &self.events
    }

    /// Move the actual checked facts out without retaining context ownership.
    ///
    /// This performs no validation, callback, fetching, clock access or temporal
    /// resolution. The current leaf failure remains unresolved. In particular,
    /// it does not clone the context or acquire backend close authority.
    ///
    /// Consumption cannot be replayed on the original borrowed evaluation:
    /// ```compile_fail
    /// use sigis_pki_certvalidator::validate::CurrentLeafRevocationEvaluation;
    /// fn twice(evaluated: CurrentLeafRevocationEvaluation<'_>) {
    ///     let facts = evaluated.into_owned_facts();
    ///     let second = evaluated.into_owned_facts();
    /// }
    /// ```
    pub fn into_owned_facts(self) -> CurrentLeafRevocationFacts {
        let Self {
            _context: _,
            path,
            failure,
            events,
            _selected_evidence,
            _caller_params,
            _completed_channels,
            _reference_timing,
        } = self;
        CurrentLeafRevocationFacts {
            path,
            failure,
            events,
            _selected_evidence,
            _caller_params,
            _completed_channels,
            _reference_timing,
        }
    }
}

/// Owned data moved from one actual current leaf-revocation evaluation.
///
/// These facts preserve their original validation reference and unresolved
/// failure. They are not a validated whole context, a current trust verdict or
/// a temporal resolver, and carry no backend ownership or close authority.
/// Constructors are private and the checked evidence cannot be injected.
///
/// An unchecked path cannot be turned into owned completion facts:
/// ```compile_fail
/// use sigis_pki_certvalidator::{ValidationContext, ValidationPath};
/// use sigis_pki_certvalidator::validate::CurrentLeafRevocationFacts;
/// fn forge(ctx: &ValidationContext, path: ValidationPath) -> CurrentLeafRevocationFacts {
///     CurrentLeafRevocationFacts {
///         path, failure: None, events: Vec::new(),
///         _selected_evidence: Vec::new(), _caller_params: None,
///         _completed_channels: Vec::new(), _reference_timing: *ctx.timing(),
///     }
/// }
/// ```
///
/// The type cannot be created as an empty default witness:
/// ```compile_fail
/// use sigis_pki_certvalidator::validate::CurrentLeafRevocationFacts;
/// let facts: CurrentLeafRevocationFacts = Default::default();
/// ```
///
/// Nor can a checked value be cloned for a second operation:
/// ```compile_fail
/// use sigis_pki_certvalidator::validate::CurrentLeafRevocationFacts;
/// fn require_clone<T: Clone>() {}
/// require_clone::<CurrentLeafRevocationFacts>();
/// ```
#[derive(Debug)]
pub struct CurrentLeafRevocationFacts {
    path: ValidationPath,
    failure: Option<Box<PathFailure>>,
    events: Vec<AuthenticatedLeafRevocation>,
    _selected_evidence: Vec<CheckedEvidence>,
    _caller_params: Option<crate::policy::PkixValidationParams>,
    _completed_channels: Vec<CompletedChannel>,
    _reference_timing: crate::policy::ValidationTimingParams,
}

impl CurrentLeafRevocationFacts {
    /// The actual checked path, including its anchor and qualified policies.
    pub fn path(&self) -> &ValidationPath {
        &self.path
    }
    /// The original unresolved current leaf failure, if present.
    pub fn unresolved_failure(&self) -> Option<&PathFailure> {
        self.failure.as_deref()
    }
    /// The actual authenticated selected events, still unresolved.
    pub fn leaf_events(&self) -> &[AuthenticatedLeafRevocation] {
        &self.events
    }
}

pub(crate) fn unsupported(what: &str) -> ValidationError {
    ValidationError::PathValidation(format!(
        "Current leaf-revocation completion is unsupported: {what}"
    ))
}

#[derive(Clone, Debug)]
pub(crate) struct CheckedEvidence {
    _target_der: Vec<u8>,
    _issuer: Cert,
    _signer: Cert,
    _raw_evidence: Vec<u8>,
    _selected_index: Option<usize>,
    _channel: &'static str,
    _rule: RevocationCheckingRule,
    _freshness: RevinfoUsability,
    _this_update: Option<Moment>,
    _next_update: Option<Moment>,
    _reason_coverage: Option<u16>,
    _timing: crate::policy::ValidationTimingParams,
    _revocation_policy: crate::policy::CertRevTrustPolicy,
}

#[derive(Debug)]
pub(crate) struct CompletedChannel {
    _target_der: Vec<u8>,
    _issuer: Cert,
    _rule: RevocationCheckingRule,
    _reason_coverage: u16,
}

/// Pending facts are committed only for an actually selected candidate/channel.
/// This stores no policy object, callback, context clone or mutable global state.
pub(crate) struct CollectorCheckpoint {
    events: usize,
    evidence: usize,
    completed: usize,
    good_ocsp: bool,
    good_crl_key_compromise: bool,
    proof_ineligible: Option<ValidationError>,
}

/// Local to one complete operation. No context state or public witness injector.
pub(crate) struct Collector {
    target: Cert,
    pub(crate) events: Vec<AuthenticatedLeafRevocation>,
    pub(crate) selected_evidence: Vec<CheckedEvidence>,
    good_ocsp: bool,
    good_crl_key_compromise: bool,
    proof_ineligible: Option<ValidationError>,
    pub(crate) completed_channels: Vec<CompletedChannel>,
}
impl Collector {
    pub(crate) fn new(target: &Cert) -> Self {
        Self {
            target: target.clone(),
            events: Vec::new(),
            selected_evidence: Vec::new(),
            good_ocsp: false,
            good_crl_key_compromise: false,
            proof_ineligible: None,
            completed_channels: Vec::new(),
        }
    }
    pub(crate) fn checkpoint(&self) -> CollectorCheckpoint {
        CollectorCheckpoint {
            events: self.events.len(),
            evidence: self.selected_evidence.len(),
            completed: self.completed_channels.len(),
            good_ocsp: self.good_ocsp,
            good_crl_key_compromise: self.good_crl_key_compromise,
            proof_ineligible: self.proof_ineligible.clone(),
        }
    }
    pub(crate) fn rollback(&mut self, checkpoint: CollectorCheckpoint) {
        self.events.truncate(checkpoint.events);
        self.selected_evidence.truncate(checkpoint.evidence);
        self.completed_channels.truncate(checkpoint.completed);
        self.good_ocsp = checkpoint.good_ocsp;
        self.good_crl_key_compromise = checkpoint.good_crl_key_compromise;
        self.proof_ineligible = checkpoint.proof_ineligible;
    }
    pub(crate) fn incomplete_crl_error(
        &self,
        checkpoint: &CollectorCheckpoint,
        subject: &Subject<'_>,
    ) -> Option<ValidationError> {
        self.events[checkpoint.events..]
            .iter()
            .find(|event| {
                event.channel == LeafRevocationChannel::Crl
                    && event.target.der() == subject.cert.der
            })
            .map(|event| {
                crate::revinfo::revoked_error(
                    "CRL",
                    &subject.description,
                    event.effective,
                    event._reason,
                )
            })
    }
    pub(crate) fn complete_crl(
        &mut self,
        ctx: &ValidationContext,
        subject: &Subject<'_>,
        reasons: u16,
    ) {
        self.completed_channels.push(CompletedChannel {
            _target_der: subject.cert.der.clone(),
            _issuer: subject.issuer.clone(),
            _rule: Self::rule(ctx, subject),
            _reason_coverage: reasons,
        });
    }
    fn record_metadata(
        &mut self,
        result: Result<(), ValidationError>,
    ) -> Result<(), ValidationError> {
        if let Err(error) = &result {
            if self.proof_ineligible.is_none() {
                self.proof_ineligible = Some(error.clone());
            }
        }
        result
    }
    pub(crate) fn mark_unsupported(&mut self, what: &str) {
        if self.proof_ineligible.is_none() {
            self.proof_ineligible = Some(unsupported(what));
        }
    }
    pub(crate) fn finish(&self) -> Result<(), ValidationError> {
        if self.events.iter().any(|event| {
            event.channel == LeafRevocationChannel::Crl
                && !self.completed_channels.iter().any(|channel| {
                    channel._target_der == event.target.der()
                        && channel._issuer == event.issuer
                        && channel._reason_coverage & 0b1_1111_1110 == 0b1_1111_1110
                })
        }) {
            return Err(unsupported(
                "a provisional CRL event has no complete selected reason coverage",
            ));
        }
        if !self.events.is_empty() {
            if let Some(error) = &self.proof_ineligible {
                return Err(error.clone());
            }
        }
        Ok(())
    }
    pub(crate) fn original_failure(&self, path: &ValidationPath) -> Option<Box<PathFailure>> {
        self.events.first().map(|event| {
            let channel = match event.channel {
                LeafRevocationChannel::Ocsp => "OCSP response",
                LeafRevocationChannel::Crl => "CRL",
            };
            let total = path.issued_certs().len();
            let error = crate::revinfo::revoked_error(
                channel,
                &path.describe(total.saturating_sub(1), total),
                event.effective,
                x509_cert::ext::pkix::CrlReason::KeyCompromise,
            );
            Box::new(PathFailure {
                error,
                path: Some(path.clone()),
                is_ee_cert: true,
                is_side_validation: false,
                time_horizon: Some(event.effective),
                invalid_certificate: false,
            })
        })
    }
    pub(crate) fn is_main(&self, subject: &Subject<'_>) -> bool {
        subject.is_ee
            && !subject.cert.is_ac
            && !subject.cert.is_ca
            && subject.cert.is(&self.target)
            && subject.stack.len() == 1
    }
    fn rule(ctx: &ValidationContext, subject: &Subject<'_>) -> RevocationCheckingRule {
        let policy = &ctx.revinfo_policy.revocation_checking_policy;
        if subject.is_ee {
            policy.ee_certificate_rule
        } else {
            policy.intermediate_ca_cert_rule
        }
    }
    fn add(&mut self, event: AuthenticatedLeafRevocation) -> Result<(), ValidationError> {
        if self.good_ocsp || self.good_crl_key_compromise {
            return Err(unsupported("selected Good and Revoked evidence conflict"));
        }
        if self.events.iter().any(|old| {
            old.effective != event.effective
                || old.target != event.target
                || old.issuer != event.issuer
        }) {
            return Err(unsupported("selected leaf events disagree"));
        }
        self.events.push(event);
        Ok(())
    }
    pub(crate) fn ocsp_good(
        &mut self,
        ctx: &ValidationContext,
        container: &OcspContainer,
        subject: &Subject<'_>,
        responder: &Cert,
        freshness: RevinfoUsability,
    ) -> Result<(), ValidationError> {
        // Proof-profile limits must not change ordinary Good selection. They
        // become terminal only if this operation needs temporal resolution.
        let _ = self.record_metadata(inspect_ocsp(container, subject));
        self.selected_evidence.push(Self::ocsp_receipt(
            ctx, container, subject, responder, freshness,
        ));
        if self.is_main(subject) {
            if !self.events.is_empty() {
                return Err(unsupported("selected Good and Revoked evidence conflict"));
            }
            self.good_ocsp = true;
        }
        Ok(())
    }
    pub(crate) fn ocsp_revoked(
        &mut self,
        ctx: &ValidationContext,
        container: &OcspContainer,
        subject: &Subject<'_>,
        responder: &Cert,
        freshness: RevinfoUsability,
        event: (Moment, Option<x509_cert::ext::pkix::CrlReason>),
    ) -> Result<(), ValidationError> {
        let (at, reason) = event;
        self.record_metadata(inspect_ocsp(container, subject))?;
        if !self.is_main(subject)
            || reason != Some(x509_cert::ext::pkix::CrlReason::KeyCompromise)
            || at > ctx.timing.validation_time
        {
            return Err(unsupported(
                "only an explicit current MAIN keyCompromise event is eligible",
            ));
        }
        let receipt = Self::ocsp_receipt(ctx, container, subject, responder, freshness);
        self.selected_evidence.push(receipt.clone());
        self.add(AuthenticatedLeafRevocation {
            target: self.target.clone(),
            issuer: subject.issuer.clone(),
            evidence: container.der().to_vec(),
            effective: at,
            rule: Self::rule(ctx, subject),
            channel: LeafRevocationChannel::Ocsp,
            selected_index: container.index,
            _reason: x509_cert::ext::pkix::CrlReason::KeyCompromise,
            _checked_evidence: receipt,
        })
    }
    fn ocsp_receipt(
        ctx: &ValidationContext,
        container: &OcspContainer,
        subject: &Subject<'_>,
        responder: &Cert,
        freshness: RevinfoUsability,
    ) -> CheckedEvidence {
        CheckedEvidence {
            _target_der: subject.cert.der.clone(),
            _issuer: subject.issuer.clone(),
            _signer: responder.clone(),
            _raw_evidence: container.der().to_vec(),
            _selected_index: Some(container.index),
            _channel: "ocsp",
            _rule: Self::rule(ctx, subject),
            _freshness: freshness,
            _this_update: container.this_update(),
            _next_update: container.next_update(),
            _reason_coverage: None,
            _timing: ctx.timing,
            _revocation_policy: ctx.revinfo_policy,
        }
    }
    pub(crate) fn crl_checked(
        &mut self,
        ctx: &ValidationContext,
        crl: &CrlContainer,
        subject: &Subject<'_>,
        signer: &Cert,
        freshness_and_reasons: (RevinfoUsability, u16),
        hit: Option<(Moment, x509_cert::ext::pkix::CrlReason)>,
    ) -> Result<bool, ValidationError> {
        let (freshness, reasons) = freshness_and_reasons;
        let inspection = inspect_crl(crl, subject);
        let selected_index = match inspection {
            Ok(index) => index,
            Err(error) => {
                let result = self.record_metadata(Err(error));
                if hit.is_some() {
                    result?;
                }
                None
            }
        };
        let receipt = CheckedEvidence {
            _target_der: subject.cert.der.clone(),
            _issuer: subject.issuer.clone(),
            _signer: signer.clone(),
            _raw_evidence: crl.der().to_vec(),
            _selected_index: selected_index,
            _channel: "crl",
            _rule: Self::rule(ctx, subject),
            _freshness: freshness,
            _this_update: Some(crl.this_update()),
            _next_update: crl.next_update(),
            _reason_coverage: Some(reasons),
            _timing: ctx.timing,
            _revocation_policy: ctx.revinfo_policy,
        };
        self.selected_evidence.push(receipt.clone());
        if let Some((at, reason)) = hit {
            if !self.is_main(subject)
                || reason != x509_cert::ext::pkix::CrlReason::KeyCompromise
                || at > ctx.timing.validation_time
            {
                return Err(unsupported(
                    "only an explicit current MAIN keyCompromise event is eligible",
                ));
            }
            let index = selected_index
                .ok_or_else(|| unsupported("revoked CRL entry identity was not retained"))?;
            self.add(AuthenticatedLeafRevocation {
                target: self.target.clone(),
                issuer: subject.issuer.clone(),
                evidence: crl.der().to_vec(),
                effective: at,
                rule: Self::rule(ctx, subject),
                channel: LeafRevocationChannel::Crl,
                selected_index: index,
                _reason: reason,
                _checked_evidence: receipt,
            })?;
            return Ok(true);
        }
        if self.is_main(subject) && reasons & (1 << 1) != 0 {
            if !self.events.is_empty() {
                return Err(unsupported("selected Good and Revoked evidence conflict"));
            }
            self.good_crl_key_compromise = true;
        }
        Ok(false)
    }
}

fn extensions(
    exts: Option<&Vec<Extension>>,
    allowed_critical: &[const_oid::ObjectIdentifier],
) -> Result<(), ValidationError> {
    let mut seen = std::collections::BTreeSet::new();
    for ext in exts.into_iter().flatten() {
        if !seen.insert(ext.extn_id) {
            return Err(unsupported("duplicate selected evidence extension"));
        }
        let oid = ext.extn_id.to_string();
        if matches!(
            oid.as_str(),
            "2.5.29.24" | "2.5.29.23" | "2.5.29.27" | "2.5.29.46"
        ) {
            return Err(unsupported(
                "invalidity, hold or delta metadata is outside this profile",
            ));
        }
        if ext.critical && !allowed_critical.contains(&ext.extn_id) {
            return Err(unsupported(
                "unsupported selected critical evidence extension",
            ));
        }
    }
    Ok(())
}

fn inspect_ocsp(container: &OcspContainer, subject: &Subject<'_>) -> Result<(), ValidationError> {
    let malformed = |_| unsupported("selected OCSP is not canonical whole-second DER");
    let outer = OcspResponse::from_der(container.der()).map_err(malformed)?;
    if outer.to_der().map_err(malformed)? != container.der() {
        return Err(unsupported(
            "selected OCSP outer encoding is not canonical DER",
        ));
    }
    let bytes = outer
        .response_bytes
        .ok_or_else(|| unsupported("missing selected OCSP payload"))?;
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).map_err(malformed)?;
    if basic.to_der().map_err(malformed)? != bytes.response.as_bytes() {
        return Err(unsupported("selected OCSP is not canonical DER"));
    }
    extensions(basic.tbs_response_data.response_extensions.as_ref(), &[])?;
    let mut matches = 0;
    for index in 0..container.basic.tbs_response_data.responses.len() {
        let mut candidate = container.clone();
        candidate.index = index;
        if matches!(
            crate::revinfo::ocsp::match_cert_id(&candidate, subject)?,
            crate::revinfo::ocsp::CertIdMatch::Match
        ) {
            matches += 1;
        }
    }
    if matches != 1 {
        return Err(unsupported("ambiguous selected OCSP CertID entries"));
    }
    let single = container
        .single()
        .ok_or_else(|| unsupported("missing selected OCSP SingleResponse"))?;
    extensions(single.single_extensions.as_ref(), &[])?;
    Ok(())
}

fn inspect_crl(
    crl: &CrlContainer,
    subject: &Subject<'_>,
) -> Result<Option<usize>, ValidationError> {
    let strict = CertificateList::<Raw>::from_der(crl.der())
        .map_err(|_| unsupported("selected CRL is not canonical whole-second DER"))?;
    if strict
        .to_der()
        .map_err(|_| unsupported("selected CRL encoding"))?
        != crl.der()
    {
        return Err(unsupported("selected CRL is not canonical DER"));
    }
    if strict.signature_algorithm != strict.tbs_cert_list.signature {
        return Err(unsupported(
            "selected CRL signed and outer signature algorithms disagree",
        ));
    }
    use sigis_pki_core::asn1::oids;
    extensions(
        strict.tbs_cert_list.crl_extensions.as_ref(),
        &[
            oids::CE_ISSUING_DISTRIBUTION_POINT,
            oids::CE_CRL_NUMBER,
            oids::CE_AUTHORITY_KEY_IDENTIFIER,
        ],
    )?;
    // This first profile supports direct complete CRLs only. An indirect entry
    // would require an additional issuer-state interpretation proof.
    let mut selected = None;
    for (index, entry) in strict
        .tbs_cert_list
        .revoked_certificates
        .iter()
        .flatten()
        .enumerate()
    {
        extensions(entry.crl_entry_extensions.as_ref(), &[oids::CE_CRL_REASONS])?;
        if entry
            .crl_entry_extensions
            .iter()
            .flatten()
            .any(|e| e.extn_id == oids::CE_CERTIFICATE_ISSUER)
        {
            return Err(unsupported(
                "indirect CRL entry issuer metadata is outside this profile",
            ));
        }
        if entry.serial_number.as_bytes() == subject.cert.serial {
            if selected.replace(index).is_some() {
                return Err(unsupported("duplicate selected CRL entries"));
            }
            let reasons: Vec<_> = entry
                .crl_entry_extensions
                .iter()
                .flatten()
                .filter(|e| e.extn_id == oids::CE_CRL_REASONS)
                .collect();
            if reasons.len() != 1 {
                return Err(unsupported("selected CRL event has no explicit reason"));
            }
            let reason =
                x509_cert::ext::pkix::CrlReason::from_der(reasons[0].extn_value.as_bytes())
                    .map_err(|_| unsupported("malformed selected CRL reason"))?;
            if reason != x509_cert::ext::pkix::CrlReason::KeyCompromise {
                return Err(unsupported("selected CRL reason is outside keyCompromise"));
            }
        }
    }
    Ok(selected)
}
