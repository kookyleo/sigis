// Derived from pyhanko-certvalidator `revinfo/validate_crl.py` (MIT, see LICENSE-pyHanko).

//! CRL-based revocation checking (`verify_crl`): direct and indirect CRLs,
//! delta CRLs, CRL issuers other than the certificate issuer (whose paths
//! are validated too), coverage of revocation reasons across
//! reason-partitioned CRLs, and fetching more CRLs when the supplied ones
//! do not suffice.

use der::Encode;
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::crl::dp::{DistributionPoint, IssuingDistributionPoint};
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::CrlReason;
use x509_cert::ext::Extension;
use x509_cert::name::{Name, RdnSequence};

use super::freshness::{RevinfoUsability, RevinfoUsabilityRating};
use super::{revoked_error, CheckOutcome, CrlContainer, Failures, SelectedOutcome, Subject};
use crate::authority::Cert;
use crate::context::ValidationContext;
use crate::path::ValidationPath;
use sigis_pki_core::algorithms::{validate_signature, SignatureValidationContext};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::errors::ValidationError;
use sigis_pki_core::time::Moment;

/// CRL extensions this module understands (`KNOWN_CRL_EXTENSIONS`).
const KNOWN_CRL_EXTENSIONS: [const_oid::ObjectIdentifier; 6] = [
    oids::CE_ISSUING_DISTRIBUTION_POINT,
    oids::CE_CRL_NUMBER,
    oids::CE_DELTA_CRL_INDICATOR,
    oids::CE_AUTHORITY_KEY_IDENTIFIER,
    oids::CE_FRESHEST_CRL,
    oids::PE_AUTHORITY_INFO_ACCESS,
];

/// CRL entry extensions this module understands.
const KNOWN_ENTRY_EXTENSIONS: [const_oid::ObjectIdentifier; 4] = [
    oids::CE_CRL_REASONS,
    oids::CE_INVALIDITY_DATE,
    oids::CE_HOLD_INSTRUCTION_CODE,
    oids::CE_CERTIFICATE_ISSUER,
];

fn find_extension<'a>(
    exts: Option<&'a Vec<Extension>>,
    oid: &const_oid::ObjectIdentifier,
) -> Option<&'a Extension> {
    exts.and_then(|e| e.iter().find(|x| x.extn_id == *oid))
}

fn has_unknown_critical(
    exts: Option<&Vec<Extension>>,
    known: &[const_oid::ObjectIdentifier],
) -> bool {
    exts.is_some_and(|e| e.iter().any(|x| x.critical && !known.contains(&x.extn_id)))
}

fn crl_extension<'a>(
    crl: &'a CrlContainer,
    oid: &const_oid::ObjectIdentifier,
) -> Option<&'a Extension> {
    find_extension(crl.crl.tbs_cert_list.crl_extensions.as_ref(), oid)
}

pub(crate) fn is_delta(crl: &CrlContainer) -> bool {
    crl_extension(crl, &oids::CE_DELTA_CRL_INDICATOR).is_some()
}

/// The general names a distribution point name stands for; a name relative
/// to the CRL issuer is appended to the issuer's name (RFC 5280 §4.2.1.13).
fn dp_names(name: &DistributionPointName, crl_issuer: &Name) -> Vec<GeneralName> {
    match name {
        DistributionPointName::FullName(names) => names.clone(),
        DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
            let mut seq: RdnSequence = crl_issuer.clone().into();
            seq.push(rdn.clone());
            vec![GeneralName::DirectoryName(Name::hazmat_from_rdn_sequence(
                seq,
            ))]
        }
    }
}

fn parse_idp(crl: &CrlContainer) -> Result<Option<IssuingDistributionPoint>, ValidationError> {
    crl_extension(crl, &oids::CE_ISSUING_DISTRIBUTION_POINT)
        .map(|ext| {
            der::Decode::from_der(ext.extn_value.as_bytes()).map_err(|e: der::Error| {
                ValidationError::Malformed(format!("issuingDistributionPoint: {e}"))
            })
        })
        .transpose()
}

pub(crate) fn signed_by(crl: &CrlContainer, signer: &Cert) -> bool {
    let alg: &AlgorithmIdentifierOwned = &crl.crl.signature_algorithm;
    validate_signature(
        crl.crl.signature.raw_bytes(),
        &crl.tbs,
        &signer.public_key(),
        alg,
        &SignatureValidationContext::default(),
    )
    .is_ok()
}

/// Record a freshness failure; `true` if the CRL is usable.
fn fresh(
    ctx: &ValidationContext,
    crl: &CrlContainer,
    prefix: &str,
    failures: &mut Failures,
) -> bool {
    fresh_outcome(ctx, crl, prefix, failures).is_some()
}

fn fresh_outcome(
    ctx: &ValidationContext,
    crl: &CrlContainer,
    prefix: &str,
    failures: &mut Failures,
) -> Option<RevinfoUsability> {
    let usability = ctx.freshness_judge.judge(
        Some(crl.this_update()),
        crl.next_update(),
        &ctx.revinfo_policy,
        &ctx.timing,
    );
    match usability.rating {
        RevinfoUsabilityRating::Ok => return Some(usability),
        RevinfoUsabilityRating::Stale => {
            failures.push_freshness(
                format!("{prefix} is not recent enough"),
                usability.last_usable_at,
            );
        }
        RevinfoUsabilityRating::TooNew => {
            failures.push_freshness(format!("{prefix} is too recent"), None)
        }
        RevinfoUsabilityRating::Unclear => {
            failures.push_freshness(format!("{prefix} freshness could not be established"), None);
        }
    }
    None
}

/// Every revocation reason (`VALID_REVOCATION_REASONS`) as `ReasonFlags`
/// bits: keyCompromise (1) to aACompromise (8).
const ALL_REASONS: u16 = 0b1_1111_1110;

/// `crl_extension` on a CRL, decoded.
fn crl_ext_value<'a, T: der::Decode<'a, Error = der::Error>>(
    crl: &'a CrlContainer,
    oid: &const_oid::ObjectIdentifier,
) -> Option<T> {
    crl_extension(crl, oid).and_then(|e| T::from_der(e.extn_value.as_bytes()).ok())
}

/// The key identifier of a CRL's authority key identifier extension.
fn crl_aki(crl: &CrlContainer) -> Option<Vec<u8>> {
    crl_ext_value::<x509_cert::ext::pkix::AuthorityKeyIdentifier>(
        crl,
        &oids::CE_AUTHORITY_KEY_IDENTIFIER,
    )
    .and_then(|aki| aki.key_identifier)
    .map(|k| k.as_bytes().to_vec())
}

fn gn_eq(a: &GeneralName, b: &GeneralName) -> bool {
    match (a, b) {
        (GeneralName::DirectoryName(n1), GeneralName::DirectoryName(n2)) => {
            certval::compare_names(n1, n2)
        }
        _ => a == b,
    }
}

fn gn_in(name: &GeneralName, list: &[GeneralName]) -> bool {
    list.iter().any(|x| gn_eq(name, x))
}

/// `_match_dps_idp_names`.
fn match_dps_idp_names(
    idp: &IssuingDistributionPoint,
    crl_dps: &[DistributionPoint],
    crl_issuer: &Cert,
    crl_authority_name: &Name,
) -> bool {
    let mut idp_names: Vec<GeneralName> = Vec::new();
    let has_idp_name = idp.distribution_point.is_some();
    if let Some(name) = &idp.distribution_point {
        idp_names = dp_names(name, crl_issuer.subject());
    }
    let mut has_dp_name = false;
    let mut matched = false;
    if !crl_dps.is_empty() {
        for dp in crl_dps {
            if matched {
                break;
            }
            if let Some(name) = &dp.distribution_point {
                has_dp_name = true;
                matched = dp_names(name, crl_issuer.subject())
                    .iter()
                    .any(|n| gn_in(n, &idp_names));
            } else if let Some(issuers) = &dp.crl_issuer {
                has_dp_name = true;
                matched = issuers.iter().any(|n| gn_in(n, &idp_names));
            }
        }
    } else {
        has_dp_name = true;
        matched = gn_in(
            &GeneralName::DirectoryName(crl_authority_name.clone()),
            &idp_names,
        );
    }
    matched || !has_idp_name || !has_dp_name
}

pub(crate) fn is_indirect(crl: &CrlContainer) -> Result<bool, ValidationError> {
    Ok(parse_idp(crl)?.is_some_and(|idp| idp.indirect_crl))
}

/// Errors gathered while processing the CRLs for one certificate (`_CRLErrs`).
#[derive(Default)]
pub(crate) struct CrlErrs {
    failures: Failures,
    issuer_failures: usize,
}

/// Outcome of the CRL issuer search (`_find_crl_issuer`).
enum IssuerSearch {
    Found(Cert),
    NoMatches,
    Error(String),
}

/// Counters of `_CRLIssuerSearchErrs`.
#[derive(Default)]
pub(crate) struct CandidateCounts {
    pub(crate) total: usize,
    pub(crate) skipped: usize,
    pub(crate) unauthorized: usize,
    pub(crate) path_failures: usize,
}

/// `_find_candidate_crl_issuer_certs` + `_find_candidate_crl_paths`: the
/// certificates that may have issued `crl` for the subject, each with a
/// provisional path (not validated).
pub(crate) fn candidate_crl_paths(
    ctx: &ValidationContext,
    crl: &CrlContainer,
    subject: &Subject<'_>,
    indirect: bool,
) -> (Vec<(Cert, ValidationPath)>, CandidateCounts) {
    let crl_issuer_name = &crl.crl.tbs_cert_list.issuer;
    let cert_issuer = subject.issuer;
    let mut candidates: Vec<Cert> = Vec::new();
    if certval::compare_names(cert_issuer.subject(), crl_issuer_name) {
        candidates.push(cert_issuer.clone());
    }
    for c in ctx.known_certs() {
        if certval::compare_names(c.subject(), crl_issuer_name) && !candidates.contains(c) {
            candidates.push(c.clone());
        }
    }
    let mut counts = CandidateCounts {
        total: candidates.len(),
        ..CandidateCounts::default()
    };
    let mut paths: Vec<(Cert, ValidationPath)> = Vec::new();
    for cand in candidates {
        let direct = certval::compare_names(cand.subject(), &subject.cert.issuer);
        let indirect_issuer =
            certval::compare_names(cand.issuer(), &subject.cert.issuer) && !subject.cert.is(&cand);
        if !direct && !indirect_issuer && !indirect {
            counts.skipped += 1;
            continue;
        }
        if cand.key_usage().is_some_and(|ku| !ku.crl_sign()) {
            counts.unauthorized += 1;
            continue;
        }
        match subject.path.truncate_to_issuer_and_append(&cand) {
            Some(p) => paths.push((cand, p)),
            None => counts.path_failures += 1,
        }
    }
    (paths, counts)
}

/// `_find_candidate_crl_issuer_certs` + `_find_candidate_crl_paths` +
/// `_find_crl_issuer`.
fn find_crl_issuer(
    ctx: &ValidationContext,
    crl: &CrlContainer,
    subject: &Subject<'_>,
    indirect: bool,
    mut completion: Option<&mut crate::validate::LeafRevocationCollector>,
) -> IssuerSearch {
    let (paths, counts) = candidate_crl_paths(ctx, crl, subject, indirect);
    let n = counts.total;
    let (skipped, unauthorized, path_failures) =
        (counts.skipped, counts.unauthorized, counts.path_failures);
    let mut sig_failures = 0;
    let mut explicit: Vec<String> = Vec::new();
    for (cand, path) in paths {
        let mut checkpoint = completion
            .as_deref()
            .map(|collector| collector.checkpoint());
        // A certificate of the path being validated is checked by that
        // validation (from the anchor down); others need their own path.
        let in_main_path = subject.path.authorities().contains(&&cand);
        // Recursion exempts only issuer certificate path validation. The
        // current CRL still requires its own signature check below.
        if !subject.stack.contains(&cand) && !in_main_path {
            let outcome = if let Some(completion) = completion.as_deref_mut() {
                crate::validate::validate_path_in_stack_with_completion(
                    ctx,
                    &path,
                    None,
                    subject.stack,
                    Some(completion),
                )
                .map(|_| ())
                .map_err(|f| f.error)
            } else {
                crate::validate::validate_path_at_depth(ctx, &path, None, subject.stack)
            };
            if let Err(e) = outcome {
                explicit.push(format!(
                    "The CRL issuer certificate path could not be validated. {e}"
                ));
                if let (Some(collector), Some(checkpoint)) =
                    (completion.as_deref_mut(), checkpoint.take())
                {
                    collector.rollback(checkpoint);
                }
                continue;
            }
        }
        if signed_by(crl, &cand) {
            return IssuerSearch::Found(cand);
        }
        if let (Some(collector), Some(checkpoint)) = (completion.as_deref_mut(), checkpoint.take())
        {
            collector.rollback(checkpoint);
        }
        sig_failures += 1;
    }
    let plural = n > 1;
    if n == 0 || skipped == n {
        IssuerSearch::NoMatches
    } else if sig_failures == n {
        IssuerSearch::Error("CRL signature could not be verified".into())
    } else if unauthorized == n {
        IssuerSearch::Error(if plural {
            "The CRL issuers that were identified are not authorized to sign CRLs".into()
        } else {
            "The CRL issuer that was identified is not authorized to sign CRLs".into()
        })
    } else if path_failures == n {
        IssuerSearch::Error(if plural {
            "The chain of trust for the CRL issuers that were identified could not be determined"
                .into()
        } else {
            "The chain of trust for the CRL issuer that was identified could not be determined"
                .into()
        })
    } else if explicit.len() == 1 {
        IssuerSearch::Error(explicit.remove(0))
    } else {
        IssuerSearch::Error(format!(
            "Unable to determine CRL trust status. {}",
            explicit.join("; ")
        ))
    }
}

/// `_get_crl_scope_assuming_authority`: the reasons the CRL covers for the
/// certificate, or `None` if it does not apply.
pub(crate) fn crl_scope(
    crl: &CrlContainer,
    crl_issuer: &Cert,
    subject: &Subject<'_>,
    indirect: bool,
    errs: &mut CrlErrs,
) -> Result<Option<u16>, ValidationError> {
    let cert = subject.cert;
    let cert_dps = cert.dps.clone();
    let issuer_gn = GeneralName::DirectoryName(crl_issuer.subject().clone());
    let mut has_dp_crl_issuer = false;
    let mut dp_match = false;
    for dp in &cert_dps {
        if let Some(names) = &dp.crl_issuer {
            has_dp_crl_issuer = true;
            if gn_in(&issuer_gn, names) {
                dp_match = true;
            }
        }
    }
    let same_issuer = certval::compare_names(crl_issuer.subject(), &cert.issuer);
    let indirect_match = has_dp_crl_issuer && dp_match && indirect;
    let missing_idp = has_dp_crl_issuer && (!dp_match || !indirect);
    let indirect_crl_issuer = certval::compare_names(crl_issuer.issuer(), &cert.issuer);
    if (!same_issuer && !indirect_match && !indirect_crl_issuer) || missing_idp {
        errs.issuer_failures += 1;
        return Ok(None);
    }
    let idp = parse_idp(crl)?;
    if let Some(idp) = idp.as_ref().filter(|_| cert.is_ac) {
        // `_handle_attr_cert_crl_idp_ext_constraints`.
        if !match_dps_idp_names(idp, &cert_dps, crl_issuer, crl_issuer.subject()) {
            errs.failures.push(
                "The CRL issuing distribution point extension does not share any names with the attribute certificate's CRL distribution point extension",
            );
            errs.issuer_failures += 1;
            return Ok(None);
        }
        if idp.only_contains_user_certs || idp.only_contains_ca_certs {
            errs.failures.push(
                "CRL only contains public-key certificates, but certificate is an attribute certificate",
            );
            return Ok(None);
        }
    } else if let Some(idp) = &idp {
        if !match_dps_idp_names(idp, &cert_dps, crl_issuer, crl_issuer.subject()) {
            errs.failures.push(
                "The CRL issuing distribution point extension does not share any names with the certificate CRL distribution point extension",
            );
            errs.issuer_failures += 1;
            return Ok(None);
        }
        let is_ca = cert.is_ca;
        if idp.only_contains_user_certs && is_ca {
            errs.failures.push(
                "CRL only contains end-entity certificates and certificate is a CA certificate",
            );
            return Ok(None);
        }
        if idp.only_contains_ca_certs && !is_ca {
            errs.failures.push(
                "CRL only contains CA certificates and certificate is an end-entity certificate",
            );
            return Ok(None);
        }
        if idp.only_contains_attribute_certs {
            errs.failures
                .push("CRL only contains attribute certificates");
            return Ok(None);
        }
    }
    let reasons = idp
        .as_ref()
        .and_then(|i| i.only_some_reasons)
        .map(|r| r.bits())
        .filter(|bits| *bits != 0)
        .unwrap_or(ALL_REASONS);
    if has_unknown_critical(
        crl.crl.tbs_cert_list.crl_extensions.as_ref(),
        &KNOWN_CRL_EXTENSIONS,
    ) {
        errs.failures
            .push("One or more unrecognized critical extensions are present in the CRL");
        return Ok(None);
    }
    Ok(Some(reasons))
}

/// `find_cert_in_list`: the revocation date and reason of the certificate
/// on `crl`, tracking `certificateIssuer` entry extensions (indirect CRLs).
/// `Err(())` means the entry has an unknown critical extension.
fn find_cert_in_list(
    crl: &CrlContainer,
    subject: &Subject<'_>,
    crl_authority_name: &Name,
) -> Result<Option<(Moment, CrlReason)>, ()> {
    let Some(entries) = crl.crl.tbs_cert_list.revoked_certificates.as_ref() else {
        return Ok(None);
    };
    let serial = subject.cert.serial.as_slice();
    let mut last_issuer: Option<Name> = None;
    for entry in entries {
        let exts = entry.crl_entry_extensions.as_ref();
        if let Some(ext) = find_extension(exts, &oids::CE_CERTIFICATE_ISSUER) {
            let names: Option<Vec<GeneralName>> =
                der::Decode::from_der(ext.extn_value.as_bytes()).ok();
            if let Some(name) = names.into_iter().flatten().find_map(|g| match g {
                GeneralName::DirectoryName(n) => Some(n),
                _ => None,
            }) {
                last_issuer = Some(name);
            }
        }
        let serial_matches = if subject.cert.is_ac {
            entry.serial_number.to_der().ok().is_some_and(|serial_der| {
                crate::ac::ac_serial_magnitude(&serial_der) == Some(serial)
            })
        } else {
            entry.serial_number.as_bytes() == serial
        };
        if !serial_matches {
            continue;
        }
        let issuer = last_issuer.as_ref().unwrap_or(crl_authority_name);
        if !certval::compare_names(issuer, &subject.cert.issuer) {
            continue;
        }
        if has_unknown_critical(exts, &KNOWN_ENTRY_EXTENSIONS) {
            return Err(());
        }
        let reason = find_extension(exts, &oids::CE_CRL_REASONS)
            .and_then(|ext| der::Decode::from_der(ext.extn_value.as_bytes()).ok())
            .unwrap_or(CrlReason::Unspecified);
        return Ok(Some((Moment::from(entry.revocation_date), reason)));
    }
    Ok(None)
}

/// `_check_cert_on_crl_and_delta`.
pub(crate) fn check_cert_on_crl_and_delta(
    crl_issuer: &Cert,
    subject: &Subject<'_>,
    crl: &CrlContainer,
    delta: Option<&CrlContainer>,
) -> Result<Option<(Moment, CrlReason)>, ()> {
    let mut hit = None;
    if let Some(d) = delta {
        hit = find_cert_in_list(d, subject, crl_issuer.subject())?;
    }
    if hit.is_none() {
        hit = find_cert_in_list(crl, subject, crl_issuer.subject())?;
    }
    Ok(hit.filter(|(_, reason)| *reason != CrlReason::RemoveFromCRL))
}

/// `_maybe_get_delta_crl`. `Err(msg)` means a required delta is missing.
pub(crate) fn maybe_get_delta<'a>(
    ctx: Option<&ValidationContext>,
    crl: &CrlContainer,
    crl_issuer: &Cert,
    deltas: &[&'a CrlContainer],
    errs: &mut CrlErrs,
) -> Result<Result<Option<&'a CrlContainer>, String>, ValidationError> {
    let has_freshest =
        crl_ext_value::<x509_cert::ext::pkix::FreshestCrl>(crl, &oids::CE_FRESHEST_CRL)
            .is_some_and(|f| !f.0.is_empty());
    if !has_freshest {
        return Ok(Ok(None));
    }
    let base_idp = parse_idp(crl)?;
    let base_aki = crl_aki(crl);
    let mut matching = None;
    for d in deltas {
        if !certval::compare_names(&d.crl.tbs_cert_list.issuer, crl_issuer.subject()) {
            continue;
        }
        if parse_idp(d)? != base_idp {
            continue;
        }
        if crl_aki(d) != base_aki {
            continue;
        }
        matching = Some(*d);
        break;
    }
    let Some(delta) = matching else {
        return Ok(Err(
            "Delta CRL matching Freshest CRL extension not available".to_owned(),
        ));
    };
    if has_unknown_critical(
        delta.crl.tbs_cert_list.crl_extensions.as_ref(),
        &KNOWN_CRL_EXTENSIONS,
    ) {
        errs.failures
            .push("One or more unrecognized critical extensions are present in the delta CRL");
        return Ok(Ok(None));
    }
    // Freshness is only checked when a context (validation timing) is given
    // (`_maybe_get_delta_crl` without `timing_params` skips it).
    if let Some(ctx) = ctx {
        if !fresh(ctx, delta, "Delta CRL", &mut errs.failures) {
            return Ok(Ok(None));
        }
    }
    Ok(Ok(Some(delta)))
}

/// `_handle_single_crl`: the reasons covered, `None` if the CRL is not
/// usable, or a revocation error.
struct SelectedCrl {
    reasons: u16,
    leaf_revoked: bool,
}

fn handle_single_crl(
    ctx: &ValidationContext,
    crl: &CrlContainer,
    subject: &Subject<'_>,
    deltas: &[&CrlContainer],
    errs: &mut CrlErrs,
    mut completion: Option<&mut crate::validate::LeafRevocationCollector>,
) -> Result<Option<SelectedCrl>, ValidationError> {
    let checkpoint = completion
        .as_deref()
        .map(|collector| collector.checkpoint());
    let result =
        handle_single_crl_inner(ctx, crl, subject, deltas, errs, completion.as_deref_mut());
    if matches!(&result, Ok(None)) {
        if let (Some(collector), Some(checkpoint)) = (completion, checkpoint) {
            collector.rollback(checkpoint);
        }
    }
    result
}

fn handle_single_crl_inner(
    ctx: &ValidationContext,
    crl: &CrlContainer,
    subject: &Subject<'_>,
    deltas: &[&CrlContainer],
    errs: &mut CrlErrs,
    mut completion: Option<&mut crate::validate::LeafRevocationCollector>,
) -> Result<Option<SelectedCrl>, ValidationError> {
    let indirect = is_indirect(crl)?;
    let crl_issuer = match find_crl_issuer(ctx, crl, subject, indirect, completion.as_deref_mut()) {
        IssuerSearch::Found(c) => c,
        IssuerSearch::NoMatches => {
            errs.issuer_failures += 1;
            return Ok(None);
        }
        IssuerSearch::Error(msg) => {
            errs.failures.push(msg);
            return Ok(None);
        }
    };
    let Some(reasons) = crl_scope(crl, &crl_issuer, subject, indirect, errs)? else {
        return Ok(None);
    };
    let Some(freshness) = fresh_outcome(ctx, crl, "CRL", &mut errs.failures) else {
        return Ok(None);
    };
    let delta = match maybe_get_delta(Some(ctx), crl, &crl_issuer, deltas, errs)? {
        Ok(d) => d,
        Err(msg) => {
            errs.failures.push(msg);
            return Ok(None);
        }
    };
    if let Some(d) = delta {
        if !signed_by(d, &crl_issuer) {
            errs.failures
                .push("Delta CRL signature could not be verified");
            return Ok(None);
        }
    }
    let hit = match check_cert_on_crl_and_delta(&crl_issuer, subject, crl, delta) {
        Ok(hit) => hit,
        Err(()) => {
            errs.failures.push(
                "One or more unrecognized critical extensions are present in the CRL entry for the certificate",
            );
            return Ok(None);
        }
    };
    if let Some(completion) = completion {
        let active_hit = hit.filter(|(at, _)| {
            !ctx.timing.point_in_time_validation || *at < ctx.timing.validation_time
        });
        if let Some((at, reason)) = active_hit {
            if !completion.is_main(subject)
                || reason != CrlReason::KeyCompromise
                || at > ctx.timing.validation_time
            {
                return Err(revoked_error("CRL", &subject.description, at, reason));
            }
        }
        if indirect {
            completion.mark_unsupported("indirect CRLs are outside the initial completion profile");
            if active_hit.is_some() {
                return Err(crate::validate::leaf_revocation::unsupported(
                    "indirect CRLs are outside the initial completion profile",
                ));
            }
        }
        let leaf_revoked = completion.crl_checked(
            ctx,
            crl,
            subject,
            &crl_issuer,
            (freshness, reasons),
            active_hit,
        )?;
        return Ok(Some(SelectedCrl {
            reasons,
            leaf_revoked,
        }));
    }
    if let Some((revoked_at, reason)) = hit {
        let timing = &ctx.timing;
        if !timing.point_in_time_validation || revoked_at < timing.validation_time {
            return Err(revoked_error(
                "CRL",
                &subject.description,
                revoked_at,
                reason,
            ));
        }
    }
    Ok(Some(SelectedCrl {
        reasons,
        leaf_revoked: false,
    }))
}

/// `_process_crl_completeness`: `None` if every reason is covered.
fn completeness(checked: u16, total: usize, errs: &mut CrlErrs) -> Option<CheckOutcome> {
    if checked & ALL_REASONS == ALL_REASONS {
        return None;
    }
    if total == errs.issuer_failures {
        return Some(CheckOutcome::NoMatches);
    }
    if errs.failures.messages.is_empty() {
        errs.failures
            .push("The available CRLs do not cover all revocation reasons");
    }
    Some(CheckOutcome::Indeterminate {
        failures: errs.failures.messages.clone(),
        suspect_stale: errs.failures.suspect_stale(),
    })
}

/// Check the certificate against the supplied CRLs, then against fetched
/// ones if those do not suffice and fetching is enabled (port of
/// `verify_crl`).
pub(crate) fn verify_crl(
    ctx: &ValidationContext,
    subject: &Subject<'_>,
) -> Result<CheckOutcome, ValidationError> {
    verify_crl_with_completion(ctx, subject, None)?.ordinary()
}

/// Discard facts from a channel that did not complete. A real authenticated
/// revoked entry remains the ordinary hard failure, never a tolerated fetch
/// failure or an eligible event with incomplete reason coverage.
fn incomplete_selected_channel(
    completion: Option<&mut crate::validate::LeafRevocationCollector>,
    checkpoint: Option<crate::validate::leaf_revocation::CollectorCheckpoint>,
    subject: &Subject<'_>,
    outcome: CheckOutcome,
) -> Result<SelectedOutcome, ValidationError> {
    if let (Some(collector), Some(checkpoint)) = (completion, checkpoint) {
        if let Some(error) = collector.incomplete_crl_error(&checkpoint, subject) {
            return Err(error);
        }
        collector.rollback(checkpoint);
    }
    Ok(SelectedOutcome::Checked(outcome))
}

pub(crate) fn verify_crl_with_completion(
    ctx: &ValidationContext,
    subject: &Subject<'_>,
    mut completion: Option<&mut crate::validate::LeafRevocationCollector>,
) -> Result<SelectedOutcome, ValidationError> {
    let checkpoint = completion
        .as_deref()
        .map(|collector| collector.checkpoint());
    let mut errs = CrlErrs::default();
    let (complete, deltas): (Vec<&CrlContainer>, Vec<&CrlContainer>) =
        ctx.crls.iter().partition(|c| !is_delta(c));
    let mut total = complete.len();
    let mut checked: u16 = 0;
    let mut leaf_revoked = false;
    for crl in &complete {
        if let Some(r) = handle_single_crl(
            ctx,
            crl,
            subject,
            &deltas,
            &mut errs,
            completion.as_deref_mut(),
        )? {
            checked |= r.reasons;
            leaf_revoked |= r.leaf_revoked;
        }
    }
    let Some(outcome) = completeness(checked, total, &mut errs) else {
        if let Some(collector) = completion.as_deref_mut() {
            collector.complete_crl(ctx, subject, checked);
        }
        return Ok(if leaf_revoked {
            SelectedOutcome::LeafRevoked
        } else {
            SelectedOutcome::Checked(CheckOutcome::Good)
        });
    };
    let Some(fetcher) = ctx.fetchers.crl.as_ref() else {
        return incomplete_selected_channel(completion, checkpoint, subject, outcome);
    };
    let fetched = if subject.cert.is_ac {
        fetcher.fetch_ac_crls(&subject.cert.der)
    } else if let Some(x509) = subject.cert.x509.as_ref() {
        fetcher.fetch_crls(x509)
    } else {
        return incomplete_selected_channel(completion, checkpoint, subject, outcome);
    };
    let fetched = match fetched {
        Ok(f) => f,
        Err(e) => {
            return incomplete_selected_channel(
                completion,
                checkpoint,
                subject,
                CheckOutcome::FetchFailed(e.message),
            )
        }
    };
    let fetched: Vec<CrlContainer> = fetched
        .iter()
        .filter_map(|der| CrlContainer::from_der(der).ok())
        .collect();
    let (extra_complete, extra_deltas): (Vec<&CrlContainer>, Vec<&CrlContainer>) =
        fetched.iter().partition(|c| !is_delta(c));
    let all_deltas: Vec<&CrlContainer> =
        deltas.iter().chain(extra_deltas.iter()).copied().collect();
    // Supplied CRLs are reprocessed if a fetched delta may complete them.
    let mut to_process: Vec<&CrlContainer> = complete
        .iter()
        .filter(|c| {
            extra_deltas.iter().any(|d| {
                certval::compare_names(&d.crl.tbs_cert_list.issuer, &c.crl.tbs_cert_list.issuer)
            })
        })
        .copied()
        .collect();
    to_process.extend(extra_complete.iter().copied());
    for crl in &to_process {
        if let Some(r) = handle_single_crl(
            ctx,
            crl,
            subject,
            &all_deltas,
            &mut errs,
            completion.as_deref_mut(),
        )? {
            checked |= r.reasons;
            leaf_revoked |= r.leaf_revoked;
        }
    }
    total += to_process.len();
    match completeness(checked, total, &mut errs) {
        Some(outcome) => incomplete_selected_channel(completion, checkpoint, subject, outcome),
        None => {
            if let Some(collector) = completion {
                collector.complete_crl(ctx, subject, checked);
            }
            Ok(if leaf_revoked {
                SelectedOutcome::LeafRevoked
            } else {
                SelectedOutcome::Checked(CheckOutcome::Good)
            })
        }
    }
}

#[cfg(test)]
mod ac_serial_tests {
    use super::*;
    use crate::ac::AttrCert;
    use crate::authority::TrustAnchor;
    use der::{Decode, Encode};
    use std::sync::Arc;
    use x509_cert::certificate::Raw;

    fn fixture(parts: &[&str]) -> Vec<u8> {
        let mut path = vec!["attribute-certs", "basic-aa"];
        path.extend_from_slice(parts);
        std::fs::read(sigis_testdata::certvalidator(&path)).unwrap()
    }

    #[test]
    fn ac_crl_entries_match_positive_magnitude_without_accepting_negative_serials() {
        let aa = Cert::from_pem_or_der(&fixture(&["interm", "role-aa.crt"])).unwrap();
        let root = Cert::from_pem_or_der(&fixture(&["root", "root.crt"])).unwrap();
        let interm = Cert::from_pem_or_der(&fixture(&["root", "interm-role.crt"])).unwrap();
        let path = ValidationPath::new(TrustAnchor::new(root), vec![interm], Some(aa.clone()));
        let mut ac = AttrCert::from_der(&fixture(&["aa", "alice-role-with-rev.attr.crt"])).unwrap();
        ac.serial = vec![0, 0x80];
        let target = ac.target().unwrap();
        assert_eq!(target.serial, [0x80]);
        let subject = Subject {
            cert: &target,
            issuer: &aa,
            path: &path,
            description: "the attribute certificate".into(),
            description_definite: "the attribute certificate".into(),
            is_ee: true,
            stack: &[],
        };
        let mut crl = CrlContainer::from_der(&fixture(&["role-aa-some-revoked.crl"])).unwrap();
        let serial = x509_cert::serial_number::SerialNumber::<Raw>::new(&[0x80]).unwrap();
        assert_eq!(serial.to_der().unwrap(), [0x02, 0x02, 0, 0x80]);
        assert_eq!(serial.as_bytes(), [0, 0x80]);
        let entries = Arc::make_mut(&mut crl.crl)
            .tbs_cert_list
            .revoked_certificates
            .as_mut()
            .unwrap();
        entries.truncate(1);
        entries[0].serial_number = serial;
        assert!(find_cert_in_list(&crl, &subject, aa.subject())
            .unwrap()
            .is_some());
        Arc::make_mut(&mut crl.crl)
            .tbs_cert_list
            .revoked_certificates
            .as_mut()
            .unwrap()[0]
            .serial_number =
            x509_cert::serial_number::SerialNumber::<Raw>::from_der(&[0x02, 0x01, 0x80]).unwrap();
        assert!(find_cert_in_list(&crl, &subject, aa.subject())
            .unwrap()
            .is_none());
        // Entry lookup only: the deliberately mutated CRL is not passed to
        // signature validation and makes no trusting verdict.
    }
}
