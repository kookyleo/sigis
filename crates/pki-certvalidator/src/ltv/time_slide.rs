// Derived from pyhanko-certvalidator `ltv/time_slide.py` and the collection
// helpers of `revinfo/validate_crl.py` / `revinfo/validate_ocsp.py`
// (MIT, see LICENSE-pyHanko).

//! Validation time sliding (ETSI EN 319 102-1 §5.6.2.2).

use x509_cert::ext::pkix::CrlReason;
use x509_ocsp::CertStatus;

use sigis_pki_core::errors::{Result, ValidationError};
use sigis_pki_core::time::Moment;

use super::poe::PoeManager;
use super::LtvError;
use crate::authority::Cert;
use crate::context::ValidationContext;
use crate::policy::ValidationTimingParams;
use crate::revinfo::crl::{self, CrlErrs};
use crate::revinfo::ocsp::{self as ocsp_mod, CertIdMatch};
use crate::revinfo::{CrlContainer, OcspContainer, Subject, Target};
use crate::ValidationPath;
use sigis_pki_core::asn1::oids;

/// A CRL with candidate issuer paths and matching delta CRLs
/// (`CRLOfInterest` / `ProvisionalCRLTrust`).
struct CrlOfInterest<'a> {
    crl: &'a CrlContainer,
    prov: Vec<(Cert, ValidationPath, Option<&'a CrlContainer>)>,
}

/// An OCSP response with the provisional path of its responder
/// (`OCSPResponseOfInterest`).
struct OcspOfInterest<'a> {
    response: &'a OcspContainer,
    responder: Cert,
    prov_path: ValidationPath,
}

fn subject<'a>(cert: &'a Target, issuer: &'a Cert, path: &'a ValidationPath) -> Subject<'a> {
    Subject {
        cert,
        issuer,
        path,
        description: String::new(),
        description_definite: String::new(),
        is_ee: false,
        stack: &[],
    }
}

/// `collect_relevant_crls_with_paths`: CRLs issued before `control_time`
/// (with POE) that apply to the leaf of `path`. No validation happens.
fn collect_crls<'a>(
    ctx: &'a ValidationContext,
    path: &ValidationPath,
    cert: &Cert,
    issuer: &Cert,
    control_time: Moment,
    poe: &PoeManager,
) -> std::result::Result<Vec<CrlOfInterest<'a>>, ValidationError> {
    let usable = |c: &&CrlContainer| {
        c.this_update() <= control_time && poe.poe_time(c.der()) <= control_time
    };
    let (complete, deltas): (Vec<&CrlContainer>, Vec<&CrlContainer>) = ctx
        .crls
        .iter()
        .filter(usable)
        .partition(|c| !crl::is_delta(c));
    let target = Target::from_cert(cert);
    let subj = subject(&target, issuer, path);
    let mut out = Vec::new();
    for c in complete {
        let indirect = crl::is_indirect(c)?;
        let (candidates, _) = crl::candidate_crl_paths(ctx, c, &subj, indirect);
        let mut prov = Vec::new();
        for (cand, cand_path) in candidates {
            let mut errs = CrlErrs::default();
            if crl::crl_scope(c, &cand, &subj, indirect, &mut errs)?.is_none() {
                continue;
            }
            let delta = match crl::maybe_get_delta(None, c, &cand, &deltas, &mut errs)? {
                Ok(d) => d,
                Err(_) => continue,
            };
            prov.push((cand, cand_path, delta));
        }
        if !prov.is_empty() {
            out.push(CrlOfInterest { crl: c, prov });
        }
    }
    Ok(out)
}

/// `collect_relevant_responses_with_paths`.
fn collect_ocsps<'a>(
    ctx: &'a ValidationContext,
    path: &ValidationPath,
    cert: &Cert,
    issuer: &Cert,
    control_time: Moment,
    poe: &PoeManager,
) -> std::result::Result<Vec<OcspOfInterest<'a>>, ValidationError> {
    let target = Target::from_cert(cert);
    let subj = subject(&target, issuer, path);
    let mut out = Vec::new();
    for r in &ctx.ocsps {
        let Some(issued) = r.this_update() else {
            continue;
        };
        if issued > control_time || poe.poe_time(&r.der) > control_time {
            continue;
        }
        if !matches!(ocsp_mod::match_cert_id(r, &subj)?, CertIdMatch::Match) {
            continue;
        }
        let Some(responder) = ocsp_mod::identify_responder(ctx, r, &subj) else {
            continue;
        };
        let Some(prov_path) = path.truncate_to_issuer_and_append(&responder) else {
            continue;
        };
        out.push(OcspOfInterest {
            response: r,
            responder,
            prov_path,
        });
    }
    Ok(out)
}

/// `_apply_algo_policy`: timed bans rewind; a ban without a time constraint fails.
fn apply_algo_policy(
    ctx: &ValidationContext,
    algorithm: &spki::AlgorithmIdentifierOwned,
    control_time: Moment,
    public_key: &spki::SubjectPublicKeyInfoOwned,
) -> std::result::Result<Moment, LtvError> {
    let c = ctx.algorithm_policy.signature_algorithm_allowed(
        algorithm,
        Some(control_time),
        Some(public_key),
    );
    if c.allowed {
        return Ok(control_time);
    }
    if let Some(cutoff) = c.not_allowed_after {
        return Ok(control_time.min(cutoff));
    }
    let mut msg = format!(
        "Algorithm {} is banned outright without time constraints.",
        algorithm.oid
    );
    if let Some(r) = c.failure_reason {
        msg.push_str(&format!(" Reason: {r}"));
    }
    Err(LtvError::Validation(ValidationError::DisallowedAlgorithm {
        msg,
        banned_since: None,
    }))
}

fn human(cert: &Cert) -> String {
    crate::names::human_friendly(cert.subject())
}

fn iso(m: Moment) -> String {
    let s = m.to_string();
    s.strip_suffix('Z')
        .map_or(s.clone(), |b| format!("{b}+00:00"))
}

/// The usability cutoff of the most recent revocation information
/// (`_update_control_time_for_unrevoked`).
fn update_for_unrevoked(
    ctx: &ValidationContext,
    control_time: Moment,
    this_update: Option<Moment>,
    next_update: Option<Moment>,
) -> Moment {
    let timing = ValidationTimingParams {
        validation_time: control_time,
        best_signature_time: control_time,
        time_tolerance: ctx.timing.time_tolerance,
        point_in_time_validation: true,
    };
    let u = ctx
        .freshness_judge
        .judge(this_update, next_update, &ctx.revinfo_policy, &timing);
    if !u.rating.usable_ades() {
        if let Some(cutoff) = u.last_usable_at.or(this_update) {
            return cutoff.min(control_time);
        }
    }
    control_time
}

/// Options of [`time_slide_with`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeSlideOptions {
    /// Apply the context's algorithm usage policy (`algo_usage_policy`;
    /// pyHanko callers may pass `None`).
    pub apply_algorithm_policy: bool,
}

impl Default for TimeSlideOptions {
    fn default() -> Self {
        Self {
            apply_algorithm_policy: true,
        }
    }
}

/// Slide the control time of `path` back from `init_control_time`
/// (`time_slide`); returns the resulting control time. Revocation
/// information and certificates come from `ctx`, POEs from `poe`.
pub fn time_slide(
    path: &ValidationPath,
    init_control_time: Moment,
    ctx: &ValidationContext,
    poe: &PoeManager,
) -> Result<Moment> {
    time_slide_with(
        path,
        init_control_time,
        ctx,
        poe,
        TimeSlideOptions::default(),
    )
    .map_err(Into::into)
}

/// [`time_slide`] with options and the detailed error type.
pub fn time_slide_with(
    path: &ValidationPath,
    init_control_time: Moment,
    ctx: &ValidationContext,
    poe: &PoeManager,
    options: TimeSlideOptions,
) -> std::result::Result<Moment, LtvError> {
    slide(path, init_control_time, ctx, poe, options, &[])
}

fn slide(
    path: &ValidationPath,
    init_control_time: Moment,
    ctx: &ValidationContext,
    poe: &PoeManager,
    options: TimeSlideOptions,
    cert_stack: &[Cert],
) -> std::result::Result<Moment, LtvError> {
    if path.pkix_len() == 0 {
        return Ok(init_control_time);
    }
    if cert_stack.len() > usize::from(crate::validate::MAX_REVINFO_DEPTH) * 2 {
        return Err(LtvError::Validation(ValidationError::InsufficientRevinfo(
            "Revocation information signers are nested too deeply.".into(),
        )));
    }
    let mut control_time = init_control_time;
    let checking = &ctx.revinfo_policy.revocation_checking_policy;
    // Partial paths, shortest first (`reversed(list(_tails(path)))`).
    let mut tails = vec![(path.clone(), true)];
    let mut cur = path.clone();
    while cur.pkix_len() > 1 {
        let Some(next) = cur.copy_and_drop_leaf() else {
            break;
        };
        tails.push((next.clone(), false));
        cur = next;
    }
    tails.reverse();

    for (current, is_ee) in tails {
        let Some(cert) = current.leaf().cloned() else {
            continue;
        };
        let issuer = current
            .find_issuing_authority(&cert)
            .cloned()
            .unwrap_or_else(|| current.trust_anchor().cert().clone());
        let rule = if is_ee {
            checking.ee_certificate_rule
        } else {
            checking.intermediate_ca_cert_rule
        };
        let crls = if rule.crl_relevant() {
            collect_crls(ctx, &current, &cert, &issuer, control_time, poe)?
        } else {
            Vec::new()
        };
        let ocsps = if rule.ocsp_relevant() {
            collect_ocsps(ctx, &current, &cert, &issuer, control_time, poe)?
        } else {
            Vec::new()
        };
        let mut new_stack = cert_stack.to_vec();
        new_stack.push(cert.clone());

        if poe.poe_time(cert.der()) > control_time {
            return Err(LtvError::InsufficientPoe(format!(
                "No proof of existence available for certificate {} at control time {}.",
                human(&cert),
                iso(control_time)
            )));
        }
        if crls.is_empty() && ocsps.is_empty() && !cert.has_extension(&oids::OCSP_NOCHECK) {
            return Err(LtvError::Validation(ValidationError::InsufficientRevinfo(
                format!(
                    "No revocation info from before {} found for certificate {}.",
                    iso(control_time),
                    human(&cert)
                ),
            )));
        }

        let mut once_revoked = false;
        let mut most_recent: Option<(Moment, Option<Moment>)> = None;
        let mut note_recent = |issued: Moment, next: Option<Moment>| {
            if most_recent.is_none_or(|(t, _)| t < issued) {
                most_recent = Some((issued, next));
            }
        };

        let target = Target::from_cert(&cert);
        let subj = subject(&target, &issuer, &current);
        for coi in &crls {
            let issued = coi.crl.this_update();
            if issued > control_time || poe.poe_time(coi.crl.der()) > control_time {
                continue;
            }
            let skip: Vec<Cert> = new_stack
                .iter()
                .cloned()
                .chain(current.certs().into_iter().cloned())
                .collect();
            for (cand, cand_path, _) in &coi.prov {
                if skip.contains(cand) {
                    continue;
                }
                let t = slide(cand_path, control_time, ctx, poe, options, &new_stack)?;
                control_time = control_time.min(t);
            }
            for (cand, _, delta) in &coi.prov {
                let hit = crl::check_cert_on_crl_and_delta(cand, &subj, coi.crl, *delta).map_err(|()| {
                    LtvError::Validation(ValidationError::InsufficientRevinfo(
                        "One or more unrecognized critical extensions are present in the CRL entry for the certificate".into(),
                    ))
                })?;
                if let Some((revoked_at, _)) = hit {
                    once_revoked = true;
                    control_time = control_time.min(revoked_at);
                }
                note_recent(issued, coi.crl.next_update());
                if options.apply_algorithm_policy {
                    control_time = apply_algo_policy(
                        ctx,
                        &coi.crl.crl.signature_algorithm,
                        control_time,
                        &cand.public_key(),
                    )?;
                }
            }
        }

        for ooi in &ocsps {
            let Some(issued) = ooi.response.this_update() else {
                continue;
            };
            if issued > control_time || poe.poe_time(&ooi.response.der) > control_time {
                continue;
            }
            control_time = slide(&ooi.prov_path, control_time, ctx, poe, options, &new_stack)?;
            if let Some(single) = ooi.response.single() {
                if let CertStatus::Revoked(info) = &single.cert_status {
                    let revoked_at = Moment::from(info.revocation_time.0.to_date_time());
                    if revoked_at <= control_time {
                        once_revoked = true;
                        control_time = control_time.min(revoked_at);
                    }
                    let _ = info.revocation_reason.unwrap_or(CrlReason::Unspecified);
                }
            }
            note_recent(issued, ooi.response.next_update());
            if options.apply_algorithm_policy {
                control_time = apply_algo_policy(
                    ctx,
                    &ooi.response.basic.signature_algorithm,
                    control_time,
                    &ooi.responder.public_key(),
                )?;
            }
        }

        if options.apply_algorithm_policy {
            control_time = apply_algo_policy(
                ctx,
                cert.decoded().signature_algorithm(),
                control_time,
                &issuer.public_key(),
            )?;
        }
        if !once_revoked {
            if let Some((issued, next)) = most_recent {
                control_time = update_for_unrevoked(ctx, control_time, Some(issued), next);
            }
        }
    }
    Ok(control_time)
}

#[cfg(test)]
#[path = "time_slide_algorithm_horizon_tests.rs"]
mod algorithm_horizon_tests;
