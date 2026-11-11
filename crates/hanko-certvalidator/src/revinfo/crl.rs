// Derived from pyhanko-certvalidator `revinfo/validate_crl.py` (MIT, see LICENSE-pyHanko).

//! CRL-based revocation checking: direct CRLs, delta CRLs, and CRLs signed by
//! a separate key of the CRL issuer (whose path is then validated too).

use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::Raw;
use x509_cert::crl::RevokedCert;
use x509_cert::ext::pkix::crl::dp::{DistributionPoint, IssuingDistributionPoint};
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::CrlReason;
use x509_cert::ext::Extension;
use x509_cert::name::{Name, RdnSequence};

use super::freshness::RevinfoUsabilityRating;
use super::{revoked_error, CheckOutcome, CrlContainer, Failures, Subject};
use crate::authority::Cert;
use crate::context::ValidationContext;
use hanko_core::algorithms::{validate_signature, SignatureValidationContext};
use hanko_core::asn1::oids;
use hanko_core::errors::ValidationError;
use hanko_core::time::Moment;

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

fn is_delta(crl: &CrlContainer) -> bool {
    crl_extension(crl, &oids::CE_DELTA_CRL_INDICATOR).is_some()
}

/// How a CRL relates to the certificate being checked.
enum Scope {
    /// The CRL does not apply (wrong issuer, wrong distribution point,
    /// indirect, ...).
    NotApplicable,
    /// The CRL applies, but its scope excludes the certificate.
    Excluded(&'static str),
    /// The CRL applies; `partial_reasons` means it only covers some reasons.
    Applies { partial_reasons: bool },
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

fn general_names_intersect(a: &[GeneralName], b: &[GeneralName]) -> bool {
    a.iter().any(|x| {
        b.iter().any(|y| match (x, y) {
            (GeneralName::DirectoryName(n1), GeneralName::DirectoryName(n2)) => {
                certval::compare_names(n1, n2)
            }
            _ => x == y,
        })
    })
}

fn idp_matches_cert_dps(
    idp_name: &DistributionPointName,
    cert_dps: &[DistributionPoint],
    crl_issuer: &Name,
) -> bool {
    let idp_names = dp_names(idp_name, crl_issuer);
    cert_dps.iter().any(|dp| {
        dp.distribution_point
            .as_ref()
            .is_some_and(|name| general_names_intersect(&dp_names(name, crl_issuer), &idp_names))
    })
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

fn crl_scope(crl: &CrlContainer, subject: &Subject<'_>) -> Result<Scope, ValidationError> {
    let tbs = &crl.crl.tbs_cert_list;
    if !certval::compare_names(&tbs.issuer, subject.cert.issuer()) || is_delta(crl) {
        return Ok(Scope::NotApplicable);
    }
    let cert_dps = subject
        .cert
        .crl_distribution_points()
        .map(|d| d.0)
        .unwrap_or_default();
    // A certificate that names a CRL issuer uses indirect CRLs (unsupported).
    if cert_dps.iter().any(|dp| dp.crl_issuer.is_some()) {
        return Ok(Scope::NotApplicable);
    }
    let Some(idp) = parse_idp(crl)? else {
        return Ok(Scope::Applies {
            partial_reasons: false,
        });
    };
    if idp.indirect_crl {
        return Ok(Scope::NotApplicable);
    }
    if let Some(name) = &idp.distribution_point {
        if !idp_matches_cert_dps(name, &cert_dps, &tbs.issuer) {
            return Ok(Scope::NotApplicable);
        }
    }
    let is_ca = subject.cert.is_ca();
    if idp.only_contains_user_certs && is_ca {
        return Ok(Scope::Excluded(
            "CRL only contains end-entity certificates and certificate is a CA certificate",
        ));
    }
    if idp.only_contains_ca_certs && !is_ca {
        return Ok(Scope::Excluded(
            "CRL only contains CA certificates and certificate is an end-entity certificate",
        ));
    }
    if idp.only_contains_attribute_certs {
        return Ok(Scope::Excluded("CRL only contains attribute certificates"));
    }
    Ok(Scope::Applies {
        partial_reasons: idp.only_some_reasons.is_some(),
    })
}

fn find_entry<'a>(crl: &'a CrlContainer, subject: &Subject<'_>) -> Option<&'a RevokedCert<Raw>> {
    let serial = subject.cert.serial_bytes();
    crl.crl
        .tbs_cert_list
        .revoked_certificates
        .as_ref()?
        .iter()
        .find(|entry| entry.serial_number.as_bytes() == serial)
}

/// Revocation date and reason of the certificate on `crl`, if listed.
/// `Err(())` means the entry has an unknown critical extension.
fn lookup(crl: &CrlContainer, subject: &Subject<'_>) -> Result<Option<(Moment, CrlReason)>, ()> {
    let Some(entry) = find_entry(crl, subject) else {
        return Ok(None);
    };
    let exts = entry.crl_entry_extensions.as_ref();
    if has_unknown_critical(exts, &KNOWN_ENTRY_EXTENSIONS) {
        return Err(());
    }
    let reason = find_extension(exts, &oids::CE_CRL_REASONS)
        .and_then(|ext| der::Decode::from_der(ext.extn_value.as_bytes()).ok())
        .unwrap_or(CrlReason::Unspecified);
    Ok(Some((Moment::from(entry.revocation_date), reason)))
}

fn signed_by(crl: &CrlContainer, signer: &Cert) -> bool {
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

/// Who signed a CRL.
enum Signer {
    /// A certificate whose key verifies the CRL and that may sign CRLs.
    Found(Cert),
    /// A matching key was found, but its certificate may not sign CRLs.
    Unauthorized,
    /// No known key verifies the CRL.
    Unknown,
}

/// Find the CRL signer: the certificate's issuer, or another certificate with
/// the CRL issuer's name (separate CRL signing key, key rollover).
fn find_signer(ctx: &ValidationContext, crl: &CrlContainer, subject: &Subject<'_>) -> Signer {
    let crl_issuer = &crl.crl.tbs_cert_list.issuer;
    let others = ctx
        .known_certs()
        .filter(|c| *c != subject.issuer && certval::compare_names(c.subject(), crl_issuer));
    let mut unauthorized = false;
    for candidate in std::iter::once(subject.issuer).chain(others) {
        if !signed_by(crl, candidate) {
            continue;
        }
        if candidate.key_usage().is_some_and(|ku| !ku.crl_sign()) {
            unauthorized = true;
            continue;
        }
        return Signer::Found(candidate.clone());
    }
    if unauthorized {
        Signer::Unauthorized
    } else {
        Signer::Unknown
    }
}

/// A CRL signer other than the certificate's issuer needs its own valid path.
fn signer_path_error(
    ctx: &ValidationContext,
    signer: &Cert,
    subject: &Subject<'_>,
) -> Option<String> {
    if signer == subject.issuer {
        return None;
    }
    if subject.depth >= crate::validate::MAX_REVINFO_DEPTH {
        return Some(
            "The CRL issuer certificate path could not be validated: nesting too deep".to_owned(),
        );
    }
    let paths = match crate::validate::build_paths(ctx, signer) {
        Ok(paths) => paths,
        Err(e) => {
            return Some(format!(
                "The CRL issuer certificate path could not be validated. {e}"
            ))
        }
    };
    let mut first_error = None;
    for path in &paths {
        match crate::validate::validate_path_at_depth(ctx, path, None, subject.depth + 1) {
            Ok(()) => return None,
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    let detail = first_error.map(|e| e.to_string()).unwrap_or_default();
    Some(format!(
        "The CRL issuer certificate path could not be validated. {detail}"
    ))
}

/// Record a freshness failure; `true` if the CRL is usable.
fn fresh(
    ctx: &ValidationContext,
    crl: &CrlContainer,
    prefix: &str,
    failures: &mut Failures,
) -> bool {
    let usability = ctx.freshness_judge.judge(
        Some(crl.this_update()),
        crl.next_update(),
        &ctx.revinfo_policy,
        &ctx.timing,
    );
    match usability.rating {
        RevinfoUsabilityRating::Ok => return true,
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
    false
}

/// Find and check the delta CRL that a base CRL with a `freshestCRL`
/// extension requires (`_maybe_get_delta_crl`). `Ok(None)` means no delta is
/// required; `Err(())` means a required delta is missing or unusable (the
/// failure is recorded).
fn delta_for<'a>(
    ctx: &'a ValidationContext,
    base: &CrlContainer,
    signer: &Cert,
    failures: &mut Failures,
) -> Result<Result<Option<&'a CrlContainer>, ()>, ValidationError> {
    if crl_extension(base, &oids::CE_FRESHEST_CRL).is_none() {
        return Ok(Ok(None));
    }
    let base_idp = parse_idp(base)?;
    let base_aki =
        crl_extension(base, &oids::CE_AUTHORITY_KEY_IDENTIFIER).map(|e| e.extn_value.as_bytes());
    let mut deltas: Vec<&CrlContainer> = ctx
        .crls
        .iter()
        .filter(|c| {
            is_delta(c)
                && certval::compare_names(
                    &c.crl.tbs_cert_list.issuer,
                    &base.crl.tbs_cert_list.issuer,
                )
        })
        .collect();
    deltas.sort_by_key(|c| std::cmp::Reverse(c.this_update()));
    let mut matching = None;
    for delta in deltas {
        let same_idp = parse_idp(delta)? == base_idp;
        let delta_aki = crl_extension(delta, &oids::CE_AUTHORITY_KEY_IDENTIFIER)
            .map(|e| e.extn_value.as_bytes());
        if same_idp && delta_aki == base_aki {
            matching = Some(delta);
            break;
        }
    }
    let Some(delta) = matching else {
        failures.push("Delta CRL matching Freshest CRL extension not available");
        return Ok(Err(()));
    };
    if has_unknown_critical(
        delta.crl.tbs_cert_list.crl_extensions.as_ref(),
        &KNOWN_CRL_EXTENSIONS,
    ) {
        failures.push("One or more unrecognized critical extensions are present in the delta CRL");
        return Ok(Err(()));
    }
    if !fresh(ctx, delta, "Delta CRL", failures) {
        return Ok(Err(()));
    }
    if !signed_by(delta, signer) {
        failures.push("Delta CRL signature could not be verified");
        return Ok(Err(()));
    }
    Ok(Ok(Some(delta)))
}

/// Check the certificate against the supplied CRLs (port of `verify_crl`).
pub(crate) fn verify_crl(
    ctx: &ValidationContext,
    subject: &Subject<'_>,
) -> Result<CheckOutcome, ValidationError> {
    let mut candidates: Vec<&CrlContainer> = ctx.crls.iter().collect();
    // Freshest first.
    candidates.sort_by_key(|c| std::cmp::Reverse(c.this_update()));

    let mut failures = Failures::default();
    let mut matched = false;
    let mut reasons_incomplete = false;
    let validation_time = ctx.timing.validation_time;

    for crl in candidates {
        let partial_reasons = match crl_scope(crl, subject)? {
            Scope::NotApplicable => continue,
            Scope::Excluded(msg) => {
                matched = true;
                failures.push(msg);
                continue;
            }
            Scope::Applies { partial_reasons } => partial_reasons,
        };
        matched = true;

        let signer = match find_signer(ctx, crl, subject) {
            Signer::Found(signer) => signer,
            Signer::Unauthorized => {
                failures.push("The CRL issuer that was identified is not authorized to sign CRLs");
                continue;
            }
            Signer::Unknown => {
                failures.push("CRL signature could not be verified");
                continue;
            }
        };
        if let Some(msg) = signer_path_error(ctx, &signer, subject) {
            failures.push(msg);
            continue;
        }
        let issuer_key = signer.public_key();
        let allowed = ctx.algorithm_policy.signature_algorithm_allowed(
            &crl.crl.signature_algorithm,
            Some(validation_time),
            Some(&issuer_key),
        );
        if !allowed.allowed {
            failures.push(format!(
                "The CRL was signed with a disallowed algorithm: {}",
                allowed.failure_reason.unwrap_or_default()
            ));
            continue;
        }
        if has_unknown_critical(
            crl.crl.tbs_cert_list.crl_extensions.as_ref(),
            &KNOWN_CRL_EXTENSIONS,
        ) {
            failures.push("One or more unrecognized critical extensions are present in the CRL");
            continue;
        }
        if !fresh(ctx, crl, "CRL", &mut failures) {
            continue;
        }
        let delta = match delta_for(ctx, crl, &signer, &mut failures)? {
            Ok(delta) => delta,
            Err(()) => continue,
        };

        // The delta CRL takes precedence; removeFromCRL lifts an entry.
        let listed = match delta.map(|d| lookup(d, subject)).transpose() {
            Ok(Some(Some(hit))) => Ok(Some(hit)),
            Ok(_) => lookup(crl, subject),
            Err(()) => Err(()),
        };
        match listed {
            Err(()) => {
                failures.push(
                    "One or more unrecognized critical extensions are present in the CRL entry for the certificate",
                );
                continue;
            }
            Ok(Some((revoked_at, reason)))
                if reason != CrlReason::RemoveFromCRL && revoked_at < validation_time =>
            {
                return Err(revoked_error(
                    "CRL",
                    &subject.description,
                    revoked_at,
                    reason,
                ));
            }
            Ok(_) => {}
        }
        if partial_reasons {
            // Coverage across reason-partitioned CRLs is not accumulated.
            reasons_incomplete = true;
            continue;
        }
        return Ok(CheckOutcome::Good);
    }

    if reasons_incomplete {
        failures.push("The available CRLs do not cover all revocation reasons");
    }
    if !matched {
        return Ok(CheckOutcome::NoMatches);
    }
    Ok(CheckOutcome::Indeterminate {
        suspect_stale: failures.suspect_stale(),
        failures: failures.messages,
    })
}
