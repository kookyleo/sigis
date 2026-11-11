// Derived from pyhanko-certvalidator `revinfo/validate_ocsp.py` (MIT, see LICENSE-pyHanko).

//! OCSP-based revocation checking.

use der::Encode;
use x509_cert::ext::pkix::CrlReason;
use x509_ocsp::{CertStatus, ResponderId};

use super::freshness::RevinfoUsabilityRating;
use super::{revoked_error, CheckOutcome, Failures, OcspContainer, Subject};
use crate::authority::Cert;
use crate::context::ValidationContext;
use hanko_core::algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext};
use hanko_core::asn1::oids;
use hanko_core::errors::ValidationError;
use hanko_core::time::Moment;

const PROVENANCE_ERR: &str =
    "Unable to verify OCSP response since response signing certificate could not be validated";

/// Outcome of matching a response's `CertID` against the certificate.
enum CertIdMatch {
    Match,
    /// Not about this certificate at all.
    Unrelated,
    /// About this certificate, but inconsistent.
    Failure(&'static str),
}

fn match_cert_id(
    container: &OcspContainer,
    subject: &Subject<'_>,
) -> Result<CertIdMatch, ValidationError> {
    let Some(single) = container.single() else {
        return Ok(CertIdMatch::Unrelated);
    };
    let cert_id = &single.cert_id;
    let Some(digest) = DigestAlgorithm::from_oid(&cert_id.hash_algorithm.oid) else {
        return Ok(CertIdMatch::Unrelated);
    };
    let name_hash = digest.digest(&subject.cert.issuer().to_der()?);
    let key_hash = digest.digest(subject.issuer.public_key().subject_public_key.raw_bytes());
    let name_mismatch = cert_id.issuer_name_hash.as_bytes() != name_hash.as_slice();
    let key_mismatch = cert_id.issuer_key_hash.as_bytes() != key_hash.as_slice();
    let serial_mismatch = cert_id.serial_number.as_bytes() != subject.cert.serial_bytes();
    Ok(if (name_mismatch || serial_mismatch) && key_mismatch {
        CertIdMatch::Unrelated
    } else if name_mismatch {
        CertIdMatch::Failure("OCSP response issuer name hash does not match")
    } else if serial_mismatch {
        CertIdMatch::Failure("OCSP response certificate serial number does not match")
    } else if key_mismatch {
        CertIdMatch::Failure("OCSP response issuer key hash does not match")
    } else {
        CertIdMatch::Match
    })
}

/// Find the certificate that signed the response, preferring certificates
/// embedded in the response.
fn identify_responder(
    ctx: &ValidationContext,
    container: &OcspContainer,
    subject: &Subject<'_>,
) -> Option<Cert> {
    let embedded = container
        .basic
        .certs
        .iter()
        .flatten()
        .filter_map(|c| c.to_der().ok())
        .filter_map(|der| Cert::from_der(&der).ok());
    let known = ctx.known_certs().cloned().chain([subject.issuer.clone()]);
    let mut candidates = embedded.chain(known);
    match &container.basic.tbs_response_data.responder_id {
        ResponderId::ByName(name) => candidates.find(|c| certval::compare_names(c.subject(), name)),
        ResponderId::ByKey(key_hash) => {
            let candidates: Vec<Cert> = candidates.collect();
            // RFC 6960: SHA-1 of the public key; fall back to the subject key
            // identifier, which is usually the same value.
            let by_hash = candidates.iter().find(|c| {
                let sha1 =
                    DigestAlgorithm::Sha1.digest(c.public_key().subject_public_key.raw_bytes());
                key_hash.as_bytes() == sha1.as_slice()
            });
            let by_ski = || {
                candidates.iter().find(|c| {
                    matches!(
                        c.extension::<x509_cert::ext::pkix::SubjectKeyIdentifier>(),
                        Ok(Some((_, ski))) if ski.0.as_bytes() == key_hash.as_bytes()
                    )
                })
            };
            by_hash.or_else(by_ski).cloned()
        }
    }
}

/// Is the responder authorized to answer for the issuer (RFC 6960 §4.2.2.2)?
fn check_authorization(
    ctx: &ValidationContext,
    responder: &Cert,
    subject: &Subject<'_>,
    failures: &mut Failures,
) -> bool {
    let issuer = subject.issuer;
    // The issuer itself signed the response.
    if responder.issuer() == issuer.issuer() && responder.serial_bytes() == issuer.serial_bytes() {
        if responder.decoded().signature() == issuer.decoded().signature() {
            return true;
        }
        failures.push("Unable to verify OCSP response since response was signed by an unauthorized certificate");
        return false;
    }
    // Delegated responder: must carry id-kp-OCSPSigning ...
    let ocsp_signing = responder
        .extended_key_usage()
        .is_some_and(|eku| eku.contains(&oids::KP_OCSP_SIGNING));
    if !ocsp_signing {
        failures.push("Unable to verify OCSP response since response was signed by an unauthorized certificate");
        return false;
    }
    // ... and be issued by the certificate's issuer, valid at the validation time.
    let provenance_ok = certval::compare_names(responder.issuer(), issuer.subject())
        && super::signed_part(responder.der()).is_ok_and(|tbs| {
            validate_signature(
                responder.decoded().signature().raw_bytes(),
                tbs,
                &issuer.public_key(),
                responder.decoded().signature_algorithm(),
                &SignatureValidationContext::default(),
            )
            .is_ok()
        })
        && responder.valid_at(ctx.timing.validation_time, ctx.timing.time_tolerance);
    if !provenance_ok {
        failures.push(PROVENANCE_ERR);
        failures.push("Unable to verify OCSP response since response was signed by an unauthorized certificate");
        return false;
    }
    true
}

/// Handle one response; `Ok(true)` means the status is good.
fn handle_single(
    ctx: &ValidationContext,
    container: &OcspContainer,
    subject: &Subject<'_>,
    failures: &mut Failures,
) -> Result<bool, ValidationError> {
    let Some(responder) = identify_responder(ctx, container, subject) else {
        failures.push("Unable to verify OCSP response since response signing certificate could not be located");
        return Ok(false);
    };

    let usability = ctx.freshness_judge.judge(
        container.this_update(),
        container.next_update(),
        &ctx.revinfo_policy,
        &ctx.timing,
    );
    match usability.rating {
        RevinfoUsabilityRating::Ok => {}
        RevinfoUsabilityRating::Stale => {
            let msg = match (usability.compared_to, usability.last_usable_at) {
                (Some(c), Some(l)) => format!("OCSP response is not recent enough ({c} > {l})"),
                _ => "OCSP response is not recent enough".to_owned(),
            };
            failures.push_freshness(msg, usability.last_usable_at);
            return Ok(false);
        }
        RevinfoUsabilityRating::TooNew => {
            failures.push_freshness("OCSP response is too recent", None);
            return Ok(false);
        }
        RevinfoUsabilityRating::Unclear => {
            failures.push_freshness("OCSP response freshness could not be established", None);
            return Ok(false);
        }
    }

    let basic = &container.basic;
    match validate_signature(
        basic.signature.raw_bytes(),
        &container.tbs,
        &responder.public_key(),
        &basic.signature_algorithm,
        &SignatureValidationContext::default(),
    ) {
        Ok(()) => {}
        Err(hanko_core::errors::SignatureError::PssParameterMismatch) => {
            failures.push("The signature parameters on the OCSP response do not match the constraints on the public key");
            return Ok(false);
        }
        Err(_) => {
            failures.push("Unable to verify OCSP response signature");
            return Ok(false);
        }
    }

    if !check_authorization(ctx, &responder, subject, failures) {
        return Ok(false);
    }

    let Some(single) = container.single() else {
        return Ok(false);
    };
    match &single.cert_status {
        CertStatus::Good(_) => Ok(true),
        CertStatus::Revoked(info) => {
            let revoked_at = Moment::from(info.revocation_time.0.to_date_time());
            if revoked_at <= ctx.timing.validation_time {
                let reason = info.revocation_reason.unwrap_or(CrlReason::Unspecified);
                return Err(revoked_error(
                    "OCSP response",
                    &subject.description,
                    revoked_at,
                    reason,
                ));
            }
            Ok(false)
        }
        CertStatus::Unknown(_) => Ok(false),
    }
}

/// Check the certificate against the supplied OCSP responses (port of
/// `verify_ocsp_response`).
pub(crate) fn verify_ocsp(
    ctx: &ValidationContext,
    subject: &Subject<'_>,
) -> Result<CheckOutcome, ValidationError> {
    let mut responses: Vec<&OcspContainer> = ctx.ocsps.iter().collect();
    // Freshest first; responses without thisUpdate last.
    responses.sort_by_key(|r| std::cmp::Reverse(r.this_update()));

    let mut failures = Failures::default();
    let mut unrelated = 0usize;
    for container in &responses {
        match match_cert_id(container, subject)? {
            CertIdMatch::Unrelated => {
                unrelated += 1;
                continue;
            }
            CertIdMatch::Failure(msg) => {
                failures.push(msg);
                continue;
            }
            CertIdMatch::Match => {}
        }
        if handle_single(ctx, container, subject, &mut failures)? {
            return Ok(CheckOutcome::Good);
        }
    }
    if unrelated == responses.len() {
        return Ok(CheckOutcome::NoMatches);
    }
    Ok(CheckOutcome::Indeterminate {
        suspect_stale: failures.suspect_stale(),
        failures: failures.messages,
    })
}
