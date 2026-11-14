// Derived from pyhanko-certvalidator `revinfo/validate_ocsp.py` (MIT, see LICENSE-pyHanko).

//! OCSP-based revocation checking.

use der::Encode;
use x509_cert::ext::pkix::CrlReason;
use x509_ocsp::{CertStatus, ResponderId};

use super::freshness::RevinfoUsabilityRating;
use super::{revoked_error, CheckOutcome, Failures, OcspContainer, SelectedOutcome, Subject};
use crate::authority::Cert;
use crate::context::ValidationContext;
use sigis_pki_core::algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::errors::ValidationError;
use sigis_pki_core::time::Moment;

const PROVENANCE_ERR: &str =
    "Unable to verify OCSP response since response signing certificate could not be validated";

/// Outcome of matching a response's `CertID` against the certificate.
pub(crate) enum CertIdMatch {
    Match,
    /// Not about this certificate at all.
    Unrelated,
    /// About this certificate, but inconsistent.
    Failure(&'static str),
}

pub(crate) fn match_cert_id(
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
    // Match the issuer Name encoding carried by the signed certificate/AC,
    // as the pinned validator does. The key hash still binds the actual AA;
    // request construction independently uses the actual AA's name and key.
    let issuer_name = subject.cert.issuer.to_der()?;
    let name_hash = digest.digest(&issuer_name);
    let key_hash = digest.digest(subject.issuer.public_key().subject_public_key.raw_bytes());
    let name_mismatch = cert_id.issuer_name_hash.as_bytes() != name_hash.as_slice();
    let key_mismatch = cert_id.issuer_key_hash.as_bytes() != key_hash.as_slice();
    let serial_mismatch = if subject.cert.is_ac {
        crate::ac::ac_serial_magnitude(&cert_id.serial_number.to_der()?)
            != Some(subject.cert.serial.as_slice())
    } else {
        cert_id.serial_number.as_bytes() != subject.cert.serial.as_slice()
    };
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
pub(crate) fn identify_responder(
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
    completion: Option<&mut crate::validate::LeafRevocationCollector>,
) -> bool {
    let issuer = subject.issuer;
    // The issuer itself signed the response.
    if responder.issuer() == issuer.issuer() && responder.serial_bytes() == issuer.serial_bytes() {
        if responder.der() == issuer.der() {
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
        && responder.valid_at(ctx.timing.validation_time, ctx.timing.time_tolerance)
        && responder_chain_ok(ctx, responder, subject, completion);
    if !provenance_ok {
        failures.push(PROVENANCE_ERR);
        failures.push("Unable to verify OCSP response since response was signed by an unauthorized certificate");
        return false;
    }
    true
}

/// `_validate_delegated_ocsp_provenance`: a delegated responder without
/// `id-pkix-ocsp-nocheck` needs a valid path, including its own revocation
/// status, through the certificate's issuer.
fn responder_chain_ok(
    ctx: &ValidationContext,
    responder: &Cert,
    subject: &Subject<'_>,
    completion: Option<&mut crate::validate::LeafRevocationCollector>,
) -> bool {
    if responder.has_extension(&oids::OCSP_NOCHECK) {
        // Signature and validity were checked against the issuer above.
        // NOCHECK exempts revocation, not the signature algorithm policy.
        // Pinned certvalidator's simplified responder context uses the
        // validation moment, independently of the subscriber's best time.
        return ctx
            .algorithm_policy
            .signature_algorithm_allowed(
                responder.decoded().signature_algorithm(),
                Some(ctx.timing.validation_time),
                Some(&subject.issuer.public_key()),
            )
            .allowed;
    }
    // "Recursion detected in OCSP responder authorisation check".
    if subject.stack.contains(responder) {
        return false;
    }
    let Some(chain) = subject.path.truncate_to_issuer_and_append(responder) else {
        return false;
    };
    if let Some(completion) = completion {
        crate::validate::validate_path_in_stack_with_completion(
            ctx,
            &chain,
            None,
            subject.stack,
            Some(completion),
        )
        .is_ok()
    } else {
        crate::validate::validate_path_at_depth(ctx, &chain, None, subject.stack).is_ok()
    }
}

enum SingleStatus {
    Rejected,
    Good,
    LeafRevoked,
}

/// Handle one response, preserving authenticated unresolved events as distinct.
fn handle_single(
    ctx: &ValidationContext,
    container: &OcspContainer,
    subject: &Subject<'_>,
    failures: &mut Failures,
    mut completion: Option<&mut crate::validate::LeafRevocationCollector>,
) -> Result<SingleStatus, ValidationError> {
    let Some(responder) = identify_responder(ctx, container, subject) else {
        failures.push("Unable to verify OCSP response since response signing certificate could not be located");
        return Ok(SingleStatus::Rejected);
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
            return Ok(SingleStatus::Rejected);
        }
        RevinfoUsabilityRating::TooNew => {
            failures.push_freshness("OCSP response is too recent", None);
            return Ok(SingleStatus::Rejected);
        }
        RevinfoUsabilityRating::Unclear => {
            failures.push_freshness("OCSP response freshness could not be established", None);
            return Ok(SingleStatus::Rejected);
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
        Err(sigis_pki_core::errors::SignatureError::PssParameterMismatch) => {
            failures.push("The signature parameters on the OCSP response do not match the constraints on the public key");
            return Ok(SingleStatus::Rejected);
        }
        Err(_) => {
            failures.push("Unable to verify OCSP response signature");
            return Ok(SingleStatus::Rejected);
        }
    }

    if !check_authorization(
        ctx,
        &responder,
        subject,
        failures,
        completion.as_deref_mut(),
    ) {
        return Ok(SingleStatus::Rejected);
    }

    let Some(single) = container.single() else {
        return Ok(SingleStatus::Rejected);
    };
    match &single.cert_status {
        CertStatus::Good(_) => {
            if let Some(completion) = completion {
                completion.ocsp_good(ctx, container, subject, &responder, usability)?;
            }
            Ok(SingleStatus::Good)
        }
        CertStatus::Revoked(info) => {
            let revoked_at = Moment::from(info.revocation_time.0.to_date_time());
            let timing = &ctx.timing;
            if !timing.point_in_time_validation || revoked_at <= timing.validation_time {
                if let Some(completion) = completion {
                    if completion.is_main(subject)
                        && info.revocation_reason == Some(CrlReason::KeyCompromise)
                        && revoked_at <= timing.validation_time
                    {
                        completion.ocsp_revoked(
                            ctx,
                            container,
                            subject,
                            &responder,
                            usability,
                            (revoked_at, info.revocation_reason),
                        )?;
                        return Ok(SingleStatus::LeafRevoked);
                    }
                }
                let reason = info.revocation_reason.unwrap_or(CrlReason::Unspecified);
                return Err(revoked_error(
                    "OCSP response",
                    &subject.description,
                    revoked_at,
                    reason,
                ));
            }
            Ok(SingleStatus::Rejected)
        }
        CertStatus::Unknown(_) => Ok(SingleStatus::Rejected),
    }
}

/// Check the certificate against the supplied OCSP responses (port of
/// `verify_ocsp_response`).
pub(crate) fn verify_ocsp(
    ctx: &ValidationContext,
    subject: &Subject<'_>,
) -> Result<CheckOutcome, ValidationError> {
    verify_ocsp_with_completion(ctx, subject, None)?.ordinary()
}

pub(crate) fn verify_ocsp_with_completion(
    ctx: &ValidationContext,
    subject: &Subject<'_>,
    mut completion: Option<&mut crate::validate::LeafRevocationCollector>,
) -> Result<SelectedOutcome, ValidationError> {
    // With an OCSP fetcher, the responses for a certificate that names a
    // responder come from the fetcher (`async_retrieve_ocsps`).
    let fetched;
    let mut responses: Vec<&OcspContainer> = match ctx.fetchers.ocsp.as_ref() {
        Some(fetcher) if subject.cert.declares_ocsp => {
            let response = if subject.cert.is_ac {
                fetcher.fetch_ac_ocsp(&subject.cert.der, subject.issuer)
            } else if let Some(x509) = subject.cert.x509.as_ref() {
                fetcher.fetch_ocsp(x509, subject.issuer)
            } else {
                return Ok(SelectedOutcome::Checked(CheckOutcome::NoMatches));
            };
            match response {
                Ok(der) => {
                    fetched = OcspContainer::load(&der).unwrap_or_default();
                    fetched.iter().collect()
                }
                Err(e) => {
                    return Ok(SelectedOutcome::Checked(CheckOutcome::FetchFailed(
                        e.message,
                    )))
                }
            }
        }
        _ => ctx.ocsps.iter().collect(),
    };
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
        let checkpoint = completion
            .as_deref()
            .map(|collector| collector.checkpoint());
        match handle_single(
            ctx,
            container,
            subject,
            &mut failures,
            completion.as_deref_mut(),
        )? {
            SingleStatus::Good => return Ok(SelectedOutcome::Checked(CheckOutcome::Good)),
            SingleStatus::LeafRevoked => return Ok(SelectedOutcome::LeafRevoked),
            SingleStatus::Rejected => {
                if let (Some(collector), Some(checkpoint)) = (completion.as_deref_mut(), checkpoint)
                {
                    collector.rollback(checkpoint);
                }
            }
        }
    }
    if unrelated == responses.len() {
        return Ok(SelectedOutcome::Checked(CheckOutcome::NoMatches));
    }
    Ok(SelectedOutcome::Checked(CheckOutcome::Indeterminate {
        suspect_stale: failures.suspect_stale(),
        failures: failures.messages,
    }))
}

#[cfg(test)]
mod ac_serial_tests {
    use super::*;
    use crate::ac::AttrCert;
    use crate::authority::TrustAnchor;
    use crate::path::ValidationPath;
    use der::Decode;
    use std::sync::Arc;

    fn fixture(parts: &[&str]) -> Vec<u8> {
        let mut path = vec!["attribute-certs", "basic-aa"];
        path.extend_from_slice(parts);
        std::fs::read(sigis_testdata::certvalidator(&path)).unwrap()
    }

    #[test]
    fn ac_certid_matching_uses_positive_magnitude_after_mature_serial_decode() {
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
        let mut response = OcspContainer::load(&fixture(&["alice-all-good.ors"]))
            .unwrap()
            .remove(0);
        let serial = x509_cert::serial_number::SerialNumber::new(&[0x80]).unwrap();
        assert_eq!(serial.to_der().unwrap(), [0x02, 0x02, 0, 0x80]);
        // x509-cert0.3 stores Int: contrary to its accessor's documentation,
        // required positive sign padding is present in as_bytes().
        assert_eq!(serial.as_bytes(), [0, 0x80]);
        Arc::make_mut(&mut response.basic)
            .tbs_response_data
            .responses[0]
            .cert_id
            .serial_number = serial;
        assert!(matches!(
            match_cert_id(&response, &subject).unwrap(),
            CertIdMatch::Match
        ));
        Arc::make_mut(&mut response.basic)
            .tbs_response_data
            .responses[0]
            .cert_id
            .serial_number =
            x509_cert::serial_number::SerialNumber::from_der(&[0x02, 0x01, 0x80]).unwrap();
        assert!(matches!(
            match_cert_id(&response, &subject).unwrap(),
            CertIdMatch::Failure(_)
        ));
        // This tests matching only. Mutating signed response fields never
        // supplies signature-validation or trust evidence.
    }
}
