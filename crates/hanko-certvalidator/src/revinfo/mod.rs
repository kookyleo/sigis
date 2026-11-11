// Derived from pyhanko-certvalidator `revinfo/*.py` and `validate.py`
// (`_check_revocation`) (MIT, see LICENSE-pyHanko).

//! Offline revocation checking from caller-supplied CRLs and OCSP responses.
//!
//! No network access happens here. Supported:
//!
//! - Direct CRLs (signed by the certificate issuer's key), with
//!   issuing-distribution-point scoping and `onlySomeReasons` handled fail-closed.
//! - OCSP responses signed by the issuer or by a delegated responder that the
//!   issuer certified with `id-kp-OCSPSigning`.
//! - The pyhanko-certvalidator revocation checking rules and freshness policies.
//!
//! Not supported yet (fail closed: such information is not used): delta CRLs,
//! indirect CRLs, CRLs signed with a key other than the issuer's (separate CRL
//! signing certificates, key rollover), and revocation checking of delegated
//! OCSP responders.

pub(crate) mod crl;
pub mod freshness;
pub(crate) mod ocsp;

use std::sync::Arc;

use der::{asn1::AnyRef, Decode, Reader, SliceReader};
use x509_cert::certificate::Raw;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::CrlReason;
use x509_ocsp::BasicOcspResponse;

use super::authority::Cert;
use super::context::ValidationContext;
use super::path::ValidationPath;
use super::policy::RevocationCheckingRule;
use hanko_core::errors::ValidationError;
use hanko_core::time::Moment;

/// A parsed CRL with the exact bytes of its signed part.
#[derive(Clone, Debug)]
pub struct CrlContainer {
    pub(crate) crl: Arc<CertificateList<Raw>>,
    pub(crate) tbs: Arc<[u8]>,
    pub(crate) der: Arc<[u8]>,
}

impl CrlContainer {
    /// Parse a DER-encoded CRL.
    pub fn from_der(der: &[u8]) -> Result<Self, ValidationError> {
        let crl = decode_lenient::<CertificateList<Raw>>(der)
            .map_err(|e| ValidationError::Malformed(format!("CRL: {e}")))?;
        let tbs = signed_part(der).map_err(|e| ValidationError::Malformed(format!("CRL: {e}")))?;
        Ok(Self {
            crl: Arc::new(crl),
            tbs: tbs.into(),
            der: der.into(),
        })
    }

    /// The DER encoding.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// `thisUpdate`.
    pub fn this_update(&self) -> Moment {
        Moment::from(self.crl.tbs_cert_list.this_update)
    }

    /// `nextUpdate`.
    pub fn next_update(&self) -> Option<Moment> {
        self.crl.tbs_cert_list.next_update.map(Moment::from)
    }
}

/// One `SingleResponse` of a successful basic OCSP response.
#[derive(Clone, Debug)]
pub struct OcspContainer {
    pub(crate) basic: Arc<BasicOcspResponse>,
    pub(crate) tbs: Arc<[u8]>,
    pub(crate) index: usize,
    /// DER of the whole `OCSPResponse`.
    pub(crate) der: Arc<[u8]>,
}

impl OcspContainer {
    /// Parse a DER-encoded `OCSPResponse` into one container per
    /// `SingleResponse`. Unsuccessful responses yield no containers.
    pub fn load(der: &[u8]) -> Result<Vec<Self>, ValidationError> {
        use x509_ocsp::{OcspResponse, OcspResponseStatus};
        let malformed = |e: der::Error| ValidationError::Malformed(format!("OCSP response: {e}"));
        let response = OcspResponse::from_der(der).map_err(malformed)?;
        let Some(bytes) = response
            .response_bytes
            .filter(|_| response.response_status == OcspResponseStatus::Successful)
        else {
            return Ok(Vec::new());
        };
        if bytes.response_type != hanko_core::asn1::oids::OCSP_BASIC {
            return Ok(Vec::new());
        }
        let basic_der = bytes.response.as_bytes();
        let basic = Arc::new(decode_lenient::<BasicOcspResponse>(basic_der).map_err(malformed)?);
        let tbs: Arc<[u8]> = signed_part(basic_der).map_err(malformed)?.into();
        let whole: Arc<[u8]> = der.into();
        Ok((0..basic.tbs_response_data.responses.len())
            .map(|index| Self {
                basic: basic.clone(),
                tbs: tbs.clone(),
                index,
                der: whole.clone(),
            })
            .collect())
    }

    pub(crate) fn single(&self) -> Option<&x509_ocsp::SingleResponse> {
        self.basic.tbs_response_data.responses.get(self.index)
    }

    /// `thisUpdate` of the single response.
    pub fn this_update(&self) -> Option<Moment> {
        self.single()
            .map(|s| Moment::from(s.this_update.0.to_date_time()))
    }

    /// `nextUpdate` of the single response.
    pub fn next_update(&self) -> Option<Moment> {
        self.single()
            .and_then(|s| s.next_update)
            .map(|t| Moment::from(t.0.to_date_time()))
    }
}

/// Decode `der`; if that fails, retry on a copy whose `GeneralizedTime`
/// values have their fractional seconds removed.
///
/// DER (X.690 §11.7) allows fractional seconds, and OCSP responders emit them,
/// but the `der` crate rejects them. Signatures are always verified over the
/// original bytes; only the decoded times lose sub-second precision.
pub(crate) fn decode_lenient<T: for<'a> Decode<'a, Error = der::Error>>(
    der: &[u8],
) -> Result<T, der::Error> {
    T::from_der(der).or_else(|e| {
        let mut normalized = Vec::with_capacity(der.len());
        match strip_fractional_seconds(der, &mut normalized, 0) {
            Some(()) if normalized != der => T::from_der(&normalized),
            _ => Err(e),
        }
    })
}

const MAX_TLV_DEPTH: u8 = 32;

fn read_length(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 {
        return None;
    }
    let bytes = input.get(1..=n)?;
    let len = bytes
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    Some((len, 1 + n))
}

fn write_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// Copy a sequence of TLVs, rewriting `GeneralizedTime` values
/// `YYYYMMDDHHMMSS.fffZ` to `YYYYMMDDHHMMSSZ`. Returns `None` on input it does
/// not understand (high tag numbers, bad lengths, excessive nesting).
fn strip_fractional_seconds(input: &[u8], out: &mut Vec<u8>, depth: u8) -> Option<()> {
    if depth > MAX_TLV_DEPTH {
        return None;
    }
    let mut rest = input;
    while let Some(&tag) = rest.first() {
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (len, len_bytes) = read_length(rest.get(1..)?)?;
        let start = 1 + len_bytes;
        let end = start.checked_add(len)?;
        let content = rest.get(start..end)?;
        if tag & 0x20 != 0 {
            let mut inner = Vec::with_capacity(content.len());
            strip_fractional_seconds(content, &mut inner, depth + 1)?;
            out.push(tag);
            write_length(out, inner.len());
            out.extend_from_slice(&inner);
        } else if tag == 0x18 && content.contains(&b'.') {
            let dot = content.iter().position(|b| *b == b'.')?;
            let suffix_start = content[dot + 1..]
                .iter()
                .position(|b| !b.is_ascii_digit())?
                + dot
                + 1;
            let mut fixed = content[..dot].to_vec();
            fixed.extend_from_slice(&content[suffix_start..]);
            out.push(tag);
            write_length(out, fixed.len());
            out.extend_from_slice(&fixed);
        } else {
            out.extend_from_slice(rest.get(..end)?);
        }
        rest = rest.get(end..)?;
    }
    Some(())
}

/// The bytes of the first element of a DER `SEQUENCE` (the signed part of a
/// certificate, CRL or OCSP response), exactly as encoded.
pub(crate) fn signed_part(der: &[u8]) -> Result<&[u8], der::Error> {
    let mut outer = SliceReader::new(der)?;
    let outer_tlv = outer.tlv_bytes()?;
    let value = AnyRef::from_der(outer_tlv)?.value();
    let mut inner = SliceReader::new(value)?;
    inner.tlv_bytes()
}

/// Failures collected while trying revocation information of one type
/// (`Errors` in pyhanko-certvalidator).
#[derive(Debug, Default)]
pub(crate) struct Failures {
    pub(crate) messages: Vec<String>,
    stale_last_usable_at: Option<Moment>,
    non_freshness_failures: usize,
}

impl Failures {
    pub(crate) fn push(&mut self, msg: impl Into<String>) {
        self.messages.push(msg.into());
        self.non_freshness_failures += 1;
    }

    pub(crate) fn push_freshness(
        &mut self,
        msg: impl Into<String>,
        last_usable_at: Option<Moment>,
    ) {
        self.messages.push(msg.into());
        if let Some(t) = last_usable_at {
            self.stale_last_usable_at = Some(self.stale_last_usable_at.map_or(t, |s| s.max(t)));
        }
    }

    /// The stale cutoff, if every failure was a freshness failure.
    pub(crate) fn suspect_stale(&self) -> Option<Moment> {
        (self.non_freshness_failures == 0)
            .then_some(self.stale_last_usable_at)
            .flatten()
    }
}

/// Result of checking one kind of revocation information for one certificate.
#[derive(Debug)]
pub(crate) enum CheckOutcome {
    /// Status established as good.
    Good,
    /// No information applies to the certificate.
    NoMatches,
    /// Information applies but could not establish the status.
    Indeterminate {
        failures: Vec<String>,
        suspect_stale: Option<Moment>,
    },
    /// Fetching revocation information failed (`OCSPFetchError` /
    /// `CRLFetchError`).
    FetchFailed(String),
}

/// Everything the CRL and OCSP checks need about the certificate being checked.
pub(crate) struct Subject<'a> {
    pub(crate) cert: &'a Cert,
    pub(crate) issuer: &'a Cert,
    /// The path being validated (the certificate's issuer is in it).
    pub(crate) path: &'a ValidationPath,
    pub(crate) description: String,
    pub(crate) description_definite: String,
    pub(crate) is_ee: bool,
    /// Leaves of the paths being validated, outermost first (the current
    /// path's leaf last): revocation information signers are validated
    /// recursively (`cert_path_stack`).
    pub(crate) stack: &'a [Cert],
}

/// Human-readable reason, as asn1crypto's `CRLReason.human_friendly`.
pub(crate) fn reason_text(reason: CrlReason) -> &'static str {
    match reason {
        CrlReason::Unspecified => "an unspecified reason",
        CrlReason::KeyCompromise => "a compromised key",
        CrlReason::CaCompromise => "the CA being compromised",
        CrlReason::AffiliationChanged => "an affiliation change",
        CrlReason::Superseded => "certificate supersession",
        CrlReason::CessationOfOperation => "a cessation of operation",
        CrlReason::CertificateHold => "a certificate hold",
        CrlReason::RemoveFromCRL => "removal from the CRL",
        CrlReason::PrivilegeWithdrawn => "privilege withdrawl",
        CrlReason::AaCompromise => "the AA being compromised",
    }
}

fn reason_name(reason: CrlReason) -> &'static str {
    match reason {
        CrlReason::Unspecified => "unspecified",
        CrlReason::KeyCompromise => "key_compromise",
        CrlReason::CaCompromise => "ca_compromise",
        CrlReason::AffiliationChanged => "affiliation_changed",
        CrlReason::Superseded => "superseded",
        CrlReason::CessationOfOperation => "cessation_of_operation",
        CrlReason::CertificateHold => "certificate_hold",
        CrlReason::RemoveFromCRL => "remove_from_crl",
        CrlReason::PrivilegeWithdrawn => "privilege_withdrawn",
        CrlReason::AaCompromise => "aa_compromise",
    }
}

/// `RevokedError.format` in pyhanko-certvalidator.
pub(crate) fn revoked_error(
    revinfo_type: &str,
    description: &str,
    at: Moment,
    reason: CrlReason,
) -> ValidationError {
    let (date, time) = match at.to_der_datetime() {
        Some(dt) => (
            format!("{:04}-{:02}-{:02}", dt.year(), dt.month(), dt.day()),
            format!("{:02}:{:02}:{:02}", dt.hour(), dt.minutes(), dt.seconds()),
        ),
        None => (at.to_string(), String::new()),
    };
    ValidationError::Revoked {
        msg: format!(
            "{revinfo_type} indicates {description} was revoked at {time} on {date}, due to {}",
            reason_text(reason)
        ),
        revocation_time: Some(at),
        reason: Some(reason_name(reason)),
    }
}

/// Check the revocation status of every certificate in `path` below the
/// trust anchor, reporting which certificate failed.
pub(crate) fn check_path_revocation_detailed(
    ctx: &ValidationContext,
    path: &ValidationPath,
    stack: &[Cert],
) -> Result<(), Box<crate::validate::PathFailure>> {
    let issued = path.issued_certs();
    let total = issued.len();
    for (index, (cert, issuer)) in issued.into_iter().enumerate() {
        let is_ee = index + 1 == total && path.leaf().is_some();
        let subject = Subject {
            cert,
            issuer,
            path,
            description: path.describe(index, total),
            description_definite: path.describe_definite(index, total),
            is_ee,
            stack,
        };
        check_revocation(ctx, &subject).map_err(|error| {
            let time_horizon = match &error {
                ValidationError::Revoked {
                    revocation_time, ..
                } => *revocation_time,
                ValidationError::StaleRevinfo { time_cutoff, .. } => *time_cutoff,
                _ => None,
            };
            Box::new(crate::validate::PathFailure {
                error,
                path: Some(path.clone()),
                is_ee_cert: is_ee,
                is_side_validation: false,
                time_horizon,
                invalid_certificate: false,
            })
        })?;
    }
    Ok(())
}

/// Port of `_check_revocation` in pyhanko-certvalidator `validate.py`.
fn check_revocation(ctx: &ValidationContext, subject: &Subject<'_>) -> Result<(), ValidationError> {
    let policy = &ctx.revinfo_policy.revocation_checking_policy;
    let rule = if subject.is_ee {
        policy.ee_certificate_rule
    } else {
        policy.intermediate_ca_cert_rule
    };
    if rule == RevocationCheckingRule::NoCheck {
        return Ok(());
    }

    // A caller-supplied assertion settles the status.
    let digest = subject.cert.sha256();
    let validation_time = ctx.timing.validation_time;
    if ctx
        .assertions
        .iter()
        .any(|a| a.cert_sha256 == digest && a.at >= validation_time)
    {
        return Ok(());
    }

    let desc = &subject.description;
    let cert_has_crl = subject.cert.declares_crl();
    let cert_has_ocsp = subject.cert.declares_ocsp();
    let revinfo_declared = cert_has_crl || cert_has_ocsp;

    let mut failures: Vec<String> = Vec::new();
    let mut soft_fail = false;
    let mut revocation_check_failed = false;
    let mut ocsp_status_good = false;
    let mut ocsp_matched = false;
    let mut crl_matched = false;
    let mut ocsp_suspect_stale = None;
    let mut crl_suspect_stale = None;

    // OCSP is only consulted if the certificate names a responder.
    if rule.ocsp_relevant() && cert_has_ocsp {
        match ocsp::verify_ocsp(ctx, subject)? {
            CheckOutcome::Good => {
                ocsp_status_good = true;
                ocsp_matched = true;
            }
            CheckOutcome::Indeterminate {
                failures: f,
                suspect_stale,
            } => {
                failures.extend(f);
                revocation_check_failed = true;
                ocsp_matched = true;
                ocsp_suspect_stale = suspect_stale;
            }
            CheckOutcome::NoMatches => {}
            CheckOutcome::FetchFailed(msg) => {
                if rule.tolerant() {
                    soft_fail = true;
                } else {
                    failures.push(msg);
                    revocation_check_failed = true;
                }
            }
        }
    }
    if !ocsp_status_good && rule.ocsp_mandatory() {
        let err = if failures.is_empty() {
            "an applicable OCSP response could not be found".to_owned()
        } else {
            failures.join("; ")
        };
        let msg = format!(
            "The path could not be validated because the mandatory OCSP check(s) for {desc} failed: {err}"
        );
        return Err(stale_or_insufficient(msg, ocsp_suspect_stale));
    }
    let status_good = ocsp_status_good && rule != RevocationCheckingRule::CrlAndOcspRequired;

    // CRLs are not consulted (even when supplied) if the certificate has no
    // distribution points, unless the policy demands it.
    let mut crl_status_good = false;
    let crl_required_by_policy =
        rule.crl_mandatory() || (!status_good && rule == RevocationCheckingRule::CrlOrOcspRequired);
    let crl_fetchable = rule.crl_relevant() && cert_has_crl;
    if crl_required_by_policy || (crl_fetchable && !status_good) {
        match crl::verify_crl(ctx, subject)? {
            CheckOutcome::Good => {
                revocation_check_failed = false;
                crl_status_good = true;
                crl_matched = true;
            }
            CheckOutcome::Indeterminate {
                failures: f,
                suspect_stale,
            } => {
                failures.extend(f);
                revocation_check_failed = true;
                crl_matched = true;
                crl_suspect_stale = suspect_stale;
            }
            CheckOutcome::NoMatches => {}
            CheckOutcome::FetchFailed(msg) => {
                if rule.tolerant() {
                    soft_fail = true;
                } else {
                    failures.push(msg);
                    revocation_check_failed = true;
                }
            }
        }
    }
    if !crl_status_good && rule.crl_mandatory() {
        let err = if failures.is_empty() {
            "an applicable CRL could not be found".to_owned()
        } else {
            failures.join("; ")
        };
        let msg = format!(
            "The path could not be validated because the mandatory CRL check(s) for {desc} failed: {err}"
        );
        return Err(stale_or_insufficient(msg, crl_suspect_stale));
    }

    let status_good = status_good || crl_status_good;
    let expected_revinfo =
        rule.strict() || (revinfo_declared && rule == RevocationCheckingRule::CheckIfDeclared);
    let matched = crl_matched || ocsp_matched;
    // Only *fetch* failures are tolerated in soft-fail mode: information
    // that applies but fails validation is still an error.
    if soft_fail {
        return Ok(());
    }
    if !status_good && matched && revocation_check_failed {
        let msg = format!(
            "The path could not be validated because {} revocation checks failed: {}",
            subject.description_definite,
            failures.join("; ")
        );
        let stale = match (ocsp_suspect_stale, crl_suspect_stale) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        return Err(stale_or_insufficient(msg, stale));
    }
    if !matched && expected_revinfo {
        return Err(ValidationError::InsufficientRevinfo(format!(
            "The path could not be validated because no revocation information could be found for {desc} {}",
            certval::name_to_string(subject.cert.subject())
        )));
    }
    Ok(())
}

fn stale_or_insufficient(msg: String, stale: Option<Moment>) -> ValidationError {
    match stale {
        Some(cutoff) => ValidationError::StaleRevinfo {
            msg,
            time_cutoff: Some(cutoff),
        },
        None => ValidationError::InsufficientRevinfo(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_fractional_generalized_time() {
        // SEQUENCE { GeneralizedTime "20210819121804.364362Z", INTEGER 5 }
        let time = b"20210819121804.364362Z";
        let mut der = vec![0x30, (2 + time.len() + 3) as u8, 0x18, time.len() as u8];
        der.extend_from_slice(time);
        der.extend_from_slice(&[0x02, 0x01, 0x05]);
        let mut out = Vec::new();
        strip_fractional_seconds(&der, &mut out, 0).expect("rewrite");
        let mut expected = vec![0x30, 20, 0x18, 15];
        expected.extend_from_slice(b"20210819121804Z");
        expected.extend_from_slice(&[0x02, 0x01, 0x05]);
        assert_eq!(out, expected);
    }

    #[test]
    fn rewriter_rejects_garbage_without_panicking() {
        for input in [
            &[0x30, 0x85, 0, 0, 0, 0, 1][..],
            &[0x30, 0x05, 0x02][..],
            &[0x1f, 0x00][..],
            &[0x30][..],
        ] {
            let mut out = Vec::new();
            assert!(
                strip_fractional_seconds(input, &mut out, 0).is_none(),
                "{input:?}"
            );
        }
        // Deep nesting is bounded.
        let mut deep = vec![0x02, 0x01, 0x00];
        for _ in 0..40 {
            let mut wrapped = vec![0x30];
            write_length(&mut wrapped, deep.len());
            wrapped.extend_from_slice(&deep);
            deep = wrapped;
        }
        assert!(strip_fractional_seconds(&deep, &mut Vec::new(), 0).is_none());
    }
}
