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
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::errors::ValidationError;
use sigis_pki_core::time::Moment;

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
        if bytes.response_type != sigis_pki_core::asn1::oids::OCSP_BASIC {
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

    /// DER of the whole `OCSPResponse` this single response came from.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub(crate) fn single(&self) -> Option<&x509_ocsp::SingleResponse> {
        self.basic.tbs_response_data.responses.get(self.index)
    }

    /// `thisUpdate` of the single response.
    pub fn this_update(&self) -> Option<Moment> {
        self.single()
            .map(|s| Moment::from(s.this_update.0.to_date_time()))
    }

    /// Strict historical issuance eligibility, using the original signed time.
    /// The public accessor keeps its existing whole-second freshness semantics.
    pub(crate) fn issued_by(&self, control_time: Moment) -> bool {
        use sigis_pki_core::asn1::tlv::{tag, Tlv};

        let eligible = || -> Option<bool> {
            self.single()?;
            let tbs = Tlv::parse_exact(&self.tbs).ok()?;
            if !tbs.is_universal(tag::SEQUENCE) || !tbs.constructed {
                return None;
            }
            let fields = tbs.children().ok()?;
            let offset = usize::from(fields.first()?.is_context(0));
            let [responder, produced_at, responses, ..] = fields.get(offset..)? else {
                return None;
            };
            if !(responder.is_context(1) || responder.is_context(2))
                || !produced_at.is_universal(tag::GENERALIZED_TIME)
                || produced_at.constructed
                || !responses.is_universal(tag::SEQUENCE)
                || !responses.constructed
            {
                return None;
            }
            let singles = responses.children().ok()?;
            let single = singles.get(self.index)?;
            if !single.is_universal(tag::SEQUENCE) || !single.constructed {
                return None;
            }
            let single_fields = single.children().ok()?;
            let time = single_fields.get(2)?;
            if !time.is_universal(tag::GENERALIZED_TIME) || time.constructed {
                return None;
            }
            let utc = time.value.strip_suffix(b"Z")?;
            let integral = utc.get(..14)?;
            if !integral.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let has_nonzero_fraction = match utc.get(14..)? {
                [] => false,
                [b'.', digits @ ..]
                    if !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) =>
                {
                    digits.iter().any(|digit| *digit != b'0')
                }
                _ => return None,
            };
            // Validate the calendar with the existing decoder. No fractional
            // digits are rounded or parsed numerically, so arbitrary precision
            // and trailing zeroes retain their exact comparison semantics.
            let mut seconds = [0u8; 17];
            seconds[..2].copy_from_slice(&[0x18, 15]);
            seconds[2..16].copy_from_slice(integral);
            seconds[16] = b'Z';
            let issued = Moment::from(
                der::asn1::GeneralizedTime::from_der(&seconds)
                    .ok()?
                    .to_date_time(),
            );
            Some(issued < control_time || (issued == control_time && !has_nonzero_fraction))
        };
        eligible().unwrap_or(false)
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

/// A selected authenticated revoked leaf stays distinct from a Good outcome.
pub(crate) enum SelectedOutcome {
    Checked(CheckOutcome),
    LeafRevoked,
}

impl SelectedOutcome {
    fn ordinary(self) -> Result<CheckOutcome, ValidationError> {
        match self {
            Self::Checked(outcome) => Ok(outcome),
            Self::LeafRevoked => Err(ValidationError::PathValidation(
                "leaf completion escaped ordinary validation".into(),
            )),
        }
    }
}

/// The object whose revocation status is checked: a public-key certificate
/// or an attribute certificate (`x509.Certificate | cms.AttributeCertificateV2`).
#[derive(Clone, Debug)]
pub(crate) struct Target {
    /// DER encoding.
    pub(crate) der: Vec<u8>,
    /// Serial number contents octets.
    pub(crate) serial: Vec<u8>,
    /// Issuer name (for an AC: its issuer's directory name).
    pub(crate) issuer: x509_cert::name::Name,
    /// CRL distribution points.
    pub(crate) dps: Vec<x509_cert::ext::pkix::crl::dp::DistributionPoint>,
    /// `basicConstraints` CA flag.
    pub(crate) is_ca: bool,
    /// The object is an attribute certificate.
    pub(crate) is_ac: bool,
    /// The AIA extension names an OCSP responder.
    pub(crate) declares_ocsp: bool,
    /// A CRL distribution points extension is present.
    pub(crate) declares_crl: bool,
    /// The public-key certificate, if this is one.
    pub(crate) x509: Option<Cert>,
    /// Subject for messages (`human_friendly`, or "" for ACs).
    pub(crate) display_name: String,
}

impl Target {
    pub(crate) fn from_cert(cert: &Cert) -> Self {
        Self {
            der: cert.der().to_vec(),
            serial: cert.serial_bytes().to_vec(),
            issuer: cert.issuer().clone(),
            dps: cert
                .crl_distribution_points()
                .map(|d| d.0)
                .unwrap_or_default(),
            is_ca: cert.is_ca(),
            is_ac: false,
            declares_ocsp: cert.declares_ocsp(),
            declares_crl: cert.declares_crl(),
            x509: Some(cert.clone()),
            display_name: certval::name_to_string(cert.subject()),
        }
    }

    /// `true` if this is `cert`.
    pub(crate) fn is(&self, cert: &Cert) -> bool {
        self.der == cert.der()
    }
}

/// Everything the CRL and OCSP checks need about the certificate being checked.
pub(crate) struct Subject<'a> {
    pub(crate) cert: &'a Target,
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
    check_path_revocation_with_completion(ctx, path, stack, None)
}

pub(crate) fn check_path_revocation_with_completion(
    ctx: &ValidationContext,
    path: &ValidationPath,
    stack: &[Cert],
    mut completion: Option<&mut crate::validate::LeafRevocationCollector>,
) -> Result<(), Box<crate::validate::PathFailure>> {
    let issued = path.issued_certs();
    let total = issued.len();
    for (index, (cert, issuer)) in issued.into_iter().enumerate() {
        let is_ee = index + 1 == total && path.leaf().is_some();
        let target = Target::from_cert(cert);
        let subject = Subject {
            cert: &target,
            issuer,
            path,
            description: path.describe(index, total),
            description_definite: path.describe_definite(index, total),
            is_ee,
            stack,
        };
        check_revocation_with_completion(ctx, &subject, completion.as_deref_mut()).map_err(
            |error| {
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
            },
        )?;
    }
    Ok(())
}

/// Port of `_check_revocation` in pyhanko-certvalidator `validate.py`.
pub(crate) fn check_revocation(
    ctx: &ValidationContext,
    subject: &Subject<'_>,
) -> Result<(), ValidationError> {
    check_revocation_with_completion(ctx, subject, None)
}

fn check_revocation_with_completion(
    ctx: &ValidationContext,
    subject: &Subject<'_>,
    mut completion: Option<&mut crate::validate::LeafRevocationCollector>,
) -> Result<(), ValidationError> {
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
    let digest: [u8; 32] = DigestAlgorithm::Sha256
        .digest(&subject.cert.der)
        .try_into()
        .unwrap_or([0u8; 32]);
    let validation_time = ctx.timing.validation_time;
    if ctx
        .assertions
        .iter()
        .any(|a| a.cert_sha256 == digest && a.at >= validation_time)
    {
        return Ok(());
    }

    let desc = &subject.description;
    let cert_has_crl = subject.cert.declares_crl;
    let cert_has_ocsp = subject.cert.declares_ocsp;
    let revinfo_declared = cert_has_crl || cert_has_ocsp;

    let mut failures: Vec<String> = Vec::new();
    let mut soft_fail = false;
    let mut revocation_check_failed = false;
    let mut ocsp_status_good = false;
    let mut ocsp_leaf_revoked = false;
    let mut ocsp_matched = false;
    let mut crl_matched = false;
    let mut ocsp_suspect_stale = None;
    let mut crl_suspect_stale = None;

    // OCSP is only consulted if the certificate names a responder.
    if rule.ocsp_relevant() && cert_has_ocsp {
        match ocsp::verify_ocsp_with_completion(ctx, subject, completion.as_deref_mut())? {
            SelectedOutcome::LeafRevoked => {
                ocsp_leaf_revoked = true;
                ocsp_matched = true;
            }
            SelectedOutcome::Checked(CheckOutcome::Good) => {
                ocsp_status_good = true;
                ocsp_matched = true;
            }
            SelectedOutcome::Checked(CheckOutcome::Indeterminate {
                failures: f,
                suspect_stale,
            }) => {
                failures.extend(f);
                revocation_check_failed = true;
                ocsp_matched = true;
                ocsp_suspect_stale = suspect_stale;
            }
            SelectedOutcome::Checked(CheckOutcome::NoMatches) => {}
            SelectedOutcome::Checked(CheckOutcome::FetchFailed(msg)) => {
                if rule.tolerant() {
                    soft_fail = true;
                } else {
                    failures.push(msg);
                    revocation_check_failed = true;
                }
            }
        }
    }
    if !ocsp_status_good && !ocsp_leaf_revoked && rule.ocsp_mandatory() {
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
    let selected_ocsp_complete = ocsp_status_good || ocsp_leaf_revoked;
    let status_good = selected_ocsp_complete && rule != RevocationCheckingRule::CrlAndOcspRequired;

    // CRLs are not consulted (even when supplied) if the certificate has no
    // distribution points, unless the policy demands it.
    let mut crl_status_good = false;
    let mut crl_leaf_revoked = false;
    let crl_required_by_policy =
        rule.crl_mandatory() || (!status_good && rule == RevocationCheckingRule::CrlOrOcspRequired);
    let crl_fetchable = rule.crl_relevant() && cert_has_crl;
    if crl_required_by_policy || (crl_fetchable && !status_good) {
        match crl::verify_crl_with_completion(ctx, subject, completion)? {
            SelectedOutcome::LeafRevoked => {
                crl_leaf_revoked = true;
                crl_matched = true;
                revocation_check_failed = false;
            }
            SelectedOutcome::Checked(CheckOutcome::Good) => {
                revocation_check_failed = false;
                crl_status_good = true;
                crl_matched = true;
            }
            SelectedOutcome::Checked(CheckOutcome::Indeterminate {
                failures: f,
                suspect_stale,
            }) => {
                failures.extend(f);
                revocation_check_failed = true;
                crl_matched = true;
                crl_suspect_stale = suspect_stale;
            }
            SelectedOutcome::Checked(CheckOutcome::NoMatches) => {}
            SelectedOutcome::Checked(CheckOutcome::FetchFailed(msg)) => {
                if rule.tolerant() {
                    soft_fail = true;
                } else {
                    failures.push(msg);
                    revocation_check_failed = true;
                }
            }
        }
    }
    if !crl_status_good && !crl_leaf_revoked && rule.crl_mandatory() {
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

    let status_good = status_good || crl_status_good || crl_leaf_revoked;
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
            subject.cert.display_name
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
    use der::{asn1::OctetString, Encode};
    use sigis_pki_core::asn1::tlv::{encode, Tlv};

    // These edited responses exercise metadata parsing only: their original
    // signatures no longer authenticate the edited ResponseData. Authenticated
    // historical verdicts are covered separately by the signed-PDF regression.
    fn ocsp_metadata(times: &[&[u8]], produced_at: &[u8]) -> Vec<OcspContainer> {
        let fixture = sigis_testdata::read(&[
            "pyhanko-certvalidator",
            "ades",
            "time-slide",
            "alice-2020-11-29.ors",
        ]);
        let mut outer = x509_ocsp::OcspResponse::from_der(&fixture).expect("OCSP fixture");
        let response_bytes = outer.response_bytes.as_mut().expect("response bytes");
        let basic = decode_lenient::<BasicOcspResponse>(response_bytes.response.as_bytes())
            .expect("basic response");
        let single_der = basic.tbs_response_data.responses[0]
            .to_der()
            .expect("single response");
        let single = Tlv::parse_exact(&single_der)
            .expect("single TLV")
            .children()
            .expect("single fields");
        let responses = times
            .iter()
            .flat_map(|time| {
                let mut fields = single
                    .iter()
                    .map(|field| field.raw.to_vec())
                    .collect::<Vec<_>>();
                fields[2] = encode(0x18, time);
                encode(0x30, &fields.concat())
            })
            .collect::<Vec<_>>();
        let tbs = encode(
            0x30,
            &[
                basic
                    .tbs_response_data
                    .responder_id
                    .to_der()
                    .expect("responder ID"),
                encode(0x18, produced_at),
                encode(0x30, &responses),
            ]
            .concat(),
        );
        let basic_der = basic.to_der().expect("basic DER");
        let mut fields = Tlv::parse_exact(&basic_der)
            .expect("basic TLV")
            .children()
            .expect("basic fields")
            .iter()
            .map(|field| field.raw.to_vec())
            .collect::<Vec<_>>();
        fields[0] = tbs;
        response_bytes.response =
            OctetString::new(encode(0x30, &fields.concat())).expect("basic response octets");
        OcspContainer::load(&outer.to_der().expect("OCSP DER")).expect("metadata response")
    }

    #[test]
    fn historical_ocsp_issuance_preserves_fractional_boundary() {
        let control = Moment::from_ymd_hms(2026, 11, 15, 4, 48, 36).expect("control time");
        for (time, eligible) in [
            (&b"20261115044835.999999Z"[..], true),
            (&b"20261115044836Z"[..], true),
            (&b"20261115044836.000000Z"[..], true),
            (&b"20261115044836.000000000000Z"[..], true),
            (&b"20261115044836.000001Z"[..], false),
            (&b"20261115044836.000000000000000001Z"[..], false),
            (&b"20261115044836.125430Z"[..], false),
            (&b"20261115044836.999999Z"[..], false),
        ] {
            let response = ocsp_metadata(&[time], b"20261115044837Z").remove(0);
            assert_eq!(response.issued_by(control), eligible, "{time:?}");
            assert!(response.issued_by(control.plus(std::time::Duration::from_secs(1))));
            // Public whole-second accessors retain their existing semantics.
            assert_eq!(
                response.this_update(),
                Some(if time.starts_with(b"20261115044835") {
                    control.minus(std::time::Duration::from_secs(1))
                } else {
                    control
                })
            );
            let next = response.single().expect("single").next_update;
            assert_eq!(
                response.next_update(),
                next.map(|t| Moment::from(t.0.to_date_time()))
            );
        }
    }

    #[test]
    fn historical_ocsp_issuance_uses_single_response_index() {
        let control = Moment::from_ymd_hms(2026, 11, 15, 4, 48, 36).expect("control time");
        let responses = ocsp_metadata(
            &[b"20261115044835.999999Z", b"20261115044836.125430Z"],
            b"20261115044837Z",
        );
        assert_eq!(responses.len(), 2);
        assert!(responses[0].issued_by(control));
        assert!(!responses[1].issued_by(control));
        assert!(responses[1].issued_by(control.plus(std::time::Duration::from_secs(1))));

        // The optional version field must not shift the SingleResponse lookup.
        let mut versioned = responses[1].clone();
        let original = Tlv::parse_exact(&versioned.tbs).expect("ResponseData");
        versioned.tbs = encode(
            0x30,
            &[encode(0xa0, &[0x02, 0x01, 0x00]), original.value.to_vec()].concat(),
        )
        .into();
        assert!(!versioned.issued_by(control));
        assert!(versioned.issued_by(control.plus(std::time::Duration::from_secs(1))));
    }

    #[test]
    fn historical_ocsp_issuance_fails_closed_without_original_time() {
        let control = Moment::from_ymd_hms(2026, 11, 15, 4, 48, 36).expect("control time");
        let response = ocsp_metadata(&[b"20261115044836Z"], b"20261115044836Z").remove(0);
        for tbs in [
            Vec::new(),
            vec![0x30, 0x00],
            vec![0x30, 0x03, 0x18, 0x02, b'Z'],
            encode(
                0x30,
                &[
                    encode(0xa2, &[0x04, 0x00]),
                    encode(0x18, b"20261115044836Z"),
                    encode(
                        0x30,
                        &encode(
                            0x30,
                            &[
                                encode(0x30, &[]),
                                encode(0x80, &[]),
                                encode(0x18, b"20261315044836.1Z"),
                            ]
                            .concat(),
                        ),
                    ),
                ]
                .concat(),
            ),
        ] {
            let mut malformed = response.clone();
            malformed.tbs = tbs.into();
            assert!(!malformed.issued_by(control));
        }
        let mut missing = response;
        missing.index = 1;
        assert!(!missing.issued_by(control));
        // The lenient decoder strips an empty fraction, but strict historical
        // eligibility still rejects the invalid original time.
        let empty_fraction = ocsp_metadata(&[b"20261115044836.Z"], b"20261115044836Z").remove(0);
        assert!(!empty_fraction.issued_by(control));
        assert!(!empty_fraction.issued_by(control.plus(std::time::Duration::from_secs(1))));
    }

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
