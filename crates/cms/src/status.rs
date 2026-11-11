// Derived from pyHanko `sign/validation/status.py` (MIT, see LICENSE-pyHanko).

//! Validation status types (`SignatureStatus` and subclasses).

use std::collections::BTreeMap;

use sigis_pki_certvalidator::ValidationPath;
use sigis_pki_core::algorithms::{DigestAlgorithm, SignatureMechanism};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::ValidationError;
use sigis_pki_core::time::Moment;

use sigis_pki_core::ades::AdesSubIndic;

/// Why trust in the signer could not be established (`trust_problem_indic`).
///
/// The AdES sub-indication is in [`SignatureStatus::trust_problem_indic`];
/// this keeps the underlying error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustProblem {
    /// Path building or validation failed, or the CMS-level algorithm
    /// policy rejected the signature
    /// ([`ValidationError::DisallowedAlgorithm`]).
    Path(ValidationError),
    /// The signer certificate is unsuitable (`InvalidCertificateError`):
    /// key usage requirements failed, or it is self-signed and untrusted.
    KeyUsage(String),
}

/// Details of a revocation affecting the signer (`RevocationDetails`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationDetails {
    /// `false` if the signer's certificate is revoked, `true` if a CA
    /// certificate in its path is.
    pub ca_revoked: bool,
    /// Revocation time.
    pub revocation_date: Option<Moment>,
    /// RFC 5280 reason name (`key_compromise`, ...).
    pub revocation_reason: Option<&'static str>,
}

/// Cryptographic and trust status of one CMS signature (`SignatureStatus`).
///
/// [`Default`] is the fail-closed status: not intact, not valid, no path.
#[derive(Clone, Debug, Default)]
pub struct SignatureStatus {
    /// The message digest attribute matches the content.
    pub intact: bool,
    /// The signature over the signed attributes verifies.
    pub valid: bool,
    /// Trust problem, if any; `None` with `validation_path` set means trusted.
    pub trust_problem: Option<TrustProblem>,
    /// The signer certificate.
    pub signing_cert: Option<Cert>,
    /// Signature mechanism used, if supported.
    pub signature_mechanism: Option<SignatureMechanism>,
    /// Digest algorithm used, if supported.
    pub md_algorithm: Option<DigestAlgorithm>,
    /// The validated certification path, if trust was established, or the
    /// path on which validation failed.
    pub validation_path: Option<ValidationPath>,
    /// AdES sub-indication of the trust problem (`trust_problem_indic`).
    pub trust_problem_indic: Option<AdesSubIndic>,
    /// asn1crypto name of the signature algorithm (`pkcs7_signature_mechanism`).
    pub pkcs7_signature_mechanism: String,
    /// asn1crypto name of the digest algorithm (`md_algorithm` in pyHanko).
    pub md_algorithm_name: String,
    /// Revocation details, if a certificate in the path is revoked.
    pub revocation_details: Option<RevocationDetails>,
    /// Moment at which the validation outcome may change (`error_time_horizon`).
    pub error_time_horizon: Option<Moment>,
    /// Reference time of the validation (`validation_time`).
    pub validation_time: Option<Moment>,
}

impl SignatureStatus {
    /// Intact, valid and trusted (`trusted`).
    pub fn bottom_line(&self) -> bool {
        self.trusted()
    }

    /// `trusted`: intact, valid, no trust problem and a validation path.
    pub fn trusted(&self) -> bool {
        self.intact
            && self.valid
            && self.trust_problem_indic.is_none()
            && self.trust_problem.is_none()
            && self.validation_path.is_some()
    }

    /// `revoked`.
    pub fn revoked(&self) -> bool {
        self.revocation_details.is_some()
    }

    /// `summary_fields`.
    pub fn summary_fields(&self) -> Vec<String> {
        let status = if self.trusted() {
            "TRUSTED"
        } else if self.revoked() {
            "REVOKED"
        } else {
            "UNTRUSTED"
        };
        vec![status.to_owned()]
    }

    /// `summary(delimiter)`.
    pub fn summary_with(&self, delimiter: &str) -> String {
        if self.intact && self.valid {
            format!("INTACT:{}", self.summary_fields().join(delimiter))
        } else {
            "INVALID".to_owned()
        }
    }

    /// `summary()`.
    pub fn summary(&self) -> String {
        self.summary_with(",")
    }

    fn trust_anchor_description(&self) -> String {
        match &self.validation_path {
            Some(p) => human_friendly(p.trust_anchor().cert()),
            None => "No path to trust anchor found.".to_owned(),
        }
    }
}

/// asn1crypto-style `human_friendly` rendering of a certificate subject.
pub fn human_friendly(cert: &Cert) -> String {
    sigis_pki_certvalidator::names::human_friendly(cert.subject())
}

/// Status of an RFC 3161 timestamp token (`TimestampSignatureStatus`).
#[derive(Clone, Debug)]
pub struct TimestampSignatureStatus {
    /// Status of the token's own CMS signature.
    pub signature: SignatureStatus,
    /// `genTime` from the `TSTInfo`.
    pub timestamp: Moment,
}

impl TimestampSignatureStatus {
    /// `trusted`.
    pub fn trusted(&self) -> bool {
        self.signature.trusted()
    }

    /// `describe_timestamp_trust`.
    pub fn describe_timestamp_trust(&self) -> String {
        let s = &self.signature;
        let (subject, sha1, sha256) = match &s.signing_cert {
            Some(c) => (
                human_friendly(c),
                hex(&DigestAlgorithm::Sha1.digest(c.der())),
                hex(&c.sha256()),
            ),
            None => (String::new(), String::new(), String::new()),
        };
        format!(
            "This timestamp is backed by a time stamping authority.\n\
             The timestamp token is cryptographically {}sound.\n\
             TSA certificate subject: \"{subject}\"\n\
             TSA certificate SHA1 fingerprint: {sha1}\n\
             TSA certificate SHA256 fingerprint: {sha256}\n\
             TSA cert trust anchor: \"{}\"\n\
             The TSA certificate is {}trusted.",
            if s.intact && s.valid { "" } else { "un" },
            s.trust_anchor_description(),
            if s.trusted() { "" } else { "un" },
        )
    }
}

/// An attribute of an attribute certificate or claimed by the signer
/// (`X509AttributeInfo` / `CertifiedAttributeInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributeInfo {
    /// Attribute type (dotted OID or asn1crypto name).
    pub attr_type: String,
    /// DER encodings of the values.
    pub attr_values: Vec<Vec<u8>>,
    /// For certified attributes: indices into the AC validation results that
    /// support the values.
    pub validation_results: Vec<usize>,
}

/// Attributes keyed by type (`ClaimedAttributes` / `CertifiedAttributes`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttributeMap(pub BTreeMap<String, AttributeInfo>);

impl AttributeMap {
    /// Number of attribute types.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// No attributes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The attribute of type `name`, if present.
    pub fn get(&self, name: &str) -> Option<&AttributeInfo> {
        self.0.get(name)
    }

    /// `name in attrs`.
    pub fn contains(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
}

/// Information from a `signer-attrs-v2` attribute
/// (`CAdESSignerAttributeAssertions`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CadesSignerAttributeAssertions {
    /// Claimed attributes.
    pub claimed_attrs: AttributeMap,
    /// Certified attributes from valid attribute certificates; `None` if no
    /// AC validation context was given.
    pub certified_attrs: Option<AttributeMap>,
    /// AC validation errors; `None` if no AC validation context was given.
    pub ac_validation_errs: Option<Vec<String>>,
    /// Unsupported certified attributes or signed assertions were present.
    pub unknown_attrs_present: bool,
}

impl CadesSignerAttributeAssertions {
    /// `valid`: no AC validation errors.
    pub fn valid(&self) -> bool {
        self.ac_validation_errs.as_ref().is_none_or(Vec::is_empty)
    }
}

/// Status of a CAdES-style CMS signature (`StandardCMSSignatureStatus`).
#[derive(Clone, Debug, Default)]
pub struct StandardCmsSignatureStatus {
    /// Core signature status.
    pub signature: SignatureStatus,
    /// `signingTime` attribute (an unverified claim).
    pub signer_reported_dt: Option<Moment>,
    /// Signature timestamp (`signatureTimeStampToken` unsigned attribute).
    pub timestamp_validity: Option<TimestampSignatureStatus>,
    /// Content timestamp (`contentTimeStamp` signed attribute).
    pub content_timestamp_validity: Option<TimestampSignatureStatus>,
    /// `signer-attrs-v2` processing result.
    pub cades_signer_attrs: Option<CadesSignerAttributeAssertions>,
    /// Attributes from valid attribute certificates (`ac_attrs`); `None`
    /// without an AC validation context.
    pub ac_attrs: Option<AttributeMap>,
    /// Attribute certificate validation errors (`ac_validation_errs`).
    pub ac_validation_errs: Option<Vec<String>>,
}

impl StandardCmsSignatureStatus {
    /// `bottom_line`: the signature is trusted and every timestamp present
    /// is valid, intact and trusted.
    pub fn bottom_line(&self) -> bool {
        let ts_ok = |ts: &Option<TimestampSignatureStatus>| {
            ts.as_ref()
                .is_none_or(|t| t.signature.valid && t.signature.intact && t.trusted())
        };
        self.signature.intact
            && self.signature.valid
            && self.signature.trusted()
            && ts_ok(&self.timestamp_validity)
            && ts_ok(&self.content_timestamp_validity)
    }

    /// `summary_fields`.
    pub fn summary_fields(&self) -> Vec<String> {
        let mut out = self.signature.summary_fields();
        if let Some(ts) = &self.timestamp_validity {
            out.push(format!(
                "TIMESTAMP_TOKEN<{}>",
                ts.signature.summary_with("|")
            ));
        }
        if let Some(ts) = &self.content_timestamp_validity {
            out.push(format!(
                "CONTENT_TIMESTAMP_TOKEN<{}>",
                ts.signature.summary_with("|")
            ));
        }
        if self.cades_signer_attrs.as_ref().is_some_and(|c| !c.valid()) {
            out.push("CERTIFIED_SIGNER_ATTRS_INVALID".to_owned());
        }
        out
    }

    /// `summary()`.
    pub fn summary(&self) -> String {
        let s = &self.signature;
        if s.intact && s.valid {
            format!("INTACT:{}", self.summary_fields().join(","))
        } else {
            "INVALID".to_owned()
        }
    }

    /// `pretty_print_sections`.
    pub fn pretty_print_sections(&self) -> Vec<(String, String)> {
        let s = &self.signature;
        let trust_status = if s.trusted() {
            "trusted"
        } else if s.revoked() {
            "revoked"
        } else {
            "untrusted"
        };
        let (subject, sha1, sha256) = match &s.signing_cert {
            Some(c) => (
                human_friendly(c),
                hex(&DigestAlgorithm::Sha1.digest(c.der())),
                hex(&c.sha256()),
            ),
            None => (String::new(), String::new(), String::new()),
        };
        let about_signer = format!(
            "Certificate subject: \"{subject}\"\n\
             Certificate SHA1 fingerprint: {sha1}\n\
             Certificate SHA256 fingerprint: {sha256}\n\
             Trust anchor: \"{}\"\n\
             The signer's certificate is {trust_status}.",
            s.trust_anchor_description()
        );
        let validity_info = format!(
            "The signature is cryptographically {}sound.\n\n\
             The digest algorithm used was '{}'.\n\
             The signature mechanism used was '{}'.",
            if s.intact && s.valid { "" } else { "un" },
            s.md_algorithm_name,
            s.pkcs7_signature_mechanism
        );
        let mut timing = Vec::new();
        if let Some(t) = self.signer_reported_dt {
            timing.push(format!(
                "Signing time as reported by signer: {}",
                isoformat(t)
            ));
        }
        if let Some(ts) = &self.timestamp_validity {
            timing.push(describe_tst(ts, "Signature"));
        }
        if let Some(ts) = &self.content_timestamp_validity {
            timing.push(describe_tst(ts, "Content"));
        }
        let timing_info = if timing.is_empty() {
            "No available information about the signing time.".to_owned()
        } else {
            timing.join("\n\n")
        };
        vec![
            ("Signer info".to_owned(), about_signer),
            ("Integrity".to_owned(), validity_info),
            ("Signing time".to_owned(), timing_info),
        ]
    }

    /// `pretty_print_details` (`format_pretty_print_details`).
    pub fn pretty_print_details(&self) -> String {
        let mut sections = self.pretty_print_sections();
        sections.push((
            "Bottom line".to_owned(),
            format!(
                "The signature is judged {}VALID.",
                if self.bottom_line() { "" } else { "IN" }
            ),
        ));
        sections
            .iter()
            .map(|(hdr, body)| format!("{hdr}\n{}\n{body}\n\n", "-".repeat(hdr.chars().count())))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn describe_tst(ts: &TimestampSignatureStatus, nature: &str) -> String {
    format!(
        "{nature} timestamp token: {}\n\
         The token is guaranteed to be newer than the signature.\n{}",
        isoformat(ts.timestamp),
        ts.describe_timestamp_trust()
    )
}

/// Python `datetime.isoformat()` of an aware UTC datetime.
pub fn isoformat(m: Moment) -> String {
    let s = m.to_string();
    match s.strip_suffix('Z') {
        Some(base) => format!("{base}+00:00"),
        None => s,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
