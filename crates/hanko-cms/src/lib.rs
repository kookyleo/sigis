// Interfaces derived from pyHanko `sign/validation/generic_cms.py` and
// `sign/validation/status.py` (MIT, see LICENSE-pyHanko).

//! CMS `SignedData` and RFC 3161 timestamp validation
//! (`pyhanko.sign.validation.generic_cms`).
//!
//! Owned by lane A (see `docs/hanko-lanes.md`). The status types are consumed
//! by lane E (PDF and AdES validation).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use hanko_certvalidator::{ValidationContext, ValidationPath};
use hanko_core::algorithms::{DigestAlgorithm, SignatureMechanism};
use hanko_core::cert::Cert;
use hanko_core::errors::{not_implemented, Result, ValidationError};
use hanko_core::time::Moment;

/// What the signature covers.
#[derive(Clone, Copy, Debug)]
pub enum SignedContent<'a> {
    /// The signed data itself (detached signatures, PDF ByteRange content).
    Data(&'a [u8]),
    /// A precomputed digest of the signed data, with its algorithm.
    Digest(DigestAlgorithm, &'a [u8]),
    /// The content is encapsulated in the `SignedData`.
    Encapsulated,
}

/// Why trust in the signer could not be established (`trust_problem_indic`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustProblem {
    /// Path building or validation failed.
    Path(ValidationError),
    /// The signer certificate's key usage does not allow signing.
    KeyUsage(String),
}

/// Cryptographic and trust status of one CMS signature (`SignatureStatus`).
#[derive(Clone, Debug)]
pub struct SignatureStatus {
    /// The message digest attribute matches the content.
    pub intact: bool,
    /// The signature over the signed attributes verifies.
    pub valid: bool,
    /// Trust problem, if any; `None` with `validation_path` set means trusted.
    pub trust_problem: Option<TrustProblem>,
    /// The signer certificate.
    pub signing_cert: Option<Cert>,
    /// Signature mechanism used.
    pub signature_mechanism: Option<SignatureMechanism>,
    /// Digest algorithm used.
    pub md_algorithm: Option<DigestAlgorithm>,
    /// The validated certification path, if trust was established.
    pub validation_path: Option<ValidationPath>,
}

impl SignatureStatus {
    /// Intact, valid and trusted (`bottom_line`).
    pub fn bottom_line(&self) -> bool {
        self.intact && self.valid && self.trust_problem.is_none() && self.validation_path.is_some()
    }
}

/// Status of an RFC 3161 timestamp token (`TimestampSignatureStatus`).
#[derive(Clone, Debug)]
pub struct TimestampSignatureStatus {
    /// Status of the token's own CMS signature.
    pub signature: SignatureStatus,
    /// `genTime` from the `TSTInfo`.
    pub timestamp: Moment,
}

/// Status of a CAdES-style CMS signature (`StandardCMSSignatureStatus`).
#[derive(Clone, Debug)]
pub struct StandardCmsSignatureStatus {
    /// Core signature status.
    pub signature: SignatureStatus,
    /// `signingTime` attribute (an unverified claim).
    pub signer_reported_dt: Option<Moment>,
    /// Signature timestamp (`signatureTimeStampToken` unsigned attribute).
    pub timestamp_validity: Option<TimestampSignatureStatus>,
    /// Content timestamp (`contentTimeStamp` signed attribute).
    pub content_timestamp_validity: Option<TimestampSignatureStatus>,
}

/// Validate a CMS `SignedData` (DER `ContentInfo`) over `content`
/// (`async_validate_cms_signature` + timestamp handling).
pub fn validate_cms_signature(
    _signed_data: &[u8],
    _content: SignedContent<'_>,
    _ctx: &ValidationContext,
) -> Result<StandardCmsSignatureStatus> {
    not_implemented("hanko_cms::validate_cms_signature")
}

/// Validate a `TimeStampToken` whose message imprint must equal
/// `expected_imprint` (`validate_tst_signed_data`).
pub fn validate_timestamp_token(
    _token: &[u8],
    _expected_imprint: &[u8],
    _ctx: &ValidationContext,
) -> Result<TimestampSignatureStatus> {
    not_implemented("hanko_cms::validate_timestamp_token")
}

/// Validate a detached CMS signature over `data` (`validate_detached_cms`).
pub fn validate_detached_cms(
    data: &[u8],
    signed_data: &[u8],
    ctx: &ValidationContext,
) -> Result<StandardCmsSignatureStatus> {
    validate_cms_signature(signed_data, SignedContent::Data(data), ctx)
}
