// Derived from pyHanko `sign/general.py` and `sign/validation/errors.py`
// (MIT, see LICENSE-pyHanko).

//! Errors of CMS validation.
//!
//! | pyHanko | here |
//! | --- | --- |
//! | `SignatureValidationError` | [`CmsError::SignatureValidation`] |
//! | `DisallowedAlgorithmError` | [`CmsError::SignatureValidation`] with a `CRYPTO_CONSTRAINTS_FAILURE*` sub-indication |
//! | `CMSExtractionError` | [`CmsError::Extraction`] |
//! | `CMSStructuralError` | [`CmsError::Structural`] |
//! | `ValueError` from ASN.1 parsing | [`CmsError::Malformed`] |

use sigis_pki_core::errors::HankoError;

use sigis_pki_core::ades::{AdesFailure, AdesIndeterminate, AdesSubIndic};

/// Failure of CMS processing.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CmsError {
    /// The signature could not be validated (`SignatureValidationError`).
    #[error("{}", format_sve(.message, .ades_subindication))]
    SignatureValidation {
        /// Failure message (`failure_message`).
        message: String,
        /// Sub-indication; `None` stands for the default `GENERIC`.
        ades_subindication: Option<AdesSubIndic>,
    },
    /// Information could not be extracted (`CMSExtractionError`).
    #[error("{0}")]
    Extraction(String),
    /// Structural error in a CMS object (`CMSStructuralError`).
    #[error("{0}")]
    Structural(String),
    /// The input could not be decoded.
    #[error("malformed CMS input: {0}")]
    Malformed(String),
}

fn format_sve(message: &str, sub: &Option<AdesSubIndic>) -> String {
    match sub {
        Some(s) => format!("{message} [{s}]"),
        None => message.to_owned(),
    }
}

impl CmsError {
    /// `SignatureValidationError(message, ades_subindication=sub)`.
    pub fn validation(message: impl Into<String>, sub: AdesSubIndic) -> Self {
        Self::SignatureValidation {
            message: message.into(),
            ades_subindication: Some(sub),
        }
    }

    /// `SignatureValidationError(message)` (sub-indication `GENERIC`).
    pub fn validation_generic(message: impl Into<String>) -> Self {
        Self::SignatureValidation {
            message: message.into(),
            ades_subindication: None,
        }
    }

    /// The pyHanko class name of this error.
    pub fn class_name(&self) -> &'static str {
        match self {
            Self::SignatureValidation {
                ades_subindication:
                    Some(
                        AdesSubIndic::Indeterminate(AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE)
                        | AdesSubIndic::Indeterminate(
                            AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
                        ),
                    ),
                ..
            } => "DisallowedAlgorithmError",
            Self::SignatureValidation { .. } => "SignatureValidationError",
            Self::Extraction(_) => "CMSExtractionError",
            Self::Structural(_) => "CMSStructuralError",
            Self::Malformed(_) => "ValueError",
        }
    }

    /// The effective AdES sub-indication (`ades_subindication`); `GENERIC`
    /// for errors without one.
    pub fn ades_subindication(&self) -> AdesSubIndic {
        match self {
            Self::SignatureValidation {
                ades_subindication: Some(s),
                ..
            } => *s,
            Self::Malformed(_) | Self::Structural(_) => {
                AdesSubIndic::Failure(AdesFailure::FORMAT_FAILURE)
            }
            _ => AdesSubIndic::Indeterminate(AdesIndeterminate::GENERIC),
        }
    }

    /// The failure message without the sub-indication suffix.
    pub fn failure_message(&self) -> &str {
        match self {
            Self::SignatureValidation { message, .. } => message,
            Self::Extraction(m) | Self::Structural(m) | Self::Malformed(m) => m,
        }
    }
}

impl From<CmsError> for HankoError {
    /// Signature validation failures map to
    /// [`HankoError::SignatureValidation`] with the effective sub-indication;
    /// extraction and structural errors (`ValueError` subclasses in pyHanko)
    /// map to [`HankoError::Malformed`].
    fn from(e: CmsError) -> Self {
        match e {
            CmsError::SignatureValidation { .. } => HankoError::SignatureValidation {
                ades_subindication: Some(e.ades_subindication()),
                message: e.failure_message().to_owned(),
            },
            other => HankoError::Malformed(other.to_string()),
        }
    }
}

impl From<der::Error> for CmsError {
    fn from(e: der::Error) -> Self {
        Self::Malformed(e.to_string())
    }
}

impl From<sigis_pki_core::asn1::tlv::TlvError> for CmsError {
    fn from(e: sigis_pki_core::asn1::tlv::TlvError) -> Self {
        Self::Malformed(e.to_string())
    }
}

/// Result type of this crate's detailed API.
pub type CmsResult<T> = Result<T, CmsError>;
