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

use hanko_core::errors::HankoError;

use crate::ades::AdesSubIndication;

/// Failure of CMS processing.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CmsError {
    /// The signature could not be validated (`SignatureValidationError`).
    #[error("{}", format_sve(.message, .ades_subindication))]
    SignatureValidation {
        /// Failure message (`failure_message`).
        message: String,
        /// Sub-indication; `None` stands for the default `GENERIC`.
        ades_subindication: Option<AdesSubIndication>,
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

fn format_sve(message: &str, sub: &Option<AdesSubIndication>) -> String {
    match sub {
        Some(s) => format!("{message} [{s}]"),
        None => message.to_owned(),
    }
}

impl CmsError {
    /// `SignatureValidationError(message, ades_subindication=sub)`.
    pub fn validation(message: impl Into<String>, sub: AdesSubIndication) -> Self {
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
                        AdesSubIndication::CryptoConstraintsFailure
                        | AdesSubIndication::CryptoConstraintsFailureNoPoe,
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
    pub fn ades_subindication(&self) -> AdesSubIndication {
        match self {
            Self::SignatureValidation {
                ades_subindication: Some(s),
                ..
            } => *s,
            Self::Malformed(_) | Self::Structural(_) => AdesSubIndication::FormatFailure,
            _ => AdesSubIndication::Generic,
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
    /// `HankoError` has no variant for signature validation failures yet
    /// (lane A request R2); until it has, they map to `Malformed` with the
    /// full message, which keeps the failure closed.
    fn from(e: CmsError) -> Self {
        HankoError::Malformed(e.to_string())
    }
}

impl From<der::Error> for CmsError {
    fn from(e: der::Error) -> Self {
        Self::Malformed(e.to_string())
    }
}

impl From<hanko_core::asn1::tlv::TlvError> for CmsError {
    fn from(e: hanko_core::asn1::tlv::TlvError) -> Self {
        Self::Malformed(e.to_string())
    }
}

/// Result type of this crate's detailed API.
pub type CmsResult<T> = Result<T, CmsError>;
