// Derived from pyhanko-certvalidator `errors.py` (MIT, see LICENSE-pyHanko).

//! Error types.
//!
//! The variants mirror the exception hierarchy of pyhanko-certvalidator so that
//! ported tests can assert on the same error classes:
//!
//! | pyhanko-certvalidator        | `sigis-hanko`                              |
//! |------------------------------|--------------------------------------------|
//! | `PathBuildingError`          | [`ValidationError::PathBuilding`]          |
//! | `PathValidationError`        | [`ValidationError::PathValidation`]        |
//! | `ExpiredError`               | [`ValidationError::Expired`]               |
//! | `NotYetValidError`           | [`ValidationError::NotYetValid`]           |
//! | `RevokedError`               | [`ValidationError::Revoked`]               |
//! | `InsufficientRevinfoError`   | [`ValidationError::InsufficientRevinfo`]   |
//! | `StaleRevinfoError`          | [`ValidationError::StaleRevinfo`]          |
//! | `DisallowedAlgorithmError`   | [`ValidationError::DisallowedAlgorithm`]   |
//! | `InvalidSignature` and subclasses | [`SignatureError`]                    |

use crate::time::Moment;

/// Failure to verify a cryptographic signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The signature does not verify under the given key.
    #[error("signature is invalid")]
    InvalidSignature,
    /// The signature or digest algorithm is not supported.
    #[error("algorithm not supported: {0}")]
    AlgorithmNotSupported(String),
    /// The PSS parameters of an `id-RSASSA-PSS` key do not match those of the signature.
    #[error("public key PSS parameters do not match those on the signature")]
    PssParameterMismatch,
    /// A DSA key without domain parameters (parameter inheritance is not supported).
    #[error("DSA public key parameters were not provided")]
    DsaParametersUnavailable,
    /// The key type does not fit the signature algorithm.
    #[error("public key type does not match the signature algorithm: {0}")]
    KeyMismatch(String),
    /// The public key, signature value or algorithm parameters are malformed.
    #[error("malformed input: {0}")]
    Malformed(String),
}

/// Failure to validate a certificate, its path, or its revocation status.
///
/// `RevokedError`, `InsufficientRevinfoError` and `StaleRevinfoError` are
/// subclasses of `PathValidationError` in Python; use
/// [`ValidationError::is_path_validation_error`] for the same `isinstance` test.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// No path from the certificate to a trust anchor could be built.
    #[error("{0}")]
    PathBuilding(String),
    /// The path failed RFC 5280 validation for a reason not covered below.
    #[error("{0}")]
    PathValidation(String),
    /// A certificate in the path had expired at the validation time.
    #[error("{msg}")]
    Expired {
        /// Description.
        msg: String,
    },
    /// A certificate in the path was not yet valid at the validation time.
    #[error("{msg}")]
    NotYetValid {
        /// Description.
        msg: String,
    },
    /// A certificate in the path was revoked at or before the validation time.
    #[error("{msg}")]
    Revoked {
        /// Description.
        msg: String,
        /// Revocation time, if known.
        revocation_time: Option<Moment>,
        /// RFC 5280 reason code name, if present.
        reason: Option<&'static str>,
    },
    /// Revocation information was required but missing or unusable.
    #[error("{0}")]
    InsufficientRevinfo(String),
    /// Revocation information was found but is not fresh enough.
    #[error("{msg}")]
    StaleRevinfo {
        /// Description.
        msg: String,
        /// Last moment at which the revocation information was usable, if known.
        time_cutoff: Option<Moment>,
    },
    /// An algorithm was used that the algorithm usage policy forbids.
    #[error("{0}")]
    DisallowedAlgorithm(String),
    /// Input could not be decoded.
    #[error("malformed input: {0}")]
    Malformed(String),
}

impl ValidationError {
    /// `true` for every error that pyhanko-certvalidator models as a
    /// `PathValidationError` subclass.
    pub fn is_path_validation_error(&self) -> bool {
        !matches!(self, Self::PathBuilding(_) | Self::Malformed(_))
    }

    /// `true` for `InsufficientRevinfo` and its subclass `StaleRevinfo`.
    pub fn is_insufficient_revinfo(&self) -> bool {
        matches!(
            self,
            Self::InsufficientRevinfo(_) | Self::StaleRevinfo { .. }
        )
    }

    /// The pyhanko-certvalidator class name of this error.
    pub fn class_name(&self) -> &'static str {
        match self {
            Self::PathBuilding(_) => "PathBuildingError",
            Self::PathValidation(_) => "PathValidationError",
            Self::Expired { .. } => "ExpiredError",
            Self::NotYetValid { .. } => "NotYetValidError",
            Self::Revoked { .. } => "RevokedError",
            Self::InsufficientRevinfo(_) => "InsufficientRevinfoError",
            Self::StaleRevinfo { .. } => "StaleRevinfoError",
            Self::DisallowedAlgorithm(_) => "DisallowedAlgorithmError",
            Self::Malformed(_) => "ValueError",
        }
    }

    /// `true` if this error is an instance of the pyhanko-certvalidator class
    /// `name`, taking the Python class hierarchy into account.
    pub fn is_instance_of(&self, name: &str) -> bool {
        match name {
            "PathValidationError" => self.is_path_validation_error(),
            "InsufficientRevinfoError" => self.is_insufficient_revinfo(),
            "PathError" => matches!(self, Self::PathBuilding(_)) || self.is_path_validation_error(),
            other => self.class_name() == other,
        }
    }
}

impl From<der::Error> for ValidationError {
    fn from(e: der::Error) -> Self {
        Self::Malformed(e.to_string())
    }
}
