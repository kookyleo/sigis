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

/// Failure of a network retrieval (OCSP, CRL, certificate, timestamp).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind:?}: {message}")]
pub struct FetchError {
    /// What went wrong.
    pub kind: FetchErrorKind,
    /// Description, including the URL if any.
    pub message: String,
}

/// Category of a [`FetchError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FetchErrorKind {
    /// Fetching is disabled or no fetcher is configured.
    Disabled,
    /// Connection or protocol failure.
    Network,
    /// The request exceeded its time budget.
    Timeout,
    /// The response exceeded the configured size limit.
    TooLarge,
    /// The response could not be used (bad status, content type, encoding).
    BadResponse,
    /// The certificate declares no location to fetch from.
    NotFound,
}

impl FetchError {
    /// Build an error.
    pub fn new(kind: FetchErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Fetching is disabled.
    pub fn disabled(what: &str) -> Self {
        Self::new(
            FetchErrorKind::Disabled,
            format!("fetching is disabled: {what}"),
        )
    }
}

/// Top-level error of the sigis-hanko crates.
///
/// Lanes add variants through the lead (see `docs/hanko-lanes.md`); match on
/// it with a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HankoError {
    /// The functionality exists in the API but is not ported yet.
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
    /// Input could not be decoded or is structurally invalid.
    #[error("malformed input: {0}")]
    Malformed(String),
    /// The operation is not supported (algorithm, PDF feature, ...).
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Certificate or path validation failed.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// A cryptographic signature could not be verified or produced.
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// A network retrieval failed.
    #[error(transparent)]
    Fetch(#[from] FetchError),
    /// A signature failed validation (`SignatureValidationError` in pyHanko),
    /// with the AdES sub-indication when one is known.
    #[error("{message}")]
    SignatureValidation {
        /// Failure description.
        message: String,
        /// AdES sub-indication (EN 319 102-1 §5.1.3).
        ades_subindication: Option<crate::ades::AdesSubIndic>,
    },
    /// Signing failed (key provider, timestamping, embedding).
    #[error("signing failed: {0}")]
    Signing(String),
    /// I/O failure.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<der::Error> for HankoError {
    fn from(e: der::Error) -> Self {
        Self::Malformed(e.to_string())
    }
}

impl From<std::io::Error> for HankoError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Result type of the sigis-hanko crates.
pub type Result<T, E = HankoError> = core::result::Result<T, E>;

/// Return [`HankoError::NotImplemented`]; used by interface stubs.
pub fn not_implemented<T>(what: &'static str) -> Result<T> {
    Err(HankoError::NotImplemented(what))
}
