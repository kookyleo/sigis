// Derived from pyHanko `sign/validation/errors.py` (MIT, see LICENSE-pyHanko).

//! Validation errors (`pyhanko.sign.validation.errors`).

use sigis_pki_core::time::Moment;

use sigis_pki_core::ades::{AdesIndeterminate, AdesStatus, AdesSubIndic};

/// Error validating a signature (`SignatureValidationError`).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.display())]
pub struct SignatureValidationError {
    /// Failure message without the sub-indication suffix.
    pub failure_message: String,
    /// AdES sub-indication (`GENERIC` if none was given).
    pub ades_subindication: AdesSubIndic,
    explicit: bool,
    /// Kind of error (subclass in pyHanko).
    pub kind: SignatureValidationErrorKind,
}

/// Subclass of [`SignatureValidationError`] in pyHanko.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureValidationErrorKind {
    /// Plain `SignatureValidationError`.
    Generic,
    /// `DisallowedAlgorithmError`.
    DisallowedAlgorithm {
        /// Time horizon of the algorithm ban, if any.
        time_horizon: Option<Moment>,
    },
    /// `SigSeedValueValidationError`.
    SeedValue,
    /// `TSTDigestNotAvailableError`.
    TstDigestNotAvailable,
}

impl SignatureValidationError {
    /// New error with an optional sub-indication.
    pub fn new(failure_message: impl Into<String>, subindic: Option<AdesSubIndic>) -> Self {
        Self {
            failure_message: failure_message.into(),
            ades_subindication: subindic.unwrap_or(AdesIndeterminate::GENERIC.into()),
            explicit: subindic.is_some(),
            kind: SignatureValidationErrorKind::Generic,
        }
    }

    /// New error with a sub-indication.
    pub fn with(failure_message: impl Into<String>, subindic: impl Into<AdesSubIndic>) -> Self {
        Self::new(failure_message, Some(subindic.into()))
    }

    /// `DisallowedAlgorithmError`.
    pub fn disallowed_algorithm(
        failure_message: impl Into<String>,
        time_horizon: Option<Moment>,
    ) -> Self {
        let sub = if time_horizon.is_none() {
            AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE
        } else {
            AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE
        };
        Self {
            kind: SignatureValidationErrorKind::DisallowedAlgorithm { time_horizon },
            ..Self::with(failure_message, sub)
        }
    }

    /// Set the subclass.
    pub fn with_kind(mut self, kind: SignatureValidationErrorKind) -> Self {
        self.kind = kind;
        self
    }

    /// Main AdES indication.
    pub fn ades_status(&self) -> AdesStatus {
        self.ades_subindication.status()
    }

    fn display(&self) -> String {
        if self.explicit {
            format!("{} [{}]", self.failure_message, self.ades_subindication)
        } else {
            self.failure_message.clone()
        }
    }
}

/// Error reading validation information (`ValidationInfoReadingError`).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ValidationInfoReadingError(pub String);

impl ValidationInfoReadingError {
    /// `NoDSSFoundError`.
    pub fn no_dss() -> Self {
        Self("No DSS found".to_owned())
    }
}

/// Error related to CMS algorithm protection checks
/// (`CMSAlgorithmProtectionError`).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CmsAlgorithmProtectionError(pub String);
