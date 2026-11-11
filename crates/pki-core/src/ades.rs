// Derived from pyHanko `sign/ades/report.py` (MIT, see LICENSE-pyHanko).

//! AdES indications (ETSI EN 319 102-1, clause 5.1.3)
//! (`pyhanko.sign.ades.report`).
//!
//! The enums live in `sigis-pki-core` because validation errors of several crates
//! carry a sub-indication ([`crate::HankoError::SignatureValidation`]);
//! `sigis_pades::report` and `sigis-pades` re-export them. Owned by lane E.

use std::fmt;

/// Main indication (`AdESStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdesStatus {
    /// `TOTAL-PASSED` / `PASSED`.
    Passed,
    /// `INDETERMINATE`.
    Indeterminate,
    /// `TOTAL-FAILED` / `FAILED`.
    Failed,
}

impl AdesStatus {
    /// The enum member name used by pyHanko (`PASSED`, ...).
    pub fn name(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Indeterminate => "INDETERMINATE",
            Self::Failed => "FAILED",
        }
    }
}

macro_rules! subindic {
    ($(#[$m:meta])* $name:ident, $status:expr, { $($(#[$vm:meta])* $v:ident),* $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[allow(non_camel_case_types)]
        pub enum $name {
            $($(#[$vm])* $v,)*
        }

        impl $name {
            /// All members.
            pub const ALL: &'static [Self] = &[$(Self::$v),*];

            /// The name of the sub-indication in EN 319 102-1.
            pub fn standard_name(self) -> &'static str {
                match self { $(Self::$v => stringify!($v),)* }
            }

            /// The main indication this sub-indication belongs to.
            pub fn status(self) -> AdesStatus {
                $status
            }
        }
    };
}

subindic!(
    /// Sub-indication of a passed validation (`AdESPassed`).
    AdesPassed, AdesStatus::Passed, {
        /// `OK`.
        OK,
    }
);

subindic!(
    /// Sub-indications of `FAILED` (`AdESFailure`).
    AdesFailure, AdesStatus::Failed, {
        /// `FORMAT_FAILURE`.
        FORMAT_FAILURE,
        /// `HASH_FAILURE`.
        HASH_FAILURE,
        /// `SIG_CRYPTO_FAILURE`.
        SIG_CRYPTO_FAILURE,
        /// `REVOKED`.
        REVOKED,
        /// `NOT_YET_VALID`.
        NOT_YET_VALID,
    }
);

subindic!(
    /// Sub-indications of `INDETERMINATE` (`AdESIndeterminate`).
    AdesIndeterminate, AdesStatus::Indeterminate, {
        /// `SIG_CONSTRAINTS_FAILURE`.
        SIG_CONSTRAINTS_FAILURE,
        /// `CHAIN_CONSTRAINTS_FAILURE`.
        CHAIN_CONSTRAINTS_FAILURE,
        /// `CERTIFICATE_CHAIN_GENERAL_FAILURE`.
        CERTIFICATE_CHAIN_GENERAL_FAILURE,
        /// `CRYPTO_CONSTRAINTS_FAILURE`.
        CRYPTO_CONSTRAINTS_FAILURE,
        /// `EXPIRED`.
        EXPIRED,
        /// `NOT_YET_VALID`.
        NOT_YET_VALID,
        /// `POLICY_PROCESSING_ERROR`.
        POLICY_PROCESSING_ERROR,
        /// `SIGNATURE_POLICY_NOT_AVAILABLE`.
        SIGNATURE_POLICY_NOT_AVAILABLE,
        /// `TIMESTAMP_ORDER_FAILURE`.
        TIMESTAMP_ORDER_FAILURE,
        /// `NO_SIGNING_CERTIFICATE_FOUND`.
        NO_SIGNING_CERTIFICATE_FOUND,
        /// `NO_CERTIFICATE_CHAIN_FOUND`.
        NO_CERTIFICATE_CHAIN_FOUND,
        /// `REVOKED_NO_POE`.
        REVOKED_NO_POE,
        /// `REVOKED_CA_NO_POE`.
        REVOKED_CA_NO_POE,
        /// `OUT_OF_BOUNDS_NO_POE`.
        OUT_OF_BOUNDS_NO_POE,
        /// `REVOCATION_OUT_OF_BOUNDS_NO_POE`.
        REVOCATION_OUT_OF_BOUNDS_NO_POE,
        /// `OUT_OF_BOUNDS_NOT_REVOKED`.
        OUT_OF_BOUNDS_NOT_REVOKED,
        /// `CRYPTO_CONSTRAINTS_FAILURE_NO_POE`.
        CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
        /// `NO_POE`.
        NO_POE,
        /// `TRY_LATER`.
        TRY_LATER,
        /// `SIGNED_DATA_NOT_FOUND`.
        SIGNED_DATA_NOT_FOUND,
        /// `GENERIC`.
        GENERIC,
    }
);

/// Any AdES sub-indication (`AdESSubIndic`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AdesSubIndic {
    /// Passed.
    Passed(AdesPassed),
    /// Failed.
    Failure(AdesFailure),
    /// Indeterminate.
    Indeterminate(AdesIndeterminate),
}

impl AdesSubIndic {
    /// Main indication.
    pub fn status(self) -> AdesStatus {
        match self {
            Self::Passed(p) => p.status(),
            Self::Failure(f) => f.status(),
            Self::Indeterminate(i) => i.status(),
        }
    }

    /// Standard name (`FORMAT_FAILURE`, ...).
    pub fn standard_name(self) -> &'static str {
        match self {
            Self::Passed(p) => p.standard_name(),
            Self::Failure(f) => f.standard_name(),
            Self::Indeterminate(i) => i.standard_name(),
        }
    }
}

impl fmt::Display for AdesSubIndic {
    /// Formats as Python's enum `str()` (`AdESFailure.FORMAT_FAILURE`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self {
            Self::Passed(_) => "AdESPassed",
            Self::Failure(_) => "AdESFailure",
            Self::Indeterminate(_) => "AdESIndeterminate",
        };
        write!(f, "{class}.{}", self.standard_name())
    }
}

impl From<AdesPassed> for AdesSubIndic {
    fn from(v: AdesPassed) -> Self {
        Self::Passed(v)
    }
}

impl From<AdesFailure> for AdesSubIndic {
    fn from(v: AdesFailure) -> Self {
        Self::Failure(v)
    }
}

impl From<AdesIndeterminate> for AdesSubIndic {
    fn from(v: AdesIndeterminate) -> Self {
        Self::Indeterminate(v)
    }
}
