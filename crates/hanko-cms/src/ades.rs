// Derived from pyHanko `sign/ades/report.py` (MIT, see LICENSE-pyHanko).

//! AdES main and sub-indications (ETSI EN 319 102-1, §5.1.3).
//!
//! CMS validation reports trust problems as AdES sub-indications, as pyHanko
//! does (`trust_problem_indic`). The names are the ones pyHanko and the ETSI
//! standard use, so lane E can map them to its report types.

use core::fmt;

/// AdES main indication (`AdESStatus`).
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
    /// The pyHanko enum member name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Indeterminate => "INDETERMINATE",
            Self::Failed => "FAILED",
        }
    }
}

macro_rules! subindications {
    ($( $(#[$m:meta])* $variant:ident => $name:literal, $status:ident; )*) => {
        /// AdES sub-indication (`AdESPassed`, `AdESFailure` and
        /// `AdESIndeterminate` in pyHanko, flattened into one type).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum AdesSubIndication {
            $( $(#[$m])* $variant, )*
        }

        impl AdesSubIndication {
            /// Every sub-indication.
            pub const ALL: &'static [AdesSubIndication] = &[$(Self::$variant,)*];

            /// The ETSI / pyHanko member name, e.g. `NO_SIGNING_CERTIFICATE_FOUND`.
            pub fn name(self) -> &'static str {
                match self { $(Self::$variant => $name,)* }
            }

            /// The main indication this sub-indication belongs to.
            pub fn status(self) -> AdesStatus {
                match self { $(Self::$variant => AdesStatus::$status,)* }
            }

            /// Look up a sub-indication by name. `NOT_YET_VALID` exists both
            /// as a failure and as an indeterminate sub-indication; `status`
            /// disambiguates.
            pub fn from_name(status: AdesStatus, name: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|s| s.status() == status && s.name() == name)
            }
        }
    };
}

subindications! {
    /// `AdESPassed.OK`.
    Ok => "OK", Passed;
    /// `AdESFailure.FORMAT_FAILURE`.
    FormatFailure => "FORMAT_FAILURE", Failed;
    /// `AdESFailure.HASH_FAILURE`.
    HashFailure => "HASH_FAILURE", Failed;
    /// `AdESFailure.SIG_CRYPTO_FAILURE`.
    SigCryptoFailure => "SIG_CRYPTO_FAILURE", Failed;
    /// `AdESFailure.REVOKED`.
    Revoked => "REVOKED", Failed;
    /// `AdESFailure.NOT_YET_VALID`.
    FailedNotYetValid => "NOT_YET_VALID", Failed;
    /// `AdESIndeterminate.SIG_CONSTRAINTS_FAILURE`.
    SigConstraintsFailure => "SIG_CONSTRAINTS_FAILURE", Indeterminate;
    /// `AdESIndeterminate.CHAIN_CONSTRAINTS_FAILURE`.
    ChainConstraintsFailure => "CHAIN_CONSTRAINTS_FAILURE", Indeterminate;
    /// `AdESIndeterminate.CERTIFICATE_CHAIN_GENERAL_FAILURE`.
    CertificateChainGeneralFailure => "CERTIFICATE_CHAIN_GENERAL_FAILURE", Indeterminate;
    /// `AdESIndeterminate.CRYPTO_CONSTRAINTS_FAILURE`.
    CryptoConstraintsFailure => "CRYPTO_CONSTRAINTS_FAILURE", Indeterminate;
    /// `AdESIndeterminate.EXPIRED`.
    Expired => "EXPIRED", Indeterminate;
    /// `AdESIndeterminate.NOT_YET_VALID`.
    NotYetValid => "NOT_YET_VALID", Indeterminate;
    /// `AdESIndeterminate.POLICY_PROCESSING_ERROR`.
    PolicyProcessingError => "POLICY_PROCESSING_ERROR", Indeterminate;
    /// `AdESIndeterminate.SIGNATURE_POLICY_NOT_AVAILABLE`.
    SignaturePolicyNotAvailable => "SIGNATURE_POLICY_NOT_AVAILABLE", Indeterminate;
    /// `AdESIndeterminate.TIMESTAMP_ORDER_FAILURE`.
    TimestampOrderFailure => "TIMESTAMP_ORDER_FAILURE", Indeterminate;
    /// `AdESIndeterminate.NO_SIGNING_CERTIFICATE_FOUND`.
    NoSigningCertificateFound => "NO_SIGNING_CERTIFICATE_FOUND", Indeterminate;
    /// `AdESIndeterminate.NO_CERTIFICATE_CHAIN_FOUND`.
    NoCertificateChainFound => "NO_CERTIFICATE_CHAIN_FOUND", Indeterminate;
    /// `AdESIndeterminate.REVOKED_NO_POE`.
    RevokedNoPoe => "REVOKED_NO_POE", Indeterminate;
    /// `AdESIndeterminate.REVOKED_CA_NO_POE`.
    RevokedCaNoPoe => "REVOKED_CA_NO_POE", Indeterminate;
    /// `AdESIndeterminate.OUT_OF_BOUNDS_NO_POE`.
    OutOfBoundsNoPoe => "OUT_OF_BOUNDS_NO_POE", Indeterminate;
    /// `AdESIndeterminate.REVOCATION_OUT_OF_BOUNDS_NO_POE`.
    RevocationOutOfBoundsNoPoe => "REVOCATION_OUT_OF_BOUNDS_NO_POE", Indeterminate;
    /// `AdESIndeterminate.OUT_OF_BOUNDS_NOT_REVOKED`.
    OutOfBoundsNotRevoked => "OUT_OF_BOUNDS_NOT_REVOKED", Indeterminate;
    /// `AdESIndeterminate.CRYPTO_CONSTRAINTS_FAILURE_NO_POE`.
    CryptoConstraintsFailureNoPoe => "CRYPTO_CONSTRAINTS_FAILURE_NO_POE", Indeterminate;
    /// `AdESIndeterminate.NO_POE`.
    NoPoe => "NO_POE", Indeterminate;
    /// `AdESIndeterminate.TRY_LATER`.
    TryLater => "TRY_LATER", Indeterminate;
    /// `AdESIndeterminate.SIGNED_DATA_NOT_FOUND`.
    SignedDataNotFound => "SIGNED_DATA_NOT_FOUND", Indeterminate;
    /// `AdESIndeterminate.GENERIC`.
    Generic => "GENERIC", Indeterminate;
}

impl fmt::Display for AdesSubIndication {
    /// Formats as Python's `str()` of the enum member, e.g.
    /// `AdESIndeterminate.GENERIC`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self.status() {
            AdesStatus::Passed => "AdESPassed",
            AdesStatus::Indeterminate => "AdESIndeterminate",
            AdesStatus::Failed => "AdESFailure",
        };
        write!(f, "{class}.{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for s in AdesSubIndication::ALL {
            assert_eq!(AdesSubIndication::from_name(s.status(), s.name()), Some(*s));
        }
        assert_eq!(
            AdesSubIndication::NoSigningCertificateFound.to_string(),
            "AdESIndeterminate.NO_SIGNING_CERTIFICATE_FOUND"
        );
        assert_eq!(
            AdesSubIndication::FailedNotYetValid.to_string(),
            "AdESFailure.NOT_YET_VALID"
        );
    }
}
