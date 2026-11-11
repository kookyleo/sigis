// Derived from pyHanko `sign/validation/qualified/q_status.py` (MIT, see LICENSE-pyHanko).

//! Qualified status of certificates (`pyhanko.sign.validation.qualified.q_status`).

use crate::tsp::{QcCertType, QualifiedServiceInformation};

/// Private key management methodology (`QcPrivateKeyManagementType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QcPrivateKeyManagementType {
    /// Unknown or unspecified.
    Unknown,
    /// The key resides in a QSCD.
    Qscd,
    /// The key resides in a QSCD managed on behalf of the subject.
    QscdDelegated,
    /// QSCD declared by pre-eIDAS certificate policy.
    QscdByPolicy,
}

impl QcPrivateKeyManagementType {
    /// `true` unless unknown (`is_qscd`).
    pub fn is_qscd(self) -> bool {
        self != Self::Unknown
    }

    /// pyHanko enum member name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Qscd => "QSCD",
            Self::QscdDelegated => "QSCD_DELEGATED",
            Self::QscdByPolicy => "QSCD_BY_POLICY",
        }
    }
}

/// Qualified status of a certificate (`QualifiedStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QualifiedStatus {
    /// The certificate is qualified.
    pub qualified: bool,
    /// Type of qualified certificate.
    pub qc_type: QcCertType,
    /// Key management declaration.
    pub qc_key_security: QcPrivateKeyManagementType,
}

/// Result of a qualification evaluation (`QualificationResult`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualificationResult {
    /// Status.
    pub status: QualifiedStatus,
    /// The service definition under which the certificate was considered
    /// qualified.
    pub service_definition: Option<QualifiedServiceInformation>,
}
