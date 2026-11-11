// Interfaces derived from pyHanko `sign/validation/qualified/` (MIT, see
// LICENSE-pyHanko).

//! EU trusted lists (ETSI TS 119 612) and qualified status of signatures and
//! timestamps (`pyhanko.sign.validation.qualified`).
//!
//! Owned by lane E (see `docs/hanko-lanes.md`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use hanko_core::cert::Cert;
use hanko_core::errors::{not_implemented, Result};
use hanko_core::time::Moment;

/// A parsed and signature-checked trusted list (`TrustedServiceProvider` set).
#[derive(Clone, Debug, Default)]
pub struct TrustedList {
    /// Service certificates with their qualification data.
    pub services: Vec<TrustService>,
}

/// One trust service entry.
#[derive(Clone, Debug)]
pub struct TrustService {
    /// Service digital identity.
    pub certs: Vec<Cert>,
    /// Service type URI.
    pub service_type: String,
}

/// Qualification of a certificate at a moment (`QualificationResult`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualificationResult {
    /// The certificate is qualified.
    pub qualified: bool,
    /// The key resides in a QSCD.
    pub qscd: Option<bool>,
}

/// Parse a trusted list and verify its XAdES signature against `signers`.
pub fn parse_trusted_list(_xml: &[u8], _signers: &[Cert]) -> Result<TrustedList> {
    not_implemented("hanko_eutl::parse_trusted_list")
}

/// Determine the qualified status of `cert` at `at`.
pub fn qualification(_tl: &TrustedList, _cert: &Cert, _at: Moment) -> Result<QualificationResult> {
    not_implemented("hanko_eutl::qualification")
}
