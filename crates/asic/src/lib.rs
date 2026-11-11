//! ASiC (ETSI EN 319 162): ZIP containers with CAdES or XAdES signatures and
//! timestamps (layer L2, `docs/crates.md`). Interface skeleton; plan in
//! `docs/xml-lanes.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use sigis_ades_model::{AdesStatus, AdesSubIndic};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::errors::{not_implemented, Result};

/// Container type (EN 319 162-1 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AsicType {
    /// ASiC-S (one signed object).
    Simple,
    /// ASiC-E (extended, several objects).
    Extended,
}

/// Format-specific result of a signature in the container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsicSignatureDetails {
    /// A CAdES signature (`META-INF/signature*.p7s`).
    Cades(sigis_cades::CadesResult),
    /// A XAdES signature (`META-INF/signatures*.xml`).
    Xades(sigis_xades::XadesResult),
}

/// Result for one signature (or timestamp) in the container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsicSignatureResult {
    /// Container entry holding the signature.
    pub entry: String,
    /// Signed container entries.
    pub signed_entries: Vec<String>,
    /// Main indication.
    pub status: AdesStatus,
    /// Sub-indication when not passed.
    pub sub_indication: Option<AdesSubIndic>,
    /// Format-specific details.
    pub details: Option<AsicSignatureDetails>,
}

/// Validate all signatures in an ASiC container.
pub fn verify_asic(
    _zip: &[u8],
    _ctx: &ValidationContext,
) -> Result<(AsicType, Vec<AsicSignatureResult>)> {
    not_implemented("sigis_asic::verify_asic")
}
