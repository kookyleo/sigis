//! CAdES (ETSI EN 319 122): CMS advanced electronic signatures outside PDF,
//! for detached files and ASiC containers (layer L2, `docs/crates.md`).
//!
//! Builds on `sigis-cms` (CMS validation, ported from pyHanko's
//! `generic_cms`) and the signing code of `sigis-pades-sign`; adds the
//! CAdES baseline levels B/T/LT/LTA for non-PDF content and reports in the
//! shared [`sigis_ades_model`] terms. Interface skeleton.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use sigis_ades_model::{AdesStatus, AdesSubIndic};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::errors::{not_implemented, Result};

/// CAdES baseline level (EN 319 122-1 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CadesLevel {
    /// CAdES-B-B.
    BB,
    /// CAdES-B-T.
    BT,
    /// CAdES-B-LT.
    BLT,
    /// CAdES-B-LTA.
    BLTA,
}

/// Result of validating one CAdES signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CadesResult {
    /// Main indication.
    pub status: AdesStatus,
    /// Sub-indication when not passed.
    pub sub_indication: Option<AdesSubIndic>,
    /// Highest level the signature satisfies.
    pub level: Option<CadesLevel>,
}

/// Validate a CAdES signature (DER `ContentInfo`) over detached `content`
/// (`None` for enveloping signatures).
pub fn verify_cades(
    _signature: &[u8],
    _content: Option<&[u8]>,
    _ctx: &ValidationContext,
) -> Result<CadesResult> {
    not_implemented("sigis_cades::verify_cades")
}
