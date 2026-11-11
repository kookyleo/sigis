//! XAdES (ETSI EN 319 132): XML advanced electronic signatures on top of
//! `sigis-xmldsig` (layer L2, `docs/crates.md`): signed properties, signing
//! certificate binding, timestamps, B/T/LT/LTA levels, results in
//! [`sigis_ades_model`] terms. Interface skeleton; plan in
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
use sigis_xmldsig::XmlDsigPolicy;

/// XAdES baseline level (EN 319 132-1 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XadesLevel {
    /// XAdES-B-B.
    BB,
    /// XAdES-B-T.
    BT,
    /// XAdES-B-LT.
    BLT,
    /// XAdES-B-LTA.
    BLTA,
}

/// Result of validating one XAdES signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XadesResult {
    /// `Id` of the signature element.
    pub signature_id: Option<String>,
    /// Main indication.
    pub status: AdesStatus,
    /// Sub-indication when not passed.
    pub sub_indication: Option<AdesSubIndic>,
    /// Highest level the signature satisfies.
    pub level: Option<XadesLevel>,
}

/// Validate every XAdES signature in `xml`.
pub fn verify_xades(
    _xml: &[u8],
    _policy: &XmlDsigPolicy,
    _ctx: &ValidationContext,
) -> Result<Vec<XadesResult>> {
    not_implemented("sigis_xades::verify_xades")
}
