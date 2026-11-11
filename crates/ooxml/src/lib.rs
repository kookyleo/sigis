//! OOXML (.docx, .xlsx, .pptx) package digital signatures (ECMA-376 Part 2, §12) (layer L3, `docs/crates.md`).
//!
//! Containers on top of `sigis-xmldsig` / `sigis-xades`. Signing is only
//! enabled after the acceptance thresholds in `docs/xml-lanes.md` are met
//! (corpus of at least 50 positive and 50 negative samples plus differential
//! testing); until then the crate is verify-only. Interface skeleton.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::errors::{not_implemented, Result};
use sigis_xades::XadesResult;
use sigis_xmldsig::XmlDsigPolicy;

/// Validate the signatures of a package; each result names the parts it signs.
pub fn verify_package(
    _package: &[u8],
    _policy: &XmlDsigPolicy,
    _ctx: &ValidationContext,
) -> Result<Vec<XadesResult>> {
    not_implemented("sigis_ooxml::verify_package")
}
