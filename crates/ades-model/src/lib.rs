//! Shared AdES verdict and report model (layer L2, `docs/crates.md`).
//!
//! Every format crate (`pades`, `cades`, `xades`, `asic`, and the containers
//! above them) reports results in these terms, so that the service facade can
//! present one model:
//!
//! - the ETSI EN 319 102-1 main and sub-indications ([`AdesStatus`],
//!   [`AdesSubIndic`], ...), defined in `sigis-pki-core` because errors of
//!   lower layers carry them, and re-exported here;
//! - [`errors::SignatureValidationError`], pyHanko's validation error with
//!   its sub-indication.
//!
//! The format-neutral validation report (signature-level results and the
//! ETSI TS 119 102-2 report structure) moves here from `sigis-pades` as the
//! XML formats arrive (see `docs/xml-lanes.md`). Owned by lane E.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod errors;

/// The indications under their pyHanko module name (`sign.ades.report`).
pub use sigis_pki_core::ades as report;
pub use sigis_pki_core::ades::*;
