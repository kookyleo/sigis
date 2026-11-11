//! Shared foundation of the sigis-hanko crates.
//!
//! Every lane of the pyHanko port depends on this crate; changes go through
//! the lead (see `docs/hanko-lanes.md`).
//!
//! - [`ades`]: AdES main and sub-indications (EN 319 102-1 §5.1.3).
//! - [`algorithms`]: digest and signature algorithms, verification, usage policy.
//! - [`asn1`]: ASN.1 types missing from the RustCrypto crates (ESS, CAdES).
//! - [`cert`]: parsed certificates.
//! - [`errors`]: error types shared by all crates.
//! - [`fetch`]: retrieval traits (OCSP, CRL, certificates).
//! - [`key_usage`]: key usage constraints (`KeyUsageConstraints`).
//! - [`sign`]: key and timestamping traits.
//! - [`time`]: points in time.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod ades;
pub mod algorithms;
pub mod asn1;
pub mod cert;
pub mod errors;
pub mod fetch;
pub mod key_usage;
pub mod sign;
pub mod time;

pub use errors::{HankoError, Result};
