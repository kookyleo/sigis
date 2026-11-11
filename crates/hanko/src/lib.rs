//! Signature validation foundation for Sigis.
//!
//! `sigis-hanko` is a Rust port of the validation foundation of
//! [pyHanko](https://github.com/MatthiasValvekens/pyHanko) and
//! pyhanko-certvalidator (MIT). See `PORTING.md` for the module mapping and
//! test status, and `NOTICE` for the files derived from pyHanko.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod algorithms;
pub mod asn1;
pub mod certvalidator;
pub mod errors;
pub mod time;
