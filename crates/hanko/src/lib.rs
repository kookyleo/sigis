//! Signature validation and signing of PDF and CMS: the facade of the Rust
//! port of [pyHanko](https://github.com/MatthiasValvekens/pyHanko) 0.38.1 and
//! pyhanko-certvalidator 0.33.0 (layer L4, `docs/crates.md`).
//!
//! This crate only re-exports; the XML side has its own facade (`sigis-xsig`)
//! and the service uses `sigis-sign`. See `PORTING.md` for the module and test
//! mapping and `NOTICE` for derived files.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use sigis_ades_model as ades_model;
pub use sigis_cades as cades;
pub use sigis_cms as cms;
pub use sigis_eutl as eutl;
pub use sigis_pades as validate;
pub use sigis_pades::ades;
pub use sigis_pades_sign as sign;
pub use sigis_pdf as pdf;
pub use sigis_pdf_diff as diff;
pub use sigis_pki_certvalidator as certvalidator;
pub use sigis_pki_core::{algorithms, asn1, cert, errors, fetch, sign as keys, time};
pub use sigis_pki_core::{HankoError, Result};
pub use sigis_pki_fetch as fetchers;
