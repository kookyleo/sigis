//! Facade of the XML signature stack (layer L4, `docs/crates.md`), parallel
//! to `sigis-hanko` (PDF and CMS). Re-exports only.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use sigis_ades_model as ades_model;
pub use sigis_asic as asic;
pub use sigis_eutl as eutl;
pub use sigis_odf as odf;
pub use sigis_ooxml as ooxml;
pub use sigis_xades as xades;
pub use sigis_xmldsig as xmldsig;
