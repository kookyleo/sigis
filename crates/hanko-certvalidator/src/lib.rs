//! Certificate path validation (port of pyhanko-certvalidator).
//!
//! | pyhanko-certvalidator | module |
//! |---|---|
//! | `authority.py` | [`authority`] |
//! | `context.py` | [`context`] |
//! | `path.py` | [`path`] |
//! | `policy_decl.py` | [`policy`] |
//! | `revinfo/` | [`revinfo`] |
//! | `validate.py`, `__init__.py` | [`validate`] |
//! | `ltv/` | [`ltv`] (skeleton) |
//!
//! RFC 5280 processing (path building, signatures, names, policies,
//! constraints) is delegated to `certval`. Owned by lane A (see
//! `docs/hanko-lanes.md`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod ac;
pub mod authority;
pub mod context;
pub mod ltv;
pub mod names;
pub mod path;
pub mod policy;
pub mod registry;
pub mod revinfo;
mod stringprep_tables;
pub mod validate;

pub use authority::{Cert, TrustAnchor, TrustManager};
pub use context::{ValidationContext, ValidationContextBuilder};
pub use path::{QualifiedPolicy, ValidationPath};
pub use policy::{
    CertRevTrustPolicy, FreshnessReqType, NonRevokedStatusAssertion, PkixValidationParams,
    RevocationCheckingPolicy, RevocationCheckingRule, NO_REVOCATION, REQUIRE_REVINFO,
};
pub use validate::{
    build_paths, find_valid_path, validate_path, validate_path_detailed, validate_path_qualified,
    CertificateValidator, PathFailure,
};
