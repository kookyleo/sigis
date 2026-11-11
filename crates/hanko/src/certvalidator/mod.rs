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
//!
//! RFC 5280 processing (path building, signatures, names, policies,
//! constraints) is delegated to `certval`.

pub mod authority;
pub mod context;
pub mod path;
pub mod policy;
pub mod revinfo;
pub mod validate;

pub use authority::{Cert, TrustAnchor};
pub use context::{ValidationContext, ValidationContextBuilder};
pub use path::ValidationPath;
pub use policy::{
    CertRevTrustPolicy, FreshnessReqType, NonRevokedStatusAssertion, PkixValidationParams,
    RevocationCheckingPolicy, RevocationCheckingRule, NO_REVOCATION, REQUIRE_REVINFO,
};
pub use validate::{build_paths, validate_path, CertificateValidator};
