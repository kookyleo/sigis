// Derived from pyhanko-certvalidator `validate.py` (`async_validate_ac`,
// `ACValidationResult`) (MIT, see LICENSE-pyHanko).

//! Attribute certificate validation (RFC 5755).

use std::collections::BTreeMap;

use hanko_core::errors::ValidationError;

use crate::authority::Cert;
use crate::context::ValidationContext;
use crate::path::ValidationPath;

/// Result of a successful attribute certificate validation
/// (`ACValidationResult`).
#[derive(Clone, Debug)]
pub struct AcValidationResult {
    /// DER of the attribute certificate.
    pub attr_cert: Vec<u8>,
    /// Path of the attribute authority's certificate.
    pub aa_path: ValidationPath,
    /// Approved attributes by type name (DER of each `Attribute`).
    pub approved_attributes: BTreeMap<String, Vec<u8>>,
}

/// Validate an attribute certificate (`async_validate_ac`). `holder`, if
/// given, must match the AC's holder entry.
pub fn validate_ac(
    _ctx: &ValidationContext,
    _attr_cert: &[u8],
    _holder: Option<&Cert>,
) -> Result<AcValidationResult, ValidationError> {
    Err(ValidationError::PathValidation(
        "attribute certificate validation is not supported yet".into(),
    ))
}
