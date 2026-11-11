// Interfaces derived from pyhanko-certvalidator `ltv/` (MIT, see LICENSE-pyHanko).

//! Long-term validation building blocks (`ltv/` in pyhanko-certvalidator):
//! proof-of-existence management, time sliding and past certificate
//! validation (ETSI EN 319 102-1 §5.6.2.1–5.6.2.3).
//!
//! Interface skeleton: owned by lane A, consumed by lane E (AdES).

pub mod poe;
pub mod time_slide;

use hanko_core::errors::{not_implemented, Result};
use hanko_core::time::Moment;

use crate::{ValidationContext, ValidationPath};

/// Past certificate validation (`ades_past.past_validate`): validate `path`
/// at the latest moment for which its revocation status and POEs allow it,
/// returning that moment.
pub fn past_validate(
    _ctx: &ValidationContext,
    _path: &ValidationPath,
    _poe: &poe::PoeManager,
    _initial_validation_time: Moment,
) -> Result<Moment> {
    not_implemented("ltv::past_validate")
}
