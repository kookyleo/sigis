// Interfaces derived from pyhanko-certvalidator `ltv/time_slide.py` (MIT, see LICENSE-pyHanko).

//! Validation time sliding (ETSI EN 319 102-1 §5.6.2.2).

use hanko_core::errors::{not_implemented, Result};
use hanko_core::time::Moment;

use super::poe::PoeManager;
use crate::{ValidationContext, ValidationPath};

/// Slide the control time of `path` back from `init_control_time`
/// (`time_slide`); returns the resulting control time.
pub fn time_slide(
    _path: &ValidationPath,
    _init_control_time: Moment,
    _ctx: &ValidationContext,
    _poe: &PoeManager,
) -> Result<Moment> {
    not_implemented("ltv::time_slide")
}
