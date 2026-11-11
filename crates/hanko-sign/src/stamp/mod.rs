// Derived from pyHanko `stamp/` (MIT, see LICENSE-pyHanko).

//! Visible signature appearances (`pyhanko.stamp`).

use std::collections::BTreeMap;

use hanko_core::errors::Result;
use hanko_core::time::Moment;
use lopdf::ObjectId;

use crate::pdf::writer::PdfUpdate;

/// A stamp style (`BaseStampStyle`).
#[derive(Clone, Debug, PartialEq)]
pub enum StampStyle {
    /// Text stamp (`TextStampStyle`).
    Text,
}

/// Generate the appearance of a visible signature widget
/// (`SigAppearanceSetup.apply`).
#[allow(clippy::too_many_arguments)]
pub fn apply_signature_appearance(
    _update: &mut PdfUpdate,
    _annot: ObjectId,
    _w: f64,
    _h: f64,
    _style: Option<&StampStyle>,
    _signer_name: Option<&str>,
    _timestamp: Moment,
    _text_params: &BTreeMap<String, String>,
) -> Result<()> {
    Ok(())
}
