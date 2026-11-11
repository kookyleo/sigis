// Interfaces derived from pyHanko `sign/diff_analysis/` (MIT, see LICENSE-pyHanko).

//! Modification analysis between PDF revisions: DocMDP / FieldMDP
//! (`pyhanko.sign.diff_analysis`).
//!
//! Owned by lane C (see `docs/hanko-lanes.md`); consumed by lane E.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::collections::BTreeSet;

use hanko_core::errors::{not_implemented, Result};
pub use hanko_pdf::MdpPerm;
use hanko_pdf::PdfFile;

/// How far a document was modified after a revision (`ModificationLevel`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModificationLevel {
    /// No modifications.
    None,
    /// Only LTV-related updates (DSS, document timestamps).
    LtaUpdates,
    /// Form filling (including signing).
    FormFilling,
    /// Annotation changes.
    Annotations,
    /// Anything else.
    Other,
}

/// FieldMDP action (`FieldMDPAction`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldMdpAction {
    /// All fields are locked.
    All,
    /// Only these fields are locked.
    Include(Vec<String>),
    /// All fields except these are locked.
    Exclude(Vec<String>),
}

/// Result of a successful review (`DiffResult`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffResult {
    /// Highest modification level found.
    pub modification_level: ModificationLevel,
    /// Form fields changed after the signed revision.
    pub changed_form_fields: BTreeSet<String>,
}

/// Outcome of a review (`DiffResult` or `SuspiciousModification`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffOutcome {
    /// The changes are explained by the rules.
    Reviewed(DiffResult),
    /// The changes could not be explained; the reason is attached.
    Suspicious(String),
}

/// Decides whether changes after a signed revision are acceptable
/// (`DiffPolicy`).
pub trait DiffPolicy: Send + Sync + std::fmt::Debug {
    /// Review all revisions after `base_revision`.
    fn review_file(
        &self,
        file: &PdfFile,
        base_revision: usize,
        field_mdp: Option<&FieldMdpAction>,
        doc_mdp: Option<MdpPerm>,
    ) -> Result<DiffOutcome>;
}

/// pyHanko's default rule set (`StandardDiffPolicy` with `DEFAULT_DIFF_POLICY`).
#[derive(Clone, Debug, Default)]
pub struct StandardDiffPolicy;

impl DiffPolicy for StandardDiffPolicy {
    fn review_file(
        &self,
        _file: &PdfFile,
        _base_revision: usize,
        _field_mdp: Option<&FieldMdpAction>,
        _doc_mdp: Option<MdpPerm>,
    ) -> Result<DiffOutcome> {
        not_implemented("hanko_diff::StandardDiffPolicy::review_file")
    }
}
