// Derived from pyHanko `sign/diff_analysis/` (`__init__.py`, `policy_api.py`,
// `policies.py`) and `sign/fields.py` (`FieldMDPSpec.is_locked`) (MIT, see
// LICENSE-pyHanko).

//! Modification analysis between PDF revisions: DocMDP / FieldMDP
//! (`pyhanko.sign.diff_analysis`).
//!
//! pyHanko reviews the changes that incremental updates made after a signed
//! revision by *whitelisting*: rules clear the objects that each revision
//! wrote, and every object that no rule clears makes the revision
//! suspicious. The highest level at which all objects are cleared is the
//! [`ModificationLevel`] of the revision.
//!
//! - [`StandardDiffPolicy`] is pyHanko's `DEFAULT_DIFF_POLICY`;
//!   [`ConfigurableDiffPolicy`] is the configurable `StandardDiffPolicy`
//!   class (custom rules, `NO_CHANGES_DIFF_POLICY`).
//! - Documents are read through [`RevisionSource`]; [`PdfFileSource`] adapts
//!   [`sigis_pdf::PdfFile`].
//!
//! Owned by lane C (see `docs/hanko-lanes.md`); consumed by lane E.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::collections::BTreeSet;

pub use sigis_pdf::MdpPerm;
use sigis_pdf::PdfFile;
use sigis_pki_core::errors::Result;

mod commons;
mod context;
mod error;
mod form;
mod history;
mod object;
mod path;
mod pdf_source;
mod policy;
pub mod rules;

pub use commons::{
    ACROFORM_EXEMPT_STRICT_COMPARISON, FORMFIELD_ALWAYS_MODIFIABLE, ROOT_EXEMPT_STRICT_COMPARISON,
    VALUE_UPDATE_KEYS,
};
pub use context::{ApprovalType, Context, FormUpdate, ReferenceUpdate};
pub use error::{DiffError, DiffResultT};
pub use form::{FieldComparisonContext, FieldComparisonSpec, FieldMdpRule, FormUpdatingRule};
pub use history::{Anchor, Revision, RevisionSource, XrefSectionInfo, MAX_USAGE_PATHS};
pub use path::{PathNode, RawPdfPath};
pub use pdf_source::{DerivedSource, PdfFileSource, PdfRevisions};
pub use policy::ConfigurableDiffPolicy;

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

impl FieldMdpAction {
    /// `FieldMDPSpec.is_locked`: whether the policy locks `field_name`. A
    /// listed non-terminal field covers all fields below it.
    pub fn is_locked(&self, field_name: &str) -> bool {
        let (fields, lock_result) = match self {
            FieldMdpAction::All => return true,
            FieldMdpAction::Include(f) => (f, true),
            FieldMdpAction::Exclude(f) => (f, false),
        };
        for scoped in fields {
            let below = field_name
                .strip_prefix(scoped.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'));
            if below {
                return lock_result;
            }
        }
        !lock_result
    }
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

impl StandardDiffPolicy {
    /// Review all revisions after `base_revision` of any [`RevisionSource`].
    pub fn review_source(
        &self,
        src: &dyn RevisionSource,
        base_revision: usize,
        field_mdp: Option<&FieldMdpAction>,
        doc_mdp: Option<MdpPerm>,
    ) -> Result<DiffOutcome> {
        ConfigurableDiffPolicy::default().review_source(src, base_revision, field_mdp, doc_mdp)
    }
}

impl DiffPolicy for StandardDiffPolicy {
    fn review_file(
        &self,
        file: &PdfFile,
        base_revision: usize,
        field_mdp: Option<&FieldMdpAction>,
        doc_mdp: Option<MdpPerm>,
    ) -> Result<DiffOutcome> {
        ConfigurableDiffPolicy::default().review_file(file, base_revision, field_mdp, doc_mdp)
    }
}

impl DiffPolicy for ConfigurableDiffPolicy {
    fn review_file(
        &self,
        file: &PdfFile,
        base_revision: usize,
        field_mdp: Option<&FieldMdpAction>,
        doc_mdp: Option<MdpPerm>,
    ) -> Result<DiffOutcome> {
        let src = PdfFileSource::new(file)?;
        self.review_source(&src, base_revision, field_mdp, doc_mdp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_mdp_locks() {
        let inc = FieldMdpAction::Include(vec!["TextInput".into(), "Signature1".into()]);
        assert!(inc.is_locked("TextInput"));
        assert!(inc.is_locked("TextInput.TextField1"));
        assert!(inc.is_locked("Signature1"));
        // shared name prefix is not a parent
        assert!(!inc.is_locked("Signature10"));
        assert!(!inc.is_locked("Other"));
        let exc = FieldMdpAction::Exclude(vec!["TextInput.TextField2".into()]);
        assert!(exc.is_locked("TextInput.TextField1"));
        assert!(!exc.is_locked("TextInput.TextField2"));
        assert!(FieldMdpAction::All.is_locked("x"));
    }
}
