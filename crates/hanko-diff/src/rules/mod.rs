// Derived from pyHanko `sign/diff_analysis/rules_api.py` (`WhitelistRule`,
// `QualifiedWhitelistRule`) and `sign/diff_analysis/rules/` (MIT, see
// LICENSE-pyHanko).

//! Whitelisting rules (`rules_api`, `rules/`).

use crate::context::ReferenceUpdate;
use crate::error::DiffResultT;
use crate::history::Revision;
use crate::ModificationLevel;

mod dss;
mod file_structure;
mod form_fields;
mod metadata;

pub use dss::DssCompareRule;
pub use file_structure::{CatalogModificationRule, ObjectStreamRule, XrefStreamRule};
pub use form_fields::{
    is_annot_visible, is_field_visible, walk_page_tree_annots_unchecked, BaseFieldModificationRule,
    GenericFieldModificationRule,
    SigFieldCreationRule, SigFieldModificationRule,
};
pub use metadata::{DocInfoRule, MetadataUpdateRule};

/// A rule that clears references together with a modification level
/// (`QualifiedWhitelistRule`).
pub trait QualifiedWhitelistRule: std::fmt::Debug + Send + Sync {
    /// Apply the rule to the changes between `old` and `new`.
    fn apply_qualified(
        &self,
        old: &Revision<'_>,
        new: &Revision<'_>,
    ) -> DiffResultT<Vec<(ModificationLevel, ReferenceUpdate)>>;
}

/// A rule that clears references without a level (`WhitelistRule`).
pub trait WhitelistRule: std::fmt::Debug + Send + Sync {
    /// Apply the rule to the changes between `old` and `new`.
    fn apply(&self, old: &Revision<'_>, new: &Revision<'_>) -> DiffResultT<Vec<ReferenceUpdate>>;

    /// `as_qualified`: clear this rule's references at `level`.
    #[allow(clippy::wrong_self_convention)]
    fn as_qualified(self, level: ModificationLevel) -> Qualified<Self>
    where
        Self: Sized,
    {
        Qualified { rule: self, level }
    }
}

/// A [`WhitelistRule`] whose references are cleared at a fixed level
/// (`_WrappingQualifiedWhitelistRule`).
#[derive(Clone, Debug)]
pub struct Qualified<R> {
    /// The wrapped rule.
    pub rule: R,
    /// The level at which its references are cleared.
    pub level: ModificationLevel,
}

impl<R: WhitelistRule> QualifiedWhitelistRule for Qualified<R> {
    fn apply_qualified(
        &self,
        old: &Revision<'_>,
        new: &Revision<'_>,
    ) -> DiffResultT<Vec<(ModificationLevel, ReferenceUpdate)>> {
        Ok(self.rule.apply(old, new)?.into_iter().map(|u| (self.level, u)).collect())
    }
}
