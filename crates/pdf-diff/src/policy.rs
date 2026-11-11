// Derived from pyHanko `sign/diff_analysis/policies.py` (MIT, see
// LICENSE-pyHanko).

//! The standard rule-based difference policy (`StandardDiffPolicy`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use lopdf::ObjectId;
use sigis_pki_core::errors::Result;

use crate::context::{ApprovalType, Context, ReferenceUpdate};
use crate::error::{suspicious, DiffError, DiffResultT};
use crate::form::FormUpdatingRule;
use crate::history::{Revision, RevisionSource};
use crate::object::{is_identical, ref_str};
use crate::rules::{
    CatalogModificationRule, DocInfoRule, DssCompareRule, MetadataUpdateRule, ObjectStreamRule,
    QualifiedWhitelistRule, WhitelistRule, XrefStreamRule,
};
use crate::{DiffOutcome, DiffResult, FieldMdpAction, MdpPerm, ModificationLevel};

/// A rule-based difference policy (pyHanko's `StandardDiffPolicy` class).
///
/// [`ConfigurableDiffPolicy::default`] is pyHanko's `DEFAULT_DIFF_POLICY`,
/// [`ConfigurableDiffPolicy::no_changes`] its `NO_CHANGES_DIFF_POLICY`.
#[derive(Clone, Debug)]
pub struct ConfigurableDiffPolicy {
    /// Rules applied to every revision (`global_rules`).
    pub global_rules: Vec<Arc<dyn QualifiedWhitelistRule>>,
    /// The form rule (`form_rule`).
    pub form_rule: Option<FormUpdatingRule>,
    /// Reject revisions that free objects (default `true`).
    pub reject_object_freeing: bool,
    /// Clear new objects that nothing references at
    /// [`ModificationLevel::LtaUpdates`] (default `true`).
    pub ignore_orphaned_objects: bool,
    /// Ignore objects overwritten with identical copies (default `true`).
    pub ignore_identical_objects: bool,
}

impl Default for ConfigurableDiffPolicy {
    /// `DEFAULT_DIFF_POLICY`.
    fn default() -> Self {
        let lta = ModificationLevel::LtaUpdates;
        Self::new(
            vec![
                Arc::new(CatalogModificationRule::default()),
                Arc::new(DocInfoRule.as_qualified(lta)),
                Arc::new(XrefStreamRule.as_qualified(lta)),
                Arc::new(ObjectStreamRule.as_qualified(lta)),
                Arc::new(DssCompareRule.as_qualified(lta)),
                Arc::new(MetadataUpdateRule::default().as_qualified(lta)),
            ],
            Some(FormUpdatingRule::default()),
        )
    }
}

/// `_find_orphans`: new objects of `new` that nothing from older revisions
/// references (assumes older revisions do not point at objects that only
/// later revisions define).
fn find_orphans(new: &Revision<'_>) -> DiffResultT<BTreeSet<ObjectId>> {
    let rev = new.revision();
    if rev == 0 {
        return Ok(BTreeSet::new());
    }
    let previous = Revision::new(new.source(), rev - 1)?;
    let mut updated_old = Vec::new();
    let mut candidates = BTreeSet::new();
    for r in new.explicit_refs() {
        if previous.is_ref_unassignable(*r) {
            candidates.insert(*r);
        } else {
            updated_old.push(*r);
        }
    }
    if candidates.is_empty() {
        return Ok(candidates);
    }
    let trailer = new.trailer_obj();
    for r in new.collect_dependencies(&trailer, Some(rev))? {
        candidates.remove(&r);
    }
    for old_ref in updated_old {
        if candidates.is_empty() {
            break;
        }
        let obj = new.get_raw(old_ref)?;
        for r in new.collect_dependencies(&obj, Some(rev))? {
            candidates.remove(&r);
        }
    }
    Ok(candidates)
}

fn refs_set_str(refs: &BTreeSet<ObjectId>) -> String {
    let parts: Vec<_> = refs.iter().map(|r| ref_str(*r)).collect();
    format!("{{{}}}", parts.join(", "))
}

impl ConfigurableDiffPolicy {
    /// A policy with the given rules and pyHanko's default flags.
    pub fn new(
        global_rules: Vec<Arc<dyn QualifiedWhitelistRule>>,
        form_rule: Option<FormUpdatingRule>,
    ) -> Self {
        Self {
            global_rules,
            form_rule,
            reject_object_freeing: true,
            ignore_orphaned_objects: true,
            ignore_identical_objects: true,
        }
    }

    /// `NO_CHANGES_DIFF_POLICY`: no rules, every change is rejected.
    pub fn no_changes() -> Self {
        Self::new(Vec::new(), None)
    }

    /// `apply`: review one revision against the signed one.
    pub fn apply(
        &self,
        old: &Revision<'_>,
        new: &Revision<'_>,
        field_mdp: Option<&FieldMdpAction>,
        doc_mdp: Option<MdpPerm>,
    ) -> DiffResultT<DiffResult> {
        if self.reject_object_freeing && !new.refs_freed().is_empty() {
            return suspicious(format!(
                "The refs {} were freed in the revision provided. The configured difference \
                 analysis policy does not allow object freeing.",
                refs_set_str(new.refs_freed())
            ));
        }
        let new_xrefs: BTreeSet<ObjectId> = new.explicit_refs().clone();
        let mut explained: HashMap<ModificationLevel, BTreeSet<ObjectId>> = HashMap::new();

        if self.ignore_orphaned_objects {
            for r in find_orphans(new)? {
                explained
                    .entry(ModificationLevel::LtaUpdates)
                    .or_default()
                    .insert(r);
            }
        }

        // overwritten references that existed in the old revision, with the
        // paths through which they are reached there; they are cleared path
        // by path
        let mut old_usages: BTreeMap<ObjectId, (ModificationLevel, BTreeSet<Context>)> =
            BTreeMap::new();
        old.usages()?;
        for r in &new_xrefs {
            let usages = old.usages_of(*r)?;
            if !usages.is_empty() {
                let contexts = usages.into_iter().map(Context::Absolute).collect();
                old_usages.insert(*r, (ModificationLevel::None, contexts));
            }
        }

        let mut ingest = |level: ModificationLevel,
                          upd: &ReferenceUpdate,
                          explained: &mut HashMap<ModificationLevel, BTreeSet<ObjectId>>|
         -> DiffResultT<()> {
            let r = upd.updated_ref;
            let mut level = level;
            if let Some((current_max, usages)) = old_usages.get_mut(&r) {
                match upd.approval_type() {
                    ApprovalType::BlanketApprove => usages.clear(),
                    ApprovalType::ApproveRelativeContext => {
                        let mut keep = BTreeSet::new();
                        for ctx in usages.iter() {
                            let rel = ctx.relative_view(old)?;
                            if Some(&rel) != upd.context_checked.as_ref() {
                                keep.insert(ctx.clone());
                            }
                        }
                        *usages = keep;
                    }
                    ApprovalType::ApprovePath => {
                        if let Some(c) = &upd.context_checked {
                            usages.remove(c);
                        }
                    }
                }
                level = level.max(*current_max);
                *current_max = level;
                if !usages.is_empty() {
                    return Ok(());
                }
            }
            explained.entry(level).or_default().insert(r);
            Ok(())
        };

        for rule in &self.global_rules {
            for (level, upd) in rule.apply_qualified(old, new)? {
                ingest(level, &upd, &mut explained)?;
            }
        }

        let mut changed_form_fields = BTreeSet::new();
        if let Some(form_rule) = &self.form_rule {
            for (level, fu) in form_rule.apply(old, new)? {
                ingest(level, &fu.update, &mut explained)?;
                if let Some(name) = &fu.field_name {
                    if !fu.valid_when_locked {
                        if field_mdp.is_some_and(|f| f.is_locked(name)) {
                            return suspicious(format!(
                                "Update of {} is not allowed because the form field {name} is \
                                 locked.",
                                ref_str(fu.update.updated_ref)
                            ));
                        }
                        changed_form_fields.insert(name.clone());
                    }
                }
                if doc_mdp.is_some() && !fu.valid_when_certifying {
                    return suspicious(format!(
                        "Update of {} is only allowed after an approval signature, not a \
                         certification signature.",
                        ref_str(fu.update.updated_ref)
                    ));
                }
            }
        }

        let level_set = |l: ModificationLevel| explained.get(&l).cloned().unwrap_or_default();
        let mut unexplained_lta: BTreeSet<ObjectId> = new_xrefs
            .difference(&level_set(ModificationLevel::LtaUpdates))
            .copied()
            .collect();
        let mut unexplained_formfill: BTreeSet<ObjectId> = unexplained_lta
            .difference(&level_set(ModificationLevel::FormFilling))
            .copied()
            .collect();
        let mut unexplained_annot: BTreeSet<ObjectId> = unexplained_formfill
            .difference(&level_set(ModificationLevel::Annotations))
            .copied()
            .collect();

        if self.ignore_identical_objects {
            let src = old.source();
            let mut identical = BTreeSet::new();
            for r in &unexplained_lta {
                if src.resolves_in(*r, old.revision())?
                    && is_identical(&*old.get_raw(*r)?, &*new.get_raw(*r)?)
                {
                    identical.insert(*r);
                }
            }
            for r in &identical {
                unexplained_annot.remove(r);
                unexplained_formfill.remove(r);
                unexplained_lta.remove(r);
            }
        }

        let level = if !unexplained_annot.is_empty() {
            let mut msg = format!(
                "There are unexplained xrefs in revision {}: {}.",
                new.revision(),
                unexplained_annot
                    .iter()
                    .map(|r| ref_str(*r))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let overrides: Vec<String> = old_usages
                .iter()
                .filter(|(_, (_, paths))| !paths.is_empty())
                .map(|(r, (_, paths))| {
                    let ps: Vec<String> = paths.iter().map(ToString::to_string).collect();
                    format!(
                        " - {} is also used in {} in the prior revision.",
                        ref_str(*r),
                        ps.join(", ")
                    )
                })
                .collect();
            if !overrides.is_empty() {
                msg.push_str(&format!(
                    "\nSome objects from revision {} were replaced in revision {} without \
                     precise justification:\n{}",
                    old.revision(),
                    new.revision(),
                    overrides.join("\n")
                ));
            }
            return suspicious(msg);
        } else if !unexplained_formfill.is_empty() {
            ModificationLevel::Annotations
        } else if !unexplained_lta.is_empty() {
            ModificationLevel::FormFilling
        } else {
            ModificationLevel::LtaUpdates
        };
        Ok(DiffResult {
            modification_level: level,
            changed_form_fields,
        })
    }

    /// `review_file`: review every revision after `base_revision`
    /// separately against `base_revision`.
    ///
    /// A suspicious modification is an [`DiffOutcome::Suspicious`] outcome;
    /// unreadable structures are errors.
    pub fn review_source(
        &self,
        src: &dyn RevisionSource,
        base_revision: usize,
        field_mdp: Option<&FieldMdpAction>,
        doc_mdp: Option<MdpPerm>,
    ) -> Result<DiffOutcome> {
        match self.review_inner(src, base_revision, field_mdp, doc_mdp) {
            Ok(r) => Ok(DiffOutcome::Reviewed(r)),
            Err(DiffError::Suspicious(m)) => Ok(DiffOutcome::Suspicious(m)),
            Err(e) => Err(e.into()),
        }
    }

    fn review_inner(
        &self,
        src: &dyn RevisionSource,
        base_revision: usize,
        field_mdp: Option<&FieldMdpAction>,
        doc_mdp: Option<MdpPerm>,
    ) -> DiffResultT<DiffResult> {
        let count = src.revision_count()?;
        let mut current_max = ModificationLevel::None;
        let mut changed = BTreeSet::new();
        if base_revision + 1 >= count {
            return Ok(DiffResult {
                modification_level: current_max,
                changed_form_fields: changed,
            });
        }
        let base = Revision::new(src, base_revision)?;
        for revision in base_revision + 1..count {
            let new = Revision::new(src, revision)?;
            let r = self.apply(&base, &new, field_mdp, doc_mdp)?;
            current_max = current_max.max(r.modification_level);
            changed.extend(r.changed_form_fields);
        }
        Ok(DiffResult {
            modification_level: current_max,
            changed_form_fields: changed,
        })
    }
}
