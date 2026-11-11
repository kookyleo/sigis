// Derived from pyHanko `sign/diff_analysis/rules/file_structure_rules.py`
// (MIT, see LICENSE-pyHanko).

//! Rules for the document catalog, object streams and cross-reference
//! streams.

use crate::commons::{compare_dicts, compare_key_refs, ROOT_EXEMPT_STRICT_COMPARISON};
use crate::context::{Context, ReferenceUpdate};
use crate::error::DiffResultT;
use crate::history::Revision;
use crate::object::as_dict;
use crate::path::RawPdfPath;
use crate::rules::{QualifiedWhitelistRule, WhitelistRule};
use crate::ModificationLevel;

/// Adjudicates modifications to the document catalog
/// (`CatalogModificationRule`).
///
/// Keys outside `ignored_keys` must be unchanged. `/Extensions` and
/// `/MarkInfo` may change (through indirect references that clobber
/// nothing); `/AcroForm`, `/DSS` and `/Metadata` are left to their rules.
#[derive(Clone, Debug)]
pub struct CatalogModificationRule {
    /// Catalog keys that may change (default
    /// [`ROOT_EXEMPT_STRICT_COMPARISON`]).
    pub ignored_keys: Vec<Vec<u8>>,
}

impl Default for CatalogModificationRule {
    fn default() -> Self {
        Self {
            ignored_keys: ROOT_EXEMPT_STRICT_COMPARISON
                .iter()
                .map(|k| k.to_vec())
                .collect(),
        }
    }
}

impl QualifiedWhitelistRule for CatalogModificationRule {
    fn apply_qualified(
        &self,
        old: &Revision<'_>,
        new: &Revision<'_>,
    ) -> DiffResultT<Vec<(ModificationLevel, ReferenceUpdate)>> {
        let old_root = old.root()?;
        let new_root = new.root()?;
        let ignored: Vec<&[u8]> = self.ignored_keys.iter().map(Vec::as_slice).collect();
        compare_dicts(Some(&old_root), Some(&new_root), &ignored, true)?;
        let (Some(old_d), Some(new_d)) = (as_dict(&old_root), as_dict(&new_root)) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for key in ["/Extensions", "/MarkInfo"] {
            let k = &key.as_bytes()[1..];
            let (refs, _) = compare_key_refs(k, old, new, old_d, new_d)?;
            for r in refs {
                out.push((
                    ModificationLevel::LtaUpdates,
                    ReferenceUpdate::with_context(
                        r,
                        Context::absolute(RawPdfPath::of(["/Root", key])),
                    ),
                ));
            }
        }
        // blanket approval of the catalog itself: compare_dicts checked it
        out.push((
            ModificationLevel::LtaUpdates,
            ReferenceUpdate::new(new.root_ref()?),
        ));
        Ok(out)
    }
}

/// Allows new object streams (`ObjectStreamRule`). Only the streams are
/// cleared, not the objects in them.
#[derive(Clone, Debug, Default)]
pub struct ObjectStreamRule;

impl WhitelistRule for ObjectStreamRule {
    fn apply(&self, old: &Revision<'_>, new: &Revision<'_>) -> DiffResultT<Vec<ReferenceUpdate>> {
        Ok(new
            .object_streams_used()
            .filter(|r| old.is_ref_unassignable(*r))
            .map(ReferenceUpdate::new)
            .collect())
    }
}

/// Allows new cross-reference streams (`XrefStreamRule`).
#[derive(Clone, Debug, Default)]
pub struct XrefStreamRule;

impl WhitelistRule for XrefStreamRule {
    fn apply(&self, old: &Revision<'_>, new: &Revision<'_>) -> DiffResultT<Vec<ReferenceUpdate>> {
        let mut out = Vec::new();
        if let Some(stm) = new.section().stream_ref {
            if old.is_ref_unassignable(stm) {
                out.push(ReferenceUpdate::new(stm));
            }
        }
        // hybrid files are only accepted in non-strict mode; there, the
        // hybrid stream of the next revision is cleared as well
        let src = new.source();
        if src.strict() {
            return Ok(out);
        }
        let next = new.revision() + 1;
        if next >= src.revision_count()? {
            return Ok(out);
        }
        if let Some(hyb) = src.section(next)?.hybrid_stream_ref {
            if old.is_ref_unassignable(hyb) {
                out.push(ReferenceUpdate::new(hyb));
            }
        }
        Ok(out)
    }
}
