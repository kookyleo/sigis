// Derived from pyHanko `sign/diff_analysis/form_rules_api.py` (MIT, see
// LICENSE-pyHanko).

//! Form analysis: field listing, comparison specs and the form updating
//! rule (`form_rules_api`).

use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use lopdf::{Object, ObjectId};

use crate::commons::{compare_dicts, compare_key_refs, ACROFORM_EXEMPT_STRICT_COMPARISON};
use crate::context::{Context, FormUpdate, ReferenceUpdate};
use crate::error::{read_error, suspicious, DiffError, DiffResultT};
use crate::history::Revision;
use crate::object::{as_dict, decode_text, py_eq, truthy};
use crate::path::{PathNode, RawPdfPath};
use crate::rules::{GenericFieldModificationRule, SigFieldCreationRule, SigFieldModificationRule};
use crate::ModificationLevel;

/// A form field in both revisions (`FieldComparisonSpec`).
#[derive(Clone, Debug, PartialEq)]
pub struct FieldComparisonSpec {
    /// The field type (`/FT`, possibly inherited; raw value).
    pub field_type: Option<Object>,
    /// The field dictionary in the old revision, if present.
    pub old_field_ref: Option<ObjectId>,
    /// The field dictionary in the new revision, if present.
    pub new_field_ref: Option<ObjectId>,
    /// Path from the trailer through the form to the field in the old
    /// revision; `None` for new fields.
    pub old_canonical_path: Option<RawPdfPath>,
}

impl FieldComparisonSpec {
    /// Whether the field type is `/Sig`.
    pub fn is_sig(&self) -> bool {
        matches!(&self.field_type, Some(Object::Name(n)) if n == b"Sig")
    }

    /// The old field dictionary (`old_field`).
    pub fn old_field(&self, old: &Revision<'_>) -> DiffResultT<Option<Rc<Object>>> {
        self.old_field_ref.map(|r| old.get(r)).transpose()
    }

    /// The new field dictionary (`new_field`).
    pub fn new_field(&self, new: &Revision<'_>) -> DiffResultT<Option<Rc<Object>>> {
        self.new_field_ref.map(|r| new.get(r)).transpose()
    }

    /// `expected_contexts`: the contexts in which the old field is expected
    /// to be referenced (page annotations, structure tree, form).
    pub fn expected_contexts(&self, old: &Revision<'_>) -> DiffResultT<Vec<Context>> {
        let Some(old_ref) = self.old_field_ref else {
            return Ok(Vec::new());
        };
        let usages = old.usages_of(old_ref)?;
        let mut sorted: Vec<&RawPdfPath> = usages.iter().collect();
        sorted.sort();
        let mut out: Vec<Context> = Vec::new();
        for p in &sorted {
            if annotation_path_ok(p)? {
                out.push(Context::absolute((*p).clone()));
            }
        }
        if let Some(c) = self.find_in_structure_tree(old, &sorted)? {
            if !out.contains(&c) {
                out.push(c);
            }
        }
        if let Some(p) = &self.old_canonical_path {
            let c = Context::absolute(p.clone());
            if !out.contains(&c) {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// `_find_in_structure_tree`.
    fn find_in_structure_tree(
        &self,
        old: &Revision<'_>,
        usages: &[&RawPdfPath],
    ) -> DiffResultT<Option<Context>> {
        let root = old.root()?;
        if !as_dict(&root).is_some_and(|d| d.has(b"StructTreeRoot")) {
            return Ok(None);
        }
        for p in usages {
            let n = p.len();
            if p.contains_key(b"StructTreeRoot")
                && n >= 5
                && p.key_at(0, b"Root")
                && p.key_at(1, b"StructTreeRoot")
                && p.key_at(2, b"K")
                && p.key_at(n - 2, b"K")
                && p.key_at(n - 1, b"Obj")
            {
                return Ok(Some(Context::absolute((*p).clone())));
            }
        }
        Ok(None)
    }
}

/// `_old_annotation_paths._path_ok`: `.Root.Pages(.Kids[i])+.Annots[j]`.
fn annotation_path_ok(p: &RawPdfPath) -> DiffResultT<bool> {
    let nodes = &p.0;
    if nodes.len() < 6 || !p.key_at(0, b"Root") || !p.key_at(1, b"Pages") {
        return Ok(false);
    }
    let rest = &nodes[2..];
    let mut i = 0;
    // `nxt, nxt_ix, *rest = rest`: pyHanko fails with a ValueError when fewer
    // than two nodes remain; treat that as unreadable (fail closed)
    let take = |i: usize| -> DiffResultT<(&PathNode, &PathNode)> {
        match (rest.get(i), rest.get(i + 1)) {
            (Some(a), Some(b)) => Ok((a, b)),
            _ => read_error(format!("Unexpected path shape {p}")),
        }
    };
    let mut descended = false;
    let (mut nxt, mut nxt_ix) = take(i)?;
    i += 2;
    while matches!(nxt, PathNode::Key(k) if k == b"Kids") && matches!(nxt_ix, PathNode::Index(_)) {
        descended = true;
        (nxt, nxt_ix) = take(i)?;
        i += 2;
    }
    Ok(descended
        && i >= rest.len()
        && matches!(nxt, PathNode::Key(k) if k == b"Annots")
        && matches!(nxt_ix, PathNode::Index(_)))
}

/// Context of a form review (`FieldComparisonContext`).
pub struct FieldComparisonContext<'r, 'a> {
    /// Fields by fully qualified name, in listing order.
    pub field_specs: Vec<(String, FieldComparisonSpec)>,
    /// The older, signed revision.
    pub old: &'r Revision<'a>,
    /// The newer revision.
    pub new: &'r Revision<'a>,
}

/// A sub-rule of [`FormUpdatingRule`] (`FieldMDPRule`).
pub trait FieldMdpRule: std::fmt::Debug + Send + Sync {
    /// Apply the rule to a form review.
    fn apply(
        &self,
        context: &FieldComparisonContext<'_, '_>,
    ) -> DiffResultT<Vec<(ModificationLevel, FormUpdate)>>;
}

/// Validates changes to the form (`FormUpdatingRule`); the individual
/// fields are checked by its field rules.
#[derive(Clone, Debug)]
pub struct FormUpdatingRule {
    /// Rules for individual fields.
    pub field_rules: Vec<Arc<dyn FieldMdpRule>>,
    /// `/AcroForm` keys that may change (default
    /// [`ACROFORM_EXEMPT_STRICT_COMPARISON`]).
    pub ignored_acroform_keys: Vec<Vec<u8>>,
}

impl Default for FormUpdatingRule {
    /// The form rule of `DEFAULT_DIFF_POLICY`.
    fn default() -> Self {
        Self::new(vec![
            Arc::new(SigFieldCreationRule::default()),
            Arc::new(SigFieldModificationRule::default()),
            Arc::new(GenericFieldModificationRule::default()),
        ])
    }
}

/// One entry of a field list (`_make_list` output).
struct Listed {
    field_type: Option<Object>,
    field_ref: ObjectId,
    kids: Rc<Object>,
    index: usize,
}

impl FormUpdatingRule {
    /// A form rule with the default ignored `/AcroForm` keys.
    pub fn new(field_rules: Vec<Arc<dyn FieldMdpRule>>) -> Self {
        Self {
            field_rules,
            ignored_acroform_keys: ACROFORM_EXEMPT_STRICT_COMPARISON
                .iter()
                .map(|k| k.to_vec())
                .collect(),
        }
    }

    /// Evaluate the changes to the form between `old` and `new`.
    pub fn apply(
        &self,
        old: &Revision<'_>,
        new: &Revision<'_>,
    ) -> DiffResultT<Vec<(ModificationLevel, FormUpdate)>> {
        let lta = ModificationLevel::LtaUpdates;
        let mut out = Vec::new();
        let old_root = old.root()?;
        let new_root = new.root()?;
        let (Some(old_rd), Some(new_rd)) = (as_dict(&old_root), as_dict(&new_root)) else {
            return read_error("Document catalog is not a dictionary");
        };
        let acroform_path = RawPdfPath::of(["/Root", "/AcroForm"]);
        let (refs, (old_af, new_af)) = compare_key_refs(b"AcroForm", old, new, old_rd, new_rd)?;
        push_ctx(&mut out, lta, refs, &acroform_path);

        let ignored: Vec<&[u8]> = self
            .ignored_acroform_keys
            .iter()
            .map(Vec::as_slice)
            .collect();
        compare_dicts(old_af.as_deref(), new_af.as_deref(), &ignored, true)?;
        let (Some(old_af), Some(new_af)) = (old_af, new_af) else {
            return read_error("/AcroForm missing");
        };
        let (Some(old_afd), Some(new_afd)) = (as_dict(&old_af), as_dict(&new_af)) else {
            return read_error("/AcroForm is not a dictionary");
        };

        let fields_path = acroform_path.child("/Fields");
        let (refs, (old_fields, new_fields)) =
            compare_key_refs(b"Fields", old, new, old_afd, new_afd)?;
        push_ctx(&mut out, lta, refs, &fields_path);

        let dr_path = acroform_path.child("/DR");
        let (refs, (_old_dr, new_dr)) = compare_key_refs(b"DR", old, new, old_afd, new_afd)?;
        push_ctx(&mut out, ModificationLevel::FormFilling, refs, &dr_path);
        if let Some(new_dr) = new_dr {
            for r in new.collect_dependencies(&new_dr, Some(old.revision() + 1))? {
                out.push((
                    ModificationLevel::FormFilling,
                    FormUpdate::new(ReferenceUpdate::new(r), None),
                ));
            }
        }

        let mut field_specs = Vec::new();
        list_fields(
            old,
            new,
            old_fields.as_deref(),
            new_fields.as_deref(),
            Some(&fields_path),
            "",
            None,
            0,
            &mut field_specs,
        )?;
        let context = FieldComparisonContext {
            field_specs,
            old,
            new,
        };
        for rule in &self.field_rules {
            out.extend(rule.apply(&context)?);
        }
        Ok(out)
    }
}

fn push_ctx(
    out: &mut Vec<(ModificationLevel, FormUpdate)>,
    level: ModificationLevel,
    refs: Vec<ObjectId>,
    path: &RawPdfPath,
) {
    for r in refs {
        out.push((
            level,
            FormUpdate::new(
                ReferenceUpdate::with_context(r, Context::absolute(path.clone())),
                None,
            ),
        ));
    }
}

/// Maximum depth of the form field hierarchy.
const MAX_FIELD_DEPTH: usize = 256;

/// `_make_list`: list the named fields in `lst`. `read_err` selects
/// `PdfReadError` (old revision) over `SuspiciousModification` (new).
fn make_list(
    rev: &Revision<'_>,
    lst: Option<&Object>,
    read_err: bool,
    parent_name: &str,
    inherited_ft: Option<&Object>,
) -> DiffResultT<BTreeMap<String, Listed>> {
    let exc = |msg: String| -> DiffError {
        if read_err {
            DiffError::Read(msg)
        } else {
            DiffError::Suspicious(msg)
        }
    };
    let Some(Object::Array(items)) = lst else {
        return Err(exc("Field list is not an array.".into()));
    };
    let mut names_seen: HashSet<String> = HashSet::new();
    let mut out = BTreeMap::new();
    for (ix, item) in items.iter().enumerate() {
        let Object::Reference(field_ref) = item else {
            return Err(exc("Fields must be indirect objects".into()));
        };
        let field = rev.get(*field_ref)?;
        let Some(fd) = as_dict(&field) else {
            return Err(exc("Fields must be dictionary objects".into()));
        };
        let Ok(name_obj) = fd.get(b"T") else { continue };
        let name = match name_obj {
            // undecodable names are byte strings in pyHanko, where the
            // period check then fails with a TypeError; reject them
            Object::String(b, _) => {
                decode_text(b).ok_or_else(|| exc("Names must be strings".into()))?
            }
            _ => return Err(exc("Names must be strings".into())),
        };
        if names_seen.contains(&name) {
            return Err(exc("Duplicate field name".into()));
        } else if name.contains('.') {
            return Err(exc("Partial names must not contain periods".into()));
        }
        names_seen.insert(name.clone());
        let fq_name = if parent_name.is_empty() {
            name
        } else {
            format!("{parent_name}.{name}")
        };
        let field_type = match fd.get(b"FT") {
            Ok(ft) => Some(ft.clone()),
            Err(_) => inherited_ft.cloned(),
        };
        let kids = match fd.get(b"Kids") {
            Ok(k) => rev.deref(k)?,
            Err(_) => Rc::new(Object::Array(Vec::new())),
        };
        if !truthy(&kids) && field_type.is_none() {
            return Err(exc(format!(
                "Field type of terminal field '{fq_name}' could not be determined"
            )));
        }
        out.insert(
            fq_name,
            Listed {
                field_type,
                field_ref: *field_ref,
                kids,
                index: ix,
            },
        );
    }
    Ok(out)
}

fn opt_eq(a: &Option<Object>, b: &Option<Object>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => py_eq(x, y),
        _ => false,
    }
}

/// `_list_fields`: pair up the fields of both revisions, depth first.
#[allow(clippy::too_many_arguments)]
fn list_fields(
    old: &Revision<'_>,
    new: &Revision<'_>,
    old_fields: Option<&Object>,
    new_fields: Option<&Object>,
    old_path: Option<&RawPdfPath>,
    parent_name: &str,
    inherited_ft: Option<&Object>,
    depth: usize,
    out: &mut Vec<(String, FieldComparisonSpec)>,
) -> DiffResultT<()> {
    if depth > MAX_FIELD_DEPTH {
        return read_error("Form field hierarchy too deep");
    }
    let mut old_by_name = make_list(old, old_fields, true, parent_name, inherited_ft)?;
    let mut new_by_name = make_list(new, new_fields, false, parent_name, inherited_ft)?;
    let names: std::collections::BTreeSet<String> = old_by_name
        .keys()
        .chain(new_by_name.keys())
        .cloned()
        .collect();
    for name in names {
        let o = old_by_name.remove(&name);
        let n = new_by_name.remove(&name);
        let old_ft = o.as_ref().and_then(|x| x.field_type.clone());
        let new_ft = n.as_ref().and_then(|x| x.field_type.clone());
        if o.is_some() && n.is_some() && !opt_eq(&new_ft, &old_ft) {
            return suspicious(format!("Update changed field type of {name}"));
        }
        let common_ft = match &old_ft {
            Some(ft) if truthy(ft) => Some(ft.clone()),
            _ => new_ft.clone(),
        };
        let field_path = match (&o, old_path) {
            (Some(l), Some(p)) => Some(p.child(l.index)),
            _ => None,
        };
        let empty = Rc::new(Object::Array(Vec::new()));
        let old_kids = o
            .as_ref()
            .map(|l| l.kids.clone())
            .unwrap_or_else(|| empty.clone());
        let new_kids = n.as_ref().map(|l| l.kids.clone()).unwrap_or(empty);
        out.push((
            name.clone(),
            FieldComparisonSpec {
                field_type: common_ft.clone(),
                old_field_ref: o.as_ref().map(|l| l.field_ref),
                new_field_ref: n.as_ref().map(|l| l.field_ref),
                old_canonical_path: field_path.clone(),
            },
        ));
        if truthy(&old_kids) || truthy(&new_kids) {
            let kids_path = field_path.as_ref().map(|p| p.child("/Kids"));
            list_fields(
                old,
                new,
                Some(&old_kids),
                Some(&new_kids),
                kids_path.as_ref(),
                &name,
                common_ft.as_ref(),
                depth + 1,
                out,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotation_paths() {
        let ok = RawPdfPath::of([
            PathNode::from("/Root"),
            "/Pages".into(),
            "/Kids".into(),
            0usize.into(),
            "/Annots".into(),
            1usize.into(),
        ]);
        assert!(annotation_path_ok(&ok).unwrap());
        let not_annot = RawPdfPath::of([
            PathNode::from("/Root"),
            "/AcroForm".into(),
            "/Fields".into(),
            0usize.into(),
            "/Kids".into(),
            1usize.into(),
        ]);
        assert!(!annotation_path_ok(&not_annot).unwrap());
        let nested = RawPdfPath::of([
            PathNode::from("/Root"),
            "/Pages".into(),
            "/Kids".into(),
            0usize.into(),
            "/Kids".into(),
            2usize.into(),
            "/Annots".into(),
            0usize.into(),
        ]);
        assert!(annotation_path_ok(&nested).unwrap());
    }
}
