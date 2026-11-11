// Derived from pyHanko `sign/diff_analysis/rules/form_field_rules.py` (MIT,
// see LICENSE-pyHanko).

//! Rules for form fields: signature field creation, signing, filling other
//! fields, appearance updates and widget annotations.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::rc::Rc;

use lopdf::{Dictionary, Object, ObjectId};

use crate::commons::{
    compare_dicts, compare_key_refs, FORMFIELD_ALWAYS_MODIFIABLE, VALUE_UPDATE_KEYS,
};
use crate::context::{Context, FormUpdate, ReferenceUpdate};
use crate::error::{read_error, suspicious, DiffError, DiffResultT};
use crate::form::{FieldComparisonContext, FieldComparisonSpec, FieldMdpRule};
use crate::history::{Anchor, Revision};
use crate::object::{as_dict, as_number, decode_text, py_eq, ref_str};
use crate::path::RawPdfPath;
use crate::ModificationLevel;

type Updates = Vec<(ModificationLevel, FormUpdate)>;

const AP_KEYS: [&[u8]; 3] = [b"N", b"R", b"D"];

/// Maximum depth of the page tree walked for widget annotations.
const MAX_PAGE_TREE_DEPTH: usize = 512;

/// `is_annot_visible`: whether the annotation's `/Rect` has a non-zero area.
pub fn is_annot_visible(rev: &Revision<'_>, annot: &Object) -> DiffResultT<bool> {
    let Some(d) = as_dict(annot) else { return Ok(false) };
    let Ok(rect_raw) = d.get(b"Rect") else { return Ok(false) };
    let rect = rev.deref(rect_raw)?;
    let coords: Option<Vec<f64>> = match &*rect {
        Object::Array(a) if a.len() == 4 => a.iter().map(as_number).collect(),
        // Python unpacks an undecodable (byte) string of length 4 into its
        // byte values
        Object::String(b, _) if b.len() == 4 && decode_text(b).is_none() => {
            Some(b.iter().map(|x| f64::from(*x)).collect())
        }
        _ => None,
    };
    Ok(match coords {
        Some(c) => (c[0] - c[2]).abs() * (c[1] - c[3]).abs() != 0.0,
        None => false,
    })
}

/// `is_field_visible`: whether the field or one of its `/Kids` is a visible
/// annotation.
pub fn is_field_visible(rev: &Revision<'_>, field: &Object) -> DiffResultT<bool> {
    let Some(d) = as_dict(field) else { return Ok(false) };
    let Ok(kids_raw) = d.get(b"Kids") else {
        return is_annot_visible(rev, field);
    };
    if is_annot_visible(rev, field)? {
        return Ok(true);
    }
    let kids = rev.deref(kids_raw)?;
    match &*kids {
        Object::Array(a) => {
            for kid in a {
                if is_annot_visible(rev, &*rev.deref(kid)?)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Object::Dictionary(_) | Object::Stream(_) => Ok(false),
        _ => read_error("/Kids of form field is not iterable"),
    }
}

fn dict_of(o: &Object) -> DiffResultT<&Dictionary> {
    as_dict(o).ok_or_else(|| DiffError::Read("expected a dictionary".into()))
}

/// Allows signature fields to be created at any level of the form, and
/// their widgets to be attached to pages; forbids creating other fields and
/// deleting fields (`SigFieldCreationRule`).
///
/// Invisible signature fields are created at
/// [`ModificationLevel::LtaUpdates`], appearance-related changes at
/// [`ModificationLevel::FormFilling`].
#[derive(Clone, Debug)]
pub struct SigFieldCreationRule {
    /// Approve new widget annotations of approved new fields (default
    /// `true`).
    pub approve_widget_bindings: bool,
    /// Allow new visible signature fields after a certification signature
    /// (default `false`, stricter than Acrobat).
    pub allow_new_visible_after_certify: bool,
}

impl Default for SigFieldCreationRule {
    fn default() -> Self {
        Self { approve_widget_bindings: true, allow_new_visible_after_certify: false }
    }
}

fn set_str(names: &BTreeSet<String>) -> String {
    let parts: Vec<_> = names.iter().map(|n| format!("'{n}'")).collect();
    format!("{{{}}}", parts.join(", "))
}

impl FieldMdpRule for SigFieldCreationRule {
    fn apply(&self, context: &FieldComparisonContext<'_, '_>) -> DiffResultT<Updates> {
        let old = context.old;
        let new = context.new;
        let deleted: BTreeSet<String> = context
            .field_specs
            .iter()
            .filter(|(_, s)| s.old_field_ref.is_some() && s.new_field_ref.is_none())
            .map(|(n, _)| n.clone())
            .collect();
        if !deleted.is_empty() {
            return suspicious(format!("Fields {} were deleted after signing.", set_str(&deleted)));
        }
        let all_new_refs: Vec<(String, ObjectId)> = context
            .field_specs
            .iter()
            .filter(|(_, s)| s.is_sig() && s.old_field_ref.is_none())
            .filter_map(|(n, s)| s.new_field_ref.map(|r| (n.clone(), r)))
            .collect();
        let approved: BTreeSet<String> = all_new_refs.iter().map(|(n, _)| n.clone()).collect();
        let actual: BTreeSet<String> = context
            .field_specs
            .iter()
            .filter(|(_, s)| s.old_field_ref.is_none())
            .map(|(n, _)| n.clone())
            .collect();
        if actual != approved {
            let extra: BTreeSet<String> = actual.difference(&approved).cloned().collect();
            return suspicious(format!(
                "More form fields added than expected: expected only {}, but found new \
                 fields named {}.",
                set_str(&approved),
                set_str(&extra)
            ));
        }

        let mut out = Vec::new();
        let mut field_ref_reverse: BTreeMap<ObjectId, String> = BTreeMap::new();
        for (fq_name, sigfield_ref) in &all_new_refs {
            let sigfield = new.get(*sigfield_ref)?;
            let visible = is_field_visible(new, &sigfield)?;
            let mod_level = if visible {
                ModificationLevel::FormFilling
            } else {
                ModificationLevel::LtaUpdates
            };
            if old.is_ref_unassignable(*sigfield_ref) {
                out.push((
                    mod_level,
                    FormUpdate::new(ReferenceUpdate::new(*sigfield_ref), Some(fq_name.clone()))
                        .locked_ok(!visible)
                        .certifying_ok(!visible || self.allow_new_visible_after_certify),
                ));
            }
            let sigfield_d = dict_of(&sigfield)?;
            let handle_deps = |d: &Dictionary, key: &[u8], out: &mut Updates| -> DiffResultT<()> {
                if let Ok(raw) = d.get(key) {
                    for r in new.collect_dependencies(raw, Some(old.revision() + 1))? {
                        out.push((
                            ModificationLevel::FormFilling,
                            FormUpdate::new(ReferenceUpdate::new(r), Some(fq_name.clone())),
                        ));
                    }
                }
                Ok(())
            };
            for key in [&b"AP"[..], b"Lock", b"SV"] {
                handle_deps(sigfield_d, key, &mut out)?;
            }
            match sigfield_d.get(b"Kids") {
                Err(_) => {
                    field_ref_reverse.insert(*sigfield_ref, fq_name.clone());
                }
                Ok(kids_raw) => {
                    if let Object::Reference(kids_ref) = kids_raw {
                        if old.is_ref_unassignable(*kids_ref) {
                            out.push((
                                mod_level,
                                FormUpdate::new(ReferenceUpdate::new(*kids_ref), Some(fq_name.clone()))
                                    .locked_ok(!visible),
                            ));
                        }
                    }
                    let kids = new.deref(kids_raw)?;
                    for kid in arr_to_refs(&kids, false)? {
                        let kid_obj = new.get(kid)?;
                        let Some(kid_d) = as_dict(&kid_obj) else {
                            return suspicious(format!("Widget {} is not a dictionary", ref_str(kid)));
                        };
                        if !kid_d.has(b"T") {
                            field_ref_reverse.insert(kid, fq_name.clone());
                            if old.is_ref_unassignable(kid) {
                                out.push((
                                    mod_level,
                                    FormUpdate::new(ReferenceUpdate::new(kid), Some(fq_name.clone()))
                                        .locked_ok(!visible),
                                ));
                            }
                            handle_deps(kid_d, b"AP", &mut out)?;
                        }
                    }
                }
            }
        }

        if !self.approve_widget_bindings || all_new_refs.is_empty() {
            return Ok(out);
        }
        let old_root = old.root()?;
        let new_root = new.root()?;
        let old_pages = page_root(old, &old_root)?;
        let new_pages = page_root(new, &new_root)?;
        let mut annots = Vec::new();
        walk_page_tree_annots(
            old,
            new,
            &old_pages,
            &new_pages,
            &field_ref_reverse,
            true,
            &HashSet::new(),
            0,
            &mut annots,
        )?;
        out.extend(annots.into_iter().map(|u| (ModificationLevel::LtaUpdates, u)));
        Ok(out)
    }
}

fn page_root(rev: &Revision<'_>, root: &Object) -> DiffResultT<Rc<Object>> {
    let d = dict_of(root)?;
    match d.get(b"Pages") {
        Ok(p) => rev.deref(p),
        Err(_) => read_error("No /Pages in document catalog"),
    }
}

/// `_arr_to_refs`: the references in an array of indirect objects.
fn arr_to_refs(arr: &Object, read_err: bool) -> DiffResultT<Vec<ObjectId>> {
    let exc = |m: &str| {
        if read_err {
            DiffError::Read(m.into())
        } else {
            DiffError::Suspicious(m.into())
        }
    };
    let Object::Array(items) = arr else { return Err(exc("Not an array object")) };
    items
        .iter()
        .map(|i| match i {
            Object::Reference(r) => Ok(*r),
            _ => Err(exc("Array contains direct objects")),
        })
        .collect()
}

/// `_extract_annots_from_page`: `Ok(None)` when the page has no `/Annots`.
fn extract_annots(
    rev: &Revision<'_>,
    page: &Object,
    read_err: bool,
) -> DiffResultT<Option<(BTreeSet<ObjectId>, Option<ObjectId>)>> {
    let Some(d) = as_dict(page) else {
        let m = "Page objects should be dictionaries".to_string();
        return Err(if read_err { DiffError::Read(m) } else { DiffError::Suspicious(m) });
    };
    let Ok(annots_value) = d.get(b"Annots") else { return Ok(None) };
    let annots_ref = match annots_value {
        Object::Reference(r) => Some(*r),
        _ => None,
    };
    let arr = rev.deref(annots_value)?;
    // pyHanko always raises SuspiciousModification here
    let refs = arr_to_refs(&arr, false)?;
    Ok(Some((refs.into_iter().collect(), annots_ref)))
}

fn refs_str(refs: &BTreeSet<ObjectId>) -> String {
    let parts: Vec<_> = refs.iter().map(|r| ref_str(*r)).collect();
    format!("{{{}}}", parts.join(", "))
}

/// `_walk_page_tree_annots`: allow new widget annotations of approved
/// fields on pages; everything else in the page tree must be unchanged.
#[allow(clippy::too_many_arguments)]
fn walk_page_tree_annots(
    old: &Revision<'_>,
    new: &Revision<'_>,
    old_page_root: &Object,
    new_page_root: &Object,
    field_name_dict: &BTreeMap<ObjectId, String>,
    valid_when_locked: bool,
    refs_seen: &HashSet<ObjectId>,
    depth: usize,
    out: &mut Vec<FormUpdate>,
) -> DiffResultT<()> {
    if depth > MAX_PAGE_TREE_DEPTH {
        return read_error("Page tree too deep during annotation analysis");
    }
    let get_kids = |rev: &Revision<'_>, root: &Object, read_err: bool| -> DiffResultT<Vec<ObjectId>> {
        let exc = |m: &str| {
            if read_err {
                DiffError::Read(m.into())
            } else {
                DiffError::Suspicious(m.into())
            }
        };
        let d = as_dict(root).ok_or_else(|| exc("No /Kids in /Pages entry"))?;
        let kids_raw = d.get(b"Kids").map_err(|_| exc("No /Kids in /Pages entry"))?;
        arr_to_refs(&*rev.deref(kids_raw)?, read_err)
    };
    let old_kids = get_kids(old, old_page_root, true)?;
    let new_kids = get_kids(new, new_page_root, false)?;
    if old_kids != new_kids {
        return suspicious("Unexpected change to page tree structure.");
    }
    for (new_kid_ref, old_kid_ref) in new_kids.iter().zip(&old_kids) {
        if refs_seen.contains(old_kid_ref) {
            return read_error("Circular reference in page tree during annotation analysis");
        }
        let new_kid = new.get(*new_kid_ref)?;
        let old_kid = old.get(*old_kid_ref)?;
        let node_type = match as_dict(&old_kid).map(|d| d.get(b"Type")) {
            Some(Ok(t)) => old.deref(t)?,
            _ => return read_error("Invalid page tree node"),
        };
        match &*node_type {
            Object::Name(n) if n == b"Pages" => {
                let mut seen = refs_seen.clone();
                seen.insert(*old_kid_ref);
                walk_page_tree_annots(
                    old,
                    new,
                    &old_kid,
                    &new_kid,
                    field_name_dict,
                    valid_when_locked,
                    &seen,
                    depth + 1,
                    out,
                )?;
            }
            Object::Name(n) if n == b"Page" => {
                let Some((new_annots, new_annots_ref)) = extract_annots(new, &new_kid, false)? else {
                    continue;
                };
                let (old_annots, old_annots_ref) =
                    extract_annots(old, &old_kid, true)?.unwrap_or_default();
                if old_annots == new_annots {
                    continue;
                }
                let deleted: BTreeSet<ObjectId> = old_annots.difference(&new_annots).copied().collect();
                if !deleted.is_empty() {
                    return suspicious(format!("Annotations {} were deleted.", refs_str(&deleted)));
                }
                let added: BTreeSet<ObjectId> = new_annots.difference(&old_annots).copied().collect();
                let unknown: BTreeSet<ObjectId> =
                    added.iter().filter(|a| !field_name_dict.contains_key(a)).copied().collect();
                if !unknown.is_empty() {
                    return suspicious(format!(
                        "The newly added annotations {} were not recognised.",
                        refs_str(&unknown)
                    ));
                }
                let field_name = if added.len() == 1 {
                    added.iter().next().and_then(|a| field_name_dict.get(a).cloned())
                } else {
                    None
                };
                compare_dicts(Some(&old_kid), Some(&new_kid), &[b"Annots"], true)?;
                let vwl = valid_when_locked && field_name.is_some();
                out.push(
                    FormUpdate::new(ReferenceUpdate::new(*new_kid_ref), field_name.clone())
                        .locked_ok(vwl),
                );
                if let Some(nar) = new_annots_ref {
                    if old_annots_ref == Some(nar) || old.is_ref_unassignable(nar) {
                        out.push(
                            FormUpdate::new(
                                ReferenceUpdate::with_context(
                                    nar,
                                    Context::relative(
                                        Anchor::Ref(*old_kid_ref),
                                        RawPdfPath::of(["/Annots"]),
                                    ),
                                ),
                                field_name.clone(),
                            )
                            .locked_ok(vwl),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Shared configuration of the field modification rules
/// (`BaseFieldModificationRule`).
#[derive(Clone, Debug)]
pub struct BaseFieldModificationRule {
    /// Allow appearance streams to be overwritten in place, if they are not
    /// used elsewhere (default `true`).
    pub allow_in_place_appearance_stream_changes: bool,
    /// Keys that may change even on a locked field (default
    /// [`FORMFIELD_ALWAYS_MODIFIABLE`]).
    pub always_modifiable: Vec<Vec<u8>>,
    /// Keys that may change when a field is filled (default
    /// [`VALUE_UPDATE_KEYS`]).
    pub value_update_keys: Vec<Vec<u8>>,
}

impl Default for BaseFieldModificationRule {
    fn default() -> Self {
        Self {
            allow_in_place_appearance_stream_changes: true,
            always_modifiable: FORMFIELD_ALWAYS_MODIFIABLE.iter().map(|k| k.to_vec()).collect(),
            value_update_keys: VALUE_UPDATE_KEYS.iter().map(|k| k.to_vec()).collect(),
        }
    }
}

impl BaseFieldModificationRule {
    /// `compare_fields`: check that only value keys changed; returns whether
    /// the change is acceptable even on a locked field.
    pub fn compare_fields(
        &self,
        spec: &FieldComparisonSpec,
        old: &Revision<'_>,
        new: &Revision<'_>,
    ) -> DiffResultT<bool> {
        let old_field = spec.old_field(old)?;
        let new_field = spec.new_field(new)?;
        let value_keys: Vec<&[u8]> = self.value_update_keys.iter().map(Vec::as_slice).collect();
        compare_dicts(old_field.as_deref(), new_field.as_deref(), &value_keys, true)?;
        let (Some(of), Some(nf)) = (old_field.as_deref(), new_field.as_deref()) else {
            return read_error("field missing");
        };
        let (od, nd) = (dict_of(of)?, dict_of(nf)?);
        let had_type = od.get(b"Type").ok();
        let has_type = nd.get(b"Type").ok();
        if let Some(type_val) = has_type {
            match had_type {
                None => {
                    if !matches!(type_val, Object::Name(n) if n == b"Annot") {
                        return suspicious("/Type of form field set to something other than /Annot");
                    }
                }
                Some(old_type) => {
                    if !py_eq(type_val, old_type) {
                        return suspicious("/Type of form field altered");
                    }
                }
            }
        }
        if had_type.is_some() && has_type.is_none() {
            return suspicious("/Type of form field deleted");
        }
        let always: Vec<&[u8]> = self.always_modifiable.iter().map(Vec::as_slice).collect();
        compare_dicts(Some(of), Some(nf), &always, false)
    }
}

/// Field updates for every expected context (`field_ref_updates`).
fn field_ref_updates(
    spec: &FieldComparisonSpec,
    old: &Revision<'_>,
    fq_name: &str,
    new_ref: ObjectId,
    valid_when_locked: bool,
    level: ModificationLevel,
    out: &mut Updates,
) -> DiffResultT<()> {
    for ctx in spec.expected_contexts(old)? {
        out.push((
            level,
            FormUpdate::new(ReferenceUpdate::with_context(new_ref, ctx), Some(fq_name.to_string()))
                .locked_ok(valid_when_locked),
        ));
    }
    Ok(())
}

/// Allows signature fields to be signed (once) and to receive an appearance
/// (`SigFieldModificationRule`). Invisible document timestamps are
/// [`ModificationLevel::LtaUpdates`], other signatures
/// [`ModificationLevel::FormFilling`].
#[derive(Clone, Debug, Default)]
pub struct SigFieldModificationRule {
    /// Shared configuration.
    pub base: BaseFieldModificationRule,
}

impl FieldMdpRule for SigFieldModificationRule {
    fn apply(&self, context: &FieldComparisonContext<'_, '_>) -> DiffResultT<Updates> {
        let mut out = Vec::new();
        for (fq_name, spec) in &context.field_specs {
            self.check_form_field(fq_name, spec, context, &mut out)?;
        }
        Ok(out)
    }
}

impl SigFieldModificationRule {
    fn check_form_field(
        &self,
        fq_name: &str,
        spec: &FieldComparisonSpec,
        context: &FieldComparisonContext<'_, '_>,
        out: &mut Updates,
    ) -> DiffResultT<()> {
        let (old, new) = (context.old, context.new);
        let Some(new_ref) = spec.new_field_ref else { return Ok(()) };
        if !spec.is_sig() {
            return Ok(());
        }
        let old_field = spec.old_field(old)?;
        let new_field = new.get(new_ref)?;
        let new_d = dict_of(&new_field)?;
        let previously_signed = match old_field.as_deref() {
            Some(of) => dict_of(of)?.has(b"V"),
            None => false,
        };
        let now_signed = new_d.has(b"V");
        let fq = Some(fq_name.to_string());

        if let Some(of) = old_field.as_deref() {
            let valid_when_locked = self.base.compare_fields(spec, old, new)?;
            if !previously_signed && now_signed {
                field_ref_updates(
                    spec,
                    old,
                    fq_name,
                    new_ref,
                    valid_when_locked,
                    ModificationLevel::LtaUpdates,
                    out,
                )?;
                for r in allow_appearance_update(of, &new_field, old, new)? {
                    out.push((
                        ModificationLevel::FormFilling,
                        FormUpdate::new(ReferenceUpdate::new(r), fq.clone()),
                    ));
                }
                if self.base.allow_in_place_appearance_stream_changes {
                    for u in allow_in_place_appearance_update(
                        spec.old_field_ref,
                        of,
                        &new_field,
                        old,
                        new,
                        fq_name,
                    )? {
                        out.push((ModificationLevel::FormFilling, u));
                    }
                }
            } else {
                // already signed, or still unsigned: the field must be
                // unchanged (Acrobat sets /Ff liberally, so that is allowed)
                if valid_when_locked {
                    field_ref_updates(
                        spec,
                        old,
                        fq_name,
                        new_ref,
                        valid_when_locked,
                        ModificationLevel::LtaUpdates,
                        out,
                    )?;
                }
                return Ok(());
            }
        }

        if !now_signed {
            return Ok(());
        }
        let current_value_ref = match new_d.get(b"V") {
            Ok(Object::Reference(r)) => *r,
            _ => {
                return suspicious(format!(
                    "Value of signature field {fq_name} should be an indirect reference"
                ))
            }
        };
        if !old.is_ref_unassignable(current_value_ref) {
            return suspicious(format!(
                "Value of signature field {fq_name} in revision {} is {}, which references an \
                 existing object in revision {}",
                new.revision(),
                ref_str(current_value_ref),
                old.revision()
            ));
        }
        let sig_obj = new.get(current_value_ref)?;
        let Some(sig_d) = as_dict(&sig_obj) else {
            return suspicious(format!("Value of signature field {fq_name} is not a dictionary"));
        };
        let visible = is_field_visible(new, &new_field)?;
        let is_dts = matches!(sig_d.get(b"Type"), Ok(Object::Name(n)) if n == b"DocTimeStamp");
        let (sig_whitelist, valid_when_locked) = if is_dts && !visible {
            (ModificationLevel::LtaUpdates, true)
        } else {
            (ModificationLevel::FormFilling, false)
        };
        out.push((
            sig_whitelist,
            FormUpdate::new(ReferenceUpdate::new(current_value_ref), fq.clone())
                .locked_ok(valid_when_locked),
        ));
        // Acrobat puts indirect /TransformParams in signature reference
        // dictionaries
        match sig_d.get(b"Reference") {
            Err(_) => {}
            Ok(Object::Array(items)) => {
                for sigref in items {
                    if let Some(d) = as_dict(sigref) {
                        if let Ok(Object::Reference(tp)) = d.get(b"TransformParams") {
                            out.push((
                                sig_whitelist,
                                FormUpdate::new(ReferenceUpdate::new(*tp), fq.clone()),
                            ));
                        }
                    }
                }
            }
            // Python iterates the value; dictionaries yield their keys (no
            // /TransformParams), anything else raises a TypeError
            Ok(Object::Dictionary(_)) => {}
            Ok(_) => return read_error("/Reference in signature dictionary is not iterable"),
        }
        Ok(())
    }
}

/// Allows non-signature fields to be filled
/// ([`ModificationLevel::FormFilling`]) (`GenericFieldModificationRule`).
#[derive(Clone, Debug, Default)]
pub struct GenericFieldModificationRule {
    /// Shared configuration.
    pub base: BaseFieldModificationRule,
}

impl FieldMdpRule for GenericFieldModificationRule {
    fn apply(&self, context: &FieldComparisonContext<'_, '_>) -> DiffResultT<Updates> {
        let (old, new) = (context.old, context.new);
        let mut out = Vec::new();
        for (fq_name, spec) in &context.field_specs {
            let (Some(old_ref), Some(new_ref)) = (spec.old_field_ref, spec.new_field_ref) else {
                continue;
            };
            if spec.is_sig() {
                continue;
            }
            let valid_when_locked = self.base.compare_fields(spec, old, new)?;
            field_ref_updates(
                spec,
                old,
                fq_name,
                new_ref,
                valid_when_locked,
                ModificationLevel::FormFilling,
                &mut out,
            )?;
            let old_field = old.get(old_ref)?;
            let new_field = new.get(new_ref)?;
            let fq = Some(fq_name.clone());
            for r in allow_appearance_update(&old_field, &new_field, old, new)? {
                out.push((
                    ModificationLevel::FormFilling,
                    FormUpdate::new(ReferenceUpdate::new(r), fq.clone()),
                ));
            }
            if self.base.allow_in_place_appearance_stream_changes {
                for u in allow_in_place_appearance_update(
                    Some(old_ref),
                    &old_field,
                    &new_field,
                    old,
                    new,
                    fq_name,
                )? {
                    out.push((ModificationLevel::FormFilling, u));
                }
            }
            let Ok(new_value) = dict_of(&new_field)?.get(b"V") else { continue };
            let changed = match dict_of(&old_field)?.get(b"V") {
                Ok(old_value) => !py_eq(new_value, old_value),
                Err(_) => true,
            };
            if changed {
                for r in new.collect_dependencies(new_value, Some(old.revision() + 1))? {
                    out.push((
                        ModificationLevel::FormFilling,
                        FormUpdate::new(ReferenceUpdate::new(r), fq.clone()),
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// `_allow_appearance_update`: new appearance streams must be new objects;
/// an indirect old `/AP` dictionary must be used in one context only.
fn allow_appearance_update(
    old_field: &Object,
    new_field: &Object,
    old: &Revision<'_>,
    new: &Revision<'_>,
) -> DiffResultT<Vec<ObjectId>> {
    let (od, nd) = (dict_of(old_field)?, dict_of(new_field)?);
    let (mut out, (old_ap, new_ap)) = compare_key_refs(b"AP", old, new, od, nd)?;
    let Some(new_ap) = new_ap else { return Ok(out) };
    let Some(new_ap_d) = as_dict(&new_ap) else {
        return suspicious("AP entry should point to a dictionary");
    };
    let mut checked = false;
    for key in AP_KEYS {
        let Ok(stm) = new_ap_d.get(key) else { continue };
        out.extend(new.collect_dependencies(stm, Some(old.revision() + 1))?);
        if old_ap.as_deref().is_some_and(|o| as_dict(o).is_some()) && !checked {
            if let Ok(Object::Reference(old_ap_ref)) = od.get(b"AP") {
                let mut contexts = BTreeSet::new();
                for p in old.usages_of(*old_ap_ref)? {
                    contexts.insert(old.relative_view(&p)?);
                }
                if contexts.len() > 1 {
                    let parts: Vec<String> = contexts
                        .iter()
                        .map(|(a, p)| Context::relative(*a, p.clone()).to_string())
                        .collect();
                    return suspicious(format!(
                        "Attempted to update an appearance stream in an annotation appearance \
                         dictionary, but that appearance dictionary is used in multiple \
                         contexts: {{{}}}.",
                        parts.join(", ")
                    ));
                }
            }
            checked = true;
        }
    }
    Ok(out)
}

/// `get_value_as_reference(key, optional=True)`; a direct value is a
/// `PdfReadError` (`IndirectObjectExpected`).
fn opt_ref(d: &Dictionary, key: &[u8]) -> DiffResultT<Option<ObjectId>> {
    match d.get(key) {
        Ok(Object::Reference(r)) => Ok(Some(*r)),
        Ok(_) => read_error("indirect object expected"),
        Err(_) => Ok(None),
    }
}

/// `_allow_in_place_appearance_update`: allow an appearance stream to be
/// overwritten in place, cleared in a relative context so that other usages
/// of the stream are not approved.
fn allow_in_place_appearance_update(
    old_field_ref: Option<ObjectId>,
    old_field: &Object,
    new_field: &Object,
    old: &Revision<'_>,
    new: &Revision<'_>,
    fq_name: &str,
) -> DiffResultT<Vec<FormUpdate>> {
    let (od, nd) = (dict_of(old_field)?, dict_of(new_field)?);
    let mut out = Vec::new();
    if od.has(b"AS") {
        return Ok(out);
    }
    let (Ok(old_ap_raw), Ok(new_ap_raw)) = (od.get(b"AP"), nd.get(b"AP")) else {
        return Ok(out);
    };
    let old_ap = old.deref(old_ap_raw)?;
    let Some(old_ap_d) = as_dict(&old_ap) else { return Ok(out) };
    let new_ap = new.deref(new_ap_raw)?;
    let Some(new_ap_d) = as_dict(&new_ap) else {
        return read_error("/AP is not a dictionary");
    };
    let fq = Some(fq_name.to_string());
    for key in AP_KEYS {
        let old_stm = opt_ref(old_ap_d, key)?;
        let new_stm = opt_ref(new_ap_d, key)?;
        let Some(old_stm) = old_stm else { continue };
        if new_stm != Some(old_stm) {
            continue;
        }
        let Some(last_change) = old.source().last_change(old_stm)? else {
            // no revision defines it: a reference to null, nothing to update
            continue;
        };
        if last_change == old.revision() {
            continue;
        }
        let key_s = format!("/{}", String::from_utf8_lossy(key));
        let context = match old_ap_raw {
            Object::Reference(ap_ref) => {
                Context::relative(Anchor::Ref(*ap_ref), RawPdfPath::of([key_s.as_str()]))
            }
            _ => {
                let Some(fref) = old_field_ref else {
                    return read_error("field without container reference");
                };
                Context::relative(Anchor::Ref(fref), RawPdfPath::of(["/AP", key_s.as_str()]))
            }
        };
        out.push(FormUpdate::new(ReferenceUpdate::with_context(old_stm, context), fq.clone()));
        let stm_obj = new.get(old_stm)?;
        for r in new.collect_dependencies(&stm_obj, Some(old.revision() + 1))? {
            out.push(FormUpdate::new(ReferenceUpdate::new(r), fq.clone()));
        }
    }
    Ok(out)
}

/// Walk the page trees of `old` and `new` for widget annotations with no
/// approved widgets (exposes `_walk_page_tree_annots` to the ported tests).
#[doc(hidden)]
pub fn walk_page_tree_annots_unchecked(old: &Revision<'_>, new: &Revision<'_>) -> DiffResultT<()> {
    let old_root = old.root()?;
    let new_root = new.root()?;
    let mut out = Vec::new();
    walk_page_tree_annots(
        old,
        new,
        &*page_root(old, &old_root)?,
        &*page_root(new, &new_root)?,
        &BTreeMap::new(),
        false,
        &HashSet::new(),
        0,
        &mut out,
    )
}
