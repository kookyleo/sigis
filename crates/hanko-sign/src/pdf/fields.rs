// Derived from pyHanko `sign/fields.py` (field creation, `FieldMDPSpec`,
// `SigFieldSpec`, `ensure_sig_flags`, `enumerate_sig_fields`) and
// `pdf_utils/form_tools.py` (`enumerate_fields_in`, `get_single_field_annot`,
// `annot_width_height`) (MIT, see LICENSE-pyHanko).

//! Signature form fields (`pyhanko.sign.fields`).

use std::collections::BTreeSet;

use sigis_pki_core::errors::{HankoError, Result};
use sigis_pdf::MdpPerm;
use lopdf::{Dictionary, Object, ObjectId};

use crate::pdf::seed::SigSeedValueSpec;
use crate::pdf::util::{ObjectResolver};
use crate::pdf::util::{as_number, decode_text_string, name, number, text_string};
use crate::pdf::writer::PdfUpdate;

fn signing_error(msg: impl Into<String>) -> HankoError {
    HankoError::Signing(msg.into())
}

/// Scope of a `/FieldMDP` policy (`FieldMDPAction`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldMdpAction {
    /// `/All`.
    All,
    /// `/Include`.
    Include,
    /// `/Exclude`.
    Exclude,
}

impl FieldMdpAction {
    fn pdf_name(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Include => "Include",
            Self::Exclude => "Exclude",
        }
    }
}

/// A field lock or `/FieldMDP` transform specification (`FieldMDPSpec`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldMdpSpec {
    /// Scope.
    pub action: FieldMdpAction,
    /// Field names (unless the action is `All`).
    pub fields: Vec<String>,
}

impl FieldMdpSpec {
    /// Render as a PDF dictionary (`as_pdf_object`).
    pub fn as_pdf_object(&self) -> Dictionary {
        let mut d = Dictionary::new();
        d.set("Action", name(self.action.pdf_name()));
        if self.action != FieldMdpAction::All {
            d.set(
                "Fields",
                Object::Array(self.fields.iter().map(|f| text_string(f)).collect()),
            );
        }
        d
    }

    /// As `/TransformParams` of a `/FieldMDP` reference (`as_transform_params`).
    pub fn as_transform_params(&self) -> Dictionary {
        let mut d = self.as_pdf_object();
        d.set("Type", name("TransformParams"));
        d.set("V", name("1.2"));
        d
    }

    /// As a signature field `/Lock` dictionary (`as_sig_field_lock`).
    pub fn as_sig_field_lock(&self) -> Dictionary {
        let mut d = self.as_pdf_object();
        d.set("Type", name("SigFieldLock"));
        d
    }

    /// Read from a PDF dictionary (`from_pdf_object`).
    pub fn from_pdf_object(update: &dyn ObjectResolver, d: &Dictionary) -> Result<Self> {
        let action = match update.get_resolved(d, b"Action")? {
            Some(Object::Name(n)) => match n.as_slice() {
                b"All" => FieldMdpAction::All,
                b"Include" => FieldMdpAction::Include,
                b"Exclude" => FieldMdpAction::Exclude,
                other => {
                    return Err(HankoError::Malformed(format!(
                        "invalid /Action {}",
                        String::from_utf8_lossy(other)
                    )))
                }
            },
            _ => return Err(HankoError::Malformed("/Action is required.".into())),
        };
        let fields = if action == FieldMdpAction::All {
            Vec::new()
        } else {
            match update.get_resolved(d, b"Fields")? {
                Some(Object::Array(a)) => a
                    .iter()
                    .filter_map(|o| update.resolve_obj(o).ok())
                    .filter_map(|o| o.as_str().ok().map(decode_text_string))
                    .collect(),
                _ => {
                    return Err(HankoError::Malformed(
                        "/Fields is required when /Action is not /All".into(),
                    ))
                }
            }
        };
        Ok(Self { action, fields })
    }

    /// Whether `field_name` is locked by this policy (`is_locked`).
    pub fn is_locked(&self, field_name: &str) -> bool {
        if self.action == FieldMdpAction::All {
            return true;
        }
        let lock_result = self.action == FieldMdpAction::Include;
        for scoped in &self.fields {
            if field_name == scoped || field_name.starts_with(&format!("{scoped}.")) {
                return lock_result;
            }
        }
        !lock_result
    }
}

/// Invisible signature widget settings (`InvisSigSettings`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvisSigSettings {
    /// Set the print flag (PDF/A).
    pub set_print_flag: bool,
    /// Set the hidden flag (PDF/UA).
    pub set_hidden_flag: bool,
    /// Put the box out of bounds.
    pub box_out_of_bounds: bool,
}

impl Default for InvisSigSettings {
    fn default() -> Self {
        Self {
            set_print_flag: true,
            set_hidden_flag: false,
            box_out_of_bounds: false,
        }
    }
}

/// Visible signature widget settings (`VisibleSigSettings`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VisibleSigSettings {
    /// Rotate with the page (else set `NoRotate`).
    pub rotate_with_page: bool,
    /// Scale with the page zoom (else set `NoZoom`).
    pub scale_with_page_zoom: bool,
    /// Print the signature.
    pub print_signature: bool,
}

impl Default for VisibleSigSettings {
    fn default() -> Self {
        Self {
            rotate_with_page: true,
            scale_with_page_zoom: true,
            print_signature: true,
        }
    }
}

/// Description of a signature field to create (`SigFieldSpec`).
#[derive(Clone, Debug)]
pub struct SigFieldSpec {
    /// Field name (may be dotted to create a hierarchy).
    pub sig_field_name: String,
    /// Page index (negative counts from the end).
    pub on_page: i64,
    /// Bounding box `(llx, lly, urx, ury)`.
    pub bbox: Option<(f64, f64, f64, f64)>,
    /// Seed value dictionary.
    pub seed_value_dict: Option<SigSeedValueSpec>,
    /// Field lock.
    pub field_mdp_spec: Option<FieldMdpSpec>,
    /// DocMDP value to put in the lock dictionary.
    pub doc_mdp_update_value: Option<MdpPerm>,
    /// Combine field and widget annotation.
    pub combine_annotation: bool,
    /// Draw a neutral appearance for empty visible fields.
    pub empty_field_appearance: bool,
    /// Invisible widget settings.
    pub invis_sig_settings: InvisSigSettings,
    /// Tooltip (`/TU`).
    pub readable_field_name: Option<String>,
    /// Visible widget settings.
    pub visible_sig_settings: VisibleSigSettings,
}

impl SigFieldSpec {
    /// A field named `name` with default settings.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            sig_field_name: name.into(),
            on_page: 0,
            bbox: None,
            seed_value_dict: None,
            field_mdp_spec: None,
            doc_mdp_update_value: None,
            combine_annotation: true,
            empty_field_appearance: false,
            invis_sig_settings: InvisSigSettings::default(),
            readable_field_name: None,
            visible_sig_settings: VisibleSigSettings::default(),
        }
    }

    /// Set the box.
    pub fn with_box(mut self, b: (f64, f64, f64, f64)) -> Self {
        self.bbox = Some(b);
        self
    }

    /// Set the page.
    pub fn on_page(mut self, page: i64) -> Self {
        self.on_page = page;
        self
    }

    /// The lock dictionary (`format_lock_dictionary`).
    pub fn format_lock_dictionary(&self) -> Option<Dictionary> {
        let spec = self.field_mdp_spec.as_ref()?;
        let mut d = spec.as_sig_field_lock();
        if let Some(p) = self.doc_mdp_update_value {
            d.set("P", Object::Integer(p as i64));
        }
        Some(d)
    }
}

/// One form field found by [`enumerate_sig_fields`].
#[derive(Clone, Debug, PartialEq)]
pub struct FoundField {
    /// Fully qualified name.
    pub name: String,
    /// `/V`, if any.
    pub value: Option<Object>,
    /// The field object.
    pub id: ObjectId,
}

/// Enumerate fields of type `target_type` (`enumerate_fields_in`).
pub fn enumerate_fields_in(
    update: &PdfUpdate,
    fields: &[Object],
    filled_status: Option<bool>,
    with_name: Option<&str>,
    target_type: &[u8],
) -> Result<Vec<FoundField>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    walk_fields(update, fields, filled_status, with_name, "", &[], target_type, &mut seen, &mut out)?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn walk_fields(
    update: &PdfUpdate,
    fields: &[Object],
    filled_status: Option<bool>,
    with_name: Option<&str>,
    parent_name: &str,
    parents: &[ObjectId],
    target_type: &[u8],
    seen: &mut BTreeSet<ObjectId>,
    out: &mut Vec<FoundField>,
) -> Result<()> {
    for f in fields {
        let Object::Reference(id) = f else {
            continue;
        };
        if !seen.insert(*id) {
            return Err(HankoError::Malformed("Circular reference in form tree".into()));
        }
        let Ok(field) = update.get_dict(*id) else {
            continue;
        };
        let Some(Object::String(t, _)) = update.dict_get(field, b"T")? else {
            continue;
        };
        let partial = decode_text_string(t);
        let fq = if parent_name.is_empty() {
            partial
        } else {
            format!("{parent_name}.{partial}")
        };
        let explicitly = with_name == Some(fq.as_str());
        let child_requested = explicitly || with_name.is_some_and(|w| w.starts_with(&fq));
        let mut field_type = None;
        for pid in std::iter::once(id).chain(parents.iter().rev()) {
            if let Ok(d) = update.get_dict(*pid) {
                if let Some(Object::Name(n)) = update.dict_get(d, b"FT")? {
                    field_type = Some(n.clone());
                    break;
                }
            }
        }
        if field_type.as_deref() == Some(target_type) {
            let value = update.dict_get(field, b"V")?.cloned();
            let filled = value.as_ref().is_some_and(|v| !matches!(v, Object::Null));
            let status_ok = filled_status.is_none_or(|s| s == filled);
            let name_ok = with_name.is_none() || explicitly;
            if status_ok && name_ok {
                out.push(FoundField {
                    name: fq.clone(),
                    value: value.filter(|v| !matches!(v, Object::Null)),
                    id: *id,
                });
            }
        } else if explicitly {
            return Err(HankoError::Malformed(format!(
                "Field with name {fq} exists but is not a {} field",
                String::from_utf8_lossy(target_type)
            )));
        }
        if with_name.is_none() || (child_requested && !explicitly) {
            if let Some(Object::Array(kids)) = update.dict_get(field, b"Kids")? {
                let kids = kids.clone();
                let mut p = parents.to_vec();
                p.push(*id);
                walk_fields(update, &kids, filled_status, with_name, &fq, &p, target_type, seen, out)?;
            }
        }
    }
    Ok(())
}

/// Enumerate signature fields (`enumerate_sig_fields`).
pub fn enumerate_sig_fields(
    update: &PdfUpdate,
    filled_status: Option<bool>,
    with_name: Option<&str>,
) -> Result<Vec<FoundField>> {
    let root = update.root()?;
    let Some(Object::Dictionary(form)) = update.dict_get(root, b"AcroForm")? else {
        return Ok(Vec::new());
    };
    let Some(Object::Array(fields)) = update.dict_get(form, b"Fields")? else {
        return Ok(Vec::new());
    };
    let fields = fields.clone();
    enumerate_fields_in(update, &fields, filled_status, with_name, b"Sig")
}

/// Id of the AcroForm dictionary, making it indirect if it is direct.
fn acroform_id(update: &mut PdfUpdate) -> Result<Option<ObjectId>> {
    match update.root()?.get(b"AcroForm") {
        Ok(Object::Reference(id)) => {
            let id = *id;
            if !update.is_strict() && update.get(id).is_err() {
                // a dangling reference reads as null in lenient mode
                update.root_mut()?.remove(b"AcroForm");
                return Ok(None);
            }
            Ok(Some(id))
        }
        Ok(Object::Dictionary(d)) => {
            let d = d.clone();
            let id = update.add(Object::Dictionary(d));
            update.root_mut()?.set("AcroForm", Object::Reference(id));
            Ok(Some(id))
        }
        _ => Ok(None),
    }
}

/// Ensure `/SigFlags` (`ensure_sig_flags`).
pub fn ensure_sig_flags(update: &mut PdfUpdate, lock_sig_flags: bool) -> Result<()> {
    let Some(form_id) = acroform_id(update)? else {
        return Ok(());
    };
    let form = update.get_dict(form_id)?;
    if lock_sig_flags {
        let orig = form.get(b"SigFlags").ok().and_then(|o| o.as_i64().ok());
        let has_na = form.get(b"NeedAppearances").is_ok();
        if orig != Some(3) || has_na {
            let form = update.get_dict_mut(form_id)?;
            form.set("SigFlags", Object::Integer(3));
            form.remove(b"NeedAppearances");
        }
    } else if form.get(b"SigFlags").is_err() {
        update.get_dict_mut(form_id)?.set("SigFlags", Object::Integer(1));
    }
    Ok(())
}

/// Settings for a new signature field widget.
#[derive(Clone, Debug, Default)]
pub struct NewFieldSettings {
    /// Box.
    pub bbox: Option<(f64, f64, f64, f64)>,
    /// Page to put the widget on (default: first page).
    pub page: Option<ObjectId>,
    /// Combine field and widget (default `true`).
    pub separate_annotation: bool,
    /// Invisible settings.
    pub invis: InvisSigSettings,
    /// Visible settings.
    pub visible: VisibleSigSettings,
}

/// Build the dictionary of a new signature field and its widget
/// (`SignatureFormField`). Returns `(field, separate_widget)`.
fn signature_form_field(
    partial_name: &str,
    s: &NewFieldSettings,
    page: ObjectId,
) -> (Dictionary, Option<Dictionary>) {
    let (rect, invisible) = match s.bbox {
        Some((x1, y1, x2, y2)) => (
            vec![number(x1), number(y1), number(x2), number(y2)],
            (x1 - x2).abs() == 0.0 || (y1 - y2).abs() == 0.0,
        ),
        None => {
            let c = if s.invis.box_out_of_bounds { -9999.0 } else { 0.0 };
            (vec![number(c); 4], true)
        }
    };
    let mut field = Dictionary::new();
    field.set("FT", name("Sig"));
    field.set("T", text_string(partial_name));
    let mut annot = Dictionary::new();
    annot.set("Type", name("Annot"));
    annot.set("Subtype", name("Widget"));
    let mut flags: i64 = 0b1000_0000;
    if invisible {
        if s.invis.set_hidden_flag {
            flags |= 0b10;
        }
        if s.invis.set_print_flag {
            flags |= 0b100;
        }
    } else {
        if s.visible.print_signature {
            flags |= 0b100;
        }
        if !s.visible.scale_with_page_zoom {
            flags |= 0b1000;
        }
        if !s.visible.rotate_with_page {
            flags |= 0b1_0000;
        }
    }
    annot.set("F", Object::Integer(flags));
    annot.set("Rect", Object::Array(rect));
    annot.set("P", Object::Reference(page));
    if s.separate_annotation {
        (field, Some(annot))
    } else {
        for (k, v) in annot.into_iter() {
            field.set(k, v);
        }
        (field, None)
    }
}

/// Find or create a signature field (`prepare_sig_field`). Returns whether
/// the field was created, and its id.
pub fn prepare_sig_field(
    update: &mut PdfUpdate,
    field_name: &str,
    existing_fields_only: bool,
    settings: &NewFieldSettings,
) -> Result<(bool, ObjectId)> {
    let form_id = acroform_id(update)?;
    let form_id = match form_id {
        Some(id) => {
            let form = update.get_dict(id)?;
            let has_fields = matches!(update.dict_get(form, b"Fields")?, Some(Object::Array(_)));
            if !has_fields {
                update.get_dict_mut(id)?.set("Fields", Object::Array(Vec::new()));
            }
            let candidates = enumerate_sig_fields(update, None, Some(field_name))?;
            if let Some(found) = candidates.first() {
                if found.value.is_some() {
                    return Err(signing_error(format!(
                        "Signature field with name {field_name} appears to be filled already."
                    )));
                }
                return Ok((false, found.id));
            }
            if existing_fields_only {
                return Err(signing_error(format!(
                    "No empty signature field with name {field_name} found."
                )));
            }
            id
        }
        None => {
            if existing_fields_only {
                return Err(signing_error("This file does not contain a form."));
            }
            let mut form = Dictionary::new();
            form.set("Fields", Object::Array(Vec::new()));
            let id = update.add(Object::Dictionary(form));
            update.root_mut()?.set("AcroForm", Object::Reference(id));
            id
        }
    };
    let page = match settings.page {
        Some(p) => p,
        None => update.page(0)?,
    };
    let path: Vec<&str> = field_name.split('.').collect();
    let field_id = insert_field_at(update, form_id, &path, settings, page)?;
    Ok((true, field_id))
}

/// Walk / create the field hierarchy (`_insert_or_get_field_at`).
fn insert_field_at(
    update: &mut PdfUpdate,
    form_id: ObjectId,
    path: &[&str],
    settings: &NewFieldSettings,
    page: ObjectId,
) -> Result<ObjectId> {
    // container: (object id holding the array, key, parent field)
    let mut container: (ObjectId, &[u8]) = (form_id, b"Fields");
    let mut parent: Option<ObjectId> = None;
    for (i, partial) in path.iter().enumerate() {
        let last = i + 1 == path.len();
        let arr_obj = {
            let d = update.get_dict(container.0)?;
            d.get(container.1).ok().cloned()
        };
        // resolve the array (it may be indirect)
        let (arr_holder, arr): (Option<ObjectId>, Vec<Object>) = match arr_obj {
            Some(Object::Reference(aid)) => match update.get(aid)? {
                Object::Array(a) => (Some(aid), a.clone()),
                _ => return Err(HankoError::Malformed("field array is not an array".into())),
            },
            Some(Object::Array(a)) => (None, a),
            _ => (None, Vec::new()),
        };
        let mut found = None;
        for f in &arr {
            if let Object::Reference(fid) = f {
                if let Ok(d) = update.get_dict(*fid) {
                    if let Some(Object::String(t, _)) = update.dict_get(d, b"T")? {
                        if decode_text_string(t) == *partial {
                            found = Some(*fid);
                            break;
                        }
                    }
                }
            }
        }
        let fid = match found {
            Some(fid) => fid,
            None => {
                let (mut field, widget) = if last {
                    signature_form_field(partial, settings, page)
                } else {
                    let mut d = Dictionary::new();
                    d.set("T", text_string(partial));
                    (d, None)
                };
                if let Some(p) = parent {
                    field.set("Parent", Object::Reference(p));
                }
                let fid = update.add(Object::Dictionary(field));
                if last {
                    let annot_id = match widget {
                        Some(mut w) => {
                            w.set("Parent", Object::Reference(fid));
                            let wid = update.add(Object::Dictionary(w));
                            update
                                .get_dict_mut(fid)?
                                .set("Kids", Object::Array(vec![Object::Reference(wid)]));
                            wid
                        }
                        None => fid,
                    };
                    update.register_annotation(page, annot_id)?;
                }
                let mut new_arr = arr.clone();
                new_arr.push(Object::Reference(fid));
                match arr_holder {
                    Some(aid) => update.update(aid, Object::Array(new_arr)),
                    None => update
                        .get_dict_mut(container.0)?
                        .set(container.1.to_vec(), Object::Array(new_arr)),
                }
                fid
            }
        };
        if last {
            return Ok(fid);
        }
        parent = Some(fid);
        container = (fid, b"Kids");
    }
    Err(HankoError::Malformed("empty field name".into()))
}

/// Append a signature field described by `spec` (`append_signature_field`).
pub fn append_signature_field(update: &mut PdfUpdate, spec: &SigFieldSpec) -> Result<ObjectId> {
    let page = update.page(spec.on_page)?;
    let settings = NewFieldSettings {
        bbox: spec.bbox,
        page: Some(page),
        separate_annotation: !spec.combine_annotation,
        invis: spec.invis_sig_settings,
        visible: spec.visible_sig_settings,
    };
    let (created, field_id) = prepare_sig_field(update, &spec.sig_field_name, false, &settings)?;
    ensure_sig_flags(update, false)?;
    if !created {
        return Err(HankoError::Signing(format!(
            "Signature field with name {} already exists.",
            spec.sig_field_name
        )));
    }
    apply_sig_field_spec_properties(update, field_id, spec)?;
    if let Some((x1, y1, x2, y2)) = spec.bbox {
        let (w, h) = ((x2 - x1).abs(), (y2 - y1).abs());
        if w > 0.0 && h > 0.0 {
            let content: Vec<u8> = if spec.empty_field_appearance {
                format!(
                    "q q 0.95 0.95 0.95 rg 0 0 {} {} re f Q 0.5 w 0 0 {} {} re S Q",
                    fmt_num(w),
                    fmt_num(h),
                    fmt_num(w),
                    fmt_num(h)
                )
                .into_bytes()
            } else {
                Vec::new()
            };
            let xobj = crate::pdf::util_form_xobject(content, w, h);
            let ap_id = update.add(xobj);
            let annot_id = single_field_annot(update, field_id)?;
            let mut ap = Dictionary::new();
            ap.set("N", Object::Reference(ap_id));
            update.get_dict_mut(annot_id)?.set("AP", Object::Dictionary(ap));
        }
    }
    Ok(field_id)
}

/// Format a number like pyHanko's `%g`.
pub fn fmt_num(x: f64) -> String {
    if x.fract() == 0.0 && x.abs() < 1e15 {
        format!("{}", x as i64)
    } else {
        let s = format!("{x:.6}");
        s.trim_end_matches('0').trim_end_matches('.').to_owned()
    }
}

/// Apply `/TU`, `/SV` and `/Lock` to a new field
/// (`apply_sig_field_spec_properties`).
pub fn apply_sig_field_spec_properties(
    update: &mut PdfUpdate,
    field_id: ObjectId,
    spec: &SigFieldSpec,
) -> Result<()> {
    if let Some(tu) = &spec.readable_field_name {
        update.get_dict_mut(field_id)?.set("TU", text_string(tu));
    }
    if let Some(sv) = &spec.seed_value_dict {
        let sv_obj = sv.as_pdf_object(update)?;
        let sv_id = update.add(Object::Dictionary(sv_obj));
        update.get_dict_mut(field_id)?.set("SV", Object::Reference(sv_id));
    }
    if let Some(lock) = spec.format_lock_dictionary() {
        let lock_id = update.add(Object::Dictionary(lock));
        update.get_dict_mut(field_id)?.set("Lock", Object::Reference(lock_id));
    }
    Ok(())
}

/// The widget annotation of a field (`get_single_field_annot`).
pub fn single_field_annot(update: &PdfUpdate, field_id: ObjectId) -> Result<ObjectId> {
    let field = update.get_dict(field_id)?;
    match field.get(b"Kids") {
        Err(_) => Ok(field_id),
        Ok(kids) => match update.resolve(kids)? {
            Object::Array(a) if a.len() == 1 => match &a[0] {
                Object::Reference(id) => Ok(*id),
                _ => Err(form_err()),
            },
            _ => Err(form_err()),
        },
    }
}

fn form_err() -> HankoError {
    HankoError::Malformed(
        "Failed to access form field's annotation. Form field must have exactly one child \
         annotation, or it must be combined with its annotation."
            .into(),
    )
}

/// Width and height of an annotation (`annot_width_height`).
pub fn annot_width_height(update: &PdfUpdate, annot: &Dictionary) -> (f64, f64) {
    let Ok(Some(Object::Array(r))) = update.dict_get(annot, b"Rect") else {
        return (0.0, 0.0);
    };
    let v: Vec<f64> = r
        .iter()
        .filter_map(|o| update.resolve(o).ok().and_then(as_number))
        .collect();
    if v.len() != 4 {
        return (0.0, 0.0);
    }
    ((v[0] - v[2]).abs(), (v[1] - v[3]).abs())
}
