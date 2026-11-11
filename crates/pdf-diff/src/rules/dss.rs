// Derived from pyHanko `sign/diff_analysis/rules/form_field_rules.py`
// (`DSSCompareRule` and its helpers) (MIT, see LICENSE-pyHanko).

//! Rule for Document Security Store updates.

use std::collections::BTreeSet;

use lopdf::{Dictionary, Object};

use crate::commons::{assert_not_stream, compare_key_refs, is_vri_key, safe_whitelist};
use crate::context::{Context, ReferenceUpdate};
use crate::error::{read_error, suspicious, DiffResultT};
use crate::history::Revision;
use crate::object::{as_dict, name_str};
use crate::path::{PathNode, RawPdfPath};
use crate::rules::WhitelistRule;

const DSS_DER_KEYS: &[&[u8]] = &[b"Certs", b"CRLs", b"OCSPs"];
const DSS_OTHER_KEYS: &[&[u8]] = &[b"Type", b"VRI"];
const VRI_DER_KEYS: &[&[u8]] = &[b"Cert", b"CRL", b"OCSP"];
const VRI_OTHER_KEYS: &[&[u8]] = &[b"Type", b"TU", b"TS"];

/// `_assert_stream_refs`: `value` must be an array of references to streams.
/// `read_err` selects `PdfReadError` (old revision) over
/// `SuspiciousModification` (new revision).
fn assert_stream_refs(
    rev: &Revision<'_>,
    der_obj_type: &[u8],
    value: &Object,
    read_err: bool,
    is_vri: bool,
) -> DiffResultT<()> {
    let arr = rev.deref(value)?;
    let ok = match &*arr {
        Object::Array(items) => {
            let mut all = true;
            for item in items {
                let is_stream_ref = match item {
                    Object::Reference(id) => matches!(&*rev.get(*id)?, Object::Stream(_)),
                    _ => false,
                };
                if !is_stream_ref {
                    all = false;
                    break;
                }
            }
            all
        }
        _ => false,
    };
    if ok {
        return Ok(());
    }
    let msg = format!(
        "Expected contents of '{}' in {} to be an array of stream references.",
        name_str(der_obj_type),
        if is_vri { "VRI" } else { "DSS" }
    );
    if read_err {
        read_error(msg)
    } else {
        suspicious(msg)
    }
}

/// `_validate_dss_substructure`.
#[allow(clippy::too_many_arguments)]
fn validate_dss_substructure(
    old: &Revision<'_>,
    new: &Revision<'_>,
    old_dict: &Dictionary,
    new_dict: &Dictionary,
    der_stream_keys: &[&[u8]],
    is_vri: bool,
    context: &RawPdfPath,
    out: &mut Vec<ReferenceUpdate>,
) -> DiffResultT<()> {
    for der in der_stream_keys {
        let ctx = Context::absolute(context.child(PathNode::Key(der.to_vec())));
        let Ok(value) = new_dict.get(der) else {
            continue;
        };
        assert_stream_refs(new, der, value, false, is_vri)?;
        if let Object::Reference(new_ref) = value {
            if let Ok(old_value) = old_dict.get(der) {
                if let Object::Reference(old_ref) = old_value {
                    if let Some(r) = safe_whitelist(old, new, Some(*old_ref), *new_ref)? {
                        out.push(ReferenceUpdate::with_context(r, ctx.clone()));
                    }
                }
                assert_stream_refs(old, der, old_value, true, is_vri)?;
            }
        }
        for r in new.collect_dependencies(value, Some(old.revision() + 1))? {
            out.push(ReferenceUpdate::with_context(r, ctx.clone()));
        }
    }
    Ok(())
}

fn key_list(keys: &BTreeSet<Vec<u8>>) -> String {
    let parts: Vec<_> = keys.iter().map(|k| format!("'{}'", name_str(k))).collect();
    format!("{{{}}}", parts.join(", "))
}

/// Allows changes to the Document Security Store (`DSSCompareRule`).
///
/// The DSS structure is checked rigidly; removing structural items is
/// suspicious, removing individual certificates, CRLs or OCSP responses is
/// allowed (as in PAdES). Existing `/VRI` entries must stay unchanged.
#[derive(Clone, Debug, Default)]
pub struct DssCompareRule;

impl WhitelistRule for DssCompareRule {
    fn apply(&self, old: &Revision<'_>, new: &Revision<'_>) -> DiffResultT<Vec<ReferenceUpdate>> {
        let dss_path = RawPdfPath::of(["/Root", "/DSS"]);
        let old_root = old.root()?;
        let new_root = new.root()?;
        let (Some(old_rd), Some(new_rd)) = (as_dict(&old_root), as_dict(&new_root)) else {
            return read_error("Document catalog is not a dictionary");
        };
        let mut out = Vec::new();
        let (refs, (old_dss, new_dss)) = compare_key_refs(b"DSS", old, new, old_rd, new_rd)?;
        out.extend(
            refs.into_iter()
                .map(|r| ReferenceUpdate::with_context(r, Context::absolute(dss_path.clone()))),
        );
        let Some(new_dss) = new_dss else {
            return Ok(out);
        };
        let empty = Dictionary::new();
        let old_dss_dict = match old_dss.as_deref() {
            None => &empty,
            Some(o) => match as_dict(o) {
                Some(d) => d,
                None => return read_error("/DSS is not a dictionary"),
            },
        };
        let Some(new_dss_dict) = as_dict(&new_dss) else {
            return suspicious("/DSS is not a dictionary");
        };
        let unexpected: BTreeSet<Vec<u8>> = new_dss_dict
            .iter()
            .map(|(k, _)| k.clone())
            .filter(|k| {
                !DSS_DER_KEYS.contains(&k.as_slice()) && !DSS_OTHER_KEYS.contains(&k.as_slice())
            })
            .collect();
        if !unexpected.is_empty() {
            return suspicious(format!(
                "Unexpected keys in DSS: {}.",
                key_list(&unexpected)
            ));
        }
        validate_dss_substructure(
            old,
            new,
            old_dss_dict,
            new_dss_dict,
            DSS_DER_KEYS,
            false,
            &dss_path,
            &mut out,
        )?;

        let vri_path = dss_path.child("/VRI");
        let (refs, (old_vri, new_vri)) =
            compare_key_refs(b"VRI", old, new, old_dss_dict, new_dss_dict)?;
        out.extend(
            refs.into_iter()
                .map(|r| ReferenceUpdate::with_context(r, Context::absolute(vri_path.clone()))),
        );
        if let Some(new_vri) = new_vri {
            let Some(new_vri_dict) = as_dict(&new_vri) else {
                return suspicious("/VRI is not a dictionary");
            };
            let old_vri_dict = match old_vri.as_deref() {
                None => &empty,
                Some(o) => match as_dict(o) {
                    Some(d) => d,
                    None => return read_error("/VRI is not a dictionary"),
                },
            };
            check_vri(old, new, old_vri_dict, new_vri_dict, &vri_path, &mut out)?;
        }
        Ok(out)
    }
}

/// `DSSCompareRule._check_vri`.
fn check_vri(
    old: &Revision<'_>,
    new: &Revision<'_>,
    old_vri: &Dictionary,
    new_vri: &Dictionary,
    vri_path: &RawPdfPath,
    out: &mut Vec<ReferenceUpdate>,
) -> DiffResultT<()> {
    for (key, old_value) in old_vri.iter() {
        let unchanged = new_vri
            .get(key)
            .is_ok_and(|v| crate::object::py_eq(v, old_value));
        if !unchanged {
            return suspicious(format!(
                "VRI key {} was modified or deleted.",
                name_str(key)
            ));
        }
    }
    for (key, raw) in new_vri.iter() {
        if old_vri.has(key) {
            continue;
        }
        if !is_vri_key(key) {
            return suspicious(format!(
                "VRI key {} is not formatted correctly.",
                name_str(key)
            ));
        }
        let entry = match raw {
            Object::Reference(id) if old.is_ref_unassignable(*id) => {
                out.push(ReferenceUpdate::new(*id));
                new.get(*id)?
            }
            other => std::rc::Rc::new(other.clone()),
        };
        assert_not_stream(&entry, None)?;
        let Object::Dictionary(entry_dict) = &*entry else {
            return suspicious("VRI entries should be dictionaries");
        };
        let unexpected: BTreeSet<Vec<u8>> = entry_dict
            .iter()
            .map(|(k, _)| k.clone())
            .filter(|k| {
                !VRI_DER_KEYS.contains(&k.as_slice()) && !VRI_OTHER_KEYS.contains(&k.as_slice())
            })
            .collect();
        if !unexpected.is_empty() {
            return suspicious(format!(
                "Unexpected keys in VRI dictionary: {}.",
                key_list(&unexpected)
            ));
        }
        validate_dss_substructure(
            old,
            new,
            &Dictionary::new(),
            entry_dict,
            VRI_DER_KEYS,
            true,
            &vri_path.child(PathNode::Key(key.clone())),
            out,
        )?;
        // /TS is also a DER stream
        if let Ok(Object::Reference(ts)) = entry_dict.get(b"TS") {
            if old.is_ref_unassignable(*ts) {
                out.push(ReferenceUpdate::new(*ts));
            }
        }
    }
    Ok(())
}
