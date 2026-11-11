// Derived from pyHanko `sign/diff_analysis/commons.py` and `constants.py`
// (MIT, see LICENSE-pyHanko).

//! Helpers shared by the rules (`commons`) and rule constants (`constants`).

use std::collections::BTreeSet;
use std::rc::Rc;

use lopdf::{Dictionary, Object, ObjectId};

use crate::error::{read_error, suspicious, DiffResultT};
use crate::history::Revision;
use crate::object::{name_str, obj_str, py_eq, ref_str};

/// `FORMFIELD_ALWAYS_MODIFIABLE`: `/Ff` and `/Type`.
pub const FORMFIELD_ALWAYS_MODIFIABLE: &[&[u8]] = &[b"Ff", b"Type"];

/// `VALUE_UPDATE_KEYS`: `/Ff`, `/Type`, `/AP`, `/AS`, `/V`, `/F`, `/DA`, `/Q`.
pub const VALUE_UPDATE_KEYS: &[&[u8]] = &[b"Ff", b"Type", b"AP", b"AS", b"V", b"F", b"DA", b"Q"];

/// `ACROFORM_EXEMPT_STRICT_COMPARISON`.
pub const ACROFORM_EXEMPT_STRICT_COMPARISON: &[&[u8]] =
    &[b"Fields", b"DR", b"DA", b"Q", b"NeedAppearances"];

/// `ROOT_EXEMPT_STRICT_COMPARISON`.
pub const ROOT_EXEMPT_STRICT_COMPARISON: &[&[u8]] =
    &[b"AcroForm", b"DSS", b"Extensions", b"Metadata", b"MarkInfo", b"Version"];

/// `VRI_KEY_PATTERN` (`/[A-Z0-9]{40}`, matched as a prefix like `re.match`).
pub(crate) fn is_vri_key(key: &[u8]) -> bool {
    key.len() >= 40 && key[..40].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// `assert_not_stream`.
pub(crate) fn assert_not_stream(obj: &Object, at: Option<ObjectId>) -> DiffResultT<()> {
    if let Object::Stream(_) = obj {
        let at = at.map(ref_str).unwrap_or_else(|| "a direct object".into());
        return suspicious(format!("Unexpected stream encountered at {at}!"));
    }
    Ok(())
}

/// `safe_whitelist`: check that `new_ref` can replace `old_ref` without
/// clobbering an older object; returns the reference to clear.
pub(crate) fn safe_whitelist(
    old: &Revision<'_>,
    new: &Revision<'_>,
    old_ref: Option<ObjectId>,
    new_ref: ObjectId,
) -> DiffResultT<Option<ObjectId>> {
    if let Some(r) = old_ref {
        assert_not_stream(&*old.get(r)?, Some(r))?;
    }
    if old_ref == Some(new_ref) {
        assert_not_stream(&*new.get(new_ref)?, Some(new_ref))?;
        Ok(Some(new_ref))
    } else if old.is_ref_unassignable(new_ref) {
        Ok(Some(new_ref))
    } else {
        suspicious(format!(
            "Update clobbers or reuses {} in an unexpected way.",
            ref_str(new_ref)
        ))
    }
}

/// The two versions of a dictionary entry, dereferenced.
pub(crate) type TwoVersions = (Option<Rc<Object>>, Option<Rc<Object>>);

/// `compare_key_refs`: check that updating `key` in a dictionary has no
/// undesirable side effects. Returns the references to clear (at most one)
/// and the old and new values (dereferenced).
pub(crate) fn compare_key_refs(
    key: &[u8],
    old: &Revision<'_>,
    new: &Revision<'_>,
    old_dict: &Dictionary,
    new_dict: &Dictionary,
) -> DiffResultT<(Vec<ObjectId>, TwoVersions)> {
    let (old_value_ref, old_value) = match old_dict.get(key) {
        Ok(Object::Reference(id)) => (Some(*id), Some(old.get(*id)?)),
        Ok(v) => (None, Some(Rc::new(v.clone()))),
        Err(_) => (None, None),
    };
    let (new_value_ref, new_value) = match new_dict.get(key) {
        Ok(Object::Reference(id)) => (Some(*id), Some(new.get(*id)?)),
        Ok(v) => (None, Some(Rc::new(v.clone()))),
        Err(_) => {
            if old_value.is_some() {
                return suspicious(format!("Key {} was deleted from dictionary", name_str(key)));
            }
            return Ok((Vec::new(), (None, None)));
        }
    };
    let mut refs = Vec::new();
    if let Some(nr) = new_value_ref {
        refs.extend(safe_whitelist(old, new, old_value_ref, nr)?);
    }
    Ok((refs, (old_value, new_value)))
}

fn key_set<'d>(d: &'d Dictionary, ignored: &[&[u8]]) -> BTreeSet<&'d [u8]> {
    d.iter().map(|(k, _)| k.as_slice()).filter(|k| !ignored.contains(k)).collect()
}

fn fmt_keys(keys: &BTreeSet<&[u8]>) -> String {
    let parts: Vec<_> = keys.iter().map(|k| format!("'{}'", name_str(k))).collect();
    format!("{{{}}}", parts.join(", "))
}

/// `compare_dicts`: compare two dictionaries, ignoring `ignored` keys.
///
/// With `raise_exc`, a difference is a suspicious modification; otherwise
/// the function returns `false`.
pub(crate) fn compare_dicts(
    old_dict: Option<&Object>,
    new_dict: Option<&Object>,
    ignored: &[&[u8]],
    raise_exc: bool,
) -> DiffResultT<bool> {
    let old_d = match old_dict {
        Some(Object::Dictionary(d)) => d,
        Some(Object::Stream(s)) => &s.dict,
        _ => return read_error("Encountered unexpected non-dictionary object in prior revision."),
    };
    let new_d = match new_dict {
        Some(Object::Dictionary(d)) => d,
        Some(Object::Stream(s)) => &s.dict,
        _ => return suspicious("Dict is overridden by non-dict in new revision"),
    };
    if let Some(o) = old_dict {
        assert_not_stream(o, None)?;
    }
    if let Some(n) = new_dict {
        assert_not_stream(n, None)?;
    }
    let new_keys = key_set(new_d, ignored);
    let old_keys = key_set(old_d, ignored);
    if new_keys != old_keys {
        if raise_exc {
            return suspicious(format!(
                "Dict keys differ: {} vs. {}.",
                fmt_keys(&new_keys),
                fmt_keys(&old_keys)
            ));
        }
        return Ok(false);
    }
    for k in new_keys {
        let (Ok(new_val), Ok(old_val)) = (new_d.get(k), old_d.get(k)) else {
            continue;
        };
        if !py_eq(new_val, old_val) {
            if raise_exc {
                return suspicious(format!(
                    "Values for dict key {} differ:{} changed to {}",
                    name_str(k),
                    obj_str(old_val),
                    obj_str(new_val)
                ));
            }
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vri_key_pattern() {
        assert!(is_vri_key(&[b'A'; 40]));
        assert!(is_vri_key(b"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"));
        assert!(!is_vri_key(b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
        assert!(!is_vri_key(b"Bleh"));
    }

    #[test]
    fn compare_dicts_ignores_keys() {
        let mut a = Dictionary::new();
        a.set("A", 1);
        a.set("B", 2);
        let mut b = a.clone();
        b.set("B", 3);
        let (a, b) = (Object::Dictionary(a), Object::Dictionary(b));
        assert!(compare_dicts(Some(&a), Some(&b), &[b"B"], true).unwrap());
        assert!(!compare_dicts(Some(&a), Some(&b), &[], false).unwrap());
        assert!(compare_dicts(Some(&a), Some(&b), &[], true).is_err());
    }
}
