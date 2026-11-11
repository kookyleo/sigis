// Derived from pyHanko `sign/validation/pdf_embedded.py` (MIT, see LICENSE-pyHanko).

//! Integrity information of an embedded signature: DocMDP / FieldMDP
//! settings, modification review and its summary.

use hanko_core::errors::{HankoError, Result};
use hanko_diff::{DiffOutcome, DiffPolicy, DiffResult, FieldMdpAction, MdpPerm, ModificationLevel};
use hanko_pdf::lopdf::{Dictionary, Object};
use hanko_pdf::PdfFile;

use crate::errors::SignatureValidationError;
use crate::SignatureCoverageLevel;

/// Resolve `obj` (following references) as of `revision`.
pub fn resolve(file: &PdfFile, obj: &Object, revision: usize) -> Result<Object> {
    let mut cur = obj.clone();
    for _ in 0..32 {
        match cur {
            Object::Reference(id) => {
                cur = file
                    .object_in_revision(id, revision)?
                    .ok_or_else(|| HankoError::Malformed(format!("dangling reference {id:?}")))?;
            }
            other => return Ok(other),
        }
    }
    Err(HankoError::Malformed("reference chain too long".into()))
}

fn name_eq(obj: &Object, name: &str) -> bool {
    matches!(obj, Object::Name(n) if n.as_slice() == name.as_bytes())
}

/// The `/Reference` dictionary of a signature with the given
/// `/TransformMethod` (`_extract_reference_dict`).
pub fn reference_dict(
    file: &PdfFile,
    sig_object: &Dictionary,
    method: &str,
    revision: usize,
) -> Result<Option<Dictionary>> {
    let Ok(refs) = sig_object.get(b"Reference") else {
        return Ok(None);
    };
    let Object::Array(refs) = resolve(file, refs, revision)? else {
        return Ok(None);
    };
    for r in refs {
        if let Object::Dictionary(d) = resolve(file, &r, revision)? {
            if d.get(b"TransformMethod").is_ok_and(|m| name_eq(m, method)) {
                return Ok(Some(d));
            }
        }
    }
    Ok(None)
}

/// Map a `/P` value to an MDP permission level.
pub fn mdp_perm(value: i64) -> Option<MdpPerm> {
    match value {
        1 => Some(MdpPerm::NoChanges),
        2 => Some(MdpPerm::FillForms),
        3 => Some(MdpPerm::Annotate),
        _ => None,
    }
}

fn read_error(msg: &str) -> HankoError {
    HankoError::Malformed(SignatureValidationError::new(msg, None).to_string())
}

/// DocMDP level of a signature: its `/DocMDP` reference, else the `/Lock`
/// dictionary of its field (`docmdp_level`).
pub fn docmdp_level(
    file: &PdfFile,
    sig_object: &Dictionary,
    sig_field: Option<&Dictionary>,
    revision: usize,
) -> Result<Option<MdpPerm>> {
    if let Some(r) = reference_dict(file, sig_object, "DocMDP", revision)? {
        let params = r
            .get(b"TransformParams")
            .map_err(|_| read_error("Failed to read document permissions"))
            .and_then(|p| resolve(file, p, revision))?;
        let p = match params {
            Object::Dictionary(d) => d.get(b"P").ok().and_then(|o| o.as_i64().ok()),
            _ => None,
        };
        return p
            .and_then(mdp_perm)
            .map(Some)
            .ok_or_else(|| read_error("Failed to read document permissions"));
    }
    if let Some(field) = sig_field {
        if let Ok(lock) = field.get(b"Lock") {
            if let Object::Dictionary(lock) = resolve(file, lock, revision)? {
                if let Some(p) = lock.get(b"P").ok().and_then(|o| o.as_i64().ok()) {
                    return Ok(mdp_perm(p));
                }
            }
        }
    }
    Ok(None)
}

/// Text value of a PDF string (PDFDocEncoding treated as Latin-1, UTF-16BE
/// with BOM decoded).
pub fn pdf_text(obj: &Object) -> Option<String> {
    let Object::String(bytes, _) = obj else {
        return None;
    };
    if let Some(rest) = bytes.strip_prefix(&[0xfe, 0xff]) {
        let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
        return String::from_utf16(&units).ok();
    }
    Some(bytes.iter().map(|b| char::from(*b)).collect())
}

/// FieldMDP settings of a signature (`fieldmdp`, `FieldMDPSpec.from_pdf_object`).
pub fn fieldmdp(file: &PdfFile, sig_object: &Dictionary, revision: usize) -> Result<Option<FieldMdpAction>> {
    let Some(r) = reference_dict(file, sig_object, "FieldMDP", revision)? else {
        return Ok(None);
    };
    let err = || read_error("Failed to read /FieldMDP settings");
    let Object::Dictionary(params) = r.get(b"TransformParams").map_err(|_| err()).and_then(|p| resolve(file, p, revision))?
    else {
        return Err(err());
    };
    let action = params.get(b"Action").map_err(|_| err())?;
    let fields = |params: &Dictionary| -> Result<Vec<String>> {
        let Object::Array(arr) = params.get(b"Fields").map_err(|_| err()).and_then(|f| resolve(file, f, revision))? else {
            return Err(err());
        };
        arr.iter()
            .map(|o| resolve(file, o, revision).ok().as_ref().and_then(pdf_text).ok_or_else(err))
            .collect()
    };
    let spec = if name_eq(action, "All") {
        FieldMdpAction::All
    } else if name_eq(action, "Include") {
        FieldMdpAction::Include(fields(&params)?)
    } else if name_eq(action, "Exclude") {
        FieldMdpAction::Exclude(fields(&params)?)
    } else {
        return Err(err());
    };
    Ok(Some(spec))
}

/// Supported `/SubFilter` values (`SigSeedSubFilter`).
pub const SUBFILTERS: [&str; 4] = ["adbe.pkcs7.detached", "ETSI.CAdES.detached", "ETSI.RFC3161", "PBAD.PAdES"];

/// Check `/SubFilter` against a permitted list (`_validate_subfilter`).
pub fn validate_subfilter(
    subfilter: Option<&str>,
    permitted: &[&str],
    err_msg: &str,
) -> std::result::Result<(), SignatureValidationError> {
    let Some(sf) = subfilter else {
        return Err(SignatureValidationError::new(err_msg.replace("%s", "None"), None));
    };
    if !SUBFILTERS.contains(&sf) || !permitted.contains(&sf) {
        return Err(SignatureValidationError::new(err_msg.replace("%s", &format!("/{sf}")), None));
    }
    Ok(())
}

/// Review the revisions after the signed one (`evaluate_modifications`).
pub fn evaluate_modifications(
    file: &PdfFile,
    coverage: SignatureCoverageLevel,
    signed_revision: usize,
    policy: &dyn DiffPolicy,
    field_mdp: Option<&FieldMdpAction>,
    doc_mdp: Option<MdpPerm>,
) -> Result<DiffOutcome> {
    if coverage < SignatureCoverageLevel::EntireRevision {
        return Ok(DiffOutcome::Suspicious("Nonstandard signature coverage level".into()));
    }
    if coverage == SignatureCoverageLevel::EntireFile {
        return Ok(DiffOutcome::Reviewed(DiffResult {
            modification_level: ModificationLevel::None,
            changed_form_fields: Default::default(),
        }));
    }
    policy.review_file(file, signed_revision, field_mdp, doc_mdp)
}

/// Value ordering of pyHanko's `ModificationLevel` (for comparison with
/// `MDPPerm` values).
fn modification_level_value(level: ModificationLevel) -> u8 {
    match level {
        ModificationLevel::None => 0,
        ModificationLevel::LtaUpdates => 1,
        ModificationLevel::FormFilling => 2,
        ModificationLevel::Annotations => 3,
        ModificationLevel::Other => 4,
    }
}

/// `docmdp_ok` as `summarise_integrity_info` computes it.
pub fn docmdp_ok(
    diff: Option<&DiffOutcome>,
    docmdp: Option<MdpPerm>,
    coverage: SignatureCoverageLevel,
) -> Option<bool> {
    match diff {
        Some(outcome) => {
            let level = match outcome {
                DiffOutcome::Reviewed(r) => r.modification_level,
                DiffOutcome::Suspicious(_) => ModificationLevel::Other,
            };
            Some(
                !(level == ModificationLevel::Other
                    || docmdp.is_some_and(|d| modification_level_value(level) > d as u8)),
            )
        }
        None if coverage != SignatureCoverageLevel::EntireRevision => {
            Some(coverage == SignatureCoverageLevel::EntireFile)
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed(level: ModificationLevel) -> DiffOutcome {
        DiffOutcome::Reviewed(DiffResult {
            modification_level: level,
            changed_form_fields: Default::default(),
        })
    }

    #[test]
    fn docmdp_ok_rules() {
        use SignatureCoverageLevel::*;
        assert_eq!(docmdp_ok(Some(&reviewed(ModificationLevel::None)), None, EntireRevision), Some(true));
        assert_eq!(docmdp_ok(Some(&reviewed(ModificationLevel::Other)), None, EntireRevision), Some(false));
        assert_eq!(
            docmdp_ok(Some(&DiffOutcome::Suspicious("x".into())), None, EntireRevision),
            Some(false)
        );
        assert_eq!(
            docmdp_ok(Some(&reviewed(ModificationLevel::FormFilling)), Some(MdpPerm::NoChanges), EntireRevision),
            Some(false)
        );
        assert_eq!(
            docmdp_ok(Some(&reviewed(ModificationLevel::LtaUpdates)), Some(MdpPerm::NoChanges), EntireRevision),
            Some(true)
        );
        assert_eq!(
            docmdp_ok(Some(&reviewed(ModificationLevel::Annotations)), Some(MdpPerm::Annotate), EntireRevision),
            Some(true)
        );
        assert_eq!(docmdp_ok(None, None, EntireFile), Some(true));
        assert_eq!(docmdp_ok(None, None, ContiguousBlockFromStart), Some(false));
        assert_eq!(docmdp_ok(None, None, EntireRevision), None);
    }

    #[test]
    fn subfilters() {
        let msg = "%s is not a recognized SubFilter type in signatures.";
        let ok = ["adbe.pkcs7.detached", "ETSI.CAdES.detached", "PBAD.PAdES"];
        assert!(validate_subfilter(Some("ETSI.CAdES.detached"), &ok, msg).is_ok());
        let e = validate_subfilter(Some("ETSI.RFC3161"), &ok, msg).unwrap_err();
        assert_eq!(e.failure_message, "/ETSI.RFC3161 is not a recognized SubFilter type in signatures.");
        assert!(validate_subfilter(Some("adbe.x509.rsa_sha1"), &ok, msg).is_err());
        assert!(validate_subfilter(None, &ok, msg).is_err());
    }
}
