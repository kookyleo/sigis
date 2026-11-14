// Derived from pyHanko0.38.1 visible signing checks (MIT, see LICENSE-pyHanko).
//! Default visible PEM signatures through the existing state-aware adapter.
use crate::{config::CliConfig, runtime::ValidationRuntime, software_signing::Options};
use sigis_pades_sign::SigFieldSpec;
use sigis_pdf::{lopdf, rw_common::PdfHandlerExt, PdfFile};

/// Execute a directly selected PEM command requiring a named visible field.
///
/// Canonical CLI and explicit-runtime callers use this same bounded callback.
/// Credential, context and signing work stays in the existing PEM adapter.
/// Configured named styles and unsupported mandatory profiles still refuse.
pub fn run_with_runtime(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    crate::pemder_signing::run_with_visible_field(args, config, runtime)
}

pub(crate) fn field_spec(opts: &Options) -> Result<SigFieldSpec, String> {
    if opts.flag("existing-only") {
        return Err("Specifying field coordinates is incompatible with --existing-only".into());
    }
    let spec = crate::fields::parse_field_spec(
        opts.get("field")
            .ok_or("A visible field specification is required.")?,
    )?;
    if spec.sig_field_name.trim().is_empty()
        || spec.bbox.is_none_or(|(x1, y1, x2, y2)| {
            ![x1, y1, x2, y2].iter().all(|v| v.is_finite()) || x2 <= x1 || y2 <= y1
        })
    {
        return Err("A named nonempty visible signature field is required.".into());
    }
    Ok(spec)
}

pub(crate) fn check_raw_schema(
    config: Option<&CliConfig>,
    name: Option<&str>,
) -> Result<(), String> {
    let Some(config) = config else { return Ok(()) };
    // This is a schema-only view of original raw settings. It never builds a
    // trust context or replaces the original borrowed config/effective fields.
    let raw = CliConfig::parse(&config.raw_config.to_string())?;
    let selected = name.unwrap_or(&config.default_validation_context);
    if let Some(context) = raw.validation_contexts.get(selected) {
        let mapping = context
            .as_object()
            .ok_or("The validation context requires a dictionary.")?;
        let allowed = [
            "trust",
            "trust-replace",
            "other-certs",
            "time-tolerance",
            "retroactive-revinfo",
            "signer-key-usage-policy",
            "signer-key-usage",
            "signer-extd-key-usage",
        ];
        crate::config::reject_unsupported_outer_aliases(mapping, &allowed)?;
        for key in mapping.keys() {
            if !allowed.contains(&key.replace('_', "-").as_str()) {
                return Err(format!("Unknown setting '{key}' in validation context."));
            }
        }
        raw.key_usages(Some(selected))?;
    }
    Ok(())
}

pub(crate) fn ensure_visible(reader: &PdfFile, spec: &SigFieldSpec) -> Result<(), String> {
    ensure_visible_field(reader, Some(&spec.sig_field_name), true)
}

// Match the upstream visibility preflight over actual fields, including filled
// fields. The signer separately enforces unique empty-field selection and all
// signature/seed constraints; the preflight never substitutes a chosen field.
pub(crate) fn ensure_visible_field(
    reader: &PdfFile,
    name: Option<&str>,
    will_create: bool,
) -> Result<(), String> {
    let fields = sigis_pdf::signatures::enumerate_sig_fields(reader, None, name)
        .map_err(|error| error.to_string())?;
    let prefix = "You seem to be trying to create a visible signature";
    if let Some(field) = fields.first() {
        ensure_field_geometry(reader, field.field_ref, &field.fq_name)?;
    } else {
        let reason = match name {
            None => Some("the PDF did not contain any signature fields".to_string()),
            Some(name) if !will_create => {
                Some(format!("the field '{name}' does not exist in the PDF file"))
            }
            Some(_) => None,
        };
        if let Some(reason) = reason {
            let suggested_name = name.unwrap_or("NAME");
            return Err(format!(
                "{prefix}, but {reason}, and you did not specify a bounding box. Please specify the field as --field \"PAGE/X1,Y1,X2,Y2/{suggested_name}\" to create a visible signature field at the coordinates provided."
            ));
        }
    }
    // Use the actual consumer's field interpretation, without creating or
    // writing a field. The view shares this reader's authentication, strictness
    // and remaining decode budget; a fresh/default reader is never substituted.
    // Reader truthiness and writer resolution of /V, /T and inherited /FT can
    // differ on malformed forms, so a second selector in the CLI is unsafe.
    let state = sigis_pades_sign::pdf::writer::PdfReopenState::from_reader(reader.clone());
    let view = sigis_pades_sign::pdf::writer::PdfUpdate::open_with_state(reader.bytes(), state)
        .map_err(|error| error.to_string())?;
    let candidates = sigis_pades_sign::pdf::fields::enumerate_sig_fields(
        &view,
        if name.is_none() { Some(false) } else { None },
        name,
    )
    .map_err(|error| error.to_string())?;
    let selected = match (name, candidates.as_slice()) {
        (Some(_), fields) => fields.first(),
        (None, [selected]) => Some(selected),
        _ => None, // The signer retains its empty-field/ambiguity refusal.
    };
    if let Some(selected) = selected {
        ensure_field_geometry(reader, selected.id, &selected.name)?;
    }
    Ok(())
}

fn ensure_field_geometry(
    reader: &PdfFile,
    field_ref: lopdf::ObjectId,
    name: &str,
) -> Result<(), String> {
    let prefix = "You seem to be trying to create a visible signature";
    let object = reader
        .get_object_at(field_ref, None)
        .map_err(|error| error.to_string())?;
    let field_dictionary = object.as_dict().map_err(|error| error.to_string())?;
    let annotation = if let Ok(kids) = field_dictionary.get(b"Kids") {
        let kids = reader.resolve(kids).map_err(|error| error.to_string())?;
        let children = kids.as_array().map_err(|error| error.to_string())?;
        if children.len() != 1 || !matches!(children[0], lopdf::Object::Reference(_)) {
            return Err("A signature field must have exactly one child annotation, or be combined with its annotation.".into());
        }
        reader
            .resolve(&children[0])
            .map_err(|error| error.to_string())?
    } else {
        object
    };
    let rect = annotation
        .as_dict()
        .ok()
        .and_then(|dict| dict.get(b"Rect").ok())
        .map(|rect| reader.resolve(rect))
        .transpose()
        .map_err(|error| error.to_string())?;
    let numeric = rect
        .as_ref()
        .and_then(|rect| rect.as_array().ok())
        .filter(|values| values.len() == 4)
        .and_then(|values| {
            values
                .iter()
                .map(|value| {
                    let value = reader.resolve(value).ok()?;
                    match value {
                        lopdf::Object::Integer(value) => Some(value as f64),
                        lopdf::Object::Real(value) => Some(value as f64),
                        _ => None,
                    }
                })
                .collect::<Option<Vec<_>>>()
        });
    let visible =
        numeric.is_some_and(|r| r.iter().all(|v| v.is_finite()) && r[0] != r[2] && r[1] != r[3]);
    if !visible {
        return Err(format!(
            "{prefix}, but the field '{}' in the PDF is not a visible one. Please specify another field name if you need a visible signature.",
            name
        ));
    }
    Ok(())
}
