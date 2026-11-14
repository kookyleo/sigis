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
    let fields = sigis_pdf::signatures::enumerate_sig_fields(
        reader,
        Some(false),
        Some(&spec.sig_field_name),
    )
    .map_err(|error| error.to_string())?;
    for field in fields {
        let object = reader
            .get_object_at(field.field_ref, None)
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
        let visible = numeric
            .is_some_and(|r| r.iter().all(|v| v.is_finite()) && r[0] != r[2] && r[1] != r[3]);
        if !visible {
            return Err(format!(
                "The field '{}' in the PDF is not a visible one.",
                spec.sig_field_name
            ));
        }
    }

    Ok(())
}
