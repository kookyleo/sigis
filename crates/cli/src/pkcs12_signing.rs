// Derived from pyHanko 0.38.1 CLI signing commands (MIT, see LICENSE-pyHanko).
//! Bounded PKCS#12 software signatures and automatic PAdES-LTA signatures.
use crate::{
    config::{CliConfig, KeyUsagePolicy},
    runtime::ValidationRuntime,
    software_signing::{options, prompt, read, Options},
};
use sigis_pades_sign::{
    pdf::writer::PdfReopenState, PdfSignatureMetadata, PdfSigner, SignOptions, SimpleSigner,
};
use sigis_pdf::{lopdf, rw_common::PdfHandlerExt};
use sigis_pki_core::{key_usage::cert_key_usages, sign::KeySigner};
use std::{collections::BTreeSet, io::BufRead, sync::Arc};

fn extended(setting: &str) -> String {
    format!("{setting} requires extended PKCS12 signing and is not supported by this command.")
}

/// Preserve the provider-independent missing-TSA diagnostic before opening keys.
/// The original negative uses PEM/DER, so this check precedes backend selection.
pub fn require_timestamp(args: &[String]) -> Result<(), String> {
    let indices = crate::argument_positions(args).collect::<Vec<_>>();
    if indices.iter().any(|&i| args[i] == "--use-pades-lta")
        && !indices
            .iter()
            .any(|&i| args[i] == "--timestamp-url" || args[i].starts_with("--timestamp-url="))
    {
        return Err("--timestamp-url is required when --use-pades-lta is specified.".into());
    }
    Ok(())
}

fn option_scope(opts: &Options, visible: bool) -> Result<(), String> {
    let allowed_values = [
        "field",
        "p12-setup",
        "passfile",
        "validation-context",
        "timestamp-url",
    ];
    let allowed_flags = [
        "no-pass",
        "with-validation-info",
        "use-pades-lta",
        "no-strict-syntax",
    ];
    if let Some(flag) = opts.repeated_flags.iter().next() {
        return Err(extended(&format!("Repeated --{flag}")));
    }
    for (key, values) in &opts.values {
        if !allowed_values.contains(&key.as_str()) || values.len() != 1 {
            return Err(extended(&format!("--{key}")));
        }
    }
    for key in &opts.flags {
        if !allowed_flags.contains(&key.as_str()) {
            return Err(extended(&format!("--{key}")));
        }
    }
    if opts
        .get("field")
        .is_some_and(|field| field.is_empty() || (!visible && field.contains('/')))
    {
        return Err(extended("A visible or empty field specification"));
    }
    Ok(())
}

fn config_scope(config: Option<&CliConfig>) -> Result<(), String> {
    let Some(config) = config else { return Ok(()) };
    let allowed = [
        "pkcs12-setups",
        "p12-setup",
        "validation-contexts",
        "default-validation-context",
        "time-tolerance",
        "retroactive-revinfo",
        "logging",
    ];
    let raw = config
        .raw_config
        .as_object()
        .ok_or_else(|| extended("Non-mapping configuration"))?;
    let mut seen = BTreeSet::new();
    for key in raw.keys() {
        let normal = key.replace('_', "-");
        if !seen.insert(normal.clone()) {
            return Err(format!(
                "Conflicting aliases in PKCS12 configuration: {normal}."
            ));
        }
        if !allowed.contains(&normal.as_str()) {
            return Err(extended(&format!("Configuration setting '{key}'")));
        }
    }
    // Check effective public fields too: a caller may mutate them without
    // replacing raw_config. Never replace the supplied object with raw data.
    let defaults = CliConfig::parse("")?;
    if config.default_stamp_style != defaults.default_stamp_style
        || config.stamp_styles != defaults.stamp_styles
    {
        return Err(extended("Configured signature appearance"));
    }
    if !config.identities.is_empty()
        || !config.plugin_endpoints.is_empty()
        || config.cache_dir.is_some()
    {
        return Err(extended("Identity, plugin or cache configuration"));
    }
    Ok(())
}

/// The full owner delegates this supported subset and preserves its other paths.
pub(crate) fn accepts_options(opts: &Options, config: Option<&CliConfig>) -> bool {
    accepts_options_for_field(opts, config, false)
}
fn accepts_options_for_field(opts: &Options, config: Option<&CliConfig>, visible: bool) -> bool {
    if option_scope(opts, visible).is_err() {
        return false;
    }
    // Invalid known-scope configuration must reach this adapter's refusal,
    // never fall back to a legacy loader that may ignore it.
    if config_scope(config).is_err() {
        return true;
    }
    if let (Some(config), Some(name)) = (config, opts.get("p12-setup")) {
        if config.key_usages(opts.get("validation-context")).is_ok()
            && setup_schema(config, name, true).is_ok()
        {
            let raw = &config.raw_config;
            let selected = raw
                .get("pkcs12-setups")
                .or_else(|| raw.get("pkcs12_setups"))
                .and_then(|setups| setups.get(name));
            let prefer = selected
                .and_then(|setup| setup.get("prefer-pss").or_else(|| setup.get("prefer_pss")));
            if prefer.is_some_and(|value| value != &serde_json::Value::Bool(false)) {
                return false;
            }
        }
    }
    true
}

fn setup_schema(config: &CliConfig, name: &str, allow_pss: bool) -> Result<(), String> {
    let raw = config
        .raw_config
        .as_object()
        .ok_or_else(|| extended("Non-mapping configuration"))?;
    let setups = raw
        .get("pkcs12-setups")
        .or_else(|| raw.get("pkcs12_setups"));
    let selected = setups
        .and_then(|setups| setups.get(name))
        .and_then(|setup| setup.as_object());
    let Some(selected) = selected else {
        return Ok(());
    }; // accepted accessor reports the exact missing-setup error
    let allowed = ["pfx-file", "pfx-passphrase", "other-certs", "prefer-pss"];
    let mut seen = BTreeSet::new();
    for (key, value) in selected {
        let normal = key.replace('_', "-");
        if !allowed.contains(&normal.as_str()) {
            return Err(format!("Unexpected key in PKCS12 setup: {key}."));
        }
        if !seen.insert(normal.clone()) {
            return Err(format!("Conflicting aliases in PKCS12 setup: {normal}."));
        }
        if normal == "prefer-pss" && !allow_pss && value != &serde_json::Value::Bool(false) {
            return Err(extended("Configured --prefer-pss"));
        }
    }
    Ok(())
}

// Pinned PKCS12 precedence is configured > passfile > prompt/no-pass.
// Keep this separate from the older generic PEM password adapter.
fn pkcs12_password(
    opts: &Options,
    configured: Option<&[u8]>,
    runtime: &ValidationRuntime,
) -> Result<Option<Vec<u8>>, String> {
    let file = opts
        .get("passfile")
        .map(|path| {
            std::fs::File::open(path)
                .map_err(|e| format!("Could not open passphrase file '{path}': {e}"))
        })
        .transpose()?;
    if let Some(configured) = configured {
        return Ok(Some(configured.to_vec()));
    }
    if let Some(file) = file {
        let mut line = String::new();
        std::io::BufReader::new(file)
            .read_line(&mut line)
            .map_err(|e| format!("Could not read UTF-8 passphrase file: {e}"))?;
        return Ok(Some(line.trim().as_bytes().to_vec()));
    }
    if opts.flag("no-pass") {
        return Ok(None);
    }
    Ok(Some(prompt("Key passphrase: ", runtime)?))
}

fn material(
    opts: &Options,
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<SimpleSigner, String> {
    if let Some(name) = opts.get("p12-setup") {
        let config = config.ok_or("The --p12-setup option requires a configuration file.")?;
        setup_schema(config, name, false)?;
        let setup = config
            .pkcs12_setup(name)
            .map_err(|e| format!("Error while reading PKCS#12 config: {e}"))?;
        let password = pkcs12_password(opts, setup.passphrase.as_deref(), runtime)?;
        setup
            .load_signer(password.as_deref())
            .map_err(|e| format!("Could not load key material: {e}"))
    } else {
        let password = pkcs12_password(opts, None, runtime)?;
        let pfx = &opts.paths[2];
        SimpleSigner::from_pkcs12_with_certs(&read(pfx)?, password.as_deref(), Vec::new())
            .map_err(|e| format!("Could not load key material: {e}"))
    }
}

fn enforce_usage(signer: &SimpleSigner, policy: &KeyUsagePolicy) -> Result<(), String> {
    let asserted = cert_key_usages(signer.signing_cert()).unwrap_or_default();
    if let Some(forbidden) = &policy.key_usage_forbidden {
        let blocked = asserted
            .intersection(forbidden)
            .cloned()
            .collect::<Vec<_>>();
        if !blocked.is_empty() {
            return Err(format!(
                "Signer certificate is not valid for the purpose: forbidden key usage {}",
                blocked.join(", ")
            ));
        }
    }
    let mut constraints = crate::usage::key_usage_constraints(policy);
    if constraints.key_usage.is_none() {
        constraints.key_usage = Some(BTreeSet::from(["non_repudiation".into()]));
    }
    constraints
        .validate(signer.signing_cert())
        .map_err(|e| format!("Signer certificate is not valid for the purpose: {e}"))
}

/// Execute a complete raw/setup PKCS#12 invocation, including automatic B-LTA.
///
/// Input is the full token list after `sign addsig`. Unsupported signing,
/// appearance, trust overrides and provider requirements reject explicitly.
/// The supplied configuration and runtime are consumed without partial copies.
pub fn run_with_runtime(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    run_with_field_policy(args, config, runtime, false)
}
pub(crate) fn run_with_visible_field(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    run_with_field_policy(args, config, runtime, true)
}
fn run_with_field_policy(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
    visible: bool,
) -> Result<String, String> {
    require_timestamp(args)?;
    let at = crate::argument_positions(args)
        .find(|&i| {
            matches!(
                args[i].as_str(),
                "pkcs12" | "pemder" | "identity" | "pkcs11" | "beid" | "csc"
            )
        })
        .ok_or_else(|| extended("A missing PKCS12 provider"))?;
    if args[at] != "pkcs12" {
        return Err(extended(&args[at]));
    }
    let mut combined = args[..at].to_vec();
    combined.extend_from_slice(&args[at + 1..]);
    let opts = options(&combined)?;
    let accepted = if visible {
        accepts_options_for_field(&opts, config, true)
    } else {
        accepts_options(&opts, config)
    };
    if !accepted {
        return Err(extended("Signing options or selected setup"));
    }
    option_scope(&opts, visible)?;
    config_scope(config)?;
    let field_spec = if visible {
        let spec = crate::fields::parse_field_spec(
            opts.get("field")
                .ok_or("A visible field specification is required.")?,
        )?;
        if spec.sig_field_name.is_empty()
            || spec
                .bbox
                .is_none_or(|(x1, y1, x2, y2)| x2 <= x1 || y2 <= y1)
        {
            return Err("A named nonempty visible signature field is required.".into());
        }
        Some(spec)
    } else {
        None
    };
    if opts.paths.len() < 2 || opts.paths.len() > 3 {
        return Err("Input and output file arguments are required.".into());
    }
    if opts.get("p12-setup").is_none() && opts.paths.len() != 3 {
        return Err("The PFX argument or the --p12-setup option must be provided.".into());
    }
    if let (Some(config), Some(name)) = (config, opts.get("p12-setup")) {
        setup_schema(config, name, false)?;
    }
    // Validate effective policy/schema before reading private keys or making
    // trust/network decisions, even when raw_config was not updated with it.
    let policy = config
        .map(|config| config.key_usages(opts.get("validation-context")))
        .transpose()?
        .unwrap_or_default();
    let context =
        crate::validation::context_from_config(config, opts.get("validation-context"), runtime)?;
    let signer = material(&opts, config, runtime)?;
    enforce_usage(&signer, &policy)?;
    let input = read(&opts.paths[0])?;
    let strict = !opts.flag("no-strict-syntax");
    let reader = crate::read_for_update(
        &input,
        sigis_pdf::ReaderOptions {
            strict,
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())?;
    if reader.encrypted() {
        return Err(extended("Encrypted PDF input"));
    }
    if let Some(spec) = &field_spec {
        let fields = sigis_pdf::signatures::enumerate_sig_fields(
            &reader,
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
    }
    let settings = SignOptions {
        // Pinned CLI addsig selects an existing field when --field is absent.
        existing_fields_only: opts.get("field").is_none(),
        strict,
        reopen_state: Some(PdfReopenState::from_reader(reader)),
        ..Default::default()
    };
    let field_name = field_spec
        .as_ref()
        .map(|spec| spec.sig_field_name.as_str())
        .or_else(|| opts.get("field"))
        .unwrap_or("");
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults(field_name);
    metadata.signer_key_usage = policy
        .key_usage
        .clone()
        .unwrap_or_else(|| BTreeSet::from(["non_repudiation".into()]))
        .into_iter()
        .collect();
    metadata.embed_validation_info =
        opts.flag("with-validation-info") || opts.flag("use-pades-lta");
    metadata.use_pades_lta = opts.flag("use-pades-lta");
    if metadata.use_pades_lta {
        metadata.subfilter = Some(sigis_pades_sign::SubFilter::Pades);
    }
    if metadata.embed_validation_info || opts.get("validation-context").is_some() {
        metadata.validation_context = Some(Arc::new(context));
    }
    let mut pdf_signer = PdfSigner::new(metadata, Arc::new(signer));
    if let Some(spec) = field_spec {
        let mut complete = crate::usage::key_usage_constraints(&policy);
        if complete.key_usage.is_none() {
            complete.key_usage = Some(BTreeSet::from(["non_repudiation".into()]));
        }
        pdf_signer = pdf_signer
            .with_signer_key_usage_policy(complete)
            .with_field_spec(spec);
    }
    pdf_signer.signing_time = Some(runtime.now);
    pdf_signer.stamp_style = Some(CliConfig::parse("")?.stamp_style(None)?);
    pdf_signer.timestamper = opts.get("timestamp-url").map(|url| {
        Arc::new(sigis_pki_fetch::HttpTimeStamper::new(url))
            as Arc<dyn sigis_pki_core::sign::TimeStamper>
    });
    crate::software_signing::sign_pdf_and_write(&pdf_signer, &input, &settings, &opts.paths[1])
}
