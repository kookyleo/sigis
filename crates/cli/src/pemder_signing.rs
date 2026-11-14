// Derived from pyHanko0.38.1 CLI simple signing (MIT, see LICENSE-pyHanko).
//! Bounded raw/setup PEM/DER signatures with complete configuration constraints.
use crate::{
    config::{CliConfig, KeyUsagePolicy},
    runtime::ValidationRuntime,
    software_signing::{options, prompt, read, Options},
};
use sigis_pades_sign::{
    pdf::writer::PdfReopenState, PdfSignatureMetadata, PdfSigner, SignOptions, SimpleSigner,
};
use sigis_pki_core::{cert::Cert, key_usage::cert_key_usages, sign::KeySigner};
use std::{collections::BTreeSet, io::BufRead, sync::Arc};

fn extended(requirement: &str) -> String {
    format!("{requirement} requires extended PEM/DER signing and is not supported by this command.")
}
fn option_scope(opts: &Options, visible: bool) -> Result<(), String> {
    if let Some(flag) = opts.repeated_flags.iter().next() {
        return Err(extended(&format!("Repeated --{flag}")));
    }
    for (key, values) in &opts.values {
        let supported = [
            "field",
            "key",
            "cert",
            "chain",
            "passfile",
            "pemder-setup",
            "validation-context",
            "reason",
            "location",
            "contact-info",
        ]
        .contains(&key.as_str())
            || (visible && ["style-name", "stamp-url"].contains(&key.as_str()));
        if !supported || (key != "chain" && values.len() != 1) {
            return Err(extended(&format!("--{key}")));
        }
    }
    for flag in &opts.flags {
        if ![
            "no-pass",
            "with-validation-info",
            "existing-only",
            "no-strict-syntax",
        ]
        .contains(&flag.as_str())
        {
            return Err(extended(&format!("--{flag}")));
        }
    }
    if opts.get("pemder-setup").is_some()
        && ["key", "cert", "chain"]
            .iter()
            .any(|key| opts.values.contains_key(*key))
    {
        return Err(extended(
            "Raw key/cert/chain options alongside a selected PEM/DER setup",
        ));
    }
    match opts.get("field") {
        Some(field) if field.is_empty() || (!visible && field.contains('/')) => {
            return Err(extended("A visible or empty field specification"));
        }
        _ => {}
    }
    Ok(())
}
fn config_scope(
    config: Option<&CliConfig>,
    identity: bool,
    visible_style: bool,
) -> Result<(), String> {
    let Some(config) = config else { return Ok(()) };
    let allowed = [
        "pemder-setups",
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
        let normalized = key.replace('_', "-");
        if !seen.insert(normalized.clone()) {
            return Err(format!(
                "Conflicting aliases in PEM/DER configuration: {normalized}."
            ));
        }
        if !allowed.contains(&normalized.as_str())
            && !(identity && normalized == "identities")
            && !(visible_style
                && ["stamp-styles", "default-stamp-style"].contains(&normalized.as_str()))
        {
            return Err(extended(&format!("Configuration setting '{key}'")));
        }
    }
    let defaults = CliConfig::parse("")?;
    if !visible_style
        && (config.default_stamp_style != defaults.default_stamp_style
            || config.stamp_styles != defaults.stamp_styles)
    {
        return Err(extended("Configured signature appearance"));
    }
    if (!identity && !config.identities.is_empty())
        || !config.plugin_endpoints.is_empty()
        || config.cache_dir.is_some()
    {
        return Err(extended("Identity, plugin or cache configuration"));
    }
    Ok(())
}
// Resolve only the selected visible appearance, retaining the original config.
// Raw settings are checked as schema; the effective style remains authoritative.
fn appearance_style(
    opts: &Options,
    config: Option<&CliConfig>,
    visible: bool,
) -> Result<sigis_pades_sign::stamp::StampStyle, String> {
    use sigis_pades_sign::stamp::StampStyle;
    let style = if visible {
        match config {
            Some(config) => {
                // Schema-check the raw selected style; the borrowed effective
                // config still supplies the appearance and complete context.
                let name = opts
                    .get("style-name")
                    .unwrap_or(&config.default_stamp_style);
                let raw = CliConfig::parse(&config.raw_config.to_string())?;
                if raw.stamp_styles.contains_key(name) {
                    raw.stamp_style(Some(name))?;
                }
                config.stamp_style(opts.get("style-name"))?
            }
            None if opts.get("style-name").is_some() => {
                return Err("Using named styles requires a configuration file.".into());
            }
            None => CliConfig::parse("")?.stamp_style(None)?,
        }
    } else {
        CliConfig::parse("")?.stamp_style(None)?
    };
    match (&style, opts.get("stamp-url")) {
        (StampStyle::Qr(_), None) => {
            return Err("QR stamp styles require the --stamp-url option.".into())
        }
        (StampStyle::Qr(_), Some(_)) => {}
        (_, Some(_)) => {
            return Err("The --stamp-url parameter is only meaningful for QR stamp styles.".into())
        }
        _ => {}
    }
    Ok(style)
}

pub(crate) fn setup_schema(config: &CliConfig, name: &str) -> Result<(), String> {
    let selected = config
        .raw_config
        .get("pemder-setups")
        .or_else(|| config.raw_config.get("pemder_setups"))
        .and_then(|v| v.get(name))
        .and_then(|v| v.as_object());
    let Some(selected) = selected else {
        return Ok(());
    }; // accepted accessor reports missing/malformed setup
    let mut seen = BTreeSet::new();
    for (key, value) in selected {
        let normalized = key.replace('_', "-");
        if !seen.insert(normalized.clone()) {
            return Err(format!(
                "Conflicting aliases in PEM/DER setup: {normalized}."
            ));
        }
        if ![
            "key-file",
            "cert-file",
            "key-passphrase",
            "other-certs",
            "prefer-pss",
            "prompt-passphrase",
        ]
        .contains(&normalized.as_str())
        {
            return Err(format!("Unexpected key in PEM/DER setup: {key}."));
        }
        if normalized == "prefer-pss" && value != &serde_json::Value::Bool(false) {
            return Err(extended("Configured --prefer-pss"));
        }
        if normalized == "prompt-passphrase" {
            return Err(extended("Configured prompt-passphrase"));
        }
    }
    Ok(())
}

// Configured passphrase wins over passfile and no-pass. Click opens a supplied
// passfile before dispatch, even when configured credentials take precedence.
fn password(
    opts: &Options,
    configured: Option<&[u8]>,
    runtime: &ValidationRuntime,
) -> Result<(Option<Vec<u8>>, bool), String> {
    let file = opts
        .get("passfile")
        .map(|path| {
            std::fs::File::open(path)
                .map_err(|e| format!("Could not open passphrase file '{path}': {e}"))
        })
        .transpose()?;
    if let Some(configured) = configured {
        return Ok((Some(configured.to_vec()), false));
    }
    if let Some(file) = file {
        let mut line = String::new();
        std::io::BufReader::new(file)
            .read_line(&mut line)
            .map_err(|e| format!("Could not read UTF-8 passphrase file: {e}"))?;
        return Ok((Some(line.trim().as_bytes().to_vec()), false));
    }
    if opts.flag("no-pass") {
        return Ok((None, false));
    }
    let value = prompt("Key passphrase: ", runtime)?;
    if value.is_empty() {
        Ok((None, true))
    } else {
        Ok((Some(value), false))
    }
}
fn raw_chain(opts: &Options) -> Result<Vec<Cert>, String> {
    let mut chain = Vec::new();
    for path in opts.values.get("chain").into_iter().flatten() {
        let data = read(path).map_err(|e| format!("Could not load certificates: {e}"))?;
        chain.extend(
            sigis_pades_sign::keys::load_certs_from_pemder_data(&data)
                .map_err(|e| format!("Could not load certificates: {e}"))?,
        );
    }
    Ok(chain)
}
pub(crate) fn material(
    opts: &Options,
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<(SimpleSigner, bool), String> {
    if let Some(name) = opts.get("pemder-setup") {
        let config = config.ok_or("The --pemder-setup option requires a configuration file.")?;
        let setup = config
            .pemder_setup(name)
            .map_err(|e| format!("Error while reading PEM/DER setup {name}: {e}"))?;
        let (pass, warn) = password(opts, setup.passphrase.as_deref(), runtime)?;
        let signer = setup
            .load_signer(pass.as_deref())
            .map_err(|e| format!("Could not load key material: {e}"))?;
        Ok((signer, warn))
    } else {
        let chain = raw_chain(opts)?;
        let (pass, warn) = password(opts, None, runtime)?;
        let key = opts.get("key").expect("validated key argument");
        let cert = opts.get("cert").expect("validated certificate argument");
        let signer = SimpleSigner::load(&read(key)?, &read(cert)?, pass.as_deref(), chain)
            .map_err(|e| format!("Could not load key material: {e}"))?;
        Ok((signer, warn))
    }
}
fn enforce_usage(signer: &SimpleSigner, policy: &KeyUsagePolicy) -> Result<(), String> {
    let asserted = cert_key_usages(signer.signing_cert()).unwrap_or_default();
    // Keep forbidden-only requirements independent of required-KU shortcuts.
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

/// Execute tokens after `sign addsig`, including the directly selected provider.
///
/// All supplied configuration stays authoritative. Unsupported mandatory inputs
/// reject explicitly; no basic/full-engine retry is attempted after a denial.
pub fn run_with_runtime(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    run_with_input_policy(args, config, runtime, false, false, false)
}

/// Top-level PEM execution with authentication of the continuing PDF reader.
/// The original direct adapter retains its explicit plaintext-only contract.
pub(crate) fn run_with_authenticated_input(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    run_with_input_policy(args, config, runtime, true, false, false)
}

pub(crate) fn run_with_identity(
    args: &[String],
    identity: &crate::identity_signing::PemIdentity<'_>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    run_with_input_policy(args, Some(identity.config()), runtime, false, true, false)
}

pub(crate) fn run_with_visible_field(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    run_with_input_policy(args, config, runtime, true, false, true)
}

fn run_with_input_policy(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
    authenticated_input: bool,
    identity: bool,
    visible: bool,
) -> Result<String, String> {
    let at = crate::argument_positions(args)
        .find(|&i| {
            matches!(
                args[i].as_str(),
                "pemder" | "pkcs12" | "identity" | "pkcs11" | "beid" | "csc"
            )
        })
        .ok_or_else(|| extended("A missing PEM/DER provider"))?;
    if args[at] != "pemder" {
        return Err(extended(&args[at]));
    }
    let mut combined = args[..at].to_vec();
    combined.extend_from_slice(&args[at + 1..]);
    let opts = options(&combined)?;
    // A named style also requests a visible existing field when coordinates
    // are omitted. Resolve it on the continuing authenticated reader below;
    // this does not create a field or alter implicit signing selection.
    let discover_existing = !identity
        && opts.get("style-name").is_some()
        && !opts.get("field").is_some_and(|field| field.contains('/'));
    let visible = visible || discover_existing;
    let field_spec = if visible && !discover_existing {
        Some(crate::signature_appearance::field_spec(&opts)?)
    } else {
        None
    };
    option_scope(&opts, visible)?;
    config_scope(config, identity, visible)?;
    if visible {
        crate::signature_appearance::check_raw_schema(config, opts.get("validation-context"))?;
    }
    let stamp_style = appearance_style(&opts, config, visible)?;
    if opts.paths.len() != 2 {
        return Err("Input and output file arguments are required.".into());
    }
    if let Some(name) = opts.get("pemder-setup") {
        let config = config.ok_or("The --pemder-setup option requires a configuration file.")?;
        setup_schema(config, name)?;
    } else if opts.get("key").is_none() || opts.get("cert").is_none() {
        return Err("Either both the --key and --cert options, or the --pemder-setup option must be provided.".into());
    }
    let policy = config
        .map(|c| c.key_usages(opts.get("validation-context")))
        .transpose()?
        .unwrap_or_default();
    let context =
        crate::validation::context_from_config(config, opts.get("validation-context"), runtime)?;
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
    if reader.encrypted() && !authenticated_input {
        return Err(extended("Encrypted PDF input"));
    }
    // Authenticate the reader that owns the spent decode budget before handing
    // its state to the signer. Do not reopen plaintext or reset reader policy.
    let password = crate::software_signing::authenticate_document(&reader, &opts, runtime)?;
    if let Some(spec) = &field_spec {
        crate::signature_appearance::ensure_visible(&reader, spec)?;
    } else if discover_existing {
        crate::signature_appearance::ensure_visible_field(&reader, opts.get("field"), false)?;
    }
    let (signer, warn) = material(&opts, config, runtime)?;
    enforce_usage(&signer, &policy)?;
    let settings = SignOptions {
        strict,
        existing_fields_only: discover_existing
            || opts.flag("existing-only")
            || opts.get("field").is_none(),
        password,
        reopen_state: Some(PdfReopenState::from_reader(reader)),
        ..Default::default()
    };
    let name = field_spec
        .as_ref()
        .map(|spec| spec.sig_field_name.as_str())
        .unwrap_or_else(|| opts.get("field").unwrap_or(""));
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults(name);
    metadata.reason = opts.get("reason").map(str::to_owned);
    metadata.location = opts.get("location").map(str::to_owned);
    metadata.contact_info = opts.get("contact-info").map(str::to_owned);
    metadata.signer_key_usage = policy
        .key_usage
        .clone()
        .unwrap_or_else(|| BTreeSet::from(["non_repudiation".into()]))
        .into_iter()
        .collect();
    metadata.embed_validation_info = opts.flag("with-validation-info");
    if metadata.embed_validation_info || opts.get("validation-context").is_some() {
        metadata.validation_context = Some(Arc::new(context));
    }
    let mut pdf_signer = PdfSigner::new(metadata, Arc::new(signer));
    if let Some(spec) = field_spec {
        pdf_signer = pdf_signer.with_field_spec(spec);
    }
    if identity || visible {
        let mut complete = crate::usage::key_usage_constraints(&policy);
        if complete.key_usage.is_none() {
            complete.key_usage = Some(BTreeSet::from(["non_repudiation".into()]));
        }
        pdf_signer = pdf_signer.with_signer_key_usage_policy(complete);
    }
    pdf_signer.signing_time = Some(runtime.now);
    pdf_signer.stamp_style = Some(stamp_style);
    if let Some(url) = opts.get("stamp-url") {
        pdf_signer
            .appearance_text_params
            .insert("url".into(), url.into());
    }
    crate::software_signing::sign_pdf_and_write(&pdf_signer, &input, &settings, &opts.paths[1])?;
    Ok(if warn {
        "WARNING: passphrase is empty. If you intended to use an unencrypted private key, use --no-pass instead.\n".into()
    } else {
        String::new()
    })
}
