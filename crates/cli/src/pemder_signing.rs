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
fn option_scope(opts: &Options) -> Result<(), String> {
    if let Some(flag) = opts.repeated_flags.iter().next() {
        return Err(extended(&format!("Repeated --{flag}")));
    }
    for (key, values) in &opts.values {
        if ![
            "field",
            "key",
            "cert",
            "chain",
            "passfile",
            "pemder-setup",
            "validation-context",
        ]
        .contains(&key.as_str())
            || (key != "chain" && values.len() != 1)
        {
            return Err(extended(&format!("--{key}")));
        }
    }
    for flag in &opts.flags {
        if !["no-pass", "with-validation-info"].contains(&flag.as_str()) {
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
    let field = opts
        .get("field")
        .ok_or_else(|| extended("An implicit field"))?;
    if field.is_empty() || field.contains('/') {
        return Err(extended("A visible or empty field specification"));
    }
    Ok(())
}
fn config_scope(config: Option<&CliConfig>) -> Result<(), String> {
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
        if !allowed.contains(&normalized.as_str()) {
            return Err(extended(&format!("Configuration setting '{key}'")));
        }
    }
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
fn setup_schema(config: &CliConfig, name: &str) -> Result<(), String> {
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
fn material(
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
    run_with_input_policy(args, config, runtime, false)
}

/// Top-level PEM execution with authentication of the continuing PDF reader.
/// The original direct adapter retains its explicit plaintext-only contract.
pub(crate) fn run_with_authenticated_input(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    run_with_input_policy(args, config, runtime, true)
}

fn run_with_input_policy(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
    authenticated_input: bool,
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
    option_scope(&opts)?;
    config_scope(config)?;
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
    let reader = crate::read_for_update(&input, sigis_pdf::ReaderOptions::default())
        .map_err(|e| e.to_string())?;
    if reader.encrypted() && !authenticated_input {
        return Err(extended("Encrypted PDF input"));
    }
    // Authenticate the reader that owns the spent decode budget before handing
    // its state to the signer. Do not reopen plaintext or reset reader policy.
    let password = crate::software_signing::authenticate_document(&reader, &opts, runtime)?;
    let (signer, warn) = material(&opts, config, runtime)?;
    enforce_usage(&signer, &policy)?;
    let settings = SignOptions {
        strict: true,
        password,
        reopen_state: Some(PdfReopenState::from_reader(reader)),
        ..Default::default()
    };
    let mut metadata =
        PdfSignatureMetadata::pyhanko_defaults(opts.get("field").expect("validated field"));
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
    pdf_signer.signing_time = Some(runtime.now);
    pdf_signer.stamp_style = Some(CliConfig::parse("")?.stamp_style(None)?);
    crate::software_signing::sign_pdf_and_write(&pdf_signer, &input, &settings, &opts.paths[1])?;
    Ok(if warn {
        "WARNING: passphrase is empty. If you intended to use an unencrypted private key, use --no-pass instead.\n".into()
    } else {
        String::new()
    })
}
