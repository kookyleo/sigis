// Derived from pyHanko0.38.1 CLI detached signing (MIT, see LICENSE-pyHanko).
//! Bounded PEM/DER detached CMS generation; this command issues no trust verdict.
use crate::{
    config::CliConfig,
    runtime::ValidationRuntime,
    software_signing::{options, read, Options},
};
use sigis_pades_sign::{
    cms::CmsSigner, signer::select_suitable_signing_md, CmsSignedAttributes, CmsSignerOptions,
};
use sigis_pki_core::sign::{KeySigner, TimeStamper};
use std::collections::BTreeMap;

fn unsupported(requirement: &str) -> String {
    format!("Detached signing does not support {requirement}.")
}
fn check_options(opts: &Options) -> Result<(), String> {
    // Match the upstream error before key/password handling or PDF field logic.
    if opts.get("field").is_some() {
        return Err("--field is not compatible with --detach".into());
    }
    if let Some(flag) = opts.repeated_flags.iter().next() {
        return Err(unsupported(&format!("repeated --{flag}")));
    }
    if opts.flag("detach") == opts.flag("detach-pem") {
        return Err(unsupported(
            "missing or conflicting detached encoding flags",
        ));
    }
    for (key, values) in &opts.values {
        if ![
            "key",
            "cert",
            "chain",
            "passfile",
            "pemder-setup",
            "timestamp-url",
        ]
        .contains(&key.as_str())
            || (key != "chain" && values.len() != 1)
        {
            return Err(unsupported(&format!("--{key}")));
        }
    }
    for flag in &opts.flags {
        if !["detach", "detach-pem", "no-pass"].contains(&flag.as_str()) {
            return Err(unsupported(&format!("--{flag}")));
        }
    }
    if opts.get("pemder-setup").is_some()
        && ["key", "cert", "chain"]
            .iter()
            .any(|key| opts.values.contains_key(*key))
    {
        return Err(unsupported(
            "raw key/cert/chain options alongside a selected PEM/DER setup",
        ));
    }
    Ok(())
}
fn check_config(config: Option<&CliConfig>) -> Result<(), String> {
    let Some(config) = config else {
        return Ok(());
    };
    let raw = config
        .raw_config
        .as_object()
        .ok_or_else(|| unsupported("non-mapping configuration"))?;
    let mut seen = BTreeMap::new();
    for (key, value) in raw {
        let normalized = key.replace('_', "-");
        if !["pemder-setups", "logging"].contains(&normalized.as_str()) {
            return Err(unsupported(&format!("configuration setting '{key}'")));
        }
        if let Some((previous_key, previous_value)) = seen.insert(normalized, (key, value)) {
            if previous_value != value {
                return Err(format!(
                    "Conflicting configuration aliases '{previous_key}' and '{key}'."
                ));
            }
        }
    }
    // Public effective fields remain authoritative even if raw_config was not
    // mutated with them. No selected context is reconstructed or discarded.
    let defaults = CliConfig::parse("")?;
    if config.validation_contexts != defaults.validation_contexts
        || config.default_validation_context != defaults.default_validation_context
        || config.time_tolerance != defaults.time_tolerance
        || config.retroactive_revinfo != defaults.retroactive_revinfo
    {
        return Err(unsupported(
            "effective validation context or policy settings",
        ));
    }
    if config.stamp_styles != defaults.stamp_styles
        || config.default_stamp_style != defaults.default_stamp_style
        || !config.identities.is_empty()
        || !config.plugin_endpoints.is_empty()
        || config.cache_dir.is_some()
    {
        return Err(unsupported(
            "effective appearance, identity, plugin or cache settings",
        ));
    }
    Ok(())
}
fn pem_encode(der: &[u8]) -> String {
    let body = openssl::base64::encode_block(der);
    let mut output = String::from("-----BEGIN PKCS7-----\n");
    for line in body.as_bytes().chunks(64) {
        // Base64 output is ASCII.
        output.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        output.push('\n');
    }
    output.push_str("-----END PKCS7-----\n");
    output
}
/// Generate a detached CMS from directly selected PEM/DER credentials.
///
/// Arguments follow `sign addsig`, including `pemder`. Only credential and
/// logging configuration is supported. Unsupported mandatory profiles refuse
/// before material, TSA access and signature-output writes. A timestamp response
/// uses the shared HTTP request binding; generation does not assert TSA trust.
/// Purpose, chain and revocation validation is a separate CMS validation task.
pub fn run_with_runtime(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    let at = crate::argument_positions(args)
        .find(|&i| {
            matches!(
                args[i].as_str(),
                "pemder" | "pkcs12" | "identity" | "pkcs11" | "beid" | "csc"
            )
        })
        .ok_or_else(|| unsupported("a missing PEM/DER provider"))?;
    if args[at] != "pemder" {
        return Err(unsupported(
            "a provider other than directly selected PEM/DER",
        ));
    }
    let mut combined = args[..at].to_vec();
    combined.extend_from_slice(&args[at + 1..]);
    let opts = options(&combined)?;
    check_options(&opts)?;
    check_config(config)?;
    if opts.paths.len() != 2 {
        return Err("Input and output file arguments are required.".into());
    }
    if let Some(name) = opts.get("pemder-setup") {
        let config = config.ok_or("The --pemder-setup option requires a configuration file.")?;
        crate::pemder_signing::setup_schema(config, name)?;
    } else if opts.get("key").is_none() || opts.get("cert").is_none() {
        return Err("Either both the --key and --cert options, or the --pemder-setup option must be provided.".into());
    }
    let input = read(&opts.paths[0])?;
    let (signer, warn) = crate::pemder_signing::material(&opts, config, runtime)?;
    let digest = select_suitable_signing_md(&signer.signing_cert().public_key());
    let tsa = opts
        .get("timestamp-url")
        .map(sigis_pki_fetch::HttpTimeStamper::new);
    let settings = CmsSignedAttributes {
        signing_time: if tsa.is_some() {
            None
        } else {
            Some(runtime.now)
        },
        ..Default::default()
    };
    let der = CmsSigner {
        signer: &signer,
        options: &CmsSignerOptions::default(),
    }
    .sign_general_data(
        &input,
        digest,
        true,
        false,
        tsa.as_ref().map(|tsa| tsa as &dyn TimeStamper),
        &settings,
    )
    .map_err(|error| error.to_string())?;
    let output = if opts.flag("detach-pem") {
        pem_encode(&der).into_bytes()
    } else {
        der
    };
    std::fs::write(&opts.paths[1], output).map_err(|error| error.to_string())?;
    Ok(if warn {
        "WARNING: passphrase is empty. If you intended to use an unencrypted private key, use --no-pass instead.\n".into()
    } else {
        String::new()
    })
}
