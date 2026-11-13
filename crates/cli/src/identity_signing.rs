// Derived from pyHanko0.38.1 CLI identity dispatch (MIT, see LICENSE-pyHanko).
//! Bounded built-in PEM identities, preserving the complete caller configuration.
use crate::{
    config::CliConfig,
    plugins::{PluginHandler, PluginRegistry},
    runtime::ValidationRuntime,
};
use serde_json::Value;
use std::collections::BTreeMap;

/// Unforgeable outside this module; the ordinary adapter never receives this
/// capability. Its config is the same borrowed object that was validated.
pub(crate) struct PemIdentity<'a> {
    config: &'a CliConfig,
}
impl PemIdentity<'_> {
    pub(crate) fn config(&self) -> &CliConfig {
        self.config
    }
}

fn raw_parameters(config: &CliConfig, name: &str) -> Result<BTreeMap<String, Value>, String> {
    let raw = config
        .raw_config
        .as_object()
        .ok_or("Identity configuration must be a mapping.")?;
    let identity = raw
        .get("identities")
        .and_then(|v| v.get(name))
        .and_then(Value::as_object)
        .ok_or("Selected identity requires consistent raw and effective configuration.")?;
    for key in identity.keys() {
        if !["plugin", "parameters"].contains(&key.as_str()) {
            return Err(format!("Unexpected key in selected identity: {key}."));
        }
    }
    let effective = config
        .identities
        .get(name)
        .ok_or_else(|| format!("Identity '{name}' not found"))?;
    if identity.get("plugin").and_then(Value::as_str) != Some(effective.plugin.as_str()) {
        return Err("Conflicting raw and effective identity plugins.".into());
    }
    let parameters = identity
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or("Identity parameters must be a mapping.")?;
    let mut normalized = BTreeMap::new();
    for (key, value) in parameters {
        let key = key.replace('-', "_");
        if normalized
            .insert(key.clone(), value.clone())
            .is_some_and(|previous| previous != *value)
        {
            return Err(format!("Conflicting identity parameter aliases: {key}."));
        }
    }
    if normalized != effective.parameters {
        return Err("Conflicting raw and effective identity parameters.".into());
    }
    Ok(normalized)
}

/// Execute the actual identity callback with an existing parsed configuration.
///
/// Arguments follow `sign addsig`. Canonical CLI and programmatic callers use
/// this same path. Unsupported providers, parameter shapes and mandatory
/// profiles refuse; no full-engine retry or config projection is performed.
pub fn run_with_runtime(
    args: &[String],
    config: Option<&CliConfig>,
    registry: &PluginRegistry,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    let at = crate::argument_positions(args)
        .find(|&i| args[i] == "identity")
        .ok_or("An identity command is required.")?;
    let name = args.get(at + 1).ok_or("An identity name is required.")?;
    // Preserve the previously accepted registry diagnostics before any material I/O.
    let identity = registry
        .resolve_identity(config, name)
        .map_err(|e| e.message)?;
    let config = config.ok_or("Identity command requires a config file")?;
    if identity.plugin.name != "pemder" || identity.plugin.handler != PluginHandler::PemDer {
        return Err(
            "Only directly configured built-in PEM/DER identities are supported by this command."
                .into(),
        );
    }
    let parameters = raw_parameters(config, name)?;
    let mut rewritten = args[..at].to_vec();
    rewritten.push("pemder".into());
    for (key, value) in &parameters {
        match (key.as_str(), value) {
            ("key" | "cert", Value::String(value)) => {
                rewritten.extend([format!("--{key}"), value.clone()])
            }
            ("chain", Value::Array(values)) => {
                for value in values {
                    rewritten.extend([
                        "--chain".into(),
                        value
                            .as_str()
                            .ok_or("Identity chain entries must be strings.")?
                            .into(),
                    ]);
                }
            }
            ("no_pass", Value::Bool(true)) => rewritten.push("--no-pass".into()),
            ("no_pass", Value::Bool(false)) => {}
            ("key" | "cert" | "chain" | "no_pass", _) => {
                return Err(format!(
                    "Invalid value type for identity parameter '{key}'."
                ))
            }
            _ => {
                return Err(format!(
                    "Identity parameter '{key}' is not supported by this bounded PEM/DER command."
                ))
            }
        }
    }
    rewritten.extend_from_slice(&args[at + 2..]);
    crate::pkcs12_signing::require_timestamp(&rewritten)?;
    let permission = PemIdentity { config };
    crate::pemder_signing::run_with_identity(&rewritten, &permission, runtime)
}
