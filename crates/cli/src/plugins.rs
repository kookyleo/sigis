//! Native signing command registry and configured identity resolution.
//!
//! The command semantics are derived from pyHanko 0.38.1's CLI plugin API
//! (MIT). Endpoint names refer to explicitly registered Rust implementations.
use crate::config::CliConfig;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Existing signing engines to which a plugin command delegates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginHandler {
    PemDer,
    Pkcs12,
    Pkcs11,
}
impl PluginHandler {
    /// Canonical built-in command for CLI routing.
    pub fn command(self) -> &'static str {
        match self {
            Self::PemDer => "pemder",
            Self::Pkcs12 => "pkcs12",
            Self::Pkcs11 => "pkcs11",
        }
    }
}

/// A registered command's public metadata and parameter contract.
#[derive(Clone, Debug)]
pub struct PluginDefinition {
    pub name: String,
    pub help_summary: String,
    pub handler: PluginHandler,
    pub unavailable_message: Option<String>,
    pub parameters: BTreeSet<String>,
}
impl PluginDefinition {
    /// Define a command backed by an existing native signing engine.
    pub fn new(name: impl Into<String>, help: impl Into<String>, handler: PluginHandler) -> Self {
        let parameters: &[&str] = match handler {
            PluginHandler::PemDer => &[
                "key",
                "cert",
                "chain",
                "passfile",
                "key_passfile",
                "no_pass",
                "prefer_pss",
                "pemder_setup",
                "setup",
            ],
            PluginHandler::Pkcs12 => &[
                "p12_pfx",
                "p12_passfile",
                "p12_setup",
                "pfx",
                "passfile",
                "setup",
                "chain",
                "no_pass",
                "prefer_pss",
            ],
            PluginHandler::Pkcs11 => &[
                "lib",
                "token_label",
                "cert_label",
                "cert_id",
                "key_label",
                "key_id",
                "slot_no",
                "pin",
                "signing_pin",
                "raw_mechanism",
                "pkcs11_setup",
                "setup",
                "chain",
                "other_certs",
                "other_certs_to_pull",
            ],
        };
        Self {
            name: name.into(),
            help_summary: help.into(),
            handler,
            unavailable_message: None,
            parameters: parameters.iter().map(|s| s.to_string()).collect(),
        }
    }
    /// Keep a command visible while rejecting execution with this reason.
    pub fn unavailable(mut self, message: impl Into<String>) -> Self {
        self.unavailable_message = Some(message.into());
        self
    }
    /// Extend a plugin's explicitly accepted parameter names.
    pub fn with_parameters(mut self, parameters: impl IntoIterator<Item = String>) -> Self {
        self.parameters.extend(parameters);
        self
    }
    fn validate(
        &self,
        identity: &str,
        parameters: &BTreeMap<String, Value>,
    ) -> Result<(), PluginError> {
        for key in parameters.keys() {
            if !self.parameters.contains(key) {
                return Err(PluginError::new(format!(
                    "Parameter '{key}' defined by '{identity}' not known to plugin '{}'.",
                    self.name
                )));
            }
        }
        let present = |k: &str| parameters.get(k).is_some_and(|v| !v.is_null());
        let has_setup = present("setup")
            || present(match self.handler {
                PluginHandler::PemDer => "pemder_setup",
                PluginHandler::Pkcs12 => "p12_setup",
                PluginHandler::Pkcs11 => "pkcs11_setup",
            });
        if !has_setup {
            match self.handler {
                PluginHandler::PemDer => {
                    for (k, option) in [("key", "--key"), ("cert", "--cert")] {
                        if !present(k) {
                            return Err(PluginError::new(format!(
                                "The {option} option must be provided."
                            )));
                        }
                    }
                }
                PluginHandler::Pkcs12 => {
                    if !present("p12_pfx") && !present("pfx") {
                        return Err(PluginError::new("The PFX file option must be provided."));
                    }
                }
                PluginHandler::Pkcs11 => {
                    if !present("lib") {
                        return Err(PluginError::new("The --lib option must be provided."));
                    }
                }
            }
        }
        Ok(())
    }
}

/// A CLI-facing plugin failure with its required exit status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginError {
    pub exit_code: i32,
    pub message: String,
}
impl PluginError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            exit_code: 1,
            message: message.into(),
        }
    }
}
impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}
impl std::error::Error for PluginError {}

/// A selected identity after native plugin and parameter validation.
#[derive(Clone, Debug)]
pub struct ResolvedIdentity {
    pub plugin: PluginDefinition,
    pub parameters: BTreeMap<String, Value>,
}

/// Native default commands, registered extension endpoints and active imports.
#[derive(Clone, Debug)]
pub struct PluginRegistry {
    defaults: BTreeMap<String, PluginDefinition>,
    endpoints: BTreeMap<String, PluginDefinition>,
    plugins: BTreeMap<String, PluginDefinition>,
}
impl Default for PluginRegistry {
    fn default() -> Self {
        let mut r = Self {
            defaults: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            plugins: BTreeMap::new(),
        };
        for (name, summary, handler) in [
            (
                "pemder",
                "Sign using PEM/DER key material",
                PluginHandler::PemDer,
            ),
            (
                "pkcs12",
                "Sign using a PKCS#12 archive",
                PluginHandler::Pkcs12,
            ),
            (
                "pkcs11",
                "Sign using a PKCS#11 token",
                PluginHandler::Pkcs11,
            ),
        ] {
            r.register(PluginDefinition::new(name, summary, handler));
        }
        r
    }
}
impl PluginRegistry {
    /// Register a command available even with configured plugins disabled.
    pub fn register(&mut self, plugin: PluginDefinition) {
        self.defaults
            .entry(plugin.name.clone())
            .or_insert_with(|| plugin.clone());
        self.plugins.entry(plugin.name.clone()).or_insert(plugin);
    }
    /// Bind a configuration endpoint to a native command implementation.
    pub fn register_endpoint(&mut self, endpoint: impl Into<String>, plugin: PluginDefinition) {
        self.endpoints.entry(endpoint.into()).or_insert(plugin);
    }
    /// Load configured native extensions and return nonfatal diagnostics.
    pub fn load(&mut self, config: Option<&CliConfig>, no_plugins: bool) -> Vec<String> {
        self.plugins = self.defaults.clone();
        let mut diagnostics = vec![];
        if !no_plugins {
            if let Some(c) = config {
                let mut seen = BTreeSet::new();
                for endpoint in &c.plugin_endpoints {
                    if !seen.insert(endpoint) {
                        continue;
                    }
                    if let Some(p) = self.endpoints.get(endpoint) {
                        self.plugins
                            .entry(p.name.clone())
                            .or_insert_with(|| p.clone());
                    } else {
                        diagnostics.push(format!("Plugins must be defined as registered native signing plugin classes; endpoint '{endpoint}' is not registered."));
                    }
                }
            }
        }
        diagnostics
    }
    /// Active command names in stable help order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.plugins.keys().map(String::as_str)
    }
    /// Render meaningful command summaries and unavailability markers.
    pub fn help(&self) -> String {
        self.plugins
            .values()
            .map(|p| {
                format!(
                    "  {}{}  {}",
                    p.name,
                    if p.unavailable_message.is_some() {
                        " [unavailable]"
                    } else {
                        ""
                    },
                    p.help_summary
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    /// Resolve a command, rejecting unavailable implementations explicitly.
    pub fn resolve(&self, name: &str) -> Result<&PluginDefinition, PluginError> {
        let p = self
            .plugins
            .get(name)
            .ok_or_else(|| PluginError::new(format!("Plugin '{name}' is not available.")))?;
        if let Some(message) = &p.unavailable_message {
            return Err(PluginError::new(message.clone()));
        }
        Ok(p)
    }
    /// Resolve an identity without coercing booleans or certificate path lists.
    pub fn resolve_identity(
        &self,
        config: Option<&CliConfig>,
        name: &str,
    ) -> Result<ResolvedIdentity, PluginError> {
        let c =
            config.ok_or_else(|| PluginError::new("Identity command requires a config file"))?;
        let identity = c
            .identities
            .get(name)
            .ok_or_else(|| PluginError::new(format!("Identity '{name}' not found")))?;
        let plugin = self.resolve(&identity.plugin)?;
        plugin.validate(name, &identity.parameters)?;
        Ok(ResolvedIdentity {
            plugin: plugin.clone(),
            parameters: identity.parameters.clone(),
        })
    }
}
