//! pyHanko-compatible configuration, native plugins, PDF cryptography and fields.
pub mod config;
pub mod crypt;
pub mod fields;
pub mod plugins;
pub mod runtime;

use clap::{Arg, ArgAction, Command};
use std::{fs, io::Write, path::Path};

/// Captured process output, used by the executable and integration tests.
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

fn command() -> Command {
    let mut c = Command::new("pyhanko")
        .version(env!("CARGO_PKG_VERSION"))
        .about("PDF signatures, validation and document utilities")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("no-plugins")
                .long("no-plugins")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .subcommand_required(true);
    for name in ["sign", "stamp", "encrypt", "decrypt"] {
        c = c.subcommand(
            Command::new(name).disable_help_flag(true).arg(
                Arg::new("arguments")
                    .num_args(0..)
                    .allow_hyphen_values(true)
                    .trailing_var_arg(true),
            ),
        );
    }
    c
}

/// Run a command without terminating the caller.
pub fn run(args: &[String]) -> Output {
    run_with_registry(args, &plugins::PluginRegistry::default())
}

/// Run with explicitly registered native signing plugins.
pub fn run_with_registry(args: &[String], registry: &plugins::PluginRegistry) -> Output {
    run_with_runtime(args, registry, &runtime::ValidationRuntime::default())
}

/// Run cryptography with explicit runtime services and native plugin dispatch.
/// Signing, validation and stamp engines are unavailable in this increment.
pub fn run_with_runtime(
    args: &[String],
    registry: &plugins::PluginRegistry,
    runtime: &runtime::ValidationRuntime,
) -> Output {
    let matches = match command()
        .try_get_matches_from(std::iter::once("pyhanko".to_owned()).chain(args.iter().cloned()))
    {
        Ok(m) => m,
        Err(e) => {
            let code = e.exit_code();
            return Output {
                code,
                stdout: if code == 0 {
                    e.to_string()
                } else {
                    String::new()
                },
                stderr: if code != 0 {
                    e.to_string()
                } else {
                    String::new()
                },
            };
        }
    };
    let explicit = matches.get_one::<String>("config");
    let path = explicit.map(String::as_str).unwrap_or("pyhanko.yml");
    let config = match fs::read_to_string(path) {
        Ok(text) => match config::CliConfig::parse(&text) {
            Ok(c) => Some(c),
            Err(e) => return error(format!("Could not process CLI configuration: {e}"), None),
        },
        Err(e) if explicit.is_none() && e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return error(
                if explicit.is_some() {
                    format!("Failed to read configuration: {e}")
                } else {
                    format!("Failed to read pyhanko.yml: {e}")
                },
                None,
            )
        }
    };
    let mut registry = registry.clone();
    let diagnostics = registry.load(config.as_ref(), matches.get_flag("no-plugins"));
    let (name, sub) = matches.subcommand().expect("required subcommand");
    let values: Vec<String> = sub
        .get_many::<String>("arguments")
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    let result = match name {
        "encrypt" | "decrypt" => {
            let mut crypt_args = vec![name.to_owned()];
            crypt_args.extend(values.iter().cloned());
            crypt::run_with_runtime(&crypt_args, runtime)
        }
        "sign" => match values.first().map(String::as_str) {
            Some("list" | "addfields") => fields::run(&values),
            Some("addsig") => run_signing(&values[1..], config.as_ref(), &registry),
            Some("--help") | None => Ok("Usage: pyhanko sign [COMMAND]\nCommands: list, addfields, addsig (native registry help and identity validation only)\n".into()),
            Some(command) => Err(format!("Command '{command}' is not available in this cryptography-and-fields increment.")),
        },
        _ => Err(format!("Command '{name}' is not available in this cryptography-and-fields increment.")),
    };
    let mut output = match result {
        Ok(stdout) => Output {
            code: 0,
            stdout,
            stderr: String::new(),
        },
        Err(message)
            if argument_positions(&values).any(|i| values[i] == "--help")
                && message.contains("Usage:") =>
        {
            Output {
                code: 0,
                stdout: message,
                stderr: String::new(),
            }
        }
        Err(message) => error(message, config.as_ref().map(|c| c.root_output())),
    };
    for message in diagnostics {
        output.stderr.push_str(&message);
        output.stderr.push('\n');
    }
    output
}

fn error(mut message: String, destination: Option<&str>) -> Output {
    // Lower-layer adapters preserve the decoding error text through their
    // own error types. Keep the reference CLI's actionable decoding advice.
    if message.contains("Decoded stream data exceeds the limit of ")
        && !message.contains("rerun with --no-decode-limits")
    {
        message.push_str("; rerun with --no-decode-limits to remove PDF decoding limits.");
    }
    let text = format!("Error: {message}\n");
    match destination.unwrap_or("stderr") {
        "stdout" => Output {
            code: 1,
            stdout: text,
            stderr: String::new(),
        },
        "stderr" => Output {
            code: 1,
            stdout: String::new(),
            stderr: text,
        },
        name => {
            let result = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(name))
                .and_then(|mut f| f.write_all(text.as_bytes()));
            let stderr = match result {
                Ok(()) => text,
                Err(e) => format!("{text}Failed to write log: {e}\n"),
            };
            Output {
                code: 1,
                stdout: String::new(),
                stderr,
            }
        }
    }
}

fn run_signing(
    args: &[String],
    config: Option<&config::CliConfig>,
    registry: &plugins::PluginRegistry,
) -> Result<String, String> {
    let positions = argument_positions(args).collect::<Vec<_>>();
    let provider = positions
        .iter()
        .copied()
        .find(|&i| args[i] == "identity" || registry.names().any(|name| name == args[i]));
    if positions.iter().any(|&i| args[i] == "--help") {
        if let Some(i) = provider {
            if args[i] != "identity" {
                registry.resolve(&args[i]).map_err(|e| e.message)?;
            }
        }
        return Ok(format!(
            "Usage: pyhanko sign addsig [OPTIONS] COMMAND\n{}\n",
            registry.help()
        ));
    }
    let Some(i) = provider else {
        return Err("A signing provider command is required; signing engines are not available in this increment.".into());
    };
    let mut rewritten = args[..i].to_vec();
    if args[i] == "identity" {
        let name = args.get(i + 1).ok_or("An identity name is required.")?;
        let identity = registry
            .resolve_identity(config, name)
            .map_err(|e| e.message)?;
        rewritten.push(identity.plugin.handler.command().to_owned());
        for (key, value) in identity.parameters {
            let key = key.replace('_', "-");
            match value {
                serde_json::Value::Bool(true) => rewritten.push(format!("--{key}")),
                serde_json::Value::Bool(false) | serde_json::Value::Null => {}
                serde_json::Value::String(v) => rewritten.extend([format!("--{key}"), v]),
                serde_json::Value::Array(values) => {
                    for value in values {
                        rewritten.extend([
                            format!("--{key}"),
                            value
                                .as_str()
                                .ok_or("Identity list parameters require strings.")?
                                .to_owned(),
                        ]);
                    }
                }
                _ => return Err(format!("Unsupported identity parameter '{key}'.")),
            }
        }
        rewritten.extend_from_slice(&args[i + 2..]);
    } else {
        let plugin = registry.resolve(&args[i]).map_err(|e| e.message)?;
        rewritten.push(plugin.handler.command().to_owned());
        rewritten.extend_from_slice(&args[i + 1..]);
    }
    Err(format!(
        "Signing engine '{}' is not available in this increment.",
        rewritten[i]
    ))
}

/// Option and positional token indices, excluding option values.
/// Used only for routing; each command still validates its own full grammar.
pub(crate) fn argument_positions(args: &[String]) -> impl Iterator<Item = usize> + '_ {
    const VALUES: &[&str] = &[
        "field",
        "style-name",
        "stamp-url",
        "timestamp-url",
        "validation-context",
        "trust",
        "other-certs",
        "key",
        "cert",
        "chain",
        "passfile",
        "pemder-setup",
        "p12-setup",
        "p11-setup",
        "reason",
        "location",
        "contact-info",
        "name",
        "docmdp-permissions",
        "password",
        "md-algorithm",
        "lib",
        "token-label",
        "slot-no",
        "cert-label",
        "key-label",
        "other-cert",
        "other-cert-file",
        "recipient",
        "text-param",
        "page",
        "validation-time",
        "detached",
        "eutl-territories",
    ];
    let mut index = 0;
    let mut options = true;
    std::iter::from_fn(move || {
        while index < args.len() {
            let current = index;
            index += 1;
            if args[current] == "--" {
                options = false;
                continue;
            }
            if !options {
                continue;
            }
            if let Some(key) = args[current].strip_prefix("--") {
                if !key.contains('=') && VALUES.contains(&key) {
                    index += 1;
                }
            }
            return Some(current);
        }
        None
    })
}

/// Resolve live indirect objects before handing input to a legacy editor.
/// This enforces object-stream limits at the CLI boundary. It does not replace
/// transfer of the remaining decode budget through downstream reopen APIs.
pub(crate) fn read_for_update(
    bytes: &[u8],
    options: sigis_pdf::ReaderOptions,
) -> Result<sigis_pdf::PdfFile, sigis_pdf::PdfError> {
    let file = sigis_pdf::PdfFile::parse_with(bytes, options)?;
    // Signing authenticates encrypted input in its downstream operation.
    // That operation still requires the accepted budget-preserving interface.
    if !file.encrypted() {
        let refs = (0..file.total_revisions())
            .flat_map(|revision| file.xrefs().explicit_refs_in_revision(revision))
            .collect::<std::collections::BTreeSet<_>>();
        for id in refs {
            if file.xrefs().get(id).is_some() {
                file.get_object_at(id, None)?;
            }
        }
    }
    Ok(file)
}
