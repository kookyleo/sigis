//! pyHanko-compatible configuration and CLI boundary.
pub mod config;

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

/// Run configuration loading before explicitly rejecting unavailable commands.
pub fn run(args: &[String]) -> Output {
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
    let (name, _) = matches.subcommand().expect("required subcommand");
    error(
        format!("Command '{name}' is not available in this configuration-only increment."),
        config.as_ref().map(|c| c.root_output()),
    )
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
