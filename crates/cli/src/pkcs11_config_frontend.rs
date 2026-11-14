//! Named PKCS11 configuration checks before real provider dispatch.

use crate::{
    argument_positions,
    config::{CliConfig, Pkcs11Setup},
    software_signing::{options, Options},
};
use std::collections::{BTreeMap, BTreeSet};

fn parse_options(args: &[String]) -> Result<Options, String> {
    const VALUES: &[&str] = &[
        "p11-setup",
        "lib",
        "token-label",
        "cert-label",
        "key-label",
        "slot-no",
        "other-cert",
        "other-cert-file",
    ];
    const FLAGS: &[&str] = &["skip-user-pin", "raw-mechanism"];
    let provider = argument_positions(args)
        .find(|&index| args[index] == "pkcs11")
        .ok_or("A PKCS#11 provider command is required.")?;
    let mut removed = BTreeSet::from([provider]);
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut flags = BTreeSet::new();
    let mut repeated_flags = BTreeSet::new();
    // Routing positions exclude common option values: a reason or field value
    // that resembles a provider option must stay with the common parser.
    for index in argument_positions(args) {
        let Some(option) = args[index].strip_prefix("--") else {
            continue;
        };
        let (key, inline) = option
            .split_once('=')
            .map(|(key, value)| (key, Some(value)))
            .unwrap_or((option, None));
        if VALUES.contains(&key) {
            let value = if let Some(value) = inline {
                value.to_owned()
            } else {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("Option --{key} requires an argument."))?;
                removed.insert(index + 1);
                value.clone()
            };
            removed.insert(index);
            values.entry(key.to_owned()).or_default().push(value);
        } else if FLAGS.contains(&key) && inline.is_none() {
            removed.insert(index);
            if !flags.insert(key.to_owned()) {
                repeated_flags.insert(key.to_owned());
            }
        }
    }
    let common: Vec<String> = args
        .iter()
        .enumerate()
        .filter(|(index, _)| !removed.contains(index))
        .map(|(_, value)| value.clone())
        .collect();
    let mut parsed = options(&common)?;
    parsed.values.extend(values);
    parsed.flags.extend(flags);
    parsed.repeated_flags.extend(repeated_flags);
    Ok(parsed)
}

pub(crate) fn run(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &crate::runtime::ValidationRuntime,
) -> Result<String, String> {
    let options = parse_options(args)?;
    if options.paths.len() != 2 {
        return Err("PKCS#11 signing requires an input and output file.".into());
    }
    let setup: Option<Pkcs11Setup> = match options.get("p11-setup").filter(|name| !name.is_empty())
    {
        Some(name) => {
            let config = config.ok_or("The --p11-setup option requires a configuration file")?;
            Some(
                config
                    .pkcs11_setup(name)
                    .map_err(|_| format!("Error while reading PKCS#11 config {name}"))?,
            )
        }
        None => None,
    };
    if setup.is_none()
        && (options.get("lib").is_none_or(str::is_empty)
            || options.get("cert-label").is_none_or(str::is_empty))
    {
        return Err("The parameters --lib and --cert-label are required.".into());
    }
    crate::pkcs11_signing::run(&options, setup.as_ref(), config, runtime)
}
