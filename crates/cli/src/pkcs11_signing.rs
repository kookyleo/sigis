//! Bounded real PKCS11 signing with typed configuration and inherited PDF state.
use crate::{
    config::{CliConfig, PinEntry, Pkcs11Setup, SigningPinEntry},
    runtime::{
        Pkcs11SigningPinPrompt, Pkcs11SigningPinPromptError, Pkcs11UserPinPrompt,
        Pkcs11UserPinPromptError, ValidationRuntime,
    },
    software_signing::Options,
};
use serde_json::Value;
use sigis_pades_sign::{
    pdf::writer::PdfReopenState,
    pkcs11::{open_signer, PinEntryMode, Pkcs11Config, SigningPinEntryMode, TokenCriteria},
    PdfSignatureMetadata, PdfSigner, SignOptions,
};
use sigis_pki_core::algorithms::DigestAlgorithm;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn unsupported(requirement: &str) -> String {
    format!("Unsupported PKCS#11 signing requirement: {requirement}.")
}

fn normalized<'a>(
    value: &'a Value,
    component: &str,
) -> Result<BTreeMap<String, &'a Value>, String> {
    let mut result = BTreeMap::new();
    for (key, value) in value
        .as_object()
        .ok_or_else(|| format!("{component} must be a mapping."))?
    {
        let name = key.replace('_', "-");
        if result.insert(name.clone(), value).is_some() {
            return Err(format!("Conflicting aliases in {component}: {name}."));
        }
    }
    Ok(result)
}

fn boolean(map: &BTreeMap<String, &Value>, name: &str, default: bool) -> Result<bool, String> {
    map.get(name).map_or(Ok(default), |value| {
        value
            .as_bool()
            .ok_or_else(|| format!("PKCS#11 setting '{name}' must be a boolean."))
    })
}

fn option_scope(options: &Options) -> Result<(), String> {
    if let Some(flag) = options.repeated_flags.iter().next() {
        return Err(unsupported(&format!("Repeated --{flag}")));
    }
    for (key, values) in &options.values {
        if ![
            "field",
            "p11-setup",
            "password",
            "validation-context",
            "md-algorithm",
            "reason",
            "location",
            "contact-info",
            "name",
        ]
        .contains(&key.as_str())
            || values.len() != 1
        {
            return Err(unsupported(&format!("--{key}")));
        }
    }
    for flag in &options.flags {
        if ![
            "existing-only",
            "no-strict-syntax",
            "no-decode-limits",
            "with-validation-info",
        ]
        .contains(&flag.as_str())
        {
            return Err(unsupported(&format!("--{flag}")));
        }
    }
    match options.get("field") {
        Some(field) if !field.is_empty() && !field.contains('/') => Ok(()),
        _ => Err(unsupported(
            "An implicit, empty or coordinate field specification",
        )),
    }
}

fn config_scope(config: Option<&CliConfig>, context_selected: bool) -> Result<(), String> {
    let Some(config) = config else { return Ok(()) };
    let map = normalized(&config.raw_config, "PKCS#11 configuration")?;
    for key in map.keys() {
        if ![
            "pkcs11-setups",
            "validation-contexts",
            "default-validation-context",
            "time-tolerance",
            "retroactive-revinfo",
            "logging",
        ]
        .contains(&key.as_str())
        {
            return Err(unsupported(&format!("Configuration setting '{key}'")));
        }
    }
    // Do not silently discard selected default validation requirements, or
    // change ordinary no-context signing into a new implicit trust profile.
    if !context_selected
        && map.keys().any(|key| {
            [
                "validation-contexts",
                "default-validation-context",
                "time-tolerance",
                "retroactive-revinfo",
            ]
            .contains(&key.as_str())
        })
    {
        return Err(unsupported("Configured validation requirements need an explicit validation-context or validation-info selection"));
    }
    let defaults = CliConfig::parse("")?;
    if config.default_stamp_style != defaults.default_stamp_style
        || config.stamp_styles != defaults.stamp_styles
        || !config.identities.is_empty()
        || !config.plugin_endpoints.is_empty()
        || config.cache_dir.is_some()
    {
        return Err(unsupported(
            "Configured appearance, identity, plugin or cache settings",
        ));
    }
    Ok(())
}

fn pull_labels(value: Option<&Value>) -> Result<Option<Vec<String>>, String> {
    Ok(match value {
        None => Some(Vec::new()),
        Some(Value::Null) => None,
        Some(Value::String(label)) => Some(if label.is_empty() {
            Vec::new()
        } else {
            vec![label.clone()]
        }),
        Some(Value::Array(labels)) => Some(
            labels
                .iter()
                .map(|label| {
                    label
                        .as_str()
                        .map(str::to_owned)
                        .ok_or("PKCS#11 certificate pull labels must be strings.".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        _ => return Err("PKCS#11 other-certs-to-pull must be a label, label list or null.".into()),
    })
}

fn resolve_cli_user_pin(
    configured: Option<&str>,
    raw_env_pin: Option<&std::ffi::OsStr>,
    mode: PinEntryMode,
    user_pin_prompt: Option<&Pkcs11UserPinPrompt>,
) -> Result<Option<String>, String> {
    let mut cli_pin = configured.map(str::to_owned);
    if cli_pin.is_none() {
        if let Some(value) = raw_env_pin.filter(|value| !value.is_empty()) {
            let value = value
                .to_str()
                .ok_or("Invalid user PIN environment encoding.")?;
            cli_pin = Some(
                value
                    .trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
                    .to_owned(),
            );
        }
    }
    if cli_pin.is_none() && mode == PinEntryMode::Prompt {
        let prompt = user_pin_prompt.ok_or_else(|| {
            unsupported("User PIN prompt; provide a configured user PIN or PYHANKO_PKCS11_PIN")
        })?;
        cli_pin = Some(prompt.request_user_pin().map_err(|error| match error {
            Pkcs11UserPinPromptError::Unavailable => "PKCS#11 user PIN is unavailable.".to_owned(),
            Pkcs11UserPinPromptError::Cancelled => {
                "PKCS#11 user PIN request was cancelled.".to_owned()
            }
        })?);
    }
    Ok(cli_pin)
}

/// Consume only direct provider arguments. Common command options and the
/// original caller configuration/runtime remain authoritative for signing.
fn direct_request(options: &Options) -> Result<(Options, Pkcs11Setup), String> {
    use serde_json::{json, Map};
    let mut common = Options {
        values: options.values.clone(),
        flags: options.flags.clone(),
        paths: options.paths.clone(),
        repeated_flags: options.repeated_flags.clone(),
    };
    let mut settings = Map::new();
    for (argument, setting) in [
        ("lib", "module-path"),
        ("cert-label", "cert-label"),
        ("key-label", "key-label"),
    ] {
        if let Some(values) = common.values.remove(argument) {
            if values.len() != 1 {
                return Err(format!("Option --{argument} must occur exactly once."));
            }
            settings.insert(setting.into(), json!(values[0]));
        }
    }
    if let Some(values) = common.values.remove("token-label") {
        if values.len() != 1 {
            return Err("Option --token-label must occur exactly once.".into());
        }
        settings.insert("token-criteria".into(), json!({"label": values[0]}));
    }
    if let Some(values) = common.values.remove("slot-no") {
        if values.len() != 1 {
            return Err("Option --slot-no must occur exactly once.".into());
        }
        let slot: u64 = values[0]
            .parse()
            .map_err(|_| "PKCS#11 slot number must be a nonnegative integer.".to_owned())?;
        settings.insert("slot-no".into(), json!(slot));
    }
    for (argument, setting) in [
        ("other-cert", "other-certs-to-pull"),
        ("other-cert-file", "other-certs"),
    ] {
        if let Some(values) = common.values.remove(argument) {
            settings.insert(setting.into(), json!(values));
        }
    }
    if common.flags.remove("raw-mechanism") {
        settings.insert("raw-mechanism".into(), Value::Bool(true));
    }
    if common.flags.remove("skip-user-pin") {
        settings.insert("prompt-pin".into(), json!("skip"));
    }
    let temporary = json!({"pkcs11-setups": {"direct": settings}});
    let setup = CliConfig::parse(&temporary.to_string())?.pkcs11_setup("direct")?;
    Ok((common, setup))
}

fn native_setup(
    setup: &Pkcs11Setup,
    user_pin_prompt: Option<&Pkcs11UserPinPrompt>,
    signing_pin_prompt: Option<&Pkcs11SigningPinPrompt>,
) -> Result<Pkcs11Config, String> {
    let map = normalized(&setup.raw, "PKCS#11 setup")?;
    if let Some(criteria) = map.get("token-criteria") {
        for key in normalized(criteria, "PKCS#11 token-criteria")?.keys() {
            if !["label", "serial"].contains(&key.as_str()) {
                return Err(format!(
                    "Unsupported PKCS#11 token-criteria setting '{key}'."
                ));
            }
        }
    }
    for key in map.keys() {
        if ![
            "module-path",
            "token-label",
            "token-criteria",
            "slot-no",
            "cert-label",
            "cert-id",
            "key-label",
            "key-id",
            "signing-certificate",
            "other-certs",
            "only-resident-certs",
            "prompt-pin",
            "signing-pin-mode",
            "user-pin",
            "signing-pin",
            "other-certs-to-pull",
            "bulk-fetch",
            "prefer-pss",
            "raw-mechanism",
            "signature-mechanism",
        ]
        .contains(&key.as_str())
        {
            return Err(unsupported(&format!("PKCS#11 setup setting '{key}'")));
        }
    }
    if map
        .get("signature-mechanism")
        .is_some_and(|value| !value.is_null())
    {
        return Err(unsupported(
            "Explicit ASN.1 signature-mechanism configuration",
        ));
    }
    // A static context-specific credential is distinct from user login and
    // document decryption. A per-sign prompt still requires its own capability.
    let signing_env =
        std::env::var_os("PYHANKO_PKCS11_SIGNING_PIN").filter(|value| !value.is_empty());
    let (signing_pin_mode, signing_pin) = if let Some(value) = signing_env {
        let value = value
            .to_str()
            .ok_or("Invalid signing PIN environment encoding.")?
            .trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c));
        // Refuse an ambiguous explicit empty credential before requesting any
        // user PIN. Python instead falls back to the user credential here.
        if value.is_empty() {
            return Err(unsupported("Empty context-specific signing PIN"));
        }
        (SigningPinEntryMode::Reauthenticate, Some(value.to_owned()))
    } else {
        match setup.signing_pin_mode {
            SigningPinEntry::Prompt if signing_pin_prompt.is_none() => {
                return Err(unsupported("Context-specific signing PIN prompt"));
            }
            SigningPinEntry::Prompt => (SigningPinEntryMode::Prompt, None),
            SigningPinEntry::Skip if setup.signing_pin.is_some() => {
                return Err(unsupported(
                    "Context-specific signing PIN needs reauthenticate mode",
                ));
            }
            SigningPinEntry::Skip => (SigningPinEntryMode::Skip, None),
            SigningPinEntry::Reauthenticate => (
                SigningPinEntryMode::Reauthenticate,
                setup.signing_pin.clone().filter(|pin| !pin.is_empty()),
            ),
        }
    };
    let pull = pull_labels(map.get("other-certs-to-pull").copied())?;
    let mut native = Pkcs11Config {
        module_path: setup.module_path.clone(),
        token_criteria: setup.token_criteria.as_ref().map(|criteria| TokenCriteria {
            label: criteria.label.clone(),
            serial: criteria.serial.clone(),
        }),
        slot_no: setup
            .slot_no
            .map(usize::try_from)
            .transpose()
            .map_err(|_| "PKCS#11 slot number is out of range.".to_owned())?,
        cert_label: setup.cert_label.clone(),
        cert_id: setup.cert_id.clone(),
        key_label: setup.key_label.clone(),
        key_id: setup.key_id.clone(),
        signing_certificate: setup.signing_certificate.clone(),
        other_certs: setup.other_certs.clone(),
        user_pin: setup.user_pin.clone(),
        signing_pin_mode,
        signing_pin,
        prompt_pin: match setup.prompt_pin {
            PinEntry::Prompt => PinEntryMode::Prompt,
            PinEntry::Skip => PinEntryMode::Skip,
            PinEntry::Defer => PinEntryMode::Defer,
        },
        other_certs_to_pull: pull,
        bulk_fetch: boolean(&map, "bulk-fetch", true)?,
        prefer_pss: boolean(&map, "prefer-pss", false)?,
        raw_mechanism: boolean(&map, "raw-mechanism", false)?,
        only_resident_certs: boolean(&map, "only-resident-certs", setup.only_resident_certs)?,
        ..Default::default()
    };
    // Match the CLI's configured-value, then truthy environment precedence.
    // The library's explicit-empty override differs from Python's `or`: an
    // empty environment after stripping must fall back to the configured value.
    let raw_env_pin = if native.user_pin.is_none() {
        std::env::var_os("PYHANKO_PKCS11_PIN")
    } else {
        None
    };
    let cli_pin = resolve_cli_user_pin(
        native.user_pin.as_deref(),
        raw_env_pin.as_deref(),
        native.prompt_pin,
        user_pin_prompt,
    )?;
    if cli_pin.as_deref().is_some_and(|pin| !pin.is_empty()) {
        native.user_pin = cli_pin;
    }
    Ok(native)
}

/// Complete the bounded request with a real token key and the caller's state.
pub(crate) fn run(
    options: &Options,
    setup: Option<&Pkcs11Setup>,
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    if options.paths.len() != 2 {
        return Err("PKCS#11 signing requires an input and output file.".into());
    }
    let direct = setup
        .is_none()
        .then(|| direct_request(options))
        .transpose()?;
    let options = direct.as_ref().map(|pair| &pair.0).unwrap_or(options);
    let setup = setup.or_else(|| direct.as_ref().map(|pair| &pair.1));
    option_scope(options)?;
    let context_selected =
        options.flag("with-validation-info") || options.get("validation-context").is_some();
    config_scope(config, context_selected)?;
    let setup =
        setup.ok_or_else(|| unsupported("Direct module signing without a named PKCS#11 setup"))?;
    let native = native_setup(
        setup,
        runtime.pkcs11_user_pin_prompt.as_ref(),
        runtime.pkcs11_signing_pin_prompt.as_ref(),
    )?;
    let policy = config
        .map(|config| config.key_usages(options.get("validation-context")))
        .transpose()?
        .unwrap_or_default();
    let mut complete_usage = crate::usage::key_usage_constraints(&policy);
    if complete_usage.key_usage.is_none() {
        complete_usage.key_usage = Some(BTreeSet::from(["non_repudiation".into()]));
    }
    let context = if context_selected {
        Some(Arc::new(crate::validation::context_from_config(
            config,
            options.get("validation-context"),
            runtime,
        )?))
    } else {
        None
    };
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults(
        options.get("field").ok_or("Missing signature field.")?,
    );
    metadata.signer_key_usage = complete_usage
        .key_usage
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    metadata.validation_context = context;
    metadata.embed_validation_info = options.flag("with-validation-info");
    metadata.md_algorithm = options
        .get("md-algorithm")
        .map(|name| {
            DigestAlgorithm::from_name(name)
                .ok_or_else(|| format!("Unknown digest algorithm '{name}'."))
        })
        .transpose()?;
    metadata.reason = options.get("reason").map(str::to_owned);
    metadata.location = options.get("location").map(str::to_owned);
    metadata.name = options.get("name").map(str::to_owned);
    metadata.contact_info = options.get("contact-info").map(str::to_owned);
    let input = crate::software_signing::read(&options.paths[0])?;
    let mut reader_options = sigis_pdf::ReaderOptions {
        strict: !options.flag("no-strict-syntax"),
        ..Default::default()
    };
    if options.flag("no-decode-limits") {
        reader_options.decode_limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input();
    }
    let reader =
        crate::read_for_update(&input, reader_options).map_err(|error| error.to_string())?;
    if reader.encrypted() && options.get("password").is_none() && runtime.password.is_none() {
        return Err(unsupported("PDF decryption password prompt"));
    }
    let password = crate::software_signing::authenticate_document(&reader, options, runtime)?;
    let settings = SignOptions {
        strict: reader.strict(),
        password,
        existing_fields_only: options.flag("existing-only"),
        reopen_state: Some(PdfReopenState::from_reader(reader)),
        ..Default::default()
    };
    let signer = open_signer(&native, None).map_err(|error| error.to_string())?;
    let signer = if native.signing_pin_mode == SigningPinEntryMode::Prompt {
        let prompt = runtime
            .pkcs11_signing_pin_prompt
            .clone()
            .ok_or_else(|| unsupported("Context-specific signing PIN prompt"))?;
        signer.with_signing_pin_callback(move || {
            prompt.request_signing_pin().map_err(|error| {
                sigis_pki_core::errors::HankoError::Signing(match error {
                    Pkcs11SigningPinPromptError::Unavailable => {
                        "PKCS#11 signing PIN is unavailable.".into()
                    }
                    Pkcs11SigningPinPromptError::Cancelled => {
                        "PKCS#11 signing PIN request was cancelled.".into()
                    }
                })
            })
        })
    } else {
        signer
    };
    let mut pdf_signer =
        PdfSigner::new(metadata, Arc::new(signer)).with_signer_key_usage_policy(complete_usage);
    pdf_signer.signing_time = Some(runtime.now);
    pdf_signer.stamp_style = Some(match config {
        Some(config) => config.stamp_style(None)?,
        None => CliConfig::parse("")?.stamp_style(None)?,
    });
    crate::software_signing::sign_pdf_and_write(&pdf_signer, &input, &settings, &options.paths[1])
}

#[cfg(test)]
mod tests {
    use super::{pull_labels, resolve_cli_user_pin, PinEntryMode};
    use crate::runtime::{Pkcs11UserPinPrompt, Pkcs11UserPinPromptError};
    use serde_json::json;
    use std::{
        ffi::OsStr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    fn forbidden_prompt() -> Pkcs11UserPinPrompt {
        Pkcs11UserPinPrompt::new(|_| panic!("An existing credential must suppress the prompt"))
    }

    #[test]
    fn configured_user_pin_including_empty_dominates_environment_and_modes() {
        for configured in ["configured", "", "  configured  "] {
            for env in [None, Some(OsStr::new("")), Some(OsStr::new("different"))] {
                for mode in [
                    PinEntryMode::Prompt,
                    PinEntryMode::Skip,
                    PinEntryMode::Defer,
                ] {
                    assert_eq!(
                        resolve_cli_user_pin(
                            Some(configured),
                            env,
                            mode,
                            Some(&forbidden_prompt())
                        )
                        .unwrap(),
                        Some(configured.to_owned())
                    );
                }
            }
        }
    }

    #[test]
    fn environment_user_pin_uses_python_strip_without_requesting_a_callback() {
        for (raw, expected) in [
            ("environment", "environment"),
            (" \tenvironment\r\n", "environment"),
            ("\u{1c}\u{1d}environment\u{1e}\u{1f}", "environment"),
            ("\u{a0}\u{2003}environment\u{3000}", "environment"),
            (" \t\n\u{1c}\u{3000}", ""),
        ] {
            for mode in [
                PinEntryMode::Prompt,
                PinEntryMode::Skip,
                PinEntryMode::Defer,
            ] {
                assert_eq!(
                    resolve_cli_user_pin(
                        None,
                        Some(OsStr::new(raw)),
                        mode,
                        Some(&forbidden_prompt())
                    )
                    .unwrap(),
                    Some(expected.to_owned())
                );
            }
        }
    }

    #[test]
    fn absent_or_raw_empty_environment_requests_only_explicit_user_authority() {
        for env in [None, Some(OsStr::new(""))] {
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let prompt = Pkcs11UserPinPrompt::new(move |label| {
                assert_eq!(label, "PKCS#11 user PIN: ");
                observed.fetch_add(1, Ordering::SeqCst);
                Ok("dedicated-user-response".into())
            });
            assert_eq!(
                resolve_cli_user_pin(None, env, PinEntryMode::Prompt, Some(&prompt)).unwrap(),
                Some("dedicated-user-response".into())
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                resolve_cli_user_pin(None, env, PinEntryMode::Prompt, None).unwrap_err(),
                "Unsupported PKCS#11 signing requirement: User PIN prompt; provide a configured user PIN or PYHANKO_PKCS11_PIN."
            );
        }
    }

    #[test]
    fn missing_credentials_in_skip_and_defer_do_not_invoke_user_prompt() {
        for env in [None, Some(OsStr::new(""))] {
            for mode in [PinEntryMode::Skip, PinEntryMode::Defer] {
                assert_eq!(
                    resolve_cli_user_pin(None, env, mode, Some(&forbidden_prompt())).unwrap(),
                    None
                );
            }
        }
    }

    #[test]
    fn returned_prompt_values_are_not_trimmed_or_retried() {
        for response in ["", "  ", "\u{1c}response\u{1f}", "response"] {
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let prompt = Pkcs11UserPinPrompt::new(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(response.to_owned())
            });
            assert_eq!(
                resolve_cli_user_pin(None, None, PinEntryMode::Prompt, Some(&prompt)).unwrap(),
                Some(response.to_owned())
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn prompt_errors_have_static_diagnostics_without_fallback_or_retry() {
        for (error, expected) in [
            (
                Pkcs11UserPinPromptError::Unavailable,
                "PKCS#11 user PIN is unavailable.",
            ),
            (
                Pkcs11UserPinPromptError::Cancelled,
                "PKCS#11 user PIN request was cancelled.",
            ),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let prompt = Pkcs11UserPinPrompt::new(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                Err(error)
            });
            assert_eq!(
                resolve_cli_user_pin(None, None, PinEntryMode::Prompt, Some(&prompt)).unwrap_err(),
                expected
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn invalid_environment_encoding_is_ignored_only_when_configured_pin_wins() {
        use std::os::unix::ffi::OsStrExt;
        let invalid = OsStr::from_bytes(&[0xff, 0xfe]);
        for mode in [
            PinEntryMode::Prompt,
            PinEntryMode::Skip,
            PinEntryMode::Defer,
        ] {
            assert_eq!(
                resolve_cli_user_pin(Some(""), Some(invalid), mode, Some(&forbidden_prompt()))
                    .unwrap(),
                Some(String::new())
            );
            assert_eq!(
                resolve_cli_user_pin(None, Some(invalid), mode, Some(&forbidden_prompt()))
                    .unwrap_err(),
                "Invalid user PIN environment encoding."
            );
        }
    }

    #[test]
    fn empty_override_preserves_existing_native_authentication_distinctions() {
        use sigis_pades_sign::pkcs11::{handle_pin, Pkcs11Config, UserPin};
        let mut configured_empty = Pkcs11Config {
            user_pin: Some(String::new()),
            ..Default::default()
        };
        let selected = resolve_cli_user_pin(
            configured_empty.user_pin.as_deref(),
            Some(OsStr::new("ignored")),
            PinEntryMode::Prompt,
            Some(&forbidden_prompt()),
        )
        .unwrap();
        if selected.as_deref().is_some_and(|pin| !pin.is_empty()) {
            configured_empty.user_pin = selected;
        }
        assert!(
            matches!(handle_pin(&configured_empty, None), UserPin::Pin(value) if value.is_empty())
        );
        for mode in [
            PinEntryMode::Prompt,
            PinEntryMode::Skip,
            PinEntryMode::Defer,
        ] {
            let mut native = Pkcs11Config {
                prompt_pin: mode,
                ..Default::default()
            };
            let selected = resolve_cli_user_pin(
                None,
                Some(OsStr::new("  \u{1c} ")),
                mode,
                Some(&forbidden_prompt()),
            )
            .unwrap();
            assert_eq!(selected, Some(String::new()));
            if selected.as_deref().is_some_and(|pin| !pin.is_empty()) {
                native.user_pin = selected;
            }
            match mode {
                PinEntryMode::Defer => {
                    assert!(matches!(handle_pin(&native, None), UserPin::ProtectedAuth))
                }
                _ => assert!(matches!(handle_pin(&native, None), UserPin::None)),
            }
        }
    }

    #[test]
    fn empty_certificate_selection_does_not_request_an_unnamed_certificate() {
        assert_eq!(pull_labels(None).unwrap(), Some(Vec::new()));
        assert_eq!(pull_labels(Some(&json!([]))).unwrap(), Some(Vec::new()));
        assert_eq!(pull_labels(Some(&json!(""))).unwrap(), Some(Vec::new()));
        assert_eq!(pull_labels(Some(&json!(null))).unwrap(), None);
        assert_eq!(
            pull_labels(Some(&json!("interm"))).unwrap(),
            Some(vec!["interm".into()])
        );
        assert!(pull_labels(Some(&json!(17))).is_err());
    }
}
