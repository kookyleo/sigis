//! Ordinary PDF validation with authenticated EU trusted-list anchors.
//! Derived from pyHanko0.38.1 CLI validation (MIT, see LICENSE-pyHanko).
use crate::{config::CliConfig, runtime::ValidationRuntime};
use clap::Parser;
use serde_json::{Map, Value};
use sigis_pdf::{PdfFile, ReaderOptions, SignatureKind};
use sigis_pki_certvalidator::{
    policy::{CertRevTrustPolicy, RevocationCheckingPolicy},
    ValidationContext,
};
use sigis_pki_core::{key_usage::KeyUsageConstraints, time::Moment};
use std::{collections::BTreeSet, time::Duration};

#[derive(Parser)]
#[command(name = "validate")]
struct Args {
    #[arg(long)]
    eutl_all: bool,
    #[arg(long)]
    eutl_territories: Option<String>,
    #[arg(long)]
    eutl_force_redownload: bool,
    #[arg(long)]
    validation_context: Option<String>,
    #[arg(long)]
    validation_time: Option<String>,
    #[arg(long)]
    pretty_print: bool,
    #[arg(long)]
    executive_summary: bool,
    #[arg(long)]
    no_revocation_check: bool,
    #[arg(long)]
    soft_revocation_check: bool,
    #[arg(long)]
    force_revinfo: bool,
    #[arg(long)]
    no_strict_syntax: bool,
    #[arg(long)]
    no_decode_limits: bool,
    #[arg(long)]
    password: Option<String>,
    infile: String,
}
fn get<'a>(m: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    m.get(key).or_else(|| m.get(&key.replace('-', "_")))
}

/// Select only the EUTL extension; every existing non-EUTL argument continues
/// through the already established ordinary validator.
pub(crate) fn handles(args: &[String], config: Option<&CliConfig>) -> bool {
    if crate::argument_positions(args).any(|index| args[index].starts_with("--eutl-")) {
        return true;
    }
    let name = crate::argument_positions(args).find_map(|index| {
        args[index]
            .strip_prefix("--validation-context=")
            .map(str::to_owned)
            .or_else(|| {
                (args[index] == "--validation-context")
                    .then(|| args.get(index + 1).cloned())
                    .flatten()
            })
    });
    config
        .and_then(|c| c.validation_settings_raw(name.as_deref()).ok())
        .and_then(Value::as_object)
        .is_some_and(|m| {
            m.keys().any(|key| {
                key.replace('_', "-").starts_with("eutl-")
                    || key.replace('_', "-") == "lotl-tlso-certs"
            })
        })
}

fn schema<'a>(config: &'a CliConfig, name: Option<&str>) -> Result<&'a Map<String, Value>, String> {
    let global = config
        .raw_config
        .as_object()
        .ok_or("CLI configuration requires a dictionary.")?;
    let outer = [
        "validation-contexts",
        "default-validation-context",
        "time-tolerance",
        "retroactive-revinfo",
        "cache-dir",
        "logging",
        "plugins",
        "stamp-styles",
        "default-stamp-style",
        "identities",
        "pkcs11-setups",
        "pkcs12-setups",
        "pemder-setups",
        "p12-setup",
    ];
    crate::config::reject_unsupported_outer_aliases(global, &outer)?;
    for key in global.keys() {
        if !outer.contains(&key.replace('_', "-").as_str()) {
            return Err(format!("Unknown setting '{key}' in CLI configuration."));
        }
    }
    let raw = config.validation_settings_raw(name)?;
    let mapping = raw
        .as_object()
        .ok_or("The validation context requires a dictionary.")?;
    let allowed = [
        "trust",
        "trust-replace",
        "other-certs",
        "time-tolerance",
        "retroactive-revinfo",
        "signer-key-usage",
        "signer-extd-key-usage",
        "signer-key-usage-policy",
        "revocation-policy",
        "eutl-lotl-url",
        "lotl-tlso-certs",
        "eutl-territories",
        "eutl-force-redownload",
    ];
    crate::config::reject_unsupported_outer_aliases(mapping, &allowed)?;
    for key in mapping.keys() {
        if !allowed.contains(&key.replace('_', "-").as_str()) {
            return Err(format!("Unknown setting '{key}' in validation context."));
        }
    }
    config.key_usages(name)?;
    Ok(mapping)
}

fn territories(value: &Value) -> Result<Option<BTreeSet<String>>, String> {
    if value.as_str() == Some("all") {
        return Ok(None);
    }
    let values: Vec<&str> = match value {
        Value::String(text) => text.split(',').map(str::trim).collect(),
        Value::Array(values) => values
            .iter()
            .map(|v| v.as_str().ok_or("EUTL territories must be strings."))
            .collect::<Result<_, _>>()?,
        _ => return Err("EUTL territories must be non-empty.".into()),
    };
    if values.is_empty() || values.iter().any(|v| v.is_empty()) {
        return Err("EUTL territories must be non-empty.".into());
    }
    Ok(Some(values.into_iter().map(|v| v.to_lowercase()).collect()))
}

fn usage(config: &CliConfig, name: Option<&str>) -> Result<KeyUsageConstraints, String> {
    let policy = config.key_usages(name)?;
    let mut usage = crate::usage::key_usage_constraints(&policy);
    if usage.key_usage.is_none() {
        usage.key_usage = Some(BTreeSet::from(["non_repudiation".into()]));
    }
    Ok(usage)
}

/// EUTL and ordinary policy are resolved once from the complete original input,
/// without an ordinary context/getter reconstruction or static anchor bypass.
pub(crate) fn run_with_runtime(
    args: &[String],
    config: Option<&CliConfig>,
    verbose: bool,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    let a =
        Args::try_parse_from(std::iter::once("validate".to_owned()).chain(args.iter().cloned()))
            .map_err(|e| e.to_string())?;
    if a.eutl_all && a.eutl_territories.is_some() {
        return Err("--eutl-all and --eutl-territories are mutually exclusive".into());
    }
    if a.eutl_territories.as_deref() == Some("") {
        return Err("argument to --eutl-territories must be non-empty".into());
    }
    if a.pretty_print && a.executive_summary {
        return Err("The --executive-summary and --pretty-print options are incompatible.".into());
    }
    if usize::from(a.no_revocation_check)
        + usize::from(a.soft_revocation_check)
        + usize::from(a.force_revinfo)
        > 1
    {
        return Err("Revocation checking options are incompatible.".into());
    }
    let config = config.ok_or("No config file was provided for the validation context.")?;
    let mapping = schema(config, a.validation_context.as_deref())
        .map_err(|e| format!("Error in validation context: {e}"))?;
    // Upstream CLI overrides the configured territory selection with all-mode
    // before constructing trust settings, including configured empty values.
    let selected = if a.eutl_all {
        None
    } else if let Some(value) = &a.eutl_territories {
        territories(&Value::String(value.clone()))?
    } else if let Some(value) = get(mapping, "eutl-territories") {
        territories(value).map_err(|e| format!("Error in validation context: {e}"))?
    } else {
        return Err("Error in validation context: EUTL territories must be non-empty.".into());
    };
    let settings = config
        .validation_settings(a.validation_context.as_deref())
        .map_err(|e| format!("Error in validation context: {e}"))?;
    let moment=match a.validation_time.as_deref(){
        None=>runtime.now,
        Some("claimed")=>return Err("Claimed-time EUTL validation requires explicit authenticated historical evidence; unsupported by this command.".into()),
        Some(value)=>Moment::parse_rfc3339(value).ok_or_else(||format!("The validation time '{value}' could not be parsed."))?,
    };
    let mode = if a.no_revocation_check {
        "none"
    } else if a.soft_revocation_check {
        "soft-fail"
    } else if a.force_revinfo {
        "require"
    } else {
        get(mapping, "revocation-policy")
            .map(|value| value.as_str().ok_or("revocation-policy must be a string."))
            .transpose()?
            .unwrap_or("hard-fail")
    };
    let mut policy = CertRevTrustPolicy::new(
        RevocationCheckingPolicy::from_legacy(mode)
            .ok_or("Unsupported revocation-policy in validation context.")?,
    );
    policy.retroactive_revinfo = settings.retroactive_revinfo;
    let registry = match crate::qualified_validation::load_for_validation(
        config,
        a.validation_context.as_deref(),
        runtime,
        a.eutl_force_redownload,
        selected.as_ref(),
    ) {
        Ok(registry) => registry,
        Err(error)
            if error.starts_with("Trusted-list loading failed")
                || error.starts_with("Unsupported authenticated trusted-list") =>
        {
            // An authenticated list processing failure never publishes partial
            // trust. This explicit signature-invalid result is distinct from
            // a fatal LOTL/certificate/configuration error.
            return Err(format!(
                "Trust list processing failed: {error}\nThe signature is judged INVALID."
            ));
        }
        Err(error) => return Err(format!("Trust list processing failed: {error}")),
    };
    let tolerance = u64::try_from(settings.time_tolerance)
        .map_err(|_| "Negative time-tolerance in validation context.")?;
    let mut builder = ValidationContext::builder()
        .moment(moment)
        .point_in_time_validation(a.validation_time.is_some())
        .time_tolerance(Duration::from_secs(tolerance))
        .revinfo_policy(policy)
        .fetchers(runtime.fetchers.clone())
        .trust_manager(crate::qualified_validation::registry_trust_manager(
            registry,
        ));
    for cert in settings.other_certs {
        builder = builder.other_cert(cert);
    }
    let context = builder
        .build()
        .map_err(|e| format!("Error in validation context: {e}"))?;
    let mut options = if a.no_strict_syntax {
        ReaderOptions::lenient()
    } else {
        ReaderOptions::default()
    };
    if a.no_decode_limits {
        options.decode_limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input();
    }
    let bytes = std::fs::read(&a.infile).map_err(|e| format!("Failed to read PDF: {e}"))?;
    let file = PdfFile::parse_with(&bytes, options)
        .map_err(|e| format!("Failed to read PDF: {e}; rerun with --no-decode-limits."))?;
    crate::validation::authenticate(&file, a.password.as_deref(), runtime)?;
    let usage = usage(config, a.validation_context.as_deref())?;
    let cms_options = sigis_cms::CmsValidationOptions {
        key_usage_settings: Some(usage.clone()),
        ..Default::default()
    };
    let mut output = if verbose {
        "Running with --verbose\n".to_string()
    } else {
        String::new()
    };
    let mut all_valid = true;
    for signature in file.embedded_signatures().map_err(|e| e.to_string())? {
        if signature.kind != SignatureKind::Signature {
            continue;
        }
        let status = match sigis_pades::validate_pdf_signature_with_options(
            &file,
            &signature,
            &context,
            Some(&sigis_pdf_diff::StandardDiffPolicy),
            &cms_options,
        ) {
            Ok(status) => status,
            Err(error) => {
                all_valid = false;
                output.push_str(&format!("The signature is judged INVALID.\n{error}\n"));
                continue;
            }
        };
        let policy_ok = status
            .cms
            .signature
            .signing_cert
            .as_ref()
            .is_some_and(|cert| usage.validate(cert).is_ok());
        let valid = status.bottom_line() && status.cms.bottom_line() && policy_ok;
        all_valid &= valid;
        if a.pretty_print {
            output.push_str(&format!(
                "Field {}\n{}\nThe signature is judged {}.\n",
                signature.field_name,
                status.cms.pretty_print_details(),
                if valid { "VALID" } else { "INVALID" }
            ));
        } else if a.executive_summary {
            output.push_str(&format!(
                "{}:{}\n",
                signature.field_name,
                if valid { "VALID" } else { "INVALID" }
            ));
        } else {
            output.push_str(&format!("{}:{}\n", signature.field_name, status.summary()));
        }
    }
    if all_valid {
        Ok(output)
    } else {
        Err(output.trim_end().into())
    }
}
