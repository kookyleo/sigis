// Derived from pyHanko0.38.1 standalone timestamp CLI (MIT, see LICENSE-pyHanko).
//! Bounded document timestamp command with explicit TSA validation.
use crate::{
    config::CliConfig,
    runtime::ValidationRuntime,
    software_signing::{options, read, Options},
};
use sigis_pades_sign::pdf::{
    timestamp::{timestamp_pdf_with_state, TimestampOptions},
    writer::PdfReopenState,
};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{
    algorithms::DigestAlgorithm,
    errors::{HankoError, Result as HankoResult},
    key_usage::KeyUsageConstraints,
    sign::TimeStamper,
};
use std::collections::BTreeSet;

fn unsupported(requirement: &str) -> String {
    format!("{requirement} is not supported by the timestamp command.")
}
fn check_options(opts: &Options) -> Result<(), String> {
    if let Some(flag) = opts.repeated_flags.iter().next() {
        return Err(unsupported(&format!("Repeated --{flag}")));
    }
    for (key, values) in &opts.values {
        if !["timestamp-url", "validation-context"].contains(&key.as_str()) || values.len() != 1 {
            return Err(unsupported(&format!("--{key}")));
        }
    }
    for flag in &opts.flags {
        if flag != "no-decode-limits" {
            return Err(unsupported(&format!("--{flag}")));
        }
    }
    Ok(())
}
fn check_config(config: Option<&CliConfig>) -> Result<(), String> {
    let Some(config) = config else { return Ok(()) };
    // The decode original includes an unused P12 setup. This command neither
    // loads that credential nor turns it into a replacement context.
    let allowed = [
        "validation-contexts",
        "default-validation-context",
        "time-tolerance",
        "retroactive-revinfo",
        "logging",
        "pkcs12-setups",
        "p12-setup",
    ];
    let raw = config
        .raw_config
        .as_object()
        .ok_or_else(|| unsupported("Non-mapping configuration"))?;
    let mut seen = BTreeSet::new();
    for key in raw.keys() {
        let normalized = key.replace('_', "-");
        if !seen.insert(normalized.clone()) {
            return Err(format!(
                "Conflicting aliases in timestamp configuration: {normalized}."
            ));
        }
        if !allowed.contains(&normalized.as_str()) {
            return Err(unsupported(&format!("Configuration setting '{key}'")));
        }
    }
    let defaults = CliConfig::parse("")?;
    if config.default_stamp_style != defaults.default_stamp_style
        || config.stamp_styles != defaults.stamp_styles
    {
        return Err(unsupported("Configured appearance"));
    }
    if !config.identities.is_empty()
        || !config.plugin_endpoints.is_empty()
        || config.cache_dir.is_some()
    {
        return Err(unsupported("Identity, plugin or cache configuration"));
    }
    Ok(())
}

#[derive(Debug)]
struct ValidatedTsa<'a> {
    http: sigis_pki_fetch::HttpTimeStamper,
    context: &'a ValidationContext,
}
impl TimeStamper for ValidatedTsa<'_> {
    fn timestamp(&self, imprint: &[u8], digest: DigestAlgorithm) -> HankoResult<Vec<u8>> {
        let token = self.http.timestamp(imprint, digest)?;
        // Validate every dummy/final response, never a one-time issuer promise.
        let status = sigis_cms::validate_timestamp_token(&token, imprint, self.context)?;
        let certificate = status.signature.signing_cert.as_ref().ok_or_else(|| {
            HankoError::Signing("The TSA token has no signing certificate.".into())
        })?;
        // A directly trusted leaf may skip path-level usage checking. The TSA
        // role still requires an explicit time_stamping EKU on that leaf.
        KeyUsageConstraints::with_extd_key_usage(["time_stamping"])
            .validate(certificate)
            .map_err(|error| {
                HankoError::Signing(format!(
                    "The TSA must explicitly assert time_stamping: {error}"
                ))
            })?;
        if !status.signature.bottom_line() {
            return Err(HankoError::Signing(format!("The TSA token did not satisfy integrity, validity and trust requirements: {status:?}")));
        }
        Ok(token)
    }
}

/// Run the standalone timestamp command with the caller's clock and fetchers.
///
/// Arguments follow `sign timestamp`. Unsupported mandatory settings reject
/// without retrying another signing engine or discarding the selected context.
pub fn run_with_runtime(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    let opts = options(args)?;
    check_options(&opts)?;
    check_config(config)?;
    if opts.paths.len() != 2 {
        return Err("Input and output file arguments are required.".into());
    }
    let url = opts
        .get("timestamp-url")
        .ok_or("The --timestamp-url option is required.")?;
    let context =
        crate::validation::context_from_config(config, opts.get("validation-context"), runtime)?;
    let input = read(&opts.paths[0])?;
    let mut reader_options = sigis_pdf::ReaderOptions::default();
    if opts.flag("no-decode-limits") {
        reader_options.decode_limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input();
    }
    let reader =
        crate::read_for_update(&input, reader_options).map_err(|error| error.to_string())?;
    if reader.encrypted() {
        return Err(unsupported("Encrypted PDF input"));
    }
    let tsa = ValidatedTsa {
        http: sigis_pki_fetch::HttpTimeStamper::new(url),
        context: &context,
    };
    let mut settings = TimestampOptions::new(DigestAlgorithm::Sha256);
    settings.validation_context = Some(&context);
    settings.reopen_state = Some(PdfReopenState::from_reader(reader));
    let output = timestamp_pdf_with_state(&input, &tsa, None, &settings)
        .map_err(|error| error.to_string())?;
    std::fs::write(&opts.paths[1], output.pdf).map_err(|error| error.to_string())?;
    Ok(String::new())
}
