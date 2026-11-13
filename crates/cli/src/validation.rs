//! Native PDF/CMS validation command, derived from pyHanko 0.38.1 (MIT).
use crate::{config::CliConfig, runtime::ValidationRuntime};
use clap::Parser;
use der::Decode;
use sigis_cms::status::StandardCmsSignatureStatus;
use sigis_pdf::{
    crypt::{AuthStatus, HandlerType},
    reader::ReaderOptions,
    PdfFile,
};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{cert::Cert, time::Moment};
use std::{
    io::{self, IsTerminal, Write},
    time::Duration,
};

#[derive(Parser)]
#[command(name = "validate")]
struct Args {
    #[arg(long)]
    trust: Vec<String>,
    #[arg(long)]
    trust_replace: bool,
    #[arg(long)]
    other_certs: Vec<String>,
    #[arg(long)]
    validation_context: Option<String>,
    #[arg(long)]
    validation_time: Option<String>,
    #[arg(long)]
    executive_summary: bool,
    #[arg(long)]
    pretty_print: bool,
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
    #[arg(long)]
    detached: Option<String>,
    infile: String,
}
impl Args {
    fn parse_values(args: &[String]) -> Result<Self, String> {
        Self::try_parse_from(std::iter::once("validate".to_owned()).chain(args.iter().cloned()))
            .map_err(|e| e.to_string())
    }
    fn moment(&self, runtime: &ValidationRuntime) -> Result<Moment, String> {
        match self.validation_time.as_deref() {
            None | Some("claimed") => Ok(runtime.now),
            Some(value) => Moment::parse_rfc3339(value)
                .ok_or_else(|| format!("The validation time '{value}' could not be parsed.")),
        }
    }
    fn check(&self) -> Result<(), String> {
        if self.detached.is_some() && self.validation_time.as_deref() == Some("claimed") {
            return Err(
                "--validation-time claimed is not supported for detached CMS validation.".into(),
            );
        }
        if self.executive_summary && self.pretty_print {
            return Err(
                "The --executive-summary and --pretty-print options are incompatible.".into(),
            );
        }
        if usize::from(self.no_revocation_check)
            + usize::from(self.soft_revocation_check)
            + usize::from(self.force_revinfo)
            > 1
        {
            return Err("Revocation checking options are incompatible.".into());
        }
        if self.validation_context.is_some()
            && (!self.trust.is_empty() || !self.other_certs.is_empty())
        {
            return Err(
                "--validation-context is incompatible with --trust and --other-certs.".into(),
            );
        }
        Ok(())
    }
}

fn config_error(error: String) -> String {
    if error.contains("Failed to read certificate") {
        format!("I/O problem while configuring validation context: {error}")
    } else {
        format!("Certificate processing problem in validation context: {error}")
    }
}
fn read_certificates(paths: &[String]) -> Result<Vec<Cert>, String> {
    let mut out = vec![];
    for path in paths {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("I/O problem while reading certificate {path}: {e}"))?;
        out.extend(
            sigis_pades_sign::keys::load_certs_from_pemder_data(&bytes)
                .map_err(|e| format!("Certificate processing problem: {e}"))?,
        );
    }
    Ok(out)
}

fn check_context_settings(config: &CliConfig, name: Option<&str>) -> Result<(), String> {
    let raw = config
        .validation_settings_raw(name)
        .map_err(|e| format!("Error in validation context: {e}"))?;
    let allowed = [
        "trust",
        "trust-replace",
        "other-certs",
        "time-tolerance",
        "retroactive-revinfo",
        "signer-key-usage-policy",
        "signer-key-usage",
        "signer-extd-key-usage",
    ];
    let mapping = raw
        .as_object()
        .ok_or("The validation context requires a dictionary.")?;
    crate::config::reject_unsupported_outer_aliases(mapping, &allowed)?;
    for key in mapping.keys() {
        if !allowed.contains(&key.replace('_', "-").as_str()) {
            return Err(format!("Unknown setting '{key}' in validation context."));
        }
    }
    Ok(())
}

/// Build a context with configured roots, clock, fetchers and hard-fail revocation.
pub fn context_from_config(
    config: Option<&CliConfig>,
    name: Option<&str>,
    runtime: &ValidationRuntime,
) -> Result<ValidationContext, String> {
    let mut builder = ValidationContext::builder()
        .moment(runtime.now)
        .time_tolerance(Duration::from_secs(30))
        .revocation_mode("hard-fail")
        .fetchers(runtime.fetchers.clone());
    if name.is_some() && config.is_none() {
        return Err("No config file was provided for the validation context.".into());
    }
    if let Some(config) = config {
        check_context_settings(config, name)?;
        let s = config.validation_settings(name).map_err(config_error)?;
        let tolerance = u64::try_from(s.time_tolerance)
            .map_err(|_| "Negative time-tolerance in validation context.")?;
        builder = builder.time_tolerance(Duration::from_secs(tolerance));
        for cert in s.trust_roots {
            builder = builder.trust_root(cert)
        }
        for cert in s.other_certs {
            builder = builder.other_cert(cert)
        }
        let mut policy = sigis_pki_certvalidator::policy::CertRevTrustPolicy::new(
            sigis_pki_certvalidator::policy::RevocationCheckingPolicy::from_legacy("hard-fail")
                .ok_or("Invalid native revocation mode.")?,
        );
        policy.retroactive_revinfo = s.retroactive_revinfo;
        builder = builder.revinfo_policy(policy);
    }
    builder
        .build()
        .map_err(|e| format!("Error while configuring validation context: {e}"))
}

// Explicit trust material selects the CLI profile in the pinned command. Only
// global timing/revocation defaults apply; default-context roots must not leak.
fn context_for_cli_trust(
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<ValidationContext, String> {
    if let Some(config) = config {
        check_context_settings(config, None)?;
        // KU requirements are selected independently of the trust profile.
        config.key_usages(None).map_err(config_error)?;
    }
    let tolerance = config.and_then(|c| c.time_tolerance).unwrap_or(30);
    let tolerance = u64::try_from(tolerance).map_err(|_| "Negative validation time tolerance.")?;
    let mut policy = sigis_pki_certvalidator::policy::CertRevTrustPolicy::new(
        sigis_pki_certvalidator::policy::RevocationCheckingPolicy::from_legacy("hard-fail")
            .ok_or("Invalid native revocation mode.")?,
    );
    policy.retroactive_revinfo = config.is_some_and(|c| c.retroactive_revinfo);
    ValidationContext::builder()
        .moment(runtime.now)
        .time_tolerance(Duration::from_secs(tolerance))
        .revinfo_policy(policy)
        .fetchers(runtime.fetchers.clone())
        .build()
        .map_err(|e| format!("Error while configuring validation context: {e}"))
}

fn build_context(
    a: &Args,
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
    moment: Moment,
) -> Result<ValidationContext, String> {
    let base = if !a.trust.is_empty() || !a.other_certs.is_empty() {
        context_for_cli_trust(config, runtime)?
    } else {
        context_from_config(config, a.validation_context.as_deref(), runtime)?
    };
    let mode = if a.no_revocation_check {
        "none"
    } else if a.soft_revocation_check {
        "soft-fail"
    } else if a.force_revinfo {
        "require"
    } else {
        "hard-fail"
    };
    let mut policy = *base.revinfo_policy();
    policy.revocation_checking_policy =
        sigis_pki_certvalidator::policy::RevocationCheckingPolicy::from_legacy(mode)
            .ok_or("Invalid native revocation mode.")?;
    let mut builder = ValidationContext::builder()
        .moment(moment)
        .time_tolerance(base.timing().time_tolerance)
        .revinfo_policy(policy)
        .fetchers(runtime.fetchers.clone());
    if a.trust.is_empty() || !a.trust_replace {
        for root in base.trust_anchors() {
            builder = builder.trust_anchor(root.clone())
        }
    }
    for cert in read_certificates(&a.trust)? {
        builder = builder.trust_root(cert)
    }
    for cert in base.other_certs() {
        builder = builder.other_cert(cert.clone())
    }
    for cert in read_certificates(&a.other_certs)? {
        builder = builder.other_cert(cert)
    }
    builder
        .build()
        .map_err(|e| format!("Error while configuring validation context: {e}"))
}

/// Nonfatal configuration diagnostics, kept separate from command output.
pub fn warnings(args: &[String], config: Option<&CliConfig>) -> Vec<String> {
    let Ok(a) = Args::parse_values(args) else {
        return vec![];
    };
    if a.trust_replace {
        return vec![];
    }
    let replace = a.trust.is_empty()
        && a.other_certs.is_empty()
        && config
            .and_then(|c| {
                c.validation_settings_raw(a.validation_context.as_deref())
                    .ok()
            })
            .and_then(|v| v.get("trust-replace"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    if replace {
        return vec![];
    }
    vec!["Operating system trust fallback was requested; the native CLI uses configured roots and does not implicitly add operating system roots.".into()]
}

fn prompt_password(runtime: &ValidationRuntime) -> Result<String, String> {
    if let Some(password) = &runtime.password {
        return Ok(password.clone());
    }
    if io::stdin().is_terminal() {
        return rpassword::prompt_password("Password: ").map_err(|e| e.to_string());
    }
    eprint!("Password: ");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut text = String::new();
    io::stdin()
        .read_line(&mut text)
        .map_err(|e| e.to_string())?;
    Ok(text.trim_end_matches(['\r', '\n']).into())
}
fn authenticate(
    file: &PdfFile,
    password: Option<&str>,
    runtime: &ValidationRuntime,
) -> Result<(), String> {
    let Some(handler) = file.security_handler().map_err(|e| e.to_string())? else {
        return Ok(());
    };
    if handler.handler_type() != HandlerType::Standard {
        return Err("Validation supports only password-based encryption.".into());
    }
    let status = if let Some(password) = password {
        file.decrypt(password).map_err(|e| e.to_string())?.status
    } else {
        let first = file.decrypt("").map_err(|e| e.to_string())?;
        if first.status == AuthStatus::Failed {
            file.decrypt(prompt_password(runtime)?.as_str())
                .map_err(|e| e.to_string())?
                .status
        } else {
            first.status
        }
    };
    if status == AuthStatus::Failed {
        return Err("Password didn't match.".into());
    }
    Ok(())
}
fn validation_error(error: impl std::fmt::Display) -> String {
    let text = error.to_string();
    let lower = text.to_lowercase();
    if lower.contains("sha1")
        && (lower.contains("allowed") || lower.contains("weak") || lower.contains("forbid"))
    {
        return format!("sha1_rsa is not allowed by the current usage policy: {text}");
    }
    if lower.contains("2.999") || lower.contains("unknown hash") || lower.contains("unknown digest")
    {
        return format!("An error occurred: Unknown hash function: {text}");
    }
    if lower.contains("decode") && lower.contains("limit") {
        return format!("An error occurred: {text}; rerun with --no-decode-limits.");
    }
    format!("An error occurred: {text}")
}
fn fingerprint(status: &StandardCmsSignatureStatus) -> String {
    status
        .signature
        .signing_cert
        .as_ref()
        .map(|c| c.sha256().iter().map(|b| format!("{b:02x}")).collect())
        .unwrap_or_else(|| "unknown".into())
}
fn report(
    name: &str,
    status: &StandardCmsSignatureStatus,
    valid: bool,
    suffix: Option<&str>,
    a: &Args,
) -> String {
    let fingerprint = fingerprint(status);
    let policy_diagnostic = match &status.signature.trust_problem {
        Some(sigis_cms::status::TrustProblem::Path(error))
            if error.is_instance_of("DisallowedAlgorithmError") =>
        {
            format!(
                "{} is not allowed by the current usage policy: {error}\n",
                status.signature.pkcs7_signature_mechanism
            )
        }
        _ => String::new(),
    };
    if a.executive_summary {
        return format!(
            "{name}:{fingerprint}:{}\n",
            if valid { "VALID" } else { "INVALID" }
        );
    }
    if a.pretty_print {
        return format!(
            "Field {name}\n{}\n{policy_diagnostic}The signature is judged {}.\n",
            status.pretty_print_details(),
            if valid { "VALID" } else { "INVALID" }
        );
    }
    format!(
        "{name}:{fingerprint}:{}{}\n{policy_diagnostic}",
        status.summary(),
        suffix.map(|s| format!(",{s}")).unwrap_or_default()
    )
}

#[derive(der::Sequence)]
struct CmsEnvelope<'a> {
    content_type: der::asn1::ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    content: Option<der::asn1::AnyRef<'a>>,
}
fn cms_der(path: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("Could not read CMS object: {e}"))?;
    let der = if sigis_pades_sign::keys::is_pem(&bytes) {
        let mut blocks = sigis_pades_sign::keys::parse_pem(&bytes)
            .map_err(|e| format!("Could not parse CMS object: {e}"))?;
        if blocks.len() != 1 {
            return Err(
                "Could not parse CMS object: exactly one CMS or PKCS7 PEM block is required."
                    .into(),
            );
        }
        let block = blocks
            .pop()
            .ok_or("Could not parse CMS object: missing PEM block.")?;
        if !matches!(block.label.as_str(), "CMS" | "PKCS7") {
            return Err(format!(
                "Could not parse CMS object: unsupported PEM label '{}'.",
                block.label
            ));
        }
        if !block.headers.is_empty() {
            return Err(
                "Could not parse CMS object: PEM headers are unsupported for CMS data.".into(),
            );
        }
        block.der
    } else {
        bytes
    };
    let envelope =
        CmsEnvelope::from_der(&der).map_err(|e| format!("Could not parse CMS object: {e}"))?;
    if envelope.content_type.to_string() != "1.2.840.113549.1.7.2" {
        return Err("CMS content type is not signedData".into());
    }
    Ok(der)
}

fn validate_cms(
    data: &[u8],
    der: &[u8],
    ctx: &ValidationContext,
    config: Option<&CliConfig>,
    name: Option<&str>,
) -> Result<StandardCmsSignatureStatus, String> {
    let usage = configured_usage(config, name)?;
    let options = sigis_cms::CmsValidationOptions {
        key_usage_settings: usage.clone(),
        ..Default::default()
    };
    let status = sigis_cms::validate_cms_signature_with(
        der,
        sigis_cms::SignedContent::Data(data),
        ctx,
        &options,
    )
    .map_err(validation_error)?;
    enforce_configured_usage(&status, usage)?;
    Ok(status)
}

fn configured_usage(
    config: Option<&CliConfig>,
    name: Option<&str>,
) -> Result<Option<sigis_pki_core::key_usage::KeyUsageConstraints>, String> {
    Ok(config
        .map(|c| c.key_usages(name))
        .transpose()
        .map_err(config_error)?
        .map(|p| crate::usage::key_usage_constraints(&p)))
}

fn enforce_configured_usage(
    status: &StandardCmsSignatureStatus,
    usage: Option<sigis_pki_core::key_usage::KeyUsageConstraints>,
) -> Result<(), String> {
    // The default status usage merge may discard policy flags. Enforce every
    // explicitly configured requirement, including forbidden usages, as well.
    if let Some(mut usage) = usage {
        let cert = status
            .signature
            .signing_cert
            .as_ref()
            .ok_or("No signing certificate was available for key usage validation.")?;
        // Class-level default usage and additional configured flags must both hold.
        if usage.key_usage.is_none() {
            usage.key_usage = Some(["non_repudiation".to_owned()].into());
        }
        if let Some(forbidden) = &usage.key_usage_forbidden {
            let asserted = sigis_pki_core::key_usage::cert_key_usages(cert).unwrap_or_default();
            if asserted.iter().any(|item| forbidden.contains(item)) {
                return Err(
                    "Signer key usage requirement was not met: a forbidden key usage was asserted."
                        .into(),
                );
            }
        }
        usage
            .validate(cert)
            .map_err(|e| format!("Signer key usage requirement was not met: {e}"))?;
    }
    Ok(())
}
fn validate_pdf(
    file: &PdfFile,
    signature: &sigis_pdf::signatures::EmbeddedSignature,
    ctx: &ValidationContext,
    config: Option<&CliConfig>,
    name: Option<&str>,
) -> Result<sigis_pades::PdfSignatureStatus, String> {
    let usage = configured_usage(config, name)?;
    let options = sigis_cms::CmsValidationOptions {
        key_usage_settings: usage.clone(),
        ..Default::default()
    };
    let status = sigis_pades::validate_pdf_signature_with_options(
        file,
        signature,
        ctx,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
        &options,
    )
    .map_err(validation_error)?;
    // Preserve the one public validator's complete verdict. A second CMS
    // validation can retrieve different evidence and overwrite a denial.
    enforce_configured_usage(&status.cms, usage)?;
    Ok(status)
}

/// Run using the current clock, real HTTP retrieval and interactive passwords.
pub fn run(args: &[String], config: Option<&CliConfig>, verbose: bool) -> Result<String, String> {
    run_with_runtime(args, config, verbose, &ValidationRuntime::default())
}

/// Validate with explicitly injected clock, native retrieval and password input.
pub fn run_with_runtime(
    args: &[String],
    config: Option<&CliConfig>,
    verbose: bool,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    let a = Args::parse_values(args)?;
    a.check()?;
    let moment = a.moment(runtime)?;
    let ctx = build_context(&a, config, runtime, moment)?;
    let bytes = std::fs::read(&a.infile).map_err(|e| format!("Failed to read PDF: {e}"))?;
    let mut output = if verbose {
        "Running with --verbose\n".into()
    } else {
        String::new()
    };
    let mut all_valid = true;
    if let Some(detached) = &a.detached {
        let der = cms_der(detached)?;
        let status = validate_cms(&bytes, &der, &ctx, config, a.validation_context.as_deref())?;
        all_valid = status.bottom_line();
        if a.pretty_print {
            output.push_str(&report("DETACHED", &status, all_valid, None, &a));
        } else if a.executive_summary {
            output.push_str(if all_valid { "VALID\n" } else { "INVALID\n" });
        } else {
            output.push_str(&status.summary());
            output.push('\n');
        }
    } else {
        let mut options = if a.no_strict_syntax {
            ReaderOptions::lenient()
        } else {
            ReaderOptions::default()
        };
        if a.no_decode_limits {
            options.decode_limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input()
        }
        let file = PdfFile::parse_with(&bytes, options).map_err(|e| {
            if a.no_strict_syntax {
                format!("Failed to read PDF: {e}")
            } else {
                format!("Failed to read PDF in strict mode; rerun with --no-strict-syntax: {e}")
            }
        })?;
        authenticate(&file, a.password.as_deref(), runtime)?;
        for signature in file.embedded_signatures().map_err(validation_error)? {
            if signature.kind != sigis_pdf::signatures::SignatureKind::Signature {
                continue;
            }
            let claimed_context = if a.validation_time.as_deref() == Some("claimed") {
                // Reading an untrusted attribute selects the explicitly
                // requested clock; it is not a first trust decision or POE.
                let der = sigis_pades::cms_from_contents(&signature.contents)
                    .map_err(validation_error)?;
                let signed_data = sigis_cms::SignedData::from_der(der).map_err(validation_error)?;
                let signer = sigis_cms::signed_data::extract_signer_info(&signed_data)
                    .map_err(validation_error)?;
                let claimed = sigis_cms::validate::extract_self_reported_ts(signer)
                    .ok_or("No claimed signing time was found.")?;
                Some(build_context(&a, config, runtime, claimed)?)
            } else {
                None
            };
            let status = validate_pdf(
                &file,
                &signature,
                claimed_context.as_ref().unwrap_or(&ctx),
                config,
                a.validation_context.as_deref(),
            )?;
            let valid = status.bottom_line() && status.cms.bottom_line();
            all_valid &= valid;
            let modification = if status.coverage == sigis_pades::SignatureCoverageLevel::EntireFile
            {
                "UNTOUCHED"
            } else if status.docmdp_ok == Some(false) {
                "MODIFIED"
            } else {
                "EXTENDED"
            };
            output.push_str(&report(
                &status.field_name,
                &status.cms,
                valid,
                Some(modification),
                &a,
            ));
        }
    }
    if all_valid {
        Ok(output)
    } else {
        Err(output.trim_end().to_owned())
    }
}
