// Derived from pyHanko0.38.1 CLI validation/ltv.py (MIT, see LICENSE-pyHanko).
//! Incremental DSS repair and archival timestamp renewal.
use crate::{config::CliConfig, runtime::ValidationRuntime};
use clap::Parser;
use sigis_pades_sign::pdf::{
    embedded::embedded_signatures,
    timestamp::{
        add_validation_info_for_with_state, timestamp_pdf_with_state,
        update_archival_chain_with_state, TimestampOptions,
    },
    writer::{PdfReopenState, PdfUpdate},
};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{
    algorithms::DigestAlgorithm,
    errors::{HankoError, Result as HankoResult},
    key_usage::KeyUsageConstraints,
    sign::TimeStamper,
};

#[derive(Parser)]
#[command(name = "ltv")]
struct Args {
    #[arg(long)]
    field: Option<String>,
    #[arg(long)]
    timestamp_url: Option<String>,
    #[arg(long)]
    validation_context: Option<String>,
    #[arg(long)]
    no_decode_limits: bool,
    #[arg(long)]
    retroactive_revinfo: bool,
    infile: String,
}

#[derive(Debug)]
struct ValidatedTsa<'a> {
    http: sigis_pki_fetch::HttpTimeStamper,
    context: &'a ValidationContext,
}

impl TimeStamper for ValidatedTsa<'_> {
    fn timestamp(&self, imprint: &[u8], digest: DigestAlgorithm) -> HankoResult<Vec<u8>> {
        let token = self.http.timestamp(imprint, digest)?;
        let info = sigis_pades_sign::timestamps::tst_info(&token)?;
        if DigestAlgorithm::from_oid(&info.message_imprint.hash_algorithm.oid) != Some(digest) {
            return Err(HankoError::Signing(
                "The timestamp response changed the requested message imprint algorithm.".into(),
            ));
        }
        let status = sigis_cms::validate_timestamp_token(&token, imprint, self.context)?;
        let certificate = status.signature.signing_cert.as_ref().ok_or_else(|| {
            HankoError::Signing("The TSA token has no signing certificate.".into())
        })?;
        KeyUsageConstraints::with_extd_key_usage(["time_stamping"])
            .validate(certificate)
            .map_err(|error| {
                HankoError::Signing(format!(
                    "The TSA must explicitly assert time_stamping: {error}"
                ))
            })?;
        if !status.signature.bottom_line() {
            return Err(HankoError::Signing(format!(
                "The TSA token did not satisfy integrity, validity and trust requirements: {status:?}"
            )));
        }
        Ok(token)
    }
}

/// Run `sign ltaupdate` or `sign ltvfix` with the selected complete context.
///
/// `args[0]` is the subcommand. Input is overwritten only after the complete
/// operation succeeds. Continuing operations preserve the authenticated reader's
/// strictness and spent decode budget rather than opening a fresh default reader.
pub fn run_with_runtime(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &ValidationRuntime,
) -> Result<String, String> {
    let command = args.first().ok_or("An LTV command is required.")?;
    if !["ltaupdate", "ltvfix"].contains(&command.as_str()) {
        return Err(format!("Unknown LTV command '{command}'."));
    }
    let options = Args::try_parse_from(args.iter().cloned()).map_err(|error| error.to_string())?;
    if command == "ltaupdate" && options.timestamp_url.is_none() {
        return Err("The --timestamp-url option is required.".into());
    }
    if command == "ltvfix" && options.field.is_none() {
        return Err("The --field option is required.".into());
    }
    if command == "ltaupdate" && options.field.is_some() {
        return Err("--field is not supported by ltaupdate.".into());
    }
    if options.retroactive_revinfo {
        return Err(
            "Retroactive revocation information is not supported by this LTV command.".into(),
        );
    }
    let context = crate::validation::context_from_config(
        config,
        options.validation_context.as_deref(),
        runtime,
    )?;
    // Upstream explicitly supplies false for these original commands. Refuse a
    // conflicting mandatory setting instead of reconstructing a weaker context.
    if context.revinfo_policy().retroactive_revinfo {
        return Err(
            "The configured retroactive revocation setting conflicts with this LTV command.".into(),
        );
    }
    let input = std::fs::read(&options.infile).map_err(|error| error.to_string())?;
    let mut reader_options = sigis_pdf::ReaderOptions::default();
    if options.no_decode_limits {
        reader_options.decode_limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input();
    }
    let reader =
        crate::read_for_update(&input, reader_options).map_err(|error| error.to_string())?;
    if reader.encrypted() {
        return Err("Encrypted PDF input is not supported by the LTV commands.".into());
    }
    let state = PdfReopenState::from_reader(reader);
    let tsa = options.timestamp_url.as_ref().map(|url| ValidatedTsa {
        http: sigis_pki_fetch::HttpTimeStamper::new(url),
        context: &context,
    });
    let output = if command == "ltaupdate" {
        update_archival_chain_with_state(
            &input,
            tsa.as_ref().unwrap(),
            &context,
            DigestAlgorithm::Sha256,
            state,
        )
        .map_err(|error| error.to_string())?
    } else {
        let update =
            PdfUpdate::open_with_state(&input, state).map_err(|error| error.to_string())?;
        let field = options.field.as_deref().unwrap();
        let signature = embedded_signatures(&update)
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|signature| !signature.is_doc_timestamp && signature.field_name == field)
            .ok_or_else(|| format!("Could not find a PDF signature labelled {field}."))?;
        let output = add_validation_info_for_with_state(
            &input,
            &signature,
            &context,
            true,
            true,
            true,
            update.state(),
        )
        .map_err(|error| error.to_string())?;
        if let Some(tsa) = tsa.as_ref() {
            let mut settings = TimestampOptions::new(DigestAlgorithm::Sha256);
            settings.validation_context = Some(&context);
            settings.reopen_state = Some(output.state);
            timestamp_pdf_with_state(&output.pdf, tsa, None, &settings)
                .map_err(|error| error.to_string())?
        } else {
            output
        }
    };
    std::fs::write(&options.infile, output.pdf).map_err(|error| error.to_string())?;
    Ok(String::new())
}
