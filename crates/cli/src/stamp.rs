//! Stamp command, derived from pyHanko 0.38.1 (MIT).
use crate::config::CliConfig;
use clap::Parser;
use sigis_pades_sign::{
    pdf::writer::PdfReopenState,
    stamp::{qr_stamp_pdf_with_state, text_stamp_pdf_with_state, StampStyle},
};
use std::collections::BTreeMap;

#[derive(Parser)]
#[command(name = "stamp")]
struct Args {
    #[arg(long)]
    style_name: Option<String>,
    #[arg(long, default_value_t = 1, allow_hyphen_values = true)]
    page: i64,
    #[arg(long)]
    stamp_url: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    text_param: Vec<String>,
    #[arg(long)]
    no_decode_limits: bool,
    infile: String,
    outfile: String,
    #[arg(allow_hyphen_values = true)]
    x: i32,
    #[arg(allow_hyphen_values = true)]
    y: i32,
}
/// Apply a configured stamp to a PDF file.
pub fn run(args: &[String], config: Option<&CliConfig>) -> Result<String, String> {
    let a = Args::try_parse_from(std::iter::once("stamp".to_owned()).chain(args.iter().cloned()))
        .map_err(|e| e.to_string())?;
    let config = config
        .ok_or("Using stamp styles requires a configuration file (pyhanko.yml by default).")?;
    let mut params = BTreeMap::new();
    for param in &a.text_param {
        let (key, value) = param.split_once(':').ok_or_else(|| {
            format!("--text-param must be of the form <name>:<value>, not f{param:?}")
        })?;
        if key.is_empty() || !key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
            return Err(format!(
                "--text-param must be of the form <name>:<value>, not f{param:?}"
            ));
        }
        params.insert(key.to_owned(), value.to_owned());
    }
    let style = config
        .stamp_style(a.style_name.as_deref())
        .map_err(|e| format!("Could not process stamp style: {e}"))?;
    match (&style, &a.stamp_url) {
        (StampStyle::Qr(_), None) => {
            return Err("QR stamp styles require the --stamp-url option.".into())
        }
        (StampStyle::Qr(_), Some(_)) => {}
        (_, Some(_)) => {
            return Err("The --stamp-url parameter is only meaningful for QR stamp styles.".into())
        }
        _ => {}
    }
    if a.page == 0 {
        return Err("Page numbers start at 1.".into());
    }
    let page = if a.page > 0 { a.page - 1 } else { a.page };
    let bytes = std::fs::read(&a.infile).map_err(|e| format!("Failed to read PDF: {e}"))?;
    let mut options = sigis_pdf::reader::ReaderOptions::default();
    if a.no_decode_limits {
        options.decode_limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input();
    }
    let reader =
        crate::read_for_update(&bytes, options).map_err(|e| format!("Failed to read PDF: {e}"))?;
    let state = PdfReopenState::from_reader(reader);
    let result = match style {
        StampStyle::Text(s) => text_stamp_pdf_with_state(
            &bytes,
            &s,
            page,
            a.x as f64,
            a.y as f64,
            Some(params),
            state,
        ),
        StampStyle::Qr(s) => qr_stamp_pdf_with_state(
            &bytes,
            &s,
            page,
            a.x as f64,
            a.y as f64,
            a.stamp_url.as_deref().expect("checked URL"),
            Some(params),
            state,
        ),
        _ => return Err("Unsupported stamp style for standalone stamping.".into()),
    };
    let result =
        result.map_err(|e| format!("Error raised while producing signature layout: {e}"))?;
    std::fs::write(&a.outfile, result.pdf).map_err(|e| e.to_string())?;
    Ok(String::new())
}
