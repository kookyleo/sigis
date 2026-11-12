//! Signature field management compatible with pyHanko 0.38.1.
use sigis_pades_sign::pdf::{
    fields::{append_signature_field, SigFieldSpec},
    writer::PdfUpdate,
};
use sigis_pdf::{reader::ReaderOptions, signatures::enumerate_sig_fields};

/// Parse a CLI field location, preserving pyHanko's diagnostic messages.
pub fn parse_field_spec(value: &str) -> Result<SigFieldSpec, String> {
    let parts: Vec<_> = value.split('/').collect();
    if parts.len() != 3 {
        return Err("Sig field spec should be of the form PAGE/X1,Y1,X2,Y2/NAME.".into());
    }
    let page = parts[0]
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|&p| p != 0)
        .ok_or_else(|| {
            format!(
                "Sig field parameter PAGE should be a nonzero integer, not {}.",
                parts[0]
            )
        })?;
    let coords = parts[1]
        .split(',')
        .map(|v| v.trim().parse::<i64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Sig field parameters X1,Y1,X2,Y2 should be four integers.".to_owned())?;
    if coords.len() != 4 {
        return Err("Sig field parameters X1,Y1,X2,Y2 should be four integers.".into());
    }
    Ok(SigFieldSpec::new(parts[2])
        .on_page(if page > 0 { page - 1 } else { page })
        .with_box((
            coords[0] as f64,
            coords[1] as f64,
            coords[2] as f64,
            coords[3] as f64,
        )))
}

/// Execute `sign list` or `sign addfields`; arguments begin with the subcommand.
pub fn run(args: &[String]) -> Result<String, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("Missing field command.".into());
    };
    if crate::argument_positions(args).any(|i| args[i] == "--help") {
        return Ok(format!(
            "Usage: pyhanko sign {command} [OPTIONS] INFILE{}\n",
            if command == "addfields" {
                " OUTFILE"
            } else {
                ""
            }
        ));
    }
    let mut paths = Vec::new();
    let mut specs = Vec::new();
    let mut skip = false;
    let mut resave = false;
    let mut no_limits = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--skip-status" if command == "list" => skip = true,
            "--resave" if command == "addfields" => resave = true,
            "--no-decode-limits" => no_limits = true,
            "--field" if command == "addfields" => {
                i += 1;
                specs.push(parse_field_spec(
                    args.get(i).ok_or("Missing value for --field.")?,
                )?);
            }
            "--" => {
                paths.extend_from_slice(&args[i + 1..]);
                break;
            }
            value if value.starts_with('-') => return Err(format!("No such option: {value}")),
            _ => paths.push(args[i].clone()),
        }
        i += 1;
    }
    let expected = match command {
        "list" => 1,
        "addfields" => 2,
        _ => return Err(format!("No such command: {command}")),
    };
    if paths.len() != expected {
        return Err("Incorrect number of file arguments.".into());
    }
    if command == "addfields" && specs.is_empty() {
        return Err("Missing option '--field'.".into());
    }
    let bytes =
        std::fs::read(&paths[0]).map_err(|e| format!("Could not open file '{}': {e}", paths[0]))?;
    let mut options = ReaderOptions::lenient();
    if no_limits {
        options.decode_limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input();
    }
    let pdf =
        crate::read_for_update(&bytes, options).map_err(|e| format!("Failed to read PDF: {e}"))?;
    if pdf.encrypted() {
        return Err("Failed to read PDF: signature field management requires authentication for encrypted documents.".into());
    }
    if command == "list" {
        let mut output = String::new();
        for field in enumerate_sig_fields(&pdf, None, None).map_err(|e| e.to_string())? {
            output.push_str(&field.fq_name);
            if !skip {
                output.push_str(if field.value.is_some() {
                    ":FILLED"
                } else {
                    ":EMPTY"
                });
            }
            output.push('\n');
        }
        return Ok(output);
    }
    let mut writer = if resave {
        PdfUpdate::fresh(&bytes)
    } else {
        PdfUpdate::new(&bytes)
    }
    .map_err(|e| format!("Failed to read PDF: {e}"))?;
    writer.set_strict(false);
    for spec in specs {
        append_signature_field(&mut writer, &spec).map_err(|e| e.to_string())?;
    }
    let output = writer.write().map_err(|e| e.to_string())?.0;
    std::fs::write(&paths[1], output).map_err(|e| e.to_string())?;
    Ok(String::new())
}
