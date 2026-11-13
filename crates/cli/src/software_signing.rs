// Derived from pyHanko 0.38.1 CLI signing commands (MIT, see LICENSE-pyHanko).
//! Ordinary PEM/DER and PKCS#12 PDF signing with explicit bounded capabilities.
use crate::config::CliConfig;
use sigis_pades_sign::pdf::writer::PdfReopenState;
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SignOptions, SimpleSigner};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
    sync::Arc,
};

#[derive(Default)]
pub(crate) struct Options {
    pub(crate) values: BTreeMap<String, Vec<String>>,
    pub(crate) flags: BTreeSet<String>,
    pub(crate) paths: Vec<String>,
    repeated_flags: BTreeSet<String>,
}
impl Options {
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.values
            .get(key)
            .and_then(|v| v.last())
            .map(String::as_str)
    }
    pub(crate) fn flag(&self, key: &str) -> bool {
        self.flags.contains(key)
    }
}
pub(crate) fn options(args: &[String]) -> Result<Options, String> {
    let value_options = [
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
        "reason",
        "location",
        "contact-info",
        "name",
        "docmdp-permissions",
        "password",
        "md-algorithm",
    ];
    let flag_options = [
        "no-pass",
        "detach",
        "detach-pem",
        "existing-only",
        "no-strict-syntax",
        "no-decode-limits",
        "with-validation-info",
        "use-pades-lta",
        "use-pades",
        "prefer-pss",
        "certify",
        "trust-replace",
        "retroactive-revinfo",
        "no-revocation-check",
        "soft-revocation-check",
        "force-revinfo",
    ];
    let mut out = Options::default();
    let mut i = 0;
    while i < args.len() {
        let s = &args[i];
        if s == "--" {
            out.paths.extend_from_slice(&args[i + 1..]);
            break;
        }
        if let Some(s) = s.strip_prefix("--") {
            let (key, inline) = s
                .split_once('=')
                .map(|(k, v)| (k, Some(v)))
                .unwrap_or((s, None));
            if value_options.contains(&key) {
                let value = if let Some(v) = inline {
                    v.to_owned()
                } else {
                    i += 1;
                    args.get(i)
                        .ok_or_else(|| format!("Option --{key} requires an argument."))?
                        .clone()
                };
                out.values.entry(key.into()).or_default().push(value);
            } else if flag_options.contains(&key) && inline.is_none() {
                if !out.flags.insert(key.into()) {
                    out.repeated_flags.insert(key.into());
                }
            } else {
                return Err(format!("No such option: --{key}"));
            }
        } else {
            out.paths.push(s.clone());
        }
        i += 1;
    }
    Ok(out)
}
pub(crate) fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("Could not read '{path}': {e}"))
}
pub(crate) fn prompt(
    label: &str,
    runtime: &crate::runtime::ValidationRuntime,
) -> Result<Vec<u8>, String> {
    if let Some(password) = &runtime.password {
        return Ok(password.as_bytes().to_vec());
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return rpassword::prompt_password(label)
            .map(String::into_bytes)
            .map_err(|e| e.to_string());
    }
    eprint!("{label}");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    Ok(line.into_bytes())
}
pub(crate) fn authenticate_document(
    reader: &sigis_pdf::PdfFile,
    options: &Options,
    runtime: &crate::runtime::ValidationRuntime,
) -> Result<Option<Vec<u8>>, String> {
    if !reader.encrypted() {
        return Ok(None);
    }
    let encryption = reader
        .encrypt_dict()
        .map_err(|e| e.to_string())?
        .ok_or("Invalid encryption dictionary.")?;
    if encryption
        .get(b"Filter")
        .and_then(|object| object.as_name())
        .ok()
        != Some(b"Standard".as_slice())
    {
        return Err("Public-key document encryption is not supported".into());
    }
    let password = match options.get("password") {
        Some(password) => password.as_bytes().to_vec(),
        None => prompt("Password to decrypt file: ", runtime)?,
    };
    let text = std::str::from_utf8(&password).map_err(|e| format!("Invalid password: {e}"))?;
    let authentication = reader
        .decrypt(text)
        .map_err(|e| format!("Failed to authenticate encrypted document: {e}"))?;
    if authentication.status == sigis_pdf::crypt::AuthStatus::Failed {
        return Err("Invalid password".into());
    }
    Ok(Some(password))
}

pub(crate) fn passphrase(
    options: &Options,
    configured: Option<&[u8]>,
    runtime: &crate::runtime::ValidationRuntime,
) -> Result<Option<Vec<u8>>, String> {
    if options.flag("no-pass") {
        return Ok(None);
    }
    if let Some(path) = options.get("passfile") {
        let mut data = read(path)?;
        while data.last().is_some_and(|b| matches!(b, b'\n' | b'\r')) {
            data.pop();
        }
        return Ok(Some(data));
    }
    if let Some(p) = configured {
        return Ok(Some(p.to_vec()));
    }
    Ok(Some(prompt("Key passphrase: ", runtime)?))
}
fn certificates(options: &Options) -> Result<Vec<sigis_pki_core::cert::Cert>, String> {
    let mut out = Vec::new();
    for path in options.values.get("chain").into_iter().flatten() {
        let b = read(path).map_err(|e| format!("Could not load certificates: {e}"))?;
        out.extend(
            sigis_pades_sign::keys::load_certs_from_pemder_data(&b)
                .map_err(|e| format!("Could not load certificates: {e}"))?,
        );
    }
    Ok(out)
}

pub(crate) fn raw_material(
    provider: &str,
    options: &Options,
    runtime: &crate::runtime::ValidationRuntime,
) -> Result<SimpleSigner, String> {
    let chain = certificates(options)?;
    let signer = match provider {
        "pemder" => {
            let key = options
                .get("key")
                .ok_or("The --key option must be provided.")?;
            let cert = options
                .get("cert")
                .ok_or("The --cert option must be provided.")?;
            let pass = passphrase(options, None, runtime)?;
            SimpleSigner::load(&read(key)?, &read(cert)?, pass.as_deref(), chain)
        }
        "pkcs12" => {
            let pfx = options
                .paths
                .get(2)
                .ok_or("The PFX argument or the --p12-setup option must be provided.")?;
            let pass = passphrase(options, None, runtime)?;
            SimpleSigner::from_pkcs12_with_certs(&read(pfx)?, pass.as_deref(), chain)
        }
        _ => return Err(format!("Unsupported signing provider '{provider}'.")),
    };
    signer.map_err(|e| format!("Could not load key material: {e}"))
}

pub(crate) fn sign_pdf_and_write(
    pdf_signer: &PdfSigner,
    input: &[u8],
    signing_options: &SignOptions,
    output_path: &str,
) -> Result<String, String> {
    let signed = pdf_signer
        .sign_pdf_with_state(input, signing_options)
        .map_err(|e| {
            let text = e.to_string();
            if signing_options.password.is_some() && text.to_ascii_lowercase().contains("password")
            {
                format!("Invalid password: {text}")
            } else {
                text
            }
        })?;
    std::fs::write(output_path, signed.pdf).map_err(|e| e.to_string())?;
    Ok(String::new())
}

fn extended(requirement: &str) -> String {
    format!("{requirement} requires extended software signing; it is not supported by this ordinary signing entry point.")
}

/// Validate the complete basic scope before opening keys, prompting or writing.
pub(crate) fn check_basic(
    provider: &str,
    options: &Options,
    config: Option<&CliConfig>,
) -> Result<(), String> {
    if !matches!(provider, "pemder" | "pkcs12") {
        return Err(extended(provider));
    }
    // Public effective fields can differ from raw_config. The bounded entry
    // accepts no configuration object; extended callers retain the whole object.
    if config.is_some() {
        return Err(extended("Signing configuration"));
    }
    if let Some(key) = options.repeated_flags.iter().next() {
        return Err(extended(&format!("Repeated --{key}")));
    }
    for flag in &options.flags {
        if flag != "no-pass" {
            return Err(extended(&format!("--{flag}")));
        }
    }
    for (key, values) in &options.values {
        let supported = key == "field"
            || (provider == "pemder" && matches!(key.as_str(), "key" | "cert" | "chain"));
        if !supported || (key != "chain" && values.len() != 1) {
            return Err(extended(&format!("--{key}")));
        }
    }
    let field = options
        .get("field")
        .ok_or_else(|| extended("An implicit signature field"))?;
    if field.is_empty() || field.contains('/') {
        return Err(extended("A visible or empty field specification"));
    }
    let expected = if provider == "pemder" { 2 } else { 3 };
    if options.paths.len() != expected {
        return Err(extended("Invalid input/output/key positional arguments"));
    }
    if provider == "pemder" {
        for key in ["key", "cert"] {
            if options.get(key).is_none() {
                return Err(extended(&format!("Missing --{key}")));
            }
        }
    }
    Ok(())
}

/// Sign an ordinary PDF with a raw PEM/DER or PKCS#12 identity.
///
/// Other signing requirements and all supplied configuration reject explicitly
/// before key loading, prompting, network use or output replacement. Encrypted
/// input requires the extended authentication pipeline and is rejected here.
/// Arguments are the complete tokens after `sign addsig`, including the provider.
pub fn run_with_runtime(
    args: &[String],
    config: Option<&CliConfig>,
    runtime: &crate::runtime::ValidationRuntime,
) -> Result<String, String> {
    let at = crate::argument_positions(args)
        .find(|&i| {
            matches!(
                args[i].as_str(),
                "pemder" | "pkcs12" | "identity" | "pkcs11" | "beid" | "csc"
            )
        })
        .ok_or_else(|| extended("A missing software signing provider"))?;
    let provider = &args[at];
    let mut combined = args[..at].to_vec();
    combined.extend_from_slice(&args[at + 1..]);
    let opts = options(&combined)?;
    check_basic(provider, &opts, config)?;
    run_basic(provider, &opts, runtime, false)
}

// The full owner can retain authenticated raw encrypted signing; the standalone
// entry point above deliberately refuses it before key/password prompting.
pub(crate) fn run_basic(
    provider: &str,
    opts: &Options,
    runtime: &crate::runtime::ValidationRuntime,
    allow_encrypted: bool,
) -> Result<String, String> {
    let input = read(&opts.paths[0])?;
    let reader = crate::read_for_update(&input, sigis_pdf::ReaderOptions::default())
        .map_err(|e| e.to_string())?;
    if reader.encrypted() && !allow_encrypted {
        return Err(extended("Encrypted PDF input"));
    }
    let password = authenticate_document(&reader, opts, runtime)?;
    let signing_options = SignOptions {
        strict: true,
        password,
        reopen_state: Some(PdfReopenState::from_reader(reader)),
        ..Default::default()
    };
    let signer = raw_material(provider, opts, runtime)?;
    let metadata =
        PdfSignatureMetadata::pyhanko_defaults(opts.get("field").expect("validated field"));
    let mut pdf_signer = PdfSigner::new(metadata, Arc::new(signer));
    pdf_signer.signing_time = Some(runtime.now);
    pdf_signer.stamp_style = Some(CliConfig::parse("")?.stamp_style(None)?);
    sign_pdf_and_write(&pdf_signer, &input, &signing_options, &opts.paths[1])
}
