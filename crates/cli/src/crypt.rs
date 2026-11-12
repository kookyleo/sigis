// Derived from pyHanko 0.38.1 cli/commands/crypt.py (MIT, see LICENSE-pyHanko).
//! PDF encryption and decryption commands.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use crate::runtime::ValidationRuntime;
use clap::{Args, Parser, Subcommand};
use openssl::{pkcs12::Pkcs12, pkey::PKey, x509::X509};
use sigis_pdf::crypt::{
    AuthStatus, HandlerType, PdfPermissions, PubKeyPermissions, SimpleEnvelopeKeyDecrypter,
};
use sigis_pdf::{PdfFile, ReaderOptions};

#[derive(Parser)]
#[command(name = "pyhanko")]
struct Commands {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt PDF files (AES-256 only).
    Encrypt(Encrypt),
    /// Decrypt PDF files.
    Decrypt {
        #[command(subcommand)]
        mode: Decrypt,
    },
}

#[derive(Args)]
struct InputOutput {
    infile: PathBuf,
    outfile: PathBuf,
    #[arg(long)]
    no_decode_limits: bool,
}

#[derive(Args)]
struct Encrypt {
    #[command(flatten)]
    files: InputOutput,
    #[arg(long, allow_hyphen_values = true)]
    password: Option<String>,
    #[arg(long)]
    recipient: Vec<PathBuf>,
}

#[derive(Args)]
struct Password {
    #[command(flatten)]
    files: InputOutput,
    #[arg(long, allow_hyphen_values = true)]
    password: Option<String>,
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct PrivateKey {
    #[command(flatten)]
    files: InputOutput,
    #[arg(long)]
    passfile: Option<PathBuf>,
    #[arg(long)]
    force: bool,
}

#[derive(Subcommand)]
enum Decrypt {
    Password(Password),
    Pemder {
        #[command(flatten)]
        options: PrivateKey,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        no_pass: bool,
    },
    Pkcs12 {
        #[command(flatten)]
        options: PrivateKey,
        pfx: PathBuf,
    },
}

fn message(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn pdf_message(error: sigis_pdf::PdfError) -> String {
    if matches!(error, sigis_pdf::PdfError::DecodeLimit(_)) {
        format!("{error}; rerun with --no-decode-limits to remove PDF decoding limits.")
    } else {
        error.to_string()
    }
}

fn prompt(text: &str, runtime: &ValidationRuntime) -> Result<String, String> {
    if let Some(password) = &runtime.password {
        return Ok(password.clone());
    }
    if io::stdin().is_terminal() {
        return rpassword::prompt_password(text).map_err(message);
    }
    eprint!("{text}");
    io::stderr().flush().map_err(message)?;
    let mut pass = String::new();
    io::stdin().read_line(&mut pass).map_err(message)?;
    while pass.ends_with(['\r', '\n']) {
        pass.pop();
    }
    Ok(pass)
}

fn read(files: &InputOutput) -> Result<PdfFile, String> {
    let bytes = std::fs::read(&files.infile).map_err(message)?;
    let mut options = ReaderOptions::default();
    if files.no_decode_limits {
        options.decode_limits = sigis_pdf::decode_limits::DecodeLimits::for_trusted_input();
    }
    PdfFile::parse_with(&bytes, options).map_err(pdf_message)
}

fn write_plain(reader: &PdfFile, output: &PathBuf) -> Result<(), String> {
    let mut writer = sigis_pdf::writer::copy_into_new_writer(reader).map_err(pdf_message)?;
    std::fs::write(output, writer.write().map_err(pdf_message)?).map_err(message)
}

fn certificate(data: &[u8]) -> Result<X509, String> {
    X509::from_pem(data)
        .or_else(|_| X509::from_der(data))
        .map_err(message)
}

fn passphrase(
    options: &PrivateKey,
    pem: bool,
    no_pass: bool,
    runtime: &ValidationRuntime,
) -> Result<Vec<u8>, String> {
    if let Some(path) = &options.passfile {
        let bytes = std::fs::read(path).map_err(message)?;
        if pem {
            Ok(bytes)
        } else {
            let text = String::from_utf8(bytes).map_err(message)?;
            Ok(text.lines().next().unwrap_or("").trim().as_bytes().to_vec())
        }
    } else if no_pass {
        Ok(Vec::new())
    } else {
        Ok(prompt("Key passphrase: ", runtime)?.into_bytes())
    }
}

fn decrypt_pubkey(
    reader: PdfFile,
    key: SimpleEnvelopeKeyDecrypter,
    options: PrivateKey,
) -> Result<(), String> {
    let handler = reader
        .security_handler()
        .map_err(pdf_message)?
        .ok_or_else(|| "File is not encrypted.".to_string())?;
    if handler.handler_type() != HandlerType::PubKey {
        return Err("File was not encrypted with a public-key security handler.".into());
    }
    let auth = reader.decrypt_pubkey(&key).map_err(pdf_message)?;
    if auth.status == AuthStatus::Failed {
        return Err("Failed to decrypt the file.".into());
    }
    if !options.force
        && matches!(auth.permission_flags,
        Some(PdfPermissions::PubKey(perms)) if !perms.contains(PubKeyPermissions::ALLOW_ENCRYPTION_CHANGE))
    {
        return Err("Change of encryption is typically not allowed with user access. Pass --force to decrypt the file anyway.".into());
    }
    write_plain(&reader, &options.files.outfile)
}

/// Run an `encrypt` or `decrypt` command with the production password prompt.
pub fn run(args: &[String]) -> Result<String, String> {
    run_with_runtime(args, &ValidationRuntime::default())
}

/// Run an encryption command with the injected CLI password prompter.
/// `args` includes the leading `encrypt` or `decrypt` command name.
pub fn run_with_runtime(args: &[String], runtime: &ValidationRuntime) -> Result<String, String> {
    let parsed =
        Commands::try_parse_from(std::iter::once("pyhanko").chain(args.iter().map(String::as_str)))
            .map_err(message)?;
    match parsed.command {
        Command::Encrypt(options) => {
            if options.password.as_ref().is_some_and(|p| !p.is_empty())
                && !options.recipient.is_empty()
            {
                return Err("Specify either a password or a list of recipients.".into());
            }
            let reader = read(&options.files)?;
            let mut writer =
                sigis_pdf::writer::copy_into_new_writer(&reader).map_err(pdf_message)?;
            if options.recipient.is_empty() {
                let pass = match options.password.filter(|p| !p.is_empty()) {
                    Some(pass) => pass,
                    None => prompt("Output file password: ", runtime)?,
                };
                writer.encrypt(&pass, None).map_err(pdf_message)?;
            } else {
                let mut recipients = Vec::new();
                for path in options.recipient {
                    let bytes = std::fs::read(path).map_err(message)?;
                    if bytes.starts_with(b"-----BEGIN") {
                        for cert in X509::stack_from_pem(&bytes).map_err(message)? {
                            recipients.push(cert.to_der().map_err(message)?);
                        }
                    } else {
                        recipients.push(certificate(&bytes)?.to_der().map_err(message)?);
                    }
                }
                if recipients.is_empty() {
                    return Err("No recipient certificates were found.".into());
                }
                writer.encrypt_pubkey(&recipients).map_err(pdf_message)?;
            }
            std::fs::write(options.files.outfile, writer.write().map_err(pdf_message)?)
                .map_err(message)?;
        }
        Command::Decrypt {
            mode: Decrypt::Password(options),
        } => {
            let reader = read(&options.files)?;
            let handler = reader
                .security_handler()
                .map_err(pdf_message)?
                .ok_or_else(|| "File is not encrypted.".to_string())?;
            if handler.handler_type() != HandlerType::Standard {
                return Err(
                    "File is not encrypted with the standard (password-based) security handler"
                        .into(),
                );
            }
            let pass = match options.password.filter(|p| !p.is_empty()) {
                Some(pass) => pass,
                None => prompt("File password: ", runtime)?,
            };
            match reader.decrypt(pass).map_err(pdf_message)?.status {
                AuthStatus::User if !options.force => return Err("Password specified was the user password, not the owner password. Pass --force to decrypt the file anyway.".into()),
                AuthStatus::Failed => return Err("Password didn't match.".into()),
                _ => {}
            }
            write_plain(&reader, &options.files.outfile)?;
        }
        Command::Decrypt {
            mode:
                Decrypt::Pemder {
                    options,
                    key,
                    cert,
                    no_pass,
                },
        } => {
            let pass = passphrase(&options, true, no_pass, runtime)?;
            let key_bytes = std::fs::read(key).map_err(message)?;
            let key = PKey::private_key_from_pem_passphrase(&key_bytes, &pass)
                .or_else(|_| PKey::private_key_from_pkcs8_passphrase(&key_bytes, &pass))
                .or_else(|_| PKey::private_key_from_der(&key_bytes))
                .map_err(message)?;
            let cert = certificate(&std::fs::read(cert).map_err(message)?)?;
            let decrypter = SimpleEnvelopeKeyDecrypter::new(
                &cert.to_der().map_err(message)?,
                &key.private_key_to_pkcs8().map_err(message)?,
            )
            .map_err(message)?;
            let reader = read(&options.files)?;
            decrypt_pubkey(reader, decrypter, options)?;
        }
        Command::Decrypt {
            mode: Decrypt::Pkcs12 { options, pfx },
        } => {
            let pass = passphrase(&options, false, false, runtime)?;
            let pass = String::from_utf8(pass).map_err(message)?;
            let archive =
                Pkcs12::from_der(&std::fs::read(pfx).map_err(message)?).map_err(message)?;
            let parsed = archive.parse2(&pass).map_err(message)?;
            let key = parsed
                .pkey
                .ok_or("PKCS#12 file does not contain a private key")?;
            let cert = parsed
                .cert
                .ok_or("PKCS#12 file does not contain a certificate")?;
            let decrypter = SimpleEnvelopeKeyDecrypter::new(
                &cert.to_der().map_err(message)?,
                &key.private_key_to_pkcs8().map_err(message)?,
            )
            .map_err(message)?;
            let reader = read(&options.files)?;
            decrypt_pubkey(reader, decrypter, options)?;
        }
    }
    Ok(String::new())
}
