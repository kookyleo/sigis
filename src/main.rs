use axum::{
    extract::{DefaultBodyLimit, Multipart, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509,
    },
};
use serde_json::{json, Value};
use std::{
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use underskrift::{
    error::{PdfSignError, VerifyError},
    policy::BasicPdfSignaturePolicy,
    trust::{TrustStore, TrustStoreSet},
    verify::{
        report::{CryptoValidity, SignatureStatus},
        SignatureVerifier,
    },
    PdfSigner, SigningOptions, SoftwareSigner, SubFilter,
};
use zeroize::Zeroizing;

const MAX_BODY: usize = 25 * 1024 * 1024;
const MAX_PDF: usize = 20 * 1024 * 1024;
const MAX_KEY: usize = 2 * 1024 * 1024;
const DEMO_FILE: &str = "demo-signer.p12";
const DEMO_PASSWORD: &str = "sigis-demo";
const DEMO_NAME: &str = "Sigis Demo Signer";

#[derive(Clone)]
struct AppState {
    /// Demo certificate plus any roots from SIGIS_TRUST_ROOTS.
    trust_roots: Arc<TrustStore>,
    custom_trust_roots: bool,
    demo: Arc<DemoCert>,
}

/// Locally generated self-signed certificate used when no PKCS#12 is uploaded.
struct DemoCert {
    pkcs12: Zeroizing<Vec<u8>>,
    cert_der: Vec<u8>,
    path: PathBuf,
}

type ApiError = (StatusCode, Json<Value>);
type ApiResult<T> = Result<T, ApiError>;

fn error(status: StatusCode, message: &str) -> ApiError {
    (status, Json(json!({"error": message})))
}

fn bad_request(message: &str) -> ApiError {
    error(StatusCode::BAD_REQUEST, message)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn demo_certificate(State(state): State<AppState>) -> Json<Value> {
    let fingerprint = openssl::sha::sha256(&state.demo.cert_der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Json(json!({
        "subject": DEMO_NAME,
        "sha256_fingerprint": fingerprint,
        "path": state.demo.path,
        "note": "Self-signed demo certificate generated on this machine. It is trusted only by this service."
    }))
}

fn generate_demo_pkcs12() -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, DEMO_NAME)?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Sigis demo (not for production)")?;
    let name = name.build();
    let mut serial = BigNum::new()?;
    serial.rand(127, MsbOption::MAYBE_ZERO, false)?;
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    cert.set_serial_number(Asn1Integer::from_bn(&serial)?.as_ref())?;
    cert.set_subject_name(&name)?;
    cert.set_issuer_name(&name)?;
    cert.set_pubkey(&key)?;
    cert.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    cert.set_not_after(Asn1Time::days_from_now(3650)?.as_ref())?;
    cert.append_extension(BasicConstraints::new().critical().build()?)?;
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .non_repudiation()
            .build()?,
    )?;
    let ski = SubjectKeyIdentifier::new().build(&cert.x509v3_context(None, None))?;
    cert.append_extension(ski)?;
    cert.sign(&key, MessageDigest::sha256())?;
    let cert = cert.build();
    Pkcs12::builder()
        .name(DEMO_NAME)
        .pkey(&key)
        .cert(&cert)
        .build2(DEMO_PASSWORD)?
        .to_der()
}

/// Load the demo PKCS#12 from `dir`, generating it on first use.
fn load_or_create_demo(dir: &Path) -> Result<DemoCert, Box<dyn std::error::Error>> {
    let path = dir.join(DEMO_FILE);
    if !path.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)?;
        // Write a private temp file, then link it into place so that
        // concurrent first runs never see a partial file or overwrite each other.
        let tmp = dir.join(format!(".{DEMO_FILE}.{}", uuid::Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let written = options
            .open(&tmp)
            .and_then(|mut file| {
                file.write_all(&generate_demo_pkcs12()?)?;
                file.sync_all()
            })
            .and_then(|_| match std::fs::hard_link(&tmp, &path) {
                Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
                _ => Ok(()),
            });
        let _ = std::fs::remove_file(&tmp);
        written?;
    }
    let pkcs12 = Zeroizing::new(std::fs::read(&path)?);
    let invalid = || {
        format!(
            "Invalid demo certificate {}; delete it to regenerate",
            path.display()
        )
    };
    let cert_der = Pkcs12::from_der(&pkcs12)
        .and_then(|p| p.parse2(DEMO_PASSWORD))
        .ok()
        .and_then(|p| p.cert)
        .and_then(|c| c.to_der().ok())
        .ok_or_else(invalid)?;
    load_signer(&pkcs12, DEMO_PASSWORD).ok_or_else(invalid)?;
    Ok(DemoCert {
        pkcs12,
        cert_der,
        path,
    })
}

struct Upload {
    pdf: Vec<u8>,
    pkcs12: Option<Zeroizing<Vec<u8>>>,
    password: Option<Zeroizing<String>>,
}

async fn parse_upload(mut multipart: Multipart, accepts_key: bool) -> ApiResult<Upload> {
    let mut pdf = None;
    let mut pkcs12 = None;
    let mut password = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| bad_request("Invalid multipart request"))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "pdf" if pdf.is_none() => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| bad_request("Could not read PDF"))?;
                if bytes.is_empty() || bytes.len() > MAX_PDF {
                    return Err(bad_request("PDF must be between 1 byte and 20 MiB"));
                }
                pdf = Some(bytes.to_vec());
            }
            "pkcs12" if accepts_key && pkcs12.is_none() => {
                let bytes = Zeroizing::new(
                    field
                        .bytes()
                        .await
                        .map_err(|_| bad_request("Could not read PKCS#12 file"))?
                        .to_vec(),
                );
                // An empty file field means "use the demo certificate".
                if bytes.len() > MAX_KEY {
                    return Err(bad_request("PKCS#12 file must not exceed 2 MiB"));
                }
                pkcs12 = Some(bytes);
            }
            "password" if accepts_key && password.is_none() => {
                let value = Zeroizing::new(
                    field
                        .text()
                        .await
                        .map_err(|_| bad_request("Could not read password"))?,
                );
                if value.len() > 4096 {
                    return Err(bad_request("Password is too long"));
                }
                password = Some(value);
            }
            _ => return Err(bad_request("Unexpected or duplicate form field")),
        }
    }
    let pdf = pdf.ok_or_else(|| bad_request("PDF is required"))?;
    Ok(Upload {
        pdf,
        pkcs12: pkcs12.filter(|key| !key.is_empty()),
        password,
    })
}

fn load_modern_rsa_pkcs12(data: &[u8], password: &str) -> Option<SoftwareSigner> {
    let parsed = openssl::pkcs12::Pkcs12::from_der(data)
        .ok()?
        .parse2(password)
        .ok()?;
    let key = parsed.pkey?;
    let cert = parsed.cert?;
    if !cert.public_key().ok()?.public_eq(&key) {
        return None;
    }
    let mut chain = vec![cert.to_der().ok()?];
    if let Some(ca) = parsed.ca {
        for cert in ca {
            chain.push(cert.to_der().ok()?);
        }
    }
    let der = Zeroizing::new(key.private_key_to_pkcs8().ok()?);
    SoftwareSigner::from_rsa_der(&der, chain).ok()
}

fn load_signer(data: &[u8], password: &str) -> Option<SoftwareSigner> {
    SoftwareSigner::from_pkcs12_data(data, password)
        .ok()
        .or_else(|| load_modern_rsa_pkcs12(data, password))
}

async fn sign(State(state): State<AppState>, multipart: Multipart) -> ApiResult<Response> {
    let upload = parse_upload(multipart, true).await?;
    let signer = match &upload.pkcs12 {
        Some(key) => load_signer(key, upload.password.as_deref().map_or("", |p| p.as_str()))
            .ok_or_else(|| {
                bad_request("Invalid or unsupported PKCS#12 file, key type, or password")
            })?,
        None => load_signer(&state.demo.pkcs12, DEMO_PASSWORD).ok_or_else(|| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Demo certificate unavailable",
            )
        })?,
    };
    let field_name = format!("Sigis-{}", uuid::Uuid::new_v4());
    let options = SigningOptions {
        sub_filter: SubFilter::Pades,
        field_name: field_name.clone(),
        ..Default::default()
    };
    let signed = PdfSigner::new()
        .options(options)
        .sign(&upload.pdf, &signer)
        .await
        .map_err(|_| bad_request("Unable to sign this PDF with the signing certificate"))?;
    // Refuse output if the embedded signer certificate does not match the key.
    let empty_stores = TrustStoreSet::new();
    let checked = SignatureVerifier::new(&empty_stores)
        .verify_pdf(&signed)
        .map_err(|_| bad_request("The signed PDF could not be verified"))?;
    let signature = checked
        .signatures
        .iter()
        .find(|s| s.field_name == field_name)
        .ok_or_else(|| bad_request("The new signature could not be found"))?;
    if signature.cryptographic_validity != CryptoValidity::Valid
        || !signature.digest_matches
        || !signature.integrity_ok
    {
        return Err(bad_request(
            "The new signature could not be verified against the signing certificate",
        ));
    }
    Ok((
        [
            (header::CONTENT_TYPE, "application/pdf"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"signed.pdf\"",
            ),
        ],
        signed,
    )
        .into_response())
}

async fn verify(State(state): State<AppState>, multipart: Multipart) -> ApiResult<Json<Value>> {
    let upload = parse_upload(multipart, false).await?;
    let stores = TrustStoreSet::new().with_sig_store((*state.trust_roots).clone());
    let report = SignatureVerifier::new(&stores)
        .policy(Box::new(BasicPdfSignaturePolicy::new()))
        .verify_pdf(&upload.pdf);
    let report = match report {
        Ok(report) => report,
        Err(PdfSignError::Verify(VerifyError::NoSignatures)) => {
            return Ok(Json(json!({
                "signature_count": 0, "signatures": [], "summary": "No signatures found",
                "trust_roots_configured": state.custom_trust_roots
            })))
        }
        Err(_) => return Err(bad_request("Unable to read or verify this PDF")),
    };
    let overall_status = summarize_statuses(
        report
            .signatures
            .iter()
            .map(|s| (&s.status, s.extended_by_non_safe_updates)),
    );
    let signatures: Vec<Value> = report
        .signatures
        .iter()
        .map(|s| {
            json!({
                "field": s.field_name,
                "signer": s.signer_name,
                "status": format!("{:?}", s.status),
                "cryptographic_validity": format!("{:?}", s.cryptographic_validity),
                "digest_matches": s.digest_matches,
                "byte_range_valid": s.integrity_ok,
                "covers_whole_document": s.covers_whole_document,
                "modified_after_signing": s.modifications_after_signing,
                "non_safe_updates": s.extended_by_non_safe_updates,
                "certificate_status": format!("{:?}", s.certificate_validity),
                "certificate_trusted": s.chain_trusted,
                "trust_anchor": s.trust_anchor,
                "pades_level": format!("{:?}", s.pades_level),
                "claimed_signing_time": s.signing_time,
                "timestamp_time": s.timestamp_time,
                "issues": s.integrity_issues,
                "summary": s.summary,
            })
        })
        .collect();
    Ok(Json(json!({
        "signature_count": signatures.len(),
        "signatures": signatures,
        "overall_status": overall_status,
        "updates_after_last_signature": report.document_modified,
        "trust_roots_configured": state.custom_trust_roots,
        "summary": format!("{} signature(s) found; review integrity and trust separately", signatures.len()),
        "note": "Offline verification only. Certificate trust requires configured trust roots; the local demo certificate is always trusted. Revocation and timestamp trust are not established by this test service. The updates-after-signature field does not establish signed-byte integrity; review each digest and overall status."
    })))
}

// Summarize both signature validity and modifications to the current document.
fn summarize_statuses<'a>(
    signatures: impl Iterator<Item = (&'a SignatureStatus, Option<bool>)>,
) -> &'static str {
    let mut invalid = false;
    let mut modified = false;
    let mut indeterminate = false;
    let mut untrusted = false;
    for (status, non_safe_updates) in signatures {
        invalid |= *status == SignatureStatus::Invalid;
        modified |= non_safe_updates == Some(true);
        indeterminate |= *status == SignatureStatus::Indeterminate || non_safe_updates.is_none();
        untrusted |= *status == SignatureStatus::ValidButUntrusted;
    }
    if invalid {
        "invalid"
    } else if modified {
        "modified_after_signing"
    } else if indeterminate {
        "indeterminate"
    } else if untrusted {
        "valid_but_untrusted"
    } else {
        "valid"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_accounts_for_unsafe_and_unknown_updates() {
        assert_eq!(
            summarize_statuses([(&SignatureStatus::Valid, Some(true))].into_iter()),
            "modified_after_signing"
        );
        assert_eq!(
            summarize_statuses([(&SignatureStatus::Valid, None)].into_iter()),
            "indeterminate"
        );
        assert_eq!(
            summarize_statuses(
                [
                    (&SignatureStatus::ValidButUntrusted, Some(false)),
                    (&SignatureStatus::Valid, Some(false))
                ]
                .into_iter()
            ),
            "valid_but_untrusted"
        );
        assert_eq!(
            summarize_statuses([(&SignatureStatus::Invalid, Some(true))].into_iter()),
            "invalid"
        );
    }

    fn minimal_pdf() -> Vec<u8> {
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        ];
        let mut pdf = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (i, object) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend(format!("{} 0 obj\n{object}\nendobj\n", i + 1).bytes());
        }
        let xref = pdf.len();
        pdf.extend(b"xref\n0 4\n0000000000 65535 f \n");
        for offset in offsets {
            pdf.extend(format!("{offset:010} 00000 n \n").bytes());
        }
        pdf.extend(
            format!("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").bytes(),
        );
        pdf
    }

    #[tokio::test]
    async fn demo_certificate_is_reused_and_trusted() {
        let dir = std::env::temp_dir().join(format!("sigis-test-{}", uuid::Uuid::new_v4()));
        let demo = load_or_create_demo(&dir).unwrap();
        let again = load_or_create_demo(&dir).unwrap();
        assert_eq!(demo.cert_der, again.cert_der);

        let signer = load_signer(&demo.pkcs12, DEMO_PASSWORD).unwrap();
        let signed = PdfSigner::new()
            .options(SigningOptions {
                sub_filter: SubFilter::Pades,
                ..Default::default()
            })
            .sign(&minimal_pdf(), &signer)
            .await
            .unwrap();
        let mut store = TrustStore::new();
        store.add_der_certificate(&demo.cert_der).unwrap();
        let stores = TrustStoreSet::new().with_sig_store(store);
        let report = SignatureVerifier::new(&stores)
            .policy(Box::new(BasicPdfSignaturePolicy::new()))
            .verify_pdf(&signed)
            .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(report.signatures.len(), 1);
        assert_eq!(report.signatures[0].status, SignatureStatus::Valid);
        assert!(report.signatures[0].chain_trusted);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address: SocketAddr = std::env::var("SIGIS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:38882".into())
        .parse()?;
    let (mut trust_store, custom_trust_roots) = match std::env::var("SIGIS_TRUST_ROOTS") {
        Ok(path) => (TrustStore::from_pem_file(&path)?, true),
        Err(std::env::VarError::NotPresent) => (TrustStore::new(), false),
        Err(e) => return Err(e.into()),
    };
    let demo = load_or_create_demo(&std::env::temp_dir().join("sigis-demo"))?;
    eprintln!("Sigis demo certificate: {}", demo.path.display());
    trust_store.add_der_certificate(&demo.cert_der)?;
    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/sign", post(sign))
        .route("/api/verify", post(verify))
        .route("/api/demo-certificate", get(demo_certificate))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(AppState {
            trust_roots: Arc::new(trust_store),
            custom_trust_roots,
            demo: Arc::new(demo),
        });
    let listener = tokio::net::TcpListener::bind(address).await?;
    eprintln!("Sigis listening on {address}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
