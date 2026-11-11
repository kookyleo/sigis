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
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::PKey,
    rsa::Rsa,
    stack::Stack,
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
    time::Duration,
};
use underskrift::{
    error::{PdfSignError, VerifyError},
    policy::BasicPdfSignaturePolicy,
    trust::{TrustStore, TrustStoreSet},
    verify::{
        report::{CryptoValidity, DetectedPadesLevel, SignatureStatus},
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
const DEFAULT_TSA_URL: &str = "http://timestamp.digicert.com";
const BUNDLED_TSA_ROOTS: &[u8] = include_bytes!("../certs/tsa-roots.pem");
const SIGN_TIMEOUT: Duration = Duration::from_secs(20);
// Room for a long certificate chain plus a TSA token with its own chain.
const CONTENTS_SIZE: usize = 32 * 1024;

#[derive(Clone)]
struct AppState {
    /// Demo certificate plus any roots from SIGIS_TRUST_ROOTS.
    trust_roots: Arc<TrustStore>,
    custom_trust_roots: bool,
    demo: Arc<DemoCert>,
    /// RFC 3161 TSA for PAdES B-T; `None` produces B-B signatures.
    tsa_url: Option<Arc<str>>,
    /// Bundled TSA roots, or the roots from SIGIS_TSA_ROOTS.
    tsa_roots: Arc<TrustStore>,
    custom_tsa_roots: bool,
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
        "tsa_url": state.tsa_url.as_deref(),
        "pades_level": if state.tsa_url.is_some() { "B-T" } else { "B-B" },
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
    let signer = signer_for(&state, &upload)?;
    let signed = sign_pdf(&state, &upload.pdf, &signer).await?;
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

fn signer_for(state: &AppState, upload: &Upload) -> ApiResult<SoftwareSigner> {
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
    Ok(signer)
}

async fn sign_pdf(state: &AppState, pdf: &[u8], signer: &SoftwareSigner) -> ApiResult<Vec<u8>> {
    let field_name = format!("Sigis-{}", uuid::Uuid::new_v4());
    let options = SigningOptions {
        sub_filter: SubFilter::Pades,
        field_name: field_name.clone(),
        content_size: CONTENTS_SIZE,
        tsa_url: state.tsa_url.as_deref().map(str::to_owned),
        ..Default::default()
    };
    let pdf_signer = PdfSigner::new().options(options);
    let signing = pdf_signer.sign(pdf, signer);
    let signed = match tokio::time::timeout(SIGN_TIMEOUT, signing).await {
        Ok(Ok(signed)) => signed,
        Ok(Err(PdfSignError::Tsp(e))) => {
            return Err(error(
                StatusCode::BAD_GATEWAY,
                &format!("Timestamping failed; the PDF was not signed: {e}"),
            ))
        }
        Ok(Err(_)) => {
            return Err(bad_request(
                "Unable to sign this PDF with the signing certificate",
            ))
        }
        Err(_) => {
            return Err(error(
                StatusCode::GATEWAY_TIMEOUT,
                &format!(
                "The timestamp authority did not respond within {} seconds; the PDF was not signed",
                SIGN_TIMEOUT.as_secs()
            ),
            ))
        }
    };
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
    if state.tsa_url.is_some() && signature.pades_level != DetectedPadesLevel::BT {
        return Err(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The new signature has no signature timestamp",
        ));
    }
    Ok(signed)
}

fn pades_level_name(level: &DetectedPadesLevel) -> &'static str {
    match level {
        DetectedPadesLevel::BB => "B-B",
        DetectedPadesLevel::BT => "B-T",
        DetectedPadesLevel::BLT => "B-LT",
        DetectedPadesLevel::BLTA => "B-LTA",
        DetectedPadesLevel::NotPades => "not PAdES",
        DetectedPadesLevel::Unknown => "unknown",
    }
}

/// Common name (or organization) of the TSA that signed a timestamp token.
fn timestamp_authority(token_der: &[u8]) -> Option<String> {
    let token = Pkcs7::from_der(token_der).ok()?;
    let extra_certs: Stack<X509> = Stack::new().ok()?;
    let signers = token.signers(&extra_certs, Pkcs7Flags::empty()).ok()?;
    let subject = signers.iter().next()?.subject_name();
    [Nid::COMMONNAME, Nid::ORGANIZATIONNAME]
        .into_iter()
        .find_map(|nid| subject.entries_by_nid(nid).next())
        .and_then(|entry| entry.data().to_string().ok())
}

async fn verify(State(state): State<AppState>, multipart: Multipart) -> ApiResult<Json<Value>> {
    let upload = parse_upload(multipart, false).await?;
    verify_pdf(&state, &upload.pdf).map(Json)
}

fn verify_pdf(state: &AppState, pdf: &[u8]) -> ApiResult<Value> {
    let stores = TrustStoreSet::new()
        .with_sig_store((*state.trust_roots).clone())
        .with_tsa_store((*state.tsa_roots).clone());
    let report = SignatureVerifier::new(&stores)
        .policy(Box::new(BasicPdfSignaturePolicy::new()))
        .verify_pdf(pdf);
    let report = match report {
        Ok(report) => report,
        Err(PdfSignError::Verify(VerifyError::NoSignatures)) => {
            return Ok(json!({
                "signature_count": 0, "signatures": [], "summary": "No signatures found",
                "trust_roots_configured": state.custom_trust_roots
            }))
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
                "pades_level": pades_level_name(&s.pades_level),
                "claimed_signing_time": s.signing_time,
                "timestamp_present": s.timestamp_token_der.is_some(),
                // underskrift sets validation_time_used only for a timestamp whose
                // TSA signature, message imprint, and TSA chain all verify.
                "timestamp_trusted": s.validation_time_used.is_some(),
                "timestamp_time": s.timestamp_time,
                "timestamp_authority": s.timestamp_token_der.as_deref().and_then(timestamp_authority),
                "issues": s.integrity_issues,
                "summary": s.summary,
            })
        })
        .collect();
    Ok(json!({
        "signature_count": signatures.len(),
        "signatures": signatures,
        "overall_status": overall_status,
        "updates_after_last_signature": report.document_modified,
        "trust_roots_configured": state.custom_trust_roots,
        "tsa_roots_configured": state.custom_tsa_roots,
        "summary": format!("{} signature(s) found; review integrity and trust separately", signatures.len()),
        "note": "Offline verification only. Certificate trust requires configured trust roots; the local demo certificate is always trusted. Timestamp trust uses the bundled TSA roots unless SIGIS_TSA_ROOTS is set. Revocation is not checked by this test service. The updates-after-signature field does not establish signed-byte integrity; review each digest and overall status."
    }))
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

/// Read SIGIS_TSA_URL and SIGIS_TSA_ROOTS.
///
/// An unset SIGIS_TSA_URL selects the default TSA; an empty one disables
/// timestamping. SIGIS_TSA_ROOTS is a list of PEM files separated like PATH;
/// when unset, the bundled roots are used.
fn tsa_config() -> Result<(Option<String>, TrustStore, bool), Box<dyn std::error::Error>> {
    let tsa_url = match std::env::var("SIGIS_TSA_URL") {
        Ok(url) if url.trim().is_empty() => None,
        Ok(url) => Some(url.trim().to_owned()),
        Err(std::env::VarError::NotPresent) => Some(DEFAULT_TSA_URL.to_owned()),
        Err(e) => return Err(e.into()),
    };
    if let Some(url) = &tsa_url {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!("SIGIS_TSA_URL must be an http(s) URL: {url}").into());
        }
    }
    let mut roots = TrustStore::new();
    let custom = match std::env::var_os("SIGIS_TSA_ROOTS") {
        Some(paths) => {
            for path in std::env::split_paths(&paths) {
                roots.add_pem_data(&std::fs::read(&path)?)?;
            }
            true
        }
        None => {
            roots.add_pem_data(BUNDLED_TSA_ROOTS)?;
            false
        }
    };
    if roots.is_empty() {
        return Err("SIGIS_TSA_ROOTS contains no certificates".into());
    }
    Ok((tsa_url, roots, custom))
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

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_state(dir: &Path, tsa_url: Option<&str>, tsa_roots: TrustStore) -> AppState {
        let demo = load_or_create_demo(dir).unwrap();
        let mut trust_roots = TrustStore::new();
        trust_roots.add_der_certificate(&demo.cert_der).unwrap();
        AppState {
            trust_roots: Arc::new(trust_roots),
            custom_trust_roots: false,
            demo: Arc::new(demo),
            tsa_url: tsa_url.map(Arc::from),
            tsa_roots: Arc::new(tsa_roots),
            custom_tsa_roots: false,
        }
    }

    fn bundled_tsa_roots() -> TrustStore {
        let mut roots = TrustStore::new();
        roots.add_pem_data(BUNDLED_TSA_ROOTS).unwrap();
        roots
    }

    async fn sign_and_verify(state: &AppState) -> Value {
        let signer = load_signer(&state.demo.pkcs12, DEMO_PASSWORD).unwrap();
        let signed = sign_pdf(state, &minimal_pdf(), &signer).await.unwrap();
        verify_pdf(state, &signed).unwrap()
    }

    fn test_cert(
        common_name: &str,
        key: &PKey<openssl::pkey::Private>,
        issuer: Option<(&X509, &PKey<openssl::pkey::Private>)>,
    ) -> X509 {
        use openssl::x509::extension::ExtendedKeyUsage;
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        cert.set_serial_number(Asn1Integer::from_bn(&serial).unwrap().as_ref())
            .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(issuer.map_or(&*name, |(ca, _)| ca.subject_name()))
            .unwrap();
        cert.set_pubkey(key).unwrap();
        cert.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        cert.set_not_after(Asn1Time::days_from_now(30).unwrap().as_ref())
            .unwrap();
        match issuer {
            None => {
                let ca = BasicConstraints::new().critical().ca().build().unwrap();
                cert.append_extension(ca).unwrap();
                let usage = KeyUsage::new().critical().key_cert_sign().build().unwrap();
                cert.append_extension(usage).unwrap();
            }
            Some(_) => {
                let leaf = BasicConstraints::new().critical().build().unwrap();
                cert.append_extension(leaf).unwrap();
                let usage = KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap();
                cert.append_extension(usage).unwrap();
                let eku = ExtendedKeyUsage::new()
                    .critical()
                    .time_stamping()
                    .build()
                    .unwrap();
                cert.append_extension(eku).unwrap();
            }
        }
        let signing_key = issuer.map_or(key, |(_, ca_key)| ca_key);
        cert.sign(signing_key, MessageDigest::sha256()).unwrap();
        cert.build()
    }

    /// Local RFC 3161 TSA backed by `openssl ts -reply`.
    struct MockTsa {
        url: String,
        roots: TrustStore,
        _dir: TempDir,
    }

    async fn mock_tsa() -> Option<MockTsa> {
        if std::process::Command::new("openssl")
            .arg("version")
            .output()
            .is_err()
        {
            eprintln!("skipping: the openssl command is not installed");
            return None;
        }
        let dir = TempDir::new("sigis-mock-tsa");
        let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let ca = test_cert("Sigis Test TSA Root", &ca_key, None);
        let tsa_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let tsa = test_cert("Sigis Test TSA", &tsa_key, Some((&ca, &ca_key)));
        let path = |name: &str| dir.0.join(name);
        std::fs::write(path("ca.pem"), ca.to_pem().unwrap()).unwrap();
        std::fs::write(path("tsa.pem"), tsa.to_pem().unwrap()).unwrap();
        std::fs::write(path("tsa.key"), tsa_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        std::fs::write(path("serial"), "01\n").unwrap();
        let config = format!(
            "[tsa]\ndefault_tsa = tsa_config1\n[tsa_config1]\nserial = {}\n\
             crypto_device = builtin\nsigner_cert = {}\ncerts = {}\nsigner_key = {}\n\
             signer_digest = sha256\ndefault_policy = 1.2.3.4.1\n\
             digests = sha256, sha384, sha512\naccuracy = secs:1\nordering = yes\n\
             tsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n",
            path("serial").display(),
            path("tsa.pem").display(),
            path("ca.pem").display(),
            path("tsa.key").display(),
        );
        std::fs::write(path("tsa.cnf"), config).unwrap();

        let work = dir.0.clone();
        let reply = move |body: axum::body::Bytes| async move {
            let id = uuid::Uuid::new_v4();
            let query = work.join(format!("{id}.tsq"));
            let response = work.join(format!("{id}.tsr"));
            std::fs::write(&query, &body).unwrap();
            let status = std::process::Command::new("openssl")
                .args(["ts", "-reply", "-config"])
                .arg(work.join("tsa.cnf"))
                .arg("-queryfile")
                .arg(&query)
                .arg("-out")
                .arg(&response)
                .output()
                .unwrap();
            assert!(status.status.success(), "{status:?}");
            (
                [(header::CONTENT_TYPE, "application/timestamp-reply")],
                std::fs::read(&response).unwrap(),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let app = Router::new().route("/", post(reply));
        tokio::spawn(async move { axum::serve(listener, app).await });
        let mut roots = TrustStore::new();
        roots.add_der_certificate(&ca.to_der().unwrap()).unwrap();
        Some(MockTsa {
            url,
            roots,
            _dir: dir,
        })
    }

    #[test]
    fn bundled_tsa_roots_load() {
        assert_eq!(bundled_tsa_roots().len(), 2);
    }

    #[tokio::test]
    async fn demo_certificate_is_reused_and_signs_b_b_without_tsa() {
        let dir = TempDir::new("sigis-test");
        let first = load_or_create_demo(&dir.0).unwrap();
        let again = load_or_create_demo(&dir.0).unwrap();
        assert_eq!(first.cert_der, again.cert_der);

        let state = test_state(&dir.0, None, bundled_tsa_roots());
        let report = sign_and_verify(&state).await;
        let signature = &report["signatures"][0];
        assert_eq!(report["overall_status"], "valid");
        assert_eq!(signature["certificate_trusted"], true);
        assert_eq!(signature["pades_level"], "B-B");
        assert_eq!(signature["timestamp_present"], false);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mock_tsa_signature_verifies_as_trusted_b_t() {
        let Some(tsa) = mock_tsa().await else { return };
        let dir = TempDir::new("sigis-test");
        let state = test_state(&dir.0, Some(&tsa.url), tsa.roots.clone());
        let report = sign_and_verify(&state).await;
        let signature = &report["signatures"][0];
        assert_eq!(report["overall_status"], "valid", "{report:#}");
        assert_eq!(signature["pades_level"], "B-T");
        assert_eq!(signature["timestamp_present"], true);
        assert_eq!(signature["timestamp_trusted"], true, "{report:#}");
        assert_eq!(signature["timestamp_authority"], "Sigis Test TSA");
        assert!(signature["timestamp_time"].is_string());

        // The same PDF is B-T but its timestamp is untrusted without the TSA root.
        let untrusted = test_state(&dir.0, Some(&tsa.url), bundled_tsa_roots());
        let signer = load_signer(&state.demo.pkcs12, DEMO_PASSWORD).unwrap();
        let signed = sign_pdf(&state, &minimal_pdf(), &signer).await.unwrap();
        let report = verify_pdf(&untrusted, &signed).unwrap();
        let signature = &report["signatures"][0];
        assert_eq!(signature["pades_level"], "B-T");
        assert_eq!(signature["timestamp_present"], true);
        assert_eq!(signature["timestamp_trusted"], false);
    }

    #[tokio::test]
    async fn tsa_failure_is_an_error_not_b_b() {
        // Bind and release a port so that nothing listens on it.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = TempDir::new("sigis-test");
        let url = format!("http://127.0.0.1:{port}/");
        let state = test_state(&dir.0, Some(&url), bundled_tsa_roots());
        let signer = load_signer(&state.demo.pkcs12, DEMO_PASSWORD).unwrap();
        let (status, body) = sign_pdf(&state, &minimal_pdf(), &signer).await.unwrap_err();
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("Timestamping failed"));
    }

    /// Network test against the default public TSA: `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "needs network access to the default TSA"]
    async fn default_tsa_signature_verifies_as_trusted_b_t() {
        let dir = TempDir::new("sigis-test");
        let state = test_state(&dir.0, Some(DEFAULT_TSA_URL), bundled_tsa_roots());
        let report = sign_and_verify(&state).await;
        let signature = &report["signatures"][0];
        eprintln!("{report:#}");
        assert_eq!(report["overall_status"], "valid");
        assert_eq!(signature["pades_level"], "B-T");
        assert_eq!(signature["timestamp_trusted"], true);
        assert!(signature["timestamp_authority"]
            .as_str()
            .unwrap()
            .contains("DigiCert"));
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
    let (tsa_url, tsa_roots, custom_tsa_roots) = tsa_config()?;
    match &tsa_url {
        Some(url) => eprintln!("Sigis timestamp authority: {url} (PAdES B-T)"),
        None => eprintln!("Sigis timestamping disabled (PAdES B-B)"),
    }
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
            tsa_url: tsa_url.map(Arc::from),
            tsa_roots: Arc::new(tsa_roots),
            custom_tsa_roots,
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
