use axum::{
    extract::{DefaultBodyLimit, Multipart, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc};
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

#[derive(Clone)]
struct AppState {
    trust_roots: Option<Arc<TrustStore>>,
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

struct Upload {
    pdf: Vec<u8>,
    pkcs12: Option<Zeroizing<Vec<u8>>>,
    password: Option<Zeroizing<String>>,
}

async fn parse_upload(mut multipart: Multipart, needs_key: bool) -> ApiResult<Upload> {
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
            "pkcs12" if needs_key && pkcs12.is_none() => {
                let bytes = Zeroizing::new(
                    field
                        .bytes()
                        .await
                        .map_err(|_| bad_request("Could not read PKCS#12 file"))?
                        .to_vec(),
                );
                if bytes.is_empty() || bytes.len() > MAX_KEY {
                    return Err(bad_request("PKCS#12 file must be between 1 byte and 2 MiB"));
                }
                pkcs12 = Some(bytes);
            }
            "password" if needs_key && password.is_none() => {
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
    if needs_key && (pkcs12.is_none() || password.is_none()) {
        return Err(bad_request("PKCS#12 and password are required"));
    }
    Ok(Upload {
        pdf,
        pkcs12,
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

async fn sign(multipart: Multipart) -> ApiResult<Response> {
    let upload = parse_upload(multipart, true).await?;
    let key = upload
        .pkcs12
        .ok_or_else(|| bad_request("PKCS#12 is required"))?;
    let password = upload
        .password
        .ok_or_else(|| bad_request("Password is required"))?;
    let signer = SoftwareSigner::from_pkcs12_data(&key, &password)
        .map_err(|_| ())
        .or_else(|_| {
            load_modern_rsa_pkcs12(&key, &password)
                .ok_or(())
                .map_err(|_| ())
        })
        .map_err(|_| bad_request("Invalid or unsupported PKCS#12 file, key type, or password"))?;
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
        .map_err(|_| bad_request("Unable to sign this PDF with the supplied certificate"))?;
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
            "The new signature could not be verified against the supplied certificate",
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
    let mut stores = TrustStoreSet::new();
    if let Some(root) = &state.trust_roots {
        stores = stores.with_sig_store((**root).clone());
    }
    let report = SignatureVerifier::new(&stores)
        .policy(Box::new(BasicPdfSignaturePolicy::new()))
        .verify_pdf(&upload.pdf);
    let report = match report {
        Ok(report) => report,
        Err(PdfSignError::Verify(VerifyError::NoSignatures)) => {
            return Ok(Json(json!({
                "signature_count": 0, "signatures": [], "summary": "No signatures found",
                "trust_roots_configured": state.trust_roots.is_some()
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
        "trust_roots_configured": state.trust_roots.is_some(),
        "summary": format!("{} signature(s) found; review integrity and trust separately", signatures.len()),
        "note": "Offline verification only. Certificate trust requires configured trust roots. Revocation and timestamp trust are not established by this test service. The updates-after-signature field does not establish signed-byte integrity; review each digest and overall status."
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address: SocketAddr = std::env::var("SIGIS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:38882".into())
        .parse()?;
    let trust_roots = match std::env::var("SIGIS_TRUST_ROOTS") {
        Ok(path) => Some(Arc::new(TrustStore::from_pem_file(&path)?)),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => return Err(e.into()),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/sign", post(sign))
        .route("/api/verify", post(verify))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(AppState { trust_roots });
    let listener = tokio::net::TcpListener::bind(address).await?;
    eprintln!("Sigis listening on {address}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
