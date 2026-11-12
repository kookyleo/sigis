// Ported from pyHanko v0.38.1 internal/integration-tests (MIT).
//! Real leaf-only B-LTA signing with strict online issuer retrieval.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/live_pki.rs"]
mod live_pki;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use live_pki::{LivePki, TIME};
use sigis_pades::ades::{basic::QualificationSpec, lta::lta_validation, AdesPassed};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SignOptions, SimpleSigner};
use sigis_pdf::PdfFile;
use sigis_pdf_diff::{ModificationLevel, StandardDiffPolicy};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{
    algorithms::DigestAlgorithm,
    cert::Cert,
    errors::FetchError,
    fetch::{CertificateFetcher, Fetchers},
    sign::KeySigner,
    time::Moment,
};
use sigis_pki_fetch::{
    transport::HttpRequest, FetchLimits, FetcherSettings, HttpFetchers, HttpTimeStamper,
    HttpTransport, ReqwestTransport,
};

// Observe the real target before forwarding to the unchanged HTTP fetcher.
// A GET count alone cannot distinguish signer AIA from a TSA using the same URL.
#[derive(Debug)]
struct RecordingCertificateFetcher {
    delegate: Arc<dyn CertificateFetcher>,
    requested: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl CertificateFetcher for RecordingCertificateFetcher {
    fn fetch_issuers(&self, cert: &Cert) -> Result<Vec<Cert>, FetchError> {
        self.requested.lock().unwrap().push(cert.der().to_vec());
        self.delegate.fetch_issuers(cert)
    }
}

fn request(
    session: &dyn HttpTransport,
    method: &'static str,
    url: &str,
    accept: &str,
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut headers = vec![("Accept".to_owned(), accept.to_owned())];
    if body.is_some() {
        headers.push((
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        ));
    }
    let response = session
        .send(&HttpRequest {
            method,
            url,
            headers,
            body,
        })
        .unwrap();
    assert_eq!(response.status, 200, "live request {method} {url}");
    response.body
}

fn request_metrics(session: &dyn HttpTransport, live: &LivePki) -> serde_json::Value {
    serde_json::from_slice(&request(
        session,
        "GET",
        &format!("{}/_sigis/requests", live.url),
        "application/json",
        None,
    ))
    .unwrap()
}

fn issuer_requests(metrics: &serde_json::Value) -> u64 {
    metrics["requests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            row["method"] == "GET"
                && row["path"] == "/testing-ca/certs/interm/ca.crt"
                && row["status"] == 200
        })
        .map(|row| row["count"].as_u64().unwrap())
        .sum()
}

fn sha256(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn test_async_strict_cert_fetchers_happy_path() {
    let live = LivePki::start();
    let limits = FetchLimits {
        timeout: Duration::from_secs(10),
        ..Default::default()
    };
    // Eagerly create one actual HTTP session. Downloads, fetchers and TSA
    // share this exact Arc, corresponding to upstream's supplied session.
    let session: Arc<dyn HttpTransport> =
        Arc::new(ReqwestTransport::new(limits.timeout, limits.max_response_bytes).unwrap());
    let pfx = request(
        session.as_ref(),
        "POST",
        &format!("{}/_certomancer/pfx-download/testing-ca", live.url),
        "application/x-pkcs12",
        Some(b"cert=signer1-long&passphrase=secret"),
    );
    let signer = {
        let imported = SimpleSigner::from_pkcs12(&pfx, Some(b"secret")).unwrap();
        // Exact skip_other_certs=True behavior. Merely removing candidates
        // from the validation context would leave the PFX signer chain usable.
        SimpleSigner::new(
            imported.key().clone(),
            imported.signing_cert().clone(),
            Vec::new(),
        )
        .unwrap()
    };
    assert!(signer.cert_chain().is_empty());
    let signing_leaf_der = signer.signing_cert().der().to_vec();
    let root_der = request(
        session.as_ref(),
        "GET",
        &format!("{}/_certomancer/any-cert/testing-ca/root.crt", live.url),
        "application/pkix-cert",
        None,
    );
    let root = Cert::from_der(&root_der).unwrap();
    let settings = FetcherSettings {
        permit_pem: false,
        limits: limits.clone(),
        ..Default::default()
    };
    // The original constructs three explicit fetchers sharing one session.
    let cert_http = HttpFetchers::with_transport(session.clone(), settings.clone());
    let ocsp_http = HttpFetchers::with_transport(session.clone(), settings.clone());
    let crl_http = HttpFetchers::with_transport(session.clone(), settings);
    assert!(!cert_http.settings().permit_pem);
    for http in [&cert_http, &ocsp_http, &crl_http] {
        assert_eq!(http.settings().limits.timeout, Duration::from_secs(10));
    }
    let fetchers = Fetchers {
        cert: cert_http.as_fetchers().cert,
        ocsp: ocsp_http.as_fetchers().ocsp,
        crl: crl_http.as_fetchers().crl,
    };
    let requested = Arc::new(Mutex::new(Vec::new()));
    let mut signing_fetchers = fetchers.clone();
    signing_fetchers.cert = Some(Arc::new(RecordingCertificateFetcher {
        delegate: signing_fetchers.cert.take().unwrap(),
        requested: requested.clone(),
    }));
    let context = ValidationContext::builder()
        .trust_root(root.clone())
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .revocation_mode("require")
        .fetchers(signing_fetchers)
        .build()
        .unwrap();
    assert!(context.other_certs().is_empty());
    // No issuer fetch, intermediate download or local chain build is allowed
    // as preflight. The real signing operation must trigger the AIA request.
    let before = request_metrics(session.as_ref(), &live);
    assert_eq!(issuer_requests(&before), 0);
    assert!(requested.lock().unwrap().is_empty());
    let mut metadata = PdfSignatureMetadata::new("Sig1");
    metadata.validation_context = Some(Arc::new(context));
    metadata.embed_validation_info = true;
    metadata.use_pades_lta = true;
    let tsa = HttpTimeStamper::new(format!("{}/testing-ca/tsa/tsa", live.url))
        .with_limits(limits)
        .with_transport(session.clone());
    let pdf_signer = PdfSigner::new(metadata, Arc::new(signer))
        .with_timestamper(Arc::new(tsa))
        .at(Moment::parse_rfc3339(TIME).unwrap());
    let input = std::fs::read(sigis_testdata::pyhanko(&["pdf", "minimal-with-field.pdf"])).unwrap();
    let output = pdf_signer
        .sign_pdf_with(
            &input,
            &SignOptions {
                existing_fields_only: true,
                ..Default::default()
            },
        )
        .expect("leaf-only signing must fetch issuers and produce real B-LTA");
    // Snapshot before V/native/Python validation can request any candidates.
    let signing_requested = requested.lock().unwrap().clone();
    assert!(
        signing_requested.contains(&signing_leaf_der),
        "the signing context must ask the real certificate fetcher for the exact downloaded signer leaf"
    );
    let after_signing = request_metrics(session.as_ref(), &live);
    assert!(
        issuer_requests(&after_signing) > issuer_requests(&before),
        "P signing must perform actual live AIA retrieval before validation"
    );
    let file = PdfFile::parse(&output).unwrap();
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|signature| signature.field_name == "Sig1")
        .unwrap();
    // Validate afresh, with root and fetchers only. The produced DSS supplies
    // evidence, never trust anchors. No intermediate is manually preloaded.
    let validation = ValidationContext::builder()
        .trust_root(root)
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .revocation_mode("require")
        .fetchers(fetchers.clone())
        .build()
        .unwrap();
    let result = lta_validation(
        &file,
        &signature,
        &validation,
        &QualificationSpec::default(),
    )
    .expect("validate the actual signed B-LTA PDF");
    assert_eq!(result.ades_subindic, AdesPassed::OK.into());
    let status = result.api_status.unwrap();
    assert!(status.signature.valid && status.signature.intact && status.signature.trusted());
    let pdf_status = sigis_pades::validate_pdf_signature(
        &file,
        &signature,
        &validation,
        Some(&StandardDiffPolicy),
    )
    .unwrap();
    assert_eq!(
        pdf_status.modification_level(),
        Some(ModificationLevel::LtaUpdates),
        "preserve the exact upstream LTA_UPDATES assertion"
    );

    // Supplemental native rejection control, not another upstream function.
    let no_roots = ValidationContext::builder()
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .revocation_mode("require")
        .fetchers(fetchers.clone())
        .build()
        .unwrap();
    match lta_validation(&file, &signature, &no_roots, &QualificationSpec::default()) {
        Err(_) => {}
        Ok(rejected) => {
            assert_ne!(rejected.ades_subindic, AdesPassed::OK.into());
            assert!(rejected
                .api_status
                .is_none_or(|status| !status.signature.trusted()));
        }
    }

    let artifacts = tempfile::tempdir().unwrap();
    let pdf_path = artifacts.path().join("strict-live-lta.pdf");
    let root_path = artifacts.path().join("root.der");
    std::fs::write(&pdf_path, &output).unwrap();
    std::fs::write(&root_path, &root_der).unwrap();
    if let Some(directory) = std::env::var_os("SIGIS_LIVE_LTA_ARTIFACT_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("strict-live-lta.pdf"), &output).unwrap();
        std::fs::write(directory.join("root.der"), &root_der).unwrap();
    }
    let oracle = std::env::var_os("SIGIS_LIVE_LTA_ORACLE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/live_pades_verdict.py")
        });
    let verdict = sigis_testdata::oracle::run_json(
        &oracle,
        &[
            pdf_path.to_str().unwrap(),
            root_path.to_str().unwrap(),
            TIME,
        ],
    )
    .expect("this exact live integration requires a fresh pinned Python LTA verdict");
    assert_eq!(verdict["pyhanko"], "0.38.1");
    assert_eq!(verdict["certvalidator"], "0.33.0");
    assert_eq!(verdict["pdf_sha256"], sha256(&output));
    assert_eq!(verdict["correct"]["valid"], true);
    assert_eq!(verdict["correct"]["trusted"], true);
    assert_eq!(verdict["correct"]["modification_level"], "LTA_UPDATES");
    assert_eq!(verdict["empty_roots"]["trusted"], false);
    eprintln!(
        "STRICT_LIVE_LTA {}",
        serde_json::json!({
            "upstream_id": "integration-tests/test_live_certomancer.py::test_async_strict_cert_fetchers_happy_path",
            "pdf_sha256": sha256(&output),
            "signing_leaf_sha256": sha256(&signing_leaf_der),
            "signing_fetch_target_sha256": signing_requested.iter().map(|der| sha256(der)).collect::<Vec<_>>(),
            "aia_before_signing": issuer_requests(&before),
            "aia_after_signing": issuer_requests(&after_signing),
            "oracle": verdict,
        })
    );
}
