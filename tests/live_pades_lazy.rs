// Ported from pyHanko v0.38.1 internal/integration-tests (MIT).
//! Real independent lazy HTTP sessions after the eager setup client closes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/live_pki.rs"]
mod live_pki;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use live_pki::{LivePki, TIME};
use sigis_pades::ades::{basic::QualificationSpec, lta::lta_validation, AdesPassed};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SignOptions, SimpleSigner, SubFilter};
use sigis_pdf::PdfFile;
use sigis_pdf_diff::{ModificationLevel, StandardDiffPolicy};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{
    algorithms::DigestAlgorithm, cert::Cert, errors::FetchError, fetch::CertificateFetcher,
    sign::KeySigner, time::Moment,
};
use sigis_pki_fetch::{
    transport::{HttpRequest, LazyTransport},
    FetchLimits, FetcherSettings, HttpFetchers, HttpResponse, HttpTimeStamper, HttpTransport,
    ReqwestTransport, TransportError,
};

// This owns the only eager setup client. No lazy factory captures this value
// or its transport. Mark closure only AFTER dropping the actual client, rather
// than marking a boolean while leaving the client alive in an Arc elsewhere.
#[derive(Debug)]
struct SetupSession {
    inner: Option<ReqwestTransport>,
    closed: Arc<AtomicBool>,
}

impl HttpTransport for SetupSession {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        assert!(!self.closed.load(Ordering::SeqCst));
        self.inner.as_ref().unwrap().send(request)
    }
}

impl Drop for SetupSession {
    fn drop(&mut self) {
        drop(self.inner.take());
        self.closed.store(true, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct RecordingCertificateFetcher {
    delegate: Arc<dyn CertificateFetcher>,
    requested: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl CertificateFetcher for RecordingCertificateFetcher {
    fn fetch_issuers(&self, cert: &Cert) -> Result<Vec<Cert>, FetchError> {
        self.requested.lock().unwrap().push(cert.der().to_vec());
        // Never substitute static issuer bytes or prefetch the target.
        self.delegate.fetch_issuers(cert)
    }
}

fn observed_lazy_session(
    role: &'static str,
    limits: &FetchLimits,
    setup_closed: Arc<AtomicBool>,
    creations: Arc<AtomicUsize>,
) -> Arc<LazyTransport> {
    let timeout = limits.timeout;
    let max_response_bytes = limits.max_response_bytes;
    Arc::new(LazyTransport::with_factory(move || {
        assert!(
            setup_closed.load(Ordering::SeqCst),
            "the {role} lazy session must not materialize before setup closes"
        );
        let ordinal = creations.fetch_add(1, Ordering::SeqCst) + 1;
        eprintln!(
            "LIVE_LAZY_FACTORY {}",
            serde_json::json!({
                "role": role,
                "ordinal": ordinal,
                "setup_closed": setup_closed.load(Ordering::SeqCst),
                "kind": "fresh production ReqwestTransport, no replay or captured setup client",
            })
        );
        // Same real HTTP client factory as production LazyTransport::new.
        let session: Arc<dyn HttpTransport> =
            Arc::new(ReqwestTransport::new(timeout, max_response_bytes)?);
        Ok(session)
    }))
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

fn route_count(metrics: &serde_json::Value, method: &str, path: &str) -> u64 {
    metrics["requests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["method"] == method && row["path"] == path && row["status"] == 200)
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
fn test_async_lazy_session() {
    let live = LivePki::start();
    let limits = FetchLimits {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    // Unlike setup/TSA/validation's five seconds, the original explicit
    // AIOHttpFetcherBackend(session=None) keeps its default ten-second timeout.
    let backend_limits = FetchLimits::default();
    assert_eq!(backend_limits.timeout, Duration::from_secs(10));
    let setup_closed = Arc::new(AtomicBool::new(false));
    let backend_creations = Arc::new(AtomicUsize::new(0));
    let tsa_creations = Arc::new(AtomicUsize::new(0));
    let requested = Arc::new(Mutex::new(Vec::new()));

    let (signer, signing_leaf_der, root, root_der, context, before) = {
        // Exact original setup scope: eagerly open a session solely to download
        // real PFX credentials and the root. It will be dropped before signing.
        let setup = SetupSession {
            inner: Some(ReqwestTransport::new(limits.timeout, limits.max_response_bytes).unwrap()),
            closed: setup_closed.clone(),
        };
        let pfx = request(
            &setup,
            "POST",
            &format!("{}/_certomancer/pfx-download/testing-ca", live.url),
            "application/x-pkcs12",
            Some(b"cert=signer1-long&passphrase=secret"),
        );
        let signer = {
            let imported = SimpleSigner::from_pkcs12(&pfx, Some(b"secret")).unwrap();
            // skip_other_certs=True: no PFX intermediate may leak into signing.
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
            &setup,
            "GET",
            &format!("{}/_certomancer/any-cert/testing-ca/root.crt", live.url),
            "application/pkix-cert",
            None,
        );
        let root = Cert::from_der(&root_der).unwrap();

        // Equivalent to backend(session=None), not an explicit eager session.
        // Instrument the real production LazyTransport factory; its only
        // customization is observations/assertions before constructing reqwest.
        let lazy_backend = observed_lazy_session(
            "fetcher-backend",
            &backend_limits,
            setup_closed.clone(),
            backend_creations.clone(),
        );
        let backend = HttpFetchers::with_transport(
            lazy_backend,
            FetcherSettings {
                limits: backend_limits.clone(),
                ..Default::default()
            },
        );
        let mut signing_fetchers = backend.as_fetchers();
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
        assert!(!setup_closed.load(Ordering::SeqCst));
        assert_eq!(backend_creations.load(Ordering::SeqCst), 0);
        assert_eq!(tsa_creations.load(Ordering::SeqCst), 0);
        assert!(requested.lock().unwrap().is_empty());
        let before = request_metrics(&setup, &live);
        assert_eq!(
            route_count(&before, "GET", "/testing-ca/certs/interm/ca.crt"),
            0,
            "setup must not prefetch the missing signer issuer"
        );
        eprintln!(
            "LIVE_LAZY_BEFORE_SETUP_DROP {}",
            serde_json::json!({
                "setup_closed": false,
                "backend_creations": backend_creations.load(Ordering::SeqCst),
                "tsa_creations": tsa_creations.load(Ordering::SeqCst),
            })
        );
        (signer, signing_leaf_der, root, root_der, context, before)
        // setup's Drop releases the real client, then publishes SetupClosed.
    };
    assert!(setup_closed.load(Ordering::SeqCst));
    assert_eq!(backend_creations.load(Ordering::SeqCst), 0);
    assert_eq!(tsa_creations.load(Ordering::SeqCst), 0);

    // Exact original order: explicit independent LazySession TSA is created
    // after the eager setup session closes. It shares neither session state
    // nor cache/budget with the default lazy fetcher backend.
    let lazy_tsa =
        observed_lazy_session("tsa", &limits, setup_closed.clone(), tsa_creations.clone());
    let tsa = HttpTimeStamper::new(format!("{}/testing-ca/tsa/tsa", live.url))
        .with_limits(limits.clone())
        .with_transport(lazy_tsa);
    assert_eq!(backend_creations.load(Ordering::SeqCst), 0);
    assert_eq!(tsa_creations.load(Ordering::SeqCst), 0);
    let mut metadata = PdfSignatureMetadata::new("Sig1");
    metadata.subfilter = Some(SubFilter::Pades);
    metadata.validation_context = Some(Arc::new(context));
    metadata.embed_validation_info = true;
    metadata.use_pades_lta = true;
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
        .expect("sign through independent real lazy HTTP sessions after setup closes");
    // Freeze observations BEFORE either native or Python output validation.
    let signing_requested = requested.lock().unwrap().clone();
    assert!(
        signing_requested.contains(&signing_leaf_der),
        "production must forward the exact downloaded signing leaf to the real HTTP issuer fetcher"
    );
    assert_eq!(backend_creations.load(Ordering::SeqCst), 1);
    assert_eq!(tsa_creations.load(Ordering::SeqCst), 1);
    assert!(setup_closed.load(Ordering::SeqCst));

    // Exact original second eager-session scope: opened only AFTER the actual
    // signing operation completes. All validation fetchers have fresh caches.
    let validation_session: Arc<dyn HttpTransport> =
        Arc::new(ReqwestTransport::new(limits.timeout, limits.max_response_bytes).unwrap());
    let after_signing = request_metrics(validation_session.as_ref(), &live);
    assert!(
        route_count(&after_signing, "GET", "/testing-ca/certs/interm/ca.crt")
            > route_count(&before, "GET", "/testing-ca/certs/interm/ca.crt"),
        "the leaf-only signing flow itself must perform live AIA HTTP"
    );
    assert!(
        route_count(&after_signing, "POST", "/testing-ca/tsa/tsa")
            > route_count(&before, "POST", "/testing-ca/tsa/tsa"),
        "the explicit lazy TSA must perform actual RFC3161 HTTP"
    );
    let validation_fetchers = HttpFetchers::with_transport(
        validation_session,
        FetcherSettings {
            limits,
            ..Default::default()
        },
    )
    .as_fetchers();
    let validation = ValidationContext::builder()
        .trust_root(root)
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .revocation_mode("require")
        .fetchers(validation_fetchers.clone())
        .build()
        .unwrap();
    assert!(validation.other_certs().is_empty());
    let file = PdfFile::parse(&output).unwrap();
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|signature| signature.field_name == "Sig1")
        .unwrap();
    let result = lta_validation(
        &file,
        &signature,
        &validation,
        &QualificationSpec::default(),
    )
    .expect("real native AdES LTA over the actual lazy-session signed output");
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
        "retain the exact upstream LTA_UPDATES assertion"
    );

    // Supplemental zero-credit negative: embedded chains/evidence and caches
    // must not turn downloaded issuers into trust anchors.
    let no_roots = ValidationContext::builder()
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .revocation_mode("require")
        .fetchers(validation_fetchers)
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
    let pdf_path = artifacts.path().join("lazy-live-lta.pdf");
    let root_path = artifacts.path().join("root.der");
    std::fs::write(&pdf_path, &output).unwrap();
    std::fs::write(&root_path, &root_der).unwrap();
    if let Some(directory) = std::env::var_os("SIGIS_LIVE_LTA_ARTIFACT_DIR") {
        let directory = std::path::PathBuf::from(directory).join("test_async_lazy_session");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("lazy-live-lta.pdf"), &output).unwrap();
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
    .expect("this exact live lazy integration requires fresh pinned Python LTA validation");
    assert_eq!(verdict["pyhanko"], "0.38.1");
    assert_eq!(verdict["certvalidator"], "0.33.0");
    assert_eq!(verdict["pdf_sha256"], sha256(&output));
    assert_eq!(verdict["root_sha256"], sha256(&root_der));
    assert_eq!(verdict["correct"]["valid"], true);
    assert_eq!(verdict["correct"]["intact"], true);
    assert_eq!(verdict["correct"]["trusted"], true);
    assert_eq!(verdict["correct"]["modification_level"], "LTA_UPDATES");
    assert_eq!(verdict["empty_roots"]["trusted"], false);
    eprintln!(
        "LIVE_LAZY_SESSION {}",
        serde_json::json!({
            "upstream_id": "integration-tests/test_live_certomancer.py::test_async_lazy_session",
            "setup_closed_before_signing": setup_closed.load(Ordering::SeqCst),
            "backend_creations": backend_creations.load(Ordering::SeqCst),
            "tsa_creations": tsa_creations.load(Ordering::SeqCst),
            "backend_timeout_secs": backend_limits.timeout.as_secs(),
            "setup_tsa_validation_timeout_secs": 5,
            "pdf_sha256": sha256(&output),
            "signing_leaf_sha256": sha256(&signing_leaf_der),
            "signing_fetch_target_sha256": signing_requested.iter().map(|der| sha256(der)).collect::<Vec<_>>(),
            "aia_before_signing": route_count(&before, "GET", "/testing-ca/certs/interm/ca.crt"),
            "aia_after_signing": route_count(&after_signing, "GET", "/testing-ca/certs/interm/ca.crt"),
            "oracle": verdict,
        })
    );
}
