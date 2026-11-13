// Ported from pyHanko v0.38.1 internal/integration-tests (MIT).
//! Blocking fetchers retain usable handles after the setup session closes.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug)]
enum RequestsMode {
    Explicit,
    Backend,
}

// This setup-only eager client is neither cloned nor handed to fetchers/TSA.
// The flag records its scoped owner drop; no LazyTransport lifecycle is tested.
struct RequestsSetupSession {
    transport: ReqwestTransport,
    closed: Arc<AtomicBool>,
}

impl Drop for RequestsSetupSession {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

fn requests_http(settings: FetcherSettings) -> HttpFetchers {
    let transport =
        ReqwestTransport::new(settings.limits.timeout, settings.limits.max_response_bytes).unwrap();
    HttpFetchers::with_transport(Arc::new(transport), settings)
}

#[test]
fn test_requests_fetchers_happy_path() {
    for strict in [true, false] {
        check_requests_case(
            RequestsMode::Explicit,
            strict,
            "test_requests_fetchers_happy_path",
        );
    }
}

#[test]
fn test_requests_fetcher_backend_happy_path() {
    // Upstream parameter is UNUSED by backend construction, but both original
    // executions remain required. Do not vary permit_pem or lifecycle with it.
    for strict in [true, false] {
        check_requests_case(
            RequestsMode::Backend,
            strict,
            "test_requests_fetcher_backend_happy_path",
        );
    }
}

fn check_requests_case(mode: RequestsMode, strict: bool, function: &str) {
    let live = LivePki::start();
    let setup_closed = Arc::new(AtomicBool::new(false));
    let five_seconds = FetchLimits {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let ten_seconds = FetchLimits {
        timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let (signer, root_der, signing_backend_fetchers) = {
        let setup = RequestsSetupSession {
            transport: ReqwestTransport::new(five_seconds.timeout, five_seconds.max_response_bytes)
                .unwrap(),
            closed: setup_closed.clone(),
        };
        let pfx = request(
            &setup.transport,
            "POST",
            &format!("{}/_certomancer/pfx-download/testing-ca", live.url),
            "application/x-pkcs12",
            Some(b"cert=signer1-long&passphrase=secret"),
        );
        let imported = SimpleSigner::from_pkcs12(&pfx, Some(b"secret")).unwrap();
        let signer = SimpleSigner::new(
            imported.key().clone(),
            imported.signing_cert().clone(),
            Vec::new(),
        )
        .unwrap();
        assert!(signer.cert_chain().is_empty());
        let root_der = request(
            &setup.transport,
            "GET",
            &format!("{}/_certomancer/any-cert/testing-ca/root.crt", live.url),
            "application/pkix-cert",
            None,
        );
        let fetchers = match mode {
            RequestsMode::Explicit => {
                // This mapping is literal upstream behavior: permit_pem=strict,
                // including permit_pem=true when strict=true. Do not invert it.
                let cert = requests_http(FetcherSettings {
                    permit_pem: strict,
                    limits: ten_seconds.clone(),
                    ..Default::default()
                });
                let ocsp = requests_http(FetcherSettings {
                    limits: ten_seconds.clone(),
                    ..Default::default()
                });
                let crl = requests_http(FetcherSettings {
                    limits: ten_seconds.clone(),
                    ..Default::default()
                });
                assert_eq!(cert.settings().permit_pem, strict);
                for http in [&cert, &ocsp, &crl] {
                    assert_eq!(http.settings().limits.timeout, Duration::from_secs(10));
                }
                Fetchers {
                    cert: cert.as_fetchers().cert,
                    ocsp: ocsp.as_fetchers().ocsp,
                    crl: crl.as_fetchers().crl,
                }
            }
            RequestsMode::Backend => {
                let backend = requests_http(FetcherSettings {
                    limits: ten_seconds.clone(),
                    ..Default::default()
                });
                assert!(backend.settings().permit_pem);
                assert_eq!(backend.settings().limits.timeout, Duration::from_secs(10));
                let retained = backend.as_fetchers();
                // Pinned RequestsFetcherBackend.close() is a NO-OP. Dropping
                // this facade retains actual inner clients through the handles;
                // do not call LazyTransport.close or demand session recreation.
                drop(backend);
                retained
            }
        };
        // No setup-session Arc/client clone escapes this lexical scope.
        (signer, root_der, fetchers)
    };
    assert!(setup_closed.load(Ordering::SeqCst));
    let root = Cert::from_der(&root_der).unwrap();
    let signing_leaf_der = signer.signing_cert().der().to_vec();
    let requested = Arc::new(Mutex::new(Vec::new()));
    let mut signing_fetchers = signing_backend_fetchers;
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

    // Inspection uses a new client; the setup client has already been dropped.
    let inspection =
        ReqwestTransport::new(five_seconds.timeout, five_seconds.max_response_bytes).unwrap();
    let before = request_metrics(&inspection, &live);
    assert_eq!(issuer_requests(&before), 0);
    assert!(requested.lock().unwrap().is_empty());
    let mut metadata = PdfSignatureMetadata::new("Sig1");
    metadata.validation_context = Some(Arc::new(context));
    metadata.embed_validation_info = true;
    metadata.use_pades_lta = true;
    // RequestsHTTPTimeStamper defaults to5s and is independent of setup client.
    let tsa = HttpTimeStamper::new(format!("{}/testing-ca/tsa/tsa", live.url))
        .with_limits(five_seconds.clone())
        .with_transport(Arc::new(
            ReqwestTransport::new(five_seconds.timeout, five_seconds.max_response_bytes).unwrap(),
        ));
    assert!(setup_closed.load(Ordering::SeqCst));
    let signer = PdfSigner::new(metadata, Arc::new(signer))
        .with_timestamper(Arc::new(tsa))
        .at(Moment::parse_rfc3339(TIME).unwrap());
    let input = std::fs::read(sigis_testdata::pyhanko(&["pdf", "minimal-with-field.pdf"])).unwrap();
    let output = signer
        .sign_pdf_with(
            &input,
            &SignOptions {
                existing_fields_only: true,
                ..Default::default()
            },
        )
        .expect("retained requests fetchers must sign actual leaf-only B-LTA after setup closes");
    let signing_requested = requested.lock().unwrap().clone();
    assert!(signing_requested.contains(&signing_leaf_der));
    let after_signing = request_metrics(&inspection, &live);
    assert!(issuer_requests(&after_signing) > issuer_requests(&before));
    // Original _check_pades_result opens a fresh validation session. Do not
    // borrow the closed setup session or merely reuse a warm signing context.
    let fetchers = requests_http(FetcherSettings {
        limits: five_seconds,
        ..Default::default()
    })
    .as_fetchers();
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
        let directory = std::path::PathBuf::from(directory).join(format!(
            "{function}-{}",
            if strict { "True" } else { "False" }
        ));
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
    assert_eq!(verdict["root_sha256"], sha256(&root_der));
    assert_eq!(verdict["correct"]["valid"], true);
    assert_eq!(verdict["correct"]["intact"], true);
    assert_eq!(verdict["correct"]["trusted"], true);
    assert_eq!(verdict["correct"]["modification_level"], "LTA_UPDATES");
    assert_eq!(verdict["empty_roots"]["trusted"], false);
    eprintln!(
        "LIVE_PADES_LTA {}",
        serde_json::json!({
            "upstream_id": format!("integration-tests/test_live_certomancer.py::{function}"),
            "strict": strict,
            "requests_mode": format!("{mode:?}"),
            "setup_session_dropped_before_signing": setup_closed.load(Ordering::SeqCst),
            "backend_facade_dropped_before_signing": matches!(mode, RequestsMode::Backend),
            "pdf_sha256": sha256(&output),
            "signing_leaf_sha256": sha256(&signing_leaf_der),
            "signing_fetch_target_sha256": signing_requested.iter().map(|der| sha256(der)).collect::<Vec<_>>(),
            "aia_before_signing": issuer_requests(&before),
            "aia_after_signing": issuer_requests(&after_signing),
            "oracle": verdict,
        })
    );
}
