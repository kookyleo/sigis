// Ported from pyHanko v0.38.1 internal/integration-tests (MIT).
// Exact upstream: integration-tests/test_live_certomancer.py::test_async_sign_many_concurrent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/live_pki.rs"]
mod live_pki;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::Duration;

use live_pki::{LivePki, TIME};
use sigis_pades::ades::{basic::QualificationSpec, lta::lta_validation, AdesPassed};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SignOptions, SimpleSigner, SubFilter};
use sigis_pdf::{PdfFile, SignatureKind};
use sigis_pdf_diff::{ModificationLevel, StandardDiffPolicy};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{algorithms::DigestAlgorithm, cert::Cert, sign::KeySigner, time::Moment};
use sigis_pki_fetch::{
    transport::HttpRequest, FetchLimits, FetcherSettings, HttpFetchers, HttpTimeStamper,
    HttpTransport, ReqwestTransport,
};

const JOBS: usize = 10;

// Observation only: no wait/lock inside the production signing or TSA path.
// A valid shared cache may serialize its own initialization without test deadlock.
struct ActiveSigning(Arc<AtomicUsize>);
impl ActiveSigning {
    fn enter(active: Arc<AtomicUsize>, peak: &AtomicUsize) -> Self {
        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(current, Ordering::SeqCst);
        Self(active)
    }
}
impl Drop for ActiveSigning {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
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
fn sha256(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn panic_text(value: Box<dyn std::any::Any + Send>) -> String {
    value
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| value.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "worker/acceptance check panicked".to_owned())
}

fn check_completed(
    i: usize,
    output: &[u8],
    root_der: &[u8],
    validation: &ValidationContext,
    artifacts: &std::path::Path,
) -> serde_json::Value {
    let file = PdfFile::parse(output).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    let regular = signatures
        .iter()
        .filter(|s| s.kind == SignatureKind::Signature)
        .collect::<Vec<_>>();
    assert_eq!(regular.len(), 1);
    let signature = regular[0];
    assert_eq!(signature.field_name, "Sig1");
    let dictionary_object = file
        .get_object_raw(signature.sig_object, Some(signature.signed_revision))
        .unwrap();
    let reason = dictionary_object
        .as_dict()
        .unwrap()
        .get(b"Reason")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(
        reason.ends_with(format!("#{i}!").as_bytes()),
        "completed output must retain its original job index {i}"
    );

    let result =
        lta_validation(&file, signature, validation, &QualificationSpec::default()).unwrap();
    assert_eq!(result.ades_subindic, AdesPassed::OK.into());
    let status = result.api_status.unwrap();
    assert!(status.signature.intact && status.signature.valid && status.signature.trusted());
    let timestamp = status
        .timestamp_validity
        .as_ref()
        .expect("actual signature timestamp");
    assert!(timestamp.signature.intact && timestamp.signature.valid && timestamp.trusted());
    let pdf = sigis_pades::validate_pdf_signature(
        &file,
        signature,
        validation,
        Some(&StandardDiffPolicy),
    )
    .unwrap();
    assert_eq!(
        pdf.modification_level(),
        Some(ModificationLevel::LtaUpdates)
    );

    // Zero-credit supplemental refusal under empty roots, for every output.
    let no_roots = ValidationContext::builder()
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .revocation_mode("require")
        .fetchers(validation.fetchers().clone())
        .build()
        .unwrap();
    match lta_validation(&file, signature, &no_roots, &QualificationSpec::default()) {
        Err(_) => {}
        Ok(rejected) => {
            assert_ne!(rejected.ades_subindic, AdesPassed::OK.into());
            assert!(rejected
                .api_status
                .is_none_or(|status| !status.signature.trusted()));
        }
    }

    // Mandatory fresh pinned public Python validation of these exact bytes.
    let pdf_path = artifacts.join(format!("concurrent-{i}.pdf"));
    let root_path = artifacts.join("root.der");
    std::fs::write(&pdf_path, output).unwrap();
    std::fs::write(&root_path, root_der).unwrap();
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
    .unwrap();
    assert_eq!(verdict["pyhanko"], "0.38.1");
    assert_eq!(verdict["certvalidator"], "0.33.0");
    assert_eq!(verdict["pdf_sha256"], sha256(output));
    assert_eq!(verdict["root_sha256"], sha256(root_der));
    assert_eq!(verdict["validation_time"], TIME);
    assert_eq!(verdict["correct"]["intact"], true);
    assert_eq!(verdict["correct"]["valid"], true);
    assert_eq!(verdict["correct"]["trusted"], true);
    assert_eq!(verdict["correct"]["modification_level"], "LTA_UPDATES");
    assert_eq!(verdict["empty_roots"]["trusted"], false);
    serde_json::json!({"index": i, "pdf_sha256": sha256(output), "oracle": verdict})
}

#[test]
fn test_async_sign_many_concurrent() {
    // One sidecar, one eager session, one full-chain signer, one context/backend,
    // one shared TSA. No ten-server/per-job-session substitution.
    let live = LivePki::start();
    let limits = FetchLimits {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let session: Arc<dyn HttpTransport> =
        Arc::new(ReqwestTransport::new(limits.timeout, limits.max_response_bytes).unwrap());
    let pfx = request(
        session.as_ref(),
        "POST",
        &format!("{}/_certomancer/pfx-download/testing-ca", live.url),
        "application/x-pkcs12",
        Some(b"cert=signer1-long&passphrase=secret"),
    );
    let signer = Arc::new(SimpleSigner::from_pkcs12(&pfx, Some(b"secret")).unwrap());
    // The exact source defaults to skip_other_certs=false; no parameter matrix.
    assert!(!signer.cert_chain().is_empty());
    let root_der = request(
        session.as_ref(),
        "GET",
        &format!("{}/_certomancer/any-cert/testing-ca/root.crt", live.url),
        "application/pkix-cert",
        None,
    );
    let fetchers = HttpFetchers::with_transport(
        session.clone(),
        FetcherSettings {
            limits: limits.clone(),
            ..Default::default()
        },
    )
    .as_fetchers();
    let context = Arc::new(
        ValidationContext::builder()
            .trust_root(Cert::from_der(&root_der).unwrap())
            .moment(Moment::parse_rfc3339(TIME).unwrap())
            .revocation_mode("require")
            .fetchers(fetchers.clone())
            .build()
            .unwrap(),
    );
    assert!(context.other_certs().is_empty());
    assert!(Arc::ptr_eq(
        context.fetchers().cert.as_ref().unwrap(),
        fetchers.cert.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        context.fetchers().ocsp.as_ref().unwrap(),
        fetchers.ocsp.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        context.fetchers().crl.as_ref().unwrap(),
        fetchers.crl.as_ref().unwrap()
    ));
    let tsa = Arc::new(
        HttpTimeStamper::new(format!("{}/testing-ca/tsa/tsa", live.url))
            .with_limits(limits)
            .with_transport(session.clone()),
    );
    let template =
        std::fs::read(sigis_testdata::pyhanko(&["pdf", "minimal-with-field.pdf"])).unwrap();
    let start = Arc::new(Barrier::new(JOBS + 1));
    let (send, receive) = mpsc::channel();
    let mut workers = Vec::new();
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    for i in 1..=JOBS {
        let worker_signer = signer.clone();
        let worker_context = context.clone();
        let worker_tsa = tsa.clone();
        let worker_active = active.clone();
        let worker_peak = peak.clone();
        assert!(Arc::ptr_eq(&signer, &worker_signer));
        assert!(Arc::ptr_eq(&context, &worker_context));
        assert!(Arc::ptr_eq(&tsa, &worker_tsa));
        // New Vec and distinct PdfSigner per job. sign_pdf_with constructs its
        // own incremental PdfUpdate/writer; no writer/output is shared.
        let input = template.clone();
        let worker_start = start.clone();
        let sender = send.clone();
        workers.push(thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut metadata = PdfSignatureMetadata::new("Sig1");
                metadata.validation_context = Some(worker_context);
                metadata.subfilter = Some(SubFilter::Pades);
                metadata.embed_validation_info = true;
                metadata.use_pades_lta = true;
                metadata.reason = Some(format!("Live revinfo concurrency test #{i}!"));
                let pdf_signer = PdfSigner::new(metadata, worker_signer)
                    .with_timestamper(worker_tsa)
                    .at(Moment::parse_rfc3339(TIME).unwrap());
                worker_start.wait();
                // Keep the original automatic estimator and incremental mode.
                // Rust's returned owned Vec replaces Python's in_place BytesIO;
                // the original test asserts no mutable-buffer identity.
                let _activity = ActiveSigning::enter(worker_active, &worker_peak);
                pdf_signer
                    .sign_pdf_with(&input, &SignOptions::default())
                    .unwrap()
            }))
            .map_err(panic_text);
            sender.send((i, result)).unwrap();
        }));
    }
    drop(send);
    start.wait();
    let temp = tempfile::tempdir().unwrap();
    let retained = std::env::var_os("SIGIS_LIVE_LTA_ARTIFACT_DIR")
        .map(|dir| std::path::PathBuf::from(dir).join("test_async_sign_many_concurrent"));
    let artifacts = retained.as_deref().unwrap_or(temp.path());
    std::fs::create_dir_all(artifacts).unwrap();
    let validation = ValidationContext::builder()
        .trust_root(Cert::from_der(&root_der).unwrap())
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .revocation_mode("require")
        .fetchers(fetchers)
        .build()
        .unwrap();
    let mut seen = BTreeSet::new();
    let mut completion_order = Vec::new();
    let mut records = Vec::new();
    let mut failures = Vec::new();
    for _ in 0..JOBS {
        // Channel messages carry the original index and arrive as completed;
        // do not join workers in launch order before validating their outputs.
        let (i, result) = match receive.recv_timeout(Duration::from_secs(120)) {
            Ok(completed) => completed,
            Err(error) => {
                failures.push(format!("completion timeout: {error}"));
                break;
            }
        };
        completion_order.push(i);
        if !(1..=JOBS).contains(&i) || !seen.insert(i) {
            failures.push(format!("invalid/duplicate completion index {i}"));
            continue;
        }
        match result {
            Err(error) => failures.push(format!("job {i}: {error}")),
            Ok(output) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                check_completed(i, &output, &root_der, &validation, artifacts)
            })) {
                Ok(record) => records.push(record),
                Err(error) => failures.push(format!("job {i} acceptance: {}", panic_text(error))),
            },
        }
    }
    // Join only these owned workers before assertions can drop their sidecar.
    for worker in workers {
        if let Err(error) = worker.join() {
            failures.push(panic_text(error));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert_eq!(seen, (1..=JOBS).collect());
    assert_eq!(records.len(), JOBS);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    let metrics: serde_json::Value = serde_json::from_slice(&request(
        session.as_ref(),
        "GET",
        &format!("{}/_sigis/requests", live.url),
        "application/json",
        None,
    ))
    .unwrap();
    assert!(metrics["requests"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["method"] == "POST"
            && row["path"] == "/testing-ca/tsa/tsa"
            && row["status"] == 200));
    let receipt = serde_json::json!({
        "upstream_id": "integration-tests/test_live_certomancer.py::test_async_sign_many_concurrent",
        "unique_functions": 1, "original_parameters": 1, "pdf_count": JOBS,
        "root_sha256": sha256(&root_der), "completion_order": completion_order,
        "peak_native_sign_calls_in_flight": peak.load(Ordering::SeqCst),
        "native_python": records, "live_requests": metrics,
    });
    std::fs::write(
        artifacts.join("concurrent-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    eprintln!("LIVE_CONCURRENT_LTA {receipt}");
}
