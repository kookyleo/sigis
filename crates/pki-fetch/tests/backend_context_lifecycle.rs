//! Explicit close authority is independent of Arc memory lifetime.
//!
//! The two same-named originals also require private owner identity assertions
//! in certvalidator's embedded context tests. All other tests are supplemental.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::json;
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{FetchError, FetchErrorKind};
use sigis_pki_core::fetch::{CertificateFetcher, FetcherBackend, Fetchers};
use sigis_pki_fetch::common::{get_ocsp_urls, get_relevant_crl_dps};
use sigis_pki_fetch::transport::{HttpRequest, LazyTransport};
use sigis_pki_fetch::{
    FetchLimits, FetcherSettings, HttpFetchers, HttpResponse, HttpTransport, TransportError,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn identity(label: &str) {
    static IMAGE: OnceLock<(std::path::PathBuf, String, usize)> = OnceLock::new();
    let (path, sha256, length) = IMAGE.get_or_init(|| {
        let path = std::env::current_exe().unwrap().canonicalize().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        (
            path,
            hex(&DigestAlgorithm::Sha256.digest(&bytes)),
            bytes.len(),
        )
    });
    eprintln!(
        "BACKEND_TEST_IDENTITY {}",
        json!({"label":label,"path":path,"sha256":sha256,"length":length,
            "cwd":std::env::current_dir().unwrap(),
            "hostname":std::fs::read_to_string("/etc/hostname").unwrap().trim()})
    );
}

fn certificate(name: &str) -> Cert {
    let path = sigis_testdata::certvalidator(&["testing-ca-ed25519", name])
        .canonicalize()
        .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    eprintln!(
        "BACKEND_TEST_INPUT {}",
        json!({"path":path,"length":bytes.len(),
            "sha256":hex(&DigestAlgorithm::Sha256.digest(&bytes))})
    );
    Cert::from_pem_or_der(&bytes).unwrap()
}

#[derive(Debug, Default)]
struct RecordingBackend {
    factories: AtomicUsize,
    closed: AtomicUsize,
    close_error: Option<FetchError>,
}

impl FetcherBackend for RecordingBackend {
    fn get_fetchers(&self) -> Fetchers {
        self.factories.fetch_add(1, Ordering::SeqCst);
        Fetchers::none()
    }

    fn close(&self) -> Result<(), FetchError> {
        self.closed.fetch_add(1, Ordering::SeqCst);
        self.close_error.clone().map_or(Ok(()), Err)
    }
}

#[test]
fn test_context_leaves_a_supplied_backend_alone() {
    identity("test_context_leaves_a_supplied_backend_alone");
    let backend = Arc::new(RecordingBackend::default());
    let context = ValidationContext::builder()
        .fetcher_backend(backend.clone())
        .build()
        .unwrap();
    context.close().unwrap();
    assert_eq!(backend.closed.load(Ordering::SeqCst), 0);
    assert_eq!(backend.factories.load(Ordering::SeqCst), 1);
    // The original's private owner-None assertion is embedded in context_tests.
}

#[test]
fn test_context_adopts_an_owned_backend() {
    identity("test_context_adopts_an_owned_backend");
    let backend = Arc::new(RecordingBackend::default());
    let context = ValidationContext::builder()
        .owned_fetcher_backend(backend.clone())
        .build()
        .unwrap();
    context.close().unwrap();
    assert_eq!(backend.closed.load(Ordering::SeqCst), 1);
    assert_eq!(backend.factories.load(Ordering::SeqCst), 1);
    // The caller and context both survive close; Arc release is not this count.
    // The original's exact private owner-Arc assertion is embedded in context_tests.
}

#[test]
fn explicit_close_errors_repeat_and_clones_retain_close_authority() {
    identity("explicit_close_errors_repeat_and_clones_retain_close_authority");
    let expected = FetchError::new(FetchErrorKind::Timeout, "backend close timeout");
    let backend = Arc::new(RecordingBackend {
        close_error: Some(expected.clone()),
        ..Default::default()
    });
    let context = ValidationContext::builder()
        .owned_fetcher_backend(backend.clone())
        .build()
        .unwrap();
    let clone = context.clone();
    let timed = context.with_timing(*context.timing());
    let replaced = context.with_fetchers(Fetchers::none());
    for clone in [&context, &clone, &timed, &replaced] {
        assert_eq!(clone.close().unwrap_err(), expected);
    }
    assert_eq!(backend.closed.load(Ordering::SeqCst), 4);
    assert_eq!(context.close().unwrap_err(), expected);
    assert_eq!(backend.closed.load(Ordering::SeqCst), 5);
    drop(context);
    drop(clone);
    drop(timed);
    drop(replaced);
    assert_eq!(
        backend.closed.load(Ordering::SeqCst),
        5,
        "no implicit Drop close"
    );
    assert_eq!(
        backend.factories.load(Ordering::SeqCst),
        1,
        "clones do not refactory"
    );
}

#[test]
fn last_backend_setter_selects_backend_and_close_mode() {
    identity("last_backend_setter_selects_backend_and_close_mode");
    for last_owned in [false, true] {
        let first = Arc::new(RecordingBackend::default());
        let last = Arc::new(RecordingBackend::default());
        let builder = if last_owned {
            ValidationContext::builder()
                .fetcher_backend(first.clone())
                .owned_fetcher_backend(last.clone())
        } else {
            ValidationContext::builder()
                .owned_fetcher_backend(first.clone())
                .fetcher_backend(last.clone())
        };
        let context = builder.build().unwrap();
        context.close().unwrap();
        assert_eq!(first.factories.load(Ordering::SeqCst), 0);
        assert_eq!(first.closed.load(Ordering::SeqCst), 0);
        assert_eq!(last.factories.load(Ordering::SeqCst), 1);
        assert_eq!(last.closed.load(Ordering::SeqCst), usize::from(last_owned));
    }
}

#[derive(Debug)]
struct MarkerFetcher;

impl CertificateFetcher for MarkerFetcher {
    fn fetch_issuers(&self, _: &Cert) -> Result<Vec<Cert>, FetchError> {
        Err(FetchError::disabled("explicit marker"))
    }
}

#[test]
fn explicit_fetchers_including_none_win_both_orders_without_losing_owner() {
    identity("explicit_fetchers_including_none_win_both_orders_without_losing_owner");
    for empty in [false, true] {
        for backend_first in [false, true] {
            for owned in [false, true] {
                let backend = Arc::new(RecordingBackend::default());
                let supplied = if empty {
                    Fetchers::none()
                } else {
                    Fetchers {
                        cert: Some(Arc::new(MarkerFetcher)),
                        ..Fetchers::none()
                    }
                };
                let mut builder = ValidationContext::builder();
                if !backend_first {
                    builder = builder.fetchers(supplied.clone());
                }
                builder = if owned {
                    builder.owned_fetcher_backend(backend.clone())
                } else {
                    builder.fetcher_backend(backend.clone())
                };
                if backend_first {
                    builder = builder.fetchers(supplied.clone());
                }
                let context = builder.build().unwrap();
                assert_eq!(context.fetchers().is_empty(), empty);
                if let Some(expected) = &supplied.cert {
                    assert!(Arc::ptr_eq(
                        context.fetchers().cert.as_ref().unwrap(),
                        expected
                    ));
                }
                assert_eq!(backend.factories.load(Ordering::SeqCst), 0);
                context.close().unwrap();
                assert_eq!(backend.closed.load(Ordering::SeqCst), usize::from(owned));
            }
        }
    }
}

#[test]
fn backend_factory_is_not_run_before_builder_validation_succeeds() {
    identity("backend_factory_is_not_run_before_builder_validation_succeeds");
    let backend = Arc::new(RecordingBackend::default());
    let error = ValidationContext::builder()
        .owned_fetcher_backend(backend.clone())
        .revocation_mode("not-a-valid-revocation-mode")
        .build()
        .unwrap_err();
    assert!(error.to_string().contains("not a valid revocation mode"));
    assert_eq!(backend.factories.load(Ordering::SeqCst), 0);
    assert_eq!(backend.closed.load(Ordering::SeqCst), 0);
}

type RecordedRequest = (String, Vec<(String, String)>);

#[derive(Debug)]
struct FailingTransport {
    count: AtomicUsize,
    error: TransportError,
    requests: Mutex<Vec<RecordedRequest>>,
}

impl FailingTransport {
    fn new(error: TransportError) -> Self {
        Self {
            count: AtomicUsize::new(0),
            error,
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl HttpTransport for FailingTransport {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .unwrap()
            .push((request.url.to_owned(), request.headers.clone()));
        Err(self.error.clone())
    }
}

fn single_request_settings() -> FetcherSettings {
    FetcherSettings {
        limits: FetchLimits {
            max_requests: Some(1),
            ..FetchLimits::default()
        },
        user_agent: "backend-lifecycle-contract".to_owned(),
        request_nonces: false,
        ..FetcherSettings::default()
    }
}

#[test]
fn factory_sets_have_independent_caches_and_budgets_retained_across_close() {
    identity("factory_sets_have_independent_caches_and_budgets_retained_across_close");
    let cert = certificate("signer.cert.pem");
    let issuer = certificate("interm.cert.pem");
    assert!(!get_ocsp_urls(&cert).is_empty());
    assert!(!get_relevant_crl_dps(&cert, true).is_empty());
    let settings = single_request_settings();
    let transport = Arc::new(FailingTransport::new(TransportError::Timeout(
        "retained".into(),
    )));
    let backend = HttpFetchers::with_transport(transport.clone(), settings.clone());
    let first = backend.get_fetchers();
    let second = backend.get_fetchers();
    assert!(!Arc::ptr_eq(
        first.ocsp.as_ref().unwrap(),
        second.ocsp.as_ref().unwrap()
    ));
    let ocsp = first.ocsp.as_ref().unwrap();
    let timeout = ocsp.fetch_ocsp(&cert, &issuer).unwrap_err();
    assert_eq!(timeout.kind, FetchErrorKind::Timeout);
    assert_eq!(ocsp.fetch_ocsp(&cert, &issuer).unwrap_err(), timeout);
    assert_eq!(transport.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        first
            .crl
            .as_ref()
            .unwrap()
            .fetch_crls(&cert)
            .unwrap_err()
            .kind,
        FetchErrorKind::Disabled,
        "component handles share one issued-set budget"
    );
    backend.close().unwrap();
    assert_eq!(backend.settings(), &settings);
    assert_eq!(
        ocsp.fetch_ocsp(&cert, &issuer).unwrap_err(),
        timeout,
        "close preserves cached errors"
    );
    assert_eq!(
        first
            .crl
            .as_ref()
            .unwrap()
            .fetch_crls(&cert)
            .unwrap_err()
            .kind,
        FetchErrorKind::Disabled,
        "close does not reset an issued budget"
    );
    assert_eq!(transport.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        second
            .ocsp
            .as_ref()
            .unwrap()
            .fetch_ocsp(&cert, &issuer)
            .unwrap_err(),
        timeout
    );
    assert_eq!(
        transport.count.load(Ordering::SeqCst),
        2,
        "another factory set starts independently"
    );
    let requests = transport.requests.lock().unwrap();
    assert!(requests
        .iter()
        .all(|(_, h)| h.contains(&("User-Agent".to_owned(), settings.user_agent.clone()))));
}

#[test]
fn as_fetchers_remains_the_same_shared_cache_and_budget_view() {
    identity("as_fetchers_remains_the_same_shared_cache_and_budget_view");
    let cert = certificate("signer.cert.pem");
    let issuer = certificate("interm.cert.pem");
    let transport = Arc::new(FailingTransport::new(TransportError::Network(
        "shared".into(),
    )));
    let backend = HttpFetchers::with_transport(transport.clone(), single_request_settings());
    let first = backend.as_fetchers();
    let second = backend.as_fetchers();
    let expected = backend.fetch_ocsp_response(&cert, &issuer).unwrap_err();
    assert_eq!(expected.kind, FetchErrorKind::Network);
    for view in [&first, &second] {
        assert_eq!(
            view.ocsp
                .as_ref()
                .unwrap()
                .fetch_ocsp(&cert, &issuer)
                .unwrap_err(),
            expected
        );
        assert_eq!(
            view.crl
                .as_ref()
                .unwrap()
                .fetch_crls(&cert)
                .unwrap_err()
                .kind,
            FetchErrorKind::Disabled
        );
    }
    backend.close().unwrap();
    assert_eq!(
        backend.fetch_ocsp_response(&cert, &issuer).unwrap_err(),
        expected
    );
    assert!(backend.budget().exhaustion_reported());
    assert_eq!(transport.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        backend
            .get_fetchers()
            .ocsp
            .unwrap()
            .fetch_ocsp(&cert, &issuer)
            .unwrap_err(),
        expected
    );
    assert_eq!(transport.count.load(Ordering::SeqCst), 2);
}

#[test]
fn backend_factory_preserves_typed_transport_failures_and_error_caches() {
    identity("backend_factory_preserves_typed_transport_failures_and_error_caches");
    let cert = certificate("signer.cert.pem");
    let issuer = certificate("interm.cert.pem");
    for (error, kind) in [
        (
            TransportError::Network("network".into()),
            FetchErrorKind::Network,
        ),
        (
            TransportError::Timeout("timeout".into()),
            FetchErrorKind::Timeout,
        ),
        (TransportError::TooLarge(31), FetchErrorKind::TooLarge),
    ] {
        let transport = Arc::new(FailingTransport::new(error));
        let backend = HttpFetchers::with_transport(transport.clone(), FetcherSettings::default());
        let fetchers = backend.get_fetchers();
        assert!(
            !fetchers.is_empty(),
            "transport failures cannot become disabled fetchers"
        );
        let handle = fetchers.ocsp.unwrap();
        let first = handle.fetch_ocsp(&cert, &issuer).unwrap_err();
        assert_eq!(first.kind, kind);
        assert_eq!(handle.fetch_ocsp(&cert, &issuer).unwrap_err(), first);
        assert_eq!(transport.count.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn custom_lazy_transport_remains_caller_managed_even_after_context_close() {
    identity("custom_lazy_transport_remains_caller_managed_even_after_context_close");
    let created = Arc::new(AtomicUsize::new(0));
    let lazy = Arc::new(LazyTransport::with_factory({
        let created = created.clone();
        move || {
            created.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(FailingTransport::new(TransportError::Network(
                "caller session".into(),
            ))) as Arc<dyn HttpTransport>)
        }
    }));
    let backend = Arc::new(HttpFetchers::with_transport(
        lazy.clone(),
        FetcherSettings::default(),
    ));
    let context = ValidationContext::builder()
        .owned_fetcher_backend(backend.clone())
        .build()
        .unwrap();
    let request = HttpRequest {
        method: "GET",
        url: "https://example.invalid/never-network",
        headers: Vec::new(),
        body: None,
    };
    assert!(lazy.send(&request).is_err());
    assert_eq!(created.load(Ordering::SeqCst), 1);
    context.close().unwrap();
    backend.close().unwrap();
    assert!(lazy.send(&request).is_err());
    assert_eq!(
        created.load(Ordering::SeqCst),
        1,
        "neither close adopts caller pool"
    );
    lazy.close().unwrap();
    assert!(lazy.send(&request).is_err());
    assert_eq!(
        created.load(Ordering::SeqCst),
        2,
        "caller close recreates real lazy session"
    );
}

#[test]
fn managed_http_pool_reopens_after_context_close_without_resetting_cache_or_budget() {
    identity("managed_http_pool_reopens_after_context_close_without_resetting_cache_or_budget");
    let path = sigis_testdata::certvalidator(&["nist_pkits", "crls", "GoodCACRL.crl"])
        .canonicalize()
        .unwrap();
    let crl = std::fs::read(&path).unwrap();
    eprintln!(
        "BACKEND_TEST_INPUT {}",
        json!({"path":path,"length":crl.len(),"sha256":hex(&DigestAlgorithm::Sha256.digest(&crl))})
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let server_timeouts = Arc::new(AtomicUsize::new(0));
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    struct Server {
        stopped: Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stopped.store(true, Ordering::SeqCst);
            self.thread.take().unwrap().join().unwrap();
        }
    }
    let server_crl = crl.clone();
    let server = Server {
        stopped: stopped.clone(),
        thread: Some(std::thread::spawn({
            let connections = connections.clone();
            let requests = requests.clone();
            let server_timeouts = server_timeouts.clone();
            move || {
                use std::io::BufRead;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !stopped.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                    let (stream, _) = match listener.accept() {
                        Ok(value) => value,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("loopback accept: {error}"),
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                        .unwrap();
                    let mut reader = std::io::BufReader::new(stream);
                    loop {
                        if stopped.load(Ordering::SeqCst) {
                            return;
                        }
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                server_timeouts.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                            Err(error) => panic!("loopback request: {error}"),
                        }
                        assert!(line.starts_with("GET "), "{line:?}");
                        loop {
                            line.clear();
                            assert!(reader.read_line(&mut line).unwrap() > 0);
                            if line == "\r\n" {
                                break;
                            }
                        }
                        requests.fetch_add(1, Ordering::SeqCst);
                        write!(reader.get_mut(), "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n", server_crl.len()).unwrap();
                        reader.get_mut().write_all(&server_crl).unwrap();
                        reader.get_mut().flush().unwrap();
                        if requests.load(Ordering::SeqCst) == 3 {
                            return;
                        }
                    }
                }
            }
        })),
    };
    let settings = FetcherSettings {
        limits: sigis_pki_fetch::FetchLimits {
            max_requests: Some(3),
            ..Default::default()
        },
        ..Default::default()
    };
    let backend = Arc::new(HttpFetchers::new(settings.clone()));
    let context = ValidationContext::builder()
        .owned_fetcher_backend(backend.clone())
        .fetchers(Fetchers::none())
        .build()
        .unwrap();
    let url = |name| format!("http://{address}/{name}");
    assert_eq!(backend.fetch_crl_url(&url("a")).unwrap(), crl);
    assert_eq!(backend.fetch_crl_url(&url("b")).unwrap(), crl);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "actual reqwest session reuses its idle connection"
    );
    context.close().unwrap();
    assert_eq!(
        backend.fetch_crl_url(&url("a")).unwrap(),
        crl,
        "cache survives close"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(backend.fetch_crl_url(&url("c")).unwrap(), crl);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "managed close drops the old idle session"
    );
    context.close().unwrap();
    context.close().unwrap();
    assert_eq!(backend.settings(), &settings);
    assert_eq!(
        backend.fetch_crl_url(&url("d")).unwrap_err().kind,
        FetchErrorKind::Disabled,
        "close never replenishes a spent budget"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    assert_eq!(
        server_timeouts.load(Ordering::SeqCst),
        0,
        "server eviction must not mimic managed client close"
    );
    drop(server);
}
