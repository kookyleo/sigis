// Ported from pyhanko-certvalidator 0.33.0
// `tests/test_fetcher_lifecycle.py` (MIT, see LICENSE-pyHanko).
// Native resource release is observed through Drop rather than asyncio.close.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_fetch::transport::HttpRequest;
use sigis_pki_fetch::transport::LazyTransport;
use sigis_pki_fetch::{FetcherSettings, HttpFetchers, HttpResponse, HttpTransport, TransportError};

#[derive(Debug)]
struct RecordingTransport {
    created: usize,
    released: Arc<AtomicUsize>,
}

impl Drop for RecordingTransport {
    fn drop(&mut self) {
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}

impl HttpTransport for RecordingTransport {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
        Ok(HttpResponse {
            status: 200,
            content_type: None,
            body: self.created.to_be_bytes().to_vec(),
        })
    }
}

fn request() -> HttpRequest<'static> {
    HttpRequest {
        method: "GET",
        url: "https://example.invalid",
        headers: Vec::new(),
        body: None,
    }
}

#[test]
fn test_lazy_session_is_reusable_after_closing() {
    let created = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    let lazy = LazyTransport::with_factory({
        let created = created.clone();
        let released = released.clone();
        move || {
            Ok(Arc::new(RecordingTransport {
                created: created.fetch_add(1, Ordering::SeqCst),
                released: released.clone(),
            }) as Arc<dyn HttpTransport>)
        }
    });
    assert_eq!(created.load(Ordering::SeqCst), 0);
    let first = lazy.send(&request()).unwrap();
    assert_eq!(first, lazy.send(&request()).unwrap());
    assert_eq!(created.load(Ordering::SeqCst), 1);
    lazy.close().unwrap();
    assert_eq!(released.load(Ordering::SeqCst), 1);
    let second = lazy.send(&request()).unwrap();
    assert_ne!(first.body, second.body);
    assert_eq!(created.load(Ordering::SeqCst), 2);
    lazy.close().unwrap();
    assert_eq!(released.load(Ordering::SeqCst), 2);
    lazy.close().unwrap();
    assert_eq!(released.load(Ordering::SeqCst), 2);
}

#[test]
fn test_lazy_session_close_without_a_session() {
    let created = Arc::new(AtomicUsize::new(0));
    let lazy = LazyTransport::with_factory({
        let created = created.clone();
        move || {
            created.fetch_add(1, Ordering::SeqCst);
            Err(TransportError::Network("factory must not be called".into()))
        }
    });
    lazy.close().unwrap();
    assert_eq!(created.load(Ordering::SeqCst), 0);
}

#[test]
fn test_context_leaves_supplied_fetchers_alone() {
    let released = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(RecordingTransport {
        created: 0,
        released: released.clone(),
    });
    let backend = HttpFetchers::with_transport(transport.clone(), FetcherSettings::default());
    let supplied_fetchers = backend.as_fetchers();
    let context = ValidationContext::builder()
        .fetchers(supplied_fetchers.clone())
        .build()
        .unwrap();
    drop(backend);
    drop(transport);
    assert!(!context.fetchers().is_empty());
    drop(context);
    assert_eq!(released.load(Ordering::SeqCst), 0);
    drop(supplied_fetchers);
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

#[test]
fn test_no_backend_without_fetching() {
    let context = ValidationContext::builder().build().unwrap();
    assert!(context.fetchers().is_empty());
    assert!(context.fetchers().ocsp.is_none());
    assert!(context.fetchers().crl.is_none());
    assert!(context.fetchers().cert.is_none());
    drop(context);
}
