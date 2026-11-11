// Ported from pyhanko-certvalidator 0.33.0 `tests/test_fetch_limits.py`
// (MIT, see LICENSE-pyHanko).
//
// Upstream runs each network test twice (aiohttp and requests backends);
// this port has one HTTP backend, behind `HttpTransport`, so each test runs
// once against a transport that fails every request and counts it.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::{load_cert, FailingTransport};
use hanko_core::fetch::OcspFetcher;
use hanko_fetch::budget::{cap_aia_urls, FetchBudget, FetchKind, FetchLimits};
use hanko_fetch::{FetcherSettings, HttpFetchers};

fn network(limits: FetchLimits) -> (HttpFetchers, Arc<FailingTransport>) {
    let transport = Arc::new(FailingTransport::default());
    let fetchers = HttpFetchers::with_transport(
        transport.clone(),
        FetcherSettings {
            limits,
            ..FetcherSettings::default()
        },
    );
    (fetchers, transport)
}

fn limits(max_requests: Option<usize>, max_cert: Option<usize>, max_aia: Option<usize>) -> FetchLimits {
    FetchLimits {
        max_requests,
        max_cert_requests: max_cert,
        max_aia_urls_per_object: max_aia,
        ..FetchLimits::default()
    }
}

fn count(t: &FailingTransport) -> usize {
    t.count.load(Ordering::SeqCst)
}

#[test]
fn test_cert_requests_beyond_total_limit_are_refused() {
    let (f, t) = network(limits(Some(2), Some(200), Some(10)));
    for i in 0..2 {
        let e = f.fetch_certs(&format!("http://x/{i}"), "certificate").expect_err("fail");
        assert!(e.message.contains("Failed to fetch"), "{e}");
    }
    let e = f.fetch_certs("http://x/2", "certificate").expect_err("limit");
    assert!(e.message.contains("limit of 2 requests"), "{e}");
    assert_eq!(count(&t), 2);
}

#[test]
fn test_cached_results_do_not_consume_budget() {
    let (f, t) = network(limits(Some(1), Some(200), Some(10)));
    for _ in 0..3 {
        let e = f.fetch_certs("http://x", "certificate").expect_err("fail");
        assert!(e.message.contains("Failed to fetch"), "{e}");
    }
    assert_eq!(count(&t), 1);
}

#[test]
fn test_cert_limit_does_not_block_other_fetch_types() {
    let (f, t) = network(limits(Some(1000), Some(1), Some(10)));
    for i in 0..3 {
        let e = f.fetch_crl_url(&format!("http://x/{i}")).expect_err("fail");
        assert!(e.message.contains("Failure to fetch"), "{e}");
    }
    let e = f.fetch_certs("http://x", "certificate").expect_err("fail");
    assert!(e.message.contains("Failed to fetch"), "{e}");
    let e = f.fetch_certs("http://y", "certificate").expect_err("limit");
    assert!(e.message.contains("1 certificate requests"), "{e}");
    assert_eq!(count(&t), 4);
}

#[test]
fn test_total_limit_is_shared_between_fetchers() {
    let (f, t) = network(limits(Some(1), Some(200), Some(10)));
    let e = f.fetch_crl_url("http://x/crl").expect_err("fail");
    assert!(e.message.contains("Failure to fetch"), "{e}");
    let e = f.fetch_certs("http://x", "certificate").expect_err("limit");
    assert!(e.message.contains("limit of 1 requests"), "{e}");
    let e = f.fetch_crl_url("http://x/crl2").expect_err("limit");
    assert!(e.message.contains("limit of 1 requests"), "{e}");
    assert_eq!(count(&t), 1);
}

#[test]
fn test_ocsp_requests_are_limited() {
    let leaf = load_cert(&["ades", "time-slide", "certs", "alice.crt"]);
    let interm = load_cert(&["ades", "time-slide", "certs", "interm.crt"]);
    let root = load_cert(&["ades", "time-slide", "certs", "root.crt"]);
    let (f, t) = network(limits(Some(1), Some(200), Some(10)));
    let e = f.fetch_ocsp(&leaf, &interm).expect_err("fail");
    assert!(e.message.contains("Failed to fetch"), "{e}");
    let e = f.fetch_ocsp(&leaf, &root).expect_err("limit");
    assert!(e.message.contains("limit of 1 requests"), "{e}");
    assert_eq!(count(&t), 1);
}

#[test]
fn test_aia_urls_per_object_are_capped() {
    // Both parametrizations (issuer URLs of a certificate, of a CRL) end in
    // the same URL list fetch.
    for origin in ["certificate", "CRL"] {
        let urls: Vec<String> = (0..5).map(|i| format!("http://x/{i}")).collect();
        let (f, t) = network(limits(Some(1000), Some(200), Some(2)));
        assert!(f.fetch_issuers_from_urls(urls, origin).is_empty());
        assert_eq!(count(&t), 2);
    }
}

#[test]
fn test_aia_urls_are_not_capped_without_a_budget_or_limit() {
    let urls: Vec<String> = (0..30).map(|i| format!("http://x/{i}")).collect();
    assert_eq!(cap_aia_urls(None, urls.clone()), urls);
    let budget = FetchBudget::new(FetchLimits::unlimited());
    assert_eq!(cap_aia_urls(Some(&budget), urls.clone()), urls);
}

#[test]
fn test_aia_cap_logs_a_warning_when_truncating() {
    // The truncation itself; this port does not log.
    let budget = FetchBudget::new(limits(Some(1000), Some(200), Some(1)));
    assert_eq!(
        cap_aia_urls(Some(&budget), vec!["a".into(), "b".into()]),
        vec!["a".to_owned()]
    );
    assert_eq!(cap_aia_urls(Some(&budget), vec!["a".into()]), vec!["a".to_owned()]);
}

#[test]
fn test_exhaustion_warns_once_then_logs_at_debug() {
    let budget = FetchBudget::new(limits(Some(0), Some(200), Some(10)));
    assert!(!budget.exhaustion_reported());
    for _ in 0..3 {
        let e = budget.charge(FetchKind::Ocsp).expect_err("refused");
        assert_eq!(e.kind, FetchKind::Ocsp);
        assert!(budget.exhaustion_reported());
    }
}

#[test]
fn test_unlimited_budget_never_refuses() {
    let budget = FetchBudget::new(FetchLimits::unlimited());
    for kind in [FetchKind::Cert, FetchKind::Crl, FetchKind::Ocsp] {
        for _ in 0..50 {
            budget.charge(kind).expect("unlimited");
        }
    }
}

#[test]
fn test_backend_limits_default_and_propagation() {
    let default = HttpFetchers::default();
    assert_eq!(default.settings().limits, FetchLimits::default());
    assert_eq!(default.budget().limits().max_requests, Some(1000));
    assert_eq!(default.budget().limits().max_cert_requests, Some(200));
    assert_eq!(default.budget().limits().max_aia_urls_per_object, Some(10));
    let custom = limits(Some(5), Some(200), Some(10));
    let first = network(custom.clone()).0;
    let second = network(custom.clone()).0;
    assert_eq!(first.budget().limits(), &custom);
    // The three fetchers of one instance share a budget; instances do not.
    let shared = first.clone();
    assert!(std::ptr::eq(first.budget(), shared.budget()));
    assert!(!std::ptr::eq(first.budget(), second.budget()));
}
