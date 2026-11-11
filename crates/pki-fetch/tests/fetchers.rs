//! Behaviour of the HTTP fetchers against a local server (original Sigis
//! tests; the upstream suites only cover the failure paths).

mod common;

use common::{load_cert, read_cv, LocalServer, Reply};
use sigis_pki_fetch::HttpFetchers;

#[test]
fn fetches_a_der_certificate_and_caches_it() {
    let cert = load_cert(&["testing-aia", "with-ldap-urls.der"]);
    let server = LocalServer::start(Reply {
        status: 200,
        content_type: Some("application/pkix-cert".into()),
        body: cert.der().to_vec(),
    });
    let f = HttpFetchers::default();
    let url = format!("{}/ca.crt", server.url);
    for _ in 0..2 {
        let certs = f.fetch_certs(&url, "certificate").expect("fetch");
        assert_eq!(certs, vec![cert.clone()]);
    }
    assert_eq!(server.received.lock().unwrap().len(), 1, "cached");
}

#[test]
fn rejects_unacceptable_content_type() {
    let cert = load_cert(&["testing-aia", "with-ldap-urls.der"]);
    let server = LocalServer::start(Reply {
        status: 200,
        content_type: Some("text/html".into()),
        body: cert.der().to_vec(),
    });
    let e = HttpFetchers::default()
        .fetch_certs(&server.url, "certificate")
        .expect_err("content type");
    assert!(e.message.contains("Unacceptable content type"), "{e}");
}

#[test]
fn http_errors_and_oversized_responses_fail() {
    let server = LocalServer::start(Reply {
        status: 404,
        content_type: Some("application/pkix-crl".into()),
        body: Vec::new(),
    });
    assert!(HttpFetchers::default().fetch_crl_url(&server.url).is_err());

    let big = LocalServer::start(Reply {
        status: 200,
        content_type: Some("application/pkix-crl".into()),
        body: vec![0x30; 4096],
    });
    let f = HttpFetchers::new(sigis_pki_fetch::FetcherSettings {
        limits: sigis_pki_fetch::FetchLimits {
            max_response_bytes: 1024,
            ..Default::default()
        },
        ..Default::default()
    });
    let e = f.fetch_crl_url(&big.url).expect_err("too large");
    assert_eq!(e.kind, sigis_pki_core::errors::FetchErrorKind::TooLarge);
}

#[test]
fn fetches_a_crl() {
    let crl = read_cv(&["nist_pkits", "crls", "GoodCACRL.crl"]);
    let server = LocalServer::start(Reply {
        status: 200,
        content_type: Some("application/pkix-crl".into()),
        body: crl.clone(),
    });
    assert_eq!(
        HttpFetchers::default()
            .fetch_crl_url(&server.url)
            .expect("crl"),
        crl
    );
}
