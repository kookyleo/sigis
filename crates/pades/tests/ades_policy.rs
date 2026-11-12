//! Exact policy/bootstrap assertions from pyHanko 0.38.1 plus transport checks.

mod common;

use sigis_pades::ades::policy::{
    bootstrap_validation_data_handlers, CertificateFetchingRule, RevinfoOnlineFetchingRule,
    RevocationInfoGatheringSpec,
};

#[test]
fn test_bootstrap_handlers_default_backend() {
    let handlers =
        bootstrap_validation_data_handlers(&RevocationInfoGatheringSpec::default(), false);
    assert!(handlers.owned_fetcher_backend.is_some());
    assert!(handlers.fetchers.ocsp.is_some());
    assert!(handlers.fetchers.crl.is_some());
    assert!(handlers.fetchers.cert.is_some());
}

#[test]
fn test_certificate_fetching_rule_matrix() {
    use CertificateFetchingRule::{FollowOnlineRule, NeverFetch};
    use RevinfoOnlineFetchingRule::{AlwaysFetch, LocalOnly, NoHistoricalFetch};
    let mut cases = 0;
    for online_rule in [AlwaysFetch, NoHistoricalFetch, LocalOnly] {
        for historical in [true, false] {
            for cert_rule in [FollowOnlineRule, NeverFetch] {
                let expect_online = matches!(
                    (online_rule, historical),
                    (AlwaysFetch, true) | (AlwaysFetch, false) | (NoHistoricalFetch, false)
                );
                let expect_cert_fetcher = cert_rule == FollowOnlineRule && expect_online;
                let spec = RevocationInfoGatheringSpec {
                    online_fetching_rule: online_rule,
                    certificate_fetching_rule: cert_rule,
                    ..Default::default()
                };
                let handlers = bootstrap_validation_data_handlers(&spec, historical);
                assert_eq!(handlers.fetchers.cert.is_some(), expect_cert_fetcher);
                assert_eq!(handlers.fetchers.ocsp.is_some(), expect_online);
                assert_eq!(handlers.fetchers.crl.is_some(), expect_online);
                assert_eq!(handlers.fetching_allowed(), expect_online);
                assert_eq!(handlers.owned_fetcher_backend.is_some(), expect_online);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 12);
}

#[test]
fn test_never_fetch_certs_keeps_revinfo_fetching() {
    let spec = RevocationInfoGatheringSpec {
        certificate_fetching_rule: CertificateFetchingRule::NeverFetch,
        ..Default::default()
    };
    let handlers = bootstrap_validation_data_handlers(&spec, false);
    assert!(handlers.fetchers.cert.is_none());
    assert!(handlers.owned_fetcher_backend.is_some());
    assert!(handlers.fetching_allowed());
    assert!(handlers.fetchers.ocsp.is_some());
    assert!(handlers.fetchers.crl.is_some());
}

#[test]
fn certificate_rule_keeps_real_revocation_http_requests() {
    use sigis_pki_fetch::transport::HttpRequest;
    use sigis_pki_fetch::{
        FetcherSettings, HttpFetchers, HttpResponse, HttpTransport, ReqwestTransport,
        TransportError,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Debug)]
    struct LocalTransport {
        url: String,
        actual: ReqwestTransport,
        paths: Mutex<Vec<String>>,
    }

    impl HttpTransport for LocalTransport {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
            self.paths.lock().unwrap().push(request.url.to_owned());
            self.actual.send(&HttpRequest {
                url: &self.url,
                ..request.clone()
            })
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/revocation", listener.local_addr().unwrap());
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = std::thread::spawn(move || {
        let mut received = 0;
        while !server_stop.load(std::sync::atomic::Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut buf = [0; 4096];
                    let _ = stream.read(&mut buf);
                    stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                    received += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("local server: {e}"),
            }
        }
        received
    });
    let transport = Arc::new(LocalTransport {
        url,
        actual: ReqwestTransport::new(Duration::from_secs(2), 4096).unwrap(),
        paths: Mutex::new(Vec::new()),
    });
    let spec = RevocationInfoGatheringSpec {
        certificate_fetching_rule: CertificateFetchingRule::NeverFetch,
        fetcher_backend: Some(HttpFetchers::with_transport(
            transport.clone(),
            FetcherSettings::default(),
        )),
        ..Default::default()
    };
    let handlers = bootstrap_validation_data_handlers(&spec, false);
    assert!(
        handlers.owned_fetcher_backend.is_none(),
        "caller owns supplied backend"
    );
    assert!(handlers.fetchers.cert.is_none());
    let rec = common::Recording::load("test_ades_validation");
    let cert = rec.cert("testing-ca", "signer1");
    let issuer = rec.cert("testing-ca", "interm");
    assert!(handlers
        .fetchers
        .ocsp
        .as_ref()
        .unwrap()
        .fetch_ocsp(&cert, &issuer)
        .is_err());
    let ctx = sigis_pki_certvalidator::ValidationContext::builder()
        .fetchers(handlers.fetchers)
        .build()
        .unwrap();
    assert!(ctx.retrieve_crls(&cert).is_empty());
    stop.store(true, std::sync::atomic::Ordering::Release);
    let received = server.join().unwrap();
    assert!(
        received >= 2,
        "OCSP and CRL requests reached the local HTTP server"
    );
    assert_eq!(received, transport.paths.lock().unwrap().len());

    for historical in [true, false] {
        let disabled = bootstrap_validation_data_handlers(
            &RevocationInfoGatheringSpec {
                online_fetching_rule: RevinfoOnlineFetchingRule::LocalOnly,
                ..spec.clone()
            },
            historical,
        );
        assert!(disabled.fetchers.is_empty());
    }
}
