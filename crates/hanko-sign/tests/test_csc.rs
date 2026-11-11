//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_csc.py`, against a local
//! fake CSC service (`support::csc_server`, a port of certomancer-csc-dummy).
//!
//! pyHanko's coroutines sharing a batch become threads; `asyncio.sleep`
//! orderings become short sleeps. pyHanko's `SlowCommitter` subclasses
//! (which delay `_do_commit`) are replaced by delays in the fake service's
//! `signHash` handler, which keep the batch in the "initiated" state for the
//! same span. Network failures use a closed local port instead of
//! `example.invalid`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hanko_core::algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext};
use hanko_core::asn1::oids;
use hanko_core::cert::Cert;
use hanko_core::errors::HankoError;
use hanko_core::sign::KeySigner;
use hanko_sign::csc::{
    self, fetch_certs_in_csc_credential, http_client, parse_csc_auth_response_at,
    process_certificate_info_response, CscAuthRequest, CscAuthorizationInfo, CscAuthorizationManager,
    CscCredentialInfo, CscServiceSessionInfo, CscSigner, CscSignerOptions,
    PrefetchedSadAuthorizationManager,
};
use hanko_sign::{PdfSignatureMetadata, PdfSigner};
use serde_json::{json, Value};
use spki::AlgorithmIdentifierOwned;
use support::csc_server::{closed_url, CscDummy, DummyClientAuthManager, DummyServiceParams, FakeServer};
use support::pdfcheck::*;
use support::*;

const SIGNER_B64: &str = "
MIIEMDCCAxigAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCQkUxFDASBgNVBAoM
C0V4YW1wbGUgSW5jMRowGAYDVQQLDBFUZXN0aW5nIEF1dGhvcml0eTEYMBYGA1UEAwwPSW50ZXJt
ZWRpYXRlIENBMCIYDzIwMjAwMTAxMDAwMDAwWhgPMjAyMjAxMDEwMDAwMDBaMHExCzAJBgNVBAYT
AkJFMRQwEgYDVQQKDAtFeGFtcGxlIEluYzEaMBgGA1UECwwRVGVzdGluZyBBdXRob3JpdHkxDjAM
BgNVBAMMBUFsaWNlMSAwHgYJKoZIhvcNAQkBFhFhbGljZUBleGFtcGxlLmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAOFzgm4eL34uvUYrX4akyEBi+sn0gCYo8UOthApfluxF4cca
GhCHdjZa1PwRpV3bDGFQpUbhNu0juCBkYbRGxasQOn1CUDF7DCCjztNEd779WwRlA5dnqWMFU5Ij
toavSYl+CA1Ase2edxq7UjEZr4kIm7ADlUVpdKxLItJFEP4QOjqv5sENuiGCKpMqb/JGmvnLxRev
xDZQ8hIDV2s07krCog8hRChie39mDNmZ/RH/JbgME6mGY99bDAnhu8xH41iBo8GemEmmFesx8YPr
MivcXHk3QNt2LsKCAGZlG51fsrtiC31732W0+dc09PoITS0NMvP8/38dQmod3ktJBusCAwEAAaOB
5TCB4jAdBgNVHQ4EFgQUXsenutQKZ62drno9rRRqOLVzCrgwHwYDVR0jBBgwFoAU7796UYsupC5K
XdLO52F4zmo2SU8wDgYDVR0PAQH/BAQDAgbAMEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9weWhh
bmtvLnRlc3RzL3Rlc3RpbmctY2EvY3Jscy9pbnRlcm0vbGF0ZXN0LmNybDBHBggrBgEFBQcBAQQ7
MDkwNwYIKwYBBQUHMAGGK2h0dHA6Ly9weWhhbmtvLnRlc3RzL3Rlc3RpbmctY2Evb2NzcC9pbnRl
cm0wDQYJKoZIhvcNAQELBQADggEBACwIBhziVaZdlWg5S7PCjnL2yEeDnJWW3c1DXzKz8++mjDR0
GNsMgy1+XxKBR7gqaIDCUIPvgWko6UNfvt74txy1eBI4KHfWG/J3R9S54MTm+jZc/ctR9ma2kqcp
nz5p6HjfgdN/ejY3Fop+dZSvapbQumk27/3boKjzftXJP1VD6LSpINBDEX4kw9w4xZDpgZOcxB+s
k36fJ/cT50B7dYFFfSfKWCU7cpOYtkwnytfOBc4PxodIjrv1Y5ZSELyC8mY+U3zTlDLdG364BMSV
x4AzyPTjm252vITdbnsFZTPkpEz2gfQnh0Ee5jq+vkPfUyB0tgGju0yu9EgFIu2pzGY=
";

const INTERM_B64: &str = "
MIID2TCCAsGgAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCQkUxFDASBgNVBAoM
C0V4YW1wbGUgSW5jMRowGAYDVQQLDBFUZXN0aW5nIEF1dGhvcml0eTEQMA4GA1UEAwwHUm9vdCBD
QTAiGA8yMDAwMDEwMTAwMDAwMFoYDzIxMDAwMTAxMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEUMBIG
A1UECgwLRXhhbXBsZSBJbmMxGjAYBgNVBAsMEVRlc3RpbmcgQXV0aG9yaXR5MRgwFgYDVQQDDA9J
bnRlcm1lZGlhdGUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDB6drP3ogV8UnY
2YM0GREPUCCEe7FX905/Ocl2MjyPyh3/vaf542LGQWdC1mf3fNQsMu2dqaZTwUQrKJwIs07QV7r1
now3rKUNG8YyGtdZfKyt6jgOsfaZ5KB54sUtWGy4LKT4cPq0vEWnm8lFo91kvJqVOjFXWpUSKwTP
YJV+riBmKg25C+8D2L5oKdMzQxd8o9K0kAI0fDF1CPbqtCB/GIzwN2Cq20bX9dpzTbZOlvIundA4
hLYBNcfXnigPLylc3x3YxypoBotQ5L9MxKceBgrv1SfgtEAqxeYgUZe/UQdEG7jRy0JIYFKS/EWv
HcJ6jAX+v64hKeIAslO/67TbAgMBAAGjga4wgaswHQYDVR0OBBYEFO+/elGLLqQuSl3SzudheM5q
NklPMB8GA1UdIwQYMBaAFPG0eZUCsrRfOXL9sI/CX69bmlC1MBIGA1UdEwEB/wQIMAYBAf8CAQAw
DgYDVR0PAQH/BAQDAgGGMEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9weWhhbmtvLnRlc3RzL3Rl
c3RpbmctY2EvY3Jscy9yb290L2xhdGVzdC5jcmwwDQYJKoZIhvcNAQELBQADggEBAAx7qZLSOIk4
B7w6ymmPF3cKrafdJg83NhWAJZHOie9E23hhOV0uOLoaab2m+TbpqUXXpeuxCC3t2duLueSceHUX
Y+UhZGF4LdTojK5yVnyHynJVwbAAzRyO1hIjI9SFW+NMsFNwN6t50RAhTGY7jZvvv2y3mMwUHE2u
lgsQNax0Tyoh6yOtb752IWm0Yj+cEMQ36cjxkcFZgYTiziuYkYJM8wL+kADG+HUsnfdYJWMM/lJ7
YEkSIm0lhec3xR6siySnZI2whU3twY37WcnxwjkAczSdHZJpyzrSyjp8rCwk0zOF4HGQr3WuJhHo
kS0gHz5+cFMDBZxeP5Oq5UFvFtU=
";

fn signing_msg<T: std::fmt::Debug>(r: hanko_core::errors::Result<T>) -> String {
    match r {
        Err(HankoError::Signing(m)) => m,
        other => panic!("expected SigningError, got {other:?}"),
    }
}

fn signer1() -> Cert {
    pki("testing-ca").cert("signer1")
}

fn cred_info(supported: &[&str], max_batch_size: i64) -> CscCredentialInfo {
    CscCredentialInfo {
        signing_cert: signer1(),
        chain: vec![],
        supported_mechanisms: supported.iter().map(|s| (*s).to_owned()).collect::<BTreeSet<_>>(),
        max_batch_size,
        hash_pinning_required: false,
        response_data: json!({}),
    }
}

fn prefetched(url: &str, cred: &str, info: CscCredentialInfo, sad: &str) -> Arc<PrefetchedSadAuthorizationManager> {
    Arc::new(PrefetchedSadAuthorizationManager::new(
        CscServiceSessionInfo::new(url, cred),
        info,
        CscAuthorizationInfo::new(sad),
    ))
}

fn signer(auth: Arc<dyn CscAuthorizationManager>, opts: CscSignerOptions) -> Arc<CscSigner> {
    Arc::new(CscSigner::new(http_client().unwrap(), auth, opts))
}

fn sha256_rsa() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: oids::SHA256_WITH_RSA,
        parameters: None,
    }
}

fn verify(sig: &[u8], data: &[u8], cert: &Cert, mech: &AlgorithmIdentifierOwned) {
    validate_signature(
        sig,
        data,
        &cert.public_key(),
        mech,
        &SignatureValidationContext {
            contextual_digest: Some(DigestAlgorithm::Sha256),
            prehashed: false,
        },
    )
    .expect("signature verifies");
}

#[test]
fn test_proc_cert_info_response() {
    let cred_info = process_certificate_info_response(&json!({
        "cert": {"certificates": [SIGNER_B64, INTERM_B64]},
        "key": {"algo": ["1.2.840.113549.1.1.11"], "len": 2048},
        "multisign": 10,
        "authMode": "implicit",
        "SCAL": 2,
    }))
    .unwrap();
    assert_eq!(cred_info.max_batch_size, 10);
    assert!(cred_info.hash_pinning_required);
    assert!(cred_info.supported_mechanisms.contains("sha256_rsa"));
    let name = hanko_sign::signer::subject_display_name(&cred_info.signing_cert).unwrap();
    assert!(name.contains("Alice"), "{name}");
}

#[test]
fn test_proc_cert_info_response_errors() {
    let algo = json!({"algo": ["1.2.840.113549.1.1.11"], "len": 2048});
    let certs = json!({"certificates": [SIGNER_B64, INTERM_B64]});
    let cases = vec![
        (
            json!({"cert": {}, "key": algo, "multisign": 10, "authMode": "implicit", "SCAL": 2}),
            "Could not retrieve certificates from response",
        ),
        (
            json!({"key": algo, "multisign": 10, "authMode": "implicit", "SCAL": 2}),
            "Could not retrieve certificates from response",
        ),
        (
            json!({"cert": {"certificates": [SIGNER_B64.replace('M', "Z")]}, "key": algo,
                   "multisign": 10, "authMode": "implicit", "SCAL": 2}),
            "Could not decode certificates in response",
        ),
        (
            json!({"cert": certs, "key": {"algo": "1.2.840.113549.1.1.11", "len": 2048},
                   "multisign": 10, "authMode": "implicit", "SCAL": 2}),
            "Could not retrieve supported signing mechanisms",
        ),
        (
            json!({"cert": certs, "key": {"algo": ["zzz1.2.840.113549.1.1.11"], "len": 2048},
                   "multisign": 10, "authMode": "implicit", "SCAL": 2}),
            "Could not retrieve supported signing mechanisms",
        ),
        (
            json!({"cert": certs, "key": {"len": 2048}, "multisign": 10, "authMode": "implicit", "SCAL": 2}),
            "Could not retrieve supported signing mechanisms",
        ),
        (
            json!({"cert": certs, "key": algo, "authMode": "implicit", "SCAL": 2}),
            "Could not retrieve max batch size",
        ),
        (
            json!({"cert": certs, "key": algo, "multisign": "foobar", "authMode": "implicit", "SCAL": 2}),
            "Could not retrieve max batch size",
        ),
        (
            json!({"cert": certs, "key": algo, "multisign": 10, "authMode": "implicit", "SCAL": 3}),
            "SCAL value must be",
        ),
        (
            json!({"cert": certs, "key": algo, "multisign": 10, "authMode": "implicit", "SCAL": "zzz"}),
            "SCAL value must be",
        ),
    ];
    assert_eq!(cases.len(), 10);
    for (resp, err) in cases {
        let msg = signing_msg(process_certificate_info_response(&resp));
        assert!(msg.contains(err), "{msg} !~ {err}");
    }
}

#[test]
fn test_format_csc_auth_request() {
    // any old auth manager will do
    let auth_man = prefetched("https://example.com", "foobar", cred_info(&[], 10), "");
    let h = "Sa6Tcy/PjWP+HM51lmSYLb1bIxYfAH26hWGGKtyW0GM=".to_owned();
    let result = auth_man.format_csc_auth_request(&CscAuthRequest {
        pin: Some("1234".into()),
        otp: Some("123456".into()),
        hash_b64s: Some(vec![h.clone(), h.clone()]),
        description: Some("baz".into()),
        client_data: Some("quux".into()),
        ..Default::default()
    });
    assert_eq!(
        result,
        json!({
            "credentialID": "foobar",
            "numSignatures": 2,
            "hash": [h, h],
            "PIN": "1234",
            "OTP": "123456",
            "description": "baz",
            "clientData": "quux",
        })
    );
}

#[test]
fn test_parse_csc_auth_response() {
    let now = at("2021-11-01T00:00:00+00:00");
    let result = parse_csc_auth_response_at(&json!({"SAD": "foobar", "expiresIn": 300}), now).unwrap();
    assert_eq!(
        result,
        CscAuthorizationInfo {
            sad: "foobar".into(),
            expires_at: Some(at("2021-11-01T00:05:00+00:00")),
        }
    );
}

#[test]
fn test_parse_csc_auth_response_default_expiry() {
    let now = at("2021-11-01T00:00:00+00:00");
    let result = parse_csc_auth_response_at(&json!({"SAD": "foobar"}), now).unwrap();
    assert_eq!(
        result,
        CscAuthorizationInfo {
            sad: "foobar".into(),
            expires_at: Some(at("2021-11-01T01:00:00+00:00")),
        }
    );
}

#[test]
fn test_parse_csc_auth_response_error() {
    for (resp, err) in [
        (json!({}), "Could not extract SAD"),
        (json!({"SAD": "foobar", "expiresIn": "nonsense"}), "Could not process expiresIn"),
    ] {
        let msg = signing_msg(csc::parse_csc_auth_response(&resp));
        assert!(msg.contains(err), "{msg}");
    }
}

// network failure tests

#[test]
fn test_cert_provision_fail() {
    let info = CscServiceSessionInfo::new(closed_url(), "foobar");
    let msg = signing_msg(fetch_certs_in_csc_credential(&http_client().unwrap(), &info, Duration::from_secs(30)));
    assert!(msg.contains("Credential info request failed"), "{msg}");
}

#[test]
fn test_sign_mechanism_not_supported() {
    let auth_man = prefetched("https://example.com", "foobar", cred_info(&["is_nonsense"], 10), "");
    // check expected failure for a signing attempt
    let s = signer(auth_man.clone(), CscSignerOptions::default());
    let msg = signing_msg(s.sign_raw(b"foobarbazquux", DigestAlgorithm::Sha256));
    assert!(msg.contains("No signing results available"), "{msg}");

    // check expected failure when fetching the signature mechanism directly
    let s = signer(auth_man.clone(), CscSignerOptions::default());
    let msg = signing_msg(s.signature_mechanism_for_digest(DigestAlgorithm::Sha256));
    assert!(msg.contains("must be one of"), "{msg}");

    // ...but overrides should still work
    let mech = sha256_rsa();
    let s = signer(
        auth_man,
        CscSignerOptions {
            signature_mechanism: Some(mech.clone()),
            ..Default::default()
        },
    );
    assert_eq!(s.signature_mechanism_for_digest(DigestAlgorithm::Sha256).unwrap(), mech);
}

#[test]
fn test_sign_network_fail() {
    let auth_man = prefetched(&closed_url(), "foobar", cred_info(&["sha256_rsa"], 10), "");
    let s = signer(auth_man, CscSignerOptions::default());
    let msg = signing_msg(s.sign_raw(b"foobarbazquux", DigestAlgorithm::Sha256));
    assert!(msg.contains("No signing results available"), "{msg}");
}

fn fixed_response_server(resp: Value) -> FakeServer {
    FakeServer::start(Arc::new(move |path: &str, _body: &Value| {
        if path == "/csc/v1/signatures/signHash" {
            (200, resp.clone())
        } else {
            (404, json!({}))
        }
    }))
}

#[test]
fn test_sign_wrong_number_of_sigs() {
    let server = fixed_response_server(json!({
        "signatures": [<base64ct::Base64 as base64ct::Encoding>::encode_string(&[0u8; 512])]
    }));
    let auth_man = prefetched(&server.url, "foobar", cred_info(&["sha256_rsa"], 2), "");
    let s = signer(
        auth_man,
        CscSignerOptions {
            batch_size: 2,
            batch_autocommit: false,
            ..Default::default()
        },
    );
    let t1 = {
        let s = s.clone();
        thread::spawn(move || s.sign_raw(b"foobarbaz", DigestAlgorithm::Sha256))
    };
    let t2 = {
        let s = s.clone();
        thread::spawn(move || s.sign_raw(b"foobarbazquux", DigestAlgorithm::Sha256))
    };
    while s.current_batch_len() < 2 {
        thread::sleep(Duration::from_millis(10));
    }
    let msg = signing_msg(s.commit());
    assert!(msg.contains("Expected 2 signatures"), "{msg}");
    // pyHanko cancels the waiting coroutines; here they see the failure
    for t in [t1, t2] {
        let msg = signing_msg(t.join().unwrap());
        assert!(msg.contains("No signing results available"), "{msg}");
    }
}

#[test]
fn test_sign_unreadable_sig() {
    for response_obj in [json!({"signatures": [null]}), json!({})] {
        let server = fixed_response_server(response_obj);
        let auth_man = prefetched(&server.url, "foobar", cred_info(&["sha256_rsa"], 1), "");
        let s = signer(
            auth_man,
            CscSignerOptions {
                batch_size: 1,
                batch_autocommit: false,
                client_data: Some("Some client data, because why not".into()),
                ..Default::default()
            },
        );
        let t = {
            let s = s.clone();
            thread::spawn(move || s.sign_raw(b"foobarbaz", DigestAlgorithm::Sha256))
        };
        while s.current_batch_len() < 1 {
            thread::sleep(Duration::from_millis(10));
        }
        let msg = signing_msg(s.commit());
        assert!(msg.contains("Expected response with b64"), "{msg}");
        let msg = signing_msg(t.join().unwrap());
        assert!(msg.contains("No signing results available"), "{msg}");
    }
}

#[test]
fn test_fail_different_digest() {
    let auth_man = prefetched("", "foobar", cred_info(&["sha256_rsa"], 2), "");
    let s = signer(
        auth_man,
        CscSignerOptions {
            batch_size: 2,
            ..Default::default()
        },
    );
    let t = {
        let s = s.clone();
        thread::spawn(move || s.sign_raw(b"foobarbaz", DigestAlgorithm::Sha256))
    };
    while s.current_batch_len() < 1 {
        thread::sleep(Duration::from_millis(10));
    }
    let msg = signing_msg(s.sign_raw(b"foobarbazquux", DigestAlgorithm::Sha512));
    assert!(msg.contains("same digest function"), "{msg}");
    // release the first signature (pyHanko abandons the coroutine): the
    // commit fails, since the service URL is empty
    let msg = signing_msg(s.commit());
    assert!(msg.contains("Signature request failed"), "{msg}");
    let msg = signing_msg(t.join().unwrap());
    assert!(msg.contains("No signing results available"), "{msg}");
}

/// `_set_up_dummy_client`.
fn set_up_dummy_client(require_hash_pinning: bool) -> (FakeServer, Arc<DummyClientAuthManager>, Arc<CscDummy>) {
    let dummy = CscDummy::new(DummyServiceParams {
        hash_pinning_required: require_hash_pinning,
        ..Default::default()
    });
    let server = dummy.start();
    let session_info = CscServiceSessionInfo::new(&server.url, "testing-ca/signer1");
    let cred = fetch_certs_in_csc_credential(&http_client().unwrap(), &session_info, Duration::from_secs(30))
        .unwrap();
    let auth_man = Arc::new(DummyClientAuthManager::new(session_info, cred));
    (server, auth_man, dummy)
}

#[test]
fn test_submit_job_during_commit() {
    let (_server, auth_man, dummy) = set_up_dummy_client(true);
    // the first commit is slow (pyHanko: `SlowCommitter`)
    dummy.sign_hash_delays.lock().unwrap().push_back(Duration::from_millis(2500));
    let s = signer(
        auth_man.clone(),
        CscSignerOptions {
            batch_autocommit: true,
            batch_size: 2,
            ..Default::default()
        },
    );
    let first = {
        let s = s.clone();
        thread::spawn(move || {
            // submit an incomplete batch
            let result = {
                let s = s.clone();
                thread::spawn(move || s.sign_raw(b"foobar1", DigestAlgorithm::Sha256))
            };
            thread::sleep(Duration::from_millis(500));
            s.commit().unwrap();
            result.join().unwrap()
        })
    };
    let others = {
        let s = s.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(1000));
            let a = {
                let s = s.clone();
                thread::spawn(move || s.sign_raw(b"foobar2", DigestAlgorithm::Sha256))
            };
            let b = {
                let s = s.clone();
                thread::spawn(move || s.sign_raw(b"foobar3", DigestAlgorithm::Sha256))
            };
            (a.join().unwrap(), b.join().unwrap())
        })
    };
    let sig1 = first.join().unwrap().unwrap();
    let (sig2, sig3) = others.join().unwrap();
    let (sig2, sig3) = (sig2.unwrap(), sig3.unwrap());
    let signer_cert = signer1();
    for (ix, sig) in [sig1, sig2, sig3].iter().enumerate() {
        verify(sig, format!("foobar{}", ix + 1).as_bytes(), &signer_cert, &sha256_rsa());
    }
    assert_eq!(auth_man.authorizations_requested.load(Ordering::SeqCst), 2);
}

#[test]
fn test_multi_commit_failure() {
    let (_server, auth_man, dummy) = set_up_dummy_client(true);
    // deliberately pass a bogus SAD to make the commit fail
    let auth_man: Arc<dyn CscAuthorizationManager> = Arc::new(PrefetchedSadAuthorizationManager::new(
        auth_man.session_info().clone(),
        auth_man.credential_info().clone(),
        CscAuthorizationInfo::new(""),
    ));
    // every commit is slow (pyHanko: `SlowCommitter`)
    dummy.sign_hash_delays.lock().unwrap().extend([Duration::from_millis(3000); 4]);
    let s = signer(
        auth_man,
        CscSignerOptions {
            batch_autocommit: false,
            batch_size: 1,
            ..Default::default()
        },
    );
    let produce_signature = {
        let s = s.clone();
        thread::spawn(move || {
            let result = {
                let s = s.clone();
                thread::spawn(move || s.sign_raw(b"foobar", DigestAlgorithm::Sha256))
            };
            thread::sleep(Duration::from_millis(1000));
            let msg = signing_msg(s.commit());
            assert!(msg.contains("Signature request failed"), "{msg}");
            let msg = signing_msg(result.join().unwrap());
            assert!(msg.contains("No signing results"), "{msg}");
        })
    };
    let commit_again = {
        let s = s.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(2000));
            let msg = signing_msg(s.commit());
            assert!(msg.contains("Commit failed"), "{msg}");
        })
    };
    produce_signature.join().unwrap();
    commit_again.join().unwrap();
    // this should now return immediately as there is no batch
    s.commit().unwrap();
    assert_eq!(dummy.sign_hash_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn test_csc_with_parameters() {
    // produce a signature with parameters
    let (_server, auth_man, _dummy) = set_up_dummy_client(true);
    let s = signer(
        auth_man,
        CscSignerOptions {
            batch_autocommit: true,
            batch_size: 1,
            prefer_pss: true,
            ..Default::default()
        },
    );
    let result = s.sign_raw(b"foobar", DigestAlgorithm::Sha256).unwrap();
    let mech = s.signature_mechanism_for_digest(DigestAlgorithm::Sha256).unwrap();
    assert_eq!(mech.oid, oids::RSASSA_PSS);
    verify(&result, b"foobar", &signer1(), &mech);
}

#[test]
fn test_prefetched_sad_not_twice() {
    let (_server, auth_man, _dummy) = set_up_dummy_client(false);
    // prefetch SAD that is not bound to any hashes
    let resp: Value = http_client()
        .unwrap()
        .post(auth_man.session_info().endpoint_url("credentials/authorize"))
        .json(&auth_man.format_csc_auth_request(&CscAuthRequest::default()))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    let sad = resp["SAD"].as_str().unwrap();
    let auth_man: Arc<dyn CscAuthorizationManager> = Arc::new(PrefetchedSadAuthorizationManager::new(
        auth_man.session_info().clone(),
        auth_man.credential_info().clone(),
        CscAuthorizationInfo::new(sad),
    ));
    let s = signer(
        auth_man,
        CscSignerOptions {
            batch_autocommit: true,
            batch_size: 1,
            ..Default::default()
        },
    );
    let result = s.sign_raw(b"foobar", DigestAlgorithm::Sha256).unwrap();
    verify(&result, b"foobar", &signer1(), &sha256_rsa());
    // but a second attempt should fail
    let msg = signing_msg(s.sign_raw(b"foobar", DigestAlgorithm::Sha256));
    assert!(msg.contains("No signing results"), "{msg}");
}

// The API docs say that the placeholder will be 512 bytes, so we record
// that in a test here
#[test]
fn test_csc_placeholder_sig_size() {
    let auth_man = prefetched("https://example.com", "foobar", cred_info(&["is_nonsense"], 10), "");
    let s = signer(auth_man, CscSignerOptions::default());
    assert_eq!(s.dry_run_signature(), vec![0u8; 512]);
}

/// Not in pyHanko's `test_csc.py`: sign a PDF through the dummy service and
/// validate it (as `test_live_csc_dummy.py` does against a live service).
#[test]
fn test_csc_sign_pdf_end_to_end() {
    let (_server, auth_man, _dummy) = set_up_dummy_client(true);
    let s = signer(auth_man.clone(), CscSignerOptions::default());
    let t = "2020-11-01T00:00:00+00:00";
    let out = PdfSigner::new(PdfSignatureMetadata::pyhanko_defaults("Sig1"), s)
        .at(at(t))
        .sign_pdf(&pdf("minimal.pdf"))
        .unwrap();
    let sigs = embedded_signatures(&out);
    assert_eq!(sigs[0].field_name, "Sig1");
    val_trusted(&out, 0, &pki("testing-ca"), t, false);
    assert_eq!(auth_man.authorizations_requested.load(Ordering::SeqCst), 1);
}
