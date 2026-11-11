// Ported from pyHanko 0.38.1 `pkgs/pyhanko/tests/test_tsa_fetcher.py`
// (MIT, see LICENSE-pyHanko).
//
// The local "TSA" serves a response pyHanko's test TSA produced for a fixed
// request (`oracle/gen_tsa_fixtures.py`); the client sends that request's
// nonce. Signing a PDF with the token is lane D; the validation of the
// signed PDFs is replayed from the recorded pyHanko calls.

#[path = "../../cms/tests/common/mod.rs"]
mod cms_replay;
mod common;
mod tsa_common;

use common::read_lane;
use sigis_pki_fetch::tsa::handle_tsp_response;
use sigis_pki_fetch::HttpTimeStamper;

#[test]
fn test_ts_fetch_supplied_session_error() {
    // A caller-supplied HTTP session is a transport here.
    tsa_common::ts_fetch_error();
}

#[test]
fn test_ts_fetch_error() {
    tsa_common::ts_fetch_error();
}

#[test]
fn test_auth_coercion() {
    // (None, None), ('user', 'pass') and BasicAuth('user', 'pass').
    let ts = HttpTimeStamper::new("http://example.invalid");
    assert_eq!(ts.authorization(), None);
    let ts = ts.with_basic_auth("user", "pass");
    assert_eq!(ts.authorization().as_deref(), Some("Basic dXNlcjpwYXNz"));
    assert!(ts
        .request_headers()
        .iter()
        .any(|(k, v)| k == "Authorization" && v == "Basic dXNlcjpwYXNz"));
}

#[test]
fn test_handle_error_response() {
    for (file, status_string, fail_info) in [
        ("error-1.der", "clock is down", "time_not_available"),
        ("error-2.der", "clock is down", ""),
        ("error-3.der", "", "time_not_available"),
    ] {
        let e =
            handle_tsp_response(&read_lane(&["tsa", file]), Some(b"0000")).expect_err("refused");
        let expected = format!("statusString \"{status_string}\", failInfo \"{fail_info}\"");
        assert!(e.0.contains("refused") && e.0.contains(&expected), "{e}");
    }
}

#[test]
fn test_handle_bad_nonce() {
    let e = handle_tsp_response(
        &read_lane(&["tsa", "granted-fixed-nonce.der"]),
        Some(b"0000"),
    )
    .expect_err("bad nonce");
    assert!(e.0.contains("bad nonce"), "{e}");
    // With the right nonce, the token is returned.
    assert!(handle_tsp_response(
        &read_lane(&["tsa", "granted-fixed-nonce.der"]),
        Some(&tsa_common::FIXED_NONCE)
    )
    .is_ok());
}

fn timestamp_trusted(test: &str) {
    let results = cms_replay::check("test_tsa_fetcher", test, &[]);
    let statuses: Vec<_> = results
        .iter()
        .filter_map(|r| match r {
            cms_replay::Replayed::Standard(s) => Some(s),
            _ => None,
        })
        .collect();
    assert_eq!(statuses.len(), 1);
    let ts = statuses[0].timestamp_validity.as_ref().expect("timestamp");
    assert!(ts.trusted());
    assert!(statuses[0].signature.trusted());
}

#[test]
fn test_dummy_timestamp() {
    timestamp_trusted("test_dummy_timestamp");
}

#[test]
fn test_http_timestamp_bad_content_type() {
    tsa_common::http_timestamp_bad_content_type();
}

#[test]
fn test_http_timestamp() {
    tsa_common::http_timestamp_round_trip();
    timestamp_trusted("test_http_timestamp");
}
