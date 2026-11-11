// Ported from pyHanko 0.38.1 `pkgs/pyhanko/tests/test_tsa_fetcher_requests.py`
// (MIT, see LICENSE-pyHanko). The `requests`-based client and the aiohttp
// one are the same client in this port.

#[path = "../../cms/tests/common/mod.rs"]
mod cms_replay;
mod common;
mod tsa_common;

#[test]
fn test_ts_fetch_supplied_session_error_requests() {
    tsa_common::ts_fetch_error();
}

#[test]
fn test_ts_fetch_error_requests() {
    tsa_common::ts_fetch_error();
}

#[test]
fn test_http_timestamp_bad_content_type_requests() {
    tsa_common::http_timestamp_bad_content_type();
}

#[test]
fn test_http_timestamp_requests() {
    tsa_common::http_timestamp_round_trip();
    let results = cms_replay::check(
        "test_tsa_fetcher_requests",
        "test_http_timestamp_requests",
        &[],
    );
    let s = results
        .iter()
        .find_map(|r| match r {
            cms_replay::Replayed::Standard(s) => Some(s),
            _ => None,
        })
        .expect("status");
    assert!(s.timestamp_validity.as_ref().expect("timestamp").trusted());
}
