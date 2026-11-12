//! Exact unsupported content-timestamp digest rejection from pyHanko 0.38.1.
mod common;
use common::*;
use sigis_pades::ades::basic::{basic_validation, QualificationSpec};
#[test]
fn test_content_ts_with_different_digest_not_supported() {
    let rec = Recording::load("test_ades_validation");
    let calls = rec.calls(
        "test_ades_validation",
        "test_content_ts_with_different_digest_not_supported",
    );
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.0["exception"]["type"], "TSTDigestNotAvailableError");
    let error = basic_validation(
        &call.content_info(),
        None,
        &default_context(&rec, call),
        &QualificationSpec::default(),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("TSTDigestNotAvailableError"),
        "content timestamp with unavailable digest must reject explicitly: {error}"
    );
}
