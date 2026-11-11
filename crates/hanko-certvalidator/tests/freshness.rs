// Port of pyhanko-certvalidator `tests/test_freshness.py` (MIT, see LICENSE-pyHanko).

mod common;

use std::time::Duration;

use common::{load_cert, moment, read};
use hanko_certvalidator::{
    build_paths, validate_path, CertRevTrustPolicy, FreshnessReqType, ValidationContext,
    REQUIRE_REVINFO,
};
use hanko_core::errors::ValidationError;

const DAY: u64 = 86_400;

fn policy(freshness: Duration, req: FreshnessReqType) -> CertRevTrustPolicy {
    CertRevTrustPolicy {
        freshness: Some(freshness),
        freshness_req_type: req,
        ..CertRevTrustPolicy::new(REQUIRE_REVINFO)
    }
}

fn run(
    policy: CertRevTrustPolicy,
    ocsps: &[&str],
    crl: &str,
    at: &str,
    signature_time: Option<&str>,
) -> Result<(), ValidationError> {
    let mut builder = ValidationContext::builder()
        .trust_root(load_cert(&["freshness", "certs", "root.crt"]))
        .other_cert(load_cert(&["freshness", "certs", "interm.crt"]))
        .crl(read(&["freshness", crl]))
        .revinfo_policy(policy)
        .moment(moment(at));
    for ocsp in ocsps {
        builder = builder.ocsp_response(read(&["freshness", ocsp]));
    }
    if let Some(t) = signature_time {
        builder = builder.best_signature_time(moment(t));
    }
    let ctx = builder.build()?;
    let alice = load_cert(&["freshness", "certs", "alice.crt"]);
    let paths = build_paths(&ctx, &alice)?;
    assert_eq!(paths.len(), 1);
    validate_path(&ctx, &paths[0], None)
}

fn assert_crl_not_recent_enough(result: Result<(), ValidationError>) {
    let err = result.expect_err("stale CRL");
    assert!(err.is_path_validation_error(), "{err:?}");
    let re = regex::Regex::new("CRL.*recent enough").expect("regex");
    assert!(re.is_match(&err.to_string()), "{err}");
}

#[test]
fn test_cooldown_period_ok() {
    run(
        policy(
            Duration::from_secs(3 * DAY),
            FreshnessReqType::TimeAfterSignature,
        ),
        &["alice-2020-10-01.ors"],
        "root-2020-10-01.crl",
        "2020-10-01T00:00:00Z",
        Some("2020-09-18T00:00:00Z"),
    )
    .expect("valid");
}

#[test]
fn test_cooldown_period_too_early() {
    assert_crl_not_recent_enough(run(
        policy(
            Duration::from_secs(3 * DAY),
            FreshnessReqType::TimeAfterSignature,
        ),
        &["alice-2020-10-01.ors"],
        "root-2020-10-01.crl",
        "2020-10-01T00:00:00Z",
        Some("2020-09-30T00:00:00Z"),
    ));
}

#[test]
fn test_use_delta_ok() {
    run(
        policy(
            Duration::from_secs(9 * DAY),
            FreshnessReqType::MaxDiffRevocationValidation,
        ),
        &["alice-2020-10-01.ors"],
        "root-2020-10-01.crl",
        "2020-10-01T00:00:00Z",
        None,
    )
    .expect("valid");
}

#[test]
fn test_use_delta_stale() {
    assert_crl_not_recent_enough(run(
        policy(
            Duration::from_secs(3600),
            FreshnessReqType::MaxDiffRevocationValidation,
        ),
        &["alice-2020-10-01.ors"],
        "root-2020-10-01.crl",
        "2020-10-01T00:00:00Z",
        None,
    ));
}

#[test]
fn test_use_most_recent() {
    let lenient = policy(
        Duration::from_secs(20 * DAY),
        FreshnessReqType::MaxDiffRevocationValidation,
    );
    let err = run(
        lenient,
        &["alice-2020-11-29.ors", "alice-2020-12-10.ors"],
        "root-2020-12-10.crl",
        "2020-12-10T00:00:00Z",
        None,
    )
    .expect_err("revoked");
    assert!(matches!(err, ValidationError::Revoked { .. }), "{err:?}");

    // With only the older response, the lenient delta lets validation pass.
    run(
        lenient,
        &["alice-2020-11-29.ors"],
        "root-2020-12-10.crl",
        "2020-12-10T00:00:00Z",
        None,
    )
    .expect("valid");
}

#[test]
fn test_discard_post_validation_time() {
    run(
        policy(
            Duration::from_secs(20 * DAY),
            FreshnessReqType::MaxDiffRevocationValidation,
        ),
        &["alice-2020-11-29.ors", "alice-2020-12-10.ors"],
        "root-2020-11-29.crl",
        "2020-11-29T00:00:00Z",
        None,
    )
    .expect("valid");
}
