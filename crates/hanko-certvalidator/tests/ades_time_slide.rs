// Port of pyhanko-certvalidator `tests/test_ades_time_slide.py`
// (MIT, see LICENSE-pyHanko).
//
// pyHanko's `RevinfoManager` (certificate registry, POE manager, CRLs, OCSP
// responses) maps to a `ValidationContext` plus a `PoeManager`. Frozen
// times become explicit moments.

mod common;

use std::time::Duration;

use common::{load_cert, moment, read};
use hanko_certvalidator::ltv::poe::{digest_for_poe, PoeManager, PoeType};
use hanko_certvalidator::ltv::{past_validate_with, time_slide_with, LtvError, TimeSlideOptions};
use hanko_certvalidator::{
    CertRevTrustPolicy, FreshnessReqType, RevocationCheckingPolicy, RevocationCheckingRule,
    TrustAnchor, ValidationContext, ValidationPath,
};
use hanko_core::time::Moment;

const DIR: [&str; 2] = ["ades", "time-slide"];

fn cert(name: &str) -> hanko_certvalidator::Cert {
    load_cert(&[DIR[0], DIR[1], "certs", name])
}

fn data(name: &str) -> Vec<u8> {
    read(&[DIR[0], DIR[1], name])
}

fn test_path(revoked_intermediate: bool) -> ValidationPath {
    let interm = if revoked_intermediate {
        "interm-revoked.crt"
    } else {
        "interm.crt"
    };
    ValidationPath::new(
        TrustAnchor::new(cert("root.crt")),
        vec![cert(interm)],
        Some(cert("alice.crt")),
    )
}

fn default_policy() -> CertRevTrustPolicy {
    CertRevTrustPolicy::new(RevocationCheckingPolicy {
        ee_certificate_rule: RevocationCheckingRule::CrlOrOcspRequired,
        intermediate_ca_cert_rule: RevocationCheckingRule::CrlOrOcspRequired,
    })
}

fn very_lenient_freshness() -> CertRevTrustPolicy {
    let mut p = default_policy();
    p.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    p.freshness = Some(Duration::from_secs(100 * 86400));
    p
}

/// `RevinfoManager(certificate_registry=load_cert_registry(...), crls, ocsps)`.
fn context(
    revoked_intermediate: bool,
    crls: &[&str],
    ocsps: &[&str],
    policy: CertRevTrustPolicy,
    now: Moment,
) -> ValidationContext {
    let interm = if revoked_intermediate {
        "interm-revoked.crt"
    } else {
        "interm.crt"
    };
    let mut b = ValidationContext::builder()
        .trust_root(cert("root.crt"))
        .other_cert(cert(interm))
        .other_cert(cert("interm-ocsp.crt"))
        .other_cert(cert("alice.crt"))
        .revinfo_policy(policy)
        .time_tolerance(Duration::from_secs(600))
        .moment(now);
    for c in crls {
        b = b.crl(data(c));
    }
    for o in ocsps {
        b = b.ocsp_response(data(o));
    }
    b.build().expect("context")
}

/// `algo_usage_policy=None`.
fn no_algo() -> TimeSlideOptions {
    TimeSlideOptions {
        apply_algorithm_policy: false,
    }
}

#[test]
fn test_time_slide_not_revoked() {
    let now = moment("2020-11-29T00:05:00Z");
    let ctx = context(
        false,
        &["root-2020-11-29.crl"],
        &["alice-2020-11-29.ors"],
        default_policy(),
        now,
    );
    let poe = PoeManager::with_current_time(now);
    let t = time_slide_with(&test_path(false), now, &ctx, &poe, no_algo()).expect("slide");
    assert_eq!(t, now);
}

#[test]
fn test_time_slide_revocation_ocsp() {
    let now = moment("2020-12-10T00:05:00Z");
    let ctx = context(
        false,
        &["root-2020-12-10.crl"],
        &["alice-2020-12-10.ors"],
        default_policy(),
        now,
    );
    let poe = PoeManager::with_current_time(now);
    let t = time_slide_with(&test_path(false), now, &ctx, &poe, no_algo()).expect("slide");
    assert_eq!(t, moment("2020-12-01T00:00:00Z"));
}

#[test]
fn test_time_slide_revocation_crl() {
    let now = moment("2020-12-10T00:05:00Z");
    let ctx = context(
        false,
        &["root-2020-12-10.crl", "interm-2020-12-10.crl"],
        &[],
        default_policy(),
        now,
    );
    let poe = PoeManager::with_current_time(now);
    let t = time_slide_with(&test_path(false), now, &ctx, &poe, no_algo()).expect("slide");
    assert_eq!(t, moment("2020-12-01T00:00:00Z"));
}

fn poe_date() -> Moment {
    moment("2020-11-30T00:00:00Z")
}

#[test]
fn test_time_slide_revoked_intermediate() {
    let now = moment("2020-12-10T00:05:00Z");
    let path = test_path(true);
    let mut poe = PoeManager::with_current_time(now);
    poe.register(
        path.leaf().expect("leaf").der(),
        poe_date(),
        PoeType::Provided,
    );
    poe.register(
        &data("interm-2020-11-29.crl"),
        poe_date(),
        PoeType::Provided,
    );
    let ctx = context(
        true,
        &["root-2020-12-10.crl", "interm-2020-11-29.crl"],
        &[],
        very_lenient_freshness(),
        now,
    );
    let t = time_slide_with(&path, now, &ctx, &poe, no_algo()).expect("slide");
    assert_eq!(t, moment("2020-12-01T00:00:00Z"));
}

#[test]
fn test_time_slide_revoked_intermediate_enforce_cert_poe() {
    let now = moment("2020-12-10T00:05:00Z");
    let path = test_path(true);
    let mut poe = PoeManager::with_current_time(now);
    poe.register(
        &data("interm-2020-11-29.crl"),
        poe_date(),
        PoeType::Provided,
    );
    let ctx = context(
        true,
        &["root-2020-12-10.crl", "interm-2020-11-29.crl"],
        &[],
        very_lenient_freshness(),
        now,
    );
    let e = time_slide_with(&path, now, &ctx, &poe, no_algo()).expect_err("no POE");
    assert_eq!(e.class_name(), "InsufficientPOEError", "{e}");
    let msg = e.to_string();
    assert!(
        msg.find("for").is_some_and(|i| msg[i..].contains("Alice")),
        "{msg}"
    );
}

#[test]
fn test_time_slide_revoked_intermediate_enforce_revinfo_poe() {
    let now = moment("2020-12-10T00:05:00Z");
    let path = test_path(true);
    let mut poe = PoeManager::with_current_time(now);
    poe.register(
        path.leaf().expect("leaf").der(),
        poe_date(),
        PoeType::Provided,
    );
    let ctx = context(
        true,
        &["root-2020-12-10.crl", "interm-2020-11-29.crl"],
        &[],
        very_lenient_freshness(),
        now,
    );
    let e = time_slide_with(&path, now, &ctx, &poe, no_algo()).expect_err("no revinfo");
    assert!(
        matches!(&e, LtvError::Validation(v) if v.is_instance_of("InsufficientRevinfoError")),
        "{e:?}"
    );
    let msg = e.to_string();
    assert!(
        msg.find("for").is_some_and(|i| msg[i..].contains("Alice")),
        "{msg}"
    );
}

/// `VALIDATION_POLICY_SPEC`: the root as trust anchor, the default policy.
fn spec_context(revoked: bool, crls: &[&str], ocsps: &[&str], now: Moment) -> ValidationContext {
    context(revoked, crls, ocsps, default_policy(), now)
}

#[test]
fn test_point_in_time_validation_not_revoked() {
    let now = moment("2020-11-29T00:05:00Z");
    let ctx = spec_context(
        false,
        &["root-2020-11-29.crl"],
        &["alice-2020-11-29.ors"],
        now,
    );
    let poe = PoeManager::with_current_time(now);
    let t = past_validate_with(&ctx, &test_path(false), &poe, now, None).expect("past");
    assert_eq!(t, now);
}

#[test]
fn test_point_in_time_validation_revoked_intermediate() {
    let now = moment("2020-12-10T00:05:00Z");
    let path = test_path(true);
    let mut poe = PoeManager::with_current_time(now);
    poe.register(
        path.leaf().expect("leaf").der(),
        poe_date(),
        PoeType::Provided,
    );
    poe.register(
        &data("interm-2020-11-29.crl"),
        poe_date(),
        PoeType::Provided,
    );
    let ctx = spec_context(
        true,
        &["root-2020-12-10.crl", "interm-2020-11-29.crl"],
        &[],
        now,
    );
    let t = past_validate_with(&ctx, &path, &poe, now, None).expect("past");
    assert_eq!(t, moment("2020-12-01T00:00:00Z"));
}

#[test]
fn test_point_in_time_validation_revinfo_insufficient_poe() {
    let now = moment("2020-12-10T00:05:00Z");
    let poe = PoeManager::with_current_time(now);
    let ctx = spec_context(true, &["root-2020-12-10.crl"], &[], now);
    let e = past_validate_with(&ctx, &test_path(true), &poe, now, None).expect_err("fail");
    assert_eq!(e.class_name(), "TimeSlideFailure", "{e:?}");
}

#[test]
fn test_poe_manager_read_cert() {
    let c = cert("root.crt");
    let mut m = PoeManager::new();
    m.register(c.der(), moment("2020-11-11T00:00:00Z"), PoeType::Provided);
    assert_eq!(m.poe_time(c.der()), moment("2020-11-11T00:00:00Z"));
}

#[test]
fn test_poe_manager_cert_by_digest() {
    let c = cert("root.crt");
    let mut m = PoeManager::new();
    m.register_by_digest(
        digest_for_poe(c.der()),
        moment("2020-11-11T00:00:00Z"),
        PoeType::Provided,
    );
    assert_eq!(m.poe_time(c.der()), moment("2020-11-11T00:00:00Z"));
}

#[test]
fn test_poe_manager_read_bytes() {
    let mut m = PoeManager::new();
    m.register(
        b"deadbeef",
        moment("2020-11-11T00:00:00Z"),
        PoeType::Provided,
    );
    assert_eq!(m.poe_time(b"deadbeef"), moment("2020-11-11T00:00:00Z"));
}

#[test]
fn test_poe_manager_read_bytes_by_digest() {
    let mut m = PoeManager::new();
    m.register_by_digest(
        digest_for_poe(b"deadbeef"),
        moment("2020-11-11T00:00:00Z"),
        PoeType::Provided,
    );
    assert_eq!(m.poe_time(b"deadbeef"), moment("2020-11-11T00:00:00Z"));
}
