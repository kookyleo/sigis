//! Supplemental immutable assertion-state API controls; no upstream IDs.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{load_cert, load_nist_cert, moment, read};
use sigis_pki_certvalidator::policy::ValidationTimingParams;
use sigis_pki_certvalidator::{
    find_valid_path, Cert, NonRevokedStatusAssertion, ValidationContext,
};
use sigis_pki_core::fetch::{CertificateFetcher, Fetchers};
use sigis_pki_core::time::Moment;

fn at() -> Moment {
    moment("2022-05-01T00:00:00Z")
}

fn assertion(cert: &Cert, cutoff: Moment) -> NonRevokedStatusAssertion {
    NonRevokedStatusAssertion {
        cert_sha256: cert.sha256(),
        at: cutoff,
    }
}

fn ordered_assertions() -> Vec<NonRevokedStatusAssertion> {
    let leaf = load_nist_cert("ValidCertificatePathTest1EE.crt");
    let ca = load_nist_cert("GoodCACert.crt");
    let later = assertion(&leaf, at().plus(Duration::from_secs(60)));
    vec![later.clone(), assertion(&ca, at()), later]
}

fn with_assertions(values: &[NonRevokedStatusAssertion]) -> ValidationContext {
    let mut builder = ValidationContext::builder()
        .moment(at())
        .time_tolerance(Duration::from_secs(7))
        .revocation_mode("require");
    for value in values {
        builder = builder.assertion(value.clone());
    }
    builder.build().expect("assertion context")
}

#[test]
fn default_assertion_view_is_empty() {
    let context = ValidationContext::builder().moment(at()).build().unwrap();
    assert!(context.non_revoked_status_assertions().is_empty());
}

#[test]
fn assertion_view_borrows_exact_builder_order_digests_times_and_duplicates() {
    let expected = ordered_assertions();
    let context = with_assertions(&expected);
    let getter: for<'a> fn(&'a ValidationContext) -> &'a [NonRevokedStatusAssertion] =
        ValidationContext::non_revoked_status_assertions;
    let borrowed: &[NonRevokedStatusAssertion] = getter(&context);
    assert_eq!(borrowed, expected.as_slice());
    assert_eq!(
        borrowed[0].cert_sha256,
        load_nist_cert("ValidCertificatePathTest1EE.crt").sha256()
    );
    assert_eq!(borrowed[1].at, at());
    assert_eq!(
        borrowed[0], borrowed[2],
        "builder duplicates remain explicit state"
    );
    assert!(
        std::ptr::eq(borrowed, getter(&context)),
        "reads return a shared borrowed view"
    );
}

#[test]
fn context_copy_operations_preserve_assertions_without_retiming_them() {
    let expected = ordered_assertions();
    let context = with_assertions(&expected);
    let changed_timing = ValidationTimingParams {
        validation_time: at().minus(Duration::from_secs(120)),
        best_signature_time: at().minus(Duration::from_secs(180)),
        ..*context.timing()
    };
    let timed = context.with_timing(changed_timing);
    let fetcher: Arc<dyn CertificateFetcher> = Arc::new(common::fakes::Failing::default());
    let fetched = context.with_fetchers(Fetchers {
        cert: Some(fetcher.clone()),
        ..Fetchers::none()
    });
    let interm = load_cert(&["ades", "time-slide", "certs", "interm.crt"]);
    let crl = read(&["ades", "time-slide", "root-2020-11-29.crl"]);
    let ocsp = read(&["ades", "time-slide", "alice-2020-11-29.ors"]);
    let extended = context
        .with_revinfo([&interm], [crl.as_slice()], [ocsp.as_slice()])
        .expect("actual parsed evidence extension");
    assert_eq!(timed.timing(), &changed_timing);
    assert!(Arc::ptr_eq(
        fetched.fetchers().cert.as_ref().unwrap(),
        &fetcher
    ));
    assert_eq!(extended.other_certs(), &[interm]);
    assert_eq!(extended.crls().collect::<Vec<_>>(), vec![crl.as_slice()]);
    assert_eq!(extended.ocsps().collect::<Vec<_>>(), vec![ocsp.as_slice()]);
    for copied in [context.clone(), timed, fetched, extended] {
        assert_eq!(copied.non_revoked_status_assertions(), expected.as_slice());
        assert_eq!(copied.revinfo_policy(), context.revinfo_policy());
    }
    assert_eq!(context.timing().validation_time, at());
    assert!(context.fetchers().cert.is_none());
    assert_eq!(context.crls().count(), 0);
    assert_eq!(context.ocsps().count(), 0);
    assert_eq!(context.non_revoked_status_assertions(), expected.as_slice());
}

fn required_path_context(value: NonRevokedStatusAssertion) -> ValidationContext {
    let ca = load_nist_cert("GoodCACert.crt");
    ValidationContext::builder()
        .trust_root(load_nist_cert("TrustAnchorRootCertificate.crt"))
        .other_cert(ca.clone())
        .moment(at())
        .best_signature_time(at().minus(Duration::from_secs(3600)))
        .time_tolerance(Duration::from_secs(7))
        .revocation_mode("require")
        .assertion(assertion(&ca, at()))
        .assertion(value)
        .build()
        .expect("mandatory path assertion context")
}

#[test]
fn actual_revocation_uses_exact_target_digest_and_inclusive_validation_time() {
    let leaf = load_nist_cert("ValidCertificatePathTest1EE.crt");
    let exact = assertion(&leaf, at());
    let mut wrong_digest = exact.clone();
    wrong_digest.cert_sha256[0] ^= 1;
    for (value, accepted) in [
        (exact, true),
        (assertion(&leaf, at().plus(Duration::from_secs(1))), true),
        // Earlier than validation_time still rejects despite clock tolerance
        // and an older best_signature_time. Getter exposure cannot relax this.
        (assertion(&leaf, at().minus(Duration::from_secs(1))), false),
        (wrong_digest, false),
    ] {
        let context = required_path_context(value.clone());
        assert_eq!(context.non_revoked_status_assertions().last(), Some(&value));
        let result = find_valid_path(&context, &leaf, None);
        assert_eq!(result.is_ok(), accepted, "assertion {value:?}: {result:?}");
        if let Err(failure) = result {
            assert_eq!(failure.error.class_name(), "InsufficientRevinfoError");
        }
    }
}

#[test]
fn successful_default_soft_fail_validation_does_not_create_explicit_assertions() {
    let context = ValidationContext::builder()
        .trust_root(load_nist_cert("TrustAnchorRootCertificate.crt"))
        .other_cert(load_nist_cert("GoodCACert.crt"))
        .moment(at())
        .build()
        .unwrap();
    let leaf = load_nist_cert("ValidCertificatePathTest1EE.crt");
    assert!(context.non_revoked_status_assertions().is_empty());
    find_valid_path(&context, &leaf, None).expect("existing default soft-fail behavior");
    assert!(context.non_revoked_status_assertions().is_empty());
}

#[test]
fn explicit_assertions_never_supply_a_missing_trust_anchor() {
    let leaf = load_nist_cert("ValidCertificatePathTest1EE.crt");
    let ca = load_nist_cert("GoodCACert.crt");
    let context = ValidationContext::builder()
        .other_cert(ca.clone())
        .moment(at())
        .revocation_mode("require")
        .assertion(assertion(&ca, at()))
        .assertion(assertion(&leaf, at()))
        .build()
        .unwrap();
    assert_eq!(context.non_revoked_status_assertions().len(), 2);
    let failure = find_valid_path(&context, &leaf, None).expect_err("no trusted root");
    assert_eq!(failure.error.class_name(), "PathBuildingError");
}
