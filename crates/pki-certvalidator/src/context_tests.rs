//! Regression assertions for context-preserving historical validation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::authority::TrustQualifiers;
use crate::policy::{FreshnessReqType, REQUIRE_REVINFO};
use crate::revinfo::freshness::{RevinfoUsability, RevinfoUsabilityRating};
use sigis_pki_core::errors::FetchError;
use sigis_pki_core::fetch::{CertificateFetcher, CrlFetcher, OcspFetcher};
use x509_cert::ext::pkix::name::GeneralName;

#[derive(Debug)]
struct MarkerFetcher;

impl CertificateFetcher for MarkerFetcher {
    fn fetch_issuers(&self, _cert: &Cert) -> Result<Vec<Cert>, FetchError> {
        Ok(Vec::new())
    }
}

impl CrlFetcher for MarkerFetcher {
    fn fetch_crls(&self, _cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        Ok(Vec::new())
    }
}

impl OcspFetcher for MarkerFetcher {
    fn fetch_ocsp(&self, _cert: &Cert, _issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        Ok(Vec::new())
    }
}

fn marker_fetchers() -> Fetchers {
    let marker = Arc::new(MarkerFetcher);
    Fetchers {
        cert: Some(marker.clone()),
        crl: Some(marker.clone()),
        ocsp: Some(marker),
    }
}

fn moment(value: &str) -> Moment {
    Moment::parse_rfc3339(value).unwrap()
}

#[derive(Debug)]
struct RejectFreshness;

impl FreshnessJudge for RejectFreshness {
    fn judge(
        &self,
        _this_update: Option<Moment>,
        _next_update: Option<Moment>,
        _policy: &CertRevTrustPolicy,
        timing: &ValidationTimingParams,
    ) -> RevinfoUsability {
        RevinfoUsability {
            rating: RevinfoUsabilityRating::Stale,
            last_usable_at: None,
            compared_to: Some(timing.validation_time),
        }
    }
}

#[derive(Debug)]
struct OneAnchor(Cert);

impl TrustManager for OneAnchor {
    fn as_trust_anchor(&self, cert: &Cert) -> Option<TrustAnchor> {
        (cert == &self.0).then(|| TrustAnchor::new(self.0.clone()))
    }

    fn find_potential_issuers(&self, _cert: &Cert) -> Vec<TrustAnchor> {
        vec![TrustAnchor::new(self.0.clone())]
    }
}

fn original_context() -> ValidationContext {
    let read = |parts: &[&str]| std::fs::read(sigis_testdata::certvalidator(parts)).unwrap();
    let certificate = |label: &str| {
        Cert::from_pem_or_der(&read(&["ades", "time-slide", "certs", label])).unwrap()
    };
    let root = certificate("root.crt");
    let intermediate = certificate("interm.crt");
    ValidationContext::builder()
        .trust_anchor(TrustAnchor::with_qualifiers(
            root,
            TrustQualifiers {
                max_path_length: Some(0),
                max_aa_path_length: Some(0),
                valid_until: Some(moment("2020-11-02T00:00:00Z")),
                ..TrustQualifiers::default()
            },
        ))
        .other_cert(intermediate.clone())
        .crl(read(&["ades", "time-slide", "root-2020-11-29.crl"]))
        .ocsp_response(read(&["ades", "time-slide", "alice-2020-11-29.ors"]))
        .moment(moment("2020-11-01T00:00:00Z"))
        .best_signature_time(moment("2020-10-01T00:00:00Z"))
        .time_tolerance(Duration::from_secs(123))
        .revinfo_policy(CertRevTrustPolicy {
            freshness: Some(Duration::from_secs(42)),
            freshness_req_type: FreshnessReqType::MaxDiffRevocationValidation,
            expected_post_expiry_revinfo_time: Some(Duration::from_secs(77)),
            retroactive_revinfo: true,
            ..CertRevTrustPolicy::new(REQUIRE_REVINFO)
        })
        .algorithm_policy(Arc::new(DisallowWeakAlgorithmsPolicy {
            rsa_key_size_threshold: 4096,
            ..DisallowWeakAlgorithmsPolicy::default()
        }))
        .freshness_judge(Arc::new(RejectFreshness))
        .assertion(NonRevokedStatusAssertion {
            cert_sha256: intermediate.sha256(),
            at: moment("2020-10-31T00:00:00Z"),
        })
        .trust_manager(Arc::new(OneAnchor(intermediate)))
        .acceptable_ac_targets(crate::ac::AcTargetDescription {
            validator_names: vec![GeneralName::DnsName(
                der::asn1::Ia5String::new("validator.example").unwrap(),
            )],
            group_memberships: vec![GeneralName::DnsName(
                der::asn1::Ia5String::new("restricted.example").unwrap(),
            )],
        })
        .fetchers(marker_fetchers())
        .build()
        .unwrap()
}

fn assert_security_configuration_preserved(a: &ValidationContext, b: &ValidationContext) {
    assert_eq!(a.trust_anchors.len(), 1);
    assert_eq!(a.trust_anchors, b.trust_anchors);
    assert_eq!(a.other_certs, b.other_certs);
    assert!(!a.crls.is_empty());
    assert!(!a.ocsps.is_empty());
    assert_eq!(a.crls().collect::<Vec<_>>(), b.crls().collect::<Vec<_>>());
    assert_eq!(a.ocsps().collect::<Vec<_>>(), b.ocsps().collect::<Vec<_>>());
    assert_eq!(a.revinfo_policy, b.revinfo_policy);
    assert!(Arc::ptr_eq(&a.algorithm_policy, &b.algorithm_policy));
    assert_eq!(b.algorithm_policy.min_rsa_key_size(), 4096);
    assert!(Arc::ptr_eq(&a.freshness_judge, &b.freshness_judge));
    assert_eq!(
        b.freshness_judge
            .judge(None, None, &b.revinfo_policy, &b.timing)
            .rating,
        RevinfoUsabilityRating::Stale,
    );
    assert_eq!(a.assertions.len(), 1);
    assert_eq!(a.assertions, b.assertions);
    let a_targets = a.acceptable_ac_targets.as_ref().unwrap();
    let b_targets = b.acceptable_ac_targets.as_ref().unwrap();
    assert_eq!(a_targets, b_targets);
    assert!(Arc::ptr_eq(
        a.trust_manager.as_ref().unwrap(),
        b.trust_manager.as_ref().unwrap(),
    ));
    assert!(b.is_trust_anchor(&a.other_certs[0]));
}

fn assert_timing_equal(a: &ValidationTimingParams, b: &ValidationTimingParams) {
    assert_eq!(a.validation_time, b.validation_time);
    assert_eq!(a.best_signature_time, b.best_signature_time);
    assert_eq!(a.point_in_time_validation, b.point_in_time_validation);
    assert_eq!(a.time_tolerance, b.time_tolerance);
}

#[test]
fn historical_timing_preserves_validation_requirements() {
    let original = original_context();
    let timing = ValidationTimingParams {
        validation_time: moment("2021-01-01T00:00:00Z"),
        best_signature_time: moment("2020-12-01T00:00:00Z"),
        point_in_time_validation: false,
        time_tolerance: Duration::from_secs(7),
    };
    let historical = original.with_timing(timing);
    assert_timing_equal(&historical.timing, &timing);
    assert_security_configuration_preserved(&original, &historical);
    assert!(Arc::ptr_eq(
        original.fetchers.cert.as_ref().unwrap(),
        historical.fetchers.cert.as_ref().unwrap(),
    ));
    assert!(Arc::ptr_eq(
        original.fetchers.crl.as_ref().unwrap(),
        historical.fetchers.crl.as_ref().unwrap(),
    ));
    assert!(Arc::ptr_eq(
        original.fetchers.ocsp.as_ref().unwrap(),
        historical.fetchers.ocsp.as_ref().unwrap(),
    ));
    assert_eq!(original.moment(), moment("2020-11-01T00:00:00Z"));
}

#[test]
fn replacement_fetchers_preserve_validation_requirements() {
    let original = original_context();
    let replacement = marker_fetchers();
    let changed = original.with_fetchers(replacement.clone());
    assert_security_configuration_preserved(&original, &changed);
    assert_timing_equal(&original.timing, &changed.timing);
    assert!(Arc::ptr_eq(
        replacement.cert.as_ref().unwrap(),
        changed.fetchers.cert.as_ref().unwrap(),
    ));
    assert!(Arc::ptr_eq(
        replacement.crl.as_ref().unwrap(),
        changed.fetchers.crl.as_ref().unwrap(),
    ));
    assert!(Arc::ptr_eq(
        replacement.ocsp.as_ref().unwrap(),
        changed.fetchers.ocsp.as_ref().unwrap(),
    ));
    assert!(!Arc::ptr_eq(
        original.fetchers.cert.as_ref().unwrap(),
        changed.fetchers.cert.as_ref().unwrap(),
    ));
    assert!(original.with_fetchers(Fetchers::none()).fetchers.is_empty());
    assert!(!original.fetchers.is_empty());
}
