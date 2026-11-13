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
    let read = |parts: &[&str]| {
        let path = sigis_testdata::certvalidator(parts).canonicalize().unwrap();
        let data = std::fs::read(&path).unwrap();
        let hash: String = sigis_pki_core::algorithms::DigestAlgorithm::Sha256
            .digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        eprintln!(
            "BACKEND_CONTEXT_INPUT {}",
            serde_json::json!({"path":path,"length":data.len(),"sha256":hash})
        );
        data
    };
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
    assert_eq!(a.other_certs, b.other_certs);
    assert_security_requirements_preserved(a, b);
}

// Registration deliberately changes candidates; every other caller requirement
// must survive through the same assertions used by historical context clones.
fn assert_security_requirements_preserved(a: &ValidationContext, b: &ValidationContext) {
    assert_eq!(a.trust_anchors.len(), 1);
    assert_eq!(a.trust_anchors, b.trust_anchors);
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

fn registered_fixture(arch: &str, label: &str, expected_sha256: &str) -> Cert {
    let path = sigis_testdata::path(&["lanes", "d", "pki", arch, &format!("{label}.crt")]);
    let der = std::fs::read(&path).unwrap();
    let actual: String = sigis_pki_core::algorithms::DigestAlgorithm::Sha256
        .digest(&der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(actual, expected_sha256, "{}", path.display());
    eprintln!(
        "REGISTERED_CONTEXT_INPUT path={} sha256={actual} length={}",
        path.display(),
        der.len()
    );
    Cert::from_der(&der).unwrap()
}

fn registered_collision_pair() -> (Cert, Cert) {
    let rsa = registered_fixture(
        "testing-ca",
        "interm",
        "0e8fa78719fdd97ac8f9a531fa32929462d65306b9c58a63881ef21ca1a9509f",
    );
    let ecc = registered_fixture(
        "testing-ca-ecdsa",
        "interm",
        "563435c97dca8ee1ba43f084d9330e66f0dee1b83bac98d03ff181b37ea00b5e",
    );
    assert_eq!(rsa.issuer(), ecc.issuer());
    assert_eq!(rsa.serial_bytes(), ecc.serial_bytes());
    assert_ne!(rsa.public_key(), ecc.public_key());
    (rsa, ecc)
}

fn assert_registered_fetchers_unchanged(a: &ValidationContext, b: &ValidationContext) {
    assert!(Arc::ptr_eq(
        a.fetchers.cert.as_ref().unwrap(),
        b.fetchers.cert.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        a.fetchers.crl.as_ref().unwrap(),
        b.fetchers.crl.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        a.fetchers.ocsp.as_ref().unwrap(),
        b.fetchers.ocsp.as_ref().unwrap()
    ));
}

#[test]
fn registered_clone_preserves_nondefault_security_state_and_caller() {
    let original = original_context();
    let before = original.clone();
    let (rsa, ecc) = registered_collision_pair();
    let registered = original.with_registered_other_certs([&rsa, &ecc]);

    // Reuse the restrictive original fixture and its full existing retention
    // checks, excluding only the intentionally changed candidate certificate set.
    assert_security_requirements_preserved(&original, &registered);
    assert_timing_equal(&original.timing, &registered.timing);
    assert_registered_fetchers_unchanged(&original, &registered);

    // The operation must not normalize/mutate the caller's candidates, policies,
    // custom trust manager, evidence or mutable-looking shared configuration.
    assert_security_configuration_preserved(&before, &original);
    assert_timing_equal(&before.timing, &original.timing);
    assert_registered_fetchers_unchanged(&before, &original);
}

fn registered_native_anchor_context() -> ValidationContext {
    let rsa_root = registered_fixture(
        "testing-ca",
        "root",
        "2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa",
    );
    let ecc_root = registered_fixture(
        "testing-ca-ecdsa",
        "root",
        "ccc409838b97b5c04b18f889fa39b9b123868ff685751f58956206fb86d5ba90",
    );
    ValidationContext::builder()
        .trust_anchor(TrustAnchor::with_qualifiers(
            rsa_root,
            TrustQualifiers {
                max_path_length: Some(0),
                valid_until: Some(moment("2020-11-02T00:00:00Z")),
                ..TrustQualifiers::default()
            },
        ))
        .trust_anchor(TrustAnchor::with_qualifiers(
            ecc_root,
            TrustQualifiers {
                max_aa_path_length: Some(0),
                valid_from: Some(moment("2020-10-01T00:00:00Z")),
                ..TrustQualifiers::default()
            },
        ))
        .moment(moment("2020-11-01T00:00:00Z"))
        .build()
        .unwrap()
}

#[test]
fn registered_candidates_keep_first_identity_per_operation_and_never_change_anchors() {
    let original = registered_native_anchor_context();
    let anchors = original.trust_anchors.clone();
    assert_eq!(anchors.len(), 2);
    let (rsa, ecc) = registered_collision_pair();
    let rsa_first = original.with_registered_other_certs([&rsa, &ecc, &rsa]);
    let ecc_first = original.with_registered_other_certs([&ecc, &rsa]);
    assert_eq!(rsa_first.other_certs(), std::slice::from_ref(&rsa));
    assert_eq!(ecc_first.other_certs(), std::slice::from_ref(&ecc));
    assert!(original.other_certs().is_empty());

    // Independent calls do not share a registry, while later additions to a
    // returned clone cannot overwrite its already-retained issuer/serial key.
    assert_eq!(
        rsa_first.with_registered_other_certs([&ecc]).other_certs(),
        std::slice::from_ref(&rsa)
    );
    assert_eq!(
        ecc_first.with_registered_other_certs([&rsa]).other_certs(),
        std::slice::from_ref(&ecc)
    );
    // General evidence extension remains a separate DER-deduplicating API.
    assert_eq!(
        original.with_other_certs([&rsa, &ecc]).other_certs(),
        &[rsa.clone(), ecc.clone()]
    );
    for context in [&original, &rsa_first, &ecc_first] {
        assert_eq!(context.trust_anchors(), anchors.as_slice());
        assert!(!context.is_trust_anchor(&rsa));
        assert!(!context.is_trust_anchor(&ecc));
        for anchor in &anchors {
            assert_eq!(context.as_trust_anchor(anchor.cert()).unwrap(), *anchor);
        }
    }
}

#[test]
fn registered_clone_does_not_enumerate_a_custom_trust_manager_into_candidates() {
    let (rsa, ecc) = registered_collision_pair();
    let manager: Arc<dyn TrustManager> = Arc::new(OneAnchor(rsa.clone()));
    let mut original = registered_native_anchor_context();
    original.trust_manager = Some(manager.clone());
    let registered = original.with_registered_other_certs([&ecc]);
    // The public TrustManager has query methods but no enumeration contract.
    // Only explicit roots are seeded; an implicit custom anchor is not a
    // hidden pre-registered candidate that can evict the incoming ECC identity.
    assert_eq!(registered.other_certs(), std::slice::from_ref(&ecc));
    assert!(original.other_certs().is_empty());
    assert_eq!(registered.trust_anchors(), original.trust_anchors());
    assert!(Arc::ptr_eq(registered.trust_manager().unwrap(), &manager));
    assert!(registered.is_trust_anchor(&rsa));
    assert!(!registered.is_trust_anchor(&ecc));
    assert!(original.is_trust_anchor(&rsa));
}

// Exact backend ownership assertions from CV 0.33.0, plus selection guards.
#[derive(Debug, Default)]
struct RecordingBackend {
    retrievals: std::sync::atomic::AtomicUsize,
    closes: std::sync::atomic::AtomicUsize,
    close_error: Option<FetchError>,
}

impl sigis_pki_core::fetch::FetcherBackend for RecordingBackend {
    fn get_fetchers(&self) -> Fetchers {
        self.retrievals
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        marker_fetchers()
    }

    fn close(&self) -> Result<(), FetchError> {
        self.closes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.close_error.clone().map_or(Ok(()), Err)
    }
}

fn backend_execution_identity() {
    static IMAGE: std::sync::Once = std::sync::Once::new();
    IMAGE.call_once(|| {
        let path = std::env::current_exe().unwrap().canonicalize().unwrap();
        let data = std::fs::read(&path).unwrap();
        let hash: String = sigis_pki_core::algorithms::DigestAlgorithm::Sha256
            .digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        eprintln!(
            "BACKEND_CONTEXT_ELF {}",
            serde_json::json!({"path":path,"length":data.len(),"sha256":hash})
        );
    });
}

fn backend_count(counter: &std::sync::atomic::AtomicUsize) -> usize {
    counter.load(std::sync::atomic::Ordering::SeqCst)
}

#[test]
fn backend_context_leaves_a_supplied_backend_alone_private_owner() {
    backend_execution_identity();
    let backend = Arc::new(RecordingBackend::default());
    let context = ValidationContext::builder()
        .fetcher_backend(backend.clone())
        .build()
        .unwrap();
    // The original inspects _owned_fetcher_backend, not just Arc lifetime.
    assert!(context.owned_fetcher_backend.is_none());
    context.close().unwrap();
    assert_eq!(backend_count(&backend.closes), 0);
    assert_eq!(backend_count(&backend.retrievals), 1);
    assert!(!context.fetchers().is_empty());
}

#[test]
fn backend_context_adopts_an_owned_backend_private_identity() {
    backend_execution_identity();
    let backend = Arc::new(RecordingBackend::default());
    let identity: Arc<dyn sigis_pki_core::fetch::FetcherBackend> = backend.clone();
    let context = ValidationContext::builder()
        .owned_fetcher_backend(identity.clone())
        .build()
        .unwrap();
    assert!(Arc::ptr_eq(
        context.owned_fetcher_backend.as_ref().unwrap(),
        &identity
    ));
    context.close().unwrap();
    assert_eq!(backend_count(&backend.closes), 1);
    assert_eq!(backend_count(&backend.retrievals), 1);
}

#[test]
fn backend_explicit_fetchers_win_in_both_orders_including_explicit_none() {
    backend_execution_identity();
    for owned in [false, true] {
        for explicit_first in [false, true] {
            for empty in [false, true] {
                let backend = Arc::new(RecordingBackend::default());
                let identity: Arc<dyn sigis_pki_core::fetch::FetcherBackend> = backend.clone();
                let explicit = if empty {
                    Fetchers::none()
                } else {
                    marker_fetchers()
                };
                let mut builder = ValidationContext::builder();
                if explicit_first {
                    builder = builder.fetchers(explicit.clone());
                }
                builder = if owned {
                    builder.owned_fetcher_backend(identity.clone())
                } else {
                    builder.fetcher_backend(identity.clone())
                };
                if !explicit_first {
                    builder = builder.fetchers(explicit.clone());
                }
                let context = builder.build().unwrap();
                assert_eq!(backend_count(&backend.retrievals), 0);
                assert_eq!(context.fetchers().is_empty(), empty);
                if !empty {
                    assert_registered_fetchers_unchanged(
                        &context,
                        &context.with_fetchers(explicit),
                    );
                }
                assert_eq!(context.owned_fetcher_backend.is_some(), owned);
                if owned {
                    assert!(Arc::ptr_eq(
                        context.owned_fetcher_backend.as_ref().unwrap(),
                        &identity
                    ));
                }
                context.close().unwrap();
                assert_eq!(backend_count(&backend.closes), usize::from(owned));
            }
        }
    }
}

#[test]
fn backend_last_selection_replaces_both_identity_and_close_authority() {
    backend_execution_identity();
    for first_owned in [false, true] {
        for last_owned in [false, true] {
            let first = Arc::new(RecordingBackend::default());
            let last = Arc::new(RecordingBackend::default());
            let last_identity: Arc<dyn sigis_pki_core::fetch::FetcherBackend> = last.clone();
            let builder = ValidationContext::builder();
            let builder = if first_owned {
                builder.owned_fetcher_backend(first.clone())
            } else {
                builder.fetcher_backend(first.clone())
            };
            let builder = if last_owned {
                builder.owned_fetcher_backend(last_identity.clone())
            } else {
                builder.fetcher_backend(last_identity.clone())
            };
            let context = builder.build().unwrap();
            assert_eq!(backend_count(&first.retrievals), 0);
            assert_eq!(backend_count(&last.retrievals), 1);
            assert_eq!(context.owned_fetcher_backend.is_some(), last_owned);
            if last_owned {
                assert!(Arc::ptr_eq(
                    context.owned_fetcher_backend.as_ref().unwrap(),
                    &last_identity
                ));
            }
            context.close().unwrap();
            drop(context);
            assert_eq!(backend_count(&first.closes), 0);
            assert_eq!(backend_count(&last.closes), usize::from(last_owned));
        }
    }
}

#[test]
fn backend_factory_runs_only_after_successful_builder_validation_once() {
    backend_execution_identity();
    for invalid in [0, 1, 2] {
        let backend = Arc::new(RecordingBackend::default());
        let builder = ValidationContext::builder().owned_fetcher_backend(backend.clone());
        let builder = match invalid {
            0 => builder.revocation_mode("invalid-mode"),
            1 => builder.crl(vec![0x30, 0x00]),
            _ => builder.ocsp_response(vec![0x30, 0x00]),
        };
        assert!(builder.build().is_err());
        assert_eq!(backend_count(&backend.retrievals), 0);
        assert_eq!(backend_count(&backend.closes), 0);
    }
    let default = ValidationContext::builder().build().unwrap();
    assert!(default.fetchers().is_empty());
    assert!(default.owned_fetcher_backend.is_none());
    default.close().unwrap();
    let backend = Arc::new(RecordingBackend::default());
    let context = ValidationContext::builder()
        .owned_fetcher_backend(backend.clone())
        .build()
        .unwrap();
    assert_eq!(backend_count(&backend.retrievals), 1);
    let clone = context
        .clone()
        .with_fetchers(Fetchers::none())
        .with_timing(*context.timing());
    assert_eq!(backend_count(&backend.retrievals), 1);
    drop(clone);
    drop(context);
    // Drop is not an implicit close, even when the context was the last owner.
    assert_eq!(backend_count(&backend.closes), 0);
}

#[test]
fn backend_explicit_close_repeats_and_preserves_typed_error_and_owner() {
    backend_execution_identity();
    let error = FetchError::new(
        sigis_pki_core::errors::FetchErrorKind::Timeout,
        "close timeout",
    );
    let backend = Arc::new(RecordingBackend {
        close_error: Some(error.clone()),
        ..Default::default()
    });
    let identity: Arc<dyn sigis_pki_core::fetch::FetcherBackend> = backend.clone();
    let context = ValidationContext::builder()
        .owned_fetcher_backend(identity.clone())
        .build()
        .unwrap();
    for count in 1..=3 {
        assert_eq!(context.close(), Err(error.clone()));
        assert_eq!(backend_count(&backend.closes), count);
        assert!(Arc::ptr_eq(
            context.owned_fetcher_backend.as_ref().unwrap(),
            &identity
        ));
    }
    drop(context);
    assert_eq!(backend_count(&backend.closes), 3);
}

#[test]
fn backend_clone_timing_and_replacement_preserve_owner_and_all_security_fields() {
    backend_execution_identity();
    let backend = Arc::new(RecordingBackend::default());
    let identity: Arc<dyn sigis_pki_core::fetch::FetcherBackend> = backend.clone();
    let mut original = original_context();
    // Reuse the accepted restrictive fixture, never reconstruct its context.
    original.owned_fetcher_backend = Some(identity.clone());
    let mut timing = *original.timing();
    timing.validation_time = moment("2020-11-02T00:00:00Z");
    timing.time_tolerance = Duration::from_secs(19);
    let copies = [
        original.clone(),
        original.with_timing(timing),
        original.with_fetchers(Fetchers::none()),
    ];
    for copy in &copies {
        assert_security_configuration_preserved(&original, copy);
        assert!(Arc::ptr_eq(
            copy.owned_fetcher_backend.as_ref().unwrap(),
            &identity
        ));
        copy.close().unwrap();
    }
    assert_timing_equal(copies[1].timing(), &timing);
    assert_timing_equal(copies[2].timing(), original.timing());
    assert_registered_fetchers_unchanged(&original, &copies[0]);
    assert_registered_fetchers_unchanged(&original, &copies[1]);
    assert!(copies[2].fetchers().is_empty());
    assert!(!original.fetchers().is_empty());
    assert_eq!(backend_count(&backend.retrievals), 0);
    assert_eq!(backend_count(&backend.closes), 3);
    original.close().unwrap();
    assert_eq!(backend_count(&backend.closes), 4);
}
