//! Consuming checked facts must move authority-free data without repeating work.
//! No new immutable upstream function credit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pki_certvalidator::{
    validate::{find_current_leaf_revocation_evaluation, CurrentLeafRevocationFacts},
    CertRevTrustPolicy, FreshnessReqType, RevocationCheckingPolicy, RevocationCheckingRule,
    ValidationContext, REQUIRE_REVINFO,
};
use sigis_pki_core::{
    algorithms::{
        AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm,
        DisallowWeakAlgorithmsPolicy,
    },
    cert::Cert,
    errors::FetchError,
    fetch::{FetcherBackend, Fetchers},
    time::Moment,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Debug, Default)]
struct OwnershipProbe {
    factories: AtomicUsize,
    closes: AtomicUsize,
}
impl FetcherBackend for OwnershipProbe {
    fn get_fetchers(&self) -> Fetchers {
        self.factories.fetch_add(1, Ordering::SeqCst);
        Fetchers::none()
    }
    fn close(&self) -> Result<(), FetchError> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct PolicyProbe {
    calls: AtomicUsize,
}
impl AlgorithmUsagePolicy for PolicyProbe {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &const_oid::ObjectIdentifier,
        moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        self.calls.fetch_add(1, Ordering::SeqCst);
        DisallowWeakAlgorithmsPolicy::default().digest_algorithm_allowed(algorithm, moment)
    }
    fn signature_algorithm_allowed(
        &self,
        algorithm: &spki::AlgorithmIdentifierOwned,
        moment: Option<Moment>,
        key: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        self.calls.fetch_add(1, Ordering::SeqCst);
        DisallowWeakAlgorithmsPolicy::default().signature_algorithm_allowed(algorithm, moment, key)
    }
    fn min_rsa_key_size(&self) -> usize {
        self.calls.fetch_add(1, Ordering::SeqCst);
        2048
    }
}

fn bytes(name: &str) -> Vec<u8> {
    let path = sigis_testdata::data_dir()
        .join("lanes/r3-v/leaf-revoked-completion")
        .join(name);
    let value = std::fs::read(&path).unwrap();
    eprintln!(
        "LEAF_COMPLETION_OWNED_INPUT {}",
        serde_json::json!({"path":path.canonicalize().unwrap(), "length":value.len(), "sha256":DigestAlgorithm::Sha256.digest(&value).iter().map(|b|format!("{b:02x}")).collect::<String>()})
    );
    value
}
fn cert(label: &str) -> Cert {
    let file = if label == "signer1" {
        "metadata/current-valid/cert-signer1.der".to_owned()
    } else {
        format!("cert-{label}.der")
    };
    Cert::from_der(&bytes(&file)).unwrap()
}
fn context(
    signer: &str,
    both: bool,
    backend: &Arc<OwnershipProbe>,
    policy: &Arc<PolicyProbe>,
) -> ValidationContext {
    let mut revinfo = CertRevTrustPolicy::new(if both {
        RevocationCheckingPolicy {
            ee_certificate_rule: RevocationCheckingRule::CrlAndOcspRequired,
            intermediate_ca_cert_rule: RevocationCheckingRule::CrlRequired,
        }
    } else {
        REQUIRE_REVINFO
    });
    revinfo.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    ValidationContext::builder()
        .moment(Moment::parse_rfc3339("2020-12-25T00:00:00Z").unwrap())
        .point_in_time_validation(false)
        .trust_root(cert("root"))
        .other_cert(cert("interm"))
        .revinfo_policy(revinfo)
        .algorithm_policy(policy.clone())
        .owned_fetcher_backend(backend.clone())
        .crl(bytes("2020-12-25/crl-root.der"))
        .crl(bytes("2020-12-25/crl-interm.der"))
        .ocsp_response(bytes(&format!("2020-12-25/ocsp-{signer}.der")))
        .build()
        .unwrap()
}

#[test]
fn consuming_actual_revoked_facts_moves_buffers_and_never_retains_backend_authority() {
    for both in [false, true] {
        let backend = Arc::new(OwnershipProbe::default());
        let policy = Arc::new(PolicyProbe::default());
        let ctx = context("signer2", both, &backend, &policy);
        assert_eq!(Arc::strong_count(&backend), 2);
        let evaluated =
            find_current_leaf_revocation_evaluation(&ctx, &cert("signer2"), None).unwrap();
        let expected_path = evaluated.path().clone();
        let expected_failure = evaluated.unresolved_failure().unwrap().clone();
        let expected_events = if both { 2 } else { 1 };
        assert_eq!(evaluated.leaf_events().len(), expected_events);
        let event_buffer = evaluated.leaf_events().as_ptr();
        let evidence_buffers: Vec<_> = evaluated
            .leaf_events()
            .iter()
            .map(|event| event.evidence_der().as_ptr())
            .collect();
        let calls = policy.calls.load(Ordering::SeqCst);
        assert!(
            calls > 0,
            "real current path evaluation must execute its actual policy"
        );
        let facts: CurrentLeafRevocationFacts = evaluated.into_owned_facts();
        assert_eq!(facts.path(), &expected_path);
        assert_eq!(facts.unresolved_failure(), Some(&expected_failure));
        assert_eq!(
            facts.leaf_events().as_ptr(),
            event_buffer,
            "move the actual checked event allocation"
        );
        assert_eq!(
            facts
                .leaf_events()
                .iter()
                .map(|event| event.evidence_der().as_ptr())
                .collect::<Vec<_>>(),
            evidence_buffers
        );
        assert_eq!(
            policy.calls.load(Ordering::SeqCst),
            calls,
            "conversion/getters cannot re-evaluate policy"
        );
        assert_eq!(
            Arc::strong_count(&backend),
            2,
            "facts cannot clone the whole context/close owner"
        );
        drop(ctx);
        assert_eq!(
            Arc::strong_count(&backend),
            1,
            "owned data must outlive the local context without retaining its authority"
        );
        assert_eq!(facts.path(), &expected_path);
        assert_eq!(facts.unresolved_failure(), Some(&expected_failure));
        assert_eq!(facts.leaf_events().len(), expected_events);
        drop(facts);
        assert_eq!(backend.factories.load(Ordering::SeqCst), 1);
        assert_eq!(backend.closes.load(Ordering::SeqCst), 0);
        assert_eq!(policy.calls.load(Ordering::SeqCst), calls);
    }
}

#[test]
fn current_valid_zero_event_conversion_keeps_the_actual_checked_path_without_resolution() {
    let backend = Arc::new(OwnershipProbe::default());
    let policy = Arc::new(PolicyProbe::default());
    let ctx = context("signer1", false, &backend, &policy);
    let evaluated = find_current_leaf_revocation_evaluation(&ctx, &cert("signer1"), None).unwrap();
    assert!(evaluated.unresolved_failure().is_none());
    let expected_path = evaluated.path().clone();
    let calls = policy.calls.load(Ordering::SeqCst);
    let facts: CurrentLeafRevocationFacts = evaluated.into_owned_facts();
    drop(ctx);
    assert_eq!(facts.path(), &expected_path);
    assert!(facts.unresolved_failure().is_none());
    assert!(facts.leaf_events().is_empty());
    assert_eq!(Arc::strong_count(&backend), 1);
    assert_eq!(backend.factories.load(Ordering::SeqCst), 1);
    assert_eq!(backend.closes.load(Ordering::SeqCst), 0);
    assert_eq!(policy.calls.load(Ordering::SeqCst), calls);
}
