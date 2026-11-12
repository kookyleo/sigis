// Native algorithm-horizon regressions using the genuine upstream time-slide
// fixtures and the production public entry point, written before implementation.
// These supplement the upstream tests; they are not new upstream functions.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{load_cert, moment, read};
use const_oid::ObjectIdentifier;
use der::Decode;
use sigis_pki_certvalidator::ltv::poe::{PoeManager, PoeType};
use sigis_pki_certvalidator::ltv::{time_slide_with, LtvError, TimeSlideOptions};
use sigis_pki_certvalidator::{
    Cert, CertRevTrustPolicy, FreshnessReqType, RevocationCheckingPolicy, RevocationCheckingRule,
    TrustAnchor, ValidationContext, ValidationPath,
};
use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
use sigis_pki_core::errors::ValidationError;
use sigis_pki_core::time::Moment;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const ROOT_CRL: &str = "root-2020-11-29.crl";
const LEAF_CRL: &str = "interm-2020-11-29.crl";
const LEAF_OCSP: &str = "alice-2020-11-29.ors";

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignatureInput {
    algorithm: AlgorithmIdentifierOwned,
    public_key: SubjectPublicKeyInfoOwned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignatureCall {
    input: SignatureInput,
    moment: Option<Moment>,
}

// A CRL and a certificate may use the identical algorithm and issuer key.
// Select one occurrence in a fully asserted production trace to distinguish
// their call sites without changing any signed fixture bytes or trust roots.
#[derive(Debug)]
struct ScriptedPolicy {
    constraint_at: Option<(usize, AlgorithmUsageConstraint)>,
    calls: Mutex<Vec<SignatureCall>>,
}

impl ScriptedPolicy {
    fn with_constraint(constraint_at: Option<(usize, AlgorithmUsageConstraint)>) -> Arc<Self> {
        Arc::new(Self {
            constraint_at,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<SignatureCall> {
        self.calls.lock().expect("calls").clone()
    }
}

impl AlgorithmUsagePolicy for ScriptedPolicy {
    fn digest_algorithm_allowed(
        &self,
        _: &ObjectIdentifier,
        _: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        panic!("time sliding must query the signature policy directly")
    }

    fn signature_algorithm_allowed(
        &self,
        algorithm: &AlgorithmIdentifierOwned,
        moment: Option<Moment>,
        key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        let mut calls = self.calls.lock().expect("calls");
        let index = calls.len();
        calls.push(SignatureCall {
            input: SignatureInput {
                algorithm: algorithm.clone(),
                public_key: key.expect("issuer public key").clone(),
            },
            moment,
        });
        match &self.constraint_at {
            Some((target, constraint)) if *target == index => constraint.clone(),
            _ => AlgorithmUsageConstraint::allowed(),
        }
    }
}

fn cert(name: &str) -> Cert {
    load_cert(&["ades", "time-slide", "certs", name])
}

fn data(name: &str) -> Vec<u8> {
    read(&["ades", "time-slide", name])
}

fn path() -> ValidationPath {
    ValidationPath::new(
        TrustAnchor::new(cert("root.crt")),
        vec![cert("interm.crt")],
        Some(cert("alice.crt")),
    )
}

fn trust_policy() -> CertRevTrustPolicy {
    CertRevTrustPolicy::new(RevocationCheckingPolicy {
        ee_certificate_rule: RevocationCheckingRule::CrlOrOcspRequired,
        intermediate_ca_cert_rule: RevocationCheckingRule::CrlOrOcspRequired,
    })
}

fn context(
    now: Moment,
    crls: &[&str],
    ocsps: &[&str],
    policy: Arc<ScriptedPolicy>,
    revinfo_policy: CertRevTrustPolicy,
) -> ValidationContext {
    let mut builder = ValidationContext::builder()
        .trust_root(cert("root.crt"))
        .other_cert(cert("interm.crt"))
        .other_cert(cert("interm-ocsp.crt"))
        .other_cert(cert("alice.crt"))
        .algorithm_policy(policy)
        .revinfo_policy(revinfo_policy)
        .time_tolerance(Duration::from_secs(600))
        .moment(now);
    for name in crls {
        builder = builder.crl(data(name));
    }
    for name in ocsps {
        builder = builder.ocsp_response(data(name));
    }
    builder.build().expect("context")
}

fn timed_denial(cutoff: Moment) -> AlgorithmUsageConstraint {
    AlgorithmUsageConstraint {
        allowed: false,
        failure_reason: Some("Timed signature prohibition".into()),
        not_allowed_after: Some(cutoff),
    }
}

fn cert_input(name: &str, issuer: &str) -> SignatureInput {
    SignatureInput {
        algorithm: cert(name).decoded().signature_algorithm().clone(),
        public_key: cert(issuer).public_key(),
    }
}

fn crl_input(name: &str, issuer: &str) -> SignatureInput {
    let crl = x509_cert::crl::CertificateList::<x509_cert::certificate::Raw>::from_der(&data(name))
        .expect("CRL fixture");
    SignatureInput {
        algorithm: crl.signature_algorithm,
        public_key: cert(issuer).public_key(),
    }
}

fn ocsp_input(name: &str) -> SignatureInput {
    let response = x509_ocsp::OcspResponse::from_der(&data(name)).expect("OCSP fixture");
    let bytes = response.response_bytes.expect("successful response");
    let basic = x509_ocsp::BasicOcspResponse::from_der(bytes.response.as_bytes())
        .expect("basic response fixture");
    SignatureInput {
        algorithm: basic.signature_algorithm,
        public_key: cert("interm-ocsp.crt").public_key(),
    }
}

fn crl_trace(root: &str, leaf: &str) -> Vec<SignatureInput> {
    vec![
        crl_input(root, "root.crt"),
        cert_input("interm.crt", "root.crt"),
        crl_input(leaf, "interm.crt"),
        cert_input("alice.crt", "interm.crt"),
    ]
}

fn ocsp_trace(root: &str, leaf: &str) -> Vec<SignatureInput> {
    vec![
        crl_input(root, "root.crt"),
        cert_input("interm.crt", "root.crt"),
        // The real delegated responder's provisional path is traversed.
        crl_input(root, "root.crt"),
        cert_input("interm.crt", "root.crt"),
        cert_input("interm-ocsp.crt", "interm.crt"),
        ocsp_input(leaf),
        cert_input("alice.crt", "interm.crt"),
    ]
}

fn assert_inputs(policy: &ScriptedPolicy, expected: &[SignatureInput]) {
    assert_eq!(
        policy
            .calls()
            .into_iter()
            .map(|c| c.input)
            .collect::<Vec<_>>(),
        expected,
        "signature algorithm and issuer/responder key at every production call site"
    );
}

// Explicitly supplied fixture POEs are test inputs, as in upstream tests.
// They establish existence only; a successful slide does not validate a path
// or authenticate these POEs. All registered objects predate this timestamp.
fn provided_poes(now: Moment, omit_cert: Option<&str>, omit_revinfo: Option<&str>) -> PoeManager {
    let mut poe = PoeManager::with_current_time(now);
    let at = moment("2020-11-29T00:01:00Z");
    for name in ["interm.crt", "alice.crt", "interm-ocsp.crt"] {
        if Some(name) != omit_cert {
            poe.register(cert(name).der(), at, PoeType::Provided);
        }
    }
    for name in [ROOT_CRL, LEAF_CRL, LEAF_OCSP] {
        if Some(name) != omit_revinfo {
            poe.register(&data(name), at, PoeType::Provided);
        }
    }
    poe
}

#[test]
fn timed_certificate_and_crl_constraints_reach_the_actual_call_sites() {
    let now = moment("2020-11-29T00:05:00Z");
    let cutoff = moment("2020-11-29T00:04:00Z");
    let expected = crl_trace(ROOT_CRL, LEAF_CRL);
    // 2 = the leaf CRL, 3 = Alice's certificate. Both use the intermediate
    // CA's key, so the full trace assertion disambiguates the two sites.
    for target in [2, 3] {
        let policy = ScriptedPolicy::with_constraint(Some((target, timed_denial(cutoff))));
        let ctx = context(
            now,
            &[ROOT_CRL, LEAF_CRL],
            &[],
            policy.clone(),
            trust_policy(),
        );
        let result = time_slide_with(
            &path(),
            now,
            &ctx,
            &provided_poes(now, None, None),
            TimeSlideOptions::default(),
        )
        .expect("timed signature denial must rewind");
        assert_eq!(result, cutoff, "target={target}; no one-second subtraction");
        assert_inputs(&policy, &expected);
        for (index, call) in policy.calls().iter().enumerate() {
            assert_eq!(
                call.moment,
                Some(if index <= target { now } else { cutoff })
            );
        }
    }
}

#[test]
fn timed_ocsp_signature_constraint_preserves_the_real_responder_path() {
    let now = moment("2020-11-29T00:05:00Z");
    let cutoff = moment("2020-11-29T00:04:00Z");
    let policy = ScriptedPolicy::with_constraint(Some((5, timed_denial(cutoff))));
    let ctx = context(
        now,
        &[ROOT_CRL],
        &[LEAF_OCSP],
        policy.clone(),
        trust_policy(),
    );
    assert_eq!(
        time_slide_with(
            &path(),
            now,
            &ctx,
            &provided_poes(now, None, None),
            TimeSlideOptions::default()
        )
        .expect("OCSP horizon"),
        cutoff
    );
    assert_inputs(&policy, &ocsp_trace(ROOT_CRL, LEAF_OCSP));
    for (index, call) in policy.calls().iter().enumerate() {
        assert_eq!(call.moment, Some(if index <= 5 { now } else { cutoff }));
    }
}

#[test]
fn permanent_denials_from_certificate_crl_and_ocsp_remain_typed() {
    let now = moment("2020-11-29T00:05:00Z");
    let reason = "No recovery even though the reason mentions 2020-11-29T00:04:00Z";
    for (use_ocsp, target) in [(false, 2), (false, 3), (true, 5)] {
        let policy = ScriptedPolicy::with_constraint(Some((
            target,
            AlgorithmUsageConstraint::denied(reason),
        )));
        let (crls, ocsps) = if use_ocsp {
            (vec![ROOT_CRL], vec![LEAF_OCSP])
        } else {
            (vec![ROOT_CRL, LEAF_CRL], vec![])
        };
        let ctx = context(now, &crls, &ocsps, policy.clone(), trust_policy());
        let error = time_slide_with(
            &path(),
            now,
            &ctx,
            &provided_poes(now, None, None),
            TimeSlideOptions::default(),
        )
        .expect_err("permanent denial cannot be recovered");
        match error {
            LtvError::Validation(ValidationError::DisallowedAlgorithm { msg, banned_since }) => {
                assert_eq!(banned_since, None);
                assert!(msg.contains(reason), "{msg}");
            }
            other => panic!("wrong error at target {target}: {other:?}"),
        }
        let expected = if use_ocsp {
            ocsp_trace(ROOT_CRL, LEAF_OCSP)
        } else {
            crl_trace(ROOT_CRL, LEAF_CRL)
        };
        assert_inputs(&policy, &expected[..=target]);
    }
}

#[test]
fn allowed_cutoff_metadata_does_not_rewind_any_call_site() {
    let now = moment("2020-11-29T00:05:00Z");
    let cutoff = moment("2020-11-29T00:04:00Z");
    for (use_ocsp, target) in [(false, 2), (false, 3), (true, 5)] {
        let policy = ScriptedPolicy::with_constraint(Some((
            target,
            AlgorithmUsageConstraint {
                allowed: true,
                failure_reason: None,
                not_allowed_after: Some(cutoff),
            },
        )));
        let (crls, ocsps) = if use_ocsp {
            (vec![ROOT_CRL], vec![LEAF_OCSP])
        } else {
            (vec![ROOT_CRL, LEAF_CRL], vec![])
        };
        let ctx = context(now, &crls, &ocsps, policy.clone(), trust_policy());
        assert_eq!(
            time_slide_with(
                &path(),
                now,
                &ctx,
                &PoeManager::with_current_time(now),
                TimeSlideOptions::default()
            )
            .expect("allowed signature"),
            now
        );
        let expected = if use_ocsp {
            ocsp_trace(ROOT_CRL, LEAF_OCSP)
        } else {
            crl_trace(ROOT_CRL, LEAF_CRL)
        };
        assert_inputs(&policy, &expected);
        assert!(policy.calls().iter().all(|c| c.moment == Some(now)));
    }
}

#[test]
fn rewinding_an_intermediate_algorithm_does_not_supply_leaf_certificate_poe() {
    let now = moment("2020-11-29T00:05:00Z");
    let cutoff = moment("2020-11-29T00:04:00Z");
    let policy = ScriptedPolicy::with_constraint(Some((1, timed_denial(cutoff))));
    let ctx = context(
        now,
        &[ROOT_CRL, LEAF_CRL],
        &[],
        policy.clone(),
        trust_policy(),
    );
    let error = time_slide_with(
        &path(),
        now,
        &ctx,
        &provided_poes(now, Some("alice.crt"), None),
        TimeSlideOptions::default(),
    )
    .expect_err("algorithm metadata cannot establish certificate POE");
    assert!(
        matches!(&error, LtvError::InsufficientPoe(msg) if msg.contains("Alice")),
        "{error:?}"
    );
    assert_inputs(&policy, &crl_trace(ROOT_CRL, LEAF_CRL)[..2]);
}

#[test]
fn rewinding_an_intermediate_algorithm_does_not_supply_revinfo_poe() {
    let now = moment("2020-11-29T00:05:00Z");
    let cutoff = moment("2020-11-29T00:04:00Z");
    let policy = ScriptedPolicy::with_constraint(Some((1, timed_denial(cutoff))));
    let ctx = context(
        now,
        &[ROOT_CRL, LEAF_CRL],
        &[],
        policy.clone(),
        trust_policy(),
    );
    let error = time_slide_with(
        &path(),
        now,
        &ctx,
        &provided_poes(now, None, Some(LEAF_CRL)),
        TimeSlideOptions::default(),
    )
    .expect_err("algorithm metadata cannot establish revocation-information POE");
    assert!(
        matches!(&error, LtvError::Validation(ValidationError::InsufficientRevinfo(msg)) if msg.contains("Alice")),
        "{error:?}"
    );
    assert_inputs(&policy, &crl_trace(ROOT_CRL, LEAF_CRL)[..2]);
}

#[test]
fn rewinding_does_not_bypass_delegated_ocsp_responder_poe() {
    let now = moment("2020-11-29T00:05:00Z");
    let cutoff = moment("2020-11-29T00:04:00Z");
    let policy = ScriptedPolicy::with_constraint(Some((0, timed_denial(cutoff))));
    let ctx = context(
        now,
        &[ROOT_CRL],
        &[LEAF_OCSP],
        policy.clone(),
        trust_policy(),
    );
    let error = time_slide_with(
        &path(),
        now,
        &ctx,
        &provided_poes(now, Some("interm-ocsp.crt"), None),
        TimeSlideOptions::default(),
    )
    .expect_err("the real responder still requires POE at the new control time");
    assert!(
        matches!(&error, LtvError::InsufficientPoe(msg) if msg.contains("OCSP Responder")),
        "{error:?}"
    );
    assert_inputs(&policy, &ocsp_trace(ROOT_CRL, LEAF_OCSP)[..4]);
}

#[test]
fn revocation_precedes_algorithm_recovery_for_crl_and_ocsp() {
    let now = moment("2020-12-10T00:05:00Z");
    let cutoff = moment("2020-12-05T00:00:00Z");
    let revoked_at = moment("2020-12-01T00:00:00Z");
    for (use_ocsp, target) in [(false, 2), (true, 5)] {
        let root = "root-2020-12-10.crl";
        let crl = "interm-2020-12-10.crl";
        let ocsp = "alice-2020-12-10.ors";
        let policy = ScriptedPolicy::with_constraint(Some((target, timed_denial(cutoff))));
        let (crls, ocsps) = if use_ocsp {
            (vec![root], vec![ocsp])
        } else {
            (vec![root, crl], vec![])
        };
        let ctx = context(now, &crls, &ocsps, policy.clone(), trust_policy());
        assert_eq!(
            time_slide_with(
                &path(),
                now,
                &ctx,
                &PoeManager::with_current_time(now),
                TimeSlideOptions::default()
            )
            .expect("revocation cutoff"),
            revoked_at,
            "a later algorithm cutoff must never move control time forward"
        );
        let expected = if use_ocsp {
            ocsp_trace(root, ocsp)
        } else {
            crl_trace(root, crl)
        };
        assert_inputs(&policy, &expected);
        assert_eq!(policy.calls()[target].moment, Some(revoked_at));
        assert_eq!(policy.calls()[target + 1].moment, Some(revoked_at));
    }
}

#[test]
fn algorithm_recovery_does_not_bypass_revinfo_freshness() {
    let now = moment("2020-11-29T00:05:00Z");
    let cutoff = moment("2020-11-29T00:04:00Z");
    let policy = ScriptedPolicy::with_constraint(Some((1, timed_denial(cutoff))));
    let mut revinfo_policy = trust_policy();
    revinfo_policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    revinfo_policy.freshness = Some(Duration::from_secs(86400));
    let ctx = context(now, &[ROOT_CRL], &[], policy.clone(), revinfo_policy);
    let intermediate_path = ValidationPath::new(
        TrustAnchor::new(cert("root.crt")),
        vec![],
        Some(cert("interm.crt")),
    );
    let result = time_slide_with(
        &intermediate_path,
        now,
        &ctx,
        &PoeManager::with_current_time(now),
        TimeSlideOptions::default(),
    )
    .expect("freshness rewinds further");
    // thisUpdate = Nov 21; MAX_DIFF = one day; existing judge applies the
    // ten-minute tolerance both in its delta and at the comparison boundary.
    assert_eq!(result, moment("2020-11-22T00:20:00Z"));
    assert!(result < cutoff);
    assert_inputs(&policy, &crl_trace(ROOT_CRL, LEAF_CRL)[..2]);
    assert_eq!(policy.calls()[1].moment, Some(now));
}
