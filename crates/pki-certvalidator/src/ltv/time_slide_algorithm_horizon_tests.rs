// Supplemental algorithm-horizon regressions for ltv/time_slide.rs.
// Written before implementation; the timed minimum failed in the initial run.
// Source semantics: certvalidator cv-0.33.0 ltv/time_slide.py:95-123.

use std::sync::{Arc, Mutex};

use const_oid::ObjectIdentifier;
use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use super::{apply_algo_policy, LtvError, Moment, ValidationContext, ValidationError};

#[derive(Debug, PartialEq, Eq)]
struct SignatureCall {
    algorithm: AlgorithmIdentifierOwned,
    moment: Option<Moment>,
    public_key: SubjectPublicKeyInfoOwned,
}

#[derive(Debug)]
struct FixedConstraint {
    constraint: AlgorithmUsageConstraint,
    calls: Mutex<Vec<SignatureCall>>,
}

impl AlgorithmUsagePolicy for FixedConstraint {
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
        self.calls.lock().expect("calls").push(SignatureCall {
            algorithm: algorithm.clone(),
            moment,
            public_key: key.expect("issuer public key").clone(),
        });
        self.constraint.clone()
    }
}

fn moment(value: &str) -> Moment {
    Moment::parse_rfc3339(value).expect("moment")
}

fn check(constraint: AlgorithmUsageConstraint, control_time: Moment) -> Result<Moment, LtvError> {
    let load = |name| {
        let bytes = std::fs::read(sigis_testdata::certvalidator(&[
            "ades",
            "time-slide",
            "certs",
            name,
        ]))
        .expect("fixture");
        crate::Cert::from_pem_or_der(&bytes).expect("certificate")
    };
    let leaf = load("alice.crt");
    let issuer = load("interm.crt");
    let algorithm = leaf.decoded().signature_algorithm().clone();
    let key = issuer.public_key();
    let policy = Arc::new(FixedConstraint {
        constraint,
        calls: Mutex::new(Vec::new()),
    });
    let ctx = ValidationContext::builder()
        .algorithm_policy(policy.clone())
        .moment(control_time)
        .build()
        .expect("context");
    let result = apply_algo_policy(&ctx, &algorithm, control_time, &key);
    assert_eq!(
        *policy.calls.lock().expect("calls"),
        vec![SignatureCall {
            algorithm,
            moment: Some(control_time),
            public_key: key,
        }],
        "the production helper must evaluate the actual signature and issuer key at control time"
    );
    result
}

#[test]
fn denied_timed_signature_uses_exact_minimum_including_equality() {
    let cutoff = moment("2020-11-29T00:04:00Z");
    for (control, expected) in [
        (
            moment("2020-11-29T00:03:59Z"),
            moment("2020-11-29T00:03:59Z"),
        ),
        (cutoff, cutoff),
        (moment("2020-11-29T00:04:01Z"), cutoff),
    ] {
        // The policy result is deliberately denied even when control < cutoff:
        // the helper must implement min(control, cutoff), not re-evaluate policy.
        let constraint = AlgorithmUsageConstraint {
            allowed: false,
            failure_reason: Some("Timed signature prohibition".into()),
            not_allowed_after: Some(cutoff),
        };
        assert_eq!(check(constraint, control).expect("timed denial"), expected);
    }
}

#[test]
fn permanent_denial_with_date_like_reason_is_a_typed_error() {
    let reason = "Disallowed since 2020-11-29T00:04:00Z";
    let error = check(
        AlgorithmUsageConstraint::denied(reason),
        moment("2020-11-29T00:05:00Z"),
    )
    .expect_err("a reason string cannot supply a recovery horizon");
    match error {
        LtvError::Validation(ValidationError::DisallowedAlgorithm { msg, banned_since }) => {
            assert_eq!(banned_since, None);
            assert!(
                msg.contains("banned outright without time constraints"),
                "{msg}"
            );
            assert!(msg.contains(reason), "{msg}");
        }
        other => panic!("expected the typed permanent denial, got {other:?}"),
    }
}

#[test]
fn permanent_denial_without_reason_is_still_a_typed_error() {
    let error = check(
        AlgorithmUsageConstraint {
            allowed: false,
            failure_reason: None,
            not_allowed_after: None,
        },
        moment("2020-11-29T00:05:00Z"),
    )
    .expect_err("permanent denial");
    assert!(
        matches!(
            &error,
            LtvError::Validation(ValidationError::DisallowedAlgorithm {
                banned_since: None,
                ..
            })
        ),
        "{error:?}"
    );
}

#[test]
fn allowed_signature_ignores_incidental_cutoff_metadata() {
    let control = moment("2020-11-29T00:05:00Z");
    for cutoff in [
        moment("2020-11-29T00:04:00Z"),
        control,
        moment("2020-11-29T00:06:00Z"),
    ] {
        let constraint = AlgorithmUsageConstraint {
            allowed: true,
            failure_reason: Some("Incidental policy metadata".into()),
            not_allowed_after: Some(cutoff),
        };
        assert_eq!(check(constraint, control).expect("allowed"), control);
    }
}
