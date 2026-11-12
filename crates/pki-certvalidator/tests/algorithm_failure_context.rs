//! Algorithm-policy failures retain the actual certificate position and path.
//!
//! Supplemental regressions for certvalidator's PathValidationError.from_state;
//! no additional upstream-function credit or cutoff API is introduced here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::{load_cert, moment, read};
use const_oid::ObjectIdentifier;
use sigis_pki_certvalidator::{
    build_paths, validate_path, validate_path_detailed, ValidationContext, ValidationPath,
};
use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
use sigis_pki_core::time::Moment;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const AT: &str = "2021-08-19T12:20:44Z";
const REASON: &str = "Permanent policy refusal; reference date 2001-02-03T04:05:06Z";

#[derive(Debug)]
struct IssuerDenial {
    denied_issuer: Option<SubjectPublicKeyInfoOwned>,
}

impl AlgorithmUsagePolicy for IssuerDenial {
    fn digest_algorithm_allowed(
        &self,
        _: &ObjectIdentifier,
        _: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::allowed()
    }

    fn signature_algorithm_allowed(
        &self,
        _: &AlgorithmIdentifierOwned,
        at: Option<Moment>,
        issuer: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        if self
            .denied_issuer
            .as_ref()
            .is_some_and(|key| issuer == Some(key))
        {
            assert_eq!(at, Some(moment(AT)));
            AlgorithmUsageConstraint::denied(REASON)
        } else {
            AlgorithmUsageConstraint::allowed()
        }
    }
}

fn context(deny_issuer: Option<&str>, include_ocsp: bool) -> ValidationContext {
    let mut builder = ValidationContext::builder()
        .trust_root(load_cert(&["multitasking-ocsp", "root.cert.pem"]))
        .other_cert(load_cert(&["multitasking-ocsp", "interm.cert.pem"]))
        .moment(moment(AT))
        .best_signature_time(moment("2021-08-18T11:22:33Z"))
        .revocation_mode("require")
        .algorithm_policy(Arc::new(IssuerDenial {
            denied_issuer: deny_issuer.map(|name| {
                load_cert(&["multitasking-ocsp", &format!("{name}.cert.pem")]).public_key()
            }),
        }));
    if include_ocsp {
        builder = builder
            .ocsp_response(read(&["multitasking-ocsp", "ocsp-resp-interm.der"]))
            .ocsp_response(read(&["multitasking-ocsp", "ocsp-resp-alice.der"]));
    }
    builder.build().unwrap()
}

fn real_path(ctx: &ValidationContext) -> ValidationPath {
    let leaf = load_cert(&["multitasking-ocsp", "alice.cert.pem"]);
    let paths = build_paths(ctx, &leaf).unwrap();
    assert_eq!(paths.len(), 1);
    let path = paths.into_iter().next().unwrap();
    assert_eq!(path.len(), 3);
    assert_eq!(path.leaf(), Some(&leaf));
    assert_eq!(
        path.trust_anchor().cert(),
        &load_cert(&["multitasking-ocsp", "root.cert.pem"])
    );
    assert_eq!(
        path.intermediates(),
        &[load_cert(&["multitasking-ocsp", "interm.cert.pem"])]
    );
    path
}

fn assert_algorithm_failure(issuer: &str, is_leaf: bool, description: &str) {
    let control = context(None, true);
    let original_path = real_path(&control);
    validate_path(&control, &original_path, None).unwrap();

    let denied = context(Some(issuer), true);
    assert_eq!(real_path(&denied), original_path);
    let failure = validate_path_detailed(&denied, &original_path, None).unwrap_err();
    assert_eq!(failure.path.as_ref(), Some(&original_path));
    assert_eq!(failure.error.class_name(), "DisallowedAlgorithmError");
    assert!(failure.error.is_instance_of("PathValidationError"));
    assert!(failure.error.to_string().contains(description));
    assert!(failure.error.to_string().contains(REASON));
    assert!(!failure.is_side_validation);
    // A date in a permanent reason is not policy metadata.
    assert_eq!(failure.time_horizon, None);
    assert_eq!(failure.is_ee_cert, is_leaf);

    let stripped = validate_path(&denied, &original_path, None).unwrap_err();
    assert_eq!(stripped, failure.error);
    assert_eq!(failure.path.as_ref(), Some(&original_path));
}

#[test]
fn leaf_algorithm_denial_retains_leaf_context_and_original_path() {
    assert_algorithm_failure("interm", true, "the end-entity certificate");
}

#[test]
fn intermediate_algorithm_denial_retains_intermediate_context_and_original_path() {
    assert_algorithm_failure("root", false, "intermediate certificate 1");
}

#[test]
fn allowed_algorithms_do_not_replace_required_ocsp_evidence() {
    let control = context(None, true);
    let original_path = real_path(&control);
    validate_path(&control, &original_path, None).unwrap();

    let failure = validate_path_detailed(&context(None, false), &original_path, None).unwrap_err();
    assert!(failure.error.is_insufficient_revinfo(), "{failure:?}");
    assert_eq!(failure.path.as_ref(), Some(&original_path));
}
