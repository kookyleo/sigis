// Port of pyhanko-certvalidator `tests/test_certificate_validator.py`
// (MIT, see LICENSE-pyHanko).
//
// pyHanko also inspects the qualified policies of the resulting path
// (`path.qualified_policies()`); this crate does not expose the valid policy
// tree yet, so those assertions are pending (see PORTING.md).

mod common;

use std::sync::Arc;

use common::{load_cert, load_nist_cert, moment};
use hanko_certvalidator::{CertificateValidator, PkixValidationParams, ValidationContext};
use hanko_core::algorithms::DisallowWeakAlgorithmsPolicy;

#[test]
fn test_certvalidator_with_params() {
    let cert = load_nist_cert("ValidPolicyMappingTest12EE.crt");
    let ctx = ValidationContext::builder()
        .trust_root(load_nist_cert("TrustAnchorRootCertificate.crt"))
        .other_cert(load_nist_cert("P12Mapping1to3CACert.crt"))
        .revocation_mode("soft-fail")
        .algorithm_policy(Arc::new(
            DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&["md2", "md5"]),
        ))
        .moment(moment("2022-05-01T00:00:00Z"))
        .build()
        .expect("context");
    let params = PkixValidationParams {
        user_initial_policy_set: vec![const_oid::ObjectIdentifier::new_unwrap(
            "2.16.840.1.101.3.2.1.48.1",
        )],
        ..PkixValidationParams::default()
    };
    let path = CertificateValidator::new(&ctx, cert.clone())
        .with_params(params)
        .validate()
        .expect("valid");
    assert_eq!(path.len(), 3);

    // The parameters reach certval: a policy outside the certificate's
    // (mapped) policies must fail.
    let other = PkixValidationParams {
        user_initial_policy_set: vec![const_oid::ObjectIdentifier::new_unwrap(
            "2.16.840.1.101.3.2.1.48.99",
        )],
        initial_explicit_policy: true,
        ..PkixValidationParams::default()
    };
    let err = CertificateValidator::new(&ctx, cert)
        .with_params(other)
        .validate()
        .expect_err("policy mismatch");
    assert!(err.is_path_validation_error(), "{err:?}");
}

#[test]
fn test_self_signed_with_policy() {
    // A corner case in policy processing when the path length is zero.
    let cert = load_cert(&["self-signed-with-policy.crt"]);
    let ctx = ValidationContext::builder()
        .trust_root(cert.clone())
        .build()
        .expect("context");
    let path = CertificateValidator::new(&ctx, cert)
        .validate()
        .expect("valid");
    assert_eq!(path.len(), 1);
}
