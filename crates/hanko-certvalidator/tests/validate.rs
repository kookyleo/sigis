// Port of the non-data-driven tests in pyhanko-certvalidator
// `tests/test_validate.py` (MIT, see LICENSE-pyHanko).

mod common;

use std::sync::Arc;

use common::{load_cert, moment, read};
use hanko_certvalidator::{
    build_paths, validate_path, NonRevokedStatusAssertion, TrustAnchor, ValidationContext,
    ValidationPath,
};
use hanko_core::algorithms::DisallowWeakAlgorithmsPolicy;
use hanko_core::errors::ValidationError;

fn weak_md_only() -> Arc<DisallowWeakAlgorithmsPolicy> {
    Arc::new(DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&[
        "md2", "md5",
    ]))
}

fn three_cert_path(dir: &str, leaf: &str, at: &str, mode: &str) -> Result<(), ValidationError> {
    let cert = load_cert(&[dir, leaf]);
    let ctx = ValidationContext::builder()
        .trust_root(load_cert(&[dir, "root.cert.pem"]))
        .other_cert(load_cert(&[dir, "interm.cert.pem"]))
        .moment(moment(at))
        .revocation_mode(mode)
        .algorithm_policy(weak_md_only())
        .build()?;
    let paths = build_paths(&ctx, &cert)?;
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].len(), 3);
    validate_path(&ctx, &paths[0], None)
}

#[test]
fn test_rsassa_pss() {
    three_cert_path(
        "testing-ca-pss",
        "signer1.cert.pem",
        "2021-05-03T00:00:00Z",
        "soft-fail",
    )
    .expect("valid");
}

#[test]
fn test_rsassa_pss_exclusive() {
    three_cert_path(
        "testing-ca-pss-exclusive",
        "signer1.cert.pem",
        "2021-05-03T00:00:00Z",
        "soft-fail",
    )
    .expect("valid");
}

#[test]
fn test_ed25519() {
    three_cert_path(
        "testing-ca-ed25519",
        "signer.cert.pem",
        "2020-11-01T00:00:00Z",
        "soft-fail",
    )
    .expect("valid");
}

/// pyHanko validates Ed448 paths. Neither certval nor this crate supports
/// Ed448 yet, so the port asserts a clean validation failure instead (see
/// PORTING.md).
#[test]
fn test_ed448_known_divergence() {
    let err = three_cert_path(
        "testing-ca-ed448",
        "signer.cert.pem",
        "2020-11-01T00:00:00Z",
        "soft-fail",
    )
    .expect_err("Ed448 is not supported");
    assert!(err.is_path_validation_error(), "{err:?}");
}

#[test]
fn test_assert_no_revinfo_needed_by_fiat() {
    let cert = load_cert(&["testing-ca-pss", "signer1.cert.pem"]);
    let at = moment("2021-05-03T00:00:00Z");
    let ctx = ValidationContext::builder()
        .trust_root(load_cert(&["testing-ca-pss", "root.cert.pem"]))
        .other_cert(load_cert(&["testing-ca-pss", "interm.cert.pem"]))
        .moment(at)
        .revocation_mode("require")
        .assertion(NonRevokedStatusAssertion {
            cert_sha256: cert.sha256(),
            at,
        })
        .build()
        .expect("context");
    let paths = build_paths(&ctx, &cert).expect("paths");
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].len(), 3);
    // The intermediate has no assertion: "require" must fail for it, which
    // shows that the assertion is what lets the leaf through.
    let err = validate_path(&ctx, &paths[0], None).expect_err("intermediate lacks revinfo");
    assert!(err.is_insufficient_revinfo(), "{err:?}");
    assert!(
        err.to_string().contains("intermediate certificate 1"),
        "{err}"
    );

    let interm = load_cert(&["testing-ca-pss", "interm.cert.pem"]);
    let ctx = ValidationContext::builder()
        .trust_root(load_cert(&["testing-ca-pss", "root.cert.pem"]))
        .other_cert(interm.clone())
        .moment(at)
        .revocation_mode("require")
        .assertion(NonRevokedStatusAssertion {
            cert_sha256: cert.sha256(),
            at,
        })
        .assertion(NonRevokedStatusAssertion {
            cert_sha256: interm.sha256(),
            at,
        })
        .build()
        .expect("context");
    validate_path(&ctx, &paths[0], None).expect("valid by fiat");
}

#[test]
fn test_multitasking_ocsp() {
    // Regression test: the same responder ID is used in OCSP responses for
    // different issuers in the same chain of trust.
    let ctx = ValidationContext::builder()
        .trust_root(load_cert(&["multitasking-ocsp", "root.cert.pem"]))
        .other_cert(load_cert(&["multitasking-ocsp", "interm.cert.pem"]))
        .revocation_mode("hard-fail")
        .ocsp_response(read(&["multitasking-ocsp", "ocsp-resp-interm.der"]))
        .ocsp_response(read(&["multitasking-ocsp", "ocsp-resp-alice.der"]))
        .moment(moment("2021-08-19T12:20:44Z"))
        .build()
        .expect("context");
    let cert = load_cert(&["multitasking-ocsp", "alice.cert.pem"]);
    let paths = build_paths(&ctx, &cert).expect("paths");
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].len(), 3);
    validate_path(&ctx, &paths[0], None).expect("valid");
}

fn root_only_path(enforce: bool, at: &str) -> Result<(), ValidationError> {
    let ca = load_cert(&["testing-ca-ed25519", "root.cert.pem"]);
    let anchor = if enforce {
        TrustAnchor::with_enforced_validity(ca)
    } else {
        TrustAnchor::new(ca)
    };
    let ctx = ValidationContext::builder()
        .trust_anchor(anchor.clone())
        .moment(moment(at))
        .build()
        .expect("context");
    validate_path(&ctx, &ValidationPath::new(anchor, Vec::new(), None), None)
}

#[test]
fn test_root_time_bound() {
    root_only_path(true, "2019-01-01T00:00:00Z").expect("valid");
}

#[test]
fn test_root_expired() {
    let err = root_only_path(true, "3124-01-01T00:00:00Z").expect_err("expired");
    assert!(matches!(err, ValidationError::Expired { .. }), "{err:?}");
    assert!(
        err.to_string().contains("the trust anchor expired"),
        "{err}"
    );
}

#[test]
fn test_root_not_yet_valid() {
    let err = root_only_path(true, "1999-01-01T00:00:00Z").expect_err("not yet valid");
    assert!(
        matches!(err, ValidationError::NotYetValid { .. }),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .contains("the trust anchor is not valid until"),
        "{err}"
    );
}

#[test]
fn test_basic_certificate_validator_root_expiration_unquestioned() {
    for at in [
        "1999-01-01T00:00:00Z",
        "2019-01-01T00:00:00Z",
        "3124-01-01T00:00:00Z",
    ] {
        root_only_path(false, at).unwrap_or_else(|e| panic!("{at}: {e}"));
    }
}

#[test]
fn test_extreme_not_after() {
    let cert = load_cert(&["testing-ca-ed25519", "signer1-indefinite.cert.pem"]);
    let anchor = TrustAnchor::new(load_cert(&["testing-ca-ed25519", "interm.cert.pem"]));
    let ctx = ValidationContext::builder()
        .trust_anchor(anchor.clone())
        .moment(moment("3124-01-01T00:00:00Z"))
        .build()
        .expect("context");
    validate_path(
        &ctx,
        &ValidationPath::new(anchor, Vec::new(), Some(cert)),
        None,
    )
    .expect("valid");
}

#[test]
fn unknown_issuer_is_a_path_building_error() {
    let ctx = ValidationContext::builder()
        .trust_root(load_cert(&["testing-ca-ed25519", "root.cert.pem"]))
        .build()
        .expect("context");
    let err = build_paths(&ctx, &load_cert(&["testing-ca-pss", "signer1.cert.pem"]))
        .expect_err("no path");
    assert!(matches!(err, ValidationError::PathBuilding(_)), "{err:?}");
    assert!(!err.is_path_validation_error());
}

#[test]
fn malformed_revinfo_is_rejected_at_build_time() {
    let err = ValidationContext::builder()
        .crl(vec![0x30, 0x03, 0x02, 0x01])
        .build()
        .expect_err("malformed");
    assert!(matches!(err, ValidationError::Malformed(_)), "{err:?}");
    let err = ValidationContext::builder()
        .ocsp_response(b"garbage".to_vec())
        .build()
        .expect_err("malformed");
    assert!(matches!(err, ValidationError::Malformed(_)), "{err:?}");
}

#[test]
fn test_fail_validation_if_required_delta_crl_not_available() {
    let cert = common::load_nist_cert("InvaliddeltaCRLTest4EE.crt");
    let ctx = ValidationContext::builder()
        .trust_root(common::load_nist_cert("TrustAnchorRootCertificate.crt"))
        .other_cert(common::load_nist_cert("deltaCRLCA1Cert.crt"))
        .crl(common::load_nist_crl("deltaCRLCA1CRL.crl"))
        .crl(common::load_nist_crl("TrustAnchorRootCRL.crl"))
        .revocation_mode("require")
        .algorithm_policy(weak_md_only())
        .moment(common::pkits_moment())
        .build()
        .expect("context");
    let paths = build_paths(&ctx, &cert).expect("paths");
    assert_eq!(paths.len(), 1);
    let err = validate_path(&ctx, &paths[0], None).expect_err("delta CRL required");
    assert!(err.is_insufficient_revinfo(), "{err:?}");
    assert!(
        regex::Regex::new(".*Delta CRL.*")
            .expect("regex")
            .is_match(&err.to_string()),
        "{err}"
    );
}
