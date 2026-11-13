//! Supplemental actual-path tolerance controls; no upstream-function credit.
//! Certificates and signatures are unchanged accepted fixtures. Tolerance is
//! applied to issued certificates, never to explicit trust-anchor qualifiers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{load_cert, load_nist_cert};
use const_oid::ObjectIdentifier;
use der::asn1::Ia5String;
use sigis_pki_certvalidator::authority::TrustQualifiers;
use sigis_pki_certvalidator::{
    validate_path_detailed, Cert, PathFailure, PkixValidationParams, TrustAnchor,
    ValidationContext, ValidationPath,
};
use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
use sigis_pki_core::errors::ValidationError;
use sigis_pki_core::time::Moment;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use x509_cert::ext::pkix::{constraints::name::GeneralSubtree, name::GeneralName};

const OFFSET: Duration = Duration::from_secs(1800);

fn hash(bytes: &[u8]) -> String {
    sigis_pki_core::algorithms::DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn pss_path() -> ValidationPath {
    ValidationPath::new(
        TrustAnchor::new(load_cert(&["testing-ca-pss", "root.cert.pem"])),
        vec![load_cert(&["testing-ca-pss", "interm.cert.pem"])],
        Some(load_cert(&["testing-ca-pss", "signer1.cert.pem"])),
    )
}

fn nist_path(ca: &str, ee: &str, qualifiers: TrustQualifiers) -> ValidationPath {
    ValidationPath::new(
        TrustAnchor::with_qualifiers(load_nist_cert("TrustAnchorRootCertificate.crt"), qualifiers),
        vec![load_nist_cert(ca)],
        Some(load_nist_cert(ee)),
    )
}

fn context(path: &ValidationPath, at: Moment, seconds: u64) -> ValidationContext {
    let context = ValidationContext::builder()
        .trust_anchor(path.trust_anchor().clone())
        .moment(at)
        .best_signature_time(at)
        .time_tolerance(Duration::from_secs(seconds))
        .revocation_mode("none")
        .build()
        .unwrap();
    assert_eq!(context.moment(), at);
    assert_eq!(context.best_signature_time(), at);
    assert_eq!(context.timing().time_tolerance.as_secs(), seconds);
    assert!(context.fetchers().is_empty());
    context
}

fn record(case: &str, path: &ValidationPath, at: Moment, seconds: u64) {
    eprintln!(
        "CV_TOLERANCE_INPUT {}",
        serde_json::json!({
            "case":case,"moment":at.to_string(),"tolerance_seconds":seconds,
            "certificates":path.certs().iter().map(|cert|serde_json::json!({
                "sha256":hash(cert.der()),"not_before":cert.not_before().to_string(),
                "not_after":cert.not_after().to_string()
            })).collect::<Vec<_>>()
        })
    );
}

fn assert_time_failure(
    failure: &PathFailure,
    path: &ValidationPath,
    before: bool,
    leaf: bool,
    certificate: &Cert,
) {
    assert_eq!(failure.path.as_ref(), Some(path));
    assert_eq!(failure.is_ee_cert, leaf);
    assert!(!failure.is_side_validation);
    if before {
        assert!(matches!(failure.error, ValidationError::NotYetValid { .. }));
        assert_eq!(failure.time_horizon, None);
    } else {
        assert!(matches!(failure.error, ValidationError::Expired { .. }));
        assert_eq!(failure.time_horizon, Some(certificate.not_after()));
    }
}

#[test]
fn leaf_not_before_and_not_after_use_the_selected_tolerance() {
    let path = pss_path();
    let leaf = path.leaf().unwrap();
    for before in [true, false] {
        let at = if before {
            leaf.not_before().minus(OFFSET)
        } else {
            leaf.not_after().plus(OFFSET)
        };
        // Isolate the leaf boundary: the actual intermediate is valid at at.
        assert!(path
            .intermediates()
            .iter()
            .all(|c| c.not_before() <= at && at <= c.not_after()));
        for seconds in [30, 3600] {
            let ctx = context(&path, at, seconds);
            let snapshot = format!("{ctx:?}");
            record(
                if before {
                    "leaf-not-before"
                } else {
                    "leaf-not-after"
                },
                &path,
                at,
                seconds,
            );
            let result = validate_path_detailed(&ctx, &path, None);
            if seconds == 30 {
                assert_time_failure(&result.unwrap_err(), &path, before, true, leaf);
            } else {
                result.expect("one hour covers the actual thirty-minute leaf boundary");
            }
            assert_eq!(format!("{ctx:?}"), snapshot);
        }
    }
}

#[test]
fn intermediate_boundaries_are_tolerated_without_hiding_the_failing_position() {
    for (before, ca, ee) in [
        (
            true,
            "GoodCACert.crt",
            "Validpre2000UTCnotBeforeDateTest3EE.crt",
        ),
        (
            false,
            "BadnotAfterDateCACert.crt",
            "InvalidCAnotAfterDateTest5EE.crt",
        ),
    ] {
        let path = nist_path(ca, ee, TrustQualifiers::default());
        let intermediate = &path.intermediates()[0];
        let at = if before {
            intermediate.not_before().minus(OFFSET)
        } else {
            intermediate.not_after().plus(OFFSET)
        };
        let leaf = path.leaf().unwrap();
        // Unlike a same-boundary chain, the EE itself is valid here.
        assert!(leaf.not_before() <= at && at <= leaf.not_after());
        for seconds in [30, 3600] {
            let ctx = context(&path, at, seconds);
            record(
                if before {
                    "intermediate-not-before"
                } else {
                    "intermediate-not-after"
                },
                &path,
                at,
                seconds,
            );
            let result = validate_path_detailed(&ctx, &path, None);
            if seconds == 30 {
                assert_time_failure(&result.unwrap_err(), &path, before, false, intermediate);
            } else {
                result.expect("tolerance also applies to the actual intermediate");
            }
            assert_eq!(ctx.moment(), at);
        }
    }
}

#[test]
fn enforced_anchor_qualifiers_stay_strict_while_default_anchor_is_unbounded() {
    let root = load_cert(&["testing-ca-pss", "root.cert.pem"]);
    for before in [true, false] {
        let at = if before {
            root.not_before().minus(OFFSET)
        } else {
            root.not_after().plus(OFFSET)
        };
        let unbounded = ValidationPath::new(TrustAnchor::new(root.clone()), Vec::new(), None);
        let enforced = ValidationPath::new(
            TrustAnchor::with_enforced_validity(root.clone()),
            Vec::new(),
            None,
        );
        for seconds in [30, 3600] {
            validate_path_detailed(&context(&unbounded, at, seconds), &unbounded, None)
                .expect("ordinary anchors are trusted without certificate validity bounds");
            record("enforced-anchor", &enforced, at, seconds);
            let failure = validate_path_detailed(&context(&enforced, at, seconds), &enforced, None)
                .expect_err("issued-certificate tolerance never extends an anchor qualifier");
            assert_time_failure(&failure, &enforced, before, false, &root);
            assert!(failure.error.to_string().contains("the trust anchor"));
        }
    }
}

fn dns_subtree(value: &str) -> GeneralSubtree {
    GeneralSubtree {
        base: GeneralName::DnsName(Ia5String::new(value).unwrap()),
        minimum: 0,
        maximum: None,
    }
}

fn permitted(value: &str) -> PkixValidationParams {
    PkixValidationParams {
        initial_permitted_subtrees: Some(vec![dns_subtree(value)]),
        ..Default::default()
    }
}

fn dns_path(anchor_permitted: Option<&str>) -> ValidationPath {
    nist_path(
        "nameConstraintsDNS1CACert.crt",
        "ValidDNSnameConstraintsTest30EE.crt",
        TrustQualifiers {
            standard_parameters: anchor_permitted.map(permitted),
            ..Default::default()
        },
    )
}

#[test]
fn additional_permitted_subtree_runs_keep_tolerance_and_real_name_denials() {
    let allowed = dns_path(Some("testcertificates.gov"));
    let at = allowed.leaf().unwrap().not_after().plus(OFFSET);
    let caller = permitted("testserver.testcertificates.gov");
    record("extra-permitted-allowed", &allowed, at, 3600);
    validate_path_detailed(&context(&allowed, at, 3600), &allowed, Some(&caller))
        .expect("both the first and extra permitted-subtree runs retain tolerance");
    assert!(matches!(
        validate_path_detailed(&context(&allowed, at, 30), &allowed, Some(&caller))
            .unwrap_err()
            .error,
        ValidationError::Expired { .. }
    ));
    // Caller set permits the actual SAN, but the second (anchor) set does not.
    // The intersection must remain a genuine name denial, not an expiry error.
    let denied = dns_path(Some("other.testcertificates.gov"));
    let failure = validate_path_detailed(&context(&denied, at, 3600), &denied, Some(&caller))
        .expect_err("tolerance cannot remove the independent anchor name restriction");
    assert_eq!(failure.path.as_ref(), Some(&denied));
    assert!(matches!(failure.error, ValidationError::PathValidation(_)));
    assert!(failure.error.to_string().contains("names"));
    assert!(failure.error.to_string().contains("namespace"));
}

#[test]
fn relaxed_excluded_subtree_retry_keeps_tolerance_and_exclusion_reason() {
    let path = dns_path(None);
    let at = path.leaf().unwrap().not_after().plus(OFFSET);
    let ctx = context(&path, at, 3600);
    let nonmatching = PkixValidationParams {
        initial_excluded_subtrees: Some(vec![dns_subtree("other.testcertificates.gov")]),
        ..Default::default()
    };
    validate_path_detailed(&ctx, &path, Some(&nonmatching))
        .expect("a tolerated certificate and a disjoint excluded name remain valid");
    let matching = PkixValidationParams {
        initial_excluded_subtrees: Some(vec![dns_subtree("testserver.testcertificates.gov")]),
        ..Default::default()
    };
    record("excluded-relaxed-retry", &path, at, 3600);
    let failure = validate_path_detailed(&ctx, &path, Some(&matching))
        .expect_err("the actual SAN remains excluded");
    assert!(matches!(failure.error, ValidationError::PathValidation(_)));
    assert_eq!(failure.path.as_ref(), Some(&path));
    // certval's retry with excluded subtrees removed must pass validity, so
    // the real constraint is classified as an exclusion rather than expiry
    // or an invented permitted-namespace failure.
    assert!(failure.error.to_string().contains("some names"));
    assert!(failure.error.to_string().contains("excluded"));
}

#[derive(Debug)]
struct ActualMomentPolicy {
    issuer: SubjectPublicKeyInfoOwned,
    at: Moment,
    cutoff: Moment,
    deny: bool,
    seen: Mutex<Vec<Moment>>,
}

impl AlgorithmUsagePolicy for ActualMomentPolicy {
    fn signature_algorithm_allowed(
        &self,
        _: &AlgorithmIdentifierOwned,
        at: Option<Moment>,
        issuer: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        assert_eq!(
            at,
            Some(self.at),
            "tolerance must not slide policy's actual clock"
        );
        self.seen.lock().unwrap().push(at.unwrap());
        if self.deny && issuer == Some(&self.issuer) && at.unwrap() >= self.cutoff {
            AlgorithmUsageConstraint {
                not_allowed_after: Some(self.cutoff),
                ..AlgorithmUsageConstraint::denied("actual-time leaf algorithm denial")
            }
        } else {
            AlgorithmUsageConstraint::allowed()
        }
    }

    fn digest_algorithm_allowed(
        &self,
        _: &ObjectIdentifier,
        _: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::allowed()
    }
}

#[test]
fn tolerated_leaf_still_enforces_typed_algorithm_cutoff_at_actual_moment() {
    let path = pss_path();
    let leaf = path.leaf().unwrap();
    let at = leaf.not_after().plus(OFFSET);
    let cutoff = leaf.not_after().plus(Duration::from_secs(900));
    for deny in [false, true] {
        let policy = Arc::new(ActualMomentPolicy {
            issuer: path.intermediates()[0].public_key(),
            at,
            cutoff,
            deny,
            seen: Mutex::default(),
        });
        let ctx = ValidationContext::builder()
            .trust_anchor(path.trust_anchor().clone())
            .moment(at)
            .best_signature_time(at)
            .time_tolerance(Duration::from_secs(3600))
            .revocation_mode("none")
            .algorithm_policy(policy.clone())
            .build()
            .unwrap();
        record("algorithm-actual-moment", &path, at, 3600);
        let result = validate_path_detailed(&ctx, &path, None);
        if deny {
            let failure = result.expect_err("validity tolerance is not algorithm permission");
            assert_eq!(failure.path.as_ref(), Some(&path));
            assert!(failure.is_ee_cert && !failure.is_side_validation);
            assert_eq!(failure.time_horizon, Some(cutoff));
            assert!(
                matches!(failure.error, ValidationError::DisallowedAlgorithm { banned_since: Some(t), .. } if t == cutoff)
            );
        } else {
            result.expect("positive actual-time policy control under tolerated validity");
        }
        assert_eq!(*policy.seen.lock().unwrap(), vec![at, at]);
        assert_eq!(ctx.moment(), at);
        assert_eq!(ctx.best_signature_time(), at);
    }
}
