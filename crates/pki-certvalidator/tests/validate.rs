// Port of the non-data-driven tests in pyhanko-certvalidator
// `tests/test_validate.py` (MIT, see LICENSE-pyHanko).

mod common;

use std::sync::Arc;

use common::{load_cert, load_nist_cert, load_nist_crl, moment, read};
use sigis_pki_certvalidator::{
    build_paths, validate_path, Cert, NonRevokedStatusAssertion, PkixValidationParams, TrustAnchor,
    ValidationContext, ValidationPath,
};
use sigis_pki_core::algorithms::DisallowWeakAlgorithmsPolicy;
use sigis_pki_core::errors::ValidationError;

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

#[test]
fn test_ed448() {
    three_cert_path(
        "testing-ca-ed448",
        "signer.cert.pem",
        "2020-11-01T00:00:00Z",
        "soft-fail",
    )
    .expect("valid");
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

// --- Fetching and policy qualifiers (pending items of the previous phase) ---

fn user_notice_cases() -> serde_json::Value {
    serde_json::from_slice(&read(&["nist_pkits", "pkits-user-notice.json"])).expect("json")
}

#[test]
fn test_nist_pkits_user_notice() {
    let cases = user_notice_cases();
    let cases: &Vec<serde_json::Value> = cases.as_array().expect("array");
    assert!(!cases.is_empty());
    for case in cases {
        let mut b = ValidationContext::builder()
            .trust_root(load_nist_cert("TrustAnchorRootCertificate.crt"))
            .crl(load_nist_crl("TrustAnchorRootCRL.crl"))
            .moment(moment("2022-05-01T00:00:00Z"))
            .point_in_time_validation(false)
            .revocation_mode("require")
            .algorithm_policy(weak_md_only());
        for c in case["crls"].as_array().into_iter().flatten() {
            b = b.crl(load_nist_crl(c.as_str().expect("crl")));
        }
        for c in case["other_certs"].as_array().into_iter().flatten() {
            b = b.other_cert(load_nist_cert(c.as_str().expect("cert")));
        }
        let ctx = b.build().expect("context");
        let leaf = load_nist_cert(case["cert"].as_str().expect("cert"));
        let params = case.get("params").map(|p| {
            let mut params = PkixValidationParams::default();
            if let Some(set) = p.get("user_initial_policy_set").and_then(|s| s.as_array()) {
                params.user_initial_policy_set = set
                    .iter()
                    .map(|o| o.as_str().expect("oid").parse().expect("oid"))
                    .collect();
            }
            if let Some(b) = p.get("initial_explicit_policy").and_then(|b| b.as_bool()) {
                params.initial_explicit_policy = b;
            }
            params
        });
        assert_eq!(build_paths(&ctx, &leaf).expect("paths").len(), 1);
        let path =
            sigis_pki_certvalidator::find_valid_path(&ctx, &leaf, params.as_ref()).expect("valid");
        let qps = path.qualified_policies().expect("qualified policies");
        assert_eq!(qps.len(), 1, "{}", case["id"]);
        assert_eq!(qps[0].qualifiers.len(), 1, "{} {:?}", case["id"], qps[0]);
        assert_eq!(
            qps[0].user_notice_text().as_deref(),
            case["notice"].as_str(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn test_408020_cps_pointer_qualifier_test20() {
    let ctx = ValidationContext::builder()
        .trust_root(load_nist_cert("TrustAnchorRootCertificate.crt"))
        .other_cert(load_nist_cert("GoodCACert.crt"))
        .crl(load_nist_crl("GoodCACRL.crl"))
        .crl(load_nist_crl("TrustAnchorRootCRL.crl"))
        .moment(moment("2022-05-01T00:00:00Z"))
        .point_in_time_validation(false)
        .revocation_mode("require")
        .algorithm_policy(weak_md_only())
        .build()
        .expect("context");
    let leaf = load_nist_cert("CPSPointerQualifierTest20EE.crt");
    assert_eq!(build_paths(&ctx, &leaf).expect("paths").len(), 1);
    let path = sigis_pki_certvalidator::find_valid_path(&ctx, &leaf, None).expect("valid");
    let qps = path.qualified_policies().expect("qualified policies");
    assert_eq!(qps.len(), 1);
    assert_eq!(qps[0].qualifiers.len(), 1);
    assert_eq!(
        qps[0].cps_uri().as_deref(),
        Some("http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/pki_registration.html#PKITest")
    );
}

#[test]
fn test_building_trust_path_fetched_in_different_orders() {
    let root = load_cert(&["multilayer", "certs", "root.cert.pem"]);
    let middle = load_cert(&["multilayer", "certs", "interm1.cert.pem"]);
    let end = load_cert(&["multilayer", "certs", "interm2.cert.pem"]);
    let alice = load_cert(&["multilayer", "certs", "alice.cert.pem"]);
    let by_name = |n: &str| match n {
        "root" => root.clone(),
        "middle" => middle.clone(),
        _ => end.clone(),
    };
    for order in [
        ["root", "middle", "end"],
        ["root", "end", "middle"],
        ["middle", "root", "end"],
        ["middle", "end", "root"],
    ] {
        let fetched: Vec<Cert> = order.iter().map(|n| by_name(n)).collect();
        let ctx = ValidationContext::builder()
            .trust_root(root.clone())
            .fetchers(sigis_pki_core::fetch::Fetchers {
                cert: Some(Arc::new(common::fakes::FixedIssuers(fetched))),
                ..Default::default()
            })
            .build()
            .expect("context");
        let paths = build_paths(&ctx, &alice).expect("paths");
        let names: Vec<Vec<String>> = paths
            .iter()
            .map(|p| {
                let mut v = vec![certval::name_to_string(p.trust_anchor().cert().subject())];
                v.extend(
                    p.intermediates()
                        .iter()
                        .map(|c| certval::name_to_string(c.subject())),
                );
                v
            })
            .collect();
        assert!(
            names.iter().any(|n| n.len() == 3
                && n[0].contains("Root CA")
                && n[1].contains("Intermediate CA 1")
                && n[2].contains("Intermediate CA 2")),
            "{order:?}: {names:?}"
        );
    }
}

#[test]
fn test_do_not_fetch_crl_if_cache_sufficient() {
    let dir = ["ades", "time-slide"];
    let crl = |n: &str| read(&[dir[0], dir[1], n]);
    let crl_fetcher = Arc::new(common::fakes::Failing::default());
    let ctx = ValidationContext::builder()
        .trust_root(load_cert(&[dir[0], dir[1], "certs", "root.crt"]))
        .other_cert(load_cert(&[dir[0], dir[1], "certs", "interm.crt"]))
        .crl(crl("interm-2020-10-01.crl"))
        .crl(crl("root-2020-10-01.crl"))
        .fetchers(sigis_pki_core::fetch::Fetchers {
            ocsp: Some(Arc::new(common::fakes::Failing::default())),
            crl: Some(crl_fetcher.clone()),
            cert: Some(Arc::new(common::fakes::Failing::default())),
        })
        .moment(moment("2020-10-02T00:00:00Z"))
        .revocation_mode("require")
        .build()
        .expect("context");
    assert_eq!(
        crl_fetcher.calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let leaf = load_cert(&[dir[0], dir[1], "certs", "alice.crt"]);
    let paths = build_paths(&ctx, &leaf).expect("paths");
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].len(), 3);
    validate_path(&ctx, &paths[0], None).expect("valid");
    assert_eq!(
        crl_fetcher.calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn test_41503_invalid_deltacrl_test3_combine_cache_with_fetched() {
    let fetcher = Arc::new(common::fakes::FixedCrls(
        vec![load_nist_crl("deltaCRLCA1deltaCRL.crl")],
        Default::default(),
    ));
    let ctx = ValidationContext::builder()
        .trust_root(load_nist_cert("TrustAnchorRootCertificate.crt"))
        .other_cert(load_nist_cert("deltaCRLCA1Cert.crt"))
        .crl(load_nist_crl("deltaCRLCA1CRL.crl"))
        .crl(load_nist_crl("TrustAnchorRootCRL.crl"))
        .fetchers(common::fakes::with_crls(fetcher))
        .moment(moment("2022-05-01T00:00:00Z"))
        .point_in_time_validation(false)
        .revocation_mode("require")
        .algorithm_policy(weak_md_only())
        .build()
        .expect("context");
    let leaf = load_nist_cert("InvaliddeltaCRLTest4EE.crt");
    let paths = build_paths(&ctx, &leaf).expect("paths");
    assert_eq!(paths.len(), 1);
    let e = validate_path(&ctx, &paths[0], None).expect_err("revoked");
    assert_eq!(e.class_name(), "RevokedError");
    assert!(e.to_string().contains("revoked at 08:30:00"), "{e}");
}

#[test]
fn test_context_retrieve_all_crls() {
    let crl1 = load_nist_crl("deltaCRLCA1CRL.crl");
    let crl2 = load_nist_crl("TrustAnchorRootCRL.crl");
    let crl3 = load_nist_crl("deltaCRLCA1deltaCRL.crl");
    let ctx = ValidationContext::builder()
        .trust_root(load_nist_cert("TrustAnchorRootCertificate.crt"))
        .other_cert(load_nist_cert("deltaCRLCA1Cert.crt"))
        .crl(crl1.clone())
        .crl(crl2.clone())
        .fetchers(common::fakes::with_crls(Arc::new(
            common::fakes::FixedCrls(vec![crl3.clone()], Default::default()),
        )))
        .revocation_mode("require")
        .build()
        .expect("context");
    let mut got = ctx.retrieve_crls(&load_nist_cert("InvaliddeltaCRLTest4EE.crt"));
    got.sort();
    let mut want = vec![crl1, crl2, crl3];
    want.sort();
    assert_eq!(got, want);
}

// Supplemental algorithm-horizon regressions using real validation evidence.
// These do not add unique upstream-function credit.
mod algorithm_horizon {
    use std::sync::{Arc, Mutex};

    use crate::common::{load_cert, moment, read};
    use const_oid::ObjectIdentifier;
    use sigis_pki_certvalidator::{
        build_paths, validate_path, validate_path_detailed, ValidationContext, ValidationPath,
    };
    use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
    use sigis_pki_core::errors::ValidationError;
    use sigis_pki_core::time::Moment;
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

    #[derive(Debug)]
    struct IssuerConstraintPolicy {
        issuer_key: SubjectPublicKeyInfoOwned,
        constraint: AlgorithmUsageConstraint,
        expected_time: Moment,
    }

    impl AlgorithmUsagePolicy for IssuerConstraintPolicy {
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
            issuer_key: Option<&SubjectPublicKeyInfoOwned>,
        ) -> AlgorithmUsageConstraint {
            if issuer_key == Some(&self.issuer_key) {
                if self.constraint.allowed {
                    // OCSP_NOCHECK responder provenance uses validation
                    // time; the main certificate still uses best time.
                    assert!(
                        at == Some(self.expected_time)
                            || at == Some(moment("2021-08-19T12:20:44Z")),
                        "unexpected main/responder policy time: {at:?}"
                    );
                } else {
                    // Main-path denials must retain the exact best-time hook.
                    assert_eq!(at, Some(self.expected_time));
                }
                self.constraint.clone()
            } else {
                AlgorithmUsageConstraint::allowed()
            }
        }
    }

    fn context(
        issuer: &str,
        constraint: AlgorithmUsageConstraint,
        include_ocsp: bool,
    ) -> ValidationContext {
        let mut builder = ValidationContext::builder()
            .trust_root(load_cert(&["multitasking-ocsp", "root.cert.pem"]))
            .other_cert(load_cert(&["multitasking-ocsp", "interm.cert.pem"]))
            .moment(moment("2021-08-19T12:20:44Z"))
            // Pinned certvalidator uses best signature time for algorithm
            // checks, independently of the certificate-validity moment.
            .best_signature_time(moment("2021-08-18T11:22:33Z"))
            .revocation_mode("require")
            .algorithm_policy(Arc::new(IssuerConstraintPolicy {
                issuer_key: load_cert(&["multitasking-ocsp", &format!("{issuer}.cert.pem")])
                    .public_key(),
                constraint,
                expected_time: moment("2021-08-18T11:22:33Z"),
            }));
        if include_ocsp {
            builder = builder
                .ocsp_response(read(&["multitasking-ocsp", "ocsp-resp-interm.der"]))
                .ocsp_response(read(&["multitasking-ocsp", "ocsp-resp-alice.der"]));
        }
        builder.build().expect("context")
    }

    fn path(ctx: &ValidationContext) -> ValidationPath {
        let leaf = load_cert(&["multitasking-ocsp", "alice.cert.pem"]);
        let paths = build_paths(ctx, &leaf).expect("real certificate path");
        assert_eq!(paths.len(), 1);
        let path = paths.into_iter().next().expect("one path");
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

    fn assert_failure(
        ctx: &ValidationContext,
        path: &ValidationPath,
        cutoff: Option<Moment>,
        is_ee_cert: bool,
        certificate_description: &str,
        reason: &str,
    ) {
        let failure = validate_path_detailed(ctx, path, None)
            .expect_err("policy must reject the certificate signature");
        assert_eq!(failure.path.as_ref(), Some(path));
        assert_eq!(failure.time_horizon, cutoff);
        assert_eq!(failure.is_ee_cert, is_ee_cert);
        assert!(!failure.is_side_validation);
        assert_eq!(failure.error.class_name(), "DisallowedAlgorithmError");
        assert!(failure.error.is_instance_of("PathValidationError"));
        let ValidationError::DisallowedAlgorithm { msg, banned_since } = &failure.error else {
            panic!("expected typed algorithm failure: {:?}", failure.error);
        };
        assert_eq!(*banned_since, cutoff);
        assert!(msg.contains(certificate_description), "{msg}");
        assert!(msg.contains(reason), "{msg}");

        // The convenience API strips PathFailure; the core error must carry
        // the cutoff itself so that callers cannot lose it at this boundary.
        let error = validate_path(ctx, path, None).expect_err("same policy rejection");
        assert_eq!(error, failure.error);
        assert_eq!(failure.path.as_ref(), Some(path));
    }

    #[test]
    fn certificate_algorithm_cutoff_survives_detailed_and_stripped_path_apis() {
        let cutoff = moment("2021-08-19T12:20:43Z");
        for (issuer, description, is_ee_cert) in [
            ("root", "intermediate certificate 1", false),
            ("interm", "the end-entity certificate", true),
        ] {
            // A successful control exercises the complete path, signature
            // verification and required OCSP checks with these same fixtures.
            let control = context(issuer, AlgorithmUsageConstraint::allowed(), true);
            let original_path = path(&control);
            validate_path(&control, &original_path, None).expect("valid control");

            let reason = "The issuer signature policy has expired";
            let denied = context(
                issuer,
                AlgorithmUsageConstraint {
                    allowed: false,
                    failure_reason: Some(reason.into()),
                    not_allowed_after: Some(cutoff),
                },
                true,
            );
            assert_eq!(path(&denied), original_path);
            assert_failure(
                &denied,
                &original_path,
                Some(cutoff),
                is_ee_cert,
                description,
                reason,
            );
        }
    }

    #[test]
    fn permanent_certificate_denial_does_not_infer_cutoff_from_reason() {
        let reason = "Permanently banned; reference date 2001-02-03T04:05:06Z";
        for (issuer, description, is_ee_cert) in [
            ("root", "intermediate certificate 1", false),
            ("interm", "the end-entity certificate", true),
        ] {
            let control = context(issuer, AlgorithmUsageConstraint::allowed(), true);
            let original_path = path(&control);
            validate_path(&control, &original_path, None).expect("valid control");

            let denied = context(issuer, AlgorithmUsageConstraint::denied(reason), true);
            assert_failure(
                &denied,
                &original_path,
                None,
                is_ee_cert,
                description,
                reason,
            );
        }
    }

    #[test]
    fn allowed_certificate_constraint_with_cutoff_still_requires_revocation() {
        let constraint = AlgorithmUsageConstraint {
            allowed: true,
            failure_reason: Some("Informational date 2001-02-03T04:05:06Z".into()),
            not_allowed_after: Some(moment("2001-02-03T04:05:06Z")),
        };
        let control = context("interm", constraint.clone(), true);
        let original_path = path(&control);
        validate_path(&control, &original_path, None).expect("allowed flag is authoritative");

        let missing = context("interm", constraint, false);
        let failure = validate_path_detailed(&missing, &original_path, None)
            .expect_err("required OCSP cannot be replaced by algorithm metadata");
        assert!(failure.error.is_insufficient_revinfo(), "{failure:?}");
        assert_eq!(failure.path.as_ref(), Some(&original_path));
    }

    #[derive(Debug)]
    struct TimedResponderPolicy {
        issuer_key: SubjectPublicKeyInfoOwned,
        cutoff: Moment,
        calls: Arc<Mutex<Vec<Moment>>>,
    }

    impl AlgorithmUsagePolicy for TimedResponderPolicy {
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
            issuer_key: Option<&SubjectPublicKeyInfoOwned>,
        ) -> AlgorithmUsageConstraint {
            if issuer_key != Some(&self.issuer_key) {
                return AlgorithmUsageConstraint::allowed();
            }
            let at = at.expect("certificate policy must receive its actual time");
            self.calls.lock().unwrap().push(at);
            if at <= self.cutoff {
                AlgorithmUsageConstraint::allowed()
            } else {
                AlgorithmUsageConstraint {
                    allowed: false,
                    failure_reason: Some("Signature policy has expired".into()),
                    not_allowed_after: Some(self.cutoff),
                }
            }
        }
    }

    fn timed_responder_context(
        issuer: &str,
        cutoff: Moment,
    ) -> (ValidationContext, Arc<Mutex<Vec<Moment>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let ctx = ValidationContext::builder()
            .trust_root(load_cert(&["multitasking-ocsp", "root.cert.pem"]))
            .other_cert(load_cert(&["multitasking-ocsp", "interm.cert.pem"]))
            .moment(moment("2021-08-19T12:20:44Z"))
            .best_signature_time(moment("2021-08-18T11:22:33Z"))
            .revocation_mode("require")
            .ocsp_response(read(&["multitasking-ocsp", "ocsp-resp-interm.der"]))
            .ocsp_response(read(&["multitasking-ocsp", "ocsp-resp-alice.der"]))
            .algorithm_policy(Arc::new(TimedResponderPolicy {
                issuer_key: load_cert(&["multitasking-ocsp", &format!("{issuer}.cert.pem")])
                    .public_key(),
                cutoff,
                calls: calls.clone(),
            }))
            .build()
            .expect("context");
        (ctx, calls)
    }

    #[test]
    fn nocheck_ocsp_responder_retains_mandatory_algorithm_policy_at_validation_time() {
        let best = moment("2021-08-18T11:22:33Z");
        let validation = moment("2021-08-19T12:20:44Z");
        let cutoff = moment("2021-08-19T12:20:43Z");
        assert!(best < cutoff && cutoff < validation);
        for (issuer, description) in [
            ("root", "intermediate certificate 1"),
            ("interm", "the end-entity certificate"),
        ] {
            // The main path is allowed at best time. OCSP_NOCHECK only
            // exempts responder revocation, not its algorithm policy at
            // validation time. The original subscriber path must reject.
            let (denied, calls) = timed_responder_context(issuer, cutoff);
            let original_path = path(&denied);
            let failure = validate_path_detailed(&denied, &original_path, None)
                .expect_err("required OCSP responder algorithm policy must reject");
            assert_eq!(failure.error.class_name(), "InsufficientRevinfoError");
            assert!(failure.error.is_insufficient_revinfo(), "{failure:?}");
            assert_eq!(failure.path.as_ref(), Some(&original_path));
            assert!(!failure.is_side_validation);
            assert!(
                failure.error.to_string().contains(description),
                "{failure:?}"
            );
            assert!(
                failure.error.to_string().contains(
                    "Unable to verify OCSP response since response signing certificate could not be validated"
                ),
                "{failure:?}"
            );
            assert_eq!(*calls.lock().unwrap(), vec![best, validation]);

            // These genuine time-dependent policies allow both signatures
            // at equality and later cutoffs; real required OCSP still runs.
            for permitted_cutoff in [validation, moment("2021-08-19T12:20:45Z")] {
                let (control, calls) = timed_responder_context(issuer, permitted_cutoff);
                let original_path = path(&control);
                validate_path(&control, &original_path, None).expect("valid complete control");
                assert_eq!(*calls.lock().unwrap(), vec![best, validation]);
            }
        }
    }
}
