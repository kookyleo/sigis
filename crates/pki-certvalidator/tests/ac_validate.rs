// Port of pyhanko-certvalidator `tests/test_ac_validate.py`
// (MIT, see LICENSE-pyHanko). Frozen time 2022-05-01 becomes the default
// moment; tests with an explicit moment pass it.

mod common;

use std::str::FromStr;

use common::{moment, read};
use sigis_pki_certvalidator::ac::{
    validate_ac, verify_ac_crl, verify_ac_ocsp, AcError, AcTargetDescription, AcValidationResult,
};
use sigis_pki_certvalidator::{Cert, TrustAnchor, ValidationContext, ValidationPath};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;

fn aa(parts: &[&str]) -> Vec<u8> {
    let mut p = vec!["attribute-certs", "basic-aa"];
    p.extend_from_slice(parts);
    read(&p)
}

fn cert(parts: &[&str]) -> Cert {
    Cert::from_pem_or_der(&aa(parts)).expect("cert")
}

fn root() -> Cert {
    cert(&["root", "root.crt"])
}

struct Ctx {
    others: Vec<Cert>,
    crls: Vec<Vec<u8>>,
    ocsps: Vec<Vec<u8>>,
    at: &'static str,
    require: bool,
    targets: Option<AcTargetDescription>,
}

impl Ctx {
    fn new(others: Vec<Cert>) -> Self {
        Self {
            others,
            crls: Vec::new(),
            ocsps: Vec::new(),
            at: "2022-05-01T00:00:00Z",
            require: false,
            targets: None,
        }
    }

    fn build(self) -> ValidationContext {
        let mut b = ValidationContext::builder()
            .trust_root(root())
            .moment(moment(self.at));
        for c in self.others {
            b = b.other_cert(c);
        }
        for c in self.crls {
            b = b.crl(c);
        }
        for o in self.ocsps {
            b = b.ocsp_response(o);
        }
        if self.require {
            b = b.revocation_mode("require");
        }
        if let Some(t) = self.targets {
            b = b.acceptable_ac_targets(t);
        }
        b.build().expect("context")
    }
}

fn role_ctx() -> Ctx {
    Ctx::new(vec![
        cert(&["root", "interm-role.crt"]),
        cert(&["interm", "role-aa.crt"]),
    ])
}

fn assert_err(r: Result<AcValidationResult, AcError>, class: &str, pattern: &[&str]) {
    let e = r.expect_err("error");
    assert!(
        e.is_instance_of(class),
        "{} is not a {class}: {e}",
        e.class_name()
    );
    let msg = e.to_string();
    let mut pos = 0;
    for p in pattern {
        let i = msg[pos..]
            .find(p)
            .unwrap_or_else(|| panic!("{p:?} not in {msg:?}"));
        pos += i + p.len();
    }
}

#[test]
fn test_basic_ac_validation_aacontrols_norev() {
    let ac = aa(&["aa", "alice-role-norev.attr.crt"]);
    let r = validate_ac(&role_ctx().build(), &ac, None).expect("valid");
    assert_eq!(r.aa_path.len(), 3);
    assert!(r.approved_attributes.contains_key("role"));
    assert!(!r.approved_attributes.contains_key("group"));
}

#[test]
fn test_basic_ac_validation_bad_signature() {
    let ac = aa(&["aa", "badsig.attr.crt"]);
    assert_err(
        validate_ac(&role_ctx().build(), &ac, None),
        "InvalidCertificateError",
        &["signature could not be verified"],
    );
}

#[test]
fn test_ac_validation_expired() {
    let ac = aa(&["aa", "alice-role-norev.attr.crt"]);
    let mut c = role_ctx();
    c.at = "3000-01-01T00:00:00Z";
    assert_err(
        validate_ac(&c.build(), &ac, None),
        "PathValidationError",
        &["intermediate certificate 1 expired"],
    );
}

#[test]
fn test_basic_ac_validation_sig_algo_mismatch() {
    use sigis_pki_core::asn1::tlv::{encode, Tlv};
    // Replace the envelope's signature algorithm by md5WithRSAEncryption.
    let ac = aa(&["aa", "badsig.attr.crt"]);
    let outer = Tlv::parse_exact(&ac).expect("ac");
    let parts = outer.children().expect("parts");
    let md5_rsa = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00,
    ];
    let mut body = parts[0].raw.to_vec();
    body.extend_from_slice(&md5_rsa);
    body.extend_from_slice(parts[2].raw);
    let tampered = encode(0x30, &body);
    assert_err(
        validate_ac(&role_ctx().build(), &tampered, None),
        "InvalidCertificateError",
        &["algorithm declaration", "does not match"],
    );
}

#[test]
fn test_basic_ac_validation_bad_aa_controls() {
    let ac = aa(&["aa", "alice-role-norev.attr.crt"]);
    let c = Ctx::new(vec![
        cert(&["root", "interm-unrestricted.crt"]),
        cert(&["interm", "role-aa.crt"]),
    ]);
    assert_err(
        validate_ac(&c.build(), &ac, None),
        "PathValidationError",
        &["AA controls extension only present on part "],
    );
}

#[test]
fn test_basic_ac_validation_aa_controls_path_too_long() {
    let ac = aa(&["aa", "alice-role-norev.attr.crt"]);
    let c = Ctx::new(vec![
        cert(&["inbetween", "interm-pathlen-violation.crt"]),
        cert(&["interm", "role-aa.crt"]),
        cert(&["root", "inbetween-aa.crt"]),
    ]);
    assert_err(
        validate_ac(&c.build(), &ac, None),
        "PathValidationError",
        &["exceeds the maximum path length for an AA certificate"],
    );
}

fn targeted() -> (Ctx, Vec<u8>) {
    (
        Ctx::new(vec![
            cert(&["root", "interm-unrestricted.crt"]),
            cert(&["interm", "aa-unrestricted.crt"]),
        ]),
        aa(&["aa", "alice-norev-targeted.attr.crt"]),
    )
}

fn dn(s: &str) -> GeneralName {
    GeneralName::DirectoryName(Name::from_str(s).expect("name"))
}

#[test]
fn test_basic_ac_validation_no_targeting() {
    let (c, ac) = targeted();
    assert_err(
        validate_ac(&c.build(), &ac, None),
        "InvalidCertificateError",
        &["no targeting information"],
    );
}

#[test]
fn test_basic_ac_validation_bad_targeting_name() {
    let (mut c, ac) = targeted();
    c.targets = Some(AcTargetDescription {
        validator_names: vec![dn(
            "CN=Not Validator,OU=Validators,O=Testing Attribute Authority,C=XX",
        )],
        group_memberships: Vec::new(),
    });
    assert_err(
        validate_ac(&c.build(), &ac, None),
        "InvalidCertificateError",
        &["AC targeting"],
    );
}

#[test]
fn test_basic_ac_validation_bad_targeting_group() {
    let (mut c, ac) = targeted();
    c.targets = Some(AcTargetDescription {
        validator_names: Vec::new(),
        group_memberships: vec![dn("OU=Not Validators,O=Testing Attribute Authority,C=XX")],
    });
    assert_err(
        validate_ac(&c.build(), &ac, None),
        "InvalidCertificateError",
        &["AC targeting"],
    );
}

#[test]
fn test_basic_ac_validation_good_targeting_name() {
    let (mut c, ac) = targeted();
    c.targets = Some(AcTargetDescription {
        validator_names: vec![dn(
            "CN=Validator,OU=Validators,O=Testing Attribute Authority,C=XX",
        )],
        group_memberships: Vec::new(),
    });
    let r = validate_ac(&c.build(), &ac, None).expect("valid");
    assert_eq!(r.aa_path.len(), 3);
    assert!(r.approved_attributes.contains_key("role"));
    assert!(r.approved_attributes.contains_key("group"));
}

#[test]
fn test_basic_ac_validation_good_targeting_group() {
    let (mut c, ac) = targeted();
    c.targets = Some(AcTargetDescription {
        validator_names: Vec::new(),
        group_memberships: vec![dn("OU=Validators,O=Testing Attribute Authority,C=XX")],
    });
    let r = validate_ac(&c.build(), &ac, None).expect("valid");
    assert_eq!(r.aa_path.len(), 3);
    assert!(r.approved_attributes.contains_key("role"));
    assert!(r.approved_attributes.contains_key("group"));
}

#[test]
fn test_match_holder_ac() {
    let ac = aa(&["aa", "alice-role-norev.attr.crt"]);
    let alice = cert(&["people-ca", "alice.crt"]);
    validate_ac(&role_ctx().build(), &ac, Some(&alice)).expect("valid");
}

fn oneoff(name: &str) -> Vec<u8> {
    read(&["attribute-certs", "oneoff", name])
}

#[test]
fn test_ac_issuer_search_nonstandard_forms() {
    let alice = cert(&["people-ca", "alice.crt"]);
    for name in [
        "alice-aki-with-issuer-id.attr.crt",
        "alice-v1form-issuer.attr.crt",
        "alice-v2form-only-base-cert-id.attr.crt",
        "alice-v2form-with-base-certificate-id.attr.crt",
        "alice-no-aki-with-base-certificate-id.attr.crt",
        "alice-aki-with-issuer-id-and-base-certificate-id.attr.crt",
    ] {
        validate_ac(&role_ctx().build(), &oneoff(name), Some(&alice))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn test_ac_issuer_search_nonstandard_forms_failures() {
    let alice = cert(&["people-ca", "alice.crt"]);
    for (name, class, pattern) in [
        (
            "alice-v2form-issuer-aki-misaligned.attr.crt",
            "InvalidAttrCertificateError",
            "conflicting",
        ),
        (
            "alice-misleading-aki.attr.crt",
            "PathBuildingError",
            "suitable AA",
        ),
        (
            "alice-v2form-wrong-serial.attr.crt",
            "PathBuildingError",
            "suitable AA",
        ),
    ] {
        assert_err(
            validate_ac(&role_ctx().build(), &oneoff(name), Some(&alice)),
            class,
            &[pattern],
        );
    }
}

#[test]
fn test_match_holder_ac_mismatch() {
    let ac = aa(&["aa", "alice-role-norev.attr.crt"]);
    let bob = cert(&["people-ca", "bob.crt"]);
    assert_err(
        validate_ac(&role_ctx().build(), &ac, Some(&bob)),
        "InvalidCertificateError",
        &["Could not match", "base_certificate_id"],
    );
}

fn ac_path() -> ValidationPath {
    ValidationPath::new(
        TrustAnchor::new(root()),
        vec![cert(&["root", "interm-role.crt"])],
        Some(cert(&["interm", "role-aa.crt"])),
    )
}

fn rev_ctx(
    others: Vec<Cert>,
    crls: &[&[&str]],
    ocsps: &[&str],
    at: &'static str,
) -> ValidationContext {
    let mut c = Ctx::new(others);
    c.crls = crls.iter().map(|p| aa(p)).collect();
    c.ocsps = ocsps.iter().map(|p| aa(&[p])).collect();
    c.at = at;
    c.require = true;
    c.build()
}

fn role_others() -> Vec<Cert> {
    vec![
        cert(&["root", "interm-role.crt"]),
        cert(&["interm", "role-aa.crt"]),
    ]
}

fn complex_others() -> Vec<Cert> {
    vec![
        cert(&["root", "interm-role.crt"]),
        cert(&["interm", "role-aa-crl-issuer.crt"]),
        cert(&["interm", "role-aa.crt"]),
    ]
}

const SOME_REVOKED: [&[&str]; 3] = [
    &["root", "root-some-revoked.crl"],
    &["interm", "interm-some-revoked.crl"],
    &["role-aa-some-revoked.crl"],
];

const ALL_GOOD: [&[&str]; 3] = [
    &["root", "root-all-good.crl"],
    &["interm", "interm-all-good.crl"],
    &["role-aa-all-good.crl"],
];

fn with_rev() -> Vec<u8> {
    aa(&["aa", "alice-role-with-rev.attr.crt"])
}

fn revoked(e: AcError) {
    assert_eq!(e.class_name(), "RevokedError", "{e}");
}

#[test]
fn test_ac_revoked_crl() {
    let ctx = rev_ctx(role_others(), &SOME_REVOKED, &[], "2021-12-12T00:00:00Z");
    revoked(verify_ac_crl(&ctx, &with_rev(), &ac_path()).expect_err("revoked"));
}

#[test]
fn test_ac_unrevoked_crl() {
    let ctx = rev_ctx(role_others(), &ALL_GOOD, &[], "2019-12-12T00:00:00Z");
    verify_ac_crl(&ctx, &with_rev(), &ac_path()).expect("not revoked");
}

#[test]
fn test_ac_revoked_full_path_validation_crl() {
    let ctx = rev_ctx(role_others(), &SOME_REVOKED, &[], "2021-12-12T00:00:00Z");
    revoked(validate_ac(&ctx, &with_rev(), None).expect_err("revoked"));
}

#[test]
fn test_ac_revoked_complex_crls_full_path_validation() {
    let ctx = rev_ctx(
        complex_others(),
        &[
            &["root", "root-some-revoked.crl"],
            &["interm", "interm-some-revoked.crl"],
            &["role-aa-aa-compromise-some-revoked.crl"],
            &["role-aa-other-reasons-some-revoked.crl"],
        ],
        &[],
        "2021-12-12T00:00:00Z",
    );
    let ac = aa(&["aa", "alice-role-complex-crls.attr.crt"]);
    revoked(validate_ac(&ctx, &ac, None).expect_err("revoked"));
}

#[test]
fn test_ac_unrevoked_full_path_validation_crl() {
    let ctx = rev_ctx(role_others(), &ALL_GOOD, &[], "2019-12-12T00:00:00Z");
    validate_ac(&ctx, &with_rev(), None).expect("valid");
}

#[test]
fn test_ac_insufficient_revinfo_crl() {
    let ctx = rev_ctx(role_others(), &ALL_GOOD[..2], &[], "2019-12-12T00:00:00Z");
    let e = validate_ac(&ctx, &with_rev(), None).expect_err("insufficient");
    assert!(e.is_instance_of("InsufficientRevinfoError"), "{e}");
}

#[test]
fn test_ac_crls_out_of_scope() {
    let ctx = rev_ctx(
        complex_others(),
        &[
            &["root", "root-all-good.crl"],
            &["interm", "interm-all-good.crl"],
            &["role-aa-nonaligned-name.crl"],
            &["role-aa-nonsensically-scoped.crl"],
        ],
        &[],
        "2019-12-12T00:00:00Z",
    );
    let ac = aa(&["aa", "alice-role-complex-crls.attr.crt"]);
    let e = verify_ac_crl(&ctx, &ac, &ac_path()).expect_err("indeterminate");
    assert!(
        e.to_string()
            .contains("insufficient information from known CRLs"),
        "{e}"
    );
}

#[test]
fn test_ac_unrevoked_complex_crls_full_path_validation() {
    let ctx = rev_ctx(
        complex_others(),
        &[
            &["root", "root-all-good.crl"],
            &["interm", "interm-all-good.crl"],
            &["role-aa-aa-compromise-all-good.crl"],
            &["role-aa-other-reasons-all-good.crl"],
        ],
        &[],
        "2019-12-12T00:00:00Z",
    );
    let ac = aa(&["aa", "alice-role-complex-crls.attr.crt"]);
    validate_ac(&ctx, &ac, None).expect("valid");
}

#[test]
fn test_ac_revoked_ocsp() {
    let ctx = rev_ctx(
        role_others(),
        &[],
        &["alice-revoked.ors"],
        "2021-12-12T00:00:00Z",
    );
    revoked(verify_ac_ocsp(&ctx, &with_rev(), &ac_path()).expect_err("revoked"));
}

#[test]
fn test_ac_unrevoked_oscp() {
    let ctx = rev_ctx(
        role_others(),
        &[],
        &["alice-all-good.ors"],
        "2019-12-12T00:00:00Z",
    );
    verify_ac_ocsp(&ctx, &with_rev(), &ac_path()).expect("good");
}

#[test]
fn test_ac_revoked_full_path_validation() {
    let ctx = rev_ctx(
        role_others(),
        &SOME_REVOKED[..2],
        &["alice-revoked.ors"],
        "2021-12-12T00:00:00Z",
    );
    revoked(validate_ac(&ctx, &with_rev(), None).expect_err("revoked"));
}

#[test]
fn test_ac_unrevoked_full_path_validation_ocsp() {
    let ctx = rev_ctx(
        role_others(),
        &ALL_GOOD[..2],
        &["alice-all-good.ors"],
        "2019-12-12T00:00:00Z",
    );
    validate_ac(&ctx, &with_rev(), None).expect("valid");
}

// Supplemental algorithm-horizon regressions using real validation evidence.
// These do not add unique upstream-function credit.
mod algorithm_horizon {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::{aa, ac_path, cert, role_others, root, with_rev, ALL_GOOD};
    use crate::common::moment;
    use const_oid::ObjectIdentifier;
    use sigis_pki_certvalidator::ac::{validate_ac, AcError};
    use sigis_pki_certvalidator::ValidationContext;
    use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
    use sigis_pki_core::errors::ValidationError;
    use sigis_pki_core::time::Moment;
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

    #[derive(Debug)]
    struct AcIssuerPolicy {
        aa_key: SubjectPublicKeyInfoOwned,
        constraint: AlgorithmUsageConstraint,
        expected_best_time: Moment,
        calls: Arc<AtomicUsize>,
    }

    impl AlgorithmUsagePolicy for AcIssuerPolicy {
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
            // The AC is signed by the role AA. The AA certificate and its
            // intermediate are signed by different keys and still undergo
            // their ordinary path and required revocation checks.
            if issuer_key != Some(&self.aa_key) {
                return AlgorithmUsageConstraint::allowed();
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(at, Some(self.expected_best_time));
            if self.constraint.allowed {
                return self.constraint.clone();
            }
            if let (Some(at), Some(cutoff)) = (at, self.constraint.not_allowed_after) {
                // The pinned upstream timed policy allows equality.
                if at <= cutoff {
                    return AlgorithmUsageConstraint::allowed();
                }
            }
            self.constraint.clone()
        }
    }

    fn context(
        constraint: AlgorithmUsageConstraint,
        best_time: Moment,
        crl_count: usize,
    ) -> (ValidationContext, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut builder = ValidationContext::builder()
            .trust_root(root())
            .moment(moment("2019-12-12T00:00:00Z"))
            .best_signature_time(best_time)
            .revocation_mode("require")
            .algorithm_policy(Arc::new(AcIssuerPolicy {
                aa_key: cert(&["interm", "role-aa.crt"]).public_key(),
                constraint,
                expected_best_time: best_time,
                calls: calls.clone(),
            }));
        for other in role_others() {
            builder = builder.other_cert(other);
        }
        for crl in &ALL_GOOD[..crl_count] {
            builder = builder.crl(aa(crl));
        }
        (builder.build().expect("context"), calls)
    }

    fn timed_constraint(cutoff: Moment) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint {
            allowed: false,
            failure_reason: Some("The attribute signature policy has expired".into()),
            not_allowed_after: Some(cutoff),
        }
    }

    fn assert_algorithm_error(error: &AcError, cutoff: Option<Moment>) {
        assert_eq!(error.class_name(), "DisallowedAlgorithmError");
        assert!(error.is_instance_of("PathValidationError"));
        let AcError::Validation(ValidationError::DisallowedAlgorithm { msg, banned_since }) = error
        else {
            panic!("expected typed AC algorithm error: {error:?}");
        };
        assert_eq!(*banned_since, cutoff);
        assert!(msg.contains("attribute certificate"), "{msg}");
        assert!(msg.contains("disallowed signature algorithm"), "{msg}");
    }

    #[test]
    fn attribute_algorithm_denial_preserves_exact_cutoff_at_best_signature_time() {
        let cutoff = moment("2019-12-11T12:34:56Z");
        let best_time = moment("2019-12-11T12:34:57Z");
        let (control, _) = context(AlgorithmUsageConstraint::allowed(), best_time, 3);
        let valid = validate_ac(&control, &with_rev(), None).expect("valid control");
        assert_eq!(valid.aa_path, ac_path());
        assert!(valid.approved_attributes.contains_key("role"));
        assert!(!valid.approved_attributes.contains_key("group"));

        let (denied, calls) = context(timed_constraint(cutoff), best_time, 3);
        assert_ne!(denied.moment(), denied.best_signature_time());
        let error = validate_ac(&denied, &with_rev(), None).expect_err("timed AC denial");
        assert_algorithm_error(&error, Some(cutoff));
        assert!(calls.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn attribute_policy_uses_best_signature_time_before_and_at_cutoff() {
        let cutoff = moment("2019-12-11T12:34:56Z");
        for best_time in [moment("2019-12-11T12:34:55Z"), cutoff] {
            let (ctx, calls) = context(timed_constraint(cutoff), best_time, 3);
            assert!(ctx.moment() > cutoff);
            let result = validate_ac(&ctx, &with_rev(), None)
                .expect("best signature time is no later than cutoff");
            assert_eq!(result.aa_path, ac_path());
            assert!(result.approved_attributes.contains_key("role"));
            assert!(!result.approved_attributes.contains_key("group"));
            assert!(calls.load(Ordering::SeqCst) > 0);
        }
    }

    #[test]
    fn permanent_attribute_denial_does_not_infer_cutoff_from_reason() {
        let reason = "Permanently banned; reference date 2001-02-03T04:05:06Z";
        for best_time in [
            moment("2019-12-10T01:02:03Z"),
            moment("2019-12-11T12:34:57Z"),
        ] {
            let (control, _) = context(AlgorithmUsageConstraint::allowed(), best_time, 3);
            validate_ac(&control, &with_rev(), None).expect("valid control");
            let (denied, calls) = context(AlgorithmUsageConstraint::denied(reason), best_time, 3);
            let error = validate_ac(&denied, &with_rev(), None).expect_err("permanent denial");
            assert_algorithm_error(&error, None);
            assert!(calls.load(Ordering::SeqCst) > 0);
        }
    }

    #[test]
    fn allowed_attribute_constraint_with_cutoff_still_requires_ac_revocation() {
        let constraint = AlgorithmUsageConstraint {
            allowed: true,
            failure_reason: Some("Informational date 2001-02-03T04:05:06Z".into()),
            not_allowed_after: Some(moment("2001-02-03T04:05:06Z")),
        };
        let best_time = moment("2019-12-11T12:34:57Z");
        let (control, calls) = context(constraint.clone(), best_time, 3);
        validate_ac(&control, &with_rev(), None).expect("allowed flag is authoritative");
        assert!(calls.load(Ordering::SeqCst) > 0);

        // Keep both AA path CRLs but remove the AC issuer's CRL. The AA path
        // remains verifiable; the AC's own required revocation check fails.
        let (missing, calls) = context(constraint, best_time, 2);
        let error = validate_ac(&missing, &with_rev(), None)
            .expect_err("algorithm metadata is no substitute for AC revocation evidence");
        assert!(
            error.is_instance_of("InsufficientRevinfoError"),
            "{error:?}"
        );
        assert!(calls.load(Ordering::SeqCst) > 0);
    }
}
