// Port of pyhanko-certvalidator `tests/test_ac_validate.py`
// (MIT, see LICENSE-pyHanko). Frozen time 2022-05-01 becomes the default
// moment; tests with an explicit moment pass it.

mod common;

use std::str::FromStr;

use common::{moment, read};
use hanko_certvalidator::ac::{
    validate_ac, verify_ac_crl, verify_ac_ocsp, AcError, AcTargetDescription, AcValidationResult,
};
use hanko_certvalidator::{Cert, TrustAnchor, ValidationContext, ValidationPath};
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
    assert!(e.is_instance_of(class), "{} is not a {class}: {e}", e.class_name());
    let msg = e.to_string();
    let mut pos = 0;
    for p in pattern {
        let i = msg[pos..].find(p).unwrap_or_else(|| panic!("{p:?} not in {msg:?}"));
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
    use hanko_core::asn1::tlv::{encode, Tlv};
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
    assert_err(validate_ac(&c.build(), &ac, None), "InvalidCertificateError", &["AC targeting"]);
}

#[test]
fn test_basic_ac_validation_bad_targeting_group() {
    let (mut c, ac) = targeted();
    c.targets = Some(AcTargetDescription {
        validator_names: Vec::new(),
        group_memberships: vec![dn("OU=Not Validators,O=Testing Attribute Authority,C=XX")],
    });
    assert_err(validate_ac(&c.build(), &ac, None), "InvalidCertificateError", &["AC targeting"]);
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
        ("alice-misleading-aki.attr.crt", "PathBuildingError", "suitable AA"),
        ("alice-v2form-wrong-serial.attr.crt", "PathBuildingError", "suitable AA"),
    ] {
        assert_err(validate_ac(&role_ctx().build(), &oneoff(name), Some(&alice)), class, &[pattern]);
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

fn rev_ctx(others: Vec<Cert>, crls: &[&[&str]], ocsps: &[&str], at: &'static str) -> ValidationContext {
    let mut c = Ctx::new(others);
    c.crls = crls.iter().map(|p| aa(p)).collect();
    c.ocsps = ocsps.iter().map(|p| aa(&[p])).collect();
    c.at = at;
    c.require = true;
    c.build()
}

fn role_others() -> Vec<Cert> {
    vec![cert(&["root", "interm-role.crt"]), cert(&["interm", "role-aa.crt"])]
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
    assert!(e.to_string().contains("insufficient information from known CRLs"), "{e}");
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
    let ctx = rev_ctx(role_others(), &[], &["alice-revoked.ors"], "2021-12-12T00:00:00Z");
    revoked(verify_ac_ocsp(&ctx, &with_rev(), &ac_path()).expect_err("revoked"));
}

#[test]
fn test_ac_unrevoked_oscp() {
    let ctx = rev_ctx(role_others(), &[], &["alice-all-good.ors"], "2019-12-12T00:00:00Z");
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
    let ctx = rev_ctx(role_others(), &ALL_GOOD[..2], &["alice-all-good.ors"], "2019-12-12T00:00:00Z");
    validate_ac(&ctx, &with_rev(), None).expect("valid");
}
