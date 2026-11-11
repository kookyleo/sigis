// Tests for `ValidationContext` additions requested by other lanes: the
// trust manager hook (lane E, A-2), access to the supplied revocation
// information (lane D, A-6) and extension with document material such as a
// PDF DSS (lane E, A-3). No pyHanko test corresponds one to one; the
// fixtures are pyhanko-certvalidator's `ades/time-slide` PKI.

mod common;

use std::sync::Arc;

use common::{load_cert, moment, read};
use sigis_pki_certvalidator::{
    find_valid_path, Cert, CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule,
    TrustAnchor, TrustManager, ValidationContext,
};

fn cert(name: &str) -> Cert {
    load_cert(&["ades", "time-slide", "certs", name])
}

fn data(name: &str) -> Vec<u8> {
    read(&["ades", "time-slide", name])
}

/// Trusts exactly one certificate.
#[derive(Debug)]
struct OneAnchor(Cert);

impl TrustManager for OneAnchor {
    fn as_trust_anchor(&self, cert: &Cert) -> Option<TrustAnchor> {
        (cert == &self.0).then(|| TrustAnchor::new(self.0.clone()))
    }

    fn find_potential_issuers(&self, cert: &Cert) -> Vec<TrustAnchor> {
        if cert.issuer() == self.0.subject() {
            vec![TrustAnchor::new(self.0.clone())]
        } else {
            Vec::new()
        }
    }
}

fn base() -> sigis_pki_certvalidator::ValidationContextBuilder {
    ValidationContext::builder()
        .other_cert(cert("interm.crt"))
        .moment(moment("2020-11-29T00:05:00Z"))
}

#[test]
fn trust_manager_supplies_the_anchor() {
    let alice = cert("alice.crt");
    let without = base().build().expect("context");
    let e = find_valid_path(&without, &alice, None).expect_err("no anchor");
    assert_eq!(e.error.class_name(), "PathBuildingError", "{}", e.error);

    let with = base()
        .trust_manager(Arc::new(OneAnchor(cert("root.crt"))))
        .build()
        .expect("context");
    assert!(with.is_trust_anchor(&cert("root.crt")));
    assert!(!with.is_trust_anchor(&alice));
    let path = find_valid_path(&with, &alice, None).expect("path");
    assert_eq!(path.trust_anchor().cert(), &cert("root.crt"));
    assert_eq!(path.pkix_len(), 2);
}

#[test]
fn trust_manager_anchor_as_leaf() {
    let root = cert("root.crt");
    let ctx = base()
        .trust_manager(Arc::new(OneAnchor(root.clone())))
        .build()
        .expect("context");
    let path = find_valid_path(&ctx, &root, None).expect("path");
    assert_eq!(path.trust_anchor().cert(), &root);
}

#[test]
fn trust_manager_unrelated_anchor_does_not_help() {
    let ctx = base()
        .trust_manager(Arc::new(OneAnchor(cert("alice.crt"))))
        .build()
        .expect("context");
    assert!(find_valid_path(&ctx, &cert("alice.crt"), None).is_ok());
    let e = find_valid_path(&ctx, &cert("interm.crt"), None).expect_err("untrusted");
    assert_eq!(e.error.class_name(), "PathBuildingError", "{}", e.error);
}

#[test]
fn supplied_revinfo_is_readable() {
    let crl = data("root-2020-11-29.crl");
    let ocsp = data("alice-2020-11-29.ors");
    let ctx = base()
        .trust_root(cert("root.crt"))
        .crl(crl.clone())
        .ocsp_response(ocsp.clone())
        .build()
        .expect("context");
    assert_eq!(ctx.crls().collect::<Vec<_>>(), vec![crl.as_slice()]);
    assert_eq!(ctx.ocsps().collect::<Vec<_>>(), vec![ocsp.as_slice()]);
}

fn required() -> CertRevTrustPolicy {
    CertRevTrustPolicy::new(RevocationCheckingPolicy {
        ee_certificate_rule: RevocationCheckingRule::CrlOrOcspRequired,
        intermediate_ca_cert_rule: RevocationCheckingRule::CrlOrOcspRequired,
    })
}

#[test]
fn with_revinfo_adds_document_material() {
    let ctx = ValidationContext::builder()
        .trust_root(cert("root.crt"))
        .revinfo_policy(required())
        .time_tolerance(std::time::Duration::from_secs(600))
        .moment(moment("2020-11-29T00:05:00Z"))
        .build()
        .expect("context");
    let alice = cert("alice.crt");
    assert!(find_valid_path(&ctx, &alice, None).is_err());

    let interm = cert("interm.crt");
    let responder = cert("interm-ocsp.crt");
    let crl = data("root-2020-11-29.crl");
    let ocsp = data("alice-2020-11-29.ors");
    let extended = ctx
        .with_revinfo([&interm, &responder], [crl.as_slice()], [ocsp.as_slice()])
        .expect("extend");
    find_valid_path(&extended, &alice, None).expect("valid with DSS material");
    // Adding the same material again changes nothing.
    let twice = extended
        .with_revinfo([&interm], [crl.as_slice()], [ocsp.as_slice()])
        .expect("extend");
    assert_eq!(twice.crls().count(), 1);
    assert_eq!(twice.ocsps().count(), 1);
    assert_eq!(twice.other_certs().len(), 2);
    // The original context is unchanged.
    assert_eq!(ctx.crls().count(), 0);
}

#[test]
fn with_revinfo_rejects_garbage() {
    let ctx = base().build().expect("context");
    assert!(ctx.with_revinfo([], [b"junk".as_slice()], []).is_err());
    assert!(ctx.with_revinfo([], [], [b"junk".as_slice()]).is_err());
}

#[test]
fn trust_qualifier_validity_period_is_enforced() {
    use sigis_pki_certvalidator::authority::TrustQualifiers;
    let at = moment("2020-11-29T00:05:00Z");
    let check = |quals: TrustQualifiers| {
        let ctx = base()
            .trust_anchor(TrustAnchor::with_qualifiers(cert("root.crt"), quals))
            .build()
            .expect("context");
        find_valid_path(&ctx, &cert("alice.crt"), None)
    };
    check(TrustQualifiers {
        valid_from: Some(at),
        valid_until: Some(at),
        ..TrustQualifiers::default()
    })
    .expect("bounds are inclusive");
    let e = check(TrustQualifiers {
        valid_until: Some(moment("2020-11-29T00:04:59Z")),
        ..TrustQualifiers::default()
    })
    .expect_err("expired");
    assert_eq!(e.error.class_name(), "ExpiredError");
    assert_eq!(
        e.error.to_string(),
        "The path could not be validated because the trust anchor expired 2020-11-29 00:04:59Z"
    );
    assert_eq!(e.time_horizon, Some(moment("2020-11-29T00:04:59Z")));
    let e = check(TrustQualifiers {
        valid_from: Some(moment("2020-11-29T00:05:01Z")),
        ..TrustQualifiers::default()
    })
    .expect_err("not yet valid");
    assert_eq!(e.error.class_name(), "NotYetValidError");
    assert!(e
        .error
        .to_string()
        .contains("the trust anchor is not valid until 2020-11-29 00:05:01Z"));
}
