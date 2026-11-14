//! Regression controls for retaining the selected EUTL service window.
//!
//! These are additional adapter controls, not new upstream test functions.
//! A window belongs to the actual selected service. An earlier service is not
//! a fallback, and an unrepresented historical condition cannot be inferred
//! from a bare trust root. No temporal recovery or qualification is performed.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use common::{data, moment};
use sigis_eutl::tsp::{
    Authority, BaseServiceInformation, QualifiedServiceInformation, QualifiedTrustAnchor,
    TrustedServiceType, TspRegistry, TspTrustManager, CA_QC_URI, QTST_URI,
};
use sigis_pki_certvalidator::authority::TrustQualifiers;
use sigis_pki_certvalidator::{
    find_valid_path, Cert, CertRevTrustPolicy, PathFailure, TrustAnchor, ValidationContext,
    ValidationPath, NO_REVOCATION,
};
use sigis_pki_core::time::Moment;

fn cert(name: &str) -> Cert {
    let path = data(&["pyhanko-certvalidator", "ades", "time-slide", "certs", name]);
    Cert::from_pem_or_der(&std::fs::read(path).expect("existing certificate fixture"))
        .expect("valid certificate fixture")
}

fn at() -> Moment {
    moment("2020-11-29T00:05:00Z")
}

fn shifted(value: Moment, seconds: i64) -> Moment {
    Moment::from_unix_secs(value.unix_secs() + seconds)
}

fn service(
    name: &str,
    tsa: bool,
    from: Moment,
    until: Option<Moment>,
) -> QualifiedServiceInformation {
    let base = BaseServiceInformation {
        service_type: if tsa { QTST_URI } else { CA_QC_URI }.to_owned(),
        service_name: name.to_owned(),
        valid_from: from,
        valid_until: until,
        provider_certs: vec![cert("root.crt")],
        additional_info_certificate_type: BTreeSet::new(),
        other_additional_info: BTreeSet::new(),
    };
    if tsa {
        QualifiedServiceInformation::qtst(base, [])
    } else {
        QualifiedServiceInformation::ca(base, [], None)
    }
}

fn registry(tsa: bool, from: Moment, until: Option<Moment>) -> TspRegistry {
    let mut registry = TspRegistry::new();
    registry.register(service("selected", tsa, from, until));
    registry
}

fn selected(registry: &TspRegistry) -> QualifiedTrustAnchor {
    TspTrustManager::new(registry)
        .as_trust_anchor(&Authority::of_cert(&cert("root.crt")))
        .expect("registered provider authority")
}

fn qualifiers(from: Moment, until: Option<Moment>) -> TrustQualifiers {
    TrustQualifiers {
        valid_from: Some(from),
        valid_until: until,
        ..TrustQualifiers::default()
    }
}

fn chain(anchor: TrustAnchor, reference: Moment) -> Result<ValidationPath, Box<PathFailure>> {
    let leaf = cert("alice.crt");
    let intermediate = cert("interm.crt");
    for issued in [&leaf, &intermediate] {
        assert!(issued.not_before() <= reference && reference <= issued.not_after());
    }
    let ctx = ValidationContext::builder()
        .trust_anchor(anchor)
        .other_cert(intermediate)
        .moment(reference)
        .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
        .build()
        .expect("fixed-clock context");
    find_valid_path(&ctx, &leaf, None)
}

fn assert_chain(
    anchor: TrustAnchor,
    reference: Moment,
    error: Option<&str>,
    until: Option<Moment>,
) {
    match error {
        Some(class) => {
            let failure = chain(anchor, reference).expect_err("service window must deny trust");
            assert_eq!(failure.error.class_name(), class);
            assert!(failure.error.to_string().contains("trust anchor"));
            if class == "ExpiredError" {
                assert_eq!(failure.time_horizon, until);
            }
        }
        None => {
            let path = chain(anchor.clone(), reference).expect("genuine issued chain validates");
            assert_eq!(path.trust_anchor(), &anchor);
            assert_eq!(path.pkix_len(), 2);
            assert_eq!(path.intermediates(), &[cert("interm.crt")]);
            assert_eq!(path.leaf(), Some(&cert("alice.crt")));
        }
    }
}

#[test]
fn selected_anchor_retains_window_and_defaults() {
    let from = shifted(at(), -1);
    for tsa in [false, true] {
        for until in [Some(shifted(at(), 1)), None] {
            let q = selected(&registry(tsa, from, until));
            assert_eq!(q.valid_from, from);
            assert_eq!(q.valid_until, until);
            assert_eq!(
                q.trusted_service_type,
                if tsa {
                    TrustedServiceType::TimeStampingAuthority
                } else {
                    TrustedServiceType::CertificateAuthority
                }
            );
            assert_eq!(q.anchor.cert(), &cert("root.crt"));
            assert_eq!(
                q.anchor.authority(),
                TrustAnchor::new(cert("root.crt")).authority()
            );
            assert!(!q.anchor.enforce_validity());
            // Preserve all default PKIX and role fields: only the window changes.
            assert_eq!(q.anchor.qualifiers(), &qualifiers(from, until));
            assert!(q.anchor.can_issue());
        }
    }
}

#[test]
fn filter_obeys_inclusive_selected_window() {
    let from = shifted(at(), -1);
    let until = shifted(at(), 1);
    let finite = registry(false, from, Some(until));
    let open = registry(false, from, None);
    // This filter's membership controls already pass on the unchanged baseline.
    for (registry, reference, present) in [
        (&finite, shifted(from, -1), false),
        (&finite, from, true),
        (&finite, at(), true),
        (&finite, until, true),
        (&finite, shifted(until, 1), false),
        (&open, shifted(from, -1), false),
        (&open, from, true),
        (&open, shifted(until, 1), true),
    ] {
        let anchors = TspTrustManager::new(registry).trust_anchors_at(reference);
        assert_eq!(anchors.len(), usize::from(present));
        for anchor in anchors {
            assert_eq!(anchor.cert(), &cert("root.crt"));
            assert!(!anchor.enforce_validity());
            assert_chain(TrustAnchor::new(cert("root.crt")), reference, None, None);
            assert_chain(anchor, reference, None, None);
        }
    }
    let empty = TspRegistry::new();
    let manager = TspTrustManager::new(&empty);
    assert!(manager.trust_anchors_at(at()).is_empty());
    assert!(manager
        .as_trust_anchor(&Authority::of_cert(&cert("root.crt")))
        .is_none());
}

#[test]
fn direct_anchor_window_is_enforced_by_cv() {
    let from = shifted(at(), -1);
    let until = shifted(at(), 1);
    let q = selected(&registry(false, from, Some(until)));
    let rows = [
        (shifted(from, -1), Some("NotYetValidError")),
        (from, None),
        (at(), None),
        (until, None),
        (shifted(until, 1), Some("ExpiredError")),
    ];
    // Establish every genuine same-chain positive before testing any refusal.
    for (reference, _) in rows {
        assert_chain(TrustAnchor::new(cert("root.crt")), reference, None, None);
    }
    for (reference, error) in rows {
        if error.is_none() {
            assert_chain(q.anchor.clone(), reference, None, None);
        }
    }
    for (reference, error) in rows {
        assert_chain(
            TrustAnchor::with_qualifiers(cert("root.crt"), qualifiers(from, Some(until))),
            reference,
            error,
            Some(until),
        );
        assert_chain(q.anchor.clone(), reference, error, Some(until));
    }
}

#[test]
fn filtered_anchor_keeps_window_when_reused() {
    let from = shifted(at(), -1);
    let until = shifted(at(), 1);
    let registry = registry(false, from, Some(until));
    // Select once at v; the later controls use the same returned anchor value.
    let anchors = TspTrustManager::new(&registry).trust_anchors_at(at());
    assert_eq!(anchors.len(), 1);
    assert_chain(anchors[0].clone(), at(), None, None);
    for (reference, error) in [
        (shifted(from, -1), Some("NotYetValidError")),
        (from, None),
        (shifted(until, 1), Some("ExpiredError")),
    ] {
        assert_chain(TrustAnchor::new(cert("root.crt")), reference, None, None);
        assert_chain(anchors[0].clone(), reference, error, Some(until));
    }
}

#[test]
fn potential_issuers_keep_selected_window() {
    let from = shifted(at(), -1);
    let until = Some(shifted(at(), 1));
    let ca = registry(false, from, until);
    let manager = TspTrustManager::new(&ca);
    let matching = manager.find_potential_issuers(&cert("interm.crt"));
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].anchor.cert(), &cert("root.crt"));
    assert_eq!(matching[0].valid_from, from);
    assert_eq!(matching[0].valid_until, until);
    assert_eq!(matching[0].anchor.qualifiers(), &qualifiers(from, until));
    assert!(manager
        .find_potential_issuers(&cert("alice.crt"))
        .is_empty());
    let tsa = registry(true, from, until);
    assert!(TspTrustManager::new(&tsa)
        .find_potential_issuers(&cert("interm.crt"))
        .is_empty());
}

#[test]
fn history_keeps_original_selection_without_fallback() {
    let old = service("old", false, shifted(at(), -20), Some(at()));
    let finite = service("finite", false, shifted(at(), 1), Some(shifted(at(), 10)));
    let open = service("open", false, shifted(at(), 2), None);
    let tied = service("tied", false, shifted(at(), -10), None);
    // Existing first/latest selection is preserved even when older entries
    // cover an earlier reference time. This is not a new ambiguity policy.
    for (services, expected) in [
        (vec![finite.clone(), open.clone()], &open),
        (vec![old.clone(), finite.clone()], &finite),
        (vec![old.clone(), open.clone()], &open),
        (vec![open.clone(), tied], &open),
    ] {
        let mut registry = TspRegistry::new();
        for service in services {
            registry.register_ca(service);
        }
        let definitions =
            registry.applicable_service_definitions(&Authority::of_cert(&cert("root.crt")), None);
        assert_eq!(definitions[0], expected);
        let q = selected(&registry);
        assert_eq!(q.valid_from, expected.base_info.valid_from);
        assert_eq!(q.valid_until, expected.base_info.valid_until);
        assert!(TspTrustManager::new(&registry)
            .trust_anchors_at(at())
            .is_empty());
    }
}

#[test]
fn same_authority_ca_tsa_keeps_identity_and_dedup() {
    let from = shifted(at(), -1);
    let until = Some(shifted(at(), 1));
    let ca = service("ca", false, from, until);
    let tsa = service("tsa", true, from, until);
    let mut registry = TspRegistry::new();
    // Both CA/TSA definitions have the same sort key. Existing CA-first order
    // wins even though the TSA was registered first.
    registry.register_tst(tsa);
    registry.register_ca(ca.clone());
    let q = selected(&registry);
    assert_eq!(
        q.trusted_service_type,
        TrustedServiceType::CertificateAuthority
    );
    let anchors = TspTrustManager::new(&registry).trust_anchors_at(at());
    assert_eq!(anchors, vec![q.anchor.clone()]);

    registry.register_ca(ca);
    assert_eq!(
        TspTrustManager::new(&registry).trust_anchors_at(at()),
        anchors
    );
    assert_eq!(
        registry
            .applicable_service_definitions(&Authority::of_cert(&cert("root.crt")), None)
            .len(),
        2
    );

    let root = cert("root.crt");
    let named = Authority::named_key(root.subject(), &root.public_key());
    assert_eq!(
        TspTrustManager::new(&registry).as_trust_anchor(&named),
        Some(q)
    );
}

#[test]
fn plain_root_and_anchor_certificate_defaults_are_preserved() {
    let root = cert("root.crt");
    let reference = root.not_after().plus(Duration::from_secs(1));
    assert!(reference > root.not_after());
    // Direct anchor trust has no issued certificates: this isolates default
    // anchor-date behavior, not an issued-chain signature validation claim.
    let direct = |anchor: TrustAnchor| {
        let ctx = ValidationContext::builder()
            .trust_anchor(anchor)
            .moment(reference)
            .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
            .build()
            .expect("direct-anchor context");
        find_valid_path(&ctx, &root, None)
    };
    let plain = TrustAnchor::new(root.clone());
    assert_eq!(plain.qualifiers(), &TrustQualifiers::default());
    assert!(!plain.enforce_validity());
    assert_eq!(
        direct(plain)
            .expect("plain root trusted by fiat")
            .pkix_len(),
        0
    );

    let q = selected(&registry(false, reference, None));
    assert!(!q.anchor.enforce_validity());
    assert_eq!(
        direct(q.anchor)
            .expect("service begins inclusively")
            .pkix_len(),
        0
    );

    let future = shifted(reference, 1);
    let explicit = TrustAnchor::with_qualifiers(root.clone(), qualifiers(future, None));
    assert_eq!(
        direct(explicit)
            .expect_err("explicit service bound")
            .error
            .class_name(),
        "NotYetValidError"
    );
    let q = selected(&registry(false, future, None));
    assert!(!q.anchor.enforce_validity());
    let error = direct(q.anchor).expect_err("EUTL service bound must remain effective");
    assert_eq!(error.error.class_name(), "NotYetValidError");
    assert!(error.error.to_string().contains("trust anchor"));
}
