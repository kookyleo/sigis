//! Real native trust controls for the two deprecated Python registry originals.
//!
//! These checks do not implement Python's deprecated entry points or runtime
//! warnings, so neither upstream function receives passing-port credit.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{load_cert, moment};
use sigis_pki_certvalidator::{find_valid_path, ValidationContext};

#[test]
fn default_registry_does_not_turn_an_untrusted_chain_into_anchors() {
    let root = load_cert(&["testing-ca-ed25519", "root.cert.pem"]);
    let intermediate = load_cert(&["testing-ca-ed25519", "interm.cert.pem"]);
    let leaf = load_cert(&["testing-ca-ed25519", "signer.cert.pem"]);
    let context = ValidationContext::builder()
        .other_cert(root.clone())
        .other_cert(intermediate.clone())
        .moment(moment("2020-11-01T00:00:00Z"))
        .revocation_mode("soft-fail")
        .build()
        .unwrap();

    assert!(context.trust_anchors().is_empty());
    assert!(context.trust_manager().is_none());
    assert!(!context.is_trust_anchor(&root));
    let error = find_valid_path(&context, &leaf, None).unwrap_err();
    assert_eq!(error.error.class_name(), "PathBuildingError");

    // Same real certificates, time and validation policy; only explicit trust
    // changes. This validates the actual signatures and PKIX path.
    let trusted = ValidationContext::builder()
        .trust_root(root.clone())
        .other_cert(intermediate.clone())
        .moment(moment("2020-11-01T00:00:00Z"))
        .revocation_mode("soft-fail")
        .build()
        .unwrap();
    let path = find_valid_path(&trusted, &leaf, None).unwrap();
    assert_eq!(path.certs(), vec![&root, &intermediate, &leaf]);
    println!("REGISTRY_BOUNDARY empty_roots=DENY explicit_root=VALID");
}

#[test]
fn adding_an_explicit_root_changes_membership_and_the_validated_path() {
    let root = load_cert(&["testing-ca-ed25519", "root.cert.pem"]);
    let unrelated = load_cert(&["testing-ca", "root.cert.pem"]);
    let intermediate = load_cert(&["testing-ca-ed25519", "interm.cert.pem"]);
    let leaf = load_cert(&["testing-ca-ed25519", "signer.cert.pem"]);
    let original = ValidationContext::builder()
        .trust_root(unrelated.clone())
        .other_cert(root.clone())
        .other_cert(intermediate.clone())
        .moment(moment("2020-11-01T00:00:00Z"))
        .revocation_mode("soft-fail")
        .build()
        .unwrap();
    assert!(!original.is_trust_anchor(&root));
    assert_eq!(
        find_valid_path(&original, &leaf, None)
            .unwrap_err()
            .error
            .class_name(),
        "PathBuildingError"
    );

    let extended = ValidationContext::builder()
        .trust_root(unrelated.clone())
        .trust_root(root.clone())
        .other_cert(intermediate.clone())
        .moment(moment("2020-11-01T00:00:00Z"))
        .revocation_mode("soft-fail")
        .build()
        .unwrap();
    assert!(extended.is_trust_anchor(&root));
    assert!(extended.is_trust_anchor(&unrelated));
    assert!(!extended.is_trust_anchor(&leaf));
    let path = find_valid_path(&extended, &leaf, None).unwrap();
    assert_eq!(path.certs(), vec![&root, &intermediate, &leaf]);
    assert!(!original.is_trust_anchor(&root));
    println!("REGISTRY_BOUNDARY unrelated_root=DENY added_root=VALID");
}
