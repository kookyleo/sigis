// Port of pyhanko-certvalidator `tests/test_registry.py` (MIT, see
// LICENSE-pyHanko). The synthetic certificates come from the upstream
// helpers (`oracle/gen_registry_fixtures.py`).

mod common;

use common::load_cert;
use hanko_certvalidator::authority::{TrustQualifiers, TrustedServiceType};
use hanko_certvalidator::registry::{key_hash, CertificateRegistry, LayeredCertificateStore};
use hanko_certvalidator::{build_paths, Cert, TrustAnchor, ValidationContext};

fn fixture(name: &str) -> Cert {
    let file = format!("{name}.der");
    Cert::from_der(&hanko_testdata::read(&["lanes", "a", "registry", &file])).expect("cert")
}

#[test]
fn test_build_paths_custom_ca_certs() {
    let cert = load_cert(&["testing-ca-ed25519", "signer.cert.pem"]);
    let interm = load_cert(&["testing-ca-ed25519", "interm.cert.pem"]);
    let ctx = ValidationContext::builder()
        .trust_root(interm.clone())
        .other_cert(interm.clone())
        .build()
        .expect("context");
    let paths = build_paths(&ctx, &cert).expect("paths");
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].len(), 2);
    let subjects: Vec<Vec<u8>> = paths[0]
        .certs()
        .iter()
        .map(|c| hanko_core::algorithms::DigestAlgorithm::Sha1.digest(&c.subject_der().unwrap()))
        .collect();
    assert_eq!(
        subjects,
        vec![
            vec![
                0x58, 0x6d, 0xb3, 0x66, 0xac, 0x5b, 0x54, 0x13, 0xba, 0x50, 0x24, 0x13, 0xfb, 0x93,
                0x4c, 0xf0, 0x9e, 0x78, 0x83, 0x56
            ],
            vec![
                0x0c, 0x08, 0xea, 0x4b, 0x9f, 0xe3, 0x10, 0xcc, 0x2a, 0x11, 0x72, 0x46, 0x8d, 0x99,
                0xbf, 0xf0, 0xd5, 0x31, 0xf6, 0x41
            ],
        ]
    );
}

#[test]
fn test_build_paths_qualified_root_with_wrong_type() {
    let cert = load_cert(&["testing-ca-ed25519", "signer.cert.pem"]);
    let ca = load_cert(&["testing-ca-ed25519", "interm.cert.pem"]);
    let ctx = ValidationContext::builder()
        .trust_anchor(TrustAnchor::with_qualifiers(
            ca.clone(),
            TrustQualifiers {
                trusted_service_type: TrustedServiceType::Unsupported,
                ..TrustQualifiers::default()
            },
        ))
        .other_cert(ca)
        .build()
        .expect("context");
    let e = build_paths(&ctx, &cert).expect_err("no path");
    assert_eq!(e.class_name(), "PathBuildingError");
}

#[test]
fn test_disambiguate_issuer_by_authority_info() {
    let issuer1 = fixture("issuer-foo-root-0");
    let issuer2 = fixture("issuer-bar-root-1");
    for subject in [
        "subject-aki-foo",
        "subject-coords-root-0",
        "subject-aki-foo-coords-root-0",
    ] {
        let registry = CertificateRegistry::build([issuer1.clone(), issuer2.clone()]);
        let found = registry.find_potential_issuers(&fixture(subject));
        assert_eq!(found, vec![issuer1.clone()], "{subject}");
    }
}

#[test]
fn test_partial_match_handling_aki_filter() {
    let subject = fixture("subject-aki-foo-coords-root-0");
    let issuer1 = fixture("issuer-foo-root-0");
    let registry = CertificateRegistry::build([
        issuer1.clone(),
        fixture("issuer-bar-root-0"),
        fixture("issuer-foo-root-1"),
    ]);
    assert_eq!(registry.find_potential_issuers(&subject), vec![issuer1]);
}

#[test]
fn test_distinguish_ski_and_key_hash() {
    let subject = fixture("subject-aki-foo-coords-root-0-ski-bar");
    let issuer = fixture("issuer-foo-root-0");
    let registry = CertificateRegistry::build([subject.clone(), issuer.clone()]);
    assert_eq!(
        registry.retrieve_by_key_hash(&key_hash(&subject)),
        Some(subject.clone())
    );
    assert_eq!(
        registry.retrieve_by_key_hash(&key_hash(&issuer)),
        Some(issuer)
    );
    assert_eq!(
        registry.retrieve_by_key_identifier(b"bar"),
        Some(subject.clone())
    );
    assert_eq!(
        registry.retrieve_by_key_identifier(&key_hash(&subject)),
        None
    );
}

#[test]
fn test_layered_prefer_first() {
    let subject1 = fixture("subject-aki-foo-coords-root-0");
    let subject2 = fixture("subject-aki-quux-coords-root-0");
    assert_eq!(subject1.issuer(), subject2.issuer());
    assert_eq!(subject1.serial_bytes(), subject2.serial_bytes());
    let layered = LayeredCertificateStore {
        stores: vec![
            CertificateRegistry::build([subject1.clone()]),
            CertificateRegistry::build([subject2]),
        ],
    };
    assert_eq!(
        layered.retrieve_by_key_hash(&key_hash(&subject1)),
        Some(subject1.clone())
    );
    assert_eq!(
        layered.retrieve_by_key_identifier(&key_hash(&subject1)),
        Some(subject1.clone())
    );
    assert_eq!(
        layered.retrieve_by_issuer_serial(subject1.issuer(), subject1.serial_bytes()),
        Some(subject1)
    );
}

#[test]
fn test_layered_fallthrough() {
    let subject1 = fixture("subject-aki-foo-coords-root-0");
    let layered = LayeredCertificateStore {
        stores: vec![
            CertificateRegistry::default(),
            CertificateRegistry::build([subject1.clone()]),
        ],
    };
    assert_eq!(
        layered.retrieve_by_key_hash(&key_hash(&subject1)),
        Some(subject1.clone())
    );
    assert_eq!(
        layered.retrieve_by_key_identifier(&key_hash(&subject1)),
        Some(subject1.clone())
    );
    assert_eq!(
        layered.retrieve_by_issuer_serial(subject1.issuer(), subject1.serial_bytes()),
        Some(subject1)
    );
}
