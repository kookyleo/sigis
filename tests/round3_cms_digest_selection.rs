// Ported from pyHanko 0.38.1 test_cms.py (MIT, see LICENSE-pyHanko).
//! Signer assertions assigned to the upstream CMS test module.
//!
//! These assertions use actual Rust signing APIs. Recorded validation
//! fixtures cannot establish signer-side refusal or digest selection.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pades_sign::signer::select_suitable_signing_md;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::cert::Cert;

fn cert(arch: &str, label: &str) -> Cert {
    let path = sigis_testdata::path(&["lanes", "d", "pki", arch, &format!("{label}.crt")]);
    let bytes = std::fs::read(&path).unwrap();
    let sha256 = DigestAlgorithm::Sha256
        .digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    eprintln!("CMS_SIGNER_INPUT path={} sha256={sha256}", path.display());
    Cert::from_der(&bytes).unwrap()
}

#[test]
fn test_key_based_digest_selection() {
    // pyHanko 0.38.1 test_cms.py:2166-2178, all four parameters.
    for (arch, expected) in [
        ("testing-ca", DigestAlgorithm::Sha256),
        ("testing-ca-ecdsa", DigestAlgorithm::Sha384),
        ("testing-ca-ed25519", DigestAlgorithm::Sha512),
        ("testing-ca-ed448", DigestAlgorithm::Shake256),
    ] {
        assert_eq!(
            select_suitable_signing_md(&cert(arch, "signer1").public_key()),
            expected,
            "{arch}"
        );
    }
}
