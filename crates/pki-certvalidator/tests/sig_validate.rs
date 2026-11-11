// Port of pyhanko-certvalidator `tests/test_sig_validate.py` (MIT, see
// LICENSE-pyHanko), plus algorithm-dispatch tests on generated fixtures.

mod common;

use common::{load_cert, load_generated_cert, load_nist_cert};
use der::{Any, Encode};
use sigis_pki_certvalidator::Cert;
use sigis_pki_core::algorithms::{validate_signature, RsaPssParams, SignatureValidationContext};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::errors::SignatureError;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// The signed part (TBSCertificate) of a certificate.
fn tbs(cert: &Cert) -> Vec<u8> {
    cert.decoded().tbs_certificate().to_der().expect("tbs")
}

fn check_issued(issuer: &Cert, issued: &Cert) -> Result<(), SignatureError> {
    validate_signature(
        issued.decoded().signature().raw_bytes(),
        &tbs(issued),
        &issuer.public_key(),
        issued.decoded().signature_algorithm(),
        &SignatureValidationContext::default(),
    )
}

#[test]
fn test_dsa_inheritance_missing_params() {
    let pubkey = load_nist_cert("DSACACert.crt").public_key();
    let stripped = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: pubkey.algorithm.oid,
            parameters: None,
        },
        subject_public_key: pubkey.subject_public_key.clone(),
    };
    let issued = load_nist_cert("InvalidDSASignatureTest6EE.crt");
    let result = validate_signature(
        issued.decoded().signature().raw_bytes(),
        &tbs(&issued),
        &stripped,
        &AlgorithmIdentifierOwned {
            oid: issued.decoded().signature_algorithm().oid,
            parameters: None,
        },
        &SignatureValidationContext::default(),
    );
    assert_eq!(result, Err(SignatureError::DsaParametersUnavailable));
}

#[test]
fn test_pss_parameter_mismatch() {
    let pubkey = load_cert(&["testing-ca-pss", "root.cert.pem"]).public_key();
    let params = RsaPssParams {
        hash_algorithm: Some(AlgorithmIdentifierOwned {
            oid: oids::SHA3_256,
            parameters: None,
        }),
        ..RsaPssParams::default()
    };
    let mangled = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: oids::RSASSA_PSS,
            parameters: Some(Any::encode_from(&params).expect("params")),
        },
        subject_public_key: pubkey.subject_public_key.clone(),
    };
    let issued = load_cert(&["testing-ca-pss", "interm.cert.pem"]);
    let result = validate_signature(
        issued.decoded().signature().raw_bytes(),
        &tbs(&issued),
        &mangled,
        issued.decoded().signature_algorithm(),
        &SignatureValidationContext::default(),
    );
    assert_eq!(result, Err(SignatureError::PssParameterMismatch));
}

#[test]
fn test_algorithm_not_supported() {
    let pubkey = load_cert(&["testing-ca-pss", "root.cert.pem"]).public_key();
    let issued = load_cert(&["testing-ca-pss", "interm.cert.pem"]);
    // pyHanko uses OID 2.999, which const-oid cannot represent; any unknown
    // OID exercises the same branch.
    let unknown = AlgorithmIdentifierOwned {
        oid: const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.2.999"),
        parameters: None,
    };
    let result = validate_signature(
        issued.decoded().signature().raw_bytes(),
        &tbs(&issued),
        &pubkey,
        &unknown,
        &SignatureValidationContext::default(),
    );
    assert!(
        matches!(result, Err(SignatureError::AlgorithmNotSupported(_))),
        "{result:?}"
    );
}

#[test]
fn pss_chain_signatures_verify() {
    let root = load_cert(&["testing-ca-pss", "root.cert.pem"]);
    let interm = load_cert(&["testing-ca-pss", "interm.cert.pem"]);
    let signer = load_cert(&["testing-ca-pss", "signer1.cert.pem"]);
    check_issued(&root, &interm).expect("interm");
    check_issued(&interm, &signer).expect("signer");
    assert_eq!(
        check_issued(&root, &signer),
        Err(SignatureError::InvalidSignature)
    );
}

#[test]
fn ed25519_chain_signatures_verify() {
    let root = load_cert(&["testing-ca-ed25519", "root.cert.pem"]);
    let interm = load_cert(&["testing-ca-ed25519", "interm.cert.pem"]);
    check_issued(&root, &interm).expect("interm");
}

#[test]
fn ed448_chain_signatures_verify() {
    let root = load_cert(&["testing-ca-ed448", "root.cert.pem"]);
    let interm = load_cert(&["testing-ca-ed448", "interm.cert.pem"]);
    check_issued(&root, &interm).expect("interm");
    // A signature by another key fails.
    let signer = load_cert(&["testing-ca-ed448", "signer.cert.pem"]);
    assert!(matches!(
        check_issued(&root, &signer),
        Err(SignatureError::InvalidSignature)
    ));
}

#[test]
fn generated_self_signed_certificates_verify() {
    for name in [
        "ec-p256-sha256.cert.pem",
        "ec-p256-sha384.cert.pem",
        "ec-p384-sha384.cert.pem",
        "ec-p521-sha512.cert.pem",
        "rsa-sha256.cert.pem",
        "rsa-pss-sha256.cert.pem",
        "rsa-pss-sha512-salt20.cert.pem",
        "ed25519.cert.pem",
    ] {
        let cert = load_generated_cert(name);
        check_issued(&cert, &cert).unwrap_or_else(|e| panic!("{name}: {e}"));

        // A modified message must not verify.
        let mut data = tbs(&cert);
        let last = data.len() - 1;
        data[last] ^= 1;
        let result = validate_signature(
            cert.decoded().signature().raw_bytes(),
            &data,
            &cert.public_key(),
            cert.decoded().signature_algorithm(),
            &SignatureValidationContext::default(),
        );
        assert_eq!(result, Err(SignatureError::InvalidSignature), "{name}");
    }
}

#[test]
fn prehashed_rsa_and_ecdsa() {
    use sigis_pki_core::algorithms::DigestAlgorithm;
    for (name, digest) in [
        ("rsa-sha256.cert.pem", DigestAlgorithm::Sha256),
        ("ec-p384-sha384.cert.pem", DigestAlgorithm::Sha384),
    ] {
        let cert = load_generated_cert(name);
        let hash = digest.digest(&tbs(&cert));
        validate_signature(
            cert.decoded().signature().raw_bytes(),
            &hash,
            &cert.public_key(),
            cert.decoded().signature_algorithm(),
            &SignatureValidationContext {
                prehashed: true,
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn key_type_mismatch_and_garbage_do_not_panic() {
    let ec = load_generated_cert("ec-p256-sha256.cert.pem");
    let rsa = load_generated_cert("rsa-sha256.cert.pem");
    // RSA signature checked with an EC key.
    let result = validate_signature(
        rsa.decoded().signature().raw_bytes(),
        &tbs(&rsa),
        &ec.public_key(),
        rsa.decoded().signature_algorithm(),
        &SignatureValidationContext::default(),
    );
    assert!(
        matches!(result, Err(SignatureError::KeyMismatch(_))),
        "{result:?}"
    );
    // Truncated signatures and keys.
    for cert in [&ec, &rsa] {
        let sig = cert.decoded().signature().raw_bytes();
        for len in [0, 1, sig.len() / 2] {
            assert!(validate_signature(
                &sig[..len],
                &tbs(cert),
                &cert.public_key(),
                cert.decoded().signature_algorithm(),
                &SignatureValidationContext::default(),
            )
            .is_err());
        }
    }
}
