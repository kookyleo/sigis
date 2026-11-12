//! A recursion exemption must never authenticate an unverified CRL signature.

use sigis_pki_certvalidator::ac::{validate_ac, verify_ac_crl, AcError};
use sigis_pki_certvalidator::{Cert, TrustAnchor, ValidationContext, ValidationPath};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::tlv::{tag, Tlv};
use sigis_pki_core::time::Moment;

fn input(parts: &[&str]) -> Vec<u8> {
    let mut path = vec!["attribute-certs", "basic-aa"];
    path.extend_from_slice(parts);
    std::fs::read(sigis_testdata::certvalidator(&path)).expect("committed fixture")
}

fn cert(parts: &[&str]) -> Cert {
    Cert::from_pem_or_der(&input(parts)).expect("certificate")
}

fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn crl_pair() -> (Vec<u8>, Vec<u8>) {
    let good = input(&["role-aa-all-good.crl"]);
    let outer = Tlv::parse_exact(&good).expect("CRL DER");
    let parts = outer.children().expect("CRL fields");
    assert_eq!(parts.len(), 3);
    assert!(parts[2].is_universal(tag::BIT_STRING));
    assert_eq!(parts[2].value[0], 0);
    assert!(parts[2].value.len() > 1);
    let offset = parts[2].value.as_ptr() as usize - good.as_ptr() as usize + 1;
    let mut bad = good.clone();
    bad[offset] ^= 1;
    let forged = Tlv::parse_exact(&bad).unwrap().children().unwrap();
    assert_eq!(parts[0].raw, forged[0].raw);
    assert_eq!(parts[1].raw, forged[1].raw);
    assert_ne!(parts[2].raw, forged[2].raw);
    eprintln!(
        "CRL_SIGNATURE_INPUT {}",
        serde_json::json!({
            "ac":sha(&input(&["aa", "alice-role-with-rev.attr.crt"])),
            "aa":sha(cert(&["interm", "role-aa.crt"]).der()),
            "good_crl":sha(&good), "bad_crl":sha(&bad),
            "tbs":sha(parts[0].raw), "algorithm":sha(parts[1].raw),
            "mutation":"only first signature byte bit0; TBS and algorithm unchanged",
        })
    );
    (good, bad)
}

fn context(crl: Vec<u8>, mode: &str) -> ValidationContext {
    ValidationContext::builder()
        .trust_root(cert(&["root", "root.crt"]))
        .other_cert(cert(&["root", "interm-role.crt"]))
        .other_cert(cert(&["interm", "role-aa.crt"]))
        .moment(Moment::parse_rfc3339("2019-12-12T00:00:00Z").unwrap())
        .revocation_mode(mode)
        .crl(input(&["root", "root-all-good.crl"]))
        .crl(input(&["interm", "interm-all-good.crl"]))
        .crl(crl)
        .build()
        .expect("context")
}

fn path() -> ValidationPath {
    ValidationPath::new(
        TrustAnchor::new(cert(&["root", "root.crt"])),
        vec![cert(&["root", "interm-role.crt"])],
        Some(cert(&["interm", "role-aa.crt"])),
    )
}

fn assert_bad(result: Result<(), AcError>, mode: &str) {
    let Err(error) = result else {
        panic!("a signature-only forged CRL was accepted under {mode}");
    };
    assert!(
        error
            .to_string()
            .contains("CRL signature could not be verified"),
        "{error}"
    );
}

#[test]
fn genuine_ac_crl_and_full_validation_positive_controls() {
    let (good, _) = crl_pair();
    let ac = input(&["aa", "alice-role-with-rev.attr.crt"]);
    for mode in ["require", "soft-fail"] {
        let ctx = context(good.clone(), mode);
        verify_ac_crl(&ctx, &ac, &path()).expect("genuine CRL");
        validate_ac(&ctx, &ac, None).expect("genuine full AC validation");
    }
}

#[test]
fn bad_signature_only_crl_is_rejected_by_the_direct_shared_consumer() {
    let (_, bad) = crl_pair();
    let ac = input(&["aa", "alice-role-with-rev.attr.crt"]);
    for mode in ["require", "soft-fail"] {
        assert_bad(
            verify_ac_crl(&context(bad.clone(), mode), &ac, &path()),
            mode,
        );
    }
}

#[test]
fn bad_signature_only_crl_is_rejected_by_full_ac_validation() {
    let (_, bad) = crl_pair();
    let ac = input(&["aa", "alice-role-with-rev.attr.crt"]);
    for mode in ["require", "soft-fail"] {
        let result = validate_ac(&context(bad.clone(), mode), &ac, None).map(|_| ());
        assert_bad(result, mode);
    }
}
