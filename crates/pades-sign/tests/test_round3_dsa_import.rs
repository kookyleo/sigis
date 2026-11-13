//! Native import controls for the still-excluded raw DSA token signing case.
//! Import is not a token signature or a completed upstream signing function.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use der::{Decode, Encode};
use sigis_pades_sign::keys::parse_pem;
use sigis_pades_sign::pkcs11::cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass,
};
use sigis_pades_sign::pkcs11::cryptoki::session::UserType;
use sigis_pades_sign::pkcs11::cryptoki::types::AuthPin;
use sigis_pades_sign::pkcs11::load_module;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::oids;

fn fixture() -> Vec<u8> {
    let bytes = support::pyhanko_data(&["crypto", "keys-dsa", "signer.key.pem"]);
    let blocks = parse_pem(&bytes).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].label, "PRIVATE KEY");
    blocks[0].der.clone()
}

fn digest(data: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn native_dsa_fixture_import_retains_prime_base_and_private_token_policy() {
    let _guard = support::softhsm::lock();
    let cfg = support::softhsm::p11_config("rsa").expect("mandatory isolated SoftHSM fixture");
    let module = load_module(&cfg.module).unwrap();
    let slot = module
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|slot| module.get_token_info(*slot).unwrap().label() == cfg.token_label)
        .unwrap();
    let session = module.open_rw_session(slot).unwrap();
    session
        .login(
            UserType::User,
            Some(&AuthPin::new(cfg.user_pin.clone().into())),
        )
        .unwrap();
    let input = fixture();
    let handle = support::softhsm::import_dsa_pkcs8(&session, &input, "dsa-import-proof").unwrap();
    let attrs = session
        .get_attributes(
            handle,
            &[
                AttributeType::Class,
                AttributeType::KeyType,
                AttributeType::Token,
                AttributeType::Private,
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::Sign,
                AttributeType::Prime,
                AttributeType::Base,
            ],
        )
        .unwrap();
    let cert = support::pki("testing-ca-dsa").cert("signer1");
    let public = cert.public_key();
    assert_eq!(public.algorithm.oid, oids::DSA);
    let params: support::softhsm::DsaParameters<'_> = public
        .algorithm
        .parameters
        .as_ref()
        .unwrap()
        .decode_as()
        .unwrap();
    for expected in [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::DSA),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Prime(params.prime.as_bytes().to_vec()),
        Attribute::Base(params.base.as_bytes().to_vec()),
    ] {
        assert!(
            attrs.contains(&expected),
            "missing imported attribute {expected:?}"
        );
    }
    // The generic input attribute can carry CKA_SUBPRIME, but cryptoki's
    // typed output conversion does not recognise that standard attribute.
    // Assert only its native presence/length, without claiming byte readback.
    let info = session
        .get_attribute_info(handle, &[AttributeType::VendorDefined(0x131)])
        .unwrap();
    assert!(matches!(
        info.as_slice(),
        [AttributeInfo::Available(length)] if *length == params.subprime.as_bytes().len()
    ));
    eprintln!(
        "DSA_IMPORT_PROOF module={} input_sha256={} input_length={} cert_sha256={}",
        cfg.module,
        digest(&input),
        input.len(),
        digest(cert.der())
    );
    session.destroy_object(handle).unwrap();
}

#[test]
fn invalid_dsa_key_metadata_is_rejected_before_token_object_creation() {
    let _guard = support::softhsm::lock();
    let cfg = support::softhsm::p11_config("rsa").expect("mandatory isolated SoftHSM fixture");
    let module = load_module(&cfg.module).unwrap();
    let slot = module
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|slot| module.get_token_info(*slot).unwrap().label() == cfg.token_label)
        .unwrap();
    let session = module.open_rw_session(slot).unwrap();
    session
        .login(
            UserType::User,
            Some(&AuthPin::new(cfg.user_pin.clone().into())),
        )
        .unwrap();
    let input = fixture();
    let valid = pkcs8::PrivateKeyInfoOwned::from_der(&input).unwrap();
    let mut wrong_oid = valid.clone();
    wrong_oid.algorithm.oid = oids::RSA_ENCRYPTION;
    let mut missing_params = valid.clone();
    missing_params.algorithm.parameters = None;
    let mut negative_x = valid.clone();
    negative_x.private_key = der::asn1::OctetString::new([2, 1, 255]).unwrap();
    let mut zero_x = valid;
    zero_x.private_key = der::asn1::OctetString::new([2, 1, 0]).unwrap();
    let query = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Label(b"dsa-import-invalid".to_vec()),
    ];
    let sentinel =
        support::softhsm::import_dsa_pkcs8(&session, &input, "dsa-import-invalid").unwrap();
    let before = session.find_objects(&query).unwrap();
    assert_eq!(before, [sentinel]);
    for (case, bytes) in [
        ("malformed", vec![0x30, 0]),
        ("wrong_algorithm", wrong_oid.to_der().unwrap()),
        ("missing_parameters", missing_params.to_der().unwrap()),
        ("negative_private_value", negative_x.to_der().unwrap()),
        ("zero_private_value", zero_x.to_der().unwrap()),
    ] {
        let error = support::softhsm::import_dsa_pkcs8(&session, &bytes, "dsa-import-invalid")
            .expect_err("invalid DSA metadata must be rejected");
        let retained =
            std::env::temp_dir().join(format!("sigis-p-dsa-{}-{case}.der", std::process::id()));
        std::fs::write(&retained, &bytes).unwrap();
        eprintln!(
            "DSA_IMPORT_NEGATIVE {}",
            serde_json::json!({
                "case": case, "input_path": retained, "input_sha256": digest(&bytes),
                "input_length": bytes.len(), "native_error": error,
            })
        );
        assert_eq!(session.find_objects(&query).unwrap(), before, "{case}");
    }
    session.destroy_object(sentinel).unwrap();
}
