//! Key loading, raw signatures, CMS assembly and the local TSA.
//!
//! These are infrastructure tests for the code under the ported pyHanko
//! suites; each CMS object is also checked by pyHanko's own validator when
//! the oracle is installed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use der::{Decode, Encode};
use sigis_pki_core::algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext};
use sigis_pki_core::sign::{KeySigner, TimeStamper};
use sigis_pades_sign::cms::decode_signed_data;
use sigis_pades_sign::keys::{load_private_key_from_pemder_data, PrivateKey};
use sigis_pades_sign::SimpleSigner;
use support::*;

#[test]
fn load_all_keysets() {
    for arch in ["testing-ca", "testing-ca-ecdsa", "testing-ca-ed25519", "testing-ca-ed448"] {
        let p = pki(arch);
        for label in ["root", "interm", "signer1", "signer2", "tsa", "interm-ocsp"] {
            let key = p.key(&p.key_label_of(label));
            assert_eq!(
                key.public_key_info().unwrap(),
                p.cert(label).public_key(),
                "{arch}/{label}"
            );
        }
    }
}

#[test]
fn unsupported_key_types_are_reported() {
    // DSA signing is not supported (pyHanko supports it; see docs/lanes/d.md)
    let p = pki("testing-ca-dsa");
    let entry = p.key_label_of("signer1");
    let r = std::panic::catch_unwind(|| p.key(&entry));
    assert!(r.is_err(), "DSA keys should be unsupported");
}

#[test]
fn encrypted_key_needs_password() {
    let data = pyhanko_data(&["crypto", "keys-rsa", "signer.key.pem"]);
    assert!(load_private_key_from_pemder_data(&data, None).is_err());
    assert!(load_private_key_from_pemder_data(&data, Some(b"wrong")).is_err());
    assert!(matches!(
        load_private_key_from_pemder_data(&data, Some(b"secret")).unwrap(),
        PrivateKey::Rsa(_)
    ));
    // PKCS#8 PBES2
    let data = pyhanko_data(&["crypto", "selfsigned.key.pem"]);
    assert!(load_private_key_from_pemder_data(&data, Some(b"secret")).is_ok());
}

#[test]
fn load_pkcs12_files() {
    // signer1.pfx: empty password, unencrypted key bag
    let pfx = pyhanko_data(&["crypto", "testing-ca", "interm", "signer1.pfx"]);
    let s = SimpleSigner::from_pkcs12(&pfx, None).unwrap();
    assert_eq!(s.cert_chain().len(), 2);
    let s2 = SimpleSigner::from_pkcs12(&pfx, Some(b"")).unwrap();
    assert_eq!(s.signing_cert(), s2.signing_cert());
    // selfsigned.pfx: RC2-40 certs, 3DES shrouded key
    let pfx = pyhanko_data(&["crypto", "selfsigned.pfx"]);
    assert!(SimpleSigner::from_pkcs12(&pfx, Some(b"wrong")).is_err());
    let s = SimpleSigner::from_pkcs12(&pfx, Some(b"exportsecret")).unwrap();
    let expected = sigis_pades_sign::keys::load_cert_from_pemder_data(&pyhanko_data(&[
        "crypto",
        "selfsigned.cert.pem",
    ]))
    .unwrap();
    assert_eq!(s.signing_cert(), &expected);
}

fn check_signer_info(cms_der: &[u8], data: &[u8], signer: &SimpleSigner, md: DigestAlgorithm) {
    let sd = decode_signed_data(cms_der).unwrap();
    let si = sd.signer_infos.0.iter().next().unwrap();
    let attrs = si.signed_attrs.as_ref().unwrap();
    let md_attr = attrs
        .iter()
        .find(|a| a.oid == sigis_pki_core::asn1::oids::MESSAGE_DIGEST)
        .unwrap();
    let digest = md_attr
        .values
        .iter()
        .next()
        .unwrap()
        .decode_as::<der::asn1::OctetString>()
        .unwrap();
    assert_eq!(digest.as_bytes(), md.digest(data));
    validate_signature(
        si.signature.as_bytes(),
        &attrs.to_der().unwrap(),
        &signer.signing_cert().public_key(),
        &si.signature_algorithm,
        &SignatureValidationContext {
            contextual_digest: Some(md),
            prehashed: false,
        },
    )
    .unwrap();
}

fn oracle_check_cms(
    p: &Pki,
    cms_der: &[u8],
    data: Option<&[u8]>,
    time: &str,
) -> Option<serde_json::Value> {
    let cms_path = temp_file("sig.p7s", cms_der);
    let root = p.cert_path("root");
    let mut args = vec![
        "--cms",
        path_str(&cms_path),
        "--trust",
        path_str(&root),
        "--time",
        time,
    ];
    let data_path;
    if let Some(d) = data {
        data_path = temp_file("data.bin", d);
        args.push("--data");
        args.push(path_str(&data_path));
    }
    let out = oracle("validate_cms.py", &args)?;
    Some(out)
}

#[test]
fn sign_general_data_all_key_types() {
    let data = b"Hello world!";
    for (arch, md) in [
        ("testing-ca", DigestAlgorithm::Sha256),
        ("testing-ca", DigestAlgorithm::Sha512),
        ("testing-ca-ecdsa", DigestAlgorithm::Sha256),
        ("testing-ca-ecdsa", DigestAlgorithm::Sha384),
        ("testing-ca-ed25519", DigestAlgorithm::Sha512),
    ] {
        let p = pki(arch);
        let signer = p.signer("signer1");
        for detached in [true, false] {
            let out = sigis_pades_sign::sign_general_data(data, &signer, md, detached, None).unwrap();
            check_signer_info(&out, data, &signer, md);
            let verdict = oracle_check_cms(
                &p,
                &out,
                detached.then_some(&data[..]),
                "2020-11-01T00:00:00+00:00",
            );
            if let Some(v) = verdict {
                assert_eq!(v["intact"], true, "{arch} {md:?}: {v}");
                assert_eq!(v["valid"], true, "{arch} {md:?}: {v}");
                assert_eq!(v["trusted"], true, "{arch} {md:?}: {v}");
                assert_eq!(v["md_algorithm"], md.name(), "{arch}: {v}");
            }
        }
    }
}

#[test]
fn ed25519_rejects_other_digest() {
    let p = pki("testing-ca-ed25519");
    let signer = p.signer("signer1");
    let err = sigis_pades_sign::sign_general_data(b"x", &signer, DigestAlgorithm::Sha256, true, None)
        .unwrap_err();
    assert!(err.to_string().contains("specifies message digest sha512"), "{err}");
}

#[test]
fn rsa_pss_signature() {
    let p = pki("testing-ca");
    let signer = p.signer("signer1").with_prefer_pss(true);
    let data = b"Hello world!";
    let out =
        sigis_pades_sign::sign_general_data(data, &signer, DigestAlgorithm::Sha256, true, None).unwrap();
    check_signer_info(&out, data, &signer, DigestAlgorithm::Sha256);
    if let Some(v) = oracle_check_cms(&p, &out, Some(data), "2020-11-01T00:00:00+00:00") {
        assert_eq!(v["valid"], true, "{v}");
        assert_eq!(v["pkcs7_signature_mechanism"], "rsassa_pss", "{v}");
    }
}

#[test]
fn signature_timestamp_from_dummy_tsa() {
    let p = pki("testing-ca");
    let signer = p.signer("signer1");
    let ts = p.tsa("tsa", at("2020-11-01T00:00:00Z"));
    let data = b"Hello world!";
    let out = sigis_pades_sign::sign_general_data(data, &signer, DigestAlgorithm::Sha256, true, Some(&ts))
        .unwrap();
    check_signer_info(&out, data, &signer, DigestAlgorithm::Sha256);
    if let Some(v) = oracle_check_cms(&p, &out, Some(data), "2020-11-01T00:00:00+00:00") {
        assert_eq!(v["valid"], true, "{v}");
        let tsv = &v["timestamp_validity"];
        assert_eq!(tsv["intact"], true, "{v}");
        assert_eq!(tsv["valid"], true, "{v}");
        assert_eq!(tsv["trusted"], true, "{v}");
        assert_eq!(tsv["timestamp"], "2020-11-01T00:00:00+00:00", "{v}");
    }
}

#[test]
fn dummy_tsa_token_validates() {
    let p = pki("testing-ca");
    let ts = p.tsa("tsa", at("2020-11-01T00:00:00Z"));
    for md in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha512] {
        let imprint = md.digest(b"some data");
        let token = ts.timestamp(&imprint, md).unwrap();
        let info = sigis_pades_sign::timestamps::tst_info(&token).unwrap();
        assert_eq!(info.message_imprint.hashed_message.as_bytes(), imprint);
        assert_eq!(
            sigis_pades_sign::timestamps::token_time(&token).unwrap(),
            at("2020-11-01T00:00:00Z")
        );
        let cms_path = temp_file("tst.der", &token);
        let root = p.cert_path("root");
        let hex: String = imprint.iter().map(|b| format!("{b:02x}")).collect();
        if let Some(v) = oracle(
            "validate_cms.py",
            &[
                "--cms",
                path_str(&cms_path),
                "--trust",
                path_str(&root),
                "--time",
                "2020-11-01T00:00:00+00:00",
                "--tst-imprint",
                &hex,
            ],
        ) {
            assert_eq!(v["intact"], true, "{v}");
            assert_eq!(v["valid"], true, "{v}");
            assert_eq!(v["trusted"], true, "{v}");
        }
    }
}

#[test]
fn signed_data_round_trips() {
    let p = pki("testing-ca");
    let signer = p.signer("signer1");
    let out =
        sigis_pades_sign::sign_general_data(b"abc", &signer, DigestAlgorithm::Sha256, true, None).unwrap();
    let ci = cms::content_info::ContentInfo::from_der(&out).unwrap();
    assert_eq!(ci.to_der().unwrap(), out);
    let sd = decode_signed_data(&out).unwrap();
    // signer cert plus root and intermediate
    assert_eq!(sd.certificates.unwrap().0.len(), 3);
}
