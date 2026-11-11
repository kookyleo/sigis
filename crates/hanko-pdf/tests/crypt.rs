// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_crypt.py`
// (MIT, see LICENSE-pyHanko). One Rust test per upstream test function;
// parametrized cases run in a loop.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::crypt::*;
use common::*;
use hanko_pdf::crypt::{
    add_crypt_filter, build_crypt_filter, encode_stream_with, AuthStatus, CipherKind, Credential, CryptFilter,
    CryptFilterConfiguration, CryptFilterRegistry, EnvelopeKeyDecrypter, HandlerType, LegacyEncryptOptions,
    PasswordCredential, PdfPermissions, PubKeyAdbeSubFilter, PubKeyCfData, PubKeyEncryptOptions, PubKeyPermissions,
    RecipientEncryptionPolicy, SecurityHandler, SecurityHandlerRegistry, SecurityHandlerVersion,
    SerialisableCredential, SerialisedCredential, SimpleEnvelopeKeyDecrypter, StandardEncryptOptions,
    StandardPermissions, StandardSecuritySettingsRevision, DEFAULT_CRYPT_FILTER, STD_CF,
};
use hanko_pdf::generic::{byte_string, pdf_name, text_string};
use hanko_pdf::lopdf::{Dictionary, Object, ObjectId};
use hanko_pdf::stream::{apply_filter_to_stream, DecodedStream, DuplicateFilter};
use hanko_pdf::writer::Encryptor;
use hanko_pdf::xref::XRefLocation;
use hanko_pdf::{IncrementalWriter, PdfError, PdfFile, PdfFileWriter, PdfHandler, PdfHandlerExt, ReaderOptions};

fn std_perms() -> StandardPermissions {
    !StandardPermissions::ALLOW_MODIFICATION_GENERIC & !StandardPermissions::ALLOW_ANNOTS_FORM_FILLING
}

fn pubkey_perms() -> PubKeyPermissions {
    !PubKeyPermissions::ALLOW_ENCRYPTION_CHANGE
        & !PubKeyPermissions::ALLOW_MODIFICATION_GENERIC
        & !PubKeyPermissions::ALLOW_ANNOTS_FORM_FILLING
}

fn vector_image_pdf() -> Vec<u8> {
    pdf("scribble.pdf")
}

fn new_writer() -> PdfFileWriter {
    PdfFileWriter::new(true, true).unwrap()
}

/// `w.root['/Pages'] = w.import_object(r.root.raw_get('/Pages'))`.
fn import_page_tree(w: &mut PdfFileWriter, r: &PdfFile) {
    let pages = r.root().unwrap().get(b"Pages").unwrap().clone();
    let new_tree = w.import_object(r, &pages, None).unwrap();
    let mut root = w.root().unwrap();
    root.set("Pages", new_tree);
    w.set_root(root);
}

fn set_root_entry(w: &mut hanko_pdf::PdfWriter, key: &str, value: Object) {
    let mut root = w.root().unwrap();
    root.set(key, value);
    let id = w.root_id();
    w.update_object(id, Object::Dictionary(root));
}

fn root_entry(h: &dyn PdfHandler, key: &str) -> Object {
    let root = h.root().unwrap();
    h.get(&root, key.as_bytes()).unwrap().unwrap()
}

fn stream_of(o: Object) -> hanko_pdf::lopdf::Stream {
    match o {
        Object::Stream(s) => s,
        other => panic!("not a stream: {other:?}"),
    }
}

fn encrypt_dict_of(r: &PdfFile) -> Dictionary {
    r.encrypt_dict().unwrap().unwrap()
}

fn auth_result_perms_sint(p: Option<PdfPermissions>) -> i32 {
    p.unwrap().as_sint32()
}

fn produce_legacy_encrypted_file(
    rev: StandardSecuritySettingsRevision,
    keylen_bytes: usize,
    use_aes: bool,
) -> Result<Vec<u8>, PdfError> {
    let r = read(&vector_image_pdf());
    let mut w = new_writer();
    let id1 = w.document_id().0.to_vec();
    let sh = SecurityHandler::build_from_pw_legacy(
        rev,
        &id1,
        "ownersecret",
        Some("usersecret".into()),
        LegacyEncryptOptions {
            keylen_bytes,
            use_aes128: use_aes,
            perms: std_perms(),
            ..Default::default()
        },
    )?;
    w.assign_security_handler(&sh)?;
    import_page_tree(&mut w, &r);
    w.write()
}

/// The checks of `_validate_pubkey_decryption` after `decrypt*`, minus
/// the status/permissions (checked by the caller).
fn check_vector_image_page(r: &PdfFile) {
    let (_, page) = first_page(r);
    let resources = r.get_dict(&page, b"Resources").unwrap().unwrap();
    assert!(resources.has(b"ExtGState"));
    let contents = stream_of(r.get(&page, b"Contents").unwrap().unwrap());
    let data = r.stream_data(&contents).unwrap();
    assert!(data.windows(15).any(|w| w == b"0 1 0 rg /a0 gs"));
}

fn validate_pubkey_decryption(r: &PdfFile, result: &hanko_pdf::crypt::AuthResult) {
    assert_eq!(result.status, AuthStatus::User);
    assert_eq!(result.permission_flags, Some(PdfPermissions::PubKey(pubkey_perms())));
    check_vector_image_page(r);
}

#[test]
fn test_legacy_encryption() {
    use StandardSecuritySettingsRevision as R;
    let cases = [
        (true, R::Rc4Basic, 5, false),
        (false, R::Rc4Basic, 5, false),
        (true, R::Rc4Extended, 5, false),
        (false, R::Rc4Extended, 5, false),
        (true, R::Rc4Extended, 16, false),
        (false, R::Rc4Extended, 16, false),
        (true, R::Rc4OrAes128, 5, false),
        (false, R::Rc4OrAes128, 5, false),
        (true, R::Rc4OrAes128, 16, false),
        (false, R::Rc4OrAes128, 16, false),
        (true, R::Rc4OrAes128, 16, true),
        (false, R::Rc4OrAes128, 16, true),
    ];
    for (use_owner_pass, rev, keylen, use_aes) in cases {
        let out = produce_legacy_encrypted_file(rev, keylen, use_aes).unwrap();
        let r = read(&out);
        let result = r
            .decrypt(if use_owner_pass { "ownersecret" } else { "usersecret" })
            .unwrap();
        let expected = if use_owner_pass { AuthStatus::Owner } else { AuthStatus::User };
        assert_eq!(result.status, expected, "{rev:?} {keylen} {use_aes}");
        assert_eq!(auth_result_perms_sint(result.permission_flags), -44);
        assert_eq!(encrypt_dict_of(&r).get(b"P").unwrap(), &Object::Integer(-44));
        check_vector_image_page(&r);
    }
}

#[test]
fn test_wrong_password() {
    for legacy in [true, false] {
        let mut w = new_writer();
        let r#ref = w.add_object(text_string("Blah blah")).unwrap();
        let sh = if legacy {
            let id1 = w.document_id().0.to_vec();
            SecurityHandler::build_from_pw_legacy(
                StandardSecuritySettingsRevision::Rc4OrAes128,
                &id1,
                "ownersecret",
                Some("usersecret".into()),
                LegacyEncryptOptions::default(),
            )
            .unwrap()
        } else {
            SecurityHandler::build_from_pw("ownersecret", Some("usersecret".into()), Default::default()).unwrap()
        };
        // w.security_handler = sh; w._encrypt = w.add_object(sh.as_pdf_object())
        w.set_encryption(Object::Dictionary(sh.as_pdf_object().unwrap()), sh.encryptor())
            .unwrap();
        let out = w.write().unwrap();
        let r = read(&out);
        let e = r.get_object(r#ref).unwrap_err();
        assert!(e.is_read_error(), "{e:?}");
        assert_eq!(r.decrypt("thispasswordiswrong").unwrap().status, AuthStatus::Failed);
        let sh = r.security_handler().unwrap().unwrap();
        assert!(sh.auth_failed());
        assert!(sh.string_filter_auth_failed());
        let e = r.get_object(r#ref).unwrap_err();
        assert!(e.is_read_error(), "{e:?}");
    }
}

#[test]
fn test_identity_crypt_filter_api() {
    let mut idf = CryptFilter::identity();
    assert!(idf.is_identity());
    assert_eq!(idf.method(), b"None");
    assert_eq!(idf.keylen(), 0);
    assert_eq!(idf.decrypt(b"", b"abc").unwrap(), b"abc");
    assert_eq!(idf.encrypt(b"", b"abc").unwrap(), b"abc");
    // derive_shared_encryption_key / derive_object_key: always empty
    let sh = SecurityHandler::build_from_pw("secret", None, Default::default()).unwrap();
    assert_eq!(sh.crypt_filter_shared_key("Identity").unwrap(), b"");
    // can't serialise /Identity
    let e = idf.as_pdf_object().unwrap_err();
    assert!(e.is_pdf_error());
}

#[test]
fn test_identity_crypt_filter() {
    for (use_alias, with_never_decrypt) in [(true, false), (false, true), (false, false)] {
        let mut w = new_writer();
        let sh = SecurityHandler::build_from_pw("secret", None, Default::default()).unwrap();
        assert!(sh.crypt_filter_config().get("/Identity").unwrap().is_identity());
        if use_alias {
            sh.insert_crypt_filter("/IdentityAlias", CryptFilter::identity());
            assert!(sh.crypt_filter_config().get("/IdentityAlias").unwrap().is_identity());
            // identity filter can't be serialised
            let e = w.assign_security_handler(&sh).unwrap_err();
            assert!(e.is_pdf_error());
            continue;
        }
        w.assign_security_handler(&sh).unwrap();
        let test_bytes = b"This is some test data that should remain unencrypted.".to_vec();
        let mut ds = DecodedStream::new(Dictionary::new(), test_bytes.clone());
        let mut params = Dictionary::new();
        params.set("Name", pdf_name("/Identity"));
        ds.apply_filter("/Crypt", Some(params), DuplicateFilter::Allow).unwrap();
        let stream = encode_stream_with(&ds, &sh).unwrap();
        let r#ref = w.add_object(Object::Stream(stream)).unwrap();
        let out = w.write().unwrap();

        let r = read(&out);
        r.decrypt("secret").unwrap();
        let the_stream = stream_of(if with_never_decrypt {
            r.get_object_raw(r#ref, None).unwrap()
        } else {
            r.get_object(r#ref).unwrap()
        });
        assert_eq!(the_stream.content, test_bytes);
        assert_eq!(r.stream_data(&the_stream).unwrap(), test_bytes);
    }
}

fn produce_pubkey_encrypted_file(
    version: SecurityHandlerVersion,
    keylen: usize,
    use_aes: bool,
    use_crypt_filters: bool,
    policy: RecipientEncryptionPolicy,
    cert: Option<Vec<u8>>,
) -> Result<Vec<u8>, PdfError> {
    let cert = cert.unwrap_or_else(|| pubkey_test_decrypter().cert_info().der().to_vec());
    let r = read(&vector_image_pdf());
    let mut w = new_writer();
    let sh = SecurityHandler::build_from_certs(
        &[cert],
        PubKeyEncryptOptions {
            keylen_bytes: keylen,
            version,
            use_aes,
            use_crypt_filters,
            perms: pubkey_perms(),
            policy,
            pdf_mac: false,
            ..Default::default()
        },
    )?;
    w.assign_security_handler(&sh)?;
    import_page_tree(&mut w, &r);
    w.write()
}

/// The first recipient's `RecipientInfo` of the default crypt filter.
fn first_recipient_info(r: &PdfFile) -> cms::enveloped_data::RecipientInfo {
    use der::Decode;
    let enc = encrypt_dict_of(r);
    let cf = as_dict(enc.get(b"CF").unwrap().clone());
    let dcf = as_dict(cf.get(DEFAULT_CRYPT_FILTER.as_bytes()).unwrap().clone());
    let recps = match dcf.get(b"Recipients").unwrap() {
        Object::Array(a) => a.clone(),
        other => vec![other.clone()],
    };
    let Object::String(recp, _) = &recps[0] else { panic!() };
    let ci = cms::content_info::ContentInfo::from_der(recp).unwrap();
    let ed: cms::enveloped_data::EnvelopedData = ci.content.decode_as().unwrap();
    ed.recip_infos.0.iter().next().unwrap().clone()
}

fn extract_ktri_kea(r: &PdfFile) -> String {
    match first_recipient_info(r) {
        cms::enveloped_data::RecipientInfo::Ktri(k) => k.key_enc_alg.oid.to_string(),
        other => panic!("not ktri: {other:?}"),
    }
}

const RSAES_PKCS1V15: &str = "1.2.840.113549.1.1.1";
const RSAES_OAEP: &str = "1.2.840.113549.1.1.7";

fn pubkey_cases() -> Vec<(SecurityHandlerVersion, usize, bool, bool)> {
    use SecurityHandlerVersion as V;
    vec![
        (V::Aes256, 32, true, true),
        (V::Rc4OrAes128, 16, true, true),
        (V::Rc4OrAes128, 16, false, true),
        (V::Rc4OrAes128, 5, false, true),
        (V::Rc4_40, 5, false, true),
        (V::Rc4_40, 5, false, false),
        (V::Rc4LongerKeys, 5, false, true),
        (V::Rc4LongerKeys, 5, false, false),
        (V::Rc4LongerKeys, 16, false, true),
        (V::Rc4LongerKeys, 16, false, false),
    ]
}

#[test]
fn test_pubkey_encryption() {
    for (version, keylen, use_aes, use_crypt_filters) in pubkey_cases() {
        let out =
            produce_pubkey_encrypted_file(version, keylen, use_aes, use_crypt_filters, Default::default(), None)
                .unwrap();
        let r = read(&out);
        if version == SecurityHandlerVersion::Aes256 {
            assert_eq!(r.input_version(), (2, 0));
        }
        let result = r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
        validate_pubkey_decryption(&r, &result);
        if version == SecurityHandlerVersion::Aes256 {
            assert_eq!(extract_ktri_kea(&r), RSAES_PKCS1V15);
        }
    }
}

const ECC_LABELS: [&str; 5] = ["decrypter1", "decrypter2", "decrypter3", "decrypter-x25519", "decrypter-x448"];

#[test]
fn test_ecdh_encryption() {
    for lbl in ECC_LABELS {
        let cert = ecc_decrypter_cert(lbl);
        let out = produce_pubkey_encrypted_file(
            SecurityHandlerVersion::Aes256,
            32,
            true,
            true,
            Default::default(),
            Some(cert),
        )
        .unwrap();
        let r = read(&out);
        let result = r.decrypt_pubkey(&ecc_decrypter(lbl)).unwrap();
        validate_pubkey_decryption(&r, &result);
    }
}

#[test]
fn test_oaep_encryption() {
    let out = produce_pubkey_encrypted_file(
        SecurityHandlerVersion::Aes256,
        32,
        true,
        true,
        RecipientEncryptionPolicy {
            prefer_oaep: true,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let r = read(&out);
    let result = r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
    validate_pubkey_decryption(&r, &result);
    assert_eq!(extract_ktri_kea(&r), RSAES_OAEP);
}

#[test]
fn test_ecdh_decryption_smoke() {
    let r = read(&pdf("pubkey-ecc-test.pdf"));
    let result = r.decrypt_pubkey(&ecc_decrypter("decrypter3")).unwrap();
    assert_eq!(result.status, AuthStatus::User);
    assert_eq!(
        result.permission_flags,
        Some(PdfPermissions::PubKey(PubKeyPermissions::allow_everything()))
    );
}

fn assert_inappropriate_credential(e: PdfError) {
    // InappropriateCredentialError (a TypeError)
    assert!(matches!(e, PdfError::Value(_)), "{e:?}");
    assert!(e.message().contains("InappropriateCredentialError"), "{e:?}");
}

#[test]
fn test_ecdh_decryption_wrong_key_type() {
    let r = read(&pdf("pubkey-ecc-test.pdf"));
    let decrypter = SimpleEnvelopeKeyDecrypter::new(
        &ecc_decrypter_cert("decrypter3"),
        pubkey_test_decrypter().private_key_der(),
    )
    .unwrap();
    assert_inappropriate_credential(r.decrypt_pubkey(&decrypter).unwrap_err());
}

#[test]
fn test_ecdh_decryption_wrong_curve() {
    let r = read(&pdf("pubkey-ecc-test.pdf"));
    let decrypter =
        SimpleEnvelopeKeyDecrypter::new(&ecc_decrypter_cert("decrypter3"), &ecc_decrypter_key("decrypter1")).unwrap();
    let e = assert_err_matches(r.decrypt_pubkey(&decrypter), "Failed to decrypt");
    assert!(e.is_read_error());
}

#[test]
fn test_rsa_decryption_wrong_key_type() {
    let r = read(&pdf("minimal-pubkey-rc4-envelope.pdf"));
    let decrypter = SimpleEnvelopeKeyDecrypter::new(
        pubkey_test_decrypter_old().cert_info().der(),
        &ecc_decrypter_key("decrypter1"),
    )
    .unwrap();
    assert_inappropriate_credential(r.decrypt_pubkey(&decrypter).unwrap_err());
}

/// Replace the originator key of the first (kari) recipient of every
/// recipient CMS object in the default crypt filter (pyHanko monkeypatches
/// `_format_kari`).
fn swap_originator_key(enc: &mut Dictionary, new_spki: &[u8]) {
    use cms::enveloped_data::{EnvelopedData, OriginatorIdentifierOrKey, OriginatorPublicKey, RecipientInfo};
    use der::{Decode, Encode};
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(new_spki).unwrap();
    let mut cf = as_dict(enc.get(b"CF").unwrap().clone());
    let mut dcf = as_dict(cf.get(DEFAULT_CRYPT_FILTER.as_bytes()).unwrap().clone());
    let Object::Array(recps) = dcf.get(b"Recipients").unwrap().clone() else { panic!() };
    let mut new_recps = Vec::new();
    for r in recps {
        let Object::String(r, _) = r else { panic!() };
        let mut ci = cms::content_info::ContentInfo::from_der(&r).unwrap();
        let mut ed: EnvelopedData = ci.content.decode_as().unwrap();
        let mut infos: Vec<RecipientInfo> = ed.recip_infos.0.iter().cloned().collect();
        for ri in infos.iter_mut() {
            if let RecipientInfo::Kari(k) = ri {
                k.originator = OriginatorIdentifierOrKey::OriginatorKey(OriginatorPublicKey {
                    algorithm: spki.algorithm.clone(),
                    public_key: spki.subject_public_key.clone(),
                });
            }
        }
        ed.recip_infos = cms::enveloped_data::RecipientInfos(infos.try_into().unwrap());
        ci.content = der::Any::encode_from(&ed).unwrap();
        new_recps.push(byte_string(ci.to_der().unwrap()));
    }
    dcf.set("Recipients", Object::Array(new_recps));
    cf.set(DEFAULT_CRYPT_FILTER, Object::Dictionary(dcf));
    enc.set("CF", Object::Dictionary(cf));
}

#[test]
fn test_invalid_originator_key() {
    for lbl in ["decrypter1", "decrypter-x25519", "decrypter-x448"] {
        let cert = ecc_decrypter_cert(lbl);
        let r = read(&vector_image_pdf());
        let mut w = new_writer();
        let sh = SecurityHandler::build_from_certs(
            &[cert],
            PubKeyEncryptOptions {
                keylen_bytes: 32,
                perms: pubkey_perms(),
                pdf_mac: false,
                ..Default::default()
            },
        )
        .unwrap();
        let eid = w.assign_security_handler(&sh).unwrap();
        let mut enc = as_dict(w.get_object(eid).unwrap());
        let rsa_spki = hanko_pdf::crypt::CertInfo::from_der(pubkey_test_decrypter().cert_info().der())
            .unwrap()
            .spki_der()
            .to_vec();
        swap_originator_key(&mut enc, &rsa_spki);
        w.update_object(eid, Object::Dictionary(enc));
        import_page_tree(&mut w, &r);
        let out = w.write().unwrap();
        let r = read(&out);
        let e = r.decrypt_pubkey(&ecc_decrypter(lbl)).unwrap_err();
        assert!(e.is_read_error(), "{lbl}: {e:?}");
    }
}

#[test]
fn test_key_encipherment_requirement() {
    let e = SecurityHandler::build_from_certs(
        &[pubkey_selfsigned_decrypter().cert_info().der().to_vec()],
        PubKeyEncryptOptions {
            keylen_bytes: 32,
            perms: pubkey_perms(),
            pdf_mac: false,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(e, PdfError::Write(_)), "{e:?}");
}

#[test]
fn test_key_encipherment_requirement_override() {
    for (version, keylen, use_aes, use_crypt_filters) in pubkey_cases() {
        let r = read(&vector_image_pdf());
        let mut w = new_writer();
        let sh = SecurityHandler::build_from_certs(
            &[pubkey_selfsigned_decrypter().cert_info().der().to_vec()],
            PubKeyEncryptOptions {
                keylen_bytes: keylen,
                version,
                use_aes,
                use_crypt_filters,
                perms: pubkey_perms(),
                policy: RecipientEncryptionPolicy {
                    ignore_key_usage: true,
                    ..Default::default()
                },
                pdf_mac: false,
                ..Default::default()
            },
        )
        .unwrap();
        w.assign_security_handler(&sh).unwrap();
        import_page_tree(&mut w, &r);
        let out = w.write().unwrap();
        let r = read(&out);
        let result = r.decrypt_pubkey(&pubkey_selfsigned_decrypter()).unwrap();
        validate_pubkey_decryption(&r, &result);
    }
}

fn modify_encrypt_dict(w: &mut hanko_pdf::PdfWriter, f: impl FnOnce(&mut Dictionary)) {
    let eid = w.encrypt_ref().unwrap();
    let mut enc = as_dict(w.get_object(eid).unwrap());
    f(&mut enc);
    w.update_object(eid, Object::Dictionary(enc));
}

fn test_cert() -> Vec<u8> {
    pubkey_test_decrypter().cert_info().der().to_vec()
}

/// `PdfFileReader(out).root['/Pages']['/Kids'][0]['/Content'].data`
fn read_first_page_contents(out: &[u8]) -> Result<(), PdfError> {
    let r = PdfFile::parse_with(out, ReaderOptions::default())?;
    let root = r.root()?;
    let pages = r.get_dict(&root, b"Pages")?.ok_or_else(|| PdfError::Value("no pages".into()))?;
    let kids = r.get_array(&pages, b"Kids")?.unwrap_or_default();
    if let Some(k) = kids.first() {
        let page = r.resolve(k)?;
        let _ = page;
    }
    Ok(())
}

#[test]
fn test_pubkey_alternative_filter() {
    let mut w = new_writer();
    w.encrypt_pubkey(&[test_cert()]).unwrap();
    // subfilter should be picked up
    modify_encrypt_dict(&mut w, |d| d.set("Filter", pdf_name("/FooBar")));
    let out = w.write().unwrap();
    let r = read(&out);
    assert_eq!(r.security_handler().unwrap().unwrap().handler_type(), HandlerType::PubKey);
}

#[test]
fn test_pubkey_unsupported_filter() {
    for delete_subfilter in [true, false] {
        let mut w = new_writer();
        w.encrypt_pubkey(&[test_cert()]).unwrap();
        modify_encrypt_dict(&mut w, |d| {
            d.set("Filter", pdf_name("/FooBar"));
            if delete_subfilter {
                d.remove(b"SubFilter");
            } else {
                d.set("SubFilter", pdf_name("/baz.quux"));
            }
        });
        let out = w.write().unwrap();
        let e = read_first_page_contents(&out).unwrap_err();
        assert!(e.is_read_error(), "{e:?}");
    }
}

#[test]
fn test_pubkey_encryption_block_cfs_s4() {
    let mut w = new_writer();
    w.encrypt_pubkey(&[test_cert()]).unwrap();
    modify_encrypt_dict(&mut w, |d| d.set("SubFilter", pdf_name("/adbe.pkcs7.s4")));
    let out = w.write().unwrap();
    let e = read_first_page_contents(&out).unwrap_err();
    assert!(e.is_read_error(), "{e:?}");
}

#[test]
fn test_pubkey_encryption_s5_requires_cfs() {
    let mut w = new_writer();
    let sh = SecurityHandler::build_from_certs(&[test_cert()], Default::default()).unwrap();
    w.assign_security_handler(&sh).unwrap();
    modify_encrypt_dict(&mut w, |d| {
        d.remove(b"CF");
    });
    let out = w.write().unwrap();
    let e = read_first_page_contents(&out).unwrap_err();
    assert!(e.is_read_error(), "{e:?}");
}

#[test]
fn test_pubkey_encryption_dict_errors() {
    let sh = SecurityHandler::build_from_certs(&[test_cert()], Default::default()).unwrap();
    let base = sh.as_pdf_object().unwrap();
    let with_dcf = |f: &dyn Fn(&mut Dictionary)| {
        let mut enc = base.clone();
        let mut cf = as_dict(enc.get(b"CF").unwrap().clone());
        let mut dcf = as_dict(cf.get(b"DefaultCryptFilter").unwrap().clone());
        f(&mut dcf);
        cf.set("DefaultCryptFilter", Object::Dictionary(dcf));
        enc.set("CF", Object::Dictionary(cf));
        enc
    };

    let mut enc = base.clone();
    enc.set("SubFilter", pdf_name("/asdflakdsjf"));
    assert!(SecurityHandler::build(&enc).unwrap_err().is_read_error());

    let mut enc = base.clone();
    enc.set("Length", Object::Integer(13));
    assert!(SecurityHandler::build(&enc).unwrap_err().is_pdf_error());

    let enc = with_dcf(&|d| {
        d.remove(b"CFM");
    });
    assert!(SecurityHandler::build(&enc).unwrap_err().is_read_error());

    let enc = with_dcf(&|d| {
        d.remove(b"Recipients");
    });
    assert!(SecurityHandler::build(&enc).unwrap_err().is_read_error());

    let enc = with_dcf(&|d| d.set("CFM", pdf_name("/None")));
    assert!(SecurityHandler::build(&enc).unwrap_err().is_read_error());
}

/// `obj['/DecodeParms']` (with hex filter: `[1]`) `['/Name']`.
fn crypt_params_name(stream: &hanko_pdf::lopdf::Stream, with_hex_filter: bool) -> Object {
    let dp = stream.dict.get(b"DecodeParms").unwrap().clone();
    let cf_dict = if with_hex_filter {
        match dp {
            Object::Array(a) => as_dict(a[1].clone()),
            other => panic!("{other:?}"),
        }
    } else {
        as_dict(dp)
    };
    cf_dict.get(b"Name").unwrap().clone()
}

#[test]
fn test_custom_crypt_filter() {
    for (with_hex_filter, main_unencrypted) in [(true, false), (true, true), (false, true), (false, false)] {
        let mut w = new_writer();
        let custom = "/Custom";
        let cfc = if main_unencrypted {
            // streams/strings are unencrypted by default
            let cfc = CryptFilterConfiguration::with_filters(vec![(custom, CryptFilter::standard_rc4(16))]).unwrap();
            assert_eq!(cfc.len(), 1);
            cfc
        } else {
            let cfc = CryptFilterConfiguration::new(
                vec![
                    (custom, CryptFilter::standard_rc4(16)),
                    (STD_CF, CryptFilter::standard_aes(16).unwrap()),
                ],
                STD_CF,
                STD_CF,
                None,
            )
            .unwrap();
            assert_eq!(cfc.len(), 2);
            cfc
        };
        let id1 = w.document_id().0.to_vec();
        let sh = SecurityHandler::build_from_pw_legacy(
            StandardSecuritySettingsRevision::Rc4OrAes128,
            &id1,
            "ownersecret",
            Some("usersecret".into()),
            LegacyEncryptOptions {
                keylen_bytes: 16,
                crypt_filter_config: Some(cfc),
                ..Default::default()
            },
        )
        .unwrap();
        w.assign_security_handler(&sh).unwrap();
        let test_data = b"This is test data!".to_vec();
        let mut dummy = DecodedStream::new(Dictionary::new(), test_data.clone());
        add_crypt_filter(&mut dummy, custom, None, Some(&sh)).unwrap();
        if with_hex_filter {
            dummy.apply_filter("/AHx", None, DuplicateFilter::Allow).unwrap();
        }
        let r#ref = w.add_object(Object::Stream(encode_stream_with(&dummy, &sh).unwrap())).unwrap();
        let ref2 = w.add_object(Object::Stream(DecodedStream::new(Dictionary::new(), test_data.clone()).to_stream().unwrap())).unwrap();
        let out = w.write().unwrap();

        let r = read(&out);
        r.decrypt("ownersecret").unwrap();
        let obj = stream_of(r.get_object(r#ref).unwrap());
        assert_eq!(r.stream_data(&obj).unwrap(), test_data);
        assert_eq!(crypt_params_name(&obj, with_hex_filter), pdf_name("/Custom"));
        let raw = stream_of(r.get_object_raw(ref2, None).unwrap());
        assert_eq!(raw.content == test_data, main_unencrypted);
    }
}

#[test]
fn test_custom_pubkey_crypt_filter() {
    for (with_hex_filter, main_unencrypted) in [(true, false), (true, true), (false, true), (false, false)] {
        let mut w = new_writer();
        let custom = "/Custom";
        let mut filters = vec![(custom, CryptFilter::pubkey_rc4(16, PubKeyCfData::new(None, false, true)))];
        let cfc = if main_unencrypted {
            CryptFilterConfiguration::with_filters(filters).unwrap()
        } else {
            filters.push((
                DEFAULT_CRYPT_FILTER,
                CryptFilter::pubkey_aes(16, PubKeyCfData::new(None, true, true)).unwrap(),
            ));
            CryptFilterConfiguration::new(filters, DEFAULT_CRYPT_FILTER, DEFAULT_CRYPT_FILTER, None).unwrap()
        };
        let sh = SecurityHandler::new_pubkey(
            SecurityHandlerVersion::Rc4OrAes128,
            PubKeyAdbeSubFilter::S5,
            16,
            true,
            Some(cfc),
            None,
            true,
            None,
        )
        .unwrap();
        let all = PubKeyPermissions::allow_everything();
        // if main_unencrypted, these should be no-ops
        sh.add_recipients(&[test_cert()], all, Default::default()).unwrap();
        // (this is always pointless, but it should be allowed)
        sh.add_recipients(&[test_cert()], all, Default::default()).unwrap();
        sh.add_crypt_filter_recipients(custom, &[test_cert()], Default::default(), all)
            .unwrap();
        let eid = w.assign_security_handler(&sh).unwrap();

        let encrypt_dict = as_dict(w.get_object(eid).unwrap());
        let cfs = as_dict(encrypt_dict.get(b"CF").unwrap().clone());
        // no /Recipients in S5 mode
        assert!(!encrypt_dict.has(b"Recipients"));
        let custom_cf = as_dict(cfs.get(b"Custom").unwrap().clone());
        assert!(matches!(custom_cf.get(b"Recipients").unwrap(), Object::String(..)));
        if main_unencrypted {
            assert!(!cfs.has(DEFAULT_CRYPT_FILTER.as_bytes()));
        } else {
            let dcf = as_dict(cfs.get(DEFAULT_CRYPT_FILTER.as_bytes()).unwrap().clone());
            let Object::Array(rs) = dcf.get(b"Recipients").unwrap() else { panic!() };
            assert_eq!(rs.len(), 2);
        }
        // custom crypt filters can only have one set of recipients
        let e = sh
            .add_crypt_filter_recipients(custom, &[test_cert()], Default::default(), all)
            .unwrap_err();
        assert!(e.is_pdf_error());

        let test_data = b"This is test data!".to_vec();
        let mut dummy = DecodedStream::new(Dictionary::new(), test_data.clone());
        add_crypt_filter(&mut dummy, custom, None, Some(&sh)).unwrap();
        if with_hex_filter {
            dummy.apply_filter("/AHx", None, DuplicateFilter::Allow).unwrap();
        }
        let r#ref = w.add_object(Object::Stream(encode_stream_with(&dummy, &sh).unwrap())).unwrap();
        let ref2 = w.add_object(Object::Stream(DecodedStream::new(Dictionary::new(), test_data.clone()).to_stream().unwrap())).unwrap();
        let out = w.write().unwrap();

        let r = read(&out);
        r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
        // the custom filter hasn't been authenticated yet: decoding fails
        let obj = stream_of(r.get_object(r#ref).unwrap());
        let e = r.stream_data(&obj).unwrap_err();
        assert!(e.is_pdf_error(), "{e:?}");
        r.security_handler()
            .unwrap()
            .unwrap()
            .authenticate_crypt_filter(custom, &pubkey_test_decrypter())
            .unwrap();
        // a fresh copy of the stream (decoded data is cached per stream)
        let obj = stream_of(r.get_object(r#ref).unwrap());
        assert_eq!(r.stream_data(&obj).unwrap(), test_data);
        assert_eq!(crypt_params_name(&obj, with_hex_filter), pdf_name("/Custom"));
        let raw = stream_of(r.get_object_raw(ref2, None).unwrap());
        assert_eq!(raw.content == test_data, main_unencrypted);
    }
}

#[test]
fn test_custom_crypt_filter_errors() {
    let w = new_writer();
    let cfc = CryptFilterConfiguration::new(
        vec![
            ("/Custom", CryptFilter::standard_rc4(16)),
            (STD_CF, CryptFilter::standard_aes(16).unwrap()),
        ],
        STD_CF,
        STD_CF,
        None,
    )
    .unwrap();
    let id1 = w.document_id().0.to_vec();
    let sh = SecurityHandler::build_from_pw_legacy(
        StandardSecuritySettingsRevision::Rc4OrAes128,
        &id1,
        "ownersecret",
        Some("usersecret".into()),
        LegacyEncryptOptions {
            keylen_bytes: 16,
            crypt_filter_config: Some(cfc),
            ..Default::default()
        },
    )
    .unwrap();
    let mut dummy = DecodedStream::new(Dictionary::new(), b"This is test data!".to_vec());
    let e = add_crypt_filter(&mut dummy, "/Idontexist", None, Some(&sh)).unwrap_err();
    assert!(e.is_stream_error());
    // no handler at encoding time
    add_crypt_filter(&mut dummy, "/Custom", None, Some(&sh)).unwrap();
    let e = dummy.to_stream().unwrap_err();
    assert!(e.is_stream_error(), "{e:?}");
}

fn standard_opts(pdf_mac: bool) -> StandardEncryptOptions {
    StandardEncryptOptions {
        pdf_mac,
        ..Default::default()
    }
}

/// A writer with a `/Test` string in the root, encrypted and written.
fn encrypted_with_test_entry(pdf_mac: bool) -> Vec<u8> {
    let mut w = new_writer();
    set_root_entry(&mut w, "Test", text_string("Blah blah"));
    w.encrypt_with("ownersecret", Some("usersecret"), standard_opts(pdf_mac)).unwrap();
    w.write().unwrap()
}

/// Update `/Test` in the root of an encrypted file without credentials.
/// The root cannot be decrypted here (eager decryption), so it is taken
/// raw; the write must fail either way.
fn continue_without_auth(out: &[u8], update_meta: bool) -> Result<Vec<u8>, PdfError> {
    let base = read(out);
    let mut w = IncrementalWriter::try_new(base.clone())?;
    w.update_meta_on_write = update_meta;
    let root_id = w.root_id();
    let mut root = match w.root() {
        Ok(r) => r,
        Err(e) => {
            // pyHanko can read the root dictionary lazily; accessing the
            // encrypted /Test string would fail the same way
            assert!(matches!(e, PdfError::KeyNotAvailable(_)), "{e:?}");
            as_dict(base.get_object_raw(root_id, None)?)
        }
    };
    root.set("Test", text_string("Bluh bluh"));
    w.update_object(root_id, Object::Dictionary(root));
    w.write_in_place()
}

#[test]
fn test_continue_encrypted_file_without_auth() {
    for pdf_mac in [true, false] {
        let out = encrypted_with_test_entry(pdf_mac);
        let e = continue_without_auth(&out, true).unwrap_err();
        // with pdf_mac=False, pyHanko fails while updating the XMP metadata
        // stream; so does the port
        assert!(matches!(e, PdfError::KeyNotAvailable(_)), "pdf_mac={pdf_mac}: {e:?}");
    }
}

#[test]
fn test_continue_encrypted_file_without_auth_disable_meta() {
    let out = encrypted_with_test_entry(true);
    let e = continue_without_auth(&out, false).unwrap_err();
    assert!(matches!(e, PdfError::KeyNotAvailable(_)), "{e:?}");
}

#[test]
fn test_continue_encrypted_file_without_auth_disable_meta_and_mac() {
    let out = encrypted_with_test_entry(false);
    assert_err_matches(continue_without_auth(&out, false), "Cannot update");
}

#[test]
fn test_continue_encrypted_file_from_reader() {
    let out = encrypted_with_test_entry(true);
    let r = read(&out);
    // first decrypt, then extend
    r.decrypt("usersecret").unwrap();
    let mut w = IncrementalWriter::new(r);
    set_root_entry(&mut w, "Test", text_string("Bluh bluh"));
    let out = w.write_in_place().unwrap();

    let r = read(&out);
    let res = r.decrypt("usersecret").unwrap();
    assert_eq!(res.mac_status, hanko_pdf::crypt::PdfMacStatus::Successful);
    assert_eq!(text(&root_entry(&r, "Test")), "Bluh bluh");
}

#[test]
fn test_aes256_perm_read() {
    let data = pdf("minimal-with-field-aes256.pdf");
    let r = read(&data);
    let result = r.decrypt("ownersecret").unwrap();
    assert_eq!(result.status, AuthStatus::Owner);
    assert_eq!(result.permission_flags, Some(StandardPermissions::allow_everything().into()));
    let r = read(&data);
    let result = r.decrypt("usersecret").unwrap();
    assert_eq!(result.status, AuthStatus::User);
    assert_eq!(result.permission_flags, Some(StandardPermissions::allow_everything().into()));
    assert_eq!(encrypt_dict_of(&r).get(b"P").unwrap(), &Object::Integer(-4));
}

fn fields_and_kids(r: &PdfFile) -> (Vec<Object>, Vec<Object>) {
    let root = r.root().unwrap();
    let acroform = r.get_dict(&root, b"AcroForm").unwrap().unwrap();
    let fields = r.get_array(&acroform, b"Fields").unwrap().unwrap();
    let pages = r.get_dict(&root, b"Pages").unwrap().unwrap();
    let kids = r.get_array(&pages, b"Kids").unwrap().unwrap();
    (fields, kids)
}

#[test]
fn test_copy_encrypted_file() {
    let r = read(&pdf("minimal-with-field-aes256.pdf"));
    r.decrypt("ownersecret").unwrap();
    let mut w = hanko_pdf::writer::copy_into_new_writer(&r).unwrap();
    let old_root_ref = w.root_id();
    let out = w.write().unwrap();
    let r = read(&out);
    assert_eq!(r.root_ref().unwrap(), old_root_ref);
    let (fields, kids) = fields_and_kids(&r);
    assert_eq!(fields.len(), 1);
    assert_eq!(kids.len(), 1);
}

#[test]
fn test_copy_to_encrypted_file() {
    let r = read(&pdf("minimal-with-field.pdf"));
    let mut w = hanko_pdf::writer::copy_into_new_writer(&r).unwrap();
    let old_root_ref = w.root_id();
    w.encrypt("ownersecret", Some("usersecret")).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    let result = r.decrypt("ownersecret").unwrap();
    assert_eq!(result.status, AuthStatus::Owner);
    assert_eq!(r.root_ref().unwrap(), old_root_ref);
    let (fields, kids) = fields_and_kids(&r);
    assert_eq!(fields.len(), 1);
    assert_eq!(kids.len(), 1);
}

#[test]
fn test_correctly_align_perms() {
    let r = read(&pdf("minimal-with-field.pdf"));
    let mut w = hanko_pdf::writer::copy_into_new_writer(&r).unwrap();
    let perms = !StandardPermissions::allow_everything();
    w.encrypt_with(
        "ownersecret",
        Some("usersecret"),
        StandardEncryptOptions {
            perms,
            ..Default::default()
        },
    )
    .unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    let result = r.decrypt("usersecret").unwrap();
    assert_eq!(result.status, AuthStatus::User);
    assert_eq!(result.permission_flags, Some(perms.into()));
}

#[test]
fn test_default_no_gcm() {
    let r = read(&minimal());
    let mut w = hanko_pdf::writer::copy_into_new_writer(&r).unwrap();
    w.encrypt("ownersecret", Some("usersecret")).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    assert_eq!(r.decrypt("usersecret").unwrap().status, AuthStatus::User);
    let cf = r.security_handler().unwrap().unwrap().get_stream_filter(None).unwrap();
    assert_eq!(cf.cipher(), CipherKind::AesCbc);
    assert!(!cf.is_pubkey());
}

#[test]
fn test_gcm_via_encrypt_call() {
    let r = read(&minimal());
    let mut w = hanko_pdf::writer::copy_into_new_writer(&r).unwrap();
    w.encrypt_with(
        "ownersecret",
        Some("usersecret"),
        StandardEncryptOptions {
            use_gcm: true,
            ..Default::default()
        },
    )
    .unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    assert_eq!(r.decrypt("usersecret").unwrap().status, AuthStatus::User);
    let cf = r.security_handler().unwrap().unwrap().get_stream_filter(None).unwrap();
    assert_eq!(cf.cipher(), CipherKind::AesGcm);
    assert!(!cf.is_pubkey());
}

#[test]
fn test_empty_user_pass() {
    let r = read(&pdf("minimal-with-field.pdf"));
    let mut w = hanko_pdf::writer::copy_into_new_writer(&r).unwrap();
    let old_root_ref = w.root_id();
    w.encrypt("ownersecret", Some("")).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    let result = r.decrypt("").unwrap();
    assert_eq!(result.status, AuthStatus::User);
    assert_eq!(r.root_ref().unwrap(), old_root_ref);
    let (fields, kids) = fields_and_kids(&r);
    assert_eq!(fields.len(), 1);
    assert_eq!(kids.len(), 1);
    let f = as_dict(r.resolve(&fields[0]).unwrap());
    assert_eq!(text(f.get(b"T").unwrap()), "Sig1");
}

#[test]
fn test_reauthenticate() {
    let r = read(&pdf("minimal-with-field.pdf"));
    let mut w = hanko_pdf::writer::copy_into_new_writer(&r).unwrap();
    w.encrypt("ownersecret", Some("usersecret")).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    assert_eq!(r.decrypt("wrong").unwrap().status, AuthStatus::Failed);
    assert_eq!(r.decrypt("usersecret").unwrap().status, AuthStatus::User);
    let (fields, _) = fields_and_kids(&r);
    let f = as_dict(r.resolve(&fields[0]).unwrap());
    assert_eq!(text(f.get(b"T").unwrap()), "Sig1");
}

#[test]
fn test_load_pkcs12() {
    let sedk = SimpleEnvelopeKeyDecrypter::load_pkcs12(&crypto(&["selfsigned.pfx"]), Some(b"exportsecret")).unwrap();
    assert_eq!(
        sedk.cert_info().subject_der(),
        pubkey_selfsigned_decrypter().cert_info().subject_der()
    );
}

#[test]
fn test_pubkey_wrong_content_type() {
    let r = read(&vector_image_pdf());
    let mut w = new_writer();
    let sh = SecurityHandler::build_from_certs(
        &[test_cert()],
        PubKeyEncryptOptions {
            version: SecurityHandlerVersion::Rc4_40,
            keylen_bytes: 16,
            use_aes: true,
            use_crypt_filters: false,
            ..Default::default()
        },
    )
    .unwrap();
    let mut enc = sh.as_pdf_object().unwrap();
    // ContentInfo { data, OCTET STRING deadbeef }
    let cms_bytes = vec![
        0x30, 0x13, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x06, 0x04, 0x04, 0xde,
        0xad, 0xbe, 0xef,
    ];
    let Object::Array(mut recps) = enc.get(b"Recipients").unwrap().clone() else { panic!() };
    recps[0] = byte_string(cms_bytes);
    enc.set("Recipients", Object::Array(recps));
    w.set_encryption(Object::Dictionary(enc), sh.encryptor()).unwrap();
    import_page_tree(&mut w, &r);
    let out = w.write().unwrap();
    let r = read(&out);
    let e = assert_err_matches(r.decrypt_pubkey(&pubkey_test_decrypter()), "must be enveloped");
    assert!(e.is_read_error());
}

#[test]
fn test_pubkey_wrong_cert() {
    let mut w = new_writer();
    let recpt_cert = hanko_pdf::crypt::CertInfo::from_der(&{
        let pem = crypto(&["testing-ca", "interm", "decrypter2.cert.pem"]);
        let text = String::from_utf8(pem).unwrap();
        base64_decode(&text.lines().filter(|l| !l.starts_with("-----")).collect::<String>())
    })
    .unwrap();
    let test_data = b"This is test data!".to_vec();
    let r#ref = w
        .add_object(Object::Stream(DecodedStream::new(Dictionary::new(), test_data).to_stream().unwrap()))
        .unwrap();
    w.encrypt_pubkey(&[recpt_cert.der().to_vec()]).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    let result = r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
    assert_eq!(result.status, AuthStatus::Failed);
    let e = r.get_object(r#ref).unwrap_err();
    assert!(e.is_pdf_error(), "{e:?}");
}

#[test]
fn test_crypt_filter_build_failures() {
    let reg = CryptFilterRegistry::default();
    let mut cfdict = Dictionary::new();
    assert!(build_crypt_filter(&reg, &cfdict, false).unwrap().is_none());
    cfdict.set("CFM", pdf_name("/None"));
    assert!(build_crypt_filter(&reg, &cfdict, false).unwrap().is_none());
    cfdict.set("CFM", pdf_name("/NoSuchCF"));
    let e = build_crypt_filter(&reg, &cfdict, false).unwrap_err();
    assert!(matches!(e, PdfError::NotImplemented(_)));
}

#[test]
fn test_custom_crypt_filter_type() {
    for on_subclass in [true, false] {
        let mut w = new_writer();
        let custom_cf = || CryptFilter::standard_rc4(16).with_method("/CustomCFType");
        let mut registry = SecurityHandlerRegistry::default();
        if on_subclass {
            // a "subclass": a new registration with its own crypt filter
            // registry, which must not affect the default one
            let mut reg = hanko_pdf::crypt::standard::default_crypt_filters();
            assert!(reg.contains("/V2"));
            reg.register("/CustomCFType", Arc::new(move |_, _| Ok(custom_cf())));
            registry.register("/Standard", HandlerType::Standard, reg);
            assert!(!hanko_pdf::crypt::standard::default_crypt_filters().contains("/CustomCFType"));
        } else {
            registry
                .crypt_filters_mut("/Standard")
                .unwrap()
                .register("/CustomCFType", Arc::new(move |_, _| Ok(custom_cf())));
        }
        let cfc = CryptFilterConfiguration::new(vec![(STD_CF, custom_cf())], STD_CF, STD_CF, None).unwrap();
        let id1 = w.document_id().0.to_vec();
        let sh = SecurityHandler::build_from_pw_legacy(
            StandardSecuritySettingsRevision::Rc4OrAes128,
            &id1,
            "ownersecret",
            Some("usersecret".into()),
            LegacyEncryptOptions {
                keylen_bytes: 16,
                crypt_filter_config: Some(cfc),
                ..Default::default()
            },
        )
        .unwrap();
        w.assign_security_handler(&sh).unwrap();
        let test_data = b"This is test data!".to_vec();
        let r#ref = w
            .add_object(Object::Stream(DecodedStream::new(Dictionary::new(), test_data.clone()).to_stream().unwrap()))
            .unwrap();
        let out = w.write().unwrap();

        // the default registry does not know the method
        let r = read(&out);
        let e = r.decrypt("ownersecret").unwrap_err();
        assert!(matches!(e, PdfError::NotImplemented(_)), "{e:?}");

        let r = read(&out);
        r.set_security_handler(SecurityHandler::build_with(&encrypt_dict_of(&r), &registry).unwrap());
        r.decrypt("ownersecret").unwrap();
        let cfc = r.security_handler().unwrap().unwrap().crypt_filter_config();
        assert_eq!(cfc.stream_filter_name(), cfc.string_filter_name());
        let obj = stream_of(r.get_object(r#ref).unwrap());
        assert_eq!(r.stream_data(&obj).unwrap(), test_data);
        let raw = stream_of(r.get_object_raw(r#ref, None).unwrap());
        assert_ne!(raw.content, test_data);
    }
}

#[test]
fn test_security_handler_version_deser() {
    assert_eq!(SecurityHandlerVersion::from_number(Some(5)), SecurityHandlerVersion::Aes256);
    assert_eq!(SecurityHandlerVersion::from_number(Some(0)), SecurityHandlerVersion::Other);
    assert_eq!(SecurityHandlerVersion::from_number(None), SecurityHandlerVersion::Other);
    assert_eq!(
        StandardSecuritySettingsRevision::from_number(Some(6)),
        StandardSecuritySettingsRevision::Aes256
    );
    assert_eq!(
        StandardSecuritySettingsRevision::from_number(Some(0)),
        StandardSecuritySettingsRevision::Other
    );
}

#[test]
fn test_key_len() {
    assert!(SecurityHandlerVersion::Rc4OrAes128.check_key_length(20).unwrap_err().is_pdf_error());
    assert_eq!(SecurityHandlerVersion::Rc4OrAes128.check_key_length(6).unwrap(), 6);
    assert_eq!(SecurityHandlerVersion::Aes256.check_key_length(6).unwrap(), 32);
    assert_eq!(SecurityHandlerVersion::Rc4_40.check_key_length(32).unwrap(), 5);
    assert_eq!(SecurityHandlerVersion::Rc4LongerKeys.check_key_length(16).unwrap(), 16);
}

fn password_cred(r: &PdfFile) -> PasswordCredential {
    r.security_handler()
        .unwrap()
        .unwrap()
        .extract_credential()
        .unwrap()
        .as_password()
        .unwrap()
        .clone()
}

fn fresh_handler(data: &[u8]) -> SecurityHandler {
    read(data).security_handler().unwrap().unwrap()
}

#[test]
fn test_ser_deser_credential_standard_sh() {
    let data = pdf("minimal-aes256.pdf");
    for pw in ["usersecret", "ownersecret"] {
        let r = read(&data);
        r.decrypt(pw).unwrap();
        let cred = password_cred(&r);
        assert_eq!(cred.pwd_bytes, pw.as_bytes());
        let cred_data = cred.serialise();
        let result = fresh_handler(&data).authenticate(Credential::Serialised(cred_data), None).unwrap();
        let exp = if pw.starts_with("user") { AuthStatus::User } else { AuthStatus::Owner };
        assert_eq!(result.status, exp);
    }
}

#[test]
fn test_ser_deser_credential_standard_sh_extract_from_builder() {
    let sh = SecurityHandler::build_from_pw("ownersecret", Some("usersecret".into()), Default::default()).unwrap();
    let cred = sh.extract_credential().unwrap().as_password().unwrap().clone();
    assert_eq!(cred.pwd_bytes, b"ownersecret");
    assert_eq!(cred.id1, None);
}

#[test]
fn test_ser_deser_credential_wrong_pw() {
    let data = pdf("minimal-aes256.pdf");
    let r = read(&data);
    r.decrypt("ownersecret").unwrap();
    let mut cred = password_cred(&r);
    cred.pwd_bytes = b"This is the wrong password".to_vec();
    let result = fresh_handler(&data).authenticate(Credential::Serialised(cred.serialise()), None).unwrap();
    assert_eq!(result.status, AuthStatus::Failed);
}

#[test]
fn test_ser_deser_credential_standard_corrupted() {
    let data = pdf("minimal-aes256.pdf");
    let r = read(&data);
    r.decrypt("ownersecret").unwrap();
    let cred = password_cred(&r);
    let cred_data = SerialisedCredential {
        credential_type: cred.serialise().credential_type,
        data: b"\xde\xad\xbe\xef".to_vec(),
    };
    let e = assert_err_matches(
        fresh_handler(&data).authenticate(Credential::Serialised(cred_data), None),
        "Failed to deserialise password",
    );
    assert!(e.is_read_error());
}

#[test]
fn test_ser_deser_credential_unknown_cred_type() {
    let data = pdf("minimal-aes256.pdf");
    let r = read(&data);
    r.decrypt("ownersecret").unwrap();
    let cred = password_cred(&r);
    let cred_data = SerialisedCredential {
        credential_type: "foobar".into(),
        data: cred.serialise().data,
    };
    let e = assert_err_matches(
        fresh_handler(&data).authenticate(Credential::Serialised(cred_data), None),
        "credential type 'foobar' not known",
    );
    assert!(e.is_read_error());
}

#[test]
fn test_ser_deser_credential_standard_sh_legacy() {
    let out = produce_legacy_encrypted_file(StandardSecuritySettingsRevision::Rc4OrAes128, 16, true).unwrap();
    for pw in ["usersecret", "ownersecret"] {
        let r = read(&out);
        r.decrypt(pw).unwrap();
        let cred = password_cred(&r);
        assert_eq!(cred.pwd_bytes, pw.as_bytes());
        assert!(cred.id1.is_some());
        let result = fresh_handler(&pdf("minimal-aes256.pdf"))
            .authenticate(Credential::Serialised(cred.serialise()), None)
            .unwrap();
        let exp = if pw.starts_with("user") { AuthStatus::User } else { AuthStatus::Owner };
        assert_eq!(result.status, exp);
    }
}

#[test]
fn test_ser_deser_credential_standard_sh_legacy_no_id1() {
    let out = produce_legacy_encrypted_file(StandardSecuritySettingsRevision::Rc4OrAes128, 16, true).unwrap();
    for pw in ["usersecret", "ownersecret"] {
        let r = read(&out);
        r.decrypt(pw).unwrap();
        let mut cred = password_cred(&r);
        cred.id1 = None;
        let e = assert_err_matches(
            fresh_handler(&out).authenticate(Credential::Serialised(cred.serialise()), None),
            "id1",
        );
        assert!(e.is_read_error());
    }
}

#[test]
fn test_ser_deser_credential_standard_legacy_sh_extract_from_builder() {
    let sh = SecurityHandler::build_from_pw_legacy(
        StandardSecuritySettingsRevision::Rc4OrAes128,
        b"\xde\xad\xbe\xef",
        b"ownersecret",
        Some(b"usersecret".into()),
        LegacyEncryptOptions {
            keylen_bytes: 16,
            ..Default::default()
        },
    )
    .unwrap();
    let cred = sh.extract_credential().unwrap().as_password().unwrap().clone();
    assert_eq!(cred.pwd_bytes, b"ownersecret");
    assert_eq!(cred.id1.as_deref(), Some(&b"\xde\xad\xbe\xef"[..]));
}

fn rc4_or_aes128_pubkey_file() -> Vec<u8> {
    produce_pubkey_encrypted_file(SecurityHandlerVersion::Rc4OrAes128, 16, true, true, Default::default(), None)
        .unwrap()
}

#[test]
fn test_ser_deser_credential_pubkey() {
    let out = rc4_or_aes128_pubkey_file();
    let r = read(&out);
    r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
    let cred_data = r.security_handler().unwrap().unwrap().extract_credential().unwrap().serialise();
    let result = fresh_handler(&out).authenticate(Credential::Serialised(cred_data), None).unwrap();
    assert_eq!(result.status, AuthStatus::User);
}

#[test]
fn test_ser_deser_credential_pubkey_sh_cannot_extract_from_builder() {
    let sh = SecurityHandler::build_from_certs(
        &[test_cert()],
        PubKeyEncryptOptions {
            keylen_bytes: 16,
            version: SecurityHandlerVersion::Rc4OrAes128,
            perms: pubkey_perms(),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(sh.extract_credential().is_none());
}

#[test]
fn test_ser_deser_credential_wrong_cred_type_pubkey() {
    let r = read(&pdf("minimal-aes256.pdf"));
    r.decrypt("ownersecret").unwrap();
    let cred_data = r.security_handler().unwrap().unwrap().extract_credential().unwrap().serialise();
    let out = rc4_or_aes128_pubkey_file();
    let e = assert_err_matches(
        fresh_handler(&out).authenticate(Credential::Serialised(cred_data), None),
        "must be an instance of",
    );
    assert!(e.is_read_error());
}

#[test]
fn test_ser_deser_credential_wrong_cred_type_standard() {
    let out = rc4_or_aes128_pubkey_file();
    let r = read(&out);
    r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
    let cred_data = r.security_handler().unwrap().unwrap().extract_credential().unwrap().serialise();
    let e = assert_err_matches(
        fresh_handler(&pdf("minimal-aes256.pdf")).authenticate(Credential::Serialised(cred_data), None),
        "Standard auth.*must be a",
    );
    assert!(e.is_read_error());
}

#[test]
fn test_ser_deser_credential_pubkey_corrupted() {
    let out = rc4_or_aes128_pubkey_file();
    let r = read(&out);
    r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
    let cred = r.security_handler().unwrap().unwrap().extract_credential().unwrap();
    let cred_data = SerialisedCredential {
        credential_type: cred.serialise().credential_type,
        data: b"\xde\xad\xbe\xef".to_vec(),
    };
    let e = assert_err_matches(
        fresh_handler(&out).authenticate(Credential::Serialised(cred_data), None),
        "Failed to decode serialised pubkey credential",
    );
    assert!(e.is_read_error());
}

#[test]
fn test_ser_deser_credential_wrong_cert() {
    let wrong_cert = SimpleEnvelopeKeyDecrypter::new(
        pubkey_selfsigned_decrypter().cert_info().der(),
        pubkey_test_decrypter().private_key_der(),
    )
    .unwrap()
    .serialise();
    let out = rc4_or_aes128_pubkey_file();
    let result = fresh_handler(&out).authenticate(Credential::Serialised(wrong_cert), None).unwrap();
    assert_eq!(result.status, AuthStatus::Failed);
}

#[test]
fn test_ser_deser_credential_wrong_key() {
    let wrong_key = SimpleEnvelopeKeyDecrypter::new(
        pubkey_test_decrypter().cert_info().der(),
        pubkey_selfsigned_decrypter().private_key_der(),
    )
    .unwrap()
    .serialise();
    let out = rc4_or_aes128_pubkey_file();
    // a certificate match with a wrong key is an error
    let e = assert_err_matches(
        fresh_handler(&out).authenticate(Credential::Serialised(wrong_key), None),
        "envelope key",
    );
    assert!(e.is_read_error());
}

/// `w.root['/Metadata'].apply_filter("/Crypt", {/Name: /Identity})`.
fn mark_metadata_identity(w: &mut hanko_pdf::PdfWriter) {
    let root = w.root().unwrap();
    let Ok(Object::Reference(mref)) = root.get(b"Metadata").cloned() else { panic!() };
    let s = stream_of(w.get_object(mref).unwrap());
    let mut params = Dictionary::new();
    params.set("Name", pdf_name("/Identity"));
    let s = apply_filter_to_stream(&s, "/Crypt", Some(params), DuplicateFilter::Allow).unwrap();
    w.update_object(mref, Object::Stream(s));
}

/// The metadata stream, read without decryption (the root dictionary holds
/// encrypted strings, which cannot be read before authenticating here).
fn check_unencrypted_metadata(r: &PdfFile) {
    let root_id = r.root_ref().unwrap();
    let root = as_dict(r.get_object_raw(root_id, None).unwrap());
    let Ok(Object::Reference(mref)) = root.get(b"Metadata").cloned() else { panic!() };
    // the metadata stream itself is readable before authentication
    let mtd = stream_of(r.get_object(mref).unwrap());
    let has = |d: &[u8]| d.windows(13).any(|w| w == b"Test document");
    assert!(has(&mtd.content));
    assert!(has(&r.stream_data(&mtd).unwrap()));
}

fn info_title(r: &PdfFile) -> String {
    let t = r.trailer_view();
    let info = as_dict(r.resolve(t.get(b"Info").unwrap()).unwrap());
    text(info.get(b"Title").unwrap())
}

#[test]
fn test_encrypt_skipping_metadata() {
    for legacy in [true, false] {
        let src = read(&pdf("minimal-pdf-ua-and-a.pdf"));
        let mut w = hanko_pdf::writer::copy_into_new_writer(&src).unwrap();
        if legacy {
            let id1 = w.document_id().0.to_vec();
            let sh = SecurityHandler::build_from_pw_legacy(
                StandardSecuritySettingsRevision::Rc4OrAes128,
                &id1,
                "secret",
                Some("secret".into()),
                LegacyEncryptOptions {
                    keylen_bytes: 16,
                    use_aes128: true,
                    perms: std_perms(),
                    encrypt_metadata: false,
                    ..Default::default()
                },
            )
            .unwrap();
            w.assign_security_handler(&sh).unwrap();
        } else {
            w.encrypt_with(
                "secret",
                Some("secret"),
                StandardEncryptOptions {
                    encrypt_metadata: false,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        mark_metadata_identity(&mut w);
        let out = w.write().unwrap();

        let r = read(&out);
        check_unencrypted_metadata(&r);
        assert_eq!(encrypt_dict_of(&r).get(b"EncryptMetadata").unwrap(), &Object::Boolean(false));
        let result = r.decrypt("secret").unwrap();
        assert_eq!(result.status, AuthStatus::Owner);
        assert_eq!(info_title(&r), "Test document");
    }
}

#[test]
fn test_encrypt_skipping_metadata_pubkey() {
    let src = read(&pdf("minimal-pdf-ua-and-a.pdf"));
    let mut w = hanko_pdf::writer::copy_into_new_writer(&src).unwrap();
    w.encrypt_pubkey_with(
        &[test_cert()],
        PubKeyEncryptOptions {
            encrypt_metadata: false,
            ..Default::default()
        },
    )
    .unwrap();
    mark_metadata_identity(&mut w);
    let out = w.write().unwrap();

    let r = read(&out);
    check_unencrypted_metadata(&r);
    let result = r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
    assert_eq!(result.status, AuthStatus::User);
    assert_eq!(info_title(&r), "Test document");
}

fn first_page_data(r: &PdfFile) -> Result<Vec<u8>, PdfError> {
    let root = r.root()?;
    let pages = r.get_dict(&root, b"Pages")?.unwrap();
    let kids = r.get_array(&pages, b"Kids")?.unwrap();
    let page = as_dict(r.resolve(&kids[0])?);
    let contents = stream_of(r.get(&page, b"Contents")?.unwrap());
    r.stream_data(&contents)
}

#[test]
fn test_pubkey_rc4_envelope() {
    let r = read(&pdf("minimal-pubkey-rc4-envelope.pdf"));
    let result = r.decrypt_pubkey(&pubkey_test_decrypter_old()).unwrap();
    assert_eq!(result.status, AuthStatus::User);
    assert!(first_page_data(&r).unwrap().windows(5).any(|w| w == b"Hello"));
}

#[test]
fn test_unknown_envelope_enc_type() {
    let r = read(&pdf("minimal-pubkey-unknown-envelope-alg.pdf"));
    let e = assert_err_matches(r.decrypt_pubkey(&pubkey_test_decrypter_old()), "Cipher.*not allowed");
    assert!(e.is_pdf_error());
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn basic_r6_enc_dict() -> Dictionary {
    let mut d = Dictionary::new();
    d.set("Filter", pdf_name("/Standard"));
    d.set(
        "O",
        byte_string(unhex(
            "047761f7f568bfacb096382f2fc7cc94ffd87f33dc472ca4a3a3a78c739c77df26a794a7819aff59b3b85780c0fafe9f",
        )),
    );
    d.set(
        "U",
        byte_string(unhex(
            "446ea469061c56060b56fa0296bfd32cc54fa9175e92ef5c0b945f4c810e309a03af4a2ff103bbd4db065e036f78ac4c",
        )),
    );
    d.set(
        "OE",
        byte_string(unhex("65012afdd09b34431117b9fa5f557202940dece9758d53c61fc5ff436cf2515c")),
    );
    d.set(
        "UE",
        byte_string(unhex("71071c8c117abc19d26b5efc44a080667ef3c3665ad3bc8f5f5b58126a15d931")),
    );
    d.set("Perms", byte_string(unhex("b8729f735b0976d80f61d16bcfe09273")));
    d.set("P", Object::Integer(-4));
    d.set("V", Object::Integer(5));
    d.set("R", Object::Integer(6));
    d.set("Length", Object::Integer(256));
    d.set("EncryptMetadata", Object::Boolean(true));
    d.set("StmF", pdf_name("/StdCF"));
    d.set("StrF", pdf_name("/StdCF"));
    let mut std_cf = Dictionary::new();
    std_cf.set("AuthEvent", pdf_name("/DocOpen"));
    std_cf.set("CFM", pdf_name("/AESV3"));
    std_cf.set("Length", Object::Integer(32));
    let mut cf = Dictionary::new();
    cf.set("StdCF", Object::Dictionary(std_cf));
    d.set("CF", Object::Dictionary(cf));
    d
}

#[test]
fn test_r6_values() {
    let cases = [
        ("OE", false, "be 32 bytes long"),
        ("OE", true, "be 32 bytes long"),
        ("UE", false, "be 32 bytes long"),
        ("UE", true, "be 32 bytes long"),
        ("O", false, "be 48 bytes long"),
        ("O", true, "be present"),
        ("U", false, "be 48 bytes long"),
        ("U", true, "be present"),
        ("Perms", false, "be 16 bytes long"),
        ("Perms", true, "be 16 bytes long"),
    ];
    for (entry, delete, err) in cases {
        let mut d = basic_r6_enc_dict();
        if delete {
            d.remove(entry.as_bytes());
        } else {
            d.set(entry, byte_string(b"\xde\xad\xbe\xef".to_vec()));
        }
        let e = assert_err_matches(SecurityHandler::instantiate_standard_from_pdf_object(&d), err);
        assert!(e.is_pdf_error());
    }
}

#[test]
fn test_legacy_o_u_values() {
    for entry in ["U", "O"] {
        let r = read(&vector_image_pdf());
        let mut w = new_writer();
        let id1 = w.document_id().0.to_vec();
        let sh = SecurityHandler::build_from_pw_legacy(
            StandardSecuritySettingsRevision::Rc4OrAes128,
            &id1,
            "ownersecret",
            Some("usersecret".into()),
            LegacyEncryptOptions {
                keylen_bytes: 1,
                use_aes128: true,
                perms: std_perms(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut enc = sh.as_pdf_object().unwrap();
        enc.set(entry, byte_string(b"\xde\xad\xbe\xef".to_vec()));
        w.set_encryption(Object::Dictionary(enc), sh.encryptor()).unwrap();
        import_page_tree(&mut w, &r);
        let out = w.write().unwrap();
        let e = assert_err_matches(read_first_page_contents(&out), "be 32 bytes long");
        assert!(e.is_pdf_error());
    }
}

#[test]
fn test_key_length_constraint() {
    let mut d = basic_r6_enc_dict();
    d.set("Length", Object::Integer(333));
    let e = assert_err_matches(
        SecurityHandler::instantiate_standard_from_pdf_object(&d),
        "must be a multiple of 8",
    );
    assert!(e.is_pdf_error());
}

#[test]
fn test_perms_decrypt_bogus() {
    let mut d = basic_r6_enc_dict();
    d.set("Perms", byte_string(b"\xde\xad\xbe\xef".repeat(4)));
    let sh = SecurityHandler::instantiate_standard_from_pdf_object(&d).unwrap();
    let e = assert_err_matches(sh.authenticate_password("usersecret", None), "tampered");
    assert!(e.is_pdf_error());
}

#[test]
fn test_legacy_no_r6() {
    let e = produce_legacy_encrypted_file(StandardSecuritySettingsRevision::Aes256, 32, true).unwrap_err();
    assert!(matches!(e, PdfError::Value(_)));
    assert!(e.message().contains("not supported"));
}

#[test]
fn test_legacy_cf_req() {
    let e = assert_err_matches(
        SecurityHandler::build_from_certs(
            &[test_cert()],
            PubKeyEncryptOptions {
                keylen_bytes: 16,
                version: SecurityHandlerVersion::Rc4OrAes128,
                use_crypt_filters: false,
                ..Default::default()
            },
        ),
        "s5 is required",
    );
    assert!(e.is_pdf_error());
}

#[test]
fn test_add_recp_before_auth_fail() {
    let out = rc4_or_aes128_pubkey_file();
    let sh = fresh_handler(&out);
    let e = assert_err_matches(
        sh.add_crypt_filter_recipients(
            DEFAULT_CRYPT_FILTER,
            &[pubkey_selfsigned_decrypter().cert_info().der().to_vec()],
            Default::default(),
            PubKeyPermissions::allow_everything(),
        ),
        "before authenticating",
    );
    assert!(e.is_pdf_error());
}

#[test]
fn test_add_recp_after_key_deriv() {
    let out = rc4_or_aes128_pubkey_file();
    let r = read(&out);
    r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
    let sh = r.security_handler().unwrap().unwrap();
    assert!(!sh.crypt_filter_shared_key(DEFAULT_CRYPT_FILTER).unwrap().is_empty());
    let e = assert_err_matches(
        sh.add_crypt_filter_recipients(
            DEFAULT_CRYPT_FILTER,
            &[pubkey_selfsigned_decrypter().cert_info().der().to_vec()],
            Default::default(),
            PubKeyPermissions::allow_everything(),
        ),
        "after deriving.*shared key",
    );
    assert!(e.is_pdf_error());
}

#[test]
fn test_encrypted_obj_stm() {
    let r = read(&minimal());
    let mut w = hanko_pdf::writer::copy_into_new_writer_with(&r, true).unwrap();
    let obj_stm = w.prepare_object_stream(true).unwrap();
    let objref = w.add_object_ext(text_string("Hello there"), Some(obj_stm), None).unwrap();
    w.encrypt("ownersecret", Some("usersecret")).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    let result = r.decrypt("ownersecret").unwrap();
    assert_eq!(result.status, AuthStatus::Owner);

    // the content is present in unencrypted form in the (decrypted) object
    // stream
    let Some(XRefLocation::ObjStream(loc)) = r.xrefs().get(objref) else { panic!() };
    let stm = stream_of(r.get_object((loc.obj_stream_id, 0)).unwrap());
    let data = r.stream_data(&stm).unwrap();
    assert!(data.windows(13).any(|w| w == b"(Hello there)"));
    // and the object can be retrieved
    assert_eq!(text(&r.get_object(objref).unwrap()), "Hello there");
}

#[test]
fn test_add_crypt_filter_to_stream_without_security_handler() {
    let mut s = DecodedStream::new(Dictionary::new(), b"1001".to_vec());
    let e = assert_err_matches(add_crypt_filter(&mut s, "/Identity", None, None), "no security handler");
    assert!(e.is_stream_error());
}

#[test]
fn test_malformed_crypt() {
    for (fname, strict) in [
        ("malformed-encrypt-dict1.pdf", true),
        ("malformed-encrypt-dict2.pdf", true),
        ("malformed-encrypt-dict2.pdf", false),
    ] {
        let r = try_read(&pdf(fname), strict).unwrap();
        let e = assert_err_matches(r.encrypt_dict(), "Encryption settings");
        assert!(e.is_read_error());
    }
}

#[test]
fn test_tolerate_direct_encryption_dict_in_nonstrict() {
    let r = read_lenient(&pdf("malformed-encrypt-dict1.pdf"));
    r.decrypt("ownersecret").unwrap();
    assert!(first_page_data(&r).unwrap().windows(5).any(|w| w == b"Hello"));
}

fn iso_extension_levels(r: &PdfFile) -> Vec<i64> {
    let root = r.root().unwrap();
    let exts = r.get_dict(&root, b"Extensions").unwrap().unwrap();
    let iso = r.get_array(&exts, b"ISO_").unwrap().unwrap();
    let mut levels: Vec<i64> = iso
        .iter()
        .map(|e| match as_dict(r.resolve(e).unwrap()).get(b"ExtensionLevel").unwrap() {
            Object::Integer(i) => *i,
            other => panic!("{other:?}"),
        })
        .collect();
    levels.sort();
    levels.dedup();
    levels
}

fn gcm_standard_file() -> Vec<u8> {
    let mut w = hanko_pdf::writer::copy_into_new_writer(&read(&minimal())).unwrap();
    let sh = SecurityHandler::build_from_pw(
        "secret",
        None,
        StandardEncryptOptions {
            pdf_mac: false,
            use_gcm: true,
            ..Default::default()
        },
    )
    .unwrap();
    w.assign_security_handler(&sh).unwrap();
    w.write().unwrap()
}

#[test]
fn test_gcm_standard() {
    let out = gcm_standard_file();
    let r = read(&out);
    r.decrypt("secret").unwrap();
    assert!(first_page_data(&r).unwrap().windows(5).any(|w| w == b"Hello"));
    assert_eq!(iso_extension_levels(&r), vec![32003]);
}

/// Writes objects without encryption (pyHanko's `NeverDecryptReader`
/// trick: raw objects are written back as they are).
#[derive(Debug)]
struct Passthrough;

impl Encryptor for Passthrough {
    fn encrypt_string(&self, _data: &[u8], _container: ObjectId) -> Result<Option<Vec<u8>>, PdfError> {
        Ok(None)
    }
    fn encrypt_stream(&self, _dict: &Dictionary, data: &[u8], _container: ObjectId) -> Result<Vec<u8>, PdfError> {
        Ok(data.to_vec())
    }
}

fn raw_first_page_contents_ref(r: &PdfFile) -> ObjectId {
    let raw = |id: ObjectId| as_dict(r.get_object_raw(id, None).unwrap());
    let root = raw(r.root_ref().unwrap());
    let Object::Reference(pages) = root.get(b"Pages").unwrap() else { panic!() };
    let Object::Array(kids) = raw(*pages).get(b"Kids").unwrap().clone() else { panic!() };
    let Object::Reference(page) = kids[0] else { panic!() };
    let Object::Reference(c) = raw(page).get(b"Contents").unwrap().clone() else { panic!() };
    c
}

fn gcm_standard_tamper(tamperer: impl Fn(Vec<u8>) -> Vec<u8>) {
    let out = gcm_standard_file();
    let r = read(&out);
    let content_ref = raw_first_page_contents_ref(&r);
    let mut content = stream_of(r.get_object_raw(content_ref, None).unwrap());
    content.content = tamperer(content.content);
    let Some(Object::Reference(eref)) = r.trailer().raw_get(b"Encrypt", None) else { panic!() };
    let mut w = IncrementalWriter::new(r);
    w.set_existing_encryption(eref, Box::new(Passthrough));
    w.update_meta_on_write = false;
    w.update_object(content_ref, Object::Stream(content));
    let out = w.write_in_place().unwrap();

    let r = read(&out);
    r.decrypt("secret").unwrap();
    // this should work
    let root = r.root().unwrap();
    let exts = r.get_dict(&root, b"Extensions").unwrap().unwrap();
    let iso = r.get_array(&exts, b"ISO_").unwrap().unwrap();
    let ext0 = as_dict(r.resolve(&iso[0]).unwrap());
    assert!(text(ext0.get(b"URL").unwrap()).contains("https"));
    // this shouldn't
    let e = assert_err_matches(first_page_data(&r), "Invalid GCM tag");
    assert!(e.is_read_error());
}

#[test]
fn test_gcm_change_content() {
    gcm_standard_tamper(|mut c| {
        c[14..18].copy_from_slice(b"\xde\xad\xbe\xef");
        c
    });
}

#[test]
fn test_gcm_remove_tag() {
    gcm_standard_tamper(|c| c[..c.len() - 16].to_vec());
}

#[test]
fn test_gcm_change_nonce() {
    gcm_standard_tamper(|mut c| {
        c[..12].copy_from_slice(&[0u8; 12]);
        c
    });
}

#[test]
fn test_gcm_pubkey() {
    let mut w = hanko_pdf::writer::copy_into_new_writer(&read(&minimal())).unwrap();
    let sh = SecurityHandler::build_from_certs(
        &[test_cert()],
        PubKeyEncryptOptions {
            version: SecurityHandlerVersion::AesGcm,
            pdf_mac: false,
            ..Default::default()
        },
    )
    .unwrap();
    w.assign_security_handler(&sh).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
    assert!(first_page_data(&r).unwrap().windows(5).any(|w| w == b"Hello"));
    assert_eq!(iso_extension_levels(&r), vec![32003]);
}

#[test]
fn test_tolerate_empty_encrypted_string() {
    let r = read(&pdf("minimal-aes256-empty-encrypted-string.pdf"));
    r.decrypt("secret").unwrap();
    match root_entry(&r, "Blah") {
        Object::String(s, _) => assert_eq!(s, b""),
        other => panic!("{other:?}"),
    }
}

#[test]
fn test_process_malformed_p_entry() {
    let r = read(&pdf("minimal-aes256-malformed-perms.pdf"));
    let e = assert_err_matches(r.decrypt("usersecret"), "Cannot parse.*as a permission");
    assert!(e.is_read_error());
}

#[test]
fn test_process_malformed_oe_entry() {
    let r = read(&pdf("minimal-aes256-malformed-oe.pdf"));
    let e = assert_err_matches(r.decrypt("usersecret"), "Expected string");
    assert!(e.is_read_error());
}

#[test]
fn test_std_permission_transformations() {
    for (perm, expected_sint, expected_bytes) in [
        (StandardPermissions::allow_everything(), -4, [0xff, 0xff, 0xff, 0xfc]),
        (std_perms(), -44, [0xff, 0xff, 0xff, 0xd4]),
    ] {
        assert_eq!((perm.as_sint32(), perm.as_bytes()), (expected_sint, expected_bytes));
    }
}

#[test]
fn test_pubkey_permission_transformations() {
    for (perm, expected_bytes) in [
        (PubKeyPermissions::allow_everything(), [0xff, 0xff, 0xff, 0xff]),
        (pubkey_perms(), [0xff, 0xff, 0xff, 0xd5]),
    ] {
        assert_eq!(perm.as_bytes(), expected_bytes);
    }
}

#[test]
fn test_pubkey_3des_decryption() {
    let r = read(&pdf("pubkey-3des-test.pdf"));
    let result = r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
    validate_pubkey_decryption(&r, &result);
}

#[test]
fn test_pubkey_rc2_decryption() {
    let r = read(&pdf("pubkey-rc2-test.pdf"));
    let result = r.decrypt_pubkey(&pubkey_test_decrypter()).unwrap();
    validate_pubkey_decryption(&r, &result);
}

#[test]
fn credential_variants_are_serialisable() {
    // not upstream: the in-memory decrypter round-trips through
    // serialisation (`raw_privkey`)
    let d = pubkey_test_decrypter();
    let ser = d.serialise();
    let back = SerialisableCredential::deserialise(&ser).unwrap();
    assert_eq!(back.name(), "raw_privkey");
    let _: &dyn EnvelopeKeyDecrypter = &d;
}

/// Not upstream: differential check that pyHanko 0.38.1 opens what this
/// port writes (`oracle/check_decrypt.py`); skipped without the oracle
/// (`HANKO_ORACLE`).
#[test]
fn differential_pyhanko_reads_our_encryption() {
    if hanko_testdata::oracle::python().is_none() {
        eprintln!("pyHanko oracle not installed; skipping differential check");
        return;
    }
    let script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("oracle/check_decrypt.py");
    let dir = std::env::temp_dir().join(format!("hanko-crypt-diff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let base = || hanko_pdf::writer::copy_into_new_writer(&read(&minimal())).unwrap();
    let pubkey = |cert: Vec<u8>, opts: PubKeyEncryptOptions| {
        let mut w = base();
        let sh = SecurityHandler::build_from_certs(&[cert], opts).unwrap();
        w.assign_security_handler(&sh).unwrap();
        w.write().unwrap()
    };
    let legacy = |rev, keylen, use_aes| {
        let mut w = base();
        let id1 = w.document_id().0.to_vec();
        let sh = SecurityHandler::build_from_pw_legacy(
            rev,
            &id1,
            "ownersecret",
            Some("usersecret".into()),
            LegacyEncryptOptions {
                keylen_bytes: keylen,
                use_aes128: use_aes,
                perms: std_perms(),
                ..Default::default()
            },
        )
        .unwrap();
        w.assign_security_handler(&sh).unwrap();
        w.write().unwrap()
    };
    let aes256 = {
        let mut w = base();
        w.encrypt("ownersecret", Some("usersecret")).unwrap();
        w.write().unwrap()
    };
    let gcm = {
        let mut w = base();
        w.encrypt_with(
            "ownersecret",
            Some("usersecret"),
            StandardEncryptOptions {
                use_gcm: true,
                ..Default::default()
            },
        )
        .unwrap();
        w.write().unwrap()
    };
    let updated = {
        let r = read(&aes256);
        r.decrypt("usersecret").unwrap();
        let mut w = IncrementalWriter::new(r);
        set_root_entry(&mut w, "Test", text_string("Bluh bluh"));
        w.write_in_place().unwrap()
    };
    let rsa = test_cert();
    let cases: Vec<(&str, Vec<u8>, String, &str, &str)> = vec![
        ("aes256", aes256, "password:usersecret".into(), "USER", "SUCCESSFUL"),
        ("gcm", gcm, "password:usersecret".into(), "USER", "SUCCESSFUL"),
        ("update", updated, "password:usersecret".into(), "USER", "SUCCESSFUL"),
        (
            "rc4-r3",
            legacy(StandardSecuritySettingsRevision::Rc4Extended, 16, false),
            "password:ownersecret".into(),
            "OWNER",
            "NOT_APPLICABLE",
        ),
        (
            "aes128-r4",
            legacy(StandardSecuritySettingsRevision::Rc4OrAes128, 16, true),
            "password:usersecret".into(),
            "USER",
            "NOT_APPLICABLE",
        ),
        ("pubkey-rsa", pubkey(rsa.clone(), Default::default()), "pubkey:rsa".into(), "USER", "SUCCESSFUL"),
        (
            "pubkey-oaep",
            pubkey(
                rsa.clone(),
                PubKeyEncryptOptions {
                    policy: RecipientEncryptionPolicy {
                        prefer_oaep: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            "pubkey:rsa".into(),
            "USER",
            "SUCCESSFUL",
        ),
        (
            "pubkey-rc4-s4",
            pubkey(
                rsa,
                PubKeyEncryptOptions {
                    version: SecurityHandlerVersion::Rc4_40,
                    use_crypt_filters: false,
                    ..Default::default()
                },
            ),
            "pubkey:rsa".into(),
            "USER",
            "NOT_APPLICABLE",
        ),
    ];
    let ecc: Vec<(&str, Vec<u8>, String, &str, &str)> = ECC_LABELS
        .iter()
        .map(|lbl| {
            (
                *lbl,
                pubkey(ecc_decrypter_cert(lbl), Default::default()),
                format!("pubkey:{lbl}"),
                "USER",
                "SUCCESSFUL",
            )
        })
        .collect();
    for (name, data, cred, status, mac) in cases.into_iter().chain(ecc) {
        let path = dir.join(format!("{name}.pdf"));
        std::fs::write(&path, &data).unwrap();
        let v = hanko_testdata::oracle::run_json(&script, &[path.to_str().unwrap(), &cred]).unwrap();
        assert_eq!(v["status"].as_str(), Some(status), "{name}: {v}");
        assert_eq!(v["mac_status"].as_str(), Some(mac), "{name}: {v}");
        assert_eq!(v["hello"].as_bool(), Some(true), "{name}: {v}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
