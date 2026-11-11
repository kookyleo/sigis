// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_embed.py`
// (MIT, see LICENSE-pyHanko).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use sigis_pdf::embed::{embed_file, embedded_file_object, EmbeddedFileParams, FileSpec};
use sigis_pdf::generic::{parse_pdf_date_obj, PdfDate};
use sigis_pdf::lopdf::Object;
use sigis_pdf::writer::copy_into_new_writer;
use sigis_pdf::{IncrementalWriter, PdfError, PdfFile, PdfHandler, PdfHandlerExt, PdfWriter};

fn frozen() -> (PdfDate, PdfDate) {
    let modified = PdfDate {
        year: 2020,
        month: 11,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
        utc_offset_minutes: Some(0),
    };
    let created = PdfDate {
        month: 10,
        day: 31,
        ..modified
    };
    (modified, created)
}

fn embed_test(
    w: &mut PdfWriter,
    fname: &str,
    ufname: &str,
    data: &[u8],
    created: PdfDate,
    modified: PdfDate,
) {
    let params = EmbeddedFileParams {
        creation_date: Some(created),
        modification_date: Some(modified),
        ..EmbeddedFileParams::default()
    };
    let ef = embedded_file_object(w, data, true, Some(&params), Some("application/pdf")).unwrap();
    let spec = FileSpec {
        file_spec_string: fname.into(),
        file_name: Some(ufname.into()),
        embedded_data: Some(ef),
        description: Some("Embedding test".into()),
        ..FileSpec::default()
    };
    embed_file(w, &spec).unwrap();
}

fn writer(incremental: bool) -> PdfWriter {
    if incremental {
        IncrementalWriter::new(read(&minimal())).into_inner()
    } else {
        copy_into_new_writer(&read(&minimal()))
            .unwrap()
            .into_inner()
    }
}

fn emb_list(r: &PdfFile) -> Vec<Object> {
    let root = r.root().unwrap();
    let names = as_dict(get(r, &root, "Names"));
    let ef = as_dict(get(r, &names, "EmbeddedFiles"));
    match get(r, &ef, "Names") {
        Object::Array(a) => a,
        _ => panic!(),
    }
}

fn ef_stream(r: &dyn PdfHandler, spec: &sigis_pdf::lopdf::Dictionary) -> sigis_pdf::lopdf::Stream {
    let ef = as_dict(get(r, spec, "EF"));
    match get(r, &ef, "F") {
        Object::Stream(s) => s,
        _ => panic!(),
    }
}

#[test]
fn test_simple_embed() {
    for incremental in [true, false] {
        let mut w = writer(incremental);
        let (modified, created) = frozen();
        let vector = pdf("scribble.pdf");
        embed_test(
            &mut w,
            "vector-test.pdf",
            "テスト.pdf",
            &vector,
            created,
            modified,
        );
        let out = w.write().unwrap();
        let r = read(&out);
        assert_eq!(r.input_version(), (1, 7));
        let lst = emb_list(&r);
        assert_eq!(lst.len(), 2);
        assert_eq!(text(&lst[0]), "vector-test.pdf");
        let spec = as_dict(r.resolve(&lst[1]).unwrap());
        assert_eq!(text(&get(&r, &spec, "Desc")), "Embedding test");
        assert_eq!(text(&get(&r, &spec, "UF")), "テスト.pdf");
        let s = ef_stream(&r, &spec);
        assert_eq!(r.stream_data(&s).unwrap(), vector);
        assert_eq!(
            s.dict.get(b"Subtype").unwrap(),
            &Object::Name(b"application/pdf".to_vec())
        );
        let params = as_dict(get(&r, &s.dict, "Params"));
        let Object::String(cs, _) = get(&r, &params, "CheckSum") else {
            panic!()
        };
        assert_eq!(cs, hex("caaf24354fd2e68c08826d65b309b404"));
        let md = parse_pdf_date_obj(&get(&r, &params, "ModDate"), true).unwrap();
        assert_eq!(md.unix_timestamp(), modified.unix_timestamp());
        let cd = parse_pdf_date_obj(&get(&r, &params, "CreationDate"), true).unwrap();
        assert_eq!(cd.unix_timestamp(), created.unix_timestamp());
        assert!(!r.root().unwrap().has(b"AF"));
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_embed_twice() {
    for incremental in [true, false] {
        let mut w = copy_into_new_writer(&read(&minimal()))
            .unwrap()
            .into_inner();
        let (modified, created) = frozen();
        let vector = pdf("scribble.pdf");
        let aes = pdf("minimal-aes256.pdf");
        embed_test(
            &mut w,
            "vector-test.pdf",
            "テスト.pdf",
            &vector,
            created,
            modified,
        );
        if incremental {
            let out = w.write().unwrap();
            w = IncrementalWriter::new(read(&out)).into_inner();
        }
        embed_test(
            &mut w,
            "some-other-file.pdf",
            "テスト2.pdf",
            &aes,
            created,
            modified,
        );
        let out = w.write().unwrap();
        let r = read(&out);
        let lst = emb_list(&r);
        assert_eq!(lst.len(), 4);
        assert_eq!(text(&lst[0]), "vector-test.pdf");
        let spec = as_dict(r.resolve(&lst[1]).unwrap());
        assert_eq!(text(&get(&r, &spec, "UF")), "テスト.pdf");
        assert_eq!(r.stream_data(&ef_stream(&r, &spec)).unwrap(), vector);
        assert_eq!(text(&lst[2]), "some-other-file.pdf");
        let spec = as_dict(r.resolve(&lst[3]).unwrap());
        assert_eq!(text(&get(&r, &spec, "UF")), "テスト2.pdf");
        assert_eq!(r.stream_data(&ef_stream(&r, &spec)).unwrap(), aes);
    }
}

#[test]
fn test_embed_with_af() {
    for incremental in [true, false] {
        let mut w = writer(incremental);
        let (modified, created) = frozen();
        let vector = pdf("scribble.pdf");
        let params = EmbeddedFileParams {
            creation_date: Some(created),
            modification_date: Some(modified),
            ..EmbeddedFileParams::default()
        };
        let ef = embedded_file_object(&mut w, &vector, true, Some(&params), None).unwrap();
        let spec = FileSpec {
            file_spec_string: "vector-test.pdf".into(),
            embedded_data: Some(ef),
            description: Some("Embedding test /w assoc file".into()),
            af_relationship: Some("Unspecified".into()),
            ..FileSpec::default()
        };
        embed_file(&mut w, &spec).unwrap();
        let out = w.write().unwrap();
        let r = read(&out);
        assert_eq!(r.input_version(), (2, 0));
        let lst = emb_list(&r);
        assert_eq!(lst.len(), 2);
        assert_eq!(text(&lst[0]), "vector-test.pdf");
        let Object::Reference(spec_ref) = lst[1] else {
            panic!()
        };
        let spec = as_dict(r.get_object(spec_ref).unwrap());
        assert!(!spec.has(b"UF"));
        assert_eq!(
            spec.get(b"AFRelationship").unwrap(),
            &Object::Name(b"Unspecified".to_vec())
        );
        assert_eq!(r.stream_data(&ef_stream(&r, &spec)).unwrap(), vector);
        assert!(!as_dict(get(&r, &spec, "EF")).has(b"UF"));
        let root = r.root().unwrap();
        let Object::Array(af) = get(&r, &root, "AF") else {
            panic!()
        };
        assert_eq!(af[0], Object::Reference(spec_ref));
    }
}

#[test]
fn test_embed_without_ef_stream() {
    let mut w = copy_into_new_writer(&read(&minimal())).unwrap();
    let spec = FileSpec {
        file_spec_string: "vector-test.pdf".into(),
        description: Some("Embedding test /w assoc file".into()),
        af_relationship: Some("Unspecified".into()),
        ..FileSpec::default()
    };
    let e = assert_err_matches(
        embed_file(&mut w, &spec),
        "File spec does not have an embedded file stream",
    );
    assert!(matches!(e, PdfError::Write(_)));
}

fn ef_ref(r: &PdfFile) -> sigis_pdf::lopdf::ObjectId {
    let lst = emb_list(r);
    let spec = as_dict(r.resolve(&lst[1]).unwrap());
    let ef = as_dict(get(r, &spec, "EF"));
    match ef.get(b"F").unwrap() {
        Object::Reference(x) => *x,
        _ => panic!(),
    }
}

fn has_crypt_filter(s: &sigis_pdf::lopdf::Stream) -> bool {
    sigis_pdf::stream::has_crypt_filter(&s.dict, &sigis_pdf::stream::no_deref).unwrap()
}

fn first_page_data(r: &PdfFile) -> Vec<u8> {
    let (_, page) = first_page(r);
    match get(r, &page, "Contents") {
        Object::Stream(s) => r.stream_data(&s).unwrap(),
        _ => panic!(),
    }
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

#[test]
fn test_encrypt_efs() {
    use sigis_pdf::crypt::{
        AuthStatus, CryptFilter, CryptFilterConfiguration, SecurityHandler, StandardEncryptOptions,
        STD_CF,
    };
    let mut w = copy_into_new_writer(&read(&minimal())).unwrap();
    let mut cf = CryptFilter::standard_aes(32).unwrap();
    cf.set_embedded_only();
    let cfc =
        CryptFilterConfiguration::new(vec![(STD_CF, cf)], "Identity", "Identity", Some(STD_CF))
            .unwrap();
    let sh = SecurityHandler::build_from_pw(
        "secret",
        None,
        StandardEncryptOptions {
            encrypt_metadata: false,
            crypt_filter_config: Some(cfc),
            ..StandardEncryptOptions::default()
        },
    )
    .unwrap();
    w.assign_security_handler(&sh).unwrap();
    let (modified, created) = frozen();
    let vector = pdf("scribble.pdf");
    embed_test(
        &mut w,
        "vector-test.pdf",
        "テスト.pdf",
        &vector,
        created,
        modified,
    );
    let out = w.write().unwrap();
    let r = read(&out);
    // accessible without authenticating
    assert!(contains(&first_page_data(&r), b"Hello"));
    let ef = ef_ref(&r);
    let result = r.decrypt("secret").unwrap();
    assert_eq!(result.status, AuthStatus::Owner);
    let Object::Stream(s) = r.get_object(ef).unwrap() else {
        panic!()
    };
    assert!(has_crypt_filter(&s));
    assert_eq!(r.stream_data(&s).unwrap(), vector);
}

#[test]
fn test_decrypt_ef_without_explicit_crypt_filter() {
    let r = read(&pdf("embedded-encrypted-nocf.pdf"));
    let ef = ef_ref(&r);
    r.decrypt("secret").unwrap();
    let Object::Stream(s) = r.get_object(ef).unwrap() else {
        panic!()
    };
    assert!(!has_crypt_filter(&s));
    assert_eq!(r.stream_data(&s).unwrap(), pdf("scribble.pdf"));
}

#[test]
fn test_wrapper_doc_underspecified() {
    // pyHanko raises ValueError unless exactly one of password/certs is
    // given; `WrapEncryption` makes that unrepresentable. The remaining
    // runtime check: an empty recipient list cannot produce a usable file.
    let res = sigis_pdf::embed::wrap_encrypted_payload(
        b"bacadsflkj",
        sigis_pdf::embed::WrapEncryption::Certs(vec![]),
        "attachment.pdf",
        None,
        None,
        "Wrapped document",
        true,
    );
    match res {
        Err(_) => {}
        Ok(mut w) => {
            // even if building succeeds, nobody can decrypt the attachment
            let out = w.write().unwrap();
            let r = read(&out);
            let decrypter = common::crypt::pubkey_test_decrypter();
            assert!(
                r.decrypt_pubkey(&decrypter).map(|a| a.status)
                    != Ok(sigis_pdf::crypt::AuthStatus::User)
            );
        }
    }
}

fn check_wrapper(out: &[u8]) -> (PdfFile, sigis_pdf::lopdf::ObjectId) {
    let r = read(out);
    assert!(contains(&first_page_data(&r), b"attached file"));
    let root = r.root().unwrap();
    let coll = as_dict(get(&r, &root, "Collection"));
    assert_eq!(text(&get(&r, &coll, "D")), "attachment.pdf");
    assert_eq!(get(&r, &coll, "View"), Object::Name(b"H".to_vec()));
    let ef = ef_ref(&r);
    (r, ef)
}

#[test]
fn test_wrapper_doc() {
    use sigis_pdf::embed::{wrap_encrypted_payload, WrapEncryption};
    let vector = pdf("scribble.pdf");
    let mut w = wrap_encrypted_payload(
        &vector,
        WrapEncryption::Password("secret".into()),
        "attachment.pdf",
        None,
        None,
        "Wrapped document",
        true,
    )
    .unwrap();
    let out = w.write().unwrap();
    let (r, ef) = check_wrapper(&out);
    let result = r.decrypt("secret").unwrap();
    assert_eq!(result.status, sigis_pdf::crypt::AuthStatus::Owner);
    let Object::Stream(s) = r.get_object(ef).unwrap() else {
        panic!()
    };
    assert!(has_crypt_filter(&s));
    assert_eq!(r.stream_data(&s).unwrap(), vector);
}

#[test]
fn test_wrapper_doc_pubkey() {
    use sigis_pdf::embed::{wrap_encrypted_payload, WrapEncryption};
    let vector = pdf("scribble.pdf");
    let decrypter = common::crypt::pubkey_test_decrypter();
    let mut w = wrap_encrypted_payload(
        &vector,
        WrapEncryption::Certs(vec![decrypter.cert_info().der().to_vec()]),
        "attachment.pdf",
        None,
        None,
        "Wrapped document",
        true,
    )
    .unwrap();
    let out = w.write().unwrap();
    let (r, ef) = check_wrapper(&out);
    let result = r.decrypt_pubkey(&decrypter).unwrap();
    assert_eq!(result.status, sigis_pdf::crypt::AuthStatus::User);
    let Object::Stream(s) = r.get_object(ef).unwrap() else {
        panic!()
    };
    assert!(has_crypt_filter(&s));
    assert_eq!(r.stream_data(&s).unwrap(), vector);
}
