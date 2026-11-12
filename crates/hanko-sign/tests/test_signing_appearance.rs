//! Appearance-related tests of pyHanko 0.38.1
//! `pkgs/pyhanko/tests/test_signing.py`: `test_simple_qr_sign`,
//! `test_qr_sign_enforce_url_param`, `test_no_email`,
//! `test_sign_appearance_noop`, `test_sign_visible_with_separate_annot`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;

use sigis_pki_core::sign::KeySigner;
use sigis_pades_sign::layout::is_layout_error;
use sigis_pades_sign::pdf::fields::append_signature_field;
use sigis_pades_sign::pdf::writer::PdfUpdate;
use sigis_pades_sign::stamp::{QrStampStyle, StampStyle, TextStampStyle};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SigFieldSpec, SignOptions, SimpleSigner};
use lopdf::Object;
use support::pdfcheck::*;
use support::*;

const T_2020_11_01: &str = "2020-11-01T00:00:00+00:00";

fn from_ca() -> SimpleSigner {
    pki("testing-ca").signer("signer1")
}

fn self_sign() -> SimpleSigner {
    SimpleSigner::load(
        &pyhanko_data(&["crypto", "selfsigned.key.pem"]),
        &pyhanko_data(&["crypto", "selfsigned.cert.pem"]),
        Some(b"secret"),
        vec![],
    )
    .unwrap()
}

fn signer(meta: PdfSignatureMetadata, s: SimpleSigner, style: Option<StampStyle>) -> PdfSigner {
    let mut p = PdfSigner::new(meta, Arc::new(s)).at(at(T_2020_11_01));
    p.stamp_style = style;
    p
}

fn existing_only() -> SignOptions {
    SignOptions {
        existing_fields_only: true,
        ..SignOptions::default()
    }
}

fn resolve<'a>(doc: &'a lopdf::Document, o: &'a Object) -> &'a Object {
    support::pdfcheck::resolve(doc, o)
}

/// `/AP /N` of an annotation dictionary: (stream dictionary, decoded data).
fn normal_appearance(doc: &lopdf::Document, annot: &lopdf::Dictionary) -> (lopdf::Dictionary, Vec<u8>) {
    let ap = resolve(doc, annot.get(b"AP").unwrap()).as_dict().unwrap();
    let n = resolve(doc, ap.get(b"N").unwrap()).as_stream().unwrap();
    let data = n.decompressed_content().unwrap_or_else(|_| n.content.clone());
    (n.dict.clone(), data)
}

#[test]
fn test_simple_qr_sign() {
    let style = StampStyle::Qr(QrStampStyle::with_text("Hi, it's\n%(ts)s"));
    let mut s = signer(PdfSignatureMetadata::pyhanko_defaults("Sig1"), from_ca(), Some(style));
    s.appearance_text_params = BTreeMap::from([("url".to_owned(), "https://example.com".to_owned())]);
    let out = s.sign_pdf_with(&pdf("minimal-with-field.pdf"), &existing_only()).unwrap();
    let sigs = embedded_signatures(&out);
    assert_eq!(sigs[0].field_name, "Sig1");
    let doc = load(&out);
    let (n, _) = normal_appearance(&doc, &sigs[0].field);
    let res = resolve(&doc, n.get(b"Resources").unwrap()).as_dict().unwrap();
    let xobj = resolve(&doc, res.get(b"XObject").unwrap()).as_dict().unwrap();
    assert!(xobj.has(b"QR"));
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
}

#[test]
fn test_qr_sign_enforce_url_param() {
    let params: [Option<BTreeMap<String, String>>; 3] = [
        None,
        Some(BTreeMap::new()),
        Some(BTreeMap::from([("some".to_owned(), "value".to_owned())])),
    ];
    for p in params {
        let style = StampStyle::Qr(QrStampStyle::with_text("Hi, it's\n%(ts)s"));
        let mut s = signer(PdfSignatureMetadata::pyhanko_defaults("Sig1"), from_ca(), Some(style));
        s.appearance_text_params = p.unwrap_or_default();
        let e = s.sign_pdf_with(&pdf("minimal-with-field.pdf"), &existing_only()).unwrap_err();
        assert!(is_layout_error(&e), "{e}");
    }
}

#[test]
fn test_no_email() {
    let tsa = SimpleSigner::load(
        &pyhanko_data(&["crypto", "keys-rsa", "tsa.key.pem"]),
        &pyhanko_data(&["crypto", "tsa.cert.pem"]),
        Some(b"secret"),
        vec![],
    )
    .unwrap();
    let cn = sigis_pades_sign::signer::subject_display_name(tsa.signing_cert()).unwrap();
    let style = StampStyle::Text(TextStampStyle::with_text("%(signer)s\n%(ts)s"));
    let out = signer(PdfSignatureMetadata::pyhanko_defaults("Sig1"), tsa, Some(style))
        .sign_pdf(&pdf("minimal-with-field.pdf"))
        .unwrap();
    let sigs = embedded_signatures(&out);
    assert_eq!(sigs[0].field_name, "Sig1");
    val_untrusted(&out, 0, T_2020_11_01, false);
    let doc = load(&out);
    let (_, ap_data) = normal_appearance(&doc, &sigs[0].field);
    assert!(!cn.contains('<'), "the TSA certificate has no e-mail address");
    let needle = cn.as_bytes();
    assert!(ap_data.windows(needle.len()).any(|w| w == needle), "{cn}");
}

#[test]
fn test_sign_appearance_noop() {
    let mut w = PdfUpdate::new(&pdf("minimal.pdf")).unwrap();
    let spec = SigFieldSpec {
        empty_field_appearance: true,
        ..SigFieldSpec::new("Sig1").with_box((20.0, 20.0, 80.0, 40.0))
    };
    append_signature_field(&mut w, &spec).unwrap();
    let (with_field, _) = w.write().unwrap();
    let field_ap = |pdf_bytes: &[u8]| -> Vec<u8> {
        let doc = load(pdf_bytes);
        let form = resolve(&doc, root(&doc).get(b"AcroForm").unwrap()).as_dict().unwrap();
        let field = resolve(&doc, &form.get(b"Fields").unwrap().as_array().unwrap()[0])
            .as_dict()
            .unwrap()
            .clone();
        normal_appearance(&doc, &field).1
    };
    let appearance_old = field_ap(&with_field);
    let out = signer(PdfSignatureMetadata::pyhanko_defaults("Sig1"), self_sign(), Some(StampStyle::NoOp))
        .sign_pdf(&with_field)
        .unwrap();
    assert_eq!(appearance_old, field_ap(&out));
}

#[test]
fn test_sign_visible_with_separate_annot() {
    for presign_ap in ["present", "removed"] {
        let mut w = PdfUpdate::new(&pdf("minimal.pdf")).unwrap();
        let spec = SigFieldSpec {
            combine_annotation: false,
            empty_field_appearance: false,
            ..SigFieldSpec::new("Sig1").with_box((20.0, 20.0, 80.0, 40.0))
        };
        let field_id = append_signature_field(&mut w, &spec).unwrap();
        let (mut cur, _) = w.write().unwrap();
        if presign_ap == "removed" {
            let mut w = PdfUpdate::new(&cur).unwrap();
            let kid = match w.get_dict(field_id).unwrap().get(b"Kids").unwrap() {
                Object::Array(a) => a[0].as_reference().unwrap(),
                Object::Reference(r) => {
                    w.get(*r).unwrap().as_array().unwrap()[0].as_reference().unwrap()
                }
                _ => panic!("kids"),
            };
            w.get_dict_mut(kid).unwrap().remove(b"AP");
            cur = w.write().unwrap().0;
        }
        let out = signer(PdfSignatureMetadata::pyhanko_defaults("Sig1"), from_ca(), None)
            .sign_pdf(&cur)
            .unwrap();
        let sigs = embedded_signatures(&out);
        assert_eq!(sigs[0].field_name, "Sig1");
        let doc = load(&out);
        assert!(!sigs[0].field.has(b"AP"));
        let kids = resolve(&doc, sigs[0].field.get(b"Kids").unwrap()).as_array().unwrap();
        let kid = resolve(&doc, &kids[0]).as_dict().unwrap();
        assert!(kid.has(b"AP"));
        let (_, data) = normal_appearance(&doc, kid);
        assert!(data.windows(16).any(|w| w == b"Digitally signed"));
        val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
    }
}
