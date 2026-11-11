//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_fields.py`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use hanko_pdf::MdpPerm;
use hanko_sign::pdf::fields::{self, FieldMdpAction, FieldMdpSpec, InvisSigSettings, SigFieldSpec, VisibleSigSettings};
use hanko_sign::pdf::writer::PdfUpdate;
use hanko_sign::{PdfSignatureMetadata, PdfSigner, SignOptions};
use lopdf::{Dictionary, Object};
use support::pdfcheck::*;
use support::*;

const T: &str = "2020-11-01T00:00:00+00:00";

fn meta(field: &str) -> PdfSignatureMetadata {
    PdfSignatureMetadata::pyhanko_defaults(field)
}

fn signer() -> PdfSigner {
    PdfSigner::new(meta(""), Arc::new(pki("testing-ca").signer("signer1"))).at(at(T))
}

fn sign_field(pdf_in: &[u8], field: &str, existing_only: bool) -> hanko_core::errors::Result<Vec<u8>> {
    let mut s = signer();
    s.metadata.field_name = field.into();
    s.sign_pdf_with(pdf_in, &SignOptions { existing_fields_only: existing_only, ..Default::default() })
}

fn field_with_lock_sp(include_docmdp: bool) -> SigFieldSpec {
    let mut s = SigFieldSpec::new("SigNew").with_box((10.0, 74.0, 140.0, 134.0));
    s.field_mdp_spec = Some(FieldMdpSpec { action: FieldMdpAction::Include, fields: vec!["blah".into()] });
    s.doc_mdp_update_value = include_docmdp.then_some(MdpPerm::NoChanges);
    s
}

fn append(pdf_in: &[u8], spec: &SigFieldSpec) -> Vec<u8> {
    let mut w = PdfUpdate::new(pdf_in).unwrap();
    fields::append_signature_field(&mut w, spec).unwrap();
    w.write().unwrap().0
}

/// The page dictionaries of `pdf`.
fn pages(pdf: &[u8]) -> (lopdf::Document, Vec<Dictionary>) {
    let doc = load(pdf);
    let ids: Vec<_> = doc.get_pages().values().copied().collect();
    let dicts = ids.iter().map(|id| doc.get_dictionary(*id).unwrap().clone()).collect();
    (doc, dicts)
}

fn annots(doc: &lopdf::Document, page: &Dictionary) -> Vec<Dictionary> {
    match dict_get(doc, page, b"Annots") {
        Some(Object::Array(a)) => a.iter().map(|x| resolve(doc, x).as_dict().unwrap().clone()).collect(),
        _ => vec![],
    }
}

fn form_fields(pdf: &[u8]) -> (lopdf::Document, Vec<Object>) {
    let doc = load(pdf);
    let r = root(&doc).clone();
    let Some(Object::Dictionary(form)) = dict_get(&doc, &r, b"AcroForm") else { panic!("no form") };
    let Some(Object::Array(f)) = dict_get(&doc, form, b"Fields") else { panic!("no fields") };
    let f = f.clone();
    (doc, f)
}

fn stream_data(doc: &lopdf::Document, o: &Object) -> Vec<u8> {
    match resolve(doc, o) {
        Object::Stream(s) => s.decompressed_content().unwrap_or_else(|_| s.content.clone()),
        _ => panic!("not a stream"),
    }
}

#[test]
fn test_append_sigfield_second_page() {
    let out = append(&pdf("minimal-two-pages.pdf"), &SigFieldSpec::new("Sig1").on_page(1));
    let (doc, pg) = pages(&out);
    assert!(pg[0].get(b"Annots").is_err());
    let a = annots(&doc, &pg[1]);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].get(b"T").unwrap(), &Object::string_literal("Sig1"));
}

#[test]
fn test_append_sigfield_ap() {
    let mut spec = SigFieldSpec::new("Sig1").with_box((20.0, 20.0, 80.0, 40.0));
    spec.empty_field_appearance = true;
    let out = append(&pdf("minimal.pdf"), &spec);
    let (doc, pg) = pages(&out);
    let a = annots(&doc, &pg[0]);
    assert_eq!(a.len(), 1);
    let ap = a[0].get(b"AP").unwrap().as_dict().unwrap();
    assert!(stream_data(&doc, ap.get(b"N").unwrap()).len() > 10);
}

#[test]
fn test_append_sigfield_trivial_ap() {
    let out = append(&pdf("minimal.pdf"), &SigFieldSpec::new("Sig1").with_box((20.0, 20.0, 80.0, 40.0)));
    let (doc, pg) = pages(&out);
    let a = annots(&doc, &pg[0]);
    let ap = a[0].get(b"AP").unwrap().as_dict().unwrap();
    assert_eq!(stream_data(&doc, ap.get(b"N").unwrap()), b"");
}

#[test]
fn test_add_sigfield_with_lock() {
    for include_docmdp in [true, false] {
        let input = append(&pdf("minimal.pdf"), &field_with_lock_sp(include_docmdp));
        let out = sign_field(&input, "SigNew", false).unwrap();
        let s = &embedded_signatures(&out)[0];
        assert_eq!(s.field_name, "SigNew");
        let doc = load(&out);
        let Some(Object::Array(refs)) = dict_get(&doc, &s.sig, b"Reference") else { panic!() };
        assert_eq!(refs.len(), 1);
        let r0 = resolve(&doc, &refs[0]).as_dict().unwrap();
        assert_eq!(r0.get(b"TransformMethod").unwrap(), &Object::Name(b"FieldMDP".to_vec()));
        let tp = resolve(&doc, r0.get(b"TransformParams").unwrap()).as_dict().unwrap();
        assert_eq!(tp.get(b"Fields").unwrap(), &Object::Array(vec![Object::string_literal("blah")]));
        assert_eq!(r0.get(b"Data").unwrap(), doc.trailer.get(b"Root").unwrap());
        assert!(root(&doc).get(b"Perms").is_err());
        if include_docmdp {
            assert_eq!(tp.get(b"P").unwrap(), &Object::Integer(1));
        }
        val_trusted(&out, 0, &pki("testing-ca"), T, false);
    }
}

#[test]
fn test_sign_field_unclear() {
    let two = pdf("minimal-two-fields.pdf");
    assert!(matches!(sign_field(&two, "", false), Err(hanko_core::errors::HankoError::Signing(_))));
    assert!(matches!(sign_field(&two, "", true), Err(hanko_core::errors::HankoError::Signing(_))));
    assert!(matches!(sign_field(&two, "SigExtra", true), Err(hanko_core::errors::HankoError::Signing(_))));
}

#[test]
fn test_sign_field_unclear_async() {
    // the Rust API is synchronous
    test_sign_field_unclear();
}

#[test]
fn test_sign_field_infer() {
    let one = pdf("minimal-with-field.pdf");
    assert!(sign_field(&one, "", false).is_err());
    let out = sign_field(&one, "", true).unwrap();
    assert_eq!(embedded_signatures(&out)[0].field_name, "Sig1");
    val_trusted(&out, 0, &pki("testing-ca"), T, false);
    assert!(sign_field(&out, "", true).is_err());
}

#[test]
fn test_sign_field_filled() {
    let out1 = sign_field(&pdf("minimal-two-fields.pdf"), "Sig1", true).unwrap();
    assert!(sign_field(&out1, "Sig1", true).is_err());
    let val2 = |out: &[u8]| {
        let sigs = embedded_signatures(out);
        assert_eq!(sigs[0].field_name, "Sig1");
        val_trusted(out, 0, &pki("testing-ca"), T, true);
        assert_eq!(sigs[1].field_name, "Sig2");
        val_trusted(out, 1, &pki("testing-ca"), T, false);
    };
    val2(&sign_field(&out1, "", true).unwrap());
    val2(&sign_field(&out1, "Sig2", true).unwrap());
}

#[test]
fn test_sign_new() {
    for f in ["minimal.pdf", "minimal-with-field.pdf"] {
        let out = sign_field(&pdf(f), "SigNew", false).unwrap();
        assert_eq!(embedded_signatures(&out)[0].field_name, "SigNew");
        val_trusted(&out, 0, &pki("testing-ca"), T, false);
    }
}

#[test]
fn test_sign_with_indir_annots() {
    let out = sign_field(&pdf("minimal-one-field-indir-annots.pdf"), "SigNew", false).unwrap();
    assert_eq!(embedded_signatures(&out)[0].field_name, "SigNew");
    val_trusted(&out, 0, &pki("testing-ca"), T, false);
    let (doc, pg) = pages(&out);
    let annots_ref = pg[0].get(b"Annots").unwrap();
    assert!(matches!(annots_ref, Object::Reference(_)));
    assert_eq!(resolve(&doc, annots_ref).as_array().unwrap().len(), 2);
}

#[test]
fn test_double_sign_lock_second() {
    let input = append(&pdf("minimal.pdf"), &field_with_lock_sp(true));
    let out = sign_field(&input, "SigFirst", false).unwrap();
    let out = sign_field(&out, "SigNew", false).unwrap();
    val_trusted(&out, 0, &pki("testing-ca"), T, true);
    let s = &embedded_signatures(&out)[1];
    let doc = load(&out);
    let Some(Object::Array(refs)) = dict_get(&doc, &s.sig, b"Reference") else { panic!() };
    assert_eq!(refs.len(), 1);
    val_trusted(&out, 1, &pki("testing-ca"), T, false);
}

#[test]
fn test_sign_new_existingonly() {
    for f in ["minimal.pdf", "minimal-with-field.pdf"] {
        assert!(matches!(sign_field(&pdf(f), "SigNew", true), Err(hanko_core::errors::HankoError::Signing(_))));
    }
}

#[test]
fn test_async_sign_new_existingonly() {
    test_sign_new_existingonly();
}

#[test]
fn test_sign_with_new_field_spec() {
    let spec = SigFieldSpec::new("Sig1").with_box((20.0, 20.0, 80.0, 40.0));
    let mut s = signer().with_field_spec(spec.clone());
    s.metadata.field_name = "Sig1".into();
    let out = s.sign_pdf(&pdf("minimal.pdf")).unwrap();
    let e = &embedded_signatures(&out)[0];
    assert_eq!(e.field_name, "Sig1");
    assert!(e.field.get(b"AP").is_ok());
    let mut s2 = signer().with_field_spec(spec.clone());
    s2.metadata.field_name = "Sig2".into();
    assert!(s2.sign_pdf(&pdf("minimal.pdf")).is_err());
    let mut s3 = signer().with_field_spec(spec);
    s3.metadata.field_name = "Sig1".into();
    assert!(s3
        .sign_pdf_with(&pdf("minimal.pdf"), &SignOptions { existing_fields_only: true, ..Default::default() })
        .is_err());
}

fn field_count_after_append(input: &[u8], sp: &SigFieldSpec) -> usize {
    let out = append(input, sp);
    form_fields(&out).1.len()
}

#[test]
fn test_append_simple_sig_field() {
    let sp = SigFieldSpec::new("InvisibleSig");
    let once = append(&pdf("minimal.pdf"), &sp);
    assert_eq!(form_fields(&once).1.len(), 1);
    let mut w = PdfUpdate::new(&once).unwrap();
    assert!(fields::append_signature_field(&mut w, &sp).is_err());
    assert_eq!(field_count_after_append(&pdf("minimal-two-fields.pdf"), &sp), 3);
}

#[test]
fn test_append_visible_sig_field() {
    let sp = SigFieldSpec::new("VisibleSig").with_box((10.0, 0.0, 50.0, 8.0));
    let once = append(&pdf("minimal.pdf"), &sp);
    assert_eq!(form_fields(&once).1.len(), 1);
    let mut w = PdfUpdate::new(&once).unwrap();
    assert!(fields::append_signature_field(&mut w, &sp).is_err());
    assert_eq!(field_count_after_append(&pdf("minimal-two-fields.pdf"), &sp), 3);
}

/// A fresh one-page document (`PdfFileWriter` + `simple_page`) whose catalog
/// gets `acroform` (if any).
fn simple_doc(acroform: Option<Object>) -> Vec<u8> {
    use lopdf::{dictionary, Document, Stream};
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let font_id = doc.add_object(dictionary! {"Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Courier"});
    let content = doc.add_object(Stream::new(dictionary! {}, b"BT /F1 18 Tf 0 0 Td (Hello world) Tj ET".to_vec()));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page", "Parent" => pages_id, "Contents" => content,
        "MediaBox" => vec![0.into(), 0.into(), 300.into(), 144.into()],
        "Resources" => dictionary! {"Font" => dictionary! {"F1" => font_id}},
    });
    doc.objects.insert(pages_id, Object::Dictionary(dictionary! {"Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1}));
    let mut catalog = dictionary! {"Type" => "Catalog", "Pages" => pages_id};
    if let Some(a) = acroform {
        catalog.set("AcroForm", a);
    }
    let cat = doc.add_object(catalog);
    doc.trailer.set("Root", cat);
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

#[test]
fn test_append_sig_field_acro_update() {
    let mut form = Dictionary::new();
    form.set("Fields", Object::Array(vec![]));
    let input = simple_doc(Some(Object::Dictionary(form)));
    assert_eq!(field_count_after_append(&input, &SigFieldSpec::new("InvisibleSig")), 1);
}

#[test]
fn test_append_acroform_no_fields() {
    let input = simple_doc(Some(Object::Dictionary(Dictionary::new())));
    assert_eq!(field_count_after_append(&input, &SigFieldSpec::new("InvisibleSig")), 1);
}

#[test]
fn test_append_acroform_reference_broken_nonstrict() {
    let input = simple_doc(Some(Object::Reference((1239481, 0))));
    let mut w = PdfUpdate::new(&input).unwrap();
    w.set_strict(false);
    fields::append_signature_field(&mut w, &SigFieldSpec::new("InvisibleSig")).unwrap();
    let out = w.write().unwrap().0;
    assert_eq!(form_fields(&out).1.len(), 1);
}

#[test]
fn test_circular_form_tree_sign() {
    let out = sign_field(&pdf("form-tree-circular-ref-input.pdf"), "Sig", false).unwrap();
    let r = std::panic::catch_unwind(|| embedded_signatures(&out));
    assert!(r.is_err(), "the test inspector rejects the circular tree");
    let root = pki("testing-ca").cert_path("root");
    if let Some(v) = oracle_verdicts(&out, &[&root], T, &[]) {
        let e = v[0]["reader_error"].as_str().unwrap_or_default();
        assert!(e.contains("Circular") && e.contains("form tree"), "{}", v[0]);
    }
}

#[test]
fn test_circular_form_tree_sign_deep() {
    let err = sign_field(&pdf("form-tree-circular-ref-input.pdf"), "TextInput.Sig", false).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("Circular") && msg.contains("form tree"), "{msg}");
}

#[test]
fn test_invisible_field_flags() {
    let cases = [
        (InvisSigSettings::default(), 0b1000_0100, [0, 0, 0, 0]),
        (InvisSigSettings { set_hidden_flag: true, set_print_flag: false, box_out_of_bounds: false }, 0b1000_0010, [0, 0, 0, 0]),
        (InvisSigSettings { box_out_of_bounds: true, ..Default::default() }, 0b1000_0100, [-9999, -9999, -9999, -9999]),
    ];
    for (settings, flags, bx) in cases {
        let mut sp = SigFieldSpec::new("Sig1");
        sp.invis_sig_settings = settings;
        let out = append(&pdf("minimal.pdf"), &sp);
        let (doc, pg) = pages(&out);
        let a = &annots(&doc, &pg[0])[0];
        assert_eq!(a.get(b"F").unwrap(), &Object::Integer(flags));
        let rect: Vec<i64> = a.get(b"Rect").unwrap().as_array().unwrap().iter().map(|x| hanko_sign::pdf::util::as_number(x).unwrap() as i64).collect();
        assert_eq!(rect, bx);
    }
}

#[test]
fn test_append_sigfield_tu() {
    let mut spec = SigFieldSpec::new("Sig1");
    spec.empty_field_appearance = true;
    spec.readable_field_name = Some("Test test".into());
    let out = append(&pdf("minimal.pdf"), &spec);
    let (doc, f) = form_fields(&out);
    let d = resolve(&doc, &f[0]).as_dict().unwrap();
    assert_eq!(d.get(b"TU").unwrap(), &Object::string_literal("Test test"));
}

#[test]
fn test_visible_field_flags() {
    let cases = [
        (VisibleSigSettings::default(), 0b1000_0100),
        (VisibleSigSettings { rotate_with_page: false, ..Default::default() }, 0b1001_0100),
        (VisibleSigSettings { scale_with_page_zoom: false, ..Default::default() }, 0b1000_1100),
        (VisibleSigSettings { print_signature: false, ..Default::default() }, 0b1000_0000),
        (VisibleSigSettings { print_signature: false, scale_with_page_zoom: false, rotate_with_page: false }, 0b1001_1000),
    ];
    for (settings, flags) in cases {
        let mut sp = SigFieldSpec::new("Sig1").with_box((10.0, 10.0, 100.0, 100.0));
        sp.visible_sig_settings = settings;
        let out = append(&pdf("minimal.pdf"), &sp);
        let (doc, pg) = pages(&out);
        assert_eq!(annots(&doc, &pg[0])[0].get(b"F").unwrap(), &Object::Integer(flags));
    }
}

#[test]
fn test_sign_field_with_needappearances() {
    let mut w = PdfUpdate::new(&pdf("minimal-with-field.pdf")).unwrap();
    let form_ref = w.root().unwrap().get(b"AcroForm").unwrap().as_reference().unwrap();
    w.get_dict_mut(form_ref).unwrap().set("NeedAppearances", Object::Boolean(true));
    let input = w.write().unwrap().0;
    let out = sign_field(&input, "", true).unwrap();
    let doc = load(&out);
    let Some(Object::Dictionary(form)) = dict_get(&doc, root(&doc), b"AcroForm") else { panic!() };
    assert!(form.get(b"NeedAppearances").is_err());
}

#[test]
fn test_create_with_separate_annot() {
    let mut spec = SigFieldSpec::new("Sig1").with_box((20.0, 20.0, 80.0, 40.0));
    spec.combine_annotation = false;
    let out = append(&pdf("minimal.pdf"), &spec);
    let (doc, f) = form_fields(&out);
    let f0 = resolve(&doc, &f[0]).as_dict().unwrap();
    assert!(f0.get(b"AP").is_err());
    let kids = f0.get(b"Kids").unwrap().as_array().unwrap();
    assert!(resolve(&doc, &kids[0]).as_dict().unwrap().get(b"AP").is_ok());
    let (_, pg) = pages(&out);
    let page_annots = dict_get(&doc, &pg[0], b"Annots").unwrap().as_array().unwrap();
    assert_eq!(kids, page_annots);
}

#[test]
fn test_sign_with_cert_no_common_name_appearance() {
    // falls back to the organisation name
    let p = pki("testing-ca-with-errors");
    let signer = hanko_sign::SimpleSigner::new(
        p.key("signer1"),
        p.cert("signer-no-cn"),
        vec![pki("testing-ca").cert("root"), pki("testing-ca").cert("interm")],
    )
    .unwrap();
    let out = PdfSigner::new(meta(""), Arc::new(signer))
        .at(at(T))
        .sign_pdf_with(&pdf("minimal-with-field.pdf"), &SignOptions { existing_fields_only: true, ..Default::default() })
        .unwrap();
    let (doc, pg) = pages(&out);
    let annot = &annots(&doc, &pg[0])[0];
    let ap = annot.get(b"AP").unwrap().as_dict().unwrap();
    let data = stream_data(&doc, ap.get(b"N").unwrap());
    let needle = b"signed by Example Inc ";
    assert!(data.windows(needle.len()).any(|w| w == needle), "{}", String::from_utf8_lossy(&data));
}
