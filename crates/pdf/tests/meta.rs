// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_meta.py`
// (MIT, see LICENSE-pyHanko). One Rust test per upstream test function;
// parametrized cases run in a loop. `freeze_time` is replaced by the
// writers' `fixed_time`; dates compare as instants, as Python's aware
// datetimes do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use sigis_pdf::generic::{pdf_name, text_string, PdfDate};
use sigis_pdf::lopdf::{Dictionary, Object};
use sigis_pdf::metadata::model::{
    self, dc_creator, dc_description, dc_title, xml_lang, DocumentMetadata, ExpandedName, MetaDate,
    MetaString, Qualifiers, XmpArray, XmpStructure, XmpUri, XmpValue, XmpValueKind, VENDOR,
};
use sigis_pdf::metadata::xmp_xml::{meta_from_xmp, parse_xmp, serialise_xmp, stream_xmp};
use sigis_pdf::writer::copy_into_new_writer;
use sigis_pdf::{
    IncrementalWriter, PdfError, PdfFile, PdfFileWriter, PdfHandler, PdfHandlerExt, PdfWriter,
};

fn date(y: i32, m: u8, d: u8, h: u8, mi: u8, s: u8, off: Option<i32>) -> PdfDate {
    PdfDate {
        year: y,
        month: m,
        day: d,
        hour: h,
        minute: mi,
        second: s,
        utc_offset_minutes: off,
    }
}

fn frozen() -> PdfDate {
    date(2022, 9, 7, 0, 0, 0, Some(0))
}

fn instant(d: &Option<MetaDate>) -> Option<i64> {
    match d {
        Some(MetaDate::At(p)) => Some(p.unix_timestamp()),
        _ => None,
    }
}

fn meta_view(r: &PdfFile) -> DocumentMetadata {
    r.document_meta_view().unwrap()
}

fn info_of(r: &PdfFile) -> Dictionary {
    as_dict(get(r, &r.trailer_view(), "Info"))
}

fn root_xmp(r: &PdfFile) -> Vec<XmpStructure> {
    let root = r.root().unwrap();
    let Object::Stream(s) = get(r, &root, "Metadata") else {
        panic!()
    };
    stream_xmp(r, &s).unwrap()
}

fn en(local: &str, ns: &str) -> ExpandedName {
    ExpandedName::new(ns, local)
}

fn is_xmp_err<T: std::fmt::Debug>(res: Result<T, PdfError>, pattern: &str) {
    let e = assert_err_matches(res, pattern);
    assert!(e.message().starts_with("XmpXmlProcessingError"), "{e:?}");
}

#[test]
fn test_no_meta_view_fails_gracefully() {
    let r = read(&minimal());
    assert_eq!(meta_view(&r), DocumentMetadata::default());
}

#[test]
fn test_copy_into_new_writer_sets_info() {
    let mut w = copy_into_new_writer(&read(&minimal())).unwrap();
    w.fixed_time = Some(frozen());
    let out = w.write().unwrap();
    let r = read(&out);
    let meta = meta_view(&r);
    assert_eq!(
        instant(&meta.last_modified),
        Some(frozen().unix_timestamp())
    );
    assert!(text(&get(&r, &info_of(&r), "Producer")).contains(VENDOR));
}

#[test]
fn test_date_parse_failure() {
    let mut w = copy_into_new_writer(&read(&minimal())).unwrap();
    let mut info = Dictionary::new();
    info.set("Title", text_string("a failure test"));
    info.set("CreationDate", text_string("this makes no sense"));
    w.set_info(Some(Object::Dictionary(info))).unwrap();
    w.update_meta_on_write = false;
    let out = w.write().unwrap();
    let meta = meta_view(&read(&out));
    assert_eq!(meta.created, None);
    assert_eq!(meta.title, Some(MetaString::plain("a failure test")));
}

#[test]
fn test_incremental_update_meta_view() {
    let mut w = IncrementalWriter::new(read(&pdf("scribble.pdf")));
    let MetaDate::At(c) = w.document_meta_view().unwrap().created.unwrap() else {
        panic!()
    };
    assert_eq!(c.year, 2020);
    w.document_meta().created = Some(MetaDate::At(date(2022, 9, 7, 0, 0, 0, None)));
    let MetaDate::At(c) = w.document_meta_view().unwrap().created.unwrap() else {
        panic!()
    };
    assert_eq!(c.year, 2022);
}

#[test]
fn test_writer_meta_view_does_not_persist_changes() {
    let exp = date(2020, 9, 5, 19, 30, 57, Some(120));
    for writer_type in ["fresh", "from_data", "incremental"] {
        let (w, expected): (PdfWriter, Option<i64>) = match writer_type {
            "fresh" => (PdfFileWriter::new(true, true).unwrap().into_inner(), None),
            "from_data" => (
                copy_into_new_writer(&read(&pdf("scribble.pdf")))
                    .unwrap()
                    .into_inner(),
                Some(exp.unix_timestamp()),
            ),
            _ => (
                IncrementalWriter::new(read(&pdf("scribble.pdf"))).into_inner(),
                Some(exp.unix_timestamp()),
            ),
        };
        assert_eq!(
            instant(&w.document_meta_view().unwrap().created),
            expected,
            "{writer_type}"
        );
        let mut view = w.document_meta_view().unwrap();
        view.created = Some(MetaDate::At(frozen()));
        assert_eq!(instant(&w.document_meta_view().unwrap().created), expected);
    }
}

fn new_writer(kind: &str, data: &[u8]) -> PdfWriter {
    match kind {
        "fresh" => PdfFileWriter::new(true, true).unwrap().into_inner(),
        "from_data" => copy_into_new_writer(&read(data)).unwrap().into_inner(),
        _ => IncrementalWriter::new(read(data)).into_inner(),
    }
}

fn write_kind(w: &mut PdfWriter, kind: &str) -> Vec<u8> {
    if kind == "in_place" {
        w.write_in_place().unwrap()
    } else {
        w.write().unwrap()
    }
}

#[test]
fn test_metadata_info_round_trip() {
    let created = date(2022, 9, 7, 0, 0, 0, Some(0));
    type Setter = fn(&mut DocumentMetadata, PdfDate);
    let cases: Vec<Setter> = vec![
        |m, _| m.title = Some(MetaString::plain("Test test")),
        |m, _| m.author = Some(MetaString::plain("John Doe")),
        |m, _| m.keywords = vec!["foo".into(), "bar".into(), "baz".into()],
        |m, c| m.created = Some(MetaDate::At(c)),
        |m, _| {
            m.author = Some(MetaString::plain("John Doe"));
            m.subject = Some(MetaString::plain("Blah blah blah"));
        },
    ];
    for kind in ["fresh", "from_data", "incremental", "in_place"] {
        for set in &cases {
            for ver in [(1, 7), (2, 0)] {
                let mut w = new_writer(kind, &minimal());
                w.output_version = ver;
                w.fixed_time = Some(frozen());
                w.update_root().unwrap();
                set(w.document_meta(), created);
                let out = write_kind(&mut w, kind);
                let r = read(&out);
                let mut expected = DocumentMetadata::default();
                set(&mut expected, created);
                expected.last_modified = Some(MetaDate::At(frozen()));
                if ver == (2, 0) {
                    assert!(!r.trailer_view().has(b"Info"), "{kind} {ver:?}");
                } else {
                    let got = meta_view(&r);
                    assert_eq!(
                        instant(&got.last_modified),
                        instant(&expected.last_modified)
                    );
                    assert_eq!(instant(&got.created), instant(&expected.created));
                    assert_eq!(got.title, expected.title);
                    assert_eq!(got.author, expected.author);
                    assert_eq!(got.subject, expected.subject);
                    assert_eq!(got.keywords, expected.keywords);
                    assert_eq!(got.creator, expected.creator);
                }
            }
        }
    }
}

#[test]
fn test_metadata_info_with_language_round_trip() {
    let title = MetaString::with_lang("Test test", "en", Some("US"));
    for kind in ["fresh", "from_data", "incremental", "in_place"] {
        for ver in [(1, 7), (2, 0)] {
            let mut w = new_writer(kind, &minimal());
            w.output_version = ver;
            w.update_root().unwrap();
            w.document_meta().title = Some(title.clone());
            let out = write_kind(&mut w, kind);
            let r = read(&out);
            let got = meta_view(&r).title.unwrap();
            if r.root().unwrap().has(b"Metadata") {
                assert_eq!(got, title, "{kind} {ver:?}");
            } else {
                assert_eq!(got.value, title.value, "{kind} {ver:?}");
            }
        }
    }
}

const XMP_WITH_PARSETYPE_RESOURCE: &str = r#"
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xmpTPg="http://ns.adobe.com/xap/1.0/t/pg/"
         xmlns:stDim="http://ns.adobe.com/xap/1.0/sType/Dimensions#"
         xmlns:xmp="http://ns.adobe.com/xap/1.0/"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xmpTPg:MaxPageSize rdf:parseType="Resource">
            <stDim:h>11.0</stDim:h>
            <stDim:w>8.5</stDim:w>
            <stDim:unit>inch</stDim:unit>
        </xmpTPg:MaxPageSize>
        <xmp:BaseURL rdf:parseType="Resource">
            <rdf:value rdf:resource="https://www.adobe.com/"/>
            <xe:qualifier>artificial example</xe:qualifier>
        </xmp:BaseURL>
   </rdf:Description>
</rdf:RDF>
"#;

const XE: &str = "http://ns.adobe.com/xmp-example/";

#[test]
fn test_xmp_parsetype_resource() {
    let result = &parse_xmp(XMP_WITH_PARSETYPE_RESOURCE.as_bytes()).unwrap()[0];
    let mps = result
        .get(&en("MaxPageSize", "http://ns.adobe.com/xap/1.0/t/pg/"))
        .unwrap();
    let XmpValueKind::Structure(s) = &mps.value else {
        panic!()
    };
    let unit = s
        .get(&en("unit", "http://ns.adobe.com/xap/1.0/sType/Dimensions#"))
        .unwrap();
    assert_eq!(unit.as_str(), Some("inch"));
    let base = result.get(&en("BaseURL", model::ns("xmp"))).unwrap();
    assert_eq!(
        base.qualifiers.get(&en("qualifier", XE)).unwrap().as_str(),
        Some("artificial example")
    );
    assert_eq!(
        base.value,
        XmpValueKind::Uri(XmpUri("https://www.adobe.com/".into()))
    );
}

#[test]
fn test_ensure_uri_is_rdf_resource() {
    let root = XmpStructure::of(vec![(
        en("BaseURL", model::ns("xmp")),
        XmpValue::new(XmpValueKind::Uri(XmpUri("https://example.com".into()))),
    )]);
    let out = serialise_xmp(&[root]);
    assert!(String::from_utf8(out)
        .unwrap()
        .contains("rdf:resource=\"https://example.com\""));
}

fn conformance() -> ExpandedName {
    en("conformance", "http://www.aiim.org/pdfa/ns/id/")
}

fn description_text(x: &XmpStructure) -> String {
    let XmpValueKind::Array(a) = &x.get(&dc_description()).unwrap().value else {
        panic!()
    };
    a.entries[0].as_str().unwrap().to_owned()
}

#[test]
fn test_incremental_update_doc_with_xmp() {
    let mut w = IncrementalWriter::new(read(&pdf("minimal-pdf-ua-and-a.pdf")));
    w.fixed_time = Some(date(2022, 9, 10, 0, 0, 0, Some(0)));
    let mut root = w.root().unwrap();
    root.set("Foo", pdf_name("Bar"));
    w.set_root(root);
    w.document_meta().subject = Some(MetaString::plain("Update test"));
    let out = w.write().unwrap();
    let r = read(&out);
    let x = &root_xmp(&r)[0];
    assert_eq!(description_text(x), "Update test");
    assert_eq!(x.get(&conformance()).unwrap().as_str(), Some("B"));
    assert_eq!(
        r.historical_resolver(0)
            .document_meta_view()
            .unwrap()
            .subject,
        None
    );
}

#[test]
fn test_rewrite_update_doc_with_xmp() {
    let mut w = copy_into_new_writer(&read(&pdf("minimal-pdf-ua-and-a.pdf"))).unwrap();
    w.fixed_time = Some(date(2022, 9, 10, 0, 0, 0, Some(0)));
    w.document_meta().subject = Some(MetaString::plain("Update test"));
    let out = w.write().unwrap();
    let r = read(&out);
    let x = &root_xmp(&r)[0];
    assert_eq!(description_text(x), "Update test");
    assert_eq!(x.get(&conformance()).unwrap().as_str(), Some("B"));
}

#[test]
fn test_meta_view_from_xmp() {
    // pyHanko wipes the Info dict; the XMP view takes precedence anyway
    let r = read(&pdf("minimal-pdf-ua-and-a.pdf"));
    assert_eq!(
        meta_view(&r).title,
        Some(MetaString::with_lang("Test document", "DEFAULT", None))
    );
}

#[test]
fn test_upgrade_pdf2_no_info_dict() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    w.output_version = (2, 0);
    let mut root = w.root().unwrap();
    root.set("Foo", pdf_name("Bar"));
    w.set_root(root);
    let m = w.document_meta();
    m.title = Some(MetaString::plain("Test document"));
    m.author = Some(MetaString::plain("John Doe"));
    m.subject = Some(MetaString::plain("Test subject"));
    m.keywords = ["these", "are", "key", "words"].map(String::from).to_vec();
    let out = w.write_in_place().unwrap();
    let r = read(&out);
    assert!(!r.trailer_view().has(b"Info"));
    let mv = meta_view(&r);
    assert_eq!(mv.title.unwrap().value, "Test document");
    assert_eq!(mv.author, Some(MetaString::plain("John Doe")));
    assert_eq!(mv.subject.unwrap().value, "Test subject");
    assert_eq!(
        mv.keywords,
        ["these", "are", "key", "words"].map(String::from).to_vec()
    );
    assert_eq!(
        r.historical_resolver(0)
            .document_meta_view()
            .unwrap()
            .subject,
        None
    );
}

fn extra_struct() -> XmpStructure {
    XmpStructure::of(vec![(
        en("BaseURL", model::ns("xmp")),
        XmpValue::with_quals(
            XmpValueKind::Uri(XmpUri("https://example.com/".into())),
            Qualifiers::of(vec![(
                en("qualifier", XE),
                XmpValue::text("artificial example"),
            )]),
        ),
    )])
}

fn check_extra(x: &XmpStructure) {
    let v = x.get(&en("BaseURL", model::ns("xmp"))).unwrap();
    assert_eq!(
        v.qualifiers.get(&en("qualifier", XE)).unwrap().as_str(),
        Some("artificial example")
    );
    assert_eq!(
        v.value,
        XmpValueKind::Uri(XmpUri("https://example.com/".into()))
    );
}

#[test]
fn test_add_extra_xmp() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    let mut root = w.root().unwrap();
    root.set("Foo", pdf_name("Bar"));
    w.set_root(root);
    w.document_meta().title = Some(MetaString::plain("Test document"));
    w.document_meta().xmp_extra = vec![extra_struct()];
    let out = w.write_in_place().unwrap();
    let r = read(&out);
    assert!(!r.trailer_view().has(b"Info"));
    assert_eq!(meta_view(&r).title.unwrap().value, "Test document");
    check_extra(&root_xmp(&r)[1]);
}

#[test]
fn test_unmanaged_xmp() {
    let mut w = copy_into_new_writer(&read(&minimal())).unwrap();
    w.document_meta().title = Some(MetaString::plain("This should not be written"));
    w.document_meta().xmp_unmanaged = true;
    w.document_meta().xmp_extra = vec![extra_struct()];
    let out = w.write().unwrap();
    let r = read(&out);
    assert!(!r.trailer_view().has(b"Info"));
    assert_eq!(meta_view(&r).title, None);
    check_extra(&root_xmp(&r)[1]);
}

#[test]
fn test_unmanaged_xmp_does_not_affect_info() {
    let mut w = copy_into_new_writer(&read(&pdf("scribble.pdf"))).unwrap();
    w.document_meta().title = Some(MetaString::plain("This should not be written"));
    w.document_meta().xmp_unmanaged = true;
    w.document_meta().xmp_extra = vec![extra_struct()];
    let out = w.write().unwrap();
    let r = read(&out);
    assert_eq!(meta_view(&r).title, None);
    assert!(text(&get(&r, &info_of(&r), "Producer")).contains(VENDOR));
}

const XMP_WITH_RESOURCE_WITH_MULTIPLE_QUALS: &str = r#"
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:dc="http://purl.org/dc/elements/1.1/"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <dc:title rdf:parseType="Resource" xml:lang="en">
            <!-- NOTE: this is actually not valid in the DC schema -->
            <rdf:value>This is a test</rdf:value>
            <xe:qualifier>artificial example</xe:qualifier>
        </dc:title>
   </rdf:Description>
</rdf:RDF>
"#;

#[test]
fn test_xmp_with_resource_with_multiple_quals() {
    let result = parse_xmp(XMP_WITH_RESOURCE_WITH_MULTIPLE_QUALS.as_bytes())
        .unwrap()
        .remove(0);
    assert_eq!(
        result
            .get(&dc_title())
            .unwrap()
            .qualifiers
            .iter_quals(true)
            .len(),
        2
    );
    let expected = XmpStructure::of(vec![
        (
            dc_title(),
            XmpValue::with_quals(
                XmpValueKind::Str("This is a test".into()),
                Qualifiers::of(vec![
                    (xml_lang(), XmpValue::text("en")),
                    (
                        en("qualifier", XE),
                        XmpValue::with_quals(
                            XmpValueKind::Str("artificial example".into()),
                            Qualifiers::lang_as_qual(Some("en")),
                        ),
                    ),
                ]),
            ),
        ),
        (model::rdf_about(), XmpValue::text("")),
    ]);
    assert_eq!(result, expected);
    let title = result.get(&dc_title()).unwrap();
    assert_eq!(
        title.qualifiers.get(&en("qualifier", XE)).unwrap().as_str(),
        Some("artificial example")
    );
    assert_eq!(
        meta_from_xmp(&[result]).unwrap().title,
        Some(MetaString::with_lang("This is a test", "en", None))
    );
}

#[test]
fn test_xmp_str() {
    let result = parse_xmp(XMP_WITH_RESOURCE_WITH_MULTIPLE_QUALS.as_bytes())
        .unwrap()
        .remove(0);
    let r = format!("{result:?}");
    assert!(r.contains("artificial"));
    assert!(r.contains("lang: Some(\"en\")"));
}

const XMP_WITH_BAG: &str = r#"
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xe:keywords rdf:parseType="Resource">
            <rdf:value>
                <rdf:Bag>
                    <rdf:li>apple</rdf:li>
                    <rdf:li>pear</rdf:li>
                    <rdf:li>banana</rdf:li>
                </rdf:Bag>
            </rdf:value>
            <xml:lang>en</xml:lang>
            <xe:qualifier>artificial example</xe:qualifier>
        </xe:keywords>
   </rdf:Description>
</rdf:RDF>
"#;

fn texts(v: &[&str]) -> Vec<XmpValue> {
    v.iter().map(|s| XmpValue::text(s)).collect()
}

#[test]
fn test_xmp_with_bag() {
    let result = parse_xmp(XMP_WITH_BAG.as_bytes()).unwrap().remove(0);
    let kw = result.get(&en("keywords", XE)).unwrap();
    assert_eq!(
        kw.qualifiers.get(&en("qualifier", XE)).unwrap().as_str(),
        Some("artificial example")
    );
    assert_eq!(
        kw.value,
        XmpValueKind::Array(XmpArray::unordered(texts(&["apple", "banana", "pear"])))
    );
}

#[test]
fn test_xmp_ord_arr_comparison() {
    let o1 = XmpArray::ordered(texts(&["apple", "pear", "banana"]));
    let o2 = XmpArray::ordered(texts(&["apple", "banana", "pear"]));
    let a = XmpArray::alternative(texts(&["apple", "pear", "banana"]));
    assert_ne!(o1, o2);
    assert_ne!(o1, a);
}

#[test]
fn test_xmp_unord_arr_comparison() {
    let u1 = XmpArray::unordered(texts(&["apple", "pear", "banana"]));
    let u2 = XmpArray::unordered(texts(&["apple", "banana", "pear"]));
    assert_eq!(u1, u2);
}

#[test]
fn test_xmp_parsetype_lit_not_supported() {
    let x = r#"
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xe:title rdf:parseType="Literal">bleh</xe:title>
   </rdf:Description>
</rdf:RDF>
"#;
    is_xmp_err(parse_xmp(x.as_bytes()), "Literal");
}

#[test]
fn test_xmp_with_invalid_form() {
    let x = r#"
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xe:title><xe:zzz/></xe:title>
   </rdf:Description>
</rdf:RDF>
"#;
    is_xmp_err(parse_xmp(x.as_bytes()), "value form");
}

#[test]
fn test_xmp_value_form_multiple_children() {
    let x = r#"
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xe:title><xe:foo/><xe:bar/></xe:title>
   </rdf:Description>
</rdf:RDF>
"#;
    is_xmp_err(parse_xmp(x.as_bytes()), "more than one child");
}

#[test]
fn test_xmp_no_rdf_in_xmpmeta() {
    let x = "\n<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n</x:xmpmeta>\n";
    is_xmp_err(parse_xmp(x.as_bytes()), "RDF node in x:xmpmeta");
}

#[test]
fn test_xmp_invalid_root() {
    is_xmp_err(parse_xmp(b"\n<xml:boo/>\n"), "XMP root must be");
}

#[test]
fn test_xmp_with_duplicate_struct_field() {
    let x = r#"
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xe:title>bleh</xe:title>
        <xe:title>bleh</xe:title>
   </rdf:Description>
</rdf:RDF>
"#;
    is_xmp_err(parse_xmp(x.as_bytes()), "Duplicate field");
}

#[test]
fn test_xmp_invalid_date1() {
    let x = r#"
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:CreateDate>1/1/2022</xmp:CreateDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
"#;
    is_xmp_err(
        meta_from_xmp(&parse_xmp(x.as_bytes()).unwrap()),
        "Failed to parse.*as a date",
    );
}

#[test]
fn test_xmp_invalid_date2() {
    let x = r#"
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:CreateDate rdf:parseType="Resource"></xmp:CreateDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
"#;
    is_xmp_err(
        meta_from_xmp(&parse_xmp(x.as_bytes()).unwrap()),
        "Wrong type",
    );
}

const PDFA_HEAD: &str = r#"
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 5.1.0-jc003">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:xmp="http://ns.adobe.com/xap/1.0/"
        xmlns:pdf="http://ns.adobe.com/pdf/1.3/"
        xmlns:pdfuaid="http://www.aiim.org/pdfua/ns/id/"
        xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/"
        xmlns:pdfaExtension="http://www.aiim.org/pdfa/ns/extension/"
        xmlns:pdfaSchema="http://www.aiim.org/pdfa/ns/schema#"
        xmlns:pdfaProperty="http://www.aiim.org/pdfa/ns/property#"
      dc:format="application/pdf"
      xmp:CreateDate="2022-07-07T01:26:05+02:00"
      xmp:ModifyDate="2022-07-07T01:26:05+02:00"
      pdfaid:part="2"
      pdfaid:conformance="A">
      <dc:creator>
        <rdf:Seq>
          <rdf:li>Matthias Valvekens</rdf:li>
        </rdf:Seq>
      </dc:creator>
      <dc:title>
        <rdf:Alt>
          <rdf:li xml:lang="x-default">Curriculum Vitae</rdf:li>
        </rdf:Alt>
      </dc:title>
      <pdfuaid:part>1</pdfuaid:part>
      <pdfaExtension:schemas>
        <rdf:Bag>
          <rdf:li>
            <rdf:Description
"#;

const PDFA_TAIL: &str = r#"
            <pdfaSchema:property>
              <rdf:Seq>
                <rdf:li
                  pdfaProperty:category="internal"
                  pdfaProperty:description="PDF/UA version identifier"
                  pdfaProperty:name="part"
                  pdfaProperty:valueType="Integer"/>
                <rdf:li
                  pdfaProperty:category="internal"
                  pdfaProperty:description="PDF/UA amendment identifier"
                  pdfaProperty:name="amd"
                  pdfaProperty:valueType="Text"/>
                <rdf:li
                  pdfaProperty:category="internal"
                  pdfaProperty:description="PDF/UA corrigenda identifier"
                  pdfaProperty:name="corr"
                  pdfaProperty:valueType="Text"/>
              </rdf:Seq>
            </pdfaSchema:property>
            </rdf:Description>
          </rdf:li>
        </rdf:Bag>
      </pdfaExtension:schemas>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
"#;

fn pdfa_wrong_uri_type() -> String {
    format!(
        "{PDFA_HEAD}              pdfaSchema:namespaceURI=\"http://www.aiim.org/pdfua/ns/id/\"\n              pdfaSchema:prefix=\"pdfuaid\"\n              pdfaSchema:schema=\"PDF/UA identification schema\">{PDFA_TAIL}"
    )
}

fn pdfa_correct_uri_type() -> String {
    format!(
        "{PDFA_HEAD}              pdfaSchema:prefix=\"pdfuaid\"\n              pdfaSchema:schema=\"PDF/UA identification schema\">\n            <pdfaSchema:namespaceURI\n              rdf:resource=\"http://www.aiim.org/pdfua/ns/id/\"/>{PDFA_TAIL}"
    )
}

const PDFA_ITEXT_PRE804: &str = r#"
<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
      xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/"
      xmlns:pdfaExtension="http://www.aiim.org/pdfa/ns/extension/"
      xmlns:pdfaSchema="http://www.aiim.org/pdfa/ns/schema#"
      xmlns:pdfaProperty="http://www.aiim.org/pdfa/ns/property#">
   <pdfaid:part>3</pdfaid:part>
   <pdfaid:conformance>A</pdfaid:conformance>
   <pdfaExtension:schemas>
    <rdf:Bag>
     <rdf:li rdf:parseType="Resource">
      <pdfaSchema:schema>PDF/UA identification schema</pdfaSchema:schema>
      <pdfaSchema:namespaceURI>http://www.aiim.org/pdfua/ns/id/</pdfaSchema:namespaceURI>
      <pdfaSchema:prefix>pdfuaid</pdfaSchema:prefix>
      <pdfaSchema:property>
       <rdf:Seq>
        <rdf:li rdf:parseType="Resource">
         <pdfaProperty:name>part</pdfaProperty:name>
         <pdfaProperty:valueType>Integer</pdfaProperty:valueType>
         <pdfaProperty:category>internal</pdfaProperty:category>
         <pdfaProperty:description>PDF/UA version identifier</pdfaProperty:description>
        </rdf:li>
       </rdf:Seq>
      </pdfaSchema:property>
     </rdf:li>
    </rdf:Bag>
   </pdfaExtension:schemas>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>
"#;

fn field<'a>(v: &'a XmpValue, name: &ExpandedName) -> &'a XmpValue {
    let XmpValueKind::Structure(s) = &v.value else {
        panic!("not a struct: {v:?}")
    };
    s.get(name).unwrap()
}

#[test]
fn test_parse_pdfa_ext_schema() {
    for sample in [
        pdfa_correct_uri_type(),
        pdfa_wrong_uri_type(),
        PDFA_ITEXT_PRE804.to_owned(),
    ] {
        let roots = parse_xmp(sample.as_bytes()).unwrap();
        let root = &roots[0];
        let ext = root
            .get(&en("schemas", model::ns("pdfaExtension")))
            .unwrap();
        let XmpValueKind::Array(arr) = &ext.value else {
            panic!()
        };
        let schema = &arr.entries[0];
        assert_eq!(
            field(schema, &en("prefix", model::ns("pdfaSchema"))).as_str(),
            Some("pdfuaid")
        );
        let prop = field(schema, &en("property", model::ns("pdfaSchema")));
        let XmpValueKind::Array(seq) = &prop.value else {
            panic!()
        };
        let desc = field(
            &seq.entries[0],
            &en("description", model::ns("pdfaProperty")),
        );
        assert_eq!(desc.as_str(), Some("PDF/UA version identifier"));
        let XmpValueKind::Structure(first) = &seq.entries[0].value else {
            panic!()
        };
        assert_eq!(first.len(), 4);
        let ns_uri = field(schema, &en("namespaceURI", model::ns("pdfaSchema")));
        assert_eq!(
            ns_uri.value,
            XmpValueKind::Uri(XmpUri(model::ns("pdfuaid").into()))
        );
    }
}

#[test]
fn test_reser_pdfa_ext_schema() {
    for sample in [pdfa_correct_uri_type(), pdfa_wrong_uri_type()] {
        let roots = parse_xmp(sample.as_bytes()).unwrap();
        let out = serialise_xmp(&roots);
        let redux = parse_xmp(&out).unwrap();
        assert_eq!(redux[0], roots[0]);
    }
}

#[test]
fn test_empty_string() {
    let x = r#"
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 5.1.0-jc003">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        dc:format="application/pdf">
      <dc:creator>
        <rdf:Seq>
          <rdf:li/>
        </rdf:Seq>
      </dc:creator>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
"#;
    let roots = parse_xmp(x.as_bytes()).unwrap();
    let XmpValueKind::Array(a) = &roots[0].get(&dc_creator()).unwrap().value else {
        panic!()
    };
    assert_eq!(a.entries[0].as_str(), Some(""));
}

#[test]
fn test_xmp_lang_explicit_xdefault() {
    let mut w = copy_into_new_writer(&read(&minimal())).unwrap();
    w.output_version = (2, 0);
    w.document_meta().subject = Some(MetaString::with_lang("Blah", "DEFAULT", None));
    let out = w.write().unwrap();
    let r = read(&out);
    let root = r.root().unwrap();
    let Object::Stream(s) = get(&r, &root, "Metadata") else {
        panic!()
    };
    let data = r.stream_data(&s).unwrap();
    let needle = b"<rdf:li xml:lang=\"x-default\">Blah</rdf:li>";
    assert!(
        data.windows(needle.len()).any(|w| w == needle),
        "{}",
        String::from_utf8_lossy(&data)
    );
}

fn producer_starts_with_vendor(out: &[u8]) {
    let r = read(out);
    assert!(text(&get(&r, &info_of(&r), "Producer")).starts_with(VENDOR));
}

#[test]
fn test_incremental_update_handle_binary_producer_string() {
    let mut w = IncrementalWriter::new(read(&pdf("info-bin-producer-string.pdf")));
    let mut root = w.root().unwrap();
    root.set("Blah", pdf_name("Blah"));
    w.set_root(root);
    producer_starts_with_vendor(&w.write().unwrap());
}

#[test]
fn test_rewrite_handle_binary_producer_string() {
    let mut w = copy_into_new_writer(&read(&pdf("info-bin-producer-string.pdf"))).unwrap();
    let mut root = w.root().unwrap();
    root.set("Blah", pdf_name("Blah"));
    w.set_root(root);
    producer_starts_with_vendor(&w.write().unwrap());
}

#[test]
fn test_bogus_metadata_key_value() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    let mut root = w.root().unwrap();
    root.set("Metadata", pdf_name("Blah"));
    w.set_root(root);
    w.update_meta_on_write = false;
    let out = w.write_in_place().unwrap();
    assert_eq!(read(&out).xmp_meta_view().unwrap(), None);
}

#[test]
fn test_xmp_with_dangerous_xml() {
    for f in [
        "cyclic.xml",
        "dtd.xml",
        "external_file.xml",
        "external.xml",
        "quadratic.xml",
        "simple-ns.xml",
        "simple.xml",
        "xmlbomb.xml",
        "xmlbomb2.xml",
        "xmp-with-harmless-entity.xml",
    ] {
        let data = sigis_testdata::read(&["pyhanko", "xml", "bad-xml", f]);
        let e = parse_xmp(&data).unwrap_err();
        assert!(
            e.message().starts_with("XmpXmlProcessingError"),
            "{f}: {e:?}"
        );
    }
}

fn raw_metadata(r: &PdfFile) -> sigis_pdf::lopdf::Stream {
    let root_ref = r.root_ref().unwrap();
    let root = as_dict(r.get_object_raw(root_ref, None).unwrap());
    let Ok(Object::Reference(mref)) = root.get(b"Metadata") else {
        panic!()
    };
    match r.get_object_raw(*mref, None).unwrap() {
        Object::Stream(s) => s,
        _ => panic!(),
    }
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

#[test]
fn test_encrypt_skipping_managed_metadata() {
    use sigis_pdf::crypt::StandardEncryptOptions;
    let mut w = copy_into_new_writer(&read(&minimal())).unwrap();
    w.encrypt_with(
        "secret",
        Some("secret"),
        StandardEncryptOptions {
            encrypt_metadata: false,
            ..StandardEncryptOptions::default()
        },
    )
    .unwrap();
    w.document_meta().title = Some(MetaString::plain("Metadata is unencrypted"));
    let out = w.write().unwrap();
    let r = read(&out);
    let raw = raw_metadata(&r);
    let parms = as_dict(raw.dict.get(b"DecodeParms").unwrap().clone());
    assert_eq!(
        parms.get(b"Name").unwrap(),
        &Object::Name(b"Identity".to_vec())
    );
    assert!(contains(&raw.content, b"Metadata is unencrypted"));
    let r = read(&out);
    r.decrypt("secret").unwrap();
    assert_eq!(
        meta_view(&r).title.unwrap().value,
        "Metadata is unencrypted"
    );
}

#[test]
fn test_encrypt_with_managed_metadata() {
    let mut w = copy_into_new_writer(&read(&minimal())).unwrap();
    w.encrypt("secret", Some("secret")).unwrap();
    w.document_meta().title = Some(MetaString::plain("Metadata is encrypted"));
    let out = w.write().unwrap();
    let r = read(&out);
    assert!(!contains(
        &raw_metadata(&r).content,
        b"Metadata is encrypted"
    ));
    let r = read(&out);
    r.decrypt("secret").unwrap();
    assert_eq!(meta_view(&r).title.unwrap().value, "Metadata is encrypted");
}
