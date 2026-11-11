// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_internal_utils.py`
// (MIT, see LICENSE-pyHanko). One Rust test per upstream test function;
// parametrized cases run in a loop. Skipped upstream tests are listed in
// PORTING.md with their reasons.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use common::*;
use hanko_pdf::extensions::{DevExtensionMultivalued, DeveloperExtension};
use hanko_pdf::filters::{ascii85_decode, ascii85_encode, ascii_hex_decode, ascii_hex_encode};
use hanko_pdf::generic::{
    self, format_real, parse_pdf_date, parse_pdf_date_obj, pdf_date, pdf_name, read_item,
    read_object, text_string, ContentOpReading, Item, ParseContext, PdfDate, PdfString,
    TextStringEncoding,
};
use hanko_pdf::lopdf::{Dictionary, Object, ObjectId, Stream, StringFormat};
use hanko_pdf::metadata::model::VENDOR;
use hanko_pdf::misc::{self, Cursor};
use hanko_pdf::reader::{read_next_end_line, PathElem, RawPdfPath};
use hanko_pdf::stream::{apply_filter_to_stream, DecodedStream, DuplicateFilter};
use hanko_pdf::writer::copy_into_new_writer;
use hanko_pdf::{
    IncrementalWriter, PdfError, PdfFile, PdfFileWriter, PdfHandler, PdfHandlerExt, PdfResult,
    PdfWriter,
};

fn ctx() -> ParseContext<'static> {
    ParseContext::default()
}

fn lenient_ctx() -> ParseContext<'static> {
    ParseContext {
        strict: false,
        length_resolver: None,
    }
}

fn parse(data: &[u8]) -> PdfResult<Object> {
    read_object(&mut Cursor::new(data), &ctx())
}

fn name(s: &str) -> Object {
    pdf_name(s)
}

fn courier() -> Dictionary {
    let mut d = Dictionary::new();
    d.set("Type", name("Font"));
    d.set("BaseFont", name("Courier"));
    d.set("Subtype", name("Type1"));
    d.set("Encoding", name("WinAnsiEncoding"));
    d
}

/// `simple_page` from pyhanko_testing_commons (Courier as a plain Type1
/// font resource instead of the lane D font engine).
fn simple_page(w: &mut PdfWriter, text: &str, compress: bool, extra_stream: bool) -> Dictionary {
    let mut font = Dictionary::new();
    font.set("F1", Object::Dictionary(courier()));
    let mut resources = Dictionary::new();
    resources.set("Font", Object::Dictionary(font));
    let stream_data =
        |y: i32| format!("BT /F1 18 Tf 0 {y} Td ({text}) Tj ET").into_bytes();
    let mk = |w: &mut PdfWriter, y: i32| {
        let mut s = DecodedStream::new(Dictionary::new(), stream_data(y));
        if compress {
            s.compress().unwrap();
        }
        w.add_object(Object::Stream(s.to_stream().unwrap())).unwrap()
    };
    let contents = if extra_stream {
        let a = mk(w, 0);
        let b = mk(w, 100);
        Object::Array(vec![Object::Reference(a), Object::Reference(b)])
    } else {
        Object::Reference(mk(w, 0))
    };
    let mut page = Dictionary::new();
    page.set("Type", name("Page"));
    page.set(
        "MediaBox",
        Object::Array(vec![0.into(), 0.into(), 300.into(), 144.into()]),
    );
    page.set("Resources", Object::Dictionary(resources));
    page.set("Contents", contents);
    page
}

fn contents_data(h: &dyn PdfHandler, page: &Dictionary) -> Vec<u8> {
    match get(h, page, "Contents") {
        Object::Stream(s) => h.stream_data(&s).unwrap(),
        other => panic!("{other:?}"),
    }
}

fn kids(h: &dyn PdfHandler) -> Vec<Object> {
    let root = h.root().unwrap();
    let pages = as_dict(get(h, &root, "Pages"));
    match get(h, &pages, "Kids") {
        Object::Array(a) => a,
        _ => panic!(),
    }
}

#[test]
fn test_create_fresh() {
    for (zip1, zip2) in [(true, true), (true, false), (false, false)] {
        let mut w = PdfFileWriter::new(true, true).unwrap();
        let p1 = simple_page(&mut w, "Hello world", zip1, false);
        let p2 = simple_page(&mut w, "Hello Page 2", zip2, false);
        let p1_ref = w.insert_page(p1, None).unwrap();
        let p2_ref = w.insert_page(p2, None).unwrap();
        let out = w.write().unwrap();
        let r = read(&out);
        let root = r.root().unwrap();
        let pages = as_dict(get(&r, &root, "Pages"));
        assert_eq!(get(&r, &pages, "Count"), Object::Integer(2));
        let k = kids(&r);
        let k0 = as_dict(r.resolve(&k[0]).unwrap());
        let k1 = as_dict(r.resolve(&k[1]).unwrap());
        assert!(contents_data(&r, &k0).windows(5).any(|w| w == b"world"));
        assert!(contents_data(&r, &k1).windows(6).any(|w| w == b"Page 2"));
        assert_eq!(r.find_page_for_modification(0).unwrap().0, p1_ref);
        assert_eq!(r.find_page_for_modification(1).unwrap().0, p2_ref);
        assert_eq!(r.find_page_for_modification(-1).unwrap().0, p2_ref);
        assert_eq!(r.find_page_for_modification(-2).unwrap().0, p1_ref);
        assert!(r.find_page_for_modification(2).unwrap_err().is_pdf_error());
        assert!(r.find_page_for_modification(-3).unwrap_err().is_pdf_error());
    }
}

fn nested_page_tree_pdf(page_count: usize, pages_per_node: usize) -> Vec<u8> {
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let page_refs: Vec<ObjectId> = (1..=page_count)
        .map(|ix| {
            let p = simple_page(&mut w, &format!("Page {ix}"), false, false);
            w.add_object(Object::Dictionary(p)).unwrap()
        })
        .collect();
    let root = w.root().unwrap();
    let Ok(Object::Reference(root_ref)) = root.get(b"Pages").cloned() else { panic!() };
    let mut intermediate = Vec::new();
    for chunk in page_refs.chunks(pages_per_node) {
        let mut node = Dictionary::new();
        node.set("Type", name("Pages"));
        node.set("Parent", Object::Reference(root_ref));
        node.set("Count", Object::Integer(chunk.len() as i64));
        node.set("Kids", Object::Array(chunk.iter().map(|r| Object::Reference(*r)).collect()));
        let node_ref = w.add_object(Object::Dictionary(node)).unwrap();
        for p in chunk {
            let mut pg = as_dict(w.get_object(*p).unwrap());
            pg.set("Parent", Object::Reference(node_ref));
            w.update_object(*p, Object::Dictionary(pg));
        }
        intermediate.push(Object::Reference(node_ref));
    }
    let mut tree = as_dict(w.get_object(root_ref).unwrap());
    tree.set("Kids", Object::Array(intermediate));
    tree.set("Count", Object::Integer(page_count as i64));
    w.update_object(root_ref, Object::Dictionary(tree));
    w.write().unwrap()
}

#[test]
fn test_insert_page_into_nested_page_tree() {
    let mut w = IncrementalWriter::new(read(&nested_page_tree_pdf(4, 2)));
    let p = simple_page(&mut w, "Appended", false, false);
    w.insert_page(p, None).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    let root = r.root().unwrap();
    let pages = as_dict(get(&r, &root, "Pages"));
    assert_eq!(get(&r, &pages, "Count"), Object::Integer(5));
    let (last, _) = r.find_page_for_modification(-1).unwrap();
    let last = as_dict(r.get_object(last).unwrap());
    assert!(contents_data(&r, &last).windows(8).any(|w| w == b"Appended"));
}

fn content_stream(y: i32) -> Object {
    let data = format!("BT /F1 18 Tf 0 {y} Td (Test Test) Tj ET").into_bytes();
    Object::Stream(DecodedStream::new(Dictionary::new(), data).to_stream().unwrap())
}

fn page_contents_refs(r: &PdfFile) -> (Dictionary, Vec<ObjectId>) {
    let k = kids(r);
    let Object::Reference(pref) = k[0] else { panic!("page must be indirect") };
    let page = as_dict(r.get_object(pref).unwrap());
    let conts = match get(r, &page, "Contents") {
        Object::Array(a) => a
            .iter()
            .map(|c| match c {
                Object::Reference(x) => *x,
                _ => panic!(),
            })
            .collect(),
        _ => panic!(),
    };
    (page, conts)
}

fn has_f1(r: &dyn PdfHandler, page: &Dictionary) -> bool {
    let res = as_dict(get(r, page, "Resources"));
    as_dict(get(r, &res, "Font")).has(b"F1")
}

#[test]
fn test_add_stream() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    let stream_ref = w.add_object(content_stream(50)).unwrap();
    w.add_stream_to_page(0, stream_ref, None, false).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    let (page, conts) = page_contents_refs(&r);
    assert_eq!(conts.len(), 2);
    assert!(conts.contains(&stream_ref));
    assert!(has_f1(&r, &page));

    let mut w = IncrementalWriter::new(r);
    let new_ref = w.add_object(content_stream(100)).unwrap();
    w.add_stream_to_page(0, new_ref, None, false).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    let (_, conts) = page_contents_refs(&r);
    assert_eq!(conts.len(), 3);
    assert!(conts.contains(&stream_ref) && conts.contains(&new_ref));
}

#[test]
fn test_add_stream_to_direct_arr() {
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let p = simple_page(&mut w, "Test Test", false, true);
    w.insert_page(p, None).unwrap();
    let out = w.write().unwrap();
    let mut w = IncrementalWriter::new(read(&out));
    let data = b"BT /F1 18 Tf 0 50 Td (Test2 Test2) Tj ET".to_vec();
    let s = Object::Stream(DecodedStream::new(Dictionary::new(), data).to_stream().unwrap());
    let stream_ref = w.add_object(s).unwrap();
    w.add_stream_to_page(0, stream_ref, None, false).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    let (page, conts) = page_contents_refs(&r);
    assert_eq!(conts.len(), 3);
    assert!(conts.contains(&stream_ref));
    assert!(has_f1(&r, &page));
}

#[test]
fn test_read_rewrite() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    assert_eq!(w.write().unwrap(), minimal());
}

#[test]
fn test_whitespace_variants() {
    let m = String::from_utf8_lossy(&minimal()).into_owned();
    assert!(m.contains(" /Pages 2 0 R"));
    let m = minimal();
    let snippet = b" /Pages 2 0 R";
    let pos = m.windows(snippet.len()).position(|w| w == snippet).unwrap();
    for ws in [b' ', b'\n', b'\r', b'\t', 0x0c] {
        let new: Vec<u8> = snippet.iter().map(|&c| if c == b' ' { ws } else { c }).collect();
        let mut data = m[..pos].to_vec();
        data.extend_from_slice(&new);
        data.extend_from_slice(&m[pos + snippet.len()..]);
        let r = read(&data);
        let root = r.root().unwrap();
        let pages = as_dict(get(&r, &root, "Pages"));
        assert_eq!(get(&r, &pages, "Count"), Object::Integer(1));
    }
}

#[test]
fn test_skip_ws_behaviour() {
    for data in [&b"   \n a"[..], b"   \r\n a", b"   \r a"] {
        let mut c = Cursor::new(data);
        assert!(misc::skip_over_whitespace(&mut c, true, true).unwrap());
        assert_eq!(c.read(1), b" ");
    }
}

#[test]
fn test_skip_ws_eof_err_behaviour() {
    for (data, stop) in [
        (&b"   \n"[..], false),
        (b"   \r", false),
        (b"   \r\n", false),
        (b"", false),
        (b"", true),
    ] {
        let mut c = Cursor::new(data);
        let e = assert_err_matches(misc::skip_over_whitespace(&mut c, stop, true), "ended prematurely");
        assert!(e.is_stream_error());
    }
}

#[test]
fn test_skip_ws_eof_ok_behaviour() {
    for data in [&b"   \n"[..], b"   \r", b"   \r\n"] {
        let mut c = Cursor::new(data);
        assert!(misc::skip_over_whitespace(&mut c, true, true).unwrap());
        assert!(c.read(1).is_empty());
    }
}

#[test]
fn test_read_non_whitespace_eof() {
    for data in [&b""[..], b"   ", b"  % comment\n"] {
        let mut c = Cursor::new(data);
        let e = assert_err_matches(misc::read_non_ws(&mut c), "ended prematurely");
        assert!(e.is_stream_error());
    }
}

#[test]
fn test_skip_comment_behaviour() {
    for (data, next) in [
        (&b"%abc\n a"[..], &b"a"[..]),
        (b"%a\x00bc\x00\r\n a", b"a"),
        (b"%abc\r a", b"a"),
        (b"%abc\n", b""),
        (b"%abc\x00\r\n", b""),
        (b"%abc\r", b""),
        (b"%abc", b""),
        (b"%abc%abc\nz", b"z"),
        (b"%abc\n%abc\nz", b"z"),
        (b"%abc\r\n%abc\nz", b"z"),
        (b"%abc\n%abc\r\nz", b"z"),
        (b"%abc\r%abc\rz", b"z"),
    ] {
        let mut c = Cursor::new(data);
        assert!(misc::skip_over_comments(&mut c, false).unwrap());
        assert_eq!(c.read_rest(), next);
    }
}

#[test]
fn test_skip_comment_end_of_stream_err() {
    for data in [
        &b"%abc\n"[..],
        b"%abc\x00\r\n",
        b"%abc\r",
        b"%abc",
        b"%abc\n  ",
        b"%abc\r\n  ",
    ] {
        let mut c = Cursor::new(data);
        let e = assert_err_matches(misc::skip_over_comments(&mut c, true), "ended prematurely");
        assert!(e.is_stream_error());
    }
}

#[test]
fn test_name_delim() {
    for data in [
        &b"/Test\x00B"[..],
        b"/Test  B",
        b"/Test\x00  B",
        b"/Test\x00 [",
        b"/Test/B",
        b"/Tes#74/B",
        b"/Tes#74\x00/B",
        b"/Tes#74 /B",
        b"/Tes#74 \x00 /B",
    ] {
        assert_eq!(generic::read_name(&mut Cursor::new(data)).unwrap(), b"Test");
    }
}

#[test]
fn test_name_with_non_pdf_ascii_whitespace() {
    let e = assert_err_matches(generic::read_name(&mut Cursor::new(b"/Test\x0bTest")), "must be escaped");
    assert!(e.is_read_error());
}

#[test]
fn test_read_until_whitespace() {
    for (data, ret, rem) in [
        (&b"abc z"[..], &b"abc"[..], &b"z"[..]),
        (b"abc\x00z", b"abc", b"z"),
        (b"abc\x0cz", b"abc", b"z"),
        (b"abc\rz", b"abc", b"z"),
        (b"abc\x0bde\nz", b"abc\x0bde", b"z"),
        (b"abc ", b"abc", b""),
        (b"abc\x00", b"abc", b""),
        (b"abc\x0c", b"abc", b""),
        (b"abc\r", b"abc", b""),
        (b"abc\x0bde\n", b"abc\x0bde", b""),
        (b"abc", b"abc", b""),
        (b"abc\r\nz", b"abc", b"\nz"),
    ] {
        let mut c = Cursor::new(data);
        assert_eq!(misc::read_until_whitespace(&mut c, None), ret);
        assert_eq!(c.read_rest(), rem);
    }
}

#[test]
fn test_read_until_whitespace_bounded() {
    for (data, ret, rem, max) in [
        (&b"abc z"[..], &b"abc"[..], &b" z"[..], 3),
        (b"abc  z", b"abc", b"  z", 3),
        (b"abc z", b"abc", b"z", 4),
        (b"abc  z", b"abc", b" z", 4),
        (b"abc z", b"ab", b"c z", 2),
    ] {
        let mut c = Cursor::new(data);
        assert_eq!(misc::read_until_whitespace(&mut c, Some(max)), ret);
        assert_eq!(c.read_rest(), rem);
    }
}

const TEST_STRING: &[u8] = b"\x74\x77\x74\x84\x66";

fn sample_data() -> Vec<u8> {
    let mut d = TEST_STRING.repeat(20);
    d.extend_from_slice(b"\0\0\0\0");
    d.extend(TEST_STRING.repeat(20));
    d.extend_from_slice(b"\x03\x02\x08");
    d
}

#[test]
fn test_ascii_hex_decode() {
    let data = sample_data();
    assert_eq!(ascii_hex_decode(&ascii_hex_encode(&data)).unwrap(), data);
}

#[test]
fn test_ascii_hex_decode_odd_digits() {
    assert_eq!(ascii_hex_decode(b"6C6C6>").unwrap(), b"ll\x60");
    assert_eq!(ascii_hex_decode(b"6C 6C\n6>").unwrap(), b"ll\x60");
    assert_eq!(ascii_hex_decode(b"A>").unwrap(), b"\xa0");
}

#[test]
fn test_ascii85_decode() {
    let data = sample_data();
    let encoded = ascii85_encode(&data);
    assert_eq!(encoded.len(), 257);
    assert_eq!(ascii85_decode(&encoded).unwrap(), data);
}

#[test]
fn test_historical_read() {
    let r = read(&pdf("minimal-with-field.pdf"));
    assert_eq!(r.total_revisions(), 2);
    let current_root = r.get_object_at((1, 0), Some(1)).unwrap();
    assert_eq!(current_root, Object::Dictionary(r.root().unwrap()));
    r.get_object_at((6, 0), Some(1)).unwrap();
    let previous_root = as_dict(r.get_object_at((1, 0), Some(0)).unwrap());
    assert!(!previous_root.has(b"AcroForm"));
    assert!(r.get_object_at((6, 0), Some(0)).unwrap_err().is_read_error());
    assert!(r.xrefs().explicit_refs_in_revision(1).contains(&(6, 0)));
    assert!(r.xrefs().explicit_refs_in_revision(0).contains(&(2, 0)));
    assert!(!r.xrefs().explicit_refs_in_revision(1).contains(&(2, 0)));
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn test_page_import() {
    let files = ["scribble.pdf", "scribble-decomp.pdf", "scribble-in-arr.pdf"];
    for f in files {
        for inherit in [true, false] {
            let input = read(&pdf(f));
            let mut w = PdfFileWriter::new(true, true).unwrap();
            let xref = w.import_page_as_xobject(&input, 0, inherit).unwrap();
            let Object::Stream(x) = w.get_object(xref).unwrap() else { panic!() };
            assert!(as_dict(get(&*w, &x.dict, "Resources")).has(b"ExtGState"));
            assert!(contains(&w.stream_data(&x).unwrap(), b"0 1 0 rg /a0 gs"), "{f} {inherit}");
        }
    }
}

#[test]
fn test_page_import_no_media_box() {
    let input = read(&pdf("no-mediabox.pdf"));
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let e = assert_err_matches(
        w.import_page_as_xobject(&input, 0, true),
        "Page 0 does not have a /MediaBox",
    );
    assert!(e.is_read_error());
}

#[test]
fn test_page_import_with_fonts() {
    for inherit in [true, false] {
        let input = read(&pdf("fontembed.pdf"));
        let mut w = PdfFileWriter::new(true, true).unwrap();
        let xref = w.import_page_as_xobject(&input, 0, inherit).unwrap();
        let Object::Stream(x) = w.get_object(xref).unwrap() else { panic!() };
        let res = as_dict(get(&*w, &x.dict, "Resources"));
        let fonts = as_dict(get(&*w, &res, "Font"));
        assert!(fonts.has(b"FEmb"));
        let femb = as_dict(get(&*w, &fonts, "FEmb"));
        let Object::Array(df) = get(&*w, &femb, "DescendantFonts") else { panic!() };
        let df = as_dict(w.resolve(&df[0]).unwrap());
        let fd = as_dict(get(&*w, &df, "FontDescriptor"));
        let Object::Stream(ff) = get(&*w, &fd, "FontFile3") else { panic!() };
        assert_eq!(w.stream_data(&ff).unwrap().len(), 1424);
    }
}

#[test]
fn test_deep_modify() {
    // pyHanko tracks the container of a deep value; in Rust, updating a
    // deep value means storing its top-level container.
    let mut w = IncrementalWriter::new(read(&minimal()));
    let mut obj3 = as_dict(w.get_object((3, 0)).unwrap());
    let res = as_dict(get(&*w, &obj3, "Resources"));
    let font = as_dict(get(&*w, &res, "Font"));
    let f1 = as_dict(get(&*w, &font, "F1"));
    assert!(f1.has(b"Subtype"));
    obj3.set("Resources", Object::Dictionary(res));
    w.update_object((3, 0), Object::Dictionary(obj3));
    assert!(w.objects().contains_key(&(0, 3)));
}

fn utc(year: i32, month: u8, day: u8, hour: u8, minute: u8, second: u8, off: Option<i32>) -> PdfDate {
    PdfDate {
        year,
        month,
        day,
        hour,
        minute,
        second,
        utc_offset_minutes: off,
    }
}

#[test]
fn test_trailer_update() {
    let mut w = IncrementalWriter::new(read(&pdf("minimal-with-field.pdf")));
    w.update_meta_on_write = false;
    let dt = pdf_date(&utc(2020, 10, 10, 0, 0, 0, Some(0)));
    let mut info = Dictionary::new();
    info.set("CreationDate", text_string(&dt));
    let info_ref = w.add_object(Object::Dictionary(info)).unwrap();
    w.set_custom_trailer_entry("Info", Object::Reference(info_ref));
    let out = w.write().unwrap();
    let r = read(&out);
    let info = as_dict(r.resolve(&r.trailer().raw_get(b"Info", None).unwrap()).unwrap());
    assert_eq!(text(&get(&r, &info, "CreationDate")), dt);
}

#[test]
fn test_incremental_trailer_operations() {
    let mut w = IncrementalWriter::new(read(&pdf("minimal-with-field.pdf")));
    w.add_object(Object::Null).unwrap();
    assert!(w.trailer().unwrap().contains(b"Root"));
    w.set_custom_trailer_entry("/TEST.Test", text_string("bleh"));
    let t = w.trailer().unwrap();
    assert!(t.contains(b"TEST.Test"));
    let flat = t.flatten(None);
    let keys: BTreeSet<Vec<u8>> = flat.iter().map(|(k, _)| k.clone()).collect();
    assert!(keys.contains(b"TEST.Test".as_slice()));
    assert!(keys.contains(b"Root".as_slice()));
    assert_eq!(text(flat.get(b"TEST.Test").unwrap()), "bleh");
    let out = w.write().unwrap();
    let r = read(&out);
    assert_eq!(text(&r.trailer().raw_get(b"TEST.Test", None).unwrap()), "bleh");
}

#[test]
fn test_generic_trailer_write() {
    for incremental in [true, false] {
        let mut w: PdfWriter = if incremental {
            IncrementalWriter::new(read(&minimal())).into_inner()
        } else {
            copy_into_new_writer(&read(&minimal())).unwrap().into_inner()
        };
        w.add_object(Object::Null).unwrap();
        w.set_custom_trailer_entry("/TEST.Test", text_string("bleh"));
        assert!(w.trailer_view().unwrap().has(b"TEST.Test"));
        let out = w.write().unwrap();
        let r = read(&out);
        assert_eq!(text(&r.trailer().raw_get(b"TEST.Test", None).unwrap()), "bleh");
    }
}

fn date_pairs() -> Vec<(&'static str, PdfDate)> {
    let cet = utc(2008, 2, 3, 1, 5, 59, Some(60));
    let est = utc(2008, 2, 3, 1, 5, 59, Some(-300));
    vec![
        ("D:2008", utc(2008, 1, 1, 0, 0, 0, None)),
        ("D:200802", utc(2008, 2, 1, 0, 0, 0, None)),
        ("D:20080203", utc(2008, 2, 3, 0, 0, 0, None)),
        ("D:20080201", utc(2008, 2, 1, 0, 0, 0, None)),
        ("D:2008020301", utc(2008, 2, 3, 1, 0, 0, None)),
        ("D:200802030105", utc(2008, 2, 3, 1, 5, 0, None)),
        ("D:20080203010559", utc(2008, 2, 3, 1, 5, 59, None)),
        ("D:20080203010559Z", utc(2008, 2, 3, 1, 5, 59, Some(0))),
        ("D:20080203010559+01'00", cet),
        ("D:20080203010559+01", cet),
        ("D:20080203010559+01'", cet),
        ("D:20080203010559+01'00'", cet),
        ("D:20080203010559-05'00", est),
        ("D:20080203010559-05", est),
        ("D:20080203010559-05'", est),
        ("D:20080203010559-05'00'", est),
        ("D:20080203010559-05'00'\n", est),
        ("D:20080203010559-05'00'\r", est),
        ("D:20080203010559-05'00'\r\n", est),
    ]
}

#[test]
fn test_date_parsing() {
    for (s, expected) in date_pairs() {
        for strict in [true, false] {
            assert_eq!(parse_pdf_date(s, strict).unwrap(), expected, "{s:?}");
        }
    }
}

#[test]
fn test_date_parsing_without_prefix() {
    for (s, expected) in date_pairs() {
        assert_eq!(parse_pdf_date(&s[2..], false).unwrap(), expected, "{s:?}");
    }
}

#[test]
fn test_date_parsing_errors() {
    for s in [
        "2008",
        "D:20",
        "D:20080",
        "D:20081301",
        "D:20030230",
        "D:20080203010559Z00",
        "D:20080203010559-05'00'11",
        "20230719131933+02'00'",
    ] {
        assert!(parse_pdf_date(s, true).unwrap_err().is_read_error(), "{s}");
    }
}

#[test]
fn test_date_parsing_non_string_type_error() {
    // ByteStringObject: in Rust, strings are classified by their bytes, so
    // byte strings are represented by bytes that do not decode as text
    for o in [
        Object::String(b"\x00D:20080203010559Z".to_vec(), StringFormat::Hexadecimal),
        Object::String(b"\x01D:20080203".to_vec(), StringFormat::Hexadecimal),
        Object::Integer(123),
        Object::Null,
    ] {
        assert_err_matches(parse_pdf_date_obj(&o, true), "text string");
    }
}

#[test]
fn test_info_delete() {
    let mut w = IncrementalWriter::new(read(&pdf("minimal-two-fields.pdf")));
    assert!(w.set_info(None).unwrap_err().is_pdf_error());
}

const SIMPLE_STREAM_WITH_FILTERS: &[u8] = b"<<\n/Filter [ /AHx /FlateDecode ]\n/Length 39\n>>\nstream\n789cf348cdc9c95728cf2fca49010018ab043d>\nendstream";

fn parse_stream(data: &[u8]) -> Stream {
    match parse(data).unwrap() {
        Object::Stream(s) => s,
        other => panic!("{other:?}"),
    }
}

fn stream_data(s: &Stream) -> Vec<u8> {
    DecodedStream::from_stream(s).unwrap().data
}

#[test]
fn test_wrong_decodeparms_length() {
    let mut s = parse_stream(SIMPLE_STREAM_WITH_FILTERS);
    s.dict.set("DecodeParms", Object::Array(vec![]));
    let out = generic::object_to_bytes(&Object::Stream(s));
    let s2 = parse_stream(&out);
    assert_eq!(s2.dict.get(b"DecodeParms").unwrap(), &Object::Array(vec![]));
    assert_eq!(stream_data(&s2), b"Hello world");
}

fn filters(s: &Stream) -> Object {
    s.dict.get(b"Filter").unwrap().clone()
}

#[test]
fn test_duplicate_filter_disregard() {
    let s = parse_stream(SIMPLE_STREAM_WITH_FILTERS);
    let s = apply_filter_to_stream(&s, "/AHx", None, DuplicateFilter::Ignore).unwrap();
    let out = generic::object_to_bytes(&Object::Stream(s.clone()));
    let s2 = parse_stream(&out);
    assert_eq!(filters(&s2), Object::Array(vec![name("AHx"), name("FlateDecode")]));
    assert_eq!(stream_data(&s2), b"Hello world");
    assert_eq!(s.content, s2.content);
}

#[test]
fn test_duplicate_filter_permitted() {
    let s = parse_stream(SIMPLE_STREAM_WITH_FILTERS);
    let s = apply_filter_to_stream(&s, "/AHx", None, DuplicateFilter::Allow).unwrap();
    let out = generic::object_to_bytes(&Object::Stream(s));
    let s2 = parse_stream(&out);
    assert_eq!(filters(&s2), Object::Array(vec![name("AHx"), name("AHx"), name("FlateDecode")]));
    assert_eq!(stream_data(&s2), b"Hello world");
}

#[test]
fn test_duplicate_filter_error() {
    let s = parse_stream(SIMPLE_STREAM_WITH_FILTERS);
    let e = assert_err_matches(
        apply_filter_to_stream(&s, "/AHx", None, DuplicateFilter::Error),
        "has already been applied",
    );
    assert!(matches!(e, PdfError::Write(_)));
}

#[test]
fn test_copy_file() {
    let r = read(&pdf("minimal-with-field.pdf"));
    let mut w = copy_into_new_writer(&r).unwrap();
    let old_root_ref = w.root_id();
    let out = w.write().unwrap();
    let r = read(&out);
    assert_eq!(r.root_ref().unwrap(), old_root_ref);
    let root = r.root().unwrap();
    let af = as_dict(get(&r, &root, "AcroForm"));
    let Object::Array(fields) = get(&r, &af, "Fields") else { panic!() };
    assert_eq!(fields.len(), 1);
    assert_eq!(kids(&r).len(), 1);
}

struct PathMockHandler;

impl PdfHandler for PathMockHandler {
    fn get_object(&self, id: ObjectId) -> PdfResult<Object> {
        if id.0 == 0 {
            Ok(text_string("OK"))
        } else {
            Ok(Object::Array(vec![Object::Integer(7)]))
        }
    }
    fn trailer_view(&self) -> PdfResult<Dictionary> {
        unimplemented!()
    }
    fn root_ref(&self) -> PdfResult<ObjectId> {
        unimplemented!()
    }
}

fn path_test_obj() -> Object {
    let mut blah = Dictionary::new();
    blah.set("Bleh", Object::Array(vec![Object::Integer(5), name("Foo")]));
    blah.set("Null", Object::Null);
    let mut with_refs = Dictionary::new();
    with_refs.set("Arr", Object::Reference((1, 0)));
    with_refs.set("String", Object::Reference((0, 0)));
    let mut d = Dictionary::new();
    d.set("Blah", Object::Dictionary(blah));
    d.set("WithRefs", Object::Dictionary(with_refs));
    Object::Dictionary(d)
}

fn path(elems: &[&str]) -> RawPdfPath {
    RawPdfPath::new(
        elems
            .iter()
            .map(|e| match e.parse::<usize>() {
                Ok(i) => PathElem::Index(i),
                Err(_) => PathElem::Key(e.trim_start_matches('/').as_bytes().to_vec()),
            })
            .collect(),
    )
}

#[test]
fn test_path_access() {
    let obj = path_test_obj();
    for (p, result) in [
        (path(&["/Blah", "/Bleh", "1"]), name("Foo")),
        (path(&["/Blah", "/Bleh", "0"]), Object::Integer(5)),
        (path(&["/Blah", "/Null"]), Object::Null),
        (path(&["/WithRefs", "/Arr", "0"]), Object::Integer(7)),
        (path(&["/WithRefs", "/String"]), text_string("OK")),
    ] {
        assert_eq!(p.access_on(&PathMockHandler, &obj, true).unwrap(), result, "{p}");
    }
}

#[test]
fn test_path_access_failures() {
    let obj = path_test_obj();
    for p in [
        path(&["0"]),
        path(&["/Blah", "/Null", "/NothingLeft"]),
        path(&["/Blah", "/Bleh", "/NotADictionary"]),
        path(&["/TheresNoSuchKey"]),
        path(&["/Blah", "/Bleh", "10000"]),
    ] {
        assert!(p.access_on(&PathMockHandler, &obj, true).unwrap_err().is_read_error(), "{p}");
    }
}

#[test]
fn test_path_access_reference() {
    let obj = path_test_obj();
    let r1 = path(&["/WithRefs", "/Arr"]).access_reference_on(&PathMockHandler, &obj).unwrap();
    assert_eq!(r1.0, 1);
    let r2 = path(&["/WithRefs", "/String"]).access_reference_on(&PathMockHandler, &obj).unwrap();
    assert_eq!(r2.0, 0);
    let e = path(&["/Blah"]).access_reference_on(&PathMockHandler, &obj).unwrap_err();
    assert!(matches!(e, PdfError::IndirectObjectExpected(_)));
}

#[test]
fn test_pdf_num_precision() {
    assert_eq!(format_real(32.00001), "32.00001");
    assert_eq!(format_real(32.92001), "32.92001");
    assert_eq!(format_real(32.0), "32");
}

#[test]
fn test_array_null_bytes() {
    for arr in [&b"[1 1 1]"[..], b"[1 1 1\x00\x00\x00]", b"[1\x00\x001 1 ]"] {
        let parsed = generic::read_array(&mut Cursor::new(arr), &ctx(), ContentOpReading::No).unwrap();
        assert_eq!(parsed, vec![Object::Integer(1); 3]);
    }
}

fn input_version(data: &[u8]) -> (u32, u32) {
    read(data).input_version()
}

#[test]
fn test_ensure_version_newfile() {
    let mut w = copy_into_new_writer(&read(&minimal())).unwrap();
    w.ensure_output_version((2, 0)).unwrap();
    let out = w.write().unwrap();
    assert_eq!(input_version(&out), (2, 0));
}

#[test]
fn test_ensure_version_update_noop() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    let out = w.write().unwrap();
    assert_eq!(input_version(&out), (1, 7));
}

#[test]
fn test_ensure_version_update() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    w.ensure_output_version((2, 0)).unwrap();
    let out = w.write().unwrap();
    assert_eq!(input_version(&out), (2, 0));
}

#[test]
fn test_ensure_version_update_twice() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    w.ensure_output_version((1, 8)).unwrap();
    let out = w.write_in_place().unwrap();
    assert_eq!(input_version(&out), (1, 8));
    let mut w = IncrementalWriter::new(read(&out));
    w.ensure_output_version((2, 0)).unwrap();
    let out = w.write_in_place().unwrap();
    assert_eq!(input_version(&out), (2, 0));
}

#[test]
fn test_ensure_version_update_twice_smaller() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    w.ensure_output_version((2, 0)).unwrap();
    let out = w.write_in_place().unwrap();
    assert_eq!(input_version(&out), (2, 0));
    let mut w = IncrementalWriter::new(read(&out));
    w.ensure_output_version((1, 7)).unwrap();
    w.add_object(text_string("Bleh")).unwrap();
    let out = w.write_in_place().unwrap();
    assert_eq!(input_version(&out), (2, 0));
}

fn ext(prefix: &str, level: i64) -> DeveloperExtension {
    DeveloperExtension::new(prefix, "/1.7", level)
}

fn ext2() -> DeveloperExtension {
    let mut e = ext("/TEST", 2);
    e.url = Some("https://example.com".into());
    e.extension_revision = Some("No-frills test extension".into());
    e
}

fn ext_multi() -> DeveloperExtension {
    let mut e = ext("/MULT", 2);
    e.url = Some("https://example.com".into());
    e.extension_revision = Some("Test extension intended to be used as multivalue".into());
    e.multivalued = DevExtensionMultivalued::Always;
    e
}

fn with(mut e: DeveloperExtension, f: impl FnOnce(&mut DeveloperExtension)) -> DeveloperExtension {
    f(&mut e);
    e
}

fn ext_value(w: &PdfWriter, prefix: &str) -> Object {
    let root = w.root().unwrap();
    let exts = as_dict(get(w, &root, "Extensions"));
    get(w, &exts, prefix)
}

fn ext_level(w: &PdfWriter, o: &Object) -> i64 {
    let d = as_dict(w.resolve(o).unwrap());
    match get(w, &d, "ExtensionLevel") {
        Object::Integer(i) => i,
        _ => panic!(),
    }
}

fn written_with(e: &DeveloperExtension) -> Vec<u8> {
    let mut w = PdfFileWriter::new(true, true).unwrap();
    w.register_extension(e).unwrap();
    w.write().unwrap()
}

#[test]
fn test_single_extension_registration() {
    let cases = vec![
        (2, ext2()),
        (3, with(ext("/TEST", 3), |e| e.compare_by_level = true)),
        (2, with(ext("/TEST", 1), |e| e.compare_by_level = true)),
        (3, with(ext("/TEST", 3), |e| e.subsumes = vec![2])),
        (2, with(ext("/TEST", 1), |e| e.subsumed_by = vec![2])),
        (
            2,
            with(ext("/TEST", 1001), |e| {
                e.subsumed_by = vec![2];
                e.subsumes = vec![1000, 1];
            }),
        ),
    ];
    for (expected, new_ext) in cases {
        let mut w = PdfFileWriter::new(true, true).unwrap();
        w.register_extension(&ext2()).unwrap();
        let v = ext_value(&w, "TEST");
        assert_eq!(ext_level(&w, &v), 2);
        let out = w.write().unwrap();
        let mut w = copy_into_new_writer(&read(&out)).unwrap();
        w.register_extension(&new_ext).unwrap();
        let v = ext_value(&w, "TEST");
        assert_eq!(ext_level(&w, &v), expected);
    }
}

#[test]
fn test_extension_registration_create_array() {
    let cases = vec![
        (2, ext("/TEST", 3)),
        (2, with(ext("/TEST", 3), |e| e.compare_by_level = false)),
        (2, with(ext("/TEST", 1), |e| e.subsumed_by = vec![5])),
        (
            2,
            with(ext("/TEST", 1001), |e| {
                e.subsumed_by = vec![2000];
                e.subsumes = vec![1000, 1];
            }),
        ),
        (
            1,
            with(ext("/TEST", 3), |e| {
                e.compare_by_level = true;
                e.multivalued = DevExtensionMultivalued::Always;
            }),
        ),
    ];
    for (expected_len, new_ext) in cases {
        let mut w = PdfFileWriter::new(true, true).unwrap();
        w.register_extension(&ext2()).unwrap();
        w.write().unwrap();
        w.register_extension(&new_ext).unwrap();
        let Object::Array(a) = ext_value(&w, "TEST") else { panic!("not an array") };
        assert_eq!(a.len(), expected_len);
    }
}

#[test]
fn test_multi_extension_registration() {
    let cases: Vec<(Vec<i64>, DeveloperExtension)> = vec![
        (vec![2], ext_multi()),
        (vec![3], with(ext("/MULT", 3), |e| e.compare_by_level = true)),
        (vec![2], with(ext("/MULT", 1), |e| e.compare_by_level = true)),
        (vec![3], with(ext("/MULT", 3), |e| e.subsumes = vec![2])),
        (vec![2], with(ext("/MULT", 1), |e| e.subsumed_by = vec![2])),
        (
            vec![2],
            with(ext("/MULT", 1001), |e| {
                e.subsumed_by = vec![2];
                e.subsumes = vec![1000, 1];
            }),
        ),
        (vec![2, 3], ext("/MULT", 3)),
        (vec![2, 3], with(ext("/MULT", 3), |e| e.compare_by_level = false)),
        (vec![2, 1], with(ext("/MULT", 1), |e| e.subsumed_by = vec![5])),
        (
            vec![2, 1001],
            with(ext("/MULT", 1001), |e| {
                e.subsumed_by = vec![2000];
                e.subsumes = vec![1000, 1];
            }),
        ),
    ];
    for (expected, new_ext) in cases {
        let mut w = PdfFileWriter::new(true, true).unwrap();
        w.register_extension(&ext_multi()).unwrap();
        let Object::Array(a) = ext_value(&w, "MULT") else { panic!() };
        assert_eq!(a.len(), 1);
        let out = w.write().unwrap();
        let mut w = copy_into_new_writer(&read(&out)).unwrap();
        w.register_extension(&new_ext).unwrap();
        let Object::Array(a) = ext_value(&w, "MULT") else { panic!() };
        let lvls: BTreeSet<i64> = a.iter().map(|o| ext_level(&w, o)).collect();
        assert_eq!(lvls, expected.into_iter().collect());
    }
}

#[test]
fn test_extension_registration_unclear() {
    let never = |mut e: DeveloperExtension| {
        e.multivalued = DevExtensionMultivalued::Never;
        e
    };
    for new_ext in [
        never(ext("/TEST", 3)),
        never(with(ext("/TEST", 3), |e| e.compare_by_level = false)),
        never(with(ext("/TEST", 1), |e| e.subsumed_by = vec![5])),
        never(with(ext("/TEST", 1001), |e| {
            e.subsumed_by = vec![2000];
            e.subsumes = vec![1000, 1];
        })),
    ] {
        let out = written_with(&ext2());
        let mut w = copy_into_new_writer(&read(&out)).unwrap();
        let e = assert_err_matches(w.register_extension(&new_ext), "Could not register ext");
        assert!(matches!(e, PdfError::Write(_)));
    }
}

fn written_with_extensions(value: Object) -> Vec<u8> {
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let mut root = w.root().unwrap();
    let mut exts = Dictionary::new();
    exts.set("TEST", value);
    root.set("Extensions", Object::Dictionary(exts));
    w.set_root(root);
    w.write().unwrap()
}

#[test]
fn test_extension_registration_type_err() {
    let out = written_with_extensions(Object::Integer(7));
    let mut w = copy_into_new_writer(&read(&out)).unwrap();
    let e = assert_err_matches(w.register_extension(&ext2()), "type.*NumberObject");
    assert!(e.is_read_error());
}

#[test]
fn test_extension_registration_type_err_arr() {
    let out = written_with_extensions(Object::Array(vec![Object::Null]));
    let mut w = copy_into_new_writer(&read(&out)).unwrap();
    let e = assert_err_matches(w.register_extension(&ext2()), "type.*NullObject");
    assert!(e.is_read_error());
}

#[test]
fn test_extension_registration_no_level() {
    let mut d = ext2().as_pdf_object();
    d.remove(b"ExtensionLevel");
    let out = written_with_extensions(Object::Dictionary(d));
    let mut w = copy_into_new_writer(&read(&out)).unwrap();
    let e = assert_err_matches(w.register_extension(&ext2()), "Could not read developer ext");
    assert!(e.is_read_error());
}

#[test]
fn test_extension_registration_bad_level() {
    let mut d = ext2().as_pdf_object();
    d.set("ExtensionLevel", Object::Null);
    let out = written_with_extensions(Object::Dictionary(d));
    let mut w = copy_into_new_writer(&read(&out)).unwrap();
    let e = assert_err_matches(w.register_extension(&ext2()), "Could not read developer ext");
    assert!(e.is_read_error());
}

#[test]
fn test_name_decode() {
    for (bytes, expected) in [
        (&b"/Name1"[..], &b"Name1"[..]),
        (b"/A;Name_With-Various***Characters", b"A;Name_With-Various***Characters"),
        (b"/1.2", b"1.2"),
        (b"/$$", b"$$"),
        (b"/@pattern", b"@pattern"),
        (b"/.notdef", b".notdef"),
        (b"/Lime#20Green", b"Lime Green"),
        (b"/paired#28#29parentheses", b"paired()parentheses"),
        (b"/The_Key_of_F#23_Minor", b"The_Key_of_F#_Minor"),
        (b"/application#2Fpdf", b"application/pdf"),
        (b"/application#2fpdf", b"application/pdf"),
    ] {
        assert_eq!(generic::read_name(&mut Cursor::new(bytes)).unwrap(), expected);
    }
}

#[test]
fn test_name_decode_failure() {
    for (bytes, err) in [
        (&b"Foo"[..], "Name object should start with /"),
        (b"/Foo#", "Unterminated escape"),
        (b"/Foo#1", "Unterminated escape"),
        (b"/Foo#z1", "hexadecimal digit"),
        (b"/Foo\x7fbar", "must be escaped"),
        (b"/Foo\xefbar", "must be escaped"),
    ] {
        let e = assert_err_matches(generic::read_name(&mut Cursor::new(bytes)), err);
        assert!(e.is_read_error());
    }
}

#[test]
fn test_name_encode() {
    for (s, expected) in [
        ("Foo", &b"/Foo"[..]),
        ("application/pdf", b"/application#2Fpdf"),
        ("Lime Green", b"/Lime#20Green"),
        ("The_Key_of_F#_Minor", b"/The_Key_of_F#23_Minor"),
    ] {
        let mut out = Vec::new();
        generic::write_name(&mut out, s.as_bytes());
        assert_eq!(out, expected);
    }
}

#[test]
fn test_parse_name_invalid_utf8() {
    assert_eq!(generic::read_name(&mut Cursor::new(b"/Test#ae")).unwrap(), b"Test\xae");
}

#[test]
fn test_parse_datetime() {
    assert_eq!(pdf_date(&utc(2020, 12, 26, 15, 5, 11, Some(-300))), "D:20201226150511-05'00'");
    assert_eq!(pdf_date(&utc(2020, 12, 26, 15, 5, 11, Some(0))), "D:20201226150511Z");
    assert_eq!(pdf_date(&utc(2020, 12, 26, 15, 5, 11, Some(60))), "D:20201226150511+01'00'");
}

#[test]
fn test_read_circular_page_tree() {
    let r = read(&pdf("circular-page-tree.pdf"));
    let (p1, _) = r.find_page_for_modification(0).unwrap();
    assert!(as_dict(r.get_object(p1).unwrap()).has(b"Contents"));
    let e = assert_err_matches(r.find_page_for_modification(1), "Circular");
    assert!(e.is_read_error());
}

#[test]
fn test_read_broken_page_tree_direct_kids() {
    let r = read(&pdf("page-tree-direct-kid.pdf"));
    let (p1, _) = r.find_page_for_modification(0).unwrap();
    assert!(as_dict(r.get_object(p1).unwrap()).has(b"Contents"));
    let e = assert_err_matches(r.find_page_for_modification(1), "must be indirect");
    assert!(e.is_read_error());
}

#[test]
fn test_parse_comments() {
    for input in [
        "\n    <</A/B%bleh\n    /C/D>>\n    ",
        "\n    <</A/B/C%bleh\n    /D>>\n    ",
        "\n    <</A/B/C%bleh >>\n    /D>>\n    ",
        "\n    <<%lkjadsf\n    /A/B/C%bleh >>\n    /D>>\n    ",
        "\n    <<%lkjadsf\r/A/B/C%bleh >>\n    /D>>\n    ",
        "\n    <<%lkjadsf\r\n/A/B/C%bleh >>\r/D>>\n    ",
    ] {
        let d = generic::read_dictionary(&mut Cursor::new(input.trim().as_bytes()), &ctx(), ContentOpReading::No)
            .unwrap();
        let d = as_dict(d);
        assert_eq!(d.len(), 2);
        assert_eq!(d.get(b"A").unwrap(), &name("B"));
        assert_eq!(d.get(b"C").unwrap(), &name("D"));
    }
}

#[test]
fn test_parse_malformed_dictionary() {
    for input in ["<</2 0 R>>", "<</Name 0 0>>", "<<(blah) 0>>"] {
        let e = assert_err_matches(
            generic::read_dictionary(&mut Cursor::new(input.as_bytes()), &ctx(), ContentOpReading::No),
            "Failed to read dictionary key",
        );
        assert!(e.is_read_error());
    }
}

fn producer(r: &PdfFile) -> String {
    let info = as_dict(r.resolve(&r.trailer().raw_get(b"Info", None).unwrap()).unwrap());
    text(&get(r, &info, "Producer"))
}

#[test]
fn test_producer_override() {
    let mut w = copy_into_new_writer(&read(&pdf("scribble.pdf"))).unwrap();
    let out = w.write().unwrap();
    let r = read(&out);
    let proc_ = producer(&r);
    assert!(proc_.starts_with("cairo"), "{proc_}");
    assert!(proc_.contains(VENDOR));
    let mut w = copy_into_new_writer(&r).unwrap();
    let out2 = w.write().unwrap();
    let r2 = read(&out2);
    assert_eq!(producer(&r2), proc_);
}

#[test]
fn test_fresh_producer() {
    let mut w = copy_into_new_writer(&read(&minimal())).unwrap();
    let out = w.write().unwrap();
    assert!(producer(&read(&out)).starts_with(VENDOR));
}

#[test]
fn test_multi_def_dictionary() {
    let e = generic::read_dictionary(
        &mut Cursor::new(b"<</Bleh /A /Bluh /B /Bleh /C>>"),
        &ctx(),
        ContentOpReading::No,
    )
    .unwrap_err();
    assert!(e.is_strict_read_error());
}

#[test]
fn test_bad_null() {
    let mut c = Cursor::new(b"nulx");
    assert!(generic::read_null(&mut c).unwrap_err().is_read_error());
    assert!(read_object(&mut c, &ctx()).unwrap_err().is_read_error());
}

#[test]
fn test_unrecognized_token() {
    let e = assert_err_matches(parse(b"##&@*#!"), "Unexpected");
    assert!(e.is_read_error());
}

#[test]
fn test_operator_literal() {
    let v = read_item(&mut Cursor::new(b"BT"), &ctx(), ContentOpReading::GraphicOps).unwrap();
    assert_eq!(v, Item::Operator("BT".into()));
    let e = assert_err_matches(parse(b"BT"), "Unexpected");
    assert!(e.is_read_error());
}

#[test]
fn test_content_stream_null() {
    let v = read_item(&mut Cursor::new(b"null"), &ctx(), ContentOpReading::GraphicOps).unwrap();
    assert_eq!(v, Item::Object(Object::Null));
}

#[test]
fn test_bad_bool() {
    assert!(generic::read_boolean(&mut Cursor::new(b"trux")).unwrap_err().is_read_error());
    let mut c = Cursor::new(b"falsx");
    assert!(generic::read_boolean(&mut c).unwrap_err().is_read_error());
    assert!(read_object(&mut c, &ctx()).unwrap_err().is_read_error());
}

#[test]
fn test_bad_array() {
    let e = generic::read_array(&mut Cursor::new(b"$null null]"), &ctx(), ContentOpReading::No).unwrap_err();
    assert!(e.is_read_error());
}

#[test]
fn test_bad_dict() {
    let e = generic::read_dictionary(&mut Cursor::new(b"</Blah/Blah>>"), &ctx(), ContentOpReading::No)
        .unwrap_err();
    assert!(e.is_read_error());
}

#[test]
fn test_bad_indirect_ref() {
    for (payload, err) in [
        (&b"   "[..], "ended unexpectedly"),
        (b"1   ", "ended unexpectedly"),
        (b"1 8 Q", "Error reading"),
        (b"0 0 R", "Parse error"),
        (b"1 -2 R", "Parse error"),
        (b"-1 0 R", "Parse error"),
        (b"Z 0 R", "Parse error"),
    ] {
        let e = assert_err_matches(generic::read_indirect_reference(&mut Cursor::new(payload)), err);
        assert!(e.is_read_error());
    }
}

#[test]
fn test_asnumeric() {
    let o = generic::read_number(&mut Cursor::new(b"1.2381")).unwrap();
    assert_eq!(o, Object::Real(1.2381));
    let o = generic::read_number(&mut Cursor::new(b"12381")).unwrap();
    assert_eq!(o, Object::Integer(12381));
}

#[test]
fn test_multi_def_dictionary_nonstrict() {
    let d = generic::read_dictionary(
        &mut Cursor::new(b"<</Bleh /A /Bluh /B /Bleh /C>>"),
        &lenient_ctx(),
        ContentOpReading::No,
    )
    .unwrap();
    assert_eq!(as_dict(d).get(b"Bleh").unwrap(), &name("A"));
}

#[test]
fn test_compacted_syntax() {
    let r = read(&hanko_testdata::read(&["pyhanko", "pdf", "safedocs", "CompactedPDFSyntaxTest.pdf"]));
    let root = r.root().unwrap();
    let mi = as_dict(get(&r, &root, "MarkInfo"));
    assert_eq!(get(&r, &mi, "Marked"), Object::Boolean(true));
    let k = kids(&r);
    let page = as_dict(r.resolve(&k[0]).unwrap());
    // numeric comparison, as in Python (ints and decimals compare equal)
    let Object::Array(mb) = get(&r, &page, "MediaBox") else { panic!() };
    let mb: Vec<f32> = mb.iter().map(|o| o.as_float().unwrap()).collect();
    assert_eq!(mb, vec![0.0, 0.0, 999.0, 999.0]);
    let Object::Array(c) = get(&r, &page, "Contents") else { panic!() };
    let Object::Stream(s) = r.resolve(&c[0]).unwrap() else { panic!() };
    assert!(contains(&r.stream_data(&s).unwrap(), b"compacted syntax sequences"));
    let tv = r.trailer_view();
    let info = as_dict(get(&r, &tv, "Info"));
    assert_eq!(text(&get(&r, &info, "Subject")), "Compacted Syntax v3.0");
}

fn simple_string_enc_samples() -> Vec<(&'static [u8], TextStringEncoding)> {
    vec![
        (b"abcdef", TextStringEncoding::PdfDoc),
        (b"\xfe\xff\x00a\x00b\x00c\x00d\x00e\x00f", TextStringEncoding::Utf16Be),
        (b"\xff\xfea\x00b\x00c\x00d\x00e\x00f\x00", TextStringEncoding::Utf16Le),
        (b"\xef\xbb\xbfabcdef", TextStringEncoding::Utf8),
    ]
}

#[test]
fn test_autodetect_string_encoding() {
    for (encoded, enc) in simple_string_enc_samples() {
        assert_eq!(generic::pdf_string(encoded), PdfString::Text("abcdef".into(), enc));
    }
}

#[test]
fn test_string_encode() {
    for (encoded, enc) in simple_string_enc_samples() {
        let bytes = enc.encode("abcdef").unwrap();
        let mut out = Vec::new();
        generic::write_string(&mut out, &bytes, StringFormat::Literal);
        let back = generic::read_string_literal_bytes(&mut Cursor::new(&out)).unwrap();
        assert_eq!(back, encoded);
    }
}

#[test]
fn test_decode_string_escapes() {
    for (encoded, decoded) in [
        (&b"(\xef\xbb\xbfHello\\nWorld)"[..], "Hello\nWorld"),
        (b"(\xef\xbb\xbfHello\\fWorld)", "Hello\x0cWorld"),
        (b"(\xef\xbb\xbfHello\\tWorld)", "Hello\tWorld"),
        (b"(\xef\xbb\xbfHello\\bWorld)", "Hello\x08World"),
        (b"(\xef\xbb\xbfHello\\rWorld)", "Hello\rWorld"),
        (b"(\xef\xbb\xbfHello\\012World)", "Hello\nWorld"),
        (b"(\xef\xbb\xbfHello\\12World)", "Hello\nWorld"),
    ] {
        let back = generic::read_string_literal_bytes(&mut Cursor::new(encoded)).unwrap();
        let mut expected = b"\xef\xbb\xbf".to_vec();
        expected.extend_from_slice(decoded.as_bytes());
        assert_eq!(back, expected);
        assert_eq!(
            generic::pdf_string(&back),
            PdfString::Text(decoded.into(), TextStringEncoding::Utf8)
        );
    }
}

#[test]
fn test_decode_string_illegal_escape_sequence() {
    let e = assert_err_matches(
        generic::read_string_literal_bytes(&mut Cursor::new(b"(Hello World\\z)")),
        "Unexpected escape.*z",
    );
    assert!(e.is_read_error());
}

#[test]
fn test_decode_string_premature_end() {
    let e = assert_err_matches(
        generic::read_string_literal_bytes(&mut Cursor::new(b"(Hello World")),
        "ended unexpectedly",
    );
    assert!(e.is_read_error());
}

#[test]
fn test_decode_hex_premature_end() {
    let e = assert_err_matches(generic::read_hex_string(&mut Cursor::new(b"<deadbeef")), "ended prematurely");
    assert!(e.is_read_error());
}

#[test]
fn test_decode_hex_invalid_token() {
    for data in [&b"<deadbeefNonsense>"[..], b"<dead%Bleh\nbeefNonsense>"] {
        let e = assert_err_matches(generic::read_hex_string(&mut Cursor::new(data)), "Unexpected.*N");
        assert!(e.is_read_error());
    }
}

fn hex_bytes(o: Object) -> Vec<u8> {
    match o {
        Object::String(s, _) => s,
        other => panic!("{other:?}"),
    }
}

#[test]
fn test_decode_hex() {
    for (data, expected) in [
        (&b"<deadbeef>"[..], &b"\xde\xad\xbe\xef"[..]),
        (b"<DeAd BeEf>", b"\xde\xad\xbe\xef"),
        (b"< \r\nde\tad\x0cbe\x00ef\n>", b"\xde\xad\xbe\xef"),
        (b"<>", b""),
        (b"<abc>", b"\xab\xc0"),
        (b"<a b c>", b"\xab\xc0"),
    ] {
        let mut buf = data.to_vec();
        buf.extend_from_slice(b" /Next");
        let mut c = Cursor::new(&buf);
        assert_eq!(hex_bytes(generic::read_hex_string(&mut c).unwrap()), expected);
        assert_eq!(c.read_rest(), b" /Next");
    }
}

#[test]
fn test_decode_hex_multiple_chunks() {
    let data: Vec<u8> = (0..=255u8).collect::<Vec<_>>().repeat(40);
    let hex: Vec<u8> = data.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect();
    let lines: Vec<&[u8]> = hex.chunks(63).collect();
    let mut buf = b"<".to_vec();
    buf.extend(lines.join(&b"\r\n"[..]));
    buf.extend_from_slice(b"> /Next");
    let mut c = Cursor::new(&buf);
    assert_eq!(hex_bytes(generic::read_hex_string(&mut c).unwrap()), data);
    assert_eq!(c.read_rest(), b" /Next");
}

#[test]
fn test_decode_hex_premature_end_multiple_chunks() {
    let mut buf = b"<".to_vec();
    buf.extend(b"ab".repeat(5000));
    let e = assert_err_matches(generic::read_hex_string(&mut Cursor::new(&buf)), "ended prematurely");
    assert!(e.is_read_error());
}

#[test]
fn test_decode_hex_gt_in_comment() {
    let mut c = Cursor::new(b"<de%a>b\nad> /Next");
    assert_eq!(hex_bytes(generic::read_hex_string(&mut c).unwrap()), b"\xde\xad");
    assert_eq!(c.read_rest(), b" /Next");
}

fn comment_test_pairs() -> Vec<(&'static [u8], Object)> {
    let mut ab = Dictionary::new();
    ab.set("A", name("B"));
    vec![
        (b"%Bleh<<>>\n<</A/B>>", Object::Dictionary(ab)),
        (b"%Bleh\n[/A/B]", Object::Array(vec![name("A"), name("B")])),
        (b"%Bleh\n/A", name("A")),
        (b"%Bleh\n.123", Object::Real(0.123)),
        (b"%Bleh\n1", Object::Integer(1)),
        (b"%Bleh\n(ABC)", Object::String(b"ABC".to_vec(), StringFormat::Literal)),
    ]
}

fn replace(data: &[u8], from: u8, to: &[u8]) -> Vec<u8> {
    data.iter()
        .flat_map(|&c| if c == from { to.to_vec() } else { vec![c] })
        .collect()
}

#[test]
fn test_read_object_comment() {
    for (data, expected) in comment_test_pairs() {
        for linesep in [&b"\n"[..], b"\r", b"\r\n"] {
            let buf = replace(data, b'\n', linesep);
            assert_eq!(parse(&buf).unwrap(), expected);
        }
    }
}

#[test]
fn test_comment_in_dict() {
    let mut ab = Dictionary::new();
    ab.set("A", name("B"));
    for data in [
        &b"<<%Bleh\n/A/B>>"[..],
        b"<</A%Bleh\n/B>>",
        b"<</A/B%Bleh\n>>",
        b"<< %Bleh\n/A/B>>",
        b"<</A %Bleh\n/B>>",
        b"<</A/B %Bleh\n>>",
        b"<<%Bleh\n /A/B>>",
        b"<</A%Bleh\n /B>>",
        b"<</A/B%Bleh\n >>",
    ] {
        for linesep in [&b"\n"[..], b"\r", b"\r\n"] {
            for space in [&b" "[..], b"\x00"] {
                let buf = replace(&replace(data, b'\n', linesep), b' ', space);
                assert_eq!(parse(&buf).unwrap(), Object::Dictionary(ab.clone()));
            }
        }
    }
}

#[test]
fn test_comment_in_hex_string() {
    for data in [
        &b"<%Bleh\ndeadbeef>"[..],
        b"<dead%Bleh\nbeef>",
        b"<deadbeef%Bleh\n>",
        b"<d%Bleh\neadbeef>",
        b"<deadbee%Bleh\nf>",
        b"< %Bleh\ndeadbeef>",
        b"<dead %Bleh\nbeef>",
        b"<deadbeef %Bleh\n>",
        b"<d %Bleh\neadbeef>",
        b"<%Bleh\n deadbeef>",
        b"<dead%Bleh\n beef>",
        b"<deadbeef%Bleh\n >",
        b"<d%Bleh\n eadbeef>",
        b"<deadbee%Bleh\n f>",
    ] {
        for linesep in [&b"\n"[..], b"\r", b"\r\n"] {
            for space in [&b" "[..], b"\x00"] {
                let buf = replace(&replace(data, b'\n', linesep), b' ', space);
                assert_eq!(hex_bytes(parse(&buf).unwrap()), b"\xde\xad\xbe\xef");
            }
        }
    }
}

#[test]
fn test_unorthodox_stream_syntax() {
    for data in [
        &b"\nstream\nabcdefg\nendstream"[..],
        b"\nstream \nabcdefg\nendstream",
        b"\nstream\nabcdefg\nendstream ",
        b"stream\nabcdefg\nendstream ",
        b" \nstream\nabcdefg\nendstream ",
    ] {
        for linesep in [&b"\n"[..], b"\r", b"\r\n"] {
            for space in [&b" "[..], b"\x00"] {
                let mut buf = b"<</A/B/Length 7>>".to_vec();
                buf.extend(replace(&replace(data, b'\n', linesep), b' ', space));
                let s = parse_stream(&buf);
                assert_eq!(s.dict.get(b"A").unwrap(), &name("B"));
                assert_eq!(s.dict.get(b"Length").unwrap(), &Object::Integer(7));
                assert_eq!(s.dict.len(), 2);
                assert_eq!(stream_data(&s), b"abcdefg");
            }
        }
    }
}

#[test]
fn test_stream_declared_length_too_long() {
    let s = parse_stream(b"<</A/B/Length 9>>\nstream\nabcdefg\nendstream\n");
    assert_eq!(s.dict.get(b"Length").unwrap(), &Object::Integer(9));
    assert_eq!(stream_data(&s), b"abcdefg\n");
}

#[test]
fn test_stream_nonsensical_filters() {
    let s = parse_stream(b"<</Filter 10/Length 7>>\nstream\nabcdefg\nendstream\n");
    let e = assert_err_matches(DecodedStream::from_stream(&s), "/Filter");
    assert!(e.is_stream_error());
}

#[test]
fn test_stream_declared_length_too_long_garbled() {
    let e = assert_err_matches(
        parse(b"<</A/B/Length 9>>\nstream\nabcdefg\nendstre@m\n"),
        "Unable to find.*marker",
    );
    assert!(e.is_read_error());
}

#[test]
fn test_all_nulls_equal() {
    assert_eq!(Object::Null, Object::Null);
}

#[test]
fn test_null_is_missing() {
    let mut d = Dictionary::new();
    d.set("A", name("Z"));
    d.set("B", Object::Null);
    let w = PdfFileWriter::new(true, true).unwrap();
    assert_eq!(w.get(&d, b"A").unwrap(), Some(name("Z")));
    assert_eq!(w.get(&d, b"B").unwrap(), None);
    assert_eq!(w.get(&d, b"C").unwrap(), None);
}

#[test]
fn test_tolerate_startxref_on_same_line() {
    let r = read(&pdf("minimal-startxref-same-line.pdf"));
    assert_eq!(r.last_startxref(), 565);
}

#[test]
fn test_startxref_parse_failure() {
    for f in ["minimal-startxref-hopeless2.pdf", "minimal-startxref-hopeless3.pdf"] {
        let e = assert_err_matches(try_read(&pdf(f), true), "startxref not found");
        assert!(e.is_read_error());
    }
}

#[test]
fn test_illegal_header() {
    let e = assert_err_matches(try_read(&pdf("minimal-illegal-header.pdf"), true), "Illegal PDF header");
    assert!(e.is_read_error());
}

#[test]
fn test_ignore_illegal_version_in_catalog() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    let mut root = w.root().unwrap();
    root.set("Version", text_string("zzzz"));
    w.set_root(root);
    let out = w.write_in_place().unwrap();
    assert_eq!(read(&out).input_version(), read(&minimal()).input_version());
}

#[test]
fn test_incremental_document_id_updated() {
    let out = copy_into_new_writer(&read(&minimal())).unwrap().write().unwrap();
    let mut w = IncrementalWriter::new(read(&out));
    let mut root = w.root().unwrap();
    root.set("Blah", name("Bluh"));
    w.set_root(root);
    let out = w.write_in_place().unwrap();
    let r = read(&out);
    let id1 = r.historical_resolver(0).document_id().unwrap();
    let id2 = r.document_id().unwrap();
    assert_eq!(id1.0, id2.0);
    assert_ne!(id1.1, id2.1);
}

#[test]
fn test_read_next_end_line_errors() {
    for (ln, err) in [
        (&b""[..], "Could not read"),
        (b"0", "EOL marker not found"),
        (b"12371", "EOL marker not found"),
        (b"\r12371", "EOL marker not found"),
    ] {
        let mut c = Cursor::at(ln, ln.len());
        let e = assert_err_matches(read_next_end_line(&mut c), err);
        assert!(e.is_read_error());
    }
}

fn page_resources(w: &dyn PdfHandler) -> (ObjectId, Dictionary, Dictionary) {
    let (pref, page) = first_page(w);
    let res = as_dict(get(w, &page, "Resources"));
    (pref, page, res)
}

#[test]
fn test_merge_resources() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    let (pref, mut page, mut res) = page_resources(&*w);
    let procset = w.add_object(Object::Array(vec![name("PDF")])).unwrap();
    let mut fnull = Dictionary::new();
    fnull.set("FNull", Object::Dictionary(Dictionary::new()));
    let mut new = Dictionary::new();
    new.set("ProcSet", Object::Reference(procset));
    new.set("Font", Object::Dictionary(fnull));
    let direct_mod = w.merge_resources(&mut res, &new).unwrap();
    // `update_container(res)`: the resources live directly in the page
    page.set("Resources", Object::Dictionary(res));
    w.update_object(pref, Object::Dictionary(page));
    let out = w.write_in_place().unwrap();
    assert!(direct_mod);

    let mut w = IncrementalWriter::new(read(&out));
    let (_, _, mut res) = page_resources(&*w);
    assert!(res.has(b"ProcSet"));
    assert!(!res.has(b"XObject"));
    assert!(as_dict(get(&*w, &res, "Font")).has(b"FNull"));
    let procset = w.add_object(Object::Array(vec![name("Text")])).unwrap();
    let mut new = Dictionary::new();
    new.set("ProcSet", Object::Reference(procset));
    let direct_mod = w.merge_resources(&mut res, &new).unwrap();
    let out = w.write_in_place().unwrap();
    assert!(!direct_mod);

    let r = read(&out);
    let (_, _, res) = page_resources(&r);
    let Object::Array(ps) = get(&r, &res, "ProcSet") else { panic!() };
    assert!(ps.contains(&name("Text")));
    assert!(ps.contains(&name("PDF")));
}

#[test]
fn test_merge_resource_conflict() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    let (_, _, mut res) = page_resources(&*w);
    let mut f1 = Dictionary::new();
    f1.set("F1", Object::Dictionary(Dictionary::new()));
    let mut new = Dictionary::new();
    new.set("Font", Object::Dictionary(f1));
    let e = assert_err_matches(w.merge_resources(&mut res, &new), "conflict");
    assert!(e.is_pdf_error());
}

#[test]
fn test_copy_deep_object_graph() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    // build the chain bottom-up: /Blah_i -> [ ref to next ]
    let mut next: Option<ObjectId> = Some(w.add_object(Object::Dictionary(Dictionary::new())).unwrap());
    for i in (1..4000).rev() {
        let mut d = Dictionary::new();
        if let Some(n) = next {
            d.set(format!("Blah_{i}"), Object::Array(vec![Object::Reference(n)]));
        }
        next = Some(w.add_object(Object::Dictionary(d)).unwrap());
    }
    let mut blah = Dictionary::new();
    blah.set("Blah_0", Object::Array(vec![Object::Reference(next.unwrap())]));
    let mut root = w.root().unwrap();
    root.set("Blah", Object::Dictionary(blah));
    w.set_root(root);
    let out = w.write_in_place().unwrap();

    let r = read(&out);
    let mut new_w = copy_into_new_writer(&r).unwrap();
    let out = new_w.write().unwrap();
    let nr = read(&out);
    let root = nr.root().unwrap();
    let b = as_dict(get(&nr, &root, "Blah"));
    let Object::Array(a0) = get(&nr, &b, "Blah_0") else { panic!() };
    let d1 = as_dict(nr.resolve(&a0[0]).unwrap());
    let Object::Array(a1) = get(&nr, &d1, "Blah_1") else { panic!() };
    let d2 = as_dict(nr.resolve(&a1[0]).unwrap());
    let Object::Array(a2) = get(&nr, &d2, "Blah_2") else { panic!() };
    assert_eq!(a2.len(), 1);
}

#[test]
fn test_copy_root_reference() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    let root_id = w.root_id();
    let arr = w.add_object(Object::Array(vec![Object::Reference(root_id)])).unwrap();
    let mut root = w.root().unwrap();
    root.set("Blah", Object::Reference(arr));
    w.set_root(root);
    let out = w.write_in_place().unwrap();
    let r = read(&out);
    let mut new_w = copy_into_new_writer(&r).unwrap();
    let out = new_w.write().unwrap();
    let nr = read(&out);
    let root = nr.root().unwrap();
    let Object::Array(a) = get(&nr, &root, "Blah") else { panic!() };
    assert_eq!(a[0], Object::Reference(root_id));
}

#[test]
fn test_circular_xref_sections() {
    let e = assert_err_matches(try_read(&pdf("circular-xref-chain.pdf"), true), "startxref loop");
    assert!(e.is_read_error());
}

#[test]
fn test_malformed_prev() {
    let e = assert_err_matches(try_read(&pdf("xref-malformed-prev.pdf"), true), "Expected /Prev to be a number");
    assert!(e.is_read_error());
}
