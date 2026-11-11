// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_xref.py`
// (MIT, see LICENSE-pyHanko). One Rust test per upstream test function;
// parametrized cases run in a loop.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use common::*;
use sigis_pdf::decode_limits::DecodeContext;
use sigis_pdf::generic::text_string;
use sigis_pdf::lopdf::{Dictionary, Object};
use sigis_pdf::misc::Cursor;
use sigis_pdf::xref::{
    parse_xref_stream, read_object_header, ObjStreamRef, XRefCache, XRefEntry, XRefLocation,
    XRefSection, XRefSectionData, XRefSectionMetaInfo, XRefSectionType,
};
use sigis_pdf::{IncrementalWriter, PdfError, PdfFileWriter, PdfHandler, PdfHandlerExt};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_object_header_whitespace() {
    for data in [
        &b"1 0 obj\n<<>>"[..],
        b"\n1 0 obj\n<<>>",
        b"\n1  0 obj\n<<>>",
        b"%this is a comment\n1  0 obj\n<<>>",
    ] {
        let r = read_object_header(&mut Cursor::new(data), true).unwrap();
        assert_eq!(r, (1, 0));
    }
}

#[test]
fn test_mildly_malformed_xref_read() {
    for fname in [
        "minimal-badxref.pdf",
        "minimal-startxref-obo1.pdf",
        "minimal-startxref-obo2.pdf",
        "minimal-startxref-obo3.pdf",
        "minimal-startxref-obo4.pdf",
        "minimal-startxref-obo5.pdf",
        "minimal-startxref-obo6.pdf",
    ] {
        let r = read_lenient(&pdf(fname));
        let root = r.root().unwrap();
        assert!(root.has(b"Pages"), "{fname}");
    }
}

#[test]
fn test_hopelessly_malformed_xref_read() {
    assert_err_matches(
        try_read(&pdf("minimal-startxref-hopeless.pdf"), false),
        "Could not find xref",
    );
}

#[test]
fn test_xref_locate_fail_strict() {
    for fname in [
        "minimal-startxref-obo2.pdf",
        "minimal-startxref-obo4.pdf",
        "minimal-startxref-obo5.pdf",
        "minimal-startxref-obo6.pdf",
    ] {
        let e = assert_err_matches(try_read(&pdf(fname), true), "Failed to locate xref");
        assert!(e.is_read_error());
    }
}

#[test]
fn test_broken_objstream() {
    for (fname, err, obj) in [
        (
            "broken-objstream1.pdf",
            "Object stream does not contain index",
            4,
        ),
        ("broken-objstream2.pdf", "Object is in wrong index.", 4),
        (
            "broken-objstream3.pdf",
            "Object stream header possibly corrupted",
            6,
        ),
        ("broken-objstream4.pdf", "not found in stream", 6),
        ("broken-objstream5.pdf", "forbidden object type", 9),
        ("broken-objstream6.pdf", "Can't read", 4),
    ] {
        let r = read(&pdf(fname));
        let e = assert_err_matches(r.get_object((obj, 0)), err);
        assert!(e.is_read_error(), "{fname}");
    }
}

#[test]
fn test_broken_obj_stream_fallback() {
    for (fname, obj, expect_null) in [
        ("broken-objstream1.pdf", 4, true),
        ("broken-objstream2.pdf", 4, false),
        ("broken-objstream3.pdf", 6, true),
        ("broken-objstream4.pdf", 6, true),
        ("broken-objstream5.pdf", 9, false),
        ("broken-objstream6.pdf", 4, true),
    ] {
        let r = read_lenient(&pdf(fname));
        let o = r.get_object((obj, 0)).unwrap();
        if expect_null {
            assert_eq!(o, Object::Null, "{fname}");
        } else {
            // StreamObject is a DictionaryObject subclass in pyHanko
            assert!(
                matches!(o, Object::Dictionary(_) | Object::Stream(_)),
                "{fname}: {o:?}"
            );
        }
    }
}

#[test]
fn test_preallocate() {
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let e = w.add_object_ext(Object::Null, None, Some(20)).unwrap_err();
    assert!(matches!(e, PdfError::Write(_)));
    let alloc = w.allocate_placeholder().unwrap();
    assert_eq!(w.get_object(alloc).unwrap(), Object::Null);
    w.add_object_ext(text_string("Test Test"), None, Some(alloc.0))
        .unwrap();
    assert_eq!(text(&w.get_object(alloc).unwrap()), "Test Test");
}

fn dummy(xrefs: &[&[&[u8]]]) -> Vec<u8> {
    fmt_dummy_xrefs(xrefs, b"\r\n", None)
}

#[test]
fn test_illegal_generation() {
    let x = dummy(&[&[b"0 2", b"0000000000 65535 f", b"0000000100 99999 n"]]);
    assert_err_matches(try_read(&x, true), "Illegal generation");
}

#[test]
fn test_illegal_generation_nonstrict() {
    let x = dummy(&[&[b"0 2", b"0000000000 65535 f", b"0000000100 99999 n"]]);
    let r = read_lenient(&x);
    assert!(r
        .xrefs()
        .get_xref_data(0)
        .unwrap()
        .explicit_refs_in_revision
        .is_empty());
}

#[test]
fn test_unparseable_idnum() {
    let x = dummy(&[&[b"0 2", b"0000000000 65535 f", b"000000010a 00000 n"]]);
    assert_err_matches(try_read(&x, true), "location.*decimal string");
}

#[test]
fn test_unparseable_generation() {
    let x = dummy(&[&[b"0 2", b"0000000000 65535 f", b"0000000100 aaaaa n"]]);
    assert_err_matches(try_read(&x, true), "generation.*decimal string");
}

#[test]
fn test_unparseable_generation_free() {
    let x = dummy(&[&[b"0 2", b"0000000000 65535 f", b"0000000100 aaaaa f"]]);
    assert_err_matches(try_read(&x, true), "to free.*decimal string");
}

#[test]
fn test_unparseable_marker() {
    let x = dummy(&[&[b"0 2", b"0000000000 65535 f", b"0000000100 00000 z"]]);
    assert_err_matches(try_read(&x, true), "Unknown marker");
}

#[test]
fn test_unparseable_marker_nonstrict() {
    let x = dummy(&[&[b"0 2", b"0000000000 65535 f", b"0000000100 00000 z"]]);
    let r = read_lenient(&x);
    assert!(r
        .xrefs()
        .get_xref_data(0)
        .unwrap()
        .explicit_refs_in_revision
        .is_empty());
}

#[test]
fn test_xref_table_too_many_entries() {
    let x = fmt_dummy_xrefs(
        &[&[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000200 00000 n",
        ]],
        b"\r\n",
        Some(2),
    );
    assert_err_matches(try_read(&x, true), "table size mismatch");
}

#[test]
fn test_xref_wrong_preamble() {
    let x = dummy(&[&[b"0 2", b"0000000000 65535 f", b"0000000100 00000 n"]]);
    let s = String::from_utf8(x).unwrap().replace("\nxref", "\nxzzz");
    assert_err_matches(try_read(s.as_bytes(), true), "table read error");
}

#[test]
fn test_xref_table_truncated_after_eol() {
    let data = b"%PDF-1.7\nxref\n0 2\n0000000000 65535 f \n\nstartxref\n9\n%%EOF";
    for strict in [true, false] {
        assert_err_matches(try_read(data, strict), "Unexpected end of file");
    }
}

#[test]
fn test_object_free() {
    let x = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000200 00000 n",
        ],
        &[b"0 2", b"0000000000 65535 f", b"0000000000 00001 f"],
        &[b"0 2", b"0000000000 65535 f", b"0000000300 00001 n"],
    ]);
    let r = read(&x);
    let xr = r.xrefs();
    assert_eq!(xr.total_revisions(), 3);
    assert_eq!(xr.get((1, 0)), None);
    assert!(xr.refs_freed_in_revision(1).contains(&(1, 0)));
    assert_eq!(xr.get((1, 1)), Some(XRefLocation::Offset(300)));
}

#[test]
fn test_object_free_no_override() {
    let x = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000200 00000 n",
        ],
        &[b"0 2", b"0000000000 65535 f", b"0000000000 00001 f"],
        &[b"0 2", b"0000000000 65535 f", b"0000000300 00001 n"],
        &[b"0 2", b"0000000000 65535 f", b"0000000000 00002 f"],
    ]);
    let r = read(&x);
    let xr = r.xrefs();
    assert_eq!(xr.total_revisions(), 4);
    assert_eq!(xr.get((1, 0)), None);
    assert_eq!(xr.get((1, 1)), None);
    assert!(xr.refs_freed_in_revision(1).contains(&(1, 0)));
    assert!(xr.refs_freed_in_revision(3).contains(&(1, 1)));
}

#[test]
fn test_refree_dead_object() {
    let x = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000000 00000 f",
            b"0000000200 00000 n",
        ],
        &[b"0 2", b"0000000000 65535 f", b"0000000000 00001 f"],
    ]);
    let r = read(&x);
    let xr = r.xrefs();
    assert_eq!(xr.total_revisions(), 2);
    assert!(!xr.refs_freed_in_revision(0).contains(&(1, 0)));
    assert!(xr.refs_freed_in_revision(1).contains(&(1, 0)));
    assert!(xr.explicit_refs_in_revision(1).contains(&(1, 0)));
}

#[test]
fn test_forbid_obj_kill() {
    let x = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000200 00000 n",
        ],
        &[b"0 2", b"0000000000 65535 f", b"0000000000 00000 f"],
    ]);
    assert_err_matches(try_read(&x, true), "free xref with next generation 0");
}

#[test]
fn test_no_resurrection_allowed() {
    let x = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000000 00000 f",
            b"0000000200 00000 n",
        ],
        &[b"0 2", b"0000000000 65535 f", b"0000000300 00001 n"],
    ]);
    assert_err_matches(try_read(&x, true), "listed as dead");
}

#[test]
fn test_increase_gen_without_free() {
    let x = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000200 00000 n",
        ],
        &[b"0 2", b"0000000000 65535 f", b"0000000300 00001 n"],
    ]);
    assert!(try_read(&x, true).unwrap_err().is_read_error());
}

#[test]
fn test_orphan_high_gen() {
    let x = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000200 00000 n",
        ],
        &[b"0 2", b"0000000000 65535 f", b"0000000300 00000 n"],
        &[b"0 1", b"0000000000 65535 f", b"3 1", b"0000000500 00001 n"],
    ]);
    assert!(try_read(&x, true).unwrap_err().is_read_error());
}

#[test]
fn test_generation_rollback() {
    let x = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000200 00000 n",
        ],
        &[b"0 2", b"0000000000 65535 f", b"0000000000 00001 f"],
        &[b"0 2", b"0000000000 65535 f", b"0000000300 00000 n"],
    ]);
    assert!(try_read(&x, true).unwrap_err().is_read_error());
}

#[test]
fn test_free_nonexistent() {
    let x = dummy(&[&[
        b"0 3",
        b"0000000000 65535 f",
        b"0000000100 00000 n",
        b"0000000000 00001 f",
    ]]);
    read(&x);
    let x = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000000 00001 f",
        ],
        &[b"0 1", b"0000000000 65535 f", b"2 1", b"0000000300 00000 n"],
    ]);
    assert!(try_read(&x, true).unwrap_err().is_read_error());
}

#[test]
fn test_free_unexpected_jump() {
    let x = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000200 00000 n",
        ],
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000200 00000 n",
            b"0000000000 00001 f",
        ],
        &[b"0 1", b"0000000000 65535 f", b"2 1", b"0000000300 00005 n"],
    ]);
    assert!(try_read(&x, true).unwrap_err().is_read_error());
}

#[test]
fn test_tagged_path_count() {
    let r = read(&pdf("minimal-two-fields-tagged.pdf"));
    let h = r.historical_resolver(0);
    let paths = h.usages_of_ref((7, 0)).unwrap();
    assert_eq!(paths.len(), 3, "{paths:?}");
}

// test_trailer_refs: skipped (container_ref / TrailerReference are Python
// object-model internals with no Rust counterpart); see PORTING.md.

#[test]
fn test_xref_access_no_decrypt() {
    let r = read(&pdf("minimal-aes256.pdf"));
    // the xref stream is never decrypted, even without credentials
    let obj = r.get_object_at((7, 0), None).unwrap();
    assert!(matches!(obj, Object::Stream(_)));
    assert!(matches!(
        r.get_object_raw((7, 0), None).unwrap(),
        Object::Stream(_)
    ));
}

#[test]
fn test_xref_null_update() {
    let mut w = IncrementalWriter::new(read(&minimal()));
    w.update_meta_on_write = false;
    let out = w.write_in_place().unwrap();
    let r = read(&out);
    assert_eq!(r.xrefs().total_revisions(), 2);
    assert!(r.xrefs().explicit_refs_in_revision(1).is_empty());
}

#[test]
fn test_xref_stream_null_update() {
    let mut w = IncrementalWriter::new(read(&pdf("minimal-xref.pdf")));
    w.update_meta_on_write = false;
    let out = w.write_in_place().unwrap();
    let r = read(&out);
    assert_eq!(r.xrefs().total_revisions(), 2);
    assert_eq!(r.xrefs().explicit_refs_in_revision(1).len(), 1);
}

#[test]
fn test_no_clobbering_xref_streams() {
    let base = read(&pdf("minimal-xref.pdf"));
    let stream_ref = base
        .xrefs()
        .get_xref_container_info(0)
        .unwrap()
        .stream_ref
        .unwrap();
    let mut w = IncrementalWriter::new(base);
    w.mark_update(stream_ref).unwrap();
    let out = w.write_in_place().unwrap();
    assert_err_matches(try_read(&out, true), "XRef.*must not be clobbered");
}

fn bleh_ref(h: &dyn PdfHandler) -> Object {
    let (_, page) = first_page(h);
    page.get(b"Bleh").unwrap().clone()
}

#[test]
fn test_nonexistent_xref_access() {
    let r = read(&pdf("minimal-with-nonexistent-refs.pdf"));
    let bad = bleh_ref(&r);
    assert_err_matches(r.resolve(&bad), "not found.*error in strict mode");
}

#[test]
fn test_nonexistent_xref_access_nonstrict() {
    let r = read_lenient(&pdf("minimal-with-nonexistent-refs.pdf"));
    let bad = bleh_ref(&r);
    assert_eq!(r.resolve(&bad).unwrap(), Object::Null);
}

fn remove_bleh() -> Vec<u8> {
    let mut w = IncrementalWriter::new(read(&pdf("minimal-with-nonexistent-refs.pdf")));
    let (pref, mut page) = first_page(&*w);
    page.remove(b"Bleh");
    w.update_object(pref, Object::Dictionary(page));
    w.write().unwrap()
}

#[test]
fn test_historical_nonexistent_xref_access() {
    let out = remove_bleh();
    let r = read(&out);
    let (_, cur) = first_page(&r);
    assert!(!cur.has(b"Bleh"));
    let h = r.historical_resolver(0);
    let bad = bleh_ref(&h);
    assert_err_matches(h.resolve(&bad), "not found.*error in strict mode");
}

#[test]
fn test_historical_nonexistent_xref_access_nonstrict() {
    let out = remove_bleh();
    let r = read_lenient(&out);
    let h = r.historical_resolver(0);
    let bad = bleh_ref(&h);
    assert_eq!(h.resolve(&bad).unwrap(), Object::Null);
}

#[test]
fn test_collect_dependencies_skips_nonexistent_ref() {
    for strict in [true, false] {
        let mut w = IncrementalWriter::new(read(&pdf("minimal-with-nonexistent-refs.pdf")));
        let (pref, mut page) = first_page(&*w);
        let new_obj = w.add_object(text_string("Hello")).unwrap();
        page.set("Foo", Object::Reference(new_obj));
        w.update_object(pref, Object::Dictionary(page));
        let out = w.write().unwrap();
        let r = try_read(&out, strict).unwrap();
        let hist = r.historical_resolver(1);
        let (pg_ref, _) = first_page(&r);
        let pg = hist.object(pg_ref).unwrap();
        let deps = hist.collect_dependencies(&pg, Some(1)).unwrap();
        assert_eq!(deps, BTreeSet::from([new_obj]));
    }
}

#[test]
fn test_no_objstms_without_xref_stm() {
    let mut w = PdfFileWriter::new(false, true).unwrap();
    let e = assert_err_matches(w.prepare_object_stream(true), "Obj");
    assert!(matches!(e, PdfError::Write(_)));
}

#[test]
fn test_no_stms_in_obj_stm() {
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let stm = w.prepare_object_stream(true).unwrap();
    let s = sigis_pdf::stream::encoded_stream(Dictionary::new(), b"Hello world!".to_vec());
    assert_err_matches(
        w.add_object_ext(s, Some(stm), None),
        "Stream obj.*references",
    );
}

#[test]
fn test_no_refs_in_obj_stm() {
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let stm = w.prepare_object_stream(true).unwrap();
    assert_err_matches(
        w.add_object_ext(Object::Reference((2, 0)), Some(stm), None),
        "Stream obj.*references",
    );
}

#[test]
fn test_xref_orphaned_nonstrict() {
    let r = read_lenient(&pdf("minimal-with-orphaned-xrefs.pdf"));
    assert_eq!(r.root_ref().unwrap().1, 9);
}

#[test]
fn test_xref_orphaned_strict() {
    assert_err_matches(
        try_read(&pdf("minimal-with-orphaned-xrefs.pdf"), true),
        "Object with id 1.*orphaned.*generation 9",
    );
}

fn xref_stream_dict(w: &[i64], size: i64) -> Dictionary {
    let mut d = Dictionary::new();
    d.set(
        "W",
        Object::Array(w.iter().map(|&x| Object::Integer(x)).collect()),
    );
    d.set("Size", Object::Integer(size));
    d
}

fn parse_entries(d: &Dictionary, data: &[u8]) -> Result<Vec<XRefEntry>, PdfError> {
    parse_xref_stream(d, data, &mut DecodeContext::default(), true)
}

#[test]
fn test_xref_stream_parse_entry_types() {
    let entries = [
        "0000000000ffff",
        "01000000110000",
        "01000000840000",
        "01000000bc0005",
        "01000001b40000",
        "01000002990000",
        "02000000030001",
        "03deadbeef1337",
        "02000000030002",
        "ffcafebabe0007",
    ];
    let data: Vec<u8> = entries.iter().flat_map(|e| hex(e)).collect();
    let out = parse_entries(&xref_stream_dict(&[1, 4, 2], 10), &data).unwrap();
    let expected = vec![
        XRefEntry::free(0, 0xffff),
        XRefEntry::standard(1, 0x11, 0),
        XRefEntry::standard(2, 0x84, 0),
        XRefEntry::standard(3, 0xbc, 5),
        XRefEntry::standard(4, 0x1b4, 0),
        XRefEntry::standard(5, 0x299, 0),
        XRefEntry::in_obj_stream(6, 3, 1),
        XRefEntry::in_obj_stream(8, 3, 2),
    ];
    assert_eq!(out, expected);
}

#[test]
fn test_xref_stream_parse_width_value_default_ix0() {
    let data: Vec<u8> = ["00000000ffff", "000000110000"]
        .iter()
        .flat_map(|e| hex(e))
        .collect();
    let out = parse_entries(&xref_stream_dict(&[0, 4, 2], 2), &data).unwrap();
    assert_eq!(
        out,
        vec![
            XRefEntry::standard(0, 0, 0xffff),
            XRefEntry::standard(1, 0x11, 0)
        ]
    );
}

#[test]
fn test_xref_stream_parse_long_width_value() {
    let data: Vec<u8> = ["0000000000000000000000ffff", "01000000000011000000110000"]
        .iter()
        .flat_map(|e| hex(e))
        .collect();
    let out = parse_entries(&xref_stream_dict(&[1, 10, 2], 2), &data).unwrap();
    assert_eq!(
        out,
        vec![
            XRefEntry::free(0, 0xffff),
            XRefEntry::standard(1, 0x1100000011, 0)
        ]
    );
}

#[test]
fn test_xref_stream_parse_width_value_default_ix2() {
    let data: Vec<u8> = ["0000000000", "0100000011"]
        .iter()
        .flat_map(|e| hex(e))
        .collect();
    let out = parse_entries(&xref_stream_dict(&[1, 4, 0], 2), &data).unwrap();
    assert_eq!(
        out,
        vec![XRefEntry::free(0, 0), XRefEntry::standard(1, 0x11, 0)]
    );
}

#[test]
fn test_premature_xref_stream_end() {
    let data: Vec<u8> = ["000000ffff", "0100110000"]
        .iter()
        .flat_map(|e| hex(e))
        .collect();
    assert_err_matches(
        parse_entries(&xref_stream_dict(&[1, 2, 2], 3), &data),
        "incomplete entry",
    );
}

#[test]
fn test_xref_stream_trailing_data() {
    let data: Vec<u8> = ["0000000000ffff", "01000000110000", "deadbeef"]
        .iter()
        .flat_map(|e| hex(e))
        .collect();
    assert_err_matches(
        parse_entries(&xref_stream_dict(&[1, 4, 2], 2), &data),
        "Trailing",
    );
}

fn info_title(r: &dyn PdfHandler, info: Object) -> String {
    let info = as_dict(r.resolve(&info).unwrap());
    text(&get(r, &info, "Title"))
}

const HYBRID_FILES: [&str; 3] = [
    "minimal-hybrid-xref.pdf",
    "minimal-hybrid-xref-weirdgen.pdf",
    "minimal-hybrid-xref-mswordstyle.pdf",
];

#[test]
fn test_hybrid_xref() {
    for fname in HYBRID_FILES {
        let r = read(&pdf(fname));
        let info = r.trailer().raw_get(b"Info", None).unwrap();
        assert_eq!(info_title(&r, info), "TestTest", "{fname}");
        assert_eq!(
            r.xrefs()
                .get_xref_container_info(1)
                .unwrap()
                .xref_section_type,
            XRefSectionType::HybridMain
        );
    }
}

#[test]
fn test_xref_size_nondecreasing() {
    assert_err_matches(
        try_read(&pdf("minimal-broken-xref-size.pdf"), true),
        "nondecreasing",
    );
}

fn update_title(data: &[u8]) -> Vec<u8> {
    let mut w = IncrementalWriter::new(read(data));
    assert!(w.trailer().unwrap().contains(b"XRefStm"));
    let info = as_dict(
        w.resolve(&w.trailer().unwrap().raw_get(b"Info", None).unwrap())
            .unwrap(),
    );
    let Ok(Object::Reference(t)) = info.get(b"Title") else {
        panic!()
    };
    let t = *t;
    w.update_object(t, text_string("Updated"));
    w.write().unwrap()
}

#[test]
fn test_update_hybrid() {
    for fname in [
        "minimal-hybrid-xref.pdf",
        "minimal-hybrid-xref-mswordstyle.pdf",
    ] {
        let out = update_title(&pdf(fname));
        let r = read(&out);
        assert!(!r.trailer().contains(b"XRefStm"));
        assert!(!r.trailer_view().has(b"XRefStm"));
        let info = r.trailer().raw_get(b"Info", None).unwrap();
        assert_eq!(info_title(&r, info), "Updated");
        let xr = r.xrefs();
        assert_eq!(
            xr.get_xref_container_info(1).unwrap().xref_section_type,
            XRefSectionType::HybridMain
        );
        assert_eq!(
            xr.get_xref_container_info(2).unwrap().xref_section_type,
            XRefSectionType::Standard
        );
    }
}

#[test]
fn test_count_refs_in_hybrid() {
    let r = read(&pdf("minimal-hybrid-xref-mswordstyle.pdf"));
    let xr = r.xrefs();
    assert_eq!(
        xr.get_xref_container_info(1).unwrap().xref_section_type,
        XRefSectionType::HybridMain
    );
    assert_eq!(
        xr.get_xref_data(1).unwrap().explicit_refs_in_revision.len(),
        0
    );
    assert_eq!(xr.explicit_refs_in_revision(1).len(), 6);
}

#[test]
fn test_update_hybrid_twice() {
    for fname in [
        "minimal-hybrid-xref.pdf",
        "minimal-hybrid-xref-mswordstyle.pdf",
    ] {
        let out = update_title(&pdf(fname));
        let r = read(&out);
        let info = r.trailer().raw_get(b"Info", None).unwrap();
        assert_eq!(info_title(&r, info), "Updated");
        let mut w = IncrementalWriter::new(r);
        w.add_object(text_string("This is an object")).unwrap();
        let out = w.write_in_place().unwrap();
        let r = read(&out);
        assert!(!r.trailer().contains(b"XRefStm"));
        assert!(!r.trailer_view().has(b"XRefStm"));
        let info = r.trailer().raw_get(b"Info", None).unwrap();
        assert_eq!(info_title(&r, info), "Updated");
        let xr = r.xrefs();
        assert_eq!(
            xr.get_xref_container_info(1).unwrap().xref_section_type,
            XRefSectionType::HybridMain
        );
        assert_eq!(
            xr.get_xref_container_info(2).unwrap().xref_section_type,
            XRefSectionType::Standard
        );
        assert_eq!(
            xr.get_xref_container_info(3).unwrap().xref_section_type,
            XRefSectionType::Standard
        );
    }
}

#[test]
fn test_xref_space_padded_offsets() {
    let r = read_lenient(&pdf("malformed-xref-space-padded.pdf"));
    assert_eq!(r.xrefs().get((5, 0)), Some(XRefLocation::Offset(361)));
}

#[test]
fn test_xref_space_padded_offsets_strict() {
    let e = assert_err_matches(
        try_read(&pdf("malformed-xref-space-padded.pdf"), true),
        "Unknown marker",
    );
    assert!(e.is_strict_read_error());
}

fn last_change_by_scan(xrefs: &XRefCache, id: (u32, u16)) -> (Option<usize>, Option<XRefLocation>) {
    for ix in (0..xrefs.total_revisions()).rev() {
        if let Some(r) = xrefs
            .get_xref_data(ix)
            .unwrap()
            .try_resolve(id.0, i64::from(id.1))
        {
            return (Some(ix), r);
        }
    }
    (None, None)
}

fn assert_last_change_matches_scan(xrefs: &XRefCache) {
    let mut refs = BTreeSet::new();
    for ix in 0..xrefs.total_revisions() {
        refs.extend(xrefs.explicit_refs_in_revision(ix));
    }
    let neighbours: Vec<_> = refs.iter().map(|&(i, g)| (i, g + 1)).collect();
    refs.extend(neighbours);
    let scans: Vec<_> = refs
        .iter()
        .map(|&r| (r, last_change_by_scan(xrefs, r)))
        .collect();
    for (r, (_, loc)) in &scans {
        assert_eq!(xrefs.get(*r), *loc, "{r:?}");
    }
    assert!(!xrefs.last_changes_indexed());
    for (r, (expected, _)) in &scans {
        assert_eq!(xrefs.get_last_change(*r), *expected, "{r:?}");
    }
    assert!(xrefs.last_changes_indexed());
    for (r, (_, loc)) in &scans {
        assert_eq!(xrefs.get(*r), *loc, "{r:?}");
    }
}

fn assert_last_changes(xrefs: &XRefCache, expected: &[((u32, u16), Option<usize>)]) {
    for (r, rev) in expected {
        assert_eq!(xrefs.get_last_change(*r), *rev, "{r:?}");
    }
}

#[test]
fn test_last_change_matches_scan() {
    let x1 = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000200 00000 n",
        ],
        &[b"0 2", b"0000000000 65535 f", b"0000000000 00001 f"],
        &[b"0 2", b"0000000000 65535 f", b"0000000300 00001 n"],
        &[b"0 1", b"0000000000 65535 f", b"2 1", b"0000000400 00000 n"],
    ]);
    let r = read(&x1);
    assert_last_change_matches_scan(r.xrefs());
    assert_last_changes(
        r.xrefs(),
        &[
            ((1, 0), Some(1)),
            ((1, 1), Some(2)),
            ((1, 2), None),
            ((2, 0), Some(3)),
        ],
    );
    let x2 = dummy(&[
        &[
            b"0 3",
            b"0000000000 65535 f",
            b"0000000100 00000 n",
            b"0000000000 00000 f",
        ],
        &[b"0 2", b"0000000000 65535 f", b"0000000100 00000 n"],
    ]);
    let r = read(&x2);
    assert_last_change_matches_scan(r.xrefs());
    assert_last_changes(r.xrefs(), &[((1, 0), Some(1)), ((2, 0), None)]);
}

fn xref_section(entries: &[XRefEntry], hybrid: Option<&[XRefEntry]>) -> XRefSection {
    let meta = |t| XRefSectionMetaInfo {
        xref_section_type: t,
        size: 10,
        declared_startxref: 0,
        start_location: 0,
        end_location: 0,
        stream_ref: None,
    };
    let mut data = XRefSectionData::default();
    data.process_entries(entries, false).unwrap();
    match hybrid {
        None => XRefSection {
            meta_info: meta(XRefSectionType::Standard),
            xref_data: data,
        },
        Some(h) => {
            data.process_hybrid_entries(h, meta(XRefSectionType::HybridStream), false)
                .unwrap();
            XRefSection {
                meta_info: meta(XRefSectionType::HybridMain),
                xref_data: data,
            }
        }
    }
}

#[test]
fn test_last_change_hybrid_main_table_shadows_stream() {
    let sections = vec![
        xref_section(
            &[
                XRefEntry::standard(1, 100, 0),
                XRefEntry::standard(3, 150, 0),
                XRefEntry::standard(4, 160, 0),
            ],
            None,
        ),
        xref_section(
            &[
                XRefEntry::standard(1, 300, 1),
                XRefEntry::standard(3, 350, 0),
                XRefEntry::free(4, 1),
            ],
            Some(&[
                XRefEntry::in_obj_stream(1, 2, 0),
                XRefEntry::standard(2, 200, 0),
                XRefEntry::in_obj_stream(3, 2, 1),
                XRefEntry::in_obj_stream(4, 2, 2),
            ]),
        ),
    ];
    let xrefs = XRefCache::new(sections);
    assert_last_change_matches_scan(&xrefs);
    assert_last_changes(
        &xrefs,
        &[
            ((1, 0), Some(0)),
            ((1, 1), Some(1)),
            ((2, 0), Some(1)),
            ((3, 0), Some(1)),
            ((4, 0), Some(1)),
        ],
    );
    assert_eq!(xrefs.get((1, 0)), Some(XRefLocation::Offset(100)));
    assert_eq!(xrefs.get((1, 1)), Some(XRefLocation::Offset(300)));
    assert_eq!(xrefs.get((3, 0)), Some(XRefLocation::Offset(350)));
    assert_eq!(xrefs.get((4, 0)), None);
    let _ = ObjStreamRef {
        obj_stream_id: 2,
        ix_in_stream: 0,
    };
}

#[test]
fn test_last_change_hybrid() {
    for fname in HYBRID_FILES {
        let r = read(&pdf(fname));
        assert_last_change_matches_scan(r.xrefs());
    }
}

#[test]
fn test_last_change_objstm_then_direct() {
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let objstm = w.prepare_object_stream(true).unwrap();
    let mut d = Dictionary::new();
    d.set("A", Object::Integer(1));
    let r1 = w
        .add_object_ext(Object::Dictionary(d), Some(objstm), None)
        .unwrap();
    let mut d = Dictionary::new();
    d.set("B", Object::Integer(1));
    let kept = w
        .add_object_ext(Object::Dictionary(d), Some(objstm), None)
        .unwrap();
    let mut root = w.root().unwrap();
    root.set("Test", Object::Reference(r1));
    root.set("Kept", Object::Reference(kept));
    w.set_root(root);
    let out = w.write().unwrap();

    let mut w = IncrementalWriter::new(read(&out));
    let mut obj = as_dict(w.get_object(r1).unwrap());
    obj.set("A", Object::Integer(2));
    w.update_object(r1, Object::Dictionary(obj));
    let out = w.write_in_place().unwrap();

    let r = read(&out);
    let xr = r.xrefs();
    assert!(xr
        .get_xref_data(0)
        .unwrap()
        .xrefs_in_objstm
        .contains_key(&r1.0));
    assert!(xr
        .get_xref_data(1)
        .unwrap()
        .standard_xrefs
        .contains_key(&r1.0));
    assert_last_change_matches_scan(xr);
    assert_eq!(xr.get_last_change(r1), Some(1));
    assert_eq!(xr.get_last_change(kept), Some(0));
    let direct = xr.get_xref_data(1).unwrap().standard_xrefs[&r1.0].1;
    let in_objstm = xr.get_xref_data(0).unwrap().xrefs_in_objstm[&kept.0];
    assert_eq!(xr.get(r1), Some(XRefLocation::Offset(direct)));
    assert_eq!(xr.get(kept), Some(XRefLocation::ObjStream(in_objstm)));
    assert_eq!(xr.get((r1.0, 1)), None);
}
