// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_content_stream_parser.py`
// (MIT, see LICENSE-pyHanko).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use hanko_pdf::content_stream_parser::{parse_content_stream, GraphicsOperator};
use hanko_pdf::generic::pdf_name;
use hanko_pdf::lopdf::{Dictionary, Object, ObjectId, StringFormat};
use hanko_pdf::{IncrementalWriter, PdfError};

/// `_wrap_as_streams`: add each part as a stream object of a writer.
fn wrap(data: &[&[u8]]) -> Vec<(ObjectId, Vec<u8>)> {
    let mut w = IncrementalWriter::new(read(&minimal()));
    data.iter()
        .map(|d| {
            let s = hanko_pdf::stream::encoded_stream(Dictionary::new(), d.to_vec());
            (w.add_object(s).unwrap(), d.to_vec())
        })
        .collect()
}

fn parse(data: &[&[u8]]) -> (Vec<ObjectId>, Result<Vec<GraphicsOperator>, PdfError>) {
    let parts = wrap(data);
    let refs = parts.iter().map(|p| p.0).collect();
    (refs, parse_content_stream(&parts))
}

fn nums(v: &[i64]) -> Vec<Object> {
    v.iter().map(|&n| Object::Integer(n)).collect()
}

#[test]
fn test_parse_simple_content_stream() {
    let d: &[u8] = b"q 1 0 0 -1 0 100 cm Q";
    let (refs, res) = parse(&[d]);
    let res = res.unwrap();
    let [push, cm, pop] = &res[..] else { panic!() };
    assert!(push.args.is_empty());
    assert_eq!(push.op, "q");
    assert_eq!(push.start, (refs[0], 0));
    assert_eq!(push.end, (refs[0], 1));
    assert!(pop.args.is_empty());
    assert_eq!(pop.op, "Q");
    assert_eq!(pop.start, (refs[0], d.len() - 1));
    assert_eq!(pop.end, (refs[0], d.len()));
    assert_eq!(cm.args, nums(&[1, 0, 0, -1, 0, 100]));
    assert_eq!(cm.op, "cm");
    assert_eq!(cm.start.1, 2);
    assert_eq!(cm.end.1, d.len() - 2);
}

#[test]
fn test_inline_image_fail_gracefully() {
    let (_, res) = parse(&[b"q 1 0 0 -1 0 100 cm BI ... EI"]);
    let e = assert_err_matches(res, "inline images");
    assert!(e.is_read_error());
}

#[test]
fn test_parse_split_content_stream() {
    let d2: &[u8] = b"1 0 0 -1 0 100 cm";
    let (refs, res) = parse(&[b"q", d2, b"Q"]);
    let res = res.unwrap();
    let [push, cm, pop] = &res[..] else { panic!() };
    assert!(push.args.is_empty());
    assert_eq!(push.op, "q");
    assert_eq!(push.start, (refs[0], 0));
    assert_eq!(push.end, (refs[0], 1));
    assert!(pop.args.is_empty());
    assert_eq!(pop.op, "Q");
    assert_eq!(pop.start, (refs[2], 0));
    assert_eq!(pop.end, (refs[2], 1));
    assert_eq!(cm.args, nums(&[1, 0, 0, -1, 0, 100]));
    assert_eq!(cm.start, (refs[1], 0));
    assert_eq!(cm.end, (refs[1], d2.len()));
}

#[test]
fn test_parse_unnaturally_split_content_stream() {
    let d2: &[u8] = b"0 -1 0 100 cm Q";
    let (refs, res) = parse(&[b"q 1 0", d2]);
    let res = res.unwrap();
    let cm = &res[1];
    assert_eq!(cm.args, nums(&[1, 0, 0, -1, 0, 100]));
    assert_eq!(cm.op, "cm");
    assert_eq!(cm.start, (refs[0], 2));
    assert_eq!(cm.end, (refs[1], d2.len() - 2));
}

#[test]
fn test_parse_content_stream_with_comments() {
    let cases: Vec<(Vec<&[u8]>, usize)> = vec![
        (vec![b"q %blah\n1 0 0 -1 0 100 cm Q"], 8),
        (vec![b"q %blah\n%foo bar baz\n1 0 0 -1 0 100 cm\nQ"], 21),
        (vec![b"q 1 0 0 -1 0 100 cm Q\n%end of stream comment"], 2),
        (
            vec![b"q %blah\n\r%foo bar baz\r\n1 0 0 -1 0 100 cm\r\nQ"],
            23,
        ),
        (vec![b"q %blah\n %foo bar baz\n 1 0 0 -1 0 100 cm\n Q"], 23),
        (vec![b"q %one", b"1 0 0 -1 0 100 cm %two", b"Q %three"], 0),
    ];
    for (ds, expected) in cases {
        let (_, res) = parse(&ds);
        let res = res.unwrap();
        assert_eq!(res.len(), 3);
        assert_eq!(res[1].args, nums(&[1, 0, 0, -1, 0, 100]));
        assert_eq!(res[1].op, "cm");
        assert_eq!(res[1].start.1, expected);
    }
}

fn dict(pairs: Vec<(&str, Object)>) -> Object {
    let mut d = Dictionary::new();
    for (k, v) in pairs {
        d.set(k, v);
    }
    Object::Dictionary(d)
}

#[test]
fn test_parse_dict_args() {
    let foo_quux = dict(vec![
        ("Foo", dict(vec![("Bar", pdf_name("Baz"))])),
        ("Quux", Object::Array(vec![Object::Integer(1)])),
    ]);
    let cases: Vec<(&[u8], Object)> = vec![
        (b"<<>> BDC EMC", dict(vec![])),
        (
            b"<</Foo /Bar>> BDC EMC",
            dict(vec![("Foo", pdf_name("Bar"))]),
        ),
        (
            b"q <</Foo /Bar>> BDC EMC Q",
            dict(vec![("Foo", pdf_name("Bar"))]),
        ),
        (
            b"q <</Foo <</Bar/Baz>> /Quux [1]>> BDC EMC Q",
            foo_quux.clone(),
        ),
        (
            b"q <</Foo<</Bar/Baz>>\n/Quux [1]>>\n BDC EMC Q",
            foo_quux.clone(),
        ),
        (
            b"q <</Foo<</Bar/Baz>> %with a comment\n/Quux [1]>>\n BDC EMC Q",
            foo_quux,
        ),
    ];
    for (d, expected) in cases {
        let (_, res) = parse(&[d]);
        let res = res.unwrap();
        let bdc = res.iter().find(|r| r.op == "BDC").unwrap();
        assert_eq!(bdc.args, vec![expected]);
    }
}

#[test]
fn test_parse_arr_args() {
    let s = |t: &str| Object::String(t.as_bytes().to_vec(), StringFormat::Literal);
    let fbb = Object::Array(vec![s("foo"), 100.into(), s("bar"), (-20).into(), s("baz")]);
    let cases: Vec<(&[u8], Object)> = vec![
        (b"[] TJ", Object::Array(vec![])),
        (
            b"[null null] TJ",
            Object::Array(vec![Object::Null, Object::Null]),
        ),
        (b"[(foo) 100 (bar) -20 (baz)] TJ", fbb.clone()),
        (b"BT [(foo) 100 (bar) -20 (baz)] TJ ET", fbb.clone()),
        (b"[(foo)\n100\n(bar)\n-20 (baz)] TJ", fbb.clone()),
        (b"[(foo) %with comment\n100\n(bar)\n-20 (baz)] TJ", fbb),
    ];
    for (d, expected) in cases {
        let (_, res) = parse(&[d]);
        let res = res.unwrap();
        let tj = res.iter().find(|r| r.op == "TJ").unwrap();
        assert_eq!(tj.args, vec![expected]);
    }
}

#[test]
fn test_bad_tokens_for_content_streams() {
    for d in [
        &b"<</Foo 1 0 R /Bar 0>> BDC"[..],
        b"<</Foo op /Bar 0>> BDC",
        b"[1 0 R] TJ",
        b"[op] TJ",
        b"1 0 R BDC",
        b"b\xe3\x83\x90\xe3\x82\xb0z BDC",
    ] {
        let (_, res) = parse(&[d]);
        assert!(res.unwrap_err().is_read_error(), "{d:?}");
    }
}
