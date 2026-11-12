// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_decode_limits.py`
// (MIT, see LICENSE-pyHanko). One Rust test per upstream test function;
// parametrized cases run in a loop.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;

use common::*;
use sigis_pdf::decode_limits::{
    default_purpose_limits, DecodeContext, DecodeLimits, DecodePurpose, DocumentDecodeBudget,
    StreamDecodeLimits,
};
use sigis_pdf::filters::{bounded_decompress, flate_compress, Decoder};
use sigis_pdf::lopdf::{Dictionary, Object, Stream};
use sigis_pdf::stream::{encoded_stream, no_deref, DecodedStream};
use sigis_pdf::xref::{expected_xref_stream_size_of, parse_xref_stream};
use sigis_pdf::{
    IncrementalWriter, PdfError, PdfFile, PdfFileWriter, PdfHandler, PdfHandlerExt, ReaderOptions,
};

const MIB: u64 = 1024 * 1024;

fn unlimited_stream() -> StreamDecodeLimits {
    StreamDecodeLimits {
        max_ratio: None,
        ratio_floor: MIB,
        max_output_size: None,
    }
}

fn make_stream(encoded: Vec<u8>, filters: &[&str], extra: &[(&str, Object)]) -> Object {
    let mut d = Dictionary::new();
    d.set(
        "Filter",
        Object::Array(
            filters
                .iter()
                .map(|f| sigis_pdf::generic::pdf_name(f))
                .collect(),
        ),
    );
    for (k, v) in extra {
        d.set(*k, v.clone());
    }
    encoded_stream(d, encoded)
}

fn pdf_with_streams(streams: Vec<Object>) -> (Vec<u8>, Vec<u32>) {
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let ids = streams
        .into_iter()
        .map(|s| w.add_object(s).unwrap().0)
        .collect();
    (w.write().unwrap(), ids)
}

fn flate_pdf(payload: &[u8]) -> (Vec<u8>, u32) {
    let (out, ids) = pdf_with_streams(vec![make_stream(
        flate_compress(payload),
        &["FlateDecode"],
        &[],
    )]);
    (out, ids[0])
}

fn open(data: &[u8], limits: Option<DecodeLimits>) -> PdfFile {
    PdfFile::parse_with(
        data,
        ReaderOptions {
            strict: true,
            decode_limits: limits.unwrap_or_default(),
            ..Default::default()
        },
    )
    .unwrap()
}

fn stream_of(h: &dyn PdfHandler, idnum: u32) -> Stream {
    match h.get_object((idnum, 0)).unwrap() {
        Object::Stream(s) => s,
        other => panic!("{other:?}"),
    }
}

fn data_of(h: &dyn PdfHandler, idnum: u32) -> Result<Vec<u8>, PdfError> {
    h.stream_data(&stream_of(h, idnum))
}

fn tiny_limit(purpose: DecodePurpose) -> DecodeLimits {
    DecodeLimits {
        per_purpose: BTreeMap::from([(
            purpose,
            StreamDecodeLimits {
                max_ratio: None,
                ratio_floor: MIB,
                max_output_size: Some(10),
            },
        )]),
        ..DecodeLimits::default()
    }
}

fn budget_limits(base_allowance: u64) -> DecodeLimits {
    DecodeLimits {
        document_budget: Some(DocumentDecodeBudget {
            base_allowance,
            max_ratio: 0.0,
        }),
        ..DecodeLimits::default()
    }
}

fn stacked_bomb() -> Vec<u8> {
    use std::io::Write;
    let level9 = |d: &[u8]| {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(9));
        e.write_all(d).unwrap();
        e.finish().unwrap()
    };
    level9(&level9(&vec![0u8; 50 * MIB as usize]))
}

fn is_limit(e: &PdfError) -> bool {
    matches!(e, PdfError::DecodeLimit(_))
}

#[test]
fn test_output_cap() {
    for (limits, size, expected) in [
        (StreamDecodeLimits::default(), 10, Some(MIB)),
        (StreamDecodeLimits::default(), 100_000, Some(110_000_000)),
        (
            StreamDecodeLimits {
                max_output_size: Some(5 * MIB),
                ..Default::default()
            },
            10 * MIB,
            Some(5 * MIB),
        ),
        (
            StreamDecodeLimits {
                max_ratio: None,
                ..Default::default()
            },
            10,
            Some(256 * MIB),
        ),
        (
            StreamDecodeLimits {
                max_output_size: None,
                ..Default::default()
            },
            10,
            Some(MIB),
        ),
        (unlimited_stream(), 10, None),
    ] {
        assert_eq!(limits.output_cap(size), expected);
    }
}

#[test]
fn test_stream_output_cap() {
    let d = DecodeLimits::default;
    let cases: Vec<(DecodeLimits, DecodePurpose, Option<i64>, Option<u64>)> = vec![
        (d(), DecodePurpose::Certificate, None, Some(MIB)),
        (d(), DecodePurpose::OcspResponse, None, Some(4 * MIB)),
        (d(), DecodePurpose::ObjectStream, None, Some(64 * MIB)),
        (d(), DecodePurpose::Crl, None, Some(50_000_000)),
        (d(), DecodePurpose::Generic, None, Some(256 * MIB)),
        (d(), DecodePurpose::XrefStream, None, Some(256 * MIB)),
        (
            DecodeLimits::for_untrusted_input(),
            DecodePurpose::Generic,
            Some(100),
            Some(4196),
        ),
        (d(), DecodePurpose::Generic, Some(-50), Some(4096)),
        (
            DecodeLimits::for_trusted_input(),
            DecodePurpose::Generic,
            Some(100),
            None,
        ),
        (
            DecodeLimits {
                per_stream: StreamDecodeLimits {
                    max_ratio: None,
                    ratio_floor: MIB,
                    max_output_size: Some(1000),
                },
                per_purpose: BTreeMap::from([(DecodePurpose::Certificate, unlimited_stream())]),
                ..DecodeLimits::default()
            },
            DecodePurpose::Certificate,
            None,
            Some(1000),
        ),
    ];
    for (limits, purpose, expected_size, expected) in cases {
        let ctx = DecodeContext::new(limits, None);
        assert_eq!(
            ctx.stream_output_cap(1_000_000, purpose, expected_size),
            expected
        );
    }
}

#[test]
fn test_budget_total() {
    let b = |a, r| DocumentDecodeBudget {
        base_allowance: a,
        max_ratio: r,
    };
    for (budget, size, expected) in [
        (b(1000, 10.0), 5, 1000),
        (b(1000, 10.0), 100, 1000),
        (b(1000, 10.0), 500, 5000),
        (b(1000, 0.5), 5001, 2500),
        (DocumentDecodeBudget::default(), 0, 256 * MIB),
        (DocumentDecodeBudget::default(), 10 * MIB, 1000 * MIB),
    ] {
        assert_eq!(budget.total(size), expected);
    }
}

#[test]
fn test_context_without_budget() {
    let no_budget = || DecodeLimits {
        document_budget: None,
        ..DecodeLimits::default()
    };
    for (limits, input_size) in [
        (DecodeLimits::default(), None),
        (no_budget(), Some(1000)),
        (no_budget(), None),
    ] {
        let mut ctx = DecodeContext::new(limits, input_size);
        assert_eq!(ctx.remaining_budget(), None);
        assert_eq!(ctx.stage_output_cap(Some(123)), Some(123));
        assert_eq!(ctx.stage_output_cap(None), None);
        ctx.record_output(1_000_000_000);
        assert_eq!(ctx.remaining_budget(), None);
    }
}

#[test]
fn test_context_stage_cap() {
    for (cap, expected) in [
        (None, 1000),
        (Some(500), 500),
        (Some(1000), 1000),
        (Some(5000), 1000),
    ] {
        let ctx = DecodeContext::new(budget_limits(1000), Some(10));
        assert_eq!(ctx.stage_output_cap(cap), Some(expected));
    }
}

#[test]
fn test_context_record_output() {
    let mut ctx = DecodeContext::new(budget_limits(1000), Some(10));
    ctx.record_output(300);
    assert_eq!(ctx.remaining_budget(), Some(700));
    assert_eq!(ctx.stage_output_cap(Some(800)), Some(700));
    assert_eq!(ctx.stage_output_cap(Some(100)), Some(100));
}

#[test]
fn test_flate_cap_boundary() {
    for (size, fails) in [(1000usize, false), (1001, true)] {
        let encoded = flate_compress(&vec![0u8; size]);
        let res = Decoder::Flate.decode_bounded(&encoded, None, Some(1000), &no_deref);
        if fails {
            let e = assert_err_matches(res, "limit of 1000 bytes");
            assert!(is_limit(&e));
        } else {
            assert_eq!(res.unwrap().len(), size);
        }
    }
}

#[test]
fn test_flate_truncated() {
    for cap in [None, Some(10 * MIB)] {
        let encoded = flate_compress(&[0u8; 1000]);
        let encoded = &encoded[..encoded.len() - 6];
        // zlib.error in pyHanko
        assert!(bounded_decompress(encoded, cap)
            .unwrap_err()
            .is_stream_error());
    }
}

const PNG_UP_ROWS: &[u8] = b"\x02\x01\x02\x03\x02\x04\x05\x06";

#[test]
fn test_flate_decode_params() {
    let mut png = Dictionary::new();
    png.set("Predictor", Object::Integer(12));
    png.set("Columns", Object::Integer(3));
    let cases: Vec<(Option<Dictionary>, &[u8])> = vec![
        (None, PNG_UP_ROWS),
        (Some(Dictionary::new()), PNG_UP_ROWS),
        // [None] (not a dictionary) is equivalent to no parameters
        (None, PNG_UP_ROWS),
        (Some(png), b"\x01\x02\x03\x05\x07\x09"),
    ];
    for (params, expected) in cases {
        for cap in [None, Some(MIB)] {
            let encoded = flate_compress(PNG_UP_ROWS);
            let out = Decoder::Flate
                .decode_bounded(&encoded, params.as_ref(), cap, &no_deref)
                .unwrap();
            assert_eq!(out, expected);
        }
    }
}

#[test]
fn test_flate_unsupported_predictor() {
    let mut p = Dictionary::new();
    p.set("Predictor", Object::Integer(2));
    p.set("Columns", Object::Integer(3));
    let e = Decoder::Flate
        .decode(&flate_compress(b"abc"), Some(&p), &no_deref)
        .unwrap_err();
    assert!(matches!(e, PdfError::NotImplemented(_)));
}

#[test]
fn test_default_decode_bounded() {
    let encoded = b"48656c6c6f>";
    assert_eq!(
        Decoder::AsciiHex
            .decode_bounded(encoded, None, Some(5), &no_deref)
            .unwrap(),
        b"Hello"
    );
    assert_eq!(
        Decoder::AsciiHex
            .decode_bounded(encoded, None, None, &no_deref)
            .unwrap(),
        b"Hello"
    );
    assert!(is_limit(
        &Decoder::AsciiHex
            .decode_bounded(encoded, None, Some(4), &no_deref)
            .unwrap_err()
    ));
}

#[test]
fn test_limit_error_is_read_error() {
    let e = PdfError::DecodeLimit("x".into());
    assert!(e.is_read_error());
    assert!(e.is_stream_error());
}

#[test]
fn test_stacked_bomb() {
    let bomb = stacked_bomb();
    for (limits, rejected) in [
        (None, true),
        (Some(DecodeLimits::for_trusted_input()), false),
    ] {
        let (out, ids) = pdf_with_streams(vec![make_stream(
            bomb.clone(),
            &["FlateDecode", "FlateDecode"],
            &[],
        )]);
        let r = open(&out, limits);
        if rejected {
            let e = assert_err_matches(data_of(&r, ids[0]), "exceeds the limit");
            assert!(is_limit(&e));
        } else {
            assert_eq!(data_of(&r, ids[0]).unwrap().len() as u64, 50 * MIB);
            assert_eq!(r.decode_context().remaining_budget(), None);
        }
    }
}

#[test]
fn test_single_layer_flate_not_rejected() {
    let size = 20 * MIB as usize;
    let (out, id) = flate_pdf(&vec![0u8; size]);
    assert_eq!(data_of(&open(&out, None), id).unwrap().len(), size);
}

#[test]
fn test_default_context_without_reader() {
    // detached / unbound streams use the default limits
    let Object::Stream(s) = make_stream(stacked_bomb(), &["FlateDecode", "FlateDecode"], &[])
    else {
        panic!()
    };
    assert!(is_limit(&DecodedStream::from_stream(&s).unwrap_err()));
    // ... as do streams of a writer
    let w = PdfFileWriter::new(true, true).unwrap();
    assert!(is_limit(&w.stream_data(&s).unwrap_err()));
}

#[test]
fn test_read_data_purpose() {
    let big = vec![0u8; 2 * MIB as usize];
    let mut overridden = default_purpose_limits();
    overridden.insert(DecodePurpose::Certificate, unlimited_stream());
    for (limits, purpose, rejected) in [
        (None, DecodePurpose::Certificate, true),
        (None, DecodePurpose::Generic, false),
        (
            Some(DecodeLimits {
                per_purpose: overridden.clone(),
                ..DecodeLimits::default()
            }),
            DecodePurpose::Certificate,
            false,
        ),
    ] {
        let (out, id) = flate_pdf(&big);
        let r = open(&out, limits);
        let s = stream_of(&r, id);
        let res = r.read_stream_data(&s, purpose, None);
        if rejected {
            assert!(is_limit(&res.unwrap_err()));
        } else {
            assert_eq!(res.unwrap(), big);
        }
    }
}

#[test]
fn test_cached_data_ignores_later_stricter_limits() {
    let big = vec![0u8; 2 * MIB as usize];
    let (out, id) = flate_pdf(&big);
    let r = open(&out, None);
    assert_eq!(data_of(&r, id).unwrap(), big);
    let s = stream_of(&r, id);
    assert_eq!(
        r.read_stream_data(&s, DecodePurpose::Certificate, None)
            .unwrap(),
        big
    );
}

fn read_objstm(limits: Option<DecodeLimits>) -> Result<(), PdfError> {
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let stm = w.prepare_object_stream(true).unwrap();
    let mut d = Dictionary::new();
    d.set("Foo", Object::Integer(7));
    let id = w
        .add_object_ext(Object::Dictionary(d), Some(stm), None)
        .unwrap();
    let r = open(&w.write().unwrap(), limits);
    let d = as_dict(r.get_object(id)?);
    assert_eq!(get(&r, &d, "Foo"), Object::Integer(7));
    Ok(())
}

fn read_dss(limits: Option<DecodeLimits>) -> Result<(), PdfError> {
    let cert_der = sigis_testdata::read(&["pyhanko-certvalidator", "self-signed-with-policy.crt"]);
    let mut w = PdfFileWriter::new(true, true).unwrap();
    let cert_ref = w
        .add_object(make_stream(
            flate_compress(&cert_der),
            &["FlateDecode"],
            &[],
        ))
        .unwrap();
    let mut dss = Dictionary::new();
    dss.set("Certs", Object::Array(vec![Object::Reference(cert_ref)]));
    let dss_ref = w.add_object(Object::Dictionary(dss)).unwrap();
    let mut root = w.root().unwrap();
    root.set("DSS", Object::Reference(dss_ref));
    w.set_root(root);
    let r = open(&w.write().unwrap(), limits);
    let dss = sigis_pdf::signatures::read_dss(&r)?.unwrap();
    assert_eq!(dss.material.certs.len(), 1);
    Ok(())
}

const EMPTY_XMP: &[u8] = b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF></x:xmpmeta>";

fn read_xmp(limits: Option<DecodeLimits>) -> Result<(), PdfError> {
    let (out, ids) = pdf_with_streams(vec![make_stream(
        flate_compress(EMPTY_XMP),
        &["FlateDecode"],
        &[
            ("Type", sigis_pdf::generic::pdf_name("Metadata")),
            ("Subtype", sigis_pdf::generic::pdf_name("XML")),
        ],
    )]);
    let r = open(&out, limits);
    let xmp = sigis_pdf::metadata::xmp_xml::stream_xmp(&r, &stream_of(&r, ids[0]))?;
    assert!(xmp.is_empty());
    Ok(())
}

#[test]
fn test_purpose_applied() {
    read_xmp(None).unwrap();
    assert!(is_limit(
        &read_xmp(Some(tiny_limit(DecodePurpose::XmpMetadata))).unwrap_err()
    ));
    read_objstm(None).unwrap();
    assert!(is_limit(
        &read_objstm(Some(tiny_limit(DecodePurpose::ObjectStream))).unwrap_err()
    ));
    read_dss(None).unwrap();
    assert!(is_limit(
        &read_dss(Some(tiny_limit(DecodePurpose::Certificate))).unwrap_err()
    ));
}

fn ints(v: &[i64]) -> Object {
    Object::Array(v.iter().map(|&i| Object::Integer(i)).collect())
}

#[test]
fn test_expected_xref_stream_size() {
    let w = ints(&[1, 2, 1]);
    assert_eq!(
        expected_xref_stream_size_of(&ints(&[0, 3, 10, 2]), Some(&w)),
        Some(25)
    );
    assert_eq!(
        expected_xref_stream_size_of(&Object::Array(vec![0.into(), Object::Null]), Some(&w)),
        None
    );
    assert_eq!(
        expected_xref_stream_size_of(&ints(&[0, 3, 10]), Some(&w)),
        None
    );
    assert_eq!(expected_xref_stream_size_of(&ints(&[0, 3]), None), None);
}

#[test]
fn test_parse_xref_stream_expected_size() {
    for (padding, fails) in [(0usize, false), (3 * 5 + 4096, true)] {
        let mut data = b"\x01\x00\x10\x00".repeat(3);
        data.extend(vec![0u8; padding]);
        let mut d = Dictionary::new();
        d.set(
            "Filter",
            Object::Array(vec![sigis_pdf::generic::pdf_name("FlateDecode")]),
        );
        d.set("W", ints(&[1, 2, 1]));
        d.set("Size", Object::Integer(3));
        let res = parse_xref_stream(
            &d,
            &flate_compress(&data),
            &mut DecodeContext::default(),
            true,
        );
        if fails {
            assert!(is_limit(&res.unwrap_err()));
        } else {
            assert_eq!(res.unwrap().len(), 3);
        }
    }
}

#[test]
fn test_budget_exhausted() {
    let payload = make_stream(
        flate_compress(&vec![0u8; MIB as usize]),
        &["FlateDecode"],
        &[],
    );
    let (out, ids) = pdf_with_streams(vec![payload; 4]);
    let r = open(&out, Some(budget_limits(3 * MIB + 100)));
    let start = r.decode_context().remaining_budget().unwrap();
    assert!(start <= (3 * MIB + 100) as i64);
    for (n, id) in ids[..3].iter().enumerate() {
        assert_eq!(data_of(&r, *id).unwrap().len() as u64, MIB);
        assert_eq!(
            r.decode_context().remaining_budget().unwrap(),
            start - (n as i64 + 1) * MIB as i64
        );
    }
    assert!(is_limit(&data_of(&r, ids[3]).unwrap_err()));
}

#[test]
fn test_budget_redecode_not_charged() {
    let (out, id) = flate_pdf(&vec![0u8; MIB as usize]);
    let r = open(&out, Some(budget_limits(2 * MIB)));
    let start = r.decode_context().remaining_budget().unwrap();
    assert_eq!(data_of(&r, id).unwrap().len() as u64, MIB);
    assert_eq!(data_of(&r, id).unwrap().len() as u64, MIB);
    assert_eq!(
        r.decode_context().remaining_budget().unwrap(),
        start - MIB as i64
    );
}

#[test]
fn test_budget_charges_every_stage() {
    let compressed = flate_compress(&vec![0u8; MIB as usize]);
    let mut hex: Vec<u8> = compressed
        .iter()
        .flat_map(|b| format!("{b:02x}").into_bytes())
        .collect();
    hex.push(b'>');
    let (out, ids) = pdf_with_streams(vec![make_stream(
        hex,
        &["ASCIIHexDecode", "FlateDecode"],
        &[],
    )]);
    let r = open(&out, Some(budget_limits(4 * MIB)));
    let start = r.decode_context().remaining_budget().unwrap();
    assert_eq!(data_of(&r, ids[0]).unwrap(), vec![0u8; MIB as usize]);
    assert_eq!(
        r.decode_context().remaining_budget().unwrap(),
        start - compressed.len() as i64 - MIB as i64
    );
}

#[test]
fn test_budget_fresh_for_historical_revisions() {
    let old_raw = vec![0u8; MIB as usize];
    let new_raw = vec![1u8; 2 * MIB as usize];
    let (out, id) = flate_pdf(&old_raw);
    let mut w = IncrementalWriter::new(open(&out, None));
    w.update_object(
        (id, 0),
        make_stream(flate_compress(&new_raw), &["FlateDecode"], &[]),
    );
    let out = w.write().unwrap();
    let r = open(&out, Some(budget_limits(10 * MIB)));
    let start = r.decode_context().remaining_budget().unwrap();
    assert_eq!(data_of(&r, id).unwrap(), new_raw);
    assert_eq!(
        r.decode_context().remaining_budget().unwrap(),
        start - 2 * MIB as i64
    );
    let hist = r.historical_resolver(0);
    assert_eq!(hist.decode_context().limits, r.decode_context().limits);
    assert_eq!(
        hist.decode_context().remaining_budget().unwrap(),
        10 * MIB as i64
    );
    assert_eq!(data_of(&hist, id).unwrap(), old_raw);
    assert_eq!(
        hist.decode_context().remaining_budget().unwrap(),
        9 * MIB as i64
    );
    assert_eq!(
        r.decode_context().remaining_budget().unwrap(),
        start - 2 * MIB as i64
    );
}

#[test]
fn test_historical_budget_enforced() {
    let (out, id) = flate_pdf(&vec![0u8; 2 * MIB as usize]);
    let mut w = IncrementalWriter::new(open(&out, None));
    w.update_object((id, 0), make_stream(b"x".to_vec(), &[], &[]));
    let out = w.write().unwrap();
    let r = open(&out, Some(budget_limits(MIB)));
    assert_eq!(data_of(&r, id).unwrap(), b"x");
    let hist = r.historical_resolver(0);
    assert!(r.historical_resolver(0).same_view(&hist));
    assert!(is_limit(&data_of(&hist, id).unwrap_err()));
}

/// `minimal_with_oversized_objstm` from pyhanko_testing_commons.
fn oversized_pdf() -> Vec<u8> {
    let r = open(&minimal(), None);
    let mut w = sigis_pdf::writer::copy_into_new_writer_with(&r, true).unwrap();
    let stm = w.prepare_object_stream(true).unwrap();
    let ids: Vec<(u16, u32)> = w.objects().keys().copied().collect();
    for (gen, idnum) in ids {
        if !matches!(w.objects()[&(gen, idnum)], Object::Stream(_)) {
            w.move_to_object_stream((idnum, gen), stm).unwrap();
        }
    }
    w.add_object_ext(
        sigis_pdf::generic::byte_string(vec![0u8; 3 * MIB as usize]),
        Some(stm),
        None,
    )
    .unwrap();
    w.write().unwrap()
}

#[test]
fn test_oversized_objstm_rejected_by_default() {
    let data = oversized_pdf();
    let r = open(&data, None);
    assert!(is_limit(&r.root().unwrap_err()));
    // and accepted for trusted input
    let r = open(&data, Some(DecodeLimits::for_trusted_input()));
    r.root().unwrap();
}
