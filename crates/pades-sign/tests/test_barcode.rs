//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_barcode.py`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use lopdf::{dictionary, Object, Stream};
use sigis_pades_sign::barcodes::BarcodeBox;
use sigis_pades_sign::content::{add_stream_to_page, ContentWriter, PdfContent};
use sigis_pades_sign::layout::BoxConstraints;
use sigis_pades_sign::pdf::writer::PdfUpdate;
use sigis_pades_sign::stamp::{CoordinateSystem, QrStampStyle, Stamp};
use support::layout::compare_output;
use support::*;

#[test]
fn test_qr_fixed_size() {
    let base = pdf("minimal.pdf");
    let mut update = PdfUpdate::new(&base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    let mut qr = Stamp::qr(
        QrStampStyle::default(),
        "https://example.com",
        Some(BoxConstraints::fixed(280.0, 60.0)),
        None,
    );
    qr.time = Some(at("2020-11-01T00:00:00+00:00"));
    qr.as_form_xobject(&mut w).unwrap();
    qr.apply(&mut w, 0, 10.0, 10.0, CoordinateSystem::PageDefault)
        .unwrap();
    assert_eq!(qr.text_box().unwrap().bbox().width().unwrap(), 224.0);
}

#[test]
fn test_code128_render() {
    let base = pdf("minimal.pdf");
    let mut update = PdfUpdate::new(&base).unwrap();
    let mut w = ContentWriter::new(&mut update);
    let mut bb = BarcodeBox::new("code128", "this is a test").unwrap();
    let xobj = bb.as_form_xobject(&mut w).unwrap();
    let xobj_ref = w.add(Object::Stream(xobj));
    let wrapper = w.add(Object::Stream(Stream::new(
        dictionary! {},
        b"q 1 0 0 1 50 50 cm /Barcode Do Q".to_vec(),
    )));
    let res = dictionary! { "XObject" => dictionary! { "Barcode" => xobj_ref } };
    add_stream_to_page(w.update(), 0, wrapper, Some(res), false).unwrap();
    let out = w.write().unwrap();
    compare_output(&out, "code128-test.pdf");
}
