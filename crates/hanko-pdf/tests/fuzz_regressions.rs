// Replays inputs that once made a fuzz target (crates/hanko-pdf/fuzz) fail.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hanko_pdf::generic::{object_to_bytes, read_object, text_string, ParseContext};
use hanko_pdf::misc::Cursor;
use hanko_pdf::{IncrementalWriter, PdfFile, PdfHandler, ReaderOptions};

fn data(name: &str) -> Vec<u8> {
    hanko_testdata::read(&["lanes", "b", "fuzz-regressions", name])
}

#[test]
fn large_real_reparses() {
    let d = data("parse_object-large-real");
    let ctx = ParseContext::default();
    let o = read_object(&mut Cursor::new(&d), &ctx).unwrap();
    let bytes = object_to_bytes(&o);
    assert_eq!(read_object(&mut Cursor::new(&bytes), &ctx).unwrap(), o);
}

#[test]
fn object_stream_offset_overflow_is_an_error() {
    let d = data("object_stream-offset-overflow");
    // same construction as the object_stream fuzz target
    let (n, first) = (i64::from(d[0] % 16), i64::from(d[1]));
    let mut pdf = b"%PDF-1.7\n".to_vec();
    let objstm_off = pdf.len();
    pdf.extend_from_slice(
        format!(
            "1 0 obj\n<</Type/ObjStm/N {n}/First {first}/Length {}>>\nstream\n",
            d.len() - 2
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(&d[2..]);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    let xref_off = pdf.len();
    let mut entries = vec![0u8, 0, 0, 0, 0xff];
    entries.extend_from_slice(&[1, (objstm_off >> 8) as u8, objstm_off as u8, 0, 0]);
    for i in 0..n {
        entries.extend_from_slice(&[2, 0, 1, 0, i as u8]);
    }
    entries.extend_from_slice(&[1, (xref_off >> 8) as u8, xref_off as u8, 0, 0]);
    let size = n + 3;
    pdf.extend_from_slice(
        format!(
            "{} 0 obj\n<</Type/XRef/Size {size}/W[1 2 2]/Root 2 0 R/Length {}>>\nstream\n",
            size - 1,
            entries.len()
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(&entries);
    pdf.extend_from_slice(
        format!("\nendstream\nendobj\nstartxref\n{xref_off}\n%%EOF\n").as_bytes(),
    );
    for opts in [ReaderOptions::default(), ReaderOptions::lenient()] {
        if let Ok(f) = PdfFile::parse_with(&pdf, opts) {
            for i in 2..(2 + n as u32) {
                let _ = f.get_object((i, 0));
            }
        }
    }
}

#[test]
fn update_does_not_clobber_uncovered_xref_stream() {
    let d = data("incremental_roundtrip-size-below-xref-stream.pdf");
    let f = PdfFile::parse_with(&d, ReaderOptions::default()).unwrap();
    let revs = f.total_revisions();
    let mut w = IncrementalWriter::new(f);
    w.update_meta_on_write = false;
    let id = w.add_object(text_string("fuzz")).unwrap();
    let out = w.write_in_place().unwrap();
    let r = PdfFile::parse_with(&out, ReaderOptions::default()).unwrap();
    assert_eq!(r.total_revisions(), revs + 1);
    assert_eq!(r.get_object(id).unwrap(), text_string("fuzz"));
}

#[test]
fn update_rewriting_xref_stream_number_is_rejected_on_read() {
    // the catalog shares object number 2 with the xref stream; upgrading the
    // header version rewrites the catalog, which clobbers the xref stream
    // number: pyHanko writes this and its strict reader rejects the result
    let d = data("incremental_roundtrip-clobber2.pdf");
    let f = PdfFile::parse_with(&d, ReaderOptions::default()).unwrap();
    assert!(f.xrefs().xref_stream_refs.contains(&f.root_ref().unwrap()));
    let mut w = IncrementalWriter::new(f);
    w.update_meta_on_write = false;
    w.add_object(text_string("fuzz")).unwrap();
    let out = w.write_in_place().unwrap();
    let e = PdfFile::parse_with(&out, ReaderOptions::default()).unwrap_err();
    assert!(e.message().contains("must not be clobbered"), "{e:?}");
}
