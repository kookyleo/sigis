// Fuzz target: object stream decoding. The fuzz input becomes the
// (uncompressed) content of an object stream in an otherwise valid file.
#![no_main]

use hanko_pdf::lopdf::{Dictionary, Object};
use hanko_pdf::{PdfFile, PdfFileWriter, PdfHandler, ReaderOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (n, first) = (i64::from(data[0] % 16), i64::from(data[1]));
    let Ok(mut w) = PdfFileWriter::new(true, true) else { return };
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"ObjStm".to_vec()));
    d.set("N", Object::Integer(n));
    d.set("First", Object::Integer(first));
    let s = hanko_pdf::stream::encoded_stream(d, data[2..].to_vec());
    let Ok(stm) = w.add_object(s) else { return };
    // xref stream entries pointing into the object stream
    let Ok(out) = w.write() else { return };
    for opts in [ReaderOptions::default(), ReaderOptions::lenient()] {
        if let Ok(f) = PdfFile::parse_with(&out, opts) {
            let _ = f.get_object(stm);
        }
    }
    // also read objects through a hand-made xref stream
    let mut pdf = b"%PDF-1.7\n".to_vec();
    let objstm_off = pdf.len();
    pdf.extend_from_slice(format!("1 0 obj\n<</Type/ObjStm/N {n}/First {first}/Length {}>>\nstream\n", data.len() - 2).as_bytes());
    pdf.extend_from_slice(&data[2..]);
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
    pdf.extend_from_slice(format!("\nendstream\nendobj\nstartxref\n{xref_off}\n%%EOF\n").as_bytes());
    for opts in [ReaderOptions::default(), ReaderOptions::lenient()] {
        if let Ok(f) = PdfFile::parse_with(&pdf, opts) {
            for i in 2..(2 + n as u32) {
                let _ = f.get_object((i, 0));
            }
        }
    }
});
