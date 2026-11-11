// Fuzz target: incremental writer round trip. If a file parses in strict
// mode and an update can be written, the result must parse in strict mode,
// keep the original bytes as a prefix, add one revision and resolve the new
// object.
#![no_main]

use hanko_pdf::generic::text_string;
use hanko_pdf::{IncrementalWriter, PdfFile, PdfHandler, ReaderOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(f) = PdfFile::parse_with(data, ReaderOptions::default()) else { return };
    if f.encrypted() {
        return;
    }
    let revs = f.total_revisions();
    let mut w = IncrementalWriter::new(f);
    w.update_meta_on_write = false;
    let Ok(id) = w.add_object(text_string("fuzz")) else { return };
    let Ok(out) = w.write_in_place() else { return };
    assert!(out.starts_with(data));
    let r = PdfFile::parse_with(&out, ReaderOptions::default());
    let r = match r {
        Ok(r) => r,
        Err(e) => panic!("round trip does not parse: {e:?}"),
    };
    assert_eq!(r.total_revisions(), revs + 1);
    assert_eq!(r.get_object(id).ok(), Some(text_string("fuzz")));
});
