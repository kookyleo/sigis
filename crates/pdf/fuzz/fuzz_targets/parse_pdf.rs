// Fuzz target: parse a whole PDF (strict and lenient) and exercise the
// reader: revisions, objects of every revision, signatures, DSS, metadata.
#![no_main]

use sigis_pdf::lopdf::Object;
use sigis_pdf::{PdfFile, PdfHandler, PdfHandlerExt, ReaderOptions};
use libfuzzer_sys::fuzz_target;

fn exercise(f: &PdfFile) {
    let _ = f.revisions();
    let _ = f.root();
    let _ = f.embedded_signatures();
    let _ = f.dss();
    let _ = f.document_meta_view();
    let _ = f.input_version();
    let n = f.total_revisions().min(8);
    for rev in 0..n {
        let _ = f.trailer_in_revision(rev);
        let Ok(ids) = f.objects_written_in(rev) else { continue };
        let hist = f.historical_resolver(rev);
        for id in ids.into_iter().take(64) {
            let _ = f.object_in_revision(id, rev);
            if let Ok(Object::Stream(s)) = hist.get_object(id) {
                let _ = hist.stream_data(&s);
            }
        }
        let _ = hist.document_meta_view();
    }
    if n > 0 {
        let hist = f.historical_resolver(n - 1);
        let _ = hist.reverse_xref_cache();
    }
    let _ = f.find_page_for_modification(0);
}

fuzz_target!(|data: &[u8]| {
    for opts in [ReaderOptions::default(), ReaderOptions::lenient()] {
        if let Ok(f) = PdfFile::parse_with(data, opts) {
            exercise(&f);
        }
    }
});
