// Fuzz target: the object parser (regular and content stream modes) and
// the content stream operator parser.
#![no_main]

use sigis_pdf::content_stream_parser::parse_content_stream;
use sigis_pdf::generic::{read_item, read_object, ContentOpReading, ParseContext};
use sigis_pdf::misc::Cursor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for strict in [true, false] {
        let ctx = ParseContext {
            strict,
            length_resolver: None,
        };
        let mut c = Cursor::new(data);
        if let Ok(o) = read_object(&mut c, &ctx) {
            let bytes = sigis_pdf::generic::object_to_bytes(&o);
            // serialised objects must parse again
            let again = read_object(&mut Cursor::new(&bytes), &ctx);
            assert!(again.is_ok(), "reparse failed: {again:?}");
        }
        let _ = read_item(&mut Cursor::new(data), &ctx, ContentOpReading::GraphicOps);
    }
    let _ = parse_content_stream(&[((1, 0), data.to_vec())]);
});
