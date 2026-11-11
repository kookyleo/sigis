// Fuzz target: XMP parsing; parsed XMP must survive serialisation.
#![no_main]

use hanko_pdf::metadata::xmp_xml::{meta_from_xmp, parse_xmp, serialise_xmp};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(roots) = parse_xmp(data) {
        let _ = meta_from_xmp(&roots);
        let out = serialise_xmp(&roots);
        let again = parse_xmp(&out);
        assert!(again.is_ok(), "reparse failed: {again:?}");
    }
});
