// Fuzz target: xref table and xref stream entry parsing.
#![no_main]

use sigis_pdf::decode_limits::DecodeContext;
use sigis_pdf::lopdf::{Dictionary, Object};
use sigis_pdf::misc::Cursor;
use sigis_pdf::xref::{parse_xref_stream, parse_xref_table};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }
    let w: Vec<Object> = data[..3].iter().map(|&b| Object::Integer(i64::from(b % 12))).collect();
    let start = i64::from(data[3]);
    let size = i64::from(u16::from_be_bytes([data[4], data[5]]));
    let mut d = Dictionary::new();
    d.set("W", Object::Array(w));
    d.set("Size", Object::Integer(start + size));
    d.set("Index", Object::Array(vec![start.into(), size.into()]));
    for strict in [true, false] {
        let _ = parse_xref_stream(&d, &data[6..], &mut DecodeContext::default(), strict);
        let _ = parse_xref_table(&mut Cursor::new(data), strict);
    }
});
