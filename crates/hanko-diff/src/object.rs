// Derived from pyHanko `pdf_utils/generic.py` (equality semantics) and
// `sign/diff_analysis/policies.py` (`_is_id`) (MIT, see LICENSE-pyHanko).

//! Object comparison with pyHanko's semantics.

use lopdf::{Dictionary, Object, ObjectId};

/// Value equality as pyHanko's `==` on raw PDF objects.
///
/// Differences from Python (all stricter, never more lenient):
/// - strings compare by their raw bytes (pyHanko compares decoded text, so
///   two encodings of the same text are equal there);
/// - a text string never equals a name (Python compares both as `str`);
/// - streams also compare their encoded data (pyHanko compares only the
///   dictionaries; direct streams do not occur in parsed files).
pub(crate) fn py_eq(a: &Object, b: &Object) -> bool {
    use Object::*;
    match (a, b) {
        (Null, Null) => true,
        (Boolean(x), Boolean(y)) => x == y,
        (Integer(x), Integer(y)) => x == y,
        (Integer(x), Real(y)) | (Real(y), Integer(x)) => (*x as f64) == f64::from(*y),
        (Real(x), Real(y)) => x == y,
        (Name(x), Name(y)) => x == y,
        (String(x, _), String(y, _)) => x == y,
        (Array(x), Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q)),
        (Dictionary(x), Dictionary(y)) => dict_eq(x, y),
        (Stream(x), Stream(y)) => dict_eq(&x.dict, &y.dict) && x.content == y.content,
        (Reference(x), Reference(y)) => x == y,
        _ => false,
    }
}

fn dict_eq(x: &Dictionary, y: &Dictionary) -> bool {
    x.len() == y.len()
        && x.iter().all(|(k, v)| match y.get(k) {
            Ok(w) => py_eq(v, w),
            Err(_) => false,
        })
}

/// pyHanko's `_is_id`: whether an overwritten object is an identical copy.
///
/// Types must match exactly (an integer is not identical to a real), strings
/// compare by raw bytes, streams by encoded data and dictionary.
/// pyHanko accepts a stream as identical to a dictionary with the same keys
/// when the *old* object is the dictionary; this port requires matching
/// types (stricter).
pub(crate) fn is_identical(old: &Object, new: &Object) -> bool {
    use Object::*;
    match (old, new) {
        (Null, Null) => true,
        (Boolean(x), Boolean(y)) => x == y,
        (Integer(x), Integer(y)) => x == y,
        (Real(x), Real(y)) => x == y,
        (Name(x), Name(y)) => x == y,
        (Reference(x), Reference(y)) => x == y,
        (String(x, _), String(y, _)) => x == y,
        (Array(x), Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| is_identical(p, q))
        }
        (Stream(x), Stream(y)) => x.content == y.content && dict_identical(&x.dict, &y.dict),
        (Dictionary(x), Dictionary(y)) => dict_identical(x, y),
        _ => false,
    }
}

fn dict_identical(x: &Dictionary, y: &Dictionary) -> bool {
    x.len() == y.len()
        && y.iter().all(|(k, v)| match x.get(k) {
            Ok(w) => is_identical(w, v),
            Err(_) => false,
        })
}

/// Name with a leading slash, as pyHanko prints it.
pub(crate) fn name_str(key: &[u8]) -> String {
    format!("/{}", String::from_utf8_lossy(key))
}

/// pyHanko's `repr` of a reference.
pub(crate) fn ref_str(id: ObjectId) -> String {
    format!("<{} {} R>", id.0, id.1)
}

/// Short rendering of an object for messages.
pub(crate) fn obj_str(o: &Object) -> String {
    use Object::*;
    match o {
        Null => "null".into(),
        Boolean(b) => b.to_string(),
        Integer(i) => i.to_string(),
        Real(r) => r.to_string(),
        Name(n) => name_str(n),
        String(s, _) => format!("({})", std::string::String::from_utf8_lossy(s)),
        Array(a) => {
            let parts: Vec<_> = a.iter().map(obj_str).collect();
            format!("[{}]", parts.join(" "))
        }
        Dictionary(d) => dict_str(d),
        Stream(s) => format!("{} stream", dict_str(&s.dict)),
        Reference(id) => format!("{} {} R", id.0, id.1),
    }
}

fn dict_str(d: &Dictionary) -> String {
    let parts: Vec<_> = d
        .iter()
        .map(|(k, v)| format!("{} {}", name_str(k), obj_str(v)))
        .collect();
    format!("<<{}>>", parts.join(" "))
}

/// Whether `o` is a dictionary-like container (dictionary or stream).
pub(crate) fn as_dict(o: &Object) -> Option<&Dictionary> {
    match o {
        Object::Dictionary(d) => Some(d),
        Object::Stream(s) => Some(&s.dict),
        _ => None,
    }
}

/// PDFDocEncoding code points 0x18-0x1F and 0x80-0x9F (0 = undefined).
const PDFDOC_18: [u16; 8] = [0x2d8, 0x2c7, 0x2c6, 0x2d9, 0x2dd, 0x2db, 0x2da, 0x2dc];
const PDFDOC_80: [u16; 32] = [
    0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x192, 0x2044, 0x2039, 0x203a, 0x2212, 0x2030,
    0x201e, 0x201c, 0x201d, 0x2018, 0x2019, 0x201a, 0x2122, 0xfb01, 0xfb02, 0x141, 0x152, 0x160,
    0x178, 0x17d, 0x131, 0x142, 0x153, 0x161, 0x17e, 0,
];

/// Decode a PDF text string as pyHanko does (`pdf_string`): a UTF-16BE,
/// UTF-16LE or UTF-8 byte order mark selects that encoding, otherwise
/// PDFDocEncoding. `None` when decoding fails (pyHanko then keeps a
/// `ByteStringObject`).
pub(crate) fn decode_text(b: &[u8]) -> Option<String> {
    if let Some(rest) = b.strip_prefix(&[0xfe, 0xff]) {
        if rest.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = rest.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16(&units).ok();
    }
    if let Some(rest) = b.strip_prefix(&[0xff, 0xfe]) {
        if rest.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = rest.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return String::from_utf16(&units).ok();
    }
    if let Some(rest) = b.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return String::from_utf8(rest.to_vec()).ok();
    }
    let mut out = String::with_capacity(b.len());
    for &c in b {
        let cp: u32 = match c {
            0x00..=0x17 | 0x7f | 0xad => return None,
            0x18..=0x1f => u32::from(PDFDOC_18[usize::from(c - 0x18)]),
            0x80..=0x9f => u32::from(PDFDOC_80[usize::from(c - 0x80)]),
            0xa0 => 0x20ac,
            _ => u32::from(c),
        };
        out.push(char::from_u32(cp).filter(|_| cp != 0)?);
    }
    Some(out)
}

/// Python truthiness of a PDF object (`bool(obj)`).
pub(crate) fn truthy(o: &Object) -> bool {
    match o {
        Object::Null => false,
        Object::Boolean(b) => *b,
        Object::Integer(i) => *i != 0,
        Object::Real(r) => *r != 0.0,
        Object::String(s, _) => !s.is_empty(),
        Object::Array(a) => !a.is_empty(),
        Object::Dictionary(d) => !d.is_empty(),
        Object::Stream(s) => !s.dict.is_empty(),
        Object::Name(_) | Object::Reference(_) => true,
    }
}

/// Numeric value of a direct number.
pub(crate) fn as_number(o: &Object) -> Option<f64> {
    match o {
        Object::Integer(i) => Some(*i as f64),
        Object::Real(r) => Some(f64::from(*r)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{Stream, StringFormat};

    #[test]
    fn numbers_compare_across_types_for_eq_but_not_identity() {
        assert!(py_eq(&Object::Integer(1), &Object::Real(1.0)));
        assert!(!is_identical(&Object::Integer(1), &Object::Real(1.0)));
    }

    #[test]
    fn strings_compare_by_bytes() {
        let a = Object::String(b"1234".to_vec(), StringFormat::Literal);
        let b = Object::String(b"1234".to_vec(), StringFormat::Hexadecimal);
        assert!(py_eq(&a, &b));
        assert!(is_identical(&a, &b));
    }

    #[test]
    fn text_decoding() {
        assert_eq!(decode_text(b"Sig1").as_deref(), Some("Sig1"));
        assert_eq!(decode_text(b"\xfe\xff\x00A").as_deref(), Some("A"));
        assert_eq!(decode_text(b"a\tb"), None);
        assert_eq!(decode_text(b"\xa0").as_deref(), Some("\u{20ac}"));
    }

    #[test]
    fn stream_and_dict_not_identical() {
        let mut d = Dictionary::new();
        d.set("Foo", Object::Name(b"Bar".to_vec()));
        let s = Object::Stream(Stream::new(d.clone(), b"hello".to_vec()));
        assert!(!is_identical(&s, &Object::Dictionary(d.clone())));
        assert!(!is_identical(&Object::Dictionary(d), &s));
    }
}
