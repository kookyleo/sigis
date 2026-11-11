// Derived from pyHanko `pdf_utils/generic.py` (`TextStringObject.write_to_stream`,
// `encode_pdfdocencoding`) and `pdf_utils/misc.py` (`rd`) (MIT, see
// LICENSE-pyHanko).

//! Formatting helpers for content streams.
//!
//! pyHanko builds content streams with Python's `%g` operator, `str()` of
//! numbers and its own string serialization. Positions and sizes in the
//! output depend on these conventions (`%g` keeps six significant digits),
//! so the port reproduces them exactly.

/// Python's `round(x, 4)` (`pdf_utils.misc.rd`).
pub fn rd(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    // Rust's exact formatting rounds the exact binary value with ties to
    // even, like Python's `round`.
    format!("{x:.4}").parse().unwrap_or(x)
}

/// Format a number like C's / Python's `%g` (six significant digits).
pub fn fmt_g(x: f64) -> String {
    if x == 0.0 {
        return if x.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    if !x.is_finite() {
        return if x.is_nan() {
            "nan".into()
        } else if x > 0.0 {
            "inf".into()
        } else {
            "-inf".into()
        };
    }
    const P: i32 = 6;
    let sci = format!("{:.*e}", (P - 1) as usize, x);
    let (_, exp) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    if !(-4..P).contains(&exp) {
        let (mant, _) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
        let mant = strip_zeros(mant);
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{mant}e{sign}{:02}", exp.abs())
    } else {
        let decimals = usize::try_from(P - 1 - exp).unwrap_or(0);
        strip_zeros(&format!("{x:.decimals$}")).to_owned()
    }
}

fn strip_zeros(s: &str) -> &str {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.')
    } else {
        s
    }
}

/// Python's `repr()` / `str()` of a float (shortest round-trip form).
pub fn py_float(x: f64) -> String {
    if !x.is_finite() {
        return fmt_g(x);
    }
    let a = x.abs();
    if x.fract() == 0.0 && a < 1e16 {
        return format!("{x:.1}");
    }
    if a >= 1e16 || (a < 1e-4 && a != 0.0) {
        let s = format!("{x:e}");
        let (mant, exp) = s.split_once('e').unwrap_or((s.as_str(), "0"));
        let exp: i32 = exp.parse().unwrap_or(0);
        let sign = if exp < 0 { '-' } else { '+' };
        return format!("{mant}e{sign}{:02}", exp.abs());
    }
    format!("{x}")
}

/// Python's `str()` of a number that is an `int` when integral and a
/// `float` otherwise.
pub fn py_num(x: f64) -> String {
    if x.fract() == 0.0 && x.abs() < 1e16 {
        format!("{}", x as i64)
    } else {
        py_float(x)
    }
}

/// Reverse PDFDocEncoding table (`_pdfDocEncoding_rev`): the code point
/// encoded by each byte, `0xffff` if the byte is not a target of the
/// reverse mapping.
const PDFDOC: [u16; 256] = [
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0x02d8, 0x02c7, 0x02c6, 0x02d9, 0x02dd, 0x02db, 0x02da, 0x02dc,
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
    0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
    0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f,
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
    0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0xffff,
    0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x0192, 0x2044,
    0x2039, 0x203a, 0x2212, 0x2030, 0x201e, 0x201c, 0x201d, 0x2018,
    0x2019, 0x201a, 0x2122, 0xfb01, 0xfb02, 0x0141, 0x0152, 0x0160,
    0x0178, 0x017d, 0x0131, 0x0142, 0x0153, 0x0161, 0x017e, 0xffff,
    0x20ac, 0x00a1, 0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7,
    0x00a8, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x0000, 0x00ae, 0x00af,
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7,
    0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00bf,
    0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,
    0x00d0, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d7,
    0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7,
    0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,
    0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff,
];

/// Encode `s` in PDFDocEncoding (`encode_pdfdocencoding`), if possible.
pub fn encode_pdfdoc(s: &str) -> Option<Vec<u8>> {
    s.chars()
        .map(|c| {
            let cp = u32::from(c);
            PDFDOC
                .iter()
                .position(|&t| u32::from(t) == cp && t != 0xffff)
                .and_then(|i| u8::try_from(i).ok())
        })
        .collect()
}

/// The bytes of a text string as pyHanko writes them: PDFDocEncoding if
/// possible, else UTF-16BE with a byte order mark.
pub fn text_string_bytes(s: &str) -> Vec<u8> {
    match encode_pdfdoc(s) {
        Some(b) => b,
        None => {
            let mut v = vec![0xfe, 0xff];
            for u in s.encode_utf16() {
                v.extend_from_slice(&u.to_be_bytes());
            }
            v
        }
    }
}

/// Serialize a text string as pyHanko does (`TextStringObject.write_to_stream`):
/// a literal string in which every byte other than ASCII letters, digits
/// and the space is written as an octal escape.
pub fn text_string_literal(s: &str) -> Vec<u8> {
    let mut out = vec![b'('];
    for b in text_string_bytes(s) {
        if b.is_ascii_alphanumeric() || b == b' ' {
            out.push(b);
        } else {
            out.extend_from_slice(format!("\\{b:03o}").as_bytes());
        }
    }
    out.push(b')');
    out
}

/// A random UUID (version 4) as lowercase hex without dashes
/// (`uuid.uuid4().hex`), or with dashes (`str(uuid.uuid4())`).
pub fn uuid4(dashes: bool) -> String {
    let mut b = [0u8; 16];
    if getrandom::fill(&mut b).is_err() {
        // fall back to a time-derived value; uniqueness within one document
        // is all that matters here
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        b = t.to_le_bytes();
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    if dashes {
        format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
    } else {
        hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g_format() {
        assert_eq!(fmt_g(1.0), "1");
        assert_eq!(fmt_g(0.5), "0.5");
        assert_eq!(fmt_g(123456.0), "123456");
        assert_eq!(fmt_g(1234567.0), "1.23457e+06");
        assert_eq!(fmt_g(0.0001), "0.0001");
        assert_eq!(fmt_g(0.00001), "1e-05");
        assert_eq!(fmt_g(-2.5), "-2.5");
        assert_eq!(fmt_g(1.0 / 3.0), "0.333333");
        assert_eq!(fmt_g(99.99999), "100");
        assert_eq!(fmt_g(0.603922), "0.603922");
    }

    #[test]
    fn py_reprs() {
        assert_eq!(py_float(7.0), "7.0");
        assert_eq!(py_float(0.1), "0.1");
        assert_eq!(py_float(1e-5), "1e-05");
        assert_eq!(py_num(3.0), "3");
        assert_eq!(py_num(3.25), "3.25");
    }

    #[test]
    fn strings() {
        assert_eq!(text_string_literal("Hi, it's"), b"(Hi\\054 it\\047s)".to_vec());
        assert_eq!(text_string_bytes("a\n")[..2], [0xfe, 0xff]);
    }
}
