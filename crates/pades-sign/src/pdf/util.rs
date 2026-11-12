// Derived from pyHanko `pdf_utils/generic.py` (`pdf_string`, `pdf_date`,
// `TextStringObject`) and `pdf_utils/misc.py` (MIT, see LICENSE-pyHanko).

//! PDF value helpers: text strings, dates, names.

use lopdf::{Object, StringFormat};
use sigis_pki_core::time::Moment;

/// Encode a text string (`TextStringObject`): PDFDocEncoding-compatible
/// ASCII as a literal string, anything else as UTF-16BE with a BOM.
pub fn text_string(s: &str) -> Object {
    if s.bytes()
        .all(|b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
    {
        Object::String(s.as_bytes().to_vec(), StringFormat::Literal)
    } else {
        let mut v = vec![0xfe, 0xff];
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_be_bytes());
        }
        Object::String(v, StringFormat::Literal)
    }
}

/// Decode a PDF text string (UTF-16BE with BOM, UTF-8 with BOM, or
/// PDFDocEncoding approximated as Latin-1).
pub fn decode_text_string(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xfe, 0xff]) {
        let units: Vec<u16> = rest
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// A PDF date string for a UTC moment (`pdf_date`): `D:YYYYMMDDHHmmSSZ`.
pub fn pdf_date(at: Moment) -> String {
    match at.to_der_datetime() {
        Some(dt) => format!(
            "D:{:04}{:02}{:02}{:02}{:02}{:02}Z",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minutes(),
            dt.seconds()
        ),
        None => "D:19700101000000Z".to_owned(),
    }
}

/// Parse a PDF date string (`parse_pdf_date`), as UTC.
pub fn parse_pdf_date(s: &str) -> Option<Moment> {
    let s = s.strip_prefix("D:").unwrap_or(s);
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    let field = |from: usize, len: usize, default: u32| -> Option<u32> {
        match digits.get(from..from + len) {
            Some(d) => d.parse().ok(),
            None => Some(default),
        }
    };
    let year = u16::try_from(field(0, 4, 0)?).ok()?;
    let month = u8::try_from(field(4, 2, 1)?).ok()?;
    let day = u8::try_from(field(6, 2, 1)?).ok()?;
    let hour = u8::try_from(field(8, 2, 0)?).ok()?;
    let min = u8::try_from(field(10, 2, 0)?).ok()?;
    let sec = u8::try_from(field(12, 2, 0)?).ok()?;
    let mut m = Moment::from_ymd_hms(year, month, day, hour, min, sec)?;
    let rest = &s[digits.len()..];
    let sign = rest.chars().next();
    if matches!(sign, Some('+') | Some('-')) {
        let tz: String = rest[1..].chars().filter(char::is_ascii_digit).collect();
        let h: u64 = tz.get(0..2).and_then(|x| x.parse().ok()).unwrap_or(0);
        let mi: u64 = tz.get(2..4).and_then(|x| x.parse().ok()).unwrap_or(0);
        let off = core::time::Duration::from_secs(h * 3600 + mi * 60);
        m = if sign == Some('+') {
            m.minus(off)
        } else {
            m.plus(off)
        };
    }
    Some(m)
}

/// A name object.
pub fn name(n: &str) -> Object {
    Object::Name(n.as_bytes().to_vec())
}

/// A number object for a coordinate, as an integer when it is integral.
pub fn number(x: f64) -> Object {
    if x.fract() == 0.0 && x.abs() < 1e15 {
        Object::Integer(x as i64)
    } else {
        Object::Real(x as f32)
    }
}

/// Read a number (integer or real) from an object.
pub fn as_number(o: &Object) -> Option<f64> {
    match o {
        Object::Integer(i) => Some(*i as f64),
        Object::Real(r) => Some(f64::from(*r)),
        _ => None,
    }
}

/// Resolution of indirect objects, so that dictionary readers (seed
/// values, field locks) work on any PDF representation: the signing
/// writer ([`crate::pdf::writer::PdfUpdate`]) or a parsed
/// [`lopdf::Document`] (for validators).
pub trait ObjectResolver {
    /// Follow references (bounded).
    fn resolve_obj<'a>(&'a self, obj: &'a Object) -> sigis_pki_core::errors::Result<&'a Object>;

    /// Resolve `dict[key]`, if present.
    fn get_resolved<'a>(
        &'a self,
        dict: &'a lopdf::Dictionary,
        key: &[u8],
    ) -> sigis_pki_core::errors::Result<Option<&'a Object>> {
        match dict.get(key) {
            Ok(o) => Ok(Some(self.resolve_obj(o)?)),
            Err(_) => Ok(None),
        }
    }
}

impl ObjectResolver for crate::pdf::writer::PdfUpdate {
    fn resolve_obj<'a>(&'a self, obj: &'a Object) -> sigis_pki_core::errors::Result<&'a Object> {
        self.resolve(obj)
    }
}

impl ObjectResolver for lopdf::Document {
    fn resolve_obj<'a>(&'a self, obj: &'a Object) -> sigis_pki_core::errors::Result<&'a Object> {
        let mut cur = obj;
        for _ in 0..32 {
            match cur {
                Object::Reference(id) => {
                    cur = self.get_object(*id).map_err(|e| {
                        sigis_pki_core::errors::HankoError::Malformed(format!(
                            "object {} {}: {e}",
                            id.0, id.1
                        ))
                    })?
                }
                other => return Ok(other),
            }
        }
        Err(sigis_pki_core::errors::HankoError::Malformed(
            "reference chain too long".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        let m = Moment::from_ymd_hms(2020, 11, 1, 0, 0, 0).unwrap_or(Moment::from_unix_secs(0));
        assert_eq!(pdf_date(m), "D:20201101000000Z");
        assert_eq!(parse_pdf_date("D:20201101000000Z"), Some(m));
        assert_eq!(parse_pdf_date("D:20201101010000+01'00'"), Some(m));
    }

    #[test]
    fn strings() {
        assert_eq!(decode_text_string(b"abc"), "abc");
        if let Object::String(b, _) = text_string("é") {
            assert_eq!(decode_text_string(&b), "é");
        }
    }
}
