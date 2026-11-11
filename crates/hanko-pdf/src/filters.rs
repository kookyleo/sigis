// Derived from pyHanko `pdf_utils/filters.py` (MIT, see LICENSE-pyHanko),
// which in turn derives from PyPDF2 (BSD-3-Clause).

//! Stream filters (`pyhanko.pdf_utils.filters`): `/FlateDecode` (with PNG
//! predictors), `/ASCIIHexDecode` and `/ASCII85Decode`. As in pyHanko, other
//! filters (LZW, RunLength, image codecs) are not supported.

use flate2::{Decompress, FlushDecompress, Status};
use lopdf::{Dictionary, Object};

use crate::decode_limits::check_output_size;
use crate::error::{PdfError, PdfResult};

/// Dereferences a value of a decode parameter dictionary.
pub type Deref<'a> = &'a dyn Fn(&Object) -> PdfResult<Object>;

/// A generic (non-crypt) stream decoder (`Decoder`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoder {
    /// `/FlateDecode` (`/Fl`).
    Flate,
    /// `/ASCIIHexDecode` (`/AHx`).
    AsciiHex,
    /// `/ASCII85Decode` (`/A85`).
    Ascii85,
}

/// Look up a decoder by name, with or without the slash (`get_generic_decoder`).
pub fn get_generic_decoder(name: &[u8]) -> PdfResult<Decoder> {
    let n = name.strip_prefix(b"/").unwrap_or(name);
    match n {
        b"FlateDecode" | b"Fl" => Ok(Decoder::Flate),
        b"ASCIIHexDecode" | b"AHx" => Ok(Decoder::AsciiHex),
        b"ASCII85Decode" | b"A85" => Ok(Decoder::Ascii85),
        other => Err(PdfError::NotImplemented(format!(
            "Stream filter '/{}' is not supported.",
            String::from_utf8_lossy(other)
        ))),
    }
}

impl Decoder {
    /// The canonical filter name (without slash).
    pub fn name(self) -> &'static str {
        match self {
            Self::Flate => "FlateDecode",
            Self::AsciiHex => "ASCIIHexDecode",
            Self::Ascii85 => "ASCII85Decode",
        }
    }

    /// Decode without limits.
    pub fn decode(
        self,
        data: &[u8],
        params: Option<&Dictionary>,
        deref: Deref<'_>,
    ) -> PdfResult<Vec<u8>> {
        self.decode_bounded(data, params, None, deref)
    }

    /// Decode, refusing to produce more than `max_output_size` bytes
    /// (`decode_bounded`).
    pub fn decode_bounded(
        self,
        data: &[u8],
        params: Option<&Dictionary>,
        max_output_size: Option<u64>,
        deref: Deref<'_>,
    ) -> PdfResult<Vec<u8>> {
        match self {
            Self::Flate => flate_decode_bounded(data, params, max_output_size, deref),
            Self::AsciiHex => {
                let out = ascii_hex_decode(data)?;
                check_output_size(out.len(), max_output_size)?;
                Ok(out)
            }
            Self::Ascii85 => {
                let out = ascii85_decode(data)?;
                check_output_size(out.len(), max_output_size)?;
                Ok(out)
            }
        }
    }

    /// Encode (`encode`); parameters are ignored as in pyHanko.
    pub fn encode(self, data: &[u8]) -> PdfResult<Vec<u8>> {
        Ok(match self {
            Self::Flate => flate_compress(data),
            Self::AsciiHex => ascii_hex_encode(data),
            Self::Ascii85 => ascii85_encode(data),
        })
    }
}

/// zlib-compress with the default level (`zlib.compress`).
pub fn flate_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
    // writing to a Vec cannot fail
    let _ = enc.write_all(data);
    enc.finish().unwrap_or_default()
}

fn zlib_error(msg: &str) -> PdfError {
    PdfError::Stream(format!("Error while decompressing data: {msg}"))
}

/// zlib-decompress, refusing to produce more than `max` bytes
/// (`_bounded_decompress`). Trailing data after the end of the zlib stream is
/// ignored, as by `zlib.decompress`.
pub fn bounded_decompress(data: &[u8], max: Option<u64>) -> PdfResult<Vec<u8>> {
    let limit = max.map(|m| m.saturating_add(1));
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::with_capacity(data.len().saturating_mul(2).min(1 << 20));
    loop {
        if let Some(l) = limit {
            if out.len() as u64 >= l {
                break;
            }
        }
        if out.capacity() == out.len() {
            let extra = out.capacity().clamp(4096, 1 << 24);
            let extra = match limit {
                Some(l) => extra.min((l - out.len() as u64) as usize),
                None => extra,
            };
            out.reserve(extra);
        }
        let consumed = d.total_in() as usize;
        let before_out = out.len();
        let status = d
            .decompress_vec(
                &data[consumed.min(data.len())..],
                &mut out,
                FlushDecompress::None,
            )
            .map_err(|e| zlib_error(&e.to_string()))?;
        if let Some(l) = limit {
            if out.len() as u64 > l {
                out.truncate(l as usize);
            }
        }
        match status {
            Status::StreamEnd => {
                check_output_size(out.len(), max)?;
                return Ok(out);
            }
            Status::Ok | Status::BufError => {
                let progressed = out.len() != before_out || d.total_in() as usize != consumed;
                if !progressed && out.capacity() > out.len() {
                    // no more input to consume and no output produced
                    return Err(zlib_error("incomplete or truncated stream"));
                }
            }
        }
    }
    check_output_size(out.len(), max)?;
    Err(zlib_error("incomplete or truncated stream"))
}

fn flate_decode_bounded(
    data: &[u8],
    params: Option<&Dictionary>,
    max_output_size: Option<u64>,
    deref: Deref<'_>,
) -> PdfResult<Vec<u8>> {
    let decompressed = bounded_decompress(data, max_output_size)?;
    let predictor = match params.map(|p| p.get(b"Predictor")) {
        None | Some(Err(_)) => 1,
        Some(Ok(Object::Integer(p))) => *p,
        Some(Ok(other)) => {
            return Err(PdfError::value(format!(
                "Unsupported flatedecode predictor {other:?}"
            )))
        }
    };
    if predictor == 1 {
        return Ok(decompressed);
    }
    let columns = match params.map(|p| p.get(b"Columns")) {
        Some(Ok(c)) => match deref(c)? {
            Object::Integer(n) if n >= 0 => n as usize,
            _ => return Err(PdfError::value("/Columns must be a nonnegative integer")),
        },
        _ => return Err(PdfError::value("/Columns is required for predictors")),
    };
    if (10..=15).contains(&predictor) {
        png_decode(&decompressed, columns)
    } else {
        Err(PdfError::NotImplemented(format!(
            "Unsupported flatedecode predictor {predictor}"
        )))
    }
}

fn png_decode(data: &[u8], columns: usize) -> PdfResult<Vec<u8>> {
    let rowlength = columns + 1;
    if !data.len().is_multiple_of(rowlength) {
        return Err(PdfError::value(
            "PNG predictor: data is not a whole number of rows",
        ));
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = vec![0u8; columns];
    for row in data.chunks_exact(rowlength) {
        let filter = row[0];
        let raw = &row[1..];
        let mut result = vec![0u8; columns];
        match filter {
            0 => result.copy_from_slice(raw),
            1 => {
                // Sub (ISO 32000 / PNG): add the previous decoded byte
                for i in 0..columns {
                    let left = if i == 0 { 0 } else { result[i - 1] };
                    result[i] = raw[i].wrapping_add(left);
                }
            }
            2 => {
                for i in 0..columns {
                    result[i] = raw[i].wrapping_add(prev[i]);
                }
            }
            other => {
                return Err(PdfError::NotImplemented(format!(
                    "Unsupported PNG filter {other}"
                )))
            }
        }
        out.extend_from_slice(&result);
        prev = result;
    }
    Ok(out)
}

fn is_re_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// `ASCIIHexDecode.encode`.
pub fn ascii_hex_encode(data: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = data
        .iter()
        .flat_map(|b| format!("{b:02x}").into_bytes())
        .collect();
    out.push(b'>');
    out
}

/// `ASCIIHexDecode.decode`.
pub fn ascii_hex_decode(data: &[u8]) -> PdfResult<Vec<u8>> {
    let Some(end) = data.iter().position(|&b| b == b'>') else {
        return Err(PdfError::value("ASCIIHex data lacks an EOD marker"));
    };
    let mut digits: Vec<u8> = data[..end]
        .iter()
        .copied()
        .filter(|&b| !is_re_ws(b))
        .collect();
    if !digits.len().is_multiple_of(2) {
        digits.push(b'0');
    }
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(PdfError::value("Non-hexadecimal digit found"));
    }
    Ok(digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            let h = |d: u8| (d as char).to_digit(16).unwrap_or(0) as u8;
            (h(c[0]) << 4) | h(c[1])
        })
        .collect())
}

const POWS: [u64; 5] = [85 * 85 * 85 * 85, 85 * 85 * 85, 85 * 85, 85, 1];

/// `ASCII85Decode.encode`.
pub fn ascii85_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for grp in data.chunks(4) {
        if grp == [0, 0, 0, 0] {
            out.push(b'z');
            continue;
        }
        let n = grp.len();
        let mut padded = [0u8; 4];
        padded[..n].copy_from_slice(grp);
        let mut v = u64::from(u32::from_be_bytes(padded));
        let pows: &[u64] = if n < 4 { &POWS[..n + 1] } else { &POWS };
        for p in pows {
            let digit = v / p;
            v %= p;
            out.push(digit as u8 + 0x21);
        }
    }
    out.extend_from_slice(b"~>");
    out
}

/// `ASCII85Decode.decode`.
pub fn ascii85_decode(data: &[u8]) -> PdfResult<Vec<u8>> {
    let Some(end) = data.windows(2).position(|w| w == b"~>") else {
        return Err(PdfError::value("ASCII85 data lacks an EOD marker"));
    };
    let clean: Vec<u8> = data[..end]
        .iter()
        .copied()
        .filter(|&b| !is_re_ws(b))
        .collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < clean.len() {
        let c = clean[i];
        i += 1;
        if c == b'z' {
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        let rest_end = (i + 4).min(clean.len());
        if rest_end == i {
            return Err(PdfError::stream(
                "Nonzero ASCII85 group must have at least two digits.",
            ));
        }
        let mut grp = vec![c];
        grp.extend_from_slice(&clean[i..rest_end]);
        i = rest_end;
        let mut result: u64 = 0;
        let mut p = 0;
        for (digit, pow) in grp.iter().zip(POWS.iter()) {
            let d = i64::from(*digit) - 0x21;
            if !(0..85).contains(&d) {
                return Err(PdfError::stream(
                    "Bytes in ASCII85 data must lie beteen 0x21 and 0x75.",
                ));
            }
            result += pow * d as u64;
            p = *pow;
        }
        if grp.len() < 5 {
            result += p;
        }
        let v = u32::try_from(result).map_err(|_| PdfError::value("ASCII85 group out of range"))?;
        out.extend_from_slice(&v.to_be_bytes()[..grp.len() - 1]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompress_roundtrip_and_limit() {
        let data = vec![7u8; 10000];
        let c = flate_compress(&data);
        assert_eq!(bounded_decompress(&c, None).unwrap(), data);
        assert_eq!(bounded_decompress(&c, Some(10000)).unwrap(), data);
        assert!(matches!(
            bounded_decompress(&c, Some(9999)),
            Err(PdfError::DecodeLimit(_))
        ));
        assert!(bounded_decompress(&c[..c.len() - 6], None).is_err());
    }
}
