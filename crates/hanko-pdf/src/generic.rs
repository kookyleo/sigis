// Derived from pyHanko `pdf_utils/generic.py` (MIT, see LICENSE-pyHanko),
// which in turn derives from PyPDF2 (BSD-3-Clause).

//! PDF object syntax (`pyhanko.pdf_utils.generic`): parsing, serialization
//! and text-string encodings.
//!
//! Objects are represented by [`lopdf::Object`]. Differences with pyHanko's
//! object classes:
//!
//! * names are kept as raw bytes (without the leading `/`); pyHanko decodes
//!   them as UTF-8 with a Latin-1 fallback;
//! * strings are kept as raw bytes; [`pdf_string`] performs pyHanko's
//!   text/byte string classification on demand;
//! * reals are `f32` (pyHanko uses `Decimal`).

use lopdf::{Dictionary, Object, ObjectId, Stream, StringFormat};

use crate::error::{PdfError, PdfResult};
use crate::misc::{
    is_regular_character, py_isspace, read_non_whitespace, read_non_ws, read_until_byte_class,
    read_until_delimiter, skip_over_whitespace, Cursor, PDF_WHITESPACE,
};

/// Content stream parsing mode (`ContentOpReading`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentOpReading {
    /// Not in a content stream.
    No,
    /// At the top level of a content stream: operators are allowed.
    GraphicOps,
    /// Inside an array or dictionary in a content stream.
    InObject,
}

impl ContentOpReading {
    fn active(self) -> bool {
        self != Self::No
    }

    fn nest(self) -> Self {
        if self.active() {
            Self::InObject
        } else {
            Self::No
        }
    }
}

/// Result of [`read_item`]: an object, or an operator in a content stream.
#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    /// A PDF object.
    Object(Object),
    /// An operator literal (`OperatorLiteral`).
    Operator(String),
}

/// Resolves indirect `/Length` entries while parsing streams.
pub type LengthResolver<'a> = &'a dyn Fn(ObjectId) -> PdfResult<Object>;

/// Parsing context (the reader behind `container_ref.get_pdf_handler()`).
#[derive(Clone, Copy)]
pub struct ParseContext<'a> {
    /// Strict mode of the handler.
    pub strict: bool,
    /// Resolver for indirect stream lengths, if any.
    pub length_resolver: Option<LengthResolver<'a>>,
}

impl Default for ParseContext<'_> {
    fn default() -> Self {
        Self {
            strict: true,
            length_resolver: None,
        }
    }
}

impl std::fmt::Debug for ParseContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParseContext")
            .field("strict", &self.strict)
            .finish_non_exhaustive()
    }
}

const OBJECT_PREFIXES: &[u8] = b"/<[tf(n%";

/// `INDIRECT_PATTERN`: `(\d+)\s+(\d+)\s+R[^a-zA-Z]` at the start of `peek`.
fn matches_indirect_pattern(peek: &[u8]) -> bool {
    fn is_re_space(b: u8) -> bool {
        py_isspace(b)
    }
    let mut i = 0;
    let digits = |i: &mut usize| {
        let s = *i;
        while *i < peek.len() && peek[*i].is_ascii_digit() {
            *i += 1;
        }
        *i > s
    };
    let spaces = |i: &mut usize| {
        let s = *i;
        while *i < peek.len() && is_re_space(peek[*i]) {
            *i += 1;
        }
        *i > s
    };
    if !digits(&mut i) || !spaces(&mut i) || !digits(&mut i) || !spaces(&mut i) {
        return false;
    }
    if peek.get(i) != Some(&b'R') {
        return false;
    }
    matches!(peek.get(i + 1), Some(b) if !b.is_ascii_alphabetic())
}

/// Read a PDF object (`read_object`).
pub fn read_object(stream: &mut Cursor<'_>, ctx: &ParseContext<'_>) -> PdfResult<Object> {
    match read_item(stream, ctx, ContentOpReading::No)? {
        Item::Object(o) => Ok(o),
        // unreachable outside content streams
        Item::Operator(op) => Err(PdfError::read(format!("Unexpected operator {op}"))),
    }
}

/// Maximal nesting depth of arrays and dictionaries (pyHanko is bounded by
/// Python's recursion limit).
pub const MAX_NESTING_DEPTH: usize = 256;

thread_local! {
    static PARSE_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct NestingGuard;

impl NestingGuard {
    fn enter() -> PdfResult<Self> {
        PARSE_DEPTH.with(|d| {
            if d.get() >= MAX_NESTING_DEPTH {
                return Err(PdfError::read("Objects are nested too deeply"));
            }
            d.set(d.get() + 1);
            Ok(NestingGuard)
        })
    }
}

impl Drop for NestingGuard {
    fn drop(&mut self) {
        PARSE_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// Read a PDF object or (in content streams) an operator (`read_object`).
pub fn read_item(
    stream: &mut Cursor<'_>,
    ctx: &ParseContext<'_>,
    in_content_stream: ContentOpReading,
) -> PdfResult<Item> {
    let _guard = NestingGuard::enter()?;
    let tok = stream.peek1();
    // Python: OBJECT_PREFIXES.find(b'') == 0
    let idx = match tok {
        None => Some(0),
        Some(t) => OBJECT_PREFIXES.iter().position(|&c| c == t),
    };
    let obj = match idx {
        Some(0) => read_name(stream).map(Object::Name)?,
        Some(1) => {
            if stream.peek(2) == b"<<" {
                read_dictionary(stream, ctx, in_content_stream.nest())?
            } else {
                read_hex_string(stream)?
            }
        }
        Some(2) => Object::Array(read_array(stream, ctx, in_content_stream.nest())?),
        Some(3) | Some(4) => Object::Boolean(read_boolean(stream)?),
        Some(5) => Object::String(read_string_literal_bytes(stream)?, StringFormat::Literal),
        Some(7) => {
            // comment
            let mut t = tok;
            while !matches!(t, Some(b'\r') | Some(b'\n')) {
                t = stream.read1();
                if t.is_none() {
                    // Python loops forever on b''; fail instead
                    return Err(PdfError::stream("Stream ended prematurely"));
                }
            }
            read_non_ws(stream)?;
            stream.seek_rel(-1)?;
            return read_item(stream, ctx, ContentOpReading::No);
        }
        _ if in_content_stream == ContentOpReading::GraphicOps
            && tok.is_some_and(|t| t.is_ascii_alphabetic()) =>
        {
            let literal = read_until_delimiter(stream);
            if !literal.is_ascii() {
                return Err(PdfError::read(format!(
                    "Failed to parse {} as operator literal",
                    py_bytes_repr(&literal)
                )));
            } else if literal == b"null" {
                return Ok(Item::Object(Object::Null));
            } else if literal == b"R" {
                return Err(PdfError::read("Indirect object reference in content stream"));
            }
            return Ok(Item::Operator(String::from_utf8_lossy(&literal).into_owned()));
        }
        Some(6) => {
            read_null(stream)?;
            Object::Null
        }
        _ if tok.is_some_and(|t| b"+-.".contains(&t)) => read_number(stream)?,
        _ if tok.is_some_and(|t| t.is_ascii_digit()) => {
            if in_content_stream.active() {
                read_number(stream)?
            } else if matches_indirect_pattern(stream.peek(20)) {
                Object::Reference(read_indirect_reference(stream)?)
            } else {
                read_number(stream)?
            }
        }
        _ => {
            let t = tok.unwrap_or(0);
            return Err(PdfError::read(format!(
                "Unexpected byte '{}' at position {}",
                py_bytes_repr(&[t]),
                stream.tell()
            )));
        }
    };
    Ok(Item::Object(obj))
}

/// Read `null` (`NullObject.read_from_stream`).
pub fn read_null(stream: &mut Cursor<'_>) -> PdfResult<()> {
    if stream.read(4) != b"null" {
        return Err(PdfError::read("Could not read Null object"));
    }
    Ok(())
}

/// Read `true` / `false` (`BooleanObject.read_from_stream`).
pub fn read_boolean(stream: &mut Cursor<'_>) -> PdfResult<bool> {
    let word = stream.read(4);
    if word == b"true" {
        return Ok(true);
    } else if word == b"fals" && stream.read(1) == b"e" {
        return Ok(false);
    }
    Err(PdfError::read("Could not read Boolean object"))
}

/// Read an array (`ArrayObject.read_from_stream`).
pub fn read_array(
    stream: &mut Cursor<'_>,
    ctx: &ParseContext<'_>,
    in_content_stream: ContentOpReading,
) -> PdfResult<Vec<Object>> {
    if stream.read(1) != b"[" {
        return Err(PdfError::read("Could not read array"));
    }
    let mut arr = Vec::new();
    loop {
        let peekahead = read_non_ws(stream)?;
        if peekahead == b']' {
            break;
        }
        stream.seek_rel(-1)?;
        match read_item(stream, ctx, in_content_stream)? {
            Item::Object(o) => arr.push(o),
            Item::Operator(op) => {
                return Err(PdfError::read(format!("Unexpected operator {op} in array")))
            }
        }
    }
    Ok(arr)
}

/// Read an indirect reference (`IndirectObject.read_from_stream`).
pub fn read_indirect_reference(stream: &mut Cursor<'_>) -> PdfResult<ObjectId> {
    let read_token = |stream: &mut Cursor<'_>| -> PdfResult<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let Some(tok) = stream.read1() else {
                return Err(PdfError::stream("Stream has ended unexpectedly"));
            };
            if py_isspace(tok) {
                if out.is_empty() {
                    continue;
                }
                break;
            }
            out.push(tok);
        }
        Ok(out)
    };
    let idnum_str = read_token(stream)?;
    let generation_str = read_token(stream)?;
    let r = read_non_ws(stream)?;
    if r != b'R' {
        return Err(PdfError::read(format!(
            "Error reading indirect object reference at byte {:#x}",
            stream.tell()
        )));
    }
    let parse_err = |stream: &Cursor<'_>| {
        PdfError::read(format!(
            "Parse error on indirect object reference around {:#x}",
            stream.tell()
        ))
    };
    let idnum = parse_py_int(&idnum_str).ok_or_else(|| parse_err(stream))?;
    let generation = parse_py_int(&generation_str).ok_or_else(|| parse_err(stream))?;
    if !(idnum > 0 && generation >= 0) {
        return Err(parse_err(stream));
    }
    let idnum = u32::try_from(idnum).map_err(|_| parse_err(stream))?;
    let generation = u16::try_from(generation).map_err(|_| parse_err(stream))?;
    Ok((idnum, generation))
}

/// Python `int(bytes)`: optional surrounding whitespace, sign, digits and
/// single underscores between digits.
pub fn parse_py_int(raw: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(raw).ok()?;
    let s = s.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b' || c == '\x0c');
    let (neg, digits) = match s.as_bytes().first()? {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    let cleaned: String = digits.chars().filter(|&c| c != '_').collect();
    let v: i64 = cleaned.parse().ok()?;
    Some(if neg { -v } else { v })
}

/// Python `Decimal(str)` restricted to the characters a PDF number token can
/// contain.
fn parse_py_decimal(raw: &str) -> Option<f32> {
    let digits = raw.trim_start_matches(['+', '-']);
    if raw.len() - digits.len() > 1 {
        return None;
    }
    let mut parts = digits.splitn(2, '.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next().unwrap_or("");
    if (int_part.is_empty() && frac_part.is_empty())
        || !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let normalized = format!(
        "{}{}.{}",
        if raw.starts_with('-') { "-" } else { "" },
        if int_part.is_empty() { "0" } else { int_part },
        if frac_part.is_empty() { "0" } else { frac_part }
    );
    normalized.parse::<f32>().ok().filter(|v| v.is_finite())
}

/// Read a number (`NumberObject.read_from_stream`).
pub fn read_number(stream: &mut Cursor<'_>) -> PdfResult<Object> {
    // NumberPattern = [^+-.0-9]; note that '+-.' is a range (includes ',')
    let num = read_until_byte_class(
        stream,
        |b| !((b'+'..=b'.').contains(&b) || b.is_ascii_digit()),
        true,
    )?;
    let text = String::from_utf8_lossy(&num);
    if num.contains(&b'.') {
        parse_py_decimal(&text)
            .map(Object::Real)
            .ok_or_else(|| PdfError::value(format!("Invalid decimal literal: {text:?}")))
    } else {
        parse_py_int(&num)
            .map(Object::Integer)
            .ok_or_else(|| {
                PdfError::value(format!("invalid literal for int() with base 10: {text:?}"))
            })
    }
}

/// Read a hex string (`read_hex_string_from_stream`).
pub fn read_hex_string(stream: &mut Cursor<'_>) -> PdfResult<Object> {
    stream.read(1);
    let start = stream.tell();
    let rest = stream.peek(usize::MAX);
    let Some(end) = rest.iter().position(|&b| b == b'>') else {
        return Err(PdfError::stream("Stream ended prematurely"));
    };
    let data = &rest[..end];
    if !data.contains(&b'%') {
        stream.seek(start + end + 1);
        let digits: Vec<u8> = data
            .iter()
            .copied()
            .filter(|b| !PDF_WHITESPACE.contains(b))
            .collect();
        if let Some(bad) = digits.iter().find(|b| !b.is_ascii_hexdigit()) {
            return Err(PdfError::stream(format!(
                "Unexpected token in hex string: {}",
                py_bytes_repr(&[*bad])
            )));
        }
        return Ok(Object::String(unhexlify_padded(&digits), StringFormat::Hexadecimal));
    }
    // Comments may contain '>', so let the tokeniser deal with them.
    stream.seek(start);
    let mut digits = Vec::new();
    loop {
        let tok = read_non_ws(stream)?;
        if tok == b'>' {
            break;
        } else if !tok.is_ascii_hexdigit() {
            return Err(PdfError::stream(format!(
                "Unexpected token in hex string: {}",
                py_bytes_repr(&[tok])
            )));
        }
        digits.push(tok);
    }
    Ok(Object::String(unhexlify_padded(&digits), StringFormat::Hexadecimal))
}

fn hexval(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn unhexlify_padded(digits: &[u8]) -> Vec<u8> {
    digits
        .chunks(2)
        .map(|c| (hexval(c[0]) << 4) | c.get(1).map_or(0, |&d| hexval(d)))
        .collect()
}

/// Read the bytes of a literal string (`_read_string_literal_bytes`).
pub fn read_string_literal_bytes(stream: &mut Cursor<'_>) -> PdfResult<Vec<u8>> {
    stream.read(1);
    let mut parens = 1;
    let mut txt = Vec::new();
    loop {
        let Some(tok) = stream.read1() else {
            return Err(PdfError::stream("Stream has ended unexpectedly"));
        };
        match tok {
            b'(' => parens += 1,
            b')' => {
                parens -= 1;
                if parens == 0 {
                    break;
                }
            }
            b'\\' => {
                let esc = stream.read1();
                let out: Option<u8> = match esc {
                    Some(c) if b"() /%<>[]#_&$\\".contains(&c) => Some(c),
                    Some(b'n') => Some(b'\n'),
                    Some(b'r') => Some(b'\r'),
                    Some(b't') => Some(b'\t'),
                    Some(b'b') => Some(0x08),
                    Some(b'f') => Some(0x0c),
                    Some(c) if c.is_ascii_digit() => {
                        let mut val: u32 = 0;
                        let mut oct_ok = c < b'8';
                        val = val * 8 + u32::from(c - b'0');
                        for _ in 0..2 {
                            match stream.read1() {
                                Some(n) if n.is_ascii_digit() => {
                                    oct_ok &= n < b'8';
                                    val = val * 8 + u32::from(n - b'0');
                                }
                                Some(_) => {
                                    stream.seek_rel(-1)?;
                                    break;
                                }
                                None => break,
                            }
                        }
                        if !oct_ok {
                            return Err(PdfError::value("invalid literal for int() with base 8"));
                        }
                        if val > 255 {
                            return Err(PdfError::value("bytes must be in range(0, 256)"));
                        }
                        Some(val as u8)
                    }
                    Some(b'\n') | Some(b'\r') => {
                        match stream.read1() {
                            Some(b'\n') | Some(b'\r') => {}
                            Some(_) => stream.seek_rel(-1)?,
                            None => {}
                        }
                        None
                    }
                    // Python: b'' in b"\n\r" is true (escaped EOL at the end)
                    None => None,
                    Some(c) => {
                        return Err(PdfError::read(format!(
                            "Unexpected escaped string: {}",
                            py_bytes_repr(&[c])
                        )))
                    }
                };
                if let Some(b) = out {
                    txt.push(b);
                }
                continue;
            }
            _ => {}
        }
        txt.push(tok);
    }
    Ok(txt)
}

/// Decode a name after the leading `/` (`_decode_name`), returning the raw
/// name bytes.
pub fn decode_name(name_bytes: &[u8]) -> PdfResult<Vec<u8>> {
    let mut out = Vec::with_capacity(name_bytes.len());
    let mut it = name_bytes.iter().copied();
    let hex = |d: u8| -> PdfResult<u8> {
        if d.is_ascii_hexdigit() {
            Ok(hexval(d))
        } else {
            Err(PdfError::read("Numeric escape in PDF name must use hexadecimal digits"))
        }
    };
    while let Some(b) = it.next() {
        if b == b'#' {
            let (Some(d1), Some(d2)) = (it.next(), it.next()) else {
                return Err(PdfError::read(format!(
                    "Unterminated escape in PDF name /{}",
                    py_bytes_repr(name_bytes)
                )));
            };
            out.push(hex(d1)? * 16 + hex(d2)?);
        } else if !(0x21..=0x7e).contains(&b) || !is_regular_character(b) {
            return Err(PdfError::read(format!(
                "Byte (0x{b:02x}) must be escaped in a PDF name"
            )));
        } else {
            out.push(b);
        }
    }
    Ok(out)
}

/// Read a name (`NameObject.read_from_stream`); returns the bytes without `/`.
pub fn read_name(stream: &mut Cursor<'_>) -> PdfResult<Vec<u8>> {
    if stream.read(1) != b"/" {
        return Err(PdfError::read("Name object should start with /"));
    }
    let raw = read_until_delimiter(stream);
    decode_name(&raw)
}

fn maybe_read_stream_payload(
    stream: &mut Cursor<'_>,
    data: &Dictionary,
    ctx: &ParseContext<'_>,
) -> PdfResult<Option<Vec<u8>>> {
    let pos = stream.tell();
    let s = read_non_whitespace(stream, false, true)?;
    if s == Some(b's') && stream.read(5) == b"tream" {
        skip_over_whitespace(stream, true, true)?;
        let length = match data.get(b"Length") {
            Ok(Object::Integer(n)) => *n,
            Ok(Object::Reference(id)) => {
                let t = stream.tell();
                let resolved = match ctx.length_resolver {
                    Some(r) => r(*id)?,
                    None => Object::Null,
                };
                stream.seek(t);
                match resolved {
                    Object::Integer(n) => n,
                    other => {
                        return Err(PdfError::read(format!(
                            "Stream /Length must be an integer, not {}",
                            other.enum_variant()
                        )))
                    }
                }
            }
            Ok(other) => {
                return Err(PdfError::read(format!(
                    "Stream /Length must be an integer, not {}",
                    other.enum_variant()
                )))
            }
            Err(_) => return Err(PdfError::read("Stream dictionary lacks a /Length entry")),
        };
        let length = usize::try_from(length)
            .map_err(|_| PdfError::read(format!("Negative stream length {length}")))?;
        let mut stream_data = stream.read(length).to_vec();
        let e = read_non_ws(stream)?;
        let ndstream = stream.read(8);
        let mut marker = vec![e];
        marker.extend_from_slice(ndstream);
        if marker != b"endstream" {
            let orig_endstream_pos = stream.tell();
            stream.seek_rel(-10)?;
            let end = stream.read(9);
            if end == b"endstream" {
                stream_data.pop();
            } else {
                return Err(PdfError::read(format!(
                    "Unable to find 'endstream' marker after stream at byte {orig_endstream_pos:#x}."
                )));
            }
        }
        Ok(Some(stream_data))
    } else {
        stream.seek(pos);
        Ok(None)
    }
}

/// Read a dictionary or stream (`DictionaryObject.read_from_stream`).
pub fn read_dictionary(
    stream: &mut Cursor<'_>,
    ctx: &ParseContext<'_>,
    in_content_stream: ContentOpReading,
) -> PdfResult<Object> {
    if stream.read(2) != b"<<" {
        return Err(PdfError::read(format!(
            "Dictionary read error at byte 0x{:#x}: stream must begin with '<<'",
            stream.tell()
        )));
    }
    let mut data = Dictionary::new();
    loop {
        let tok = read_non_ws(stream)?;
        if tok == b'>' {
            stream.read(1);
            break;
        }
        stream.seek_rel(-1)?;
        let key = read_name(stream).map_err(|_| {
            PdfError::read(format!(
                "Failed to read dictionary key at byte 0x{:#x}; expected PDF name",
                stream.tell()
            ))
        })?;
        read_non_ws(stream)?;
        stream.seek_rel(-1)?;
        let value = match read_item(stream, ctx, in_content_stream)? {
            Item::Object(o) => o,
            Item::Operator(op) => {
                return Err(PdfError::read(format!("Unexpected operator {op} in dictionary")))
            }
        };
        if !data.has(&key) {
            data.set(key, value);
        } else {
            let err = format!(
                "Multiple definitions in dictionary at byte {:#x} for key /{}",
                stream.tell(),
                String::from_utf8_lossy(&key)
            );
            if ctx.strict {
                return Err(PdfError::StrictRead(err));
            }
            log::warn!("{err}");
        }
    }
    let payload = if in_content_stream.active() {
        None
    } else {
        maybe_read_stream_payload(stream, &data, ctx)?
    };
    Ok(match payload {
        Some(content) => Object::Stream(Stream {
            dict: data,
            content,
            allows_compression: true,
            start_position: None,
        }),
        None => Object::Dictionary(data),
    })
}

/// Python-style `repr()` of a byte string (`b'...'`).
pub fn py_bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') { '"' } else { '\'' };
    let mut s = String::from("b");
    s.push(quote);
    for &c in b {
        match c {
            b'\\' => s.push_str("\\\\"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            c if c as char == quote => {
                s.push('\\');
                s.push(quote);
            }
            0x20..=0x7e => s.push(c as char),
            c => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s.push(quote);
    s
}

// ---------------------------------------------------------------------------
// Text strings
// ---------------------------------------------------------------------------

/// Encodings for PDF text strings (`TextStringEncoding`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextStringEncoding {
    /// PDFDocEncoding.
    PdfDoc,
    /// UTF-16BE with BOM.
    Utf16Be,
    /// UTF-8 with BOM (PDF 2.0).
    Utf8,
    /// UTF-16LE with BOM (invalid, but seen in the wild).
    Utf16Le,
}

impl TextStringEncoding {
    /// Encode a string with BOM (`TextStringEncoding.encode`).
    pub fn encode(self, s: &str) -> PdfResult<Vec<u8>> {
        Ok(match self {
            Self::PdfDoc => encode_pdfdocencoding(s)?,
            Self::Utf16Be => {
                let mut out = vec![0xfe, 0xff];
                for u in s.encode_utf16() {
                    out.extend_from_slice(&u.to_be_bytes());
                }
                out
            }
            Self::Utf16Le => {
                let mut out = vec![0xff, 0xfe];
                for u in s.encode_utf16() {
                    out.extend_from_slice(&u.to_le_bytes());
                }
                out
            }
            Self::Utf8 => {
                let mut out = vec![0xef, 0xbb, 0xbf];
                out.extend_from_slice(s.as_bytes());
                out
            }
        })
    }

    /// Decode a string with BOM (`TextStringEncoding.decode`).
    pub fn decode(self, b: &[u8]) -> Option<String> {
        match self {
            Self::PdfDoc => decode_pdfdocencoding(b),
            Self::Utf8 => {
                let b = b.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(b);
                String::from_utf8(b.to_vec()).ok()
            }
            Self::Utf16Be | Self::Utf16Le => {
                // Python's 'utf-16' codec: BOM-driven, BOM stripped
                let (le, body) = if let Some(r) = b.strip_prefix(&[0xff, 0xfe]) {
                    (true, r)
                } else if let Some(r) = b.strip_prefix(&[0xfe, 0xff]) {
                    (false, r)
                } else {
                    (cfg!(target_endian = "little"), b)
                };
                if body.len() % 2 != 0 {
                    return None;
                }
                let units: Vec<u16> = body
                    .as_chunks::<2>().0.iter()
                    .map(|c| {
                        if le {
                            u16::from_le_bytes([c[0], c[1]])
                        } else {
                            u16::from_be_bytes([c[0], c[1]])
                        }
                    })
                    .collect();
                String::from_utf16(&units).ok()
            }
        }
    }

    /// Guess the encoding by BOM (`_guess_enc_by_bom`).
    pub fn guess_by_bom(b: &[u8]) -> Self {
        if b.starts_with(&[0xfe, 0xff]) {
            Self::Utf16Be
        } else if b.starts_with(&[0xff, 0xfe]) {
            Self::Utf16Le
        } else if b.starts_with(&[0xef, 0xbb, 0xbf]) {
            Self::Utf8
        } else {
            Self::PdfDoc
        }
    }
}

/// A classified PDF string (`pdf_string` on bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PdfString {
    /// Text string with its autodetected encoding (`TextStringObject`).
    Text(String, TextStringEncoding),
    /// Byte string (`ByteStringObject`).
    Bytes(Vec<u8>),
}

/// Classify string bytes as text or bytes (`pdf_string`).
pub fn pdf_string(b: &[u8]) -> PdfString {
    let guessed = TextStringEncoding::guess_by_bom(b);
    match guessed.decode(b) {
        Some(s) => PdfString::Text(s, guessed),
        None => PdfString::Bytes(b.to_vec()),
    }
}

/// Decode string bytes as text, or `None` for byte strings.
pub fn decode_text(b: &[u8]) -> Option<String> {
    match pdf_string(b) {
        PdfString::Text(s, _) => Some(s),
        PdfString::Bytes(_) => None,
    }
}

/// Encode text the way pyHanko serialises a `TextStringObject`:
/// PDFDocEncoding if possible, else UTF-16BE with BOM.
pub fn encode_text(s: &str) -> Vec<u8> {
    encode_pdfdocencoding(s).unwrap_or_else(|_| {
        let mut out = vec![0xfe, 0xff];
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_be_bytes());
        }
        out
    })
}

/// A text string object (`TextStringObject(s)`).
pub fn text_string(s: &str) -> Object {
    Object::String(encode_text(s), StringFormat::Literal)
}

/// A byte string object (`ByteStringObject(b)`), serialised in hex.
pub fn byte_string(b: impl Into<Vec<u8>>) -> Object {
    Object::String(b.into(), StringFormat::Hexadecimal)
}

/// A name object from a string with or without the leading slash.
pub fn pdf_name(s: &str) -> Object {
    Object::Name(s.strip_prefix('/').unwrap_or(s).as_bytes().to_vec())
}

const PDFDOC_80: [char; 31] = [
    '\u{2022}', '\u{2020}', '\u{2021}', '\u{2026}', '\u{2014}', '\u{2013}', '\u{0192}',
    '\u{2044}', '\u{2039}', '\u{203a}', '\u{2212}', '\u{2030}', '\u{201e}', '\u{201c}',
    '\u{201d}', '\u{2018}', '\u{2019}', '\u{201a}', '\u{2122}', '\u{fb01}', '\u{fb02}',
    '\u{0141}', '\u{0152}', '\u{0160}', '\u{0178}', '\u{017d}', '\u{0131}', '\u{0142}',
    '\u{0153}', '\u{0161}', '\u{017e}',
];
const PDFDOC_18: [char; 8] = [
    '\u{02d8}', '\u{02c7}', '\u{02c6}', '\u{02d9}', '\u{02dd}', '\u{02db}', '\u{02da}',
    '\u{02dc}',
];

fn pdfdoc_char(b: u8) -> Option<char> {
    match b {
        0x18..=0x1f => Some(PDFDOC_18[(b - 0x18) as usize]),
        0x20..=0x7e => Some(b as char),
        0x80..=0x9e => Some(PDFDOC_80[(b - 0x80) as usize]),
        0xa0 => Some('\u{20ac}'),
        0xa1..=0xac | 0xae..=0xff => Some(b as char),
        _ => None,
    }
}

/// Decode PDFDocEncoding; `None` if a byte is undefined.
pub fn decode_pdfdocencoding(b: &[u8]) -> Option<String> {
    b.iter().map(|&c| pdfdoc_char(c)).collect()
}

/// Encode PDFDocEncoding.
pub fn encode_pdfdocencoding(s: &str) -> PdfResult<Vec<u8>> {
    s.chars()
        .map(|c| {
            (0u8..=255)
                .rev()
                .find(|&b| pdfdoc_char(b) == Some(c))
                .or(if c == '\0' { Some(0xad) } else { None })
                .ok_or_else(|| {
                    PdfError::value(format!(
                        "'pdfdocencoding' codec can't encode character {c:?}: does not exist in translation table"
                    ))
                })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Write a name (`NameObject.write_to_stream`), given its bytes without `/`.
pub fn write_name(out: &mut Vec<u8>, name: &[u8]) {
    out.push(b'/');
    for &b in name {
        if b == b'#' || !(0x21..=0x7e).contains(&b) || !is_regular_character(b) {
            out.extend_from_slice(format!("#{b:02X}").as_bytes());
        } else {
            out.push(b);
        }
    }
}

/// Format a real number like pyHanko's `FloatObject.__repr__`.
pub fn format_real(v: f32) -> String {
    if v == 0.0 && v.is_sign_negative() {
        return "-0".into();
    }
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    format!("{v}")
}

fn write_literal_string(out: &mut Vec<u8>, b: &[u8]) {
    out.push(b'(');
    for &c in b {
        if c.is_ascii_alphanumeric() || c == b' ' {
            out.push(c);
        } else {
            out.extend_from_slice(format!("\\{c:03o}").as_bytes());
        }
    }
    out.push(b')');
}

fn write_hex_string(out: &mut Vec<u8>, b: &[u8]) {
    out.push(b'<');
    for &c in b {
        out.extend_from_slice(format!("{c:02x}").as_bytes());
    }
    out.push(b'>');
}

/// Write a string the way pyHanko writes the corresponding object: text
/// strings as escaped literals, byte strings (and strings explicitly marked
/// hexadecimal) in hex.
pub fn write_string(out: &mut Vec<u8>, b: &[u8], format: StringFormat) {
    if format == StringFormat::Hexadecimal || decode_text(b).is_none() {
        write_hex_string(out, b);
    } else {
        write_literal_string(out, b);
    }
}

/// Serialise an object (`PdfObject.write_to_stream`) without encryption.
pub fn write_object(out: &mut Vec<u8>, obj: &Object) {
    match obj {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(true) => out.extend_from_slice(b"true"),
        Object::Boolean(false) => out.extend_from_slice(b"false"),
        Object::Integer(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Object::Real(r) => out.extend_from_slice(format_real(*r).as_bytes()),
        Object::Name(n) => write_name(out, n),
        Object::String(s, f) => write_string(out, s, *f),
        Object::Array(a) => {
            out.push(b'[');
            for v in a {
                out.push(b' ');
                write_object(out, v);
            }
            out.extend_from_slice(b" ]");
        }
        Object::Dictionary(d) => write_dictionary(out, d),
        Object::Stream(s) => write_stream(out, &s.dict, &s.content),
        Object::Reference((id, gen)) => {
            out.extend_from_slice(format!("{id} {gen} R").as_bytes());
        }
    }
}

/// Serialise a dictionary.
pub fn write_dictionary(out: &mut Vec<u8>, d: &Dictionary) {
    out.extend_from_slice(b"<<\n");
    for (k, v) in d.iter() {
        write_name(out, k);
        out.push(b' ');
        write_object(out, v);
        out.push(b'\n');
    }
    out.extend_from_slice(b">>");
}

/// Serialise a stream with already encoded (and encrypted) data; `/Length` is
/// set to the data length.
pub fn write_stream(out: &mut Vec<u8>, dict: &Dictionary, data: &[u8]) {
    let mut d = dict.clone();
    d.set("Length", Object::Integer(data.len() as i64));
    write_dictionary(out, &d);
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
}

/// Serialise an object into a fresh buffer.
pub fn object_to_bytes(obj: &Object) -> Vec<u8> {
    let mut out = Vec::new();
    write_object(&mut out, obj);
    out
}

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

/// A parsed PDF date (`parse_pdf_date` result).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PdfDate {
    /// Year.
    pub year: i32,
    /// Month (1-12).
    pub month: u8,
    /// Day (1-31).
    pub day: u8,
    /// Hour.
    pub hour: u8,
    /// Minute.
    pub minute: u8,
    /// Second.
    pub second: u8,
    /// UTC offset in minutes; `None` for naive dates.
    pub utc_offset_minutes: Option<i32>,
}

impl PdfDate {
    /// Seconds since the Unix epoch (naive dates are taken as UTC).
    pub fn unix_timestamp(&self) -> i64 {
        let days = days_from_civil(self.year, self.month, self.day);
        days * 86400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
            - i64::from(self.utc_offset_minutes.unwrap_or(0)) * 60
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
pub(crate) fn days_from_civil(y: i32, m: u8, d: u8) -> i64 {
    let y = i64::from(y) - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn days_in_month(y: i32, m: u8) -> u8 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

/// Format a date as a PDF date string (`pdf_date`).
pub fn pdf_date(d: &PdfDate) -> String {
    let mut s = format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}",
        d.year, d.month, d.day, d.hour, d.minute, d.second
    );
    if let Some(off) = d.utc_offset_minutes {
        if off == 0 {
            s.push('Z');
        } else {
            let sign = if off < 0 { '-' } else { '+' };
            let a = off.abs();
            s.push_str(&format!("{sign}{:02}'{:02}'", a / 60, a % 60));
        }
    }
    s
}

/// Parse a PDF date string (`parse_pdf_date`).
pub fn parse_pdf_date(date_str: &str, strict: bool) -> PdfResult<PdfDate> {
    let date_str = date_str.trim_end();
    let rest = if strict {
        date_str.strip_prefix("D:")
    } else {
        Some(date_str.strip_prefix("D:").unwrap_or(date_str))
    };
    let not_a_date = || PdfError::read(format!("{date_str} does not appear to be a date string."));
    let rest = rest.ok_or_else(not_a_date)?;
    let rb = rest.as_bytes();
    if rb.len() < 4 || !rb[..4].iter().all(u8::is_ascii_digit) {
        return Err(not_a_date());
    }
    let year: i32 = rest[..4].parse().map_err(|_| not_a_date())?;
    let mut remaining = &rest[4..];
    let mut lower = [1u8, 1, 0, 0, 0];
    for slot in lower.iter_mut() {
        let b = remaining.as_bytes();
        if b.len() >= 2 && b[0].is_ascii_digit() && b[1].is_ascii_digit() {
            *slot = (b[0] - b'0') * 10 + (b[1] - b'0');
            remaining = &remaining[2..];
        } else {
            break;
        }
    }
    let [month, day, hour, minute, second] = lower;
    let mut offset = None;
    if !remaining.is_empty() {
        let sgn = remaining.as_bytes()[0];
        if sgn == b'Z' && remaining.len() == 1 {
            offset = Some(0);
        } else if sgn == b'+' || sgn == b'-' {
            let spec = &remaining[1..];
            let improper = || {
                PdfError::read(format!(
                    "Improper timezone specification in {date_str}: {spec}"
                ))
            };
            // (\d\d)(?:'(\d\d))?'? fullmatch
            let sb = spec.as_bytes();
            let two = |i: usize| -> Option<i32> {
                if sb.len() >= i + 2 && sb[i].is_ascii_digit() && sb[i + 1].is_ascii_digit() {
                    Some(i32::from(sb[i] - b'0') * 10 + i32::from(sb[i + 1] - b'0'))
                } else {
                    None
                }
            };
            let h = two(0).ok_or_else(improper)?;
            let (m, consumed) = if sb.len() >= 5 && sb[2] == b'\'' {
                match two(3) {
                    Some(m) => (m, 5),
                    None => (0, 2),
                }
            } else {
                (0, 2)
            };
            let tail = &sb[consumed..];
            if !(tail.is_empty() || tail == b"'") {
                return Err(improper());
            }
            let mut total = h * 60 + m;
            if sgn == b'-' {
                total = -total;
            }
            offset = Some(total);
        } else {
            return Err(PdfError::read(format!(
                "Improper trailing characters in {date_str}."
            )));
        }
    }
    let valid = (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour < 24
        && minute < 60
        && second < 60
        && year >= 1
        && offset.is_none_or(|o: i32| o.abs() < 24 * 60);
    if !valid {
        return Err(PdfError::read("Improper date value"));
    }
    Ok(PdfDate {
        year,
        month,
        day,
        hour,
        minute,
        second,
        utc_offset_minutes: offset,
    })
}

// ---------------------------------------------------------------------------
// Small helpers on lopdf objects
// ---------------------------------------------------------------------------

/// `Object` type name in pyHanko terms (for messages).
pub fn type_name(obj: &Object) -> &'static str {
    match obj {
        Object::Null => "NullObject",
        Object::Boolean(_) => "BooleanObject",
        Object::Integer(_) => "NumberObject",
        Object::Real(_) => "FloatObject",
        Object::Name(_) => "NameObject",
        Object::String(s, _) => match pdf_string(s) {
            PdfString::Text(..) => "TextStringObject",
            PdfString::Bytes(_) => "ByteStringObject",
        },
        Object::Array(_) => "ArrayObject",
        Object::Dictionary(_) => "DictionaryObject",
        Object::Stream(_) => "StreamObject",
        Object::Reference(_) => "IndirectObject",
    }
}

/// Name bytes as a `/Name` string (lossy).
pub fn name_str(n: &[u8]) -> String {
    format!("/{}", String::from_utf8_lossy(n))
}

/// `true` if `obj` is the name `/name` (`name` without slash).
pub fn is_name(obj: &Object, name: &str) -> bool {
    matches!(obj, Object::Name(n) if n == name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_format() {
        assert_eq!(format_real(32.0), "32");
        assert_eq!(format_real(32.00001), "32.00001");
        assert_eq!(format_real(-0.5), "-0.5");
    }
}
