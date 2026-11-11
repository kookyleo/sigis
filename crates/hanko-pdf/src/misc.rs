// Derived from pyHanko `pdf_utils/misc.py` (MIT, see LICENSE-pyHanko).

//! Low-level tokenizer helpers (`pyhanko.pdf_utils.misc`).
//!
//! [`Cursor`] mimics the seekable byte stream (`BytesIO`) that pyHanko's
//! parsing functions operate on, so that the functions here can follow the
//! upstream logic step by step, including where they leave the position.

use crate::error::{PdfError, PdfResult};

/// PDF whitespace characters (`PDF_WHITESPACE`).
pub const PDF_WHITESPACE: &[u8] = b" \n\r\t\x0c\x00";
/// PDF delimiter characters (`PDF_DELIMITERS`).
pub const PDF_DELIMITERS: &[u8] = b"()<>[]{}/%";

/// `True` for PDF whitespace.
#[inline]
pub fn is_whitespace(b: u8) -> bool {
    PDF_WHITESPACE.contains(&b)
}

/// `True` for PDF delimiters.
#[inline]
pub fn is_delimiter(b: u8) -> bool {
    PDF_DELIMITERS.contains(&b)
}

/// Neither whitespace nor delimiter (`is_regular_character`).
#[inline]
pub fn is_regular_character(b: u8) -> bool {
    !is_whitespace(b) && !is_delimiter(b)
}

/// A position in a byte buffer with `BytesIO`-like semantics: reads past the
/// end return fewer bytes, seeking past the end is allowed, seeking before
/// the start is an error.
#[derive(Clone, Debug)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// A cursor at `pos`.
    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    /// The underlying data.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Current position.
    #[inline]
    pub fn tell(&self) -> usize {
        self.pos
    }

    /// Total length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Absolute seek.
    #[inline]
    pub fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Relative seek (`seek(off, SEEK_CUR)`).
    #[inline]
    pub fn seek_rel(&mut self, off: i64) -> PdfResult<()> {
        let new = self.pos as i64 + off;
        if new < 0 {
            return Err(PdfError::read(format!("negative seek value {new}")));
        }
        self.pos = new as usize;
        Ok(())
    }

    /// Seek relative to the end (`seek(off, SEEK_END)`).
    pub fn seek_end(&mut self, off: i64) -> PdfResult<()> {
        let new = self.data.len() as i64 + off;
        if new < 0 {
            return Err(PdfError::read(format!("negative seek value {new}")));
        }
        self.pos = new as usize;
        Ok(())
    }

    /// Read one byte.
    #[inline]
    pub fn read1(&mut self) -> Option<u8> {
        let b = self.data.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    /// Look at the next byte without consuming it.
    #[inline]
    pub fn peek1(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Read up to `n` bytes.
    pub fn read(&mut self, n: usize) -> &'a [u8] {
        if self.pos >= self.data.len() {
            return &[];
        }
        let end = self.pos.saturating_add(n).min(self.data.len());
        let out = &self.data[self.pos..end];
        self.pos = end;
        out
    }

    /// Look at up to `n` bytes without consuming them.
    pub fn peek(&self, n: usize) -> &'a [u8] {
        let start = self.pos.min(self.data.len());
        let end = start.saturating_add(n).min(self.data.len());
        &self.data[start..end]
    }

    /// Read everything that remains.
    pub fn read_rest(&mut self) -> &'a [u8] {
        self.read(usize::MAX)
    }
}

fn premature() -> PdfError {
    PdfError::stream("Stream ended prematurely")
}

/// Read until whitespace (`read_until_whitespace`). The whitespace byte is
/// consumed. `maxchars` bounds the number of bytes read.
pub fn read_until_whitespace(stream: &mut Cursor<'_>, maxchars: Option<usize>) -> Vec<u8> {
    read_until_class(stream, is_whitespace, maxchars).0
}

/// Read until a delimiter or whitespace, and leave the cursor on it
/// (`read_until_delimiter`).
pub fn read_until_delimiter(stream: &mut Cursor<'_>) -> Vec<u8> {
    let (res, end) = read_until_class(stream, |b| is_whitespace(b) || is_delimiter(b), None);
    if !end {
        // cannot underflow: at least one byte was read
        stream.pos -= 1;
    }
    res
}

fn read_until_class(
    stream: &mut Cursor<'_>,
    class: impl Fn(u8) -> bool,
    maxchars: Option<usize>,
) -> (Vec<u8>, bool) {
    let maxchars = maxchars.filter(|&m| m > 0);
    let stop_at = maxchars.map(|m| stream.tell() + m);
    let mut out = Vec::new();
    loop {
        if let Some(stop) = stop_at {
            if stream.tell() >= stop {
                return (out, false);
            }
        }
        match stream.read1() {
            None => return (out, true),
            Some(b) if class(b) => return (out, false),
            Some(b) => out.push(b),
        }
    }
}

/// Read the next non-whitespace byte, skipping comments
/// (`read_non_whitespace`). Returns `None` only at the end of the stream
/// with `allow_eof`.
pub fn read_non_whitespace(
    stream: &mut Cursor<'_>,
    seek_back: bool,
    allow_eof: bool,
) -> PdfResult<Option<u8>> {
    let tok = loop {
        let tok = loop {
            match stream.read1() {
                None => {
                    if allow_eof {
                        return Ok(None);
                    }
                    return Err(premature());
                }
                Some(b) if is_whitespace(b) => continue,
                Some(b) => break b,
            }
        };
        if tok != b'%' {
            break tok;
        }
        stream.seek_rel(-1)?;
        skip_over_comments(stream, true)?;
    };
    if seek_back {
        stream.seek_rel(-1)?;
    }
    Ok(Some(tok))
}

/// Like [`read_non_whitespace`] without `allow_eof`.
pub fn read_non_ws(stream: &mut Cursor<'_>) -> PdfResult<u8> {
    read_non_whitespace(stream, false, false)?.ok_or_else(premature)
}

/// Skip whitespace (`skip_over_whitespace`); returns `true` if more than one
/// byte was read.
pub fn skip_over_whitespace(
    stream: &mut Cursor<'_>,
    stop_after_eol: bool,
    error_on_end_of_stream: bool,
) -> PdfResult<bool> {
    let mut cnt = 0usize;
    loop {
        let Some(tok) = stream.read1() else {
            if error_on_end_of_stream {
                return Err(premature());
            }
            return Ok(true);
        };
        cnt += 1;
        if !is_whitespace(tok) {
            break;
        }
        if stop_after_eol {
            if tok == b'\n' {
                return Ok(cnt > 1);
            } else if tok == b'\r' {
                match stream.read1() {
                    Some(b'\n') | None => return Ok(cnt > 1),
                    Some(_) => break,
                }
            }
        }
    }
    stream.seek_rel(-1)?;
    Ok(cnt > 1)
}

/// Skip comments (`skip_over_comments`); returns `true` if a comment was read.
pub fn skip_over_comments(stream: &mut Cursor<'_>, error_on_end_of_stream: bool) -> PdfResult<bool> {
    let mut tok = stream.read1();
    let mut seen = false;
    while tok == Some(b'%') {
        seen = true;
        while !matches!(tok, Some(b'\n') | Some(b'\r') | None) {
            tok = stream.read1();
        }
        skip_over_whitespace(stream, false, error_on_end_of_stream)?;
        tok = stream.read1();
    }
    if tok.is_some() {
        stream.seek_rel(-1)?;
    }
    Ok(seen)
}

/// Read until the first byte matching `stop` and leave the cursor on it
/// (`read_until_regex` with a single-character class).
pub fn read_until_byte_class(
    stream: &mut Cursor<'_>,
    stop: impl Fn(u8) -> bool,
    ignore_eof: bool,
) -> PdfResult<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        match stream.peek1() {
            None => {
                if ignore_eof {
                    return Ok(out);
                }
                return Err(PdfError::stream("Stream has ended unexpectedly"));
            }
            Some(b) if stop(b) => return Ok(out),
            Some(b) => {
                out.push(b);
                stream.pos += 1;
            }
        }
    }
}

/// Iterate over pairs of a flat list (`pair_iter`).
pub fn pair_iter<T: Copy>(items: &[T]) -> PdfResult<Vec<(T, T)>> {
    if !items.len().is_multiple_of(2) {
        return Err(PdfError::value("List has odd number of elements"));
    }
    Ok(items.as_chunks::<2>().0.iter().map(|c| (c[0], c[1])).collect())
}

/// Python's `bytes.isspace()` for a single byte (ASCII whitespace incl. `\v`).
#[inline]
pub(crate) fn py_isspace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_read_semantics() {
        let mut c = Cursor::new(b"abc");
        assert_eq!(c.read(2), b"ab");
        assert_eq!(c.read(5), b"c");
        assert_eq!(c.read(1), b"");
        assert_eq!(c.tell(), 3);
        c.seek(10);
        assert_eq!(c.read(1), b"");
        assert_eq!(c.tell(), 10);
        assert!(c.seek_rel(-11).is_err());
    }
}
