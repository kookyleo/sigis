// Interfaces derived from pyHanko `pdf_utils/` (reader, xref, writer,
// incremental_writer) and `sign/validation/pdf_embedded.py` / `dss.py`
// (MIT, see LICENSE-pyHanko).

//! PDF layer for signing and validation (`pyhanko.pdf_utils`).
//!
//! Built on [`lopdf`] (re-exported) for the object model; this crate adds
//! what signatures need, following pyHanko's reader and writer closely:
//! revision history (incremental updates, xref tables and streams, hybrid
//! files, object streams, strict and lenient modes), decoding limits,
//! byte-exact signed ranges, signature and DSS discovery, and an incremental
//! writer.
//!
//! Module map (pyHanko → Rust): `generic` → [`generic`], `misc` →
//! [`misc`], `xref` → [`xref`], `reader` → [`reader`], `writer` /
//! `incremental_writer` → [`writer`], `rw_common` → [`rw_common`],
//! `filters` → [`filters`], `decode_limits` → [`decode_limits`],
//! `metadata` → [`metadata`], signature discovery → [`signatures`].
//!
//! Owned by lane B (see `docs/hanko-lanes.md`). Lanes C, D and E code against
//! these types; changes go through the lead.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod decode_limits;
pub mod error;
pub mod filters;
pub mod generic;
pub mod metadata;
pub mod misc;
pub mod reader;
pub mod rw_common;
pub mod signatures;
pub mod stream;
pub mod writer;
pub mod xref;

use hanko_core::errors::Result;
pub use lopdf;
use lopdf::{Dictionary, Object, ObjectId};

pub use error::{PdfError, PdfResult};
pub use reader::{HistoricalResolver, PdfFile, ReaderOptions};
pub use rw_common::{PdfHandler, PdfHandlerExt};
pub use signatures::{DocumentSecurityStore, EmbeddedSignature, SignatureKind, VriEntry};
pub use writer::{IncrementalWriter, PdfFileWriter, PdfWriter};

/// DocMDP permission level (`MDPPerm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MdpPerm {
    /// No changes allowed (P=1).
    NoChanges = 1,
    /// Form filling and signing (P=2).
    FillForms = 2,
    /// Form filling, signing and annotations (P=3).
    Annotate = 3,
}

/// One revision (incremental update) of the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionInfo {
    /// Index, 0 for the original document.
    pub index: usize,
    /// Byte length of the file up to and including this revision's `%%EOF`.
    pub end_offset: usize,
    /// Whether the revision uses an xref stream.
    pub xref_stream: bool,
}

fn eof_after(bytes: &[u8], from: usize) -> usize {
    let from = from.min(bytes.len());
    match bytes[from..].windows(5).position(|w| w == b"%%EOF") {
        None => bytes.len(),
        Some(p) => skip_eol(bytes, from + p + 5),
    }
}

fn skip_eol(bytes: &[u8], mut end: usize) -> usize {
    if bytes.get(end) == Some(&b'\r') {
        end += 1;
    }
    if bytes.get(end) == Some(&b'\n') {
        end += 1;
    }
    end
}

/// `(startxref value, offset of the keyword, end of the following %%EOF
/// line)` for every `startxref N %%EOF` in the file.
fn startxref_markers(bytes: &[u8]) -> Vec<(i64, usize, usize)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(p) = bytes[pos..].windows(9).position(|w| w == b"startxref") {
        let kw = pos + p;
        pos = kw + 9;
        let skip_ws = |mut i: usize| {
            while i < bytes.len() && misc::is_whitespace(bytes[i]) {
                i += 1;
            }
            i
        };
        let start = skip_ws(pos);
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        let Some(v) = generic::parse_py_int(&bytes[start..end]) else { continue };
        let eof = skip_ws(end);
        if bytes[eof.min(bytes.len())..].starts_with(b"%%EOF") {
            out.push((v, kw, skip_eol(bytes, eof + 5)));
        }
    }
    out
}

impl PdfFile {
    /// Revisions, oldest first (`XRefCache` sections).
    pub fn revisions(&self) -> Result<Vec<RevisionInfo>> {
        let bytes = self.bytes();
        let markers = startxref_markers(bytes);
        Ok(self
            .xrefs()
            .sections()
            .iter()
            .enumerate()
            .map(|(index, s)| {
                let m = &s.meta_info;
                let end_offset = markers
                    .iter()
                    .find(|(v, kw, _)| *v == m.declared_startxref && *kw >= m.start_location)
                    .map(|(_, _, end)| *end)
                    .unwrap_or_else(|| eof_after(bytes, m.end_location));
                RevisionInfo {
                    index,
                    end_offset,
                    xref_stream: matches!(
                        s.meta_info.xref_section_type,
                        xref::XRefSectionType::Stream
                    ),
                }
            })
            .collect())
    }

    /// The object `id` as it existed in `revision`
    /// (`get_historical_resolver(revision).get_object(id)`), or `None` if
    /// the object is not defined (or freed) as of that revision.
    pub fn object_in_revision(&self, id: ObjectId, revision: usize) -> Result<Option<Object>> {
        if revision >= self.total_revisions() {
            return Err(PdfError::value(format!("No revision {revision}")).into());
        }
        if self.xrefs().get_historical_ref(id, revision).is_none() {
            return Ok(None);
        }
        Ok(Some(self.historical_resolver(revision).object(id)?))
    }

    /// Objects written in the xref section of `revision`
    /// (`explicit_refs_in_revision`), including hybrid entries.
    pub fn objects_written_in(&self, revision: usize) -> Result<Vec<ObjectId>> {
        if revision >= self.total_revisions() {
            return Err(PdfError::value(format!("No revision {revision}")).into());
        }
        Ok(self.xrefs().explicit_refs_in_revision(revision).into_iter().collect())
    }

    /// The effective trailer dictionary as of `revision` (all trailers up
    /// to that revision merged, `TrailerDictionary.flatten(revision)`).
    pub fn trailer_in_revision(&self, revision: usize) -> Result<Dictionary> {
        if revision >= self.total_revisions() {
            return Err(PdfError::value(format!("No revision {revision}")).into());
        }
        Ok(self.trailer().flatten(Some(revision)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eof_scan() {
        assert_eq!(eof_after(b"abc%%EOF\r\nx", 0), 10);
        assert_eq!(eof_after(b"abc%%EOFx", 0), 8);
        assert_eq!(eof_after(b"abc", 0), 3);
    }
}
