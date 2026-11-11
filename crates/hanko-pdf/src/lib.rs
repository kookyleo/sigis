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

pub mod content_stream_parser;
pub mod crypt;
pub mod decode_limits;
pub mod embed;
pub mod error;
pub mod extensions;
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
    /// Offset pointed to by the revision's `startxref` / `/Prev`.
    pub startxref: u64,
    /// End of the revision's xref table (before the trailer) or xref stream
    /// object (`get_xref_container_info(rev).end_location`).
    pub xref_end: u64,
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
                    startxref: u64::try_from(m.declared_startxref).unwrap_or(0),
                    xref_end: m.end_location as u64,
                }
            })
            .collect())
    }

    /// The object `id` as it existed in `revision`: what
    /// `HistoricalResolver(revision).get_object(id)` returns, or `None` when
    /// the reference does not resolve as of that revision (freed or never
    /// defined).
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

    /// The trailer dictionary written in `revision` itself (for xref
    /// streams: the stream dictionary). Older trailers are not merged; see
    /// [`PdfFile::effective_trailer_in_revision`].
    pub fn trailer_in_revision(&self, revision: usize) -> Result<Dictionary> {
        self.trailer()
            .raw_revision(revision)
            .cloned()
            .ok_or_else(|| PdfError::value(format!("No revision {revision}")).into())
    }

    /// The effective trailer as of `revision`: all trailers up to that
    /// revision merged, minus stream/xref keys (`TrailerDictionary.flatten`).
    pub fn effective_trailer_in_revision(&self, revision: usize) -> Result<Dictionary> {
        if revision >= self.total_revisions() {
            return Err(PdfError::value(format!("No revision {revision}")).into());
        }
        Ok(self.trailer().flatten(Some(revision)))
    }

    /// Cross-reference details of `revision` (`XRefSectionData` +
    /// `XRefSectionMetaInfo`; requested by lane C as C1).
    pub fn xref_section(&self, revision: usize) -> Result<XrefSectionInfo> {
        let xr = self.xrefs();
        let meta = xr.get_xref_container_info(revision)?;
        let data = xr.get_xref_data(revision)?;
        Ok(XrefSectionInfo {
            size: u32::try_from(meta.size.max(0)).unwrap_or(u32::MAX),
            stream_ref: match meta.xref_section_type {
                xref::XRefSectionType::Stream => meta.stream_ref,
                _ => None,
            },
            hybrid_stream_ref: match meta.xref_section_type {
                xref::XRefSectionType::HybridMain => meta.stream_ref,
                _ => None,
            },
            explicit_refs: xr.explicit_refs_in_revision(revision),
            freed: xr.refs_freed_in_revision(revision),
            object_streams_used: data.obj_streams_used.clone(),
        })
    }

    /// Where the xref data of `revision` lies (`XRefSectionMetaInfo`;
    /// requested by lane E as R-E6).
    pub fn xref_location(&self, revision: usize) -> Result<XrefLocation> {
        let meta = self.xrefs().get_xref_container_info(revision)?;
        Ok(XrefLocation {
            declared_startxref: u64::try_from(meta.declared_startxref).unwrap_or(0),
            start: meta.start_location as u64,
            end: meta.end_location as u64,
        })
    }

    /// The last revision that wrote `id` (`get_last_change`).
    pub fn last_change(&self, id: ObjectId) -> Result<Option<usize>> {
        Ok(self.xrefs().get_last_change(id))
    }

    /// The first revision that defines `id` (`get_introducing_revision`).
    pub fn introducing_revision(&self, id: ObjectId) -> Result<Option<usize>> {
        Ok(self.xrefs().get_introducing_revision(id))
    }

    /// `true` if `id` resolves to an object as of `revision`
    /// (`get_historical_ref(id, revision) is not None`).
    pub fn resolves_in(&self, id: ObjectId, revision: usize) -> Result<bool> {
        if revision >= self.total_revisions() {
            return Err(PdfError::value(format!("No revision {revision}")).into());
        }
        Ok(self.xrefs().get_historical_ref(id, revision).is_some())
    }

    /// The signature field holding the signature dictionary `sig_object`
    /// (requested by lane E as R-E6).
    pub fn signature_field_ref(&self, sig_object: ObjectId) -> Result<Option<ObjectId>> {
        let fields = signatures::enumerate_sig_fields(self, Some(true), None)?;
        Ok(fields
            .into_iter()
            .find(|f| f.value == Some(Object::Reference(sig_object)))
            .map(|f| f.field_ref))
    }
}

/// Cross-reference details of one revision (see [`PdfFile::xref_section`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XrefSectionInfo {
    /// `/Size` of the section.
    pub size: u32,
    /// The xref stream of the section, if it is an xref stream section.
    pub stream_ref: Option<ObjectId>,
    /// The `/XRefStm` stream of a hybrid section.
    pub hybrid_stream_ref: Option<ObjectId>,
    /// References written in the section, including hybrid entries and freed
    /// objects as `(n, next_gen - 1)` (`explicit_refs_in_revision`).
    pub explicit_refs: std::collections::BTreeSet<ObjectId>,
    /// References freed in the section (`refs_freed_in_revision`).
    pub freed: std::collections::BTreeSet<ObjectId>,
    /// Object streams used by the section (`obj_streams_used`).
    pub object_streams_used: std::collections::BTreeSet<u32>,
}

/// Location of a revision's xref data (see [`PdfFile::xref_location`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XrefLocation {
    /// Offset pointed to by `startxref` / `/Prev`.
    pub declared_startxref: u64,
    /// Actual start of the xref table or stream.
    pub start: u64,
    /// End of the xref table (before the trailer) or of the xref stream
    /// object (`end_location`).
    pub end: u64,
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
