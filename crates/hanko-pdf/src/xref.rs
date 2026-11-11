// Derived from pyHanko `pdf_utils/xref.py` (MIT, see LICENSE-pyHanko).

//! Cross-reference sections and trailers (`pyhanko.pdf_utils.xref`).
//!
//! Sections are kept per revision, so that objects can be resolved as of
//! any revision. In strict mode, the consistency rules of pyHanko apply:
//! free/reuse generation bookkeeping, nondecreasing sizes, no clobbering of
//! xref streams.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use lopdf::{Dictionary, Object, ObjectId};

use crate::decode_limits::{DecodeContext, DecodePurpose};
use crate::error::{PdfError, PdfResult};
use crate::generic::{self, parse_py_int, read_number, ParseContext};
use crate::misc::{
    read_non_whitespace, read_until_whitespace, skip_over_comments, skip_over_whitespace, Cursor,
};
use crate::stream::{decode_stream_data, no_deref};

/// Type of a cross-reference entry (`XRefType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XRefType {
    /// A freeing instruction.
    Free,
    /// A regular top-level object.
    Standard,
    /// An object in an object stream.
    InObjStream,
}

/// An object in an object stream (`ObjStreamRef`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjStreamRef {
    /// Object number of the object stream (generation 0).
    pub obj_stream_id: u32,
    /// Index in the stream.
    pub ix_in_stream: i64,
}

/// Where an object lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XRefLocation {
    /// Byte offset of a top-level object.
    Offset(i64),
    /// Position in an object stream.
    ObjStream(ObjStreamRef),
}

/// A single cross-reference entry (`XRefEntry`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XRefEntry {
    /// Entry type.
    pub xref_type: XRefType,
    /// Location (`None` for free entries).
    pub location: Option<XRefLocation>,
    /// Object number.
    pub idnum: i64,
    /// Generation number (next generation for free entries).
    pub generation: i64,
}

impl XRefEntry {
    /// A standard entry.
    pub fn standard(idnum: i64, location: i64, generation: i64) -> Self {
        Self {
            xref_type: XRefType::Standard,
            location: Some(XRefLocation::Offset(location)),
            idnum,
            generation,
        }
    }

    /// An entry in an object stream.
    pub fn in_obj_stream(idnum: i64, obj_stream_id: u32, ix: i64) -> Self {
        Self {
            xref_type: XRefType::InObjStream,
            location: Some(XRefLocation::ObjStream(ObjStreamRef {
                obj_stream_id,
                ix_in_stream: ix,
            })),
            idnum,
            generation: 0,
        }
    }

    /// A free entry.
    pub fn free(idnum: i64, generation: i64) -> Self {
        Self {
            xref_type: XRefType::Free,
            location: None,
            idnum,
            generation,
        }
    }
}

fn xref_parse_decimal(raw: &[u8], context: &str) -> PdfResult<i64> {
    parse_py_int(raw).ok_or_else(|| {
        PdfError::read(format!(
            "{context}: expected decimal string, but got {}",
            generic::py_bytes_repr(raw)
        ))
    })
}

fn read_int(stream: &mut Cursor<'_>) -> PdfResult<i64> {
    match read_number(stream)? {
        Object::Integer(i) => Ok(i),
        other => Err(PdfError::value(format!("Expected an integer, got {other:?}"))),
    }
}

/// Parse a cross-reference table at the cursor (`parse_xref_table`).
pub fn parse_xref_table(stream: &mut Cursor<'_>, strict: bool) -> PdfResult<Vec<XRefEntry>> {
    let mut out = Vec::new();
    read_non_whitespace(stream, true, false)?;
    let mut seen = BTreeSet::new();
    loop {
        let first = read_int(stream)?;
        read_non_whitespace(stream, true, false)?;
        let size = read_int(stream)?;
        read_non_whitespace(stream, true, false)?;
        for num in first..first.saturating_add(size.max(0)) {
            if !seen.insert(num) {
                return Err(PdfError::read(format!(
                    "Object number {num} appears in more than one subsection of the same xref section"
                )));
            }
            let mut line = stream.read(20);
            loop {
                match line.first() {
                    None => return Err(PdfError::read("Unexpected end of file in xref table")),
                    Some(b'\r') | Some(b'\n') => {
                        stream.seek_rel(-20 + 1)?;
                        line = stream.read(20);
                        if line.len() != 20 {
                            return Err(PdfError::read("Unexpected end of file in xref table"));
                        }
                    }
                    Some(_) => break,
                }
            }
            if line.last().is_some_and(|b| b"0123456789t".contains(b)) {
                stream.seek_rel(-1)?;
            }
            let head = &line[..line.len().min(18)];
            let mut parts: Vec<&[u8]> = head.splitn(3, |&b| b == b' ').collect();
            if !strict && parts.len() == 3 && parts[2].len() > 1 {
                parts = py_split_ws(head, 2);
            }
            if parts.len() != 3 {
                return Err(PdfError::value(format!(
                    "not enough values to unpack in xref line {}",
                    generic::py_bytes_repr(line)
                )));
            }
            let (offset, generation, marker) = (parts[0], parts[1], parts[2]);
            if marker == b"n" {
                out.push(XRefEntry::standard(
                    num,
                    xref_parse_decimal(offset, "XRef line parsing error (location)")?,
                    xref_parse_decimal(generation, "XRef line parsing error (generation)")?,
                ));
            } else if marker == b"f" {
                out.push(XRefEntry::free(
                    num,
                    xref_parse_decimal(generation, "XRef line parsing error (generation to free)")?,
                ));
            } else if strict {
                return Err(PdfError::strict(format!(
                    "Unknown marker {}",
                    generic::py_bytes_repr(marker)
                )));
            }
        }
        read_non_whitespace(stream, true, false)?;
        let trailertag = stream.read(7);
        if trailertag == b"trailer" {
            read_non_whitespace(stream, true, false)?;
            return Ok(out);
        }
        stream.seek_rel(-(trailertag.len() as i64))?;
    }
}

/// Python `bytes.split(maxsplit=n)` (split on runs of ASCII whitespace).
fn py_split_ws(s: &[u8], maxsplit: usize) -> Vec<&[u8]> {
    let is_ws = |b: &u8| matches!(*b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        while i < s.len() && is_ws(&s[i]) {
            i += 1;
        }
        if i >= s.len() {
            break;
        }
        if out.len() == maxsplit {
            let mut end = s.len();
            while end > i && is_ws(&s[end - 1]) {
                end -= 1;
            }
            out.push(&s[i..end]);
            return out;
        }
        let start = i;
        while i < s.len() && !is_ws(&s[i]) {
            i += 1;
        }
        out.push(&s[start..i]);
    }
    out
}

fn int_array(obj: Option<&Object>) -> Option<Vec<i64>> {
    match obj? {
        Object::Array(a) => a
            .iter()
            .map(|o| match o {
                Object::Integer(i) => Some(*i),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// Expected decoded size of an xref stream from its `/Index` and `/W`
/// (`_expected_xref_stream_size`); `None` if they are malformed.
pub fn expected_xref_stream_size_of(index: &Object, w: Option<&Object>) -> Option<i64> {
    let idx = int_array(Some(index))?;
    let w = int_array(w)?;
    expected_xref_stream_size(&idx, &w)
}

fn expected_xref_stream_size(idx_pairs: &[i64], entry_sizes: &[i64]) -> Option<i64> {
    if !idx_pairs.len().is_multiple_of(2) {
        return None;
    }
    let count: i64 = idx_pairs.as_chunks::<2>().0.iter().map(|c| c[1]).sum();
    let width: i64 = entry_sizes.iter().sum();
    count.checked_mul(width + 1)
}

/// Big-endian integer of `size` bytes (`convert_to_int`).
fn convert_to_int(d: &[u8], size: usize) -> PdfResult<i64> {
    if size <= 8 {
        let mut buf = [0u8; 8];
        buf[8 - d.len()..].copy_from_slice(d);
        Ok(i64::from_be_bytes(buf))
    } else {
        let mut v: i128 = 0;
        for &b in d {
            v = v
                .checked_mul(256)
                .and_then(|v| v.checked_add(i128::from(b)))
                .ok_or_else(|| PdfError::read("XRef stream entry value too large"))?;
        }
        i64::try_from(v).map_err(|_| PdfError::read("XRef stream entry value too large"))
    }
}

/// Parse the entries of a cross-reference stream (`parse_xref_stream`).
pub fn parse_xref_stream(
    dict: &Dictionary,
    encoded: &[u8],
    ctx: &mut DecodeContext,
    strict: bool,
) -> PdfResult<Vec<XRefEntry>> {
    let idx_pairs = match dict.get(b"Index") {
        Ok(o) => int_array(Some(o)),
        Err(_) => match dict.get(b"Size") {
            Ok(Object::Integer(s)) => Some(vec![0, *s]),
            _ => None,
        },
    }
    .ok_or_else(|| PdfError::value("Invalid /Index or /Size in xref stream"))?;
    let entry_sizes =
        int_array(dict.get(b"W").ok()).ok_or_else(|| PdfError::value("Invalid /W in xref stream"))?;
    if entry_sizes.len() < 3 || entry_sizes.iter().any(|&w| w < 0) {
        return Err(PdfError::value("Invalid /W in xref stream"));
    }
    let data = decode_stream_data(
        dict,
        encoded,
        ctx,
        DecodePurpose::XrefStream,
        expected_xref_stream_size(&idx_pairs, &entry_sizes),
        &no_deref,
        None,
    )?;
    let mut sd = Cursor::new(&data);
    let get_entry = |sd: &mut Cursor<'_>, ix: usize| -> PdfResult<i64> {
        let width = entry_sizes[ix] as usize;
        if width > 0 {
            let d = sd.read(width);
            if d.len() >= width {
                return convert_to_int(d, width);
            } else if strict {
                return Err(PdfError::strict(format!(
                    "XRef stream ended prematurely; incomplete entry: expected to read {width} bytes, but only got {}.",
                    d.len()
                )));
            }
        }
        Ok(if ix == 0 { 1 } else { 0 })
    };
    if idx_pairs.len() % 2 != 0 {
        return Err(PdfError::value("List has odd number of elements"));
    }
    // Guard against absurd entry counts (pyHanko would loop until memory
    // runs out): an entry needs at least one byte unless all widths are 0.
    let width: i64 = entry_sizes.iter().sum();
    let declared: i64 = idx_pairs.as_chunks::<2>().0.iter().map(|c| c[1].max(0)).fold(0i64, i64::saturating_add);
    if declared > (data.len() as i64 / width.max(1)).saturating_add(1_000_000) {
        return Err(PdfError::read("XRef stream declares too many entries"));
    }
    let mut out = Vec::new();
    let mut last_end = 0i64;
    for pair in idx_pairs.as_chunks::<2>().0 {
        let (start, size) = (pair[0], pair[1]);
        if start < last_end {
            return Err(PdfError::read("XRef stream subsections must be increasing"));
        }
        last_end = start.saturating_add(size);
        for num in start..last_end {
            let xref_type = get_entry(&mut sd, 0)?;
            match xref_type {
                1 => {
                    let location = get_entry(&mut sd, 1)?;
                    let generation = get_entry(&mut sd, 2)?;
                    out.push(XRefEntry::standard(num, location, generation));
                }
                2 => {
                    let objstr_num = get_entry(&mut sd, 1)?;
                    let objstr_idx = get_entry(&mut sd, 2)?;
                    let objstr_num = u32::try_from(objstr_num)
                        .map_err(|_| PdfError::read("Invalid object stream number"))?;
                    out.push(XRefEntry::in_obj_stream(num, objstr_num, objstr_idx));
                }
                0 => {
                    get_entry(&mut sd, 1)?;
                    let next_generation = get_entry(&mut sd, 2)?;
                    out.push(XRefEntry::free(num, next_generation));
                }
                _ => {
                    get_entry(&mut sd, 1)?;
                    get_entry(&mut sd, 2)?;
                }
            }
        }
    }
    if !sd.read(1).is_empty() && strict {
        return Err(PdfError::strict("Trailing data in cross-reference stream"));
    }
    Ok(out)
}

/// Type of a cross-reference section (`XRefSectionType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XRefSectionType {
    /// Classical xref table.
    Standard,
    /// Xref stream.
    Stream,
    /// Table of a hybrid-reference section.
    HybridMain,
    /// Stream of a hybrid-reference section.
    HybridStream,
}

/// Metadata of a section (`XRefSectionMetaInfo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XRefSectionMetaInfo {
    /// Section type.
    pub xref_section_type: XRefSectionType,
    /// Declared `/Size`.
    pub size: i64,
    /// Offset pointed to by `startxref` / `/Prev`.
    pub declared_startxref: i64,
    /// Actual start of the xref data.
    pub start_location: usize,
    /// End of the xref data.
    pub end_location: usize,
    /// The xref stream, if any.
    pub stream_ref: Option<ObjectId>,
}

/// Entries of one section (`XRefSectionData`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct XRefSectionData {
    /// Freed objects: object number → next generation.
    pub freed: BTreeMap<u32, i64>,
    /// Standard entries: object number → (generation, offset).
    pub standard_xrefs: BTreeMap<u32, (u16, i64)>,
    /// Entries in object streams.
    pub xrefs_in_objstm: BTreeMap<u32, ObjStreamRef>,
    /// `(idnum, generation)` pairs written in this section (free entries
    /// register `generation - 1`, which may be `-1` for dead objects).
    pub explicit_refs_in_revision: BTreeSet<(u32, i64)>,
    /// Object streams used.
    pub obj_streams_used: BTreeSet<u32>,
    /// The hybrid stream section, if any.
    pub hybrid: Option<Box<XRefSection>>,
}

/// Result of [`XRefSectionData::try_resolve`].
pub type TryResolve = Option<Option<XRefLocation>>;

impl XRefSectionData {
    /// Look up a reference in this section: `None` if the section has nothing
    /// to say (Python `KeyError`), `Some(None)` if it frees the object,
    /// `Some(Some(loc))` if it defines it.
    pub fn try_resolve(&self, idnum: u32, generation: i64) -> TryResolve {
        if generation == 0 {
            if let Some(r) = self.xrefs_in_objstm.get(&idnum) {
                return Some(Some(XRefLocation::ObjStream(*r)));
            }
        }
        if let Some((gen, off)) = self.standard_xrefs.get(&idnum) {
            if i64::from(*gen) == generation {
                return Some(Some(XRefLocation::Offset(*off)));
            }
            return None;
        }
        if let Some(next) = self.freed.get(&idnum) {
            if generation == next - 1 {
                return Some(None);
            }
        }
        match &self.hybrid {
            Some(h) => h.xref_data.try_resolve(idnum, generation),
            None => None,
        }
    }

    /// Register entries (`process_entries`); returns the highest object number.
    pub fn process_entries(&mut self, entries: &[XRefEntry], strict: bool) -> PdfResult<i64> {
        let mut highest = 0i64;
        for e in entries {
            highest = highest.max(e.idnum);
            if e.generation > 0xffff {
                if strict {
                    return Err(PdfError::strict(format!(
                        "Illegal generation {} for object ID {}.",
                        e.generation, e.idnum
                    )));
                }
                continue;
            }
            if e.idnum == 0 {
                continue;
            }
            let Ok(idnum) = u32::try_from(e.idnum) else {
                if strict {
                    return Err(PdfError::strict(format!(
                        "Illegal object ID {} in xref section.",
                        e.idnum
                    )));
                }
                continue;
            };
            let generation = e.generation;
            match (e.xref_type, e.location) {
                (XRefType::Standard, Some(XRefLocation::Offset(off))) => {
                    let Ok(g) = u16::try_from(generation) else {
                        if strict {
                            return Err(PdfError::strict(format!(
                                "Illegal generation {generation} for object ID {idnum}."
                            )));
                        }
                        continue;
                    };
                    self.standard_xrefs.insert(idnum, (g, off));
                    self.explicit_refs_in_revision.insert((idnum, generation));
                }
                (XRefType::InObjStream, Some(XRefLocation::ObjStream(loc))) => {
                    self.xrefs_in_objstm.insert(idnum, loc);
                    self.obj_streams_used.insert(loc.obj_stream_id);
                    self.explicit_refs_in_revision.insert((idnum, 0));
                }
                (XRefType::Free, _) => {
                    self.freed.insert(idnum, generation);
                    self.explicit_refs_in_revision.insert((idnum, generation - 1));
                }
                _ => return Err(PdfError::value("Inconsistent xref entry")),
            }
        }
        Ok(highest)
    }

    /// Register the hybrid stream entries (`process_hybrid_entries`).
    pub fn process_hybrid_entries(
        &mut self,
        entries: &[XRefEntry],
        meta_info: XRefSectionMetaInfo,
        strict: bool,
    ) -> PdfResult<()> {
        let mut hybrid = XRefSectionData::default();
        hybrid.process_entries(entries, strict)?;
        self.hybrid = Some(Box::new(XRefSection {
            meta_info,
            xref_data: hybrid,
        }));
        Ok(())
    }

    /// Standard entries with a generation above zero.
    pub fn higher_generation_refs(&self) -> impl Iterator<Item = (u32, u16)> + '_ {
        self.standard_xrefs
            .iter()
            .filter(|(_, (g, _))| *g > 0)
            .map(|(i, (g, _))| (*i, *g))
    }
}

/// A cross-reference section (`XRefSection`).
#[derive(Clone, Debug, PartialEq)]
pub struct XRefSection {
    /// Metadata.
    pub meta_info: XRefSectionMetaInfo,
    /// Entries.
    pub xref_data: XRefSectionData,
}

fn check_freed_refs(ix: usize, section: &XRefSection, all: &[XRefSection]) -> PdfResult<()> {
    if let Some((sid, sgen)) = section.meta_info.stream_ref {
        let as_tuple = (sid, i64::from(sgen));
        for s in &all[ix + 1..] {
            if s.xref_data.explicit_refs_in_revision.contains(&as_tuple) {
                return Err(PdfError::strict(
                    "XRef stream objects must not be clobbered in strict mode.",
                ));
            }
        }
    }
    for (&idnum, &expected_next_generation) in &section.xref_data.freed {
        if expected_next_generation == 0 && ix > 0 {
            return Err(PdfError::strict(
                "In strict mode, a free xref with next generation 0 is onlypermitted in an initial revision due to unclear semantics.",
            ));
        }
        if ix + 1 < all.len() {
            if let Some(h) = &all[ix + 1].xref_data.hybrid {
                let h = &h.xref_data;
                if h.standard_xrefs.contains_key(&idnum) || h.xrefs_in_objstm.contains_key(&idnum) {
                    continue;
                }
            }
        }
        let mut improper_generation: Option<i64> = None;
        for succ in &all[ix + 1..] {
            let data = &succ.xref_data;
            if data.xrefs_in_objstm.contains_key(&idnum) {
                improper_generation = Some(0);
            } else if let Some((next_generation, _)) = data.standard_xrefs.get(&idnum) {
                let ng = i64::from(*next_generation);
                if expected_next_generation == 0 || ng < expected_next_generation {
                    improper_generation = Some(ng);
                }
            }
            if let Some(ig) = improper_generation {
                if expected_next_generation == 0 {
                    return Err(PdfError::strict(format!(
                        "Object with id {idnum} was listed as dead, but is reused later, with generation number {ig}."
                    )));
                }
                return Err(PdfError::strict(format!(
                    "Object with id {idnum} and generation {ig} was found after {} was freed.",
                    expected_next_generation - 1
                )));
            }
        }
    }
    Ok(())
}

fn check_xref_consistency(all: &[XRefSection]) -> PdfResult<()> {
    for (ix, section) in all.iter().enumerate() {
        check_freed_refs(ix, section, all)?;
    }
    let mut expanded: Vec<&XRefSection> = Vec::new();
    for s in all {
        if let Some(h) = &s.xref_data.hybrid {
            expanded.push(h);
        }
        expanded.push(s);
    }
    let mut prev_size = 0i64;
    for (ix, section) in expanded.iter().enumerate() {
        let sz = section.meta_info.size;
        let xref_type = section.meta_info.xref_section_type;
        if sz < prev_size && xref_type != XRefSectionType::HybridStream {
            return Err(PdfError::strict(format!(
                "XRef section sizes must be nondecreasing; found XRef section of size {sz} after section of size {prev_size}."
            )));
        }
        prev_size = prev_size.max(sz);
        let is_hybrid_stream = xref_type == XRefSectionType::HybridStream;
        for (idnum, generation) in section.xref_data.higher_generation_refs() {
            let generation = i64::from(generation);
            let mut preceding = expanded[..ix].iter().rev();
            if is_hybrid_stream {
                // the hybrid stream special case: the next element always
                // exists because hybrid streams precede their main section
                let Some(prec) = preceding.next() else {
                    return Err(PdfError::read("Hybrid xref stream without a main section"));
                };
                if prec.xref_data.freed.contains_key(&idnum) {
                    // Python: `break` out of the loop over higher_gen
                    break;
                }
            }
            let found = preceding.any(|prec| prec.xref_data.freed.get(&idnum) == Some(&generation));
            if !found {
                return Err(PdfError::strict(format!(
                    "Object with id {idnum} has an orphaned generation: generation {generation} was not preceded by a free instruction for generation {}.",
                    generation - 1
                )));
            }
        }
    }
    Ok(())
}

/// Error from [`read_object_header`]: a header that could not be parsed
/// (`ObjectHeaderReadError`) or another error.
#[derive(Debug)]
pub(crate) enum HeaderError {
    Header(PdfError),
    Other(PdfError),
}

impl From<HeaderError> for PdfError {
    fn from(e: HeaderError) -> Self {
        match e {
            HeaderError::Header(e) | HeaderError::Other(e) => e,
        }
    }
}

pub(crate) fn read_object_header_inner(
    stream: &mut Cursor<'_>,
    strict: bool,
) -> Result<(i64, i64), HeaderError> {
    let pos = stream.tell();
    let header_err = || HeaderError::Header(PdfError::read(format!("Failed to read object header at {pos}")));
    let mut extra = skip_over_whitespace(stream, false, true).map_err(HeaderError::Other)?;
    extra |= skip_over_comments(stream, true).map_err(HeaderError::Other)?;
    let idnum = parse_py_int(&read_until_whitespace(stream, None)).ok_or_else(header_err)?;
    extra |= skip_over_whitespace(stream, false, true).map_err(HeaderError::Other)?;
    let generation = parse_py_int(&read_until_whitespace(stream, None)).ok_or_else(header_err)?;
    stream.read(3);
    read_non_whitespace(stream, true, false).map_err(HeaderError::Other)?;
    if extra && strict {
        log::warn!("Superfluous whitespace found in object header {idnum} {generation}");
    }
    Ok((idnum, generation))
}

/// Read an object header `n g obj` (`read_object_header`).
pub fn read_object_header(stream: &mut Cursor<'_>, strict: bool) -> PdfResult<(i64, i64)> {
    read_object_header_inner(stream, strict).map_err(PdfError::from)
}

/// Trailer dictionaries of all revisions (`TrailerDictionary`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrailerDictionary {
    /// Trailers in processing order: index 0 is the most recent.
    revisions: Vec<Dictionary>,
    new_changes: Dictionary,
}

/// Keys not subject to trailer inheritance (`non_trailer_keys`).
pub const NON_TRAILER_KEYS: [&[u8]; 7] = [
    b"Length",
    b"Filter",
    b"DecodeParms",
    b"W",
    b"Type",
    b"Index",
    b"XRefStm",
];

impl TrailerDictionary {
    /// Add a revision (older revisions are added later).
    pub fn add_trailer_revision(&mut self, d: Dictionary) {
        self.revisions.push(d);
    }

    /// Number of trailer revisions.
    pub fn len(&self) -> usize {
        self.revisions.len()
    }

    /// `true` if there are no revisions.
    pub fn is_empty(&self) -> bool {
        self.revisions.is_empty()
    }

    /// Raw value of `key`, as of `revision` (latest if `None`, including
    /// pending changes) (`raw_get`).
    pub fn raw_get(&self, key: &[u8], revision: Option<usize>) -> Option<Object> {
        let revs: &[Dictionary] = match revision {
            None => {
                if let Ok(v) = self.new_changes.get(key) {
                    return Some(v.clone());
                }
                &self.revisions
            }
            Some(r) => {
                let section = self.revisions.len().checked_sub(1 + r)?;
                &self.revisions[section..]
            }
        };
        if NON_TRAILER_KEYS.contains(&key) {
            return revs.first()?.get(key).ok().cloned();
        }
        revs.iter().find_map(|d| d.get(key).ok().cloned())
    }

    /// The trailer of `revision` as written in that section (chronological
    /// index; hybrid xref streams contribute no trailer of their own).
    pub fn raw_revision(&self, revision: usize) -> Option<&Dictionary> {
        let ix = self.revisions.len().checked_sub(1 + revision)?;
        self.revisions.get(ix)
    }

    /// Set a pending value.
    pub fn set(&mut self, key: &[u8], value: Object) {
        self.new_changes.set(key.to_vec(), value);
    }

    /// Delete a pending value (`__delitem__`).
    pub fn remove(&mut self, key: &[u8]) -> PdfResult<()> {
        if self.new_changes.remove(key).is_some() {
            Ok(())
        } else {
            Err(PdfError::Generic(
                "Cannot remove existing entries from trailer dictionary, only update them.".into(),
            ))
        }
    }

    /// `key in trailer`.
    pub fn contains(&self, key: &[u8]) -> bool {
        self.raw_get(key, None).is_some()
    }

    /// The merged trailer as of `revision` (`flatten`).
    pub fn flatten(&self, revision: Option<usize>) -> Dictionary {
        let relevant: &[Dictionary] = match revision {
            None => &self.revisions,
            Some(r) => {
                let start = self.revisions.len().saturating_sub(r + 1);
                &self.revisions[start..]
            }
        };
        let mut trailer = Dictionary::new();
        for rev in relevant.iter().rev() {
            for (k, v) in rev.iter() {
                trailer.set(k.clone(), v.clone());
            }
        }
        if revision.is_none() {
            for (k, v) in self.new_changes.iter() {
                trailer.set(k.clone(), v.clone());
            }
        }
        for k in NON_TRAILER_KEYS {
            trailer.remove(k);
        }
        trailer
    }
}

/// Reads the chain of xref sections (`XRefBuilder`).
pub(crate) struct XRefBuilder<'a> {
    data: &'a [u8],
    strict: bool,
    last_startxref: i64,
    sections: Vec<XRefSection>,
    pub(crate) trailer: TrailerDictionary,
    pub(crate) has_xref_stream: bool,
}

const ERR_LIMIT: usize = 10;

fn prev_of(trailer: &Dictionary) -> PdfResult<Option<i64>> {
    match trailer.get(b"Prev") {
        Err(_) => Ok(None),
        Ok(Object::Integer(i)) => Ok(Some(*i)),
        Ok(other) => Err(PdfError::read(format!(
            "Expected /Prev to be a number, not {}",
            debug_obj(other)
        ))),
    }
}

fn debug_obj(o: &Object) -> String {
    String::from_utf8_lossy(&generic::object_to_bytes(o)).into_owned()
}

impl<'a> XRefBuilder<'a> {
    pub(crate) fn new(data: &'a [u8], strict: bool, last_startxref: i64) -> Self {
        Self {
            data,
            strict,
            last_startxref,
            sections: Vec::new(),
            trailer: TrailerDictionary::default(),
            has_xref_stream: false,
        }
    }

    fn read_xref_stream_object(
        &self,
        stream: &mut Cursor<'_>,
    ) -> Result<(ObjectId, Dictionary, Vec<u8>), HeaderError> {
        let (idnum, generation) = read_object_header_inner(stream, self.strict)?;
        let id = (
            u32::try_from(idnum).map_err(|_| HeaderError::Other(PdfError::read("Invalid xref stream ID")))?,
            u16::try_from(generation)
                .map_err(|_| HeaderError::Other(PdfError::read("Invalid xref stream generation")))?,
        );
        let ctx = ParseContext {
            strict: self.strict,
            length_resolver: None,
        };
        let obj = generic::read_dictionary(stream, &ctx, generic::ContentOpReading::No)
            .map_err(HeaderError::Other)?;
        let Object::Stream(s) = obj else {
            return Err(HeaderError::Other(PdfError::read("XRef stream must be a stream object")));
        };
        if !matches!(s.dict.get(b"Type"), Ok(Object::Name(n)) if n == b"XRef") {
            return Err(HeaderError::Other(PdfError::read("XRef stream must have /Type /XRef")));
        }
        Ok((id, s.dict, s.content))
    }

    fn read_xref_stream(
        &mut self,
        stream: &mut Cursor<'_>,
        declared_startxref: i64,
        ctx: &mut DecodeContext,
    ) -> Result<Option<i64>, HeaderError> {
        let start_location = stream.tell();
        let (id, dict, content) = self.read_xref_stream_object(stream)?;
        let entries = parse_xref_stream(&dict, &content, ctx, self.strict).map_err(HeaderError::Other)?;
        let mut data = XRefSectionData::default();
        data.process_entries(&entries, self.strict).map_err(HeaderError::Other)?;
        let size = match dict.get(b"Size") {
            Ok(Object::Integer(s)) => *s,
            _ => return Err(HeaderError::Other(PdfError::read("XRef stream lacks an integer /Size"))),
        };
        let meta = XRefSectionMetaInfo {
            xref_section_type: XRefSectionType::Stream,
            size,
            declared_startxref,
            start_location,
            end_location: stream.tell(),
            stream_ref: Some(id),
        };
        self.sections.push(XRefSection {
            meta_info: meta,
            xref_data: data,
        });
        let prev = prev_of(&dict).map_err(HeaderError::Other)?;
        self.trailer.add_trailer_revision(dict);
        Ok(prev)
    }

    fn read_xref_table(
        &mut self,
        stream: &mut Cursor<'_>,
        declared_startxref: i64,
        ctx: &mut DecodeContext,
    ) -> PdfResult<Option<i64>> {
        let xref_start = stream.tell();
        let mut data = XRefSectionData::default();
        let entries = parse_xref_table(stream, self.strict)?;
        let highest = data.process_entries(&entries, self.strict)?;
        let xref_end = stream.tell();
        let pctx = ParseContext {
            strict: self.strict,
            length_resolver: None,
        };
        let new_trailer = match generic::read_dictionary(stream, &pctx, generic::ContentOpReading::No)? {
            Object::Dictionary(d) => d,
            Object::Stream(s) => s.dict,
            _ => return Err(PdfError::read("Trailer must be a dictionary")),
        };
        let declared_size = match new_trailer.get(b"Size") {
            Ok(Object::Integer(s)) => *s,
            Ok(_) => return Err(PdfError::value("Trailer /Size must be an integer")),
            Err(_) => return Err(PdfError::value("Trailer lacks /Size")),
        };
        if self.strict && highest >= declared_size {
            return Err(PdfError::strict(format!(
                "Xref table size mismatch: table allocated object with id {highest}, but according to the trailer {} is the maximal allowed object id.",
                declared_size - 1
            )));
        }
        let hybrid_loc = match new_trailer.get(b"XRefStm") {
            Ok(Object::Integer(i)) => Some(*i),
            Ok(Object::Real(r)) => Some(*r as i64),
            _ => None,
        };
        let (xref_type, stream_ref) = if let Some(loc) = hybrid_loc {
            let stream_pos = stream.tell();
            let loc_u = usize::try_from(loc).map_err(|_| PdfError::read("Negative /XRefStm offset"))?;
            stream.seek(loc_u);
            let (sref, sdict, scontent) = self.read_xref_stream_object(stream).map_err(PdfError::from)?;
            let meta = XRefSectionMetaInfo {
                xref_section_type: XRefSectionType::HybridStream,
                size: match sdict.get(b"Size") {
                    Ok(Object::Integer(s)) => *s,
                    _ => return Err(PdfError::read("XRef stream lacks an integer /Size")),
                },
                declared_startxref: loc,
                start_location: loc_u,
                end_location: stream.tell(),
                stream_ref: Some(sref),
            };
            // pyHanko parses hybrid streams with the default (strict) setting
            let entries = parse_xref_stream(&sdict, &scontent, ctx, true)?;
            data.process_hybrid_entries(&entries, meta, self.strict)?;
            stream.seek(stream_pos);
            (XRefSectionType::HybridMain, Some(sref))
        } else {
            (XRefSectionType::Standard, None)
        };
        let meta = XRefSectionMetaInfo {
            xref_section_type: xref_type,
            size: declared_size,
            declared_startxref,
            start_location: xref_start,
            end_location: xref_end,
            stream_ref,
        };
        self.sections.push(XRefSection {
            meta_info: meta,
            xref_data: data,
        });
        let prev = prev_of(&new_trailer)?;
        self.trailer.add_trailer_revision(new_trailer);
        Ok(prev)
    }

    /// Read all sections; returns them in chronological order (`read_xrefs`).
    pub(crate) fn read_xrefs(&mut self, ctx: &mut DecodeContext) -> PdfResult<Vec<XRefSection>> {
        let mut stream = Cursor::new(self.data);
        let mut startxref = Some(self.last_startxref);
        let mut declared_startxref = self.last_startxref;
        let mut err_count = 0usize;
        let mut seen = BTreeSet::new();
        while let Some(mut sx) = startxref {
            if !seen.insert(sx) {
                return Err(PdfError::read(format!("startxref loop detected at {sx}")));
            }
            if (self.strict && err_count > 0) || err_count > ERR_LIMIT {
                return Err(PdfError::strict("Failed to locate xref section"));
            }
            if err_count == 0 {
                declared_startxref = sx;
            }
            let pos = usize::try_from(sx).map_err(|_| PdfError::read(format!("negative seek value {sx}")))?;
            stream.seek(pos);
            if skip_over_whitespace(&mut stream, false, true)? {
                log::debug!("Encountered unexpected whitespace when looking for xref stream");
                sx = stream.tell() as i64;
            }
            let x = stream.read1();
            if x == Some(b'x') {
                let r = stream.read(4);
                if r.get(..3) != Some(b"ref".as_slice()) {
                    return Err(PdfError::read("xref table read error"));
                }
                startxref = self.read_xref_table(&mut stream, declared_startxref, ctx)?;
            } else if x.is_some_and(|b| b.is_ascii_digit()) {
                stream.seek_rel(-1)?;
                match self.read_xref_stream(&mut stream, declared_startxref, ctx) {
                    Ok(prev) => startxref = prev,
                    Err(HeaderError::Header(e)) => {
                        log::debug!("Failed to read xref stream header, attempting to correct: {e}");
                        startxref = Some(attempt_startxref_correction(&mut stream, sx)?);
                        err_count += 1;
                        continue;
                    }
                    Err(HeaderError::Other(e)) => return Err(e),
                }
                self.has_xref_stream = true;
            } else {
                startxref = Some(attempt_startxref_correction(&mut stream, sx)?);
                err_count += 1;
                continue;
            }
            err_count = 0;
        }
        let mut chrono = std::mem::take(&mut self.sections);
        chrono.reverse();
        if self.strict {
            check_xref_consistency(&chrono)?;
        }
        Ok(chrono)
    }
}

fn attempt_startxref_correction(stream: &mut Cursor<'_>, startxref: i64) -> PdfResult<i64> {
    stream.seek_rel(-11)?;
    let tmp = stream.read(20);
    if let Some(xref_loc) = tmp.windows(4).position(|w| w == b"xref") {
        return Ok(startxref - (10 - xref_loc as i64));
    }
    let readback = 5i64;
    let base = startxref - readback;
    let base_u = usize::try_from(base).map_err(|_| PdfError::read(format!("negative seek value {base}")))?;
    stream.seek(base_u);
    let tmp = stream.read((2 * readback) as usize);
    if let Some(nl) = tmp.iter().rposition(|&b| b == b'\n') {
        let target = base + nl as i64 - 1;
        let target = usize::try_from(target).map_err(|_| PdfError::read(format!("negative seek value {target}")))?;
        stream.seek(target);
        skip_over_whitespace(stream, false, true)?;
        let line_start = stream.tell() as i64;
        for look in 0..5 {
            if stream.read1().is_some_and(|b| b.is_ascii_digit()) {
                return Ok(line_start + look);
            }
        }
    }
    Err(PdfError::read("Could not find xref table at specified location"))
}

/// Cross-reference data of all revisions (`XRefCache`).
#[derive(Debug)]
pub struct XRefCache {
    sections: Vec<XRefSection>,
    /// The xref stream objects of all sections.
    pub xref_stream_refs: BTreeSet<ObjectId>,
    last_changes: OnceLock<BTreeMap<(u32, i64), usize>>,
}

impl XRefCache {
    /// Build from chronologically ordered sections.
    pub fn new(sections: Vec<XRefSection>) -> Self {
        let xref_stream_refs = sections.iter().filter_map(|s| s.meta_info.stream_ref).collect();
        Self {
            sections,
            xref_stream_refs,
            last_changes: OnceLock::new(),
        }
    }

    /// Number of revisions.
    pub fn total_revisions(&self) -> usize {
        self.sections.len()
    }

    fn index_last_changes(&self) -> BTreeMap<(u32, i64), usize> {
        let mut out = BTreeMap::new();
        for (ix, section) in self.sections.iter().enumerate() {
            let data = &section.xref_data;
            let mut candidates: BTreeSet<(u32, i64)> = data.explicit_refs_in_revision.clone();
            if let Some(h) = &data.hybrid {
                candidates.extend(h.xref_data.explicit_refs_in_revision.iter().copied());
            }
            for (idnum, generation) in candidates {
                if data.try_resolve(idnum, generation).is_some() {
                    out.insert((idnum, generation), ix);
                }
            }
        }
        out
    }

    /// `true` once the last-change index has been built.
    pub fn last_changes_indexed(&self) -> bool {
        self.last_changes.get().is_some()
    }

    /// The last revision that wrote `id` (`get_last_change`); `None` for
    /// Python's `KeyError`.
    pub fn get_last_change(&self, id: ObjectId) -> Option<usize> {
        let idx = self.last_changes.get_or_init(|| self.index_last_changes());
        idx.get(&(id.0, i64::from(id.1))).copied()
    }

    /// The object streams used in `revision` (`object_streams_used_in`).
    pub fn object_streams_used_in(&self, revision: usize) -> BTreeSet<ObjectId> {
        self.sections
            .get(revision)
            .map(|s| s.xref_data.obj_streams_used.iter().map(|&i| (i, 0)).collect())
            .unwrap_or_default()
    }

    /// The first revision that defines `id` (`get_introducing_revision`).
    pub fn get_introducing_revision(&self, id: ObjectId) -> Option<usize> {
        self.sections
            .iter()
            .position(|s| matches!(s.xref_data.try_resolve(id.0, i64::from(id.1)), Some(Some(_))))
    }

    /// Metadata of `revision` (`get_xref_container_info`).
    pub fn get_xref_container_info(&self, revision: usize) -> PdfResult<&XRefSectionMetaInfo> {
        self.sections
            .get(revision)
            .map(|s| &s.meta_info)
            .ok_or_else(|| PdfError::value(format!("No revision {revision}")))
    }

    /// Entries of `revision` (`get_xref_data`).
    pub fn get_xref_data(&self, revision: usize) -> PdfResult<&XRefSectionData> {
        self.sections
            .get(revision)
            .map(|s| &s.xref_data)
            .ok_or_else(|| PdfError::value(format!("No revision {revision}")))
    }

    /// References written in `revision`, including hybrid entries
    /// (`explicit_refs_in_revision`). Pairs with generation `-1` (dead
    /// objects freed with next generation 0) have no `ObjectId` and are
    /// left out; see [`Self::explicit_refs_raw`].
    pub fn explicit_refs_in_revision(&self, revision: usize) -> BTreeSet<ObjectId> {
        self.explicit_refs_raw(revision)
            .into_iter()
            .filter_map(|(i, g)| u16::try_from(g).ok().map(|g| (i, g)))
            .collect()
    }

    /// Raw `(idnum, generation)` pairs written in `revision`.
    pub fn explicit_refs_raw(&self, revision: usize) -> BTreeSet<(u32, i64)> {
        let Some(section) = self.sections.get(revision) else {
            return BTreeSet::new();
        };
        let mut out = section.xref_data.explicit_refs_in_revision.clone();
        if let Some(h) = &section.xref_data.hybrid {
            out.extend(h.xref_data.explicit_refs_in_revision.iter().copied());
        }
        out
    }

    /// References freed in `revision` (`refs_freed_in_revision`).
    pub fn refs_freed_in_revision(&self, revision: usize) -> BTreeSet<ObjectId> {
        let Some(section) = self.sections.get(revision) else {
            return BTreeSet::new();
        };
        section
            .xref_data
            .freed
            .iter()
            .filter(|(_, &g)| g > 0)
            .filter_map(|(&i, &g)| u16::try_from(g - 1).ok().map(|g| (i, g)))
            .collect()
    }

    /// `startxref` / `/Prev` of `revision` (`get_startxref_for_revision`).
    pub fn get_startxref_for_revision(&self, revision: usize) -> PdfResult<i64> {
        Ok(self.get_xref_container_info(revision)?.declared_startxref)
    }

    /// Location of `id` as of `revision` (`get_historical_ref`); `None` if
    /// the object does not resolve.
    pub fn get_historical_ref(&self, id: ObjectId, revision: usize) -> Option<XRefLocation> {
        let end = (revision + 1).min(self.sections.len());
        for s in self.sections[..end].iter().rev() {
            if let Some(r) = s.xref_data.try_resolve(id.0, i64::from(id.1)) {
                return r;
            }
        }
        None
    }

    /// Location of `id` in the latest revision (`__getitem__`).
    pub fn get(&self, id: ObjectId) -> Option<XRefLocation> {
        match self.last_changes.get() {
            None => self.get_historical_ref(id, self.sections.len().saturating_sub(1)),
            Some(idx) => {
                let ix = *idx.get(&(id.0, i64::from(id.1)))?;
                self.sections[ix].xref_data.try_resolve(id.0, i64::from(id.1)).flatten()
            }
        }
    }

    /// `true` if any section is a hybrid section (`hybrid_xrefs_present`).
    pub fn hybrid_xrefs_present(&self) -> bool {
        self.sections
            .iter()
            .any(|s| s.meta_info.xref_section_type == XRefSectionType::HybridMain)
    }

    /// The sections, oldest first.
    pub fn sections(&self) -> &[XRefSection] {
        &self.sections
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Position of a written object: a file offset or a slot in an object stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrittenPosition {
    /// File offset.
    Offset(u64),
    /// (object stream number, index).
    InStream(u32, u32),
}

/// Written objects: `(generation, idnum)` → position (`PositionDict`).
pub type PositionDict = BTreeMap<(u16, u32), WrittenPosition>;

fn contiguous_xref_chunks(positions: &PositionDict) -> Vec<(u32, Vec<(WrittenPosition, u16)>)> {
    let mut keys: Vec<(u16, u32)> = positions.keys().copied().collect();
    // sorted by object number (stable with respect to generation order)
    keys.sort_by_key(|k| k.1);
    let mut out: Vec<(u32, Vec<(WrittenPosition, u16)>)> = Vec::new();
    let mut prev: Option<u32> = None;
    for (generation, idnum) in keys {
        let pos = positions[&(generation, idnum)];
        match (prev, out.last_mut()) {
            (Some(p), Some(last)) if idnum == p.wrapping_add(1) => last.1.push((pos, generation)),
            _ => out.push((idnum, vec![(pos, generation)])),
        }
        prev = Some(idnum);
    }
    out
}

/// Write a classical xref table (`write_xref_table`).
pub fn write_xref_table(out: &mut Vec<u8>, positions: &PositionDict) -> PdfResult<u64> {
    let xref_location = out.len() as u64;
    out.extend_from_slice(b"xref\n");
    let chunks = contiguous_xref_chunks(positions);
    let write_sub = |out: &mut Vec<u8>, chunk: &[(WrittenPosition, u16)]| -> PdfResult<()> {
        for (pos, generation) in chunk {
            let WrittenPosition::Offset(p) = pos else {
                return Err(PdfError::write("Object streams require xref streams"));
            };
            out.extend_from_slice(format!("{p:010} {generation:05} n \n").as_bytes());
        }
        Ok(())
    };
    let Some((first_idnum, first)) = chunks.first() else {
        out.extend_from_slice(b"0 0\n");
        return Ok(xref_location);
    };
    let null_obj_ref = b"0000000000 65535 f \n";
    if *first_idnum == 1 {
        out.extend_from_slice(format!("0 {}\n", first.len() + 1).as_bytes());
        out.extend_from_slice(null_obj_ref);
    } else {
        out.extend_from_slice(b"0 1\n");
        out.extend_from_slice(null_obj_ref);
        out.extend_from_slice(format!("{first_idnum} {}\n", first.len()).as_bytes());
    }
    write_sub(out, first)?;
    for (idnum, chunk) in &chunks[1..] {
        out.extend_from_slice(format!("{idnum} {}\n", chunk.len()).as_bytes());
        write_sub(out, chunk)?;
    }
    Ok(xref_location)
}

/// Content and `/Index` of an xref stream (`XRefStream.write_to_stream`),
/// with `/W [1 8 2]`.
pub fn xref_stream_content(positions: &PositionDict) -> (Vec<u8>, Vec<i64>) {
    let mut index = vec![0i64, 1];
    let mut content = vec![0u8; 9];
    content.extend_from_slice(&[0xff, 0xff]);
    for (first, chunk) in contiguous_xref_chunks(positions) {
        index.push(i64::from(first));
        index.push(chunk.len() as i64);
        for (pos, generation) in chunk {
            match pos {
                WrittenPosition::InStream(stm, ix) => {
                    content.push(2);
                    content.extend_from_slice(&u64::from(stm).to_be_bytes());
                    content.extend_from_slice(&(ix as u16).to_be_bytes());
                }
                WrittenPosition::Offset(p) => {
                    content.push(1);
                    content.extend_from_slice(&p.to_be_bytes());
                    content.extend_from_slice(&generation.to_be_bytes());
                }
            }
        }
    }
    (content, index)
}
