// Derived from pyHanko `pdf_utils/incremental_writer.py`, the writing parts of
// `pdf_utils/writer.py` and `pdf_utils/xref.py` (`write_xref_table`,
// `XRefStream`), and `sign/signers/pdf_byterange.py` (placeholders) (MIT, see
// LICENSE-pyHanko).

//! Incremental updates for signing (`IncrementalPdfFileWriter`).
//!
//! Lane B owns the general PDF layer (`hanko_pdf::IncrementalWriter`); until
//! it lands, signing uses this writer, which reads the latest revision with
//! `lopdf` and appends an update section (classic xref table or xref
//! stream, following the previous revision) after the original bytes, which
//! are never modified.

use std::collections::BTreeMap;
use std::io::Write as _;

use hanko_core::errors::{HankoError, Result};
use lopdf::{Dictionary, Object, ObjectId, Stream};

/// Width of the `/ByteRange` placeholder, as in pyHanko
/// (`BYTE_RANGE_ARR_PLACE_HOLDER_LENGTH` plus the brackets).
pub const BYTE_RANGE_PLACEHOLDER_LEN: usize = 62;

const CONTENTS_TOKEN: &[u8] = b"HankoContentsPlaceholder";
const BYTE_RANGE_TOKEN: &[u8] = b"HankoByteRangePlaceholder";

fn malformed(msg: impl Into<String>) -> HankoError {
    HankoError::Malformed(msg.into())
}

/// Name object used to mark the `/Contents` placeholder.
pub fn contents_placeholder() -> Object {
    Object::Name(CONTENTS_TOKEN.to_vec())
}

/// Name object used to mark the `/ByteRange` placeholder.
pub fn byte_range_placeholder() -> Object {
    Object::Name(BYTE_RANGE_TOKEN.to_vec())
}

/// Locations of a signature placeholder in the written output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaceholderOffsets {
    /// Offset of the `<` that opens the `/Contents` hex string.
    pub contents_start: usize,
    /// Offset just after the closing `>`.
    pub contents_end: usize,
    /// Offset of the `/ByteRange` array placeholder.
    pub byte_range_at: usize,
}

/// An incremental update of a PDF file.
#[derive(Debug, Clone)]
pub struct PdfUpdate {
    base: Vec<u8>,
    doc: lopdf::Document,
    objects: BTreeMap<ObjectId, Object>,
    next_id: u32,
    root_id: ObjectId,
    info_id: Option<ObjectId>,
    document_id: [Vec<u8>; 2],
    prev_startxref: usize,
    stream_xrefs: bool,
    hybrid: bool,
    encrypted: bool,
    placeholders: BTreeMap<ObjectId, usize>,
    fresh: bool,
    strict: bool,
    crypt: Option<lopdf::EncryptionState>,
    encrypt_ref: Option<ObjectId>,
}

/// Find the offset after the last `startxref` keyword.
fn last_startxref(bytes: &[u8]) -> Option<usize> {
    let tail_start = bytes.len().saturating_sub(2048);
    let tail = &bytes[tail_start..];
    let pos = tail.windows(9).rposition(|w| w == b"startxref")?;
    let rest = &tail[pos + 9..];
    let digits: String = rest
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take_while(|b| b.is_ascii_digit())
        .map(|&b| b as char)
        .collect();
    digits.parse().ok()
}

impl PdfUpdate {
    /// Start an update of `bytes`.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        Self::open(bytes, None)
    }

    /// Start an update of an encrypted document, authenticating with the
    /// user or owner `password` (`IncrementalPdfFileWriter.encrypt`).
    /// Objects written by the update are encrypted with the file's key.
    pub fn with_password(bytes: &[u8], password: &[u8]) -> Result<Self> {
        Self::open(bytes, Some(password))
    }

    fn open(bytes: &[u8], password: Option<&[u8]>) -> Result<Self> {
        let raw_encrypted = has_encrypt_entry(bytes);
        let doc = match password {
            Some(p) => {
                let p = std::str::from_utf8(p)
                    .map_err(|_| malformed("password is not valid UTF-8"))?;
                lopdf::Document::load_mem_with_options(bytes, lopdf::LoadOptions::with_password(p))
            }
            None => lopdf::Document::load_mem(bytes),
        }
        .map_err(|e| malformed(format!("could not parse PDF: {e}")))?;
        let crypt = doc.encryption_state.clone();
        let encrypt_ref = crypt.as_ref().and_then(|c| c.encrypt_object_id());
        let prev_startxref =
            last_startxref(bytes).ok_or_else(|| malformed("no startxref found"))?;
        // An xref stream starts with "N G obj"; a table with "xref".
        let at_xref = bytes
            .get(prev_startxref..)
            .map(|b| {
                let s: Vec<u8> = b.iter().skip_while(|c| c.is_ascii_whitespace()).take(4).copied().collect();
                s
            })
            .unwrap_or_default();
        let stream_xrefs = at_xref.first().is_some_and(u8::is_ascii_digit);
        let trailer = &doc.trailer;
        let hybrid = trailer.get(b"XRefStm").is_ok() || has_hybrid_trailer(bytes);
        let encrypted = raw_encrypted || trailer.get(b"Encrypt").is_ok() || crypt.is_some();
        let root_id = trailer
            .get(b"Root")
            .and_then(Object::as_reference)
            .map_err(|_| malformed("trailer without /Root reference"))?;
        let info_id = trailer.get(b"Info").and_then(Object::as_reference).ok();
        let id1 = trailer
            .get(b"ID")
            .and_then(Object::as_array)
            .ok()
            .and_then(|a| a.first())
            .and_then(|o| o.as_str().ok())
            .map(<[u8]>::to_vec);
        let id1 = match id1 {
            Some(v) => v,
            None => random_bytes(16)?,
        };
        let size = trailer
            .get(b"Size")
            .and_then(Object::as_i64)
            .ok()
            .and_then(|s| u32::try_from(s).ok())
            .unwrap_or(0);
        let next_id = size.max(doc.max_id + 1);
        Ok(Self {
            base: bytes.to_vec(),
            doc,
            objects: BTreeMap::new(),
            next_id,
            root_id,
            info_id,
            document_id: [id1, random_bytes(16)?],
            prev_startxref,
            stream_xrefs,
            hybrid,
            encrypted,
            placeholders: BTreeMap::new(),
            fresh: false,
            strict: true,
            crypt,
            encrypt_ref,
        })
    }

    /// [`PdfUpdate::new`] or [`PdfUpdate::with_password`].
    pub fn open_with(bytes: &[u8], password: Option<&[u8]>) -> Result<Self> {
        Self::open(bytes, password)
    }

    /// Start a new document with the contents of `bytes` instead of an
    /// incremental update (`copy_into_new_writer`): `write` produces a
    /// single-revision file with a classic cross-reference table.
    pub fn fresh(bytes: &[u8]) -> Result<Self> {
        let mut u = Self::new(bytes)?;
        u.fresh = true;
        u.stream_xrefs = false;
        u.hybrid = false;
        Ok(u)
    }

    /// Lenient mode (pyHanko's `strict=False`): dangling references read
    /// as `null` where the signing code tolerates it.
    pub fn set_strict(&mut self, strict: bool) {
        self.strict = strict;
    }

    /// Strict mode (the default).
    pub fn is_strict(&self) -> bool {
        self.strict
    }

    /// `true` for a document started with [`PdfUpdate::fresh`].
    pub fn is_fresh(&self) -> bool {
        self.fresh
    }

    /// The original file.
    pub fn base(&self) -> &[u8] {
        &self.base
    }

    /// The parsed latest revision of the original file.
    pub fn document(&self) -> &lopdf::Document {
        &self.doc
    }

    /// The file uses hybrid cross-reference sections (`/XRefStm`).
    pub fn is_hybrid(&self) -> bool {
        self.hybrid
    }

    /// The file is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// The update section uses an xref stream.
    pub fn uses_xref_stream(&self) -> bool {
        self.stream_xrefs
    }

    /// The document catalog's object id.
    pub fn root_id(&self) -> ObjectId {
        self.root_id
    }

    /// The trailer of the latest original revision.
    pub fn prev_trailer(&self) -> &Dictionary {
        &self.doc.trailer
    }

    /// `true` if `id` was added or changed in this update.
    pub fn is_updated(&self, id: ObjectId) -> bool {
        self.objects.contains_key(&id)
    }

    /// Ids written in this update.
    pub fn updated_ids(&self) -> Vec<ObjectId> {
        self.objects.keys().copied().collect()
    }

    /// The current value of object `id`.
    pub fn get(&self, id: ObjectId) -> Result<&Object> {
        if let Some(o) = self.objects.get(&id) {
            return Ok(o);
        }
        self.doc
            .get_object(id)
            .map_err(|e| malformed(format!("object {} {}: {e}", id.0, id.1)))
    }

    /// The current value of `id` as a dictionary (streams yield their
    /// dictionary).
    pub fn get_dict(&self, id: ObjectId) -> Result<&Dictionary> {
        match self.get(id)? {
            Object::Dictionary(d) => Ok(d),
            Object::Stream(s) => Ok(&s.dict),
            _ => Err(malformed(format!("object {} {} is not a dictionary", id.0, id.1))),
        }
    }

    /// Follow references (bounded).
    pub fn resolve<'a>(&'a self, obj: &'a Object) -> Result<&'a Object> {
        let mut cur = obj;
        for _ in 0..32 {
            match cur {
                Object::Reference(id) => cur = self.get(*id)?,
                other => return Ok(other),
            }
        }
        Err(malformed("reference chain too long"))
    }

    /// Resolve `dict[key]`, if present.
    pub fn dict_get<'a>(&'a self, dict: &'a Dictionary, key: &[u8]) -> Result<Option<&'a Object>> {
        match dict.get(key) {
            Ok(o) => Ok(Some(self.resolve(o)?)),
            Err(_) => Ok(None),
        }
    }

    /// A mutable copy of `id`, registered as updated (`mark_update`).
    pub fn get_mut(&mut self, id: ObjectId) -> Result<&mut Object> {
        if !self.objects.contains_key(&id) {
            let obj = self.get(id)?.clone();
            self.objects.insert(id, obj);
        }
        self.objects
            .get_mut(&id)
            .ok_or_else(|| malformed("object vanished"))
    }

    /// Mutable dictionary of `id` (or of the stream `id`).
    pub fn get_dict_mut(&mut self, id: ObjectId) -> Result<&mut Dictionary> {
        match self.get_mut(id)? {
            Object::Dictionary(d) => Ok(d),
            Object::Stream(s) => Ok(&mut s.dict),
            _ => Err(malformed(format!("object {} {} is not a dictionary", id.0, id.1))),
        }
    }

    /// Replace object `id`.
    pub fn update(&mut self, id: ObjectId, obj: Object) {
        self.objects.insert(id, obj);
    }

    /// Mark `id` as updated without changing it.
    pub fn mark_update(&mut self, id: ObjectId) -> Result<()> {
        self.get_mut(id).map(|_| ())
    }

    /// Add a new object.
    pub fn add(&mut self, obj: Object) -> ObjectId {
        let id = (self.next_id, 0);
        self.next_id += 1;
        self.objects.insert(id, obj);
        id
    }

    /// The document catalog.
    pub fn root(&self) -> Result<&Dictionary> {
        self.get_dict(self.root_id)
    }

    /// The document catalog, marked as updated.
    pub fn root_mut(&mut self) -> Result<&mut Dictionary> {
        let id = self.root_id;
        self.get_dict_mut(id)
    }

    /// Pages in document order.
    pub fn pages(&self) -> Result<Vec<ObjectId>> {
        let pages_ref = self
            .root()?
            .get(b"Pages")
            .and_then(Object::as_reference)
            .map_err(|_| malformed("catalog without /Pages"))?;
        let mut out = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        self.collect_pages(pages_ref, &mut out, &mut seen, 0)?;
        Ok(out)
    }

    fn collect_pages(
        &self,
        node: ObjectId,
        out: &mut Vec<ObjectId>,
        seen: &mut std::collections::BTreeSet<ObjectId>,
        depth: usize,
    ) -> Result<()> {
        if depth > 64 || !seen.insert(node) {
            return Err(malformed("circular or too deep page tree"));
        }
        let dict = self.get_dict(node)?;
        let is_pages = dict
            .get(b"Type")
            .and_then(Object::as_name)
            .is_ok_and(|n| n == b"Pages")
            || dict.get(b"Kids").is_ok();
        if !is_pages {
            out.push(node);
            return Ok(());
        }
        let kids = match self.dict_get(dict, b"Kids")? {
            Some(Object::Array(a)) => a.clone(),
            _ => return Err(malformed("page tree node without /Kids")),
        };
        for kid in kids {
            match kid {
                Object::Reference(id) => self.collect_pages(id, out, seen, depth + 1)?,
                _ => return Err(malformed("direct object in page tree /Kids")),
            }
        }
        Ok(())
    }

    /// The page at `index` (negative counts from the end)
    /// (`find_page_for_modification`).
    pub fn page(&self, index: i64) -> Result<ObjectId> {
        let pages = self.pages()?;
        let n = i64::try_from(pages.len()).unwrap_or(i64::MAX);
        let ix = if index < 0 { n + index } else { index };
        usize::try_from(ix)
            .ok()
            .and_then(|i| pages.get(i).copied())
            .ok_or_else(|| HankoError::Signing(format!("page index {index} out of range")))
    }

    /// Add `annot` to the `/Annots` of `page` (`register_annotation`).
    pub fn register_annotation(&mut self, page: ObjectId, annot: ObjectId) -> Result<()> {
        let page_dict = self.get_dict(page)?;
        match page_dict.get(b"Annots") {
            Ok(Object::Reference(arr_id)) => {
                let arr_id = *arr_id;
                match self.get_mut(arr_id)? {
                    Object::Array(a) => a.push(Object::Reference(annot)),
                    _ => return Err(malformed("/Annots is not an array")),
                }
            }
            Ok(Object::Array(_)) => {
                if let Ok(Object::Array(a)) = self.get_dict_mut(page)?.get_mut(b"Annots") {
                    a.push(Object::Reference(annot));
                }
            }
            _ => {
                self.get_dict_mut(page)?
                    .set("Annots", Object::Array(vec![Object::Reference(annot)]));
            }
        }
        Ok(())
    }

    /// Register `id` as a signature dictionary whose `/Contents` and
    /// `/ByteRange` hold the placeholders, reserving `bytes_reserved` hex
    /// digits for the contents.
    pub fn register_placeholder(&mut self, id: ObjectId, bytes_reserved: usize) {
        self.placeholders.insert(id, bytes_reserved);
    }

    /// Update the `/Info` dictionary as pyHanko does on every write
    /// (`update_info_dict`): `/ModDate` and `/Producer`. An `/Info`
    /// dictionary is created only if the document has no XMP metadata.
    pub fn update_info(&mut self, mod_date: &str, producer: &str) -> Result<()> {
        let has_xmp = self.root()?.get(b"Metadata").is_ok();
        match self.info_id {
            Some(id) => {
                let prod = match self.get_dict(id).ok().and_then(|d| d.get(b"Producer").ok()) {
                    Some(Object::String(s, _)) => {
                        let existing = crate::pdf::util::decode_text_string(s);
                        if existing.contains(producer) {
                            existing
                        } else {
                            format!("{existing}; {producer}")
                        }
                    }
                    _ => producer.to_owned(),
                };
                let info = self.get_dict_mut(id)?;
                if !has_xmp || info.get(b"ModDate").is_ok() {
                    info.set("ModDate", crate::pdf::util::text_string(mod_date));
                }
                info.set("Producer", crate::pdf::util::text_string(&prod));
            }
            None if !has_xmp => {
                let mut info = Dictionary::new();
                info.set("ModDate", crate::pdf::util::text_string(mod_date));
                info.set("Producer", crate::pdf::util::text_string(producer));
                self.info_id = Some(self.add(Object::Dictionary(info)));
            }
            None => {}
        }
        Ok(())
    }

    /// Serialize the original file followed by the update. Returns the
    /// output and the placeholder offsets of registered signature objects.
    pub fn write(&self) -> Result<(Vec<u8>, BTreeMap<ObjectId, PlaceholderOffsets>)> {
        let crypt = if self.fresh { None } else { self.crypt.as_ref() };
        if self.encrypted && !self.fresh && (crypt.is_none() || self.encrypt_ref.is_none()) {
            return Err(HankoError::Signing(
                "Cannot update this document without encryption credentials from the original. \
                 Authenticate with the password of the original file."
                    .into(),
            ));
        }
        let mut all: BTreeMap<ObjectId, &Object> = BTreeMap::new();
        let mut out = if self.fresh {
            for (id, obj) in &self.doc.objects {
                let skip = match obj {
                    Object::Stream(s) => matches!(
                        s.dict.get(b"Type").and_then(Object::as_name),
                        Ok(b"XRef") | Ok(b"ObjStm")
                    ),
                    _ => false,
                };
                if !skip {
                    all.insert(*id, obj);
                }
            }
            let v = self.doc.version.as_bytes();
            let mut h = b"%PDF-".to_vec();
            h.extend_from_slice(if v.is_empty() { b"1.7" } else { v });
            h.extend_from_slice(b"\n%\xe2\xe3\xcf\xd3\n");
            h
        } else {
            let mut o = self.base.clone();
            if !o.ends_with(b"\n") && !o.ends_with(b"\r") {
                o.push(b'\n');
            }
            o
        };
        for (id, obj) in &self.objects {
            all.insert(*id, obj);
        }
        let mut positions: BTreeMap<ObjectId, usize> = BTreeMap::new();
        let mut offsets = BTreeMap::new();
        // The placeholders normally sit in the registered signature
        // dictionary, but may live in another object (e.g. an indirect
        // `/Contents`); patch them wherever they are written.
        let reserved = self.placeholders.values().next().copied();
        let mut contents_at: Option<usize> = None;
        let mut byte_range_at: Option<usize> = None;
        for (&id, obj) in &all {
            let encrypted_copy;
            let obj: &Object = match crypt {
                Some(state) if Some(id) != self.encrypt_ref => {
                    let mut o = (*obj).clone();
                    lopdf::encryption::encrypt_object(state, id, &mut o)
                        .map_err(|e| HankoError::Signing(format!("encrypt object: {e}")))?;
                    encrypted_copy = o;
                    &encrypted_copy
                }
                _ => obj,
            };
            positions.insert(id, out.len());
            let _ = writeln!(out, "{} {} obj", id.0, id.1);
            let start = out.len();
            let mut body = Vec::new();
            lopdf::Writer::write_object(&mut body, obj)
                .map_err(|e| HankoError::Signing(format!("serialize object: {e}")))?;
            if let Some(reserved) = reserved {
                let (patched, c_off, b_off) = patch_placeholders(&body, reserved);
                if let Some(c) = c_off {
                    contents_at = Some(start + c);
                }
                if let Some(b) = b_off {
                    byte_range_at = Some(start + b);
                }
                body = patched;
            }
            out.extend_from_slice(&body);
            out.extend_from_slice(b"\nendobj\n");
        }
        if let (Some(reserved), Some(c), Some(b)) = (reserved, contents_at, byte_range_at) {
            for id in self.placeholders.keys() {
                offsets.insert(
                    *id,
                    PlaceholderOffsets {
                        contents_start: c,
                        contents_end: c + reserved + 2,
                        byte_range_at: b,
                    },
                );
            }
        }
        let mut trailer = Dictionary::new();
        trailer.set("Root", Object::Reference(self.root_id));
        if let Some(info) = self.info_id {
            trailer.set("Info", Object::Reference(info));
        }
        if !self.fresh {
            if let Some(r) = self.encrypt_ref {
                trailer.set("Encrypt", Object::Reference(r));
            } else if let Ok(enc) = self.doc.trailer.get(b"Encrypt") {
                trailer.set("Encrypt", enc.clone());
            }
        }
        trailer.set(
            "ID",
            Object::Array(vec![
                Object::String(self.document_id[0].clone(), lopdf::StringFormat::Hexadecimal),
                Object::String(self.document_id[1].clone(), lopdf::StringFormat::Hexadecimal),
            ]),
        );
        if !self.fresh {
            trailer.set(
                "Prev",
                Object::Integer(i64::try_from(self.prev_startxref).unwrap_or(i64::MAX)),
            );
        }
        let xref_location;
        if self.stream_xrefs {
            xref_location = out.len();
            let xref_id = self.next_id;
            positions.insert((xref_id, 0), xref_location);
            trailer.set("Size", Object::Integer(i64::from(xref_id) + 1));
            trailer.set("Type", Object::Name(b"XRef".to_vec()));
            trailer.set(
                "W",
                Object::Array(vec![Object::Integer(1), Object::Integer(8), Object::Integer(2)]),
            );
            let mut index = vec![Object::Integer(0), Object::Integer(1)];
            let mut data = vec![0u8; 9];
            data.extend_from_slice(&[0xff, 0xff]);
            for (first, chunk) in contiguous_chunks(&positions) {
                index.push(Object::Integer(i64::from(first)));
                index.push(Object::Integer(i64::try_from(chunk.len()).unwrap_or(0)));
                for (pos, gen) in chunk {
                    data.push(1);
                    data.extend_from_slice(&(pos as u64).to_be_bytes());
                    data.extend_from_slice(&gen.to_be_bytes());
                }
            }
            trailer.set("Index", Object::Array(index));
            let mut stream = Stream::new(trailer, data);
            stream
                .compress()
                .map_err(|e| HankoError::Signing(format!("compress xref stream: {e}")))?;
            let _ = writeln!(out, "{xref_id} 0 obj");
            lopdf::Writer::write_object(&mut out, &Object::Stream(stream))
                .map_err(|e| HankoError::Signing(format!("serialize xref stream: {e}")))?;
            out.extend_from_slice(b"\nendobj\n");
        } else {
            xref_location = out.len();
            out.extend_from_slice(b"xref\n");
            let chunks = contiguous_chunks(&positions);
            if chunks.is_empty() {
                out.extend_from_slice(b"0 0\n");
            }
            let null_ref = b"0000000000 65535 f \n";
            let mut first_chunk = true;
            for (first, chunk) in chunks {
                if first_chunk && first == 1 {
                    let _ = writeln!(out, "0 {}", chunk.len() + 1);
                    out.extend_from_slice(null_ref);
                } else {
                    if first_chunk {
                        out.extend_from_slice(b"0 1\n");
                        out.extend_from_slice(null_ref);
                    }
                    let _ = writeln!(out, "{first} {}", chunk.len());
                }
                first_chunk = false;
                for (pos, gen) in chunk {
                    let _ = writeln!(out, "{pos:010} {gen:05} n ");
                }
            }
            trailer.set("Size", Object::Integer(i64::from(self.next_id)));
            out.extend_from_slice(b"trailer\n");
            lopdf::Writer::write_object(&mut out, &Object::Dictionary(trailer))
                .map_err(|e| HankoError::Signing(format!("serialize trailer: {e}")))?;
        }
        let _ = write!(out, "\nstartxref\n{xref_location}\n%%EOF\n");
        Ok((out, offsets))
    }
}

/// `true` if the file declares encryption in a trailer or xref stream.
fn has_encrypt_entry(bytes: &[u8]) -> bool {
    let tail = &bytes[bytes.len().saturating_sub(64 * 1024)..];
    find(tail, b"/Encrypt").is_some()
}

/// `true` if any classic trailer of the file points to an xref stream
/// (`/XRefStm`), i.e. the file uses hybrid cross-references.
fn has_hybrid_trailer(bytes: &[u8]) -> bool {
    let mut from = 0;
    while let Some(p) = find(&bytes[from..], b"trailer") {
        let start = from + p + 7;
        let end = (start + 4096).min(bytes.len());
        let window = &bytes[start..end];
        let stop = find(window, b"startxref").unwrap_or(window.len());
        if find(&window[..stop], b"/XRefStm").is_some() {
            return true;
        }
        from = start;
    }
    false
}

fn contiguous_chunks(positions: &BTreeMap<ObjectId, usize>) -> Vec<(u32, Vec<(usize, u16)>)> {
    let mut chunks: Vec<(u32, Vec<(usize, u16)>)> = Vec::new();
    let mut prev: Option<u32> = None;
    for (&(id, gen), &pos) in positions {
        match (prev, chunks.last_mut()) {
            (Some(p), Some(last)) if p + 1 == id => last.1.push((pos, gen)),
            _ => chunks.push((id, vec![(pos, gen)])),
        }
        prev = Some(id);
    }
    chunks
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Replace the placeholder names in a serialized object. Returns the
/// patched bytes and the offsets of `<` and of the `/ByteRange` array
/// within them, for the placeholders the object contains.
fn patch_placeholders(body: &[u8], reserved: usize) -> (Vec<u8>, Option<usize>, Option<usize>) {
    let mut out = body.to_vec();
    let c_tok: Vec<u8> = [b"/".as_slice(), CONTENTS_TOKEN].concat();
    let b_tok: Vec<u8> = [b"/".as_slice(), BYTE_RANGE_TOKEN].concat();
    let mut c_pos = find(&out, &c_tok);
    if let Some(p) = c_pos {
        let mut contents = Vec::with_capacity(reserved + 2);
        contents.push(b'<');
        contents.extend(std::iter::repeat_n(b'0', reserved));
        contents.push(b'>');
        out.splice(p..p + c_tok.len(), contents);
    }
    let b_pos = find(&out, &b_tok);
    if let Some(p) = b_pos {
        let mut br = b"[]".to_vec();
        br.extend(std::iter::repeat_n(b' ', BYTE_RANGE_PLACEHOLDER_LEN - 2));
        out.splice(p..p + b_tok.len(), br);
        // the contents placeholder moves if the byte range preceded it
        if let Some(c) = c_pos.as_mut() {
            if p < *c {
                *c = *c + BYTE_RANGE_PLACEHOLDER_LEN - b_tok.len();
            }
        }
    }
    (out, c_pos, b_pos)
}

/// Fill the `/ByteRange` placeholder and return the byte range.
pub fn fill_byte_range(out: &mut [u8], offsets: &PlaceholderOffsets) -> Result<[usize; 4]> {
    let eof = out.len();
    let range = [
        0,
        offsets.contents_start,
        offsets.contents_end,
        eof - offsets.contents_end,
    ];
    let s = format!("[{} {} {} {}]", range[0], range[1], range[2], range[3]);
    if s.len() > BYTE_RANGE_PLACEHOLDER_LEN {
        return Err(HankoError::Signing("byte range does not fit its placeholder".into()));
    }
    let dst = out
        .get_mut(offsets.byte_range_at..offsets.byte_range_at + s.len())
        .ok_or_else(|| malformed("byte range offset out of bounds"))?;
    dst.copy_from_slice(s.as_bytes());
    Ok(range)
}

/// Write `content` hex-encoded into the reserved `/Contents` region
/// (`PreparedByteRangeDigest.fill_reserved_region`).
pub fn fill_contents(out: &mut [u8], offsets: &PlaceholderOffsets, content: &[u8]) -> Result<()> {
    let reserved = offsets.contents_end - offsets.contents_start - 2;
    let hex: Vec<u8> = content
        .iter()
        .flat_map(|b| {
            const H: &[u8; 16] = b"0123456789ABCDEF";
            [H[usize::from(b >> 4)], H[usize::from(b & 15)]]
        })
        .collect();
    if hex.len() > reserved {
        return Err(HankoError::Signing(format!(
            "Final ByteRange payload larger than expected: allocated {reserved} bytes, but contents required {} bytes.",
            hex.len()
        )));
    }
    out[offsets.contents_start + 1..offsets.contents_start + 1 + hex.len()].copy_from_slice(&hex);
    Ok(())
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).map_err(|e| HankoError::Signing(format!("RNG failure: {e}")))?;
    Ok(v)
}
