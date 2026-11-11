// Derived from pyHanko `pdf_utils/reader.py` (MIT, see LICENSE-pyHanko),
// which in turn contains code from PyPDF2 (BSD-3-Clause).

//! PDF reader with revision history (`PdfFileReader`, `HistoricalResolver`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::{Arc, Mutex, OnceLock};

use lopdf::{Dictionary, Object, ObjectId, Stream};

use crate::decode_limits::{DecodeContext, DecodeLimits, DecodePurpose};
use crate::error::{PdfError, PdfResult};
use crate::generic::{self, ParseContext};
use crate::misc::{read_non_whitespace, read_until_whitespace, Cursor};
use crate::rw_common::{PdfHandler, PdfHandlerExt};
use crate::stream::{decode_stream_data, CryptFilterDecode};
use crate::xref::{
    read_object_header, TrailerDictionary, XRefBuilder, XRefCache, XRefLocation,
};

/// Reader options.
#[derive(Clone, Debug, PartialEq)]
pub struct ReaderOptions {
    /// Strict mode (default `true`).
    pub strict: bool,
    /// Decoding limits (default: for untrusted input).
    pub decode_limits: DecodeLimits,
}

impl Default for ReaderOptions {
    fn default() -> Self {
        Self {
            strict: true,
            decode_limits: DecodeLimits::default(),
        }
    }
}

impl ReaderOptions {
    /// Lenient (non-strict) reading.
    pub fn lenient() -> Self {
        Self {
            strict: false,
            ..Self::default()
        }
    }
}

/// Parse `/M.m` (`parse_catalog_version`); `.` matches any character as in
/// pyHanko's regex.
pub fn parse_catalog_version(version: &[u8]) -> Option<(u32, u32)> {
    // version is the name without slash; pyHanko matches r'/(\d).(\d)'
    if version.len() >= 3 && version[0].is_ascii_digit() && version[2].is_ascii_digit() {
        return Some((u32::from(version[0] - b'0'), u32::from(version[2] - b'0')));
    }
    None
}

/// Read backwards to the previous end of line (`read_next_end_line`).
pub fn read_next_end_line(stream: &mut Cursor<'_>) -> PdfResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut x;
    loop {
        if stream.tell() == 0 {
            return Err(PdfError::read("Could not read malformed PDF file"));
        }
        x = stream.read1();
        if stream.tell() < 2 || x.is_none() {
            return Err(PdfError::read("EOL marker not found"));
        }
        stream.seek_rel(-2)?;
        if matches!(x, Some(b'\n') | Some(b'\r')) {
            break;
        }
        if let Some(b) = x {
            out.push(b);
        }
    }
    let mut crlf = false;
    while matches!(x, Some(b'\n') | Some(b'\r')) {
        x = stream.read1();
        if matches!(x, Some(b'\n') | Some(b'\r')) {
            stream.seek_rel(-1)?;
            crlf = true;
        }
        stream.seek_rel(-2)?;
    }
    stream.seek_rel(if crlf { 2 } else { 1 })?;
    out.reverse();
    Ok(out)
}

/// Find `%%EOF` and the `startxref` value, reading backwards from the cursor
/// (`process_data_at_eof`).
pub fn process_data_at_eof(stream: &mut Cursor<'_>) -> PdfResult<i64> {
    let last_1k = stream.tell() as i64 - 1024 + 1;
    let mut line: Vec<u8> = Vec::new();
    while !line.starts_with(b"%%EOF") {
        if (stream.tell() as i64) < last_1k {
            return Err(PdfError::read("EOF marker not found"));
        }
        line = read_next_end_line(stream)?;
    }
    let line = read_next_end_line(stream)?;
    if let Some(v) = generic::parse_py_int(&line) {
        let line = read_next_end_line(stream)?;
        if !line.starts_with(b"startxref") {
            return Err(PdfError::read("startxref not found"));
        }
        return Ok(v);
    }
    if !line.starts_with(b"startxref") {
        return Err(PdfError::read("startxref not found"));
    }
    log::warn!("startxref on same line as offset");
    generic::parse_py_int(&line[9..]).ok_or_else(|| {
        PdfError::value(format!(
            "invalid literal for int() with base 10: {}",
            generic::py_bytes_repr(&line[9..])
        ))
    })
}

fn read_header_version(data: &[u8]) -> PdfResult<(u32, u32)> {
    let mut c = Cursor::new(data);
    let header = read_until_whitespace(&mut c, Some(20));
    // %PDF-(\d).(\d)
    if header.len() >= 8
        && header.starts_with(b"%PDF-")
        && header[5].is_ascii_digit()
        && header[7].is_ascii_digit()
    {
        return Ok((u32::from(header[5] - b'0'), u32::from(header[7] - b'0')));
    }
    Err(PdfError::read("Illegal PDF header"))
}

/// Decoded stream data, keyed by a digest of the stream dictionary and
/// encoded data: like pyHanko's per-object `_data` cache, decoding the same
/// stream again through the same handler returns the cached data and does not
/// charge the decoding budget again.
#[derive(Debug, Default)]
pub(crate) struct DecodedCache(Mutex<HashMap<[u8; 32], Arc<Vec<u8>>>>);

impl DecodedCache {
    fn key(stream: &Stream) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        match stream.start_position {
            Some(p) => {
                h.update([1u8]);
                h.update((p as u64).to_be_bytes());
            }
            None => h.update([0u8]),
        }
        h.update(generic::object_to_bytes(&Object::Dictionary(stream.dict.clone())));
        h.update([0u8]);
        h.update(&stream.content);
        h.finalize().into()
    }

    pub(crate) fn get_or_decode(
        &self,
        stream: &Stream,
        decode: impl FnOnce() -> PdfResult<Vec<u8>>,
    ) -> PdfResult<Vec<u8>> {
        let key = Self::key(stream);
        let cached = lock(&self.0).get(&key).cloned();
        if let Some(d) = cached {
            return Ok(d.as_ref().clone());
        }
        let data = decode()?;
        lock(&self.0).insert(key, Arc::new(data.clone()));
        Ok(data)
    }
}

/// Security state of an encrypted document (filled by the `crypt` module).
pub trait Decryptor: Send + Sync + std::fmt::Debug {
    /// Decrypt an object read from `id` (`DecryptedObjectProxy.decrypted`).
    fn decrypt_object(&self, obj: Object, id: ObjectId) -> PdfResult<Object>;
    /// Crypt filters for explicit `/Crypt` stream filters.
    fn crypt_filters(&self) -> Option<&dyn CryptFilterDecode>;
}

#[derive(Debug)]
pub(crate) struct ReaderInner {
    pub(crate) bytes: Arc<[u8]>,
    pub(crate) strict: bool,
    pub(crate) header_version: (u32, u32),
    pub(crate) xrefs: XRefCache,
    pub(crate) trailer: TrailerDictionary,
    pub(crate) last_startxref: i64,
    pub(crate) has_xref_stream: bool,
    cache: Mutex<HashMap<ObjectId, Object>>,
    objstm_cache: Mutex<HashMap<u32, Arc<Vec<u8>>>>,
    decode_ctx: Mutex<DecodeContext>,
    decoded: DecodedCache,
    hist_states: Mutex<HashMap<usize, Arc<HistState>>>,
    pub(crate) decryptor: Mutex<Option<Arc<dyn Decryptor>>>,
    pub(crate) embedded_signatures: OnceLock<Vec<crate::signatures::EmbeddedSignature>>,
}

/// A PDF file with its full revision history (`PdfFileReader`).
///
/// Cheap to clone: clones share the parsed cross-reference data and caches.
#[derive(Clone, Debug)]
pub struct PdfFile {
    pub(crate) inner: Arc<ReaderInner>,
}

const MAX_RESOLVE_DEPTH: usize = 32;

thread_local! {
    static RESOLVE_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct DepthGuard;

impl DepthGuard {
    fn enter() -> PdfResult<Self> {
        RESOLVE_DEPTH.with(|d| {
            if d.get() >= MAX_RESOLVE_DEPTH {
                return Err(PdfError::read("Object resolution nested too deeply"));
            }
            d.set(d.get() + 1);
            Ok(DepthGuard)
        })
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        RESOLVE_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run `f` on a snapshot of the decoding context and charge the bytes it
/// decoded to the shared budget afterwards. The lock is not held while
/// decoding, since decoding may resolve (and decode) other objects.
fn with_decode_ctx<T>(
    m: &Mutex<DecodeContext>,
    f: impl FnOnce(&mut DecodeContext) -> PdfResult<T>,
) -> PdfResult<T> {
    let mut snapshot = lock(m).clone();
    let before = snapshot.remaining_budget();
    let res = f(&mut snapshot);
    if let (Some(b), Some(a)) = (before, snapshot.remaining_budget()) {
        let used = b.saturating_sub(a);
        lock(m).record_output(usize::try_from(used).unwrap_or(usize::MAX));
    }
    res
}

impl PdfFile {
    /// Parse a PDF in strict mode with default decoding limits.
    pub fn parse(bytes: &[u8]) -> hanko_core::errors::Result<Self> {
        Ok(Self::parse_with(bytes, ReaderOptions::default())?)
    }

    /// Parse a PDF with explicit options (`PdfFileReader(stream, strict, decode_limits)`).
    pub fn parse_with(bytes: &[u8], options: ReaderOptions) -> PdfResult<Self> {
        Self::from_arc(bytes.into(), options)
    }

    /// Parse a PDF shared through an `Arc`.
    pub fn from_arc(bytes: Arc<[u8]>, options: ReaderOptions) -> PdfResult<Self> {
        let mut ctx = DecodeContext::new(options.decode_limits.clone(), Some(bytes.len() as u64));
        let header_version = read_header_version(&bytes)?;
        let mut c = Cursor::new(&bytes);
        c.seek_end(-1)?;
        let last_startxref = process_data_at_eof(&mut c)?;
        let mut builder = XRefBuilder::new(&bytes, options.strict, last_startxref);
        let sections = builder.read_xrefs(&mut ctx)?;
        let trailer = std::mem::take(&mut builder.trailer);
        let has_xref_stream = builder.has_xref_stream;
        let inner = ReaderInner {
            bytes: bytes.clone(),
            strict: options.strict,
            header_version,
            xrefs: XRefCache::new(sections),
            trailer,
            last_startxref,
            has_xref_stream,
            cache: Mutex::new(HashMap::new()),
            objstm_cache: Mutex::new(HashMap::new()),
            decode_ctx: Mutex::new(ctx),
            decoded: DecodedCache::default(),
            hist_states: Mutex::new(HashMap::new()),
            decryptor: Mutex::new(None),
            embedded_signatures: OnceLock::new(),
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The file bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.inner.bytes
    }

    /// Shared handle to the file bytes.
    pub fn bytes_arc(&self) -> Arc<[u8]> {
        self.inner.bytes.clone()
    }

    /// Strict mode.
    pub fn strict(&self) -> bool {
        self.inner.strict
    }

    /// Cross-reference data (`xrefs`).
    pub fn xrefs(&self) -> &XRefCache {
        &self.inner.xrefs
    }

    /// Trailer dictionaries (`trailer`).
    pub fn trailer(&self) -> &TrailerDictionary {
        &self.inner.trailer
    }

    /// `startxref` of the latest revision (`last_startxref`).
    pub fn last_startxref(&self) -> i64 {
        self.inner.last_startxref
    }

    /// Whether any revision uses an xref stream (`has_xref_stream`).
    pub fn has_xref_stream(&self) -> bool {
        self.inner.has_xref_stream
    }

    /// Number of revisions (`total_revisions`).
    pub fn total_revisions(&self) -> usize {
        self.inner.xrefs.total_revisions()
    }

    /// Version in the file header.
    pub fn header_version(&self) -> (u32, u32) {
        self.inner.header_version
    }

    /// Effective input version: catalog `/Version` or header (`input_version`).
    pub fn input_version(&self) -> (u32, u32) {
        let header = self.inner.header_version;
        let Ok(root) = self.root() else {
            return header;
        };
        match self.get(&root, b"Version") {
            Ok(Some(Object::Name(n))) => parse_catalog_version(&n).unwrap_or(header),
            Ok(Some(Object::String(s, _))) => {
                let s = s.strip_prefix(b"/").unwrap_or(&s).to_vec();
                parse_catalog_version(&s).unwrap_or(header)
            }
            _ => header,
        }
    }

    /// The `/Encrypt` dictionary, if any (`encrypt_dict`).
    pub fn encrypt_dict(&self) -> PdfResult<Option<Dictionary>> {
        let Some(enc) = self.inner.trailer.raw_get(b"Encrypt", None) else {
            return Ok(None);
        };
        let d = match enc {
            Object::Reference(id) => self.get_object_opts(id, None, true)?,
            other if !self.inner.strict => other,
            _ => {
                return Err(PdfError::read(
                    "Encryption settings must be an indirect reference",
                ))
            }
        };
        match d {
            Object::Dictionary(d) => Ok(Some(d)),
            _ => Err(PdfError::read("Encryption settings must be a dictionary")),
        }
    }

    /// `true` if the document is encrypted (`encrypted`).
    pub fn encrypted(&self) -> bool {
        self.inner.trailer.raw_get(b"Encrypt", None).is_some()
    }

    /// Install the decryption state (used by the `crypt` module).
    pub fn set_decryptor(&self, d: Option<Arc<dyn Decryptor>>) {
        *lock(&self.inner.decryptor) = d;
    }

    /// The installed decryption state.
    pub fn decryptor(&self) -> Option<Arc<dyn Decryptor>> {
        lock(&self.inner.decryptor).clone()
    }

    /// The document ID (`document_id`), as raw bytes.
    pub fn document_id(&self) -> PdfResult<(Vec<u8>, Vec<u8>)> {
        let id = self
            .inner
            .trailer
            .raw_get(b"ID", None)
            .ok_or_else(|| PdfError::Value("KeyError: /ID".into()))?;
        document_id_from(&self.deref_raw(&id)?)
    }

    fn deref_raw(&self, o: &Object) -> PdfResult<Object> {
        match o {
            Object::Reference(id) => self.get_object_opts(*id, None, true),
            other => Ok(other.clone()),
        }
    }

    /// A view of the merged trailer of the latest revision (`trailer_view`).
    pub fn trailer_view(&self) -> Dictionary {
        self.inner.trailer.flatten(None)
    }

    /// Read an object (`get_object`): the latest version if `revision` is
    /// `None` (cached), else the version as of `revision` (not cached).
    pub fn get_object_at(&self, id: ObjectId, revision: Option<usize>) -> PdfResult<Object> {
        let never_decrypt = self.inner.xrefs.xref_stream_refs.contains(&id);
        self.get_object_opts(id, revision, never_decrypt)
    }

    /// Read an object without decryption (`transparent_decrypt=False` and
    /// `never_decrypt=True`).
    pub fn get_object_raw(&self, id: ObjectId, revision: Option<usize>) -> PdfResult<Object> {
        self.get_object_opts(id, revision, true)
    }

    pub(crate) fn get_object_opts(
        &self,
        id: ObjectId,
        revision: Option<usize>,
        never_decrypt: bool,
    ) -> PdfResult<Object> {
        let _guard = DepthGuard::enter()?;
        let (raw, marker) = match revision {
            None => {
                let marker = self.inner.xrefs.get(id);
                let cached = lock(&self.inner.cache).get(&id).cloned();
                if let Some(o) = cached {
                    (o, marker)
                } else {
                    let o = self.read_object(id, marker)?;
                    lock(&self.inner.cache).insert(id, o.clone());
                    (o, marker)
                }
            }
            Some(rev) => {
                let marker = self.inner.xrefs.get_historical_ref(id, rev);
                if marker.is_none() {
                    log::warn!(
                        "Could not find object ({} {}) in history at revision {rev}.",
                        id.0,
                        id.1
                    );
                }
                (self.read_object(id, marker)?, marker)
            }
        };
        let in_objstm = matches!(marker, Some(XRefLocation::ObjStream(_)));
        if never_decrypt || in_objstm || !self.encrypted() {
            return Ok(raw);
        }
        let Some(dec) = self.decryptor() else {
            return match raw {
                // primitives are never proxied in pyHanko
                Object::Null
                | Object::Boolean(_)
                | Object::Integer(_)
                | Object::Real(_)
                | Object::Name(_)
                | Object::Reference(_) => Ok(raw),
                _ => Err(PdfError::Generic(
                    "Document is encrypted; authenticate before accessing objects".into(),
                )),
            };
        };
        dec.decrypt_object(raw, id)
    }

    fn read_object(&self, id: ObjectId, marker: Option<XRefLocation>) -> PdfResult<Object> {
        match marker {
            None => {
                if self.inner.strict {
                    Err(PdfError::strict(format!(
                        "Object addressed by {} {} R not found in the current context. This is an error in strict mode.",
                        id.0, id.1
                    )))
                } else {
                    log::info!(
                        "Object addressed by {} {} R not found in the current context, substituting null in non-strict mode.",
                        id.0,
                        id.1
                    );
                    Ok(Object::Null)
                }
            }
            Some(XRefLocation::ObjStream(r)) => {
                self.get_object_from_stream(id.0, r.obj_stream_id, r.ix_in_stream)
            }
            Some(XRefLocation::Offset(off)) => {
                let off = usize::try_from(off)
                    .map_err(|_| PdfError::read(format!("negative seek value {off}")))?;
                let mut c = Cursor::at(&self.inner.bytes, off);
                let (idnum, generation) = read_object_header(&mut c, self.inner.strict)?;
                if idnum != i64::from(id.0) || generation != i64::from(id.1) {
                    return Err(PdfError::read(format!(
                        "Expected object ID ({} {}) does not match actual ({idnum} {generation}).",
                        id.0, id.1
                    )));
                }
                let resolver = |rid: ObjectId| self.get_object_at(rid, None);
                let ctx = ParseContext {
                    strict: self.inner.strict,
                    length_resolver: Some(&resolver),
                };
                let obj = generic::read_object(&mut c, &ctx)?;
                read_non_whitespace(&mut c, true, false)?;
                let obj_data_end = c.tell().saturating_sub(1);
                let endobj = c.read(6);
                if endobj != b"endobj" && self.inner.strict {
                    return Err(PdfError::strict(format!(
                        "Expected endobj marker at position {obj_data_end} but found {}",
                        generic::py_bytes_repr(endobj)
                    )));
                }
                Ok(obj)
            }
        }
    }

    fn objstm_data(&self, stmnum: u32) -> PdfResult<(Arc<Vec<u8>>, i64, i64)> {
        let stream = match self.get_object_at((stmnum, 0), None)? {
            Object::Stream(s) => s,
            _ => return Err(PdfError::read("Object stream reference does not point to a stream")),
        };
        if !matches!(self.get(&stream.dict, b"Type")?, Some(Object::Name(n)) if n == b"ObjStm") {
            return Err(PdfError::read("Object stream must have /Type /ObjStm"));
        }
        let n = crate::rw_common::as_int(&self.get_required(&stream.dict, b"N")?)?;
        let first = crate::rw_common::as_int(&self.get_required(&stream.dict, b"First")?)?;
        if let Some(d) = lock(&self.inner.objstm_cache).get(&stmnum).cloned() {
            return Ok((d, n, first));
        }
        let data = {
            let dec = self.decryptor();
            let cf = dec.as_ref().and_then(|d| d.crypt_filters());
            with_decode_ctx(&self.inner.decode_ctx, |ctx| {
                decode_stream_data(
                    &stream.dict,
                    &stream.content,
                    ctx,
                    DecodePurpose::ObjectStream,
                    None,
                    &|o| self.resolve(o),
                    cf,
                )
            })?
        };
        let data = Arc::new(data);
        lock(&self.inner.objstm_cache).insert(stmnum, data.clone());
        Ok((data, n, first))
    }

    fn get_object_from_stream(&self, idnum: u32, stmnum: u32, idx: i64) -> PdfResult<Object> {
        let strict = self.inner.strict;
        let stream = match self.get_object_at((stmnum, 0), None)? {
            Object::Stream(s) => s,
            _ => return Err(PdfError::read("Object stream reference does not point to a stream")),
        };
        if !matches!(self.get(&stream.dict, b"Type")?, Some(Object::Name(n)) if n == b"ObjStm") {
            return Err(PdfError::read("Object stream must have /Type /ObjStm"));
        }
        let n = crate::rw_common::as_int(&self.get_required(&stream.dict, b"N")?)?;
        if !(0 <= idx && idx < n) {
            if strict {
                return Err(PdfError::strict("Object stream does not contain index"));
            }
            return Ok(Object::Null);
        }
        let (data, n, first_object) = self.objstm_data(stmnum)?;
        let mut sd = Cursor::new(&data);
        for i in 0..n {
            let header = (|| -> PdfResult<(Object, Object)> {
                read_non_whitespace(&mut sd, true, false)?;
                let objnum = generic::read_number(&mut sd)?;
                read_non_whitespace(&mut sd, true, false)?;
                let offset = generic::read_number(&mut sd)?;
                read_non_whitespace(&mut sd, true, false)?;
                Ok((objnum, offset))
            })();
            let (objnum, offset) = match header {
                Ok(h) => h,
                Err(PdfError::Value(_)) => {
                    if strict {
                        return Err(PdfError::strict("Object stream header possibly corrupted"));
                    }
                    return Ok(Object::Null);
                }
                Err(e) => return Err(e),
            };
            let objnum_matches = match objnum {
                Object::Integer(v) => v == i64::from(idnum),
                Object::Real(v) => v == idnum as f32,
                _ => false,
            };
            if !objnum_matches {
                continue;
            }
            if strict && idx != i {
                return Err(PdfError::strict("Object is in wrong index."));
            }
            let offset = crate::rw_common::as_int(&offset)?;
            let obj_start = first_object + offset;
            let obj_start = usize::try_from(obj_start)
                .map_err(|_| PdfError::value(format!("negative seek value {obj_start}")))?;
            sd.seek(obj_start);
            let resolver = |rid: ObjectId| self.get_object_at(rid, None);
            let ctx = ParseContext {
                strict,
                length_resolver: Some(&resolver),
            };
            let obj = match generic::read_object(&mut sd, &ctx) {
                Ok(o) => o,
                Err(e) if e.is_read_error() => {
                    log::warn!("Invalid stream (index {i}) within object {idnum} 0: {e}");
                    if strict {
                        return Err(PdfError::strict(format!("Can't read object stream: {e}")));
                    }
                    Object::Null
                }
                Err(e) => return Err(e),
            };
            if matches!(obj, Object::Stream(_) | Object::Reference(_)) {
                if strict {
                    return Err(PdfError::strict(
                        "Encountered forbidden object type in object stream",
                    ));
                }
                return Ok(obj);
            }
            return Ok(obj);
        }
        if strict {
            return Err(PdfError::strict(
                "Object not found in stream, this is a fatal error in strict mode",
            ));
        }
        Ok(Object::Null)
    }

    /// The document catalog as of `revision` (`get_historical_root`).
    pub fn historical_root(&self, revision: usize) -> PdfResult<Dictionary> {
        self.historical_resolver(revision).root()
    }

    /// A view of the file as of `revision` (`get_historical_resolver`).
    pub fn historical_resolver(&self, revision: usize) -> HistoricalResolver {
        HistoricalResolver::new(self.clone(), revision)
    }

    /// Decode a stream with the reader's limits and budget.
    pub fn read_stream_data(
        &self,
        stream: &Stream,
        purpose: DecodePurpose,
        expected_size: Option<i64>,
    ) -> PdfResult<Vec<u8>> {
        let dec = self.decryptor();
        let cf = dec.as_ref().and_then(|d| d.crypt_filters());
        self.inner.decoded.get_or_decode(stream, || {
            with_decode_ctx(&self.inner.decode_ctx, |ctx| {
                decode_stream_data(
                    &stream.dict,
                    &stream.content,
                    ctx,
                    purpose,
                    expected_size,
                    &|o| self.resolve(o),
                    cf,
                )
            })
        })
    }

    /// Remaining document decoding budget.
    pub fn remaining_decode_budget(&self) -> Option<i64> {
        lock(&self.inner.decode_ctx).remaining_budget()
    }

    /// The XMP metadata view (`_xmp_meta_view`): `None` unless the catalog's
    /// `/Metadata` is a stream.
    pub fn xmp_meta_view(&self) -> PdfResult<Option<crate::metadata::model::DocumentMetadata>> {
        let root = self.root()?;
        match self.get(&root, b"Metadata")? {
            Some(Object::Stream(s)) => {
                let xmp = crate::metadata::xmp_xml::stream_xmp(self, &s)?;
                Ok(Some(crate::metadata::xmp_xml::meta_from_xmp(&xmp)?))
            }
            _ => Ok(None),
        }
    }

    /// Document metadata: from XMP if present, else from the Info
    /// dictionary (`document_meta_view`).
    pub fn document_meta_view(&self) -> PdfResult<crate::metadata::model::DocumentMetadata> {
        if let Some(m) = self.xmp_meta_view()? {
            return Ok(m);
        }
        let tv = self.trailer_view();
        match self.get(&tv, b"Info")? {
            Some(Object::Dictionary(info)) => Ok(crate::metadata::info::view_from_info_dict(
                self,
                &info,
                self.inner.strict,
            )),
            _ => Ok(crate::metadata::model::DocumentMetadata::default()),
        }
    }

    /// Snapshot of the reader's decoding context (`decode_context`).
    pub fn decode_context(&self) -> DecodeContext {
        lock(&self.inner.decode_ctx).clone()
    }
}

pub(crate) fn document_id_from(id: &Object) -> PdfResult<(Vec<u8>, Vec<u8>)> {
    match id {
        Object::Array(a) if a.len() >= 2 => match (&a[0], &a[1]) {
            (Object::String(x, _), Object::String(y, _)) => Ok((x.clone(), y.clone())),
            _ => Err(PdfError::read("/ID entries must be strings")),
        },
        _ => Err(PdfError::read("/ID must be an array of two strings")),
    }
}

impl PdfHandler for PdfFile {
    fn get_object(&self, id: ObjectId) -> PdfResult<Object> {
        self.get_object_at(id, None)
    }

    fn trailer_view(&self) -> PdfResult<Dictionary> {
        Ok(PdfFile::trailer_view(self))
    }

    fn root_ref(&self) -> PdfResult<ObjectId> {
        match self.inner.trailer.raw_get(b"Root", None) {
            Some(Object::Reference(id)) => Ok(id),
            Some(_) => Err(PdfError::read("/Root must be an indirect reference")),
            None => Err(PdfError::Value("KeyError: /Root".into())),
        }
    }

    fn is_strict(&self) -> bool {
        self.inner.strict
    }

    fn decode_stream(&self, stream: &Stream, purpose: DecodePurpose) -> PdfResult<Vec<u8>> {
        self.read_stream_data(stream, purpose, None)
    }
}

// ---------------------------------------------------------------------------
// Historical resolver
// ---------------------------------------------------------------------------

/// Element of a [`RawPdfPath`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathElem {
    /// Dictionary key (without slash).
    Key(Vec<u8>),
    /// Array index.
    Index(usize),
}

/// A path through the object graph (`RawPdfPath`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct RawPdfPath(pub Vec<PathElem>);

impl std::fmt::Display for RawPdfPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for e in &self.0 {
            match e {
                PathElem::Key(k) => write!(f, ".{}", String::from_utf8_lossy(k))?,
                PathElem::Index(i) => write!(f, "[{i}]")?,
            }
        }
        Ok(())
    }
}

impl RawPdfPath {
    /// Parse a path from keys (`"/Root"`, with slash) and indices.
    pub fn new(elems: Vec<PathElem>) -> Self {
        Self(elems)
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Walk the path from `from`, yielding the nodes (`walk_nodes`).
    pub fn walk_nodes(
        &self,
        handler: &dyn PdfHandler,
        from: &Object,
        transparent_dereference: bool,
    ) -> PdfResult<Vec<(Option<PathElem>, Object)>> {
        let mut out = Vec::new();
        let mut current = from.clone();
        let mut elem: Option<PathElem> = None;
        for (ix, entry) in self.0.iter().enumerate() {
            if !transparent_dereference {
                out.push((elem.clone(), current.clone()));
            }
            if matches!(current, Object::Reference(_)) {
                current = handler.resolve(&current)?;
            }
            if transparent_dereference {
                out.push((elem.clone(), current.clone()));
            }
            match (entry, &current) {
                (PathElem::Key(k), Object::Dictionary(d)) => match d.get(k) {
                    Ok(v) => {
                        current = v.clone();
                        elem = Some(entry.clone());
                        continue;
                    }
                    Err(_) => {
                        return Err(PdfError::read(format!(
                            "Encountered missing dictionary entry /{} at position {ix} in path {self}.",
                            String::from_utf8_lossy(k)
                        )))
                    }
                },
                (PathElem::Index(i), Object::Array(a)) => {
                    if *i > a.len() {
                        return Err(PdfError::read(format!(
                            "Encountered out-of-range array index {i} at position {ix} in path {self}."
                        )));
                    }
                    match a.get(*i) {
                        Some(v) => {
                            current = v.clone();
                            elem = Some(entry.clone());
                            continue;
                        }
                        None => {
                            return Err(PdfError::value("list index out of range"));
                        }
                    }
                }
                _ => {}
            }
            return Err(PdfError::read(format!("Type error in path {self} at position {ix}.")));
        }
        if matches!(current, Object::Reference(_)) && transparent_dereference {
            out.push((elem, handler.resolve(&current)?));
        } else {
            out.push((elem, current));
        }
        Ok(out)
    }

    /// The object at the end of the path (`access_on`).
    pub fn access_on(
        &self,
        handler: &dyn PdfHandler,
        from: &Object,
        dereference_last: bool,
    ) -> PdfResult<Object> {
        Ok(self
            .walk_nodes(handler, from, dereference_last)?
            .pop()
            .map(|(_, o)| o)
            .unwrap_or(Object::Null))
    }

    /// The reference at the end of the path (`access_reference_on`).
    pub fn access_reference_on(&self, handler: &dyn PdfHandler, from: &Object) -> PdfResult<ObjectId> {
        match self.access_on(handler, from, false)? {
            Object::Reference(id) => Ok(id),
            _ => Err(PdfError::IndirectObjectExpected(format!(
                "Final entity on path {self} is not an indirect object."
            ))),
        }
    }

    /// Append an element (`__add__`).
    pub fn with(&self, e: PathElem) -> Self {
        let mut v = self.0.clone();
        v.push(e);
        Self(v)
    }
}

/// A view of a PDF file as of a revision (`HistoricalResolver`).
#[derive(Debug)]
pub struct HistoricalResolver {
    reader: PdfFile,
    revision: usize,
    state: Arc<HistState>,
}

/// Per-revision state shared by all [`HistoricalResolver`]s of a reader for
/// the same revision (pyHanko caches the resolver itself).
#[derive(Debug)]
pub(crate) struct HistState {
    cache: Mutex<HashMap<ObjectId, Object>>,
    decode_ctx: Mutex<DecodeContext>,
    decoded: DecodedCache,
    trailer: Dictionary,
    access_cache: OnceLock<PdfResult<BTreeMap<ObjectId, BTreeSet<RawPdfPath>>>>,
}

/// Singly linked list used while collecting paths (`ConsList`).
#[derive(Debug)]
enum Cons<T> {
    Nil,
    Cell(T, Rc<Cons<T>>),
}

impl<T: Clone + PartialEq> Cons<T> {
    fn push(self: &Rc<Self>, v: T) -> Rc<Self> {
        Rc::new(Cons::Cell(v, self.clone()))
    }

    fn contains(&self, v: &T) -> bool {
        let mut cur = self;
        while let Cons::Cell(h, t) = cur {
            if h == v {
                return true;
            }
            cur = t;
        }
        false
    }

    fn to_vec_rev(&self) -> Vec<T> {
        let mut out = Vec::new();
        let mut cur = self;
        while let Cons::Cell(h, t) = cur {
            out.push(h.clone());
            cur = t;
        }
        out.reverse();
        out
    }

    fn head(&self) -> Option<&T> {
        match self {
            Cons::Cell(h, _) => Some(h),
            Cons::Nil => None,
        }
    }

    fn tail(&self) -> Option<&Rc<Cons<T>>> {
        match self {
            Cons::Cell(_, t) => Some(t),
            Cons::Nil => None,
        }
    }
}

impl HistoricalResolver {
    fn new(reader: PdfFile, revision: usize) -> Self {
        let state = lock(&reader.inner.hist_states)
            .entry(revision)
            .or_insert_with(|| {
                Arc::new(HistState {
                    cache: Mutex::new(HashMap::new()),
                    decode_ctx: Mutex::new(lock(&reader.inner.decode_ctx).fresh()),
                    decoded: DecodedCache::default(),
                    trailer: reader.inner.trailer.flatten(Some(revision)),
                    access_cache: OnceLock::new(),
                })
            })
            .clone();
        Self {
            reader,
            revision,
            state,
        }
    }

    /// `true` if both resolvers share their state (pyHanko: `is`).
    pub fn same_view(&self, other: &HistoricalResolver) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    /// Document metadata from the Info dictionary of this revision
    /// (`document_meta_view`; XMP is not consulted, as in pyHanko).
    pub fn document_meta_view(&self) -> PdfResult<crate::metadata::model::DocumentMetadata> {
        let tv = self.state.trailer.clone();
        match self.get(&tv, b"Info")? {
            Some(Object::Dictionary(info)) => Ok(crate::metadata::info::view_from_info_dict(
                self,
                &info,
                self.reader.inner.strict,
            )),
            _ => Ok(crate::metadata::model::DocumentMetadata::default()),
        }
    }

    /// Snapshot of the decoding context of this view (`decode_context`).
    pub fn decode_context(&self) -> DecodeContext {
        lock(&self.state.decode_ctx).clone()
    }

    /// The underlying reader.
    pub fn reader(&self) -> &PdfFile {
        &self.reader
    }

    /// The revision of this view.
    pub fn revision(&self) -> usize {
        self.revision
    }

    /// The object `id` as of this revision, `Ok(None)`-free variant of
    /// [`PdfHandler::get_object`].
    pub fn object(&self, id: ObjectId) -> PdfResult<Object> {
        PdfHandler::get_object(self, id)
    }

    /// Like [`Self::object`], but without decryption.
    pub fn object_raw(&self, id: ObjectId) -> PdfResult<Object> {
        match self.reader.inner.xrefs.get_last_change(id) {
            Some(lc) if lc <= self.revision => self.reader.get_object_raw(id, None),
            _ => self.reader.get_object_raw(id, Some(self.revision)),
        }
    }

    /// References written in this revision (`explicit_refs_in_revision`).
    pub fn explicit_refs_in_revision(&self) -> BTreeSet<ObjectId> {
        self.reader.inner.xrefs.explicit_refs_in_revision(self.revision)
    }

    /// References freed in this revision (`refs_freed_in_revision`).
    pub fn refs_freed_in_revision(&self) -> BTreeSet<ObjectId> {
        self.reader.inner.xrefs.refs_freed_in_revision(self.revision)
    }

    /// Object streams used in this revision (`object_streams_used`).
    pub fn object_streams_used(&self) -> BTreeSet<ObjectId> {
        self.reader.inner.xrefs.object_streams_used_in(self.revision)
    }

    /// `true` if `id` could not have been assigned in this revision
    /// (`is_ref_unassignable`).
    pub fn is_ref_unassignable(&self, id: ObjectId) -> PdfResult<bool> {
        let meta = self.reader.inner.xrefs.get_xref_container_info(self.revision)?;
        Ok(i64::from(id.0) >= meta.size)
    }

    /// The document ID as of this revision.
    pub fn document_id(&self) -> PdfResult<(Vec<u8>, Vec<u8>)> {
        let id = self.get_required(&self.state.trailer, b"ID")?;
        document_id_from(&id)
    }

    /// References used by `obj` and its descendants (`collect_dependencies`).
    pub fn collect_dependencies(
        &self,
        obj: &Object,
        since_revision: Option<usize>,
    ) -> PdfResult<BTreeSet<ObjectId>> {
        let mut seen = BTreeSet::new();
        self.collect_refs(obj, &mut seen, since_revision)?;
        Ok(seen)
    }

    fn collect_refs(
        &self,
        obj: &Object,
        seen: &mut BTreeSet<ObjectId>,
        since_revision: Option<usize>,
    ) -> PdfResult<()> {
        let resolved;
        let obj = if let Object::Reference(id) = obj {
            if seen.contains(id) {
                return Ok(());
            }
            let Some(intro) = self.reader.inner.xrefs.get_introducing_revision(*id) else {
                return Ok(());
            };
            let relevant = since_revision.is_none_or(|s| intro >= s);
            if relevant {
                seen.insert(*id);
            } else if since_revision.is_some() {
                return Ok(());
            }
            resolved = PdfHandler::get_object(self, *id)?;
            &resolved
        } else {
            obj
        };
        match obj {
            Object::Dictionary(d) => {
                for (_, v) in d.iter() {
                    self.collect_refs(v, seen, since_revision)?;
                }
            }
            Object::Stream(s) => {
                for (_, v) in s.dict.iter() {
                    self.collect_refs(v, seen, since_revision)?;
                }
            }
            Object::Array(a) => {
                for v in a {
                    self.collect_refs(v, seen, since_revision)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// All paths from the trailer to `id` (`_get_usages_of_ref`), after
    /// loading the reverse index (`_load_reverse_xref_cache`).
    pub fn usages_of_ref(&self, id: ObjectId) -> PdfResult<BTreeSet<RawPdfPath>> {
        let cache = self.state.access_cache.get_or_init(|| self.load_reverse_xref_cache());
        match cache {
            Ok(c) => Ok(c.get(&id).cloned().unwrap_or_default()),
            Err(e) => Err(e.clone()),
        }
    }

    /// The full reverse index (`_indirect_object_access_cache`).
    pub fn reverse_xref_cache(&self) -> PdfResult<&BTreeMap<ObjectId, BTreeSet<RawPdfPath>>> {
        let cache = self.state.access_cache.get_or_init(|| self.load_reverse_xref_cache());
        cache.as_ref().map_err(Clone::clone)
    }

    fn load_reverse_xref_cache(&self) -> PdfResult<BTreeMap<ObjectId, BTreeSet<RawPdfPath>>> {
        type Path = Rc<Cons<PathElem>>;
        let root = self.root()?;
        let pages_ref = root
            .get(b"Pages")
            .map_err(|_| PdfError::Value("KeyError: /Pages".into()))?
            .clone();
        let nil: Path = Rc::new(Cons::Nil);
        let pages_path = nil.push(PathElem::Key(b"Root".to_vec())).push(PathElem::Key(b"Pages".to_vec()));
        let mut page_tree_nodes: HashMap<ObjectId, Vec<PathElem>> = HashMap::new();
        if let Object::Reference(r) = &pages_ref {
            page_tree_nodes.insert(*r, pages_path.to_vec_rev());
        }
        // collect page tree refs
        let mut stack: Vec<(Object, Path)> = vec![(self.resolve(&pages_ref)?, pages_path.clone())];
        while let Some((node, path)) = stack.pop() {
            let Object::Dictionary(d) = node else {
                return Err(PdfError::read("Page tree node must be a dictionary"));
            };
            let kids = self.get_required(&d, b"Kids")?;
            let Object::Array(kids) = kids else {
                return Err(PdfError::read("/Kids must be an array"));
            };
            let mut children = Vec::new();
            for (ix, kid) in kids.iter().enumerate() {
                let kid_path = path.push(PathElem::Key(b"Kids".to_vec())).push(PathElem::Index(ix));
                if let Object::Reference(r) = kid {
                    if page_tree_nodes.contains_key(r) {
                        return Err(PdfError::read("Circular reference in page tree in mapping stage"));
                    }
                    page_tree_nodes.insert(*r, kid_path.to_vec_rev());
                }
                let kid_obj = self.resolve(kid)?;
                if let Object::Dictionary(kd) = &kid_obj {
                    if matches!(kd.get(b"Type"), Ok(t) if generic::is_name(&self.resolve(t)?, "Pages")) {
                        children.push((kid_obj.clone(), kid_path));
                    }
                }
            }
            // depth-first, preserving order
            for c in children.into_iter().rev() {
                stack.push(c);
            }
        }
        let mut struct_tree_nodes: BTreeSet<ObjectId> = BTreeSet::new();
        if let Ok(str_root) = root.get(b"StructTreeRoot") {
            let str_root = self.resolve(str_root)?;
            let mut todo: Vec<Object> = vec![str_root];
            while let Some(elem) = todo.pop() {
                let Object::Dictionary(ed) = &elem else { continue };
                let Some(children) = self.get(ed, b"K")? else { continue };
                let children = match children {
                    Object::Array(a) => a,
                    other => {
                        // /K may be a single child; recover the raw value
                        match ed.get(b"K") {
                            Ok(raw) => vec![raw.clone()],
                            Err(_) => vec![other],
                        }
                    }
                };
                let mut next = Vec::new();
                for child in children {
                    let child_ref = if let Object::Reference(r) = child { Some(r) } else { None };
                    let child_obj = self.resolve(&child)?;
                    let Object::Dictionary(cd) = &child_obj else { continue };
                    if let Some(t) = self.get(cd, b"Type")? {
                        if !generic::is_name(&t, "StructElem") {
                            continue;
                        }
                    }
                    if let Some(r) = child_ref {
                        if !struct_tree_nodes.insert(r) {
                            return Err(PdfError::read(
                                "Circular reference in structure tree in mapping stage",
                            ));
                        }
                    }
                    next.push(child_obj.clone());
                }
                for n in next.into_iter().rev() {
                    todo.push(n);
                }
            }
        }
        let mut collected: BTreeMap<ObjectId, BTreeSet<RawPdfPath>> = BTreeMap::new();
        let trailer = Object::Dictionary(self.state.trailer.clone());
        let root_key = PathElem::Key(b"Root".to_vec());
        let str_key = PathElem::Key(b"StructTreeRoot".to_vec());
        let k_key = PathElem::Key(b"K".to_vec());
        #[allow(clippy::too_many_arguments)]
        fn compute(
            this: &HistoricalResolver,
            obj: &Object,
            cur_path: &Path,
            seen_in_path: &Rc<Cons<ObjectId>>,
            page_tree: &HashMap<ObjectId, Vec<PathElem>>,
            is_struct_tree: bool,
            struct_nodes: &BTreeSet<ObjectId>,
            collected: &mut BTreeMap<ObjectId, BTreeSet<RawPdfPath>>,
            keys: (&PathElem, &PathElem, &PathElem),
        ) -> PdfResult<()> {
            let resolved;
            let mut seen_in_path = seen_in_path.clone();
            let obj = if let Object::Reference(r) = obj {
                if seen_in_path.contains(r) {
                    return Ok(());
                }
                collected
                    .entry(*r)
                    .or_default()
                    .insert(RawPdfPath(cur_path.to_vec_rev()));
                seen_in_path = seen_in_path.push(*r);
                resolved = PdfHandler::get_object(this, *r)?;
                if let Some(canonical) = page_tree.get(r) {
                    if *canonical != cur_path.to_vec_rev() {
                        return Ok(());
                    }
                }
                if !is_struct_tree && struct_nodes.contains(r) {
                    return Ok(());
                }
                &resolved
            } else {
                obj
            };
            let dict = match obj {
                Object::Dictionary(d) => Some(d),
                Object::Stream(s) => Some(&s.dict),
                _ => None,
            };
            if let Some(d) = dict {
                for (k, v) in d.iter() {
                    if k == b"Parent" || (is_struct_tree && k == b"P") {
                        continue;
                    }
                    let entering_struct = cur_path.head() == Some(keys.1)
                        && k == b"K"
                        && cur_path
                            .tail()
                            .is_some_and(|t| matches!(&**t, Cons::Cell(h, tt) if h == keys.0 && matches!(**tt, Cons::Nil)));
                    let _ = keys.2;
                    compute(
                        this,
                        v,
                        &cur_path.push(PathElem::Key(k.clone())),
                        &seen_in_path,
                        page_tree,
                        is_struct_tree || entering_struct,
                        struct_nodes,
                        collected,
                        keys,
                    )?;
                }
            } else if let Object::Array(a) = obj {
                for (ix, v) in a.iter().enumerate() {
                    compute(
                        this,
                        v,
                        &cur_path.push(PathElem::Index(ix)),
                        &seen_in_path,
                        page_tree,
                        is_struct_tree,
                        struct_nodes,
                        collected,
                        keys,
                    )?;
                }
            }
            Ok(())
        }
        compute(
            self,
            &trailer,
            &nil,
            &Rc::new(Cons::Nil),
            &page_tree_nodes,
            false,
            &struct_tree_nodes,
            &mut collected,
            (&root_key, &str_key, &k_key),
        )?;
        Ok(collected)
    }
}

impl PdfHandler for HistoricalResolver {
    fn get_object(&self, id: ObjectId) -> PdfResult<Object> {
        if let Some(o) = lock(&self.state.cache).get(&id).cloned() {
            return Ok(o);
        }
        let reader = &self.reader;
        let last_change = reader.inner.xrefs.get_last_change(id);
        if last_change.is_none() {
            log::warn!("Could not determine history of {} {} R in xref sections", id.0, id.1);
        }
        let obj = match last_change {
            Some(lc) if lc <= self.revision => reader.get_object_at(id, None)?,
            _ => {
                let never_decrypt = reader.inner.xrefs.xref_stream_refs.contains(&id);
                reader.get_object_opts(id, Some(self.revision), never_decrypt)?
            }
        };
        lock(&self.state.cache).insert(id, obj.clone());
        Ok(obj)
    }

    fn trailer_view(&self) -> PdfResult<Dictionary> {
        Ok(self.state.trailer.clone())
    }

    fn root_ref(&self) -> PdfResult<ObjectId> {
        match self.reader.inner.trailer.raw_get(b"Root", Some(self.revision)) {
            Some(Object::Reference(id)) => Ok(id),
            Some(_) => Err(PdfError::read("/Root must be an indirect reference")),
            None => Err(PdfError::Value("KeyError: /Root".into())),
        }
    }

    fn is_strict(&self) -> bool {
        self.reader.inner.strict
    }

    fn decode_stream(&self, stream: &Stream, purpose: DecodePurpose) -> PdfResult<Vec<u8>> {
        let dec = self.reader.decryptor();
        let cf = dec.as_ref().and_then(|d| d.crypt_filters());
        self.state.decoded.get_or_decode(stream, || {
            with_decode_ctx(&self.state.decode_ctx, |ctx| {
                decode_stream_data(
                    &stream.dict,
                    &stream.content,
                    ctx,
                    purpose,
                    None,
                    &|o| self.resolve(o),
                    cf,
                )
            })
        })
    }
}
