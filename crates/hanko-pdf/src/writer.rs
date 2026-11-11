// Derived from pyHanko `pdf_utils/writer.py` and
// `pdf_utils/incremental_writer.py` (MIT, see LICENSE-pyHanko), which in turn
// contain code from PyPDF2 (BSD-3-Clause).

//! PDF writers (`BasePdfFileWriter`, `PdfFileWriter`,
//! `IncrementalPdfFileWriter`).
//!
//! Objects are values: to modify an object, fetch it with
//! [`PdfHandler::get_object`], change it, and store it back with
//! [`PdfWriter::update_object`] (pyHanko's `mark_update` /
//! `update_container`).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};

use lopdf::{Dictionary, Object, ObjectId, Stream};

use crate::error::{PdfError, PdfResult};
use crate::generic::{self, byte_string, PdfDate};
use crate::metadata::info::{now_utc, update_info_dict, view_from_info_dict};
use crate::metadata::model::DocumentMetadata;
use crate::reader::{parse_catalog_version, PdfFile};
use crate::rw_common::{as_int, PdfHandler, PdfHandlerExt};
use crate::stream::{DecodedStream, DuplicateFilter};
use crate::xref::{write_xref_table, xref_stream_content, PositionDict, WrittenPosition};

/// Encrypts objects on output (filled by the `crypt` module).
pub trait Encryptor: std::fmt::Debug {
    /// Encrypt a string belonging to object `container`; `None` if strings
    /// are not encrypted (identity string filter), in which case text
    /// strings are written as literals.
    fn encrypt_string(&self, data: &[u8], container: ObjectId) -> PdfResult<Option<Vec<u8>>>;
    /// Encrypt stream data belonging to object `container` (not called for
    /// streams with an explicit `/Crypt` filter).
    fn encrypt_stream(&self, dict: &Dictionary, data: &[u8], container: ObjectId) -> PdfResult<Vec<u8>>;
    /// The crypt filter for embedded files (name without slash), if it
    /// differs from the default stream filter; embedded file streams then
    /// get an explicit `/Crypt` filter.
    fn embedded_file_filter_name(&self) -> Option<Vec<u8>> {
        None
    }
    /// Crypt filters for explicit `/Crypt` stream filters.
    fn crypt_filters(&self) -> Option<&dyn crate::stream::CryptFilterDecode> {
        None
    }
    /// `security_handler.is_authenticated()`: updates of encrypted files
    /// are refused without credentials.
    fn is_authenticated(&self) -> bool {
        true
    }
    /// The `/AuthCode` trailer entry of a standalone PDF MAC (ISO 32004),
    /// if the output needs one (`_need_mac_on_write`).
    fn standalone_mac_placeholder(&self) -> PdfResult<Option<Object>> {
        Ok(None)
    }
    /// Fill the placeholder announced by [`Self::standalone_mac_placeholder`]
    /// in the complete output (`add_standalone_mac`).
    fn fill_standalone_mac(&self, _out: &mut [u8]) -> PdfResult<()> {
        Ok(())
    }
}

/// Serialise an object, encrypting strings and streams with `enc` as
/// belonging to `container` (`write_to_stream(stream, handler, container_ref)`).
pub fn write_object_encrypted(
    out: &mut Vec<u8>,
    obj: &Object,
    enc: Option<(&dyn Encryptor, ObjectId)>,
) -> PdfResult<()> {
    let Some((e, container)) = enc else {
        generic::write_object(out, obj);
        return Ok(());
    };
    match obj {
        Object::String(s, f) => match e.encrypt_string(s, container)? {
            Some(ct) => generic::write_string(out, &ct, lopdf::StringFormat::Hexadecimal),
            None => generic::write_string(out, s, *f),
        },
        Object::Array(a) => {
            out.push(b'[');
            for v in a {
                out.push(b' ');
                write_object_encrypted(out, v, enc)?;
            }
            out.extend_from_slice(b" ]");
        }
        Object::Dictionary(d) => write_dictionary_encrypted(out, d, enc)?,
        Object::Stream(s) => {
            let has_crypt = crate::stream::has_crypt_filter(&s.dict, &crate::stream::no_deref)?;
            let data = if has_crypt {
                s.content.clone()
            } else {
                e.encrypt_stream(&s.dict, &s.content, container)?
            };
            let mut d = s.dict.clone();
            d.set("Length", Object::Integer(data.len() as i64));
            write_dictionary_encrypted(out, &d, enc)?;
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(&data);
            out.extend_from_slice(b"\nendstream");
        }
        other => generic::write_object(out, other),
    }
    Ok(())
}

fn write_dictionary_encrypted(
    out: &mut Vec<u8>,
    d: &Dictionary,
    enc: Option<(&dyn Encryptor, ObjectId)>,
) -> PdfResult<()> {
    out.extend_from_slice(b"<<\n");
    for (k, v) in d.iter() {
        generic::write_name(out, k);
        out.push(b' ');
        write_object_encrypted(out, v, enc)?;
        out.push(b'\n');
    }
    out.extend_from_slice(b">>");
    Ok(())
}

/// Handle of an object stream prepared with [`PdfWriter::prepare_object_stream`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectStreamHandle(usize);

/// Collects objects into an object stream (`ObjectStream`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ObjectStreamBuilder {
    objs: Vec<(u32, Object)>,
    /// Compress the stream.
    pub compress: bool,
    id: Option<u32>,
}

impl ObjectStreamBuilder {
    /// A new object stream.
    pub fn new(compress: bool) -> Self {
        Self {
            objs: Vec::new(),
            compress,
            id: None,
        }
    }

    /// Add an object (`add_object`); streams and bare references are refused.
    pub fn add_object(&mut self, idnum: u32, obj: Object) -> PdfResult<()> {
        if matches!(obj, Object::Stream(_) | Object::Reference(_)) {
            return Err(PdfError::value(
                "Stream objects and bare references cannot be embedded into object streams.",
            ));
        }
        if let Some(slot) = self.objs.iter_mut().find(|(i, _)| *i == idnum) {
            slot.1 = obj;
        } else {
            self.objs.push((idnum, obj));
        }
        Ok(())
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.objs.is_empty()
    }

    /// Render to a stream object (`as_pdf_object`).
    pub fn as_pdf_object(&self) -> PdfResult<Stream> {
        let mut header = Vec::new();
        let mut body = Vec::new();
        for (idnum, obj) in &self.objs {
            let offset = body.len();
            generic::write_object(&mut body, obj);
            header.extend_from_slice(format!("{idnum} {offset} ").as_bytes());
        }
        let first = header.len();
        let mut data = header;
        data.extend_from_slice(&body);
        let mut d = Dictionary::new();
        d.set("Type", Object::Name(b"ObjStm".to_vec()));
        d.set("N", Object::Integer(self.objs.len() as i64));
        d.set("First", Object::Integer(first as i64));
        let mut s = DecodedStream::new(d, data);
        if self.compress {
            s.compress()?;
        }
        s.to_stream()
    }
}

/// What a writer is based on.
#[derive(Clone, Debug)]
enum Base {
    /// A new file (`PdfFileWriter`).
    Fresh {
        custom_trailer_entries: Dictionary,
    },
    /// An incremental update (`IncrementalPdfFileWriter`).
    Incremental {
        prev: PdfFile,
        trailer: crate::xref::TrailerDictionary,
    },
}

/// A PDF writer (`BasePdfFileWriter`); see [`PdfFileWriter`] and
/// [`IncrementalWriter`] for the constructors.
#[derive(Debug)]
pub struct PdfWriter {
    objects: BTreeMap<(u16, u32), Object>,
    object_streams: Vec<ObjectStreamBuilder>,
    objs_in_streams: BTreeMap<u32, Object>,
    lastobj_id: u32,
    allocated_placeholders: BTreeSet<u32>,
    root: ObjectId,
    info: Option<ObjectId>,
    document_id: (Vec<u8>, Vec<u8>),
    /// Use an xref stream (`stream_xrefs`).
    pub stream_xrefs: bool,
    /// Output version (`output_version`).
    pub output_version: (u32, u32),
    meta: DocumentMetadata,
    encrypt: Option<ObjectId>,
    encryptor: Option<Box<dyn Encryptor>>,
    /// Whether metadata streams are encrypted (`encrypt_metadata` of the
    /// security handler); only relevant with encryption.
    pub encrypt_metadata: bool,
    base: Base,
    /// Run the metadata update (`_update_meta`) on write (default `true`).
    pub update_meta_on_write: bool,
    /// Fixed time for metadata updates (default: the current time, in UTC).
    pub fixed_time: Option<PdfDate>,
    /// Write an incremental update even if no objects changed.
    pub force_write_when_empty: bool,
    /// Skip the standalone PDF MAC on write (`digest_aware_write`; set by
    /// signers, which attach the MAC to the signature).
    pub digest_aware_write: bool,
    init_error: Option<PdfError>,
}

fn random_id() -> Vec<u8> {
    let mut b = [0u8; 16];
    // fall back to a time-derived value if the OS RNG is unavailable
    if getrandom::fill(&mut b).is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        b.copy_from_slice(&t.to_le_bytes());
    }
    b.to_vec()
}

impl PdfWriter {
    fn with_base(base: Base, obj_id_start: u32, stream_xrefs: bool) -> Self {
        Self {
            objects: BTreeMap::new(),
            object_streams: Vec::new(),
            objs_in_streams: BTreeMap::new(),
            lastobj_id: obj_id_start,
            allocated_placeholders: BTreeSet::new(),
            root: (0, 0),
            info: None,
            document_id: (Vec::new(), Vec::new()),
            stream_xrefs,
            output_version: (1, 7),
            meta: DocumentMetadata::default(),
            encrypt: None,
            encryptor: None,
            encrypt_metadata: true,
            base,
            update_meta_on_write: true,
            fixed_time: None,
            force_write_when_empty: false,
            digest_aware_write: false,
            init_error: None,
        }
    }

    /// The previous revision, for incremental writers.
    pub fn prev(&self) -> Option<&PdfFile> {
        match &self.base {
            Base::Incremental { prev, .. } => Some(prev),
            Base::Fresh { .. } => None,
        }
    }

    /// `true` for incremental writers.
    pub fn is_incremental(&self) -> bool {
        matches!(self.base, Base::Incremental { .. })
    }

    /// Document metadata to apply on write (`document_meta`).
    pub fn document_meta(&mut self) -> &mut DocumentMetadata {
        &mut self.meta
    }

    /// Metadata view (`document_meta_view`).
    pub fn document_meta_view(&self) -> PdfResult<DocumentMetadata> {
        let base = match (&self.base, self.info) {
            (Base::Incremental { prev, .. }, _) => prev.document_meta_view()?,
            (Base::Fresh { .. }, Some(info)) => match self.get_object(info)? {
                Object::Dictionary(d) => view_from_info_dict(self, &d, true),
                _ => DocumentMetadata::default(),
            },
            _ => DocumentMetadata::default(),
        };
        Ok(self.meta.view_over(&base))
    }

    /// Raise the output version (`ensure_output_version`).
    pub fn ensure_output_version(&mut self, version: (u32, u32)) -> PdfResult<()> {
        if let Base::Incremental { prev, .. } = &self.base {
            if prev.input_version() >= version {
                return Ok(());
            }
            let mut root = self.root()?;
            if let Some(Object::Name(v)) = self.get(&root, b"Version")? {
                if parse_catalog_version(&v).is_some_and(|cv| cv >= version) {
                    return Ok(());
                }
            }
            root.set("Version", Object::Name(format!("{}.{}", version.0, version.1).into_bytes()));
            self.update_object(self.root, Object::Dictionary(root));
            self.output_version = version;
            return Ok(());
        }
        self.output_version = self.output_version.max(version);
        Ok(())
    }

    /// The document ID (`document_id`).
    pub fn document_id(&self) -> (&[u8], &[u8]) {
        (&self.document_id.0, &self.document_id.1)
    }

    /// Override the document ID (for reproducible output).
    pub fn set_document_id(&mut self, id1: Vec<u8>, id2: Vec<u8>) {
        self.document_id = (id1, id2);
    }

    /// Reference to the catalog.
    pub fn root_id(&self) -> ObjectId {
        self.root
    }

    /// Reference to the Info dictionary, if any.
    pub fn info_id(&self) -> Option<ObjectId> {
        self.info
    }

    /// Set `/Info` (`set_info`).
    pub fn set_info(&mut self, info: Option<Object>) -> PdfResult<Option<ObjectId>> {
        let new = match info {
            None => None,
            Some(Object::Reference(r)) => Some(r),
            Some(other) => Some(self.add_object(other)?),
        };
        self.info = new;
        if let Base::Incremental { trailer, .. } = &mut self.base {
            match new {
                Some(r) => trailer.set(b"Info", Object::Reference(r)),
                None => trailer.remove(b"Info")?,
            }
        }
        Ok(new)
    }

    /// Set a custom trailer entry (`set_custom_trailer_entry`).
    pub fn set_custom_trailer_entry(&mut self, key: &str, value: Object) {
        let key = key.strip_prefix('/').unwrap_or(key).as_bytes().to_vec();
        match &mut self.base {
            Base::Fresh {
                custom_trailer_entries,
            } => custom_trailer_entries.set(key, value),
            Base::Incremental { trailer, .. } => trailer.set(&key, value),
        }
    }

    /// The pending trailer entries of an incremental writer (`trailer`).
    pub fn trailer(&self) -> Option<&crate::xref::TrailerDictionary> {
        match &self.base {
            Base::Incremental { trailer, .. } => Some(trailer),
            Base::Fresh { .. } => None,
        }
    }

    /// Store `obj` under `id` (`mark_update` after modifying it, or
    /// `objects[id] = obj`).
    pub fn update_object(&mut self, id: ObjectId, obj: Object) {
        self.objects.insert((id.1, id.0), obj);
    }

    /// Mark an existing object for rewriting without changes (`mark_update`).
    pub fn mark_update(&mut self, id: ObjectId) -> PdfResult<()> {
        let obj = self.get_object(id)?;
        self.update_object(id, obj);
        Ok(())
    }

    /// Rewrite the catalog (`update_root`).
    pub fn update_root(&mut self) -> PdfResult<()> {
        if self.is_incremental() {
            self.mark_update(self.root)?;
        }
        Ok(())
    }

    /// Replace the catalog dictionary.
    pub fn set_root(&mut self, root: Dictionary) {
        self.update_object(self.root, Object::Dictionary(root));
    }

    /// Objects written by this writer, keyed by `(generation, idnum)`.
    pub fn objects(&self) -> &BTreeMap<(u16, u32), Object> {
        &self.objects
    }

    /// Mutable access to written objects (`objects`).
    pub fn objects_mut(&mut self) -> &mut BTreeMap<(u16, u32), Object> {
        &mut self.objects
    }

    /// Allocate a placeholder reference (`allocate_placeholder`).
    pub fn allocate_placeholder(&mut self) -> PdfResult<ObjectId> {
        let idnum = self
            .lastobj_id
            .checked_add(1)
            .ok_or_else(|| PdfError::write("Object numbers exhausted"))?;
        self.allocated_placeholders.insert(idnum);
        self.lastobj_id = idnum;
        Ok((idnum, 0))
    }

    /// Add a new object (`add_object`).
    pub fn add_object(&mut self, obj: Object) -> PdfResult<ObjectId> {
        self.add_object_ext(obj, None, None)
    }

    /// Add an object, optionally into an object stream or under a
    /// preallocated number (`add_object(obj, obj_stream, idnum)`).
    pub fn add_object_ext(
        &mut self,
        obj: Object,
        obj_stream: Option<ObjectStreamHandle>,
        idnum: Option<u32>,
    ) -> PdfResult<ObjectId> {
        let (idnum, preallocated) = match idnum {
            Some(i) => {
                if !self.allocated_placeholders.contains(&i) {
                    return Err(PdfError::write(
                        "Manually specifying idnum is only allowed for references previously allocated using allocate_placeholder().",
                    ));
                }
                (i, true)
            }
            None => (
                self.lastobj_id
                    .checked_add(1)
                    .ok_or_else(|| PdfError::write("Object numbers exhausted"))?,
                false,
            ),
        };
        match obj_stream {
            None => {
                self.objects.insert((0, idnum), obj);
            }
            Some(ObjectStreamHandle(ix)) => {
                let Some(stm) = self.object_streams.get_mut(ix) else {
                    return Err(PdfError::write("Stream is unknown to this PDF writer."));
                };
                stm.add_object(idnum, obj.clone())?;
                self.objs_in_streams.insert(idnum, obj);
            }
        }
        if preallocated {
            self.allocated_placeholders.remove(&idnum);
        } else {
            self.lastobj_id = idnum;
        }
        Ok((idnum, 0))
    }

    /// Move an already added object into an object stream (pyHanko tests do
    /// this by editing `objects` and `objs_in_streams` directly).
    pub fn move_to_object_stream(&mut self, id: ObjectId, handle: ObjectStreamHandle) -> PdfResult<()> {
        let Some(obj) = self.objects.remove(&(id.1, id.0)) else {
            return Err(PdfError::write("No such object in this writer"));
        };
        let Some(stm) = self.object_streams.get_mut(handle.0) else {
            return Err(PdfError::write("Stream is unknown to this PDF writer."));
        };
        stm.add_object(id.0, obj.clone())?;
        self.objs_in_streams.insert(id.0, obj);
        Ok(())
    }

    /// Prepare an object stream (`prepare_object_stream`).
    pub fn prepare_object_stream(&mut self, compress: bool) -> PdfResult<ObjectStreamHandle> {
        if !self.stream_xrefs {
            return Err(PdfError::write("Object streams require Xref streams to be enabled."));
        }
        self.object_streams.push(ObjectStreamBuilder::new(compress));
        Ok(ObjectStreamHandle(self.object_streams.len() - 1))
    }

    /// Install encryption for output (`_assign_security_handler`); the
    /// `/Encrypt` dictionary is added as an object.
    pub fn set_encryption(&mut self, encrypt_dict: Object, encryptor: Box<dyn Encryptor>) -> PdfResult<ObjectId> {
        let id = self.add_object(encrypt_dict)?;
        self.encrypt = Some(id);
        self.encryptor = Some(encryptor);
        Ok(id)
    }

    /// Use an existing `/Encrypt` object and the given encryptor (updates of
    /// encrypted files).
    pub fn set_existing_encryption(&mut self, encrypt_ref: ObjectId, encryptor: Box<dyn Encryptor>) {
        self.encrypt = Some(encrypt_ref);
        self.encryptor = Some(encryptor);
    }

    /// The embedded-file crypt filter to add to new embedded file streams.
    pub fn embedded_file_crypt_filter(&self) -> Option<Vec<u8>> {
        self.encryptor.as_ref().and_then(|e| e.embedded_file_filter_name())
    }

    /// Encode a stream, applying explicit `/Crypt` filters with this
    /// writer's encryption settings.
    pub fn encode_with_crypt_filters(&self, s: &DecodedStream) -> PdfResult<Stream> {
        let cf = self.encryptor.as_ref().and_then(|e| e.crypt_filters());
        let content = crate::stream::encode_stream_data(&s.dict, &s.data, &crate::stream::no_deref, cf)?;
        Ok(Stream {
            dict: s.dict.clone(),
            content,
            allows_compression: false,
            start_position: None,
        })
    }

    /// The `/Encrypt` reference, if any.
    pub fn encrypt_ref(&self) -> Option<ObjectId> {
        self.encrypt
    }

    /// Register an annotation on a page (`register_annotation`).
    pub fn register_annotation(&mut self, page_ref: ObjectId, annot_ref: ObjectId) -> PdfResult<()> {
        let mut page = match self.get_object(page_ref)? {
            Object::Dictionary(d) => d,
            _ => return Err(PdfError::read("Page must be a dictionary")),
        };
        match page.get(b"Annots").cloned() {
            Ok(Object::Reference(arr_ref)) => {
                let mut annots = match self.get_object(arr_ref)? {
                    Object::Array(a) => a,
                    _ => return Err(PdfError::read("/Annots must be an array")),
                };
                annots.push(Object::Reference(annot_ref));
                self.update_object(arr_ref, Object::Array(annots));
            }
            Ok(Object::Array(mut a)) => {
                a.push(Object::Reference(annot_ref));
                page.set("Annots", Object::Array(a));
                self.update_object(page_ref, Object::Dictionary(page));
            }
            _ => {
                page.set("Annots", Object::Array(vec![Object::Reference(annot_ref)]));
                self.update_object(page_ref, Object::Dictionary(page));
            }
        }
        Ok(())
    }

    fn now(&self) -> PdfDate {
        self.fixed_time.unwrap_or_else(now_utc)
    }

    /// Update the Info dictionary and XMP metadata before writing
    /// (`_update_meta`).
    pub fn update_meta(&mut self) -> PdfResult<()> {
        let root = self.root()?;
        let need_xmp = self.meta.xmp_unmanaged
            || !self.meta.xmp_extra.is_empty()
            || self.output_version >= (2, 0)
            || root.has(b"Metadata");
        self.meta.last_modified = Some(crate::metadata::model::MetaDate::Now);
        let now = self.now();
        let meta = self.meta.clone();
        match self.info {
            Some(info_ref) => {
                let mut info = match self.get_object(info_ref)? {
                    Object::Dictionary(d) => d,
                    _ => return Err(PdfError::read("/Info must be a dictionary")),
                };
                if update_info_dict(self, &meta, &mut info, need_xmp, now)? {
                    self.update_object(info_ref, Object::Dictionary(info));
                }
            }
            None if !need_xmp => {
                let mut info = Dictionary::new();
                update_info_dict(self, &meta, &mut info, false, now)?;
                let id = self.add_object(Object::Dictionary(info))?;
                self.info = Some(id);
            }
            None => {}
        }
        if !need_xmp {
            return Ok(());
        }
        use crate::metadata::xmp_xml;
        let mut updated = false;
        if root.has(b"Metadata") {
            // `root['/Metadata']` as a metadata stream
            if let (Ok(Object::Reference(mref)), Some(Object::Stream(s))) =
                (root.get(b"Metadata").cloned(), self.get(&root, b"Metadata")?)
            {
                let new = xmp_xml::update_metadata_stream(self, &s, &meta, now)?;
                let new = self.encode_metadata_stream(new)?;
                self.update_object(mref, Object::Stream(new));
                updated = true;
            } else if let Some(Object::Stream(s)) = self.get(&root, b"Metadata")? {
                // direct metadata stream in the catalog
                let new = xmp_xml::update_metadata_stream(self, &s, &meta, now)?;
                let new = self.encode_metadata_stream(new)?;
                let mut root = self.root()?;
                root.set("Metadata", Object::Stream(new));
                self.set_root(root);
                updated = true;
            }
        }
        if !updated {
            let ds = xmp_xml::metadata_stream_from_xmp(&xmp_xml::update_xmp_with_meta(&meta, &[], now));
            let ds = self.prepare_new_metadata_stream(ds)?;
            let id = self.add_object(Object::Stream(ds))?;
            let mut root = self.root()?;
            root.set("Metadata", Object::Reference(id));
            self.set_root(root);
        }
        self.update_root()?;
        Ok(())
    }

    /// Encode an updated metadata stream with its existing filters.
    fn encode_metadata_stream(&self, ds: DecodedStream) -> PdfResult<Stream> {
        ds.to_stream()
    }

    /// Prepare a new metadata stream for output: with an encrypted output
    /// that does not encrypt metadata, an identity crypt filter is added
    /// (`add_crypt_filter`).
    fn prepare_new_metadata_stream(&self, mut ds: DecodedStream) -> PdfResult<Stream> {
        if self.encryptor.is_some() && !self.encrypt_metadata {
            let mut params = Dictionary::new();
            params.set("Type", Object::Name(b"CryptFilterDecodeParms".to_vec()));
            params.set("Name", Object::Name(b"Identity".to_vec()));
            ds.apply_filter("Crypt", Some(params), crate::stream::DuplicateFilter::Allow)?;
        }
        ds.to_stream()
    }

    fn populate_trailer(&self, trailer: &mut Dictionary) -> PdfResult<()> {
        match &self.base {
            Base::Fresh {
                custom_trailer_entries,
            } => {
                for (k, v) in custom_trailer_entries.iter() {
                    trailer.set(k.clone(), v.clone());
                }
            }
            Base::Incremental { trailer: t, .. } => {
                for (k, v) in t.flatten(None).iter() {
                    trailer.set(k.clone(), v.clone());
                }
            }
        }
        trailer.set("Root", Object::Reference(self.root));
        if let Some(i) = self.info {
            trailer.set("Info", Object::Reference(i));
        }
        if let Some(e) = self.encrypt {
            trailer.set("Encrypt", Object::Reference(e));
        }
        trailer.set(
            "ID",
            Object::Array(vec![
                byte_string(self.document_id.0.clone()),
                byte_string(self.document_id.1.clone()),
            ]),
        );
        if let Base::Incremental { prev, .. } = &self.base {
            trailer.set("Prev", Object::Integer(prev.last_startxref()));
            if prev.encrypted() && !self.encryptor.as_ref().is_some_and(|e| e.is_authenticated()) {
                return Err(PdfError::write(
                    "Cannot update this document without encryption credentials from the original. Please call encrypt() with the password of the original file before calling write().",
                ));
            }
        }
        Ok(())
    }

    /// The trailer as it would be written (`trailer_view`).
    pub fn writer_trailer_view(&self) -> PdfResult<Dictionary> {
        let mut t = Dictionary::new();
        self.populate_trailer(&mut t)?;
        Ok(t)
    }

    fn write_header(&self, out: &mut Vec<u8>) {
        match &self.base {
            Base::Fresh { .. } => {
                let (major, minor) = self.output_version;
                out.extend_from_slice(format!("%PDF-{major}.{minor}\n").as_bytes());
                out.extend_from_slice(b"%\xc2\xa5\xc2\xb1\xc3\xab\n");
            }
            Base::Incremental { prev, .. } => out.extend_from_slice(prev.bytes()),
        }
    }

    fn write_objects(&mut self, out: &mut Vec<u8>, positions: &mut PositionDict) -> PdfResult<()> {
        for ix in 0..self.object_streams.len() {
            if self.object_streams[ix].is_empty() {
                continue;
            }
            let stm_id = match self.object_streams[ix].id {
                Some(id) => id,
                None => {
                    let s = self.object_streams[ix].as_pdf_object()?;
                    let (id, _) = self.add_object(Object::Stream(s))?;
                    self.object_streams[ix].id = Some(id);
                    id
                }
            };
            for (i, (idnum, _)) in self.object_streams[ix].objs.iter().enumerate() {
                positions.insert(
                    (0, *idnum),
                    WrittenPosition::InStream(stm_id, u32::try_from(i).unwrap_or(u32::MAX)),
                );
            }
        }
        for ((generation, idnum), obj) in &self.objects {
            positions.insert((*generation, *idnum), WrittenPosition::Offset(out.len() as u64));
            out.extend_from_slice(format!("{idnum} {generation} obj\n").as_bytes());
            let id = (*idnum, *generation);
            let enc = match (&self.encryptor, self.encrypt) {
                (Some(e), Some(eid)) if eid != id => Some((e.as_ref(), id)),
                _ => None,
            };
            write_object_encrypted(out, obj, enc)?;
            out.extend_from_slice(b"\nendobj\n");
        }
        Ok(())
    }

    /// Prepare the document for writing (`_prep_dom_for_writing`).
    pub fn prep_dom_for_writing(&mut self) -> PdfResult<()> {
        if let Some(e) = self.init_error.clone() {
            return Err(e);
        }
        if self.update_meta_on_write {
            self.update_meta()?;
        }
        Ok(())
    }

    /// Write the file (`write`): for incremental writers, the original
    /// followed by the update (or the original only, if nothing changed).
    pub fn write(&mut self) -> PdfResult<Vec<u8>> {
        if let Some(e) = self.init_error.clone() {
            return Err(e);
        }
        if let Base::Incremental { prev, .. } = &self.base {
            if self.objects.is_empty() && !self.force_write_when_empty {
                return Ok(prev.bytes().to_vec());
            }
        }
        self.prep_dom_for_writing()?;
        let mut out = Vec::new();
        self.write_raw(&mut out, false)?;
        Ok(out)
    }

    /// Write only the update section (`_write_updated_section`); offsets
    /// assume it is appended to the original file.
    pub fn write_updated_section(&mut self) -> PdfResult<Vec<u8>> {
        self.prep_dom_for_writing()?;
        let mut out = match &self.base {
            Base::Incremental { prev, .. } => prev.bytes().to_vec(),
            Base::Fresh { .. } => Vec::new(),
        };
        let start = out.len();
        self.write_raw(&mut out, true)?;
        Ok(out.split_off(start))
    }

    /// Write the original file followed by the update, like
    /// `write_in_place` (without the early exit for empty updates).
    pub fn write_in_place(&mut self) -> PdfResult<Vec<u8>> {
        self.prep_dom_for_writing()?;
        let mut out = Vec::new();
        self.write_raw(&mut out, false)?;
        Ok(out)
    }

    /// Serialise (`_write`).
    fn write_raw(&mut self, out: &mut Vec<u8>, skip_header: bool) -> PdfResult<()> {
        let mut positions = PositionDict::new();
        let mut trailer = Dictionary::new();
        if self.stream_xrefs {
            trailer.set("W", Object::Array(vec![1.into(), 8.into(), 2.into()]));
            trailer.set("Type", Object::Name(b"XRef".to_vec()));
            trailer.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        }
        if !skip_header {
            self.write_header(out);
        } else if let Base::Incremental { prev, .. } = &self.base {
            // offsets are relative to the full file
            out.extend_from_slice(prev.bytes());
        }
        let mac_placeholder = match &self.encryptor {
            Some(e) if !self.digest_aware_write => e.standalone_mac_placeholder()?,
            _ => None,
        };
        self.populate_trailer(&mut trailer)?;
        if let Some(p) = &mac_placeholder {
            trailer.set("AuthCode", p.clone());
        }
        self.write_objects(out, &mut positions)?;
        let xref_location;
        if self.stream_xrefs {
            xref_location = out.len() as u64;
            let xrefs_id = self
                .lastobj_id
                .checked_add(1)
                .ok_or_else(|| PdfError::write("Object numbers exhausted"))?;
            positions.insert((0, xrefs_id), WrittenPosition::Offset(xref_location));
            trailer.set("Size", Object::Integer(i64::from(xrefs_id) + 1));
            out.extend_from_slice(format!("{xrefs_id} 0 obj\n").as_bytes());
            let (content, index) = xref_stream_content(&positions);
            trailer.set("Index", Object::Array(index.into_iter().map(Object::Integer).collect()));
            let data = crate::filters::flate_compress(&content);
            generic::write_stream(out, &trailer, &data);
            out.extend_from_slice(b"\nendobj\n");
        } else {
            xref_location = write_xref_table(out, &positions)?;
            trailer.set("Size", Object::Integer(i64::from(self.lastobj_id) + 1));
            out.extend_from_slice(b"trailer\n");
            generic::write_dictionary(out, &trailer);
        }
        out.extend_from_slice(format!("\nstartxref\n{xref_location}\n%%EOF\n").as_bytes());
        if mac_placeholder.is_some() {
            if let Some(e) = &self.encryptor {
                e.fill_standalone_mac(out)?;
            }
        }
        Ok(())
    }

    /// Insert a page into the page tree (`insert_page`).
    pub fn insert_page(&mut self, mut new_page: Dictionary, after: Option<i64>) -> PdfResult<ObjectId> {
        if !matches!(self.get(&new_page, b"Type")?, Some(t) if generic::is_name(&t, "Page")) {
            return Err(PdfError::write("Not a page object"));
        }
        if new_page.has(b"Parent") {
            return Err(PdfError::write("/Parent must not be set."));
        }
        let root = self.root()?;
        let Ok(Object::Reference(tree_root)) = root.get(b"Pages").cloned() else {
            return Err(PdfError::read("/Pages must be an indirect reference"));
        };
        let after = match after {
            Some(a) => a,
            None => {
                let tr = match self.get_object(tree_root)? {
                    Object::Dictionary(d) => d,
                    _ => return Err(PdfError::read("Page tree root must be a dictionary")),
                };
                as_int(&self.get_required(&tr, b"Count")?)? - 1
            }
        };
        let (pages_obj_ref, kid_ix) = if after == -1 {
            (tree_root, -1i64)
        } else {
            let loc = self.find_page_container(after)?;
            (loc.node, loc.kid_index as i64)
        };
        // update counts up the tree
        let mut parent = Some(pages_obj_ref);
        let mut guard = 0;
        while let Some(pid) = parent {
            guard += 1;
            if guard > 4096 {
                return Err(PdfError::read("Page tree too deep"));
            }
            let mut p = match self.get_object(pid)? {
                Object::Dictionary(d) => d,
                _ => return Err(PdfError::read("Page tree node must be a dictionary")),
            };
            let count = as_int(&self.get_required(&p, b"Count")?)?;
            p.set("Count", Object::Integer(count + 1));
            parent = match p.get(b"Parent") {
                Ok(Object::Reference(r)) => Some(*r),
                _ => None,
            };
            self.update_object(pid, Object::Dictionary(p));
        }
        new_page.set("Parent", Object::Reference(pages_obj_ref));
        let new_page_ref = self.add_object(Object::Dictionary(new_page))?;
        let mut pages_obj = match self.get_object(pages_obj_ref)? {
            Object::Dictionary(d) => d,
            _ => return Err(PdfError::read("Page tree node must be a dictionary")),
        };
        let insert_at = usize::try_from(kid_ix + 1).unwrap_or(0);
        match pages_obj.get(b"Kids").cloned() {
            Ok(Object::Reference(kids_ref)) => {
                let mut kids = match self.get_object(kids_ref)? {
                    Object::Array(a) => a,
                    _ => return Err(PdfError::Generic("/Pages must have /Kids".into())),
                };
                kids.insert(insert_at.min(kids.len()), Object::Reference(new_page_ref));
                self.update_object(kids_ref, Object::Array(kids));
            }
            Ok(Object::Array(mut kids)) => {
                kids.insert(insert_at.min(kids.len()), Object::Reference(new_page_ref));
                pages_obj.set("Kids", Object::Array(kids));
                self.update_object(pages_obj_ref, Object::Dictionary(pages_obj));
            }
            _ => return Err(PdfError::Generic("/Pages must have /Kids".into())),
        }
        Ok(new_page_ref)
    }

    /// Merge resources into a resource dictionary (`merge_resources`);
    /// indirect sub-dictionaries are updated in place. Returns `true` if
    /// `orig` itself was modified.
    pub fn merge_resources(&mut self, orig: &mut Dictionary, new: &Dictionary) -> PdfResult<bool> {
        let mut update_needed = false;
        for (key, value) in new.iter() {
            let Ok(orig_value_ref) = orig.get(key).cloned() else {
                update_needed = true;
                orig.set(key.clone(), value.clone());
                continue;
            };
            let (mut orig_value, target) = match orig_value_ref {
                Object::Reference(r) => (self.get_object(r)?, Some(r)),
                other => {
                    update_needed = true;
                    (other, None)
                }
            };
            match &mut orig_value {
                Object::Array(arr) if key == b"ProcSet" => {
                    if let Object::Array(items) = self.resolve(value)? {
                        for x in items {
                            if matches!(x, Object::Name(_)) && !arr.contains(&x) {
                                arr.push(x);
                            }
                        }
                    }
                }
                Object::Dictionary(od) => {
                    let nv = match self.resolve(value)? {
                        Object::Dictionary(d) => d,
                        _ => Dictionary::new(),
                    };
                    for (k2, v2) in nv.iter() {
                        if od.has(k2) {
                            return Err(PdfError::Generic(format!(
                                "Naming conflict in resource of type /{}: key /{} occurs in both.",
                                String::from_utf8_lossy(key),
                                String::from_utf8_lossy(k2)
                            )));
                        }
                        od.set(k2.clone(), v2.clone());
                    }
                }
                _ => {}
            }
            match target {
                Some(r) => self.update_object(r, orig_value),
                None => orig.set(key.clone(), orig_value),
            }
        }
        Ok(update_needed)
    }

    /// Append (or prepend) a content stream to a page (`add_stream_to_page`).
    pub fn add_stream_to_page(
        &mut self,
        page_ix: i64,
        stream_ref: ObjectId,
        resources: Option<&Dictionary>,
        prepend: bool,
    ) -> PdfResult<ObjectId> {
        let (page_ref, res_ref) = self.find_page_for_modification(page_ix)?;
        let mut page = match self.get_object(page_ref)? {
            Object::Dictionary(d) => d,
            _ => return Err(PdfError::read("Page must be a dictionary")),
        };
        let new = Object::Reference(stream_ref);
        match page.get(b"Contents").cloned() {
            Ok(Object::Reference(cref)) => match self.get_object(cref)? {
                Object::Array(mut a) => {
                    if prepend {
                        a.insert(0, new);
                    } else {
                        a.push(new);
                    }
                    self.update_object(cref, Object::Array(a));
                }
                Object::Stream(_) => {
                    let arr = if prepend {
                        vec![new, Object::Reference(cref)]
                    } else {
                        vec![Object::Reference(cref), new]
                    };
                    let aref = self.add_object(Object::Array(arr))?;
                    page.set("Contents", Object::Reference(aref));
                    self.update_object(page_ref, Object::Dictionary(page.clone()));
                }
                _ => return Err(PdfError::Generic("Unexpected type for page /Contents".into())),
            },
            Ok(Object::Array(mut a)) => {
                if prepend {
                    a.insert(0, new);
                } else {
                    a.push(new);
                }
                let aref = self.add_object(Object::Array(a))?;
                page.set("Contents", Object::Reference(aref));
                self.update_object(page_ref, Object::Dictionary(page.clone()));
            }
            _ => return Err(PdfError::Generic("Unexpected type for page /Contents".into())),
        }
        let Some(resources) = resources else {
            return Ok(page_ref);
        };
        match res_ref {
            Object::Reference(r) => {
                let mut orig = match self.get_object(r)? {
                    Object::Dictionary(d) => d,
                    _ => return Err(PdfError::read("Resources must be a dictionary")),
                };
                if self.merge_resources(&mut orig, resources)? {
                    self.update_object(r, Object::Dictionary(orig));
                }
            }
            other => {
                let mut orig = match other {
                    Object::Dictionary(d) => d,
                    _ => Dictionary::new(),
                };
                let rid = self.allocate_placeholder()?;
                page.set("Resources", Object::Reference(rid));
                self.update_object(page_ref, Object::Dictionary(page));
                self.merge_resources(&mut orig, resources)?;
                self.add_object_ext(Object::Dictionary(orig), None, Some(rid.0))?;
            }
        }
        Ok(page_ref)
    }

    /// Register a developer extension in the catalog (`register_extension`).
    pub fn register_extension(&mut self, ext: &crate::extensions::DeveloperExtension) -> PdfResult<()> {
        use crate::extensions::DevExtensionMultivalued as Mv;
        let root = self.root()?;
        // where /Extensions lives: an indirect object, or directly in the root
        let (extensions, ext_ref) = match root.get(b"Extensions").cloned() {
            Ok(Object::Reference(r)) => match self.resolve(&Object::Reference(r))? {
                Object::Dictionary(d) => (d, Some(r)),
                Object::Null => (Dictionary::new(), None),
                _ => return Err(PdfError::read("/Extensions must be a dictionary")),
            },
            Ok(Object::Dictionary(d)) => (d, None),
            _ => (Dictionary::new(), None),
        };
        let prefix = ext.prefix_name.clone();
        // the current value, and where it lives if it is an indirect array
        let (cur, cur_ref) = match extensions.get(&prefix).cloned() {
            Ok(Object::Reference(r)) => (self.resolve(&Object::Reference(r))?, Some(r)),
            Ok(o) => (o, None),
            Err(_) => (Object::Null, None),
        };
        let (ext_dicts, old_multivalued): (Vec<Object>, bool) = match &cur {
            Object::Dictionary(_) => (vec![cur.clone()], false),
            Object::Array(a) => (a.clone(), true),
            Object::Null => (Vec::new(), false),
            other => {
                return Err(PdfError::read(format!(
                    "PDF extension value is of type {}, expected (direct) PDF dictionary or array.",
                    generic::type_name(other)
                )))
            }
        };
        let write_back = |w: &mut Self, mut extensions: Dictionary, value: Option<Object>, arr: Option<Vec<Object>>| -> PdfResult<()> {
            if let Some(a) = arr {
                match cur_ref {
                    Some(r) => w.update_object(r, Object::Array(a)),
                    None => extensions.set(prefix.clone(), Object::Array(a)),
                }
            }
            if let Some(v) = value {
                extensions.set(prefix.clone(), v);
            }
            match ext_ref {
                Some(r) => w.update_object(r, Object::Dictionary(extensions)),
                None => {
                    let mut root = w.root()?;
                    root.set("Extensions", Object::Dictionary(extensions));
                    w.set_root(root);
                }
            }
            Ok(())
        };
        for (ix, ext_dict) in ext_dicts.iter().enumerate() {
            let Object::Dictionary(ed) = ext_dict else {
                return Err(PdfError::read(format!(
                    "PDF extension array entry is of type {}, expected (direct) PDF dictionary",
                    generic::type_name(ext_dict)
                )));
            };
            let lvl = match ed.get(b"ExtensionLevel") {
                Ok(Object::Integer(i)) => *i,
                Ok(Object::Real(r)) => *r as i64,
                _ => return Err(PdfError::read("Could not read developer extension level")),
            };
            if lvl == ext.extension_level {
                return Ok(());
            }
            let (old_applies, replace_old) = if ext.compare_by_level {
                let applies = lvl >= ext.extension_level;
                (applies, !applies)
            } else {
                (ext.subsumed_by.contains(&lvl), ext.subsumes.contains(&lvl))
            };
            if old_applies {
                return Ok(());
            } else if replace_old {
                let new = Object::Dictionary(ext.as_pdf_object());
                if old_multivalued {
                    let mut arr = ext_dicts.clone();
                    arr[ix] = new;
                    return write_back(self, extensions, None, Some(arr));
                } else if ext.multivalued == Mv::Always {
                    return write_back(self, extensions, Some(Object::Array(vec![new])), None);
                }
                return write_back(self, extensions, Some(new), None);
            } else if ext.multivalued == Mv::Never {
                return Err(PdfError::write(format!(
                    "Could not register extension with prefix /{} and level {}; file contains extension with same prefix and extension level {lvl}. If this extension level is safe to override, mark it as subsumed.",
                    String::from_utf8_lossy(&prefix),
                    ext.extension_level
                )));
            }
        }
        let new = Object::Dictionary(ext.as_pdf_object());
        if matches!(cur, Object::Null) {
            let v = if ext.multivalued == Mv::Always {
                Object::Array(vec![new])
            } else {
                new
            };
            write_back(self, extensions, Some(v), None)
        } else if old_multivalued {
            let mut arr = ext_dicts;
            arr.push(new);
            write_back(self, extensions, None, Some(arr))
        } else {
            write_back(self, extensions, Some(Object::Array(vec![cur, new])), None)
        }
    }

    /// Import a page of `other` as a form XObject (`import_page_as_xobject`).
    pub fn import_page_as_xobject(
        &mut self,
        other: &dyn PdfHandler,
        page_ix: i64,
        inherit_filters: bool,
    ) -> PdfResult<ObjectId> {
        let (page_ref, resources) = other.find_page_for_modification(page_ix)?;
        let page = match other.get_object(page_ref)? {
            Object::Dictionary(d) => d,
            _ => return Err(PdfError::read("Page must be a dictionary")),
        };
        let Some(mb) = other.find_inherited_value(&page, b"MediaBox", b"Parent")? else {
            return Err(PdfError::read(format!("Page {page_ix} does not have a /MediaBox")));
        };
        let mut stream_dict = Dictionary::new();
        stream_dict.set("BBox", mb);
        stream_dict.set("Resources", self.import_object(other, &resources, None)?);
        stream_dict.set("Type", Object::Name(b"XObject".to_vec()));
        stream_dict.set("Subtype", Object::Name(b"Form".to_vec()));
        let mut command_stream = other.get_required(&page, b"Contents")?;
        if let Object::Array(parts) = &command_stream {
            if parts.len() == 1 && inherit_filters {
                command_stream = other.resolve(&parts[0])?;
            } else {
                let mut data = Vec::new();
                for p in parts {
                    match other.resolve(p)? {
                        Object::Stream(s) => data.extend(other.stream_data(&s)?),
                        _ => return Err(PdfError::read("Content stream must be a stream")),
                    }
                }
                let mut ds = DecodedStream::new(stream_dict, data);
                ds.compress()?;
                return self.add_object(Object::Stream(ds.to_stream()?));
            }
        }
        let Object::Stream(cs) = command_stream else {
            return Err(PdfError::read("Page /Contents must be a stream"));
        };
        let filters = if inherit_filters { other.get(&cs.dict, b"Filter")? } else { None };
        let result = match filters {
            Some(f) => {
                stream_dict.set("Filter", self.import_object(other, &f, None)?);
                Stream {
                    dict: stream_dict,
                    content: cs.content.clone(),
                    allows_compression: false,
                    start_position: None,
                }
            }
            None => DecodedStream::new(stream_dict, other.stream_data(&cs)?).to_stream()?,
        };
        self.add_object(Object::Stream(result))
    }

    /// Deep-copy an object from `source` into this writer (`import_object`).
    pub fn import_object(
        &mut self,
        source: &dyn PdfHandler,
        obj: &Object,
        obj_stream: Option<ObjectStreamHandle>,
    ) -> PdfResult<Object> {
        let mut importer = ObjectImporter {
            reference_map: BTreeMap::new(),
            queued: Vec::new(),
            obj_stream,
        };
        importer.import_object(source, self, obj)
    }
}

/// Copies objects between documents (`_ObjectImporter`).
#[derive(Debug, Default)]
pub struct ObjectImporter {
    /// Source reference → target reference.
    pub reference_map: BTreeMap<ObjectId, ObjectId>,
    queued: Vec<(ObjectId, ObjectId)>,
    obj_stream: Option<ObjectStreamHandle>,
}

impl ObjectImporter {
    /// An importer with a preset reference map.
    pub fn new(reference_map: BTreeMap<ObjectId, ObjectId>, obj_stream: Option<ObjectStreamHandle>) -> Self {
        Self {
            reference_map,
            queued: Vec::new(),
            obj_stream,
        }
    }

    /// Import `obj` and everything it references (`import_object`).
    pub fn import_object(
        &mut self,
        source: &dyn PdfHandler,
        target: &mut PdfWriter,
        obj: &Object,
    ) -> PdfResult<Object> {
        let result = self.ingest(source, target, obj)?;
        while let Some((src, dst)) = self.queued.pop() {
            let src_obj = source.get_object(src)?;
            let imported = self.ingest(source, target, &src_obj)?;
            let stm = if matches!(imported, Object::Stream(_) | Object::Reference(_)) {
                None
            } else {
                self.obj_stream
            };
            target.add_object_ext(imported, stm, Some(dst.0))?;
        }
        Ok(result)
    }

    fn ingest(&mut self, source: &dyn PdfHandler, target: &mut PdfWriter, obj: &Object) -> PdfResult<Object> {
        Ok(match obj {
            Object::Reference(r) => Object::Reference(self.process_reference(target, *r)?),
            Object::Dictionary(d) => Object::Dictionary(self.ingest_dict(source, target, d)?),
            Object::Stream(s) => Object::Stream(Stream {
                dict: self.ingest_dict(source, target, &s.dict)?,
                content: s.content.clone(),
                allows_compression: s.allows_compression,
                start_position: None,
            }),
            Object::Array(a) => Object::Array(
                a.iter()
                    .map(|v| self.ingest(source, target, v))
                    .collect::<PdfResult<_>>()?,
            ),
            other => other.clone(),
        })
    }

    fn ingest_dict(&mut self, source: &dyn PdfHandler, target: &mut PdfWriter, d: &Dictionary) -> PdfResult<Dictionary> {
        let mut out = Dictionary::new();
        for (k, v) in d.iter() {
            if k == b"Metadata" {
                continue;
            }
            out.set(k.clone(), self.ingest(source, target, v)?);
        }
        if let Ok(Object::Reference(m)) = d.get(b"Metadata") {
            out.set("Metadata", Object::Reference(self.process_reference(target, *m)?));
        }
        let _ = source;
        Ok(out)
    }

    fn process_reference(&mut self, target: &mut PdfWriter, r: ObjectId) -> PdfResult<ObjectId> {
        if let Some(t) = self.reference_map.get(&r) {
            return Ok(*t);
        }
        let new = target.allocate_placeholder()?;
        self.reference_map.insert(r, new);
        self.queued.push((r, new));
        Ok(new)
    }
}

impl PdfHandler for PdfWriter {
    fn get_object(&self, id: ObjectId) -> PdfResult<Object> {
        if let Some(o) = self.objects.get(&(id.1, id.0)) {
            return Ok(o.clone());
        }
        if id.1 == 0 {
            if self.allocated_placeholders.contains(&id.0) {
                return Ok(Object::Null);
            }
            if let Some(o) = self.objs_in_streams.get(&id.0) {
                return Ok(o.clone());
            }
        }
        match &self.base {
            Base::Incremental { prev, .. } => prev.get_object_at(id, None),
            Base::Fresh { .. } => Err(PdfError::Value(format!("KeyError: {} {} R", id.0, id.1))),
        }
    }

    fn trailer_view(&self) -> PdfResult<Dictionary> {
        self.writer_trailer_view()
    }

    fn root_ref(&self) -> PdfResult<ObjectId> {
        Ok(self.root)
    }

    fn is_strict(&self) -> bool {
        match &self.base {
            Base::Incremental { prev, .. } => prev.strict(),
            Base::Fresh { .. } => true,
        }
    }

    fn decode_stream(&self, stream: &Stream, purpose: crate::decode_limits::DecodePurpose) -> PdfResult<Vec<u8>> {
        match &self.base {
            Base::Incremental { prev, .. } => prev.read_stream_data(stream, purpose, None),
            Base::Fresh { .. } => {
                let mut ctx = crate::decode_limits::DecodeContext::default();
                crate::stream::decode_stream_data(
                    &stream.dict,
                    &stream.content,
                    &mut ctx,
                    purpose,
                    None,
                    &|o| self.resolve(o),
                    None,
                )
            }
        }
    }
}

/// Writer for new files (`PdfFileWriter`).
#[derive(Debug)]
pub struct PdfFileWriter(PdfWriter);

impl PdfFileWriter {
    /// A new document with a catalog and (optionally) an empty page tree.
    pub fn new(stream_xrefs: bool, init_page_tree: bool) -> PdfResult<Self> {
        let mut w = PdfWriter::with_base(
            Base::Fresh {
                custom_trailer_entries: Dictionary::new(),
            },
            0,
            stream_xrefs,
        );
        w.document_id = (random_id(), random_id());
        let mut root = Dictionary::new();
        root.set("Type", Object::Name(b"Catalog".to_vec()));
        w.root = w.add_object(Object::Dictionary(root.clone()))?;
        if init_page_tree {
            let mut pages = Dictionary::new();
            pages.set("Type", Object::Name(b"Pages".to_vec()));
            pages.set("Count", Object::Integer(0));
            pages.set("Kids", Object::Array(vec![]));
            let pid = w.add_object(Object::Dictionary(pages))?;
            root.set("Pages", Object::Reference(pid));
            w.update_object(w.root, Object::Dictionary(root));
        }
        Ok(Self(w))
    }

    /// Unwrap.
    pub fn into_inner(self) -> PdfWriter {
        self.0
    }
}

impl Deref for PdfFileWriter {
    type Target = PdfWriter;
    fn deref(&self) -> &PdfWriter {
        &self.0
    }
}

impl DerefMut for PdfFileWriter {
    fn deref_mut(&mut self) -> &mut PdfWriter {
        &mut self.0
    }
}

/// Appends an incremental update to a PDF (`IncrementalPdfFileWriter`).
#[derive(Debug)]
pub struct IncrementalWriter(PdfWriter);

impl IncrementalWriter {
    /// Start an update of `base`. Errors (e.g. a missing `/Size`) are
    /// reported by [`Self::write`]; use [`Self::try_new`] to get them early.
    pub fn new(base: PdfFile) -> Self {
        match Self::try_new(base.clone()) {
            Ok(w) => w,
            Err(e) => {
                let mut w = PdfWriter::with_base(
                    Base::Incremental {
                        trailer: base.trailer().clone(),
                        prev: base,
                    },
                    0,
                    false,
                );
                w.init_error = Some(e);
                Self(w)
            }
        }
    }

    /// Start an update of `base` (`IncrementalPdfFileWriter.__init__`).
    pub fn try_new(base: PdfFile) -> PdfResult<Self> {
        let trailer = base.trailer().clone();
        let root_ref = match trailer.raw_get(b"Root", None) {
            Some(Object::Reference(r)) => r,
            _ => return Err(PdfError::read("/Root must be an indirect reference")),
        };
        let info_ref = match trailer.raw_get(b"Info", None) {
            Some(Object::Reference(r)) => Some(r),
            Some(Object::Dictionary(_)) => {
                return Err(PdfError::read("/Info must be an indirect reference"))
            }
            _ => None,
        };
        let id1 = match trailer.raw_get(b"ID", None).map(|o| base.resolve(&o)).transpose()? {
            Some(Object::Array(a)) => match a.first() {
                Some(Object::String(s, _)) => s.clone(),
                _ => random_id(),
            },
            _ => random_id(),
        };
        let size = match trailer.raw_get(b"Size", None).map(|o| base.resolve(&o)).transpose()? {
            Some(Object::Integer(s)) => u32::try_from(s).map_err(|_| PdfError::read("Invalid /Size"))?,
            _ => return Err(PdfError::read("Trailer lacks a valid /Size")),
        };
        // pyHanko starts numbering at /Size; files whose /Size does not
        // cover all their objects (e.g. their own xref stream) would then
        // get objects (or the new xref stream) clobbered, which the reader
        // rejects. Start above every number the file uses.
        let highest_used = base
            .xrefs()
            .sections()
            .iter()
            .enumerate()
            .flat_map(|(ix, _)| base.xrefs().explicit_refs_raw(ix))
            .map(|(id, _)| id)
            .chain(base.xrefs().xref_stream_refs.iter().map(|r| r.0))
            .max()
            .unwrap_or(0);
        let size = size.max(highest_used);
        let stream_xrefs = base.has_xref_stream();
        let input_version = base.input_version();
        // updates of encrypted files reuse the reader's security handler
        let encryption = crate::crypt::encryptor_for_update(&base)?;
        let mut w = PdfWriter::with_base(
            Base::Incremental {
                prev: base,
                trailer,
            },
            size,
            stream_xrefs,
        );
        w.root = root_ref;
        w.info = info_ref;
        w.document_id = (id1, random_id());
        if let (Some(i), Base::Incremental { trailer, .. }) = (info_ref, &mut w.base) {
            trailer.set(b"Info", Object::Reference(i));
        }
        if let Some((r, enc)) = encryption {
            w.set_existing_encryption(r, enc);
            if let Base::Incremental { prev, .. } = &w.base {
                if let Ok(Some(sh)) = prev.security_handler() {
                    w.encrypt_metadata = sh.encrypt_metadata();
                }
            }
        }
        w.output_version = w.output_version.max(input_version);
        w.ensure_output_version((1, 7))?;
        Ok(Self(w))
    }

    /// The document being updated.
    pub fn base(&self) -> &PdfFile {
        match &self.0.base {
            Base::Incremental { prev, .. } => prev,
            // constructed only with an incremental base
            Base::Fresh { .. } => unreachable_base(),
        }
    }

    /// Add or replace an object in the update.
    pub fn put(&mut self, id: ObjectId, object: Object) {
        self.0.update_object(id, object);
    }

    /// Allocate a fresh object number.
    pub fn allocate(&mut self) -> hanko_core::errors::Result<ObjectId> {
        if let Some(e) = self.0.init_error.clone() {
            return Err(e.into());
        }
        Ok(self.0.allocate_placeholder()?)
    }

    /// Serialise the original file followed by the update.
    pub fn write(&mut self) -> hanko_core::errors::Result<Vec<u8>> {
        Ok(self.0.write()?)
    }

    /// Unwrap.
    pub fn into_inner(self) -> PdfWriter {
        self.0
    }
}

#[allow(clippy::panic)]
fn unreachable_base() -> ! {
    // IncrementalWriter is only ever built with an incremental base
    panic!("IncrementalWriter without incremental base")
}

impl Deref for IncrementalWriter {
    type Target = PdfWriter;
    fn deref(&self) -> &PdfWriter {
        &self.0
    }
}

impl DerefMut for IncrementalWriter {
    fn deref_mut(&mut self) -> &mut PdfWriter {
        &mut self.0
    }
}

/// Copy a document into a new writer (`copy_into_new_writer`).
pub fn copy_into_new_writer(input: &dyn PdfHandler) -> PdfResult<PdfFileWriter> {
    copy_into_new_writer_with(input, false)
}

/// [`copy_into_new_writer`] with an explicit `stream_xrefs` setting
/// (`writer_kwargs={'stream_xrefs': ...}`).
pub fn copy_into_new_writer_with(input: &dyn PdfHandler, stream_xrefs: bool) -> PdfResult<PdfFileWriter> {
    let mut w = PdfFileWriter::new(stream_xrefs, false)?;
    let input_root = input.root_ref()?;
    let out_root = w.root;
    let mut importer = ObjectImporter::new(BTreeMap::from([(input_root, out_root)]), None);
    // preprocess signature data: keep /Contents raw
    for f in crate::signatures::enumerate_sig_fields(input, Some(true), None)? {
        if let Some(Object::Reference(sig_ref)) = f.value {
            log::warn!("Source document contains filled signature fields--the copy operation will invalidate them.");
            let sig = match input.get_object(sig_ref)? {
                Object::Dictionary(d) => d,
                _ => continue,
            };
            let mut raw = Dictionary::new();
            for (k, v) in sig.iter() {
                if k == b"Contents" {
                    continue;
                }
                raw.set(k.clone(), importer.ingest(input, &mut w, v)?);
            }
            if let Ok(Object::String(c, _)) = sig.get(b"Contents") {
                raw.set("Contents", byte_string(c.clone()));
            }
            let nid = w.add_object(Object::Dictionary(raw))?;
            importer.reference_map.insert(sig_ref, nid);
        }
    }
    let root = Object::Dictionary(input.root()?);
    let new_root = importer.import_object(input, &mut w, &root)?;
    w.update_object(out_root, new_root);
    if let Ok(info) = input.trailer_view()?.get(b"Info") {
        let info = input.resolve(info)?;
        if !matches!(info, Object::Null) {
            let mut imp = ObjectImporter::default();
            let imported = imp.import_object(input, &mut w, &info)?;
            let iid = w.add_object(imported)?;
            w.info = Some(iid);
        }
    }
    Ok(w)
}

/// Apply a filter to a decoded stream (convenience re-export).
pub fn apply_filter(s: &mut DecodedStream, name: &str, allow_duplicates: DuplicateFilter) -> PdfResult<()> {
    s.apply_filter(name, None, allow_duplicates)
}
