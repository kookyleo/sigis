// Derived from pyHanko `pdf_utils/incremental_writer.py`, the writing parts of
// `pdf_utils/writer.py` and `pdf_utils/xref.py` (`write_xref_table`,
// `XRefStream`), and `sign/signers/pdf_byterange.py` (placeholders) (MIT, see
// LICENSE-pyHanko).

//! Incremental updates for signing (`IncrementalPdfFileWriter`).
//!
//! Native `sigis_pdf` readers enforce decoding limits and retain authenticated
//! security handlers. A compatibility `lopdf::Document` stores parsed objects
//! for the signing API. Updates append a cross-reference table or stream after
//! the original bytes, which are never modified.

use std::collections::BTreeMap;
use std::io::Write as _;

use lopdf::{Dictionary, Object, ObjectId, Stream};
use sigis_pdf::crypt::{AuthStatus, EnvelopeKeyDecrypter, SecurityHandler};
use sigis_pdf::decode_limits::{DecodeContext, DecodeLimits, DecodePurpose};
use sigis_pdf::{PdfFile, ReaderOptions};
use sigis_pki_core::errors::{HankoError, Result};

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

/// Authenticated reader state carried across related signing operations.
///
/// Clones share the current reader's decoding budget. Reopening carries its
/// remaining budget and strictness into a new reader. Authentication is reused
/// only if the raw encryption settings and permanent document ID still match.
#[derive(Clone, Debug)]
pub struct PdfReopenState {
    reader: PdfFile,
}

impl PdfReopenState {
    /// Preserve the policy and authentication of an existing reader.
    pub fn from_reader(reader: PdfFile) -> Self {
        Self { reader }
    }

    /// The reader carrying the decoding policy and authenticated handler.
    pub fn reader(&self) -> &PdfFile {
        &self.reader
    }

    /// Strictness of the carried reader.
    pub fn strict(&self) -> bool {
        self.reader.strict()
    }

    /// Snapshot of the carried decoding limits and remaining budget.
    pub fn decode_context(&self) -> DecodeContext {
        self.reader.decode_context()
    }

    /// Reopen a related revision while preserving the PDF reader state.
    pub fn reopen(&self, bytes: &[u8]) -> Result<Self> {
        let reader = if bytes == self.reader.bytes() {
            self.reader.clone()
        } else {
            self.reader.reopen(bytes)?
        };
        Ok(Self { reader })
    }
}

/// Output bytes together with the state required to continue editing them.
#[derive(Clone, Debug)]
pub struct PdfOperationResult {
    /// The completed PDF operation's output.
    pub pdf: Vec<u8>,
    /// Reader state for reopening this output in a related operation.
    pub state: PdfReopenState,
}

impl PdfOperationResult {
    /// Bind continuation state to the completed output without replenishing allowance.
    pub(crate) fn from_output(pdf: Vec<u8>, state: PdfReopenState) -> Result<Self> {
        let state = state.reopen(&pdf)?;
        Ok(Self { pdf, state })
    }
}

/// An incremental update of a PDF file.
#[derive(Debug, Clone)]
pub struct PdfUpdate {
    base: Vec<u8>,
    doc: lopdf::Document,
    /// Native syntax errors stay errors when accessed; unrelated incremental
    /// edits do not force the caller to read every malformed historical object.
    object_errors: BTreeMap<ObjectId, sigis_pdf::PdfError>,
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
    reader: PdfFile,
    crypt: Option<SecurityHandler>,
    auth_code: Option<Object>,
    encrypt_ref: Option<ObjectId>,
    /// Indirect encryption settings and file identifiers are never encrypted.
    unencrypted_objects: std::collections::BTreeSet<ObjectId>,
    /// Objects to write into an object stream when the update uses an xref
    /// stream (`add_object(..., obj_stream=...)`).
    objstm_members: std::collections::BTreeSet<ObjectId>,
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
        Self::open_with_limits(bytes, password, DecodeLimits::default(), true)
    }

    /// Parse with bounded native PDF decoding and explicit reader policy.
    pub fn open_with_limits(
        bytes: &[u8],
        password: Option<&[u8]>,
        limits: DecodeLimits,
        strict: bool,
    ) -> Result<Self> {
        let reader = PdfFile::parse_with(
            bytes,
            ReaderOptions {
                strict,
                decode_limits: limits,
                ..Default::default()
            },
        )?;
        if reader.encrypted() {
            let password = password.unwrap_or_default();
            let password = std::str::from_utf8(password)
                .map_err(|_| malformed("password is not valid UTF-8"))?;
            if reader.decrypt(password)?.status == AuthStatus::Failed {
                return Err(HankoError::Signing(
                    "Failed to authenticate encrypted document or validate its PDF MAC".into(),
                ));
            }
        }
        Self::from_reader(reader)
    }

    /// Open with the recipient credentials of a public-key encrypted PDF.
    pub fn with_pubkey(bytes: &[u8], decrypter: &dyn EnvelopeKeyDecrypter) -> Result<Self> {
        let reader = PdfFile::parse_with(bytes, ReaderOptions::default())?;
        if reader.decrypt_pubkey(decrypter)?.status == AuthStatus::Failed {
            return Err(HankoError::Signing(
                "Failed to authenticate public-key encrypted document or validate its PDF MAC"
                    .into(),
            ));
        }
        Self::from_reader(reader)
    }

    /// Reopen a related revision with preserved limits and authentication.
    pub fn open_with_state(bytes: &[u8], state: PdfReopenState) -> Result<Self> {
        Self::from_reader(state.reopen(bytes)?.reader)
    }

    fn from_reader(reader: PdfFile) -> Result<Self> {
        let bytes = reader.bytes();
        let trailer = reader.trailer_view();
        let encrypted = reader.encrypted();
        let crypt = reader.security_handler()?;
        if encrypted
            && !crypt
                .as_ref()
                .is_some_and(SecurityHandler::is_authenticated)
        {
            return Err(HankoError::Signing(
                "Cannot update this document without authenticated encryption credentials".into(),
            ));
        }
        if let Some(handler) = &crypt {
            let mac_required = handler
                .standard_permissions()
                .is_some_and(|permissions| permissions.mac_required());
            if trailer.has(b"AuthCode") || handler.pdf_mac_enabled() || mac_required {
                // Reopening reuses keys, not a MAC verdict for these bytes.
                // Authenticate every operation's actual input before editing.
                sigis_pdf::crypt::pdfmac::validate_pdf_mac(
                    &reader,
                    sigis_pdf::crypt::pdfmac::ALLOWED_MD_ALGS,
                )
                .map_err(|error| match error {
                    sigis_pdf::crypt::pdfmac::MacValidationFailure::Invalid(reason) => {
                        HankoError::Signing(format!("Failed to validate input PDF MAC: {reason}"))
                    }
                    sigis_pdf::crypt::pdfmac::MacValidationFailure::Error(error) => error.into(),
                })?;
            }
        }
        let encrypt_ref = trailer.get(b"Encrypt").and_then(Object::as_reference).ok();
        let prev_startxref = usize::try_from(reader.last_startxref())
            .map_err(|_| malformed("negative startxref offset"))?;
        let stream_xrefs = reader.has_xref_stream();
        let hybrid = reader.xrefs().hybrid_xrefs_present();
        let root_id = trailer
            .get(b"Root")
            .and_then(Object::as_reference)
            .map_err(|_| malformed("trailer without /Root reference"))?;
        let info_id = trailer.get(b"Info").and_then(Object::as_reference).ok();
        let id1 = if trailer.has(b"ID") {
            reader.document_id()?.0
        } else {
            random_bytes(16)?
        };
        let unencrypted_objects = raw_trailer_references(&reader, &trailer)?;
        let size = trailer
            .get(b"Size")
            .and_then(Object::as_i64)
            .ok()
            .and_then(|size| u32::try_from(size).ok())
            .unwrap_or(0);
        let mut doc = lopdf::Document::with_version(format!(
            "{}.{}",
            reader.header_version().0,
            reader.header_version().1
        ));
        doc.trailer = trailer;
        let mut refs = std::collections::BTreeSet::new();
        for revision in 0..reader.total_revisions() {
            refs.extend(reader.xrefs().explicit_refs_in_revision(revision));
        }
        // The compatibility Document stores native parsed objects, never
        // invoking lopdf's eager, unbounded object-stream decoder. Ordinary
        // stream data stays encoded; native object streams obey the reader's
        // shared purpose limits and document decoding budget.
        let mut object_errors = BTreeMap::new();
        for id in refs {
            if reader.xrefs().get(id).is_some() {
                let object = if unencrypted_objects.contains(&id) {
                    reader.get_object_raw(id, None)
                } else {
                    reader.get_object_at(id, None)
                };
                doc.max_id = doc.max_id.max(id.0);
                match object {
                    Ok(object) => {
                        doc.objects.insert(id, object);
                    }
                    Err(
                        error @ (sigis_pdf::PdfError::Read(_) | sigis_pdf::PdfError::StrictRead(_)),
                    ) if !encrypted => {
                        object_errors.insert(id, error);
                    }
                    // Encrypted objects can report authentication failures as
                    // Read errors too, so all their errors remain eager. Budget
                    // and stream-decoding failures are never deferred either.
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let next_id = size.max(doc.max_id.saturating_add(1));
        Ok(Self {
            base: bytes.to_vec(),
            doc,
            object_errors,
            reader: reader.clone(),
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
            strict: reader.strict(),
            crypt,
            encrypt_ref,
            unencrypted_objects,
            auth_code: None,
            objstm_members: std::collections::BTreeSet::new(),
        })
    }

    /// State required to reopen the output without resetting reader policy.
    pub fn state(&self) -> PdfReopenState {
        PdfReopenState::from_reader(self.reader.clone())
    }

    /// Authenticated security handler for encryption and PDF MAC generation.
    pub fn security_handler(&self) -> Option<&SecurityHandler> {
        if self.fresh {
            None
        } else {
            self.crypt.as_ref()
        }
    }

    /// Decode a stream through the native reader's shared bounded context.
    pub fn read_stream_data(&self, stream: &Stream, purpose: DecodePurpose) -> Result<Vec<u8>> {
        Ok(self.reader.read_stream_data(stream, purpose, None)?)
    }

    /// Register a direct trailer AuthCode dictionary before signing.
    pub fn set_auth_code(&mut self, auth: Object) {
        self.auth_code = Some(auth);
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
        u.make_fresh();
        Ok(u)
    }

    /// Convert an authenticated update into a single-revision plaintext copy.
    pub fn make_fresh(&mut self) {
        self.fresh = true;
        self.stream_xrefs = false;
        self.hybrid = false;
        self.auth_code = None;
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
        if let Some(error) = self.object_errors.get(&id) {
            return Err(error.clone().into());
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
            _ => Err(malformed(format!(
                "object {} {} is not a dictionary",
                id.0, id.1
            ))),
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
            _ => Err(malformed(format!(
                "object {} {} is not a dictionary",
                id.0, id.1
            ))),
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

    /// Add a new object to be written into an object stream if the update
    /// uses an xref stream (`add_object(obj, obj_stream=...)`); streams are
    /// never put into object streams.
    pub fn add_in_object_stream(&mut self, obj: Object) -> ObjectId {
        let id = self.add(obj);
        self.objstm_members.insert(id);
        id
    }

    /// Replace object `id` and write it into an object stream if possible
    /// (see [`Self::add_in_object_stream`]).
    pub fn update_in_object_stream(&mut self, id: ObjectId, obj: Object) {
        self.update(id, obj);
        self.objstm_members.insert(id);
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
        if self.fresh {
            if let Some((_, error)) = self
                .object_errors
                .iter()
                .find(|(id, _)| !self.objects.contains_key(id))
            {
                return Err(error.clone().into());
            }
        }

        let crypt = if self.fresh {
            None
        } else {
            self.crypt.as_ref()
        };
        let encryptor = crypt.map(SecurityHandler::encryptor);
        if crypt.is_some_and(SecurityHandler::pdf_mac_enabled)
            && !self.placeholders.is_empty()
            && self.auth_code.is_none()
        {
            return Err(HankoError::Signing(
                "A MAC-enabled signature requires an attached AuthCode trailer entry".into(),
            ));
        }
        let standalone_mac = if self.auth_code.is_none() && self.placeholders.is_empty() {
            match encryptor.as_ref() {
                Some(encryptor) => encryptor.standalone_mac_placeholder()?,
                None => None,
            }
        } else {
            None
        };
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
        // Explicit /Crypt data remains encoded in native parsed streams.
        // A plaintext rewrite must decode it under the original reader policy
        // and remove its source-specific filter configuration.
        let mut plaintext_streams = BTreeMap::new();
        if self.fresh {
            for (id, object) in &all {
                if let Object::Stream(stream) = object {
                    if sigis_pdf::stream::has_crypt_filter(&stream.dict, &|object| {
                        sigis_pdf::PdfHandlerExt::resolve(&self.reader, object)
                    })? {
                        let data = self.read_stream_data(stream, DecodePurpose::Generic)?;
                        let mut dict = stream.dict.clone();
                        dict.remove(b"Filter");
                        dict.remove(b"DecodeParms");
                        plaintext_streams.insert(*id, Object::Stream(Stream::new(dict, data)));
                    }
                }
            }
        }
        for (id, object) in &plaintext_streams {
            all.insert(*id, object);
        }
        let mut positions: BTreeMap<ObjectId, usize> = BTreeMap::new();
        let mut offsets = BTreeMap::new();
        // objects packed into an object stream: id -> index in the stream
        let mut in_objstm: BTreeMap<ObjectId, u16> = BTreeMap::new();
        let mut next_id = self.next_id;
        let objstm_id = if self.stream_xrefs && crypt.is_none() && !self.fresh {
            let members: Vec<ObjectId> = self
                .objstm_members
                .iter()
                .copied()
                .filter(|id| {
                    id.1 == 0
                        && !self.placeholders.contains_key(id)
                        && matches!(self.objects.get(id), Some(o) if !matches!(o, Object::Stream(_)))
                })
                .collect();
            if members.is_empty() {
                None
            } else {
                let objstm_id = (next_id, 0);
                next_id += 1;
                let mut header = Vec::new();
                let mut body = Vec::new();
                for (ix, id) in members.iter().enumerate() {
                    let _ = write!(header, "{} {} ", id.0, body.len());
                    if let Some(obj) = self.objects.get(id) {
                        sigis_pdf::writer::write_object_encrypted(&mut body, obj, None)?;
                    }
                    body.push(b'\n');
                    in_objstm.insert(*id, u16::try_from(ix).unwrap_or(u16::MAX));
                }
                let mut d = Dictionary::new();
                d.set("Type", Object::Name(b"ObjStm".to_vec()));
                d.set(
                    "N",
                    Object::Integer(i64::try_from(members.len()).unwrap_or(0)),
                );
                d.set(
                    "First",
                    Object::Integer(i64::try_from(header.len()).unwrap_or(0)),
                );
                header.extend_from_slice(&body);
                let mut stream = Stream::new(d, header);
                stream
                    .compress()
                    .map_err(|e| HankoError::Signing(format!("compress object stream: {e}")))?;
                positions.insert(objstm_id, out.len());
                let _ = writeln!(out, "{} {} obj", objstm_id.0, objstm_id.1);
                sigis_pdf::writer::write_object_encrypted(&mut out, &Object::Stream(stream), None)?;
                out.extend_from_slice(b"\nendobj\n");
                Some(objstm_id)
            }
        } else {
            None
        };
        // The placeholders normally sit in the registered signature
        // dictionary, but may live in another object (e.g. an indirect
        // `/Contents`); patch them wherever they are written.
        let reserved = self.placeholders.values().next().copied();
        let mut contents_at: Option<usize> = None;
        let mut byte_range_at: Option<usize> = None;
        for (&id, obj) in &all {
            if in_objstm.contains_key(&id) {
                continue;
            }
            positions.insert(id, out.len());
            let _ = writeln!(out, "{} {} obj", id.0, id.1);
            let start = out.len();
            let mut body = Vec::new();
            let encryption = encryptor
                .as_deref()
                .filter(|_| !self.unencrypted_objects.contains(&id))
                .map(|encryptor| (encryptor, id));
            sigis_pdf::writer::write_object_encrypted(&mut body, obj, encryption)?;
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
        if let Some(auth_code) = self.auth_code.as_ref().or(standalone_mac.as_ref()) {
            trailer.set("AuthCode", auth_code.clone());
        }
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
                Object::String(
                    self.document_id[0].clone(),
                    lopdf::StringFormat::Hexadecimal,
                ),
                Object::String(
                    self.document_id[1].clone(),
                    lopdf::StringFormat::Hexadecimal,
                ),
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
            let xref_id = next_id;
            positions.insert((xref_id, 0), xref_location);
            let objstm_index: u32 = objstm_id.map(|o| o.0).unwrap_or(0);
            // entries in object streams are listed with their stream's id
            // and their index (type 2); positions holds a placeholder
            for id in in_objstm.keys() {
                positions.insert(*id, 0);
            }
            trailer.set("Size", Object::Integer(i64::from(xref_id) + 1));
            trailer.set("Type", Object::Name(b"XRef".to_vec()));
            trailer.set(
                "W",
                Object::Array(vec![
                    Object::Integer(1),
                    Object::Integer(8),
                    Object::Integer(2),
                ]),
            );
            let mut index = vec![Object::Integer(0), Object::Integer(1)];
            let mut data = vec![0u8; 9];
            data.extend_from_slice(&[0xff, 0xff]);
            for (first, chunk) in contiguous_chunks(&positions) {
                index.push(Object::Integer(i64::from(first)));
                index.push(Object::Integer(i64::try_from(chunk.len()).unwrap_or(0)));
                for (pos, gen, id) in chunk_ids(first, &chunk) {
                    match in_objstm.get(&(id, gen)) {
                        Some(ix) => {
                            data.push(2);
                            data.extend_from_slice(&u64::from(objstm_index).to_be_bytes());
                            data.extend_from_slice(&ix.to_be_bytes());
                        }
                        None => {
                            data.push(1);
                            data.extend_from_slice(&(pos as u64).to_be_bytes());
                            data.extend_from_slice(&gen.to_be_bytes());
                        }
                    }
                }
            }
            trailer.set("Index", Object::Array(index));
            let mut stream = Stream::new(trailer, data);
            stream
                .compress()
                .map_err(|e| HankoError::Signing(format!("compress xref stream: {e}")))?;
            let _ = writeln!(out, "{xref_id} 0 obj");
            sigis_pdf::writer::write_object_encrypted(&mut out, &Object::Stream(stream), None)?;
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
            sigis_pdf::writer::write_object_encrypted(
                &mut out,
                &Object::Dictionary(trailer),
                None,
            )?;
        }
        let _ = write!(out, "\nstartxref\n{xref_location}\n%%EOF\n");
        if standalone_mac.is_some() {
            if let Some(encryptor) = encryptor.as_ref() {
                encryptor.fill_standalone_mac(&mut out)?;
            }
        }
        Ok((out, offsets))
    }
}

/// Traverse encryption settings and file identifiers without treating their
/// indirect strings as encrypted document content. The native security handler
/// also resolves the encryption graph raw when authenticating the document.
fn raw_trailer_references(
    reader: &PdfFile,
    trailer: &Dictionary,
) -> Result<std::collections::BTreeSet<ObjectId>> {
    fn visit(
        reader: &PdfFile,
        object: &Object,
        references: &mut std::collections::BTreeSet<ObjectId>,
        depth: usize,
        remaining: &mut usize,
    ) -> Result<()> {
        if depth > 64 || *remaining == 0 {
            return Err(malformed(
                "Encryption settings or file identifier graph exceeds limits",
            ));
        }
        *remaining -= 1;
        match object {
            Object::Reference(id) if references.insert(*id) => {
                visit(
                    reader,
                    &reader.get_object_raw(*id, None)?,
                    references,
                    depth + 1,
                    remaining,
                )?;
            }
            Object::Array(values) => {
                for value in values {
                    visit(reader, value, references, depth + 1, remaining)?;
                }
            }
            Object::Dictionary(dictionary) => {
                for (_, value) in dictionary {
                    visit(reader, value, references, depth + 1, remaining)?;
                }
            }
            Object::Stream(_) => {
                return Err(malformed(
                    "Stream in encryption settings or file identifier graph",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    let mut references = std::collections::BTreeSet::new();
    let mut remaining = 4096;
    for key in [b"Encrypt".as_slice(), b"ID".as_slice()] {
        if let Ok(object) = trailer.get(key) {
            visit(reader, object, &mut references, 0, &mut remaining)?;
        }
    }
    Ok(references)
}

/// The entries of a chunk with their object numbers.
fn chunk_ids(first: u32, chunk: &[(usize, u16)]) -> Vec<(usize, u16, u32)> {
    chunk
        .iter()
        .zip(first..)
        .map(|(&(pos, gen), id)| (pos, gen, id))
        .collect()
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
        return Err(HankoError::Signing(
            "byte range does not fit its placeholder".into(),
        ));
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
    let reserved = offsets
        .contents_end
        .checked_sub(offsets.contents_start)
        .and_then(|length| length.checked_sub(2))
        .ok_or_else(|| malformed("invalid signature reserved region"))?;
    let region = out
        .get_mut(offsets.contents_start..offsets.contents_end)
        .ok_or_else(|| malformed("signature reserved region out of bounds"))?;
    if region.first() != Some(&b'<') || region.last() != Some(&b'>') {
        return Err(malformed("invalid signature reserved region delimiters"));
    }
    let required = content.len().checked_mul(2).ok_or_else(|| {
        HankoError::Signing("CMS payload size overflows the reserved region".into())
    })?;
    if required > reserved {
        return Err(HankoError::Signing(format!(
            "Final ByteRange payload larger than expected: allocated {reserved} bytes, but contents required {required} bytes."
        )));
    }
    let hex: Vec<u8> = content
        .iter()
        .flat_map(|b| {
            const H: &[u8; 16] = b"0123456789ABCDEF";
            [H[usize::from(b >> 4)], H[usize::from(b & 15)]]
        })
        .collect();
    region[1..1 + hex.len()].copy_from_slice(&hex);
    Ok(())
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).map_err(|e| HankoError::Signing(format!("RNG failure: {e}")))?;
    Ok(v)
}
