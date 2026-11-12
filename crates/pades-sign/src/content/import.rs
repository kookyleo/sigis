// Derived from pyHanko `pdf_utils/writer.py` (`import_object`,
// `_ObjectImporter`, `import_page_as_xobject`) (MIT, see LICENSE-pyHanko).

//! Importing objects and pages from another PDF document.

use std::cell::RefCell;
use std::collections::BTreeMap;

use lopdf::{Dictionary, Object, ObjectId, Stream};
use sigis_pdf::decode_limits::{DecodeContext, DecodeLimits, DecodePurpose};
use sigis_pdf::stream::decode_stream_data;
use sigis_pdf::{PdfError, PdfFile, PdfHandler, PdfHandlerExt, PdfResult};
use sigis_pki_core::errors::{HankoError, Result};

use crate::pdf::writer::PdfUpdate;

fn malformed(msg: impl Into<String>) -> HankoError {
    HankoError::Malformed(msg.into())
}

/// Native access for caller-selected policy; bounded compatibility access for
/// documents parsed by callers of the legacy API.
enum ImportSource<'s> {
    Reader(&'s PdfFile),
    Document {
        document: &'s lopdf::Document,
        context: RefCell<DecodeContext>,
    },
}

impl<'s> ImportSource<'s> {
    fn document(document: &'s lopdf::Document) -> Self {
        Self::Document {
            document,
            // Original input length is unavailable in a borrowed Document.
            // Keep the base document allowance without granting ratio credit.
            context: RefCell::new(DecodeContext::new(DecodeLimits::default(), Some(0))),
        }
    }
}

impl PdfHandler for ImportSource<'_> {
    fn get_object(&self, id: ObjectId) -> PdfResult<Object> {
        match self {
            Self::Reader(reader) => reader.get_object_at(id, None),
            Self::Document { document, .. } => document.get_object(id).cloned().map_err(|error| {
                PdfError::Read(format!("Imported object {} {}: {error}", id.0, id.1))
            }),
        }
    }

    fn trailer_view(&self) -> PdfResult<Dictionary> {
        Ok(match self {
            Self::Reader(reader) => reader.trailer_view(),
            Self::Document { document, .. } => document.trailer.clone(),
        })
    }

    fn root_ref(&self) -> PdfResult<ObjectId> {
        self.trailer_view()?
            .get(b"Root")
            .and_then(Object::as_reference)
            .map_err(|error| PdfError::Read(format!("Imported catalog reference: {error}")))
    }

    fn is_strict(&self) -> bool {
        match self {
            Self::Reader(reader) => reader.strict(),
            Self::Document { .. } => true,
        }
    }

    fn decode_stream(&self, stream: &Stream, purpose: DecodePurpose) -> PdfResult<Vec<u8>> {
        match self {
            Self::Reader(reader) => reader.read_stream_data(stream, purpose, None),
            Self::Document { context, .. } => decode_stream_data(
                &stream.dict,
                &stream.content,
                &mut context.borrow_mut(),
                purpose,
                None,
                &|object| self.resolve(object),
                None,
            ),
        }
    }
}

/// Deep-copies objects from a source document into an update, mapping
/// indirect references (`_ObjectImporter`).
pub struct ObjectImporter<'s> {
    source: ImportSource<'s>,
    reference_map: BTreeMap<ObjectId, ObjectId>,
    depth: usize,
}

impl<'s> ObjectImporter<'s> {
    /// An importer from `source`, using default stream decoding limits.
    /// Use [`import_page_as_xobject_from_reader`] to preserve native policy.
    pub fn new(source: &'s lopdf::Document) -> Self {
        Self::from_source(ImportSource::document(source))
    }

    fn from_source(source: ImportSource<'s>) -> Self {
        Self {
            source,
            reference_map: BTreeMap::new(),
            depth: 0,
        }
    }

    /// Import `obj` (`import_object`).
    pub fn import_object(&mut self, target: &mut PdfUpdate, obj: &Object) -> Result<Object> {
        if self.depth >= 256 {
            return Err(malformed("object nesting too deep while importing"));
        }
        self.depth += 1;
        let result = self.import_object_inner(target, obj);
        self.depth -= 1;
        result
    }

    fn import_object_inner(&mut self, target: &mut PdfUpdate, obj: &Object) -> Result<Object> {
        Ok(match obj {
            Object::Reference(id) => {
                if let Some(new) = self.reference_map.get(id) {
                    Object::Reference(*new)
                } else {
                    // Allocate first to deal with circular references.
                    let new_id = target.add(Object::Null);
                    self.reference_map.insert(*id, new_id);
                    let source = self.source.get_object(*id)?;
                    let imported = self.import_object(target, &source)?;
                    target.update(new_id, imported);
                    Object::Reference(new_id)
                }
            }
            Object::Dictionary(d) => Object::Dictionary(self.import_dict(target, d)?),
            Object::Array(a) => {
                let mut out = Vec::with_capacity(a.len());
                for x in a {
                    out.push(self.import_object(target, x)?);
                }
                Object::Array(out)
            }
            Object::Stream(s) => {
                let mut src_dict = s.dict.clone();
                src_dict.remove(b"Length");
                let data = if sigis_pdf::stream::has_crypt_filter(&s.dict, &|object| {
                    self.source.resolve(object)
                })? {
                    // Source-specific crypt filters cannot be copied to a
                    // different document, even when other filters are retained.
                    src_dict.remove(b"Filter");
                    src_dict.remove(b"DecodeParms");
                    self.source.stream_data(s)?
                } else {
                    s.content.clone()
                };
                let dict = self.import_dict(target, &src_dict)?;
                let mut st = Stream::new(dict, data);
                st.allows_compression = s.allows_compression;
                Object::Stream(st)
            }
            other => other.clone(),
        })
    }

    fn import_dict(&mut self, target: &mut PdfUpdate, d: &Dictionary) -> Result<Dictionary> {
        let mut out = Dictionary::new();
        for (k, v) in d.iter() {
            out.set(k.clone(), self.import_object(target, v)?);
        }
        Ok(out)
    }
}

/// Import page `page_ix` of `source` as a form XObject
/// (`import_page_as_xobject`); returns the XObject's id.
pub fn import_page_as_xobject(
    target: &mut PdfUpdate,
    source: &lopdf::Document,
    page_ix: usize,
    inherit_filters: bool,
) -> Result<ObjectId> {
    import_page(
        target,
        ImportSource::document(source),
        page_ix,
        inherit_filters,
    )
}

/// Import a page using the source reader's existing limits, remaining budget,
/// strictness and authentication. No source document is reparsed.
pub fn import_page_as_xobject_from_reader(
    target: &mut PdfUpdate,
    source: &PdfFile,
    page_ix: usize,
    inherit_filters: bool,
) -> Result<ObjectId> {
    import_page(
        target,
        ImportSource::Reader(source),
        page_ix,
        inherit_filters,
    )
}

fn import_page(
    target: &mut PdfUpdate,
    source: ImportSource<'_>,
    page_ix: usize,
    inherit_filters: bool,
) -> Result<ObjectId> {
    let page_ix = i64::try_from(page_ix).map_err(|_| malformed("Page index out of range"))?;
    let (page_id, resources) = source.find_page_for_modification(page_ix)?;
    let page = match source.get_object(page_id)? {
        Object::Dictionary(page) => page,
        _ => return Err(malformed("page object is not a dictionary")),
    };
    let media_box = source
        .find_inherited_value(&page, b"MediaBox", b"Parent")?
        .ok_or_else(|| malformed(format!("Page {page_ix} does not have a /MediaBox")))?;
    let resources = source.resolve(&resources)?;
    let mut importer = ObjectImporter::from_source(source);
    let resources = importer.import_object(target, &resources)?;
    let mut stream_dict = Dictionary::new();
    stream_dict.set("BBox", media_box);
    stream_dict.set("Resources", resources);
    stream_dict.set("Type", Object::Name(b"XObject".to_vec()));
    stream_dict.set("Subtype", Object::Name(b"Form".to_vec()));
    let contents = importer
        .source
        .get(&page, b"Contents")?
        .unwrap_or(Object::Null);
    let single = match contents {
        Object::Array(a) if a.len() == 1 && inherit_filters => {
            match importer.source.resolve(&a[0])? {
                Object::Stream(s) => s,
                _ => return Err(malformed("page content is not a stream")),
            }
        }
        Object::Array(a) => {
            let mut data = Vec::new();
            for part in a {
                match importer.source.resolve(&part)? {
                    Object::Stream(s) => data.extend(importer.source.stream_data(&s)?),
                    _ => return Err(malformed("page content is not a stream")),
                }
            }
            let st = super::compressed(Stream::new(stream_dict, data));
            return Ok(target.add(Object::Stream(st)));
        }
        Object::Stream(s) => s,
        _ => return Err(malformed("page has no content stream")),
    };
    let cs = single;
    let filters = if inherit_filters
        && !sigis_pdf::stream::has_crypt_filter(&cs.dict, &|object| {
            importer.source.resolve(object)
        })? {
        cs.dict.get(b"Filter").ok().cloned()
    } else {
        None
    };
    let result = match filters {
        Some(f) => {
            let f = importer.import_object(target, &f)?;
            stream_dict.set("Filter", f);
            if let Ok(dp) = cs.dict.get(b"DecodeParms") {
                let dp = importer.import_object(target, dp)?;
                stream_dict.set("DecodeParms", dp);
            }
            let mut s = Stream::new(stream_dict, cs.content.clone());
            s.allows_compression = false;
            s
        }
        None => Stream::new(stream_dict, importer.source.stream_data(&cs)?),
    };
    Ok(target.add(Object::Stream(result)))
}

/// Decode standalone stream data with default limits. Indirect filter
/// parameters require the source-aware page import API.
pub fn decoded(s: &Stream) -> Result<Vec<u8>> {
    Ok(decode_stream_data(
        &s.dict,
        &s.content,
        &mut DecodeContext::new(DecodeLimits::default(), Some(0)),
        DecodePurpose::Generic,
        None,
        &|object| match object {
            Object::Reference(_) => Err(PdfError::Read(
                "Indirect stream parameters require a source reader".into(),
            )),
            other => Ok(other.clone()),
        },
        None,
    )?)
}
