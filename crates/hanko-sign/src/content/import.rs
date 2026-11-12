// Derived from pyHanko `pdf_utils/writer.py` (`import_object`,
// `_ObjectImporter`, `import_page_as_xobject`) (MIT, see LICENSE-pyHanko).

//! Importing objects and pages from another PDF document.

use std::collections::BTreeMap;

use sigis_pki_core::errors::{HankoError, Result};
use lopdf::{Dictionary, Object, ObjectId, Stream};

use crate::pdf::writer::PdfUpdate;

fn malformed(msg: impl Into<String>) -> HankoError {
    HankoError::Malformed(msg.into())
}

/// Deep-copies objects from a source document into an update, mapping
/// indirect references (`_ObjectImporter`).
pub struct ObjectImporter<'s> {
    source: &'s lopdf::Document,
    reference_map: BTreeMap<ObjectId, ObjectId>,
    depth: usize,
}

impl<'s> ObjectImporter<'s> {
    /// An importer from `source`.
    pub fn new(source: &'s lopdf::Document) -> Self {
        Self {
            source,
            reference_map: BTreeMap::new(),
            depth: 0,
        }
    }

    /// Import `obj` (`import_object`).
    pub fn import_object(&mut self, target: &mut PdfUpdate, obj: &Object) -> Result<Object> {
        self.depth += 1;
        if self.depth > 256 {
            return Err(malformed("object nesting too deep while importing"));
        }
        let r = match obj {
            Object::Reference(id) => {
                if let Some(new) = self.reference_map.get(id) {
                    Object::Reference(*new)
                } else {
                    // allocate first to deal with circular references
                    let new_id = target.add(Object::Null);
                    self.reference_map.insert(*id, new_id);
                    let src = self
                        .source
                        .get_object(*id)
                        .cloned()
                        .unwrap_or(Object::Null);
                    let imported = self.import_object(target, &src)?;
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
                let dict = self.import_dict(target, &src_dict)?;
                let mut st = Stream::new(dict, s.content.clone());
                st.allows_compression = s.allows_compression;
                Object::Stream(st)
            }
            other => other.clone(),
        };
        self.depth -= 1;
        Ok(r)
    }

    fn import_dict(&mut self, target: &mut PdfUpdate, d: &Dictionary) -> Result<Dictionary> {
        let mut out = Dictionary::new();
        for (k, v) in d.iter() {
            out.set(k.clone(), self.import_object(target, v)?);
        }
        Ok(out)
    }
}

fn resolve<'a>(doc: &'a lopdf::Document, o: &'a Object) -> &'a Object {
    let mut cur = o;
    for _ in 0..32 {
        match cur {
            Object::Reference(id) => match doc.get_object(*id) {
                Ok(x) => cur = x,
                Err(_) => return &Object::Null,
            },
            _ => return cur,
        }
    }
    &Object::Null
}

/// Import page `page_ix` of `source` as a form XObject
/// (`import_page_as_xobject`); returns the XObject's id.
pub fn import_page_as_xobject(
    target: &mut PdfUpdate,
    source: &lopdf::Document,
    page_ix: usize,
    inherit_filters: bool,
) -> Result<ObjectId> {
    let pages = source.get_pages();
    let page_id = *pages
        .values()
        .nth(page_ix)
        .ok_or_else(|| malformed("Page index out of range"))?;
    let page = source
        .get_dictionary(page_id)
        .map_err(|e| malformed(format!("page object: {e}")))?;
    // inherited /MediaBox and /Resources
    let mut media_box = None;
    let mut resources = None;
    let mut node = Some(page);
    let mut guard = 0;
    while let Some(n) = node {
        guard += 1;
        if guard > 64 {
            break;
        }
        if media_box.is_none() {
            media_box = n.get(b"MediaBox").ok().map(|o| resolve(source, o).clone());
        }
        if resources.is_none() {
            resources = n.get(b"Resources").ok().cloned();
        }
        node = match n.get(b"Parent") {
            Ok(Object::Reference(p)) => source.get_dictionary(*p).ok(),
            _ => None,
        };
    }
    let media_box = media_box.ok_or_else(|| malformed(format!("Page {page_ix} does not have a /MediaBox")))?;
    let mut importer = ObjectImporter::new(source);
    let resources = resources.unwrap_or_else(|| Object::Dictionary(Dictionary::new()));
    let resources = importer.import_object(target, resolve(source, &resources))?;
    let mut stream_dict = Dictionary::new();
    stream_dict.set("BBox", media_box);
    stream_dict.set("Resources", resources);
    stream_dict.set("Type", Object::Name(b"XObject".to_vec()));
    stream_dict.set("Subtype", Object::Name(b"Form".to_vec()));
    let contents = page.get(b"Contents").map(|o| resolve(source, o)).unwrap_or(&Object::Null);
    let single: Option<&Stream> = match contents {
        Object::Array(a) if a.len() == 1 && inherit_filters => match resolve(source, &a[0]) {
            Object::Stream(s) => Some(s),
            _ => return Err(malformed("page content is not a stream")),
        },
        Object::Array(a) => {
            let mut data = Vec::new();
            for part in a {
                match resolve(source, part) {
                    Object::Stream(s) => data.extend(decoded(s)?),
                    _ => return Err(malformed("page content is not a stream")),
                }
            }
            let st = super::compressed(Stream::new(stream_dict, data));
            return Ok(target.add(Object::Stream(st)));
        }
        Object::Stream(s) => Some(s),
        _ => return Err(malformed("page has no content stream")),
    };
    let Some(cs) = single else {
        return Err(malformed("page has no content stream"));
    };
    let filters = if inherit_filters { cs.dict.get(b"Filter").ok().cloned() } else { None };
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
        None => Stream::new(stream_dict, decoded(cs)?),
    };
    Ok(target.add(Object::Stream(result)))
}

/// The decoded data of a stream.
pub fn decoded(s: &Stream) -> Result<Vec<u8>> {
    if s.dict.get(b"Filter").is_err() {
        return Ok(s.content.clone());
    }
    s.decompressed_content()
        .map_err(|e| malformed(format!("could not decode stream: {e}")))
}
