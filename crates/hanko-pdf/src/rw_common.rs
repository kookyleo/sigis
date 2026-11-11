// Derived from pyHanko `pdf_utils/rw_common.py` and `generic.py`
// (`Dereferenceable`, `DictionaryObject.__getitem__`) (MIT, see LICENSE-pyHanko).

//! Common interface of readers, historical views and writers (`PdfHandler`).

use std::collections::BTreeSet;

use lopdf::{Dictionary, Object, ObjectId, Stream};

use crate::decode_limits::{DecodeContext, DecodePurpose};
use crate::error::{PdfError, PdfResult};
use crate::stream::{decode_stream_data, CryptFilterDecode};

/// Maximal length of a chain of references pointing to references.
pub const MAX_REFERENCE_CHAIN: usize = 64;

/// Access to the objects of a PDF (`PdfHandler`).
pub trait PdfHandler {
    /// The object `id` refers to (`get_object`), decrypted if applicable.
    /// Undefined objects resolve to `null` in lenient mode.
    fn get_object(&self, id: ObjectId) -> PdfResult<Object>;

    /// A view of the trailer (`trailer_view`).
    fn trailer_view(&self) -> PdfResult<Dictionary>;

    /// Reference to the document catalog (`root_ref`).
    fn root_ref(&self) -> PdfResult<ObjectId>;

    /// Strict mode (`strict`).
    fn is_strict(&self) -> bool {
        true
    }

    /// Decode stream data with this handler's decoding limits (`read_data`).
    fn decode_stream(&self, stream: &Stream, purpose: DecodePurpose) -> PdfResult<Vec<u8>> {
        let mut ctx = DecodeContext::default();
        decode_stream_data(
            &stream.dict,
            &stream.content,
            &mut ctx,
            purpose,
            None,
            &|o| self.resolve(o),
            self.crypt_filters(),
        )
    }

    /// Security handler for explicit `/Crypt` filters, if any.
    fn crypt_filters(&self) -> Option<&dyn CryptFilterDecode> {
        None
    }
}

/// Convenience methods on [`PdfHandler`]s.
pub trait PdfHandlerExt: PdfHandler {
    /// Follow references until a direct object is reached
    /// (`IndirectObject.get_object`).
    fn resolve(&self, obj: &Object) -> PdfResult<Object> {
        let mut cur = match obj {
            Object::Reference(id) => self.get_object(*id)?,
            other => return Ok(other.clone()),
        };
        for _ in 0..MAX_REFERENCE_CHAIN {
            match cur {
                Object::Reference(id) => cur = self.get_object(id)?,
                other => return Ok(other),
            }
        }
        Err(PdfError::read("Reference chain too long"))
    }

    /// The document catalog (`root`).
    fn root(&self) -> PdfResult<Dictionary> {
        match self.get_object(self.root_ref()?)? {
            Object::Dictionary(d) => Ok(d),
            _ => Err(PdfError::read("Document catalog must be a dictionary")),
        }
    }

    /// `dict[key]`: dereferenced value, with `null` treated as absent.
    fn get(&self, dict: &Dictionary, key: &[u8]) -> PdfResult<Option<Object>> {
        match dict.get(key) {
            Err(_) => Ok(None),
            Ok(v) => match self.resolve(v)? {
                Object::Null => Ok(None),
                other => Ok(Some(other)),
            },
        }
    }

    /// `dict[key]`, failing with `KeyError` semantics as a [`PdfError::Value`].
    fn get_required(&self, dict: &Dictionary, key: &[u8]) -> PdfResult<Object> {
        self.get(dict, key)?
            .ok_or_else(|| PdfError::Value(format!("KeyError: /{}", String::from_utf8_lossy(key))))
    }

    /// `dict[key]` as a dictionary (streams yield their dictionary).
    fn get_dict(&self, dict: &Dictionary, key: &[u8]) -> PdfResult<Option<Dictionary>> {
        Ok(match self.get(dict, key)? {
            Some(Object::Dictionary(d)) => Some(d),
            Some(Object::Stream(s)) => Some(s.dict),
            _ => None,
        })
    }

    /// `dict[key]` as an array.
    fn get_array(&self, dict: &Dictionary, key: &[u8]) -> PdfResult<Option<Vec<Object>>> {
        Ok(match self.get(dict, key)? {
            Some(Object::Array(a)) => Some(a),
            _ => None,
        })
    }

    /// Decoded data of a stream (`StreamObject.data`).
    fn stream_data(&self, stream: &Stream) -> PdfResult<Vec<u8>> {
        self.decode_stream(stream, DecodePurpose::Generic)
    }

    /// Walk the page tree (`_walk_page_tree`).
    fn walk_page_tree(&self, page_ix: i64, retrieve_parent: bool) -> PdfResult<PageTreeLocation> {
        let root = self.root()?;
        let Ok(Object::Reference(pages_ref)) = root.get(b"Pages") else {
            return Err(PdfError::read("/Pages must be an indirect reference"));
        };
        let pages_ref = *pages_ref;
        let page_tree_root = match self.get_object(pages_ref)? {
            Object::Dictionary(d) => d,
            _ => return Err(PdfError::read("Page tree root must be a dictionary")),
        };
        let root_resources = self
            .get(&page_tree_root, b"Resources")?
            .unwrap_or_else(|| Object::Dictionary(Dictionary::new()));
        let page_count = as_int(&self.get_required(&page_tree_root, b"Count")?)?;
        let page_ix = if page_ix < 0 {
            page_count + page_ix
        } else {
            page_ix
        };
        if !(0 <= page_ix && page_ix < page_count) {
            return Err(PdfError::Generic("Page index out of range".into()));
        }
        let mut refs_seen = BTreeSet::new();
        self.walk_rec(
            0,
            pages_ref,
            root_resources,
            &mut refs_seen,
            page_ix,
            retrieve_parent,
        )
    }

    #[doc(hidden)]
    fn walk_rec(
        &self,
        first_page_ix: i64,
        pages_obj_ref: ObjectId,
        mut last_rsrc: Object,
        refs_seen: &mut BTreeSet<ObjectId>,
        page_ix: i64,
        retrieve_parent: bool,
    ) -> PdfResult<PageTreeLocation> {
        let pages_obj = match self.get_object(pages_obj_ref)? {
            Object::Dictionary(d) => d,
            _ => return Err(PdfError::read("Page tree node must be a dictionary")),
        };
        let kids = match self.get(&pages_obj, b"Kids")? {
            Some(Object::Array(a)) => a,
            _ => return Err(PdfError::read("Page tree node lacks /Kids")),
        };
        if let Ok(r) = pages_obj.get(b"Resources") {
            last_rsrc = r.clone();
        }
        let mut cur = first_page_ix;
        for (kid_index, kid_ref) in kids.iter().enumerate() {
            let Object::Reference(kid_id) = kid_ref else {
                return Err(PdfError::read(
                    "Page tree node children must be indirect objects",
                ));
            };
            if refs_seen.contains(kid_id) {
                return Err(PdfError::read("Circular reference in page tree"));
            }
            let kid = match self.get_object(*kid_id)? {
                Object::Dictionary(d) => d,
                _ => return Err(PdfError::read("Page tree node must be a dictionary")),
            };
            let node_type = self.get_required(&kid, b"Type")?;
            if crate::generic::is_name(&node_type, "Pages") {
                let desc = as_int(&self.get_required(&kid, b"Count")?)?;
                if cur <= page_ix && page_ix < cur + desc {
                    refs_seen.insert(*kid_id);
                    return self.walk_rec(
                        cur,
                        *kid_id,
                        last_rsrc,
                        refs_seen,
                        page_ix,
                        retrieve_parent,
                    );
                }
                cur += desc;
            } else if crate::generic::is_name(&node_type, "Page") {
                if cur == page_ix {
                    if retrieve_parent {
                        return Ok(PageTreeLocation {
                            node: pages_obj_ref,
                            kid_index,
                            resources: last_rsrc,
                        });
                    }
                    if let Ok(r) = kid.get(b"Resources") {
                        last_rsrc = r.clone();
                    }
                    return Ok(PageTreeLocation {
                        node: *kid_id,
                        kid_index,
                        resources: last_rsrc,
                    });
                }
                cur += 1;
            }
        }
        Err(PdfError::Generic("Page not found".into()))
    }

    /// The page tree node containing page `page_ix`, the index in its
    /// `/Kids`, and the inherited resources (`find_page_container`).
    fn find_page_container(&self, page_ix: i64) -> PdfResult<PageTreeLocation> {
        self.walk_page_tree(page_ix, true)
    }

    /// The page `page_ix` and its (possibly inherited) resources
    /// (`find_page_for_modification`).
    fn find_page_for_modification(&self, page_ix: i64) -> PdfResult<(ObjectId, Object)> {
        let loc = self.walk_page_tree(page_ix, false)?;
        Ok((loc.node, loc.resources))
    }

    /// `find_inherited_value_in_tree`.
    fn find_inherited_value(
        &self,
        init: &Dictionary,
        key: &[u8],
        parent_key: &[u8],
    ) -> PdfResult<Option<Object>> {
        let mut obj = init.clone();
        for _ in 0..1024 {
            if let Some(v) = self.get(&obj, key)? {
                return Ok(Some(v));
            }
            match self.get(&obj, parent_key)? {
                Some(Object::Dictionary(d)) => obj = d,
                _ => return Ok(None),
            }
        }
        Err(PdfError::read("Inheritance chain too long"))
    }
}

impl<T: PdfHandler + ?Sized> PdfHandlerExt for T {}

/// Result of a page tree walk.
#[derive(Clone, Debug, PartialEq)]
pub struct PageTreeLocation {
    /// The page (or, for `find_page_container`, its parent node).
    pub node: ObjectId,
    /// Index in the parent's `/Kids`.
    pub kid_index: usize,
    /// Resource dictionary (or a reference to it).
    pub resources: Object,
}

/// An integer value (pyHanko accepts both ints and integral decimals in
/// arithmetic; we require integers).
pub fn as_int(o: &Object) -> PdfResult<i64> {
    match o {
        Object::Integer(i) => Ok(*i),
        Object::Real(r) if r.fract() == 0.0 => Ok(*r as i64),
        other => Err(PdfError::value(format!("Expected a number, got {other:?}"))),
    }
}
