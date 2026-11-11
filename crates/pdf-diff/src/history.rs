// Derived from pyHanko `pdf_utils/reader.py` (`HistoricalResolver`:
// `get_object`, `is_ref_unassignable`, `collect_dependencies`,
// `_load_reverse_xref_cache`) and `pdf_utils/xref.py` (`XRefCache` queries)
// (MIT, see LICENSE-pyHanko).

//! Historical view of a PDF revision (`HistoricalResolver`).
//!
//! The rule engine reads documents through [`RevisionSource`], which exposes
//! exactly the cross-reference information that pyHanko's difference
//! analysis consults. `sigis_pdf::PdfFile` implements it through
//! [`crate::PdfFileSource`]; tests use sources built from pyHanko's own
//! cross-reference model.

use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use lopdf::{Dictionary, Object, ObjectId};
use sigis_pki_core::errors::Result;

use crate::error::{read_error, DiffError, DiffResultT};
use crate::object::{as_dict, name_str, ref_str};
use crate::path::{PathNode, RawPdfPath};

/// Cross-reference data of one revision (`XRefSectionData` plus
/// `XRefSectionMetaInfo`), defined by `sigis-pdf` (request C1).
pub use sigis_pdf::XrefSectionInfo;

/// Read access to the revision history of a PDF file.
///
/// Revisions are numbered from 0 (the original document).
pub trait RevisionSource {
    /// Number of revisions (`XRefCache.total_revisions`).
    fn revision_count(&self) -> Result<usize>;

    /// Cross-reference data of `revision`.
    fn section(&self, revision: usize) -> Result<XrefSectionInfo>;

    /// The value of `id` as seen from `revision`; `None` if the reference does
    /// not resolve there (free or never defined).
    fn object(&self, id: ObjectId, revision: usize) -> Result<Option<Object>>;

    /// The trailer as seen from `revision`: all trailers up to `revision`
    /// merged (newest wins), without `/Length`, `/Filter`, `/DecodeParms`,
    /// `/W`, `/Type`, `/Index` and `/XRefStm` (`TrailerDictionary.flatten`).
    fn trailer(&self, revision: usize) -> Result<Dictionary>;

    /// The newest revision whose section resolves `id`
    /// (`XRefCache.get_last_change`).
    fn last_change(&self, id: ObjectId) -> Result<Option<usize>>;

    /// The oldest revision whose section resolves `id` to an object
    /// (`XRefCache.get_introducing_revision`).
    fn introducing_revision(&self, id: ObjectId) -> Result<Option<usize>>;

    /// Whether `id` resolves to an object in `revision`
    /// (`XRefCache.get_historical_ref(..) is not None`).
    fn resolves_in(&self, id: ObjectId, revision: usize) -> Result<bool>;

    /// Strict reading mode (`PdfFileReader.strict`, default `true`).
    fn strict(&self) -> bool {
        true
    }
}

/// Anchor of a relative context: the trailer or an indirect object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Anchor {
    /// The trailer dictionary (`TrailerReference`).
    Trailer,
    /// An indirect object.
    Ref(ObjectId),
}

/// Upper bound on the number of (reference, path) records computed by the
/// reverse cross-reference cache. pyHanko has no bound; documents that hit
/// it are rejected (fail closed) instead of exhausting memory.
pub const MAX_USAGE_PATHS: usize = 2_000_000;

/// Persistent singly linked list (`misc.ConsList`).
#[derive(Clone)]
struct Cons<T>(Option<Rc<(T, Cons<T>)>>);

impl<T: Clone + PartialEq> Cons<T> {
    fn empty() -> Self {
        Cons(None)
    }
    fn cons(&self, head: T) -> Self {
        Cons(Some(Rc::new((head, self.clone()))))
    }
    fn contains(&self, x: &T) -> bool {
        let mut cur = &self.0;
        while let Some(node) = cur {
            if &node.0 == x {
                return true;
            }
            cur = &node.1 .0;
        }
        false
    }
    fn to_vec_rev(&self) -> Vec<T> {
        let mut out = Vec::new();
        let mut cur = &self.0;
        while let Some(node) = cur {
            out.push(node.0.clone());
            cur = &node.1 .0;
        }
        out.reverse();
        out
    }
}

/// A view of the document as it was in one revision (`HistoricalResolver`).
pub struct Revision<'a> {
    src: &'a dyn RevisionSource,
    revision: usize,
    section: XrefSectionInfo,
    trailer_dict: Dictionary,
    trailer: Rc<Object>,
    cache: RefCell<HashMap<ObjectId, Rc<Object>>>,
    usages: OnceCell<HashMap<ObjectId, HashSet<RawPdfPath>>>,
}

impl std::fmt::Debug for Revision<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Revision")
            .field("revision", &self.revision)
            .finish()
    }
}

impl<'a> Revision<'a> {
    /// Open `revision` of `src`.
    pub fn new(src: &'a dyn RevisionSource, revision: usize) -> DiffResultT<Self> {
        let section = src.section(revision)?;
        let trailer_dict = src.trailer(revision)?;
        let trailer = Rc::new(Object::Dictionary(trailer_dict.clone()));
        Ok(Self {
            src,
            revision,
            section,
            trailer_dict,
            trailer,
            cache: RefCell::new(HashMap::new()),
            usages: OnceCell::new(),
        })
    }

    /// The revision number.
    pub fn revision(&self) -> usize {
        self.revision
    }

    /// The underlying source.
    pub fn source(&self) -> &'a dyn RevisionSource {
        self.src
    }

    /// Cross-reference data of this revision.
    pub fn section(&self) -> &XrefSectionInfo {
        &self.section
    }

    /// The flattened trailer (`trailer_view`).
    pub fn trailer(&self) -> &Dictionary {
        &self.trailer_dict
    }

    pub(crate) fn trailer_obj(&self) -> Rc<Object> {
        self.trailer.clone()
    }

    /// `HistoricalResolver.get_object` without following reference chains:
    /// the raw value of `id` in this revision.
    pub fn get_raw(&self, id: ObjectId) -> DiffResultT<Rc<Object>> {
        if let Some(o) = self.cache.borrow().get(&id) {
            return Ok(o.clone());
        }
        let obj = match self.src.object(id, self.revision)? {
            Some(o) => o,
            None if self.src.strict() => {
                return read_error(format!(
                    "Object addressed by {} not found in the current context. \
                     This is an error in strict mode.",
                    ref_str(id)
                ))
            }
            None => Object::Null,
        };
        let obj = Rc::new(obj);
        self.cache.borrow_mut().insert(id, obj.clone());
        Ok(obj)
    }

    /// `Reference.get_object`: resolve `id`, following reference chains.
    pub fn get(&self, id: ObjectId) -> DiffResultT<Rc<Object>> {
        let mut cur = self.get_raw(id)?;
        let mut hops = 0;
        while let Object::Reference(next) = &*cur {
            hops += 1;
            if hops > 64 {
                return read_error(format!("Reference chain too long at {}", ref_str(id)));
            }
            cur = self.get_raw(*next)?;
        }
        Ok(cur)
    }

    /// Dereference a value if it is a reference (`get_object()`).
    pub fn deref(&self, obj: &Object) -> DiffResultT<Rc<Object>> {
        match obj {
            Object::Reference(id) => self.get(*id),
            other => Ok(Rc::new(other.clone())),
        }
    }

    /// The `/Root` reference in the trailer (`root_ref`).
    pub fn root_ref(&self) -> DiffResultT<ObjectId> {
        match self.trailer().get(b"Root") {
            Ok(Object::Reference(id)) => Ok(*id),
            Ok(_) => read_error("/Root in trailer is not an indirect reference"),
            Err(_) => read_error("No /Root in trailer"),
        }
    }

    /// The document catalog (`root`).
    pub fn root(&self) -> DiffResultT<Rc<Object>> {
        let root = self.get(self.root_ref()?)?;
        if as_dict(&root).is_none() {
            return read_error("Document catalog is not a dictionary");
        }
        Ok(root)
    }

    /// `explicit_refs_in_revision`.
    pub fn explicit_refs(&self) -> &BTreeSet<ObjectId> {
        &self.section.explicit_refs
    }

    /// `refs_freed_in_revision`.
    pub fn refs_freed(&self) -> &BTreeSet<ObjectId> {
        &self.section.freed
    }

    /// `object_streams_used`.
    pub fn object_streams_used(&self) -> impl Iterator<Item = ObjectId> + '_ {
        self.section.object_streams_used.iter().map(|n| (*n, 0))
    }

    /// `is_ref_unassignable`: whether `id` was out of scope in this revision
    /// (its number is at least the section's `/Size`).
    pub fn is_ref_unassignable(&self, id: ObjectId) -> bool {
        id.0 >= self.section.size
    }

    /// `collect_dependencies`: all references used by `obj` and its
    /// descendants. With `since_revision`, only references introduced in
    /// that revision or later are collected and older objects are not
    /// entered. References that no revision defines are skipped.
    pub fn collect_dependencies(
        &self,
        obj: &Object,
        since_revision: Option<usize>,
    ) -> DiffResultT<BTreeSet<ObjectId>> {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<ObjectId> = Vec::new();
        push_refs(obj, &mut stack);
        while let Some(id) = stack.pop() {
            if seen.contains(&id) {
                continue;
            }
            let Some(intro) = self.src.introducing_revision(id)? else {
                continue;
            };
            let relevant = since_revision.is_none_or(|s| intro >= s);
            if relevant {
                seen.insert(id);
            } else if since_revision.is_some() {
                continue;
            }
            let o = self.get_raw(id)?;
            if matches!(
                &*o,
                Object::Dictionary(_) | Object::Stream(_) | Object::Array(_)
            ) {
                push_refs_children(&o, &mut stack);
            }
        }
        Ok(seen)
    }

    /// `_get_usages_of_ref`: the paths from the trailer through which `id`
    /// is reached in this revision. Computes the reverse cross-reference
    /// cache on first use.
    pub fn usages_of(&self, id: ObjectId) -> DiffResultT<HashSet<RawPdfPath>> {
        Ok(self.usages()?.get(&id).cloned().unwrap_or_default())
    }

    /// The reverse cross-reference cache (`_load_reverse_xref_cache`).
    pub fn usages(&self) -> DiffResultT<&HashMap<ObjectId, HashSet<RawPdfPath>>> {
        if let Some(u) = self.usages.get() {
            return Ok(u);
        }
        let computed = self.compute_usages()?;
        Ok(self.usages.get_or_init(|| computed))
    }

    fn compute_usages(&self) -> DiffResultT<HashMap<ObjectId, HashSet<RawPdfPath>>> {
        let root = self.root()?;
        let root_dict = as_dict(&root).ok_or_else(|| DiffError::Read("bad catalog".into()))?;

        // page tree nodes and their canonical paths
        let pages_raw = root_dict
            .get(b"Pages")
            .map_err(|_| DiffError::Read("No /Pages in document catalog".into()))?
            .clone();
        let pages_path = RawPdfPath::of(["/Root", "/Pages"]);
        let mut page_tree: HashMap<ObjectId, RawPdfPath> = HashMap::new();
        if let Object::Reference(id) = pages_raw {
            page_tree.insert(id, pages_path.clone());
        }
        let pages_obj = self.deref(&pages_raw)?;
        self.collect_page_tree_refs(&pages_obj, &pages_path, &mut page_tree)?;

        // structure tree elements
        let mut struct_tree: HashSet<ObjectId> = HashSet::new();
        if let Ok(str_root_raw) = root_dict.get(b"StructTreeRoot") {
            let str_root = self.deref(str_root_raw)?;
            self.collect_struct_tree_refs(&str_root, &mut struct_tree)?;
        }

        let mut walker = UsageWalker {
            rev: self,
            page_tree: &page_tree,
            struct_tree: &struct_tree,
            collected: HashMap::new(),
            records: 0,
            pending: Vec::new(),
        };
        let trailer = self.trailer_obj();
        walker.walk_value(&trailer, &Cons::empty(), &Cons::empty(), false)?;
        while let Some(item) = walker.pending.pop() {
            walker.visit_ref(item)?;
        }
        Ok(walker
            .collected
            .into_iter()
            .map(|(id, paths)| (id, paths.into_iter().map(RawPdfPath).collect()))
            .collect())
    }

    fn collect_page_tree_refs(
        &self,
        pages_obj: &Object,
        path: &RawPdfPath,
        out: &mut HashMap<ObjectId, RawPdfPath>,
    ) -> DiffResultT<()> {
        // explicit stack of (node, path) to avoid deep recursion
        let mut stack: Vec<(Rc<Object>, RawPdfPath)> =
            vec![(Rc::new(pages_obj.clone()), path.clone())];
        while let Some((node, node_path)) = stack.pop() {
            let dict =
                as_dict(&node).ok_or_else(|| DiffError::Read("Invalid page tree node".into()))?;
            let kids_raw = dict
                .get(b"Kids")
                .map_err(|_| DiffError::Read("No /Kids in page tree node".into()))?;
            let kids = self.deref(kids_raw)?;
            let Object::Array(kids) = &*kids else {
                return read_error("/Kids in page tree node is not an array");
            };
            let mut children = Vec::new();
            for (ix, kid) in kids.iter().enumerate() {
                let kid_path = node_path.child("/Kids").child(ix);
                if let Object::Reference(id) = kid {
                    if out.contains_key(id) {
                        return read_error("Circular reference in page tree in mapping stage");
                    }
                    out.insert(*id, kid_path.clone());
                }
                let kid_obj = self.deref(kid)?;
                let is_pages = as_dict(&kid_obj)
                    .and_then(|d| d.get(b"Type").ok())
                    .is_some_and(|t| matches!(t, Object::Name(n) if n == b"Pages"));
                if is_pages {
                    children.push((kid_obj, kid_path));
                }
            }
            // keep pyHanko's depth-first order
            stack.extend(children.into_iter().rev());
        }
        Ok(())
    }

    fn collect_struct_tree_refs(
        &self,
        root: &Object,
        out: &mut HashSet<ObjectId>,
    ) -> DiffResultT<()> {
        let mut stack: Vec<Rc<Object>> = vec![Rc::new(root.clone())];
        while let Some(elem) = stack.pop() {
            let Some(dict) = as_dict(&elem) else { continue };
            let Ok(k_raw) = dict.get(b"K") else { continue };
            let k = self.deref(k_raw)?;
            let children: Vec<Object> = match &*k {
                Object::Array(a) => a.clone(),
                other => vec![other.clone()],
            };
            let mut next = Vec::new();
            for child in children {
                let child_ref = match child {
                    Object::Reference(id) => Some(id),
                    _ => None,
                };
                let child_obj = self.deref(&child)?;
                let Some(cd) = as_dict(&child_obj) else {
                    continue;
                };
                if let Ok(t) = cd.get(b"Type") {
                    let t = self.deref(t)?;
                    if !matches!(&*t, Object::Name(n) if n == b"StructElem") {
                        continue;
                    }
                }
                if let Some(id) = child_ref {
                    if !out.insert(id) {
                        return read_error("Circular reference in structure tree in mapping stage");
                    }
                }
                next.push(child_obj);
            }
            stack.extend(next.into_iter().rev());
        }
        Ok(())
    }

    /// `Context.relative_to(start, path)` where `start` is the object at
    /// `anchor`: walk `path` without dereferencing transparently, and
    /// re-anchor at every indirect object passed on the way.
    pub fn relative_to(
        &self,
        anchor: Anchor,
        path: &RawPdfPath,
    ) -> DiffResultT<(Anchor, RawPdfPath)> {
        let start: Rc<Object> = match anchor {
            Anchor::Trailer => self.trailer_obj(),
            Anchor::Ref(id) => self.get(id)?,
        };
        let mut cur_anchor = anchor;
        let mut rel: Vec<PathNode> = Vec::new();
        let mut raw: Rc<Object> = start;
        let mut elem: Option<PathNode> = None;
        let n = path.len();
        for ix in 0..=n {
            match &*raw {
                Object::Reference(id) if ix < n => {
                    cur_anchor = Anchor::Ref(*id);
                    rel.clear();
                }
                _ => {
                    if let Some(e) = &elem {
                        rel.push(e.clone());
                    }
                }
            }
            if ix == n {
                break;
            }
            let current = match &*raw {
                Object::Reference(id) => self.get(*id)?,
                _ => raw.clone(),
            };
            let entry = &path.0[ix];
            let next = match (entry, &*current) {
                (PathNode::Key(k), obj) if as_dict(obj).is_some() => {
                    let d = as_dict(obj).ok_or_else(|| DiffError::Read(String::new()))?;
                    match d.get(k) {
                        Ok(v) => v.clone(),
                        Err(_) => {
                            return read_error(format!(
                                "Encountered missing dictionary entry {} at position {ix} \
                                 in path {path}.",
                                name_str(k)
                            ))
                        }
                    }
                }
                (PathNode::Index(i), Object::Array(a)) => match a.get(*i) {
                    Some(v) => v.clone(),
                    None => {
                        return read_error(format!(
                            "Encountered out-of-range array index {i} at position {ix} \
                             in path {path}."
                        ))
                    }
                },
                _ => return read_error(format!("Type error in path {path} at position {ix}.")),
            };
            raw = Rc::new(next);
            elem = Some(entry.clone());
        }
        Ok((cur_anchor, RawPdfPath(rel)))
    }

    /// `Context.from_absolute(...).relative_view`.
    pub fn relative_view(&self, path: &RawPdfPath) -> DiffResultT<(Anchor, RawPdfPath)> {
        self.relative_to(Anchor::Trailer, path)
    }

    /// `RelativeContext.descend`: the context `path` below a relative
    /// context, normalised to its nearest indirect anchor.
    pub fn descend_relative(
        &self,
        anchor: Anchor,
        rel: &RawPdfPath,
        path: &RawPdfPath,
    ) -> DiffResultT<(Anchor, RawPdfPath)> {
        if let Anchor::Ref(id) = anchor {
            let root = self.get(id)?;
            if !matches!(
                &*root,
                Object::Dictionary(_) | Object::Array(_) | Object::Stream(_)
            ) {
                return read_error(format!("Anchor {} is not a container object", ref_str(id)));
            }
        }
        self.relative_to(anchor, &rel.join(path))
    }
}

fn push_refs(obj: &Object, stack: &mut Vec<ObjectId>) {
    match obj {
        Object::Reference(id) => stack.push(*id),
        other => push_refs_children(other, stack),
    }
}

fn push_refs_children(obj: &Object, stack: &mut Vec<ObjectId>) {
    // direct nesting is walked recursively; its depth is bounded by the parser
    match obj {
        Object::Dictionary(d) => d.iter().for_each(|(_, v)| push_refs(v, stack)),
        Object::Stream(s) => s.dict.iter().for_each(|(_, v)| push_refs(v, stack)),
        Object::Array(a) => a.iter().for_each(|v| push_refs(v, stack)),
        _ => {}
    }
}

struct PendingRef {
    id: ObjectId,
    path: Cons<PathNode>,
    seen: Cons<ObjectId>,
    is_struct_tree: bool,
}

struct UsageWalker<'r, 'a> {
    rev: &'r Revision<'a>,
    page_tree: &'r HashMap<ObjectId, RawPdfPath>,
    struct_tree: &'r HashSet<ObjectId>,
    collected: HashMap<ObjectId, HashSet<Vec<PathNode>>>,
    records: usize,
    pending: Vec<PendingRef>,
}

impl UsageWalker<'_, '_> {
    /// `_compute_paths_to_refs` for an indirect reference.
    fn visit_ref(&mut self, item: PendingRef) -> DiffResultT<()> {
        let PendingRef {
            id,
            path,
            seen,
            is_struct_tree,
        } = item;
        if seen.contains(&id) {
            return Ok(());
        }
        self.records += 1;
        if self.records > MAX_USAGE_PATHS {
            return read_error("Too many object paths in document (reverse xref cache limit)");
        }
        let flat = path.to_vec_rev();
        let seen = seen.cons(id);
        let obj = self.rev.get_raw(id)?;
        // only enter page tree nodes via their canonical path
        let off_canonical = self.page_tree.get(&id).is_some_and(|c| c.0 != flat);
        self.collected.entry(id).or_default().insert(flat);
        if off_canonical {
            return Ok(());
        }
        if !is_struct_tree && self.struct_tree.contains(&id) {
            return Ok(());
        }
        self.walk_container(&obj, &path, &seen, is_struct_tree)
    }

    fn walk_value(
        &mut self,
        obj: &Object,
        path: &Cons<PathNode>,
        seen: &Cons<ObjectId>,
        is_struct_tree: bool,
    ) -> DiffResultT<()> {
        match obj {
            Object::Reference(id) => {
                self.pending.push(PendingRef {
                    id: *id,
                    path: path.clone(),
                    seen: seen.clone(),
                    is_struct_tree,
                });
                Ok(())
            }
            other => self.walk_container(other, path, seen, is_struct_tree),
        }
    }

    fn walk_container(
        &mut self,
        obj: &Object,
        path: &Cons<PathNode>,
        seen: &Cons<ObjectId>,
        is_struct_tree: bool,
    ) -> DiffResultT<()> {
        if let Some(d) = as_dict(obj) {
            let at_struct_root = {
                let p = path.to_vec_rev();
                p.len() == 2
                    && p[0] == PathNode::Key(b"Root".to_vec())
                    && p[1] == PathNode::Key(b"StructTreeRoot".to_vec())
            };
            for (k, v) in d.iter() {
                if k == b"Parent" || (is_struct_tree && k == b"P") {
                    continue;
                }
                let child_struct = is_struct_tree || (at_struct_root && k == b"K");
                self.walk_value(v, &path.cons(PathNode::Key(k.clone())), seen, child_struct)?;
            }
        } else if let Object::Array(a) = obj {
            for (ix, v) in a.iter().enumerate() {
                self.walk_value(v, &path.cons(PathNode::Index(ix)), seen, is_struct_tree)?;
            }
        }
        Ok(())
    }
}
