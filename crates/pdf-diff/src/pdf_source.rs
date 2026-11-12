// Interfaces derived from pyHanko `pdf_utils/xref.py` (`XRefCache`) (MIT, see
// LICENSE-pyHanko).

//! [`RevisionSource`] for [`sigis_pdf::PdfFile`].
//!
//! `PdfFile` exposes revisions, historical objects, the objects written per
//! revision and per-revision trailers. The cross-reference details that the
//! rules need are derived from these (see `docs/lanes/c.md`, request C1, for
//! the exact accessors requested from lane B). Every derivation errs on the
//! strict side: anything it cannot establish is left unexplained.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};

use lopdf::{Dictionary, Object, ObjectId};
use sigis_pdf::PdfFile;
use sigis_pki_core::errors::{HankoError, Result};

use crate::history::{RevisionSource, XrefSectionInfo};

/// Trailer keys that are not inherited (`TrailerDictionary.non_trailer_keys`).
pub(crate) const NON_TRAILER_KEYS: &[&[u8]] = &[
    b"Length",
    b"Filter",
    b"DecodeParms",
    b"W",
    b"Type",
    b"Index",
    b"XRefStm",
];

/// The revision primitives of [`PdfFile`] that [`DerivedSource`] builds on.
pub trait PdfRevisions {
    /// For each revision, oldest first: whether it uses a cross-reference
    /// stream (`PdfFile::revisions`).
    fn xref_stream_flags(&self) -> Result<Vec<bool>>;
    /// `PdfFile::objects_written_in`.
    fn objects_written_in(&self, revision: usize) -> Result<Vec<ObjectId>>;
    /// `PdfFile::object_in_revision`.
    fn object_in_revision(&self, id: ObjectId, revision: usize) -> Result<Option<Object>>;
    /// `PdfFile::trailer_in_revision`.
    fn trailer_in_revision(&self, revision: usize) -> Result<Dictionary>;
    /// Strict reading mode (unresolvable references are errors). `PdfFile`
    /// does not expose its mode yet (request C1), so the default is strict.
    fn strict(&self) -> bool {
        true
    }
}

impl PdfRevisions for PdfFile {
    fn xref_stream_flags(&self) -> Result<Vec<bool>> {
        Ok(self.revisions()?.iter().map(|r| r.xref_stream).collect())
    }
    fn objects_written_in(&self, revision: usize) -> Result<Vec<ObjectId>> {
        PdfFile::objects_written_in(self, revision)
    }
    fn object_in_revision(&self, id: ObjectId, revision: usize) -> Result<Option<Object>> {
        PdfFile::object_in_revision(self, id, revision)
    }
    fn trailer_in_revision(&self, revision: usize) -> Result<Dictionary> {
        PdfFile::trailer_in_revision(self, revision)
    }
}

/// Production adapter with independent, precision-checked parsing caches.
///
/// General PDF reading permits lossy f32 conversion for compatibility.
/// Modification analysis must reject that loss before comparing objects.
#[derive(Debug)]
pub struct PdfFileSource<'f> {
    file: PdfFile,
    _original: &'f PdfFile,
}

impl<'f> PdfFileSource<'f> {
    /// Reopen `file` for fail-closed decimal comparisons, retaining its
    /// decryption state, reading mode and decoding limits.
    pub fn new(file: &'f PdfFile) -> Result<Self> {
        Ok(Self {
            file: file.for_modification_analysis()?,
            _original: file,
        })
    }
}

impl RevisionSource for PdfFileSource<'_> {
    fn revision_count(&self) -> Result<usize> {
        Ok(self.file.total_revisions())
    }

    fn section(&self, revision: usize) -> Result<XrefSectionInfo> {
        self.file.xref_section(revision)
    }

    fn object(&self, id: ObjectId, revision: usize) -> Result<Option<Object>> {
        self.file.object_in_revision(id, revision)
    }

    fn trailer(&self, revision: usize) -> Result<Dictionary> {
        self.file.effective_trailer_in_revision(revision)
    }

    fn last_change(&self, id: ObjectId) -> Result<Option<usize>> {
        self.file.last_change(id)
    }

    fn introducing_revision(&self, id: ObjectId) -> Result<Option<usize>> {
        self.file.introducing_revision(id)
    }

    fn resolves_in(&self, id: ObjectId, revision: usize) -> Result<bool> {
        self.file.resolves_in(id, revision)
    }

    fn strict(&self) -> bool {
        self.file.strict()
    }
}

/// A [`RevisionSource`] derived from [`PdfRevisions`] primitives.
#[derive(Debug)]
pub struct DerivedSource<'f, P: ?Sized> {
    file: &'f P,
    count: usize,
    xref_stream: Vec<bool>,
    written: RefCell<HashMap<usize, BTreeSet<ObjectId>>>,
    sections: RefCell<HashMap<usize, XrefSectionInfo>>,
}

impl<'f, P: PdfRevisions + ?Sized> DerivedSource<'f, P> {
    /// Wrap `file`.
    pub fn new(file: &'f P) -> Result<Self> {
        let xref_stream = file.xref_stream_flags()?;
        Ok(Self {
            file,
            count: xref_stream.len(),
            xref_stream,
            written: RefCell::new(HashMap::new()),
            sections: RefCell::new(HashMap::new()),
        })
    }

    fn written(&self, revision: usize) -> Result<BTreeSet<ObjectId>> {
        if let Some(w) = self.written.borrow().get(&revision) {
            return Ok(w.clone());
        }
        let w: BTreeSet<ObjectId> = self
            .file
            .objects_written_in(revision)?
            .into_iter()
            .collect();
        self.written.borrow_mut().insert(revision, w.clone());
        Ok(w)
    }

    fn defined_in(&self, id: ObjectId, revision: usize) -> Result<bool> {
        Ok(self.written(revision)?.contains(&id)
            && self.file.object_in_revision(id, revision)?.is_some())
    }

    fn stream_type(obj: &Object) -> Option<&[u8]> {
        match obj {
            Object::Stream(s) => match s.dict.get(b"Type") {
                Ok(Object::Name(n)) => Some(n.as_slice()),
                _ => None,
            },
            _ => None,
        }
    }
}

impl<P: PdfRevisions + ?Sized> RevisionSource for DerivedSource<'_, P> {
    fn revision_count(&self) -> Result<usize> {
        Ok(self.count)
    }

    fn section(&self, revision: usize) -> Result<XrefSectionInfo> {
        if let Some(s) = self.sections.borrow().get(&revision) {
            return Ok(s.clone());
        }
        let trailer = self.file.trailer_in_revision(revision)?;
        let size = match trailer.get(b"Size") {
            Ok(Object::Integer(n)) => u32::try_from(*n)
                .map_err(|_| HankoError::Malformed("invalid /Size in trailer".into()))?,
            _ => return Err(HankoError::Malformed("missing /Size in trailer".into())),
        };
        let explicit_refs = self.written(revision)?;
        let mut freed = BTreeSet::new();
        let mut xref_streams = Vec::new();
        let mut object_streams_used = BTreeSet::new();
        for id in &explicit_refs {
            match self.file.object_in_revision(*id, revision)? {
                None => {
                    freed.insert(*id);
                }
                Some(obj) => match Self::stream_type(&obj) {
                    Some(b"XRef") => xref_streams.push(*id),
                    Some(b"ObjStm") => {
                        object_streams_used.insert(id.0);
                    }
                    _ => {}
                },
            }
        }
        // only one cross-reference stream can be the revision's own
        let stream_ref = match (self.xref_stream.get(revision), xref_streams.as_slice()) {
            (Some(true), [one]) => Some(*one),
            _ => None,
        };
        let info = XrefSectionInfo {
            size,
            stream_ref,
            hybrid_stream_ref: None,
            explicit_refs,
            freed,
            object_streams_used,
        };
        self.sections.borrow_mut().insert(revision, info.clone());
        Ok(info)
    }

    fn object(&self, id: ObjectId, revision: usize) -> Result<Option<Object>> {
        self.file.object_in_revision(id, revision)
    }

    fn trailer(&self, revision: usize) -> Result<Dictionary> {
        let mut merged = Dictionary::new();
        for r in 0..=revision {
            for (k, v) in self.file.trailer_in_revision(r)?.iter() {
                merged.set(k.clone(), v.clone());
            }
        }
        for k in NON_TRAILER_KEYS {
            merged.remove(k);
        }
        Ok(merged)
    }

    fn last_change(&self, id: ObjectId) -> Result<Option<usize>> {
        for r in (0..self.count).rev() {
            if self.written(r)?.contains(&id) {
                return Ok(Some(r));
            }
        }
        Ok(None)
    }

    fn introducing_revision(&self, id: ObjectId) -> Result<Option<usize>> {
        for r in 0..self.count {
            if self.defined_in(id, r)? {
                return Ok(Some(r));
            }
        }
        Ok(None)
    }

    fn resolves_in(&self, id: ObjectId, revision: usize) -> Result<bool> {
        Ok(self.file.object_in_revision(id, revision)?.is_some())
    }

    fn strict(&self) -> bool {
        self.file.strict()
    }
}
