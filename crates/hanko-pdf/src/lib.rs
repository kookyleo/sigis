// Interfaces derived from pyHanko `pdf_utils/` (reader, xref, writer,
// incremental_writer) and `sign/validation/pdf_embedded.py` / `dss.py`
// (MIT, see LICENSE-pyHanko).

//! PDF layer for signing and validation (`pyhanko.pdf_utils`).
//!
//! Built on [`lopdf`] (re-exported) for object parsing and serialization; this
//! crate adds what signatures need: revision history (incremental updates,
//! xref tables and streams), byte-exact signed ranges, signature and DSS
//! discovery, and an incremental writer.
//!
//! Owned by lane B (see `docs/hanko-lanes.md`). Lanes C, D and E code against
//! these types; changes go through the lead.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::collections::BTreeMap;
use std::sync::Arc;

use hanko_core::errors::{not_implemented, Result};
pub use lopdf;
use lopdf::{Dictionary, Object, ObjectId};

/// A PDF file with its full revision history (`PdfFileReader`).
#[derive(Clone, Debug)]
pub struct PdfFile {
    bytes: Arc<[u8]>,
}

impl PdfFile {
    /// Parse a PDF. Encrypted files are rejected until `crypt` is ported.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            bytes: bytes.into(),
        })
    }

    /// The file bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Revisions, oldest first (`HistoricalResolver` / `XRefCache`).
    pub fn revisions(&self) -> Result<Vec<RevisionInfo>> {
        not_implemented("hanko_pdf::PdfFile::revisions")
    }

    /// The object `id` as it existed in `revision` (`get_historical_resolver`).
    pub fn object_in_revision(&self, _id: ObjectId, _revision: usize) -> Result<Option<Object>> {
        not_implemented("hanko_pdf::PdfFile::object_in_revision")
    }

    /// Objects written in the xref section of `revision`
    /// (`explicit_refs_in_revision`).
    pub fn objects_written_in(&self, _revision: usize) -> Result<Vec<ObjectId>> {
        not_implemented("hanko_pdf::PdfFile::objects_written_in")
    }

    /// The trailer dictionary of `revision`.
    pub fn trailer_in_revision(&self, _revision: usize) -> Result<Dictionary> {
        not_implemented("hanko_pdf::PdfFile::trailer_in_revision")
    }

    /// Signature fields with a signature value, in file order
    /// (`EmbeddedPdfSignature` discovery).
    pub fn embedded_signatures(&self) -> Result<Vec<EmbeddedSignature>> {
        not_implemented("hanko_pdf::PdfFile::embedded_signatures")
    }

    /// The Document Security Store of the latest revision, if any.
    pub fn dss(&self) -> Result<Option<DocumentSecurityStore>> {
        not_implemented("hanko_pdf::PdfFile::dss")
    }
}

/// DocMDP permission level (`MDPPerm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MdpPerm {
    /// No changes allowed (P=1).
    NoChanges = 1,
    /// Form filling and signing (P=2).
    FillForms = 2,
    /// Form filling, signing and annotations (P=3).
    Annotate = 3,
}

/// One revision (incremental update) of the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionInfo {
    /// Index, 0 for the original document.
    pub index: usize,
    /// Byte length of the file up to and including this revision's `%%EOF`.
    pub end_offset: usize,
    /// Whether the revision uses an xref stream.
    pub xref_stream: bool,
}

/// Kind of an embedded signature dictionary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureKind {
    /// `/Type /Sig`.
    Signature,
    /// `/Type /DocTimeStamp`.
    DocTimeStamp,
}

/// A signature embedded in a PDF (`EmbeddedPdfSignature`, structural part).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedSignature {
    /// Fully qualified field name.
    pub field_name: String,
    /// Signature dictionary object.
    pub sig_object: ObjectId,
    /// Signature or document timestamp.
    pub kind: SignatureKind,
    /// `/SubFilter`.
    pub sub_filter: Option<String>,
    /// `/ByteRange` as four integers.
    pub byte_range: [u64; 4],
    /// `/Contents` with trailing padding removed (DER CMS).
    pub contents: Vec<u8>,
    /// Revision in which the signature was added.
    pub signed_revision: usize,
}

impl EmbeddedSignature {
    /// The bytes covered by the byte range.
    pub fn signed_data(&self, _file: &PdfFile) -> Result<Vec<u8>> {
        not_implemented("hanko_pdf::EmbeddedSignature::signed_data")
    }
}

/// Validation-related information of a DSS `/VRI` entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VriEntry {
    /// Certificates (DER).
    pub certs: Vec<Vec<u8>>,
    /// OCSP responses (DER).
    pub ocsps: Vec<Vec<u8>>,
    /// CRLs (DER).
    pub crls: Vec<Vec<u8>>,
}

/// The Document Security Store (`DocumentSecurityStore`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DocumentSecurityStore {
    /// `/Certs`, `/OCSPs` and `/CRLs` of the DSS.
    pub material: VriEntry,
    /// `/VRI`, keyed by the upper-case hex SHA-1 of the signature contents.
    pub vri: BTreeMap<String, VriEntry>,
}

/// Appends an incremental update to a PDF (`IncrementalPdfFileWriter`).
#[derive(Debug)]
pub struct IncrementalWriter {
    base: PdfFile,
    objects: BTreeMap<ObjectId, Object>,
}

impl IncrementalWriter {
    /// Start an update of `base`.
    pub fn new(base: PdfFile) -> Self {
        Self {
            base,
            objects: BTreeMap::new(),
        }
    }

    /// The document being updated.
    pub fn base(&self) -> &PdfFile {
        &self.base
    }

    /// Add or replace an object in the update.
    pub fn put(&mut self, id: ObjectId, object: Object) {
        self.objects.insert(id, object);
    }

    /// Allocate a fresh object number.
    pub fn allocate(&mut self) -> Result<ObjectId> {
        not_implemented("hanko_pdf::IncrementalWriter::allocate")
    }

    /// Serialize the original file followed by the update.
    pub fn write(&self) -> Result<Vec<u8>> {
        not_implemented("hanko_pdf::IncrementalWriter::write")
    }
}
