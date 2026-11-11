//! Unified sign / verify / report API for the Sigis service (layer L5,
//! `docs/crates.md`).
//!
//! The service talks only to this crate. Formats are feature-gated: `pdf`
//! (default) uses the pyHanko port through `sigis-hanko`, `xml` uses
//! `sigis-xsig`. Results use the shared AdES model of `sigis-ades-model`.
//! Interface skeleton: dispatch returns [`HankoError::NotImplemented`] until
//! the facades are wired.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use sigis_ades_model::{AdesStatus, AdesSubIndic};
use sigis_pki_core::errors::{not_implemented, Result};

pub use sigis_pki_core::HankoError;

/// The PDF and CMS stack (feature `pdf`).
#[cfg(feature = "pdf")]
pub use sigis_hanko as pdf;
/// The XML stack (feature `xml`).
#[cfg(feature = "xml")]
pub use sigis_xsig as xml;

/// Document formats the service understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DocumentFormat {
    /// PDF (PAdES and legacy PDF signatures).
    Pdf,
    /// Detached or enveloping CMS (CAdES).
    Cms,
    /// XML with XMLDSig / XAdES signatures.
    Xml,
    /// ASiC-S / ASiC-E container.
    Asic,
    /// Office Open XML package.
    Ooxml,
    /// OpenDocument package.
    Odf,
}

/// Guess the format from the leading bytes (no parsing beyond that).
pub fn detect_format(bytes: &[u8]) -> Option<DocumentFormat> {
    let head = bytes.get(..1024).unwrap_or(bytes);
    if head.starts_with(b"%PDF-") {
        Some(DocumentFormat::Pdf)
    } else if head.starts_with(b"PK\x03\x04") {
        // ASiC, OOXML and ODF are ZIP; the mimetype entry decides later.
        None
    } else if head.first() == Some(&0x30) {
        Some(DocumentFormat::Cms)
    } else if head.trim_ascii_start().starts_with(b"<") {
        Some(DocumentFormat::Xml)
    } else {
        None
    }
}

/// Result for one signature or timestamp in a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureReport {
    /// Where the signature is (field name, XML `Id`, container entry).
    pub locator: String,
    /// Main indication.
    pub status: AdesStatus,
    /// Sub-indication when not passed.
    pub sub_indication: Option<AdesSubIndic>,
}

/// Verification report of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationReport {
    /// Detected format.
    pub format: DocumentFormat,
    /// One entry per signature or timestamp.
    pub signatures: Vec<SignatureReport>,
}

/// Verify all signatures in `document`.
pub fn verify(document: &[u8]) -> Result<VerificationReport> {
    let format = detect_format(document)
        .ok_or_else(|| HankoError::Unsupported("unrecognised document format".into()))?;
    let enabled = match format {
        DocumentFormat::Pdf | DocumentFormat::Cms => cfg!(feature = "pdf"),
        DocumentFormat::Xml
        | DocumentFormat::Asic
        | DocumentFormat::Ooxml
        | DocumentFormat::Odf => {
            cfg!(feature = "xml")
        }
    };
    if !enabled {
        return Err(HankoError::Unsupported(format!(
            "format {format:?} not enabled in this build"
        )));
    }
    not_implemented("sigis_sign::verify")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_formats() {
        assert_eq!(detect_format(b"%PDF-1.7\n"), Some(DocumentFormat::Pdf));
        assert_eq!(
            detect_format(b"  <?xml version=\"1.0\"?>"),
            Some(DocumentFormat::Xml)
        );
        assert_eq!(detect_format(&[0x30, 0x82]), Some(DocumentFormat::Cms));
        assert_eq!(detect_format(b"PK\x03\x04"), None);
        assert_eq!(detect_format(b""), None);
    }
}
