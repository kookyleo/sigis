// Derived from pyHanko `pdf_utils/metadata/model.py` (MIT, see LICENSE-pyHanko).

//! Metadata model (`pyhanko.pdf_utils.metadata.model`).

use crate::generic::PdfDate;

/// Producer string written by this library (`VENDOR`).
pub const VENDOR: &str = concat!("sigis-hanko ", env!("CARGO_PKG_VERSION"));

/// A string with an optional language (`StringWithLanguage` / `MetaString`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaString {
    /// The value.
    pub value: String,
    /// Language code.
    pub lang_code: Option<String>,
    /// Country code.
    pub country_code: Option<String>,
}

impl MetaString {
    /// A plain string.
    pub fn plain(s: impl Into<String>) -> Self {
        Self {
            value: s.into(),
            lang_code: None,
            country_code: None,
        }
    }
}

impl From<&str> for MetaString {
    fn from(s: &str) -> Self {
        Self::plain(s)
    }
}

/// A metadata date: the current time, or a fixed one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaDate {
    /// `'now'`.
    Now,
    /// A fixed date.
    At(PdfDate),
}

/// Document metadata (`DocumentMetadata`).
#[derive(Clone, Debug, PartialEq)]
pub struct DocumentMetadata {
    /// Title.
    pub title: Option<MetaString>,
    /// Author.
    pub author: Option<MetaString>,
    /// Subject.
    pub subject: Option<MetaString>,
    /// Keywords.
    pub keywords: Vec<String>,
    /// Creator application.
    pub creator: Option<MetaString>,
    /// Creation date.
    pub created: Option<MetaDate>,
    /// Modification date (default: now).
    pub last_modified: Option<MetaDate>,
    /// XMP-only metadata (`xmp_unmanaged`).
    pub xmp_unmanaged: bool,
}

impl Default for DocumentMetadata {
    fn default() -> Self {
        Self {
            title: None,
            author: None,
            subject: None,
            keywords: Vec::new(),
            creator: None,
            created: None,
            last_modified: Some(MetaDate::Now),
            xmp_unmanaged: false,
        }
    }
}

impl DocumentMetadata {
    /// Overlay `self` over `base` (`view_over`).
    pub fn view_over(&self, base: &DocumentMetadata) -> DocumentMetadata {
        let or = |a: &Option<MetaString>, b: &Option<MetaString>| {
            a.clone().filter(|s| !s.value.is_empty()).or_else(|| b.clone())
        };
        DocumentMetadata {
            title: or(&self.title, &base.title),
            author: or(&self.author, &base.author),
            subject: or(&self.subject, &base.subject),
            keywords: if self.keywords.is_empty() {
                base.keywords.clone()
            } else {
                self.keywords.clone()
            },
            creator: or(&self.creator, &base.creator),
            created: self.created.or(base.created),
            last_modified: self.last_modified,
            xmp_unmanaged: false,
        }
    }
}
