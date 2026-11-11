// Derived from pyHanko `pdf_utils/misc.py` (exception classes)
// (MIT, see LICENSE-pyHanko).

//! Errors of the PDF layer.
//!
//! The variants mirror pyHanko's exception hierarchy so that ported tests can
//! assert on the same classes:
//!
//! | pyHanko                  | `PdfError`                         |
//! |--------------------------|------------------------------------|
//! | `PdfError`               | [`PdfError::Generic`]              |
//! | `PdfReadError`           | [`PdfError::Read`]                 |
//! | `PdfKeyNotAvailableError`| [`PdfError::KeyNotAvailable`]      |
//! | `PdfStrictReadError`     | [`PdfError::StrictRead`]           |
//! | `IndirectObjectExpected` | [`PdfError::IndirectObjectExpected`] |
//! | `PdfWriteError`          | [`PdfError::Write`]                |
//! | `PdfStreamError`         | [`PdfError::Stream`]               |
//! | `PdfDecodeLimitError`    | [`PdfError::DecodeLimit`]          |
//! | `NotImplementedError`    | [`PdfError::NotImplemented`]       |
//! | `ValueError`/`TypeError` | [`PdfError::Value`]                |
//! | `FormFillingError`       | [`PdfError::FormFilling`]          |
//!
//! Use [`PdfError::is_read_error`] and friends for `isinstance` checks.

use hanko_core::errors::HankoError;

/// Error of the PDF layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PdfError {
    /// Generic PDF error (`PdfError`).
    #[error("{0}")]
    Generic(String),
    /// Error while reading a PDF (`PdfReadError`).
    #[error("{0}")]
    Read(String),
    /// No decryption key is available (`PdfKeyNotAvailableError`, a
    /// `PdfReadError`).
    #[error("{0}")]
    KeyNotAvailable(String),
    /// Error that only occurs in strict mode (`PdfStrictReadError`).
    #[error("{0}")]
    StrictRead(String),
    /// An indirect object was expected (`IndirectObjectExpected`).
    #[error("{0}")]
    IndirectObjectExpected(String),
    /// Error while writing a PDF (`PdfWriteError`).
    #[error("{0}")]
    Write(String),
    /// Error while reading or decoding stream data (`PdfStreamError`).
    #[error("{0}")]
    Stream(String),
    /// A decoding limit was exceeded (`PdfDecodeLimitError`).
    #[error("{0}")]
    DecodeLimit(String),
    /// Unsupported feature (`NotImplementedError`).
    #[error("{0}")]
    NotImplemented(String),
    /// Invalid value or type (`ValueError` / `TypeError` / `KeyError`).
    #[error("{0}")]
    Value(String),
    /// Error while filling in a form (`FormFillingError`).
    #[error("{0}")]
    FormFilling(String),
}

impl PdfError {
    /// `isinstance(e, PdfReadError)`.
    pub fn is_read_error(&self) -> bool {
        matches!(
            self,
            Self::Read(_)
                | Self::KeyNotAvailable(_)
                | Self::StrictRead(_)
                | Self::IndirectObjectExpected(_)
                | Self::Stream(_)
                | Self::DecodeLimit(_)
        )
    }

    /// `isinstance(e, PdfStrictReadError)`.
    pub fn is_strict_read_error(&self) -> bool {
        matches!(self, Self::StrictRead(_))
    }

    /// `isinstance(e, PdfStreamError)`.
    pub fn is_stream_error(&self) -> bool {
        matches!(self, Self::Stream(_) | Self::DecodeLimit(_))
    }

    /// `isinstance(e, PdfError)` (all PDF errors, but not `ValueError` & co).
    pub fn is_pdf_error(&self) -> bool {
        !matches!(self, Self::NotImplemented(_) | Self::Value(_) | Self::FormFilling(_))
    }

    /// The message.
    pub fn message(&self) -> &str {
        match self {
            Self::Generic(m)
            | Self::Read(m)
            | Self::KeyNotAvailable(m)
            | Self::StrictRead(m)
            | Self::IndirectObjectExpected(m)
            | Self::Write(m)
            | Self::Stream(m)
            | Self::DecodeLimit(m)
            | Self::NotImplemented(m)
            | Self::Value(m)
            | Self::FormFilling(m) => m,
        }
    }

    /// The pyHanko class name of this error.
    pub fn class_name(&self) -> &'static str {
        match self {
            Self::Generic(_) => "PdfError",
            Self::Read(_) => "PdfReadError",
            Self::KeyNotAvailable(_) => "PdfKeyNotAvailableError",
            Self::StrictRead(_) => "PdfStrictReadError",
            Self::IndirectObjectExpected(_) => "IndirectObjectExpected",
            Self::Write(_) => "PdfWriteError",
            Self::Stream(_) => "PdfStreamError",
            Self::DecodeLimit(_) => "PdfDecodeLimitError",
            Self::NotImplemented(_) => "NotImplementedError",
            Self::Value(_) => "ValueError",
            Self::FormFilling(_) => "FormFillingError",
        }
    }

    pub(crate) fn read(msg: impl Into<String>) -> Self {
        Self::Read(msg.into())
    }

    pub(crate) fn strict(msg: impl Into<String>) -> Self {
        Self::StrictRead(msg.into())
    }

    pub(crate) fn stream(msg: impl Into<String>) -> Self {
        Self::Stream(msg.into())
    }

    pub(crate) fn write(msg: impl Into<String>) -> Self {
        Self::Write(msg.into())
    }

    pub(crate) fn value(msg: impl Into<String>) -> Self {
        Self::Value(msg.into())
    }
}

impl From<PdfError> for HankoError {
    fn from(e: PdfError) -> Self {
        match e {
            PdfError::NotImplemented(m) => HankoError::Unsupported(m),
            other => HankoError::Malformed(format!("{}: {}", other.class_name(), other.message())),
        }
    }
}

/// Result type of the PDF layer.
pub type PdfResult<T> = Result<T, PdfError>;
