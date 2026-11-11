// Derived from pyHanko `sign/diff_analysis/policy_api.py` (`SuspiciousModification`)
// and `pdf_utils/misc.py` (`PdfReadError`) (MIT, see LICENSE-pyHanko).

//! Error type of the rule engine.

use hanko_core::errors::HankoError;

/// Error raised while reviewing a revision.
///
/// pyHanko distinguishes a [`SuspiciousModification`](DiffError::Suspicious)
/// (the review completed and rejected the change) from a `PdfReadError`
/// (the document could not be read). `review_file` turns the first into
/// [`crate::DiffOutcome::Suspicious`] and propagates the second as an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffError {
    /// `SuspiciousModification`: a change that the rules cannot explain.
    Suspicious(String),
    /// `PdfReadError` (including `PdfStrictReadError`): unreadable structure.
    Read(String),
    /// Error reported by the revision source (for example
    /// [`HankoError::NotImplemented`]).
    Source(HankoError),
}

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiffError::Suspicious(m) => write!(f, "suspicious modification: {m}"),
            DiffError::Read(m) => write!(f, "PDF read error: {m}"),
            DiffError::Source(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DiffError {}

impl From<HankoError> for DiffError {
    fn from(e: HankoError) -> Self {
        DiffError::Source(e)
    }
}

impl From<DiffError> for HankoError {
    fn from(e: DiffError) -> Self {
        match e {
            DiffError::Suspicious(m) => {
                HankoError::Malformed(format!("suspicious modification: {m}"))
            }
            DiffError::Read(m) => HankoError::Malformed(m),
            DiffError::Source(e) => e,
        }
    }
}

/// Result type of the rule engine.
pub type DiffResultT<T> = std::result::Result<T, DiffError>;

pub(crate) fn suspicious<T>(msg: impl Into<String>) -> DiffResultT<T> {
    Err(DiffError::Suspicious(msg.into()))
}

pub(crate) fn read_error<T>(msg: impl Into<String>) -> DiffResultT<T> {
    Err(DiffError::Read(msg.into()))
}
