// Derived from pyHanko `pdf_utils/crypt/_saslprep.py` (MIT, see LICENSE-pyHanko),
// itself based on PyMongo's RFC 4013 implementation (Apache-2.0).

//! RFC 4013 SASLprep for PDF 2.0 passwords (`saslprep`).
//!
//! Delegates to the `stringprep` crate, which implements the same profile
//! (mapping, NFKC, prohibited output, bidirectional checks, unassigned code
//! points prohibited). pyHanko normalises with the Unicode 3.2 tables that
//! RFC 3454 references; `stringprep` normalises with the current Unicode
//! version, which only differs for code points unassigned in Unicode 3.2,
//! and those are rejected by both.

use crate::error::{PdfError, PdfResult};

/// SASLprep a password (`saslprep(data)`), as a `ValueError` on failure.
pub(crate) fn saslprep(data: &str) -> PdfResult<String> {
    stringprep::saslprep(data)
        .map(|s| s.into_owned())
        .map_err(|e| PdfError::Value(format!("SASLprep: {e}")))
}

#[cfg(test)]
mod tests {
    use super::saslprep;

    #[test]
    fn rfc4013_examples() {
        assert_eq!(saslprep("I\u{00AD}X").unwrap(), "IX");
        assert_eq!(saslprep("user").unwrap(), "user");
        assert_eq!(saslprep("USER").unwrap(), "USER");
        assert_eq!(saslprep("\u{00AA}").unwrap(), "a");
        assert_eq!(saslprep("\u{2168}").unwrap(), "IX");
        assert!(saslprep("\u{0007}").is_err());
        assert!(saslprep("\u{0627}\u{0031}").is_err());
    }
}
