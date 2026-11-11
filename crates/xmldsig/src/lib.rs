//! XML Signature (W3C XMLDSig 1.0/1.1) with a security policy (layer L1,
//! `docs/crates.md`).
//!
//! Planned as a thin wrapper over the `bergshamra` crate (XML-DSig engine),
//! adding what a signature service must enforce on untrusted XML: a reference
//! whitelist, defences against signature wrapping (XSW), and limits on
//! transforms and document size. The backend decision and its acceptance
//! thresholds are in `docs/xml-lanes.md` (lane X1). Interface skeleton: the
//! functions return [`HankoError::NotImplemented`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{not_implemented, Result};

pub use sigis_pki_core::HankoError;

/// Which references a signature may contain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferencePolicy {
    /// Only same-document references (`URI=""` or `URI="#id"`).
    SameDocumentOnly,
    /// Same-document references plus these external URIs (exact match).
    Allowlist(Vec<String>),
}

/// Security policy applied before and during verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlDsigPolicy {
    /// Allowed references.
    pub references: ReferencePolicy,
    /// Maximum number of `ds:Reference` elements per signature.
    pub max_references: usize,
    /// Maximum number of transforms per reference.
    pub max_transforms: usize,
    /// Allowed transform and canonicalization algorithm URIs (XPath and XSLT
    /// are never allowed).
    pub allowed_transforms: Vec<String>,
    /// Maximum input size in bytes.
    pub max_document_bytes: usize,
    /// Maximum element nesting depth.
    pub max_depth: usize,
    /// Reject documents with a DTD (no entity expansion).
    pub forbid_dtd: bool,
}

impl Default for XmlDsigPolicy {
    fn default() -> Self {
        Self {
            references: ReferencePolicy::SameDocumentOnly,
            max_references: 32,
            max_transforms: 4,
            allowed_transforms: vec![
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature".into(),
                "http://www.w3.org/2001/10/xml-exc-c14n#".into(),
                "http://www.w3.org/2001/10/xml-exc-c14n#WithComments".into(),
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".into(),
                "http://www.w3.org/2006/12/xml-c14n11".into(),
            ],
            max_document_bytes: 64 * 1024 * 1024,
            max_depth: 256,
            forbid_dtd: true,
        }
    }
}

/// One verified reference. Callers must only consume the content it names
/// (XSW defence): `signed_element_path` locates the signed element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReference {
    /// The reference URI as written.
    pub uri: String,
    /// Digest algorithm URI.
    pub digest_algorithm: String,
    /// Element path of the signed node (empty for the whole document).
    pub signed_element_path: Vec<String>,
}

/// A cryptographically verified `ds:Signature`.
#[derive(Clone, Debug)]
pub struct VerifiedSignature {
    /// `Id` of the `ds:Signature` element, if any.
    pub id: Option<String>,
    /// Signature algorithm URI.
    pub signature_algorithm: String,
    /// The certificate whose key verified the signature, if taken from `ds:KeyInfo`.
    pub signer_cert: Option<Cert>,
    /// Verified references.
    pub references: Vec<VerifiedReference>,
}

/// Verify every `ds:Signature` in `xml` under `policy`. Trust in the signer
/// is not established here (that is the job of `sigis-xades`).
pub fn verify(_xml: &[u8], _policy: &XmlDsigPolicy) -> Result<Vec<VerifiedSignature>> {
    not_implemented("sigis_xmldsig::verify")
}
