// Derived from pyhanko-certvalidator `path.py` (MIT, see LICENSE-pyHanko).

//! Certification paths.

use super::authority::{Cert, TrustAnchor};

/// A certification path: a trust anchor, intermediate CA certificates in
/// order from the anchor, and the certificate being validated.
///
/// The leaf is optional so that a trust anchor can be validated on its own,
/// as in pyhanko-certvalidator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationPath {
    trust_anchor: TrustAnchor,
    intermediates: Vec<Cert>,
    leaf: Option<Cert>,
}

impl ValidationPath {
    /// Build a path.
    pub fn new(trust_anchor: TrustAnchor, intermediates: Vec<Cert>, leaf: Option<Cert>) -> Self {
        Self {
            trust_anchor,
            intermediates,
            leaf,
        }
    }

    /// The trust anchor.
    pub fn trust_anchor(&self) -> &TrustAnchor {
        &self.trust_anchor
    }

    /// Intermediate CA certificates, starting with the one the anchor issued.
    pub fn intermediates(&self) -> &[Cert] {
        &self.intermediates
    }

    /// The certificate being validated.
    pub fn leaf(&self) -> Option<&Cert> {
        self.leaf.as_ref()
    }

    /// Number of certificates in the path, counting the trust anchor (as
    /// `len(ValidationPath)` in pyhanko-certvalidator). A leaf equal to the
    /// anchor certificate is not counted twice.
    pub fn len(&self) -> usize {
        let leaf = usize::from(
            self.leaf
                .as_ref()
                .is_some_and(|l| l != self.trust_anchor.cert()),
        );
        1 + self.intermediates.len() + leaf
    }

    /// Number of certificates below the trust anchor (`pkix_len`): 0 when
    /// the validated certificate is the anchor itself.
    pub fn pkix_len(&self) -> usize {
        self.issued_certs().len()
    }

    /// Every certificate of the path, from the anchor to the leaf
    /// (`iter_certs` / indexing in pyhanko-certvalidator).
    pub fn certs(&self) -> Vec<&Cert> {
        let mut out = vec![self.trust_anchor.cert()];
        out.extend(self.issued_certs().into_iter().map(|(c, _)| c));
        out
    }

    /// Paths always contain at least the trust anchor.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The certificates below the anchor, in order, each with its issuer.
    ///
    /// The issuer of the first certificate is the anchor certificate.
    pub(crate) fn issued_certs(&self) -> Vec<(&Cert, &Cert)> {
        let mut out = Vec::new();
        let mut issuer = self.trust_anchor.cert();
        for cert in self.intermediates.iter().chain(self.leaf.iter()) {
            if cert == self.trust_anchor.cert() {
                continue;
            }
            out.push((cert, issuer));
            issuer = cert;
        }
        out
    }

    /// Describe the certificate at `index` in [`Self::issued_certs`] as
    /// pyhanko-certvalidator does ("the end-entity certificate",
    /// "intermediate certificate 2").
    pub(crate) fn describe(&self, index: usize, total: usize) -> String {
        if index + 1 == total && self.leaf.is_some() {
            "the end-entity certificate".to_owned()
        } else {
            format!("intermediate certificate {}", index + 1)
        }
    }

    /// As [`Self::describe`], with a definite article for intermediates
    /// (`describe_cert(def_interm=True)`).
    pub(crate) fn describe_definite(&self, index: usize, total: usize) -> String {
        let d = self.describe(index, total);
        if d.starts_with("the ") {
            d
        } else {
            format!("the {d}")
        }
    }
}
