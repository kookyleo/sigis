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
    qualified_policies: Option<Vec<QualifiedPolicy>>,
}

/// A certificate policy valid for the path, with the qualifiers the leaf
/// certificate attaches to it (`QualifiedPolicy`).
///
/// Simplification: policy mapping is not traced back, so the user-domain
/// and issuer-domain identifiers are both the valid policy of the leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualifiedPolicy {
    /// `user_domain_policy_id`.
    pub user_domain_policy_id: const_oid::ObjectIdentifier,
    /// `issuer_domain_policy_id`.
    pub issuer_domain_policy_id: const_oid::ObjectIdentifier,
    /// The policy qualifiers (`PolicyQualifierInfo`).
    pub qualifiers: Vec<x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo>,
}

impl QualifiedPolicy {
    /// The explicit text of the first user notice qualifier, if any.
    /// (`x509-cert`'s `DisplayText` lacks VisibleString and BMPString, so
    /// the notice is decoded here.)
    pub fn user_notice_text(&self) -> Option<String> {
        use hanko_core::asn1::tlv::{tag, Tlv};
        let q = self
            .qualifiers
            .iter()
            .find(|q| q.policy_qualifier_id == const_oid::db::rfc5280::ID_QT_UNOTICE)?;
        let der = der::Encode::to_der(q.qualifier.as_ref()?).ok()?;
        let notice = Tlv::parse_exact(&der).ok()?;
        let text = notice
            .children()
            .ok()?
            .into_iter()
            .find(|t| !t.is_universal(tag::SEQUENCE))?;
        match (text.class, text.number) {
            (hanko_core::asn1::tlv::Class::Universal, 12 | 22 | 26) => {
                String::from_utf8(text.value.to_vec()).ok()
            }
            (hanko_core::asn1::tlv::Class::Universal, 30) => {
                let units: Vec<u16> = text
                    .value
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                    .collect();
                String::from_utf16(&units).ok()
            }
            _ => None,
        }
    }

    /// The URI of the first CPS pointer qualifier, if any.
    pub fn cps_uri(&self) -> Option<String> {
        let q = self
            .qualifiers
            .iter()
            .find(|q| q.policy_qualifier_id == const_oid::db::rfc5280::ID_QT_CPS)?;
        let any = q.qualifier.as_ref()?;
        der::asn1::Ia5StringRef::new(any.value())
            .ok()
            .map(|s| s.as_str().to_owned())
    }
}

impl ValidationPath {
    /// Build a path.
    pub fn new(trust_anchor: TrustAnchor, intermediates: Vec<Cert>, leaf: Option<Cert>) -> Self {
        Self {
            trust_anchor,
            intermediates,
            leaf,
            qualified_policies: None,
        }
    }

    /// The policies valid for this path with their qualifiers
    /// (`qualified_policies`), once the path has been validated through
    /// [`crate::find_valid_path`] or [`crate::validate::validate_path_qualified`].
    pub fn qualified_policies(&self) -> Option<&[QualifiedPolicy]> {
        self.qualified_policies.as_deref()
    }

    pub(crate) fn set_qualified_policies(&mut self, policies: Vec<QualifiedPolicy>) {
        self.qualified_policies = Some(policies);
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

    /// The authority certificates of the path (anchor and intermediates;
    /// the leaf too if it is a CA in the middle of a longer chain is not
    /// included), in order from the anchor (`iter_authorities`).
    pub fn authorities(&self) -> Vec<&Cert> {
        let mut out = vec![self.trust_anchor.cert()];
        out.extend(self.intermediates.iter());
        out
    }

    /// The issuer of `cert` within this path (`find_issuing_authority`):
    /// the last authority whose subject is `cert`'s issuer and whose key
    /// identifier does not contradict `cert`'s authority key identifier.
    pub fn find_issuing_authority(&self, cert: &Cert) -> Option<&Cert> {
        let aki = crate::validate::authority_key_id(cert);
        self.authorities().into_iter().find(|a| {
            certval::compare_names(a.subject(), cert.issuer())
                && match (crate::validate::subject_key_id(a), &aki) {
                    (Some(k), Some(aki)) => &k == aki,
                    _ => true,
                }
        })
    }

    /// The path up to the issuer of `cert`, with `cert` appended as leaf
    /// (`truncate_to_issuer_and_append`); `None` if the issuer is not in
    /// the path.
    pub fn truncate_to_issuer_and_append(&self, cert: &Cert) -> Option<ValidationPath> {
        let anchor = self.trust_anchor.cert();
        let aki = crate::validate::authority_key_id(cert);
        let names_chain = |issuer: &Cert| certval::compare_names(issuer.subject(), cert.issuer());
        let keys_agree = |issuer: &Cert| match (crate::validate::subject_key_id(issuer), &aki) {
            (Some(k), Some(aki)) => &k == aki,
            _ => true,
        };
        if names_chain(anchor) && keys_agree(anchor) {
            let leaf = (cert != anchor).then(|| cert.clone());
            return Some(ValidationPath::new(
                self.trust_anchor.clone(),
                Vec::new(),
                leaf,
            ));
        }
        let index = self
            .intermediates
            .iter()
            .position(|c| names_chain(c) && keys_agree(c))?;
        Some(ValidationPath::new(
            self.trust_anchor.clone(),
            self.intermediates[..=index].to_vec(),
            Some(cert.clone()),
        ))
    }

    /// This path without its leaf; the last intermediate becomes the leaf
    /// (`copy_and_drop_leaf`). `None` without intermediates.
    pub fn copy_and_drop_leaf(&self) -> Option<ValidationPath> {
        let (leaf, rest) = self.intermediates.split_last()?;
        Some(ValidationPath::new(
            self.trust_anchor.clone(),
            rest.to_vec(),
            Some(leaf.clone()),
        ))
    }

    /// This path with `cert` appended as new leaf (`copy_and_append`).
    pub fn copy_and_append(&self, cert: Cert) -> ValidationPath {
        let mut intermediates = self.intermediates.clone();
        intermediates.extend(self.leaf.clone());
        ValidationPath::new(self.trust_anchor.clone(), intermediates, Some(cert))
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
