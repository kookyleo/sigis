// Derived from pyhanko-certvalidator `registry.py` (`SimpleCertificateStore`,
// `CertificateRegistry.find_potential_issuers`, `LayeredCertificateStore`)
// (MIT, see LICENSE-pyHanko).

//! Certificate stores with the lookups pyhanko-certvalidator offers.

use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::AuthorityKeyIdentifier;
use x509_cert::name::Name;

use hanko_core::algorithms::DigestAlgorithm;

use crate::authority::Cert;

/// SHA-1 of the subject public key bits (`public_key.sha1`).
pub fn key_hash(cert: &Cert) -> Vec<u8> {
    DigestAlgorithm::Sha1.digest(cert.public_key().subject_public_key.raw_bytes())
}

/// The subject key identifier (`key_identifier`).
pub fn key_identifier(cert: &Cert) -> Option<Vec<u8>> {
    crate::validate::subject_key_id(cert)
}

fn normalize_int(b: &[u8]) -> &[u8] {
    let mut b = b;
    while b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
        b = &b[1..];
    }
    b
}

/// Issuer name and serial number, the key of a store (`issuer_serial`).
fn same_issuer_serial(a: &Cert, b: &Cert) -> bool {
    certval::compare_names(a.issuer(), b.issuer())
        && normalize_int(a.serial_bytes()) == normalize_int(b.serial_bytes())
}

/// `authority_issuer_serial`: issuer and serial of the issuer's own
/// certificate, from the authority key identifier extension.
pub fn authority_issuer_serial(cert: &Cert) -> Option<(Name, Vec<u8>)> {
    let (_, aki) = cert.extension::<AuthorityKeyIdentifier>().ok().flatten()?;
    let names = aki.authority_cert_issuer?;
    let serial = aki.authority_cert_serial_number?;
    let name = names.into_iter().find_map(|g| match g {
        GeneralName::DirectoryName(n) => Some(n),
        _ => None,
    })?;
    Some((name, serial.as_bytes().to_vec()))
}

/// A set of certificates indexed like `SimpleCertificateStore`.
#[derive(Clone, Debug, Default)]
pub struct CertificateRegistry {
    certs: Vec<Cert>,
}

impl CertificateRegistry {
    /// A registry holding `certs` (duplicates by issuer and serial dropped).
    pub fn build(certs: impl IntoIterator<Item = Cert>) -> Self {
        let mut r = Self::default();
        for c in certs {
            r.register(c);
        }
        r
    }

    /// Add a certificate; `false` if one with the same issuer and serial
    /// number is already present.
    pub fn register(&mut self, cert: Cert) -> bool {
        if self.certs.iter().any(|c| same_issuer_serial(c, &cert)) {
            return false;
        }
        self.certs.push(cert);
        true
    }

    /// Every certificate.
    pub fn certs(&self) -> &[Cert] {
        &self.certs
    }

    /// `retrieve_by_name`.
    pub fn retrieve_by_name(&self, name: &Name) -> Vec<Cert> {
        self.certs
            .iter()
            .filter(|c| certval::compare_names(c.subject(), name))
            .cloned()
            .collect()
    }

    /// `retrieve_by_key_hash`: by SHA-1 of the public key.
    pub fn retrieve_by_key_hash(&self, hash: &[u8]) -> Option<Cert> {
        self.certs.iter().find(|c| key_hash(c) == hash).cloned()
    }

    /// `retrieve_by_key_identifier`: by subject key identifier, or by key
    /// hash for certificates without one.
    pub fn retrieve_by_key_identifier(&self, ki: &[u8]) -> Option<Cert> {
        self.certs
            .iter()
            .find(|c| key_identifier(c).unwrap_or_else(|| key_hash(c)) == ki)
            .cloned()
    }

    /// `retrieve_by_issuer_serial`.
    pub fn retrieve_by_issuer_serial(&self, issuer: &Name, serial: &[u8]) -> Option<Cert> {
        self.certs
            .iter()
            .find(|c| {
                certval::compare_names(c.issuer(), issuer)
                    && normalize_int(c.serial_bytes()) == normalize_int(serial)
            })
            .cloned()
    }

    /// `find_potential_issuers`: certificates named as `cert`'s issuer
    /// whose key identifier and issuer/serial do not contradict `cert`'s
    /// authority key identifier.
    pub fn find_potential_issuers(&self, cert: &Cert) -> Vec<Cert> {
        self.certs
            .iter()
            .filter(|issuer| potential_issuer(issuer, cert))
            .cloned()
            .collect()
    }
}

/// The filter of `CertificateRegistry.find_potential_issuers`.
pub(crate) fn potential_issuer(issuer: &Cert, cert: &Cert) -> bool {
    if !certval::compare_names(issuer.subject(), cert.issuer()) {
        return false;
    }
    if let (Some(aki), Some(ski)) = (
        crate::validate::authority_key_id(cert),
        key_identifier(issuer),
    ) {
        if aki != ski {
            return false;
        }
    }
    if let Some((name, serial)) = authority_issuer_serial(cert) {
        if !(certval::compare_names(&name, issuer.issuer())
            && normalize_int(&serial) == normalize_int(issuer.serial_bytes()))
        {
            return false;
        }
    }
    true
}

/// Stores consulted in order (`LayeredCertificateStore`).
#[derive(Clone, Debug, Default)]
pub struct LayeredCertificateStore {
    /// The stores, highest priority first.
    pub stores: Vec<CertificateRegistry>,
}

impl LayeredCertificateStore {
    /// `retrieve_by_key_hash`.
    pub fn retrieve_by_key_hash(&self, hash: &[u8]) -> Option<Cert> {
        self.stores
            .iter()
            .find_map(|s| s.retrieve_by_key_hash(hash))
    }

    /// `retrieve_by_key_identifier`.
    pub fn retrieve_by_key_identifier(&self, ki: &[u8]) -> Option<Cert> {
        self.stores
            .iter()
            .find_map(|s| s.retrieve_by_key_identifier(ki))
    }

    /// `retrieve_by_issuer_serial`.
    pub fn retrieve_by_issuer_serial(&self, issuer: &Name, serial: &[u8]) -> Option<Cert> {
        self.stores
            .iter()
            .find_map(|s| s.retrieve_by_issuer_serial(issuer, serial))
    }
}
