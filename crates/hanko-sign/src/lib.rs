// Interfaces derived from pyHanko `sign/signers/`, `sign/fields.py`,
// `sign/timestamps/`, `sign/pkcs11.py` (MIT, see LICENSE-pyHanko).

//! Signing: CMS signatures and PAdES B-B / B-T / B-LT / B-LTA PDF signatures,
//! document timestamps, DSS updates, signature fields, key providers
//! (`pyhanko.sign.signers`).
//!
//! Owned by lane D (see `docs/hanko-lanes.md`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::sync::Arc;

use hanko_certvalidator::ValidationContext;
use hanko_core::algorithms::DigestAlgorithm;
use hanko_core::cert::Cert;
use hanko_core::errors::{not_implemented, Result};
use hanko_core::sign::{KeySigner, TimeStamper};
use hanko_pdf::MdpPerm;
use spki::AlgorithmIdentifierOwned;

/// A software key held in memory (`SimpleSigner`).
#[derive(Debug)]
pub struct SimpleSigner {
    cert: Cert,
    chain: Vec<Cert>,
}

impl SimpleSigner {
    /// Load from a PKCS#8 private key (DER) and its certificate chain.
    pub fn from_pkcs8_der(_key_der: &[u8], _cert: Cert, _chain: Vec<Cert>) -> Result<Self> {
        not_implemented("hanko_sign::SimpleSigner::from_pkcs8_der")
    }

    /// Load from a PKCS#12 file.
    pub fn from_pkcs12(_data: &[u8], _passphrase: Option<&[u8]>) -> Result<Self> {
        not_implemented("hanko_sign::SimpleSigner::from_pkcs12")
    }
}

impl KeySigner for SimpleSigner {
    fn signing_cert(&self) -> &Cert {
        &self.cert
    }

    fn cert_chain(&self) -> &[Cert] {
        &self.chain
    }

    fn signature_algorithm(&self, _digest: DigestAlgorithm) -> Result<AlgorithmIdentifierOwned> {
        not_implemented("hanko_sign::SimpleSigner::signature_algorithm")
    }

    fn sign_raw(&self, _data: &[u8], _digest: DigestAlgorithm) -> Result<Vec<u8>> {
        not_implemented("hanko_sign::SimpleSigner::sign_raw")
    }
}

/// `/SubFilter` of a PDF signature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SubFilter {
    /// `adbe.pkcs7.detached`.
    Pkcs7Detached,
    /// `ETSI.CAdES.detached` (PAdES).
    #[default]
    Pades,
}

/// Signature metadata and options (`PdfSignatureMetadata`).
#[derive(Clone, Debug)]
pub struct PdfSignatureMetadata {
    /// Signature field name; created if absent.
    pub field_name: String,
    /// Digest algorithm.
    pub md_algorithm: DigestAlgorithm,
    /// `/SubFilter`.
    pub subfilter: SubFilter,
    /// `/Reason`.
    pub reason: Option<String>,
    /// `/Location`.
    pub location: Option<String>,
    /// `/Name`.
    pub name: Option<String>,
    /// `/ContactInfo`.
    pub contact_info: Option<String>,
    /// Certify the document with this DocMDP level.
    pub certify: Option<MdpPerm>,
    /// Embed revocation information (PAdES B-LT).
    pub embed_validation_info: bool,
    /// Add a document timestamp after the signature (PAdES B-LTA).
    pub use_pades_lta: bool,
    /// Context used to collect validation information.
    pub validation_context: Option<Arc<ValidationContext>>,
}

impl PdfSignatureMetadata {
    /// Defaults for a PAdES signature in `field_name`.
    pub fn new(field_name: impl Into<String>) -> Self {
        Self {
            field_name: field_name.into(),
            md_algorithm: DigestAlgorithm::Sha256,
            subfilter: SubFilter::Pades,
            reason: None,
            location: None,
            name: None,
            contact_info: None,
            certify: None,
            embed_validation_info: false,
            use_pades_lta: false,
            validation_context: None,
        }
    }
}

/// Signs PDF documents (`PdfSigner`).
#[derive(Debug)]
pub struct PdfSigner {
    /// Signature options.
    pub metadata: PdfSignatureMetadata,
    /// The key.
    pub signer: Arc<dyn KeySigner>,
    /// TSA for signature timestamps (B-T) and document timestamps (B-LTA).
    pub timestamper: Option<Arc<dyn TimeStamper>>,
}

impl PdfSigner {
    /// Sign `pdf` and return the signed file (`sign_pdf`).
    pub fn sign_pdf(&self, _pdf: &[u8]) -> Result<Vec<u8>> {
        not_implemented("hanko_sign::PdfSigner::sign_pdf")
    }
}

/// Produce a CMS `SignedData` over `data` (`Signer.sign_general_data`).
pub fn sign_general_data(
    _data: &[u8],
    _signer: &dyn KeySigner,
    _digest: DigestAlgorithm,
    _detached: bool,
    _timestamper: Option<&dyn TimeStamper>,
) -> Result<Vec<u8>> {
    not_implemented("hanko_sign::sign_general_data")
}

/// Append a document timestamp (`PdfTimeStamper.timestamp_pdf`).
pub fn add_document_timestamp(
    _pdf: &[u8],
    _timestamper: &dyn TimeStamper,
    _field_name: &str,
) -> Result<Vec<u8>> {
    not_implemented("hanko_sign::add_document_timestamp")
}

/// Add validation information for existing signatures to the DSS and
/// optionally renew with a document timestamp (`PdfTimeStamper.update_archival_timestamp_chain`,
/// `add_validation_info`).
pub fn add_validation_info(
    _pdf: &[u8],
    _ctx: &ValidationContext,
    _timestamper: Option<&dyn TimeStamper>,
) -> Result<Vec<u8>> {
    not_implemented("hanko_sign::add_validation_info")
}

/// PKCS#11 key access via `cryptoki` (`pyhanko.sign.pkcs11`).
pub mod pkcs11 {
    use hanko_core::errors::{not_implemented, Result};

    /// How to find a key on a token.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Pkcs11Config {
        /// Path of the PKCS#11 module.
        pub module_path: String,
        /// Token label.
        pub token_label: Option<String>,
        /// Key label.
        pub key_label: Option<String>,
        /// Key id.
        pub key_id: Option<Vec<u8>>,
    }

    /// Open a PKCS#11 signer; returns a [`hanko_core::sign::KeySigner`].
    pub fn open(
        _config: &Pkcs11Config,
        _pin: Option<&str>,
    ) -> Result<std::sync::Arc<dyn hanko_core::sign::KeySigner>> {
        not_implemented("hanko_sign::pkcs11::open")
    }
}
