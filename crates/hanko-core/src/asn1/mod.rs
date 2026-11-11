//! ASN.1 definitions that the RustCrypto `cms` and `x509-cert` crates lack.
//!
//! This corresponds to the ASN.1 extensions that pyHanko registers on top of
//! `asn1crypto` (for example in `pyhanko/sign/ades/asn1_util.py`) and to the
//! ESS types that `asn1crypto.cms` provides.
//!
//! - [`ess`]: `SigningCertificate` / `SigningCertificateV2` (RFC 2634, RFC 5035).
//! - [`sig_policy`]: `SignaturePolicyIdentifier` (RFC 5126 / ETSI EN 319 122-1).
//! - [`commitment`]: `CommitmentTypeIndication` (RFC 5126 / ETSI EN 319 122-1).
//! - [`oids`]: object identifiers.

/// Re-exports of the RustCrypto format crates at the exact (pinned) versions
/// that `certval` uses, so downstream code shares their types.
pub use {cms, x509_cert, x509_ocsp, x509_tsp};

pub mod commitment;
pub mod ess;
pub mod oids;
pub mod sig_policy;

use spki::AlgorithmIdentifierOwned;

/// `OtherHashAlgAndValue` (RFC 5126): a digest algorithm and a digest value.
#[derive(Clone, Debug, Eq, PartialEq, der::Sequence)]
pub struct OtherHashAlgAndValue {
    /// Digest algorithm.
    pub hash_algorithm: AlgorithmIdentifierOwned,
    /// Digest value.
    pub hash_value: der::asn1::OctetString,
}
