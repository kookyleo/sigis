//! Interfaces for producing signatures and timestamps.
//!
//! [`KeySigner`] corresponds to pyHanko's `Signer.async_sign_raw` contract: a
//! key holder (software key, PKCS#11 token, CSC remote service) that signs
//! raw data. [`TimeStamper`] corresponds to `TimeStamper`: it returns an RFC
//! 3161 `TimeStampToken`.

use spki::AlgorithmIdentifierOwned;

use crate::algorithms::DigestAlgorithm;
use crate::cert::Cert;
use crate::errors::Result;

/// A signing key with its certificate (`Signer` in pyHanko).
pub trait KeySigner: Send + Sync + std::fmt::Debug {
    /// The signer certificate.
    fn signing_cert(&self) -> &Cert;

    /// Other certificates to embed (intermediates, optionally the root).
    fn cert_chain(&self) -> &[Cert];

    /// The `signatureAlgorithm` to put in the `SignerInfo` for `digest`.
    fn signature_algorithm(&self, digest: DigestAlgorithm) -> Result<AlgorithmIdentifierOwned>;

    /// Sign `data` (not prehashed) with `digest`; returns the raw signature
    /// value (DER `ECDSA-Sig-Value` for ECDSA).
    fn sign_raw(&self, data: &[u8], digest: DigestAlgorithm) -> Result<Vec<u8>>;
}

/// An RFC 3161 time-stamping client (`TimeStamper`).
pub trait TimeStamper: Send + Sync + std::fmt::Debug {
    /// Request a timestamp over `message_digest` computed with `digest`;
    /// returns the DER-encoded `TimeStampToken` (a CMS `ContentInfo`).
    fn timestamp(&self, message_digest: &[u8], digest: DigestAlgorithm) -> Result<Vec<u8>>;
}
