// Derived from pyHanko `sign/validation/generic_cms.py`, `sign/validation/status.py`
// and `sign/general.py` (MIT, see LICENSE-pyHanko).

//! CMS `SignedData` and RFC 3161 timestamp validation
//! (`pyhanko.sign.validation.generic_cms`).
//!
//! Owned by lane A (see `docs/hanko-lanes.md`). The status types are consumed
//! by lane E (PDF and AdES validation).
//!
//! | pyHanko | module |
//! | --- | --- |
//! | `sign/validation/generic_cms.py` | [`validate`] |
//! | `sign/validation/status.py` (CMS part) | [`status`] |
//! | `sign/validation/settings.py` (`KeyUsageConstraints`) | [`key_usage`] |
//! | `sign/validation/utils.py` | [`policy`] |
//! | `sign/validation/errors.py`, `sign/general.py` errors | [`errors`] |
//! | `sign/general.py` (attributes, certificates) | [`signed_data`] |
//! | `sign/ades/report.py` (indications) | [`ades`] |
//! | signer attributes, ACs | [`attributes`] |

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod ades;
pub mod attributes;
pub mod errors;
/// Key usage constraints, shared with lane E ([`sigis_pki_core::key_usage`]).
pub use sigis_pki_core::key_usage;
pub mod policy;
pub mod signed_data;
pub mod status;
pub mod validate;

use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::errors::Result;

pub use ades::{AdesStatus, AdesSubIndic};
pub use errors::{CmsError, CmsResult};
pub use sigis_pki_core::key_usage::KeyUsageConstraints;
pub use signed_data::{SignedData, SignerInfo};
pub use status::{
    RevocationDetails, SignatureStatus, StandardCmsSignatureStatus, TimestampSignatureStatus,
    TrustProblem,
};
pub use validate::{CmsValidationOptions, ContentDigester, DataDigester, PrecomputedDigest};

/// What the signature covers.
#[derive(Clone, Copy, Debug)]
pub enum SignedContent<'a> {
    /// The signed data itself (detached signatures, PDF ByteRange content).
    Data(&'a [u8]),
    /// A precomputed digest of the signed data, with its algorithm.
    Digest(DigestAlgorithm, &'a [u8]),
    /// The content is encapsulated in the `SignedData`.
    Encapsulated,
}

/// [`validate_cms_signature`] with options and the detailed error type.
///
/// This runs `async_validate_detached_cms`: timing information (signing
/// time, signature and content timestamps), integrity, trust, and signer
/// attributes.
pub fn validate_cms_signature_with(
    signed_data: &[u8],
    content: SignedContent<'_>,
    ctx: &ValidationContext,
    options: &CmsValidationOptions<'_>,
) -> CmsResult<StandardCmsSignatureStatus> {
    let sd = SignedData::from_der(signed_data)?;
    match content {
        SignedContent::Data(data) => validate::validate_detached_cms_with(
            &sd,
            &DataDigester::new(data),
            false,
            Some(ctx),
            options,
        ),
        SignedContent::Digest(algorithm, digest) => validate::validate_detached_cms_with(
            &sd,
            &PrecomputedDigest {
                algorithm,
                digest: digest.to_vec(),
            },
            false,
            Some(ctx),
            options,
        ),
        SignedContent::Encapsulated => {
            let econtent = sd.econtent.clone().unwrap_or_default();
            validate::validate_detached_cms_with(
                &sd,
                &DataDigester::new(&econtent),
                true,
                Some(ctx),
                options,
            )
        }
    }
}

/// Validate a CMS `SignedData` (DER `ContentInfo`) over `content`
/// (`async_validate_cms_signature` + timestamp handling).
pub fn validate_cms_signature(
    signed_data: &[u8],
    content: SignedContent<'_>,
    ctx: &ValidationContext,
) -> Result<StandardCmsSignatureStatus> {
    Ok(validate_cms_signature_with(
        signed_data,
        content,
        ctx,
        &CmsValidationOptions::default(),
    )?)
}

/// Validate a `TimeStampToken` whose message imprint must equal
/// `expected_imprint` (`validate_tst_signed_data`).
pub fn validate_timestamp_token(
    token: &[u8],
    expected_imprint: &[u8],
    ctx: &ValidationContext,
) -> Result<TimestampSignatureStatus> {
    Ok(validate::validate_timestamp_token_with(
        token,
        expected_imprint,
        Some(ctx),
        None,
    )?)
}

/// Validate a detached CMS signature over `data` (`validate_detached_cms`).
pub fn validate_detached_cms(
    data: &[u8],
    signed_data: &[u8],
    ctx: &ValidationContext,
) -> Result<StandardCmsSignatureStatus> {
    validate_cms_signature(signed_data, SignedContent::Data(data), ctx)
}
