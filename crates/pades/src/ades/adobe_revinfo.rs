// Derived from pyHanko 0.38.1 validation/ades.py (MIT).
//! Adobe signed revocation archival attributes as local candidate evidence.
//!
//! Importing evidence does not authenticate its revocation assertions or
//! establish a proof of existence. Ordinary PKI validation still applies.

use der::{Any, Decode, Encode, Sequence};
use sigis_cms::{signed_data::find_unique_cms_attribute, SignedContent, SignedData, SignerInfo};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{
    algorithms::DigestAlgorithm,
    asn1::oids,
    cert::Cert,
    errors::{HankoError, Result},
};

// Adobe's explicit envelopes contain SEQUENCE OF full DER objects, rather
// than the BasicOCSPResponse payload alone. Unknown otherRevInfo is retained
// by the decoder but is not a supported source of validation evidence.
#[derive(Sequence)]
struct RevocationInfoArchival {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    crl: Option<Vec<Any>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    ocsp: Option<Vec<Any>>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    other_rev_info: Option<Vec<Any>>,
}

#[derive(Default)]
pub(crate) struct AdobeRevinfo {
    pub(crate) crls: Vec<Vec<u8>>,
    pub(crate) ocsps: Vec<Vec<u8>>,
}

/// Read the physically contained objects. A caller establishing timestamp
/// POE must first authenticate the enclosing bytes; this parser grants none.
pub(crate) fn archival_material(signer: &SignerInfo) -> Result<AdobeRevinfo> {
    let Ok(value) = find_unique_cms_attribute(
        signer.signed_attr_list(),
        oids::ADBE_REVOCATION_INFO_ARCHIVAL,
    ) else {
        // Like the reference, absent or ambiguous attributes supply no facts.
        return Ok(AdobeRevinfo::default());
    };
    let ria = RevocationInfoArchival::from_der(value)?;
    let encode = |values: Option<Vec<Any>>| -> Result<Vec<Vec<u8>>> {
        Ok(values
            .unwrap_or_default()
            .iter()
            .map(Encode::to_der)
            .collect::<der::Result<_>>()?)
    };
    Ok(AdobeRevinfo {
        crls: encode(ria.crl)?,
        ocsps: encode(ria.ocsp)?,
    })
}

/// Clone a complete caller context, adding unique signed Adobe CRLs/OCSPs.
///
/// Actual CMS signature and signed-content integrity are checked before
/// importing any attribute bytes. Missing, ambiguous, unsigned-only or invalid
/// signatures supply no additional evidence; the normal validator retains its
/// integrity failure. Malformed authenticated archival data returns an error.
///
/// This performs no network or path validation, adds no trust anchors or
/// certificates, and creates no POE. Imported objects remain untrusted
/// candidates subject to every caller policy and ordinary revocation check.
/// Call independently for the PKC and AC contexts to preserve separate roots.
pub fn with_signed_adobe_revinfo(
    context: &ValidationContext,
    content_info: &[u8],
    content: SignedContent<'_>,
) -> Result<ValidationContext> {
    let sd = SignedData::from_der(content_info)?;
    let [signer] = sd.signer_infos.as_slice() else {
        return Err(HankoError::Malformed(
            "exactly one CMS signer is required".into(),
        ));
    };
    if find_unique_cms_attribute(
        signer.signed_attr_list(),
        oids::ADBE_REVOCATION_INFO_ARCHIVAL,
    )
    .is_err()
    {
        return Ok(context.clone());
    }
    let certs = sigis_cms::validate::extract_certs_for_validation(&sd)?;
    let algorithm = DigestAlgorithm::from_oid(&signer.digest_algorithm.oid).ok_or(
        HankoError::NotImplemented("unsupported CMS digest algorithm"),
    )?;
    let digest = match content {
        SignedContent::Data(bytes) => algorithm.digest(bytes),
        SignedContent::Digest(provided, digest) => {
            if provided != algorithm {
                return Err(HankoError::Malformed(
                    "precomputed CMS digest algorithm mismatch".into(),
                ));
            }
            digest.to_vec()
        }
        SignedContent::Encapsulated => algorithm.digest(sd.econtent.as_deref().unwrap_or_default()),
    };
    let (intact, valid) = sigis_cms::validate::validate_sig_integrity(
        signer,
        &certs.signer_cert,
        &sd.econtent_type,
        &digest,
    )?;
    if !intact || !valid {
        return Ok(context.clone());
    }
    let evidence = archival_material(signer)?;
    Ok(context.with_revinfo(
        std::iter::empty::<&Cert>(),
        evidence.crls.iter().map(Vec::as_slice),
        evidence.ocsps.iter().map(Vec::as_slice),
    )?)
}
