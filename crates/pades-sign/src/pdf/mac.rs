// Derived from pyHanko `sign/signers/pdf_signer.py` (`PdfMacAttrProvider`,
// `PdfMacAttrProviderSpec`, `add_mac_to_external_cms`) (MIT, see LICENSE-pyHanko).

//! Per-document ISO 32004 MAC attributes and signing-session ownership.
//!
//! The reusable signer stores only [`PdfMacSessions`]. Encryption-derived
//! key material belongs to the returned [`PdfMacSigningSession`], which must
//! remain alive from size estimation until the CMS container is embedded.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{EncapsulatedContentInfo, SignerInfos};
use const_oid::ObjectIdentifier;
use der::asn1::{OctetString, SetOfVec};
use der::{Any, Decode, Encode};
use sigis_pdf::crypt::pdfmac::{
    digest_name, digest_oid, md_hash, PdfMacTokenHandler, ALLOWED_MD_ALGS,
};
use sigis_pdf::crypt::SecurityHandler;
use sigis_pki_core::errors::{HankoError, Result};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;

/// Unsigned attribute containing a PDF MAC `ContentInfo`.
pub const PDF_MAC_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.0.32004.1.2");

const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

fn signing_error(message: impl Into<String>) -> HankoError {
    HankoError::Signing(message.into())
}

fn pdf_error(error: sigis_pdf::PdfError) -> HankoError {
    signing_error(format!("PDF MAC generation failed: {error}"))
}

fn concurrent_session() -> HankoError {
    signing_error(
        "Other PDF MAC attribute provider found. This may be the result of signer instances \
         being shared across multiple documents. This workflow is not supported for encrypted \
         documents. Either turn off MAC generation, or use separate signer instances for \
         different documents.",
    )
}

/// Shared activity state of a reusable PDF signer, without document keys.
///
/// Clones share the same lease. Documents without MAC support do not acquire
/// a lease and can continue to use a signer concurrently.
#[derive(Clone, Debug, Default)]
pub struct PdfMacSessions {
    active: Arc<AtomicBool>,
}

impl PdfMacSessions {
    /// Start a MAC signing session with an authenticated security handler.
    ///
    /// Returns `None` if MAC generation is disabled. Overlapping MAC sessions
    /// on this signer fail with pyHanko's provider-conflict signing error.
    /// Failed initialization always releases the lease.
    pub fn begin(
        &self,
        security_handler: &SecurityHandler,
        md_algorithm: &str,
    ) -> Result<Option<PdfMacSigningSession>> {
        if !security_handler.pdf_mac_enabled() {
            return Ok(None);
        }
        if !ALLOWED_MD_ALGS.contains(&md_algorithm) {
            return Err(signing_error(format!(
                "Digest algorithm {md_algorithm} is not allowed for PDF MAC tokens"
            )));
        }
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| concurrent_session())?;
        let lease = MacLease(self.active.clone());
        let salt = security_handler.get_kdf_salt().map_err(pdf_error)?;
        let mut key = security_handler
            .get_file_encryption_key()
            .map_err(pdf_error)?;
        let handler = PdfMacTokenHandler::from_key_mat(
            &key,
            &salt,
            md_algorithm,
            security_handler.mac_token_handler(),
        );
        key.fill(0);
        let handler = handler.map_err(pdf_error)?;
        Ok(Some(PdfMacSigningSession {
            state: Arc::new(SessionState {
                handler,
                _lease: lease,
            }),
        }))
    }
}

struct MacLease(Arc<AtomicBool>);

impl Drop for MacLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct SessionState {
    handler: PdfMacTokenHandler,
    _lease: MacLease,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.handler.mac_kek.fill(0);
    }
}

/// Document-specific MAC provider and its exclusive signer lease.
///
/// Clones refer to the same document session. The final clone's destruction
/// discards its key material and makes the reusable signer available again.
#[derive(Clone)]
pub struct PdfMacSigningSession {
    state: Arc<SessionState>,
}

impl fmt::Debug for PdfMacSigningSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PdfMacSigningSession")
            .field("md_algorithm", &self.state.handler.md_algorithm)
            .finish_non_exhaustive()
    }
}

// Keep certificate and revocation choices opaque: CMS's public certificate
// enum does not model v2 attribute certificates, which must survive adding
// a MAC to a CAdES container.
#[derive(der::Sequence)]
struct SignedDataWithOpaqueChoices {
    version: CmsVersion,
    digest_algorithms: SetOfVec<AlgorithmIdentifierOwned>,
    encap_content_info: EncapsulatedContentInfo,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    certificates: Option<SetOfVec<Any>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    crls: Option<SetOfVec<Any>>,
    signer_infos: SignerInfos,
}

impl PdfMacSigningSession {
    /// Add exactly one `pdfMacData` unsigned attribute to a CMS signature.
    ///
    /// The MAC binds the prepared byte-range digest and the hash of the raw
    /// signature value. Existing unsigned attributes, including RFC 3161
    /// signature timestamps, are preserved. Dry-run mode uses the PDF layer's
    /// deterministic MAC-key placeholder and is suitable for size estimation.
    pub fn attach_to_cms(
        &self,
        document_digest: &[u8],
        cms_der: &[u8],
        dry_run: bool,
    ) -> Result<Vec<u8>> {
        let handler = &self.state.handler;
        let expected_length = md_hash(&handler.md_algorithm, &[])
            .map_err(pdf_error)?
            .len();
        if document_digest.len() != expected_length {
            return Err(signing_error(
                "PDF MAC document digest has an invalid length",
            ));
        }
        let mut content_info = ContentInfo::from_der(cms_der)?;
        if content_info.content_type != SIGNED_DATA {
            return Err(signing_error("PDF MAC requires a CMS SignedData container"));
        }
        let mut data = SignedDataWithOpaqueChoices::from_der(&content_info.content.to_der()?)?;
        if data.signer_infos.0.len() != 1 {
            return Err(signing_error("PDF MAC requires exactly 1 signerInfo"));
        }
        let mut signer = data
            .signer_infos
            .0
            .iter()
            .next()
            .ok_or_else(|| signing_error("PDF MAC requires exactly 1 signerInfo"))?
            .clone();
        let signed_message_digest = if data.encap_content_info.econtent_type == TST_INFO {
            let content = data
                .encap_content_info
                .econtent
                .as_ref()
                .ok_or_else(|| signing_error("PDF MAC timestamp has no TSTInfo content"))?
                .decode_as::<OctetString>()?;
            let info = x509_tsp::TstInfo::from_der(content.as_bytes())?;
            if digest_oid(&handler.md_algorithm)
                != Some(info.message_imprint.hash_algorithm.oid.to_string().as_str())
                || info.message_imprint.hashed_message.as_bytes() != document_digest
            {
                return Err(signing_error(
                    "PDF MAC document digest does not match timestamp messageImprint",
                ));
            }
            // RFC 3161 permits a TSA signer digest different from the
            // request's message-imprint (and therefore PDF MAC) digest.
            md_hash(
                &digest_name(&signer.digest_alg.oid.to_string()),
                &[content.as_bytes()],
            )
            .map_err(pdf_error)?
        } else {
            if data.encap_content_info.econtent.is_some() {
                return Err(signing_error(
                    "PDF MAC requires a detached signature or RFC 3161 timestamp",
                ));
            }
            if digest_oid(&handler.md_algorithm) != Some(signer.digest_alg.oid.to_string().as_str())
            {
                return Err(signing_error(
                    "PDF MAC digest does not match the CMS signer digest",
                ));
            }
            document_digest.to_vec()
        };
        let attributes = signer
            .signed_attrs
            .as_ref()
            .ok_or_else(|| signing_error("PDF MAC requires signed messageDigest attributes"))?;
        let digests: Vec<_> = attributes
            .iter()
            .filter(|attribute| attribute.oid == MESSAGE_DIGEST)
            .collect();
        let [digest] = digests.as_slice() else {
            return Err(signing_error(
                "PDF MAC requires exactly 1 messageDigest attribute",
            ));
        };
        if digest.values.len() != 1 {
            return Err(signing_error(
                "PDF MAC requires exactly 1 messageDigest value",
            ));
        }
        let digest_value = digest
            .values
            .iter()
            .next()
            .ok_or_else(|| signing_error("PDF MAC requires a messageDigest value"))?
            .decode_as::<OctetString>()?;
        if digest_value.as_bytes() != signed_message_digest {
            return Err(signing_error(
                "PDF MAC document digest does not match signed messageDigest",
            ));
        }
        let mut unsigned = signer.unsigned_attrs.take().unwrap_or_default();
        if unsigned
            .iter()
            .any(|attribute| attribute.oid == PDF_MAC_DATA)
        {
            return Err(concurrent_session());
        }
        let signature_digest =
            md_hash(&handler.md_algorithm, &[signer.signature.as_bytes()]).map_err(pdf_error)?;
        let token = handler
            .build_pdfmac_token(document_digest, Some(&signature_digest), dry_run)
            .map_err(pdf_error)?;
        let mut values = SetOfVec::new();
        values.insert(Any::from_der(&token)?)?;
        unsigned.insert(Attribute {
            oid: PDF_MAC_DATA,
            values,
        })?;
        signer.unsigned_attrs = Some(unsigned);
        let mut infos = SetOfVec::new();
        infos.insert(signer)?;
        data.signer_infos = SignerInfos(infos);
        content_info.content = Any::encode_from(&data)?;
        Ok(content_info.to_der()?)
    }
}
