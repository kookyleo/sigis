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

pub mod attributes;
pub mod cms;
pub mod csc;
pub mod keys;
pub mod ltv;
pub mod pdf;
pub mod pkcs11;
pub mod pkcs12;
pub mod signer;
pub mod stamp;
pub mod timestamps;

// appearances: layout, text, fonts, images, QR codes, barcodes, forms
pub mod barcodes;
pub mod content;
pub mod font;
pub mod form_tools;
pub mod images;
pub mod layout;
pub mod qr;
pub mod text;

use std::sync::Arc;

use sigis_pdf::MdpPerm;
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::errors::Result;
use sigis_pki_core::sign::{KeySigner, TimeStamper};

pub use crate::attributes::{CadesSignedAttrSpec, CmsSignedAttributes, SignerAttrSpec};
pub use crate::cms::CmsSignerOptions;
pub use crate::pdf::fields::{FieldMdpAction, FieldMdpSpec, SigFieldSpec};
pub use crate::pdf::seed::{SigSeedSubFilter, SigSeedValueSpec};
pub use crate::pdf::signer::{BuildProps, SigAuthType, SignOptions};
pub use crate::signer::{
    DeferredSignatureValue, DeferredSigner, ExternalSigner, SigningProvider, SimpleSigner,
};
pub use crate::stamp::StampStyle;
pub use crate::timestamps::DummyTimeStamper;

/// `/SubFilter` of a PDF signature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SubFilter {
    /// `adbe.pkcs7.detached`.
    Pkcs7Detached,
    /// `ETSI.CAdES.detached` (PAdES).
    #[default]
    Pades,
    /// `PBAD.PAdES` (Brazilian PAdES profile).
    PbadPades,
}

/// Signature metadata and options (`PdfSignatureMetadata`).
#[derive(Clone, Debug)]
pub struct PdfSignatureMetadata {
    /// Signature field name; created if absent. Empty: use the only empty
    /// signature field (requires `existing_fields_only`).
    pub field_name: String,
    /// Digest algorithm; if `None`, taken from the signer's mechanism, the
    /// seed value dictionary, or chosen for the key
    /// (`select_suitable_signing_md`).
    pub md_algorithm: Option<DigestAlgorithm>,
    /// `/SubFilter`; if `None`, taken from the seed value dictionary, else
    /// `adbe.pkcs7.detached` (pyHanko's default).
    pub subfilter: Option<SubFilter>,
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
    /// DocMDP level for approval signatures that lock fields
    /// (`docmdp_permissions`).
    pub docmdp_permissions: MdpPerm,
    /// `/Prop_Build`.
    pub app_build_props: Option<BuildProps>,
    /// `/Prop_AuthTime`.
    pub prop_auth_time: Option<i64>,
    /// `/Prop_AuthType`.
    pub prop_auth_type: Option<SigAuthType>,
    /// CAdES signed attributes.
    pub cades_signed_attr_spec: Option<CadesSignedAttrSpec>,
    /// No safety margin in size estimates.
    pub tight_size_estimates: bool,
    /// Name of the document timestamp field (B-LTA).
    pub timestamp_field_name: Option<String>,
    /// Key usage required of the signer's certificate when a validation
    /// context is given (`signer_key_usage`).
    pub signer_key_usage: Vec<String>,
    /// DSS output settings (`dss_settings`).
    pub dss_settings: crate::pdf::signer::DssContentSettings,
}

impl PdfSignatureMetadata {
    /// Defaults for a PAdES signature in `field_name`.
    pub fn new(field_name: impl Into<String>) -> Self {
        Self {
            field_name: field_name.into(),
            md_algorithm: None,
            subfilter: Some(SubFilter::Pades),
            reason: None,
            location: None,
            name: None,
            contact_info: None,
            certify: None,
            embed_validation_info: false,
            use_pades_lta: false,
            validation_context: None,
            docmdp_permissions: MdpPerm::FillForms,
            app_build_props: None,
            prop_auth_time: None,
            prop_auth_type: None,
            cades_signed_attr_spec: None,
            tight_size_estimates: false,
            timestamp_field_name: None,
            signer_key_usage: vec!["non_repudiation".into()],
            dss_settings: Default::default(),
        }
    }

    /// pyHanko's defaults (`PdfSignatureMetadata(field_name=...)`):
    /// `adbe.pkcs7.detached` unless the seed values say otherwise.
    pub fn pyhanko_defaults(field_name: impl Into<String>) -> Self {
        Self {
            subfilter: None,
            ..Self::new(field_name)
        }
    }
}

/// Signs PDF documents (`PdfSigner`).
#[derive(Debug, Clone)]
pub struct PdfSigner {
    /// Signature options.
    pub metadata: PdfSignatureMetadata,
    /// The key.
    pub signer: Arc<dyn SigningProvider>,
    /// TSA for signature timestamps (B-T) and document timestamps (B-LTA).
    pub timestamper: Option<Arc<dyn TimeStamper>>,
    /// Field to create if the field does not exist (`new_field_spec`).
    pub new_field_spec: Option<SigFieldSpec>,
    /// Appearance of visible signatures (`stamp_style`).
    pub stamp_style: Option<StampStyle>,
    /// Extra text parameters for the appearance.
    pub appearance_text_params: std::collections::BTreeMap<String, String>,
    /// CMS options of the signer (`embed_roots`, attribute certificates).
    pub cms_options: CmsSignerOptions,
    /// Signing time (`/M`, `signingTime`); the current time if `None`.
    pub signing_time: Option<sigis_pki_core::time::Moment>,
    /// Ignore seed value dictionaries (testing).
    pub ignore_sv: bool,
}

impl PdfSigner {
    /// A signer with default settings.
    pub fn new(metadata: PdfSignatureMetadata, signer: Arc<dyn KeySigner>) -> Self {
        Self::with_signing_provider(
            metadata,
            Arc::new(crate::signer::LegacyKeySignerAdapter(signer)),
        )
    }

    /// Configure a provider whose certificate may arrive after digest preparation.
    pub fn with_signing_provider(
        metadata: PdfSignatureMetadata,
        signer: Arc<dyn SigningProvider>,
    ) -> Self {
        Self {
            metadata,
            signer,
            timestamper: None,
            new_field_spec: None,
            stamp_style: None,
            appearance_text_params: Default::default(),
            cms_options: CmsSignerOptions::default(),
            signing_time: None,
            ignore_sv: false,
        }
    }

    /// Set the timestamper.
    pub fn with_timestamper(mut self, ts: Arc<dyn TimeStamper>) -> Self {
        self.timestamper = Some(ts);
        self
    }

    /// Set the signing time.
    pub fn at(mut self, t: sigis_pki_core::time::Moment) -> Self {
        self.signing_time = Some(t);
        self
    }

    /// Set the field specification for new fields.
    pub fn with_field_spec(mut self, spec: SigFieldSpec) -> Self {
        self.new_field_spec = Some(spec);
        self
    }

    /// Sign `pdf` and return the signed file (`sign_pdf`).
    pub fn sign_pdf(&self, pdf: &[u8]) -> Result<Vec<u8>> {
        self.sign_pdf_with(pdf, &SignOptions::default())
    }
}

/// Produce a CMS `SignedData` over `data` (`Signer.sign_general_data`).
pub fn sign_general_data(
    data: &[u8],
    signer: &dyn KeySigner,
    digest: DigestAlgorithm,
    detached: bool,
    timestamper: Option<&dyn TimeStamper>,
) -> Result<Vec<u8>> {
    crate::cms::sign_general_data(data, signer, digest, detached, timestamper)
}

/// Append a document timestamp (`PdfTimeStamper.timestamp_pdf`), with
/// SHA-256. An empty `field_name` generates `Timestamp-<uuid>`.
pub fn add_document_timestamp(
    pdf: &[u8],
    timestamper: &dyn TimeStamper,
    field_name: &str,
) -> Result<Vec<u8>> {
    use crate::pdf::timestamp::{timestamp_pdf_with, TimestampOptions};
    let field = (!field_name.is_empty()).then(|| field_name.to_owned());
    timestamp_pdf_with(
        pdf,
        timestamper,
        field,
        &TimestampOptions::new(DigestAlgorithm::Sha256),
    )
}

/// Add validation information for the existing signatures to the DSS
/// (`add_validation_info`, one VRI entry per signature) and, if a
/// timestamper is given, renew the archival timestamp chain
/// (`PdfTimeStamper.update_archival_timestamp_chain`).
pub fn add_validation_info(
    pdf: &[u8],
    ctx: &ValidationContext,
    timestamper: Option<&dyn TimeStamper>,
) -> Result<Vec<u8>> {
    use crate::pdf::embedded::embedded_signatures;
    use crate::pdf::writer::PdfUpdate;
    let update = PdfUpdate::new(pdf)?;
    let sigs = embedded_signatures(&update)?;
    let mut out = pdf.to_vec();
    for s in sigs.iter().filter(|s| !s.is_doc_timestamp) {
        out = crate::pdf::timestamp::add_validation_info_for(&out, s, ctx, true, true, false)?;
    }
    match timestamper {
        Some(ts) => crate::pdf::timestamp::update_archival_chain_with(
            &out,
            ts,
            ctx,
            DigestAlgorithm::Sha256,
        ),
        None => Ok(out),
    }
}
