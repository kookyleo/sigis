// Derived from pyHanko `sign/signers/pdf_signer.py` (`PdfSigner`,
// `PdfSigningSession`, `PdfTBSDocument`, `_apply_locking_rules`,
// `_enforce_seed_value_constraints`, `estimate_signature_container_size`),
// `sign/signers/cms_embedder.py` (`PdfCMSEmbedder`, `SigMDPSetup`) and
// `sign/signers/pdf_byterange.py` (`SignatureObject`, `DocumentTimestamp`,
// `BuildProps`) (MIT, see LICENSE-pyHanko).

//! The PDF signing workflow.

use lopdf::{Dictionary, Object, ObjectId, StringFormat};
use sigis_pdf::MdpPerm;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::errors::{HankoError, Result};
use sigis_pki_core::sign::{KeySigner, TimeStamper};
use sigis_pki_core::time::Moment;

use crate::attributes::CmsSignedAttributes;
use crate::cms::{AttrProfile, CmsSigner};
use crate::pdf::fields::{
    self, ensure_sig_flags, enumerate_sig_fields, prepare_sig_field, FieldMdpSpec, NewFieldSettings,
};
use crate::pdf::seed::{SeedLockDocument, SigSeedSubFilter, SigSeedValFlags, SigSeedValueSpec};
use crate::pdf::util::{name, number, pdf_date, text_string};
use crate::pdf::writer::{
    byte_range_placeholder, contents_placeholder, fill_byte_range, fill_contents, PdfUpdate,
};
use crate::signer::{implied_digest, select_suitable_signing_md, subject_display_name};
use crate::{PdfSignatureMetadata, PdfSigner, SubFilter};

fn signing_error(msg: impl Into<String>) -> HankoError {
    HankoError::Signing(msg.into())
}

/// Default number of hex digits reserved for `/Contents` (16 KiB).
pub const DEFAULT_BYTES_RESERVED: usize = 16 * 1024;

/// Producer string written to `/Info`.
pub const PRODUCER: &str = "sigis-hanko";

/// Signature build properties (`BuildProps`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildProps {
    /// Application name.
    pub name: String,
    /// Revision (`/REx`).
    pub revision: Option<String>,
}

impl BuildProps {
    /// As a PDF dictionary (`as_pdf_object`).
    pub fn as_pdf_object(&self) -> Dictionary {
        let mut d = Dictionary::new();
        d.set("Name", name(&self.name));
        if let Some(r) = &self.revision {
            d.set("REx", text_string(r));
        }
        d
    }
}

/// `/Prop_AuthType` values (`SigAuthType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAuthType {
    /// `PIN`.
    Pin,
    /// `Password`.
    Password,
    /// `Fingerprint`.
    Fingerprint,
}

impl SigAuthType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pin => "PIN",
            Self::Password => "Password",
            Self::Fingerprint => "Fingerprint",
        }
    }
}

/// Where to put the DSS update for a signature (`SigDSSPlacementPreference`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SigDssPlacement {
    /// In the signature's own revision (requires `include_vri = false`).
    TogetherWithSignature,
    /// In a separate revision after the signature.
    SeparateRevision,
    /// Together with the next document timestamp, else separate.
    #[default]
    TogetherWithNextTs,
}

/// DSS settings for a signature (`DSSContentSettings`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DssContentSettings {
    /// Add VRI entries.
    pub include_vri: bool,
    /// Skip a separate DSS revision if nothing new would be added.
    pub skip_if_unneeded: bool,
    /// Placement.
    pub placement: SigDssPlacement,
    /// Settings for the document timestamp of the same workflow.
    pub next_ts_settings: Option<crate::pdf::timestamp::TimestampDssSettings>,
}

impl Default for DssContentSettings {
    fn default() -> Self {
        Self {
            include_vri: true,
            skip_if_unneeded: true,
            placement: SigDssPlacement::TogetherWithNextTs,
            next_ts_settings: None,
        }
    }
}

impl DssContentSettings {
    /// `get_settings_for_ts`.
    pub fn settings_for_ts(&self) -> crate::pdf::timestamp::TimestampDssSettings {
        self.next_ts_settings
            .unwrap_or(crate::pdf::timestamp::TimestampDssSettings {
                include_vri: self.include_vri,
                skip_if_unneeded: self.skip_if_unneeded,
                update_before_ts: self.placement == SigDssPlacement::TogetherWithSignature,
            })
    }

    /// `assert_viable`.
    pub fn assert_viable(&self) -> Result<()> {
        if self.include_vri && self.placement == SigDssPlacement::TogetherWithSignature {
            return Err(signing_error(
                "If VRI entries are to be included, DSS updates can only be performed after the signature in question was created.",
            ));
        }
        self.settings_for_ts().assert_viable()
    }
}

/// Per-call options of [`PdfSigner::sign_pdf_with`].
#[derive(Clone, Debug)]
pub struct SignOptions {
    /// Never create a new signature field.
    pub existing_fields_only: bool,
    /// Hex digits to reserve for `/Contents`; estimated if `None`.
    pub bytes_reserved: Option<usize>,
    /// Refuse hybrid-reference files (pyHanko's strict reader mode).
    pub strict: bool,
    /// Write a new single-revision document instead of an incremental
    /// update (signing the output of `copy_into_new_writer`).
    pub fresh_document: bool,
    /// Password of an encrypted document (user or owner).
    pub password: Option<Vec<u8>>,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            existing_fields_only: false,
            bytes_reserved: None,
            strict: true,
            fresh_document: false,
            password: None,
        }
    }
}

/// DocMDP / FieldMDP settings for the signature (`SigMDPSetup`).
#[derive(Clone, Debug)]
pub struct SigMdpSetup {
    /// Certification signature.
    pub certify: bool,
    /// Field lock of the signature field.
    pub field_lock: Option<FieldMdpSpec>,
    /// DocMDP permission level.
    pub docmdp_perms: Option<MdpPerm>,
}

/// The `/SubFilter` in use.
pub(crate) fn subfilter_name(sf: SigSeedSubFilter) -> &'static str {
    sf.pdf_name()
}

impl From<SubFilter> for SigSeedSubFilter {
    fn from(s: SubFilter) -> Self {
        match s {
            SubFilter::Pkcs7Detached => SigSeedSubFilter::AdobePkcs7Detached,
            SubFilter::Pades => SigSeedSubFilter::Pades,
            SubFilter::PbadPades => SigSeedSubFilter::PbadPades,
        }
    }
}

/// `/Reference` dictionary for DocMDP (`docmdp_reference_dictionary`).
fn docmdp_reference_dictionary(perm: MdpPerm) -> Dictionary {
    let mut tp = Dictionary::new();
    tp.set("Type", name("TransformParams"));
    tp.set("V", name("1.2"));
    tp.set("P", Object::Integer(perm as i64));
    let mut d = Dictionary::new();
    d.set("Type", name("SigRef"));
    d.set("TransformMethod", name("DocMDP"));
    d.set("TransformParams", Object::Dictionary(tp));
    d
}

/// `/Reference` dictionary for FieldMDP (`fieldmdp_reference_dictionary`).
fn fieldmdp_reference_dictionary(spec: &FieldMdpSpec, root: ObjectId) -> Dictionary {
    let mut d = Dictionary::new();
    d.set("Type", name("SigRef"));
    d.set("TransformMethod", name("FieldMDP"));
    d.set("Data", Object::Reference(root));
    d.set(
        "TransformParams",
        Object::Dictionary(spec.as_transform_params()),
    );
    d
}

impl SigMdpSetup {
    /// Apply to the signature object (`SigMDPSetup.apply`).
    pub fn apply(
        &self,
        update: &mut PdfUpdate,
        sig_obj: &mut Dictionary,
        sig_id: ObjectId,
    ) -> Result<()> {
        let mut refs = Vec::new();
        if self.certify {
            let perms = self
                .docmdp_perms
                .ok_or_else(|| signing_error("certification without DocMDP level"))?;
            let root_id = update.root_id();
            let perms_obj = update.get_dict(root_id)?.get(b"Perms").ok().cloned();
            match perms_obj {
                Some(Object::Reference(pid)) => {
                    update
                        .get_dict_mut(pid)?
                        .set("DocMDP", Object::Reference(sig_id));
                }
                Some(Object::Dictionary(mut d)) => {
                    d.set("DocMDP", Object::Reference(sig_id));
                    update.root_mut()?.set("Perms", Object::Dictionary(d));
                }
                _ => {
                    let mut d = Dictionary::new();
                    d.set("DocMDP", Object::Reference(sig_id));
                    update.root_mut()?.set("Perms", Object::Dictionary(d));
                }
            }
            refs.push(Object::Dictionary(docmdp_reference_dictionary(perms)));
        }
        if let Some(lock) = &self.field_lock {
            let mut r = fieldmdp_reference_dictionary(lock, update.root_id());
            if let Some(p) = self.docmdp_perms {
                // not spec-compatible, but emulates Acrobat (as pyHanko does)
                if let Ok(Object::Dictionary(tp)) = r.get_mut(b"TransformParams") {
                    tp.set("P", Object::Integer(p as i64));
                }
            }
            refs.push(Object::Dictionary(r));
        }
        if !refs.is_empty() {
            sig_obj.set("Reference", Object::Array(refs));
        }
        Ok(())
    }
}

/// Read the DocMDP level of the certification signature, if any
/// (`read_certification_data`).
pub fn read_certification_level(update: &PdfUpdate) -> Result<Option<MdpPerm>> {
    let root = update.root()?;
    let Some(Object::Dictionary(perms)) = update.dict_get(root, b"Perms")? else {
        return Ok(None);
    };
    let Some(Object::Dictionary(sig)) = update.dict_get(perms, b"DocMDP")? else {
        return Ok(None);
    };
    let Some(Object::Array(refs)) = update.dict_get(sig, b"Reference")? else {
        return Ok(None);
    };
    for r in refs {
        let Object::Dictionary(rd) = update.resolve(r)? else {
            continue;
        };
        if !matches!(update.dict_get(rd, b"TransformMethod")?, Some(Object::Name(n)) if n == b"DocMDP")
        {
            continue;
        }
        let p = match update.dict_get(rd, b"TransformParams")? {
            Some(Object::Dictionary(tp)) => update
                .dict_get(tp, b"P")?
                .and_then(|o| o.as_i64().ok())
                .unwrap_or(2),
            _ => 2,
        };
        return Ok(Some(match p {
            1 => MdpPerm::NoChanges,
            3 => MdpPerm::Annotate,
            _ => MdpPerm::FillForms,
        }));
    }
    Ok(None)
}

/// Fields of a `/Sig` signature dictionary other than the placeholders
/// (`SignatureObject`).
#[derive(Clone, Debug, Default)]
pub struct SignatureObjectSpec {
    /// `/SubFilter`.
    pub subfilter: Option<SigSeedSubFilter>,
    /// `/M`.
    pub timestamp: Option<Moment>,
    /// `/Name`.
    pub name: Option<String>,
    /// `/Location`.
    pub location: Option<String>,
    /// `/Reason`.
    pub reason: Option<String>,
    /// `/ContactInfo`.
    pub contact_info: Option<String>,
    /// `/Prop_AuthTime`.
    pub prop_auth_time: Option<i64>,
    /// `/Prop_AuthType`.
    pub prop_auth_type: Option<SigAuthType>,
    /// `/Prop_Build`.
    pub app_build_props: Option<BuildProps>,
}

impl SignatureObjectSpec {
    /// Build the dictionary, with placeholders for `/Contents` and
    /// `/ByteRange`.
    pub fn to_dict(&self, doc_timestamp: bool) -> Dictionary {
        let mut d = Dictionary::new();
        d.set(
            "Type",
            name(if doc_timestamp { "DocTimeStamp" } else { "Sig" }),
        );
        d.set("Filter", name("Adobe.PPKLite"));
        let sf = self.subfilter.unwrap_or(if doc_timestamp {
            SigSeedSubFilter::EtsiRfc3161
        } else {
            SigSeedSubFilter::AdobePkcs7Detached
        });
        d.set("SubFilter", name(subfilter_name(sf)));
        if let Some(t) = self.timestamp {
            d.set("M", text_string(&pdf_date(t)));
        }
        if let Some(n) = &self.name {
            d.set("Name", text_string(n));
        }
        if let Some(l) = &self.location {
            d.set("Location", text_string(l));
        }
        if let Some(r) = &self.reason {
            d.set("Reason", text_string(r));
        }
        if let Some(c) = &self.contact_info {
            d.set("ContactInfo", text_string(c));
        }
        if let Some(t) = self.prop_auth_time {
            d.set("Prop_AuthTime", Object::Integer(t));
        }
        if let Some(t) = self.prop_auth_type {
            d.set("Prop_AuthType", text_string(t.as_str()));
        }
        if let Some(b) = &self.app_build_props {
            let mut pb = Dictionary::new();
            pb.set("App", Object::Dictionary(b.as_pdf_object()));
            d.set("Prop_Build", Object::Dictionary(pb));
        }
        d.set("Contents", contents_placeholder());
        d.set("ByteRange", byte_range_placeholder());
        d
    }
}

/// A document prepared for signing: the update with its placeholder, and
/// the digest of the byte range (`PdfTBSDocument` + `PreparedByteRangeDigest`).
#[derive(Clone, Debug)]
pub struct PreparedDocument {
    /// The output with the placeholder in place.
    pub output: Vec<u8>,
    /// Digest of the byte range.
    pub document_digest: Vec<u8>,
    /// `<` of `/Contents`.
    pub reserved_region_start: usize,
    /// After `>` of `/Contents`.
    pub reserved_region_end: usize,
    /// The byte range.
    pub byte_range: [usize; 4],
    /// Digest algorithm used.
    pub md_algorithm: DigestAlgorithm,
}

impl PreparedDocument {
    /// Fill the reserved region with `cms` (`fill_with_cms`) and return the
    /// final file.
    pub fn fill_with_cms(mut self, cms: &[u8]) -> Result<Vec<u8>> {
        let offsets = crate::pdf::writer::PlaceholderOffsets {
            contents_start: self.reserved_region_start,
            contents_end: self.reserved_region_end,
            byte_range_at: 0,
        };
        fill_contents(&mut self.output, &offsets, cms)?;
        Ok(self.output)
    }
}

/// Insert a signature object into `update`, write the file, fill the byte
/// range and digest it.
pub fn write_and_digest(
    update: &mut PdfUpdate,
    sig_id: ObjectId,
    bytes_reserved: usize,
    md: DigestAlgorithm,
) -> Result<PreparedDocument> {
    if bytes_reserved % 2 == 1 {
        return Err(signing_error("bytes_reserved must be even"));
    }
    update.register_placeholder(sig_id, bytes_reserved);
    let (mut out, offsets) = update.write()?;
    let off = offsets
        .get(&sig_id)
        .copied()
        .ok_or_else(|| signing_error("signature object was not written"))?;
    let range = fill_byte_range(&mut out, &off)?;
    let mut data = Vec::with_capacity(out.len());
    data.extend_from_slice(&out[..off.contents_start]);
    data.extend_from_slice(&out[off.contents_end..]);
    Ok(PreparedDocument {
        document_digest: md.digest(&data),
        output: out,
        reserved_region_start: off.contents_start,
        reserved_region_end: off.contents_end,
        byte_range: range,
        md_algorithm: md,
    })
}

/// Register a developer extension in the catalog (`register_extension`):
/// `ESIC` (level 1, by level) or a multivalued `ISO_` extension.
pub fn register_extension(
    update: &mut PdfUpdate,
    prefix: &str,
    level: i64,
    multivalued: bool,
    base: &str,
    revision: Option<&str>,
    url: Option<&str>,
) -> Result<()> {
    let mut ext = Dictionary::new();
    ext.set("Type", name("DeveloperExtensions"));
    ext.set("BaseVersion", name(base));
    ext.set("ExtensionLevel", Object::Integer(level));
    if let Some(r) = revision {
        ext.set("ExtensionRevision", text_string(r));
    }
    if let Some(u) = url {
        ext.set("URL", text_string(u));
    }
    let root = update.root()?;
    let existing = match update.dict_get(root, b"Extensions")? {
        Some(Object::Dictionary(d)) => Some(d.clone()),
        _ => None,
    };
    let mut exts = existing.unwrap_or_default();
    let cur = exts.get(prefix.as_bytes()).ok().cloned();
    let cur = match cur {
        Some(Object::Reference(id)) => Some(update.get(id)?.clone()),
        other => other,
    };
    let levels = |o: &Object| -> Vec<i64> {
        match o {
            Object::Dictionary(d) => vec![d
                .get(b"ExtensionLevel")
                .and_then(Object::as_i64)
                .unwrap_or(-1)],
            Object::Array(a) => a
                .iter()
                .filter_map(|x| x.as_dict().ok())
                .map(|d| {
                    d.get(b"ExtensionLevel")
                        .and_then(Object::as_i64)
                        .unwrap_or(-1)
                })
                .collect(),
            _ => Vec::new(),
        }
    };
    let new_val = match cur {
        None => {
            if multivalued {
                Object::Array(vec![Object::Dictionary(ext)])
            } else {
                Object::Dictionary(ext)
            }
        }
        Some(c) => {
            let lv = levels(&c);
            if lv.contains(&level) {
                return Ok(());
            }
            if multivalued {
                let mut arr = match c {
                    Object::Array(a) => a,
                    Object::Dictionary(d) => vec![Object::Dictionary(d)],
                    _ => Vec::new(),
                };
                arr.push(Object::Dictionary(ext));
                Object::Array(arr)
            } else if lv.iter().any(|l| *l >= level) {
                return Ok(());
            } else {
                Object::Dictionary(ext)
            }
        }
    };
    exts.set(prefix.as_bytes().to_vec(), new_val);
    update
        .root_mut()?
        .set("Extensions", Object::Dictionary(exts));
    Ok(())
}

/// Parse the header version `%PDF-x.y`.
fn header_version(bytes: &[u8]) -> (u8, u8) {
    let head = &bytes[..bytes.len().min(1024)];
    if let Some(p) = head.windows(5).position(|w| w == b"%PDF-") {
        let v = &head[p + 5..];
        if v.len() >= 3 && v[0].is_ascii_digit() && v[2].is_ascii_digit() {
            return (v[0] - b'0', v[2] - b'0');
        }
    }
    (1, 7)
}

/// Ensure the output version is at least `version` (`ensure_output_version`).
pub fn ensure_output_version(update: &mut PdfUpdate, version: (u8, u8)) -> Result<()> {
    if header_version(update.base()) >= version {
        return Ok(());
    }
    let root = update.root()?;
    if let Some(Object::Name(v)) = update.dict_get(root, b"Version")? {
        let s = String::from_utf8_lossy(v);
        let mut parts = s.split('.');
        let maj = parts.next().and_then(|p| p.parse::<u8>().ok());
        let min = parts.next().and_then(|p| p.parse::<u8>().ok());
        if let (Some(a), Some(b)) = (maj, min) {
            if (a, b) >= version {
                return Ok(());
            }
        }
    }
    update
        .root_mut()?
        .set("Version", name(&format!("{}.{}", version.0, version.1)));
    Ok(())
}

fn effective_version(update: &PdfUpdate) -> (u8, u8) {
    let hv = header_version(update.base());
    let cv = update
        .root()
        .ok()
        .and_then(|r| r.get(b"Version").ok())
        .and_then(|o| o.as_name().ok())
        .and_then(|n| {
            let s = String::from_utf8_lossy(n);
            let mut p = s.split('.');
            Some((p.next()?.parse::<u8>().ok()?, p.next()?.parse::<u8>().ok()?))
        });
    cv.map_or(hv, |c| c.max(hv))
}

/// Register the ESIC extension for PAdES (`_ensure_esic_ext`).
pub fn ensure_esic_ext(update: &mut PdfUpdate) -> Result<()> {
    ensure_output_version(update, (1, 7))?;
    if effective_version(update) < (2, 0) {
        register_extension(update, "ESIC", 1, false, "1.7", None, None)?;
    }
    Ok(())
}

/// ISO 32001 (SHA-3 / SHAKE256) extension (`_ensure_iso32001_ext`).
pub fn ensure_iso32001_ext(update: &mut PdfUpdate) -> Result<()> {
    ensure_output_version(update, (2, 0))?;
    register_extension(
        update,
        "ISO_",
        32001,
        true,
        "2.0",
        Some(":2022"),
        Some("https://www.iso.org/standard/45874.html"),
    )
}

/// ISO 32002 (EdDSA / additional curves) extension (`_ensure_iso32002_ext`).
pub fn ensure_iso32002_ext(update: &mut PdfUpdate) -> Result<()> {
    ensure_output_version(update, (2, 0))?;
    register_extension(
        update,
        "ISO_",
        32002,
        true,
        "2.0",
        Some(":2022"),
        Some("https://www.iso.org/standard/45875.html"),
    )
}

/// Instructions for the updates after the signature
/// (`PostSignInstructions`): DSS and document timestamp (B-LT / B-LTA).
#[derive(Clone, Debug)]
pub struct PostSignInstructions {
    /// Validation information to embed.
    pub validation_info: crate::ltv::ValidationInfo,
    /// Digest for the document timestamp.
    pub timestamp_md_algorithm: DigestAlgorithm,
    /// TSA for the document timestamp; none if `None`.
    pub timestamper: Option<std::sync::Arc<dyn TimeStamper>>,
    /// Name of the timestamp field.
    pub timestamp_field_name: Option<String>,
    /// DSS settings.
    pub dss_settings: DssContentSettings,
    /// No safety margin in the timestamp size estimate.
    pub tight_size_estimates: bool,
    /// Embed trust anchors in the DSS.
    pub embed_roots: bool,
    /// Password of an encrypted document (`file_credential`).
    pub file_password: Option<Vec<u8>>,
}

/// A document in its final pre-signing state (`PdfTBSDocument`).
#[derive(Clone, Debug)]
pub struct PdfTbsDocument {
    /// The output with the placeholder, and its digest.
    pub prepared: PreparedDocument,
    /// Digest algorithm.
    pub md_algorithm: DigestAlgorithm,
    /// PAdES signature.
    pub use_pades: bool,
    /// Post-signing instructions, if any.
    pub post_sign_instructions: Option<PostSignInstructions>,
    /// Signed attribute settings for the CMS object.
    pub signed_attr_settings: CmsSignedAttributes,
    /// Attribute profile for the CMS object.
    pub attr_profile: AttrProfile,
}

impl PdfTbsDocument {
    /// Embed an externally produced CMS object and run the post-signing
    /// steps (`PdfTBSDocument.finish_signing`).
    pub fn finish_signing(
        prepared: PreparedDocument,
        cms: &[u8],
        psi: Option<&PostSignInstructions>,
        validation_context: Option<&sigis_pki_certvalidator::ValidationContext>,
    ) -> Result<Vec<u8>> {
        let reserved = prepared.reserved_region_end - prepared.reserved_region_start - 2;
        let mut sig_contents = cms.to_vec();
        sig_contents.resize(reserved / 2, 0);
        let signed = prepared.fill_with_cms(cms)?;
        match psi {
            Some(psi) => post_signature_processing(signed, &sig_contents, psi, validation_context),
            None => Ok(signed),
        }
    }
}

/// DSS update and document timestamp after signing
/// (`PdfPostSignatureDocument.post_signature_processing`).
pub fn post_signature_processing(
    signed: Vec<u8>,
    sig_contents: &[u8],
    psi: &PostSignInstructions,
    validation_context: Option<&sigis_pki_certvalidator::ValidationContext>,
) -> Result<Vec<u8>> {
    use crate::pdf::dss::{add_dss_with_password, DssContent};
    let info = &psi.validation_info;
    let dss_settings = psi.dss_settings;
    let vri = dss_settings.include_vri.then_some(sig_contents);
    let separate = match dss_settings.placement {
        SigDssPlacement::SeparateRevision => true,
        SigDssPlacement::TogetherWithNextTs => psi.timestamper.is_none(),
        SigDssPlacement::TogetherWithSignature => false,
    };
    let mut out = signed;
    if separate {
        out = add_dss_with_password(
            &out,
            &DssContent {
                sig_contents: vri,
                paths: info.paths.clone(),
                ocsps: info.ocsps.clone(),
                crls: info.crls.clone(),
                embed_roots: psi.embed_roots,
                ..Default::default()
            },
            !dss_settings.skip_if_unneeded,
            psi.file_password.as_deref(),
        )?;
    }
    if let Some(ts) = &psi.timestamper {
        let mut opts = crate::pdf::timestamp::TimestampOptions::new(psi.timestamp_md_algorithm);
        opts.validation_context = validation_context;
        opts.validation_info = Some(info.clone());
        opts.dss_settings = dss_settings.settings_for_ts();
        opts.tight_size_estimates = psi.tight_size_estimates;
        opts.embed_roots = psi.embed_roots;
        opts.password = psi.file_password.clone();
        if dss_settings.placement == SigDssPlacement::TogetherWithNextTs {
            opts.dss_with_ts = Some((vri.map(<[u8]>::to_vec), info.clone()));
        }
        out = crate::pdf::timestamp::timestamp_pdf_with(
            &out,
            ts.as_ref(),
            psi.timestamp_field_name.clone(),
            &opts,
        )?;
    }
    Ok(out)
}

/// Session state of one signing operation (`PdfSigningSession`).
struct Session<'a> {
    signer: &'a PdfSigner,
    field_id: ObjectId,
    md: DigestAlgorithm,
    subfilter: SigSeedSubFilter,
    sv_spec: Option<SigSeedValueSpec>,
    system_time: Moment,
    validation_info: Option<crate::ltv::ValidationInfo>,
    adobe_revinfo: Option<crate::attributes::RevocationInfoArchival>,
}

impl Session<'_> {
    fn use_pades(&self) -> bool {
        matches!(
            self.subfilter,
            SigSeedSubFilter::Pades | SigSeedSubFilter::PbadPades
        )
    }
}

impl PdfSigner {
    fn meta(&self) -> &PdfSignatureMetadata {
        &self.metadata
    }

    /// The digest implied by the signer's mechanism, if any
    /// (`signer_hash_algo`).
    fn signer_hash_algo(&self) -> Option<DigestAlgorithm> {
        // pyHanko asks the signer for its mechanism without a digest; only
        // mechanisms that fix the digest (EdDSA, explicit mechanisms) yield
        // one. Probe with two digests: a fixed mechanism ignores them.
        let a = self
            .signer
            .signature_algorithm(DigestAlgorithm::Sha256)
            .ok()?;
        let b = self
            .signer
            .signature_algorithm(DigestAlgorithm::Sha512)
            .ok()?;
        if a == b {
            implied_digest(&a)
        } else {
            None
        }
    }

    fn default_md_for_signer(&self) -> Option<DigestAlgorithm> {
        self.meta().md_algorithm.or_else(|| self.signer_hash_algo())
    }

    fn select_md(&self, sv: Option<&SigSeedValueSpec>) -> Result<DigestAlgorithm> {
        if let Some(md) = self.default_md_for_signer() {
            return Ok(md);
        }
        if let Some(dm) = sv
            .and_then(|s| s.digest_methods.as_ref())
            .and_then(|v| v.first())
        {
            return digest_from_name(dm)
                .ok_or_else(|| HankoError::Unsupported(format!("digest method {dm}")));
        }
        Ok(select_suitable_signing_md(
            &self.signer.signing_cert().public_key(),
        ))
    }

    /// Sign `pdf` with explicit options (`PdfSigner.sign_pdf`).
    pub fn sign_pdf_with(&self, pdf: &[u8], opts: &SignOptions) -> Result<Vec<u8>> {
        let tbs = self.digest_doc_for_signing(pdf, opts)?;
        let cms = CmsSigner {
            signer: self.signer.as_ref(),
            options: &self.cms_options,
        }
        .sign(
            &tbs.prepared.document_digest,
            tbs.md_algorithm,
            &tbs.signed_attr_settings,
            tbs.attr_profile,
            self.timestamper.as_deref(),
            false,
            None,
        )?;
        PdfTbsDocument::finish_signing(
            tbs.prepared,
            &cms,
            tbs.post_sign_instructions.as_ref(),
            self.metadata.validation_context.as_deref(),
        )
    }

    /// Prepare the document up to the computation of the byte range digest
    /// (`async_digest_doc_for_signing`).
    pub fn digest_doc_for_signing(&self, pdf: &[u8], opts: &SignOptions) -> Result<PdfTbsDocument> {
        let mut update = if opts.fresh_document {
            PdfUpdate::fresh(pdf)?
        } else {
            PdfUpdate::open_with(pdf, opts.password.as_deref())?
        };
        update.set_strict(opts.strict);
        let (prepared, session) = self.prepare(&mut update, opts)?;
        let meta = self.meta();
        let post_sign_instructions = if session.use_pades() && meta.embed_validation_info {
            let info = session.validation_info.clone().ok_or_else(|| {
                signing_error("Requested embedding of validation info, but none was collected")
            })?;
            Some(PostSignInstructions {
                validation_info: info,
                timestamp_md_algorithm: session.md,
                timestamper: if meta.use_pades_lta {
                    self.timestamper.clone()
                } else {
                    None
                },
                timestamp_field_name: meta.timestamp_field_name.clone(),
                dss_settings: meta.dss_settings,
                tight_size_estimates: meta.tight_size_estimates,
                embed_roots: self.cms_options.embed_roots,
                file_password: opts.password.clone(),
            })
        } else {
            None
        };
        Ok(PdfTbsDocument {
            signed_attr_settings: self.signed_attr_settings(&session),
            attr_profile: profile_for(session.subfilter),
            md_algorithm: session.md,
            use_pades: session.use_pades(),
            prepared,
            post_sign_instructions,
        })
    }

    fn signed_attr_settings(&self, session: &Session<'_>) -> CmsSignedAttributes {
        CmsSignedAttributes {
            signing_time: Some(session.system_time),
            cades_signed_attrs: self.meta().cades_signed_attr_spec.clone(),
            adobe_revinfo_attr: session.adobe_revinfo.clone(),
        }
    }

    /// Validate the signer (and TSA) before signing, collecting validation
    /// information (`perform_presign_validation`).
    fn presign_validation(
        &self,
        update: &PdfUpdate,
        md: DigestAlgorithm,
        use_pades: bool,
    ) -> Result<(
        Option<crate::ltv::ValidationInfo>,
        Option<crate::attributes::RevocationInfoArchival>,
    )> {
        use crate::ltv::{validate_and_collect, ValidationInfo};
        let meta = self.meta();
        if meta.embed_validation_info && meta.validation_context.is_none() {
            return Err(signing_error(
                "A validation context must be provided if validation/revocation info is to be embedded into the signature.",
            ));
        }
        let Some(ctx) = meta.validation_context.as_deref() else {
            return Ok((None, None));
        };
        let mut info = ValidationInfo::default();
        let cert = self.signer.signing_cert();
        validate_and_collect(ctx, cert, self.signer.cert_chain(), &mut info).map_err(|e| {
            signing_error(format!(
                "The signer's certificate could not be validated: {e}"
            ))
        })?;
        let have = crate::pdf::seed::cert_key_usage_names(cert);
        if cert.key_usage().is_some() {
            for ku in &meta.signer_key_usage {
                if !have.contains(ku) {
                    return Err(signing_error(format!(
                        "The signer's certificate could not be validated: the key usage extension does not include {ku}"
                    )));
                }
            }
        }
        if meta.use_pades_lta {
            let sigs = crate::pdf::embedded::embedded_signatures(update)?;
            if let Some(ts) = sigs.iter().rev().find(|s| s.is_doc_timestamp) {
                let (tsa, certs) = crate::pdf::timestamp::token_signer(ts.cms())?;
                let mut pool = self.signer.cert_chain().to_vec();
                pool.extend(certs);
                validate_and_collect(ctx, &tsa, &pool, &mut info).map_err(|e| {
                    signing_error(format!(
                        "Requested a PAdES-LTA signature on an existing document, but the most recent timestamp could not be validated: {e}"
                    ))
                })?;
            }
        }
        if let Some(ts) = &self.timestamper {
            crate::pdf::timestamp::tsa_validation_info(ts.as_ref(), md, ctx, &mut info)?;
        }
        let adobe = if meta.embed_validation_info && !use_pades {
            crate::attributes::RevocationInfoArchival::from_der_lists(&info.ocsps, &info.crls)?
        } else {
            None
        };
        Ok((Some(info), adobe))
    }

    /// Steps up to the computation of the document digest.
    fn prepare(
        &self,
        update: &mut PdfUpdate,
        opts: &SignOptions,
    ) -> Result<(PreparedDocument, Session<'_>)> {
        let meta = self.meta();
        if update.is_hybrid() && opts.strict {
            return Err(signing_error(
                "Attempting to sign document with hybrid cross-reference sections while hybrid xrefs are disabled",
            ));
        }
        if let Some(spec) = &self.new_field_spec {
            if spec.sig_field_name != meta.field_name {
                return Err(signing_error(
                    "Field names specified in SigFieldSpec and PdfSignatureMetadata do not agree.",
                ));
            }
        }
        // field
        let field_id = self.get_or_create_field(update, opts.existing_fields_only)?;
        ensure_sig_flags(update, true)?;
        // seed values
        let sv_spec = if self.ignore_sv {
            None
        } else {
            let field = update.get_dict(field_id)?;
            match update.dict_get(field, b"SV")? {
                Some(Object::Dictionary(sv)) => {
                    let sv = sv.clone();
                    Some(SigSeedValueSpec::from_pdf_object(update, &sv)?)
                }
                _ => None,
            }
        };
        // certification constraints
        if meta.certify.is_some() && !enumerate_sig_fields(update, Some(true), None)?.is_empty() {
            return Err(signing_error(
                "Certification signatures must be the first signature in a given document.",
            ));
        }
        if read_certification_level(update)? == Some(MdpPerm::NoChanges) {
            return Err(signing_error("Author signature forbids all changes"));
        }
        let md = self.select_md(sv_spec.as_ref())?;
        // subfilter
        let subfilter = match meta.subfilter {
            Some(s) => s.into(),
            None => sv_spec
                .as_ref()
                .and_then(|s| s.subfilters.as_ref())
                .and_then(|v| v.first().copied())
                .unwrap_or(SigSeedSubFilter::AdobePkcs7Detached),
        };
        if subfilter == SigSeedSubFilter::Pades {
            ensure_esic_ext(update)?;
        }
        let mech = self.signer.signature_algorithm(md)?;
        let ec_iso_curve = mech.oid != sigis_pki_core::asn1::oids::ED25519
            && self.signer.signing_cert().public_key().algorithm.oid
                == sigis_pki_core::asn1::oids::EC_PUBLIC_KEY
            && self
                .signer
                .signing_cert()
                .public_key()
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<const_oid::ObjectIdentifier>().ok())
                .is_some_and(|c| {
                    [
                        sigis_pki_core::asn1::oids::SECP256R1,
                        sigis_pki_core::asn1::oids::SECP384R1,
                        sigis_pki_core::asn1::oids::SECP521R1,
                    ]
                    .contains(&c)
                });
        // `register_extensions`
        if mech.oid == sigis_pki_core::asn1::oids::ED25519 {
            ensure_iso32002_ext(update)?;
        } else if mech.oid == sigis_pki_core::asn1::oids::ED448 {
            ensure_iso32001_ext(update)?;
            ensure_iso32002_ext(update)?;
        } else {
            if matches!(
                md,
                DigestAlgorithm::Sha3_224
                    | DigestAlgorithm::Sha3_256
                    | DigestAlgorithm::Sha3_384
                    | DigestAlgorithm::Sha3_512
                    | DigestAlgorithm::Shake256
            ) {
                ensure_iso32001_ext(update)?;
            }
            if ec_iso_curve {
                ensure_iso32002_ext(update)?;
            }
        }
        if sv_spec.as_ref().is_some_and(|s| s.timestamp_required) && self.timestamper.is_none() {
            return Err(HankoError::Unsupported(
                "the seed value dictionary requires a timestamp, but no timestamper is configured"
                    .into(),
            ));
        }
        let use_pades = matches!(
            subfilter,
            SigSeedSubFilter::Pades | SigSeedSubFilter::PbadPades
        );
        let (validation_info, adobe_revinfo) = self.presign_validation(update, md, use_pades)?;
        let session = Session {
            signer: self,
            field_id,
            md,
            subfilter,
            sv_spec,
            system_time: self.signing_time.unwrap_or_else(Moment::now),
            validation_info,
            adobe_revinfo,
        };
        if session.use_pades() {
            if let Some(info) = &session.validation_info {
                meta.dss_settings.assert_viable()?;
                if meta.dss_settings.placement == SigDssPlacement::TogetherWithSignature {
                    crate::pdf::dss::supply_dss_in_writer(
                        update,
                        &crate::pdf::dss::DssContent {
                            sig_contents: None,
                            paths: info.paths.clone(),
                            ocsps: info.ocsps.clone(),
                            crls: info.crls.clone(),
                            embed_roots: self.cms_options.embed_roots,
                            ..Default::default()
                        },
                    )?;
                }
            }
        }
        if let Some(sv) = &session.sv_spec {
            self.enforce_seed_value_constraints(sv, &session)?;
        }
        let mdp = self.apply_locking_rules(update, &session)?;
        let bytes_reserved = match opts.bytes_reserved {
            Some(b) => b,
            None => self.estimate_signature_container_size(&session)?,
        };
        // signature object
        let spec = SignatureObjectSpec {
            subfilter: Some(subfilter),
            timestamp: Some(session.system_time),
            name: meta.name.clone(),
            location: meta.location.clone(),
            reason: meta.reason.clone(),
            contact_info: meta.contact_info.clone(),
            prop_auth_time: meta.prop_auth_time,
            prop_auth_type: meta.prop_auth_type,
            app_build_props: meta.app_build_props.clone(),
        };
        let mut sig_dict = spec.to_dict(false);
        let sig_id = update.add(Object::Null);
        mdp.apply(update, &mut sig_dict, sig_id)?;
        update.update(sig_id, Object::Dictionary(sig_dict));
        // appearance
        self.apply_appearance(update, field_id, &session)?;
        update
            .get_dict_mut(field_id)?
            .set("V", Object::Reference(sig_id));
        update.update_info(&pdf_date(session.system_time), PRODUCER)?;
        let prepared = write_and_digest(update, sig_id, bytes_reserved, md)?;
        let _ = session.signer;
        Ok((prepared, session))
    }

    fn apply_appearance(
        &self,
        update: &mut PdfUpdate,
        field_id: ObjectId,
        session: &Session<'_>,
    ) -> Result<()> {
        let annot = fields::single_field_annot(update, field_id)?;
        let annot_dict = update.get_dict(annot)?.clone();
        let (w, h) = fields::annot_width_height(update, &annot_dict);
        if w == 0.0 || h == 0.0 {
            return Ok(());
        }
        let signer_name = self
            .meta()
            .name
            .clone()
            .or_else(|| subject_display_name(self.signer.signing_cert()));
        crate::stamp::apply_signature_appearance(
            update,
            annot,
            w,
            h,
            self.stamp_style.as_ref(),
            signer_name.as_deref(),
            session.system_time,
            &self.appearance_text_params,
        )
    }

    fn get_or_create_field(&self, update: &mut PdfUpdate, existing_only: bool) -> Result<ObjectId> {
        let field_name = self.meta().field_name.as_str();
        if field_name.is_empty() {
            if !existing_only {
                return Err(signing_error(
                    "Not specifying a field name is only allowed when existing_fields_only=True",
                ));
            }
            let empty = enumerate_sig_fields(update, Some(false), None)?;
            let Some(first) = empty.first() else {
                return Err(signing_error("There are no empty signature fields."));
            };
            if empty.len() > 1 {
                let others: Vec<&str> = empty[1..].iter().map(|f| f.name.as_str()).collect();
                return Err(signing_error(format!(
                    "There are several empty signature fields. Please specify a field name. The options are {}, {}.",
                    first.name,
                    others.join(", ")
                )));
            }
            return Ok(first.id);
        }
        let spec = if existing_only {
            None
        } else {
            self.new_field_spec.as_ref()
        };
        let settings = match spec {
            Some(s) => NewFieldSettings {
                bbox: s.bbox,
                page: Some(update.page(s.on_page)?),
                separate_annotation: !s.combine_annotation,
                invis: s.invis_sig_settings,
                visible: s.visible_sig_settings,
            },
            None => NewFieldSettings::default(),
        };
        let (created, id) = prepare_sig_field(update, field_name, existing_only, &settings)?;
        if created {
            if let Some(s) = spec {
                fields::apply_sig_field_spec_properties(update, id, s)?;
            }
        }
        Ok(id)
    }

    /// `_apply_locking_rules`.
    fn apply_locking_rules(
        &self,
        update: &mut PdfUpdate,
        session: &Session<'_>,
    ) -> Result<SigMdpSetup> {
        let meta = self.meta();
        let (sv_lock_values, sv_lock_req) = match &session.sv_spec {
            Some(sv) => {
                let vals = match sv.lock_document {
                    Some(SeedLockDocument::Lock) => vec![MdpPerm::NoChanges],
                    Some(SeedLockDocument::DoNotLock) => {
                        vec![MdpPerm::FillForms, MdpPerm::Annotate]
                    }
                    _ => Vec::new(),
                };
                let req = sv.flags.contains(SigSeedValFlags::LOCK_DOCUMENT);
                (vals, req)
            }
            None => (Vec::new(), false),
        };
        let mut docmdp_perms = sv_lock_values.first().copied();
        let field = update.get_dict(session.field_id)?.clone();
        let mut lock = None;
        let lock_obj = field.get(b"Lock").ok().cloned();
        let mut lock_holder: Option<ObjectId> = None;
        if let Some(lo) = &lock_obj {
            if let Object::Reference(id) = lo {
                lock_holder = Some(*id);
            }
            if let Object::Dictionary(ld) = update.resolve(lo)? {
                let ld = ld.clone();
                lock =
                    Some(FieldMdpSpec::from_pdf_object(update, &ld).map_err(|e| {
                        signing_error(format!("Failed to read /Lock dictionary: {e}"))
                    })?);
                if let Some(p) = update.dict_get(&ld, b"P")?.and_then(|o| o.as_i64().ok()) {
                    let perm = match p {
                        1 => MdpPerm::NoChanges,
                        2 => MdpPerm::FillForms,
                        3 => MdpPerm::Annotate,
                        _ => return Err(signing_error("Failed to read /Lock dictionary")),
                    };
                    docmdp_perms = Some(perm);
                    if sv_lock_req && !sv_lock_values.contains(&perm) {
                        return Err(signing_error(format!(
                            "Inconsistency in form field data. The field lock dictionary imposes the DocMDP policy '{perm:?}', but the seed value dictionary's /LockDocument does not allow that."
                        )));
                    }
                }
            }
        }
        let meta_certify = meta.certify.is_some();
        let meta_perms = meta.certify.unwrap_or(meta.docmdp_permissions);
        if meta_certify || docmdp_perms.is_some() {
            if sv_lock_req && !sv_lock_values.contains(&meta_perms) {
                docmdp_perms = sv_lock_values.first().copied();
            } else {
                docmdp_perms = Some(match docmdp_perms {
                    None => meta_perms,
                    Some(p) => p.min(meta_perms),
                });
            }
        }
        if !meta_certify {
            if let Some(p) = docmdp_perms {
                match (lock_holder, lock_obj) {
                    (Some(id), _) => {
                        update.get_dict_mut(id)?.set("P", Object::Integer(p as i64));
                    }
                    (None, Some(Object::Dictionary(mut ld))) => {
                        ld.set("P", Object::Integer(p as i64));
                        update
                            .get_dict_mut(session.field_id)?
                            .set("Lock", Object::Dictionary(ld));
                    }
                    _ => {
                        let mut ld = Dictionary::new();
                        ld.set("Action", name("Include"));
                        ld.set("Fields", Object::Array(Vec::new()));
                        ld.set("P", Object::Integer(p as i64));
                        update
                            .get_dict_mut(session.field_id)?
                            .set("Lock", Object::Dictionary(ld));
                    }
                }
            }
        }
        Ok(SigMdpSetup {
            certify: meta_certify,
            field_lock: lock,
            docmdp_perms,
        })
    }

    /// `_enforce_seed_value_constraints`.
    fn enforce_seed_value_constraints(
        &self,
        sv: &SigSeedValueSpec,
        session: &Session<'_>,
    ) -> Result<()> {
        let meta = self.meta();
        if let Some(c) = &sv.cert {
            let chain = self.signer.cert_chain().to_vec();
            c.satisfied_by(self.signer.signing_cert(), Some(&chain))?;
        }
        if let Some(st) = &sv.seed_signature_type {
            let sv_certify = st.is_some();
            let certify = meta.certify.is_some();
            let ty = |c: bool| if c { "a certification" } else { "an approval" };
            if sv_certify != certify {
                return Err(signing_error(format!(
                    "The seed value dictionary's /MDP entry specifies that this field should contain {} signature, but {} was requested.",
                    ty(sv_certify),
                    ty(certify)
                )));
            }
            if let (Some(p), Some(req)) = (st, meta.certify) {
                if *p != req {
                    return Err(signing_error(format!(
                        "The seed value dictionary specified that this certification signature should use the MDP policy '{p:?}', but '{req:?}' was requested."
                    )));
                }
            }
        }
        let flags = sv.flags;
        if flags.0 == 0 {
            return Ok(());
        }
        let mut selected_sf: Option<SigSeedSubFilter> = meta.subfilter.map(Into::into);
        if flags.contains(SigSeedValFlags::SUBFILTER) {
            if let Some(sfs) = &sv.subfilters {
                let Some(mandated) = sfs.first() else {
                    return Err(HankoError::Unsupported(
                        "The signature encodings mandated by the seed value dictionary are not supported."
                            .into(),
                    ));
                };
                if let Some(sel) = selected_sf {
                    if sel != *mandated {
                        return Err(signing_error(format!(
                            "The seed value dictionary mandates subfilter '{}', but '{}' was requested.",
                            mandated.pdf_name(),
                            sel.pdf_name()
                        )));
                    }
                }
            }
        }
        if selected_sf.is_none() {
            selected_sf = sv.subfilters.as_ref().and_then(|v| v.first().copied());
        }
        if flags.contains(SigSeedValFlags::APPEARANCE_FILTER) {
            if let Some(a) = &sv.appearance {
                return Err(signing_error(format!(
                    "pyHanko does not define any named appearances, but the seed value dictionary requires that the named appearance '{a}' be used."
                )));
            }
        }
        if flags.contains(SigSeedValFlags::ADD_REV_INFO) {
            if let Some(req) = sv.add_rev_info {
                if req != meta.embed_validation_info {
                    return Err(signing_error(format!(
                        "The seed value dict mandates that revocation info {}be added; adjust PdfSignatureMetadata settings accordingly.",
                        if req { "" } else { "not " }
                    )));
                }
                if req && selected_sf != Some(SigSeedSubFilter::AdobePkcs7Detached) {
                    return Err(signing_error(
                        "The seed value dict mandates that Adobe-style revocation info be added; this requires subfilter 'adbe.pkcs7.detached'",
                    ));
                }
            }
        }
        if flags.contains(SigSeedValFlags::DIGEST_METHOD) {
            if let Some(dms) = &sv.digest_methods {
                if let Some(sel) = self.default_md_for_signer() {
                    if !dms.iter().any(|d| d == sel.name()) {
                        return Err(signing_error(format!(
                            "The selected message digest {} is not allowed by the seed value dictionary. Please select one of {}.",
                            sel.name(),
                            dms.join(", ")
                        )));
                    }
                }
            }
        }
        if flags.contains(SigSeedValFlags::REASONS) {
            let reasons = sv.reasons.clone().unwrap_or_default();
            let must_omit = reasons.is_empty() || reasons == ["."];
            if must_omit && meta.reason.is_some() {
                return Err(signing_error(
                    "The seed value dictionary prohibits giving a reason for signing.",
                ));
            }
            if !must_omit && !reasons.iter().any(|r| Some(r) == meta.reason.as_ref()) {
                return Err(signing_error(format!(
                    "Reason \"{}\" is not a valid reason for signing, please choose one of the following: {}.",
                    meta.reason.clone().unwrap_or_else(|| "None".into()),
                    reasons.iter().map(|r| format!("\"{r}\"")).collect::<Vec<_>>().join(", ")
                )));
            }
        }
        let _ = session;
        Ok(())
    }

    /// `estimate_signature_container_size`.
    fn estimate_signature_container_size(&self, session: &Session<'_>) -> Result<usize> {
        let test_md = session.md.digest(b"");
        let cms = CmsSigner {
            signer: self.signer.as_ref(),
            options: &self.cms_options,
        }
        .sign(
            &test_md,
            session.md,
            &self.signed_attr_settings(session),
            profile_for(session.subfilter),
            self.timestamper.as_deref(),
            true,
            None,
        )?;
        let test_len = cms.len() * 2;
        Ok(if self.meta().tight_size_estimates {
            test_len
        } else {
            test_len + 2 * (test_len / 4)
        })
    }
}

/// Attribute profile for a subfilter.
fn profile_for(sf: SigSeedSubFilter) -> AttrProfile {
    match sf {
        SigSeedSubFilter::Pades | SigSeedSubFilter::PbadPades => {
            AttrProfile::Cades { is_pades: true }
        }
        _ => AttrProfile::GenericPdf,
    }
}

/// Resolve a digest name as used in seed value dictionaries.
pub fn digest_from_name(n: &str) -> Option<DigestAlgorithm> {
    Some(match n.to_ascii_lowercase().replace('-', "").as_str() {
        "sha1" => DigestAlgorithm::Sha1,
        "sha224" => DigestAlgorithm::Sha224,
        "sha256" => DigestAlgorithm::Sha256,
        "sha384" => DigestAlgorithm::Sha384,
        "sha512" => DigestAlgorithm::Sha512,
        "sha3_224" => DigestAlgorithm::Sha3_224,
        "sha3_256" => DigestAlgorithm::Sha3_256,
        "sha3_384" => DigestAlgorithm::Sha3_384,
        "sha3_512" => DigestAlgorithm::Sha3_512,
        "shake256" => DigestAlgorithm::Shake256,
        _ => return None,
    })
}

/// A hex-string object (for raw `/Contents` values in tests).
pub fn hex_string(bytes: &[u8]) -> Object {
    Object::String(bytes.to_vec(), StringFormat::Hexadecimal)
}

#[doc(hidden)]
pub fn _number(x: f64) -> Object {
    number(x)
}

#[doc(hidden)]
pub fn _signer_type(_s: &dyn KeySigner) {}

#[doc(hidden)]
pub fn _ts_type(_s: &dyn TimeStamper) {}
