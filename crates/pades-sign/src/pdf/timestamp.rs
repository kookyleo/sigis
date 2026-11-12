// Derived from pyHanko `sign/signers/pdf_signer.py` (`PdfTimeStamper`,
// `timestamp_pdf`, `update_archival_timestamp_chain`,
// `TimestampDSSContentSettings`) and `sign/validation/dss.py`
// (`async_add_validation_info`) (MIT, see LICENSE-pyHanko).

//! Document timestamps and archival timestamp chains (PAdES B-LTA).

use std::sync::Arc;

use lopdf::Object;
use sigis_pdf::decode_limits::DecodeLimits;
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};
use sigis_pki_core::sign::TimeStamper;

use crate::cms::dummy_digest;
use crate::ltv::{validate_and_collect, ValidationInfo};
use crate::pdf::dss::{supply_dss_in_writer, DssContent};
use crate::pdf::embedded::{embedded_signatures, EmbeddedSig};
use crate::pdf::fields::{self, InvisSigSettings, NewFieldSettings};
use crate::pdf::seed::SigSeedSubFilter;
use crate::pdf::signer::{ensure_esic_ext, write_and_digest, SignatureObjectSpec};
use crate::pdf::util::text_string;
use crate::pdf::writer::{PdfOperationResult, PdfReopenState, PdfUpdate};
use crate::timestamps::token_certs;

/// DSS settings for document timestamps (`TimestampDSSContentSettings`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimestampDssSettings {
    /// Add VRI entries.
    pub include_vri: bool,
    /// Skip the DSS revision if nothing new would be added.
    pub skip_if_unneeded: bool,
    /// Update the DSS in the timestamp's revision, before the timestamp.
    pub update_before_ts: bool,
}

impl Default for TimestampDssSettings {
    fn default() -> Self {
        Self {
            include_vri: true,
            skip_if_unneeded: true,
            update_before_ts: false,
        }
    }
}

impl TimestampDssSettings {
    /// `assert_viable`.
    pub fn assert_viable(&self) -> Result<()> {
        if self.include_vri && self.update_before_ts {
            return Err(HankoError::Signing(
                "If VRI entries are to be included, DSS updates can only be performed after the timestamp in question was created.".into(),
            ));
        }
        Ok(())
    }
}

/// A random UUID (version 4), formatted.
pub fn uuid4() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| HankoError::Signing(format!("RNG failure: {e}")))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        h[0..4].concat(),
        h[4..6].concat(),
        h[6..8].concat(),
        h[8..10].concat(),
        h[10..16].concat()
    ))
}

/// The signer certificate and other certificates of a timestamp token.
pub fn token_signer(token: &[u8]) -> Result<(Cert, Vec<Cert>)> {
    let sd = crate::cms::decode_signed_data(token)?;
    let certs = token_certs(token)?;
    let si = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| HankoError::Malformed("timestamp token without signer".into()))?;
    let signer = match &si.sid {
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(isn) => certs
            .iter()
            .find(|c| c.issuer() == &isn.issuer && c.serial_bytes() == isn.serial_number.as_bytes())
            .cloned(),
        cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(_) => None,
    }
    .ok_or_else(|| HankoError::Malformed("timestamp signer certificate not embedded".into()))?;
    Ok((signer, certs))
}

/// Validation paths and revocation information for the TSA behind
/// `timestamper` (`TimeStamper.validation_paths`).
pub fn tsa_validation_info(
    timestamper: &dyn TimeStamper,
    md: DigestAlgorithm,
    ctx: &ValidationContext,
    info: &mut ValidationInfo,
) -> Result<()> {
    let token = timestamper.timestamp(&dummy_digest(md), md)?;
    let (signer, certs) = token_signer(&token)?;
    validate_and_collect(ctx, &signer, &certs, info).map_err(|e| {
        HankoError::Signing(format!("The TSA's certificate could not be validated: {e}"))
    })?;
    Ok(())
}

/// Appends document timestamps (`PdfTimeStamper`).
#[derive(Clone, Debug)]
pub struct PdfTimeStamper {
    /// The TSA.
    pub timestamper: Arc<dyn TimeStamper>,
    /// Field name; `Timestamp-<uuid>` if `None`.
    pub field_name: Option<String>,
    /// Widget settings.
    pub invis_settings: InvisSigSettings,
    /// `/TU` of the field.
    pub readable_field_name: String,
}

/// Options of [`PdfTimeStamper::timestamp_pdf`].
#[derive(Clone, Debug)]
pub struct TimestampOptions<'a> {
    /// Digest algorithm.
    pub md_algorithm: DigestAlgorithm,
    /// Context to validate the TSA and to collect DSS data.
    pub validation_context: Option<&'a ValidationContext>,
    /// Hex digits to reserve.
    pub bytes_reserved: Option<usize>,
    /// Already known validation information.
    pub validation_info: Option<ValidationInfo>,
    /// DSS settings.
    pub dss_settings: TimestampDssSettings,
    /// No safety margin in size estimates.
    pub tight_size_estimates: bool,
    /// Embed trust anchors in the DSS.
    pub embed_roots: bool,
    /// Extra DSS content to put into the timestamp's revision
    /// (`TOGETHER_WITH_NEXT_TS`).
    pub dss_with_ts: Option<(Option<Vec<u8>>, ValidationInfo)>,
    /// Password of an encrypted document (`file_credential`).
    pub password: Option<Vec<u8>>,
    /// Limits for a newly opened input.
    pub decode_limits: DecodeLimits,
    /// Strict parsing for an input without an inherited reader state.
    pub strict: bool,
    /// Existing limits, budget, authentication and strictness; authoritative if set.
    pub reopen_state: Option<PdfReopenState>,
}

impl<'a> TimestampOptions<'a> {
    /// Defaults for `md`.
    pub fn new(md: DigestAlgorithm) -> Self {
        Self {
            md_algorithm: md,
            validation_context: None,
            bytes_reserved: None,
            validation_info: None,
            dss_settings: TimestampDssSettings::default(),
            tight_size_estimates: false,
            embed_roots: true,
            dss_with_ts: None,
            password: None,
            decode_limits: DecodeLimits::default(),
            strict: true,
            reopen_state: None,
        }
    }
}

impl PdfTimeStamper {
    /// A timestamper with pyHanko's defaults.
    pub fn new(timestamper: Arc<dyn TimeStamper>) -> Self {
        Self {
            timestamper,
            field_name: None,
            invis_settings: InvisSigSettings::default(),
            readable_field_name: "Timestamp".into(),
        }
    }

    /// Append a document timestamp to `pdf` (`timestamp_pdf`).
    pub fn timestamp_pdf(&self, pdf: &[u8], opts: &TimestampOptions<'_>) -> Result<Vec<u8>> {
        Ok(self.timestamp_pdf_with_state(pdf, opts)?.pdf)
    }

    /// Append a timestamp without discarding its authenticated reader state.
    pub fn timestamp_pdf_with_state(
        &self,
        pdf: &[u8],
        opts: &TimestampOptions<'_>,
    ) -> Result<PdfOperationResult> {
        timestamp_pdf_full(
            pdf,
            self.timestamper.as_ref(),
            self.field_name.clone(),
            self.invis_settings,
            &self.readable_field_name,
            opts,
        )
    }

    /// Renew the archival timestamp chain (`update_archival_timestamp_chain`):
    /// add validation information for the latest document timestamp to the
    /// DSS and append a new document timestamp in the same revision.
    pub fn update_archival_timestamp_chain(
        &self,
        pdf: &[u8],
        ctx: &ValidationContext,
        default_md: DigestAlgorithm,
    ) -> Result<Vec<u8>> {
        update_archival_chain_with(pdf, self.timestamper.as_ref(), ctx, default_md)
    }

    /// Renew an archival chain using the caller's remaining document budget.
    pub fn update_archival_timestamp_chain_with_state(
        &self,
        pdf: &[u8],
        ctx: &ValidationContext,
        default_md: DigestAlgorithm,
        state: PdfReopenState,
    ) -> Result<PdfOperationResult> {
        update_archival_chain_with_state(pdf, self.timestamper.as_ref(), ctx, default_md, state)
    }
}

/// [`PdfTimeStamper::timestamp_pdf`] with a borrowed timestamper and
/// default field settings.
pub fn timestamp_pdf_with(
    pdf: &[u8],
    ts: &dyn TimeStamper,
    field_name: Option<String>,
    opts: &TimestampOptions<'_>,
) -> Result<Vec<u8>> {
    Ok(timestamp_pdf_with_state(pdf, ts, field_name, opts)?.pdf)
}

/// Timestamp an input with explicit state propagation.
pub fn timestamp_pdf_with_state(
    pdf: &[u8],
    ts: &dyn TimeStamper,
    field_name: Option<String>,
    opts: &TimestampOptions<'_>,
) -> Result<PdfOperationResult> {
    timestamp_pdf_full(
        pdf,
        ts,
        field_name,
        InvisSigSettings::default(),
        "Timestamp",
        opts,
    )
}

/// [`PdfTimeStamper::update_archival_timestamp_chain`] with a borrowed
/// timestamper.
pub fn update_archival_chain_with(
    pdf: &[u8],
    ts: &dyn TimeStamper,
    ctx: &ValidationContext,
    default_md: DigestAlgorithm,
) -> Result<Vec<u8>> {
    let update = PdfUpdate::new(pdf)?;
    Ok(update_archival_chain_from_update(pdf, ts, ctx, default_md, update)?.pdf)
}

/// Borrowed TSA archival update preserving the inherited reader state.
pub fn update_archival_chain_with_state(
    pdf: &[u8],
    ts: &dyn TimeStamper,
    ctx: &ValidationContext,
    default_md: DigestAlgorithm,
    state: PdfReopenState,
) -> Result<PdfOperationResult> {
    let update = PdfUpdate::open_with_state(pdf, state)?;
    update_archival_chain_from_update(pdf, ts, ctx, default_md, update)
}

fn update_archival_chain_from_update(
    pdf: &[u8],
    ts: &dyn TimeStamper,
    ctx: &ValidationContext,
    default_md: DigestAlgorithm,
    update: PdfUpdate,
) -> Result<PdfOperationResult> {
    let sigs = embedded_signatures(&update)?;
    let last_ts = sigs.iter().rev().find(|s| s.is_doc_timestamp).cloned();
    let mut opts = TimestampOptions {
        validation_context: Some(ctx),
        reopen_state: Some(update.state()),
        ..TimestampOptions::new(default_md)
    };
    if let Some(ts_sig) = last_ts {
        opts.md_algorithm = token_md(ts_sig.cms()).unwrap_or(default_md);
        let mut info = ValidationInfo::default();
        collect_signature_info(ts_sig.cms(), ctx, false, &mut info)?;
        opts.dss_with_ts = Some((Some(ts_sig.contents.clone()), info));
    }
    timestamp_pdf_with_state(pdf, ts, None, &opts)
}

fn timestamp_pdf_full(
    pdf: &[u8],
    ts: &dyn TimeStamper,
    field_name_opt: Option<String>,
    invis: InvisSigSettings,
    readable_field_name: &str,
    opts: &TimestampOptions<'_>,
) -> Result<PdfOperationResult> {
    {
        let mut update = match &opts.reopen_state {
            Some(state) => PdfUpdate::open_with_state(pdf, state.clone())?,
            None => PdfUpdate::open_with_limits(
                pdf,
                opts.password.as_deref(),
                opts.decode_limits.clone(),
                opts.strict,
            )?,
        };
        let mac_registry = crate::pdf::mac::PdfMacSessions::default();
        let mac_session = match update.security_handler() {
            Some(handler) => mac_registry.begin(handler, opts.md_algorithm.name())?,
            None => None,
        };
        ensure_esic_ext(&mut update)?;
        let md = opts.md_algorithm;
        let mut vinfo = opts.validation_info.clone().unwrap_or_default();
        if let Some(ctx) = opts.validation_context {
            tsa_validation_info(ts, md, ctx, &mut vinfo)?;
            opts.dss_settings.assert_viable()?;
            if opts.dss_settings.update_before_ts {
                supply_dss_in_writer(
                    &mut update,
                    &DssContent {
                        sig_contents: None,
                        paths: vinfo.paths.clone(),
                        ocsps: vinfo.ocsps.clone(),
                        crls: vinfo.crls.clone(),
                        embed_roots: opts.embed_roots,
                        ..Default::default()
                    },
                )?;
            }
        }
        if let Some((sig_contents, info)) = &opts.dss_with_ts {
            supply_dss_in_writer(
                &mut update,
                &DssContent {
                    sig_contents: sig_contents.as_deref(),
                    paths: info.paths.clone(),
                    ocsps: info.ocsps.clone(),
                    crls: info.crls.clone(),
                    embed_roots: opts.embed_roots,
                    ..Default::default()
                },
            )?;
        }
        let bytes_reserved = match opts.bytes_reserved {
            Some(b) => b,
            None => {
                let test_digest = dummy_digest(md);
                let test_token = ts.timestamp(&test_digest, md)?;
                let test_token = match &mac_session {
                    Some(mac) => mac.attach_to_cms(&test_digest, &test_token, true)?,
                    None => test_token,
                };
                let test_len = test_token.len() * 2;
                if opts.tight_size_estimates {
                    test_len
                } else {
                    test_len + 2 * (test_len / 4)
                }
            }
        };
        let field_name = match field_name_opt {
            Some(n) => n,
            None => format!("Timestamp-{}", uuid4()?),
        };
        let page = update.page(0)?;
        let settings = NewFieldSettings {
            bbox: None,
            page: Some(page),
            separate_annotation: false,
            invis,
            visible: Default::default(),
        };
        let (created, field_id) =
            fields::prepare_sig_field(&mut update, &field_name, false, &settings)?;
        if created {
            update
                .get_dict_mut(field_id)?
                .set("TU", text_string(readable_field_name));
        }
        fields::ensure_sig_flags(&mut update, true)?;
        let spec = SignatureObjectSpec {
            subfilter: Some(SigSeedSubFilter::EtsiRfc3161),
            ..Default::default()
        };
        let sig_id = update.add(Object::Dictionary(spec.to_dict(true)));
        if mac_session.is_some() {
            crate::pdf::signer::register_extension(
                &mut update,
                "ISO_",
                32004,
                true,
                "2.0",
                Some(":2024"),
                None,
            )?;
            let mut auth = lopdf::Dictionary::new();
            auth.set("MACLocation", crate::pdf::util::name("AttachedToSig"));
            auth.set("SigObjRef", Object::Reference(sig_id));
            update.set_auth_code(Object::Dictionary(auth));
        }
        update
            .get_dict_mut(field_id)?
            .set("V", Object::Reference(sig_id));
        update.update_info(
            &crate::pdf::util::pdf_date(sigis_pki_core::time::Moment::now()),
            crate::pdf::signer::PRODUCER,
        )?;
        let prepared = write_and_digest(&mut update, sig_id, bytes_reserved, md)?;
        let token = ts.timestamp(&prepared.document_digest, md)?;
        let token = match &mac_session {
            Some(mac) => mac.attach_to_cms(&prepared.document_digest, &token, false)?,
            None => token,
        };
        let state = prepared.reopen_state.clone();
        let reserved = prepared.reserved_region_end - prepared.reserved_region_start - 2;
        let mut sig_contents = token.clone();
        sig_contents.resize(reserved / 2, 0);
        let out = prepared.fill_with_cms(&token)?;
        if opts.validation_context.is_some() && !opts.dss_settings.update_before_ts {
            let vri = opts
                .dss_settings
                .include_vri
                .then_some(sig_contents.as_slice());
            return crate::pdf::dss::add_dss_with_state(
                &out,
                &DssContent {
                    sig_contents: vri,
                    paths: vinfo.paths.clone(),
                    ocsps: vinfo.ocsps.clone(),
                    crls: vinfo.crls.clone(),
                    embed_roots: opts.embed_roots,
                    ..Default::default()
                },
                !opts.dss_settings.skip_if_unneeded,
                state,
            );
        }
        PdfOperationResult::from_output(out, state)
    }
}

/// The digest algorithm of the signer of a CMS object.
pub fn token_md(cms: &[u8]) -> Option<DigestAlgorithm> {
    let sd = crate::cms::decode_signed_data(cms).ok()?;
    let si = sd.signer_infos.0.iter().next()?;
    DigestAlgorithm::from_oid(&si.digest_alg.oid)
}

/// Collect and embed validation information for one signature
/// (`async_add_validation_info`). With `add_vri_entry`, the VRI key is
/// computed as pyHanko does here: over the hexadecimal text of the
/// `/Contents` value.
pub fn add_validation_info_for(
    pdf: &[u8],
    sig: &EmbeddedSig,
    ctx: &ValidationContext,
    include_timestamps: bool,
    add_vri_entry: bool,
    force_write: bool,
) -> Result<Vec<u8>> {
    let state = PdfUpdate::new(pdf)?.state();
    Ok(add_validation_info_for_with_state(
        pdf,
        sig,
        ctx,
        include_timestamps,
        add_vri_entry,
        force_write,
        state,
    )?
    .pdf)
}

/// Collect and embed signature evidence using the inherited reader state.
pub fn add_validation_info_for_with_state(
    pdf: &[u8],
    sig: &EmbeddedSig,
    ctx: &ValidationContext,
    include_timestamps: bool,
    add_vri_entry: bool,
    force_write: bool,
    state: PdfReopenState,
) -> Result<PdfOperationResult> {
    let mut info = ValidationInfo::default();
    collect_signature_info(sig.cms(), ctx, include_timestamps, &mut info)?;
    let hex: Vec<u8> = sig
        .contents
        .iter()
        .flat_map(|b| format!("{b:02x}").into_bytes())
        .collect();
    crate::pdf::dss::add_dss_with_state(
        pdf,
        &DssContent {
            sig_contents: add_vri_entry.then_some(hex.as_slice()),
            paths: info.paths,
            ocsps: info.ocsps,
            crls: info.crls,
            embed_roots: true,
            ..Default::default()
        },
        force_write,
        state,
    )
}

/// Validate the signer of a CMS object (and of its timestamps), collecting
/// validation information (`collect_validation_info`).
pub fn collect_signature_info(
    cms_der: &[u8],
    ctx: &ValidationContext,
    include_timestamps: bool,
    info: &mut ValidationInfo,
) -> Result<()> {
    let (signer, certs) = token_signer(cms_der)?;
    validate_and_collect(ctx, &signer, &certs, info)?;
    if include_timestamps {
        let sd = crate::cms::decode_signed_data(cms_der)?;
        if let Some(si) = sd.signer_infos.0.iter().next() {
            let mut tokens = Vec::new();
            let attr_sets = [si.unsigned_attrs.as_ref(), si.signed_attrs.as_ref()];
            for attrs in attr_sets.into_iter().flatten() {
                for a in attrs.iter() {
                    if a.oid == sigis_pki_core::asn1::oids::AA_SIGNATURE_TIME_STAMP_TOKEN
                        || a.oid == crate::attributes::CONTENT_TIME_STAMP
                    {
                        for v in a.values.iter() {
                            tokens.push(der::Encode::to_der(v)?);
                        }
                    }
                }
            }
            for t in tokens {
                let (tsa, tcerts) = token_signer(&t)?;
                validate_and_collect(ctx, &tsa, &tcerts, info)?;
            }
        }
    }
    Ok(())
}
