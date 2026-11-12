// Derived from pyHanko `sign/signers/pdf_cms.py` (`Signer.signed_attrs`,
// `unsigned_attrs`, `signer_info`, `_package_signature`, `async_sign`,
// `async_sign_prescribed_attributes`, `async_sign_general_data`, the
// attribute provider specs) (MIT, see LICENSE-pyHanko).

//! CMS `SignedData` assembly (`pyhanko.sign.signers.pdf_cms`).
//!
//! The containers are built from the `cms` crate types directly instead of
//! its `SignedDataBuilder`, because the signature comes from an external
//! [`KeySigner`] (software key, PKCS#11, CSC) and pyHanko's attribute set and
//! size estimation (dry run) must be reproduced.

use cms::cert::IssuerAndSerialNumber;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::ObjectIdentifier as Oid;
use der::asn1::{OctetString, SetOfVec};
use der::{Any, Decode, Encode};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::oids;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};
use sigis_pki_core::sign::{KeySigner, TimeStamper};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;

use crate::attributes::{
    self, as_signing_certificate_v2, CmsAlgorithmProtection, CmsSignedAttributes,
    ADOBE_REVOCATION_INFO_ARCHIVAL, CONTENT_TIME_STAMP, ID_DATA, ID_SIGNED_DATA,
    SIGNER_ATTRIBUTES_V2,
};
use crate::signer::implied_digest;

fn signing_error(msg: impl Into<String>) -> HankoError {
    HankoError::Signing(msg.into())
}

/// Which attribute profile to use (`Signer._signed_attr_provider_spec`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrProfile {
    /// `GenericCMSSignedAttributeProviderSpec`.
    GenericCms,
    /// `GenericPdfSignedAttributeProviderSpec` (`adbe.pkcs7.detached`).
    GenericPdf,
    /// `CAdESSignedAttributeProviderSpec` with `is_pades`.
    Cades {
        /// PAdES: no `signingTime`.
        is_pades: bool,
    },
}

/// Options of the CMS signer that pyHanko keeps on `Signer`.
#[derive(Clone, Debug)]
pub struct CmsSignerOptions {
    /// Embed self-signed certificates of the registry (`embed_roots`).
    pub embed_roots: bool,
    /// DER-encoded attribute certificates to embed (`attribute_certs`).
    pub attribute_certs: Vec<Vec<u8>>,
}

impl Default for CmsSignerOptions {
    fn default() -> Self {
        Self {
            embed_roots: true,
            attribute_certs: Vec::new(),
        }
    }
}

/// A CMS signer over a [`KeySigner`].
#[derive(Clone, Copy, Debug)]
pub struct CmsSigner<'a> {
    /// The key.
    pub signer: &'a dyn KeySigner,
    /// Options.
    pub options: &'a CmsSignerOptions,
}

/// Placeholder value of the raw signature in dry-run mode.
fn placeholder_signature(cert: &Cert) -> Vec<u8> {
    let spki = cert.public_key();
    let len = match spki.algorithm.oid {
        oids::RSA_ENCRYPTION | oids::RSASSA_PSS => {
            sigis_pki_core::algorithms::rsa_key_size(&spki).map_or(512, |b| b.div_ceil(8))
        }
        oids::EC_PUBLIC_KEY => {
            // DER ECDSA-Sig-Value of maximal size for the curve.
            let field = match spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<Oid>().ok())
            {
                Some(oids::SECP384R1) => 48,
                Some(oids::SECP521R1) => 66,
                _ => 32,
            };
            2 * (field + 1) + 9
        }
        oids::ED25519 => 64,
        oids::ED448 => 114,
        oids::ML_DSA_44 => 2420,
        oids::ML_DSA_65 => 3309,
        oids::ML_DSA_87 => 4627,
        _ => 512,
    };
    vec![0u8; len]
}

/// Dummy digest used for dry-run timestamps (`dummy_digest`).
pub fn dummy_digest(md: DigestAlgorithm) -> Vec<u8> {
    md.digest(b"dummy")
}

impl CmsSigner<'_> {
    /// The signature mechanism for `digest`, checking that it is consistent
    /// with the digest (`_check_digest_algorithm`).
    pub fn mechanism(&self, digest: DigestAlgorithm) -> Result<AlgorithmIdentifierOwned> {
        let mech = self.signer.signature_algorithm(digest)?;
        if let Some(implied) = implied_digest(&mech) {
            if implied != digest {
                return Err(signing_error(format!(
                    "Selected signature mechanism specifies message digest {}, but {} was requested.",
                    implied.name(),
                    digest.name()
                )));
            }
        }
        Ok(mech)
    }

    /// Format the signed attributes (`Signer.signed_attrs`).
    #[allow(clippy::too_many_arguments)]
    pub fn signed_attrs(
        &self,
        data_digest: &[u8],
        digest: DigestAlgorithm,
        settings: &CmsSignedAttributes,
        profile: AttrProfile,
        content_type: Oid,
        timestamper: Option<&dyn TimeStamper>,
        dry_run: bool,
    ) -> Result<Vec<Attribute>> {
        let cert = self.signer.signing_cert();
        let mut attrs = vec![
            attributes::content_type_attribute(content_type)?,
            attributes::message_digest_attribute(data_digest)?,
        ];
        attrs.push(attributes::simple_attribute(
            oids::AA_SIGNING_CERTIFICATE_V2,
            &as_signing_certificate_v2(cert, DigestAlgorithm::Sha256)?,
        )?);
        let signing_time = match profile {
            AttrProfile::GenericCms | AttrProfile::GenericPdf => settings.signing_time,
            AttrProfile::Cades { is_pades: true } => None,
            // CAdES requires signingTime.
            AttrProfile::Cades { is_pades: false } => {
                Some(settings.signing_time.unwrap_or_else(sigis_pki_core::time::Moment::now))
            }
        };
        if let Some(t) = signing_time {
            attrs.push(attributes::simple_attribute(
                oids::SIGNING_TIME,
                &attributes::utc_time(t)?,
            )?);
        }
        if let Some(cades) = &settings.cades_signed_attrs {
            if cades.timestamp_content {
                if let Some(ts) = timestamper {
                    let token = if dry_run {
                        ts.timestamp(&dummy_digest(digest), digest)?
                    } else {
                        ts.timestamp(data_digest, digest)?
                    };
                    attrs.push(attributes::raw_attribute(CONTENT_TIME_STAMP, &token)?);
                }
            }
            if let Some(policy) = &cades.signature_policy_identifier {
                attrs.push(attributes::simple_attribute(oids::AA_ETS_SIG_POLICY_ID, policy)?);
            }
            if let Some(ct) = &cades.commitment_type {
                attrs.push(attributes::simple_attribute(oids::AA_ETS_COMMITMENT_TYPE, ct)?);
            }
            if let Some(sa) = &cades.signer_attributes {
                attrs.push(attributes::simple_attribute(
                    SIGNER_ATTRIBUTES_V2,
                    &sa.to_asn1()?,
                )?);
            }
        }
        if matches!(profile, AttrProfile::GenericCms | AttrProfile::GenericPdf) {
            let mech = self.signer.signature_algorithm(digest)?;
            attrs.push(attributes::simple_attribute(
                attributes::CMS_ALGORITHM_PROTECTION,
                &CmsAlgorithmProtection {
                    digest_algorithm: crate::signer::digest_algorithm_id_for(digest, &mech),
                    signature_algorithm: Some(mech),
                    mac_algorithm: None,
                },
            )?);
        }
        if profile == AttrProfile::GenericPdf {
            if let Some(revinfo) = &settings.adobe_revinfo_attr {
                attrs.push(attributes::simple_attribute(
                    ADOBE_REVOCATION_INFO_ARCHIVAL,
                    revinfo,
                )?);
            }
        }
        Ok(attrs)
    }

    /// Sign prescribed signed attributes and package the result
    /// (`async_sign_prescribed_attributes`); returns the DER `ContentInfo`.
    pub fn sign_prescribed_attributes(
        &self,
        digest: DigestAlgorithm,
        signed_attrs: Vec<Attribute>,
        cms_version: CmsVersion,
        timestamper: Option<&dyn TimeStamper>,
        dry_run: bool,
        encap: Option<EncapsulatedContentInfo>,
    ) -> Result<Vec<u8>> {
        let mech = self.mechanism(digest)?;
        let signed_set = attrs_to_set(signed_attrs)?;
        let to_sign = signed_set.to_der()?;
        let signature = if dry_run {
            placeholder_signature(self.signer.signing_cert())
        } else {
            self.signer.sign_raw(&to_sign, digest)?
        };
        let mut unsigned = Vec::new();
        if let Some(ts) = timestamper {
            let token = if dry_run {
                ts.timestamp(&dummy_digest(digest), digest)?
            } else {
                ts.timestamp(&digest.digest(&signature), digest)?
            };
            unsigned.push(attributes::raw_attribute(
                oids::AA_SIGNATURE_TIME_STAMP_TOKEN,
                &token,
            )?);
        }
        let unsigned = if unsigned.is_empty() {
            None
        } else {
            Some(attrs_to_set(unsigned)?)
        };
        self.package(digest, mech, cms_version, signed_set, signature, unsigned, encap)
    }

    #[allow(clippy::too_many_arguments)]
    fn package(
        &self,
        digest: DigestAlgorithm,
        mech: AlgorithmIdentifierOwned,
        cms_version: CmsVersion,
        signed_attrs: SetOfVec<Attribute>,
        signature: Vec<u8>,
        unsigned_attrs: Option<SetOfVec<Attribute>>,
        encap: Option<EncapsulatedContentInfo>,
    ) -> Result<Vec<u8>> {
        let cert = self.signer.signing_cert();
        let strict = x509_cert::Certificate::from_der(cert.der())?;
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: strict.tbs_certificate().issuer().clone(),
            serial_number: strict.tbs_certificate().serial_number().clone(),
        });
        let digest_alg = crate::signer::digest_algorithm_id_for(digest, &mech);
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid,
            digest_alg: digest_alg.clone(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: mech,
            signature: OctetString::new(signature)?,
            unsigned_attrs,
        };
        let mut certs: SetOfVec<Any> = SetOfVec::new();
        let mut add = |der: &[u8]| -> Result<()> {
            let any = Any::from_der(der)?;
            if !certs.iter().any(|x| x == &any) {
                certs.insert(any)?;
            }
            Ok(())
        };
        for c in self.signer.cert_chain() {
            if self.options.embed_roots || !is_self_signed(c) {
                add(c.der())?;
            }
        }
        add(cert.der())?;
        for ac in &self.options.attribute_certs {
            // v2AttrCert [2] IMPLICIT AttributeCertificateV2
            let mut tagged = ac.clone();
            if tagged.first() != Some(&0x30) {
                return Err(HankoError::Malformed("attribute certificate is not a SEQUENCE".into()));
            }
            tagged[0] = 0xA2;
            add(&tagged)?;
        }
        let mut digest_algs = SetOfVec::new();
        digest_algs.insert(digest_alg)?;
        let mut infos = SetOfVec::new();
        infos.insert(signer_info)?;
        let sd = SignedDataOut {
            version: cms_version,
            digest_algorithms: digest_algs,
            encap_content_info: encap.unwrap_or(EncapsulatedContentInfo {
                econtent_type: ID_DATA,
                econtent: None,
            }),
            certificates: Some(certs),
            signer_infos: SignerInfos(infos),
        };
        let ci = ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::encode_from(&sd)?,
        };
        Ok(ci.to_der()?)
    }

    /// Produce a CMS signature from a digest (`Signer.async_sign`).
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        data_digest: &[u8],
        digest: DigestAlgorithm,
        settings: &CmsSignedAttributes,
        profile: AttrProfile,
        timestamper: Option<&dyn TimeStamper>,
        dry_run: bool,
        encap: Option<EncapsulatedContentInfo>,
    ) -> Result<Vec<u8>> {
        let content_type = encap.as_ref().map_or(ID_DATA, |e| e.econtent_type);
        let attrs = self.signed_attrs(
            data_digest,
            digest,
            settings,
            profile,
            content_type,
            timestamper,
            dry_run,
        )?;
        let version = cms_version(content_type, !self.options.attribute_certs.is_empty());
        self.sign_prescribed_attributes(digest, attrs, version, timestamper, dry_run, encap)
    }

    /// Sign arbitrary data (`Signer.async_sign_general_data`).
    pub fn sign_general_data(
        &self,
        data: &[u8],
        digest: DigestAlgorithm,
        detached: bool,
        use_cades: bool,
        timestamper: Option<&dyn TimeStamper>,
        settings: &CmsSignedAttributes,
    ) -> Result<Vec<u8>> {
        let data_digest = digest.digest(data);
        let encap = if detached {
            None
        } else {
            Some(EncapsulatedContentInfo {
                econtent_type: ID_DATA,
                econtent: Some(Any::encode_from(&OctetString::new(data)?)?),
            })
        };
        let profile = if use_cades {
            AttrProfile::Cades { is_pades: false }
        } else {
            AttrProfile::GenericCms
        };
        self.sign(&data_digest, digest, settings, profile, timestamper, false, encap)
    }
}

/// `SignedData` for encoding, with the certificate set kept as raw
/// `CertificateChoices` so that attribute certificates (`[2]`) can be
/// embedded (the `cms` crate only models `certificate` and `other`).
#[derive(der::Sequence)]
struct SignedDataOut {
    version: CmsVersion,
    digest_algorithms: SetOfVec<AlgorithmIdentifierOwned>,
    encap_content_info: EncapsulatedContentInfo,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    certificates: Option<SetOfVec<Any>>,
    signer_infos: SignerInfos,
}

/// CMS version for a content type (`_cms_version`).
pub fn cms_version(content_type: Oid, has_attribute_certs: bool) -> CmsVersion {
    if has_attribute_certs {
        CmsVersion::V4
    } else if content_type == ID_DATA {
        CmsVersion::V1
    } else {
        CmsVersion::V3
    }
}

/// Collect attributes into a DER `SET OF`, merging values of attributes with
/// the same type (`format_attributes`).
pub fn attrs_to_set(attrs: Vec<Attribute>) -> Result<SetOfVec<Attribute>> {
    let mut merged: Vec<Attribute> = Vec::new();
    for a in attrs {
        if let Some(existing) = merged.iter_mut().find(|m| m.oid == a.oid) {
            for v in a.values.iter() {
                existing.values.insert(v.clone())?;
            }
        } else {
            merged.push(a);
        }
    }
    let mut set = SetOfVec::new();
    for a in merged {
        set.insert(a)?;
    }
    Ok(set)
}

fn is_self_signed(cert: &Cert) -> bool {
    cert.is_self_issued()
        && sigis_pki_core::algorithms::validate_signature(
            cert.decoded().signature().raw_bytes(),
            &cert.decoded().tbs_certificate().to_der().unwrap_or_default(),
            &cert.public_key(),
            cert.decoded().signature_algorithm(),
            &Default::default(),
        )
        .is_ok()
}

/// Sign `data` and return a DER `ContentInfo` (`Signer.sign_general_data`).
pub fn sign_general_data(
    data: &[u8],
    signer: &dyn KeySigner,
    digest: DigestAlgorithm,
    detached: bool,
    timestamper: Option<&dyn TimeStamper>,
) -> Result<Vec<u8>> {
    let options = CmsSignerOptions::default();
    CmsSigner {
        signer,
        options: &options,
    }
    .sign_general_data(
        data,
        digest,
        detached,
        false,
        timestamper,
        &CmsSignedAttributes::default(),
    )
}

/// Decode a DER `ContentInfo` holding `SignedData`.
pub fn decode_signed_data(der: &[u8]) -> Result<SignedData> {
    let ci = ContentInfo::from_der(der)?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(HankoError::Malformed(format!(
            "expected signedData, got {}",
            ci.content_type
        )));
    }
    Ok(ci.content.decode_as()?)
}
