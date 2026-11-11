// Derived from pyHanko `sign/timestamps/dummy_client.py`,
// `sign/timestamps/common_utils.py` and `sign/timestamps/api.py` (MIT, see
// LICENSE-pyHanko).

//! A local time-stamping authority for tests (`DummyTimeStamper`), and
//! helpers for timestamp tokens.

use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos};
use const_oid::ObjectIdentifier as Oid;
use der::asn1::{Int, OctetString, SetOfVec};
use der::{Any, Decode, Encode};
use hanko_core::algorithms::DigestAlgorithm;
use hanko_core::asn1::oids;
use hanko_core::cert::Cert;
use hanko_core::errors::{HankoError, Result};
use hanko_core::sign::TimeStamper;
use hanko_core::time::Moment;
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::name::GeneralName;
use x509_tsp::{GeneralizedTimeNanos, MessageImprint, TspVersion, TstInfo};

use crate::attributes::{self, as_signing_certificate, ID_CT_TST_INFO, ID_SIGNED_DATA};
use crate::cms::attrs_to_set;
use crate::keys::PrivateKey;
use crate::signer::{default_signature_mechanism, digest_algorithm_id, sign_with_key};

/// Random nonce (`get_nonce`): a positive 64-bit integer.
pub fn get_nonce() -> Result<Vec<u8>> {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).map_err(|e| HankoError::Signing(format!("RNG failure: {e}")))?;
    buf[0] &= 0x7f;
    if buf[0] == 0 {
        buf[0] = 1;
    }
    Ok(buf.to_vec())
}

/// Policy OID used by the dummy TSA (`1.3.6.1.4.1.4146.2.2`).
pub const DUMMY_TSA_POLICY: Oid = Oid::new_unwrap("1.3.6.1.4.1.4146.2.2");

/// A time-stamping authority that signs locally (`DummyTimeStamper`).
#[derive(Debug, Clone)]
pub struct DummyTimeStamper {
    tsa_cert: Cert,
    tsa_key: PrivateKey,
    certs_to_embed: Vec<Cert>,
    /// Fixed time to put in the tokens; the current time if `None`.
    pub fixed_dt: Option<Moment>,
    /// Include a nonce in the request.
    pub include_nonce: bool,
    /// Sign the token with this digest instead of the imprint's.
    pub override_md: Option<DigestAlgorithm>,
}

impl DummyTimeStamper {
    /// Build a TSA from its certificate and key; `certs_to_embed` go into
    /// every token.
    pub fn new(tsa_cert: Cert, tsa_key: PrivateKey, certs_to_embed: Vec<Cert>) -> Self {
        Self {
            tsa_cert,
            tsa_key,
            certs_to_embed,
            fixed_dt: None,
            include_nonce: true,
            override_md: None,
        }
    }

    /// Use a fixed time.
    pub fn with_fixed_time(mut self, at: Moment) -> Self {
        self.fixed_dt = Some(at);
        self
    }

    /// The TSA certificate.
    pub fn tsa_cert(&self) -> &Cert {
        &self.tsa_cert
    }

    /// Answer a timestamp request (`request_tsa_response`); returns the
    /// DER `TimeStampToken`.
    pub fn respond(&self, imprint: &MessageImprint, nonce: Option<Int>) -> Result<Vec<u8>> {
        let md = match self.override_md {
            Some(md) => md,
            None => DigestAlgorithm::from_oid(&imprint.hash_algorithm.oid).ok_or_else(|| {
                HankoError::Unsupported(format!(
                    "digest algorithm {}",
                    imprint.hash_algorithm.oid
                ))
            })?,
        };
        let dt = self.fixed_dt.unwrap_or_else(Moment::now);
        let gen_time = GeneralizedTimeNanos::from_unix_duration(core::time::Duration::from_secs(
            u64::try_from(dt.unix_secs())
                .map_err(|_| HankoError::Signing("timestamp before 1970".into()))?,
        ))?;
        let tst_info = TstInfo {
            version: TspVersion::V1,
            policy: DUMMY_TSA_POLICY,
            message_imprint: imprint.clone(),
            serial_number: Int::new(&get_nonce()?)?,
            gen_time,
            accuracy: None,
            ordering: false,
            nonce,
            tsa: Some(GeneralName::DirectoryName(self.tsa_cert.subject().clone())),
            extensions: None,
        };
        let tst_der = tst_info.to_der()?;
        let signed_attrs = attrs_to_set(vec![
            attributes::content_type_attribute(ID_CT_TST_INFO)?,
            attributes::simple_attribute(oids::SIGNING_TIME, &attributes::utc_time(dt)?)?,
            attributes::simple_attribute(
                oids::AA_SIGNING_CERTIFICATE,
                &as_signing_certificate(&self.tsa_cert)?,
            )?,
            attributes::message_digest_attribute(&md.digest(&tst_der))?,
        ])?;
        let mech = if self.tsa_cert.public_key().algorithm.oid == oids::RSA_ENCRYPTION {
            // pyHanko uses `rsassa_pkcs1v15` (rsaEncryption) here.
            AlgorithmIdentifierOwned {
                oid: oids::RSA_ENCRYPTION,
                parameters: Some(Any::encode_from(&der::asn1::Null)?),
            }
        } else {
            default_signature_mechanism(&self.tsa_cert, md, false)?
        };
        let signature = sign_with_key(&self.tsa_key, &mech, &signed_attrs.to_der()?, md)?;
        let strict = x509_cert::Certificate::from_der(self.tsa_cert.der())?;
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
                issuer: strict.tbs_certificate().issuer().clone(),
                serial_number: strict.tbs_certificate().serial_number().clone(),
            }),
            digest_alg: digest_algorithm_id(md),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: mech,
            signature: OctetString::new(signature)?,
            unsigned_attrs: None,
        };
        let mut certs = SetOfVec::new();
        for c in self.certs_to_embed.iter().chain(std::iter::once(&self.tsa_cert)) {
            let choice =
                cms::cert::CertificateChoices::Certificate(x509_cert::Certificate::from_der(c.der())?);
            if !certs.iter().any(|x| x == &choice) {
                certs.insert(choice)?;
            }
        }
        let mut digest_algs = SetOfVec::new();
        digest_algs.insert(digest_algorithm_id(md))?;
        let mut infos = SetOfVec::new();
        infos.insert(signer_info)?;
        let sd = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: digest_algs,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_CT_TST_INFO,
                econtent: Some(Any::encode_from(&OctetString::new(tst_der)?)?),
            },
            certificates: Some(cms::signed_data::CertificateSet(certs)),
            crls: None,
            signer_infos: SignerInfos(infos),
        };
        Ok(ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::encode_from(&sd)?,
        }
        .to_der()?)
    }
}

impl TimeStamper for DummyTimeStamper {
    fn timestamp(&self, message_digest: &[u8], digest: DigestAlgorithm) -> Result<Vec<u8>> {
        let imprint = MessageImprint {
            hash_algorithm: digest_algorithm_id(digest),
            hashed_message: OctetString::new(message_digest)?,
        };
        let nonce = if self.include_nonce {
            Some(Int::new(&get_nonce()?)?)
        } else {
            None
        };
        self.respond(&imprint, nonce)
    }
}

/// Decode the `TSTInfo` of a timestamp token.
pub fn tst_info(token_der: &[u8]) -> Result<TstInfo> {
    let sd = crate::cms::decode_signed_data(token_der)?;
    if sd.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err(HankoError::Malformed("timestamp token without TSTInfo".into()));
    }
    let content = sd
        .encap_content_info
        .econtent
        .ok_or_else(|| HankoError::Malformed("timestamp token without content".into()))?
        .decode_as::<OctetString>()?;
    Ok(TstInfo::from_der(content.as_bytes())?)
}

/// The certificates embedded in a timestamp token (`extract_ts_certs`).
pub fn token_certs(token_der: &[u8]) -> Result<Vec<Cert>> {
    let sd = crate::cms::decode_signed_data(token_der)?;
    let mut out = Vec::new();
    if let Some(set) = sd.certificates {
        for c in set.0.iter() {
            if let cms::cert::CertificateChoices::Certificate(cert) = c {
                out.push(Cert::from_der(&cert.to_der()?)?);
            }
        }
    }
    Ok(out)
}

/// The `genTime` of a timestamp token.
pub fn token_time(token_der: &[u8]) -> Result<Moment> {
    let info = tst_info(token_der)?;
    Ok(Moment::from(info.gen_time.to_date_time()))
}

/// Re-export so callers do not need `x509-tsp`.
pub use x509_tsp::MessageImprint as TspMessageImprint;

#[doc(hidden)]
pub fn _content_info_type(der: &[u8]) -> Result<Oid> {
    Ok(ContentInfo::from_der(der)?.content_type)
}
