// Derived from pyHanko `sign/signers/pdf_cms.py` (`Signer`, `SimpleSigner`,
// `select_suitable_signing_md`) and `sign/general.py`
// (`optimal_pss_params`, `get_cms_hash_algo_for_mechanism`) (MIT, see
// LICENSE-pyHanko).

//! Signers: key holders that produce raw signatures (`SimpleSigner`), and the
//! choice of signature mechanism and digest.

use der::{Any, Decode, Encode};
use hanko_core::algorithms::{DigestAlgorithm, RsaPssParams, SignatureMechanism};
use hanko_core::asn1::oids;
use hanko_core::cert::Cert;
use hanko_core::errors::{HankoError, Result};
use hanko_core::sign::KeySigner;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::keys::{self, PrivateKey};

fn signing_error(msg: impl Into<String>) -> HankoError {
    HankoError::Signing(msg.into())
}

/// A software key held in memory (`SimpleSigner`).
#[derive(Debug, Clone)]
pub struct SimpleSigner {
    pub(crate) key: PrivateKey,
    pub(crate) cert: Cert,
    pub(crate) chain: Vec<Cert>,
    /// Explicit signature mechanism (`signature_mechanism`); if `None`, it
    /// is derived from the certificate's key.
    pub signature_mechanism: Option<AlgorithmIdentifierOwned>,
    /// Prefer RSASSA-PSS over PKCS#1 v1.5 for RSA keys (`prefer_pss`).
    pub prefer_pss: bool,
}

impl SimpleSigner {
    /// Build from a decoded key, its certificate and other certificates
    /// (`cert_registry`).
    pub fn new(key: PrivateKey, cert: Cert, chain: Vec<Cert>) -> Result<Self> {
        if key.public_key_info()? != cert.public_key() {
            return Err(signing_error(
                "the private key does not match the signer's certificate",
            ));
        }
        Ok(Self {
            key,
            cert,
            chain,
            signature_mechanism: None,
            prefer_pss: false,
        })
    }

    /// Load from a PKCS#8 private key (DER) and its certificate chain.
    pub fn from_pkcs8_der(key_der: &[u8], cert: Cert, chain: Vec<Cert>) -> Result<Self> {
        Self::new(PrivateKey::from_pkcs8_der(key_der)?, cert, chain)
    }

    /// Load from a PKCS#12 file (`load_pkcs12_data`).
    pub fn from_pkcs12(data: &[u8], passphrase: Option<&[u8]>) -> Result<Self> {
        Self::from_pkcs12_with_certs(data, passphrase, Vec::new())
    }

    /// Load from a PKCS#12 file, adding `other_certs` to the registry.
    pub fn from_pkcs12_with_certs(
        data: &[u8],
        passphrase: Option<&[u8]>,
        other_certs: Vec<Cert>,
    ) -> Result<Self> {
        let contents = crate::pkcs12::load_pkcs12(data, passphrase)?;
        let key = contents
            .key
            .ok_or_else(|| HankoError::Malformed("PKCS#12 data contains no private key".into()))?;
        let cert = contents.cert.ok_or_else(|| {
            HankoError::Malformed("PKCS#12 data contains no certificate for the key".into())
        })?;
        let mut chain = contents.other_certs;
        for c in other_certs {
            if !chain.contains(&c) {
                chain.push(c);
            }
        }
        Self::new(key, cert, chain)
    }

    /// Load from PEM / DER files' contents (`SimpleSigner.load`).
    pub fn load(
        key_data: &[u8],
        cert_data: &[u8],
        key_passphrase: Option<&[u8]>,
        other_certs: Vec<Cert>,
    ) -> Result<Self> {
        let key = keys::load_private_key_from_pemder_data(key_data, key_passphrase)?;
        let cert = keys::load_cert_from_pemder_data(cert_data)?;
        Self::new(key, cert, other_certs)
    }

    /// Set an explicit signature mechanism.
    pub fn with_signature_mechanism(mut self, mech: AlgorithmIdentifierOwned) -> Self {
        self.signature_mechanism = Some(mech);
        self
    }

    /// Prefer RSASSA-PSS.
    pub fn with_prefer_pss(mut self, prefer_pss: bool) -> Self {
        self.prefer_pss = prefer_pss;
        self
    }

    /// The private key.
    pub fn key(&self) -> &PrivateKey {
        &self.key
    }
}

impl KeySigner for SimpleSigner {
    fn signing_cert(&self) -> &Cert {
        &self.cert
    }

    fn cert_chain(&self) -> &[Cert] {
        &self.chain
    }

    fn signature_algorithm(&self, digest: DigestAlgorithm) -> Result<AlgorithmIdentifierOwned> {
        if let Some(m) = &self.signature_mechanism {
            return Ok(m.clone());
        }
        default_signature_mechanism(&self.cert, digest, self.prefer_pss)
    }

    fn sign_raw(&self, data: &[u8], digest: DigestAlgorithm) -> Result<Vec<u8>> {
        let mech = self.signature_algorithm(digest)?;
        sign_with_key(&self.key, &mech, data, digest)
    }
}

/// The default signature mechanism for a certificate's key and a digest
/// (`Signer.get_signature_mechanism_for_digest`).
pub fn default_signature_mechanism(
    cert: &Cert,
    digest: DigestAlgorithm,
    prefer_pss: bool,
) -> Result<AlgorithmIdentifierOwned> {
    let spki = cert.public_key();
    let null = || Any::encode_from(&der::asn1::Null).ok();
    let (oid, parameters) = match spki.algorithm.oid {
        oids::RSA_ENCRYPTION if prefer_pss => {
            (oids::RSASSA_PSS, Some(Any::encode_from(&optimal_pss_params(&spki, digest)?)?))
        }
        oids::RSA_ENCRYPTION => (
            match digest {
                DigestAlgorithm::Sha1 => oids::SHA1_WITH_RSA,
                DigestAlgorithm::Sha224 => oids::SHA224_WITH_RSA,
                DigestAlgorithm::Sha256 => oids::SHA256_WITH_RSA,
                DigestAlgorithm::Sha384 => oids::SHA384_WITH_RSA,
                DigestAlgorithm::Sha512 => oids::SHA512_WITH_RSA,
            },
            null(),
        ),
        oids::RSASSA_PSS => (oids::RSASSA_PSS, Some(Any::encode_from(&optimal_pss_params(&spki, digest)?)?)),
        oids::EC_PUBLIC_KEY => (
            match digest {
                DigestAlgorithm::Sha1 => oids::ECDSA_WITH_SHA1,
                DigestAlgorithm::Sha224 => oids::ECDSA_WITH_SHA224,
                DigestAlgorithm::Sha256 => oids::ECDSA_WITH_SHA256,
                DigestAlgorithm::Sha384 => oids::ECDSA_WITH_SHA384,
                DigestAlgorithm::Sha512 => oids::ECDSA_WITH_SHA512,
            },
            None,
        ),
        oids::ED25519 => (oids::ED25519, None),
        other => {
            return Err(signing_error(format!(
                "Signature mechanism {other} is unsupported."
            )))
        }
    };
    Ok(AlgorithmIdentifierOwned { oid, parameters })
}

/// RSASSA-PSS parameters with the maximal salt length for the key
/// (`optimal_pss_params`).
pub fn optimal_pss_params(
    spki: &SubjectPublicKeyInfoOwned,
    digest: DigestAlgorithm,
) -> Result<RsaPssParams> {
    let bits = hanko_core::algorithms::rsa_key_size(spki)
        .ok_or_else(|| signing_error("Expected RSA key"))?;
    let em_len = (bits - 1).div_ceil(8);
    let salt = em_len
        .checked_sub(digest.output_len() + 2)
        .ok_or_else(|| signing_error("RSA key too small for PSS"))?;
    let md = digest_algorithm_id(digest);
    let mgf = AlgorithmIdentifierOwned {
        oid: oids::MGF1,
        parameters: Some(Any::encode_from(&md)?),
    };
    Ok(RsaPssParams {
        hash_algorithm: Some(md),
        mask_gen_algorithm: Some(mgf),
        salt_length: Some(u32::try_from(salt).map_err(|_| signing_error("PSS salt length"))?),
        trailer_field: None,
    })
}

/// A digest `AlgorithmIdentifier` encoded as asn1crypto does (with explicit
/// NULL parameters).
pub fn digest_algorithm_id(digest: DigestAlgorithm) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: digest.oid(),
        parameters: Any::encode_from(&der::asn1::Null).ok(),
    }
}

/// The digest that the `messageDigest` attribute must use for a mechanism
/// (`get_cms_hash_algo_for_mechanism`): SHA-512 for Ed25519, the
/// mechanism's own digest otherwise.
pub fn implied_digest(mech: &AlgorithmIdentifierOwned) -> Option<DigestAlgorithm> {
    if mech.oid == oids::ED25519 {
        return Some(DigestAlgorithm::Sha512);
    }
    SignatureMechanism::from_algorithm_identifier(mech, None)
        .ok()
        .and_then(|m| m.digest())
}

/// Choose a digest for a key (`select_suitable_signing_md`).
pub fn select_suitable_signing_md(spki: &SubjectPublicKeyInfoOwned) -> DigestAlgorithm {
    fn with_thresholds(size: usize, thresholds: &[(usize, DigestAlgorithm)]) -> DigestAlgorithm {
        thresholds
            .iter()
            .find(|(sz, _)| size <= *sz)
            .map_or(DigestAlgorithm::Sha512, |(_, md)| *md)
    }
    match spki.algorithm.oid {
        oids::RSA_ENCRYPTION | oids::RSASSA_PSS => {
            let size = hanko_core::algorithms::rsa_key_size(spki).unwrap_or(2048);
            with_thresholds(
                size,
                &[(2048, DigestAlgorithm::Sha256), (3072, DigestAlgorithm::Sha384)],
            )
        }
        oids::EC_PUBLIC_KEY => {
            let size = match spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
            {
                Some(oids::SECP384R1) => 384,
                Some(oids::SECP521R1) => 521,
                _ => 256,
            };
            with_thresholds(
                size,
                &[(256, DigestAlgorithm::Sha256), (384, DigestAlgorithm::Sha384)],
            )
        }
        oids::ED25519 => DigestAlgorithm::Sha512,
        _ => DigestAlgorithm::Sha256,
    }
}

/// Produce a raw signature over `data` with `key` and `mech`
/// (`SimpleSigner.sign_raw`).
pub fn sign_with_key(
    key: &PrivateKey,
    mech: &AlgorithmIdentifierOwned,
    data: &[u8],
    digest: DigestAlgorithm,
) -> Result<Vec<u8>> {
    let resolved = if mech.oid == oids::ED25519 {
        SignatureMechanism::Ed25519
    } else {
        SignatureMechanism::from_algorithm_identifier(mech, Some(digest))
            .map_err(|e| signing_error(e.to_string()))?
    };
    let mismatch = || {
        signing_error(format!(
            "The signature mechanism {} is unsupported by this signer.",
            resolved.name()
        ))
    };
    match (&resolved, key) {
        (SignatureMechanism::RsaPkcs1v15(md), PrivateKey::Rsa(k)) => {
            let hashed = md.digest(data);
            let scheme = match md {
                DigestAlgorithm::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                DigestAlgorithm::Sha224 => rsa::Pkcs1v15Sign::new::<sha2::Sha224>(),
                DigestAlgorithm::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                DigestAlgorithm::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                DigestAlgorithm::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
            };
            k.sign(scheme, &hashed)
                .map_err(|e| signing_error(format!("RSA signing failed: {e}")))
        }
        (SignatureMechanism::RsaPss(params), PrivateKey::Rsa(k)) => {
            if params.mgf1_digest != params.digest {
                return Err(signing_error(
                    "RSASSA-PSS with an MGF1 digest different from the message digest is unsupported",
                ));
            }
            let md = params.digest;
            let hashed = md.digest(data);
            let salt = params.salt_length;
            let res = match md {
                DigestAlgorithm::Sha1 => k.sign(rsa::Pss::<sha1::Sha1>::new_with_salt(salt), &hashed),
                DigestAlgorithm::Sha224 => {
                    k.sign(rsa::Pss::<sha2::Sha224>::new_with_salt(salt), &hashed)
                }
                DigestAlgorithm::Sha256 => {
                    k.sign(rsa::Pss::<sha2::Sha256>::new_with_salt(salt), &hashed)
                }
                DigestAlgorithm::Sha384 => {
                    k.sign(rsa::Pss::<sha2::Sha384>::new_with_salt(salt), &hashed)
                }
                DigestAlgorithm::Sha512 => {
                    k.sign(rsa::Pss::<sha2::Sha512>::new_with_salt(salt), &hashed)
                }
            };
            res.map_err(|e| signing_error(format!("RSA-PSS signing failed: {e}")))
        }
        (SignatureMechanism::Ecdsa(md), _) => {
            use signature::hazmat::PrehashSigner;
            let prehash = md.digest(data);
            let bad = |e: signature::Error| signing_error(format!("ECDSA signing failed: {e}"));
            match key {
                PrivateKey::P256(k) => {
                    let s: p256::ecdsa::DerSignature = k.sign_prehash(&prehash).map_err(bad)?;
                    Ok(s.as_bytes().to_vec())
                }
                PrivateKey::P384(k) => {
                    let s: p384::ecdsa::DerSignature = k.sign_prehash(&prehash).map_err(bad)?;
                    Ok(s.as_bytes().to_vec())
                }
                PrivateKey::P521(k) => {
                    let s: p521::ecdsa::DerSignature = k.sign_prehash(&prehash).map_err(bad)?;
                    Ok(s.as_bytes().to_vec())
                }
                _ => Err(mismatch()),
            }
        }
        (SignatureMechanism::Ed25519, PrivateKey::Ed25519(k)) => {
            use ed25519_dalek::Signer;
            Ok(k.sign(data).to_bytes().to_vec())
        }
        _ => Err(mismatch()),
    }
}

/// A signer whose raw signature is computed elsewhere and supplied up front
/// (`ExternalSigner`): useful for interrupted signing and tests.
#[derive(Debug, Clone)]
pub struct ExternalSigner {
    cert: Cert,
    chain: Vec<Cert>,
    mechanism: AlgorithmIdentifierOwned,
    signature_value: Vec<u8>,
}

impl ExternalSigner {
    /// `signature_value` is returned by every `sign_raw` call.
    pub fn new(
        cert: Cert,
        chain: Vec<Cert>,
        mechanism: AlgorithmIdentifierOwned,
        signature_value: Vec<u8>,
    ) -> Self {
        Self {
            cert,
            chain,
            mechanism,
            signature_value,
        }
    }
}

impl KeySigner for ExternalSigner {
    fn signing_cert(&self) -> &Cert {
        &self.cert
    }

    fn cert_chain(&self) -> &[Cert] {
        &self.chain
    }

    fn signature_algorithm(&self, _digest: DigestAlgorithm) -> Result<AlgorithmIdentifierOwned> {
        Ok(self.mechanism.clone())
    }

    fn sign_raw(&self, _data: &[u8], _digest: DigestAlgorithm) -> Result<Vec<u8>> {
        Ok(self.signature_value.clone())
    }
}

/// The subject name of a certificate formatted as pyHanko's
/// `Signer.subject_name`: the common name (or organisation name), followed by
/// ` <email>` if the subject has an e-mail address.
pub fn subject_display_name(cert: &Cert) -> Option<String> {
    let name = cert.subject();
    let mut cn = None;
    let mut org = None;
    let mut email = None;
    {
        for atv in name.iter() {
            let value = directory_string(&atv.value);
            match atv.oid {
                const_oid::db::rfc4519::CN => cn = cn.or(value),
                const_oid::db::rfc4519::O => org = org.or(value),
                EMAIL_ADDRESS => email = email.or(value),
                _ => {}
            }
        }
    }
    let base = cn.or(org)?;
    Some(match email {
        Some(e) => format!("{base} <{e}>"),
        None => base,
    })
}

const EMAIL_ADDRESS: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

/// Decode a `DirectoryString` (or IA5String) attribute value.
pub fn directory_string(value: &Any) -> Option<String> {
    use der::asn1::{BmpString, Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
    use der::{Tag, Tagged};
    let bytes = value.value();
    match value.tag() {
        Tag::Utf8String => Utf8StringRef::new(bytes).ok().map(|s| s.as_str().to_owned()),
        Tag::PrintableString => PrintableStringRef::new(bytes).ok().map(|s| s.as_str().to_owned()),
        Tag::Ia5String => Ia5StringRef::new(bytes).ok().map(|s| s.as_str().to_owned()),
        Tag::TeletexString => TeletexStringRef::new(bytes).ok().map(|s| s.as_str().to_owned()),
        Tag::BmpString => BmpString::from_ucs2(bytes.to_vec()).ok().map(|s| s.to_string()),
        _ => None,
    }
}

/// Re-encode a public key to check it parses (helper for tests).
#[doc(hidden)]
pub fn spki_der(spki: &SubjectPublicKeyInfoOwned) -> Result<Vec<u8>> {
    let der = spki.to_der()?;
    SubjectPublicKeyInfoOwned::from_der(&der)?;
    Ok(der)
}
