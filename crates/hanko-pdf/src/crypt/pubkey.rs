// Derived from pyHanko `pdf_utils/crypt/pubkey.py` (MIT, see LICENSE-pyHanko).

//! The public-key security handler (`PubKeySecurityHandler`): recipient
//! envelopes (CMS `EnvelopedData`) with RSA key transport (PKCS#1 v1.5 and
//! OAEP) and ECDH key agreement (NIST curves, X25519, X448), and the crypt
//! filters bound to them.

use std::sync::Arc;

use lopdf::{Dictionary, Object};
use sha2::Digest;

use super::api::{
    build_crypt_filter, AuthResult, AuthStatus, CipherKind, CryptFilter, CryptFilterConfiguration,
    CryptFilterRegistry, HandlerKind, HandlerState, SecurityHandler, SecurityHandlerVersion,
};
use super::asn1::{self, tag, AlgId, Tlv};
use super::cred_ser::{SerialisableCredential, SerialisedCredential};
use super::permissions::{PdfPermissions, PubKeyPermissions};
use super::standard::{encrypt_metadata_of, kdf_salt_of, number_entry, process_crypt_filters};
use super::util::{
    aes_cbc_decrypt, aes_cbc_encrypt, aes_key_unwrap, aes_key_wrap, random_bytes, rc2_decrypt, rc4_encrypt,
    tripledes_decrypt,
};
use crate::error::{PdfError, PdfResult};
use crate::generic::{byte_string, name_str, type_name};

/// Default crypt filter name of public-key handlers (`DEFAULT_CRYPT_FILTER`).
pub const DEFAULT_CRYPT_FILTER: &str = "DefaultCryptFilter";

/// Embedded-file filter name for documents where only embedded files are
/// encrypted (`DEF_EMBEDDED_FILE`).
pub const DEF_EMBEDDED_FILE: &str = "DefEmbeddedFile";

mod oids {
    pub const DATA: &str = "1.2.840.113549.1.7.1";
    pub const ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
    pub const RSA: &str = "1.2.840.113549.1.1.1";
    pub const RSAES_OAEP: &str = "1.2.840.113549.1.1.7";
    pub const MGF1: &str = "1.2.840.113549.1.1.8";
    pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    pub const P256: &str = "1.2.840.10045.3.1.7";
    pub const P384: &str = "1.3.132.0.34";
    pub const P521: &str = "1.3.132.0.35";
    pub const X25519: &str = "1.3.101.110";
    pub const X448: &str = "1.3.101.111";
    pub const SHA1: &str = "1.3.14.3.2.26";
    pub const SHA224: &str = "2.16.840.1.101.3.4.2.4";
    pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
    pub const SHA384: &str = "2.16.840.1.101.3.4.2.2";
    pub const SHA512: &str = "2.16.840.1.101.3.4.2.3";
    pub const AES128_CBC: &str = "2.16.840.1.101.3.4.1.2";
    pub const AES192_CBC: &str = "2.16.840.1.101.3.4.1.22";
    pub const AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";
    pub const DES_EDE3_CBC: &str = "1.2.840.113549.3.7";
    pub const RC2_CBC: &str = "1.2.840.113549.3.2";
    pub const RC4: &str = "1.2.840.113549.3.4";
    pub const DES_CBC: &str = "1.3.14.3.2.7";
    pub const KEY_USAGE: &str = "2.5.29.15";
    pub const DH_SINGLE_PASS_PREFIX: &str = "1.3.132.1.11.";
}

/// asn1crypto's name for an OID, where pyHanko's messages show it.
fn oid_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.7.1" => "data",
        "1.2.840.113549.1.7.2" => "signed_data",
        "1.2.840.113549.1.7.3" => "enveloped_data",
        "1.2.840.113549.1.7.4" => "signed_and_enveloped_data",
        "1.2.840.113549.1.7.5" => "digested_data",
        "1.2.840.113549.1.7.6" => "encrypted_data",
        "1.2.840.113549.1.9.16.1.2" => "authenticated_data",
        "2.16.840.1.101.3.4.1.1" => "aes128_ecb",
        "2.16.840.1.101.3.4.1.3" => "aes128_ofb",
        "2.16.840.1.101.3.4.1.4" => "aes128_cfb",
        "2.16.840.1.101.3.4.1.6" => "aes128_gcm",
        "2.16.840.1.101.3.4.1.21" => "aes192_ecb",
        "2.16.840.1.101.3.4.1.41" => "aes256_ecb",
        "2.16.840.1.101.3.4.1.46" => "aes256_gcm",
        other => other,
    }
    .to_string()
}

/// Public-key `/SubFilter` values (`PubKeyAdbeSubFilter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PubKeyAdbeSubFilter {
    /// `/adbe.pkcs7.s3`.
    S3,
    /// `/adbe.pkcs7.s4`.
    S4,
    /// `/adbe.pkcs7.s5`.
    S5,
}

impl PubKeyAdbeSubFilter {
    /// The name, without slash.
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::S3 => b"adbe.pkcs7.s3",
            Self::S4 => b"adbe.pkcs7.s4",
            Self::S5 => b"adbe.pkcs7.s5",
        }
    }

    /// Parse a name (without slash).
    pub fn from_name(n: &[u8]) -> Option<Self> {
        match n {
            b"adbe.pkcs7.s3" => Some(Self::S3),
            b"adbe.pkcs7.s4" => Some(Self::S4),
            b"adbe.pkcs7.s5" => Some(Self::S5),
            _ => None,
        }
    }
}

/// Recipient data of a public-key crypt filter (`PubKeyCryptFilter`).
#[derive(Clone, Debug)]
pub struct PubKeyCfData {
    pub(crate) recipients: Option<Vec<Vec<u8>>>,
    pub(crate) acts_as_default: bool,
    pub(crate) encrypt_metadata: bool,
    pub(crate) recp_key_seed: Option<Vec<u8>>,
    pub(crate) auth_failed: bool,
}

impl PubKeyCfData {
    /// Recipient data: `recipients` are DER-encoded CMS `ContentInfo`
    /// objects (`None` for a fresh filter).
    pub fn new(recipients: Option<Vec<Vec<u8>>>, acts_as_default: bool, encrypt_metadata: bool) -> Self {
        Self {
            recipients,
            acts_as_default,
            encrypt_metadata,
            recp_key_seed: None,
            auth_failed: false,
        }
    }
}

impl CryptFilter {
    /// RC4 filter for public-key handlers (`PubKeyRC4CryptFilter`).
    pub fn pubkey_rc4(keylen: usize, data: PubKeyCfData) -> Self {
        let mut cf = CryptFilter::standard_rc4(keylen);
        cf.pubkey = Some(data);
        cf
    }

    /// AES filter for public-key handlers (`PubKeyAESCryptFilter`).
    pub fn pubkey_aes(keylen: usize, data: PubKeyCfData) -> PdfResult<Self> {
        CryptFilter::pubkey_with(CipherKind::AesCbc, keylen, data)
    }

    /// AES-GCM filter for public-key handlers (`PubKeyAESGCMCryptFilter`).
    pub fn pubkey_aes_gcm(data: PubKeyCfData) -> PdfResult<Self> {
        CryptFilter::pubkey_with(CipherKind::AesGcm, 32, data)
    }
}

/// Recipient encryption options (`RecipientEncryptionPolicy`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecipientEncryptionPolicy {
    /// Ignore the key usage extension of recipient certificates.
    pub ignore_key_usage: bool,
    /// Use RSAES-OAEP for RSA recipients.
    pub prefer_oaep: bool,
}

/// A parsed certificate (the parts the public-key handler needs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertInfo {
    der: Vec<u8>,
    issuer: Vec<u8>,
    serial: Vec<u8>,
    subject: Vec<u8>,
    spki: Vec<u8>,
    key_usage: Option<Vec<u8>>,
}

fn strip_int(v: &[u8]) -> &[u8] {
    let mut v = v;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    v
}

impl CertInfo {
    /// Parse a DER certificate.
    pub fn from_der(der: &[u8]) -> PdfResult<Self> {
        let bad = |m: &str| PdfError::Value(format!("Invalid certificate: {m}"));
        let cert = Tlv::parse_exact(der).map_err(|_| bad("not a DER SEQUENCE"))?;
        let parts = cert.children()?;
        let tbs = parts.first().ok_or_else(|| bad("empty"))?;
        let mut f = tbs.children()?.into_iter().peekable();
        if f.peek().is_some_and(|t| t.tag == 0xa0) {
            f.next();
        }
        let serial = f.next().filter(|t| t.tag == tag::INTEGER).ok_or_else(|| bad("serial"))?;
        let _sig = f.next().ok_or_else(|| bad("signature"))?;
        let issuer = f.next().ok_or_else(|| bad("issuer"))?;
        let _validity = f.next().ok_or_else(|| bad("validity"))?;
        let subject = f.next().ok_or_else(|| bad("subject"))?;
        let spki = f.next().ok_or_else(|| bad("spki"))?;
        let mut key_usage = None;
        for t in f {
            if t.tag != 0xa3 {
                continue;
            }
            for ext in t.explicit_inner()?.children()? {
                let ch = ext.children()?;
                if ch.first().and_then(|o| o.oid().ok()).as_deref() == Some(oids::KEY_USAGE) {
                    if let Some(val) = ch.last() {
                        let bits = Tlv::parse_exact(val.value)?;
                        key_usage = Some(bits.value.to_vec());
                    }
                }
            }
        }
        Ok(Self {
            der: der.to_vec(),
            issuer: issuer.raw.to_vec(),
            serial: serial.value.to_vec(),
            subject: subject.raw.to_vec(),
            spki: spki.raw.to_vec(),
            key_usage,
        })
    }

    /// The DER encoding.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Encoded issuer name.
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer
    }

    /// Serial number content octets.
    pub fn serial_bytes(&self) -> &[u8] {
        &self.serial
    }

    /// Encoded subject name.
    pub fn subject_der(&self) -> &[u8] {
        &self.subject
    }

    /// Encoded `SubjectPublicKeyInfo`.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }

    fn matches(&self, issuer: &[u8], serial: &[u8]) -> bool {
        self.issuer == issuer && strip_int(&self.serial) == strip_int(serial)
    }

    /// `keyEncipherment` in the key usage extension (`None` if absent).
    pub fn key_encipherment(&self) -> Option<bool> {
        let ku = self.key_usage.as_ref()?;
        // BIT STRING: unused-bits octet, then the bits (bit 2 = 0x20)
        Some(ku.get(1).is_some_and(|b| b & 0x20 != 0))
    }

    fn subject_human_friendly(&self) -> String {
        use der::Decode;
        match x509_cert::name::Name::from_der(&self.subject) {
            Ok(n) => n.to_string(),
            Err(_) => "<unparseable subject>".into(),
        }
    }
}

/// Failure of an [`EnvelopeKeyDecrypter`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyDecryptError {
    /// The credential cannot be used for this kind of recipient
    /// (`InappropriateCredentialError`); propagated as is.
    InappropriateCredential(String),
    /// Any other failure; reported as "Failed to decrypt envelope key".
    Failed(String),
}

impl From<PdfError> for KeyDecryptError {
    fn from(e: PdfError) -> Self {
        Self::Failed(e.to_string())
    }
}

/// A recipient's private key operation (`EnvelopeKeyDecrypter`); allows
/// the key to live elsewhere (e.g. a token).
pub trait EnvelopeKeyDecrypter: Send + Sync + std::fmt::Debug {
    /// The recipient's certificate (`cert`).
    fn cert(&self) -> &CertInfo;

    /// Decrypt a key-transport payload (`decrypt`); `algo` is the DER
    /// `KeyEncryptionAlgorithmIdentifier`.
    fn decrypt(&self, encrypted_key: &[u8], algo: &[u8]) -> Result<Vec<u8>, KeyDecryptError>;

    /// Decrypt a key-agreement payload (`decrypt_with_exchange`); `algo` is
    /// the DER key encryption algorithm, `originator` the DER
    /// `OriginatorIdentifierOrKey`.
    fn decrypt_with_exchange(
        &self,
        encrypted_key: &[u8],
        algo: &[u8],
        originator: &[u8],
        user_keying_material: Option<&[u8]>,
    ) -> Result<Vec<u8>, KeyDecryptError>;

    /// The credential in serialisable form, if supported.
    fn as_serialisable(&self) -> Option<SerialisableCredential> {
        None
    }
}

/// Private key kinds supported by [`SimpleEnvelopeKeyDecrypter`].
enum PrivKey {
    Rsa(Box<rsa::RsaPrivateKey>),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    X25519([u8; 32]),
    X448(Box<[u8; 56]>),
}

fn parse_private_key(pkcs8: &[u8]) -> PdfResult<PrivKey> {
    use pkcs8::DecodePrivateKey;
    let bad = |m: &str| PdfError::Value(format!("Could not load private key: {m}"));
    let pki = Tlv::parse_exact(pkcs8).map_err(|_| bad("not DER"))?;
    let ch = pki.children()?;
    let alg = AlgId::parse(ch.get(1).ok_or_else(|| bad("missing algorithm"))?)?;
    let inner = ch.get(2).filter(|t| t.tag == tag::OCTET_STRING).ok_or_else(|| bad("missing key"))?;
    match alg.oid.as_str() {
        oids::RSA => Ok(PrivKey::Rsa(Box::new(
            rsa::RsaPrivateKey::from_pkcs8_der(pkcs8).map_err(|e| bad(&e.to_string()))?,
        ))),
        oids::EC_PUBLIC_KEY => {
            let curve = alg.params.map(|p| p.oid()).transpose()?.unwrap_or_default();
            match curve.as_str() {
                oids::P256 => Ok(PrivKey::P256(p256::SecretKey::from_pkcs8_der(pkcs8).map_err(|e| bad(&e.to_string()))?)),
                oids::P384 => Ok(PrivKey::P384(p384::SecretKey::from_pkcs8_der(pkcs8).map_err(|e| bad(&e.to_string()))?)),
                oids::P521 => Ok(PrivKey::P521(p521::SecretKey::from_pkcs8_der(pkcs8).map_err(|e| bad(&e.to_string()))?)),
                other => Err(PdfError::NotImplemented(format!("Unsupported curve {other}"))),
            }
        }
        oids::X25519 => {
            let k = Tlv::expect(inner.value, tag::OCTET_STRING)?.0.value;
            Ok(PrivKey::X25519(k.try_into().map_err(|_| bad("X25519 key length"))?))
        }
        oids::X448 => {
            let k = Tlv::expect(inner.value, tag::OCTET_STRING)?.0.value;
            Ok(PrivKey::X448(Box::new(k.try_into().map_err(|_| bad("X448 key length"))?)))
        }
        other => Err(PdfError::NotImplemented(format!("Unsupported private key algorithm {other}"))),
    }
}

/// Recipient credential with an in-memory private key
/// (`SimpleEnvelopeKeyDecrypter`).
#[derive(Clone)]
pub struct SimpleEnvelopeKeyDecrypter {
    cert: CertInfo,
    private_key: Vec<u8>,
}

impl std::fmt::Debug for SimpleEnvelopeKeyDecrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleEnvelopeKeyDecrypter")
            .field("subject", &self.cert.subject_human_friendly())
            .finish_non_exhaustive()
    }
}

impl SimpleEnvelopeKeyDecrypter {
    /// Registered credential type name (`get_name`).
    pub const NAME: &'static str = "raw_privkey";

    /// From a DER certificate and a DER PKCS#8 `PrivateKeyInfo`.
    pub fn new(cert_der: &[u8], private_key_pkcs8: &[u8]) -> PdfResult<Self> {
        Ok(Self {
            cert: CertInfo::from_der(cert_der)?,
            private_key: private_key_pkcs8.to_vec(),
        })
    }

    /// Load from key and certificate files' contents, PEM or DER, with an
    /// optional passphrase for an encrypted key (`load`).
    pub fn load(key_data: &[u8], cert_data: &[u8], passphrase: Option<&[u8]>) -> PdfResult<Self> {
        let cert = super::keys::load_cert_from_pemder(cert_data)?;
        let key = super::keys::load_private_key_from_pemder(key_data, passphrase)?;
        Self::new(&cert, &key)
    }

    /// Load from a PKCS#12 file's contents (`load_pkcs12`).
    pub fn load_pkcs12(pfx_data: &[u8], passphrase: Option<&[u8]>) -> PdfResult<Self> {
        let (key, cert) = super::keys::load_pkcs12(pfx_data, passphrase)?;
        Self::new(&cert, &key)
    }

    /// The certificate.
    pub fn cert_info(&self) -> &CertInfo {
        &self.cert
    }

    /// The PKCS#8 private key.
    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key
    }

    /// Serialise as `SEQUENCE { PrivateKeyInfo, Certificate }` (`_ser_value`).
    pub fn serialise(&self) -> SerialisedCredential {
        SerialisedCredential {
            credential_type: Self::NAME.into(),
            data: asn1::seq(&[&self.private_key, &self.cert.der]),
        }
    }

    /// Deserialise (`_deser_value`).
    pub fn from_serialised(data: &[u8]) -> PdfResult<Self> {
        let err = || PdfError::Read("Failed to decode serialised pubkey credential".into());
        let (t, _) = Tlv::expect(data, tag::SEQUENCE).map_err(|_| err())?;
        let ch = t.children().map_err(|_| err())?;
        let [key, cert] = ch.as_slice() else {
            return Err(err());
        };
        Self::new(cert.raw, key.raw).map_err(|_| err())
    }
}

fn digest_by_oid(oid: &str, data: &[u8]) -> Option<Vec<u8>> {
    Some(match oid {
        oids::SHA1 => sha1::Sha1::digest(data).to_vec(),
        oids::SHA224 => sha2::Sha224::digest(data).to_vec(),
        oids::SHA256 => sha2::Sha256::digest(data).to_vec(),
        oids::SHA384 => sha2::Sha384::digest(data).to_vec(),
        oids::SHA512 => sha2::Sha512::digest(data).to_vec(),
        _ => return None,
    })
}

fn rsa_oaep_decrypt(key: &rsa::RsaPrivateKey, hash: &str, mgf_hash: &str, ct: &[u8]) -> Result<Vec<u8>, KeyDecryptError> {
    macro_rules! oaep {
        ($d:ty, $m:ty) => {
            key.decrypt(rsa::Oaep::<$d, $m>::new_with_mgf_hash(), ct)
        };
    }
    macro_rules! by_mgf {
        ($d:ty) => {
            match mgf_hash {
                oids::SHA1 => oaep!($d, sha1::Sha1),
                oids::SHA224 => oaep!($d, sha2::Sha224),
                oids::SHA256 => oaep!($d, sha2::Sha256),
                oids::SHA384 => oaep!($d, sha2::Sha384),
                oids::SHA512 => oaep!($d, sha2::Sha512),
                other => return Err(KeyDecryptError::Failed(format!("Unsupported MGF1 hash {other}"))),
            }
        };
    }
    let r = match hash {
        oids::SHA1 => by_mgf!(sha1::Sha1),
        oids::SHA224 => by_mgf!(sha2::Sha224),
        oids::SHA256 => by_mgf!(sha2::Sha256),
        oids::SHA384 => by_mgf!(sha2::Sha384),
        oids::SHA512 => by_mgf!(sha2::Sha512),
        other => return Err(KeyDecryptError::Failed(format!("Unsupported OAEP hash {other}"))),
    };
    r.map_err(|e| KeyDecryptError::Failed(e.to_string()))
}

/// Parse RSAES-OAEP parameters: (hash OID, MGF1 hash OID), with the
/// defaults of RFC 8017 (SHA-1).
fn oaep_params(params: Option<Tlv<'_>>) -> Result<(String, String), KeyDecryptError> {
    let mut hash = oids::SHA1.to_string();
    let mut mgf_hash = oids::SHA1.to_string();
    if let Some(p) = params.filter(|p| p.tag == tag::SEQUENCE) {
        for f in p.children()? {
            match f.tag {
                0xa0 => hash = AlgId::parse(&f.explicit_inner()?)?.oid,
                0xa1 => {
                    let mgf = AlgId::parse(&f.explicit_inner()?)?;
                    if mgf.oid != oids::MGF1 {
                        return Err(KeyDecryptError::Failed(format!(
                            "Only MGF1 is implemented, but got '{}'",
                            mgf.oid
                        )));
                    }
                    if let Some(mp) = mgf.params {
                        mgf_hash = AlgId::parse(&mp)?.oid;
                    }
                }
                _ => {}
            }
        }
    }
    Ok((hash, mgf_hash))
}

fn x963_kdf(digest_oid: &str, z: &[u8], shared_info: &[u8], len: usize) -> PdfResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < len {
        let block = [z, &counter.to_be_bytes(), shared_info].concat();
        out.extend(
            digest_by_oid(digest_oid, &block)
                .ok_or_else(|| PdfError::NotImplemented(format!("Unsupported KDF digest {digest_oid}")))?,
        );
        counter += 1;
    }
    out.truncate(len);
    Ok(out)
}

/// AES key wrap algorithms: (KEK bits, padded) (`AES_WRAP_PATTERN`).
fn aes_wrap_params(oid: &str) -> Option<(usize, bool)> {
    match oid {
        "2.16.840.1.101.3.4.1.5" => Some((128, false)),
        "2.16.840.1.101.3.4.1.25" => Some((192, false)),
        "2.16.840.1.101.3.4.1.45" => Some((256, false)),
        "2.16.840.1.101.3.4.1.8" => Some((128, true)),
        "2.16.840.1.101.3.4.1.28" => Some((192, true)),
        "2.16.840.1.101.3.4.1.48" => Some((256, true)),
        _ => None,
    }
}

/// `ECC-CMS-SharedInfo` (RFC 5753) for the X9.63 KDF (`_kdf_for_exchange`).
fn ecc_cms_shared_info(key_wrap_algo: &[u8], ukm: Option<&[u8]>, kek_bits: usize) -> Vec<u8> {
    let supp = asn1::tlv(0xa2, &asn1::octets(&(kek_bits as u32).to_be_bytes()));
    match ukm {
        Some(u) => asn1::seq(&[key_wrap_algo, &asn1::tlv(0xa0, &asn1::octets(u)), &supp]),
        None => asn1::seq(&[key_wrap_algo, &supp]),
    }
}

fn x448_dh(scalar: &[u8; 56], point: &[u8]) -> PdfResult<[u8; 56]> {
    let point: [u8; 56] = point
        .try_into()
        .map_err(|_| PdfError::Value("Invalid X448 public key length".into()))?;
    let out = super::x448::x448(scalar, &point)?;
    if out == [0u8; 56] {
        return Err(PdfError::Value("Error computing shared key.".into()));
    }
    Ok(out)
}

fn x448_public(scalar: &[u8; 56]) -> PdfResult<[u8; 56]> {
    let mut base = [0u8; 56];
    base[0] = 5;
    x448_dh(scalar, &base)
}

fn x25519_dh(scalar: &[u8; 32], point: &[u8]) -> PdfResult<[u8; 32]> {
    let point: [u8; 32] = point
        .try_into()
        .map_err(|_| PdfError::Value("Invalid X25519 public key length".into()))?;
    let out = curve25519_dalek::MontgomeryPoint(point).mul_clamped(*scalar);
    if out.0 == [0u8; 32] {
        return Err(PdfError::Value("Error computing shared key.".into()));
    }
    Ok(out.0)
}

/// Public key of an SPKI: (algorithm OID, curve OID if EC, key bits).
fn spki_parts(spki: &[u8]) -> PdfResult<(String, Option<String>, Vec<u8>)> {
    let t = Tlv::parse_exact(spki)?;
    let ch = t.children()?;
    let alg = AlgId::parse(ch.first().ok_or_else(|| PdfError::Value("empty SPKI".into()))?)?;
    let bits = ch
        .get(1)
        .filter(|b| b.tag == tag::BIT_STRING && !b.value.is_empty())
        .ok_or_else(|| PdfError::Value("SPKI without key".into()))?;
    let curve = match alg.params {
        Some(p) if p.tag == tag::OID => Some(p.oid()?),
        _ => None,
    };
    Ok((alg.oid, curve, bits.value[1..].to_vec()))
}

impl EnvelopeKeyDecrypter for SimpleEnvelopeKeyDecrypter {
    fn cert(&self) -> &CertInfo {
        &self.cert
    }

    fn decrypt(&self, encrypted_key: &[u8], algo: &[u8]) -> Result<Vec<u8>, KeyDecryptError> {
        let t = Tlv::parse_exact(algo)?;
        let alg = AlgId::parse(&t)?;
        let oaep = match alg.oid.as_str() {
            oids::RSA => None,
            oids::RSAES_OAEP => Some(oaep_params(alg.params)?),
            other => {
                return Err(KeyDecryptError::Failed(format!(
                    "Only 'rsaes_pkcs1v15' and 'rsaes_oaep' are supported for envelope decryption, not '{other}'."
                )))
            }
        };
        let PrivKey::Rsa(key) = parse_private_key(&self.private_key)? else {
            return Err(KeyDecryptError::InappropriateCredential(
                "The loaded key does not seem to be an RSA private key".into(),
            ));
        };
        match oaep {
            None => key
                .decrypt(rsa::Pkcs1v15Encrypt, encrypted_key)
                .map_err(|e| KeyDecryptError::Failed(e.to_string())),
            Some((h, m)) => rsa_oaep_decrypt(&key, &h, &m, encrypted_key),
        }
    }

    fn decrypt_with_exchange(
        &self,
        encrypted_key: &[u8],
        algo: &[u8],
        originator: &[u8],
        user_keying_material: Option<&[u8]>,
    ) -> Result<Vec<u8>, KeyDecryptError> {
        let alg = AlgId::parse(&Tlv::parse_exact(algo)?)?;
        let kdf_digest = match alg.oid.strip_prefix(oids::DH_SINGLE_PASS_PREFIX) {
            Some("0") => oids::SHA224,
            Some("1") => oids::SHA256,
            Some("2") => oids::SHA384,
            Some("3") => oids::SHA512,
            _ => {
                return Err(KeyDecryptError::Failed(
                    "Only dhSinglePass-stdDH algorithms from SEC 1 / RFC 5753 are supported.".into(),
                ))
            }
        };
        let wrap = alg
            .params
            .ok_or_else(|| KeyDecryptError::Failed("Missing key wrap algorithm".into()))?;
        let wrap_alg = AlgId::parse(&wrap)?;
        let (kek_bits, padded) = aes_wrap_params(&wrap_alg.oid).ok_or_else(|| {
            KeyDecryptError::Failed(format!("{} is not a supported key wrapping algorithm", wrap_alg.oid))
        })?;
        let shared_info = ecc_cms_shared_info(wrap.raw, user_keying_material, kek_bits);
        let orig = Tlv::parse_exact(originator)?;
        if orig.tag != 0xa1 {
            return Err(KeyDecryptError::Failed("Only originator_key is supported".into()));
        }
        let orig_spki = orig.retagged(tag::SEQUENCE);
        let (o_alg, o_curve, o_key) = spki_parts(&orig_spki)?;
        let mismatch = || KeyDecryptError::Failed("Originator's public key is not compatible with selected private key".into());
        let z: Vec<u8> = match parse_private_key(&self.private_key)? {
            PrivKey::P256(k) => {
                if o_alg != oids::EC_PUBLIC_KEY || o_curve.as_deref() != Some(oids::P256) {
                    return Err(mismatch());
                }
                let pk = p256::PublicKey::from_sec1_bytes(&o_key).map_err(|_| mismatch())?;
                p256::ecdh::diffie_hellman(k.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()
            }
            PrivKey::P384(k) => {
                if o_alg != oids::EC_PUBLIC_KEY || o_curve.as_deref() != Some(oids::P384) {
                    return Err(mismatch());
                }
                let pk = p384::PublicKey::from_sec1_bytes(&o_key).map_err(|_| mismatch())?;
                p384::ecdh::diffie_hellman(k.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()
            }
            PrivKey::P521(k) => {
                if o_alg != oids::EC_PUBLIC_KEY || o_curve.as_deref() != Some(oids::P521) {
                    return Err(mismatch());
                }
                let pk = p521::PublicKey::from_sec1_bytes(&o_key).map_err(|_| mismatch())?;
                p521::ecdh::diffie_hellman(k.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()
            }
            PrivKey::X25519(k) => {
                if o_alg != oids::X25519 {
                    return Err(mismatch());
                }
                x25519_dh(&k, &o_key)?.to_vec()
            }
            PrivKey::X448(k) => {
                if o_alg != oids::X448 {
                    return Err(mismatch());
                }
                x448_dh(&k, &o_key)?.to_vec()
            }
            PrivKey::Rsa(_) => {
                return Err(KeyDecryptError::InappropriateCredential(
                    "The loaded key does not seem to be an EC private key".into(),
                ))
            }
        };
        let kek = x963_kdf(kdf_digest, &z, &shared_info, kek_bits / 8)?;
        Ok(aes_key_unwrap(&kek, encrypted_key, padded)?)
    }

    fn as_serialisable(&self) -> Option<SerialisableCredential> {
        Some(SerialisableCredential::PrivateKey(self.clone()))
    }
}

fn sys_rng() -> rand_core::UnwrapErr<getrandom04::SysRng> {
    rand_core::UnwrapErr(getrandom04::SysRng)
}

fn rsa_recipient(cert: &CertInfo, envelope_key: &[u8], oaep: bool) -> PdfResult<Vec<u8>> {
    use pkcs8::DecodePublicKey;
    let pk = rsa::RsaPublicKey::from_public_key_der(&cert.spki)
        .map_err(|e| PdfError::Value(format!("Invalid RSA public key: {e}")))?;
    let mut rng = sys_rng();
    let (algo, ct) = if oaep {
        // pyHanko selects the digest as for signing: SHA-256 for RSA keys
        let sha256 = asn1::alg_id(oids::SHA256, None);
        let params = asn1::seq(&[
            &asn1::tlv(0xa0, &sha256),
            &asn1::tlv(0xa1, &asn1::alg_id(oids::MGF1, Some(&sha256))),
        ]);
        let ct = pk
            .encrypt(&mut rng, rsa::Oaep::<sha2::Sha256>::new(), envelope_key)
            .map_err(|e| PdfError::Value(e.to_string()))?;
        (asn1::alg_id(oids::RSAES_OAEP, Some(&params)), ct)
    } else {
        let ct = pk
            .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, envelope_key)
            .map_err(|e| PdfError::Value(e.to_string()))?;
        (asn1::alg_id(oids::RSA, Some(&asn1::tlv(tag::NULL, &[]))), ct)
    };
    let rid = asn1::seq(&[&cert.issuer, &asn1::tlv(tag::INTEGER, &cert.serial)]);
    Ok(asn1::seq(&[&asn1::uint(0), &rid, &algo, &asn1::octets(&ct)]))
}

/// (KDF digest OID, key wrap OID, KEK bits, key agreement OID)
/// (`_choose_ecdh_settings`).
fn choose_ecdh_settings(sec_level: usize) -> (&'static str, &'static str, usize, &'static str) {
    if sec_level <= 128 {
        (oids::SHA256, "2.16.840.1.101.3.4.1.5", 128, "1.3.132.1.11.1")
    } else if sec_level <= 192 {
        (oids::SHA384, "2.16.840.1.101.3.4.1.25", 192, "1.3.132.1.11.2")
    } else {
        (oids::SHA512, "2.16.840.1.101.3.4.1.45", 256, "1.3.132.1.11.3")
    }
}

/// A uniformly random scalar: rejection sampling over field-size byte
/// strings (top bits masked to the field size).
fn random_secret<K>(parse: impl Fn(&[u8]) -> Option<K>, len: usize) -> PdfResult<K> {
    let excess_bits = len * 8 - match len {
        66 => 521,
        n => n * 8,
    };
    for _ in 0..256 {
        let mut b = random_bytes(len)?;
        if excess_bits > 0 {
            b[0] &= 0xff >> excess_bits;
        }
        if let Some(k) = parse(&b) {
            return Ok(k);
        }
    }
    Err(PdfError::Generic("Could not generate an ephemeral key".into()))
}

fn ecdh_recipient(cert: &CertInfo, envelope_key: &[u8]) -> PdfResult<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let (alg, curve, key) = spki_parts(&cert.spki)?;
    let ecdh_err = |e: &dyn std::fmt::Display| PdfError::Value(format!("ECDH failure: {e}"));
    macro_rules! nist {
        ($c:ident, $bits:expr) => {{
            let peer = $c::PublicKey::from_sec1_bytes(&key).map_err(|e| ecdh_err(&e))?;
            let eph = random_secret(|b| $c::SecretKey::from_slice(b).ok(), ($bits as usize).div_ceil(8))?;
            let z = $c::ecdh::diffie_hellman(eph.to_nonzero_scalar(), peer.as_affine())
                .raw_secret_bytes()
                .to_vec();
            let point = eph.public_key().to_sec1_point(false);
            let mut bits = vec![0u8];
            bits.extend_from_slice(point.as_bytes());
            let spki = asn1::seq(&[
                &asn1::alg_id(oids::EC_PUBLIC_KEY, curve.as_deref().map(asn1::oid).as_deref()),
                &asn1::tlv(tag::BIT_STRING, &bits),
            ]);
            ($bits / 2, z, spki)
        }};
    }
    let (sec_level, z, originator_spki) = match (alg.as_str(), curve.as_deref()) {
        (oids::EC_PUBLIC_KEY, Some(oids::P256)) => nist!(p256, 256usize),
        (oids::EC_PUBLIC_KEY, Some(oids::P384)) => nist!(p384, 384usize),
        (oids::EC_PUBLIC_KEY, Some(oids::P521)) => nist!(p521, 521usize),
        (oids::X25519, _) => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&random_bytes(32)?);
            let z = x25519_dh(&k, &key)?.to_vec();
            let public = curve25519_dalek::MontgomeryPoint::mul_base_clamped(k).0;
            let mut bits = vec![0u8];
            bits.extend_from_slice(&public);
            let spki = asn1::seq(&[&asn1::alg_id(oids::X25519, None), &asn1::tlv(tag::BIT_STRING, &bits)]);
            (128, z, spki)
        }
        (oids::X448, _) => {
            let mut k = [0u8; 56];
            k.copy_from_slice(&random_bytes(56)?);
            let z = x448_dh(&k, &key)?.to_vec();
            let public = x448_public(&k)?;
            let mut bits = vec![0u8];
            bits.extend_from_slice(&public);
            let spki = asn1::seq(&[&asn1::alg_id(oids::X448, None), &asn1::tlv(tag::BIT_STRING, &bits)]);
            (256, z, spki)
        }
        _ => return Err(PdfError::NotImplemented(format!("Cannot encrypt for key type '{alg}'"))),
    };
    let (kdf_digest, wrap_oid, kek_bits, ka_oid) = choose_ecdh_settings(sec_level);
    let wrap_algo = asn1::alg_id(wrap_oid, None);
    let ukm = random_bytes(16)?;
    let kek = x963_kdf(kdf_digest, &z, &ecc_cms_shared_info(&wrap_algo, Some(&ukm), kek_bits), kek_bits / 8)?;
    let encrypted = aes_key_wrap(&kek, envelope_key)?;
    // originator [0] EXPLICIT { originatorKey [1] IMPLICIT OriginatorPublicKey }
    let mut orig_key = originator_spki.clone();
    if let Some(b) = orig_key.first_mut() {
        *b = 0xa1;
    }
    let rid = asn1::seq(&[&cert.issuer, &asn1::tlv(tag::INTEGER, &cert.serial)]);
    let rek = asn1::seq(&[&rid, &asn1::octets(&encrypted)]);
    let kari_body = [
        asn1::uint(3),
        asn1::tlv(0xa0, &orig_key),
        asn1::tlv(0xa1, &asn1::octets(&ukm)),
        asn1::alg_id(ka_oid, Some(&wrap_algo)),
        asn1::seq(&[&rek]),
    ]
    .concat();
    Ok(asn1::tlv(0xa1, &kari_body))
}

fn recipient_info(envelope_key: &[u8], cert: &CertInfo, policy: RecipientEncryptionPolicy) -> PdfResult<Vec<u8>> {
    if !policy.ignore_key_usage && cert.key_encipherment() != Some(true) {
        return Err(PdfError::Write(format!(
            "Certificate for subject {} does not have the 'key_encipherment' key usage bit set.",
            cert.subject_human_friendly()
        )));
    }
    let (alg, _, _) = spki_parts(&cert.spki)?;
    match alg.as_str() {
        oids::RSA => rsa_recipient(cert, envelope_key, policy.prefer_oaep),
        oids::EC_PUBLIC_KEY | oids::X25519 | oids::X448 => ecdh_recipient(cert, envelope_key),
        other => Err(PdfError::NotImplemented(format!("Cannot encrypt for key type '{other}'"))),
    }
}

/// Build a recipient `ContentInfo` holding the seed (and permissions)
/// (`construct_recipient_cms`).
pub fn construct_recipient_cms(
    certificates: &[CertInfo],
    seed: &[u8],
    perms: PubKeyPermissions,
    policy: RecipientEncryptionPolicy,
    include_permissions: bool,
) -> PdfResult<Vec<u8>> {
    let mut content = seed.to_vec();
    if include_permissions {
        content.extend_from_slice(&perms.as_bytes());
    }
    let envelope_key = random_bytes(32)?;
    let (iv, encrypted) = aes_cbc_encrypt(&envelope_key, &content, None, true)?;
    let rec_infos: Vec<Vec<u8>> = certificates
        .iter()
        .map(|c| recipient_info(&envelope_key, c, policy))
        .collect::<PdfResult<_>>()?;
    let eci = asn1::seq(&[
        &asn1::oid(oids::DATA),
        &asn1::alg_id(oids::AES256_CBC, Some(&asn1::octets(&iv))),
        &asn1::tlv(0x80, &encrypted),
    ]);
    let ris: Vec<&[u8]> = rec_infos.iter().map(Vec::as_slice).collect();
    let ed = asn1::seq(&[&asn1::uint(0), &asn1::cons(tag::SET, &ris), &eci]);
    Ok(asn1::seq(&[&asn1::oid(oids::ENVELOPED_DATA), &asn1::tlv(0xa0, &ed)]))
}

fn rid_issuer_serial<'a>(rid: &Tlv<'a>) -> PdfResult<(&'a [u8], &'a [u8])> {
    if rid.tag != tag::SEQUENCE {
        return Err(PdfError::NotImplemented(
            "Recipient identifier must be of type IssuerAndSerialNumber.".into(),
        ));
    }
    let ch = rid.children()?;
    match ch.as_slice() {
        [issuer, serial] if serial.tag == tag::INTEGER => Ok((issuer.raw, serial.value)),
        _ => Err(PdfError::Value("Malformed IssuerAndSerialNumber".into())),
    }
}

fn map_decrypt_err(e: KeyDecryptError) -> PdfError {
    match e {
        KeyDecryptError::InappropriateCredential(m) => PdfError::Value(format!("InappropriateCredentialError: {m}")),
        KeyDecryptError::Failed(m) => {
            log::debug!("envelope key decryption failed: {m}");
            PdfError::Read("Failed to decrypt envelope key".into())
        }
    }
}

/// Find and decrypt the envelope key for `decrypter` (`read_envelope_key`).
fn read_envelope_key(recipient_infos: &Tlv<'_>, decrypter: &dyn EnvelopeKeyDecrypter) -> PdfResult<Option<Vec<u8>>> {
    for ri in recipient_infos.children()? {
        match ri.tag {
            tag::SEQUENCE => {
                let ch = ri.children()?;
                let [_, rid, kea, ek, ..] = ch.as_slice() else {
                    return Err(PdfError::Value("Malformed KeyTransRecipientInfo".into()));
                };
                let (issuer, serial) = rid_issuer_serial(rid)?;
                if decrypter.cert().matches(issuer, serial) {
                    if ek.tag != tag::OCTET_STRING {
                        return Err(PdfError::Value("Malformed KeyTransRecipientInfo".into()));
                    }
                    return decrypter.decrypt(ek.value, kea.raw).map(Some).map_err(map_decrypt_err);
                }
            }
            0xa1 => {
                let ch = ri.children()?;
                let mut it = ch.iter();
                let _version = it.next();
                let originator = it
                    .next()
                    .filter(|t| t.tag == 0xa0)
                    .ok_or_else(|| PdfError::Value("Malformed KeyAgreeRecipientInfo".into()))?
                    .explicit_inner()?;
                let mut next = it.next();
                let ukm = match next {
                    Some(t) if t.tag == 0xa1 => {
                        let u = t.explicit_inner()?;
                        next = it.next();
                        Some(u.value)
                    }
                    _ => None,
                };
                let kea = next.ok_or_else(|| PdfError::Value("Malformed KeyAgreeRecipientInfo".into()))?;
                let reks = it
                    .next()
                    .ok_or_else(|| PdfError::Value("Malformed KeyAgreeRecipientInfo".into()))?;
                for rek in reks.children()? {
                    let rch = rek.children()?;
                    let [rid, ek] = rch.as_slice() else {
                        return Err(PdfError::Value("Malformed RecipientEncryptedKey".into()));
                    };
                    let (issuer, serial) = rid_issuer_serial(rid)?;
                    if decrypter.cert().matches(issuer, serial) {
                        return decrypter
                            .decrypt_with_exchange(ek.value, kea.raw, originator.raw, ukm)
                            .map(Some)
                            .map_err(map_decrypt_err);
                    }
                }
            }
            _ => {
                return Err(PdfError::NotImplemented(
                    "RecipientInfo must be of type KeyTransRecipientInfo or KeyAgreeRecipientInfo".into(),
                ))
            }
        }
    }
    Ok(None)
}

/// Decrypt the seed (and permissions) of a recipient `ContentInfo`
/// (`read_seed_from_recipient_cms`).
pub(crate) fn read_seed_from_recipient_cms(
    recipient_cms: &[u8],
    decrypter: &dyn EnvelopeKeyDecrypter,
) -> PdfResult<(Option<Vec<u8>>, Option<PubKeyPermissions>)> {
    let (ci, _) = Tlv::expect(recipient_cms, tag::SEQUENCE)?;
    let ch = ci.children()?;
    let content_type = ch.first().ok_or_else(|| PdfError::Value("Empty ContentInfo".into()))?.oid()?;
    if content_type != oids::ENVELOPED_DATA {
        return Err(PdfError::Read(format!(
            "Recipient CMS content type must be enveloped data, not {}",
            oid_name(&content_type)
        )));
    }
    let ed = ch
        .get(1)
        .filter(|t| t.tag == 0xa0)
        .ok_or_else(|| PdfError::Value("ContentInfo without content".into()))?
        .explicit_inner()?;
    let mut fields = ed.children()?.into_iter();
    let _version = fields.next();
    let mut ris = fields.next().ok_or_else(|| PdfError::Value("Malformed EnvelopedData".into()))?;
    if ris.tag == 0xa0 {
        // originatorInfo
        ris = fields.next().ok_or_else(|| PdfError::Value("Malformed EnvelopedData".into()))?;
    }
    let eci = fields.next().ok_or_else(|| PdfError::Value("Malformed EnvelopedData".into()))?;
    let Some(envelope_key) = read_envelope_key(&ris, decrypter)? else {
        return Ok((None, None));
    };
    let eci_ch = eci.children()?;
    let alg = AlgId::parse(eci_ch.get(1).ok_or_else(|| PdfError::Value("Malformed EncryptedContentInfo".into()))?)?;
    let encrypted = match eci_ch.get(2) {
        Some(t) if t.tag == 0x80 => t.value.to_vec(),
        Some(t) if t.tag == 0xa0 => t.children()?.iter().flat_map(|c| c.value.to_vec()).collect(),
        _ => Vec::new(),
    };
    let iv_of = |p: Option<Tlv<'_>>| -> PdfResult<Vec<u8>> {
        match p {
            Some(t) if t.tag == tag::OCTET_STRING => Ok(t.value.to_vec()),
            Some(t) if t.tag == tag::SEQUENCE => t
                .children()?
                .into_iter()
                .find(|c| c.tag == tag::OCTET_STRING)
                .map(|c| c.value.to_vec())
                .ok_or_else(|| PdfError::Value("Missing IV".into())),
            _ => Err(PdfError::Value("Missing IV".into())),
        }
    };
    let content = match alg.oid.as_str() {
        oids::DES_CBC => {
            return Err(PdfError::NotImplemented(
                "Support for DES has been dropped in pyHanko 0.26.0".into(),
            ))
        }
        oids::AES128_CBC | oids::AES192_CBC | oids::AES256_CBC => {
            aes_cbc_decrypt(&envelope_key, &encrypted, &iv_of(alg.params)?, true)?
        }
        oids::DES_EDE3_CBC => tripledes_decrypt(&envelope_key, &encrypted, &iv_of(alg.params)?)?,
        oids::RC2_CBC => rc2_decrypt(&envelope_key, &encrypted, &iv_of(alg.params)?)?,
        oids::RC4 => rc4_encrypt(&envelope_key, &encrypted),
        other => {
            return Err(PdfError::Read(format!(
                "Cipher {} is not allowed in PDF 2.0.",
                oid_name(other)
            )))
        }
    };
    let seed = content[..content.len().min(20)].to_vec();
    let perms = if content.len() == 24 {
        Some(PubKeyPermissions::from_bytes([content[20], content[21], content[22], content[23]]))
    } else {
        None
    };
    Ok((Some(seed), perms))
}

/// `PubKeyCryptFilter.derive_shared_encryption_key`.
pub(crate) fn derive_pubkey_shared_key(version: SecurityHandlerVersion, cf: &CryptFilter) -> PdfResult<Vec<u8>> {
    let p = cf
        .pubkey
        .as_ref()
        .ok_or_else(|| PdfError::Generic("Not a public-key crypt filter".into()))?;
    let seed = p
        .recp_key_seed
        .as_ref()
        .ok_or_else(|| PdfError::Generic("No seed available; authenticate first.".into()))?;
    let mut data = seed.clone();
    for r in p.recipients.iter().flatten() {
        data.extend_from_slice(r);
    }
    if !p.encrypt_metadata && p.acts_as_default {
        data.extend_from_slice(&[0xff; 4]);
    }
    let digest = if version >= SecurityHandlerVersion::Aes256 {
        sha2::Sha256::digest(&data).to_vec()
    } else {
        sha1::Sha1::digest(&data).to_vec()
    };
    Ok(digest[..cf.keylen.min(digest.len())].to_vec())
}

/// `_read_generic_pubkey_cf_info`.
fn read_generic_pubkey_cf_info(cfdict: &Dictionary, acts_as_default: bool) -> PdfResult<PubKeyCfData> {
    let recipients = cfdict
        .get(b"Recipients")
        .map_err(|_| PdfError::Read("PubKey CF dictionary must have /Recipients key".into()))?;
    let list: Vec<Vec<u8>> = match recipients {
        Object::String(s, _) => vec![first_tlv(s)?],
        Object::Array(a) => a
            .iter()
            .map(|x| match x {
                Object::String(s, _) => first_tlv(s),
                other => Err(PdfError::Value(format!(
                    "Recipient must be a string, not {}",
                    type_name(other)
                ))),
            })
            .collect::<PdfResult<_>>()?,
        other => {
            return Err(PdfError::Value(format!(
                "/Recipients must be a string or an array, not {}",
                type_name(other)
            )))
        }
    };
    let encrypt_metadata = encrypt_metadata_of(cfdict);
    Ok(PubKeyCfData::new(Some(list), acts_as_default, encrypt_metadata))
}

/// `cms.ContentInfo.load(data)`: the first TLV (trailing data is ignored).
fn first_tlv(data: &[u8]) -> PdfResult<Vec<u8>> {
    let (t, _) = Tlv::expect(data, tag::SEQUENCE)?;
    Ok(t.raw.to_vec())
}

fn length_bits(d: &Dictionary, default: i64) -> PdfResult<i64> {
    match d.get(b"Length") {
        Err(_) => Ok(default),
        Ok(Object::Integer(n)) => Ok(*n),
        Ok(other) => Err(PdfError::Value(format!("Invalid /Length: {}", type_name(other)))),
    }
}

/// Crypt filter methods of the public-key handler (`_known_crypt_filters`).
pub fn default_crypt_filters() -> CryptFilterRegistry {
    let mut r = CryptFilterRegistry::default();
    r.register(
        "V2",
        Arc::new(|d: &Dictionary, acts_as_default| {
            let bits = length_bits(d, 40)?;
            let keylen = usize::try_from(bits.div_euclid(8)).unwrap_or(0);
            Ok(CryptFilter::pubkey_rc4(keylen, read_generic_pubkey_cf_info(d, acts_as_default)?))
        }),
    );
    r.register(
        "AESV2",
        Arc::new(|d: &Dictionary, a| CryptFilter::pubkey_aes(16, read_generic_pubkey_cf_info(d, a)?)),
    );
    r.register(
        "AESV3",
        Arc::new(|d: &Dictionary, a| CryptFilter::pubkey_aes(32, read_generic_pubkey_cf_info(d, a)?)),
    );
    r.register(
        "AESV4",
        Arc::new(|d: &Dictionary, a| CryptFilter::pubkey_aes_gcm(read_generic_pubkey_cf_info(d, a)?)),
    );
    r.register("Identity", Arc::new(|_, _| Ok(CryptFilter::identity())));
    r
}

/// `PubKeySecurityHandler.read_cf_dictionary`.
pub(crate) fn read_cf_dictionary(
    reg: &CryptFilterRegistry,
    cfdict: &Dictionary,
    acts_as_default: bool,
) -> PdfResult<Option<CryptFilter>> {
    match build_crypt_filter(reg, cfdict, acts_as_default)? {
        Some(cf) => Ok(Some(cf)),
        None => Err(PdfError::Read(
            "An absent CFM or CFM of /None doesn't make sense in a PubSec CF dictionary".into(),
        )),
    }
}

fn pubkey_config(cf: CryptFilter) -> CryptFilterConfiguration {
    CryptFilterConfiguration {
        filters: vec![(DEFAULT_CRYPT_FILTER.as_bytes().to_vec(), cf)],
        stmf: DEFAULT_CRYPT_FILTER.as_bytes().to_vec(),
        strf: DEFAULT_CRYPT_FILTER.as_bytes().to_vec(),
        eff: None,
    }
}

/// `_pubkey_rc4_config`.
pub fn pubkey_rc4_config(keylen: usize, recipients: Option<Vec<Vec<u8>>>, encrypt_metadata: bool) -> CryptFilterConfiguration {
    pubkey_config(CryptFilter::pubkey_rc4(keylen, PubKeyCfData::new(recipients, true, encrypt_metadata)))
}

/// `_pubkey_aes_config`.
pub fn pubkey_aes_config(
    keylen: usize,
    recipients: Option<Vec<Vec<u8>>>,
    encrypt_metadata: bool,
) -> PdfResult<CryptFilterConfiguration> {
    Ok(pubkey_config(CryptFilter::pubkey_aes(
        keylen,
        PubKeyCfData::new(recipients, true, encrypt_metadata),
    )?))
}

/// `_pubkey_gcm_config`.
pub fn pubkey_gcm_config(recipients: Option<Vec<Vec<u8>>>, encrypt_metadata: bool) -> PdfResult<CryptFilterConfiguration> {
    Ok(pubkey_config(CryptFilter::pubkey_aes_gcm(PubKeyCfData::new(
        recipients,
        true,
        encrypt_metadata,
    ))?))
}

/// Options of [`SecurityHandler::build_from_certs`].
#[derive(Clone, Debug)]
pub struct PubKeyEncryptOptions {
    /// Key length in bytes for legacy handlers (default 16).
    pub keylen_bytes: usize,
    /// Handler version (default AES-256).
    pub version: SecurityHandlerVersion,
    /// Use AES-128 instead of RC4 for version 4 (default `true`).
    pub use_aes: bool,
    /// Use crypt filters (`/adbe.pkcs7.s5`; default `true`).
    pub use_crypt_filters: bool,
    /// Permissions.
    pub perms: PubKeyPermissions,
    /// `encrypt_metadata`.
    pub encrypt_metadata: bool,
    /// Recipient policy.
    pub policy: RecipientEncryptionPolicy,
    /// Add an ISO 32004 MAC (PDF 2.0 handlers only; default `true`).
    pub pdf_mac: bool,
    /// `compat_entries`.
    pub compat_entries: bool,
}

impl Default for PubKeyEncryptOptions {
    fn default() -> Self {
        Self {
            keylen_bytes: 16,
            version: SecurityHandlerVersion::Aes256,
            use_aes: true,
            use_crypt_filters: true,
            perms: PubKeyPermissions::allow_everything(),
            encrypt_metadata: true,
            policy: RecipientEncryptionPolicy::default(),
            pdf_mac: true,
            compat_entries: true,
        }
    }
}

/// `_determine_subfilter`.
fn determine_subfilter(encrypt_dict: &Dictionary) -> PdfResult<PubKeyAdbeSubFilter> {
    match encrypt_dict.get(b"SubFilter") {
        Err(_) => Ok(if encrypt_dict.has(b"CF") {
            PubKeyAdbeSubFilter::S5
        } else {
            PubKeyAdbeSubFilter::S4
        }),
        Ok(Object::Name(n)) => PubKeyAdbeSubFilter::from_name(n).ok_or_else(|| {
            PdfError::Read(format!(
                "Invalid /SubFilter in public key encryption dictionary: /{}",
                name_str(n)
            ))
        }),
        Ok(other) => Err(PdfError::Read(format!(
            "Invalid /SubFilter in public key encryption dictionary: {}",
            type_name(other)
        ))),
    }
}

impl SecurityHandler {
    /// `PubKeySecurityHandler.__init__`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_pubkey(
        version: SecurityHandlerVersion,
        subfilter: PubKeyAdbeSubFilter,
        legacy_keylen: usize,
        encrypt_metadata: bool,
        crypt_filter_config: Option<CryptFilterConfiguration>,
        recipient_objs: Option<Vec<Vec<u8>>>,
        compat_entries: bool,
        kdf_salt: Option<Vec<u8>>,
    ) -> PdfResult<Self> {
        if version >= SecurityHandlerVersion::Rc4OrAes128 && subfilter != PubKeyAdbeSubFilter::S5 {
            return Err(PdfError::Generic(
                "Subfilter /adbe.pkcs7.s5 is required for security handlers beyond V4.".into(),
            ));
        }
        let cfc = match crypt_filter_config {
            Some(c) => c,
            None => match version {
                SecurityHandlerVersion::Rc4_40 => pubkey_rc4_config(5, recipient_objs, encrypt_metadata),
                SecurityHandlerVersion::Rc4LongerKeys => {
                    pubkey_rc4_config(legacy_keylen, recipient_objs, encrypt_metadata)
                }
                SecurityHandlerVersion::AesGcm => pubkey_gcm_config(recipient_objs, encrypt_metadata)?,
                v if v >= SecurityHandlerVersion::Aes256 => pubkey_aes_config(32, recipient_objs, encrypt_metadata)?,
                _ => {
                    return Err(PdfError::Generic(
                        "Failed to impute a reasonable crypt filter config".into(),
                    ))
                }
            },
        };
        let state = HandlerState::new(
            version,
            legacy_keylen,
            cfc,
            encrypt_metadata,
            compat_entries,
            kdf_salt,
            HandlerKind::PubKey { subfilter },
        )?;
        Ok(Self::from_state(state))
    }

    /// A public-key handler for new documents (`build_from_certs`);
    /// `certs` are DER certificates.
    pub fn build_from_certs(certs: &[Vec<u8>], opts: PubKeyEncryptOptions) -> PdfResult<Self> {
        let subfilter = if opts.use_crypt_filters {
            PubKeyAdbeSubFilter::S5
        } else {
            PubKeyAdbeSubFilter::S4
        };
        let cfc = if opts.version == SecurityHandlerVersion::Rc4OrAes128 {
            Some(if opts.use_aes {
                pubkey_aes_config(16, None, opts.encrypt_metadata)?
            } else {
                pubkey_rc4_config(opts.keylen_bytes, None, opts.encrypt_metadata)
            })
        } else {
            None
        };
        let mut perms = opts.perms;
        let kdf_salt = if opts.pdf_mac && opts.version >= SecurityHandlerVersion::Aes256 {
            perms = perms - PubKeyPermissions::TOLERATE_MISSING_PDF_MAC;
            Some(random_bytes(32)?)
        } else {
            None
        };
        let sh = Self::new_pubkey(
            opts.version,
            subfilter,
            opts.keylen_bytes,
            opts.encrypt_metadata,
            cfc,
            None,
            opts.compat_entries,
            kdf_salt,
        )?;
        sh.add_recipients(certs, perms, opts.policy)?;
        Ok(sh)
    }

    pub(crate) fn instantiate_pubkey(encrypt_dict: &Dictionary, reg: &CryptFilterRegistry) -> PdfResult<Self> {
        let v = SecurityHandlerVersion::from_number(number_entry(encrypt_dict, "V")?);
        let subfilter = determine_subfilter(encrypt_dict)?;
        let cfc = process_crypt_filters(encrypt_dict, reg, true)?;
        let subfilter2 = determine_subfilter(encrypt_dict)?;
        if cfc.is_some() && subfilter2 != PubKeyAdbeSubFilter::S5 {
            return Err(PdfError::Read(
                "Crypt filters require /adbe.pkcs7.s5 as the declared handler.".into(),
            ));
        } else if cfc.is_none() && subfilter2 == PubKeyAdbeSubFilter::S5 {
            return Err(PdfError::Read("/adbe.pkcs7.s5 handler requires crypt filters.".into()));
        }
        // gather_pub_key_metadata
        let keylen_bits = length_bits(encrypt_dict, 128)?;
        if keylen_bits.rem_euclid(8) != 0 {
            return Err(PdfError::Generic("Key length must be a multiple of 8".into()));
        }
        let keylen = usize::try_from(keylen_bits / 8)
            .map_err(|_| PdfError::Generic("Key length must be positive".into()))?;
        let recipients = match encrypt_dict.get(b"Recipients") {
            Err(_) => None,
            Ok(Object::Array(a)) => Some(
                a.iter()
                    .map(|x| match x {
                        Object::String(s, _) => first_tlv(s),
                        other => Err(PdfError::Value(format!(
                            "Recipient must be a string, not {}",
                            type_name(other)
                        ))),
                    })
                    .collect::<PdfResult<Vec<_>>>()?,
            ),
            Ok(other) => {
                return Err(PdfError::Value(format!(
                    "/Recipients must be an array, not {}",
                    type_name(other)
                )))
            }
        };
        Self::new_pubkey(
            v,
            subfilter,
            keylen,
            encrypt_metadata_of(encrypt_dict),
            cfc,
            recipients,
            true,
            kdf_salt_of(encrypt_dict),
        )
    }

    /// `PubKeySecurityHandler.instantiate_from_pdf_object` with the default
    /// crypt filter methods.
    pub fn instantiate_pubkey_from_pdf_object(encrypt_dict: &Dictionary) -> PdfResult<Self> {
        Self::instantiate_pubkey(encrypt_dict, &default_crypt_filters())
    }

    /// Add recipients to all default public-key crypt filters
    /// (`add_recipients`); `certs` are DER certificates.
    pub fn add_recipients(&self, certs: &[Vec<u8>], perms: PubKeyPermissions, policy: RecipientEncryptionPolicy) -> PdfResult<()> {
        let certs: Vec<CertInfo> = certs.iter().map(|c| CertInfo::from_der(c)).collect::<PdfResult<_>>()?;
        let mut s = self.lock();
        for name in s.cfc.standard_filter_names() {
            if let Some(i) = s.cfc.index_of(&name) {
                if s.cfc.filters[i].1.pubkey.is_some() {
                    cf_add_recipients(&mut s.cfc.filters[i].1, &certs, policy, perms)?;
                }
            }
        }
        Ok(())
    }

    /// Add recipients to the crypt filter named `name` (`cf.add_recipients`).
    pub fn add_crypt_filter_recipients(
        &self,
        name: &str,
        certs: &[Vec<u8>],
        policy: RecipientEncryptionPolicy,
        perms: PubKeyPermissions,
    ) -> PdfResult<()> {
        let certs: Vec<CertInfo> = certs.iter().map(|c| CertInfo::from_der(c)).collect::<PdfResult<_>>()?;
        let mut s = self.lock();
        let n = name.trim_start_matches('/').as_bytes();
        let i = s
            .cfc
            .index_of(n)
            .ok_or_else(|| PdfError::Value(format!("KeyError: /{}", name_str(n))))?;
        cf_add_recipients(&mut s.cfc.filters[i].1, &certs, policy, perms)
    }

    /// Authenticate to the crypt filter named `name` only
    /// (`cf.authenticate`).
    pub fn authenticate_crypt_filter(&self, name: &str, credential: &dyn EnvelopeKeyDecrypter) -> PdfResult<AuthResult> {
        let mut s = self.lock();
        let n = name.trim_start_matches('/').as_bytes();
        let i = s
            .cfc
            .index_of(n)
            .ok_or_else(|| PdfError::Value(format!("KeyError: /{}", name_str(n))))?;
        cf_authenticate(&mut s.cfc.filters[i].1, credential)
    }

    /// Authenticate with a recipient credential
    /// (`PubKeySecurityHandler.authenticate`).
    pub fn authenticate_pubkey(&self, credential: &dyn EnvelopeKeyDecrypter) -> PdfResult<AuthResult> {
        let mut s = self.lock();
        if !matches!(s.kind, HandlerKind::PubKey { .. }) {
            return Err(PdfError::Read(
                "Standard authentication credential must be a string, byte string or _PasswordCredential, not <class 'pyhanko.pdf_utils.crypt.pubkey.SimpleEnvelopeKeyDecrypter'>.".into(),
            ));
        }
        let mut perms = PubKeyPermissions::allow_everything();
        for name in s.cfc.standard_filter_names() {
            let Some(i) = s.cfc.index_of(&name) else { continue };
            if s.cfc.filters[i].1.pubkey.is_none() {
                continue;
            }
            let result = cf_authenticate(&mut s.cfc.filters[i].1, credential)?;
            if result.status == AuthStatus::Failed {
                return Ok(result);
            }
            if let Some(PdfPermissions::PubKey(p)) = result.permission_flags {
                perms = perms & p;
            }
        }
        if let Some(c) = credential.as_serialisable() {
            s.credential = Some(c);
        }
        Ok(AuthResult::new(AuthStatus::User, Some(perms.into())))
    }
}

fn cf_add_recipients(
    cf: &mut CryptFilter,
    certs: &[CertInfo],
    policy: RecipientEncryptionPolicy,
    perms: PubKeyPermissions,
) -> PdfResult<()> {
    let shared_key_set = cf.shared_key.is_some();
    let Some(p) = cf.pubkey.as_mut() else {
        return Err(PdfError::Generic("Not a public-key crypt filter".into()));
    };
    if !p.acts_as_default && p.recipients.as_ref().is_some_and(|r| !r.is_empty()) {
        return Err(PdfError::Generic(
            "A non-default crypt filter cannot have multiple sets of recipients.".into(),
        ));
    }
    if p.recipients.is_none() {
        // a freshly created filter: set up the shared seed
        p.recp_key_seed = Some(random_bytes(20)?);
        p.recipients = Some(Vec::new());
    }
    let Some(seed) = p.recp_key_seed.clone().filter(|_| !shared_key_set) else {
        return Err(PdfError::Generic(
            "Adding recipients after deriving the shared key or before authenticating is not possible.".into(),
        ));
    };
    let new_cms = construct_recipient_cms(certs, &seed, perms, policy, p.acts_as_default)?;
    if let Some(r) = p.recipients.as_mut() {
        r.push(new_cms);
    }
    Ok(())
}

fn cf_authenticate(cf: &mut CryptFilter, credential: &dyn EnvelopeKeyDecrypter) -> PdfResult<AuthResult> {
    let Some(p) = cf.pubkey.as_mut() else {
        return Err(PdfError::Generic("Not a public-key crypt filter".into()));
    };
    for recp in p.recipients.clone().into_iter().flatten() {
        let (seed, perms) = read_seed_from_recipient_cms(&recp, credential)?;
        if let Some(seed) = seed {
            p.recp_key_seed = Some(seed);
            return Ok(AuthResult::new(AuthStatus::User, perms.map(PdfPermissions::PubKey)));
        }
    }
    Ok(AuthResult::new(AuthStatus::Failed, None))
}

pub(crate) fn pubkey_as_pdf_object(s: &HandlerState, subfilter: PubKeyAdbeSubFilter) -> PdfResult<Dictionary> {
    let mut d = Dictionary::new();
    d.set("Filter", Object::Name(b"Adobe.PubSec".to_vec()));
    d.set("SubFilter", Object::Name(subfilter.name().to_vec()));
    d.set("V", s.version.as_pdf_object());
    if let Some(salt) = s.kdf_salt.as_ref().filter(|s| !s.is_empty()) {
        d.set("KDFSalt", byte_string(salt.clone()));
    }
    if s.compat_entries || s.version == SecurityHandlerVersion::Rc4LongerKeys {
        d.set("Length", Object::Integer(s.keylen as i64 * 8));
    }
    if s.version > SecurityHandlerVersion::Rc4LongerKeys {
        d.set("EncryptMetadata", Object::Boolean(s.encrypt_metadata));
    }
    if subfilter == PubKeyAdbeSubFilter::S5 {
        for (k, v) in s.cfc.as_pdf_object()?.into_iter() {
            d.set(k, v);
        }
    } else {
        let cf = s
            .cfc
            .get_raw(&s.cfc.stmf)
            .filter(CryptFilter::is_pubkey)
            .ok_or_else(|| PdfError::Value("The default crypt filter is not a public-key filter".into()))?;
        let recipients = cf.recipients().unwrap_or_default();
        d.set(
            "Recipients",
            Object::Array(recipients.iter().map(|r| byte_string(r.clone())).collect()),
        );
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn x25519_rfc7748() {
        let a: [u8; 32] = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").try_into().unwrap();
        let b_pub = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let k = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519_dh(&a, &b_pub).unwrap().to_vec(), k);
    }

    #[test]
    fn x448_rfc7748() {
        let a: [u8; 56] = unhex(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        )
        .try_into()
        .unwrap();
        let a_pub = unhex(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
        );
        let b_pub = unhex(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        );
        let k = unhex(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
        );
        assert_eq!(x448_public(&a).unwrap().to_vec(), a_pub);
        assert_eq!(x448_dh(&a, &b_pub).unwrap().to_vec(), k);
    }
}
