// Derived from pyHanko `keys/pemder.py`, `keys/internal.py` and the
// key-loading parts of `sign/signers/pdf_cms.py` (MIT, see LICENSE-pyHanko).

//! Loading private keys and certificates from PEM / DER data
//! (`pyhanko.keys`).
//!
//! pyHanko delegates key parsing to `cryptography`; this module accepts the
//! same container formats:
//!
//! - PKCS#8 `PrivateKeyInfo` (PEM `PRIVATE KEY` or DER),
//! - PKCS#8 `EncryptedPrivateKeyInfo` (PBES1 / PBES2, PEM
//!   `ENCRYPTED PRIVATE KEY` or DER),
//! - PKCS#1 `RSA PRIVATE KEY` and SEC1 `EC PRIVATE KEY`, optionally with
//!   OpenSSL's legacy `Proc-Type: 4,ENCRYPTED` / `DEK-Info` encryption,
//! - PKCS#12 (see [`crate::pkcs12`]).

use base64ct::Encoding;
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use hanko_core::asn1::oids;
use hanko_core::cert::Cert;
use hanko_core::errors::{HankoError, Result};
use pkcs8::{EncryptedPrivateKeyInfoRef, PrivateKeyInfoOwned};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// A private key held in memory, with the key types pyHanko's
/// `SimpleSigner` supports.
#[derive(Clone)]
pub enum PrivateKey {
    /// RSA.
    Rsa(Box<rsa::RsaPrivateKey>),
    /// ECDSA on P-256.
    P256(p256::ecdsa::SigningKey),
    /// ECDSA on P-384.
    P384(p384::ecdsa::SigningKey),
    /// ECDSA on P-521.
    P521(Box<p521::ecdsa::SigningKey>),
    /// Ed25519.
    Ed25519(Box<ed25519_dalek::SigningKey>),
    /// Ed448.
    Ed448(Box<ed448_goldilocks::SigningKey>),
    /// ML-DSA-44 (FIPS 204).
    MlDsa44(Box<ml_dsa::SigningKey<ml_dsa::MlDsa44>>),
    /// ML-DSA-65.
    MlDsa65(Box<ml_dsa::SigningKey<ml_dsa::MlDsa65>>),
    /// ML-DSA-87.
    MlDsa87(Box<ml_dsa::SigningKey<ml_dsa::MlDsa87>>),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rsa(_) => "PrivateKey::Rsa(..)",
            Self::P256(_) => "PrivateKey::P256(..)",
            Self::P384(_) => "PrivateKey::P384(..)",
            Self::P521(_) => "PrivateKey::P521(..)",
            Self::Ed25519(_) => "PrivateKey::Ed25519(..)",
            Self::Ed448(_) => "PrivateKey::Ed448(..)",
            Self::MlDsa44(_) => "PrivateKey::MlDsa44(..)",
            Self::MlDsa65(_) => "PrivateKey::MlDsa65(..)",
            Self::MlDsa87(_) => "PrivateKey::MlDsa87(..)",
        })
    }
}

fn malformed(what: impl std::fmt::Display) -> HankoError {
    HankoError::Malformed(what.to_string())
}

fn unsupported(what: impl std::fmt::Display) -> HankoError {
    HankoError::Unsupported(what.to_string())
}

impl PrivateKey {
    /// Decode an unencrypted PKCS#8 `PrivateKeyInfo`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let pki = PrivateKeyInfoOwned::from_der(der)
            .map_err(|e| malformed(format!("PKCS#8 private key: {e}")))?;
        let oid = pki.algorithm.oid;
        let key_bytes = pki.private_key.as_bytes();
        match oid {
            oids::RSA_ENCRYPTION | oids::RSASSA_PSS => Self::from_pkcs1_der(key_bytes),
            oids::EC_PUBLIC_KEY => {
                let curve = pki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
                Self::from_sec1_der(key_bytes, curve)
            }
            oids::ED25519 => {
                let seed = OctetString::from_der(key_bytes)
                    .map_err(|e| malformed(format!("Ed25519 key: {e}")))?;
                let seed: [u8; 32] = seed
                    .as_bytes()
                    .try_into()
                    .map_err(|_| malformed("Ed25519 key: wrong length"))?;
                Ok(Self::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(
                    &seed,
                ))))
            }
            oids::ED448 => {
                use pkcs8::DecodePrivateKey;
                let k = ed448_goldilocks::SigningKey::from_pkcs8_der(der)
                    .map_err(|e| malformed(format!("Ed448 private key: {e}")))?;
                Ok(Self::Ed448(Box::new(k)))
            }
            oids::DSA => Err(unsupported("DSA private keys are not supported")),
            oids::ML_DSA_44 | oids::ML_DSA_65 | oids::ML_DSA_87 => {
                use pkcs8::DecodePrivateKey;
                let bad = |e: pkcs8::Error| malformed(format!("ML-DSA private key: {e}"));
                Ok(match oid {
                    oids::ML_DSA_44 => Self::MlDsa44(Box::new(
                        ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_pkcs8_der(der).map_err(bad)?,
                    )),
                    oids::ML_DSA_65 => Self::MlDsa65(Box::new(
                        ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_pkcs8_der(der).map_err(bad)?,
                    )),
                    _ => Self::MlDsa87(Box::new(
                        ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_pkcs8_der(der).map_err(bad)?,
                    )),
                })
            }
            other => Err(unsupported(format!("private key algorithm {other}"))),
        }
    }

    /// Decode a PKCS#1 `RSAPrivateKey`.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs1_der(der)
            .map_err(|e| malformed(format!("RSA private key: {e}")))?;
        Ok(Self::Rsa(Box::new(key)))
    }

    /// Decode a SEC1 `ECPrivateKey`; `curve` overrides the curve named in
    /// the structure (as in PKCS#8, where the curve is in the algorithm).
    pub fn from_sec1_der(der: &[u8], curve: Option<ObjectIdentifier>) -> Result<Self> {
        let ec = Sec1EcPrivateKey::from_der(der)
            .map_err(|e| malformed(format!("EC private key: {e}")))?;
        let curve = curve
            .or(ec.parameters)
            .ok_or_else(|| malformed("EC private key without named curve"))?;
        let scalar = ec.private_key.as_bytes();
        let bad = |e: ecdsa::Error| malformed(format!("EC private key: {e}"));
        match curve {
            oids::SECP256R1 => Ok(Self::P256(
                p256::ecdsa::SigningKey::from_slice(scalar).map_err(bad)?,
            )),
            oids::SECP384R1 => Ok(Self::P384(
                p384::ecdsa::SigningKey::from_slice(scalar).map_err(bad)?,
            )),
            oids::SECP521R1 => Ok(Self::P521(Box::new(
                p521::ecdsa::SigningKey::from_slice(scalar).map_err(bad)?,
            ))),
            other => Err(unsupported(format!("elliptic curve {other}"))),
        }
    }

    /// The `SubjectPublicKeyInfo` of the matching public key.
    pub fn public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned> {
        let der = match self {
            Self::Rsa(k) => {
                use rsa::pkcs8::EncodePublicKey;
                k.to_public_key()
                    .to_public_key_der()
                    .map_err(malformed)?
                    .into_vec()
            }
            Self::P256(k) => ec_spki(
                oids::SECP256R1,
                k.verifying_key().to_sec1_point(false).as_bytes(),
            )?,
            Self::P384(k) => ec_spki(
                oids::SECP384R1,
                k.verifying_key().to_sec1_point(false).as_bytes(),
            )?,
            Self::P521(k) => ec_spki(
                oids::SECP521R1,
                k.verifying_key().to_sec1_point(false).as_bytes(),
            )?,
            Self::Ed25519(k) => SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: oids::ED25519,
                    parameters: None,
                },
                subject_public_key: der::asn1::BitString::from_bytes(
                    k.verifying_key().as_bytes(),
                )?,
            }
            .to_der()?,
            Self::Ed448(k) => SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: oids::ED448,
                    parameters: None,
                },
                subject_public_key: der::asn1::BitString::from_bytes(
                    k.verifying_key().to_bytes().as_slice(),
                )?,
            }
            .to_der()?,
            Self::MlDsa44(k) => mldsa_spki(k.as_ref())?,
            Self::MlDsa65(k) => mldsa_spki(k.as_ref())?,
            Self::MlDsa87(k) => mldsa_spki(k.as_ref())?,
        };
        Ok(SubjectPublicKeyInfoOwned::from_der(&der)?)
    }

    /// Short name of the key algorithm (`rsa`, `ec`, `ed25519`), as in
    /// asn1crypto's `PublicKeyInfo.algorithm`.
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Rsa(_) => "rsa",
            Self::P256(_) | Self::P384(_) | Self::P521(_) => "ec",
            Self::Ed25519(_) => "ed25519",
            Self::Ed448(_) => "ed448",
            Self::MlDsa44(_) => "mldsa44",
            Self::MlDsa65(_) => "mldsa65",
            Self::MlDsa87(_) => "mldsa87",
        }
    }
}

fn mldsa_spki<P: ml_dsa::MlDsaParams>(k: &ml_dsa::SigningKey<P>) -> Result<Vec<u8>>
where
    ml_dsa::VerifyingKey<P>: pkcs8::EncodePublicKey,
{
    use pkcs8::EncodePublicKey;
    use signature::Keypair;
    Ok(k.verifying_key()
        .to_public_key_der()
        .map_err(|e| malformed(format!("ML-DSA public key: {e}")))?
        .into_vec())
}

fn ec_spki(curve: ObjectIdentifier, point: &[u8]) -> Result<Vec<u8>> {
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: oids::EC_PUBLIC_KEY,
            parameters: Some(der::Any::encode_from(&curve)?),
        },
        subject_public_key: der::asn1::BitString::from_bytes(point)?,
    }
    .to_der()?)
}

/// SEC1 `ECPrivateKey` (RFC 5915), decoded leniently.
#[derive(der::Sequence)]
struct Sec1EcPrivateKey {
    _version: u8,
    private_key: OctetString,
    #[asn1(context_specific = "0", optional = "true")]
    parameters: Option<ObjectIdentifier>,
    #[asn1(context_specific = "1", optional = "true")]
    _public_key: Option<der::asn1::BitString>,
}

/// One PEM block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PemBlock {
    /// The label after `BEGIN`.
    pub label: String,
    /// RFC 1421 headers (`Proc-Type`, `DEK-Info`), in order.
    pub headers: Vec<(String, String)>,
    /// Decoded body.
    pub der: Vec<u8>,
}

/// `true` if `data` looks like PEM (asn1crypto's `pem.detect`).
pub fn is_pem(data: &[u8]) -> bool {
    find(data, b"-----BEGIN").is_some()
}

/// Parse every PEM block in `data`. Text outside the blocks is ignored.
pub fn parse_pem(data: &[u8]) -> Result<Vec<PemBlock>> {
    let text = String::from_utf8_lossy(data);
    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        else {
            continue;
        };
        let end_marker = format!("-----END {label}-----");
        let mut headers = Vec::new();
        let mut body = String::new();
        let mut ended = false;
        for l in lines.by_ref() {
            let l = l.trim();
            if l == end_marker {
                ended = true;
                break;
            }
            if body.is_empty() {
                if let Some((k, v)) = l.split_once(':') {
                    headers.push((k.trim().to_owned(), v.trim().to_owned()));
                    continue;
                }
            }
            body.push_str(l);
        }
        if !ended {
            return Err(malformed(format!("PEM block {label}: no END line")));
        }
        let der = base64ct::Base64::decode_vec(&body)
            .map_err(|e| malformed(format!("PEM block {label}: {e}")))?;
        blocks.push(PemBlock {
            label: label.to_owned(),
            headers,
            der,
        });
    }
    Ok(blocks)
}

/// Load certificates from PEM or DER data (`load_certs_from_pemder_data`).
/// PEM blocks with a label other than `CERTIFICATE` are skipped.
pub fn load_certs_from_pemder_data(data: &[u8]) -> Result<Vec<Cert>> {
    if is_pem(data) {
        parse_pem(data)?
            .into_iter()
            .filter(|b| b.label.eq_ignore_ascii_case("certificate"))
            .map(|b| Cert::from_der(&b.der).map_err(Into::into))
            .collect()
    } else {
        Ok(vec![Cert::from_der(data)?])
    }
}

/// Load exactly one certificate (`load_cert_from_pemder`).
pub fn load_cert_from_pemder_data(data: &[u8]) -> Result<Cert> {
    let mut certs = load_certs_from_pemder_data(data)?;
    if certs.len() != 1 {
        return Err(malformed(format!(
            "Number of certs should be exactly 1, found {}",
            certs.len()
        )));
    }
    Ok(certs.remove(0))
}

/// Load a private key from PEM or DER data
/// (`load_private_key_from_pemder_data`).
pub fn load_private_key_from_pemder_data(
    data: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<PrivateKey> {
    if !is_pem(data) {
        return load_private_key_der(data, passphrase);
    }
    let blocks = parse_pem(data)?;
    let block = blocks
        .iter()
        .find(|b| b.label.ends_with("PRIVATE KEY"))
        .ok_or_else(|| malformed("no private key in PEM data"))?;
    let encrypted_legacy = block
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("Proc-Type") && v.contains("ENCRYPTED"));
    let der = if encrypted_legacy {
        let pass = passphrase.ok_or_else(|| {
            HankoError::Malformed("Password was not given but private key is encrypted".into())
        })?;
        decrypt_legacy_pem(block, pass)?
    } else {
        block.der.clone()
    };
    match block.label.as_str() {
        "PRIVATE KEY" => PrivateKey::from_pkcs8_der(&der),
        "ENCRYPTED PRIVATE KEY" => decrypt_pkcs8(&der, passphrase),
        "RSA PRIVATE KEY" => PrivateKey::from_pkcs1_der(&der),
        "EC PRIVATE KEY" => PrivateKey::from_sec1_der(&der, None),
        other => Err(unsupported(format!("PEM key type {other}"))),
    }
}

fn load_private_key_der(der: &[u8], passphrase: Option<&[u8]>) -> Result<PrivateKey> {
    if PrivateKeyInfoOwned::from_der(der).is_ok() {
        return PrivateKey::from_pkcs8_der(der);
    }
    if EncryptedPrivateKeyInfoRef::from_der(der).is_ok() {
        return decrypt_pkcs8(der, passphrase);
    }
    PrivateKey::from_pkcs1_der(der).or_else(|_| PrivateKey::from_sec1_der(der, None))
}

fn decrypt_pkcs8(der: &[u8], passphrase: Option<&[u8]>) -> Result<PrivateKey> {
    let pass = passphrase.ok_or_else(|| {
        HankoError::Malformed("Password was not given but private key is encrypted".into())
    })?;
    let info = EncryptedPrivateKeyInfoRef::from_der(der)
        .map_err(|e| malformed(format!("encrypted PKCS#8 key: {e}")))?;
    let doc = info
        .decrypt(pass)
        .map_err(|_| malformed("Bad decrypt. Incorrect password?"))?;
    PrivateKey::from_pkcs8_der(doc.as_bytes())
}

/// OpenSSL's `EVP_BytesToKey` with MD5 and one iteration.
fn evp_bytes_to_key(pass: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    use md5::Digest;
    let mut out = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut h = md5::Md5::new();
        h.update(&prev);
        h.update(pass);
        h.update(salt);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

fn decrypt_legacy_pem(block: &PemBlock, pass: &[u8]) -> Result<Vec<u8>> {
    let dek = block
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("DEK-Info"))
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| malformed("encrypted PEM without DEK-Info"))?;
    let (alg, iv_hex) = dek
        .split_once(',')
        .ok_or_else(|| malformed("malformed DEK-Info"))?;
    let iv = decode_hex(iv_hex.trim()).ok_or_else(|| malformed("malformed DEK-Info IV"))?;
    if iv.len() < 8 {
        return Err(malformed("DEK-Info IV too short"));
    }
    let bad = || malformed("Bad decrypt. Incorrect password?");
    let alg = alg.trim().to_ascii_uppercase();
    let key_len = match alg.as_str() {
        "AES-128-CBC" => 16,
        "AES-192-CBC" => 24,
        "AES-256-CBC" => 32,
        "DES-EDE3-CBC" => 24,
        "DES-CBC" => 8,
        other => return Err(unsupported(format!("PEM encryption {other}"))),
    };
    let key = evp_bytes_to_key(pass, &iv[..8], key_len);
    crate::pkcs12::cbc_decrypt(&alg, &key, &iv, &block.der).ok_or_else(bad)
}

pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_bytes_to_key_matches_openssl() {
        // `openssl enc -aes-256-cbc -k secret -S 0001020304050607 -P -md md5`
        let key = evp_bytes_to_key(b"secret", &[0, 1, 2, 3, 4, 5, 6, 7], 32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn hex() {
        assert_eq!(decode_hex("0aFF"), Some(vec![10, 255]));
        assert_eq!(decode_hex("0"), None);
    }
}
