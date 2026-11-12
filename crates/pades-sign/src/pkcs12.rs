// Replaces `cryptography.hazmat.primitives.serialization.pkcs12`, which
// pyHanko's `SimpleSigner.load_pkcs12_data` (`sign/signers/pdf_cms.py`, MIT,
// see LICENSE-pyHanko) calls.

//! PKCS#12 (RFC 7292) decoding: the key and certificates of a `.pfx` file.
//!
//! No maintained Rust crate decodes PKCS#12 with the RustCrypto 0.8 / 0.11
//! stack that the workspace pins (`p12` uses the 0.4 cipher stack and lacks
//! PBES2), so this module implements the container on top of `der` / `cms`
//! types and RustCrypto ciphers. It supports what OpenSSL and `cryptography`
//! produce: MAC with SHA-1 / SHA-2 HMAC, legacy PBEs
//! (`pbeWithSHAAnd3-KeyTripleDES-CBC`, `pbeWithSHAAnd40BitRC2-CBC`,
//! `pbeWithSHAAnd128BitRC2-CBC`) and PBES2.

use cms::content_info::ContentInfo;
use cms::encrypted_data::EncryptedData;
use der::asn1::{ObjectIdentifier as Oid, OctetString};
use der::{Any, Decode, Encode, Sequence};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};
use spki::AlgorithmIdentifierOwned;

use crate::keys::PrivateKey;

const ID_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
const ID_ENCRYPTED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.6");
const KEY_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.1");
const SHROUDED_KEY_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.2");
const CERT_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.3");
const X509_CERTIFICATE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.22.1");
const LOCAL_KEY_ID: Oid = Oid::new_unwrap("1.2.840.113549.1.9.21");
const PBE_SHA1_3DES: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.3");
const PBE_SHA1_2DES: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.4");
const PBE_SHA1_RC2_128: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.5");
const PBE_SHA1_RC2_40: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.6");
const PBES2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.13");
const SHA1: Oid = Oid::new_unwrap("1.3.14.3.2.26");
const SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
const SHA512: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");

#[derive(Sequence)]
struct Pfx {
    _version: u8,
    auth_safe: ContentInfo,
    #[asn1(optional = "true")]
    mac_data: Option<MacData>,
}

#[derive(Sequence)]
struct MacData {
    mac: DigestInfo,
    mac_salt: OctetString,
    #[asn1(default = "one")]
    iterations: u32,
}

fn one() -> u32 {
    1
}

#[derive(Sequence)]
struct DigestInfo {
    algorithm: AlgorithmIdentifierOwned,
    digest: OctetString,
}

#[derive(Sequence)]
struct SafeBag {
    bag_id: Oid,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    bag_value: Any,
    #[asn1(optional = "true")]
    bag_attributes: Option<der::asn1::SetOfVec<x509_cert::attr::Attribute>>,
}

#[derive(Sequence)]
struct CertBag {
    cert_id: Oid,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    cert_value: OctetString,
}

#[derive(Sequence)]
struct EncryptedPrivateKeyInfo {
    algorithm: AlgorithmIdentifierOwned,
    data: OctetString,
}

#[derive(Sequence)]
struct PbeParams {
    salt: OctetString,
    iterations: u32,
}

/// Key and certificates from a PKCS#12 file.
#[derive(Debug)]
pub struct Pkcs12Contents {
    /// The private key, if any.
    pub key: Option<PrivateKey>,
    /// The certificate matching the key (by `localKeyId`, else by public
    /// key), if any.
    pub cert: Option<Cert>,
    /// The other certificates.
    pub other_certs: Vec<Cert>,
}

fn err(msg: impl Into<String>) -> HankoError {
    HankoError::Malformed(format!(
        "Could not load key material from PKCS#12 data: {}",
        msg.into()
    ))
}

/// Decode a PKCS#12 file. `passphrase` `None` and `Some(b"")` are both
/// tried as the empty password, as OpenSSL does.
pub fn load_pkcs12(data: &[u8], passphrase: Option<&[u8]>) -> Result<Pkcs12Contents> {
    let pfx = Pfx::from_der(data).map_err(|e| err(e.to_string()))?;
    if pfx.auth_safe.content_type != ID_DATA {
        return Err(err("public-key integrity mode is not supported"));
    }
    let auth_safe_bytes = pfx
        .auth_safe
        .content
        .decode_as::<OctetString>()
        .map_err(|e| err(e.to_string()))?;
    let pass = passphrase.unwrap_or(b"");
    // Candidate BMPString encodings of the password: with the trailing NUL
    // (RFC 7292), and the zero-length form some writers use for "no password".
    let mut candidates = vec![bmp_password(pass)];
    if pass.is_empty() {
        candidates.push(Vec::new());
    }
    let bmp_pass = match &pfx.mac_data {
        Some(mac) => candidates
            .into_iter()
            .find(|c| verify_mac(mac, c, auth_safe_bytes.as_bytes()).unwrap_or(false))
            .ok_or_else(|| err("MAC verification failed (wrong password?)"))?,
        None => candidates.remove(0),
    };

    let safes: Vec<ContentInfo> =
        Vec::<ContentInfo>::from_der(auth_safe_bytes.as_bytes()).map_err(|e| err(e.to_string()))?;
    let mut bags = Vec::new();
    for ci in safes {
        let contents = if ci.content_type == ID_DATA {
            ci.content
                .decode_as::<OctetString>()
                .map_err(|e| err(e.to_string()))?
                .as_bytes()
                .to_vec()
        } else if ci.content_type == ID_ENCRYPTED_DATA {
            let ed = ci.content.decode_as::<EncryptedData>().map_err(|e| err(e.to_string()))?;
            let enc = ed
                .enc_content_info
                .encrypted_content
                .ok_or_else(|| err("encrypted data without content"))?;
            pbe_decrypt(
                &ed.enc_content_info.content_enc_alg,
                pass,
                &bmp_pass,
                enc.as_bytes(),
            )?
        } else {
            return Err(err(format!("unsupported content type {}", ci.content_type)));
        };
        let safe_bags =
            Vec::<SafeBag>::from_der(&contents).map_err(|e| err(e.to_string()))?;
        bags.extend(safe_bags);
    }

    let mut key = None;
    let mut key_id = None;
    let mut certs: Vec<(Cert, Option<Vec<u8>>)> = Vec::new();
    for bag in bags {
        let local_id = bag.bag_attributes.as_ref().and_then(|attrs| {
            attrs
                .iter()
                .find(|a| a.oid == LOCAL_KEY_ID)
                .and_then(|a| a.values.iter().next())
                .and_then(|v| v.decode_as::<OctetString>().ok())
                .map(|o| o.as_bytes().to_vec())
        });
        match bag.bag_id {
            KEY_BAG => {
                let der = bag.bag_value.to_der()?;
                key = Some(PrivateKey::from_pkcs8_der(&der)?);
                key_id = local_id;
            }
            SHROUDED_KEY_BAG => {
                let epki: EncryptedPrivateKeyInfo =
                    bag.bag_value.decode_as::<EncryptedPrivateKeyInfo>().map_err(|e| err(e.to_string()))?;
                let der = pbe_decrypt(&epki.algorithm, pass, &bmp_pass, epki.data.as_bytes())?;
                key = Some(PrivateKey::from_pkcs8_der(&der)?);
                key_id = local_id;
            }
            CERT_BAG => {
                let cb = bag.bag_value.decode_as::<CertBag>().map_err(|e| err(e.to_string()))?;
                if cb.cert_id == X509_CERTIFICATE {
                    certs.push((Cert::from_der(cb.cert_value.as_bytes())?, local_id));
                }
            }
            _ => {}
        }
    }

    let mut cert_idx = None;
    if key.is_some() {
        if let Some(id) = &key_id {
            cert_idx = certs.iter().position(|(_, cid)| cid.as_ref() == Some(id));
        }
        if cert_idx.is_none() {
            if let Some(spki) = key.as_ref().and_then(|k| k.public_key_info().ok()) {
                cert_idx = certs.iter().position(|(c, _)| c.public_key() == spki);
            }
        }
    }
    let cert = cert_idx.map(|i| certs.remove(i).0);
    Ok(Pkcs12Contents {
        key,
        cert,
        other_certs: certs.into_iter().map(|(c, _)| c).collect(),
    })
}

fn bmp_password(pass: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(pass);
    let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_be_bytes).collect();
    out.extend_from_slice(&[0, 0]);
    out
}

#[derive(Clone, Copy)]
enum Md {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Md {
    fn from_oid(oid: &Oid) -> Option<Self> {
        Some(match *oid {
            SHA1 => Self::Sha1,
            SHA256 => Self::Sha256,
            SHA384 => Self::Sha384,
            SHA512 => Self::Sha512,
            _ => return None,
        })
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn block_len(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha256 => 64,
            Self::Sha384 | Self::Sha512 => 128,
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{KeyInit, Mac};
        macro_rules! run {
            ($h:ty) => {{
                match hmac::Hmac::<$h>::new_from_slice(key) {
                    Ok(mut m) => {
                        m.update(data);
                        m.finalize().into_bytes().to_vec()
                    }
                    Err(_) => Vec::new(),
                }
            }};
        }
        match self {
            Self::Sha1 => run!(sha1::Sha1),
            Self::Sha256 => run!(sha2::Sha256),
            Self::Sha384 => run!(sha2::Sha384),
            Self::Sha512 => run!(sha2::Sha512),
        }
    }
}

/// The PKCS#12 key derivation function (RFC 7292, appendix B.2).
fn pkcs12_kdf(md: Md, bmp_pass: &[u8], salt: &[u8], id: u8, iterations: u32, n: usize) -> Vec<u8> {
    let u = md.output_len();
    let v = md.block_len();
    let fill = |src: &[u8]| -> Vec<u8> {
        if src.is_empty() {
            return Vec::new();
        }
        let len = v * src.len().div_ceil(v);
        (0..len).map(|i| src[i % src.len()]).collect()
    };
    let d = vec![id; v];
    let mut i_buf = fill(salt);
    i_buf.extend(fill(bmp_pass));
    let mut out = Vec::with_capacity(n + u);
    while out.len() < n {
        let mut a = md.hash(&[d.as_slice(), &i_buf].concat());
        for _ in 1..iterations.max(1) {
            a = md.hash(&a);
        }
        out.extend_from_slice(&a);
        if out.len() >= n {
            break;
        }
        let b: Vec<u8> = (0..v).map(|k| a[k % u]).collect();
        for chunk in i_buf.chunks_mut(v) {
            // chunk = (chunk + b + 1) mod 2^(8v)
            let mut carry: u16 = 1;
            for k in (0..chunk.len()).rev() {
                let s = u16::from(chunk[k]) + u16::from(b[k]) + carry;
                chunk[k] = (s & 0xff) as u8;
                carry = s >> 8;
            }
        }
    }
    out.truncate(n);
    out
}

fn verify_mac(mac: &MacData, bmp_pass: &[u8], data: &[u8]) -> Result<bool> {
    let md = Md::from_oid(&mac.mac.algorithm.oid)
        .ok_or_else(|| err(format!("MAC digest {}", mac.mac.algorithm.oid)))?;
    let key = pkcs12_kdf(md, bmp_pass, mac.mac_salt.as_bytes(), 3, mac.iterations, md.output_len());
    Ok(md.hmac(&key, data) == mac.mac.digest.as_bytes())
}

fn pbe_decrypt(
    alg: &AlgorithmIdentifierOwned,
    pass: &[u8],
    bmp_pass: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let bad = || err("decryption failed (wrong password?)");
    if alg.oid == PBES2 {
        let der = alg.to_der()?;
        let scheme = pkcs8::pkcs5::EncryptionScheme::try_from(
            spki::AlgorithmIdentifierRef::from_der(&der).map_err(|e| err(e.to_string()))?,
        )
        .map_err(|e: der::Error| err(e.to_string()))?;
        return scheme.decrypt(pass, data).map_err(|_| bad());
    }
    let params: PbeParams = alg
        .parameters
        .as_ref()
        .ok_or_else(|| err("PBE without parameters"))?
        .decode_as::<PbeParams>()
        .map_err(|e| err(e.to_string()))?;
    let salt = params.salt.as_bytes();
    let it = params.iterations;
    let derive = |id, n| pkcs12_kdf(Md::Sha1, bmp_pass, salt, id, it, n);
    let (cipher, key_len) = match alg.oid {
        PBE_SHA1_3DES => ("DES-EDE3-CBC", 24),
        PBE_SHA1_2DES => ("DES-EDE2-CBC", 16),
        PBE_SHA1_RC2_128 => ("RC2-128-CBC", 16),
        PBE_SHA1_RC2_40 => ("RC2-40-CBC", 5),
        other => return Err(err(format!("unsupported encryption algorithm {other}"))),
    };
    let key = derive(1, key_len);
    let iv = derive(2, 8);
    cbc_decrypt(cipher, &key, &iv, data).ok_or_else(bad)
}

/// CBC decryption with PKCS#7 padding for the ciphers that PKCS#12 and
/// legacy PEM encryption use. Returns `None` on a bad key or padding.
pub(crate) fn cbc_decrypt(cipher: &str, key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
    use cbc_legacy::cipher::{
        block_padding::Pkcs7 as Pkcs7Legacy, BlockDecryptMut, InnerIvInit, KeyIvInit as _,
    };
    macro_rules! modern {
        ($c:ty) => {
            cbc::Decryptor::<$c>::new_from_slices(key, iv)
                .ok()?
                .decrypt_padded_vec::<Pkcs7>(data)
                .ok()
        };
    }
    macro_rules! legacy {
        ($c:ty) => {
            cbc_legacy::Decryptor::<$c>::new_from_slices(key, iv)
                .ok()?
                .decrypt_padded_vec_mut::<Pkcs7Legacy>(data)
                .ok()
        };
    }
    match cipher {
        "AES-128-CBC" => modern!(aes::Aes128),
        "AES-192-CBC" => modern!(aes::Aes192),
        "AES-256-CBC" => modern!(aes::Aes256),
        "DES-EDE3-CBC" => legacy!(des::TdesEde3),
        "DES-EDE2-CBC" => {
            let mut k = key.to_vec();
            k.extend_from_slice(key.get(..8)?);
            cbc_legacy::Decryptor::<des::TdesEde3>::new_from_slices(&k, iv)
                .ok()?
                .decrypt_padded_vec_mut::<Pkcs7Legacy>(data)
                .ok()
        }
        "DES-CBC" => legacy!(des::Des),
        "RC2-40-CBC" | "RC2-128-CBC" => {
            let rc2 = rc2::Rc2::new_with_eff_key_len(key, key.len() * 8);
            cbc_legacy::Decryptor::<rc2::Rc2>::inner_iv_slice_init(rc2, iv)
                .ok()?
                .decrypt_padded_vec_mut::<Pkcs7Legacy>(data)
                .ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_vector() {
        // RFC 7292 KDF test vector from OpenSSL's test suite
        // (pkcs12 KDF, SHA-1, password "smeg", salt 0A58CF64530D823F, id 1,
        // iteration 1, 24 bytes).
        let pass = bmp_password(b"smeg");
        let salt = [0x0A, 0x58, 0xCF, 0x64, 0x53, 0x0D, 0x82, 0x3F];
        let k = pkcs12_kdf(Md::Sha1, &pass, &salt, 1, 1, 24);
        assert_eq!(
            k,
            crate::keys::decode_hex("8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3")
                .unwrap_or_default()
        );
    }
}
