// Derived from pyHanko `keys/pemder.py` (MIT, see LICENSE-pyHanko), as used
// by `SimpleEnvelopeKeyDecrypter.load` / `load_pkcs12` in
// `pdf_utils/crypt/pubkey.py`.

//! Loading of recipient keys and certificates (PEM or DER; unencrypted or
//! encrypted PKCS#8, OpenSSL "traditional" encrypted PEM, PKCS#12).
//!
//! Only what the public-key security handler needs; lane D owns the general
//! key loading of the signers.

use md5::{Digest, Md5};

use super::asn1::{self, tag, Tlv};
use super::util::{aes_cbc_decrypt, tripledes_decrypt};
use crate::error::{PdfError, PdfResult};

/// One PEM block: label, headers and decoded body.
struct PemBlock {
    label: String,
    headers: Vec<(String, String)>,
    der: Vec<u8>,
}

fn b64_decode(s: &str) -> PdfResult<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in s.as_bytes() {
        if c.is_ascii_whitespace() || c == b'=' {
            continue;
        }
        let v = val(c).ok_or_else(|| PdfError::Value("Invalid base64 in PEM data".into()))?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn is_pem(data: &[u8]) -> bool {
    data.windows(11).any(|w| w == b"-----BEGIN ")
}

fn parse_pem(data: &[u8]) -> PdfResult<Vec<PemBlock>> {
    let text = std::str::from_utf8(data).map_err(|_| PdfError::Value("PEM data is not ASCII".into()))?;
    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(label) = line.trim().strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) else {
            continue;
        };
        let end = format!("-----END {label}-----");
        let mut headers = Vec::new();
        let mut body = String::new();
        let mut in_headers = true;
        let mut closed = false;
        for l in lines.by_ref() {
            let l = l.trim();
            if l == end {
                closed = true;
                break;
            }
            if in_headers {
                if let Some((k, v)) = l.split_once(':') {
                    headers.push((k.trim().to_string(), v.trim().to_string()));
                    continue;
                }
                in_headers = false;
                if l.is_empty() {
                    continue;
                }
            }
            body.push_str(l);
        }
        if !closed {
            return Err(PdfError::Value(format!("PEM block {label} is not terminated")));
        }
        blocks.push(PemBlock {
            label: label.to_string(),
            headers,
            der: b64_decode(&body)?,
        });
    }
    Ok(blocks)
}

/// Load exactly one certificate (`load_cert_from_pemder`), returning DER.
pub(crate) fn load_cert_from_pemder(data: &[u8]) -> PdfResult<Vec<u8>> {
    let certs: Vec<Vec<u8>> = if is_pem(data) {
        parse_pem(data)?
            .into_iter()
            .filter(|b| b.label.eq_ignore_ascii_case("certificate"))
            .map(|b| b.der)
            .collect()
    } else {
        vec![data.to_vec()]
    };
    match certs.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(PdfError::Value("Number of certs should be exactly 1".into())),
    }
}

/// OpenSSL's `EVP_BytesToKey` with MD5 and one iteration.
fn evp_bytes_to_key(pass: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(pass);
        h.update(salt);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    out
}

fn hex_decode(s: &str) -> PdfResult<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(PdfError::Value("Invalid hex IV".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| PdfError::Value("Invalid hex IV".into())))
        .collect()
}

/// Decrypt an OpenSSL "traditional" encrypted PEM body (`DEK-Info`).
fn decrypt_traditional(block: &PemBlock, passphrase: Option<&[u8]>) -> PdfResult<Vec<u8>> {
    let Some((_, dek)) = block.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("DEK-Info")) else {
        return Ok(block.der.clone());
    };
    let pass = passphrase.ok_or_else(|| PdfError::Value("Password was not given but private key is encrypted".into()))?;
    let (alg, iv_hex) = dek
        .split_once(',')
        .ok_or_else(|| PdfError::Value("Malformed DEK-Info".into()))?;
    let iv = hex_decode(iv_hex.trim())?;
    let salt = iv.get(..8).ok_or_else(|| PdfError::Value("Malformed DEK-Info IV".into()))?;
    let keylen = match alg.trim() {
        "AES-128-CBC" => 16,
        "AES-192-CBC" => 24,
        "AES-256-CBC" => 32,
        "DES-EDE3-CBC" => 24,
        other => return Err(PdfError::NotImplemented(format!("Unsupported PEM encryption {other}"))),
    };
    let key = evp_bytes_to_key(pass, salt, keylen);
    if alg.trim() == "DES-EDE3-CBC" {
        tripledes_decrypt(&key, &block.der, &iv)
    } else {
        aes_cbc_decrypt(&key, &block.der, &iv, true)
            .map_err(|_| PdfError::Value("Bad decrypt. Incorrect password?".into()))
    }
}

/// Wrap a PKCS#1 `RSAPrivateKey` into a PKCS#8 `PrivateKeyInfo`.
fn pkcs1_to_pkcs8(pkcs1: &[u8]) -> Vec<u8> {
    let alg = asn1::alg_id("1.2.840.113549.1.1.1", Some(&asn1::tlv(tag::NULL, &[])));
    asn1::seq(&[&asn1::uint(0), &alg, &asn1::octets(pkcs1)])
}

fn is_private_key_info(der: &[u8]) -> bool {
    Tlv::parse_exact(der)
        .and_then(|t| t.children())
        .is_ok_and(|ch| ch.len() >= 3 && ch[0].tag == tag::INTEGER && ch[1].tag == tag::SEQUENCE && ch[2].tag == tag::OCTET_STRING)
}

fn decrypt_pkcs8(der: &[u8], passphrase: Option<&[u8]>) -> PdfResult<Vec<u8>> {
    let pass = passphrase.ok_or_else(|| PdfError::Value("Password was not given but private key is encrypted".into()))?;
    let epki = pkcs8::EncryptedPrivateKeyInfoRef::try_from(der)
        .map_err(|e| PdfError::Value(format!("Could not deserialize key data: {e}")))?;
    let doc = epki
        .decrypt(pass)
        .map_err(|_| PdfError::Value("Bad decrypt. Incorrect password?".into()))?;
    Ok(doc.as_bytes().to_vec())
}

/// Load a private key as unencrypted PKCS#8 DER
/// (`load_private_key_from_pemder_data`).
pub(crate) fn load_private_key_from_pemder(data: &[u8], passphrase: Option<&[u8]>) -> PdfResult<Vec<u8>> {
    if is_pem(data) {
        let blocks = parse_pem(data)?;
        let block = blocks
            .iter()
            .find(|b| b.label.ends_with("PRIVATE KEY"))
            .ok_or_else(|| PdfError::Value("No private key found in PEM data".into()))?;
        return match block.label.as_str() {
            "PRIVATE KEY" => Ok(block.der.clone()),
            "ENCRYPTED PRIVATE KEY" => decrypt_pkcs8(&block.der, passphrase),
            "RSA PRIVATE KEY" => Ok(pkcs1_to_pkcs8(&decrypt_traditional(block, passphrase)?)),
            other => Err(PdfError::NotImplemented(format!("Unsupported key type {other}"))),
        };
    }
    if is_private_key_info(data) {
        return Ok(data.to_vec());
    }
    if passphrase.is_some() {
        if let Ok(k) = decrypt_pkcs8(data, passphrase) {
            return Ok(k);
        }
    }
    let t = Tlv::parse_exact(data).map_err(|_| PdfError::Value("Could not deserialize key data".into()))?;
    if t.children().is_ok_and(|ch| ch.len() >= 9) {
        return Ok(pkcs1_to_pkcs8(data));
    }
    Err(PdfError::Value("Could not deserialize key data".into()))
}

/// Load the first key and certificate from a PKCS#12 file
/// (`SimpleEnvelopeKeyDecrypter.load_pkcs12`): `(pkcs8, cert)`.
pub(crate) fn load_pkcs12(data: &[u8], passphrase: Option<&[u8]>) -> PdfResult<(Vec<u8>, Vec<u8>)> {
    let pass = std::str::from_utf8(passphrase.unwrap_or(b""))
        .map_err(|_| PdfError::Value("PKCS#12 passphrase must be UTF-8".into()))?;
    let pfx = p12::PFX::parse(data).map_err(|e| PdfError::Value(format!("Could not parse PKCS#12 data: {e:?}")))?;
    if !pfx.verify_mac(pass) {
        return Err(PdfError::Value("Invalid password or PKCS12 data".into()));
    }
    let key = pfx
        .key_bags(pass)
        .map_err(|e| PdfError::Value(format!("Could not decrypt PKCS#12 keys: {e:?}")))?
        .into_iter()
        .next()
        .ok_or_else(|| PdfError::Value("No private key in PKCS#12 data".into()))?;
    let cert = pfx
        .cert_x509_bags(pass)
        .map_err(|e| PdfError::Value(format!("Could not decrypt PKCS#12 certificates: {e:?}")))?
        .into_iter()
        .next()
        .ok_or_else(|| PdfError::Value("No certificate in PKCS#12 data".into()))?;
    Ok((key, cert))
}
