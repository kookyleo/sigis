// Derived from pyHanko `pdf_utils/crypt/_legacy.py` (MIT, see LICENSE-pyHanko),
// which follows the algorithms of the PDF 1.6 reference, section 3.5.2.

//! Key derivation of the legacy (RC4 / AES-128) standard security handler.

use md5::{Digest, Md5};

use super::permissions::StandardPermissions;
use super::util::rc4_encrypt;
use crate::error::PdfResult;
use crate::generic::encode_pdfdocencoding;

/// The 32-byte password padding string of Algorithm 2.
pub(crate) const ENCRYPTION_PADDING: [u8; 32] = [
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
    0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
];

fn padded(password: &[u8]) -> Vec<u8> {
    let mut p = password.to_vec();
    p.extend_from_slice(&ENCRYPTION_PADDING);
    p.truncate(32);
    p
}

fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

/// Algorithm 2 (algorithm 3.2 in PDF 1.6): file key from the user password
/// (`derive_legacy_file_key`).
pub(crate) fn derive_legacy_file_key(
    password: &[u8],
    rev: i64,
    keylen: usize,
    owner_entry: &[u8],
    p_entry: StandardPermissions,
    id1_entry: &[u8],
    encrypt_metadata: bool,
) -> Vec<u8> {
    let mut m = Md5::new();
    m.update(padded(password));
    m.update(owner_entry);
    m.update(p_entry.as_uint32().to_le_bytes());
    m.update(id1_entry);
    if rev >= 4 && !encrypt_metadata {
        m.update([0xff; 4]);
    }
    let mut hash: [u8; 16] = m.finalize().into();
    if rev >= 3 {
        for _ in 0..50 {
            hash = md5(&hash[..keylen.min(16)]);
        }
    }
    hash[..keylen.min(16)].to_vec()
}

/// Password normalisation for legacy handlers: text is encoded in
/// PDFDocEncoding, everything is truncated to 32 bytes (`legacy_normalise_pw`).
pub(crate) fn legacy_normalise_pw_text(password: &str) -> PdfResult<Vec<u8>> {
    let truncated: String = password.chars().take(32).collect();
    encode_pdfdocencoding(&truncated)
}

/// Byte passwords are truncated to 32 bytes (`legacy_normalise_pw`).
pub(crate) fn legacy_normalise_pw_bytes(password: &[u8]) -> Vec<u8> {
    password[..password.len().min(32)].to_vec()
}

/// Algorithm 3 (3.3), the `/O` value (`compute_o_value_legacy`).
pub(crate) fn compute_o_value_legacy(owner_pwd: &[u8], user_pwd: &[u8], rev: i64, keylen: usize) -> Vec<u8> {
    let key = compute_o_value_legacy_prep(owner_pwd, rev, keylen);
    let mut val = rc4_encrypt(&key, &padded(user_pwd));
    if rev >= 3 {
        for i in 1..20u8 {
            let new_key: Vec<u8> = key.iter().map(|b| b ^ i).collect();
            val = rc4_encrypt(&new_key, &val);
        }
    }
    val
}

/// Steps 1–4 of algorithm 3 (`compute_o_value_legacy_prep`).
pub(crate) fn compute_o_value_legacy_prep(password: &[u8], rev: i64, keylen: usize) -> Vec<u8> {
    let mut hash = md5(&padded(password));
    if rev >= 3 {
        for _ in 0..50 {
            hash = md5(&hash);
        }
    }
    hash[..keylen.min(16)].to_vec()
}

/// Algorithm 4 (3.4), the `/U` value for revision 2 (`compute_u_value_r2`).
pub(crate) fn compute_u_value_r2(
    password: &[u8],
    owner_entry: &[u8],
    p_entry: StandardPermissions,
    id1_entry: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let key = derive_legacy_file_key(password, 2, 5, owner_entry, p_entry, id1_entry, true);
    let u = rc4_encrypt(&key, &ENCRYPTION_PADDING);
    (u, key)
}

/// Algorithm 5 (3.5), the `/U` value for revisions 3 and 4
/// (`compute_u_value_r34`).
pub(crate) fn compute_u_value_r34(
    password: &[u8],
    rev: i64,
    keylen: usize,
    owner_entry: &[u8],
    p_entry: StandardPermissions,
    id1_entry: &[u8],
    encrypt_metadata: bool,
) -> (Vec<u8>, Vec<u8>) {
    let key = derive_legacy_file_key(password, rev, keylen, owner_entry, p_entry, id1_entry, encrypt_metadata);
    let mut m = Md5::new();
    m.update(ENCRYPTION_PADDING);
    m.update(id1_entry);
    let hash: [u8; 16] = m.finalize().into();
    let mut val = rc4_encrypt(&key, &hash);
    for i in 1..20u8 {
        let new_key: Vec<u8> = key.iter().map(|b| b ^ i).collect();
        val = rc4_encrypt(&new_key, &val);
    }
    val.extend_from_slice(&[0u8; 16]);
    (val, key)
}

/// Object key derivation of the legacy handlers (Algorithm 1,
/// `legacy_derive_object_key`).
pub(crate) fn legacy_derive_object_key(shared_key: &[u8], idnum: u32, generation: u16, use_aes: bool) -> Vec<u8> {
    let mut key = shared_key.to_vec();
    key.extend_from_slice(&idnum.to_le_bytes()[..3]);
    key.extend_from_slice(&generation.to_le_bytes()[..2]);
    if use_aes {
        key.extend_from_slice(b"sAlT");
    }
    let hash = md5(&key);
    hash[..16.min(shared_key.len() + 5)].to_vec()
}
