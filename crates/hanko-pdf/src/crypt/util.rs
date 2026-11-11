// Derived from pyHanko `pdf_utils/crypt/_util.py` (MIT, see LICENSE-pyHanko).

//! Symmetric primitives used by the security handlers (`_util.py`), on top
//! of RustCrypto block ciphers. CBC and ECB are applied by hand on the block
//! cipher, with PKCS#7 padding as in pyca/cryptography.

use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

use crate::error::{PdfError, PdfResult};

/// `len` random bytes from the operating system (`secrets.token_bytes`).
pub(crate) fn random_bytes(len: usize) -> PdfResult<Vec<u8>> {
    let mut b = vec![0u8; len];
    getrandom::fill(&mut b)
        .map_err(|e| PdfError::Generic(format!("Random number generator failure: {e}")))?;
    Ok(b)
}

fn invalid(msg: &str) -> PdfError {
    PdfError::Value(msg.to_string())
}

/// A block cipher reduced to "encrypt one block" / "decrypt one block".
trait Block {
    const SIZE: usize;
    fn enc(&self, block: &mut [u8]);
    fn dec(&self, block: &mut [u8]);
}

macro_rules! cipher05_block {
    ($name:ident, $ty:ty, $size:expr) => {
        struct $name($ty);
        impl Block for $name {
            const SIZE: usize = $size;
            fn enc(&self, block: &mut [u8]) {
                if let Ok(mut b) = Array::try_from(&*block) {
                    self.0.encrypt_block(&mut b);
                    block.copy_from_slice(&b);
                }
            }
            fn dec(&self, block: &mut [u8]) {
                if let Ok(mut b) = Array::try_from(&*block) {
                    self.0.decrypt_block(&mut b);
                    block.copy_from_slice(&b);
                }
            }
        }
    };
}

cipher05_block!(Aes128B, aes::Aes128, 16);
cipher05_block!(Aes192B, aes::Aes192, 16);
cipher05_block!(Aes256B, aes::Aes256, 16);
cipher05_block!(TdesB, des::TdesEde3, 8);
cipher05_block!(Tdes2B, des::TdesEde2, 8);

struct Rc2B(rc2::Rc2);

impl Block for Rc2B {
    const SIZE: usize = 8;
    fn enc(&self, block: &mut [u8]) {
        use rc2::cipher::BlockEncrypt;
        let b = rc2::cipher::generic_array::GenericArray::from_mut_slice(block);
        self.0.encrypt_block(b);
    }
    fn dec(&self, block: &mut [u8]) {
        use rc2::cipher::BlockDecrypt;
        let b = rc2::cipher::generic_array::GenericArray::from_mut_slice(block);
        self.0.decrypt_block(b);
    }
}

fn cbc_decrypt_raw<B: Block>(c: &B, iv: &[u8], data: &[u8]) -> PdfResult<Vec<u8>> {
    if iv.len() != B::SIZE {
        return Err(invalid(&format!(
            "Invalid IV size ({}) for CBC mode.",
            iv.len()
        )));
    }
    if !data.len().is_multiple_of(B::SIZE) {
        return Err(invalid(
            "The length of the provided data is not a multiple of the block length.",
        ));
    }
    let mut prev = iv.to_vec();
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(B::SIZE) {
        let mut block = chunk.to_vec();
        c.dec(&mut block);
        for (b, p) in block.iter_mut().zip(&prev) {
            *b ^= p;
        }
        out.extend_from_slice(&block);
        prev = chunk.to_vec();
    }
    Ok(out)
}

fn cbc_encrypt_raw<B: Block>(c: &B, iv: &[u8], data: &[u8]) -> PdfResult<Vec<u8>> {
    if iv.len() != B::SIZE {
        return Err(invalid("Invalid IV size for CBC mode."));
    }
    if !data.len().is_multiple_of(B::SIZE) {
        return Err(invalid(
            "The length of the provided data is not a multiple of the block length.",
        ));
    }
    let mut prev = iv.to_vec();
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(B::SIZE) {
        let mut block: Vec<u8> = chunk.iter().zip(&prev).map(|(a, b)| a ^ b).collect();
        c.enc(&mut block);
        out.extend_from_slice(&block);
        prev = block;
    }
    Ok(out)
}

/// Strict PKCS#7 unpadding, tolerating empty input (`_maybe_unpad`).
fn maybe_unpad(mut plaintext: Vec<u8>, use_padding: bool, block_size: usize) -> PdfResult<Vec<u8>> {
    if !use_padding || plaintext.is_empty() {
        return Ok(plaintext);
    }
    let n = plaintext.last().copied().map_or(0, usize::from);
    let ok = (1..=block_size).contains(&n)
        && n <= plaintext.len()
        && plaintext[plaintext.len() - n..].iter().all(|&b| usize::from(b) == n);
    if !ok {
        return Err(invalid("Invalid padding bytes."));
    }
    plaintext.truncate(plaintext.len() - n);
    Ok(plaintext)
}

fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let n = block_size - data.len() % block_size;
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(n as u8, n));
    out
}

fn with_aes<T>(
    key: &[u8],
    f128: impl FnOnce(&dyn AesOps) -> T,
) -> PdfResult<T> {
    match key.len() {
        16 => Ok(f128(&AesImpl(Aes128B(aes::Aes128::new_from_slice(key).map_err(|_| invalid("Invalid key size"))?)))),
        24 => Ok(f128(&AesImpl(Aes192B(aes::Aes192::new_from_slice(key).map_err(|_| invalid("Invalid key size"))?)))),
        32 => Ok(f128(&AesImpl(Aes256B(aes::Aes256::new_from_slice(key).map_err(|_| invalid("Invalid key size"))?)))),
        n => Err(invalid(&format!("Invalid key size ({}) for AES.", n * 8))),
    }
}

/// Object-safe view of an AES block cipher of any key size.
trait AesOps {
    fn cbc_dec(&self, iv: &[u8], data: &[u8]) -> PdfResult<Vec<u8>>;
    fn cbc_enc(&self, iv: &[u8], data: &[u8]) -> PdfResult<Vec<u8>>;
    fn ecb_dec(&self, block: &mut [u8]);
    fn ecb_enc(&self, block: &mut [u8]);
}

struct AesImpl<B: Block>(B);

impl<B: Block> AesOps for AesImpl<B> {
    fn cbc_dec(&self, iv: &[u8], data: &[u8]) -> PdfResult<Vec<u8>> {
        cbc_decrypt_raw(&self.0, iv, data)
    }
    fn cbc_enc(&self, iv: &[u8], data: &[u8]) -> PdfResult<Vec<u8>> {
        cbc_encrypt_raw(&self.0, iv, data)
    }
    fn ecb_dec(&self, block: &mut [u8]) {
        self.0.dec(block)
    }
    fn ecb_enc(&self, block: &mut [u8]) {
        self.0.enc(block)
    }
}

/// AES-CBC decryption with optional PKCS#7 unpadding (`aes_cbc_decrypt`).
pub(crate) fn aes_cbc_decrypt(key: &[u8], data: &[u8], iv: &[u8], use_padding: bool) -> PdfResult<Vec<u8>> {
    let pt = with_aes(key, |c| c.cbc_dec(iv, data))??;
    maybe_unpad(pt, use_padding, 16)
}

/// AES-CBC encryption with optional PKCS#7 padding (`aes_cbc_encrypt`);
/// a random IV is chosen if `iv` is `None`. Returns `(iv, ciphertext)`.
pub(crate) fn aes_cbc_encrypt(
    key: &[u8],
    data: &[u8],
    iv: Option<&[u8]>,
    use_padding: bool,
) -> PdfResult<(Vec<u8>, Vec<u8>)> {
    let iv = match iv {
        Some(iv) => iv.to_vec(),
        None => random_bytes(16)?,
    };
    let data = if use_padding { pad(data, 16) } else { data.to_vec() };
    let ct = with_aes(key, |c| c.cbc_enc(&iv, &data))??;
    Ok((iv, ct))
}

/// AES-ECB on whole blocks (used for the `/Perms` entry).
pub(crate) fn aes_ecb(key: &[u8], data: &[u8], encrypt: bool) -> PdfResult<Vec<u8>> {
    if !data.len().is_multiple_of(16) {
        return Err(invalid(
            "The length of the provided data is not a multiple of the block length.",
        ));
    }
    with_aes(key, |c| {
        let mut out = data.to_vec();
        for block in out.as_chunks_mut::<16>().0 {
            if encrypt {
                c.ecb_enc(&mut block[..])
            } else {
                c.ecb_dec(&mut block[..])
            }
        }
        out
    })
}

/// Triple-DES-CBC decryption with PKCS#7 unpadding (`tripledes_decrypt`).
pub(crate) fn tripledes_decrypt(key: &[u8], data: &[u8], iv: &[u8]) -> PdfResult<Vec<u8>> {
    let pt = match key.len() {
        24 => cbc_decrypt_raw(
            &TdesB(des::TdesEde3::new_from_slice(key).map_err(|_| invalid("Invalid key size"))?),
            iv,
            data,
        )?,
        16 => cbc_decrypt_raw(
            &Tdes2B(des::TdesEde2::new_from_slice(key).map_err(|_| invalid("Invalid key size"))?),
            iv,
            data,
        )?,
        n => return Err(invalid(&format!("Invalid key size ({}) for TripleDES.", n * 8))),
    };
    maybe_unpad(pt, true, 8)
}

/// RC2-CBC decryption with PKCS#7 unpadding (`rc2_decrypt`); the effective
/// key length equals the key length, as with pyca/cryptography.
pub(crate) fn rc2_decrypt(key: &[u8], data: &[u8], iv: &[u8]) -> PdfResult<Vec<u8>> {
    if key.is_empty() || key.len() > 128 {
        return Err(invalid("Invalid key size for RC2."));
    }
    let c = Rc2B(rc2::Rc2::new_with_eff_key_len(key, key.len() * 8));
    let pt = cbc_decrypt_raw(&c, iv, data)?;
    maybe_unpad(pt, true, 8)
}

/// RC4 (`rc4_encrypt`; decryption is the same operation).
pub(crate) fn rc4_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    super::rc4::rc4(key, data)
}

/// AES-GCM encryption with a 12-byte nonce, returning ciphertext and tag.
pub(crate) fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> PdfResult<Vec<u8>> {
    use aes_gcm::aead::{Aead, Payload};
    let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| invalid("Invalid nonce length"))?;
    let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| invalid("AESGCM key must be 256 bits."))?;
    c.encrypt(&nonce, Payload { msg: plaintext, aad: b"" })
        .map_err(|_| invalid("AES-GCM encryption failed"))
}

/// AES-GCM decryption; any failure is reported as an invalid tag.
pub(crate) fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], data: &[u8]) -> PdfResult<Vec<u8>> {
    use aes_gcm::aead::{Aead, Payload};
    let bad = || PdfError::Read("Invalid GCM tag".into());
    let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| bad())?;
    let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| invalid("AESGCM key must be 256 bits."))?;
    c.decrypt(&nonce, Payload { msg: data, aad: b"" }).map_err(|_| bad())
}

/// AES key wrap (RFC 3394) with a KEK of 16, 24 or 32 bytes.
pub(crate) fn aes_key_wrap(kek: &[u8], key: &[u8]) -> PdfResult<Vec<u8>> {
    let mut buf = vec![0u8; key.len() + 8];
    let r = match kek.len() {
        16 => aes_kw::KwAes128::new_from_slice(kek).map(|k| k.wrap_key(key, &mut buf).map(<[u8]>::to_vec)),
        24 => aes_kw::KwAes192::new_from_slice(kek).map(|k| k.wrap_key(key, &mut buf).map(<[u8]>::to_vec)),
        32 => aes_kw::KwAes256::new_from_slice(kek).map(|k| k.wrap_key(key, &mut buf).map(<[u8]>::to_vec)),
        _ => return Err(invalid("The wrapping key must be a valid AES key length")),
    };
    r.map_err(|_| invalid("Invalid key length"))?
        .map_err(|_| invalid("The key to wrap must be at least 16 bytes and a multiple of 8"))
}

/// AES key unwrap (RFC 3394, or RFC 5649 with padding if `padded`).
pub(crate) fn aes_key_unwrap(kek: &[u8], wrapped: &[u8], padded: bool) -> PdfResult<Vec<u8>> {
    let mut buf = vec![0u8; wrapped.len()];
    let bad = || invalid("InvalidUnwrap");
    macro_rules! unwrap_with {
        ($t:ty) => {
            <$t>::new_from_slice(kek)
                .map_err(|_| bad())?
                .unwrap_key(wrapped, &mut buf)
                .map(<[u8]>::to_vec)
                .map_err(|_| bad())
        };
    }
    match (kek.len(), padded) {
        (16, false) => unwrap_with!(aes_kw::KwAes128),
        (24, false) => unwrap_with!(aes_kw::KwAes192),
        (32, false) => unwrap_with!(aes_kw::KwAes256),
        (16, true) => unwrap_with!(aes_kw::KwpAes128),
        (24, true) => unwrap_with!(aes_kw::KwpAes192),
        (32, true) => unwrap_with!(aes_kw::KwpAes256),
        _ => Err(invalid("The wrapping key must be a valid AES key length")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbc_roundtrip_and_padding() {
        let key = [7u8; 32];
        let (iv, ct) = aes_cbc_encrypt(&key, b"hello world", None, true).unwrap();
        assert_eq!(ct.len(), 16);
        assert_eq!(aes_cbc_decrypt(&key, &ct, &iv, true).unwrap(), b"hello world");
        // empty plaintext without padding is tolerated
        assert_eq!(aes_cbc_decrypt(&key, b"", &iv, true).unwrap(), b"");
        // bad padding
        let (iv, ct) = aes_cbc_encrypt(&key, &[0u8; 16], None, false).unwrap();
        assert!(aes_cbc_decrypt(&key, &ct, &iv, true).is_err());
        assert!(aes_cbc_decrypt(&key, &ct[..10], &iv, true).is_err());
    }

    #[test]
    fn kw_rfc3394() {
        // RFC 3394 4.1: 128-bit KEK, 128-bit key
        let kek: Vec<u8> = (0u8..16).collect();
        let key: Vec<u8> = (0u8..16).map(|i| i * 0x11).collect();
        let wrapped = aes_key_wrap(&kek, &key).unwrap();
        assert_eq!(
            wrapped,
            [
                0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
                0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
            ]
        );
        assert_eq!(aes_key_unwrap(&kek, &wrapped, false).unwrap(), key);
        let mut bad = wrapped.clone();
        bad[3] ^= 1;
        assert!(aes_key_unwrap(&kek, &bad, false).is_err());
    }

    #[test]
    fn gcm_roundtrip() {
        let key = [3u8; 32];
        let ct = aes_gcm_encrypt(&key, &[0u8; 12], b"abc").unwrap();
        assert_eq!(aes_gcm_decrypt(&key, &[0u8; 12], &ct).unwrap(), b"abc");
        assert!(aes_gcm_decrypt(&key, &[1u8; 12], &ct).is_err());
    }
}
