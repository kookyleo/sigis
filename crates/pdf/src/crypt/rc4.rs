//! RC4 stream cipher (ARC4), as required by the legacy PDF security
//! handlers (ISO 32000-1, 7.6.3).
//!
//! There is no maintained RustCrypto `rc4` crate in the offline registry, so
//! this small private implementation is used instead. RC4 is weak; it is
//! only supported to read (and, for tests, write) legacy documents.

/// Encrypt or decrypt `data` with RC4 under `key` (the operation is its own
/// inverse). An empty key is treated like a one-byte zero key would be in
/// OpenSSL's key schedule, i.e. it never panics.
pub(crate) fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = [0; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    if !key.is_empty() {
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, usize::from(j));
        }
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[usize::from(i)]);
            s.swap(usize::from(i), usize::from(j));
            let k = s[usize::from(s[usize::from(i)].wrapping_add(s[usize::from(j)]))];
            b ^ k
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::rc4;

    #[test]
    fn rfc6229_vectors() {
        // RFC 6229, key 0x0102030405, first 16 output bytes
        let ks = rc4(&[1, 2, 3, 4, 5], &[0u8; 16]);
        assert_eq!(
            ks,
            [
                0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11,
                0x18, 0xa8
            ]
        );
        // classic "Key"/"Plaintext" vector
        assert_eq!(
            rc4(b"Key", b"Plaintext"),
            [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
        );
        assert_eq!(rc4(b"Key", &rc4(b"Key", b"abc")), b"abc");
    }
}
