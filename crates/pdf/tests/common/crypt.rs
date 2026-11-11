// Test credentials mirroring pyhanko_testing_commons.test_data.samples
// (PUBKEY_*_DECRYPTER) and the certomancer-based ECC decrypters of
// pkgs/pyhanko/tests/test_crypt.py (MIT, see LICENSE-pyHanko).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pdf::crypt::SimpleEnvelopeKeyDecrypter;

/// A file of pyHanko's test PKI (`CRYPTO_DATA_DIR/...`).
pub fn crypto(parts: &[&str]) -> Vec<u8> {
    let mut p = vec!["pyhanko", "crypto"];
    p.extend_from_slice(parts);
    sigis_testdata::read(&p)
}

/// `PUBKEY_TEST_DECRYPTER`.
pub fn pubkey_test_decrypter() -> SimpleEnvelopeKeyDecrypter {
    SimpleEnvelopeKeyDecrypter::load(
        &crypto(&["keys-rsa", "signer.key.pem"]),
        &crypto(&["testing-ca", "interm", "decrypter1.cert.pem"]),
        Some(b"secret"),
    )
    .unwrap()
}

/// `PUBKEY_TEST_DECRYPTER_OLD` (certificate embedded in some fixtures).
pub fn pubkey_test_decrypter_old() -> SimpleEnvelopeKeyDecrypter {
    SimpleEnvelopeKeyDecrypter::load(
        &crypto(&["keys-rsa", "signer.key.pem"]),
        &crypto(&["testing-ca", "interm", "decrypter1-old.cert.pem"]),
        Some(b"secret"),
    )
    .unwrap()
}

/// `PUBKEY_SELFSIGNED_DECRYPTER` (no keyEncipherment bit).
pub fn pubkey_selfsigned_decrypter() -> SimpleEnvelopeKeyDecrypter {
    SimpleEnvelopeKeyDecrypter::load(
        &crypto(&["selfsigned.key.pem"]),
        &crypto(&["selfsigned.cert.pem"]),
        Some(b"secret"),
    )
    .unwrap()
}

/// DER certificate of an `ecc-testing-ca-with-decrypters` entity, exported
/// by `oracle/export_crypt_pki.py`.
pub fn ecc_decrypter_cert(label: &str) -> Vec<u8> {
    let pem = sigis_testdata::read(&["lanes", "b", "crypt-pki", &format!("{label}.cert.pem")]);
    let text = String::from_utf8(pem).unwrap();
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    base64_decode(&body)
}

/// Unencrypted PKCS#8 key of an ECC decrypter (`keys-ecdsa/<label>.key.pem`).
pub fn ecc_decrypter_key(label: &str) -> Vec<u8> {
    let pem = crypto(&["keys-ecdsa", &format!("{label}.key.pem")]);
    let text = String::from_utf8(pem).unwrap();
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    base64_decode(&body)
}

/// An ECC decrypter (`SimpleEnvelopeKeyDecrypter(cert, key)`).
pub fn ecc_decrypter(label: &str) -> SimpleEnvelopeKeyDecrypter {
    SimpleEnvelopeKeyDecrypter::new(&ecc_decrypter_cert(label), &ecc_decrypter_key(label)).unwrap()
}

pub fn base64_decode(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("bad base64"),
        }
    };
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        acc = (acc << 6) | val(c);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}
