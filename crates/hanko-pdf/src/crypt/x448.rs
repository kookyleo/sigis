//! X448 (RFC 7748, section 5) on `crypto-bigint` field arithmetic.
//!
//! RustCrypto has no released X448 crate in the offline registry, and the
//! Montgomery ladder of the `ed448-goldilocks` pre-release does not
//! reproduce the RFC 7748 test vectors, so the ladder is implemented here
//! (constant-time swaps, fixed iteration count).

use crypto_bigint::ctutils::{Choice, CtSelect};
use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U448};

use crate::error::{PdfError, PdfResult};

/// p = 2^448 - 2^224 - 1.
const P_HEX: &str = concat!(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
);

/// (A - 2) / 4 for Curve448.
const A24: u64 = 39081;

type Fe = FixedMontyForm<{ U448::LIMBS }>;

fn params() -> PdfResult<(U448, FixedMontyParams<{ U448::LIMBS }>)> {
    let p = U448::from_be_hex(P_HEX);
    let odd = Odd::new(p)
        .into_option()
        .ok_or_else(|| PdfError::Generic("X448 modulus must be odd".into()))?;
    Ok((p, FixedMontyParams::new_vartime(odd)))
}

fn le_bytes(x: &U448) -> [u8; 56] {
    let mut out = [0u8; 56];
    for (i, limb) in x.as_words().iter().enumerate() {
        let b = limb.to_le_bytes();
        let start = i * b.len();
        out[start..start + b.len()].copy_from_slice(&b);
    }
    out
}

/// `X448(k, u)`: scalar multiplication of the u-coordinate `u` by the
/// clamped scalar `k` (both little-endian, 56 bytes).
pub(crate) fn x448(k: &[u8; 56], u: &[u8; 56]) -> PdfResult<[u8; 56]> {
    let (p, params) = params()?;
    let mut k = *k;
    k[0] &= 252;
    k[55] |= 128;
    // decodeUCoordinate: all 448 bits, reduced modulo p (u < 2^448 < 2p)
    let u = U448::from_le_slice(u);
    let u = U448::ct_select(&u, &u.wrapping_sub(&p), Choice::from_u8_lsb(u8::from(u >= p)));
    let x1 = Fe::new(&u, &params);
    let one = Fe::new(&U448::ONE, &params);
    let zero = Fe::new(&U448::ZERO, &params);
    let a24 = Fe::new(&U448::from_u64(A24), &params);
    let (mut x2, mut z2, mut x3, mut z3) = (one, zero, x1, one);
    let mut swap = Choice::from_u8_lsb(0);
    for t in (0..448).rev() {
        let k_t = Choice::from_u8_lsb((k[t / 8] >> (t % 8)) & 1);
        swap ^= k_t;
        x2.ct_swap(&mut x3, swap);
        z2.ct_swap(&mut z3, swap);
        swap = k_t;
        let a = x2 + z2;
        let aa = a * a;
        let b = x2 - z2;
        let bb = b * b;
        let e = aa - bb;
        let c = x3 + z3;
        let d = x3 - z3;
        let da = d * a;
        let cb = c * b;
        let s = da + cb;
        x3 = s * s;
        let t2 = da - cb;
        z3 = x1 * (t2 * t2);
        x2 = aa * bb;
        z2 = e * (aa + a24 * e);
    }
    x2.ct_swap(&mut x3, swap);
    z2.ct_swap(&mut z3, swap);
    let p_minus_2 = p.wrapping_sub(&U448::from_u64(2));
    let out = (x2 * z2.pow(&p_minus_2)).retrieve();
    Ok(le_bytes(&out))
}

#[cfg(test)]
mod tests {
    use super::x448;

    fn unhex(s: &str) -> [u8; 56] {
        let v: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    }

    #[test]
    fn rfc7748_vector() {
        // RFC 7748, 5.2, first X448 test vector
        let k = unhex("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
        let u = unhex("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
        let out = unhex("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");
        assert_eq!(x448(&k, &u).unwrap(), out);
    }
}
