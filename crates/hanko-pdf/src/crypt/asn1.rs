//! Minimal DER reading and writing helpers for the CMS structures of the
//! crypt module (PDF MAC tokens, recipient envelopes, serialised
//! credentials).
//!
//! The MAC of a PDF MAC token covers the authenticated attributes *as
//! encoded*, and the public-key file key covers the recipient structures as
//! encoded, so these structures are handled at the TLV level, keeping the
//! original bytes. Only definite lengths (DER) are accepted.

use crate::error::{PdfError, PdfResult};

/// Universal and context tags used by the crypt module.
pub(crate) mod tag {
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
}

/// One decoded TLV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tlv<'a> {
    /// Identifier octet (low-number tags only).
    pub tag: u8,
    /// Content octets.
    pub value: &'a [u8],
    /// The full encoding (identifier, length and content).
    pub raw: &'a [u8],
}

fn asn1_err(msg: &str) -> PdfError {
    PdfError::Value(format!("ASN.1 decoding error: {msg}"))
}

impl<'a> Tlv<'a> {
    /// Parse the first TLV of `input`, returning it and the remaining bytes.
    pub fn parse(input: &'a [u8]) -> PdfResult<(Tlv<'a>, &'a [u8])> {
        let (&tag, rest) = input.split_first().ok_or_else(|| asn1_err("unexpected end of data"))?;
        if tag & 0x1f == 0x1f {
            return Err(asn1_err("high tag numbers are not supported"));
        }
        let (&l0, mut rest) = rest.split_first().ok_or_else(|| asn1_err("missing length"))?;
        let len = if l0 < 0x80 {
            usize::from(l0)
        } else {
            let n = usize::from(l0 & 0x7f);
            if n == 0 {
                return Err(asn1_err("indefinite length is not DER"));
            }
            if n > 4 || rest.len() < n {
                return Err(asn1_err("invalid length"));
            }
            let mut len = 0usize;
            for &b in &rest[..n] {
                len = (len << 8) | usize::from(b);
            }
            rest = &rest[n..];
            len
        };
        if rest.len() < len {
            return Err(asn1_err("value extends beyond the end of the data"));
        }
        let header_len = input.len() - rest.len();
        let (value, rest) = rest.split_at(len);
        Ok((
            Tlv {
                tag,
                value,
                raw: &input[..header_len + len],
            },
            rest,
        ))
    }

    /// Parse exactly one TLV (no trailing data).
    pub fn parse_exact(input: &'a [u8]) -> PdfResult<Tlv<'a>> {
        let (t, rest) = Self::parse(input)?;
        if !rest.is_empty() {
            return Err(asn1_err("trailing data"));
        }
        Ok(t)
    }

    /// Parse and check the tag.
    pub fn expect(input: &'a [u8], tag: u8) -> PdfResult<(Tlv<'a>, &'a [u8])> {
        let (t, rest) = Self::parse(input)?;
        if t.tag != tag {
            return Err(asn1_err(&format!("expected tag {tag:#04x}, found {:#04x}", t.tag)));
        }
        Ok((t, rest))
    }

    /// The children of a constructed value.
    pub fn children(&self) -> PdfResult<Vec<Tlv<'a>>> {
        let mut out = Vec::new();
        let mut rest = self.value;
        while !rest.is_empty() {
            let (t, r) = Tlv::parse(rest)?;
            out.push(t);
            rest = r;
        }
        Ok(out)
    }

    /// The encoding of this value with a different identifier octet (used to
    /// turn `[n] IMPLICIT SET OF` into `SET OF`, like asn1crypto's
    /// `untag()`).
    pub fn retagged(&self, tag: u8) -> Vec<u8> {
        let mut out = self.raw.to_vec();
        if let Some(b) = out.first_mut() {
            *b = tag;
        }
        out
    }

    /// The single child of an explicitly tagged value.
    pub fn explicit_inner(&self) -> PdfResult<Tlv<'a>> {
        Tlv::parse_exact(self.value)
    }

    /// Value of an OBJECT IDENTIFIER, in dotted form.
    pub fn oid(&self) -> PdfResult<String> {
        if self.tag != tag::OID {
            return Err(asn1_err("expected OBJECT IDENTIFIER"));
        }
        oid_to_string(self.value)
    }

    /// Value of a non-negative INTEGER that fits in an `i64`.
    pub fn small_int(&self) -> PdfResult<i64> {
        if self.tag != tag::INTEGER || self.value.is_empty() || self.value.len() > 8 {
            return Err(asn1_err("expected small INTEGER"));
        }
        let mut v: i64 = if self.value[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in self.value {
            v = (v << 8) | i64::from(b);
        }
        Ok(v)
    }
}

/// Dotted form of an encoded OID.
pub(crate) fn oid_to_string(v: &[u8]) -> PdfResult<String> {
    if v.is_empty() {
        return Err(asn1_err("empty OBJECT IDENTIFIER"));
    }
    let mut arcs: Vec<u128> = Vec::new();
    let mut cur: u128 = 0;
    for (i, &b) in v.iter().enumerate() {
        if cur == 0 && b == 0x80 {
            return Err(asn1_err("non-minimal OID encoding"));
        }
        cur = cur.checked_mul(128).ok_or_else(|| asn1_err("OID arc too large"))? | u128::from(b & 0x7f);
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let (a, b) = if cur < 40 {
                    (0, cur)
                } else if cur < 80 {
                    (1, cur - 40)
                } else {
                    (2, cur - 80)
                };
                arcs.push(a);
                arcs.push(b);
            } else {
                arcs.push(cur);
            }
            cur = 0;
        } else if i == v.len() - 1 {
            return Err(asn1_err("truncated OID"));
        }
    }
    Ok(arcs.iter().map(u128::to_string).collect::<Vec<_>>().join("."))
}

/// Encode a TLV.
pub(crate) fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(value);
    out
}

/// Encode a constructed value from already encoded children.
pub(crate) fn cons(tag: u8, children: &[&[u8]]) -> Vec<u8> {
    tlv(tag, &children.concat())
}

/// SEQUENCE of encoded children.
pub(crate) fn seq(children: &[&[u8]]) -> Vec<u8> {
    cons(tag::SEQUENCE, children)
}

/// OCTET STRING.
pub(crate) fn octets(v: &[u8]) -> Vec<u8> {
    tlv(tag::OCTET_STRING, v)
}

/// Non-negative INTEGER.
pub(crate) fn uint(v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count().min(7);
    let mut body = bytes[skip..].to_vec();
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    tlv(tag::INTEGER, &body)
}

/// OBJECT IDENTIFIER from dotted form (panics are impossible: invalid input
/// yields an empty OID, which callers never pass).
pub(crate) fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u128> = dotted.split('.').filter_map(|a| a.parse().ok()).collect();
    let mut body = Vec::new();
    if arcs.len() >= 2 {
        let mut push = |mut v: u128| {
            let mut tmp = vec![(v & 0x7f) as u8];
            v >>= 7;
            while v > 0 {
                tmp.push(((v & 0x7f) as u8) | 0x80);
                v >>= 7;
            }
            tmp.reverse();
            body.extend(tmp);
        };
        push(arcs[0] * 40 + arcs[1]);
        for &a in &arcs[2..] {
            push(a);
        }
    }
    tlv(tag::OID, &body)
}

/// AlgorithmIdentifier with optional encoded parameters.
pub(crate) fn alg_id(dotted: &str, params: Option<&[u8]>) -> Vec<u8> {
    match params {
        Some(p) => seq(&[&oid(dotted), p]),
        None => seq(&[&oid(dotted)]),
    }
}

/// An AlgorithmIdentifier as (OID, encoded parameters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AlgId<'a> {
    pub oid: String,
    pub params: Option<Tlv<'a>>,
}

impl<'a> AlgId<'a> {
    pub fn parse(t: &Tlv<'a>) -> PdfResult<Self> {
        if t.tag != tag::SEQUENCE {
            return Err(asn1_err("expected AlgorithmIdentifier"));
        }
        let ch = t.children()?;
        let first = ch.first().ok_or_else(|| asn1_err("empty AlgorithmIdentifier"))?;
        if ch.len() > 2 {
            return Err(asn1_err("malformed AlgorithmIdentifier"));
        }
        Ok(AlgId {
            oid: first.oid()?,
            params: ch.get(1).copied(),
        })
    }

    /// Equality as asn1crypto's `.native` sees it: absent parameters and
    /// NULL parameters are the same.
    pub fn same_as(&self, other: &AlgId<'_>) -> bool {
        let norm = |p: &Option<Tlv<'_>>| match p {
            Some(t) if t.tag == tag::NULL && t.value.is_empty() => None,
            Some(t) => Some(t.raw.to_vec()),
            None => None,
        };
        self.oid == other.oid && norm(&self.params) == norm(&other.params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_roundtrip() {
        for o in ["1.2.840.113549.1.9.16.1.2", "1.0.32004.1.0", "2.16.840.1.101.3.4.2.1", "2.999"] {
            let enc = oid(o);
            let (t, rest) = Tlv::parse(&enc).unwrap();
            assert!(rest.is_empty());
            assert_eq!(t.oid().unwrap(), o);
        }
    }

    #[test]
    fn long_lengths() {
        let v = vec![0xabu8; 300];
        let enc = octets(&v);
        let t = Tlv::parse_exact(&enc).unwrap();
        assert_eq!(t.value, &v[..]);
        assert_eq!(Tlv::parse(&[0x30, 0x80, 0, 0]).unwrap_err().class_name(), "ValueError");
        assert_eq!(uint(0), [2, 1, 0]);
        assert_eq!(uint(128), [2, 2, 0, 128]);
    }
}
