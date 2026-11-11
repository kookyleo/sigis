//! A small, lenient reader for BER/DER tag-length-value encodings.
//!
//! The `der` crate decodes DER strictly: it sorts or rejects `SET OF`
//! elements and refuses some deviations that real signers produce. pyHanko
//! (through `asn1crypto`) keeps the original encoding of every value and only
//! re-encodes values that were modified. Signature checks must run over the
//! bytes as they were signed, so structures such as CMS signed attributes are
//! walked with this reader, which returns borrowed slices of the input.
//!
//! Supported: single-byte and multi-byte tag numbers, definite lengths up to
//! four length octets. Indefinite lengths are rejected (they never occur in
//! DER, and CMS signed attributes must be DER). Nothing here panics on any
//! input.

/// Tag class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Universal.
    Universal,
    /// Application.
    Application,
    /// Context-specific.
    ContextSpecific,
    /// Private.
    Private,
}

/// One decoded TLV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Tag class.
    pub class: Class,
    /// Constructed bit.
    pub constructed: bool,
    /// Tag number.
    pub number: u32,
    /// The complete encoding (identifier, length and contents octets).
    pub raw: &'a [u8],
    /// The contents octets.
    pub value: &'a [u8],
}

/// Decoding failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed ASN.1 encoding: {0}")]
pub struct TlvError(pub &'static str);

impl<'a> Tlv<'a> {
    /// Decode exactly one TLV spanning all of `input`.
    pub fn parse_exact(input: &'a [u8]) -> Result<Self, TlvError> {
        let (tlv, rest) = Self::parse(input)?;
        if !rest.is_empty() {
            return Err(TlvError("trailing data"));
        }
        Ok(tlv)
    }

    /// Decode the first TLV of `input`; returns it and the remaining bytes.
    pub fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), TlvError> {
        let first = *input.first().ok_or(TlvError("unexpected end of input"))?;
        let class = match first >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        };
        let constructed = first & 0x20 != 0;
        let mut pos = 1usize;
        let mut number = u32::from(first & 0x1f);
        if number == 0x1f {
            number = 0;
            loop {
                let b = *input.get(pos).ok_or(TlvError("truncated tag"))?;
                pos += 1;
                if number > (u32::MAX >> 7) {
                    return Err(TlvError("tag number too large"));
                }
                number = (number << 7) | u32::from(b & 0x7f);
                if b & 0x80 == 0 {
                    break;
                }
            }
        }
        let len_byte = *input.get(pos).ok_or(TlvError("truncated length"))?;
        pos += 1;
        let len = if len_byte < 0x80 {
            usize::from(len_byte)
        } else {
            let n = usize::from(len_byte & 0x7f);
            if n == 0 {
                return Err(TlvError("indefinite length"));
            }
            if n > 4 {
                return Err(TlvError("length too large"));
            }
            let bytes = input
                .get(pos..pos + n)
                .ok_or(TlvError("truncated length"))?;
            pos += n;
            bytes
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
        };
        let end = pos.checked_add(len).ok_or(TlvError("length overflow"))?;
        let value = input.get(pos..end).ok_or(TlvError("truncated contents"))?;
        let raw = input.get(..end).ok_or(TlvError("truncated contents"))?;
        let rest = input.get(end..).ok_or(TlvError("truncated contents"))?;
        Ok((
            Self {
                class,
                constructed,
                number,
                raw,
                value,
            },
            rest,
        ))
    }

    /// The children of a constructed value.
    pub fn children(&self) -> Result<Vec<Tlv<'a>>, TlvError> {
        if !self.constructed {
            return Err(TlvError("primitive value has no children"));
        }
        parse_all(self.value)
    }

    /// `true` for a universal tag with this number.
    pub fn is_universal(&self, number: u32) -> bool {
        self.class == Class::Universal && self.number == number
    }

    /// `true` for a context-specific tag with this number.
    pub fn is_context(&self, number: u32) -> bool {
        self.class == Class::ContextSpecific && self.number == number
    }
}

/// Universal tag numbers used by callers.
pub mod tag {
    /// BOOLEAN.
    pub const BOOLEAN: u32 = 1;
    /// INTEGER.
    pub const INTEGER: u32 = 2;
    /// BIT STRING.
    pub const BIT_STRING: u32 = 3;
    /// OCTET STRING.
    pub const OCTET_STRING: u32 = 4;
    /// NULL.
    pub const NULL: u32 = 5;
    /// OBJECT IDENTIFIER.
    pub const OID: u32 = 6;
    /// SEQUENCE.
    pub const SEQUENCE: u32 = 16;
    /// SET.
    pub const SET: u32 = 17;
    /// UTCTime.
    pub const UTC_TIME: u32 = 23;
    /// GeneralizedTime.
    pub const GENERALIZED_TIME: u32 = 24;
}

/// Decode a concatenation of TLVs.
pub fn parse_all(mut input: &[u8]) -> Result<Vec<Tlv<'_>>, TlvError> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let (tlv, rest) = Tlv::parse(input)?;
        out.push(tlv);
        input = rest;
    }
    Ok(out)
}

/// Re-encode `tlv` with a different identifier octet (single-byte tags
/// only), keeping its contents octets. Used to turn an `[0] IMPLICIT SET OF`
/// into a universal `SET OF` before verifying a signature over it.
pub fn retag(tlv: &Tlv<'_>, identifier: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(tlv.raw.len() + 2);
    out.push(identifier);
    push_length(&mut out, tlv.value.len());
    out.extend_from_slice(tlv.value);
    out
}

/// Append a DER length.
pub fn push_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        // Truncation is impossible: len < 0x80.
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let n = bytes.len() - skip;
        out.push(0x80 | n as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// Encode a TLV with a single-byte identifier.
pub fn encode(identifier: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(identifier);
    push_length(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_and_long_forms() {
        let inner = encode(0x04, &[0xaa; 200]);
        let outer = encode(0x30, &inner);
        let tlv = Tlv::parse_exact(&outer).expect("parse");
        assert!(tlv.is_universal(tag::SEQUENCE) && tlv.constructed);
        let kids = tlv.children().expect("children");
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].value.len(), 200);
        assert_eq!(kids[0].raw, &inner[..]);
    }

    #[test]
    fn high_tag_numbers_and_retag() {
        let tlv = Tlv::parse_exact(&[0x9f, 0x81, 0x00, 0x01, 0x07]).expect("parse");
        assert_eq!((tlv.class, tlv.number, tlv.value), (Class::ContextSpecific, 128, &[7u8][..]));
        let set = retag(&Tlv::parse_exact(&[0xa0, 0x02, 0x05, 0x00]).expect("p"), 0x31);
        assert_eq!(set, vec![0x31, 0x02, 0x05, 0x00]);
    }

    #[test]
    fn garbage_is_rejected_without_panicking() {
        for input in [
            &[][..],
            &[0x30][..],
            &[0x30, 0x80, 0, 0][..],
            &[0x30, 0x85, 1, 1, 1, 1, 1][..],
            &[0x30, 0x05, 0x01][..],
            &[0x1f][..],
            &[0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00][..],
            &[0x04, 0x84, 0xff, 0xff, 0xff, 0xff][..],
        ] {
            assert!(Tlv::parse(input).is_err(), "{input:?}");
        }
        assert!(Tlv::parse_exact(&[0x05, 0x00, 0x00]).is_err());
    }
}
