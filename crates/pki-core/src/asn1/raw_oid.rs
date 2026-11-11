//! Object identifiers kept as their encoded contents octets.
//!
//! `const-oid` rejects some valid identifiers (for example `2.999`, whose
//! first sub-identifier needs two octets). Values read from untrusted
//! structures are compared in encoded form instead, so such identifiers are
//! simply "unknown" rather than a decoding failure.

use core::fmt;

use const_oid::ObjectIdentifier;

use super::tlv::{tag, Tlv, TlvError};

/// An object identifier as encoded (contents octets of the OID TLV).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RawOid(Vec<u8>);

impl RawOid {
    /// Decode an OID TLV.
    pub fn from_der(der: &[u8]) -> Result<Self, TlvError> {
        Self::from_tlv(&Tlv::parse_exact(der)?)
    }

    /// Take the contents of an OID TLV.
    pub fn from_tlv(t: &Tlv<'_>) -> Result<Self, TlvError> {
        if !t.is_universal(tag::OID) || t.constructed {
            return Err(TlvError("expected OBJECT IDENTIFIER"));
        }
        if t.value.is_empty() || t.value.last().is_some_and(|b| b & 0x80 != 0) {
            return Err(TlvError("malformed OBJECT IDENTIFIER"));
        }
        Ok(Self(t.value.to_vec()))
    }

    /// The contents octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// `true` if this is `oid`.
    pub fn is(&self, oid: &ObjectIdentifier) -> bool {
        self.0 == oid.as_bytes()
    }

    /// Convert to a `const-oid` identifier, if it can represent it.
    pub fn to_oid(&self) -> Option<ObjectIdentifier> {
        ObjectIdentifier::from_bytes(&self.0).ok()
    }

    /// Dotted decimal notation.
    pub fn dotted(&self) -> String {
        let mut arcs: Vec<u128> = Vec::new();
        let mut acc: u128 = 0;
        for b in &self.0 {
            acc = (acc << 7) | u128::from(b & 0x7f);
            if b & 0x80 == 0 {
                arcs.push(acc);
                acc = 0;
            }
        }
        let mut out = Vec::with_capacity(arcs.len() + 1);
        if let Some(first) = arcs.first() {
            let (a, b) = match *first {
                f if f < 40 => (0, f),
                f if f < 80 => (1, f - 40),
                f => (2, f - 80),
            };
            out.push(a.to_string());
            out.push(b.to_string());
        }
        out.extend(arcs.iter().skip(1).map(u128::to_string));
        out.join(".")
    }
}

impl From<ObjectIdentifier> for RawOid {
    fn from(oid: ObjectIdentifier) -> Self {
        Self(oid.as_bytes().to_vec())
    }
}

impl PartialEq<ObjectIdentifier> for RawOid {
    fn eq(&self, other: &ObjectIdentifier) -> bool {
        self.is(other)
    }
}

impl fmt::Display for RawOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.dotted())
    }
}

impl fmt::Debug for RawOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawOid({})", self.dotted())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_and_compare() {
        let oid = RawOid::from_der(&[0x06, 0x02, 0x88, 0x37]).expect("2.999");
        assert_eq!(oid.dotted(), "2.999");
        let sha256 = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        let raw = RawOid::from(sha256);
        assert_eq!(raw.dotted(), "2.16.840.1.101.3.4.2.1");
        assert!(raw == sha256 && raw.to_oid() == Some(sha256));
        assert!(RawOid::from_der(&[0x06, 0x01, 0x80]).is_err());
        assert!(RawOid::from_der(&[0x06, 0x00]).is_err());
    }
}
