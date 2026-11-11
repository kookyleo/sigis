//! OID encoder with `const` support.

use crate::{
    Arc, Buffer, Error, ObjectIdentifier, Result,
    arcs::{ARC_MAX_FIRST, ARC_MAX_SECOND},
};

/// BER/DER encoder.
#[derive(Debug)]
pub(crate) struct Encoder<const MAX_SIZE: usize> {
    /// Current state.
    state: State,

    /// Bytes of the OID being BER-encoded in-progress.
    bytes: [u8; MAX_SIZE],

    /// Current position within the byte buffer.
    cursor: usize,
}

/// Current state of the encoder.
#[derive(Debug)]
enum State {
    /// Initial state - no arcs yet encoded.
    Initial,

    /// First arc has been supplied and stored as the wrapped [`Arc`].
    FirstArc(Arc),

    /// Encoding base 128 body of the OID.
    Body,
}

impl<const MAX_SIZE: usize> Encoder<MAX_SIZE> {
    /// Create a new encoder initialized to an empty default state.
    pub(crate) const fn new() -> Self {
        Self {
            state: State::Initial,
            bytes: [0u8; MAX_SIZE],
            cursor: 0,
        }
    }

    /// Extend an existing OID.
    pub(crate) const fn extend(oid: ObjectIdentifier<MAX_SIZE>) -> Self {
        Self {
            state: State::Body,
            bytes: oid.ber.bytes,
            cursor: oid.ber.length as usize,
        }
    }

    /// Encode an [`Arc`] as base 128 into the internal buffer.
    pub(crate) const fn arc(mut self, arc: Arc) -> Result<Self> {
        match self.state {
            State::Initial => {
                if arc > ARC_MAX_FIRST {
                    return Err(Error::ArcInvalid { arc });
                }

                self.state = State::FirstArc(arc);
                Ok(self)
            }
            State::FirstArc(first_arc) => {
                // Only the first arcs 0 and 1 bound the second arc
                // (X.690 §8.19.4); under 2 it is encoded as `80 + arc`.
                if first_arc < ARC_MAX_FIRST && arc > ARC_MAX_SECOND {
                    return Err(Error::ArcInvalid { arc });
                }
                let root = match checked_mul!(checked_add!(ARC_MAX_SECOND, 1), first_arc).checked_add(arc) {
                    Some(root) => root,
                    None => return Err(Error::ArcTooBig),
                };

                self.state = State::Body;
                self.encode_base128(root)
            }
            State::Body => self.encode_base128(arc),
        }
    }

    /// Finish encoding an OID.
    pub(crate) const fn finish(self) -> Result<ObjectIdentifier<MAX_SIZE>> {
        if self.cursor == 0 {
            return Err(Error::Empty);
        }

        let ber = Buffer {
            bytes: self.bytes,
            length: self.cursor as u8,
        };

        Ok(ObjectIdentifier { ber })
    }

    /// Encode base 128.
    const fn encode_base128(mut self, arc: Arc) -> Result<Self> {
        let nbytes = base128_len(arc);
        let end_pos = checked_add!(self.cursor, nbytes);

        if end_pos > MAX_SIZE {
            return Err(Error::Length);
        }

        let mut i = 0;
        while i < nbytes {
            // TODO(tarcieri): use `?` when stable in `const fn`
            self.bytes[self.cursor] = match base128_byte(arc, i, nbytes) {
                Ok(byte) => byte,
                Err(e) => return Err(e),
            };
            self.cursor = checked_add!(self.cursor, 1);
            i = checked_add!(i, 1);
        }

        Ok(self)
    }
}

/// Compute the length of an arc when encoded in base 128.
const fn base128_len(arc: Arc) -> usize {
    match arc {
        0..=0x7f => 1,              // up to 7 bits
        0x80..=0x3fff => 2,         // up to 14 bits
        0x4000..=0x1fffff => 3,     // up to 21 bits
        0x200000..=0x0fffffff => 4, // up to 28 bits
        _ => 5,
    }
}

/// Compute the big endian base 128 encoding of the given [`Arc`] at the given byte.
const fn base128_byte(arc: Arc, pos: usize, total: usize) -> Result<u8> {
    debug_assert!(pos < total);
    let last_byte = checked_add!(pos, 1) == total;
    let mask = if last_byte { 0 } else { 0b10000000 };
    let shift = checked_mul!(checked_sub!(checked_sub!(total, pos), 1), 7);
    Ok(((arc >> shift) & 0b1111111) as u8 | mask)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::Encoder;
    use hex_literal::hex;

    /// OID `1.2.840.10045.2.1` encoded as ASN.1 BER/DER
    const EXAMPLE_OID_BER: &[u8] = &hex!("2A8648CE3D0201");

    #[test]
    fn base128_byte() {
        let example_arc = 0x44332211;
        assert_eq!(super::base128_len(example_arc), 5);
        assert_eq!(super::base128_byte(example_arc, 0, 5).unwrap(), 0b10000100);
        assert_eq!(super::base128_byte(example_arc, 1, 5).unwrap(), 0b10100001);
        assert_eq!(super::base128_byte(example_arc, 2, 5).unwrap(), 0b11001100);
        assert_eq!(super::base128_byte(example_arc, 3, 5).unwrap(), 0b11000100);
        assert_eq!(super::base128_byte(example_arc, 4, 5).unwrap(), 0b10001);
    }

    #[test]
    fn encode_large_second_arc_under_joint_iso_itu_t() {
        // 2.999 -> first subidentifier 1079 = 0x88 0x37
        let encoder = Encoder::<4>::new().arc(2).unwrap().arc(999).unwrap().arc(3).unwrap();
        assert_eq!(&encoder.bytes[..encoder.cursor], &hex!("883703"));
        assert!(Encoder::<4>::new().arc(1).unwrap().arc(40).is_err());
        assert!(Encoder::<4>::new().arc(0).unwrap().arc(40).is_err());
        assert!(Encoder::<4>::new().arc(2).unwrap().arc(u32::MAX).is_err());
    }

    #[test]
    fn encode() {
        let encoder = Encoder::<7>::new();
        let encoder = encoder.arc(1).unwrap();
        let encoder = encoder.arc(2).unwrap();
        let encoder = encoder.arc(840).unwrap();
        let encoder = encoder.arc(10045).unwrap();
        let encoder = encoder.arc(2).unwrap();
        let encoder = encoder.arc(1).unwrap();
        assert_eq!(&encoder.bytes[..encoder.cursor], EXAMPLE_OID_BER);
    }
}
