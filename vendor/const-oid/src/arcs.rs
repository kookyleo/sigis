//! Arcs are integer values which exist within an OID's hierarchy.

use crate::{Error, Result};

#[cfg(doc)]
use crate::ObjectIdentifier;

/// Type alias used to represent an "arc", i.e. integer identifier value, where an OID comprises a
/// sequence of arcs.
///
/// X.660 does not define a maximum size of an arc. We instead follow Mozilla* conventions for
/// maximum values of an arc, with a maximum value of 2^32-1 (4294967295), a.k.a. [`u32::MAX`]
/// with [`Arc`] being a type alias for [`u32`].
///
/// Note that this means we deliberately do *NOT* support UUIDs used as OIDs.
///
/// *NOTE: please see this study for a survey of how various OID libraries handle maximum arcs:
/// <https://misc.daniel-marschall.de/asn.1/oid_facts.html>
pub type Arc = u32;

/// Maximum value of the first arc in an OID.
pub(crate) const ARC_MAX_FIRST: Arc = 2;

/// Maximum value of the second arc in an OID whose first arc is 0 or 1.
///
/// Under the first arc 2 the second arc is unbounded (X.690 §8.19.4): the
/// first subidentifier is `80 + second`, base-128 encoded like any other.
pub(crate) const ARC_MAX_SECOND: Arc = 39;

/// Decode the first subidentifier of an OID (which combines the first two
/// arcs) and return `(first_arc, second_arc, encoded_length)`.
fn root_arcs(bytes: &[u8]) -> Result<(Arc, Arc, usize)> {
    let mut value: Arc = 0;
    let mut len = 0usize;
    loop {
        let byte = *bytes.get(len).ok_or(if len == 0 { Error::Empty } else { Error::Base128 })?;
        len = checked_add!(len, 1);
        value = value
            .checked_mul(0x80)
            .and_then(|v| v.checked_add((byte & 0b0111_1111) as Arc))
            .ok_or(Error::ArcTooBig)?;
        if byte & 0b1000_0000 == 0 {
            break;
        }
    }
    let first = match value {
        0..=39 => 0,
        40..=79 => 1,
        _ => 2,
    };
    // `first * (ARC_MAX_SECOND + 1) <= value` by construction.
    #[allow(clippy::arithmetic_side_effects)]
    let second = value - first * (ARC_MAX_SECOND + 1);
    Ok((first, second, len))
}

/// [`Iterator`] over [`Arc`] values (a.k.a. nodes) in an [`ObjectIdentifier`].
///
/// This iterates over all arcs in an OID, including the root.
pub struct Arcs<'a> {
    /// OID bytes we're iterating over.
    bytes: &'a [u8],

    /// Current position within the serialized BER bytes of this OID.
    cursor: Option<usize>,
}

impl<'a> Arcs<'a> {
    /// Create a new iterator over an OID encoded as BER bytes.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            cursor: None,
        }
    }

    /// Try to parse the next arc in this OID.
    ///
    /// This method is fallible so it can be used as a first pass to determine
    /// that the arcs in the OID are well-formed.
    pub(crate) fn try_next(&mut self) -> Result<Option<Arc>> {
        match self.cursor {
            // Indicates we're on the root arc
            None => {
                let (first, _, _) = root_arcs(self.bytes)?;
                self.cursor = Some(0);
                Ok(Some(first))
            }
            // `Some(0)` means the second arc is next; body offsets are >= 1.
            Some(0) => {
                let (_, second, len) = root_arcs(self.bytes)?;
                self.cursor = Some(len);
                Ok(Some(second))
            }
            Some(offset) => {
                let mut result: Arc = 0;
                let mut arc_bytes = 0;

                loop {
                    let len = checked_add!(offset, arc_bytes);

                    match self.bytes.get(len).cloned() {
                        Some(byte) => {
                            arc_bytes = checked_add!(arc_bytes, 1);

                            // A five byte arc can still exceed `Arc`, so the digits are
                            // accumulated with overflow checking rather than by counting
                            // bytes.
                            result = match result
                                .checked_mul(0x80)
                                .and_then(|result| result.checked_add((byte & 0b0111_1111) as Arc))
                            {
                                Some(result) => result,
                                None => return Err(Error::ArcTooBig),
                            };

                            if byte & 0b1000_0000 == 0 {
                                self.cursor = Some(checked_add!(offset, arc_bytes));
                                return Ok(Some(result));
                            }
                        }
                        None => {
                            if arc_bytes == 0 {
                                return Ok(None);
                            } else {
                                return Err(Error::Base128);
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Iterator for Arcs<'_> {
    type Item = Arc;

    fn next(&mut self) -> Option<Arc> {
        // ObjectIdentifier constructors should ensure the OID is well-formed
        self.try_next().expect("OID malformed")
    }
}
