// Derived from pyHanko `pdf_utils/crypt/permissions.py` (MIT, see LICENSE-pyHanko).

//! Permission flags of the standard and public-key security handlers
//! (`PdfPermissions`, `StandardPermissions`, `PubKeyPermissions`).
//!
//! Like pyHanko's `Flag` classes, a value only holds the defined flags;
//! the reserved bits are set on serialisation ([`StandardPermissions::as_uint32`]).

use std::ops::{BitAnd, BitOr, Not, Sub};

macro_rules! permission_set {
    (
        $(#[$meta:meta])*
        $name:ident, reserved = $reserved:expr,
        { $($(#[$fmeta:meta])* $flag:ident = $val:expr,)* }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name(u32);

        impl $name {
            $($(#[$fmeta])* pub const $flag: Self = Self($val);)*

            const ALL_BITS: u32 = 0 $(| $val)*;

            /// No flags set.
            pub const fn empty() -> Self {
                Self(0)
            }

            /// All defined flags (`allow_everything`).
            pub const fn allow_everything() -> Self {
                Self(Self::ALL_BITS)
            }

            /// The defined flags set in a 32-bit unsigned value (`from_uint`).
            pub const fn from_uint(uint_flags: u32) -> Self {
                Self(uint_flags & Self::ALL_BITS)
            }

            /// Flags from 4 big-endian bytes (`from_bytes`).
            pub fn from_bytes(flags: [u8; 4]) -> Self {
                Self::from_uint(u32::from_be_bytes(flags))
            }

            /// Flags from a 32-bit signed value, as stored in `/P` (`from_sint32`).
            pub const fn from_sint32(sint32_flags: i64) -> Self {
                Self::from_uint((sint32_flags & 0xFFFF_FFFF) as u32)
            }

            /// The defined flags as a bit mask (without reserved bits).
            pub const fn bits(self) -> u32 {
                self.0
            }

            /// `flag in self`.
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            /// 32-bit unsigned representation, with the reserved bits set as
            /// the specification requires (`as_uint32`).
            pub const fn as_uint32(self) -> u32 {
                self.0 | $reserved
            }

            /// Big-endian bytes of [`Self::as_uint32`] (`as_bytes`).
            pub const fn as_bytes(self) -> [u8; 4] {
                self.as_uint32().to_be_bytes()
            }

            /// Signed 32-bit representation, as stored in `/P` (`as_sint32`).
            pub const fn as_sint32(self) -> i32 {
                self.as_uint32() as i32
            }

            /// `True` if a PDF MAC is required (`mac_required`).
            pub const fn mac_required(self) -> bool {
                !self.contains(Self::TOLERATE_MISSING_PDF_MAC)
            }
        }

        impl BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl BitAnd for $name {
            type Output = Self;
            fn bitand(self, rhs: Self) -> Self {
                Self(self.0 & rhs.0)
            }
        }

        impl Sub for $name {
            type Output = Self;
            fn sub(self, rhs: Self) -> Self {
                Self(self.0 & !rhs.0)
            }
        }

        /// Complement within the defined flags (Python's `~flag`).
        impl Not for $name {
            type Output = Self;
            fn not(self) -> Self {
                Self(!self.0 & Self::ALL_BITS)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let names: Vec<&str> = [$((stringify!($flag), $val)),*]
                    .iter()
                    .filter(|(_, v)| self.0 & v != 0)
                    .map(|(n, _)| *n)
                    .collect();
                write!(f, "{}({})", stringify!($name), names.join("|"))
            }
        }
    };
}

permission_set! {
    /// Permission flags for the standard security handler (ISO 32000-2,
    /// Table 22).
    StandardPermissions, reserved = 0xFFFF_E0C0,
    {
        /// Bit 3.
        ALLOW_PRINTING = 4,
        /// Bit 4.
        ALLOW_MODIFICATION_GENERIC = 8,
        /// Bit 5.
        ALLOW_CONTENT_EXTRACTION = 16,
        /// Bit 6.
        ALLOW_ANNOTS_FORM_FILLING = 32,
        /// Bit 9.
        ALLOW_FORM_FILLING = 256,
        /// Bit 10.
        ALLOW_ASSISTIVE_TECHNOLOGY = 512,
        /// Bit 11.
        ALLOW_REASSEMBLY = 1024,
        /// Bit 12.
        ALLOW_HIGH_QUALITY_PRINTING = 2048,
        /// Bit 13 (ISO 32004).
        TOLERATE_MISSING_PDF_MAC = 4096,
    }
}

permission_set! {
    /// Permission flags for the public-key security handler (ISO 32000-2,
    /// Table 24). Bit 1 is always set on output, for Acrobat.
    PubKeyPermissions, reserved = 0xFFFF_E0C1,
    {
        /// Bit 2.
        ALLOW_ENCRYPTION_CHANGE = 2,
        /// Bit 3.
        ALLOW_PRINTING = 4,
        /// Bit 4.
        ALLOW_MODIFICATION_GENERIC = 8,
        /// Bit 5.
        ALLOW_CONTENT_EXTRACTION = 16,
        /// Bit 6.
        ALLOW_ANNOTS_FORM_FILLING = 32,
        /// Bit 9.
        ALLOW_FORM_FILLING = 256,
        /// Bit 10.
        ALLOW_ASSISTIVE_TECHNOLOGY = 512,
        /// Bit 11.
        ALLOW_REASSEMBLY = 1024,
        /// Bit 12.
        ALLOW_HIGH_QUALITY_PRINTING = 2048,
        /// Bit 13 (ISO 32004).
        TOLERATE_MISSING_PDF_MAC = 4096,
    }
}

/// Permission flags of either handler type (`PdfPermissions`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PdfPermissions {
    /// Standard security handler flags.
    Standard(StandardPermissions),
    /// Public-key security handler flags.
    PubKey(PubKeyPermissions),
}

impl PdfPermissions {
    /// `mac_required`.
    pub fn mac_required(self) -> bool {
        match self {
            Self::Standard(p) => p.mac_required(),
            Self::PubKey(p) => p.mac_required(),
        }
    }

    /// `as_uint32`.
    pub fn as_uint32(self) -> u32 {
        match self {
            Self::Standard(p) => p.as_uint32(),
            Self::PubKey(p) => p.as_uint32(),
        }
    }

    /// `as_sint32`.
    pub fn as_sint32(self) -> i32 {
        self.as_uint32() as i32
    }

    /// `as_bytes`.
    pub fn as_bytes(self) -> [u8; 4] {
        self.as_uint32().to_be_bytes()
    }
}

impl From<StandardPermissions> for PdfPermissions {
    fn from(p: StandardPermissions) -> Self {
        Self::Standard(p)
    }
}

impl From<PubKeyPermissions> for PdfPermissions {
    fn from(p: PubKeyPermissions) -> Self {
        Self::PubKey(p)
    }
}

impl PartialEq<StandardPermissions> for PdfPermissions {
    fn eq(&self, other: &StandardPermissions) -> bool {
        matches!(self, Self::Standard(p) if p == other)
    }
}

impl PartialEq<PubKeyPermissions> for PdfPermissions {
    fn eq(&self, other: &PubKeyPermissions) -> bool {
        matches!(self, Self::PubKey(p) if p == other)
    }
}
