// Derived from pyHanko `pdf_utils/crypt/cred_ser.py` (MIT, see LICENSE-pyHanko).

//! Credential serialisation (`SerialisedCredential`,
//! `SerialisableCredential`).
//!
//! pyHanko keeps a registry of credential classes; the two built-in ones
//! (`pwd_bytes` and `raw_privkey`) are the variants of
//! [`SerialisableCredential`].

use super::pubkey::SimpleEnvelopeKeyDecrypter;
use super::standard::PasswordCredential;
use crate::error::{PdfError, PdfResult};

/// A credential in serialised form (`SerialisedCredential`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerialisedCredential {
    /// Registered type name of the credential.
    pub credential_type: String,
    /// The credential data.
    pub data: Vec<u8>,
}

/// A credential that can be serialised (`SerialisableCredential`).
#[derive(Clone, Debug)]
pub enum SerialisableCredential {
    /// Password credential of the standard handler (`pwd_bytes`).
    Password(PasswordCredential),
    /// In-memory private key and certificate (`raw_privkey`).
    PrivateKey(SimpleEnvelopeKeyDecrypter),
}

impl SerialisableCredential {
    /// The registered type name (`get_name`).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Password(_) => PasswordCredential::NAME,
            Self::PrivateKey(_) => SimpleEnvelopeKeyDecrypter::NAME,
        }
    }

    /// Serialise (`serialise`).
    pub fn serialise(&self) -> SerialisedCredential {
        match self {
            Self::Password(p) => p.serialise(),
            Self::PrivateKey(k) => k.serialise(),
        }
    }

    /// Deserialise by type name (`SerialisableCredential.deserialise`).
    pub fn deserialise(ser_value: &SerialisedCredential) -> PdfResult<Self> {
        match ser_value.credential_type.as_str() {
            PasswordCredential::NAME => PasswordCredential::from_der(&ser_value.data).map(Self::Password),
            SimpleEnvelopeKeyDecrypter::NAME => {
                SimpleEnvelopeKeyDecrypter::from_serialised(&ser_value.data).map(Self::PrivateKey)
            }
            other => Err(PdfError::Read(format!(
                "Failed to deserialise credential: credential type '{other}' not known."
            ))),
        }
    }

    /// The password credential, if this is one.
    pub fn as_password(&self) -> Option<&PasswordCredential> {
        match self {
            Self::Password(p) => Some(p),
            Self::PrivateKey(_) => None,
        }
    }

    /// Python class name, for error messages.
    pub(crate) fn class_name(&self) -> &'static str {
        match self {
            Self::Password(_) => "<class 'pyhanko.pdf_utils.crypt.standard._PasswordCredential'>",
            Self::PrivateKey(_) => "<class 'pyhanko.pdf_utils.crypt.pubkey.SimpleEnvelopeKeyDecrypter'>",
        }
    }
}
