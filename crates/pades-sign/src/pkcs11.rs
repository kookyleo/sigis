// Derived from pyHanko `pyhanko/sign/pkcs11.py` and `pyhanko/config/pkcs11.py`
// (MIT, see LICENSE-pyHanko).

//! PKCS#11 key access via `cryptoki` (`pyhanko.sign.pkcs11`).
//!
//! The entry points mirror pyHanko:
//!
//! - [`open`] (`PKCS11SigningContext`): open a session from a
//!   [`Pkcs11Config`] and return a loaded signer.
//! - [`open_pkcs11_session`] and [`Pkcs11Signer::new`] (`PKCS11Signer`):
//!   the lower-level API.
//! - [`find_token`], [`select_pkcs11_signing_params`]: helpers that pyHanko
//!   exposes for testing and customisation.
//!
//! pyHanko loads the signing certificate and key handle lazily, on the first
//! signature. [`Pkcs11Signer::new`] loads them eagerly (the
//! [`KeySigner`] interface returns the certificate without an error
//! channel), in the same order, so the same errors surface one step earlier.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use der::asn1::{OctetString, UintRef};
use der::{Encode, Sequence};
use sigis_pki_core::algorithms::{DigestAlgorithm, SignatureMechanism};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};
use sigis_pki_core::sign::KeySigner;
use spki::AlgorithmIdentifierOwned;

pub use cryptoki;

use crate::signer::{default_signature_mechanism, digest_algorithm_id};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// An error from the PKCS#11 layer (`pkcs11.PKCS11Error` and its subclasses
/// in python-pkcs11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11Error {
    /// The python-pkcs11 exception class name (`PKCS11Error`,
    /// `ArgumentsBad`, ...), or the PKCS#11 return value.
    pub kind: String,
    /// Description.
    pub message: String,
}

impl Pkcs11Error {
    /// A generic `PKCS11Error`.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            kind: "PKCS11Error".into(),
            message: message.into(),
        }
    }

    fn with_kind(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Pkcs11Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Pkcs11Error {}

impl From<CkError> for Pkcs11Error {
    fn from(e: CkError) -> Self {
        match &e {
            CkError::Pkcs11(rv, func) => {
                Self::with_kind(&format!("{rv:?}"), format!("{func}: {rv:?}"))
            }
            CkError::LibraryLoading(err) => Self::with_kind(
                "LibraryLoading",
                format!("could not load PKCS#11 module: {err}"),
            ),
            other => Self::new(other.to_string()),
        }
    }
}

impl From<Pkcs11Error> for HankoError {
    /// PKCS#11 errors surface as signing errors whose message starts with the
    /// python-pkcs11 class name in brackets.
    fn from(e: Pkcs11Error) -> Self {
        HankoError::Signing(format!("[{}] {}", e.kind, e.message))
    }
}

fn signing_error(msg: impl Into<String>) -> HankoError {
    HankoError::Signing(msg.into())
}

// ---------------------------------------------------------------------------
// Configuration (`pyhanko.config.pkcs11`)
// ---------------------------------------------------------------------------

/// Search criteria for a PKCS#11 token (`TokenCriteria`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenCriteria {
    /// Label of the token; `None`: no constraint.
    pub label: Option<String>,
    /// Serial number of the token; `None`: no constraint.
    pub serial: Option<Vec<u8>>,
}

impl TokenCriteria {
    /// Criteria on the label only.
    pub fn label(label: impl Into<String>) -> Self {
        Self {
            label: Some(label.into()),
            serial: None,
        }
    }
}

/// PIN entry behaviour if no user PIN is configured (`PKCS11PinEntryMode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PinEntryMode {
    /// Prompt for a PIN. Only the CLI prompts; library code treats this as
    /// [`PinEntryMode::Skip`].
    #[default]
    Prompt,
    /// Let the module authenticate by itself (protected authentication path,
    /// e.g. a PIN pad).
    Defer,
    /// Do not log in.
    Skip,
}

/// PIN entry behaviour for signing operations (`PKCS11SigningPinEntryMode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SigningPinEntryMode {
    /// Do not re-authenticate before signing.
    #[default]
    Skip,
    /// Prompt for a PIN (CLI only; library code skips).
    Prompt,
    /// Re-authenticate with the signing PIN (or the login PIN).
    Reauthenticate,
}

/// How to find a key on a token (`PKCS11SignatureConfig`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkcs11Config {
    /// Path of the PKCS#11 module.
    pub module_path: String,
    /// Token label (deprecated alias of `token_criteria.label`).
    pub token_label: Option<String>,
    /// Key label. Defaults to `cert_label` when neither `key_label` nor
    /// `key_id` is set.
    pub key_label: Option<String>,
    /// Key id.
    pub key_id: Option<Vec<u8>>,
    /// Label of the signer's certificate.
    pub cert_label: Option<String>,
    /// Id of the signer's certificate.
    pub cert_id: Option<Vec<u8>>,
    /// The signer's certificate; if set, the certificate is not read from
    /// the token.
    pub signing_certificate: Option<Cert>,
    /// Criteria for the token.
    pub token_criteria: Option<TokenCriteria>,
    /// Other relevant certificates.
    pub other_certs: Vec<Cert>,
    /// Slot index.
    pub slot_no: Option<usize>,
    /// The user PIN.
    pub user_pin: Option<String>,
    /// Login behaviour if no PIN is given.
    pub prompt_pin: PinEntryMode,
    /// Labels of other certificates to read from the token; `None`: all.
    pub other_certs_to_pull: Option<Vec<String>>,
    /// Fetch all certificates at once and filter (`bulk_fetch`).
    pub bulk_fetch: bool,
    /// Prefer RSASSA-PSS for RSA keys.
    pub prefer_pss: bool,
    /// Use the raw (hash-less) mechanism.
    pub raw_mechanism: bool,
    /// Only consider certificates stored on the token (`CKA_TOKEN`).
    pub only_resident_certs: bool,
    /// Explicit signature mechanism.
    pub signature_mechanism: Option<AlgorithmIdentifierOwned>,
    /// Re-authentication before signing.
    pub signing_pin_mode: SigningPinEntryMode,
    /// PIN for re-authentication.
    pub signing_pin: Option<String>,
}

impl Default for Pkcs11Config {
    fn default() -> Self {
        Self {
            module_path: String::new(),
            token_label: None,
            key_label: None,
            key_id: None,
            cert_label: None,
            cert_id: None,
            signing_certificate: None,
            token_criteria: None,
            other_certs: Vec::new(),
            slot_no: None,
            user_pin: None,
            prompt_pin: PinEntryMode::Prompt,
            other_certs_to_pull: Some(Vec::new()),
            bulk_fetch: true,
            prefer_pss: false,
            raw_mechanism: false,
            only_resident_certs: false,
            signature_mechanism: None,
            signing_pin_mode: SigningPinEntryMode::Skip,
            signing_pin: None,
        }
    }
}

impl Pkcs11Config {
    /// The effective token criteria: `token_criteria`, with `token_label`
    /// as the label if the criteria do not set one.
    pub fn effective_token_criteria(&self) -> Option<TokenCriteria> {
        match (&self.token_criteria, &self.token_label) {
            (Some(c), Some(lbl)) if c.label.is_none() => Some(TokenCriteria {
                label: Some(lbl.clone()),
                serial: c.serial.clone(),
            }),
            (Some(c), _) => Some(c.clone()),
            (None, Some(lbl)) => Some(TokenCriteria::label(lbl.clone())),
            (None, None) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tokens and slots
// ---------------------------------------------------------------------------

/// A token as seen by [`find_token`].
pub trait TokenView {
    /// Token label (without padding).
    fn label(&self) -> &str;
    /// Token serial number.
    fn serial(&self) -> &[u8];
}

/// A slot as seen by [`find_token`].
pub trait SlotView {
    /// The token type.
    type Token: TokenView;
    /// The token in the slot; an error if the slot is empty.
    fn get_token(&self) -> std::result::Result<Self::Token, Pkcs11Error>;
}

/// The criteria `token` violates, as `(field, expected value)`
/// (`criteria_mismatches`).
pub fn criteria_mismatches(
    criteria: Option<&TokenCriteria>,
    token: &impl TokenView,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let Some(c) = criteria else {
        return out;
    };
    if let Some(lbl) = &c.label {
        if token.label() != lbl {
            out.push(("label", lbl.clone()));
        }
    }
    if let Some(serial) = &c.serial {
        if token.serial() != serial.as_slice() {
            out.push(("serial", hex(serial)));
        }
    }
    out
}

/// Whether `token` satisfies `criteria` (`criteria_satisfied_by`).
pub fn criteria_satisfied_by(criteria: Option<&TokenCriteria>, token: &impl TokenView) -> bool {
    criteria_mismatches(criteria, token).is_empty()
}

/// Find a token (`find_token`): the token in slot `slot_no`, or the first
/// token matching `criteria`. `Ok(None)` if no token matches.
pub fn find_token<S: SlotView>(
    slots: &[S],
    slot_no: Option<usize>,
    criteria: Option<&TokenCriteria>,
) -> std::result::Result<Option<S::Token>, Pkcs11Error> {
    match slot_no {
        None if criteria.is_none() => {
            if let [only] = slots {
                only.get_token().map(Some)
            } else {
                Err(Pkcs11Error::new(
                    "Module has more than 1 slot; slot index or token criteria must be provided",
                ))
            }
        }
        None => {
            for slot in slots {
                if let Ok(token) = slot.get_token() {
                    if criteria_satisfied_by(criteria, &token) {
                        return Ok(Some(token));
                    }
                }
            }
            Ok(None)
        }
        Some(ix) => {
            let slot = slots.get(ix).ok_or_else(|| {
                Pkcs11Error::new(format!(
                    "Slot index {ix} too large; there are only {}",
                    slots.len()
                ))
            })?;
            let token = slot.get_token()?;
            let errors = criteria_mismatches(criteria, &token);
            if errors.is_empty() {
                Ok(Some(token))
            } else {
                let err_str = errors
                    .iter()
                    .map(|(field, val)| format!("{field} is not '{val}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(Pkcs11Error::new(format!(
                    "Token in slot {ix} does not satisfy criteria; {err_str}."
                )))
            }
        }
    }
}

/// Load and initialise a PKCS#11 module. Modules are cached per path for the
/// lifetime of the process (as python-pkcs11 does), since `C_Initialize` may
/// only be called once per process.
pub fn load_module(path: &str) -> std::result::Result<Pkcs11, Pkcs11Error> {
    static MODULES: OnceLock<Mutex<HashMap<String, Pkcs11>>> = OnceLock::new();
    let modules = MODULES.get_or_init(Default::default);
    let mut guard = modules
        .lock()
        .map_err(|_| Pkcs11Error::new("PKCS#11 module cache poisoned"))?;
    if let Some(m) = guard.get(path) {
        return Ok(m.clone());
    }
    let ctx = Pkcs11::new(path)?;
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => return Err(e.into()),
    }
    guard.insert(path.to_owned(), ctx.clone());
    Ok(ctx)
}

/// A slot of a loaded module.
#[derive(Clone, Debug)]
pub struct Pkcs11Slot {
    ctx: Pkcs11,
    slot: Slot,
}

/// A token of a loaded module.
#[derive(Clone, Debug)]
pub struct Pkcs11Token {
    ctx: Pkcs11,
    slot: Slot,
    label: String,
    serial: Vec<u8>,
    protected_auth: bool,
}

impl SlotView for Pkcs11Slot {
    type Token = Pkcs11Token;
    fn get_token(&self) -> std::result::Result<Pkcs11Token, Pkcs11Error> {
        let info = self.ctx.get_token_info(self.slot)?;
        Ok(Pkcs11Token {
            ctx: self.ctx.clone(),
            slot: self.slot,
            label: info.label().trim_end().to_owned(),
            serial: info.serial_number().trim_end().as_bytes().to_vec(),
            protected_auth: info.protected_authentication_path(),
        })
    }
}

impl TokenView for Pkcs11Token {
    fn label(&self) -> &str {
        &self.label
    }
    fn serial(&self) -> &[u8] {
        &self.serial
    }
}

/// All slots of a module (`lib.get_slots()`).
pub fn get_slots(ctx: &Pkcs11) -> std::result::Result<Vec<Pkcs11Slot>, Pkcs11Error> {
    Ok(ctx
        .get_all_slots()?
        .into_iter()
        .map(|slot| Pkcs11Slot {
            ctx: ctx.clone(),
            slot,
        })
        .collect())
}

/// How to log in when opening a session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum UserPin {
    /// Do not log in.
    #[default]
    None,
    /// Log in as the user with this PIN.
    Pin(String),
    /// Log in through the protected authentication path (`PROTECTED_AUTH`).
    ProtectedAuth,
}

/// An open PKCS#11 session, shareable between threads.
pub struct Pkcs11Session {
    session: Mutex<Session>,
    token: Pkcs11Token,
}

impl fmt::Debug for Pkcs11Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11Session")
            .field("token", &self.token.label)
            .finish()
    }
}

impl Pkcs11Session {
    /// Run `f` with exclusive access to the session.
    pub fn with<T>(
        &self,
        f: impl FnOnce(&Session) -> std::result::Result<T, Pkcs11Error>,
    ) -> std::result::Result<T, Pkcs11Error> {
        let guard = self
            .session
            .lock()
            .map_err(|_| Pkcs11Error::new("PKCS#11 session lock poisoned"))?;
        f(&guard)
    }

    /// The token label.
    pub fn token_label(&self) -> &str {
        &self.token.label
    }

    /// Mechanisms the token's slot supports, as `CKM_*` values.
    pub fn mechanisms(&self) -> std::result::Result<Vec<u64>, Pkcs11Error> {
        Ok(self
            .token
            .ctx
            .get_mechanism_list(self.token.slot)?
            .into_iter()
            .map(|m| ck_value(*m))
            .collect())
    }

    /// Find objects matching `template`; returns them all, in token order.
    pub fn find_objects(
        &self,
        template: &[Attribute],
    ) -> std::result::Result<Vec<ObjectHandle>, Pkcs11Error> {
        self.with(|s| Ok(s.find_objects(template)?))
    }

    fn attribute_bytes(
        &self,
        obj: ObjectHandle,
        ty: AttributeType,
    ) -> std::result::Result<Vec<u8>, Pkcs11Error> {
        let attrs = self.with(|s| Ok(s.get_attributes(obj, &[ty])?))?;
        for a in attrs {
            match a {
                Attribute::Value(v) if ty == AttributeType::Value => return Ok(v),
                Attribute::Label(v) if ty == AttributeType::Label => return Ok(v),
                _ => {}
            }
        }
        Err(Pkcs11Error::with_kind(
            "AttributeTypeInvalid",
            format!("object has no {ty:?} attribute"),
        ))
    }
}

/// Open a session on a token (`open_pkcs11_session`).
pub fn open_pkcs11_session(
    lib_location: &str,
    slot_no: Option<usize>,
    token_criteria: Option<&TokenCriteria>,
    user_pin: &UserPin,
) -> std::result::Result<Pkcs11Session, Pkcs11Error> {
    let ctx = load_module(lib_location)?;
    let slots = get_slots(&ctx)?;
    let token = find_token(&slots, slot_no, token_criteria)?.ok_or_else(|| {
        Pkcs11Error::new(match token_criteria {
            Some(c) => format!("No token matching criteria {c:?} found"),
            None => "No token found".to_owned(),
        })
    })?;
    open_token(token, user_pin)
}

/// Open a read-only session on `token` and log in (`Token.open`).
pub fn open_token(
    token: Pkcs11Token,
    user_pin: &UserPin,
) -> std::result::Result<Pkcs11Session, Pkcs11Error> {
    if *user_pin == UserPin::ProtectedAuth && !token.protected_auth {
        return Err(Pkcs11Error::with_kind(
            "ArgumentsBad",
            "Protected authentication is not supported by loaded module",
        ));
    }
    let session = token.ctx.open_ro_session(token.slot)?;
    let login = match user_pin {
        UserPin::None => Ok(()),
        UserPin::Pin(pin) => session.login(UserType::User, Some(&AuthPin::new(pin.clone().into()))),
        UserPin::ProtectedAuth => session.login(UserType::User, None),
    };
    match login {
        // the user is already logged in through another session of this
        // process; login state is shared per token
        Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(Pkcs11Session {
        session: Mutex::new(session),
        token,
    })
}

// ---------------------------------------------------------------------------
// Mechanism selection (`select_pkcs11_signing_params`)
// ---------------------------------------------------------------------------

/// A `CK_ULONG` as `u64` (`CK_ULONG` is 32 bits wide on some platforms).
#[allow(clippy::useless_conversion)]
fn ck_value(v: std::ffi::c_ulong) -> u64 {
    u64::from(v)
}

/// `CKM_*` values of mechanisms that `cryptoki` has no constant for.
mod ckm {
    pub const DSA: u64 = 0x11;
    pub const DSA_SHA1: u64 = 0x12;
    pub const DSA_SHA224: u64 = 0x13;
    pub const DSA_SHA256: u64 = 0x14;
    pub const DSA_SHA384: u64 = 0x15;
    pub const DSA_SHA512: u64 = 0x16;
    pub const SHA224_RSA_PKCS: u64 = 0x46;
    pub const SHA224_RSA_PKCS_PSS: u64 = 0x47;
    pub const ECDSA_SHA224: u64 = 0x1043;
    pub const ML_DSA: u64 = 0x1d;
    pub const VENDOR_DEFINED: u64 = 0x8000_0000;
}

/// A PKCS#11 signing mechanism with its parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pkcs11Mechanism {
    /// `CKM_RSA_PKCS` (raw PKCS#1 v1.5 padding over a `DigestInfo`).
    RsaPkcs,
    /// `CKM_SHA*_RSA_PKCS`.
    ShaRsaPkcs(DigestAlgorithm),
    /// `CKM_SHA*_RSA_PKCS_PSS` with `(digest, MGF1 digest, salt length)`.
    ShaRsaPkcsPss {
        /// Message digest.
        digest: DigestAlgorithm,
        /// MGF1 digest.
        mgf_digest: DigestAlgorithm,
        /// Salt length in bytes.
        salt_len: u64,
    },
    /// `CKM_DSA`.
    Dsa,
    /// `CKM_DSA_SHA*`.
    DsaSha(DigestAlgorithm),
    /// `CKM_ECDSA`.
    Ecdsa,
    /// `CKM_ECDSA_SHA*`.
    EcdsaSha(DigestAlgorithm),
    /// `CKM_EDDSA` (pure Ed25519).
    Eddsa,
    /// `CKM_EDDSA` with explicit parameters (pure Ed448).
    EddsaEd448,
    /// `CKM_ML_DSA`.
    MlDsa,
    /// Any other mechanism, by `CKM_*` value, without parameters.
    Other(u64),
}

/// Placeholder `CKM_*` value for digests without a PKCS#11 mechanism.
const CKM_INVALID: u64 = u64::MAX;

impl Pkcs11Mechanism {
    /// The `CKM_*` value.
    pub fn mechanism_type(&self) -> u64 {
        use DigestAlgorithm::*;
        let t = |m: MechanismType| ck_value(*m);
        match self {
            Self::RsaPkcs => t(MechanismType::RSA_PKCS),
            Self::ShaRsaPkcs(d) => match d {
                Sha1 => t(MechanismType::SHA1_RSA_PKCS),
                Sha224 => ckm::SHA224_RSA_PKCS,
                Sha256 => t(MechanismType::SHA256_RSA_PKCS),
                Sha384 => t(MechanismType::SHA384_RSA_PKCS),
                Sha512 => t(MechanismType::SHA512_RSA_PKCS),
                Sha3_224 => 0x66,
                Sha3_256 => 0x60,
                Sha3_384 => 0x61,
                Sha3_512 => 0x62,
                Md5 | Shake256 => CKM_INVALID,
            },
            Self::ShaRsaPkcsPss { digest, .. } => match digest {
                Sha1 => t(MechanismType::SHA1_RSA_PKCS_PSS),
                Sha224 => ckm::SHA224_RSA_PKCS_PSS,
                Sha256 => t(MechanismType::SHA256_RSA_PKCS_PSS),
                Sha384 => t(MechanismType::SHA384_RSA_PKCS_PSS),
                Sha512 => t(MechanismType::SHA512_RSA_PKCS_PSS),
                Sha3_224 => 0x67,
                Sha3_256 => 0x63,
                Sha3_384 => 0x64,
                Sha3_512 => 0x65,
                Md5 | Shake256 => CKM_INVALID,
            },
            Self::Dsa => ckm::DSA,
            Self::DsaSha(d) => match d {
                Sha1 => ckm::DSA_SHA1,
                Sha224 => ckm::DSA_SHA224,
                Sha256 => ckm::DSA_SHA256,
                Sha384 => ckm::DSA_SHA384,
                Sha512 => ckm::DSA_SHA512,
                Sha3_224 => 0x18,
                Sha3_256 => 0x19,
                Sha3_384 => 0x1a,
                Sha3_512 => 0x1b,
                Md5 | Shake256 => CKM_INVALID,
            },
            Self::Ecdsa => t(MechanismType::ECDSA),
            Self::EcdsaSha(d) => match d {
                Sha1 => t(MechanismType::ECDSA_SHA1),
                Sha224 => ckm::ECDSA_SHA224,
                Sha256 => t(MechanismType::ECDSA_SHA256),
                Sha384 => t(MechanismType::ECDSA_SHA384),
                Sha512 => t(MechanismType::ECDSA_SHA512),
                Sha3_224 => 0x1047,
                Sha3_256 => 0x1048,
                Sha3_384 => 0x1049,
                Sha3_512 => 0x104a,
                Md5 | Shake256 => CKM_INVALID,
            },
            Self::Eddsa | Self::EddsaEd448 => t(MechanismType::EDDSA),
            Self::MlDsa => ckm::ML_DSA,
            Self::Other(v) => *v,
        }
    }

    fn unsupported(&self) -> Pkcs11Error {
        Pkcs11Error::with_kind(
            "MechanismInvalid",
            format!(
                "mechanism 0x{:x} ({self:?}) cannot be invoked through cryptoki",
                self.mechanism_type()
            ),
        )
    }

    fn digest_mech(&self, d: DigestAlgorithm) -> std::result::Result<MechanismType, Pkcs11Error> {
        Ok(match d {
            DigestAlgorithm::Sha1 => MechanismType::SHA1,
            DigestAlgorithm::Sha224 => MechanismType::SHA224,
            DigestAlgorithm::Sha256 => MechanismType::SHA256,
            DigestAlgorithm::Sha384 => MechanismType::SHA384,
            DigestAlgorithm::Sha512 => MechanismType::SHA512,
            _ => return Err(self.unsupported()),
        })
    }

    fn mgf(&self, d: DigestAlgorithm) -> std::result::Result<PkcsMgfType, Pkcs11Error> {
        Ok(match d {
            DigestAlgorithm::Sha1 => PkcsMgfType::MGF1_SHA1,
            DigestAlgorithm::Sha224 => PkcsMgfType::MGF1_SHA224,
            DigestAlgorithm::Sha256 => PkcsMgfType::MGF1_SHA256,
            DigestAlgorithm::Sha384 => PkcsMgfType::MGF1_SHA384,
            DigestAlgorithm::Sha512 => PkcsMgfType::MGF1_SHA512,
            _ => return Err(self.unsupported()),
        })
    }

    /// Build the `cryptoki` mechanism; `pss` holds the PSS parameters for
    /// the lifetime of the call.
    fn to_cryptoki<'a>(
        &self,
        pss: &'a mut Option<PkcsPssParams>,
    ) -> std::result::Result<Mechanism<'a>, Pkcs11Error> {
        use DigestAlgorithm::*;
        Ok(match self {
            Self::RsaPkcs => Mechanism::RsaPkcs,
            Self::ShaRsaPkcs(Sha1) => Mechanism::Sha1RsaPkcs,
            Self::ShaRsaPkcs(Sha224) => Mechanism::Sha224RsaPkcs,
            Self::ShaRsaPkcs(Sha256) => Mechanism::Sha256RsaPkcs,
            Self::ShaRsaPkcs(Sha384) => Mechanism::Sha384RsaPkcs,
            Self::ShaRsaPkcs(Sha512) => Mechanism::Sha512RsaPkcs,
            Self::ShaRsaPkcsPss {
                digest,
                mgf_digest,
                salt_len,
            } => {
                let params = PkcsPssParams {
                    hash_alg: self.digest_mech(*digest)?,
                    mgf: self.mgf(*mgf_digest)?,
                    s_len: (*salt_len).into(),
                };
                match digest {
                    Sha1 => Mechanism::Sha1RsaPkcsPss(params),
                    Sha256 => Mechanism::Sha256RsaPkcsPss(params),
                    Sha384 => Mechanism::Sha384RsaPkcsPss(params),
                    Sha512 => Mechanism::Sha512RsaPkcsPss(params),
                    Sha224 => {
                        let stored = pss.insert(params);
                        let ty = MechanismType::try_from(ckm::SHA224_RSA_PKCS_PSS)
                            .map_err(|_| self.unsupported())?;
                        Mechanism::VendorDefined(VendorDefinedMechanism::new(ty, Some(&*stored)))
                    }
                    _ => return Err(self.unsupported()),
                }
            }
            Self::Ecdsa => Mechanism::Ecdsa,
            Self::EcdsaSha(Sha1) => Mechanism::EcdsaSha1,
            Self::EcdsaSha(Sha224) => Mechanism::EcdsaSha224,
            Self::EcdsaSha(Sha256) => Mechanism::EcdsaSha256,
            Self::EcdsaSha(Sha384) => Mechanism::EcdsaSha384,
            Self::EcdsaSha(Sha512) => Mechanism::EcdsaSha512,
            Self::Eddsa => Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
            Self::EddsaEd448 => {
                Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed448(&[])))
            }
            Self::ShaRsaPkcs(_) | Self::EcdsaSha(_) => return Err(self.unsupported()),
            Self::MlDsa | Self::Dsa | Self::DsaSha(_) | Self::Other(_) => {
                let v = self.mechanism_type();
                let ty = if v >= ckm::VENDOR_DEFINED {
                    MechanismType::new_vendor_defined(v)
                } else {
                    MechanismType::try_from(v)
                }
                .map_err(|_| self.unsupported())?;
                Mechanism::VendorDefined(VendorDefinedMechanism::new::<()>(ty, None))
            }
        })
    }
}

/// A transformation of the data before signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreSignTransform {
    /// Hash the data, optionally wrapping the digest in a `DigestInfo`.
    HashFully {
        /// The digest.
        digest: DigestAlgorithm,
        /// Wrap in a DER `DigestInfo` (for `CKM_RSA_PKCS`).
        wrap_digest_info: bool,
    },
}

/// A transformation of the token's output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostSignTransform {
    /// `r || s` to a DER `ECDSA-Sig-Value` (`encode_ecdsa_signature`).
    EncodeEcdsa,
    /// `r || s` to a DER `Dss-Sig-Value` (`encode_dsa_signature`).
    EncodeDsa,
}

/// How to invoke a signature operation on a token
/// (`PKCS11SignatureOperationSpec`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkcs11SignatureOperationSpec {
    /// The mechanism (`sign_kwargs['mechanism']`).
    pub mechanism: Pkcs11Mechanism,
    /// Transformation before signing.
    pub pre_sign_transform: Option<PreSignTransform>,
    /// Transformation after signing.
    pub post_sign_transform: Option<PostSignTransform>,
}

/// The asn1crypto `signature_algo` name of a signature algorithm OID.
fn signature_algo_name(oid: &der::asn1::ObjectIdentifier) -> Option<&'static str> {
    Some(match oid.to_string().as_str() {
        "1.2.840.113549.1.1.1"
        | "1.3.14.3.2.3"
        | "1.3.14.3.2.29"
        | "1.3.14.7.2.3.1"
        | "1.2.840.113549.1.1.2"
        | "1.2.840.113549.1.1.4"
        | "1.2.840.113549.1.1.5"
        | "1.2.840.113549.1.1.14"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.113549.1.1.12"
        | "1.2.840.113549.1.1.13" => "rsassa_pkcs1v15",
        "1.2.840.113549.1.1.10" => "rsassa_pss",
        "1.2.840.10040.4.1"
        | "1.2.840.10040.4.3"
        | "1.3.14.3.2.13"
        | "1.3.14.3.2.27"
        | "2.16.840.1.101.3.4.3.1"
        | "2.16.840.1.101.3.4.3.2"
        | "2.16.840.1.101.3.4.3.3"
        | "2.16.840.1.101.3.4.3.4" => "dsa",
        "1.2.840.10045.4"
        | "1.2.840.10045.4.1"
        | "1.2.840.10045.4.3.1"
        | "1.2.840.10045.4.3.2"
        | "1.2.840.10045.4.3.3"
        | "1.2.840.10045.4.3.4"
        | "2.16.840.1.101.3.4.3.9"
        | "2.16.840.1.101.3.4.3.10"
        | "2.16.840.1.101.3.4.3.11"
        | "2.16.840.1.101.3.4.3.12" => "ecdsa",
        "1.3.101.112" => "ed25519",
        "1.3.101.113" => "ed448",
        "2.16.840.1.101.3.4.3.17" => "mldsa44",
        "2.16.840.1.101.3.4.3.18" => "mldsa65",
        "2.16.840.1.101.3.4.3.19" => "mldsa87",
        _ => return None,
    })
}

/// Set up a PKCS#11 signing operation (`select_pkcs11_signing_params`).
///
/// `mechanism_override` corresponds to `sign_kwargs['mechanism']`: it
/// replaces the selected mechanism (keeping the transformations), and makes
/// otherwise unsupported algorithms acceptable.
pub fn select_pkcs11_signing_params(
    signature_mechanism: &AlgorithmIdentifierOwned,
    digest: DigestAlgorithm,
    use_raw_mechanism: bool,
    mechanism_override: Option<Pkcs11Mechanism>,
) -> Result<Pkcs11SignatureOperationSpec> {
    let raw_unavailable =
        |what: &str| HankoError::Unsupported(format!("{what} not available in raw mode"));
    let algo = signature_algo_name(&signature_mechanism.oid);
    let mut pre = None;
    let mut post = None;
    let mechanism = match algo {
        Some("rsassa_pkcs1v15") => {
            if use_raw_mechanism {
                pre = Some(PreSignTransform::HashFully {
                    digest,
                    wrap_digest_info: true,
                });
                Some(Pkcs11Mechanism::RsaPkcs)
            } else {
                Some(Pkcs11Mechanism::ShaRsaPkcs(digest))
            }
        }
        Some("dsa") => {
            post = Some(PostSignTransform::EncodeDsa);
            if use_raw_mechanism {
                pre = Some(PreSignTransform::HashFully {
                    digest,
                    wrap_digest_info: false,
                });
                Some(Pkcs11Mechanism::Dsa)
            } else {
                Some(Pkcs11Mechanism::DsaSha(digest))
            }
        }
        Some("ecdsa") => {
            post = Some(PostSignTransform::EncodeEcdsa);
            if use_raw_mechanism {
                pre = Some(PreSignTransform::HashFully {
                    digest,
                    wrap_digest_info: false,
                });
                Some(Pkcs11Mechanism::Ecdsa)
            } else {
                Some(Pkcs11Mechanism::EcdsaSha(digest))
            }
        }
        Some("rsassa_pss") => {
            if use_raw_mechanism {
                return Err(raw_unavailable("RSASSA-PSS"));
            }
            let SignatureMechanism::RsaPss(params) =
                SignatureMechanism::from_algorithm_identifier(signature_mechanism, Some(digest))?
            else {
                return Err(HankoError::Malformed("RSASSA-PSS parameters".into()));
            };
            if params.digest != digest {
                return Err(signing_error(format!(
                    "PSS parameters specify digest {}, but {} was requested",
                    params.digest.name(),
                    digest.name()
                )));
            }
            Some(Pkcs11Mechanism::ShaRsaPkcsPss {
                digest,
                mgf_digest: params.mgf1_digest,
                salt_len: params.salt_length as u64,
            })
        }
        Some("ed25519") => {
            if use_raw_mechanism {
                return Err(raw_unavailable("Ed25519"));
            }
            Some(Pkcs11Mechanism::Eddsa)
        }
        Some("ed448") => {
            if use_raw_mechanism {
                return Err(raw_unavailable("Ed448"));
            }
            Some(Pkcs11Mechanism::EddsaEd448)
        }
        Some("mldsa44" | "mldsa65" | "mldsa87") => {
            if use_raw_mechanism {
                return Err(raw_unavailable("ML-DSA"));
            }
            Some(Pkcs11Mechanism::MlDsa)
        }
        _ => None,
    };
    let mechanism = match (mechanism_override, mechanism) {
        (Some(m), _) => m,
        (None, Some(m)) => m,
        (None, None) => {
            return Err(HankoError::Unsupported(format!(
                "Signature algorithm '{}' is not supported.",
                algo.map_or_else(|| signature_mechanism.oid.to_string(), str::to_owned)
            )))
        }
    };
    Ok(Pkcs11SignatureOperationSpec {
        mechanism,
        pre_sign_transform: pre,
        post_sign_transform: post,
    })
}

#[derive(Sequence)]
struct DigestInfo {
    algorithm: AlgorithmIdentifierOwned,
    digest: OctetString,
}

impl PreSignTransform {
    fn apply(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::HashFully {
                digest,
                wrap_digest_info,
            } => {
                let h = digest.digest(data);
                if *wrap_digest_info {
                    Ok(DigestInfo {
                        algorithm: digest_algorithm_id(*digest),
                        digest: OctetString::new(h)?,
                    }
                    .to_der()?)
                } else {
                    Ok(h)
                }
            }
        }
    }
}

#[derive(Sequence)]
struct DssSigValue<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

impl PostSignTransform {
    fn apply(&self, sig: &[u8]) -> Result<Vec<u8>> {
        if sig.is_empty() || !sig.len().is_multiple_of(2) {
            return Err(signing_error(format!(
                "the token returned a malformed signature of {} bytes",
                sig.len()
            )));
        }
        let (r, s) = sig.split_at(sig.len() / 2);
        Ok(DssSigValue {
            r: UintRef::new(r)?,
            s: UintRef::new(s)?,
        }
        .to_der()?)
    }
}

// ---------------------------------------------------------------------------
// The signer (`PKCS11Signer`)
// ---------------------------------------------------------------------------

/// Labels and ids identifying the key and the certificate, after pyHanko's
/// defaulting rules (`PKCS11Signer.__init__`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectSelectors {
    /// Certificate label.
    pub cert_label: Option<String>,
    /// Certificate id.
    pub cert_id: Option<Vec<u8>>,
    /// Key label.
    pub key_label: Option<String>,
    /// Key id.
    pub key_id: Option<Vec<u8>>,
}

impl ObjectSelectors {
    /// Apply the fallbacks: each of the key and certificate selectors
    /// defaults to the other's, unless the other side is pinned by the other
    /// kind of selector.
    pub fn resolve(
        cert_label: Option<String>,
        cert_id: Option<Vec<u8>>,
        key_label: Option<String>,
        key_id: Option<Vec<u8>>,
    ) -> Self {
        fn falsy<T: AsRef<[u8]>>(x: &Option<T>) -> bool {
            x.as_ref().is_none_or(|v| v.as_ref().is_empty())
        }
        let out_cert_label = cert_label.clone().or_else(|| {
            if falsy(&cert_id) {
                key_label.clone()
            } else {
                None
            }
        });
        let out_key_id = key_id.clone().or_else(|| {
            if falsy(&key_label) {
                cert_id.clone()
            } else {
                None
            }
        });
        let out_cert_id = cert_id.or_else(|| {
            if falsy(&cert_label) {
                key_id.clone()
            } else {
                None
            }
        });
        let out_key_label = key_label.or_else(|| if falsy(&key_id) { cert_label } else { None });
        Self {
            cert_label: out_cert_label,
            cert_id: out_cert_id,
            key_label: out_key_label,
            key_id: out_key_id,
        }
    }
}

/// Options of a [`Pkcs11Signer`] (the keyword arguments of `PKCS11Signer`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkcs11SignerOptions {
    /// Label of the signer's certificate.
    pub cert_label: Option<String>,
    /// Id of the signer's certificate.
    pub cert_id: Option<Vec<u8>>,
    /// Label of the key.
    pub key_label: Option<String>,
    /// Id of the key.
    pub key_id: Option<Vec<u8>>,
    /// The signer's certificate; if given, it is not read from the token.
    pub signing_cert: Option<Cert>,
    /// Other relevant certificates (`ca_chain`).
    pub ca_chain: Vec<Cert>,
    /// Labels of other certificates to read from the token; `None`: all of
    /// them.
    pub other_certs_to_pull: Option<Vec<String>>,
    /// Fetch all certificates and filter, instead of one query per label.
    /// Ignored (treated as `false`) for one label or fewer.
    pub bulk_fetch: bool,
    /// Prefer RSASSA-PSS for RSA keys.
    pub prefer_pss: bool,
    /// Use the raw mechanism on locally hashed data.
    pub use_raw_mechanism: bool,
    /// Explicit signature mechanism.
    pub signature_mechanism: Option<AlgorithmIdentifierOwned>,
    /// Override of the PKCS#11 mechanism (`base_sign_kwargs['mechanism']`).
    pub mechanism_override: Option<Pkcs11Mechanism>,
    /// PIN for context-specific re-authentication before each signature
    /// (`base_sign_kwargs['pin']`).
    pub signing_pin: Option<String>,
    /// Only consider certificates stored on the token.
    pub only_resident_certs: bool,
}

impl Default for Pkcs11SignerOptions {
    fn default() -> Self {
        Self {
            cert_label: None,
            cert_id: None,
            key_label: None,
            key_id: None,
            signing_cert: None,
            ca_chain: Vec::new(),
            other_certs_to_pull: Some(Vec::new()),
            bulk_fetch: true,
            prefer_pss: false,
            use_raw_mechanism: false,
            signature_mechanism: None,
            mechanism_override: None,
            signing_pin: None,
            only_resident_certs: false,
        }
    }
}

#[derive(Clone)]
struct SigningPinCallback(Arc<dyn Fn() -> Result<String> + Send + Sync>);

impl fmt::Debug for SigningPinCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningPinCallback(<redacted>)")
    }
}

/// A key on a PKCS#11 token (`PKCS11Signer`).
#[derive(Debug)]
pub struct Pkcs11Signer {
    session: Arc<Pkcs11Session>,
    selectors: ObjectSelectors,
    signing_cert: Cert,
    registry: Vec<Cert>,
    key: ObjectHandle,
    options: Pkcs11SignerOptions,
    signing_pin_callback: Option<SigningPinCallback>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The error message for a failed object lookup (`_format_pull_err_msg`).
pub fn format_pull_err_msg(
    object_kind: &str,
    no_results: bool,
    label: Option<&str>,
    id_value: Option<&[u8]>,
) -> String {
    let mut info = Vec::new();
    if let Some(l) = label {
        info.push(format!("label '{l}'"));
    }
    if let Some(id) = id_value {
        info.push(format!("ID '{}'", hex(id)));
    }
    let qualifier = if info.is_empty() {
        String::new()
    } else {
        format!(" with {}", info.join(", "))
    };
    if no_results {
        format!("Could not find {object_kind}{qualifier}.")
    } else {
        format!("Found more than one {object_kind}{qualifier}.")
    }
}

fn push_unique(registry: &mut Vec<Cert>, c: Cert) {
    if !registry.contains(&c) {
        registry.push(c);
    }
}

/// Object lookups on a session (`_pull_single_cert`, `__pull`,
/// `_pull_signing_key_handle`).
struct Loader<'a> {
    session: &'a Pkcs11Session,
    options: &'a Pkcs11SignerOptions,
    selectors: &'a ObjectSelectors,
}

impl Loader<'_> {
    fn cert_query(&self) -> Vec<Attribute> {
        let mut q = vec![Attribute::Class(ObjectClass::CERTIFICATE)];
        if self.options.only_resident_certs {
            q.push(Attribute::Token(true));
        }
        q
    }

    fn pull_single_cert(&self, label: Option<&str>, cert_id: Option<&[u8]>) -> Result<Cert> {
        let mut q = self.cert_query();
        if let Some(l) = label {
            q.push(Attribute::Label(l.as_bytes().to_vec()));
        }
        if let Some(id) = cert_id {
            q.push(Attribute::Id(id.to_vec()));
        }
        let results = self.session.find_objects(&q)?;
        if let [only] = results.as_slice() {
            let der = self.session.attribute_bytes(*only, AttributeType::Value)?;
            Ok(Cert::from_der(&der)?)
        } else {
            Err(Pkcs11Error::new(format_pull_err_msg(
                "certificate",
                results.is_empty(),
                label,
                cert_id,
            ))
            .into())
        }
    }

    fn pull_signing_key_handle(&self) -> Result<ObjectHandle> {
        let mut q = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Sign(true),
        ];
        if let Some(l) = &self.selectors.key_label {
            q.push(Attribute::Label(l.as_bytes().to_vec()));
        }
        if let Some(id) = &self.selectors.key_id {
            q.push(Attribute::Id(id.clone()));
        }
        let results = self.session.find_objects(&q)?;
        if let [only] = results.as_slice() {
            Ok(*only)
        } else {
            Err(Pkcs11Error::new(format_pull_err_msg(
                "private key",
                results.is_empty(),
                self.selectors.key_label.as_deref(),
                self.selectors.key_id.as_deref(),
            ))
            .into())
        }
    }

    fn pull_other_certs(&self) -> Result<Vec<Cert>> {
        let labels = &self.options.other_certs_to_pull;
        let bulk = match labels {
            Some(l) if l.is_empty() => return Ok(Vec::new()),
            Some(l) => self.options.bulk_fetch && l.len() > 1,
            None => true,
        };
        let mut out = Vec::new();
        if bulk {
            for obj in self.session.find_objects(&self.cert_query())? {
                let label = self.session.attribute_bytes(obj, AttributeType::Label)?;
                let label = String::from_utf8_lossy(&label);
                if labels
                    .as_ref()
                    .is_none_or(|l| l.iter().any(|x| *x == label))
                {
                    let der = self.session.attribute_bytes(obj, AttributeType::Value)?;
                    out.push(Cert::from_der(&der)?);
                }
            }
        } else if let Some(labels) = labels {
            for label in labels {
                out.push(self.pull_single_cert(Some(label), None)?);
            }
        }
        Ok(out)
    }
}

impl Pkcs11Signer {
    /// Create the signer and load the certificates and the key handle from
    /// the token (`PKCS11Signer(...)` followed by `_load_objects`).
    pub fn new(session: Arc<Pkcs11Session>, options: Pkcs11SignerOptions) -> Result<Self> {
        let selectors = ObjectSelectors::resolve(
            options.cert_label.clone(),
            options.cert_id.clone(),
            options.key_label.clone(),
            options.key_id.clone(),
        );
        let mut registry = Vec::new();
        for c in &options.ca_chain {
            push_unique(&mut registry, c.clone());
        }
        if let Some(c) = &options.signing_cert {
            push_unique(&mut registry, c.clone());
        }
        let loader = Loader {
            session: &session,
            options: &options,
            selectors: &selectors,
        };
        for c in loader.pull_other_certs()? {
            push_unique(&mut registry, c);
        }
        let signing_cert = match &options.signing_cert {
            Some(c) => c.clone(),
            None => loader.pull_single_cert(
                selectors.cert_label.as_deref(),
                selectors.cert_id.as_deref(),
            )?,
        };
        let key = loader.pull_signing_key_handle()?;
        Ok(Self {
            session,
            selectors,
            signing_cert,
            registry,
            key,
            options,
            signing_pin_callback: None,
        })
    }

    /// The resolved key and certificate selectors.
    pub fn selectors(&self) -> &ObjectSelectors {
        &self.selectors
    }

    /// Certificates known to the signer (`cert_registry`): `ca_chain`, the
    /// explicitly given signing certificate, and those read from the token.
    pub fn cert_registry(&self) -> &[Cert] {
        &self.registry
    }

    /// The session.
    pub fn session(&self) -> &Arc<Pkcs11Session> {
        &self.session
    }

    /// Supply a fresh context-specific signing PIN for each signature.
    ///
    /// The existing session, resolved key and static configuration are retained.
    /// The callback overrides the static PIN, is never cached and is not called
    /// by construction, Debug or mechanism selection. Errors propagate without
    /// falling back to a USER or static credential or starting a provider sign.
    /// Repeated calls replace only the callback. Callbacks run after mechanism
    /// preparation and before the session lock, so concurrent callers control
    /// callback blocking, logging and synchronization themselves.
    pub fn with_signing_pin_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn() -> Result<String> + Send + Sync + 'static,
    {
        self.signing_pin_callback = Some(SigningPinCallback(Arc::new(callback)));
        self
    }

    fn mechanism_for(&self, digest: DigestAlgorithm) -> Result<AlgorithmIdentifierOwned> {
        if let Some(m) = &self.options.signature_mechanism {
            return Ok(m.clone());
        }
        signature_mechanism_for_key(&self.signing_cert, digest, self.options.prefer_pss)
    }
}

/// The default signature mechanism for a certificate's key
/// (`Signer.get_signature_mechanism_for_digest`), including DSA.
pub fn signature_mechanism_for_key(
    cert: &Cert,
    digest: DigestAlgorithm,
    prefer_pss: bool,
) -> Result<AlgorithmIdentifierOwned> {
    if cert.public_key().algorithm.oid == oids::DSA {
        let oid = match digest {
            DigestAlgorithm::Sha1 => "1.2.840.10040.4.3",
            DigestAlgorithm::Sha224 => "2.16.840.1.101.3.4.3.1",
            DigestAlgorithm::Sha256 => "2.16.840.1.101.3.4.3.2",
            DigestAlgorithm::Sha384 => "2.16.840.1.101.3.4.3.3",
            DigestAlgorithm::Sha512 => "2.16.840.1.101.3.4.3.4",
            DigestAlgorithm::Sha3_224 => "2.16.840.1.101.3.4.3.5",
            DigestAlgorithm::Sha3_256 => "2.16.840.1.101.3.4.3.6",
            DigestAlgorithm::Sha3_384 => "2.16.840.1.101.3.4.3.7",
            DigestAlgorithm::Sha3_512 => "2.16.840.1.101.3.4.3.8",
            other => {
                return Err(HankoError::Signing(format!(
                    "No DSA signature algorithm identifier for {}",
                    other.name()
                )))
            }
        };
        return Ok(AlgorithmIdentifierOwned {
            oid: der::asn1::ObjectIdentifier::new(oid)
                .map_err(|e| HankoError::Malformed(e.to_string()))?,
            parameters: None,
        });
    }
    default_signature_mechanism(cert, digest, prefer_pss)
}

impl KeySigner for Pkcs11Signer {
    fn signing_cert(&self) -> &Cert {
        &self.signing_cert
    }

    fn cert_chain(&self) -> &[Cert] {
        &self.registry
    }

    fn signature_algorithm(&self, digest: DigestAlgorithm) -> Result<AlgorithmIdentifierOwned> {
        self.mechanism_for(digest)
    }

    fn sign_raw(&self, data: &[u8], digest: DigestAlgorithm) -> Result<Vec<u8>> {
        let mech = self.mechanism_for(digest)?;
        let spec = select_pkcs11_signing_params(
            &mech,
            digest,
            self.options.use_raw_mechanism,
            self.options.mechanism_override.clone(),
        )?;
        let tbs = match &spec.pre_sign_transform {
            Some(t) => t.apply(data)?,
            None => data.to_vec(),
        };
        let mut pss_store = None;
        let mechanism = spec.mechanism.to_cryptoki(&mut pss_store)?;
        let key = self.key;
        let pin = match &self.signing_pin_callback {
            Some(callback) => Some((callback.0)()?),
            None => self.options.signing_pin.clone(),
        };
        let sig = self.session.with(|s| {
            if let Some(pin) = pin {
                s.sign_init(&mechanism, key)?;
                s.login(UserType::ContextSpecific, Some(&AuthPin::new(pin.into())))?;
                s.sign_update(&tbs)?;
                Ok(s.sign_final()?)
            } else {
                Ok(s.sign(&mechanism, key, &tbs)?)
            }
        })?;
        match &spec.post_sign_transform {
            Some(t) => t.apply(&sig),
            None => Ok(sig),
        }
    }
}

// ---------------------------------------------------------------------------
// `PKCS11SigningContext`
// ---------------------------------------------------------------------------

/// The login PIN for a configuration (`PKCS11SigningContext._handle_pin`).
pub fn handle_pin(config: &Pkcs11Config, user_pin: Option<&str>) -> UserPin {
    match user_pin
        .map(str::to_owned)
        .or_else(|| config.user_pin.clone())
    {
        Some(p) => UserPin::Pin(p),
        None if config.prompt_pin == PinEntryMode::Defer => UserPin::ProtectedAuth,
        None => UserPin::None,
    }
}

/// Open a session and create a loaded signer from a configuration
/// (`PKCS11SigningContext.__enter__`).
pub fn open_signer(config: &Pkcs11Config, pin: Option<&str>) -> Result<Pkcs11Signer> {
    let user_pin = handle_pin(config, pin);
    let criteria = config.effective_token_criteria();
    let session = open_pkcs11_session(
        &config.module_path,
        config.slot_no,
        criteria.as_ref(),
        &user_pin,
    )
    .map_err(|ex| {
        signing_error(format!(
            "PKCS#11 error while opening session to {}: [{}] {}",
            config.module_path, ex.kind, ex.message
        ))
    })?;
    let signing_pin = match config.signing_pin_mode {
        SigningPinEntryMode::Reauthenticate => config.signing_pin.clone().or(match user_pin {
            UserPin::Pin(p) => Some(p),
            _ => None,
        }),
        _ => None,
    };
    Pkcs11Signer::new(
        Arc::new(session),
        Pkcs11SignerOptions {
            cert_label: config.cert_label.clone(),
            cert_id: config.cert_id.clone(),
            key_label: config.key_label.clone(),
            key_id: config.key_id.clone(),
            signing_cert: config.signing_certificate.clone(),
            ca_chain: config.other_certs.clone(),
            other_certs_to_pull: config.other_certs_to_pull.clone(),
            bulk_fetch: config.bulk_fetch,
            prefer_pss: config.prefer_pss,
            use_raw_mechanism: config.raw_mechanism,
            signature_mechanism: config.signature_mechanism.clone(),
            mechanism_override: None,
            signing_pin,
            only_resident_certs: config.only_resident_certs,
        },
    )
}

/// Open a PKCS#11 signer; returns a [`sigis_pki_core::sign::KeySigner`].
///
/// `pin` overrides `config.user_pin`.
pub fn open(config: &Pkcs11Config, pin: Option<&str>) -> Result<Arc<dyn KeySigner>> {
    Ok(Arc::new(open_signer(config, pin)?))
}
