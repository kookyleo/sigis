// Derived from pyHanko `pdf_utils/crypt/api.py` and `filter_mixins.py`
// (MIT, see LICENSE-pyHanko).

//! Security handler model (`SecurityHandler`, `CryptFilter`,
//! `CryptFilterConfiguration`, `AuthResult`, ...).
//!
//! pyHanko's class hierarchy (security handler subclasses, crypt filter
//! mixins) is flattened: a [`CryptFilter`] is a value with a cipher, a key
//! length and, for public-key filters, its recipient data; a
//! [`SecurityHandler`] is a cheaply clonable, shared handle (readers and
//! incremental writers share one, like pyHanko's `security_handler`
//! attribute) whose state is either a standard or a public-key handler.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use lopdf::{Dictionary, Object, ObjectId};

use super::cred_ser::SerialisableCredential;
use super::permissions::{PdfPermissions, StandardPermissions};
use super::pubkey::{PubKeyAdbeSubFilter, PubKeyCfData};
use super::standard::{StandardSecuritySettingsRevision, StandardState};
use super::util;
use crate::error::{PdfError, PdfResult};
use crate::extensions::{DevExtensionMultivalued, DeveloperExtension};
use crate::generic::name_str;

/// Status after an authentication attempt (`AuthStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthStatus {
    /// Authentication failed.
    Failed = 0,
    /// User access.
    User = 1,
    /// Owner access.
    Owner = 2,
}

/// Status of PDF MAC validation (`PdfMacStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PdfMacStatus {
    /// No MAC was validated.
    NotApplicable,
    /// The MAC is valid.
    Successful,
    /// MAC validation failed.
    Failed,
}

/// Result of an authentication attempt (`AuthResult`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthResult {
    /// Authentication status.
    pub status: AuthStatus,
    /// Permission flags granted, if known.
    pub permission_flags: Option<PdfPermissions>,
    /// PDF MAC validation status.
    pub mac_status: PdfMacStatus,
    /// Reason for a MAC validation failure.
    pub mac_failure_reason: Option<String>,
}

impl AuthResult {
    /// A result without MAC information.
    pub fn new(status: AuthStatus, permission_flags: Option<PdfPermissions>) -> Self {
        Self {
            status,
            permission_flags,
            mac_status: PdfMacStatus::NotApplicable,
            mac_failure_reason: None,
        }
    }
}

/// Security handler version, the `/V` entry (`SecurityHandlerVersion`).
///
/// Ordered like pyHanko's `VersionEnum`: [`Self::Other`] stands for "any
/// future version" and compares greater than all others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityHandlerVersion {
    /// `/V 1`.
    Rc4_40,
    /// `/V 2`.
    Rc4LongerKeys,
    /// `/V 4`.
    Rc4OrAes128,
    /// `/V 5`.
    Aes256,
    /// `/V 6` (ISO 32003).
    AesGcm,
    /// Any other value.
    Other,
}

impl SecurityHandlerVersion {
    /// The numeric value, `None` for [`Self::Other`].
    pub fn value(self) -> Option<i64> {
        match self {
            Self::Rc4_40 => Some(1),
            Self::Rc4LongerKeys => Some(2),
            Self::Rc4OrAes128 => Some(4),
            Self::Aes256 => Some(5),
            Self::AesGcm => Some(6),
            Self::Other => None,
        }
    }

    /// `from_number`.
    pub fn from_number(value: Option<i64>) -> Self {
        match value {
            Some(1) => Self::Rc4_40,
            Some(2) => Self::Rc4LongerKeys,
            Some(4) => Self::Rc4OrAes128,
            Some(5) => Self::Aes256,
            Some(6) => Self::AesGcm,
            _ => Self::Other,
        }
    }

    /// `as_pdf_object`.
    pub fn as_pdf_object(self) -> Object {
        self.value().map_or(Object::Null, Object::Integer)
    }

    /// `check_key_length`.
    pub fn check_key_length(self, key_length: usize) -> PdfResult<usize> {
        match self {
            Self::Rc4_40 => Ok(5),
            Self::Aes256 => Ok(32),
            _ if !(5..=16).contains(&key_length) && self <= Self::Rc4OrAes128 => Err(
                PdfError::Generic("Key length must be between 5 and 16".into()),
            ),
            _ => Ok(key_length),
        }
    }
}

/// Name of the identity crypt filter (without slash).
pub const IDENTITY: &[u8] = b"Identity";

/// The cipher behind a crypt filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherKind {
    /// No encryption (`IdentityCryptFilter`).
    Identity,
    /// RC4 (`RC4CryptFilterMixin`).
    Rc4,
    /// AES-CBC with PKCS#7 padding (`AESCryptFilterMixin`).
    AesCbc,
    /// AES-256-GCM (`AESGCMCryptFilterMixin`, ISO 32003).
    AesGcm,
}

/// `ISO32003` developer extension (AES-GCM crypt filters).
pub fn iso32003_extension() -> DeveloperExtension {
    let mut e = DeveloperExtension::new("ISO_", "2.0", 32003);
    e.extension_revision = Some(":2023".into());
    e.url = Some("https://www.iso.org/standard/45876.html".into());
    e.compare_by_level = false;
    e.multivalued = DevExtensionMultivalued::Always;
    e
}

/// A crypt filter (`CryptFilter` and its subclasses).
#[derive(Clone, Debug)]
pub struct CryptFilter {
    pub(crate) method: Vec<u8>,
    pub(crate) cipher: CipherKind,
    pub(crate) keylen: usize,
    pub(crate) embedded_only: bool,
    pub(crate) pubkey: Option<PubKeyCfData>,
    pub(crate) shared_key: Option<Vec<u8>>,
    pub(crate) gcm_counter: u64,
}

impl CryptFilter {
    fn with(cipher: CipherKind, method: &[u8], keylen: usize) -> Self {
        Self {
            method: method.to_vec(),
            cipher,
            keylen,
            embedded_only: false,
            pubkey: None,
            shared_key: None,
            gcm_counter: 0,
        }
    }

    /// The identity filter (`IdentityCryptFilter`).
    pub fn identity() -> Self {
        Self::with(CipherKind::Identity, b"None", 0)
    }

    /// RC4 filter for the standard handler (`StandardRC4CryptFilter`).
    pub fn standard_rc4(keylen: usize) -> Self {
        Self::with(CipherKind::Rc4, b"V2", keylen)
    }

    /// AES filter for the standard handler (`StandardAESCryptFilter`);
    /// `keylen` must be 16 or 32.
    pub fn standard_aes(keylen: usize) -> PdfResult<Self> {
        Ok(Self::with(CipherKind::AesCbc, aes_method(keylen)?, keylen))
    }

    /// AES-GCM filter for the standard handler (`StandardAESGCMCryptFilter`).
    pub fn standard_aes_gcm() -> Self {
        Self::with(CipherKind::AesGcm, b"AESV4", 32)
    }

    pub(crate) fn pubkey_with(
        cipher: CipherKind,
        keylen: usize,
        data: PubKeyCfData,
    ) -> PdfResult<Self> {
        let mut cf = match cipher {
            CipherKind::Rc4 => Self::with(cipher, b"V2", keylen),
            CipherKind::AesCbc => Self::with(cipher, aes_method(keylen)?, keylen),
            CipherKind::AesGcm => Self::with(cipher, b"AESV4", 32),
            CipherKind::Identity => Self::identity(),
        };
        cf.pubkey = Some(data);
        Ok(cf)
    }

    /// Replace the `/CFM` name (custom crypt filter types registered with
    /// [`CryptFilterRegistry::register`]).
    pub fn with_method(mut self, method: &str) -> Self {
        self.method = method.trim_start_matches('/').as_bytes().to_vec();
        self
    }

    /// The `/CFM` name, without slash (`method`).
    pub fn method(&self) -> &[u8] {
        &self.method
    }

    /// The cipher.
    pub fn cipher(&self) -> CipherKind {
        self.cipher
    }

    /// Key length in bytes (`keylen`).
    pub fn keylen(&self) -> usize {
        self.keylen
    }

    /// `true` for public-key crypt filters.
    pub fn is_pubkey(&self) -> bool {
        self.pubkey.is_some()
    }

    /// `true` for the identity filter.
    pub fn is_identity(&self) -> bool {
        self.cipher == CipherKind::Identity
    }

    /// Recipient CMS objects (DER) of a public-key filter.
    pub fn recipients(&self) -> Option<&[Vec<u8>]> {
        self.pubkey.as_ref().and_then(|p| p.recipients.as_deref())
    }

    /// The cached shared key, if derived.
    pub fn cached_shared_key(&self) -> Option<&[u8]> {
        self.shared_key.as_deref()
    }

    /// Mark as used for embedded files only (`set_embedded_only`).
    pub fn set_embedded_only(&mut self) {
        self.embedded_only = true;
    }

    /// Developer extensions this filter needs (`get_extensions`).
    pub fn get_extensions(&self) -> Vec<DeveloperExtension> {
        if self.cipher == CipherKind::AesGcm {
            vec![iso32003_extension()]
        } else {
            Vec::new()
        }
    }

    /// Encrypt with an explicit local key (`encrypt`).
    pub fn encrypt(&mut self, key: &[u8], plaintext: &[u8]) -> PdfResult<Vec<u8>> {
        match self.cipher {
            CipherKind::Identity => Ok(plaintext.to_vec()),
            CipherKind::Rc4 => Ok(util::rc4_encrypt(key, plaintext)),
            CipherKind::AesCbc => {
                let (iv, ct) = util::aes_cbc_encrypt(key, plaintext, None, true)?;
                Ok([iv, ct].concat())
            }
            CipherKind::AesGcm => {
                // 4 random bytes and an 8-byte counter, as in pyHanko
                self.gcm_counter = self.gcm_counter.wrapping_add(1);
                let mut nonce = util::random_bytes(4)?;
                nonce.extend_from_slice(&self.gcm_counter.to_be_bytes());
                let ct = util::aes_gcm_encrypt(key, &nonce, plaintext)?;
                Ok([nonce, ct].concat())
            }
        }
    }

    /// Decrypt with an explicit local key (`decrypt`).
    pub fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> PdfResult<Vec<u8>> {
        match self.cipher {
            CipherKind::Identity => Ok(ciphertext.to_vec()),
            CipherKind::Rc4 => Ok(util::rc4_encrypt(key, ciphertext)),
            CipherKind::AesCbc => {
                let (iv, data) = ciphertext.split_at(ciphertext.len().min(16));
                util::aes_cbc_decrypt(key, data, iv, true)
            }
            CipherKind::AesGcm => {
                let (nonce, data) = ciphertext.split_at(ciphertext.len().min(12));
                util::aes_gcm_decrypt(key, nonce, data)
            }
        }
    }

    /// Crypt filter dictionary (`as_pdf_object`).
    pub fn as_pdf_object(&self) -> PdfResult<Dictionary> {
        if self.cipher == CipherKind::Identity {
            return Err(PdfError::Generic(
                "Identity filter cannot be serialised".into(),
            ));
        }
        let mut d = Dictionary::new();
        d.set(
            "AuthEvent",
            Object::Name(if self.embedded_only {
                b"EFOpen".to_vec()
            } else {
                b"DocOpen".to_vec()
            }),
        );
        d.set("CFM", Object::Name(self.method.clone()));
        match &self.pubkey {
            None => {
                // in bytes, as ISO 32000-2:2020 mandates
                d.set("Length", Object::Integer(self.keylen as i64));
            }
            Some(p) => {
                d.set("Length", Object::Integer(self.keylen as i64 * 8));
                let recipients = p.recipients.as_ref().ok_or_else(|| {
                    PdfError::Value("Public-key crypt filter has no recipients".into())
                })?;
                if p.acts_as_default {
                    d.set(
                        "Recipients",
                        Object::Array(
                            recipients
                                .iter()
                                .map(|r| crate::generic::byte_string(r.clone()))
                                .collect(),
                        ),
                    );
                } else {
                    let first = recipients
                        .first()
                        .ok_or_else(|| PdfError::Value("list index out of range".into()))?;
                    d.set("Recipients", crate::generic::byte_string(first.clone()));
                }
                d.set("EncryptMetadata", Object::Boolean(p.encrypt_metadata));
            }
        }
        Ok(d)
    }
}

fn aes_method(keylen: usize) -> PdfResult<&'static [u8]> {
    match keylen {
        16 => Ok(b"AESV2"),
        32 => Ok(b"AESV3"),
        _ => Err(PdfError::NotImplemented(
            "Only AES-128 and AES-256 are supported".into(),
        )),
    }
}

/// Crypt filters of a security handler with the default filter names
/// (`CryptFilterConfiguration`). Names are stored without slash.
#[derive(Clone, Debug)]
pub struct CryptFilterConfiguration {
    pub(crate) filters: Vec<(Vec<u8>, CryptFilter)>,
    pub(crate) stmf: Vec<u8>,
    pub(crate) strf: Vec<u8>,
    pub(crate) eff: Option<Vec<u8>>,
}

fn strip(n: &str) -> Vec<u8> {
    n.trim_start_matches('/').as_bytes().to_vec()
}

impl CryptFilterConfiguration {
    /// A configuration; the default filters must be `Identity` or one of
    /// `filters` (pyHanko raises `KeyError` otherwise).
    pub fn new(
        filters: Vec<(&str, CryptFilter)>,
        default_stream_filter: &str,
        default_string_filter: &str,
        default_file_filter: Option<&str>,
    ) -> PdfResult<Self> {
        Self::from_names(
            filters.into_iter().map(|(n, f)| (strip(n), f)).collect(),
            strip(default_stream_filter),
            strip(default_string_filter),
            default_file_filter.map(strip),
        )
    }

    /// A configuration where streams and strings are not encrypted by
    /// default (`CryptFilterConfiguration(crypt_filters=...)`).
    pub fn with_filters(filters: Vec<(&str, CryptFilter)>) -> PdfResult<Self> {
        Self::new(filters, "Identity", "Identity", None)
    }

    pub(crate) fn from_names(
        filters: Vec<(Vec<u8>, CryptFilter)>,
        stmf: Vec<u8>,
        strf: Vec<u8>,
        eff: Option<Vec<u8>>,
    ) -> PdfResult<Self> {
        let cfc = Self {
            filters,
            stmf,
            strf,
            eff,
        };
        for n in [&cfc.stmf, &cfc.strf, cfc.file_filter_name()] {
            if !cfc.contains(n) {
                return Err(PdfError::Read(format!(
                    "Crypt filter /{} is not defined",
                    name_str(n)
                )));
            }
        }
        Ok(cfc)
    }

    /// `name in config`.
    pub fn contains(&self, name: &[u8]) -> bool {
        name == IDENTITY || self.filters.iter().any(|(n, _)| n == name)
    }

    pub(crate) fn index_of(&self, name: &[u8]) -> Option<usize> {
        self.filters.iter().position(|(n, _)| n == name)
    }

    /// `config[name]` (a copy); `Identity` is always available.
    pub fn get(&self, name: &str) -> Option<CryptFilter> {
        let n = strip(name);
        self.get_raw(&n)
    }

    pub(crate) fn get_raw(&self, name: &[u8]) -> Option<CryptFilter> {
        if name == IDENTITY {
            return Some(CryptFilter::identity());
        }
        self.index_of(name).map(|i| self.filters[i].1.clone())
    }

    /// The configured filters (`filters`), excluding the implicit identity.
    pub fn filters(&self) -> impl Iterator<Item = (&[u8], &CryptFilter)> {
        self.filters.iter().map(|(n, f)| (n.as_slice(), f))
    }

    /// Number of configured filters.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// `true` if no filters are configured.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Insert (or replace) a filter.
    pub fn insert(&mut self, name: &str, cf: CryptFilter) {
        let n = strip(name);
        match self.index_of(&n) {
            Some(i) => self.filters[i].1 = cf,
            None => self.filters.push((n, cf)),
        }
    }

    /// Default stream filter name (`stream_filter_name`).
    pub fn stream_filter_name(&self) -> &[u8] {
        &self.stmf
    }

    /// Default string filter name (`string_filter_name`).
    pub fn string_filter_name(&self) -> &[u8] {
        &self.strf
    }

    /// Declared embedded file filter name (`embedded_file_filter_name`).
    pub fn embedded_file_filter_name(&self) -> Option<&[u8]> {
        self.eff.as_deref()
    }

    /// Effective embedded file filter name (`/EFF`, else `/StmF`).
    pub fn file_filter_name(&self) -> &Vec<u8> {
        self.eff.as_ref().unwrap_or(&self.stmf)
    }

    /// Distinct names of the default filters (`standard_filters`).
    pub fn standard_filter_names(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        for n in [&self.stmf, &self.strf, self.file_filter_name()] {
            if !out.contains(n) {
                out.push(n.clone());
            }
        }
        out
    }

    /// Serialise (`as_pdf_object`): `/StmF`, `/StrF`, `/EFF` and `/CF`.
    pub fn as_pdf_object(&self) -> PdfResult<Dictionary> {
        let mut d = Dictionary::new();
        d.set("StmF", Object::Name(self.stmf.clone()));
        d.set("StrF", Object::Name(self.strf.clone()));
        if let Some(e) = &self.eff {
            d.set("EFF", Object::Name(e.clone()));
        }
        let mut cf = Dictionary::new();
        for (n, f) in &self.filters {
            if n.as_slice() != IDENTITY {
                cf.set(n.clone(), Object::Dictionary(f.as_pdf_object()?));
            }
        }
        d.set("CF", Object::Dictionary(cf));
        Ok(d)
    }
}

/// Builds a crypt filter from its dictionary and whether it is a default
/// filter (`/StmF` or `/StrF`) (`CryptFilterBuilder`).
pub type CryptFilterBuilder =
    Arc<dyn Fn(&Dictionary, bool) -> PdfResult<CryptFilter> + Send + Sync>;

/// Crypt filter methods known to a security handler type
/// (`_known_crypt_filters`).
#[derive(Clone, Default)]
pub struct CryptFilterRegistry {
    builders: BTreeMap<Vec<u8>, CryptFilterBuilder>,
}

impl std::fmt::Debug for CryptFilterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.builders.keys().map(|k| name_str(k)))
            .finish()
    }
}

impl CryptFilterRegistry {
    /// Register a builder for a `/CFM` method (`register_crypt_filter`).
    pub fn register(&mut self, method: &str, builder: CryptFilterBuilder) {
        self.builders.insert(strip(method), builder);
    }

    /// Remove a method.
    pub fn unregister(&mut self, method: &str) {
        self.builders.remove(&strip(method));
    }

    /// `method in registry`.
    pub fn contains(&self, method: &str) -> bool {
        self.builders.contains_key(&strip(method))
    }
}

/// Interpret a crypt filter dictionary (`build_crypt_filter`): `None` if
/// `/CFM` is absent or `/None`.
pub fn build_crypt_filter(
    reg: &CryptFilterRegistry,
    cfdict: &Dictionary,
    acts_as_default: bool,
) -> PdfResult<Option<CryptFilter>> {
    let Ok(cfm) = cfdict.get(b"CFM") else {
        return Ok(None);
    };
    let name = match cfm {
        Object::Name(n) => n.clone(),
        other => {
            return Err(PdfError::NotImplemented(format!(
                "No such crypt filter method: {}",
                crate::generic::type_name(other)
            )))
        }
    };
    if name == b"None" {
        return Ok(None);
    }
    match reg.builders.get(&name) {
        Some(b) => b(cfdict, acts_as_default).map(Some),
        None => Err(PdfError::NotImplemented(format!(
            "No such crypt filter method: /{}",
            name_str(&name)
        ))),
    }
}

/// The kinds of security handler implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HandlerType {
    /// Password-based (`StandardSecurityHandler`).
    Standard,
    /// Public-key (`PubKeySecurityHandler`).
    PubKey,
}

/// Registered security handlers (`SecurityHandler.register`), each with its
/// crypt filter registry.
#[derive(Clone, Debug)]
pub struct SecurityHandlerRegistry {
    handlers: Vec<(Vec<u8>, HandlerType, CryptFilterRegistry)>,
}

impl Default for SecurityHandlerRegistry {
    fn default() -> Self {
        Self {
            handlers: vec![
                (
                    b"Standard".to_vec(),
                    HandlerType::Standard,
                    super::standard::default_crypt_filters(),
                ),
                (
                    b"Adobe.PubSec".to_vec(),
                    HandlerType::PubKey,
                    super::pubkey::default_crypt_filters(),
                ),
            ],
        }
    }
}

impl SecurityHandlerRegistry {
    /// Register (or replace) a handler under `name` (`register`).
    pub fn register(&mut self, name: &str, ty: HandlerType, filters: CryptFilterRegistry) {
        let n = strip(name);
        self.handlers.retain(|(h, _, _)| *h != n);
        self.handlers.push((n, ty, filters));
    }

    /// The crypt filter registry of the handler registered under `name`.
    pub fn crypt_filters_mut(&mut self, name: &str) -> Option<&mut CryptFilterRegistry> {
        let n = strip(name);
        self.handlers
            .iter_mut()
            .find(|(h, _, _)| *h == n)
            .map(|(_, _, r)| r)
    }

    fn lookup(&self, encrypt_dict: &Dictionary) -> PdfResult<(HandlerType, &CryptFilterRegistry)> {
        let handler_name = match encrypt_dict.get(b"Filter") {
            Ok(o) => o.clone(),
            Err(_) => Object::Name(b"Standard".to_vec()),
        };
        if let Object::Name(n) = &handler_name {
            if let Some((_, ty, reg)) = self.handlers.iter().find(|(h, _, _)| h == n) {
                return Ok((*ty, reg));
            }
        }
        let shown = match &handler_name {
            Object::Name(n) => format!("/{}", name_str(n)),
            other => format!("{other:?}"),
        };
        let Ok(subfilter) = encrypt_dict.get(b"SubFilter") else {
            return Err(PdfError::Read(format!(
                "There is no security handler named {shown}, and the encryption dictionary does not contain a generic /SubFilter entry."
            )));
        };
        if let Object::Name(sf) = subfilter {
            if PubKeyAdbeSubFilter::from_name(sf).is_some() {
                if let Some((_, ty, reg)) = self
                    .handlers
                    .iter()
                    .find(|(_, t, _)| *t == HandlerType::PubKey)
                {
                    return Ok((*ty, reg));
                }
            }
        }
        let sf_shown = match subfilter {
            Object::Name(n) => format!("/{}", name_str(n)),
            other => format!("{other:?}"),
        };
        Err(PdfError::Read(format!(
            "There is no security handler named {shown}, and none of the available handlers support the declared /SubFilter {sf_shown}."
        )))
    }
}

/// Data specific to the handler type.
#[derive(Debug)]
pub(crate) enum HandlerKind {
    Standard(StandardState),
    PubKey { subfilter: PubKeyAdbeSubFilter },
}

/// Mutable state of a security handler.
#[derive(Debug)]
pub(crate) struct HandlerState {
    pub(crate) version: SecurityHandlerVersion,
    pub(crate) keylen: usize,
    pub(crate) cfc: CryptFilterConfiguration,
    pub(crate) encrypt_metadata: bool,
    pub(crate) compat_entries: bool,
    pub(crate) credential: Option<SerialisableCredential>,
    pub(crate) kdf_salt: Option<Vec<u8>>,
    pub(crate) kind: HandlerKind,
    pub(crate) mac_handler: Option<Arc<dyn super::pdfmac::PdfMacTokenHandlerFactory>>,
}

impl HandlerState {
    /// `SecurityHandler.__init__`: binds the filters (resetting their keys)
    /// and checks the key length.
    pub(crate) fn new(
        version: SecurityHandlerVersion,
        legacy_keylen: usize,
        mut cfc: CryptFilterConfiguration,
        encrypt_metadata: bool,
        compat_entries: bool,
        kdf_salt: Option<Vec<u8>>,
        kind: HandlerKind,
    ) -> PdfResult<Self> {
        for (_, cf) in cfc.filters.iter_mut() {
            cf.shared_key = None;
            if let Some(p) = cf.pubkey.as_mut() {
                p.recp_key_seed = None;
            }
        }
        let keylen = version.check_key_length(legacy_keylen)?;
        Ok(Self {
            version,
            keylen,
            cfc,
            encrypt_metadata,
            compat_entries,
            credential: None,
            kdf_salt,
            kind,
            mac_handler: None,
        })
    }

    fn auth_failed_for(&self, cf: &CryptFilter) -> bool {
        match (&cf.pubkey, &self.kind) {
            (Some(p), _) => p.auth_failed,
            (None, HandlerKind::Standard(s)) => s.auth_failed,
            (None, HandlerKind::PubKey { .. }) => false,
        }
    }

    /// `CryptFilter.shared_key` for the filter named `name`.
    pub(crate) fn cf_shared_key(&mut self, name: &[u8]) -> PdfResult<Vec<u8>> {
        if name == IDENTITY && self.cfc.index_of(name).is_none() {
            return Ok(Vec::new());
        }
        let i = self.cfc.index_of(name).ok_or_else(|| {
            PdfError::Generic(format!("The crypt filter /{} is not known", name_str(name)))
        })?;
        if self.cfc.filters[i].1.cipher == CipherKind::Identity {
            return Ok(Vec::new());
        }
        if let Some(k) = &self.cfc.filters[i].1.shared_key {
            return Ok(k.clone());
        }
        if self.auth_failed_for(&self.cfc.filters[i].1) {
            return Err(PdfError::KeyNotAvailable("Authentication failed".into()));
        }
        let key = if self.cfc.filters[i].1.pubkey.is_some() {
            super::pubkey::derive_pubkey_shared_key(self.version, &self.cfc.filters[i].1)?
        } else {
            self.standard_file_key()?
        };
        self.cfc.filters[i].1.shared_key = Some(key.clone());
        Ok(key)
    }

    /// `StandardSecurityHandler.get_file_encryption_key`.
    pub(crate) fn standard_file_key(&self) -> PdfResult<Vec<u8>> {
        match &self.kind {
            HandlerKind::Standard(s) => s.shared_key.clone().ok_or_else(|| {
                PdfError::KeyNotAvailable(if s.auth_failed {
                    "Authentication failed.".into()
                } else {
                    "No key available to decrypt, please authenticate first.".into()
                })
            }),
            HandlerKind::PubKey { .. } => {
                Err(PdfError::Generic("Not a standard security handler".into()))
            }
        }
    }

    /// `get_file_encryption_key`.
    pub(crate) fn file_encryption_key(&mut self) -> PdfResult<Vec<u8>> {
        match &self.kind {
            HandlerKind::Standard(_) => self.standard_file_key(),
            HandlerKind::PubKey { .. } => {
                let stmf = self.cfc.stmf.clone();
                self.cf_shared_key(&stmf)
            }
        }
    }

    /// `derive_object_key` of the filter named `name`.
    pub(crate) fn object_key(
        &mut self,
        name: &[u8],
        id: ObjectId,
    ) -> PdfResult<(CryptFilter, Vec<u8>)> {
        let cf = self.cfc.get_raw(name).ok_or_else(|| {
            PdfError::Generic(format!("The crypt filter /{} is not known", name_str(name)))
        })?;
        let key = match cf.cipher {
            CipherKind::Identity => Vec::new(),
            CipherKind::Rc4 => {
                let shared = self.cf_shared_key(name)?;
                super::legacy::legacy_derive_object_key(&shared, id.0, id.1, false)
            }
            CipherKind::AesCbc => {
                let shared = self.cf_shared_key(name)?;
                if self.version >= SecurityHandlerVersion::Aes256 {
                    shared
                } else {
                    super::legacy::legacy_derive_object_key(&shared, id.0, id.1, true)
                }
            }
            CipherKind::AesGcm => self.cf_shared_key(name)?,
        };
        Ok((cf, key))
    }

    /// Encrypt with the filter named `name` under `key` (keeps the GCM
    /// nonce counter of the stored filter).
    pub(crate) fn encrypt_with(
        &mut self,
        name: &[u8],
        key: &[u8],
        data: &[u8],
    ) -> PdfResult<Vec<u8>> {
        match self.cfc.index_of(name) {
            Some(i) => self.cfc.filters[i].1.encrypt(key, data),
            None => CryptFilter::identity().encrypt(key, data),
        }
    }

    pub(crate) fn pdf_mac_enabled(&self) -> bool {
        match &self.kind {
            HandlerKind::Standard(s) => self.kdf_salt.is_some() || s.mac_required,
            HandlerKind::PubKey { .. } => self.kdf_salt.is_some(),
        }
    }
}

/// A PDF security handler (`SecurityHandler`): a shared handle, cheap to
/// clone; clones see the same authentication state.
#[derive(Clone)]
pub struct SecurityHandler {
    pub(crate) inner: Arc<Mutex<HandlerState>>,
}

impl std::fmt::Debug for SecurityHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.lock();
        f.debug_struct("SecurityHandler")
            .field("type", &self.handler_type_of(&s))
            .field("version", &s.version)
            .finish_non_exhaustive()
    }
}

impl SecurityHandler {
    pub(crate) fn from_state(state: HandlerState) -> Self {
        Self {
            inner: Arc::new(Mutex::new(state)),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, HandlerState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn handler_type_of(&self, s: &HandlerState) -> HandlerType {
        match s.kind {
            HandlerKind::Standard(_) => HandlerType::Standard,
            HandlerKind::PubKey { .. } => HandlerType::PubKey,
        }
    }

    /// `true` if both handles refer to the same handler.
    pub fn same_handler(&self, other: &SecurityHandler) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Instantiate a handler from an encryption dictionary, with the default
    /// registry (`SecurityHandler.build`).
    pub fn build(encrypt_dict: &Dictionary) -> PdfResult<Self> {
        Self::build_with(encrypt_dict, &SecurityHandlerRegistry::default())
    }

    /// [`Self::build`] with an explicit registry.
    pub fn build_with(
        encrypt_dict: &Dictionary,
        registry: &SecurityHandlerRegistry,
    ) -> PdfResult<Self> {
        let (ty, reg) = registry.lookup(encrypt_dict)?;
        match ty {
            HandlerType::Standard => Self::instantiate_standard(encrypt_dict, reg),
            HandlerType::PubKey => Self::instantiate_pubkey(encrypt_dict, reg),
        }
    }

    /// Handler type.
    pub fn handler_type(&self) -> HandlerType {
        let s = self.lock();
        self.handler_type_of(&s)
    }

    /// Handler name, the `/Filter` value without slash (`get_name`).
    pub fn name(&self) -> &'static str {
        match self.handler_type() {
            HandlerType::Standard => "Standard",
            HandlerType::PubKey => "Adobe.PubSec",
        }
    }

    /// `/V` (`version`).
    pub fn version(&self) -> SecurityHandlerVersion {
        self.lock().version
    }

    /// Key length in bytes (`keylen`).
    pub fn keylen(&self) -> usize {
        self.lock().keylen
    }

    /// `encrypt_metadata`.
    pub fn encrypt_metadata(&self) -> bool {
        self.lock().encrypt_metadata
    }

    /// A copy of the crypt filter configuration (`crypt_filter_config`).
    pub fn crypt_filter_config(&self) -> CryptFilterConfiguration {
        self.lock().cfc.clone()
    }

    /// Add or replace a crypt filter in the configuration.
    pub fn insert_crypt_filter(&self, name: &str, cf: CryptFilter) {
        self.lock().cfc.insert(name, cf);
    }

    /// The default string filter (`get_string_filter`), as a copy.
    pub fn get_string_filter(&self) -> CryptFilter {
        let s = self.lock();
        s.cfc
            .get_raw(&s.cfc.strf)
            .unwrap_or_else(CryptFilter::identity)
    }

    /// The default stream filter, or the filter named `name`
    /// (`get_stream_filter`), as a copy.
    pub fn get_stream_filter(&self, name: Option<&str>) -> PdfResult<CryptFilter> {
        let s = self.lock();
        let n = name.map_or_else(|| s.cfc.stmf.clone(), strip);
        s.cfc
            .get_raw(&n)
            .ok_or_else(|| PdfError::Value(format!("KeyError: /{}", name_str(&n))))
    }

    /// The embedded file filter (`get_embedded_file_filter`), as a copy.
    pub fn get_embedded_file_filter(&self) -> CryptFilter {
        let s = self.lock();
        s.cfc
            .get_raw(s.cfc.file_filter_name())
            .unwrap_or_else(CryptFilter::identity)
    }

    /// `True` if `get_string_filter()._auth_failed`.
    pub fn string_filter_auth_failed(&self) -> bool {
        let s = self.lock();
        match s.cfc.get_raw(&s.cfc.strf) {
            Some(cf) if !cf.is_identity() => s.auth_failed_for(&cf),
            _ => false,
        }
    }

    /// The shared key of the filter named `name` (`cf.shared_key`), deriving
    /// it if necessary.
    pub fn crypt_filter_shared_key(&self, name: &str) -> PdfResult<Vec<u8>> {
        self.lock().cf_shared_key(&strip(name))
    }

    /// Global file encryption key (`get_file_encryption_key`).
    pub fn get_file_encryption_key(&self) -> PdfResult<Vec<u8>> {
        self.lock().file_encryption_key()
    }

    /// `is_authenticated`.
    pub fn is_authenticated(&self) -> bool {
        match self.get_file_encryption_key() {
            Ok(_) => true,
            Err(PdfError::KeyNotAvailable(_)) => false,
            // other errors (e.g. no seed for public-key handlers) propagate
            // in pyHanko; treat them as "not authenticated" here
            Err(_) => false,
        }
    }

    /// KDF salt for PDF MAC (`get_kdf_salt`).
    pub fn get_kdf_salt(&self) -> PdfResult<Vec<u8>> {
        self.lock()
            .kdf_salt
            .clone()
            .ok_or_else(|| PdfError::Read("No KDF salt available".into()))
    }

    /// `pdf_mac_enabled`.
    pub fn pdf_mac_enabled(&self) -> bool {
        self.lock().pdf_mac_enabled()
    }

    /// The serialisable credential of the last successful authentication
    /// (`extract_credential`).
    pub fn extract_credential(&self) -> Option<SerialisableCredential> {
        self.lock().credential.clone()
    }

    /// Minimal PDF version for this handler (`get_min_pdf_version`).
    pub fn get_min_pdf_version(&self) -> Option<(u32, u32)> {
        let v = self.version();
        if v >= SecurityHandlerVersion::Aes256 {
            Some((2, 0))
        } else if v >= SecurityHandlerVersion::Rc4OrAes128 {
            Some((1, 5))
        } else if v >= SecurityHandlerVersion::Rc4LongerKeys {
            Some((1, 4))
        } else {
            None
        }
    }

    /// Developer extensions to register on output (`get_extensions`).
    pub fn get_extensions(&self) -> Vec<DeveloperExtension> {
        let s = self.lock();
        let mut out = Vec::new();
        if s.pdf_mac_enabled() {
            out.push(super::pdfmac::iso32004_extension());
        }
        for (_, cf) in s.cfc.filters() {
            out.extend(cf.get_extensions());
        }
        out
    }

    /// Serialise to an encryption dictionary (`as_pdf_object`).
    pub fn as_pdf_object(&self) -> PdfResult<Dictionary> {
        let s = self.lock();
        match &s.kind {
            HandlerKind::Standard(st) => super::standard::standard_as_pdf_object(&s, st),
            HandlerKind::PubKey { subfilter } => {
                super::pubkey::pubkey_as_pdf_object(&s, *subfilter)
            }
        }
    }

    /// Install a custom PDF MAC token handler factory (pyHanko's
    /// `writer._mac_handler_cls`), used when writing MACs.
    pub fn set_mac_token_handler(
        &self,
        f: Option<Arc<dyn super::pdfmac::PdfMacTokenHandlerFactory>>,
    ) {
        self.lock().mac_handler = f;
    }

    /// The installed MAC factory, preserving its shared handle identity.
    /// This exposes factory configuration, not a document key or MAC verdict.
    pub fn mac_token_handler(&self) -> Option<Arc<dyn super::pdfmac::PdfMacTokenHandlerFactory>> {
        self.lock().mac_handler.clone()
    }

    /// Permission flags declared by the handler (standard handlers only).
    pub fn standard_permissions(&self) -> Option<StandardPermissions> {
        match &self.lock().kind {
            HandlerKind::Standard(s) => Some(s.perms),
            HandlerKind::PubKey { .. } => None,
        }
    }

    /// Revision `/R` (standard handlers only).
    pub fn revision(&self) -> Option<StandardSecuritySettingsRevision> {
        match &self.lock().kind {
            HandlerKind::Standard(s) => Some(s.revision),
            HandlerKind::PubKey { .. } => None,
        }
    }

    /// `/SubFilter` (public-key handlers only).
    pub fn subfilter(&self) -> Option<PubKeyAdbeSubFilter> {
        match &self.lock().kind {
            HandlerKind::Standard(_) => None,
            HandlerKind::PubKey { subfilter } => Some(*subfilter),
        }
    }

    /// `true` if authentication previously failed (standard handlers,
    /// `_auth_failed`).
    pub fn auth_failed(&self) -> bool {
        match &self.lock().kind {
            HandlerKind::Standard(s) => s.auth_failed,
            HandlerKind::PubKey { .. } => false,
        }
    }

    /// Decrypt a string of object `id` with the default string filter.
    pub fn decrypt_string(&self, data: &[u8], id: ObjectId) -> PdfResult<Vec<u8>> {
        let mut s = self.lock();
        let strf = s.cfc.strf.clone();
        let (cf, key) = s.object_key(&strf, id)?;
        drop(s);
        cf.decrypt(&key, data)
    }

    /// Encrypt a string of object `id` with the default string filter;
    /// `None` if strings are not encrypted (`/StrF /Identity`).
    pub fn encrypt_string(&self, data: &[u8], id: ObjectId) -> PdfResult<Option<Vec<u8>>> {
        let mut s = self.lock();
        let strf = s.cfc.strf.clone();
        if strf == IDENTITY {
            return Ok(None);
        }
        let (_, key) = s.object_key(&strf, id)?;
        s.encrypt_with(&strf, &key, data).map(Some)
    }

    /// Decrypt implicitly encrypted stream data of object `id`
    /// (`_implicit_decrypt_stream_content`): embedded file streams use the
    /// embedded file filter, all others the default stream filter.
    pub fn decrypt_stream_data(
        &self,
        data: &[u8],
        id: ObjectId,
        embedded_file: bool,
    ) -> PdfResult<Vec<u8>> {
        let mut s = self.lock();
        let name = if embedded_file {
            s.cfc.file_filter_name().clone()
        } else {
            s.cfc.stmf.clone()
        };
        let (cf, key) = s.object_key(&name, id)?;
        drop(s);
        cf.decrypt(&key, data)
    }

    /// Encrypt stream data of object `id` with the default stream filter
    /// (as pyHanko's writer does, for all streams).
    pub fn encrypt_stream_data(&self, data: &[u8], id: ObjectId) -> PdfResult<Vec<u8>> {
        let mut s = self.lock();
        let stmf = s.cfc.stmf.clone();
        let (_, key) = s.object_key(&stmf, id)?;
        s.encrypt_with(&stmf, &key, data)
    }

    /// Decode with an explicit crypt filter: the filter's global key is
    /// used, as ISO 32000 7.4.10 specifies (`CryptFilterDecoder.decode`).
    pub fn crypt_filter_decode(&self, name: &[u8], data: &[u8]) -> PdfResult<Vec<u8>> {
        let mut s = self.lock();
        let cf = s
            .cfc
            .get_raw(name)
            .ok_or_else(|| PdfError::Value(format!("KeyError: /{}", name_str(name))))?;
        let key = s.cf_shared_key(name)?;
        drop(s);
        cf.decrypt(&key, data)
    }

    /// Encode with an explicit crypt filter (`CryptFilterDecoder.encode`).
    pub fn crypt_filter_encode(&self, name: &[u8], data: &[u8]) -> PdfResult<Vec<u8>> {
        let mut s = self.lock();
        if s.cfc.get_raw(name).is_none() {
            return Err(PdfError::Value(format!("KeyError: /{}", name_str(name))));
        }
        let key = s.cf_shared_key(name)?;
        s.encrypt_with(name, &key, data)
    }
}
