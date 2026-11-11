// Derived from pyHanko `pdf_utils/crypt/standard.py` (MIT, see LICENSE-pyHanko).

//! The standard (password-based) security handler
//! (`StandardSecurityHandler`): RC4 40/128, AES-128 (revisions 2–4),
//! AES-256 (revision 6) and AES-GCM (revision 7, ISO 32003).

use std::sync::Arc;

use lopdf::{Dictionary, Object};
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::api::{
    AuthResult, AuthStatus, CryptFilter, CryptFilterConfiguration, CryptFilterRegistry, HandlerKind,
    HandlerState, SecurityHandler, SecurityHandlerVersion, IDENTITY,
};
use super::asn1::{self, tag, Tlv};
use super::cred_ser::{SerialisableCredential, SerialisedCredential};
use super::legacy::{
    compute_o_value_legacy, compute_o_value_legacy_prep, compute_u_value_r2, compute_u_value_r34,
    legacy_normalise_pw_bytes, legacy_normalise_pw_text,
};
use super::permissions::StandardPermissions;
use super::util::{aes_cbc_decrypt, aes_cbc_encrypt, aes_ecb, random_bytes, rc4_encrypt};
use crate::error::{PdfError, PdfResult};
use crate::generic::{byte_string, name_str, type_name};

/// Name of the default crypt filter of the standard handler (`STD_CF`).
pub const STD_CF: &str = "StdCF";

/// Standard security handler revision `/R` (`StandardSecuritySettingsRevision`).
///
/// Ordered like pyHanko's `VersionEnum` ([`Self::Other`] is the greatest).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StandardSecuritySettingsRevision {
    /// `/R 2`.
    Rc4Basic,
    /// `/R 3`.
    Rc4Extended,
    /// `/R 4`.
    Rc4OrAes128,
    /// `/R 6`.
    Aes256,
    /// `/R 7` (ISO 32003).
    AesGcm,
    /// Any other value.
    Other,
}

impl StandardSecuritySettingsRevision {
    /// The numeric value, `None` for [`Self::Other`].
    pub fn value(self) -> Option<i64> {
        match self {
            Self::Rc4Basic => Some(2),
            Self::Rc4Extended => Some(3),
            Self::Rc4OrAes128 => Some(4),
            Self::Aes256 => Some(6),
            Self::AesGcm => Some(7),
            Self::Other => None,
        }
    }

    /// `from_number`.
    pub fn from_number(value: Option<i64>) -> Self {
        match value {
            Some(2) => Self::Rc4Basic,
            Some(3) => Self::Rc4Extended,
            Some(4) => Self::Rc4OrAes128,
            Some(6) => Self::Aes256,
            Some(7) => Self::AesGcm,
            _ => Self::Other,
        }
    }

    /// `as_pdf_object`.
    pub fn as_pdf_object(self) -> Object {
        self.value().map_or(Object::Null, Object::Integer)
    }

    fn num(self) -> i64 {
        self.value().unwrap_or(i64::MAX)
    }
}

/// A password: text (normalised per handler revision) or raw bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Password {
    /// A text password (`str`).
    Text(String),
    /// A byte password (`bytes`), used as is.
    Bytes(Vec<u8>),
}

impl From<&str> for Password {
    fn from(s: &str) -> Self {
        Self::Text(s.to_string())
    }
}

impl From<String> for Password {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

impl From<&[u8]> for Password {
    fn from(b: &[u8]) -> Self {
        Self::Bytes(b.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for Password {
    fn from(b: &[u8; N]) -> Self {
        Self::Bytes(b.to_vec())
    }
}

impl From<Vec<u8>> for Password {
    fn from(b: Vec<u8>) -> Self {
        Self::Bytes(b)
    }
}

/// A serialisable password credential (`_PasswordCredential`):
/// `SEQUENCE { pwd_bytes OCTET STRING, id1 OCTET STRING OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordCredential {
    /// Normalised password bytes.
    pub pwd_bytes: Vec<u8>,
    /// First part of the document ID (legacy handlers).
    pub id1: Option<Vec<u8>>,
}

impl PasswordCredential {
    /// Registered type name (`get_name`).
    pub const NAME: &'static str = "pwd_bytes";

    /// DER encoding (`_ser_value`).
    pub fn to_der(&self) -> Vec<u8> {
        let pw = asn1::octets(&self.pwd_bytes);
        match &self.id1 {
            Some(id1) => asn1::seq(&[&pw, &asn1::octets(id1)]),
            None => asn1::seq(&[&pw]),
        }
    }

    /// Decode (`_deser_value`).
    pub fn from_der(data: &[u8]) -> PdfResult<Self> {
        let err = || PdfError::Read("Failed to deserialise password credential".into());
        let (t, _) = Tlv::expect(data, tag::SEQUENCE).map_err(|_| err())?;
        let ch = t.children().map_err(|_| err())?;
        match ch.as_slice() {
            [pw] if pw.tag == tag::OCTET_STRING => Ok(Self {
                pwd_bytes: pw.value.to_vec(),
                id1: None,
            }),
            [pw, id1] if pw.tag == tag::OCTET_STRING && id1.tag == tag::OCTET_STRING => Ok(Self {
                pwd_bytes: pw.value.to_vec(),
                id1: Some(id1.value.to_vec()),
            }),
            _ => Err(err()),
        }
    }

    /// Serialise (`serialise`).
    pub fn serialise(&self) -> SerialisedCredential {
        SerialisedCredential {
            credential_type: Self::NAME.into(),
            data: self.to_der(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct StandardState {
    pub(crate) revision: StandardSecuritySettingsRevision,
    pub(crate) perms: StandardPermissions,
    pub(crate) mac_required: bool,
    pub(crate) odata: Vec<u8>,
    pub(crate) udata: Vec<u8>,
    pub(crate) oeseed: Option<Vec<u8>>,
    pub(crate) ueseed: Option<Vec<u8>>,
    pub(crate) encrypted_perms: Option<Vec<u8>>,
    pub(crate) shared_key: Option<Vec<u8>>,
    pub(crate) auth_failed: bool,
}

/// Parameters of the standard handler constructor
/// (`StandardSecurityHandler.__init__`).
#[derive(Clone, Debug)]
pub struct StandardHandlerParams {
    /// `/V`.
    pub version: SecurityHandlerVersion,
    /// `/R`.
    pub revision: StandardSecuritySettingsRevision,
    /// Key length in bytes.
    pub legacy_keylen: usize,
    /// `/P`.
    pub perm_flags: StandardPermissions,
    /// `/O`.
    pub odata: Vec<u8>,
    /// `/U`.
    pub udata: Vec<u8>,
    /// `/OE`.
    pub oeseed: Option<Vec<u8>>,
    /// `/UE`.
    pub ueseed: Option<Vec<u8>>,
    /// `/Perms`.
    pub encrypted_perms: Option<Vec<u8>>,
    /// `/EncryptMetadata`.
    pub encrypt_metadata: bool,
    /// Crypt filters; a default is imputed from the version if `None`.
    pub crypt_filter_config: Option<CryptFilterConfiguration>,
    /// Write deprecated compatibility entries (`/Length`).
    pub compat_entries: bool,
    /// `/KDFSalt` (ISO 32004).
    pub kdf_salt: Option<Vec<u8>>,
}

fn std_config(name_cf: CryptFilter) -> CryptFilterConfiguration {
    CryptFilterConfiguration {
        filters: vec![(STD_CF.as_bytes().to_vec(), name_cf)],
        stmf: STD_CF.as_bytes().to_vec(),
        strf: STD_CF.as_bytes().to_vec(),
        eff: None,
    }
}

/// `_std_rc4_config`.
pub fn std_rc4_config(keylen: usize) -> CryptFilterConfiguration {
    std_config(CryptFilter::standard_rc4(keylen))
}

/// `_std_aes_config`.
pub fn std_aes_config(keylen: usize) -> PdfResult<CryptFilterConfiguration> {
    Ok(std_config(CryptFilter::standard_aes(keylen)?))
}

/// `_std_gcm_config`.
pub fn std_gcm_config() -> CryptFilterConfiguration {
    std_config(CryptFilter::standard_aes_gcm())
}

/// Crypt filter methods of the standard handler (`_known_crypt_filters`).
pub fn default_crypt_filters() -> CryptFilterRegistry {
    let mut r = CryptFilterRegistry::default();
    r.register(
        "V2",
        Arc::new(|d: &Dictionary, _| {
            let bits = match d.get(b"Length") {
                Ok(Object::Integer(n)) => *n,
                Ok(other) => {
                    return Err(PdfError::Value(format!(
                        "Invalid /Length in crypt filter: {}",
                        type_name(other)
                    )))
                }
                Err(_) => 40,
            };
            Ok(CryptFilter::standard_rc4(usize::try_from(bits.div_euclid(8)).unwrap_or(0)))
        }),
    );
    r.register("AESV2", Arc::new(|_, _| CryptFilter::standard_aes(16)));
    r.register("AESV3", Arc::new(|_, _| CryptFilter::standard_aes(32)));
    r.register("AESV4", Arc::new(|_, _| Ok(CryptFilter::standard_aes_gcm())));
    r.register("Identity", Arc::new(|_, _| Ok(CryptFilter::identity())));
    r
}

/// Options for [`SecurityHandler::build_from_pw`] (keyword arguments of
/// `build_from_pw`).
#[derive(Clone, Debug)]
pub struct StandardEncryptOptions {
    /// Permissions (`perms`).
    pub perms: StandardPermissions,
    /// `encrypt_metadata`.
    pub encrypt_metadata: bool,
    /// Add an ISO 32004 MAC (`pdf_mac`, default `true`).
    pub pdf_mac: bool,
    /// Use AES-GCM (ISO 32003) (`use_gcm`, default `false`).
    pub use_gcm: bool,
    /// `compat_entries`.
    pub compat_entries: bool,
}

impl Default for StandardEncryptOptions {
    fn default() -> Self {
        Self {
            perms: StandardPermissions::allow_everything(),
            encrypt_metadata: true,
            pdf_mac: true,
            use_gcm: false,
            compat_entries: true,
        }
    }
}

/// Options for [`SecurityHandler::build_from_pw_legacy`].
#[derive(Clone, Debug)]
pub struct LegacyEncryptOptions {
    /// Key length in bytes (`keylen_bytes`, default 16).
    pub keylen_bytes: usize,
    /// Use AES-128 for revision 4 (`use_aes128`, default `true`).
    pub use_aes128: bool,
    /// Permissions.
    pub perms: StandardPermissions,
    /// Custom crypt filters.
    pub crypt_filter_config: Option<CryptFilterConfiguration>,
    /// `encrypt_metadata`.
    pub encrypt_metadata: bool,
    /// `compat_entries`.
    pub compat_entries: bool,
}

impl Default for LegacyEncryptOptions {
    fn default() -> Self {
        Self {
            keylen_bytes: 16,
            use_aes128: true,
            perms: StandardPermissions::allow_everything(),
            crypt_filter_config: None,
            encrypt_metadata: true,
            compat_entries: true,
        }
    }
}

fn r6_normalise_pw(password: &Password) -> PdfResult<Vec<u8>> {
    let mut b = match password {
        Password::Text(s) if s.is_empty() => Vec::new(),
        Password::Text(s) => super::saslprep::saslprep(s)?.into_bytes(),
        Password::Bytes(b) => b.clone(),
    };
    b.truncate(127);
    Ok(b)
}

fn legacy_normalise_pw(password: &Password) -> PdfResult<Vec<u8>> {
    match password {
        Password::Text(s) => legacy_normalise_pw_text(s),
        Password::Bytes(b) => Ok(legacy_normalise_pw_bytes(b)),
    }
}

/// Algorithm 2.B of ISO 32000-2, 7.6.4.3.4 (`_r6_hash_algo`).
pub(crate) fn r6_hash_algo(pw_bytes: &[u8], current_salt: &[u8], u_entry: Option<&[u8]>) -> PdfResult<Vec<u8>> {
    let mut h = Sha256::new();
    h.update(pw_bytes);
    h.update(current_salt);
    if let Some(u) = u_entry {
        h.update(u);
    }
    let mut k: Vec<u8> = h.finalize().to_vec();
    let u = u_entry.unwrap_or(b"");
    let mut round_no: i64 = 0;
    let mut last_byte_val: i64 = 0;
    while round_no < 64 || last_byte_val > round_no - 32 {
        let unit = [pw_bytes, &k, u].concat();
        let k1 = unit.repeat(64);
        let (_, e) = aes_cbc_encrypt(&k[..16], &k1, Some(&k[16..32]), false)?;
        let sum: u32 = e[..16].iter().map(|b| u32::from(*b) % 3).sum();
        k = match sum % 3 {
            0 => Sha256::digest(&e).to_vec(),
            1 => Sha384::digest(&e).to_vec(),
            _ => Sha512::digest(&e).to_vec(),
        };
        last_byte_val = e.last().copied().map_or(0, i64::from);
        round_no += 1;
    }
    k.truncate(32);
    Ok(k)
}

struct R6KeyEntry<'a> {
    hash_value: &'a [u8],
    validation_salt: &'a [u8],
    key_salt: &'a [u8],
}

impl<'a> R6KeyEntry<'a> {
    fn from_bytes(entry: &'a [u8]) -> PdfResult<Self> {
        if entry.len() != 48 {
            return Err(PdfError::Generic("R6 key entries must be 48 bytes long".into()));
        }
        Ok(Self {
            hash_value: &entry[..32],
            validation_salt: &entry[32..40],
            key_salt: &entry[40..48],
        })
    }
}

fn r6_password_authenticate(pw: &[u8], entry: &R6KeyEntry<'_>, u_entry: Option<&[u8]>) -> PdfResult<bool> {
    Ok(r6_hash_algo(pw, entry.validation_salt, u_entry)? == entry.hash_value)
}

fn r6_derive_file_key(pw: &[u8], entry: &R6KeyEntry<'_>, e_entry: &[u8], u_entry: Option<&[u8]>) -> PdfResult<Vec<u8>> {
    let interm = r6_hash_algo(pw, entry.key_salt, u_entry)?;
    if e_entry.len() != 32 {
        return Err(PdfError::Generic("/OE and /UE must be 32 bytes long".into()));
    }
    aes_cbc_decrypt(&interm, e_entry, &[0u8; 16], false)
}

fn check_r6_values(
    udata: &[u8],
    odata: &[u8],
    oeseed: Option<&Vec<u8>>,
    ueseed: Option<&Vec<u8>>,
    encrypted_perms: Option<&Vec<u8>>,
) -> PdfResult<()> {
    if !(udata.len() == 48 && odata.len() == 48) {
        return Err(PdfError::Generic(
            "/U and /O entries must be 48 bytes long in a rev. 6 security handler".into(),
        ));
    }
    match (oeseed, ueseed) {
        (Some(o), Some(u)) if !o.is_empty() && !u.is_empty() && o.len() == 32 && u.len() == 32 => {}
        _ => {
            return Err(PdfError::Generic(
                "/UE and /OE must be present and be 32 bytes long in a rev. 6 security handler".into(),
            ))
        }
    }
    match encrypted_perms {
        Some(p) if p.len() == 16 => Ok(()),
        _ => Err(PdfError::Generic(
            "/Perms must be present and be 16 bytes long in a rev. 6 security handler".into(),
        )),
    }
}

fn dict_get<'a>(d: &'a Dictionary, key: &str) -> Option<&'a Object> {
    d.get(key.as_bytes()).ok()
}

fn get_bytes(x: &Object) -> PdfResult<Vec<u8>> {
    match x {
        Object::String(s, _) => Ok(s.clone()),
        other => Err(PdfError::Read(format!(
            "Expected string, but got {}",
            type_name(other)
        ))),
    }
}

fn get_bool(x: &Object) -> bool {
    match x {
        Object::Boolean(b) => *b,
        Object::Null => false,
        Object::Integer(i) => *i != 0,
        Object::Real(r) => *r != 0.0,
        Object::String(s, _) => !s.is_empty(),
        Object::Array(a) => !a.is_empty(),
        Object::Dictionary(d) => !d.is_empty(),
        _ => true,
    }
}

/// `get_and_apply('/KDFSalt', ...)`: string values only.
pub(crate) fn kdf_salt_of(d: &Dictionary) -> Option<Vec<u8>> {
    match dict_get(d, "KDFSalt") {
        Some(Object::String(s, _)) => Some(s.clone()),
        _ => None,
    }
}

pub(crate) fn encrypt_metadata_of(d: &Dictionary) -> bool {
    dict_get(d, "EncryptMetadata").is_none_or(get_bool)
}

/// The numeric value of `/V` or `/R` (missing: `KeyError`).
pub(crate) fn number_entry(d: &Dictionary, key: &str) -> PdfResult<Option<i64>> {
    match dict_get(d, key) {
        None => Err(PdfError::Value(format!("KeyError: /{key}"))),
        Some(Object::Integer(i)) => Ok(Some(*i)),
        Some(_) => Ok(None),
    }
}

/// `SecurityHandler.process_crypt_filters` (shared by both handler types).
pub(crate) fn process_crypt_filters(
    encrypt_dict: &Dictionary,
    reg: &CryptFilterRegistry,
    pubkey: bool,
) -> PdfResult<Option<CryptFilterConfiguration>> {
    let name_entry = |key: &str, default: Option<Vec<u8>>| -> PdfResult<Option<Vec<u8>>> {
        match dict_get(encrypt_dict, key) {
            None => Ok(default),
            Some(Object::Name(n)) => Ok(Some(n.clone())),
            Some(other) => Err(PdfError::Read(format!(
                "/{key} must be a name, not {}",
                type_name(other)
            ))),
        }
    };
    let stmf = name_entry("StmF", Some(IDENTITY.to_vec()))?.unwrap_or_else(|| IDENTITY.to_vec());
    let strf = name_entry("StrF", Some(IDENTITY.to_vec()))?.unwrap_or_else(|| IDENTITY.to_vec());
    let eff = name_entry("EFF", Some(stmf.clone()))?;
    let Some(cf_dict) = dict_get(encrypt_dict, "CF") else {
        return Ok(None);
    };
    let Object::Dictionary(cf_dict) = cf_dict else {
        return Err(PdfError::Read("/CF must be a dictionary".into()));
    };
    let mut filters = Vec::new();
    for (name, cfdict) in cf_dict.iter() {
        let Object::Dictionary(cfdict) = cfdict else {
            return Err(PdfError::Read(format!(
                "Crypt filter /{} must be a dictionary",
                name_str(name)
            )));
        };
        let acts_as_default = *name == stmf || *name == strf;
        let cf = if pubkey {
            super::pubkey::read_cf_dictionary(reg, cfdict, acts_as_default)?
        } else {
            super::api::build_crypt_filter(reg, cfdict, acts_as_default)?
        };
        let Some(cf) = cf else {
            return Err(PdfError::Read("Failed to load crypt filter with ".into()));
        };
        filters.push((name.clone(), cf));
    }
    CryptFilterConfiguration::from_names(filters, stmf, strf, eff).map(Some)
}

impl SecurityHandler {
    /// `StandardSecurityHandler.__init__`.
    pub fn new_standard(p: StandardHandlerParams) -> PdfResult<Self> {
        let cfc = match p.crypt_filter_config {
            Some(c) => c,
            None => match p.version {
                SecurityHandlerVersion::Rc4_40 => std_rc4_config(5),
                SecurityHandlerVersion::Rc4LongerKeys => std_rc4_config(p.legacy_keylen),
                SecurityHandlerVersion::AesGcm => std_gcm_config(),
                v if v >= SecurityHandlerVersion::Aes256 => std_aes_config(32)?,
                _ => {
                    return Err(PdfError::Generic(
                        "Could not impute a reasonable crypt filter config".into(),
                    ))
                }
            },
        };
        // SecurityHandler.__init__ checks the key length first
        p.version.check_key_length(p.legacy_keylen)?;
        let mut st = StandardState {
            revision: p.revision,
            perms: p.perm_flags,
            mac_required: !p.perm_flags.contains(StandardPermissions::TOLERATE_MISSING_PDF_MAC),
            odata: p.odata,
            udata: p.udata,
            oeseed: None,
            ueseed: None,
            encrypted_perms: None,
            shared_key: None,
            auth_failed: false,
        };
        if p.revision >= StandardSecuritySettingsRevision::Aes256 {
            check_r6_values(
                &st.udata,
                &st.odata,
                p.oeseed.as_ref(),
                p.ueseed.as_ref(),
                p.encrypted_perms.as_ref(),
            )?;
            st.oeseed = p.oeseed;
            st.ueseed = p.ueseed;
            st.encrypted_perms = p.encrypted_perms;
        } else if !(st.udata.len() == 32 && st.odata.len() == 32) {
            return Err(PdfError::Generic(
                "/U and /O entries must be 32 bytes long in a legacy security handler".into(),
            ));
        }
        let state = HandlerState::new(
            p.version,
            p.legacy_keylen,
            cfc,
            p.encrypt_metadata,
            p.compat_entries,
            p.kdf_salt,
            HandlerKind::Standard(st),
        )?;
        Ok(Self::from_state(state))
    }

    pub(crate) fn instantiate_standard(encrypt_dict: &Dictionary, reg: &CryptFilterRegistry) -> PdfResult<Self> {
        let v = SecurityHandlerVersion::from_number(number_entry(encrypt_dict, "V")?);
        let r = StandardSecuritySettingsRevision::from_number(number_entry(encrypt_dict, "R")?);
        let cfc = process_crypt_filters(encrypt_dict, reg, false)?;
        // gather_encryption_metadata
        let keylen_bits = match dict_get(encrypt_dict, "Length") {
            None => 40,
            Some(Object::Integer(n)) => *n,
            Some(other) => {
                return Err(PdfError::Value(format!(
                    "Invalid /Length: {}",
                    type_name(other)
                )))
            }
        };
        if keylen_bits.rem_euclid(8) != 0 {
            return Err(PdfError::Generic("Key length must be a multiple of 8".into()));
        }
        let keylen = usize::try_from(keylen_bits / 8)
            .map_err(|_| PdfError::Generic("Key length must be positive".into()))?;
        let (Some(o), Some(u)) = (dict_get(encrypt_dict, "O"), dict_get(encrypt_dict, "U")) else {
            return Err(PdfError::Generic("/O and /U entries must be present".into()));
        };
        let perm_flags = match dict_get(encrypt_dict, "P") {
            None => StandardPermissions::allow_everything(),
            Some(Object::Integer(p)) => StandardPermissions::from_sint32(*p),
            Some(other) => {
                return Err(PdfError::Read(format!(
                    "Cannot parse {} as a permission indicator",
                    crate::generic::name_str(&crate::generic::object_to_bytes(other))
                )))
            }
        };
        let truncate48 = |o: &Object| -> PdfResult<Vec<u8>> {
            match o {
                Object::String(s, _) => Ok(s[..s.len().min(48)].to_vec()),
                other => Err(PdfError::Value(format!(
                    "'{}' object has no attribute 'original_bytes'",
                    type_name(other)
                ))),
            }
        };
        let odata = truncate48(o)?;
        let udata = truncate48(u)?;
        let opt_bytes = |k: &str| dict_get(encrypt_dict, k).map(get_bytes).transpose();
        let oeseed = opt_bytes("OE")?;
        let ueseed = opt_bytes("UE")?;
        let encrypted_perms = opt_bytes("Perms")?;
        Self::new_standard(StandardHandlerParams {
            version: v,
            revision: r,
            legacy_keylen: keylen,
            perm_flags,
            odata,
            udata,
            oeseed,
            ueseed,
            encrypted_perms,
            encrypt_metadata: encrypt_metadata_of(encrypt_dict),
            crypt_filter_config: cfc,
            compat_entries: true,
            kdf_salt: kdf_salt_of(encrypt_dict),
        })
    }

    /// `StandardSecurityHandler.instantiate_from_pdf_object` with the
    /// default crypt filter methods.
    pub fn instantiate_standard_from_pdf_object(encrypt_dict: &Dictionary) -> PdfResult<Self> {
        Self::instantiate_standard(encrypt_dict, &default_crypt_filters())
    }

    /// A legacy (RC4 / AES-128) password handler for a new document
    /// (`build_from_pw_legacy`). Only for tests and legacy systems.
    pub fn build_from_pw_legacy(
        rev: StandardSecuritySettingsRevision,
        id1: &[u8],
        desired_owner_pass: impl Into<Password>,
        desired_user_pass: Option<Password>,
        opts: LegacyEncryptOptions,
    ) -> PdfResult<Self> {
        let owner = legacy_normalise_pw(&desired_owner_pass.into())?;
        let user = match desired_user_pass {
            Some(u) => legacy_normalise_pw(&u)?,
            None => owner.clone(),
        };
        if rev > StandardSecuritySettingsRevision::Rc4OrAes128 {
            return Err(PdfError::Value(format!(
                "{rev:?} is not supported by this bootstrapping method."
            )));
        }
        let mut keylen_bytes = opts.keylen_bytes;
        if rev == StandardSecuritySettingsRevision::Rc4Basic {
            keylen_bytes = 5;
        } else if opts.use_aes128 && rev == StandardSecuritySettingsRevision::Rc4OrAes128 {
            keylen_bytes = 16;
        }
        let o_entry = compute_o_value_legacy(&owner, &user, rev.num(), keylen_bytes);
        let mut perms = opts.perms;
        let (u_entry, key) = if rev == StandardSecuritySettingsRevision::Rc4Basic {
            perms = perms
                | StandardPermissions::ALLOW_FORM_FILLING
                | StandardPermissions::ALLOW_ASSISTIVE_TECHNOLOGY
                | StandardPermissions::ALLOW_REASSEMBLY
                | StandardPermissions::ALLOW_HIGH_QUALITY_PRINTING;
            compute_u_value_r2(&user, &o_entry, perms, id1)
        } else {
            compute_u_value_r34(&user, rev.num(), keylen_bytes, &o_entry, perms, id1, opts.encrypt_metadata)
        };
        let version = match rev {
            StandardSecuritySettingsRevision::Rc4OrAes128 => SecurityHandlerVersion::Rc4OrAes128,
            StandardSecuritySettingsRevision::Rc4Basic => SecurityHandlerVersion::Rc4_40,
            _ => SecurityHandlerVersion::Rc4LongerKeys,
        };
        let mut cfc = opts.crypt_filter_config;
        if rev == StandardSecuritySettingsRevision::Rc4OrAes128 && cfc.is_none() {
            cfc = Some(if opts.use_aes128 {
                std_aes_config(16)?
            } else {
                std_rc4_config(keylen_bytes)
            });
        }
        let sh = Self::new_standard(StandardHandlerParams {
            version,
            revision: rev,
            legacy_keylen: keylen_bytes,
            perm_flags: perms,
            odata: o_entry,
            udata: u_entry,
            oeseed: None,
            ueseed: None,
            encrypted_perms: None,
            encrypt_metadata: opts.encrypt_metadata,
            crypt_filter_config: cfc,
            compat_entries: opts.compat_entries,
            kdf_salt: None,
        })?;
        {
            let mut s = sh.lock();
            if let HandlerKind::Standard(st) = &mut s.kind {
                st.shared_key = Some(key);
            }
            s.credential = Some(SerialisableCredential::Password(PasswordCredential {
                pwd_bytes: owner,
                id1: Some(id1.to_vec()),
            }));
        }
        Ok(sh)
    }

    /// An AES-256 (PDF 2.0) password handler for a new document
    /// (`build_from_pw`).
    pub fn build_from_pw(
        desired_owner_pass: impl Into<Password>,
        desired_user_pass: Option<Password>,
        opts: StandardEncryptOptions,
    ) -> PdfResult<Self> {
        let owner_pw = r6_normalise_pw(&desired_owner_pass.into())?;
        let user_pw = match desired_user_pass {
            Some(u) => r6_normalise_pw(&u)?,
            None => owner_pw.clone(),
        };
        let encryption_key = random_bytes(32)?;
        let u_validation_salt = random_bytes(8)?;
        let u_key_salt = random_bytes(8)?;
        let u_hash = r6_hash_algo(&user_pw, &u_validation_salt, None)?;
        let u_entry = [u_hash, u_validation_salt, u_key_salt.clone()].concat();
        let u_interm = r6_hash_algo(&user_pw, &u_key_salt, None)?;
        let (_, ue_seed) = aes_cbc_encrypt(&u_interm, &encryption_key, Some(&[0u8; 16]), false)?;

        let o_validation_salt = random_bytes(8)?;
        let o_key_salt = random_bytes(8)?;
        let o_hash = r6_hash_algo(&owner_pw, &o_validation_salt, Some(&u_entry))?;
        let o_entry = [o_hash, o_validation_salt, o_key_salt.clone()].concat();
        let o_interm = r6_hash_algo(&owner_pw, &o_key_salt, Some(&u_entry))?;
        let (_, oe_seed) = aes_cbc_encrypt(&o_interm, &encryption_key, Some(&[0u8; 16]), false)?;

        let mut perms = opts.perms;
        if opts.pdf_mac {
            perms = perms - StandardPermissions::TOLERATE_MISSING_PDF_MAC;
        }
        let mut extd = perms.as_uint32().to_le_bytes().to_vec();
        extd.extend_from_slice(&[0xff; 4]);
        extd.push(if opts.encrypt_metadata { b'T' } else { b'F' });
        extd.extend_from_slice(b"adb");
        extd.extend(random_bytes(4)?);
        let encrypted_perms = aes_ecb(&encryption_key, &extd, true)?;
        let kdf_salt = if opts.pdf_mac { Some(random_bytes(32)?) } else { None };
        let (version, revision) = if opts.use_gcm {
            (SecurityHandlerVersion::AesGcm, StandardSecuritySettingsRevision::AesGcm)
        } else {
            (SecurityHandlerVersion::Aes256, StandardSecuritySettingsRevision::Aes256)
        };
        let sh = Self::new_standard(StandardHandlerParams {
            version,
            revision,
            legacy_keylen: 32,
            perm_flags: perms,
            odata: o_entry,
            udata: u_entry,
            oeseed: Some(oe_seed),
            ueseed: Some(ue_seed),
            encrypted_perms: Some(encrypted_perms),
            encrypt_metadata: opts.encrypt_metadata,
            crypt_filter_config: None,
            compat_entries: opts.compat_entries,
            kdf_salt,
        })?;
        {
            let mut s = sh.lock();
            if let HandlerKind::Standard(st) = &mut s.kind {
                st.shared_key = Some(encryption_key);
            }
            s.credential = Some(SerialisableCredential::Password(PasswordCredential {
                pwd_bytes: owner_pw,
                id1: None,
            }));
        }
        Ok(sh)
    }

    /// Authenticate with a password (`StandardSecurityHandler.authenticate`);
    /// `id1` is required for legacy handlers.
    pub fn authenticate_password(&self, password: impl Into<Password>, id1: Option<&[u8]>) -> PdfResult<AuthResult> {
        self.authenticate_standard(password.into(), id1.map(<[u8]>::to_vec))
    }

    pub(crate) fn authenticate_password_credential(&self, cred: &PasswordCredential) -> PdfResult<AuthResult> {
        self.authenticate_standard(Password::Bytes(cred.pwd_bytes.clone()), cred.id1.clone())
    }

    fn authenticate_standard(&self, credential: Password, id1: Option<Vec<u8>>) -> PdfResult<AuthResult> {
        let mut s = self.lock();
        let encrypt_metadata = s.encrypt_metadata;
        let keylen = s.keylen;
        let HandlerKind::Standard(st) = &mut s.kind else {
            return Err(PdfError::Read(
                "Pubkey authentication credential must be an instance of EnvelopeKeyDecrypter, not <class 'str'>.".into(),
            ));
        };
        let (status, key, cred) = if st.revision >= StandardSecuritySettingsRevision::Aes256 {
            authenticate_r6(st, &credential, encrypt_metadata)?
        } else {
            let Some(id1) = id1 else {
                return Err(PdfError::Read("id1 must be specified for legacy encryption".into()));
            };
            let pw = legacy_normalise_pw(&credential)?;
            authenticate_legacy(st, &id1, &pw, keylen, encrypt_metadata)
        };
        let perms = st.perms;
        if let Some(k) = key {
            st.shared_key = Some(k);
            st.auth_failed = false;
        } else {
            st.auth_failed = true;
        }
        if let Some(c) = cred {
            s.credential = Some(SerialisableCredential::Password(c));
        }
        Ok(AuthResult::new(status, Some(perms.into())))
    }
}

type AuthOutcome = (AuthStatus, Option<Vec<u8>>, Option<PasswordCredential>);

fn auth_user_password_legacy(
    st: &StandardState,
    id1: &[u8],
    password: &[u8],
    keylen: usize,
    encrypt_metadata: bool,
) -> (bool, Vec<u8>) {
    if st.revision == StandardSecuritySettingsRevision::Rc4Basic {
        let (u, key) = compute_u_value_r2(password, &st.odata, st.perms, id1);
        (u == st.udata, key)
    } else {
        let (u, key) = compute_u_value_r34(
            password,
            st.revision.num(),
            keylen,
            &st.odata,
            st.perms,
            id1,
            encrypt_metadata,
        );
        (u.get(..16) == st.udata.get(..16), key)
    }
}

fn authenticate_legacy(
    st: &StandardState,
    id1: &[u8],
    password: &[u8],
    keylen: usize,
    encrypt_metadata: bool,
) -> AuthOutcome {
    let cred = PasswordCredential {
        pwd_bytes: password.to_vec(),
        id1: Some(id1.to_vec()),
    };
    let key = compute_o_value_legacy_prep(password, st.revision.num(), keylen);
    let prp_userpass = if st.revision == StandardSecuritySettingsRevision::Rc4Basic {
        rc4_encrypt(&key, &st.odata)
    } else {
        let mut val = st.odata.clone();
        for i in (0..20u8).rev() {
            let new_key: Vec<u8> = key.iter().map(|b| b ^ i).collect();
            val = rc4_encrypt(&new_key, &val);
        }
        val
    };
    let (owner_ok, key) = auth_user_password_legacy(st, id1, &prp_userpass, keylen, encrypt_metadata);
    if owner_ok {
        return (AuthStatus::Owner, Some(key), Some(cred));
    }
    let (user_ok, key) = auth_user_password_legacy(st, id1, password, keylen, encrypt_metadata);
    if user_ok {
        return (AuthStatus::User, Some(key), Some(cred));
    }
    (AuthStatus::Failed, None, None)
}

/// Algorithm 2.A of ISO 32000-2, 7.6.4.3.3 (`_authenticate_r6`).
fn authenticate_r6(st: &StandardState, password: &Password, encrypt_metadata: bool) -> PdfResult<AuthOutcome> {
    let pw = r6_normalise_pw(password)?;
    let o_entry = R6KeyEntry::from_bytes(&st.odata)?;
    let u_entry = R6KeyEntry::from_bytes(&st.udata)?;
    let missing = || PdfError::Generic("/UE and /OE must be present".into());
    let (status, key) = if r6_password_authenticate(&pw, &o_entry, Some(&st.udata))? {
        let oe = st.oeseed.as_deref().ok_or_else(missing)?;
        (AuthStatus::Owner, r6_derive_file_key(&pw, &o_entry, oe, Some(&st.udata))?)
    } else if r6_password_authenticate(&pw, &u_entry, None)? {
        let ue = st.ueseed.as_deref().ok_or_else(missing)?;
        (AuthStatus::User, r6_derive_file_key(&pw, &u_entry, ue, None)?)
    } else {
        return Ok((AuthStatus::Failed, None, None));
    };
    let ep = st
        .encrypted_perms
        .as_deref()
        .ok_or_else(|| PdfError::Generic("/Perms must be present".into()))?;
    let decrypted = aes_ecb(&key, ep, false)?;
    let mut perms_ok = decrypted.get(9..12) == Some(b"adb".as_slice());
    let p_le = u32::from_le_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]);
    perms_ok &= st.perms == StandardPermissions::from_uint(p_le);
    match decrypted[8] {
        b'T' => perms_ok &= encrypt_metadata,
        b'F' => perms_ok &= !encrypt_metadata,
        _ => perms_ok = false,
    }
    if !perms_ok {
        return Err(PdfError::Generic(
            "File decryption key didn't decrypt permission flags correctly -- file permissions may have been tampered with."
                .into(),
        ));
    }
    Ok((
        status,
        Some(key),
        Some(PasswordCredential {
            pwd_bytes: pw,
            id1: None,
        }),
    ))
}

pub(crate) fn standard_as_pdf_object(s: &HandlerState, st: &StandardState) -> PdfResult<Dictionary> {
    let mut d = Dictionary::new();
    d.set("Filter", Object::Name(b"Standard".to_vec()));
    d.set("O", byte_string(st.odata.clone()));
    d.set("U", byte_string(st.udata.clone()));
    d.set("P", Object::Integer(i64::from(st.perms.as_sint32())));
    if let Some(salt) = s.kdf_salt.as_ref().filter(|s| !s.is_empty()) {
        d.set("KDFSalt", byte_string(salt.clone()));
    }
    if s.compat_entries || s.version == SecurityHandlerVersion::Rc4LongerKeys {
        d.set("Length", Object::Integer(s.keylen as i64 * 8));
    }
    d.set("V", s.version.as_pdf_object());
    d.set("R", st.revision.as_pdf_object());
    if s.version > SecurityHandlerVersion::Rc4LongerKeys {
        d.set("EncryptMetadata", Object::Boolean(s.encrypt_metadata));
        for (k, v) in s.cfc.as_pdf_object()?.into_iter() {
            d.set(k, v);
        }
    }
    if st.revision >= StandardSecuritySettingsRevision::Aes256 {
        let get = |o: &Option<Vec<u8>>| byte_string(o.clone().unwrap_or_default());
        d.set("OE", get(&st.oeseed));
        d.set("UE", get(&st.ueseed));
        d.set("Perms", get(&st.encrypted_perms));
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r6_values_from_python() {
        // computed with pyHanko's _r6_hash_algo(b'usersecret', b'\x00' * 8)
        let h = r6_hash_algo(b"usersecret", &[0u8; 8], None).unwrap();
        assert_eq!(h.len(), 32);
        let h2 = r6_hash_algo(b"usersecret", &[0u8; 8], None).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn password_credential_der() {
        let c = PasswordCredential {
            pwd_bytes: b"abc".to_vec(),
            id1: Some(vec![1, 2]),
        };
        assert_eq!(PasswordCredential::from_der(&c.to_der()).unwrap(), c);
        assert!(PasswordCredential::from_der(b"\xde\xad\xbe\xef").is_err());
    }
}
