// Derived from pyHanko `pdf_utils/crypt/__init__.py`, the encryption parts of
// `pdf_utils/reader.py` (`decrypt`, `decrypt_pubkey`, `_validate_pdf_mac`,
// `security_handler`), `pdf_utils/writer.py` (`encrypt`, `encrypt_pubkey`,
// `_assign_security_handler`), `pdf_utils/incremental_writer.py` (`encrypt`,
// `encrypt_pubkey`) and `pdf_utils/generic.py` (`DecryptedObjectProxy`,
// `StreamObject.add_crypt_filter`) (MIT, see LICENSE-pyHanko).

//! PDF encryption (`pyhanko.pdf_utils.crypt`).
//!
//! Supported: the standard security handler (RC4 40–128 bit, AES-128,
//! AES-256 revision 6, AES-GCM revision 7 / ISO 32003) and the public-key
//! security handler (`/adbe.pkcs7.s4` and `.s5`, RSA key transport with
//! PKCS#1 v1.5 or OAEP, ECDH key agreement on P-256/384/521, X25519 and
//! X448), crypt filters (default and explicit `/Crypt`), credential
//! serialisation, and PDF MAC (ISO 32004).
//!
//! Reading: [`PdfFile::decrypt`] / [`PdfFile::decrypt_pubkey`] authenticate;
//! objects are then decrypted as they are read. Objects inside object
//! streams, the `/Encrypt` dictionary and cross-reference streams are never
//! decrypted. Unlike pyHanko, which decrypts lazily, objects are decrypted
//! as a whole when read; to keep signatures readable, the `/Contents` of
//! signature dictionaries (dictionaries with `/ByteRange` or `/Type /Sig` or
//! `/DocTimeStamp`) is left as is, since ISO 32000 exempts it from
//! encryption.
//!
//! Writing: [`PdfWriter::encrypt`] / [`PdfWriter::encrypt_pubkey`] for new
//! documents, [`IncrementalWriter::encrypt`] /
//! [`IncrementalWriter::encrypt_pubkey`] for updates of encrypted documents.
//! Writers of handlers with PDF MAC support add a standalone MAC on write
//! unless [`PdfWriter::digest_aware_write`] is set.

pub mod api;
mod asn1;
pub mod cred_ser;
pub mod iso32004_asn1;
mod keys;
mod legacy;
pub mod pdfmac;
pub mod permissions;
pub mod pubkey;
mod rc4;
mod saslprep;
pub mod standard;
mod util;
mod x448;

use std::sync::{Arc, Mutex};

use lopdf::{Dictionary, Object, ObjectId};

pub use api::{
    build_crypt_filter, AuthResult, AuthStatus, CipherKind, CryptFilter, CryptFilterBuilder,
    CryptFilterConfiguration, CryptFilterRegistry, HandlerType, PdfMacStatus, SecurityHandler,
    SecurityHandlerRegistry, SecurityHandlerVersion, IDENTITY,
};
pub use cred_ser::{SerialisableCredential, SerialisedCredential};
pub use permissions::{PdfPermissions, PubKeyPermissions, StandardPermissions};
pub use pubkey::{
    CertInfo, EnvelopeKeyDecrypter, KeyDecryptError, PubKeyAdbeSubFilter, PubKeyCfData, PubKeyEncryptOptions,
    RecipientEncryptionPolicy, SimpleEnvelopeKeyDecrypter, DEFAULT_CRYPT_FILTER, DEF_EMBEDDED_FILE,
};
pub use standard::{
    LegacyEncryptOptions, Password, PasswordCredential, StandardEncryptOptions, StandardHandlerParams,
    StandardSecuritySettingsRevision, STD_CF,
};

use crate::error::{PdfError, PdfResult};
use crate::reader::{Decryptor, PdfFile};
use crate::stream::{CryptFilterDecode, DecodedStream, DuplicateFilter};
use crate::writer::{Encryptor, IncrementalWriter, PdfWriter};

/// A credential for [`SecurityHandler::authenticate`].
#[derive(Clone, Debug)]
pub enum Credential {
    /// A password (standard handler).
    Password(Password),
    /// A password credential (standard handler; carries `id1` for legacy
    /// handlers).
    PasswordCredential(PasswordCredential),
    /// A recipient key (public-key handler).
    Decrypter(Arc<dyn EnvelopeKeyDecrypter>),
    /// A serialised credential of either kind.
    Serialised(SerialisedCredential),
}

impl SecurityHandler {
    /// Authenticate with any credential (`authenticate`); `id1` is the first
    /// part of the document ID (required by legacy standard handlers).
    pub fn authenticate(&self, credential: Credential, id1: Option<&[u8]>) -> PdfResult<AuthResult> {
        let credential = match credential {
            Credential::Serialised(s) => match SerialisableCredential::deserialise(&s)? {
                SerialisableCredential::Password(p) => Credential::PasswordCredential(p),
                SerialisableCredential::PrivateKey(k) => Credential::Decrypter(Arc::new(k)),
            },
            other => other,
        };
        match (self.handler_type(), credential) {
            (HandlerType::Standard, Credential::Password(p)) => self.authenticate_password(p, id1),
            (HandlerType::Standard, Credential::PasswordCredential(p)) => self.authenticate_password_credential(&p),
            (HandlerType::Standard, Credential::Decrypter(d)) => Err(PdfError::Read(format!(
                "Standard authentication credential must be a string, byte string or _PasswordCredential, not {}.",
                d.as_serialisable()
                    .map_or("<class 'EnvelopeKeyDecrypter'>", |c| c.class_name())
            ))),
            (HandlerType::PubKey, Credential::Decrypter(d)) => self.authenticate_pubkey(d.as_ref()),
            (HandlerType::PubKey, Credential::PasswordCredential(p)) => Err(PdfError::Read(format!(
                "Pubkey authentication credential must be an instance of EnvelopeKeyDecrypter, not {}.",
                SerialisableCredential::Password(p).class_name()
            ))),
            (HandlerType::PubKey, Credential::Password(_)) => Err(PdfError::Read(
                "Pubkey authentication credential must be an instance of EnvelopeKeyDecrypter, not <class 'str'>.".into(),
            )),
            (_, Credential::Serialised(_)) => Err(PdfError::Read("Unexpected serialised credential".into())),
        }
    }

    /// The handler as a writer [`Encryptor`] (pyHanko assigns
    /// `writer.security_handler`).
    pub fn encryptor(&self) -> Box<dyn Encryptor> {
        Box::new(HandlerEncryptor {
            sh: self.clone(),
            pending_mac: Mutex::new(None),
        })
    }
}

fn is_signature_dict(d: &Dictionary) -> bool {
    matches!(d.get(b"Type"), Ok(Object::Name(n)) if n == b"Sig" || n == b"DocTimeStamp")
        || d.has(b"ByteRange")
}

fn has_crypt_filter(d: &Dictionary) -> bool {
    // references cannot be resolved here; treat them as absent
    let deref = |o: &Object| -> PdfResult<Object> {
        Ok(match o {
            Object::Reference(_) => Object::Null,
            other => other.clone(),
        })
    };
    crate::stream::has_crypt_filter(d, &deref).unwrap_or(false)
}

fn decrypt_dict(sh: &SecurityHandler, d: Dictionary, id: ObjectId, depth: usize) -> PdfResult<Dictionary> {
    let keep_contents = is_signature_dict(&d);
    let mut out = Dictionary::new();
    for (k, v) in d.into_iter() {
        let v = if keep_contents && k == b"Contents" {
            v
        } else {
            decrypt_obj(sh, v, id, depth + 1)?
        };
        out.set(k, v);
    }
    Ok(out)
}

/// `DecryptedObjectProxy.decrypted`, applied eagerly to a whole object.
fn decrypt_obj(sh: &SecurityHandler, obj: Object, id: ObjectId, depth: usize) -> PdfResult<Object> {
    if depth > 512 {
        return Err(PdfError::Read("Object nested too deeply".into()));
    }
    Ok(match obj {
        Object::String(s, f) => Object::String(sh.decrypt_string(&s, id)?, f),
        Object::Array(a) => Object::Array(
            a.into_iter()
                .map(|v| decrypt_obj(sh, v, id, depth + 1))
                .collect::<PdfResult<_>>()?,
        ),
        Object::Dictionary(d) => Object::Dictionary(decrypt_dict(sh, d, id, depth)?),
        Object::Stream(mut s) => {
            let dict = std::mem::take(&mut s.dict);
            let content = if has_crypt_filter(&dict) {
                // explicit /Crypt filters are applied while decoding
                std::mem::take(&mut s.content)
            } else {
                let embedded = matches!(dict.get(b"Type"), Ok(Object::Name(n)) if n == b"EmbeddedFile");
                sh.decrypt_stream_data(&s.content, id, embedded)?
            };
            s.dict = decrypt_dict(sh, dict, id, depth)?;
            s.content = content;
            Object::Stream(s)
        }
        other => other,
    })
}

impl Decryptor for SecurityHandler {
    fn decrypt_object(&self, obj: Object, id: ObjectId) -> PdfResult<Object> {
        decrypt_obj(self, obj, id, 0)
    }

    fn crypt_filters(&self) -> Option<&dyn CryptFilterDecode> {
        Some(self)
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

impl CryptFilterDecode for SecurityHandler {
    fn crypt_decode(&self, name: &[u8], _params: &Dictionary, data: &[u8]) -> PdfResult<Vec<u8>> {
        self.crypt_filter_decode(name.strip_prefix(b"/").unwrap_or(name), data)
    }

    fn crypt_encode(&self, name: &[u8], _params: &Dictionary, data: &[u8]) -> PdfResult<Vec<u8>> {
        self.crypt_filter_encode(name.strip_prefix(b"/").unwrap_or(name), data)
    }
}

/// The writer-side view of a security handler.
#[derive(Debug)]
struct HandlerEncryptor {
    sh: SecurityHandler,
    pending_mac: Mutex<Option<pdfmac::PendingStandaloneMac>>,
}

impl Encryptor for HandlerEncryptor {
    fn encrypt_string(&self, data: &[u8], container: ObjectId) -> PdfResult<Option<Vec<u8>>> {
        self.sh.encrypt_string(data, container)
    }

    fn encrypt_stream(&self, _dict: &Dictionary, data: &[u8], container: ObjectId) -> PdfResult<Vec<u8>> {
        self.sh.encrypt_stream_data(data, container)
    }

    fn is_authenticated(&self) -> bool {
        self.sh.is_authenticated()
    }

    fn embedded_file_filter_name(&self) -> Option<Vec<u8>> {
        let cfc = self.sh.crypt_filter_config();
        let eff = cfc.embedded_file_filter_name()?;
        (eff != cfc.stream_filter_name()).then(|| eff.to_vec())
    }

    fn crypt_filters(&self) -> Option<&dyn CryptFilterDecode> {
        Some(&self.sh)
    }

    fn standalone_mac_placeholder(&self) -> PdfResult<Option<Object>> {
        if !self.sh.pdf_mac_enabled() {
            return Ok(None);
        }
        let (placeholder, pending) = pdfmac::prepare_standalone_mac(&self.sh, "sha256")?;
        *self.pending_mac.lock().unwrap_or_else(|e| e.into_inner()) = Some(pending);
        Ok(Some(placeholder))
    }

    fn fill_standalone_mac(&self, out: &mut [u8]) -> PdfResult<()> {
        let pending = self.pending_mac.lock().unwrap_or_else(|e| e.into_inner()).take();
        match pending {
            Some(p) => p.fill(out),
            None => Ok(()),
        }
    }
}

/// Deep-resolve references in the encryption dictionary, without
/// decryption.
fn resolve_raw(reader: &PdfFile, obj: Object, depth: usize) -> PdfResult<Object> {
    if depth > 32 {
        return Err(PdfError::Read("Encryption dictionary nested too deeply".into()));
    }
    Ok(match obj {
        Object::Reference(r) => resolve_raw(reader, reader.get_object_raw(r, None)?, depth + 1)?,
        Object::Array(a) => Object::Array(
            a.into_iter()
                .map(|v| resolve_raw(reader, v, depth + 1))
                .collect::<PdfResult<_>>()?,
        ),
        Object::Dictionary(d) => {
            let mut out = Dictionary::new();
            for (k, v) in d.into_iter() {
                out.set(k, resolve_raw(reader, v, depth + 1)?);
            }
            Object::Dictionary(out)
        }
        other => other,
    })
}

/// Build and install the security handler of an encrypted document
/// (pyHanko's lazy `security_handler` property); used by the reader on the
/// first access to an encrypted object.
pub(crate) fn default_decryptor(reader: &PdfFile) -> PdfResult<Arc<dyn Decryptor>> {
    match reader.security_handler()? {
        Some(sh) => Ok(Arc::new(sh)),
        None => Err(PdfError::Read("Document is not encrypted".into())),
    }
}

/// The encryptor for an incremental update of `reader`, if it is encrypted.
pub(crate) fn encryptor_for_update(reader: &PdfFile) -> PdfResult<Option<(ObjectId, Box<dyn Encryptor>)>> {
    let Some(enc) = reader.trailer().raw_get(b"Encrypt", None) else {
        return Ok(None);
    };
    let Object::Reference(r) = enc else {
        return Err(PdfError::Read("Encryption settings must be an indirect reference".into()));
    };
    let Some(sh) = reader.security_handler()? else {
        return Ok(None);
    };
    Ok(Some((r, sh.encryptor())))
}

impl PdfFile {
    /// The security handler (`security_handler`): built from the `/Encrypt`
    /// dictionary on first use and installed as the decryptor; `None` if the
    /// document is not encrypted.
    pub fn security_handler(&self) -> PdfResult<Option<SecurityHandler>> {
        if !self.encrypted() {
            return Ok(None);
        }
        if let Some(d) = self.decryptor() {
            if let Some(sh) = d.as_any().and_then(|a| a.downcast_ref::<SecurityHandler>()) {
                return Ok(Some(sh.clone()));
            }
        }
        let dict = self
            .encrypt_dict()?
            .ok_or_else(|| PdfError::Read("Document is not encrypted".into()))?;
        let Object::Dictionary(dict) = resolve_raw(self, Object::Dictionary(dict), 0)? else {
            return Err(PdfError::Read("Encryption settings must be a dictionary".into()));
        };
        let sh = SecurityHandler::build(&dict)?;
        self.set_decryptor(Some(Arc::new(sh.clone())));
        Ok(Some(sh))
    }

    /// Install a security handler built elsewhere (e.g. with a custom
    /// [`SecurityHandlerRegistry`]).
    pub fn set_security_handler(&self, sh: SecurityHandler) {
        self.set_decryptor(Some(Arc::new(sh)));
    }

    /// Authenticate with a password (standard handler; `decrypt`), then
    /// validate the PDF MAC if the document has one or the permissions
    /// require one.
    pub fn decrypt(&self, password: impl Into<Password>) -> PdfResult<AuthResult> {
        let sh = self.security_handler()?.ok_or_else(|| {
            PdfError::Read("Security handler is of type 'NoneType', not StandardSecurityHandler".into())
        })?;
        if sh.handler_type() != HandlerType::Standard {
            return Err(PdfError::Read(
                "Security handler is of type 'PubKeySecurityHandler', not StandardSecurityHandler".into(),
            ));
        }
        let id1 = self.document_id()?.0;
        let res = sh.authenticate_password(password, Some(&id1))?;
        self.validate_pdf_mac_after_auth(&sh, res)
    }

    /// Authenticate with a recipient credential (public-key handler;
    /// `decrypt_pubkey`), then validate the PDF MAC if required.
    pub fn decrypt_pubkey(&self, credential: &dyn EnvelopeKeyDecrypter) -> PdfResult<AuthResult> {
        let sh = self.security_handler()?.ok_or_else(|| {
            PdfError::Read("Security handler is of type 'NoneType', not PubKeySecurityHandler".into())
        })?;
        if sh.handler_type() != HandlerType::PubKey {
            return Err(PdfError::Read(
                "Security handler is of type 'StandardSecurityHandler', not PubKeySecurityHandler".into(),
            ));
        }
        let res = sh.authenticate_pubkey(credential)?;
        self.validate_pdf_mac_after_auth(&sh, res)
    }

    /// `_validate_pdf_mac`: a MAC is validated whenever there are traces of
    /// one (`/AuthCode` in the trailer, a KDF salt) or the permissions
    /// require one; validation failure turns the result into a failure.
    pub fn validate_pdf_mac_after_auth(&self, sh: &SecurityHandler, prelim: AuthResult) -> PdfResult<AuthResult> {
        let traces_of_mac = self.trailer_view().has(b"AuthCode") || sh.pdf_mac_enabled();
        let mac_required = prelim.permission_flags.is_some_and(PdfPermissions::mac_required);
        if prelim.status == AuthStatus::Failed || !(traces_of_mac || mac_required) {
            return Ok(prelim);
        }
        match pdfmac::validate_pdf_mac(self, pdfmac::ALLOWED_MD_ALGS) {
            Ok(()) => Ok(AuthResult {
                mac_status: PdfMacStatus::Successful,
                ..prelim
            }),
            Err(pdfmac::MacValidationFailure::Invalid(reason)) => {
                log::warn!("Failed to validate MAC: {reason}");
                Ok(AuthResult {
                    status: AuthStatus::Failed,
                    permission_flags: None,
                    mac_status: PdfMacStatus::Failed,
                    mac_failure_reason: Some(reason),
                })
            }
            Err(pdfmac::MacValidationFailure::Error(e)) => Err(e),
        }
    }
}

impl PdfWriter {
    /// Use `sh` to encrypt the output (`_assign_security_handler`): adds the
    /// `/Encrypt` dictionary, raises the output version and registers the
    /// handler's developer extensions.
    pub fn assign_security_handler(&mut self, sh: &SecurityHandler) -> PdfResult<ObjectId> {
        let dict = sh.as_pdf_object()?;
        let id = self.set_encryption(Object::Dictionary(dict), sh.encryptor())?;
        self.encrypt_metadata = sh.encrypt_metadata();
        if let Some(v) = sh.get_min_pdf_version() {
            self.ensure_output_version(v)?;
        }
        for ext in sh.get_extensions() {
            self.register_extension(&ext)?;
        }
        Ok(id)
    }

    /// Encrypt with PDF 2.0 password encryption (AES-256; `encrypt`),
    /// with the default options (PDF MAC enabled).
    pub fn encrypt(&mut self, owner_pass: &str, user_pass: Option<&str>) -> PdfResult<SecurityHandler> {
        self.encrypt_with(owner_pass, user_pass, StandardEncryptOptions::default())
    }

    /// [`Self::encrypt`] with explicit options.
    pub fn encrypt_with(
        &mut self,
        owner_pass: &str,
        user_pass: Option<&str>,
        opts: StandardEncryptOptions,
    ) -> PdfResult<SecurityHandler> {
        let sh = SecurityHandler::build_from_pw(owner_pass, user_pass.map(Password::from), opts)?;
        self.assign_security_handler(&sh)?;
        Ok(sh)
    }

    /// Encrypt with PDF 2.0 public-key encryption (`encrypt_pubkey`);
    /// `recipients` are DER certificates.
    pub fn encrypt_pubkey(&mut self, recipients: &[Vec<u8>]) -> PdfResult<SecurityHandler> {
        self.encrypt_pubkey_with(recipients, PubKeyEncryptOptions::default())
    }

    /// [`Self::encrypt_pubkey`] with explicit options.
    pub fn encrypt_pubkey_with(&mut self, recipients: &[Vec<u8>], opts: PubKeyEncryptOptions) -> PdfResult<SecurityHandler> {
        self.output_version = (2, 0);
        let sh = SecurityHandler::build_from_certs(recipients, opts)?;
        self.assign_security_handler(&sh)?;
        Ok(sh)
    }
}

impl IncrementalWriter {
    fn reuse_encryption(&mut self) -> PdfResult<()> {
        if let Some((r, enc)) = encryptor_for_update(self.base())? {
            self.set_existing_encryption(r, enc);
            if let Some(sh) = self.base().security_handler()? {
                self.encrypt_metadata = sh.encrypt_metadata();
            }
        }
        Ok(())
    }

    /// Authenticate to the original document with its user password, so the
    /// update is encrypted the same way (`encrypt`).
    pub fn encrypt(&mut self, user_pwd: impl Into<Password>) -> PdfResult<AuthResult> {
        let result = self.base().decrypt(user_pwd)?;
        self.reuse_encryption()?;
        Ok(result)
    }

    /// Authenticate to a public-key encrypted original (`encrypt_pubkey`).
    pub fn encrypt_pubkey(&mut self, credential: &dyn EnvelopeKeyDecrypter) -> PdfResult<AuthResult> {
        let result = self.base().decrypt_pubkey(credential)?;
        self.reuse_encryption()?;
        Ok(result)
    }
}

/// Add an explicit `/Crypt` filter to a stream (`add_crypt_filter`):
/// `name` must be known to `handler`.
pub fn add_crypt_filter(
    stream: &mut DecodedStream,
    name: &str,
    params: Option<Dictionary>,
    handler: Option<&SecurityHandler>,
) -> PdfResult<()> {
    let Some(handler) = handler else {
        return Err(PdfError::Stream("There is no security handler around".into()));
    };
    let n = name.trim_start_matches('/');
    if !handler.crypt_filter_config().contains(n.as_bytes()) {
        return Err(PdfError::Stream(format!(
            "The crypt filter /{n} is not known to the security handler."
        )));
    }
    let mut params = params.unwrap_or_default();
    params.set("Type", Object::Name(b"CryptFilterDecodeParms".to_vec()));
    params.set("Name", Object::Name(n.as_bytes().to_vec()));
    stream.apply_filter("Crypt", Some(params), DuplicateFilter::Error)
}

/// Encode a stream, applying explicit `/Crypt` filters with `handler`
/// (`StreamObject.encoded_data` with a handler attached).
pub fn encode_stream_with(stream: &DecodedStream, handler: &SecurityHandler) -> PdfResult<lopdf::Stream> {
    let content = crate::stream::encode_stream_data(&stream.dict, &stream.data, &crate::stream::no_deref, Some(handler))?;
    Ok(lopdf::Stream {
        dict: stream.dict.clone(),
        content,
        allows_compression: false,
        start_position: None,
    })
}
