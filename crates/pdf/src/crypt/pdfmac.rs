// Derived from pyHanko `pdf_utils/crypt/pdfmac.py` (MIT, see LICENSE-pyHanko),
// with the parts of `sign/general.py` (`byte_range_digest`,
// `find_unique_cms_attribute`) and `sign/validation/generic_cms.py`
// (`validate_algorithm_protection`) that it uses.

//! PDF MAC (ISO 32004): creation and validation of MAC tokens (CMS
//! `AuthenticatedData` over the document's byte range), stored standalone in
//! the trailer's `/AuthCode` dictionary or as an unsigned attribute of a
//! signature.
//!
//! Token construction goes through [`PdfMacTokenHandlerFactory`], whose
//! default methods mirror the methods of pyHanko's `PdfMacTokenHandler`;
//! tests override single steps to produce defective tokens, like pyHanko's
//! test suite does with subclasses.

use std::sync::Arc;

use hmac::{KeyInit, Mac};
use lopdf::{Dictionary, Object};

use super::asn1::{self, tag, AlgId, Tlv};
use super::iso32004_asn1::{
    PdfMacIntegrityInfo, PDF_MAC_DATA, PDF_MAC_INTEGRITY_INFO, PDF_MAC_WRAP_KDF,
};
use super::util::{aes_key_unwrap, aes_key_wrap, random_bytes};
use crate::error::{PdfError, PdfResult};
use crate::extensions::{DevExtensionMultivalued, DeveloperExtension};
use crate::reader::PdfFile;

/// `ISO32004` developer extension.
pub fn iso32004_extension() -> DeveloperExtension {
    let mut e = DeveloperExtension::new("ISO_", "2.0", 32004);
    e.extension_revision = Some(":2024".into());
    e.url = Some("https://www.iso.org/standard/45877.html".into());
    e.compare_by_level = false;
    e.multivalued = DevExtensionMultivalued::Always;
    e
}

/// Permissible message digest algorithms in PDF MAC tokens
/// (`ALLOWED_MD_ALGS`).
pub const ALLOWED_MD_ALGS: &[&str] = &[
    "sha256", "sha3_256", "sha384", "sha3_384", "sha512", "sha3_512", "shake256",
];

pub(crate) mod oids {
    pub const AUTHENTICATED_DATA: &str = "1.2.840.113549.1.9.16.1.2";
    pub const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
    pub const HMAC_SHA256: &str = "1.2.840.113549.2.9";
    pub const AES256_WRAP: &str = "2.16.840.1.101.3.4.1.45";
    pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
    pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
    pub const CMS_ALGORITHM_PROTECTION: &str = "1.2.840.113549.1.9.52";
}

const DIGESTS: &[(&str, &str)] = &[
    ("md5", "1.2.840.113549.2.5"),
    ("sha1", "1.3.14.3.2.26"),
    ("sha224", "2.16.840.1.101.3.4.2.4"),
    ("sha256", "2.16.840.1.101.3.4.2.1"),
    ("sha384", "2.16.840.1.101.3.4.2.2"),
    ("sha512", "2.16.840.1.101.3.4.2.3"),
    ("sha512_224", "2.16.840.1.101.3.4.2.5"),
    ("sha512_256", "2.16.840.1.101.3.4.2.6"),
    ("sha3_224", "2.16.840.1.101.3.4.2.7"),
    ("sha3_256", "2.16.840.1.101.3.4.2.8"),
    ("sha3_384", "2.16.840.1.101.3.4.2.9"),
    ("sha3_512", "2.16.840.1.101.3.4.2.10"),
    ("shake128", "2.16.840.1.101.3.4.2.11"),
    ("shake256", "2.16.840.1.101.3.4.2.12"),
];

/// OID of a digest algorithm named as in asn1crypto.
pub fn digest_oid(name: &str) -> Option<&'static str> {
    DIGESTS.iter().find(|(n, _)| *n == name).map(|(_, o)| *o)
}

/// asn1crypto name of a digest OID (the dotted OID if unknown).
pub fn digest_name(oid: &str) -> String {
    DIGESTS
        .iter()
        .find(|(_, o)| *o == oid)
        .map_or_else(|| oid.to_string(), |(n, _)| (*n).to_string())
}

/// Hash with a digest algorithm named as in asn1crypto
/// (`get_pyca_cryptography_hash`); SHAKE256 yields 64 bytes.
pub fn md_hash(md_algorithm: &str, chunks: &[&[u8]]) -> PdfResult<Vec<u8>> {
    fn run<D: sha2::Digest>(chunks: &[&[u8]]) -> Vec<u8> {
        let mut h = D::new();
        for c in chunks {
            h.update(c);
        }
        h.finalize().to_vec()
    }
    fn run10<D: sha3::Digest>(chunks: &[&[u8]]) -> Vec<u8> {
        let mut h = D::new();
        for c in chunks {
            sha3::Digest::update(&mut h, c);
        }
        h.finalize().to_vec()
    }
    Ok(match md_algorithm {
        "sha1" => run::<sha1::Sha1>(chunks),
        "sha224" => run::<sha2::Sha224>(chunks),
        "sha256" => run::<sha2::Sha256>(chunks),
        "sha384" => run::<sha2::Sha384>(chunks),
        "sha512" => run::<sha2::Sha512>(chunks),
        "sha512_224" => run::<sha2::Sha512_224>(chunks),
        "sha512_256" => run::<sha2::Sha512_256>(chunks),
        "sha3_224" => run10::<sha3::Sha3_224>(chunks),
        "sha3_256" => run10::<sha3::Sha3_256>(chunks),
        "sha3_384" => run10::<sha3::Sha3_384>(chunks),
        "sha3_512" => run10::<sha3::Sha3_512>(chunks),
        "shake256" => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut h = sha3::Shake256::default();
            for c in chunks {
                h.update(c);
            }
            let mut out = vec![0u8; 64];
            h.finalize_xof().read(&mut out);
            out
        }
        other => {
            return Err(PdfError::Value(format!(
                "Unsupported digest algorithm: {other}"
            )))
        }
    })
}

/// A CMS attribute with the given values (`simple_cms_attribute`, and
/// multi-valued variants).
pub fn cms_attribute(attr_type: &str, values: &[&[u8]]) -> Vec<u8> {
    asn1::seq(&[&asn1::oid(attr_type), &asn1::cons(tag::SET, values)])
}

/// A `CMSAttributes` value (`SET OF Attribute`), in the given order.
pub fn cms_attributes(attrs: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = attrs.iter().map(Vec::as_slice).collect();
    asn1::cons(tag::SET, &refs)
}

/// `CMSAlgorithmProtection` with a digest and (optionally) a MAC algorithm.
pub fn cms_algorithm_protection(digest_algorithm: &[u8], mac_algorithm: Option<&[u8]>) -> Vec<u8> {
    match mac_algorithm {
        Some(m) => {
            let mut implicit = m.to_vec();
            if let Some(b) = implicit.first_mut() {
                *b = 0xa2;
            }
            asn1::seq(&[digest_algorithm, &implicit])
        }
        None => asn1::seq(&[digest_algorithm]),
    }
}

/// `HmacAlgorithm({'algorithm': 'sha256'})`.
pub fn hmac_sha256_algorithm() -> Vec<u8> {
    asn1::alg_id(oids::HMAC_SHA256, None)
}

/// `DigestAlgorithm({'algorithm': name})`.
pub fn digest_algorithm(name: &str) -> PdfResult<Vec<u8>> {
    let oid = digest_oid(name)
        .ok_or_else(|| PdfError::Value(format!("Unknown digest algorithm {name}")))?;
    Ok(asn1::alg_id(oid, None))
}

/// A `PasswordRecipientInfo` for the wrapped MAC key, optionally without the
/// `pdfMacWrapKdf` key derivation algorithm.
pub fn password_recipient_info(encrypted_key: &[u8], with_kdf: bool) -> Vec<u8> {
    let mut body = asn1::uint(0);
    if with_kdf {
        body.extend(asn1::tlv(0xa0, &asn1::oid(PDF_MAC_WRAP_KDF)));
    }
    body.extend(asn1::alg_id(oids::AES256_WRAP, None));
    body.extend(asn1::octets(encrypted_key));
    asn1::tlv(0xa3, &body)
}

/// The fields of a CMS `AuthenticatedData`, as encoded values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthDataParts {
    /// Version.
    pub version: u64,
    /// Encoded `RecipientInfo` values.
    pub recipient_infos: Vec<Vec<u8>>,
    /// Encoded MAC algorithm identifier.
    pub mac_algorithm: Vec<u8>,
    /// Encoded digest algorithm identifier (`[1] IMPLICIT` on output).
    pub digest_algorithm: Vec<u8>,
    /// Encapsulated content type (dotted OID).
    pub encap_content_type: String,
    /// Encapsulated content (octet string contents).
    pub encap_content: Vec<u8>,
    /// Authenticated attributes as `SET OF` encoding.
    pub auth_attrs: Option<Vec<u8>>,
    /// MAC value.
    pub mac: Vec<u8>,
    /// Unauthenticated attributes as `SET OF` encoding.
    pub unauth_attrs: Option<Vec<u8>>,
}

fn retag(der: &[u8], t: u8) -> Vec<u8> {
    let mut v = der.to_vec();
    if let Some(b) = v.first_mut() {
        *b = t;
    }
    v
}

impl AuthDataParts {
    /// The `AuthenticatedData` encoding.
    pub fn to_der(&self) -> Vec<u8> {
        let ris: Vec<&[u8]> = self.recipient_infos.iter().map(Vec::as_slice).collect();
        let eci = asn1::seq(&[
            &asn1::oid(&self.encap_content_type),
            &asn1::tlv(0xa0, &asn1::octets(&self.encap_content)),
        ]);
        let mut body = asn1::uint(self.version);
        body.extend(asn1::cons(tag::SET, &ris));
        body.extend_from_slice(&self.mac_algorithm);
        body.extend(retag(&self.digest_algorithm, 0xa1));
        body.extend(eci);
        if let Some(a) = &self.auth_attrs {
            body.extend(retag(a, 0xa2));
        }
        body.extend(asn1::octets(&self.mac));
        if let Some(u) = &self.unauth_attrs {
            body.extend(retag(u, 0xa3));
        }
        asn1::tlv(tag::SEQUENCE, &body)
    }

    /// The token: a `ContentInfo` of type `authenticated_data`.
    pub fn to_content_info(&self) -> Vec<u8> {
        asn1::seq(&[
            &asn1::oid(oids::AUTHENTICATED_DATA),
            &asn1::tlv(0xa0, &self.to_der()),
        ])
    }
}

/// `PdfMacTokenHandler._derive_mac_kek`: HKDF-SHA256 with info `PDFMAC`.
pub fn derive_mac_kek(file_encryption_key: &[u8], kdf_salt: &[u8]) -> PdfResult<Vec<u8>> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(kdf_salt), file_encryption_key);
    let mut okm = vec![0u8; 32];
    hk.expand(b"PDFMAC", &mut okm)
        .map_err(|_| PdfError::Value("HKDF output length error".into()))?;
    Ok(okm)
}

/// Overridable steps of PDF MAC token creation (pyHanko's
/// `PdfMacTokenHandler` methods; implementors override what they need).
pub trait PdfMacTokenHandlerFactory: Send + Sync + std::fmt::Debug {
    /// `from_key_mat`: the MAC key encryption key and digest algorithm.
    fn derive_key_material(
        &self,
        file_encryption_key: &[u8],
        kdf_salt: &[u8],
        md_algorithm: &str,
    ) -> PdfResult<(Vec<u8>, String)> {
        Ok((
            derive_mac_kek(file_encryption_key, kdf_salt)?,
            md_algorithm.to_string(),
        ))
    }

    /// `_get_mac_keying_info`: the MAC key and its `RecipientInfo`.
    fn get_mac_keying_info(
        &self,
        h: &PdfMacTokenHandler,
        dry_run: bool,
    ) -> PdfResult<(Vec<u8>, Vec<u8>)> {
        default_get_mac_keying_info(h, dry_run)
    }

    /// `_format_message`: the encoded `PdfMacIntegrityInfo` and its digest.
    fn format_message(
        &self,
        h: &PdfMacTokenHandler,
        document_digest: &[u8],
        signature_digest: Option<&[u8]>,
    ) -> PdfResult<(Vec<u8>, Vec<u8>)> {
        default_format_message(h, document_digest, signature_digest)
    }

    /// `_format_auth_attrs`: the authenticated attributes (`SET OF`).
    fn format_auth_attrs(
        &self,
        h: &PdfMacTokenHandler,
        message_digest: &[u8],
    ) -> PdfResult<Vec<u8>> {
        default_format_auth_attrs(h, message_digest)
    }

    /// `_format_auth_data`.
    fn format_auth_data(
        &self,
        h: &PdfMacTokenHandler,
        recipient_info: Vec<u8>,
        message_bytes: Vec<u8>,
        auth_attrs: Vec<u8>,
        mac: Vec<u8>,
    ) -> PdfResult<AuthDataParts> {
        default_format_auth_data(h, recipient_info, message_bytes, auth_attrs, mac)
    }

    /// `compute_mac`: HMAC-SHA256.
    fn compute_mac(
        &self,
        _h: &PdfMacTokenHandler,
        mac_key: &[u8],
        data_to_mac: &[u8],
    ) -> PdfResult<Vec<u8>> {
        hmac_sha256(mac_key, data_to_mac)
    }

    /// `build_pdfmac_token`: the token as a DER `ContentInfo`.
    fn build_pdfmac_token(
        &self,
        h: &PdfMacTokenHandler,
        document_digest: &[u8],
        signature_digest: Option<&[u8]>,
        dry_run: bool,
    ) -> PdfResult<Vec<u8>> {
        Ok(
            default_build_auth_data(self, h, document_digest, signature_digest, dry_run)?
                .to_content_info(),
        )
    }
}

/// The default token handler (`PdfMacTokenHandler` itself).
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultPdfMacTokenHandler;

impl PdfMacTokenHandlerFactory for DefaultPdfMacTokenHandler {}

fn hmac_sha256(key: &[u8], data: &[u8]) -> PdfResult<Vec<u8>> {
    let mut m = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|_| PdfError::Value("Invalid HMAC key".into()))?;
    m.update(data);
    Ok(m.finalize().into_bytes().to_vec())
}

/// Default `_get_mac_keying_info`.
pub fn default_get_mac_keying_info(
    h: &PdfMacTokenHandler,
    dry_run: bool,
) -> PdfResult<(Vec<u8>, Vec<u8>)> {
    let mac_key = if dry_run {
        vec![0u8; 32]
    } else {
        random_bytes(32)?
    };
    let encrypted_key = aes_key_wrap(&h.mac_kek, &mac_key)?;
    Ok((mac_key, password_recipient_info(&encrypted_key, true)))
}

/// Default `_format_message`.
pub fn default_format_message(
    h: &PdfMacTokenHandler,
    document_digest: &[u8],
    signature_digest: Option<&[u8]>,
) -> PdfResult<(Vec<u8>, Vec<u8>)> {
    let message = PdfMacIntegrityInfo {
        version: 0,
        data_digest: document_digest.to_vec(),
        signature_digest: signature_digest.map(<[u8]>::to_vec),
    }
    .to_der();
    let digest = md_hash(&h.md_algorithm, &[&message])?;
    Ok((message, digest))
}

/// Default `_format_auth_attrs`.
pub fn default_format_auth_attrs(
    h: &PdfMacTokenHandler,
    message_digest: &[u8],
) -> PdfResult<Vec<u8>> {
    let protection = cms_algorithm_protection(
        &digest_algorithm(&h.md_algorithm)?,
        Some(&hmac_sha256_algorithm()),
    );
    Ok(cms_attributes(&[
        cms_attribute(oids::CONTENT_TYPE, &[&asn1::oid(PDF_MAC_INTEGRITY_INFO)]),
        cms_attribute(oids::MESSAGE_DIGEST, &[&asn1::octets(message_digest)]),
        cms_attribute(oids::CMS_ALGORITHM_PROTECTION, &[&protection]),
    ]))
}

/// Default `_format_auth_data`.
pub fn default_format_auth_data(
    h: &PdfMacTokenHandler,
    recipient_info: Vec<u8>,
    message_bytes: Vec<u8>,
    auth_attrs: Vec<u8>,
    mac: Vec<u8>,
) -> PdfResult<AuthDataParts> {
    Ok(AuthDataParts {
        version: 0,
        recipient_infos: vec![recipient_info],
        mac_algorithm: hmac_sha256_algorithm(),
        digest_algorithm: digest_algorithm(&h.md_algorithm)?,
        encap_content_type: PDF_MAC_INTEGRITY_INFO.into(),
        encap_content: message_bytes,
        auth_attrs: Some(auth_attrs),
        mac,
        unauth_attrs: None,
    })
}

/// Default `build_pdfmac_token`, before wrapping in a `ContentInfo`.
pub fn default_build_auth_data<F: PdfMacTokenHandlerFactory + ?Sized>(
    f: &F,
    h: &PdfMacTokenHandler,
    document_digest: &[u8],
    signature_digest: Option<&[u8]>,
    dry_run: bool,
) -> PdfResult<AuthDataParts> {
    let (mac_key, ri) = f.get_mac_keying_info(h, dry_run)?;
    let (message_bytes, message_digest) = f.format_message(h, document_digest, signature_digest)?;
    let auth_attrs = f.format_auth_attrs(h, &message_digest)?;
    let mac = f.compute_mac(h, &mac_key, &auth_attrs)?;
    f.format_auth_data(h, ri, message_bytes, auth_attrs, mac)
}

/// Creates and validates PDF MAC tokens (`PdfMacTokenHandler`).
#[derive(Clone, Debug)]
pub struct PdfMacTokenHandler {
    /// The MAC key encryption key.
    pub mac_kek: Vec<u8>,
    /// The message digest algorithm (asn1crypto name).
    pub md_algorithm: String,
    hooks: Arc<dyn PdfMacTokenHandlerFactory>,
}

impl PdfMacTokenHandler {
    /// A handler with explicit key material and the default steps.
    pub fn new(mac_kek: Vec<u8>, md_algorithm: &str) -> Self {
        Self {
            mac_kek,
            md_algorithm: md_algorithm.to_string(),
            hooks: Arc::new(DefaultPdfMacTokenHandler),
        }
    }

    /// `from_key_mat` with the given (or default) steps.
    pub fn from_key_mat(
        file_encryption_key: &[u8],
        kdf_salt: &[u8],
        md_algorithm: &str,
        hooks: Option<Arc<dyn PdfMacTokenHandlerFactory>>,
    ) -> PdfResult<Self> {
        let hooks = hooks.unwrap_or_else(|| Arc::new(DefaultPdfMacTokenHandler));
        let (mac_kek, md) =
            hooks.derive_key_material(file_encryption_key, kdf_salt, md_algorithm)?;
        Ok(Self {
            mac_kek,
            md_algorithm: md,
            hooks,
        })
    }

    /// Build a token (`build_pdfmac_token`), as DER.
    pub fn build_pdfmac_token(
        &self,
        document_digest: &[u8],
        signature_digest: Option<&[u8]>,
        dry_run: bool,
    ) -> PdfResult<Vec<u8>> {
        self.hooks
            .build_pdfmac_token(self, document_digest, signature_digest, dry_run)
    }

    /// Size of a token in bytes (`determine_token_size`).
    pub fn determine_token_size(&self, include_signature_digest: bool) -> PdfResult<usize> {
        let dummy = md_hash(&self.md_algorithm, &[])?;
        let sig = include_signature_digest.then_some(dummy.as_slice());
        Ok(self.build_pdfmac_token(&dummy, sig, true)?.len())
    }
}

/// Outcome of a failed MAC validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacValidationFailure {
    /// The MAC is invalid (`PdfMacValidationError`); authentication fails.
    Invalid(String),
    /// Another error (unsupported algorithm, malformed DER, ...), raised as
    /// an error by `decrypt`.
    Error(PdfError),
}

impl From<PdfError> for MacValidationFailure {
    fn from(e: PdfError) -> Self {
        Self::Error(e)
    }
}

type MacResult<T> = Result<T, MacValidationFailure>;

fn invalid<T>(msg: impl Into<String>) -> MacResult<T> {
    Err(MacValidationFailure::Invalid(msg.into()))
}

enum AttrLookup<'a> {
    Found(Tlv<'a>),
    Missing,
    Multiple,
}

/// `find_unique_cms_attribute` over a `SET OF Attribute` encoding.
fn find_unique_attr<'a>(attrs: Option<&'a [u8]>, oid: &str) -> PdfResult<AttrLookup<'a>> {
    let Some(attrs) = attrs else {
        return Ok(AttrLookup::Missing);
    };
    let set = Tlv::parse_exact(attrs)?;
    let mut found = Vec::new();
    for attr in set.children()? {
        let ch = attr.children()?;
        if ch.first().map(|t| t.oid()).transpose()?.as_deref() == Some(oid) {
            if let Some(vals) = ch.get(1) {
                found.extend(vals.children()?);
            }
        }
    }
    Ok(match found.len() {
        0 => AttrLookup::Missing,
        1 => AttrLookup::Found(found[0]),
        _ => AttrLookup::Multiple,
    })
}

/// A parsed `AuthenticatedData`, keeping the encodings.
struct AuthData<'a> {
    recipient_infos: Vec<Tlv<'a>>,
    mac_algorithm: Tlv<'a>,
    digest_algorithm: Option<Vec<u8>>,
    encap_content_type: String,
    encap_content: Vec<u8>,
    auth_attrs: Option<Vec<u8>>,
    mac: &'a [u8],
    has_unauth_attrs: bool,
}

fn parse_auth_data(ad: Tlv<'_>) -> PdfResult<AuthData<'_>> {
    let bad = || PdfError::Value("Malformed AuthenticatedData".into());
    let mut it = ad.children()?.into_iter().peekable();
    it.next()
        .filter(|t| t.tag == tag::INTEGER)
        .ok_or_else(bad)?;
    if it.peek().is_some_and(|t| t.tag == 0xa0) {
        it.next();
    }
    let ris = it.next().filter(|t| t.tag == tag::SET).ok_or_else(bad)?;
    let mac_algorithm = it
        .next()
        .filter(|t| t.tag == tag::SEQUENCE)
        .ok_or_else(bad)?;
    let digest_algorithm = if it.peek().is_some_and(|t| t.tag == 0xa1) {
        it.next().map(|t| t.retagged(tag::SEQUENCE))
    } else {
        None
    };
    let eci = it
        .next()
        .filter(|t| t.tag == tag::SEQUENCE)
        .ok_or_else(bad)?;
    let eci_ch = eci.children()?;
    let encap_content_type = eci_ch.first().ok_or_else(bad)?.oid()?;
    let encap_content = match eci_ch.get(1) {
        Some(t) if t.tag == 0xa0 => {
            let inner = t.explicit_inner()?;
            if inner.tag != tag::OCTET_STRING {
                return Err(bad());
            }
            inner.value.to_vec()
        }
        _ => Vec::new(),
    };
    let auth_attrs = if it.peek().is_some_and(|t| t.tag == 0xa2) {
        it.next().map(|t| t.retagged(tag::SET))
    } else {
        None
    };
    let mac = it
        .next()
        .filter(|t| t.tag == tag::OCTET_STRING)
        .ok_or_else(bad)?
        .value;
    let has_unauth_attrs = it.next().is_some_and(|t| t.tag == 0xa3);
    Ok(AuthData {
        recipient_infos: ris.children()?,
        mac_algorithm,
        digest_algorithm,
        encap_content_type,
        encap_content,
        auth_attrs,
        mac,
        has_unauth_attrs,
    })
}

impl PdfMacTokenHandler {
    /// Validation handler for a token (`for_validation`): checks the MAC
    /// and digest algorithms.
    fn for_validation(
        file_encryption_key: &[u8],
        kdf_salt: &[u8],
        auth_data: &AuthData<'_>,
        allowed_mds: &[&str],
    ) -> MacResult<Self> {
        let mac_algo = AlgId::parse(&auth_data.mac_algorithm)?;
        if mac_algo.oid != oids::HMAC_SHA256 {
            return Err(PdfError::NotImplemented(
                "Only HMAC-SHA256 is currently supported for PDF MAC tokens".into(),
            )
            .into());
        }
        let md = md_name_of(auth_data)?;
        if !allowed_mds.contains(&md.as_str()) {
            return Err(PdfError::Value(format!(
                "DisallowedAlgorithmError: Digest algorithm {md} is not allowed in PDF MAC tokens"
            ))
            .into());
        }
        Ok(Self::from_key_mat(
            file_encryption_key,
            kdf_salt,
            &md,
            None,
        )?)
    }

    fn retrieve_mac_key(&self, recipient_infos: &[Tlv<'_>]) -> MacResult<Vec<u8>> {
        let pwri = match recipient_infos {
            [ri] if ri.tag == 0xa3 => *ri,
            _ => {
                return invalid(
                    "PDF MAC requires exactly one recipientInfo, which must be of PasswordRecipientInfo type",
                )
            }
        };
        let mut it = pwri.children()?.into_iter().peekable();
        it.next();
        let kdf = if it.peek().is_some_and(|t| t.tag == 0xa0) {
            it.next()
        } else {
            None
        };
        let kdf_ok = match kdf {
            Some(k) => {
                AlgId::parse(&Tlv::parse_exact(&k.retagged(tag::SEQUENCE))?)?.oid
                    == PDF_MAC_WRAP_KDF
            }
            None => false,
        };
        if !kdf_ok {
            return invalid(
                "PDF MAC tokens must have their key derivation algorithm explicitly identified as pdfMacWrapKdf.",
            );
        }
        let kea = AlgId::parse(
            &it.next()
                .ok_or_else(|| PdfError::Value("Malformed PWRI".into()))?,
        )?;
        if kea.oid != oids::AES256_WRAP {
            return Err(PdfError::NotImplemented(format!(
                "PDF MAC only supports unpadded 256-bit AES key wrapping for key encryption; not '{}'.",
                kea.oid
            ))
            .into());
        }
        let ek = it
            .next()
            .filter(|t| t.tag == tag::OCTET_STRING)
            .ok_or_else(|| PdfError::Value("Malformed PWRI".into()))?;
        match aes_key_unwrap(&self.mac_kek, ek.value, false) {
            Ok(k) => Ok(k),
            Err(_) => invalid("Failed to unwrap MAC key"),
        }
    }

    fn validate_auth_attrs(&self, auth_data: &AuthData<'_>) -> MacResult<()> {
        let attrs = auth_data.auth_attrs.as_deref();
        // (a) contentType
        match find_unique_attr(attrs, oids::CONTENT_TYPE)? {
            AttrLookup::Found(ct) => {
                let v = ct.oid()?;
                if v != PDF_MAC_INTEGRITY_INFO {
                    return invalid(format!(
                        "The content type attribute of a PDF MAC token must be id-pdfMacIntegrityInfo, not '{v}'"
                    ));
                }
            }
            _ => {
                return invalid(
                    "Content type not found in authenticated attributes, or multiple content-type attributes present.",
                )
            }
        }
        // (b) CMSAlgorithmProtection
        match find_unique_attr(attrs, oids::CMS_ALGORITHM_PROTECTION)? {
            AttrLookup::Missing => {}
            AttrLookup::Multiple => {
                return invalid(
                    "CMS structural error: Multiple CMS algorithm protection attributes present",
                )
            }
            AttrLookup::Found(prot) => {
                let pfx = "CMS alg protection validation error: ";
                let ch = prot.children()?;
                let digest =
                    AlgId::parse(ch.first().ok_or_else(|| {
                        PdfError::Value("Malformed CMSAlgorithmProtection".into())
                    })?)?;
                let claimed_digest = match &auth_data.digest_algorithm {
                    Some(d) => Some(Tlv::parse_exact(d)?),
                    None => None,
                };
                let claimed_digest = claimed_digest.as_ref().map(AlgId::parse).transpose()?;
                if claimed_digest.as_ref().is_none_or(|c| !digest.same_as(c)) {
                    return invalid(format!(
                        "{pfx}Digest algorithm does not match CMS algorithm protection attribute."
                    ));
                }
                let mac = ch
                    .iter()
                    .find(|t| t.tag == 0xa2)
                    .map(|t| t.retagged(tag::SEQUENCE));
                let Some(mac) = mac else {
                    return invalid(format!(
                        "{pfx}CMS algorithm protection attribute not valid for authenticated data"
                    ));
                };
                let mac_t = Tlv::parse_exact(&mac)?;
                if !AlgId::parse(&mac_t)?.same_as(&AlgId::parse(&auth_data.mac_algorithm)?) {
                    return invalid(format!(
                        "{pfx}MAC mechanism does not match CMS algorithm protection attribute."
                    ));
                }
            }
        }
        // (c) messageDigest
        let md = md_hash(&self.md_algorithm, &[&auth_data.encap_content])?;
        match find_unique_attr(attrs, oids::MESSAGE_DIGEST)? {
            AttrLookup::Found(v) if v.tag == tag::OCTET_STRING => {
                if v.value != md.as_slice() {
                    return invalid(
                        "Value of messageDigest attribute does not match hash of encapsulated content.",
                    );
                }
                Ok(())
            }
            AttrLookup::Found(_) => Err(PdfError::Value("Malformed messageDigest attribute".into()).into()),
            _ => invalid(
                "Message digest not found in authenticated attributes, or multiple messageDigest attributes present.",
            ),
        }
    }

    fn validate_and_extract_encap_content(
        &self,
        auth_data: &AuthData<'_>,
    ) -> MacResult<PdfMacIntegrityInfo> {
        if auth_data.has_unauth_attrs {
            return invalid("PDF MAC tokens cannot have unauthenticated attributes");
        }
        let mac_key = self.retrieve_mac_key(&auth_data.recipient_infos)?;
        let attrs = auth_data.auth_attrs.as_deref().ok_or_else(|| {
            PdfError::Value("PDF MAC token without authenticated attributes".into())
        })?;
        let computed = hmac_sha256(&mac_key, attrs)?;
        if !constant_time_eq(&computed, auth_data.mac) {
            return invalid("PDF MAC token has invalid MAC");
        }
        self.validate_auth_attrs(auth_data)?;
        if auth_data.encap_content_type != PDF_MAC_INTEGRITY_INFO {
            return invalid(
                "The content type of the encapsulated content in a PDF MAC token must be id-pdfMacIntegrityInfo.",
            );
        }
        Ok(PdfMacIntegrityInfo::from_der(&auth_data.encap_content)?)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn md_name_of(auth_data: &AuthData<'_>) -> PdfResult<String> {
    let d = auth_data
        .digest_algorithm
        .as_ref()
        .ok_or_else(|| PdfError::Value("PDF MAC token without digest algorithm".into()))?;
    Ok(digest_name(&AlgId::parse(&Tlv::parse_exact(d)?)?.oid).to_lowercase())
}

fn validate_integrity_info(
    info: &PdfMacIntegrityInfo,
    document_digest: &[u8],
    signature_digest: Option<&[u8]>,
) -> MacResult<()> {
    if info.data_digest != document_digest {
        return invalid("Document digest does not match value in PdfMacIntegrityInfo");
    }
    match (signature_digest, &info.signature_digest) {
        (None, Some(_)) => invalid("PdfMacIntegrityInfo contains an unexpected signature digest"),
        (None, None) => Ok(()),
        (Some(_), None) => invalid("Could not find signature digest in PdfMacIntegrityInfo"),
        (Some(expected), Some(claimed)) if expected != claimed.as_slice() => {
            invalid("Signature digest does not match value in PdfMacIntegrityInfo")
        }
        (Some(_), Some(_)) => Ok(()),
    }
}

fn int_of(o: &Object) -> Option<i64> {
    match o {
        Object::Integer(i) => Some(*i),
        _ => None,
    }
}

/// `_validate_byte_range`: the range must cover the whole file except the
/// hex string holding the token.
fn validate_byte_range(
    dict: &Dictionary,
    file_len: usize,
    payload_len: usize,
    what: &str,
) -> MacResult<Vec<i64>> {
    let Ok(Object::Array(br)) = dict.get(b"ByteRange") else {
        return invalid(format!("No sensible /ByteRange found in {what}"));
    };
    let vals: Option<Vec<i64>> = br.iter().map(int_of).collect();
    if let Some(v) = vals.as_ref().filter(|v| v.len() == 4) {
        let (o1, l1, o2, l2) = (v[0], v[1], v[2], v[3]);
        let value_lit_len = 2 * payload_len as i64 + 2;
        if o1 == 0 && l1 + value_lit_len == o2 && file_len as i64 == l1 + l2 + value_lit_len {
            return Ok(v.clone());
        }
    }
    invalid("PDF MAC token must have /ByteRange covering the entire file")
}

/// `byte_range_digest`: digest of the given `(offset, length)` pairs.
pub fn byte_range_digest(
    data: &[u8],
    byte_range: &[i64],
    md_algorithm: &str,
) -> PdfResult<Vec<u8>> {
    let mut chunks = Vec::new();
    for pair in byte_range.chunks(2) {
        let [lo, len] = pair else {
            return Err(PdfError::Value("Byte range must consist of pairs".into()));
        };
        let lo = usize::try_from(*lo)
            .map_err(|_| PdfError::Value("Negative byte range offset".into()))?;
        let len = usize::try_from(*len)
            .map_err(|_| PdfError::Value("Negative byte range length".into()))?;
        let end = lo
            .checked_add(len)
            .filter(|e| *e <= data.len())
            .ok_or_else(|| {
                PdfError::Read("Byte range extends beyond the end of the file".into())
            })?;
        chunks.push(&data[lo..end]);
    }
    md_hash(md_algorithm, &chunks)
}

/// `_extract_mac_in_sig`: the token and the signature value.
fn extract_mac_in_sig(
    sig_dict: &Dictionary,
    file_len: usize,
) -> MacResult<(Vec<u8>, Vec<u8>, Vec<i64>)> {
    let Ok(Object::String(sig_bytes, _)) = sig_dict.get(b"Contents") else {
        return invalid("Failed to retrieve signature contents");
    };
    let (sig_ci, _) = Tlv::parse(sig_bytes)?;
    let byte_range = validate_byte_range(sig_dict, file_len, sig_bytes.len(), "AuthCode")?;
    let signer_info = (|| -> PdfResult<Option<Tlv<'_>>> {
        let ch = sig_ci.children()?;
        if ch.first().map(|t| t.oid()).transpose()?.as_deref() != Some(oids::SIGNED_DATA) {
            return Ok(None);
        }
        let Some(sd) = ch.get(1).filter(|t| t.tag == 0xa0) else {
            return Ok(None);
        };
        let sd = sd.explicit_inner()?;
        let Some(sis) = sd.children()?.into_iter().rev().find(|t| t.tag == tag::SET) else {
            return Ok(None);
        };
        let sis = sis.children()?;
        Ok(match sis.as_slice() {
            [one] => Some(*one),
            _ => None,
        })
    })()?;
    let Some(si) = signer_info else {
        return invalid(
            "Signature dictionary must contain a SignedData message with exactly 1 signerInfo.",
        );
    };
    let si_ch = si.children()?;
    let signature = si_ch
        .iter()
        .find(|t| t.tag == tag::OCTET_STRING)
        .ok_or_else(|| PdfError::Value("SignerInfo without signature".into()))?
        .value
        .to_vec();
    let unsigned = si_ch
        .iter()
        .find(|t| t.tag == 0xa1)
        .map(|t| t.retagged(tag::SET));
    match find_unique_attr(unsigned.as_deref(), PDF_MAC_DATA)? {
        AttrLookup::Found(ci) => Ok((ci.raw.to_vec(), signature, byte_range)),
        _ => invalid("Signature must have exactly 1 pdfMacData unsigned attribute"),
    }
}

/// Validate the PDF MAC of a document (`validate_pdf_mac`), with the
/// file encryption key and KDF salt of its (authenticated) security handler.
pub fn validate_pdf_mac(
    reader: &PdfFile,
    allowed_mds: &[&str],
) -> Result<(), MacValidationFailure> {
    let trailer = reader.trailer_view();
    let ac_dict = match trailer.get(b"AuthCode") {
        Ok(Object::Reference(_)) => return invalid("AuthCode dictionary cannot be indirect"),
        Ok(Object::Dictionary(d)) => d.clone(),
        _ => return invalid("Failed to locate AuthCode dictionary"),
    };
    let location = match ac_dict.get(b"MACLocation") {
        Ok(Object::Name(n)) => n.clone(),
        _ => Vec::new(),
    };
    let data = reader.bytes();
    let file_len = data.len();
    let (mac_ci, byte_range, signature_value) = match location.as_slice() {
        b"Standalone" => {
            let Ok(Object::String(mac_bytes, _)) = ac_dict.get(b"MAC") else {
                return invalid("Failed to retrieve standalone MAC value");
            };
            let (ci, _) = Tlv::parse(mac_bytes)?;
            let (payload_len, token_len) = (mac_bytes.len(), ci.raw.len());
            if payload_len != token_len {
                return invalid(format!(
                    "Standalone MACs must not have trailing CMS data: payload is {payload_len} bytes long, but token is {token_len} bytes."
                ));
            }
            let br = validate_byte_range(&ac_dict, file_len, payload_len, "AuthCode")?;
            (ci.raw.to_vec(), br, None)
        }
        b"AttachedToSig" => {
            let sig_ref = match ac_dict.get(b"SigObjRef") {
                Ok(Object::Reference(r)) => *r,
                Ok(_) => return invalid("Value of /SigObjRef entry must be an indirect reference"),
                Err(_) => return invalid("/AttachedToSig requires /SigObjRef"),
            };
            let Object::Dictionary(sig_dict) = reader.get_object_raw(sig_ref, None)? else {
                return invalid("/SigObjRef does not point to a dictionary");
            };
            let (ci, sig, br) = extract_mac_in_sig(&sig_dict, file_len)?;
            (ci, br, Some(sig))
        }
        _ => return invalid("Failed to locate MAC in document"),
    };
    let ci = Tlv::parse_exact(&mac_ci)?;
    let ci_ch = ci.children()?;
    if ci_ch.first().map(|t| t.oid()).transpose()?.as_deref() != Some(oids::AUTHENTICATED_DATA) {
        return invalid("MAC tokens must be of CMS type AuthenticatedData");
    }
    let ad = ci_ch
        .get(1)
        .filter(|t| t.tag == 0xa0)
        .ok_or_else(|| PdfError::Value("ContentInfo without content".into()))?
        .explicit_inner()?;
    let auth_data = parse_auth_data(ad)?;
    let md_algorithm = md_name_of(&auth_data)?;
    let document_digest = byte_range_digest(data, &byte_range, &md_algorithm)?;
    let signature_digest = signature_value
        .as_ref()
        .map(|s| md_hash(&md_algorithm, &[s]))
        .transpose()?;
    let sh = reader
        .security_handler()?
        .ok_or_else(|| PdfError::Generic("Document is not encrypted".into()))?;
    let salt = match sh.get_kdf_salt() {
        Ok(s) => s,
        Err(e) if e.is_read_error() => return invalid("Error retrieving salt"),
        Err(e) => return Err(e.into()),
    };
    let fek = sh.get_file_encryption_key()?;
    let handler = PdfMacTokenHandler::for_validation(&fek, &salt, &auth_data, allowed_mds)?;
    let info = handler.validate_and_extract_encap_content(&auth_data)?;
    validate_integrity_info(&info, &document_digest, signature_digest.as_deref())
}

/// A standalone MAC being written: the handler and the placeholder layout.
#[derive(Debug)]
pub(crate) struct PendingStandaloneMac {
    handler: PdfMacTokenHandler,
    placeholder: Vec<u8>,
    br_placeholder: Vec<u8>,
    token_size: usize,
}

const BR_PLACEHOLDER: i64 = 9_999_999_999;

/// Prepare the `/AuthCode` placeholder of a standalone MAC
/// (`add_standalone_mac`, first half).
pub(crate) fn prepare_standalone_mac(
    sh: &super::api::SecurityHandler,
    md_algorithm: &str,
) -> PdfResult<(Object, PendingStandaloneMac)> {
    let fek = sh.get_file_encryption_key()?;
    let salt = sh.get_kdf_salt()?;
    let handler =
        PdfMacTokenHandler::from_key_mat(&fek, &salt, md_algorithm, sh.mac_token_handler())?;
    let token_size = handler.determine_token_size(false)?;
    let br = Object::Array(vec![
        Object::Integer(0),
        Object::Integer(BR_PLACEHOLDER),
        Object::Integer(BR_PLACEHOLDER),
        Object::Integer(BR_PLACEHOLDER),
    ]);
    let mut d = Dictionary::new();
    d.set(
        "MAC",
        Object::String(vec![0u8; token_size], lopdf::StringFormat::Hexadecimal),
    );
    d.set("ByteRange", br.clone());
    d.set("MACLocation", Object::Name(b"Standalone".to_vec()));
    let obj = Object::Dictionary(d);
    Ok((
        obj.clone(),
        PendingStandaloneMac {
            handler,
            placeholder: crate::generic::object_to_bytes(&obj),
            br_placeholder: crate::generic::object_to_bytes(&br),
            token_size,
        },
    ))
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

impl PendingStandaloneMac {
    /// Fill the byte range and the token into the written file
    /// (`add_standalone_mac`, second half).
    pub(crate) fn fill(&self, out: &mut [u8]) -> PdfResult<()> {
        let not_found =
            || PdfError::Write("Could not locate the PDF MAC placeholder in the output".into());
        let start = rfind(out, &self.placeholder).ok_or_else(not_found)?;
        let region = &out[start..start + self.placeholder.len()];
        let br_off = start + rfind(region, &self.br_placeholder).ok_or_else(not_found)?;
        let hex_len = 2 * self.token_size + 2;
        let hex_placeholder: Vec<u8> = std::iter::once(b'<')
            .chain(std::iter::repeat_n(b'0', 2 * self.token_size))
            .chain(std::iter::once(b'>'))
            .collect();
        let mac_off = start + rfind(region, &hex_placeholder).ok_or_else(not_found)?;
        let (sig_start, sig_end) = (mac_off, mac_off + hex_len);
        let eof = out.len();
        let filled = format!("[0 {} {} {}]", sig_start, sig_end, eof - sig_end).into_bytes();
        if filled.len() > self.br_placeholder.len() {
            return Err(PdfError::Write(
                "Byte range does not fit in its placeholder".into(),
            ));
        }
        let br_slot = &mut out[br_off..br_off + self.br_placeholder.len()];
        br_slot.fill(b' ');
        br_slot[..filled.len()].copy_from_slice(&filled);
        let br = [0, sig_start as i64, sig_end as i64, (eof - sig_end) as i64];
        let digest = byte_range_digest(out, &br, &self.handler.md_algorithm)?;
        let token = self.handler.build_pdfmac_token(&digest, None, false)?;
        let hex: Vec<u8> = token
            .iter()
            .flat_map(|b| format!("{b:02X}").into_bytes())
            .collect();
        if hex.len() > 2 * self.token_size {
            return Err(PdfError::Write(format!(
                "Final ByteRange payload larger than expected: allocated {} bytes, but contents required {} bytes.",
                2 * self.token_size,
                hex.len()
            )));
        }
        out[sig_start + 1..sig_start + 1 + hex.len()].copy_from_slice(&hex);
        Ok(())
    }
}
