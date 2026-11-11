// Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_pdfmac.py`
// (MIT, see LICENSE-pyHanko). One Rust test per upstream test function;
// parametrized cases run in a loop.
//
// pyHanko overrides `PdfMacTokenHandler` methods in subclasses to produce
// defective tokens; here the same steps are overridden in implementations
// of `PdfMacTokenHandlerFactory`. Cases that put the MAC into a signature
// (`MacLocation.IN_SIG`) need a signer (lane D): until it lands, their
// documents are produced by pyHanko 0.38.1 (`oracle/gen_pdfmac_sig_fixtures.py`,
// self-checked against pyHanko's verdict) and validated here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::crypt::*;
use common::*;
use sigis_pdf::crypt::pdfmac::{
    cms_algorithm_protection, cms_attribute, cms_attributes, default_build_auth_data,
    default_format_auth_attrs, default_format_auth_data, default_format_message,
    default_get_mac_keying_info, derive_mac_kek, digest_algorithm, hmac_sha256_algorithm, md_hash,
    password_recipient_info, AuthDataParts, PdfMacTokenHandler, PdfMacTokenHandlerFactory,
};
use sigis_pdf::crypt::{
    AuthResult, Credential, HandlerType, PdfMacStatus, PubKeyEncryptOptions, SecurityHandler,
    StandardEncryptOptions,
};
use sigis_pdf::generic::pdf_name;
use sigis_pdf::lopdf::{Dictionary, Object};
use sigis_pdf::stream::DecodedStream;
use sigis_pdf::{IncrementalWriter, PdfError, PdfFile, PdfFileWriter, PdfHandler, PdfHandlerExt};

const DUMMY_PASSWORD: &str = "secret";

const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_ALG_PROTECTION: &str = "1.2.840.113549.1.9.52";
const OID_PDF_MAC_INTEGRITY_INFO: &str = "1.0.32004.1.0";
const OID_DATA: &str = "1.2.840.113549.1.7.1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncryptionType {
    Standard,
    PubKey,
}

const ENCRYPTION_TYPES: [EncryptionType; 2] = [EncryptionType::Standard, EncryptionType::PubKey];

// --- small DER builders for the hand-made tokens --------------------------

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        let b = value.len().to_be_bytes();
        let skip = b.iter().take_while(|x| **x == 0).count();
        out.push(0x80 | (b.len() - skip) as u8);
        out.extend_from_slice(&b[skip..]);
    }
    out.extend_from_slice(value);
    out
}

fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut body = Vec::new();
    let mut push = |mut v: u64| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        tmp.reverse();
        body.extend(tmp);
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    tlv(0x06, &body)
}

fn octets(v: &[u8]) -> Vec<u8> {
    tlv(0x04, v)
}

// --- sample document --------------------------------------------------------

/// `init_sample_doc`.
fn init_sample_doc(encryption_type: EncryptionType) -> (PdfFileWriter, SecurityHandler) {
    let mut w = PdfFileWriter::new(false, true).unwrap();
    let mut font = Dictionary::new();
    font.set("Type", pdf_name("/Font"));
    font.set("Subtype", pdf_name("/Type1"));
    font.set("BaseFont", pdf_name("/Courier"));
    let font_ref = w.add_object(Object::Dictionary(font)).unwrap();
    let mut fonts = Dictionary::new();
    fonts.set("F1", Object::Reference(font_ref));
    let mut resources = Dictionary::new();
    resources.set("Font", Object::Dictionary(fonts));
    let content = b"\n    BT\n        /F1 12 Tf 40 700 Td 12 TL\n        (Hello ISO/TS 32004!) Tj\n    ET\n    ";
    let stream = DecodedStream::new(Dictionary::new(), content.to_vec())
        .to_stream()
        .unwrap();
    let contents = w.add_object(Object::Stream(stream)).unwrap();
    let mut page = Dictionary::new();
    page.set("Type", pdf_name("/Page"));
    page.set("Contents", Object::Reference(contents));
    page.set(
        "MediaBox",
        Object::Array(vec![
            0.into(),
            0.into(),
            Object::Real(595.28),
            Object::Real(841.89),
        ]),
    );
    page.set("Resources", Object::Dictionary(resources));
    w.insert_page(page, None).unwrap();
    let sh = match encryption_type {
        EncryptionType::PubKey => {
            let sh = SecurityHandler::build_from_certs(
                &[pubkey_test_decrypter().cert_info().der().to_vec()],
                PubKeyEncryptOptions {
                    compat_entries: false,
                    ..Default::default()
                },
            )
            .unwrap();
            w.assign_security_handler(&sh).unwrap();
            sh
        }
        EncryptionType::Standard => w
            .encrypt_with(
                DUMMY_PASSWORD,
                None,
                StandardEncryptOptions {
                    compat_entries: false,
                    ..Default::default()
                },
            )
            .unwrap(),
    };
    (w, sh)
}

/// `_dummy_decrypt`; with `ignore_mac`, the handler is authenticated
/// without MAC validation.
fn dummy_decrypt(r: &PdfFile, ignore_mac: bool) -> Result<AuthResult, PdfError> {
    let sh = r.security_handler()?.unwrap();
    match (sh.handler_type(), ignore_mac) {
        (HandlerType::PubKey, false) => r.decrypt_pubkey(&pubkey_test_decrypter()),
        (HandlerType::Standard, false) => r.decrypt(DUMMY_PASSWORD),
        (HandlerType::PubKey, true) => sh.authenticate(
            Credential::Decrypter(Arc::new(pubkey_test_decrypter())),
            None,
        ),
        (HandlerType::Standard, true) => {
            let id1 = r.document_id()?.0;
            sh.authenticate_password(DUMMY_PASSWORD, Some(&id1))
        }
    }
}

fn iso_extension_levels(r: &PdfFile) -> Vec<i64> {
    let root = r.root().unwrap();
    let exts = r.get_dict(&root, b"Extensions").unwrap().unwrap();
    let iso = r.get_array(&exts, b"ISO_").unwrap().unwrap();
    iso.iter()
        .map(|e| {
            match as_dict(r.resolve(e).unwrap())
                .get(b"ExtensionLevel")
                .unwrap()
            {
                Object::Integer(i) => *i,
                other => panic!("{other:?}"),
            }
        })
        .collect()
}

/// `pdf_mac_good`.
#[track_caller]
fn assert_mac_good(out: &[u8]) {
    let r = read(out);
    let result = dummy_decrypt(&r, false).unwrap();
    assert_eq!(
        result.mac_status,
        PdfMacStatus::Successful,
        "{:?}",
        result.mac_failure_reason
    );
    assert!(iso_extension_levels(&r).contains(&32004));
}

/// `pdfmac_known_bad_case`: `re.search(error_message, reason, re.I)`.
#[track_caller]
fn assert_mac_bad(out: &[u8], error_message: &str) {
    let r = read(out);
    let result = dummy_decrypt(&r, false).unwrap();
    assert_eq!(result.mac_status, PdfMacStatus::Failed);
    assert_eq!(result.status, sigis_pdf::crypt::AuthStatus::Failed);
    let reason = result.mac_failure_reason.unwrap();
    assert!(
        search(&error_message.to_lowercase(), &reason.to_lowercase()),
        "Error {reason:?} did not match {error_message:?}"
    );
}

fn write_with_handler(
    encryption_type: EncryptionType,
    handler: Option<Arc<dyn PdfMacTokenHandlerFactory>>,
) -> Vec<u8> {
    let (mut w, sh) = init_sample_doc(encryption_type);
    sh.set_mac_token_handler(handler);
    w.write().unwrap()
}

/// A pyHanko-signed document of a `MacLocation.IN_SIG` case.
fn sig_fixture(test: &str, enc: &str) -> Vec<u8> {
    sigis_testdata::read(&["lanes", "b", "pdfmac-sig", &format!("{test}-{enc}.pdf")])
}

/// Check the pyHanko-signed documents of an IN_SIG case (`None`: good).
fn check_in_sig(test: &str, encs: &[&str], error_message: Option<&str>) {
    for enc in encs {
        let out = sig_fixture(test, enc);
        match error_message {
            None => assert_mac_good(&out),
            Some(m) => assert_mac_bad(&out, m),
        }
    }
}

const BOTH: &[&str] = &["standard", "pubkey"];

/// `pdfmac_with_handler(error_message, only_location=STANDALONE)`.
fn check_standalone_with_handler(handler: Arc<dyn PdfMacTokenHandlerFactory>, error_message: &str) {
    for et in ENCRYPTION_TYPES {
        let out = write_with_handler(et, Some(handler.clone()));
        assert_mac_bad(&out, error_message);
    }
}

/// `pdfmac_with_handler(error_message)`: standalone MACs written here,
/// MACs in signatures from the pyHanko fixtures.
fn check_with_handler(
    test: &str,
    handler: Arc<dyn PdfMacTokenHandlerFactory>,
    error_message: &str,
) {
    for et in ENCRYPTION_TYPES {
        let out = write_with_handler(et, Some(handler.clone()));
        assert_mac_bad(&out, error_message);
    }
    check_in_sig(test, BOTH, Some(error_message));
}

#[test]
fn test_simple_mac() {
    for et in ENCRYPTION_TYPES {
        let out = write_with_handler(et, None);
        assert_mac_good(&out);
    }
}

#[derive(Debug)]
struct Md(&'static str);

impl PdfMacTokenHandlerFactory for Md {
    fn derive_key_material(
        &self,
        fek: &[u8],
        kdf_salt: &[u8],
        _md: &str,
    ) -> Result<(Vec<u8>, String), PdfError> {
        Ok((derive_mac_kek(fek, kdf_salt)?, self.0.to_string()))
    }
}

#[test]
fn test_simple_mac_nondefault_hash() {
    for et in ENCRYPTION_TYPES {
        let out = write_with_handler(et, Some(Arc::new(Md("sha384"))));
        assert_mac_good(&out);
    }
}

#[test]
fn test_sign_crypt_aes256_with_mac() {
    // signing: pyHanko fixture until lane D lands; the signature validation
    // (`val_trusted`) is pending lane E
    check_in_sig("test_sign_crypt_aes256_with_mac", BOTH, None);
}

#[test]
fn test_signature_nondefault_hash() {
    check_in_sig("test_signature_nondefault_hash", BOTH, None);
}

#[test]
#[ignore = "pending: needs lane D PAdES signing with a TSA and lane E AdES validation"]
fn test_pdf_mac_pades() {}

#[test]
fn test_pdf_mac_timestamp() {
    // the upstream test ignores its encryption_type parameter
    check_in_sig("test_pdf_mac_timestamp", &["standard"], None);
}

/// Overrides `_format_auth_attrs` with a fixed attribute builder.
type AttrsFn = Box<dyn Fn(&PdfMacTokenHandler, &[u8]) -> Vec<u8> + Send + Sync>;

struct Attrs(AttrsFn);

impl std::fmt::Debug for Attrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Attrs")
    }
}

impl PdfMacTokenHandlerFactory for Attrs {
    fn format_auth_attrs(
        &self,
        h: &PdfMacTokenHandler,
        message_digest: &[u8],
    ) -> Result<Vec<u8>, PdfError> {
        Ok((self.0)(h, message_digest))
    }
}

fn attrs(
    f: impl Fn(&PdfMacTokenHandler, &[u8]) -> Vec<u8> + Send + Sync + 'static,
) -> Arc<dyn PdfMacTokenHandlerFactory> {
    Arc::new(Attrs(Box::new(f)))
}

fn content_type_attr(ct: &str) -> Vec<u8> {
    cms_attribute(OID_CONTENT_TYPE, &[&oid(ct)])
}

fn md_attr(md: &[u8]) -> Vec<u8> {
    cms_attribute(OID_MESSAGE_DIGEST, &[&octets(md)])
}

fn protection(h: &PdfMacTokenHandler) -> Vec<u8> {
    cms_algorithm_protection(
        &digest_algorithm(&h.md_algorithm).unwrap(),
        Some(&hmac_sha256_algorithm()),
    )
}

#[test]
fn test_cms_algorithm_protection_attr_missing() {
    // this is actually allowed, it's a 'should' in ISO 32004
    let h = attrs(|_, md| {
        cms_attributes(&[content_type_attr(OID_PDF_MAC_INTEGRITY_INFO), md_attr(md)])
    });
    for et in ENCRYPTION_TYPES {
        let out = write_with_handler(et, Some(h.clone()));
        assert_mac_good(&out);
    }
}

#[test]
fn test_standalone_mac_tamper() {
    for et in ENCRYPTION_TYPES {
        let mut out = write_with_handler(et, None);
        // in the middle of the second line of the header, so pretty benign
        out[10] = 0x01;
        assert_mac_bad(&out, "Document digest does not match");
    }
}

/// Overrides `_get_mac_keying_info`.
struct KeyingInfo(fn(Vec<u8>) -> Vec<u8>);

impl std::fmt::Debug for KeyingInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyingInfo")
    }
}

impl PdfMacTokenHandlerFactory for KeyingInfo {
    fn get_mac_keying_info(
        &self,
        h: &PdfMacTokenHandler,
        dry_run: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), PdfError> {
        let (mac_key, ri) = default_get_mac_keying_info(h, dry_run)?;
        Ok((mac_key, (self.0)(ri)))
    }
}

/// The wrapped key: the last 40 bytes of the `PasswordRecipientInfo`.
fn wrapped_key(ri: &[u8]) -> Vec<u8> {
    ri[ri.len() - 40..].to_vec()
}

#[test]
fn test_alter_key() {
    check_with_handler(
        "test_alter_key",
        Arc::new(KeyingInfo(|ri| {
            // by altering the key record, we mess up the unwrapping later
            let mut ek = wrapped_key(&ri);
            ek.reverse();
            password_recipient_info(&ek, true)
        })),
        "Failed to unwrap",
    );
}

#[derive(Debug)]
struct AlterSalt;

impl PdfMacTokenHandlerFactory for AlterSalt {
    fn derive_key_material(
        &self,
        fek: &[u8],
        _kdf_salt: &[u8],
        md: &str,
    ) -> Result<(Vec<u8>, String), PdfError> {
        // do calculations with a different salt
        Ok((derive_mac_kek(fek, &[0u8; 32])?, md.to_string()))
    }
}

#[test]
fn test_alter_salt() {
    check_with_handler("test_alter_salt", Arc::new(AlterSalt), "Failed to unwrap");
}

#[derive(Debug)]
struct AppendAuthAttr;

impl PdfMacTokenHandlerFactory for AppendAuthAttr {
    fn compute_mac(
        &self,
        h: &PdfMacTokenHandler,
        mac_key: &[u8],
        _data: &[u8],
    ) -> Result<Vec<u8>, PdfError> {
        // the MAC is computed over a different set of attributes
        sigis_pdf::crypt::pdfmac::DefaultPdfMacTokenHandler.compute_mac(
            h,
            mac_key,
            &cms_attributes(&[]),
        )
    }
}

#[test]
fn test_append_auth_attr() {
    check_with_handler(
        "test_append_auth_attr",
        Arc::new(AppendAuthAttr),
        "token has invalid MAC",
    );
}

#[test]
fn test_cms_algorithm_protection_attr_multival() {
    check_with_handler(
        "test_cms_algorithm_protection_attr_multival",
        attrs(|h, md| {
            let p = protection(h);
            cms_attributes(&[
                content_type_attr(OID_PDF_MAC_INTEGRITY_INFO),
                md_attr(md),
                cms_attribute(OID_ALG_PROTECTION, &[&p, &p]),
            ])
        }),
        "Multiple CMS algorithm protection attributes present",
    );
}

#[test]
fn test_cms_algorithm_protection_attr_duplicated() {
    check_with_handler(
        "test_cms_algorithm_protection_attr_duplicated",
        attrs(|h, md| {
            let p = protection(h);
            cms_attributes(&[
                content_type_attr(OID_PDF_MAC_INTEGRITY_INFO),
                md_attr(md),
                cms_attribute(OID_ALG_PROTECTION, &[&p]),
                cms_attribute(OID_ALG_PROTECTION, &[&p]),
            ])
        }),
        "Multiple CMS algorithm protection attributes",
    );
}

#[test]
fn test_cms_algorithm_protection_digest_algo_mismatch() {
    check_with_handler(
        "test_cms_algorithm_protection_digest_algo_mismatch",
        attrs(|_, md| {
            let p = cms_algorithm_protection(
                &digest_algorithm("sha3_512").unwrap(),
                Some(&hmac_sha256_algorithm()),
            );
            cms_attributes(&[
                content_type_attr(OID_PDF_MAC_INTEGRITY_INFO),
                md_attr(md),
                cms_attribute(OID_ALG_PROTECTION, &[&p]),
            ])
        }),
        "Digest algorithm does not match",
    );
}

#[test]
fn test_cms_algorithm_protection_mac_algo_mismatch() {
    check_with_handler(
        "test_cms_algorithm_protection_mac_algo_mismatch",
        attrs(|h, md| {
            // HmacAlgorithm({'algorithm': 'sha512'})
            let hmac_sha512 = tlv(0x30, &oid("1.2.840.113549.2.11"));
            let p = cms_algorithm_protection(
                &digest_algorithm(&h.md_algorithm).unwrap(),
                Some(&hmac_sha512),
            );
            cms_attributes(&[
                content_type_attr(OID_PDF_MAC_INTEGRITY_INFO),
                md_attr(md),
                cms_attribute(OID_ALG_PROTECTION, &[&p]),
            ])
        }),
        "MAC mechanism does not match",
    );
}

#[test]
fn test_cms_algorithm_protection_mac_algo_missing() {
    check_with_handler(
        "test_cms_algorithm_protection_mac_algo_missing",
        attrs(|h, md| {
            let p = cms_algorithm_protection(&digest_algorithm(&h.md_algorithm).unwrap(), None);
            cms_attributes(&[
                content_type_attr(OID_PDF_MAC_INTEGRITY_INFO),
                md_attr(md),
                cms_attribute(OID_ALG_PROTECTION, &[&p]),
            ])
        }),
        "attribute not valid for authenticated data",
    );
}

#[test]
fn test_duplicate_content_type_attr() {
    check_with_handler(
        "test_duplicate_content_type_attr",
        attrs(|_, md| {
            cms_attributes(&[
                cms_attribute(
                    OID_CONTENT_TYPE,
                    &[&oid(OID_DATA), &oid(OID_PDF_MAC_INTEGRITY_INFO)],
                ),
                md_attr(md),
            ])
        }),
        "Content type not found in authenticated attributes",
    );
}

#[test]
fn test_no_content_type_attr() {
    check_with_handler(
        "test_no_content_type_attr",
        attrs(|_, md| cms_attributes(&[md_attr(md)])),
        "Content type not found in authenticated attributes",
    );
}

#[test]
fn test_wrong_content_type_attr() {
    check_with_handler(
        "test_wrong_content_type_attr",
        attrs(|_, md| cms_attributes(&[content_type_attr(OID_DATA), md_attr(md)])),
        "content type.*must be id-pdfMacIntegrityInfo",
    );
}

#[test]
fn test_no_md() {
    check_with_handler(
        "test_no_md",
        attrs(|_, _| cms_attributes(&[content_type_attr(OID_PDF_MAC_INTEGRITY_INFO)])),
        "Message digest not found",
    );
}

#[test]
fn test_bad_md() {
    check_with_handler(
        "test_bad_md",
        attrs(|_, _| {
            let dummy = md_hash("sha256", &[b"\xde\xad\xbe\xef"]).unwrap();
            cms_attributes(&[
                content_type_attr(OID_PDF_MAC_INTEGRITY_INFO),
                md_attr(&dummy),
            ])
        }),
        "messageDigest attribute does not match",
    );
}

/// Overrides `build_pdfmac_token` on top of the default parts.
struct Token(fn(&mut AuthDataParts, bool) -> Option<Vec<u8>>);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token")
    }
}

impl PdfMacTokenHandlerFactory for Token {
    fn build_pdfmac_token(
        &self,
        h: &PdfMacTokenHandler,
        document_digest: &[u8],
        signature_digest: Option<&[u8]>,
        dry_run: bool,
    ) -> Result<Vec<u8>, PdfError> {
        let mut parts =
            default_build_auth_data(self, h, document_digest, signature_digest, dry_run)?;
        Ok((self.0)(&mut parts, dry_run).unwrap_or_else(|| parts.to_content_info()))
    }
}

fn data_content_type_attrs() -> Vec<u8> {
    cms_attributes(&[content_type_attr(OID_DATA)])
}

#[test]
fn test_with_unauth_attrs() {
    check_with_handler(
        "test_with_unauth_attrs",
        Arc::new(Token(|parts, _| {
            // doesn't have to make any sense
            parts.unauth_attrs = Some(data_content_type_attrs());
            None
        })),
        "PDF MAC tokens cannot have unauthenticated attributes",
    );
}

#[test]
fn test_no_kdf() {
    check_with_handler(
        "test_no_kdf",
        Arc::new(KeyingInfo(|ri| {
            password_recipient_info(&wrapped_key(&ri), false)
        })),
        "key derivation.*identified as pdfMacWrapKdf",
    );
}

/// Overrides `_format_auth_data`.
type AuthDataFn = fn(&PdfMacTokenHandler, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) -> AuthDataParts;

struct AuthData(AuthDataFn);

impl std::fmt::Debug for AuthData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthData")
    }
}

impl PdfMacTokenHandlerFactory for AuthData {
    fn format_auth_data(
        &self,
        h: &PdfMacTokenHandler,
        recipient_info: Vec<u8>,
        message_bytes: Vec<u8>,
        auth_attrs: Vec<u8>,
        mac: Vec<u8>,
    ) -> Result<AuthDataParts, PdfError> {
        Ok((self.0)(h, recipient_info, message_bytes, auth_attrs, mac))
    }
}

#[test]
fn test_too_many_recipients() {
    check_with_handler(
        "test_too_many_recipients",
        Arc::new(AuthData(|h, ri, msg, attrs, mac| {
            let mut ad = default_format_auth_data(h, ri, msg, attrs, mac).unwrap();
            let first = ad.recipient_infos[0].clone();
            ad.recipient_infos.push(first);
            ad
        })),
        "requires exactly one recipientInfo",
    );
}

#[test]
fn test_wrong_recipient_type() {
    check_with_handler(
        "test_wrong_recipient_type",
        Arc::new(AuthData(|h, _ri, msg, attrs, mac| {
            // ori [4] { oriType 2.999, oriValue OCTET STRING deadbeef }
            let ori = tlv(0xa4, &[oid("2.999"), octets(b"\xde\xad\xbe\xef")].concat());
            default_format_auth_data(h, ori, msg, attrs, mac).unwrap()
        })),
        "must be.*PasswordRecipientInfo",
    );
}

#[derive(Debug)]
struct WrongEncContentType;

impl PdfMacTokenHandlerFactory for WrongEncContentType {
    fn format_auth_attrs(
        &self,
        h: &PdfMacTokenHandler,
        _message_digest: &[u8],
    ) -> Result<Vec<u8>, PdfError> {
        let md = md_hash(&h.md_algorithm, &[b"\xde\xad\xbe\xef"])?;
        default_format_auth_attrs(h, &md)
    }

    fn format_auth_data(
        &self,
        h: &PdfMacTokenHandler,
        recipient_info: Vec<u8>,
        message_bytes: Vec<u8>,
        auth_attrs: Vec<u8>,
        mac: Vec<u8>,
    ) -> Result<AuthDataParts, PdfError> {
        let mut ad = default_format_auth_data(h, recipient_info, message_bytes, auth_attrs, mac)?;
        ad.encap_content_type = OID_DATA.into();
        ad.encap_content = b"\xde\xad\xbe\xef".to_vec();
        Ok(ad)
    }
}

#[test]
fn test_wrong_enc_content_type() {
    check_with_handler(
        "test_wrong_enc_content_type",
        Arc::new(WrongEncContentType),
        "must be.*pdfMacIntegrityInfo",
    );
}

#[test]
fn test_wrong_token_content_type() {
    check_with_handler(
        "test_wrong_token_content_type",
        Arc::new(Token(|_, _| {
            Some(tlv(
                0x30,
                &[oid(OID_DATA), tlv(0xa0, &octets(b"\xde\xad\xbe\xef"))].concat(),
            ))
        })),
        "must be.*type AuthenticatedData",
    );
}

#[derive(Debug)]
struct UnexpectedSigDigest;

impl PdfMacTokenHandlerFactory for UnexpectedSigDigest {
    fn format_message(
        &self,
        h: &PdfMacTokenHandler,
        document_digest: &[u8],
        _signature_digest: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), PdfError> {
        default_format_message(h, document_digest, Some(document_digest))
    }
}

#[test]
fn test_unexpected_sig_digest() {
    // only_location=STANDALONE
    check_standalone_with_handler(Arc::new(UnexpectedSigDigest), "unexpected signature digest");
}

#[test]
fn test_missing_sig_digest() {
    check_in_sig(
        "test_missing_sig_digest",
        BOTH,
        Some("could not find signature digest"),
    );
}

#[test]
fn test_sig_wrong_sig_digest() {
    check_in_sig(
        "test_sig_wrong_sig_digest",
        BOTH,
        Some("Signature digest does not match value in"),
    );
}

#[test]
fn test_sig_wrong_document_digest() {
    check_in_sig(
        "test_sig_wrong_document_digest",
        BOTH,
        Some("Document digest does not match value in"),
    );
}

#[test]
fn test_with_trailing_data() {
    // only_location=STANDALONE: the size estimate (dry run) is too large
    check_standalone_with_handler(
        Arc::new(Token(|parts, dry_run| {
            if dry_run {
                parts.unauth_attrs = Some(data_content_type_attrs());
            }
            None
        })),
        "must not have trailing CMS data",
    );
}

fn remove_kdf_salt(w: &mut sigis_pdf::PdfWriter) {
    let eid = w.encrypt_ref().unwrap();
    let mut enc = as_dict(w.get_object(eid).unwrap());
    enc.remove(b"KDFSalt");
    w.update_object(eid, Object::Dictionary(enc));
}

#[test]
fn test_do_not_store_salt() {
    for et in ENCRYPTION_TYPES {
        let (mut w, _) = init_sample_doc(et);
        remove_kdf_salt(&mut w);
        let out = w.write().unwrap();
        assert_mac_bad(&out, "Error retrieving salt");
    }
}

#[test]
fn test_mac_no_full_coverage() {
    for et in ENCRYPTION_TYPES {
        let out = write_with_handler(et, None);
        let r = read(&out);
        dummy_decrypt(&r, true).unwrap();
        let mut w = IncrementalWriter::new(r);
        // short-circuit MAC
        w.digest_aware_write = true;
        let mut root = w.root().unwrap();
        root.set("Foo", pdf_name("/Bar"));
        let rid = w.root_id();
        w.update_object(rid, Object::Dictionary(root));
        let out = w.write_in_place().unwrap();
        assert_mac_bad(&out, "must have /ByteRange covering the entire file");
    }
}

#[test]
fn test_mac_with_signature_no_full_coverage() {
    check_in_sig(
        "test_mac_with_signature_no_full_coverage",
        BOTH,
        Some("must have /ByteRange covering the entire file"),
    );
}

#[test]
fn test_simple_mac_weak_hash() {
    let out = write_with_handler(EncryptionType::Standard, Some(Arc::new(Md("sha1"))));
    let r = read(&out);
    // DisallowedAlgorithmError
    let e = dummy_decrypt(&r, false).unwrap_err();
    assert!(matches!(e, PdfError::Value(_)), "{e:?}");
    assert!(e.message().contains("DisallowedAlgorithmError"));
}

#[test]
fn test_stripped_mac_detected() {
    for et in ENCRYPTION_TYPES {
        for remove_salt in [true, false] {
            let (mut w, _) = init_sample_doc(et);
            // skip writing the MAC
            w.digest_aware_write = true;
            if remove_salt {
                remove_kdf_salt(&mut w);
            }
            let out = w.write().unwrap();
            assert_mac_bad(&out, "Failed to locate AuthCode dictionary");
        }
    }
}

#[test]
fn test_ac_dict_indirect() {
    // MacLocation.STANDALONE: pyHanko's writer stores /AuthCode as an
    // indirect object; here an update (without a new MAC) points the
    // trailer's /AuthCode to an indirect copy of the original dictionary.
    // MacLocation.IN_SIG: pyHanko fixture.
    for et in ENCRYPTION_TYPES {
        let out = write_with_handler(et, None);
        let r = read(&out);
        dummy_decrypt(&r, true).unwrap();
        let ac = r.trailer_view().get(b"AuthCode").unwrap().clone();
        let mut w = IncrementalWriter::new(r);
        w.digest_aware_write = true;
        let ac_ref = w.add_object(ac).unwrap();
        w.set_custom_trailer_entry("/AuthCode", Object::Reference(ac_ref));
        let out = w.write_in_place().unwrap();
        assert_mac_bad(&out, "AuthCode.*indirect");
    }
    check_in_sig("test_ac_dict_indirect", BOTH, Some("AuthCode.*indirect"));
}

#[test]
fn test_missing_sig_ref() {
    check_in_sig("test_missing_sig_ref", BOTH, Some("requires /SigObjRef"));
}

#[test]
fn test_malformed_sig_ref_direct() {
    check_in_sig(
        "test_malformed_sig_ref_direct",
        BOTH,
        Some("must be an indirect reference"),
    );
}

#[test]
fn test_malformed_sig_ref_not_dictionary() {
    check_in_sig(
        "test_malformed_sig_ref_not_dictionary",
        BOTH,
        Some("does not point to a dictionary"),
    );
}

#[test]
fn test_malformed_sig_ref_not_signature() {
    check_in_sig(
        "test_malformed_sig_ref_not_signature",
        BOTH,
        Some("Failed to retrieve signature contents"),
    );
}

fn rfind(hay: &[u8], needle: &[u8]) -> usize {
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
        .unwrap()
}

/// Same-length byte replacement in the last trailer of the file.
fn patch_last(out: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let i = rfind(out, from);
    out[i..i + to.len()].copy_from_slice(to);
}

#[test]
fn test_mac_location_missing() {
    let mut out = write_with_handler(EncryptionType::Standard, None);
    // `del value['/MACLocation']`: rename the key
    patch_last(
        &mut out,
        b"/MACLocation /Standalone",
        b"/MACLocatioX /Standalone",
    );
    assert_mac_bad(&out, "Failed to locate MAC in document");
}

#[test]
fn test_mac_location_unsupported() {
    let mut out = write_with_handler(EncryptionType::Standard, None);
    patch_last(
        &mut out,
        b"/MACLocation /Standalone",
        b"/MACLocation /Bleh      ",
    );
    assert_mac_bad(&out, "Failed to locate MAC in document");
}

/// The values of the `/ByteRange` of the trailer's `/AuthCode`.
fn auth_code_byte_range(out: &[u8]) -> Vec<i64> {
    let r = read(out);
    let ac = as_dict(r.trailer_view().get(b"AuthCode").unwrap().clone());
    match ac.get(b"ByteRange").unwrap() {
        Object::Array(a) => a
            .iter()
            .map(|x| match x {
                Object::Integer(i) => *i,
                other => panic!("{other:?}"),
            })
            .collect(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn test_mac_wrong_type() {
    for et in ENCRYPTION_TYPES {
        let mut out = write_with_handler(et, None);
        let region_start = auth_code_byte_range(&out)[1] as usize;
        out[region_start..region_start + 6].copy_from_slice(b"/Bleh%");
        assert_mac_bad(&out, "Failed to retrieve standalone MAC value");
    }
}

#[test]
fn test_byte_range_missing() {
    let mut out = write_with_handler(EncryptionType::Standard, None);
    let range_object_offset = rfind(&out, b"/ByteRange [") + b"/ByteRange ".len();
    out[range_object_offset - 3..range_object_offset + 5].copy_from_slice(b"%\n/Bleh%");
    assert_mac_bad(&out, "No sensible /ByteRange found");
}

#[test]
fn test_signer_info_cardinality_multi() {
    check_in_sig(
        "test_signer_info_cardinality_multi",
        &["standard"],
        Some("exactly 1 signerInfo"),
    );
}

#[test]
fn test_signer_info_cardinality_zero() {
    check_in_sig(
        "test_signer_info_cardinality_zero",
        &["standard"],
        Some("exactly 1 signerInfo"),
    );
}

#[test]
fn test_pdf_mac_attr_missing() {
    check_in_sig(
        "test_pdf_mac_attr_missing",
        &["standard"],
        Some("exactly 1 pdfMacData unsigned attribute"),
    );
}

#[test]
#[ignore = "pending: needs lane D (PdfSigner reuse with PDF MAC attribute providers)"]
fn test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel() {}

#[test]
fn standalone_mac_on_incremental_update() {
    // not upstream: an authenticated incremental update carries a new MAC
    // covering the whole file
    let out = write_with_handler(EncryptionType::Standard, None);
    let r = read(&out);
    let mut w = IncrementalWriter::new(r);
    w.encrypt(DUMMY_PASSWORD).unwrap();
    let mut root = w.root().unwrap();
    root.set("Foo", pdf_name("/Bar"));
    let rid = w.root_id();
    w.update_object(rid, Object::Dictionary(root));
    let out2 = w.write_in_place().unwrap();
    assert!(out2.len() > out.len());
    assert_mac_good(&out2);
}
