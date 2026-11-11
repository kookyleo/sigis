// Derived from pyhanko-certvalidator `fetchers/common_utils.py` and `util.py`
// (`get_ocsp_urls`, `get_relevant_crl_dps`), and asn1crypto `pem.py`
// (`detect`, `unarmor`) (MIT, see LICENSE-pyHanko).

//! Backend-independent helpers to process fetched certificates, CRLs and
//! OCSP responses.

use base64::Engine;
use const_oid::ObjectIdentifier;
use der::asn1::{Ia5String, OctetString};
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};
use x509_cert::ext::{Extension, Extensions};
use x509_ocsp::{OcspRequest, OcspResponse, OcspResponseStatus, Request, TbsRequest};

use hanko_core::algorithms::DigestAlgorithm;
use hanko_core::asn1::oids;
use hanko_core::asn1::raw_oid::RawOid;
use hanko_core::asn1::tlv::{tag, Tlv};
use hanko_core::cert::Cert;

/// `ACCEPTABLE_STRICT_CERT_CONTENT_TYPES`.
pub const ACCEPTABLE_STRICT_CERT_CONTENT_TYPES: &[&str] = &[
    "application/pkix-cert",
    "application/pkix-ca",
    "application/pkcs7-mime",
    "application/x-x509-ca-cert",
    "application/x-pkcs7-certificates",
];

/// `ACCEPTABLE_CERT_PEM_ALIASES`.
pub const ACCEPTABLE_CERT_PEM_ALIASES: &[&str] = &[
    "application/x-pem-file",
    "text/plain",
    "application/octet-stream",
    "binary/octet-stream",
];

/// `ACCEPTABLE_CERT_DER_ALIASES`.
pub const ACCEPTABLE_CERT_DER_ALIASES: &[&str] = &[
    "application/pkix-cert",
    "application/x-x509-ca-cert",
    "application/octet-stream",
    "binary/octet-stream",
];

/// `ACCEPTABLE_PKCS7_DER_ALIASES`.
pub const ACCEPTABLE_PKCS7_DER_ALIASES: &[&str] = &[
    "application/pkcs7-mime",
    "application/x-pkcs7-certificates",
    "application/octet-stream",
    "binary/octet-stream",
];

/// A payload could not be interpreted (a `ValueError` in pyHanko).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ContentError(pub String);

/// `pem.detect`: the bytes contain a PEM `BEGIN` line.
pub fn pem_detect(data: &[u8]) -> bool {
    find(data, b"-----BEGIN").is_some() || find(data, b"---- BEGIN").is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// `pem.unarmor(data, multiple=True)`: every PEM block as (type, DER).
pub fn pem_unarmor(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ContentError> {
    #[derive(PartialEq)]
    enum State {
        Trash,
        Headers,
        Body,
    }
    let mut out = Vec::new();
    let mut state = State::Trash;
    let mut object_type = String::new();
    let mut b64 = Vec::new();
    let (mut found_start, mut found_end) = (false, false);
    for line in data.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if state == State::Trash {
            let rest = line
                .strip_prefix(b"-----BEGIN ")
                .or_else(|| line.strip_prefix(b"---- BEGIN "));
            let Some(rest) = rest else { continue };
            let name_len = rest
                .iter()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || **c == b' ')
                .count();
            let tail = &rest[name_len..];
            if name_len == 0 || !(tail.starts_with(b"-----") || tail.starts_with(b" ----")) {
                continue;
            }
            object_type = String::from_utf8_lossy(&rest[..name_len]).into_owned();
            found_start = true;
            state = State::Headers;
            continue;
        }
        if state == State::Headers {
            if line.contains(&b':') {
                continue;
            }
            state = State::Body;
        }
        if line.starts_with(b"-----") || line.starts_with(b"---- ") {
            let der = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .map_err(|e| ContentError(format!("PEM base64: {e}")))?;
            out.push((core::mem::take(&mut object_type), der));
            b64.clear();
            state = State::Trash;
            found_end = true;
            continue;
        }
        b64.extend(line.iter().filter(|c| !c.is_ascii_whitespace()));
    }
    if !found_start || !found_end {
        return Err(ContentError(
            "pem_bytes does not appear to contain PEM-encoded data - no BEGIN/END combination found"
                .into(),
        ));
    }
    Ok(out)
}

fn cert_from_der(der: &[u8]) -> Result<Cert, ContentError> {
    Cert::from_der(der).map_err(|e| ContentError(e.to_string()))
}

fn content_type_name(oid: &RawOid) -> String {
    match oid.to_oid() {
        Some(oids::CT_DATA) => "data".into(),
        Some(oids::CT_SIGNED_DATA) => "signed_data".into(),
        Some(oids::CT_ENVELOPED_DATA) => "enveloped_data".into(),
        Some(oids::CT_DIGESTED_DATA) => "digested_data".into(),
        Some(oids::CT_ENCRYPTED_DATA) => "encrypted_data".into(),
        _ => oid.dotted(),
    }
}

/// `_unpack_der_pkcs7`: the public-key certificates of a PKCS#7
/// certs-only `SignedData`.
pub fn unpack_der_pkcs7(data: &[u8], url: &str) -> Result<Vec<Cert>, ContentError> {
    let malformed = |e: &dyn std::fmt::Display| ContentError(format!("PKCS#7 payload: {e}"));
    let ci = Tlv::parse_exact(data).map_err(|e| malformed(&e))?;
    let parts = ci.children().map_err(|e| malformed(&e))?;
    let ct = parts
        .first()
        .ok_or_else(|| malformed(&"empty ContentInfo"))?;
    let ct = RawOid::from_tlv(ct).map_err(|e| malformed(&e))?;
    if !ct.is(&oids::CT_SIGNED_DATA) {
        return Err(ContentError(format!(
            "Expected CMS SignedData when extracting certs from application/pkcs7-mime payload, but content type was '{}'. Source URL: {url}.",
            content_type_name(&ct)
        )));
    }
    let content = parts
        .get(1)
        .filter(|c| c.is_context(0))
        .ok_or_else(|| malformed(&"missing content"))?;
    let sd = Tlv::parse_exact(content.value).map_err(|e| malformed(&e))?;
    let mut certs = Vec::new();
    for field in sd.children().map_err(|e| malformed(&e))? {
        if field.is_context(0) && field.constructed {
            for choice in field.children().map_err(|e| malformed(&e))? {
                if choice.is_universal(tag::SEQUENCE) {
                    certs.push(cert_from_der(choice.raw)?);
                }
            }
        }
    }
    Ok(certs)
}

/// `unpack_cert_content`: interpret a `caIssuers` response.
pub fn unpack_cert_content(
    data: &[u8],
    content_type: Option<&str>,
    url: &str,
    permit_pem: bool,
) -> Result<Vec<Cert>, ContentError> {
    let is_pem = pem_detect(data);
    let der_alias = content_type.is_none_or(|ct| ACCEPTABLE_CERT_DER_ALIASES.contains(&ct));
    if der_alias && !is_pem {
        let seq = Tlv::parse_exact(data).map_err(|e| ContentError(e.to_string()))?;
        if !seq.is_universal(tag::SEQUENCE) {
            return Err(ContentError("payload is not a SEQUENCE".into()));
        }
        let len = seq
            .children()
            .map_err(|e| ContentError(e.to_string()))?
            .len();
        return match len {
            2 => unpack_der_pkcs7(data, url),
            3 => Ok(vec![cert_from_der(data)?]),
            _ => Err(ContentError(format!(
                "Failed to heuristically determine content of payload from source URL {url}"
            ))),
        };
    }
    if content_type.is_some_and(|ct| ACCEPTABLE_PKCS7_DER_ALIASES.contains(&ct)) && !is_pem {
        return unpack_der_pkcs7(data, url);
    }
    if permit_pem && is_pem {
        let mut certs = Vec::new();
        for (ty, der) in pem_unarmor(data)? {
            if ty == "PKCS7" {
                certs.extend(unpack_der_pkcs7(&der, url)?);
            } else {
                certs.push(cert_from_der(&der)?);
            }
        }
        return Ok(certs);
    }
    Err(ContentError(format!(
        "Failed to extract certs from {} payload. Source URL: {url}.",
        content_type.unwrap_or("None")
    )))
}

fn uri(name: &GeneralName) -> Option<&str> {
    match name {
        GeneralName::UniformResourceIdentifier(u) => Some(u.as_str()),
        _ => None,
    }
}

/// `enumerate_delivery_point_urls`: the HTTP(S) URLs of a distribution
/// point given by full name. Relative names, LDAP and non-URI names are
/// skipped.
pub fn enumerate_delivery_point_urls(dp: &DistributionPoint) -> Vec<String> {
    let Some(DistributionPointName::FullName(names)) = &dp.distribution_point else {
        return Vec::new();
    };
    names
        .iter()
        .filter_map(uri)
        .filter(|u| {
            let l = u.to_ascii_lowercase();
            l.starts_with("http://") || l.starts_with("https://")
        })
        .map(str::to_owned)
        .collect()
}

/// The extensions of a certificate.
fn cert_extensions(cert: &Cert) -> Vec<Extension> {
    cert.decoded()
        .tbs_certificate()
        .extensions()
        .cloned()
        .unwrap_or_default()
}

/// The extensions of a DER attribute certificate (`AttributeCertificate`).
pub fn ac_extensions(ac_der: &[u8]) -> Vec<Extension> {
    let parse = || -> Option<Vec<Extension>> {
        let ac = Tlv::parse_exact(ac_der).ok()?;
        let parts = ac.children().ok()?;
        let info = parts.first()?;
        let fields = info.children().ok()?;
        // version, holder, issuer, signature, serial, validity, attributes,
        // [issuerUniqueID], [extensions]
        let last = fields
            .get(7..)?
            .iter()
            .rev()
            .find(|f| f.is_universal(tag::SEQUENCE))?;
        Extensions::from_der(last.raw).ok()
    };
    parse().unwrap_or_default()
}

fn find_extension<'a>(exts: &'a [Extension], oid: &ObjectIdentifier) -> Option<&'a Extension> {
    exts.iter().find(|e| e.extn_id == *oid)
}

fn aia_urls(exts: &[Extension], method: ObjectIdentifier) -> Vec<String> {
    let Some(ext) = find_extension(exts, &oids::PE_AUTHORITY_INFO_ACCESS) else {
        return Vec::new();
    };
    let Ok(aia) = AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()) else {
        return Vec::new();
    };
    aia.0
        .iter()
        .filter(|ad| ad.access_method == method)
        .filter_map(|ad| uri(&ad.access_location).map(str::to_owned))
        .collect()
}

/// `id-ad-caIssuers`.
const AD_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");

fn issuer_urls(exts: &[Extension]) -> Vec<String> {
    aia_urls(exts, AD_CA_ISSUERS)
        .into_iter()
        .filter(|u| u.starts_with("http"))
        .collect()
}

/// `gather_aia_issuer_urls` for a certificate: `caIssuers` URLs over HTTP.
pub fn gather_aia_issuer_urls(cert: &Cert) -> Vec<String> {
    issuer_urls(&cert_extensions(cert))
}

/// `gather_aia_issuer_urls` for a DER attribute certificate.
pub fn gather_aia_issuer_urls_ac(ac_der: &[u8]) -> Vec<String> {
    issuer_urls(&ac_extensions(ac_der))
}

/// `get_ocsp_urls`: OCSP responder URLs over HTTP(S).
pub fn get_ocsp_urls(cert: &Cert) -> Vec<String> {
    aia_urls(&cert_extensions(cert), oids::AD_OCSP)
        .into_iter()
        .filter(|u| {
            let l = u.to_ascii_lowercase();
            l.starts_with("http://") || l.starts_with("https://")
        })
        .collect()
}

/// `x509.Certificate._get_http_crl_distribution_points`: distribution
/// points with a full name, once per URI they contain.
fn http_dps(exts: &[Extension], oid: &ObjectIdentifier) -> Vec<DistributionPoint> {
    let Some(ext) = find_extension(exts, oid) else {
        return Vec::new();
    };
    let Ok(dps) = CrlDistributionPoints::from_der(ext.extn_value.as_bytes()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for dp in dps.0 {
        if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
            for _ in names.iter().filter(|n| uri(n).is_some()) {
                out.push(dp.clone());
            }
        }
    }
    out
}

/// `get_relevant_crl_dps`: CRL distribution points, plus freshest-CRL
/// points if `use_deltas`.
pub fn get_relevant_crl_dps(cert: &Cert, use_deltas: bool) -> Vec<DistributionPoint> {
    let exts = cert_extensions(cert);
    let mut out = http_dps(&exts, &oids::CE_CRL_DISTRIBUTION_POINTS);
    if use_deltas {
        out.extend(http_dps(&exts, &oids::CE_FRESHEST_CRL));
    }
    out
}

/// CertID hash algorithm for OCSP requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertIdHash {
    /// SHA-1 (the default, as in pyHanko).
    Sha1,
    /// SHA-256.
    Sha256,
}

impl CertIdHash {
    fn digest(self) -> DigestAlgorithm {
        match self {
            Self::Sha1 => DigestAlgorithm::Sha1,
            Self::Sha256 => DigestAlgorithm::Sha256,
        }
    }
}

/// `format_ocsp_request`: an OCSP request for `cert` issued by `issuer`,
/// with a random 16-byte nonce if `nonce` is set. Returns the request and
/// the nonce.
pub fn format_ocsp_request(
    cert: &Cert,
    issuer: &Cert,
    hash: CertIdHash,
    nonce: Option<[u8; 16]>,
) -> Result<OcspRequest, der::Error> {
    let d = hash.digest();
    let issuer_name = issuer.subject_der().map_err(|_| der::ErrorKind::Failed)?;
    let key = issuer.public_key();
    let cert_id = x509_ocsp::CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: d.oid(),
            parameters: Some(der::asn1::Null.into()),
        },
        issuer_name_hash: OctetString::new(d.digest(&issuer_name))?,
        issuer_key_hash: OctetString::new(d.digest(key.subject_public_key.raw_bytes()))?,
        serial_number: x509_cert::serial_number::SerialNumber::new(cert.serial_bytes())?,
    };
    let request_extensions = match nonce {
        Some(n) => Some(vec![Extension {
            extn_id: oids::OCSP_NONCE,
            critical: false,
            extn_value: OctetString::new(OctetString::new(n)?.to_der()?)?,
        }]),
        None => None,
    };
    Ok(OcspRequest {
        tbs_request: TbsRequest {
            version: Default::default(),
            requestor_name: None,
            request_list: vec![Request {
                req_cert: cert_id,
                single_request_extensions: None,
            }],
            request_extensions,
        },
        optional_signature: None,
    })
}

/// The nonce of an OCSP request or basic response, if any.
fn nonce_value(exts: Option<&Vec<Extension>>) -> Option<Vec<u8>> {
    let ext = exts?.iter().find(|e| e.extn_id == oids::OCSP_NONCE)?;
    // The value is an OCTET STRING wrapped in the extension's OCTET STRING;
    // asn1crypto compares the inner `native` values.
    match OctetString::from_der(ext.extn_value.as_bytes()) {
        Ok(inner) => Some(inner.as_bytes().to_vec()),
        Err(_) => Some(ext.extn_value.as_bytes().to_vec()),
    }
}

/// Failure of [`process_ocsp_response_data`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OcspResponseError {
    /// `OCSPFetchError`: the response does not parse.
    #[error("Failed to parse response from OCSP server")]
    Unparseable,
    /// `OCSPValidationError`: unsuccessful status or nonce mismatch.
    #[error("{0}")]
    Validation(String),
}

fn status_name(s: OcspResponseStatus) -> &'static str {
    match s {
        OcspResponseStatus::Successful => "successful",
        OcspResponseStatus::MalformedRequest => "malformed_request",
        OcspResponseStatus::InternalError => "internal_error",
        OcspResponseStatus::TryLater => "try_later",
        OcspResponseStatus::SigRequired => "sign_required",
        OcspResponseStatus::Unauthorized => "unauthorized",
    }
}

/// `process_ocsp_response_data`: check the status and the nonce.
pub fn process_ocsp_response_data(
    data: &[u8],
    request: &OcspRequest,
    url: &str,
) -> Result<OcspResponse, OcspResponseError> {
    let response = OcspResponse::from_der(data).map_err(|_| OcspResponseError::Unparseable)?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(OcspResponseError::Validation(format!(
            "OCSP server at {url} returned an error. Status was '{}'.",
            status_name(response.response_status)
        )));
    }
    if let Some(request_nonce) = nonce_value(request.tbs_request.request_extensions.as_ref()) {
        let response_nonce = response.response_bytes.as_ref().and_then(|b| {
            x509_ocsp::BasicOcspResponse::from_der(b.response.as_bytes())
                .ok()
                .and_then(|basic| nonce_value(basic.tbs_response_data.response_extensions.as_ref()))
        });
        if response_nonce.is_some_and(|n| n != request_nonce) {
            return Err(OcspResponseError::Validation(
                "Unable to verify OCSP response since the request and response nonces do not match"
                    .into(),
            ));
        }
    }
    Ok(response)
}

/// Random bytes from the operating system.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    // Failure leaves zeros; nonces are a freshness aid, not a security
    // boundary for these protocols.
    let _ = getrandom::fill(&mut out);
    out
}

/// An IA5 URI general name (test helper for building distribution points).
pub fn uri_name(url: &str) -> Option<GeneralName> {
    Ia5String::new(url)
        .ok()
        .map(GeneralName::UniformResourceIdentifier)
}
