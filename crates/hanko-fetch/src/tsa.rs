// Derived from pyHanko `sign/timestamps/api.py`, `common_utils.py`,
// `requests_client.py` and `aiohttp_client.py` (MIT, see LICENSE-pyHanko).

//! RFC 3161 time-stamping client.

use std::sync::Arc;

use base64::Engine;
use der::asn1::{Int, OctetString};
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_tsp::{MessageImprint, TimeStampReq, TspVersion, TstInfo};

use hanko_core::algorithms::DigestAlgorithm;
use hanko_core::asn1::oids;
use hanko_core::asn1::raw_oid::RawOid;
use hanko_core::asn1::tlv::{tag, Tlv};
use hanko_core::errors::{FetchError, FetchErrorKind, HankoError, Result};
use hanko_core::sign::TimeStamper;

use crate::budget::FetchLimits;
use crate::common::random_bytes;
use crate::transport::{HttpRequest, HttpTransport, ReqwestTransport};

/// `TimestampRequestError`: the request failed or the response is invalid.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TimestampRequestError(pub String);

impl From<TimestampRequestError> for HankoError {
    fn from(e: TimestampRequestError) -> Self {
        HankoError::Fetch(FetchError::new(FetchErrorKind::BadResponse, e.0))
    }
}

/// `get_nonce`: a random positive 64-bit integer with a fixed width (first
/// octet 0x01), big-endian.
pub fn get_nonce() -> [u8; 8] {
    let mut n = [0u8; 8];
    n[0] = 0x01;
    n[1..].copy_from_slice(&random_bytes::<7>());
    n
}

/// `TimeStamper.request_cms`: a `TimeStampReq` for `message_digest`,
/// asking for the TSA certificate.
pub fn request_cms(
    message_digest: &[u8],
    digest: DigestAlgorithm,
    nonce: Option<&[u8]>,
) -> std::result::Result<TimeStampReq, der::Error> {
    // asn1crypto encodes SHA-1/SHA-2 identifiers with an explicit NULL.
    let parameters = matches!(
        digest,
        DigestAlgorithm::Sha1
            | DigestAlgorithm::Sha224
            | DigestAlgorithm::Sha256
            | DigestAlgorithm::Sha384
            | DigestAlgorithm::Sha512
    )
    .then(|| der::asn1::Null.into());
    Ok(TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: digest.oid(),
                parameters,
            },
            hashed_message: OctetString::new(message_digest)?,
        },
        req_policy: None,
        nonce: nonce.map(Int::new).transpose()?,
        cert_req: true,
        extensions: None,
    })
}

/// asn1crypto `PKIFailureInfo` bit names.
const FAIL_INFO_NAMES: [(usize, &str); 8] = [
    (0, "bad_alg"),
    (2, "bad_request"),
    (5, "bad_data_format"),
    (14, "time_not_available"),
    (15, "unaccepted_policy"),
    (16, "unaccepted_extension"),
    (17, "add_info_not_available"),
    (25, "system_failure"),
];

fn normalize_int(bytes: &[u8]) -> &[u8] {
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
        b = &b[1..];
    }
    b
}

/// `handle_tsp_response`: check a `TimeStampResp` (DER) and return its
/// token (DER `ContentInfo`). `nonce`, if given, must equal the token's
/// nonce (big-endian integer bytes).
pub fn handle_tsp_response(
    response: &[u8],
    nonce: Option<&[u8]>,
) -> std::result::Result<Vec<u8>, TimestampRequestError> {
    let bad = |what: &str| {
        TimestampRequestError(format!("Timestamp server response is malformed: {what}"))
    };
    let resp = Tlv::parse_exact(response).map_err(|e| bad(&e.to_string()))?;
    let parts = resp.children().map_err(|e| bad(&e.to_string()))?;
    let status_info = parts.first().ok_or_else(|| bad("no status"))?;
    let fields = status_info.children().map_err(|e| bad(&e.to_string()))?;
    let status = fields
        .first()
        .filter(|t| t.is_universal(tag::INTEGER))
        .ok_or_else(|| bad("no status"))?;
    let mut status_strings = Vec::new();
    let mut fail_infos = Vec::new();
    for f in fields.iter().skip(1) {
        if f.is_universal(tag::SEQUENCE) {
            for s in f.children().map_err(|e| bad(&e.to_string()))? {
                status_strings.push(String::from_utf8_lossy(s.value).into_owned());
            }
        } else if f.is_universal(tag::BIT_STRING) {
            let bits = f.value.get(1..).unwrap_or_default();
            for (bit, name) in FAIL_INFO_NAMES {
                if bits
                    .get(bit / 8)
                    .is_some_and(|b| b & (0x80 >> (bit % 8)) != 0)
                {
                    fail_infos.push(name);
                }
            }
        }
    }
    if status.value != [0] {
        return Err(TimestampRequestError(format!(
            "Timestamp server refused our request: statusString \"{}\", failInfo \"{}\"",
            status_strings.join("; "),
            fail_infos.join("; ")
        )));
    }
    let token = parts.get(1).ok_or_else(|| bad("no timestamp token"))?;
    let tst_info = token_tst_info(token.raw).map_err(|e| bad(&e))?;
    if let Some(expected) = nonce {
        let received = tst_info.nonce.as_ref().map(|n| normalize_int(n.as_bytes()));
        if received != Some(normalize_int(expected)) {
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            return Err(TimestampRequestError(format!(
                "Time stamping authority sent back bad nonce value. Expected {}, but got {}.",
                hex(expected),
                received.map_or_else(|| "None".to_owned(), |r| format!("0x{}", hex(r)))
            )));
        }
    }
    Ok(token.raw.to_vec())
}

/// The `TSTInfo` of a timestamp token (DER `ContentInfo`).
pub fn token_tst_info(token: &[u8]) -> std::result::Result<TstInfo, String> {
    let ci = Tlv::parse_exact(token).map_err(|e| e.to_string())?;
    let parts = ci.children().map_err(|e| e.to_string())?;
    let content = parts
        .get(1)
        .filter(|c| c.is_context(0))
        .ok_or("token without content")?;
    let sd = Tlv::parse_exact(content.value).map_err(|e| e.to_string())?;
    let eci = sd
        .children()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|f| f.is_universal(tag::SEQUENCE))
        .ok_or("no encapContentInfo")?;
    let eci_parts = eci.children().map_err(|e| e.to_string())?;
    let ct = eci_parts.first().ok_or("no content type")?;
    if !RawOid::from_tlv(ct)
        .map_err(|e| e.to_string())?
        .is(&oids::CT_TST_INFO)
    {
        return Err("token does not encapsulate TSTInfo".into());
    }
    let econtent = eci_parts
        .get(1)
        .filter(|c| c.is_context(0))
        .ok_or("no TSTInfo")?;
    let octets = OctetString::from_der(econtent.value).map_err(|e| e.to_string())?;
    TstInfo::from_der(octets.as_bytes()).map_err(|e| e.to_string())
}

/// How nonces are chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NonceMode {
    /// A fresh random nonce per request (the default).
    Random,
    /// No nonce (`include_nonce=False`).
    None,
    /// A fixed nonce (tests).
    Fixed(Vec<u8>),
}

/// RFC 3161 client over HTTP (`HTTPTimeStamper`).
#[derive(Clone, Debug)]
pub struct HttpTimeStamper {
    /// TSA URL.
    pub url: String,
    /// Request limits (timeout, response size).
    pub limits: FetchLimits,
    auth: Option<(String, String)>,
    headers: Vec<(String, String)>,
    nonce: NonceMode,
    transport: Option<Arc<dyn HttpTransport>>,
}

impl HttpTimeStamper {
    /// A client for `url` with default limits.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            limits: FetchLimits::default(),
            auth: None,
            headers: Vec::new(),
            nonce: NonceMode::Random,
            transport: None,
        }
    }

    /// Require `https:` (`https=True`).
    pub fn require_https(self) -> std::result::Result<Self, TimestampRequestError> {
        if self.url.starts_with("https:") {
            Ok(self)
        } else {
            Err(TimestampRequestError("Timestamp URL is not HTTPS.".into()))
        }
    }

    /// Set the limits.
    pub fn with_limits(mut self, limits: FetchLimits) -> Self {
        self.limits = limits;
        self
    }

    /// HTTP basic authentication (`auth=(user, password)`).
    pub fn with_basic_auth(mut self, user: &str, password: &str) -> Self {
        self.auth = Some((user.to_owned(), password.to_owned()));
        self
    }

    /// An extra request header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Choose how nonces are sent.
    pub fn with_nonce(mut self, nonce: NonceMode) -> Self {
        self.nonce = nonce;
        self
    }

    /// Use a custom transport.
    pub fn with_transport(mut self, transport: Arc<dyn HttpTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// The `Authorization` header value, if any (`auth`).
    pub fn authorization(&self) -> Option<String> {
        self.auth.as_ref().map(|(u, p)| {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
            )
        })
    }

    /// `request_headers`.
    pub fn request_headers(&self) -> Vec<(String, String)> {
        let mut h = self.headers.clone();
        h.retain(|(k, _)| {
            !k.eq_ignore_ascii_case("Content-Type") && !k.eq_ignore_ascii_case("Accept")
        });
        h.push(("Content-Type".into(), "application/timestamp-query".into()));
        h.push(("Accept".into(), "application/timestamp-reply".into()));
        if let Some(a) = self.authorization() {
            h.push(("Authorization".into(), a));
        }
        h
    }

    /// `async_request_tsa_response`: POST the request; returns the DER
    /// `TimeStampResp`.
    pub fn request_tsa_response(
        &self,
        request: &[u8],
    ) -> std::result::Result<Vec<u8>, TimestampRequestError> {
        let comm = || TimestampRequestError("Error while contacting timestamp service".into());
        let transport: Arc<dyn HttpTransport> = match &self.transport {
            Some(t) => t.clone(),
            None => Arc::new(
                ReqwestTransport::new(self.limits.timeout, self.limits.max_response_bytes)
                    .map_err(|_| comm())?,
            ),
        };
        let response = transport
            .send(&HttpRequest {
                method: "POST",
                url: &self.url,
                headers: self.request_headers(),
                body: Some(request),
            })
            .map_err(|_| comm())?;
        if !(200..300).contains(&response.status) {
            return Err(comm());
        }
        if response.content_type.as_deref() != Some("application/timestamp-reply") {
            return Err(comm());
        }
        Ok(response.body)
    }

    /// `async_timestamp`: request a token over `message_digest`.
    pub fn timestamp_token(
        &self,
        message_digest: &[u8],
        digest: DigestAlgorithm,
    ) -> std::result::Result<Vec<u8>, TimestampRequestError> {
        let nonce = match &self.nonce {
            NonceMode::Random => Some(get_nonce().to_vec()),
            NonceMode::None => None,
            NonceMode::Fixed(n) => Some(n.clone()),
        };
        let req = request_cms(message_digest, digest, nonce.as_deref())
            .and_then(|r| r.to_der())
            .map_err(|e| TimestampRequestError(format!("could not encode the request: {e}")))?;
        let response = self.request_tsa_response(&req)?;
        handle_tsp_response(&response, nonce.as_deref())
    }
}

impl TimeStamper for HttpTimeStamper {
    fn timestamp(&self, message_digest: &[u8], digest: DigestAlgorithm) -> Result<Vec<u8>> {
        Ok(self.timestamp_token(message_digest, digest)?)
    }
}
