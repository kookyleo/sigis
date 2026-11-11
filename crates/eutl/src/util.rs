//! Small helpers: XML Schema `dateTime` parsing and PEM/DER certificate
//! loading (`pyhanko.keys.load_certs_from_pemder_data`).

use base64::Engine as _;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::time::Moment;

/// Parse an `xsd:dateTime` value (surrounding whitespace allowed, fractional
/// seconds ignored, `Z` / `±hh:mm` offsets applied, no offset = UTC).
pub fn parse_xsd_datetime(s: &str) -> Option<Moment> {
    Moment::parse_xsd_datetime(s)
}

/// Error loading certificates.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CertLoadError(pub String);

/// Load all certificates from PEM data (one or more `CERTIFICATE` blocks)
/// or a single DER certificate.
pub fn load_certs_from_pemder(data: &[u8]) -> Result<Vec<Cert>, CertLoadError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if let Ok(text) = std::str::from_utf8(data) {
        if text.contains(BEGIN) {
            let mut out = Vec::new();
            let mut rest = text;
            while let Some(start) = rest.find(BEGIN) {
                let after = &rest[start + BEGIN.len()..];
                let end = after
                    .find(END)
                    .ok_or_else(|| CertLoadError("unterminated PEM block".into()))?;
                let b64: String = after[..end]
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                let der = base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .map_err(|e| CertLoadError(format!("PEM base64: {e}")))?;
                out.push(Cert::from_der(&der).map_err(|e| CertLoadError(e.to_string()))?);
                rest = &after[end + END.len()..];
            }
            return Ok(out);
        }
    }
    Ok(vec![
        Cert::from_der(data).map_err(|e| CertLoadError(e.to_string()))?
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datetimes() {
        let utc = Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap();
        assert_eq!(parse_xsd_datetime(" 2020-11-01T00:00:00Z\n"), Some(utc));
        assert_eq!(parse_xsd_datetime("2020-11-01T01:00:00+01:00"), Some(utc));
        assert_eq!(parse_xsd_datetime("2020-10-31T23:00:00-01:00"), Some(utc));
        assert_eq!(parse_xsd_datetime("2020-11-01T00:00:00.123Z"), Some(utc));
        assert_eq!(parse_xsd_datetime("2020-11-01T00:00:00"), Some(utc));
        assert_eq!(parse_xsd_datetime("garbage"), None);
    }
}

/// Minimal DER reader for the few structures read without `const-oid`.
///
/// `const-oid` 0.10 rejects OIDs whose second arc under `2` exceeds 39
/// (such as `2.999.1`), which appear in certificate policies of real and
/// test PKIs. These helpers decode OIDs to dotted strings without that limit.
pub mod der_lite {
    /// One TLV: (tag, content).
    pub fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, rest) = input.split_first()?;
        let (&len0, rest) = rest.split_first()?;
        let (len, rest) = if len0 < 0x80 {
            (usize::from(len0), rest)
        } else {
            let n = usize::from(len0 & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let mut len = 0usize;
            for b in &rest[..n] {
                len = (len << 8) | usize::from(*b);
            }
            (len, &rest[n..])
        };
        if rest.len() < len {
            return None;
        }
        Some((tag, &rest[..len], &rest[len..]))
    }

    /// The elements of a constructed value.
    pub fn elements(mut content: &[u8]) -> Option<Vec<(u8, &[u8])>> {
        let mut out = Vec::new();
        while !content.is_empty() {
            let (tag, c, rest) = read_tlv(content)?;
            out.push((tag, c));
            content = rest;
        }
        Some(out)
    }

    /// Dotted string of an OID content (without tag and length).
    pub fn oid_to_string(content: &[u8]) -> Option<String> {
        let mut arcs: Vec<u128> = Vec::new();
        let mut cur: u128 = 0;
        let mut in_arc = false;
        for &b in content {
            if !in_arc && b == 0x80 {
                return None; // non-minimal encoding
            }
            cur = cur.checked_mul(128)? | u128::from(b & 0x7f);
            in_arc = b & 0x80 != 0;
            if !in_arc {
                arcs.push(cur);
                cur = 0;
            }
        }
        if in_arc || arcs.is_empty() {
            return None;
        }
        let first = arcs[0];
        let (a, b) = if first < 40 {
            (0, first)
        } else if first < 80 {
            (1, first - 40)
        } else {
            (2, first - 80)
        };
        let mut s = format!("{a}.{b}");
        for arc in &arcs[1..] {
            s.push('.');
            s.push_str(&arc.to_string());
        }
        Some(s)
    }
}

/// Dotted policy OIDs of the certificate policies extension, decoded
/// without `const-oid`'s arc limits. `None` if absent or malformed.
pub fn certificate_policy_oids(cert: &Cert) -> Option<std::collections::BTreeSet<String>> {
    let exts = cert.decoded().tbs_certificate().extensions()?;
    let ext = exts
        .iter()
        .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_CERTIFICATE_POLICIES)?;
    let (tag, seq, rest) = der_lite::read_tlv(ext.extn_value.as_bytes())?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let mut out = std::collections::BTreeSet::new();
    for (t, pi) in der_lite::elements(seq)? {
        if t != 0x30 {
            return None;
        }
        let (otag, oid, _) = der_lite::read_tlv(pi)?;
        if otag != 0x06 {
            return None;
        }
        out.insert(der_lite::oid_to_string(oid)?);
    }
    Some(out)
}
