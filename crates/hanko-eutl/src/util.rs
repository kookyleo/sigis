//! Small helpers: XML Schema `dateTime` parsing and PEM/DER certificate
//! loading (`pyhanko.keys.load_certs_from_pemder_data`).

use base64::Engine as _;
use hanko_core::cert::Cert;
use hanko_core::time::Moment;

/// Parse an `xsd:dateTime` value (surrounding whitespace allowed, fractional
/// seconds ignored, `Z` / `±hh:mm` offsets applied, no offset = UTC).
pub fn parse_xsd_datetime(s: &str) -> Option<Moment> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    // Split off a timezone designator.
    let (time, offset_secs) = if let Some(t) = rest.strip_suffix('Z') {
        (t, 0i64)
    } else if let Some(pos) = rest.rfind(['+', '-']) {
        let (t, tz) = rest.split_at(pos);
        let sign = if tz.starts_with('-') { -1 } else { 1 };
        let (h, m) = tz[1..].split_once(':')?;
        let (h, m): (i64, i64) = (h.parse().ok()?, m.parse().ok()?);
        if h > 14 || m > 59 {
            return None;
        }
        (t, sign * (h * 3600 + m * 60))
    } else {
        (rest, 0)
    };
    let mut d = date.split('-');
    let (y, mo, da) = (d.next()?, d.next()?, d.next()?);
    if d.next().is_some() || y.len() < 4 {
        return None;
    }
    let mut t = time.split(':');
    let (h, mi, se) = (t.next()?, t.next()?, t.next()?);
    if t.next().is_some() {
        return None;
    }
    let se = se.split('.').next()?;
    let m = Moment::from_ymd_hms(
        y.parse().ok()?,
        mo.parse().ok()?,
        da.parse().ok()?,
        h.parse().ok()?,
        mi.parse().ok()?,
        se.parse().ok()?,
    )?;
    Some(Moment::from_unix_secs(m.unix_secs() - offset_secs))
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
                let b64: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
                let der = base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .map_err(|e| CertLoadError(format!("PEM base64: {e}")))?;
                out.push(Cert::from_der(&der).map_err(|e| CertLoadError(e.to_string()))?);
                rest = &after[end + END.len()..];
            }
            return Ok(out);
        }
    }
    Ok(vec![Cert::from_der(data).map_err(|e| CertLoadError(e.to_string()))?])
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
