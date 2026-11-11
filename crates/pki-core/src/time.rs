//! Points in time used for validation (the "time of interest").
//!
//! [`Moment`] is a UTC instant with one-second resolution, the resolution of
//! X.509 `Time`. It converts to and from [`der::DateTime`] and X.509 [`Time`].

use core::fmt;
use core::time::Duration;

use x509_cert::time::Time;

/// A UTC instant, in whole seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Moment(i64);

impl Moment {
    /// Build from seconds since the Unix epoch.
    pub const fn from_unix_secs(secs: i64) -> Self {
        Self(secs)
    }

    /// Seconds since the Unix epoch.
    pub const fn unix_secs(self) -> i64 {
        self.0
    }

    /// The current system time.
    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self(i64::try_from(secs).unwrap_or(i64::MAX))
    }

    /// Build from calendar fields (UTC). Returns `None` for invalid dates.
    pub fn from_ymd_hms(year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8) -> Option<Self> {
        der::DateTime::new(year, month, day, hour, min, sec)
            .ok()
            .map(Self::from)
    }

    /// Parse an RFC 3339 / ISO 8601 timestamp such as
    /// `2012-10-12T00:00:00+00:00`, `2012-10-12T00:00:00Z` or
    /// `2012-10-12T02:00:00.5+02:00`. A missing time means midnight and a
    /// missing zone designator means UTC; fractional seconds are truncated.
    pub fn parse_rfc3339(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.contains('T') {
            parse_iso8601(s, false)
        } else {
            parse_iso8601(&format!("{s}T00:00:00"), false)
        }
    }

    /// Parse an `xsd:dateTime` (`YYYY-MM-DDThh:mm:ss[.f][Z|(+|-)hh:mm]`),
    /// strictly: hours, minutes and seconds are required. A missing zone
    /// designator means UTC; fractional seconds are truncated.
    pub fn parse_xsd_datetime(s: &str) -> Option<Self> {
        parse_iso8601(s.trim(), true)
    }

    /// `self + d`, saturating.
    pub fn plus(self, d: Duration) -> Self {
        Self(self.0.saturating_add(duration_secs(d)))
    }

    /// `self - d`, saturating.
    pub fn minus(self, d: Duration) -> Self {
        Self(self.0.saturating_sub(duration_secs(d)))
    }

    /// Absolute distance between two moments.
    pub fn abs_diff(self, other: Self) -> Duration {
        Duration::from_secs(self.0.abs_diff(other.0))
    }

    /// Convert to [`der::DateTime`], if the moment lies in 1970..=9999.
    pub fn to_der_datetime(self) -> Option<der::DateTime> {
        let secs = u64::try_from(self.0).ok()?;
        der::DateTime::from_unix_duration(Duration::from_secs(secs)).ok()
    }
}

/// `YYYY-MM-DDThh:mm:ss[.f][Z|(+|-)hh:mm]`, offsets up to 14 hours. Without
/// `require_seconds`, missing minutes and seconds count as zero.
fn parse_iso8601(s: &str, require_seconds: bool) -> Option<Moment> {
    let (date, rest) = s.split_once('T')?;
    let (time, offset_secs) = if let Some(t) = rest.strip_suffix('Z') {
        (t, 0i64)
    } else if let Some(pos) = rest.rfind(['+', '-']) {
        let (t, tz) = rest.split_at(pos);
        let sign = if tz.starts_with('-') { -1 } else { 1 };
        let (h, m) = tz.get(1..)?.split_once(':')?;
        let (h, m): (i64, i64) = (h.parse().ok()?, m.parse().ok()?);
        if !(0..=14).contains(&h) || !(0..=59).contains(&m) {
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
    let (h, mi, se) = if require_seconds {
        (t.next()?, t.next()?, t.next()?)
    } else {
        (t.next()?, t.next().unwrap_or("0"), t.next().unwrap_or("0"))
    };
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
    Some(Moment::from_unix_secs(
        m.unix_secs().checked_sub(offset_secs)?,
    ))
}

fn duration_secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

impl From<der::DateTime> for Moment {
    fn from(dt: der::DateTime) -> Self {
        Self(duration_secs(dt.unix_duration()))
    }
}

impl From<Time> for Moment {
    fn from(t: Time) -> Self {
        Self::from(t.to_date_time())
    }
}

impl From<&Time> for Moment {
    fn from(t: &Time) -> Self {
        Self::from(t.to_date_time())
    }
}

impl fmt::Display for Moment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_der_datetime() {
            Some(dt) => write!(
                f,
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                dt.year(),
                dt.month(),
                dt.day(),
                dt.hour(),
                dt.minutes(),
                dt.seconds()
            ),
            None => write!(f, "@{}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_round_trip() {
        let m = Moment::parse_rfc3339("2012-10-12T00:00:00+00:00").expect("parse");
        assert_eq!(m.to_string(), "2012-10-12T00:00:00Z");
        assert_eq!(
            Moment::parse_rfc3339("2021-08-19T12:20:44Z")
                .map(|m| m.to_string())
                .as_deref(),
            Some("2021-08-19T12:20:44Z")
        );
        assert_eq!(Moment::parse_rfc3339("garbage"), None);
        assert_eq!(
            Moment::parse_rfc3339("2012-10-12T02:30:00.75+02:30"),
            Moment::parse_rfc3339("2012-10-12T00:00:00Z")
        );
        assert_eq!(
            Moment::parse_rfc3339("2012-10-11T19:00:00-05:00"),
            Moment::parse_rfc3339("2012-10-12T00:00:00Z")
        );
        assert_eq!(
            Moment::parse_rfc3339("2012-10-12"),
            Moment::parse_rfc3339("2012-10-12T00:00:00Z")
        );
        assert_eq!(Moment::parse_rfc3339("2012-10-12T00:00:00+15:00"), None);
        assert_eq!(
            Moment::parse_xsd_datetime("2016-06-01T00:00:00"),
            Moment::parse_rfc3339("2016-06-01T00:00:00Z")
        );
        assert_eq!(Moment::parse_xsd_datetime("2016-06-01"), None);
        assert_eq!(Moment::parse_xsd_datetime("2016-06-01T00:00"), None);
        assert_eq!(Moment::parse_rfc3339("2021-02-30T00:00:00Z"), None);
    }
}
