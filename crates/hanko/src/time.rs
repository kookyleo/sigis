//! Points in time used for validation (the "time of interest").
//!
//! [`Moment`] is a UTC instant with one-second resolution, the resolution of
//! X.509 `Time`. It converts to and from [`der::DateTime`], X.509 [`Time`] and
//! certval's [`TimeOfInterest`](certval::TimeOfInterest).

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

    /// Parse an RFC 3339 / ISO 8601 UTC timestamp such as
    /// `2012-10-12T00:00:00+00:00` or `2012-10-12T00:00:00Z`.
    pub fn parse_rfc3339(s: &str) -> Option<Self> {
        let s = s.trim();
        let body = s
            .strip_suffix("+00:00")
            .or_else(|| s.strip_suffix('Z'))
            .unwrap_or(s);
        let (date, time) = body.split_once('T').unwrap_or((body, "00:00:00"));
        let mut d = date.split('-').map(str::parse::<u16>);
        let mut t = time
            .split(':')
            .map(|p| p.split('.').next().unwrap_or(p).parse::<u8>());
        let (year, month, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
        let (hour, min, sec) = (
            t.next()?.ok()?,
            t.next().unwrap_or(Ok(0)).ok()?,
            t.next().unwrap_or(Ok(0)).ok()?,
        );
        Self::from_ymd_hms(
            year,
            u8::try_from(month).ok()?,
            u8::try_from(day).ok()?,
            hour,
            min,
            sec,
        )
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

    /// Convert to certval's time of interest.
    pub fn to_time_of_interest(self) -> Option<certval::TimeOfInterest> {
        self.to_der_datetime().map(certval::TimeOfInterest)
    }
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
        assert_eq!(Moment::parse_rfc3339("2021-02-30T00:00:00Z"), None);
    }
}
