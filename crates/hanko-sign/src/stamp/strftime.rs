//! A subset of C's `strftime` for UTC moments, used to render the `ts`
//! stamp parameter (`datetime.strftime`).

use sigis_pki_core::time::Moment;

const MONTHS: [&str; 12] = [
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
    "November", "December",
];
const DAYS: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

/// Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Format `t` (in UTC) with `fmt`. Supported directives: `%Y %y %m %d %e
/// %H %I %M %S %p %j %b %B %h %a %A %w %u %Z %z %F %T %%`; others are
/// copied verbatim.
pub fn strftime(t: Moment, fmt: &str) -> String {
    let secs = t.unix_secs();
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let wd = (days + 3).rem_euclid(7) as usize; // 0 = Monday
    let cum = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let yday = cum[(m - 1) as usize] + d as i64 + i64::from(m > 2 && is_leap(y));
    let mut out = String::new();
    let mut it = fmt.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let Some(n) = it.next() else {
            out.push('%');
            break;
        };
        let s = match n {
            'Y' => format!("{y:04}"),
            'y' => format!("{:02}", y.rem_euclid(100)),
            'm' => format!("{m:02}"),
            'd' => format!("{d:02}"),
            'e' => format!("{d:2}"),
            'H' => format!("{hh:02}"),
            'I' => format!("{:02}", if hh % 12 == 0 { 12 } else { hh % 12 }),
            'M' => format!("{mm:02}"),
            'S' => format!("{ss:02}"),
            'p' => (if hh < 12 { "AM" } else { "PM" }).to_owned(),
            'j' => format!("{yday:03}"),
            'b' | 'h' => MONTHS[(m - 1) as usize][..3].to_owned(),
            'B' => MONTHS[(m - 1) as usize].to_owned(),
            'a' => DAYS[wd][..3].to_owned(),
            'A' => DAYS[wd].to_owned(),
            'w' => format!("{}", (wd + 1) % 7),
            'u' => format!("{}", wd + 1),
            'Z' => "UTC".to_owned(),
            'z' => "+0000".to_owned(),
            'F' => format!("{y:04}-{m:02}-{d:02}"),
            'T' => format!("{hh:02}:{mm:02}:{ss:02}"),
            '%' => "%".to_owned(),
            other => format!("%{other}"),
        };
        out.push_str(&s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let t = Moment::from_ymd_hms(2020, 11, 1, 13, 5, 9).unwrap_or(Moment::from_unix_secs(0));
        assert_eq!(strftime(t, "%Y-%m-%d %H:%M:%S %Z"), "2020-11-01 13:05:09 UTC");
        assert_eq!(strftime(t, "%a %b %j"), "Sun Nov 306");
    }
}
