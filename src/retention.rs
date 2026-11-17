//! Calendar quarter encoding and retention verification utilities (`SPEC.md` §6.3).

/// Earliest representable voucher retention year.
pub const MIN_QUARTER_YEAR: u16 = 2020;
/// Latest representable voucher retention year.
pub const MAX_QUARTER_YEAR: u16 = 9999;
/// Safety margin in seconds after quarter end before lock buckets may be purged (30 days).
pub const RETENTION_PURGE_GRACE_SECS: u64 = 30 * 86_400;

/// Encodes a `(year, quarter)` pair (`year` in `2020..=9999`, `quarter` in `1..=4`)
/// as `year * 4 + (quarter - 1)`.
pub fn encode_quarter(year: u16, quarter: u8) -> Result<u16, &'static str> {
    if !(MIN_QUARTER_YEAR..=MAX_QUARTER_YEAR).contains(&year) || !(1..=4).contains(&quarter) {
        return Err("quarter out of range");
    }
    Ok(year * 4 + u16::from(quarter - 1))
}

/// Decodes a canonical encoded quarter into `(year, quarter)` (`quarter` in `1..=4`).
pub fn decode_quarter(encoded: u16) -> Result<(u16, u8), &'static str> {
    let year = encoded / 4;
    let quarter = (encoded % 4) as u8 + 1;
    if !(MIN_QUARTER_YEAR..=MAX_QUARTER_YEAR).contains(&year) {
        return Err("encoded quarter year out of range");
    }
    Ok((year, quarter))
}

/// Formats an encoded quarter as `"YYYY-QN"` (e.g., `"2031-Q2"`).
pub fn format_quarter(encoded: u16) -> Result<String, &'static str> {
    let (year, quarter) = decode_quarter(encoded)?;
    Ok(format!("{year:04}-Q{quarter}"))
}

/// Parses `"YYYY-QN"` into an encoded quarter `u16`.
pub fn parse_quarter(s: &str) -> Result<u16, &'static str> {
    if s.len() != 7 || &s[4..6] != "-Q" {
        return Err("invalid quarter format");
    }
    let year: u16 = s[0..4].parse().map_err(|_| "invalid quarter year")?;
    let quarter: u8 = s[6..7].parse().map_err(|_| "invalid quarter digit")?;
    encode_quarter(year, quarter)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Converts UTC Unix seconds into Gregorian `(year, month)` (`month` in `1..=12`)
/// using Howard Hinnant's civil-from-days algorithm.
fn utc_secs_to_year_month(secs: u64) -> Option<(u16, u8)> {
    let days = i64::try_from(secs / 86_400).ok()?;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let m = mp + if mp < 10 { 3 } else { -9 }; // [1, 12]
    let year = y + if m <= 2 { 1 } else { 0 };
    let year_u16 = u16::try_from(year).ok()?;
    let month_u8 = u8::try_from(m).ok()?;
    Some((year_u16, month_u8))
}

/// Converts Gregorian `(year, month, 1)` (`00:00:00Z`) to UTC Unix seconds.
fn year_month_first_unix_secs(year: u16, month: u8) -> Result<u64, &'static str> {
    if !(1..=12).contains(&month) {
        return Err("invalid month");
    }
    let y = i64::from(year) - if month <= 2 { 1 } else { 0 };
    let m = i64::from(month);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5; // d = 1 => d - 1 = 0
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400).map_err(|_| "pre-epoch timestamp")
}

/// Maps a UTC Unix timestamp in milliseconds to its encoded calendar quarter.
pub fn quarter_of_timestamp_ms(ts_ms: u64) -> Option<u16> {
    if ts_ms == 0 {
        return None;
    }
    let (year, month) = utc_secs_to_year_month(ts_ms / 1000)?;
    let quarter = (month - 1) / 3 + 1;
    encode_quarter(year, quarter).ok()
}

/// Returns the exclusive UTC Unix second immediately following the end of `encoded`
/// (i.e., `00:00:00Z` on the first day of the next quarter).
pub fn quarter_end_exclusive_secs(encoded: u16) -> Result<u64, &'static str> {
    let (year, quarter) = decode_quarter(encoded)?;
    let (next_year, next_month) = match quarter {
        1 => (year, 4),
        2 => (year, 7),
        3 => (year, 10),
        4 => (year.checked_add(1).ok_or("year overflow")?, 1),
        _ => return Err("invalid quarter"),
    };
    let _ = is_leap_year(i64::from(next_year));
    year_month_first_unix_secs(next_year, next_month)
}

/// Returns the UTC Unix second after which an entire bucket for `retain_until_quarter`
/// may physically be deleted (`quarter_end_exclusive + 30 days`).
pub fn bucket_purge_after_secs(retain_until_quarter: u16) -> Result<u64, &'static str> {
    quarter_end_exclusive_secs(retain_until_quarter)?
        .checked_add(RETENTION_PURGE_GRACE_SECS)
        .ok_or("purge timestamp overflow")
}

/// Verifies whether `retain_until_quarter` fully covers the voucher's `init.deletable_at`
/// retention timestamp (Concept §6.6; fails closed on invalid inputs).
pub fn retention_covers(deletable_at_ms: u64, retain_until_quarter: u16) -> bool {
    if decode_quarter(retain_until_quarter).is_err() {
        return false;
    }
    match quarter_of_timestamp_ms(deletable_at_ms) {
        Some(required_quarter) => retain_until_quarter >= required_quarter,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarter_roundtrip_and_formatting() {
        let q = encode_quarter(2031, 2).unwrap();
        assert_eq!(q, 8125);
        assert_eq!(decode_quarter(q).unwrap(), (2031, 2));
        assert_eq!(format_quarter(q).unwrap(), "2031-Q2");
        assert_eq!(parse_quarter("2031-Q2").unwrap(), q);

        assert!(encode_quarter(2019, 4).is_err());
        assert!(encode_quarter(2031, 0).is_err());
        assert!(encode_quarter(2031, 5).is_err());
        assert!(parse_quarter("2031-Q5").is_err());
        assert!(parse_quarter("2031Q2").is_err());
    }

    #[test]
    fn test_retention_covers_quarter_and_year_boundaries() {
        // 2031-03-31T23:59:59.999Z -> last ms of 2031-Q1
        let q1_end_sec = year_month_first_unix_secs(2031, 4).unwrap();
        let q1_last_ms = q1_end_sec * 1000 - 1;
        let q2_first_ms = q1_end_sec * 1000;

        let q1_2031 = encode_quarter(2031, 1).unwrap();
        let q2_2031 = encode_quarter(2031, 2).unwrap();

        assert_eq!(quarter_of_timestamp_ms(q1_last_ms), Some(q1_2031));
        assert_eq!(quarter_of_timestamp_ms(q2_first_ms), Some(q2_2031));

        assert!(retention_covers(q1_last_ms, q1_2031));
        assert!(retention_covers(q1_last_ms, q2_2031));
        assert!(!retention_covers(q2_first_ms, q1_2031));
        assert!(retention_covers(q2_first_ms, q2_2031));

        // Year boundary: 2031-12-31T23:59:59.999Z vs 2032-01-01T00:00:00.000Z
        let y2032_start_sec = year_month_first_unix_secs(2032, 1).unwrap();
        let dec31_last_ms = y2032_start_sec * 1000 - 1;
        let jan01_first_ms = y2032_start_sec * 1000;

        let q4_2031 = encode_quarter(2031, 4).unwrap();
        let q1_2032 = encode_quarter(2032, 1).unwrap();

        assert!(retention_covers(dec31_last_ms, q4_2031));
        assert!(!retention_covers(jan01_first_ms, q4_2031));
        assert!(retention_covers(jan01_first_ms, q1_2032));

        // Leap day 2028-02-29 belongs to 2028-Q1, and 2028-04-01 starts Q2 (91 days from Jan 1 in leap year)
        let jan1_2028 = year_month_first_unix_secs(2028, 1).unwrap();
        let apr1_2028 = year_month_first_unix_secs(2028, 4).unwrap();
        assert_eq!((apr1_2028 - jan1_2028) / 86_400, 91);
        let q1_2028 = encode_quarter(2028, 1).unwrap();
        assert_eq!(quarter_end_exclusive_secs(q1_2028).unwrap(), apr1_2028);
        assert_eq!(
            bucket_purge_after_secs(q1_2028).unwrap(),
            apr1_2028 + 30 * 86_400
        );

        // Zero timestamp fails closed
        assert!(!retention_covers(0, q4_2031));
    }
}
