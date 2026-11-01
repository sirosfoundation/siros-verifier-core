//! Calendar dates for the age check, without a time library: proleptic Gregorian, year 0000 to 9999.

use siros_verifier_core::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Date {
    pub y: i32,
    pub m: u32,
    pub d: u32,
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

impl Date {
    /// Strict `YYYY-MM-DD`: four, two and two ASCII digits, a real date.
    pub fn parse(text: &str, what: &str) -> Result<Self> {
        let b = text.as_bytes();
        let ok_shape = b.len() == 10
            && b[4] == b'-'
            && b[7] == b'-'
            && b.iter()
                .enumerate()
                .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit());
        if !ok_shape {
            return Err(Error::Policy(format!(
                "{what} {text:?} is not a YYYY-MM-DD date"
            )));
        }
        let n = |r: std::ops::Range<usize>| text[r].parse::<u32>().expect("digits checked");
        let (y, m, d) = (n(0..4) as i32, n(5..7), n(8..10));
        if m == 0 || m > 12 || d == 0 || d > days_in_month(y, m) {
            return Err(Error::Policy(format!(
                "{what} {text:?} is not a YYYY-MM-DD date"
            )));
        }
        Ok(Self { y, m, d })
    }

    /// Days since 1970-01-01 (Howard Hinnant's algorithm).
    pub fn to_days(self) -> i64 {
        let y = i64::from(self.y) - i64::from(self.m <= 2);
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = (i64::from(self.m) + 9) % 12;
        let doy = (153 * mp + 2) / 5 + i64::from(self.d) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    pub fn from_days(days: i64) -> (i64, u32, u32) {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let y = yoe + era * 400 + i64::from(m <= 2);
        (y, m, d)
    }

    /// This date moved by whole days, as text. Refuses a result outside year 0000..=9999, which the circuits'
    /// 10-byte date cannot express (and which is never clamped: clamping "after the last day" to "no bound" would
    /// turn an unsatisfiable request into one everybody satisfies).
    pub fn shifted(self, days: i64, what: &str, original: &str) -> Result<String> {
        let (y, m, d) = Self::from_days(self.to_days() + days);
        if !(0..=9999).contains(&y) {
            return Err(Error::Policy(format!(
                "{what} {original} shifts to year {y}, which the circuits' 10-byte date cannot express"
            )));
        }
        Ok(format!("{y:04}-{m:02}-{d:02}"))
    }
}
