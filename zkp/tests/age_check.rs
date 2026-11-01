//! age_check parameters to the circuits' inclusive bounds (ported from SUNET/vc's agecheck tests).
use siros_verifier_zkp::dates::Date;
use siros_verifier_zkp::functions::*;

fn chk(ge: Option<&str>, gt: Option<&str>, le: Option<&str>, lt: Option<&str>) -> AgeCheck {
    let o = |s: Option<&str>| s.map(str::to_owned);
    AgeCheck {
        ge: o(ge),
        gt: o(gt),
        le: o(le),
        lt: o(lt),
    }
}
fn b(e: &str, c: &str) -> AgeBounds {
    AgeBounds {
        earliest: e.into(),
        cutoff: c.into(),
    }
}
fn err<T: std::fmt::Debug>(r: siros_verifier_core::Result<T>) -> String {
    r.err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "OK".into())
}

#[test]
fn maps_to_inclusive_bounds() {
    let cases = [
        (
            "ge passes through",
            chk(Some("2008-10-07"), None, None, None),
            b("2008-10-07", NO_UPPER_BOUND),
        ),
        (
            "gt is one day later",
            chk(None, Some("2008-10-07"), None, None),
            b("2008-10-08", NO_UPPER_BOUND),
        ),
        (
            "le passes through",
            chk(None, None, Some("2008-10-07"), None),
            b(NO_LOWER_BOUND, "2008-10-07"),
        ),
        (
            "lt is one day earlier",
            chk(None, None, None, Some("2008-10-07")),
            b(NO_LOWER_BOUND, "2008-10-06"),
        ),
        (
            "absent bounds disable both ends",
            chk(None, None, None, None),
            b(NO_LOWER_BOUND, NO_UPPER_BOUND),
        ),
        (
            "both ends",
            chk(Some("2000-01-01"), None, Some("2008-10-07"), None),
            b("2000-01-01", "2008-10-07"),
        ),
        (
            "gt at the end of a month",
            chk(None, Some("2008-01-31"), None, None),
            b("2008-02-01", NO_UPPER_BOUND),
        ),
        (
            "lt just after a leap day",
            chk(None, None, None, Some("2008-03-01")),
            b(NO_LOWER_BOUND, "2008-02-29"),
        ),
        (
            "gt across a year end",
            chk(None, Some("2007-12-31"), None, None),
            b("2008-01-01", NO_UPPER_BOUND),
        ),
        (
            "lt across a year start",
            chk(None, None, None, Some("2008-01-01")),
            b(NO_LOWER_BOUND, "2007-12-31"),
        ),
        (
            "gt on a non-leap february end",
            chk(None, Some("2009-02-28"), None, None),
            b("2009-03-01", NO_UPPER_BOUND),
        ),
    ];
    for (name, check, want) in cases {
        assert_eq!(check.bounds().unwrap(), want, "{name}");
    }
}

#[test]
fn a_narrow_window_is_refused_and_the_boundary_is_inclusive() {
    assert!(
        err(chk(Some("2008-01-01"), None, Some("2008-01-02"), None).bounds())
            .contains("at least 365")
    );
    assert!(
        chk(Some("2001-01-01"), None, Some("2001-12-30"), None)
            .bounds()
            .is_err(),
        "364 days is still short"
    );
    chk(Some("2001-01-01"), None, Some("2001-12-31"), None)
        .bounds()
        .expect("365 inclusive days is the minimum");
    for c in [
        chk(Some("2008-01-01"), None, None, None),
        chk(None, None, Some("2008-01-01"), None),
        chk(None, Some("2008-01-01"), None, None),
        chk(None, None, None, Some("2008-01-01")),
    ] {
        c.bounds().expect("one bound is not a window");
    }
}

#[test]
fn an_impossible_window_is_refused() {
    assert!(
        err(chk(Some("2008-10-07"), None, Some("2000-01-01"), None).bounds())
            .contains("no birth date satisfies")
    );
    assert!(
        chk(Some("2008-10-07"), None, Some("2008-10-07"), None)
            .bounds()
            .is_err(),
        "one day is not a range"
    );
}

#[test]
fn two_spellings_of_one_bound_are_refused_not_resolved() {
    assert!(
        err(chk(Some("2000-01-01"), Some("2000-01-01"), None, None).bounds())
            .contains("lower bound")
    );
    assert!(
        err(chk(None, None, Some("2008-01-01"), Some("2008-01-01")).bounds())
            .contains("upper bound")
    );
}

#[test]
fn malformed_dates_never_reach_the_circuit() {
    for bad in [
        "2008-13-01",
        "not a date",
        "2008-02-30",
        "08-01-01",
        "2008-1-5",
        "2008-01-01 ",
        "２００８-01-01",
        "2009-02-29",
        "",
    ] {
        assert!(
            chk(Some(bad), None, None, None).bounds().is_err(),
            "ge {bad:?}"
        );
        assert!(
            chk(None, Some(bad), None, None).bounds().is_err(),
            "gt {bad:?}"
        );
        assert!(
            chk(None, None, Some(bad), None).bounds().is_err(),
            "le {bad:?}"
        );
        assert!(
            chk(None, None, None, Some(bad)).bounds().is_err(),
            "lt {bad:?}"
        );
    }
    chk(Some("2008-02-29"), None, None, None)
        .bounds()
        .expect("2008 is a leap year");
    chk(Some("2000-02-29"), None, None, None)
        .bounds()
        .expect("2000 is a leap year");
    assert!(
        chk(Some("1900-02-29"), None, None, None).bounds().is_err(),
        "1900 is not"
    );
}

#[test]
fn a_shift_out_of_the_date_format_is_refused_not_clamped() {
    let e = err(chk(None, Some("9999-12-31"), None, None).bounds());
    assert!(e.contains("10000"), "{e}");
    let e = err(chk(None, None, None, Some("0000-01-01")).bounds());
    assert!(e.contains("cannot express"), "{e}");
    // the days either side of the edges still work
    assert_eq!(
        chk(None, Some("9999-12-30"), None, None)
            .bounds()
            .unwrap()
            .earliest,
        "9999-12-31"
    );
    assert_eq!(
        chk(None, None, None, Some("0000-01-02"))
            .bounds()
            .unwrap()
            .cutoff,
        "0000-01-01"
    );
}

#[test]
fn calendar_arithmetic_round_trips_over_the_whole_range() {
    // every day from year 0 to 9999 would be slow; sample densely around the interesting places and sparsely elsewhere
    let mut days: Vec<i64> = (-719_528..-719_528 + 800).collect(); // year 0000 start
    days.extend((0..800).map(|i| i * 3 + 10_000)); // 1997..
    days.extend((2_932_000..2_932_896).collect::<Vec<_>>()); // up to 9999-12-31
    for d in days {
        let (y, m, dd) = Date::from_days(d);
        let again = Date {
            y: y as i32,
            m,
            d: dd,
        }
        .to_days();
        assert_eq!(again, d, "{y:04}-{m:02}-{dd:02}");
    }
    assert_eq!(
        Date {
            y: 1970,
            m: 1,
            d: 1
        }
        .to_days(),
        0
    );
    assert_eq!(
        Date {
            y: 2000,
            m: 3,
            d: 1
        }
        .to_days()
            - Date {
                y: 2000,
                m: 2,
                d: 28
            }
            .to_days(),
        2,
        "leap 2000"
    );
    assert_eq!(
        Date {
            y: 1900,
            m: 3,
            d: 1
        }
        .to_days()
            - Date {
                y: 1900,
                m: 2,
                d: 28
            }
            .to_days(),
        1,
        "not leap 1900"
    );
}
