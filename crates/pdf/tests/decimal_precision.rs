//! Regressions for decimal collisions in lopdf's f32 object representation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pdf::generic::{read_object, ParseContext};
use sigis_pdf::misc::Cursor;

#[test]
fn common_decimals_and_equivalent_formatting_remain_supported() {
    for strict in [true, false] {
        let context = ParseContext {
            strict,
            ..Default::default()
        };
        for raw in [
            "0.1",
            "+.1000",
            "000.1000",
            "595.28",
            "32.00001",
            ".5",
            "1.",
            "-0.000",
            "-.0",
            "0.00000000000000000001",
        ] {
            assert!(
                read_object(&mut Cursor::new(raw.as_bytes()), &context).is_ok(),
                "rejected {raw:?}, strict={strict}"
            );
        }
    }
}

#[test]
fn distinct_decimals_cannot_collapse_into_an_accepted_float() {
    for (canonical, colliding) in [
        ("1.0", "1.00000001"),
        ("1.0", "1.00000002"),
        ("-1.0", "-1.00000001"),
        ("0.1", ".1000000001"),
        ("595.28", "595.28000001"),
    ] {
        assert_eq!(canonical.parse::<f32>(), colliding.parse::<f32>());
        for strict in [true, false] {
            let context = ParseContext {
                strict,
                ..Default::default()
            };
            assert!(read_object(&mut Cursor::new(canonical.as_bytes()), &context).is_ok());
            assert!(
                read_object(&mut Cursor::new(colliding.as_bytes()), &context).is_err(),
                "precision loss accepted for {colliding:?}, strict={strict}"
            );
        }
    }
}

#[test]
fn decimal_overflow_and_underflow_are_rejected() {
    for strict in [true, false] {
        let context = ParseContext {
            strict,
            ..Default::default()
        };
        for raw in [
            "9999999999999999999999999999999999999999999999.0",
            "0.00000000000000000000000000000000000000000000000001",
            "-0.00000000000000000000000000000000000000000000000001",
        ] {
            assert!(
                read_object(&mut Cursor::new(raw.as_bytes()), &context).is_err(),
                "out-of-range decimal accepted for {raw:?}, strict={strict}"
            );
        }
    }
}
