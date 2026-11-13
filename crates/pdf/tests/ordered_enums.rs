// Exact assertion ports from pyHanko 0.38.1 test_internal_utils.py
// (MIT, see LICENSE-pyHanko). These use existing production PDF security
// enums rather than introducing test-only substitutes for the upstream types.

use std::fmt::Debug;

use sigis_pdf::crypt::api::{AuthStatus, SecurityHandlerVersion};

#[derive(Clone, Copy, Debug)]
enum Comparison {
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

impl Comparison {
    fn evaluate<T: Ord>(self, left: T, right: T) -> bool {
        match self {
            Self::Greater => left > right,
            Self::GreaterOrEqual => left >= right,
            Self::Less => left < right,
            Self::LessOrEqual => left <= right,
        }
    }
}

fn assert_comparisons<T: Copy + Debug + Ord>(cases: &[(&str, T, T, Comparison, bool)]) {
    for &(expression, left, right, comparison, expected) in cases {
        assert_eq!(
            comparison.evaluate(left, right),
            expected,
            "upstream assertion {expression}; actual operands {left:?}, {right:?}"
        );
    }
}

#[test]
fn test_ordered_enum() {
    use Comparison::{Greater, GreaterOrEqual, Less, LessOrEqual};

    // The upstream local enum uses values 1 and 2. AuthStatus is a real
    // OrderedEnum consumer in Python, with those values for USER and OWNER.
    let version1 = AuthStatus::User;
    let version2 = AuthStatus::Owner;

    assert_comparisons(&[
        ("VER2 > VER1", version2, version1, Greater, true),
        ("VER2 >= VER1", version2, version1, GreaterOrEqual, true),
        ("not (VER1 > VER1)", version1, version1, Greater, false),
        ("VER1 < VER2", version1, version2, Less, true),
        ("VER1 <= VER2", version1, version2, LessOrEqual, true),
        ("not (VER1 < VER1)", version1, version1, Less, false),
    ]);
}

#[test]
fn test_version_enum() {
    use Comparison::{Greater, GreaterOrEqual, Less, LessOrEqual};

    // This production enum is also a VersionEnum consumer in Python.
    // Its first two versions have exactly the upstream values 1 and 2;
    // Other has raw value None and represents every future version.
    let version1 = SecurityHandlerVersion::Rc4_40;
    let version2 = SecurityHandlerVersion::Rc4LongerKeys;
    let future = SecurityHandlerVersion::Other;
    assert_eq!(version1.value(), Some(1));
    assert_eq!(version2.value(), Some(2));
    assert_eq!(future.value(), None);

    assert_comparisons(&[
        ("VER2 > VER1", version2, version1, Greater, true),
        ("VER2 >= VER1", version2, version1, GreaterOrEqual, true),
        ("FUTURE > VER1", future, version1, Greater, true),
        ("FUTURE >= VER1", future, version1, GreaterOrEqual, true),
        ("not (FUTURE > FUTURE)", future, future, Greater, false),
        (
            "not (VER2 >= FUTURE)",
            version2,
            future,
            GreaterOrEqual,
            false,
        ),
        ("not (VER2 > FUTURE)", version2, future, Greater, false),
        ("VER1 < VER2", version1, version2, Less, true),
        ("VER1 <= VER2", version1, version2, LessOrEqual, true),
        ("VER1 < FUTURE", version1, future, Less, true),
        ("VER1 <= FUTURE", version1, future, LessOrEqual, true),
        ("not (FUTURE < FUTURE)", future, future, Less, false),
        ("not (FUTURE <= VER2)", future, version2, LessOrEqual, false),
        ("not (FUTURE < VER2)", future, version2, Less, false),
    ]);
}
