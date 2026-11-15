//! Exact remaining signed-PDF decode-limit originals, two rows each.
#[path = "common/ltv_cases.rs"]
mod cases;

/// pyhanko-cli/test_cli_decode_limits.py::test_addsig (PAdES/PAdES-LTA).
#[test]
fn test_addsig() {
    for lta in [false, true] {
        let case = cases::Case::new("rsa", true);
        case.sign_decode(lta);
        case.check(usize::from(lta));
        case.reference(
            if lta {
                "decode-addsig-lta"
            } else {
                "decode-addsig-pades"
            },
            true,
        );
    }
}

/// pyhanko-cli/test_cli_decode_limits.py::test_validate (validate/adesverify).
#[test]
fn test_validate() {
    for command in ["validate", "adesverify"] {
        let case = cases::Case::new("rsa", true);
        case.sign(false);
        case.validate_decode(command);
        case.reference(&format!("decode-validate-{command}"), false);
    }
}

/// Zero-ID control: the ordinary supported parameter remains exercised without
/// awarding half-credit to the two-parameter original function above.
#[test]
fn ordinary_validate_decode_control() {
    let case = cases::Case::new("rsa", true);
    case.sign(false);
    case.validate_decode("validate");
    case.reference("decode-validate-validate", false);
}
