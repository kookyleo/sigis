//! Five original CLI LTV/decode functions; twelve original parameter rows.
//! Current-clock signer1-long credentials adapt the frozen original test PKI.
#[path = "common/ltv_cases.rs"]
mod cases;

/// pyhanko-cli/test_cli_ltv.py::test_cli_lta_update: RSA/ECDSA/Ed25519.
#[test]
fn test_cli_lta_update() {
    for architecture in ["rsa", "ecdsa", "ed25519"] {
        let case = cases::Case::new(architecture, false);
        case.sign(true);
        case.command("ltaupdate", true, true);
        case.check(1);
        case.reference("lta", true);
    }
}

/// pyhanko-cli/test_cli_ltv.py::test_cli_ltvfix: three architectures x two bools.
#[test]
fn test_cli_ltvfix() {
    for architecture in ["rsa", "ecdsa", "ed25519"] {
        for with_lta_timestamp in [true, false] {
            let case = cases::Case::new(architecture, false);
            case.sign(false);
            case.command("ltvfix", with_lta_timestamp, true);
            case.check(usize::from(with_lta_timestamp));
            case.reference("ltvfix", with_lta_timestamp);
        }
    }
}

/// pyhanko-cli/test_cli_ltv.py::test_cli_ltvfix_require_signed_field.
#[test]
fn test_cli_ltvfix_require_signed_field() {
    let case = cases::Case::new("rsa", false);
    case.require_signed_field();
    case.reference("unsigned", false);
}

/// pyhanko-cli/test_cli_decode_limits.py::test_ltaupdate: exact FLAG pair.
#[test]
fn test_ltaupdate() {
    let case = cases::Case::new("rsa", true);
    case.sign(false);
    case.command("ltaupdate", true, false);
    case.command("ltaupdate", true, true);
    case.check(1);
    case.reference("decode-ltaupdate", true);
}

/// pyhanko-cli/test_cli_decode_limits.py::test_ltvfix: exact FLAG pair.
#[test]
fn test_ltvfix() {
    let case = cases::Case::new("rsa", true);
    case.sign(false);
    case.command("ltvfix", true, false);
    case.command("ltvfix", true, true);
    case.check(1);
    case.reference("decode-ltvfix", true);
}
