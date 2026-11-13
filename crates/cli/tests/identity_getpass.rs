//! Two actual-CLI originals; four architectures each, not a provider substitute.
#[path = "common/identity_cases.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;
#[test]
fn test_cli_addsig_pemder_with_identity_setup() {
    let mut failures = Vec::new();
    for arch in cases::ARCHES {
        let case = cases::Case::new(arch, "identity");
        let native = case.native();
        let reference = case.reference();
        assert_eq!(reference["code"], 0);
        if native["exit_code"] == 0 {
            case.verify();
        } else {
            assert_eq!(
                std::fs::read(case.path("output.pdf")).unwrap(),
                b"identity-getpass-output-sentinel"
            );
            failures.push(format!("{arch}: {native}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn test_cli_sign_getpass() {
    let mut failures = Vec::new();
    for arch in cases::ARCHES {
        let case = cases::Case::new(arch, "getpass");
        let native = case.native();
        let reference = case.reference();
        assert_eq!(reference["code"], 0);
        assert_eq!(reference["getpass_calls"].as_array().unwrap().len(), 1);
        if native["exit_code"] == 0 {
            case.verify();
        } else {
            assert_eq!(
                std::fs::read(case.path("output.pdf")).unwrap(),
                b"identity-getpass-output-sentinel"
            );
            failures.push(format!("{arch}: {native}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
