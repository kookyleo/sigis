// Exact pyHanko 0.38.1 test_cli_decode_limits.py ports (MIT).
// Three unique original functions, six cases; all assertions remain enabled.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "common/decode_limits_simple_cases.rs"]
mod cases;
#[path = "common/mod.rs"]
mod common;
#[path = "common/signing_record.rs"]
mod signing_record;
use cases::{Case, SIMPLE};

/// Upstream test_simple_commands: encrypt/list/addfields/addfields-resave, all four.
#[test]
fn test_simple_commands() {
    let errors: Vec<_> = SIMPLE
        .into_iter()
        .filter_map(|kind| Case::new(kind).check().err())
        .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}
/// Upstream test_text_stamp: exact configured text style, both flag states.
#[test]
fn test_text_stamp() {
    Case::new("text").check().unwrap();
}
/// Upstream test_qr_stamp: nosmoke is an upstream marker, never a provider skip.
#[test]
fn test_qr_stamp() {
    Case::new("qr").check().unwrap();
}

/// Supplemental: encrypted field editing stays unsupported, without output damage.
#[test]
fn encrypted_field_management_keeps_its_refusal() {
    use std::{fs, process::Command};
    for resave in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.pdf");
        let output = dir.path().join("out.pdf");
        fs::copy(
            sigis_testdata::pyhanko(&["pdf", "minimal-aes256.pdf"]),
            &input,
        )
        .unwrap();
        fs::write(&output, cases::SENTINEL).unwrap();
        let mut args: Vec<String> = [
            "sign",
            "addfields",
            cases::FLAG,
            "--field",
            "1/0,0,100,100/Sig1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if resave {
            args.push("--resave".into());
        }
        args.extend([
            input.to_string_lossy().into_owned(),
            output.to_string_lossy().into_owned(),
        ]);
        let before = signing_record::before(std::slice::from_ref(&input));
        let result = Command::new(common::cli())
            .args(&args)
            .current_dir(dir.path())
            .output()
            .unwrap();
        signing_record::process(
            "decode-simple-encrypted-field-refusal",
            &args,
            dir.path(),
            b"",
            common::cli(),
            &result,
            &before,
            &[("unchanged-output-sentinel", &output)],
        );
        assert_eq!(result.status.code(), Some(1), "{}", cases::text(&result));
        assert!(cases::text(&result).contains(
            "signature field management requires authentication for encrypted documents"
        ));
        assert_eq!(fs::read(output).unwrap(), cases::SENTINEL);
    }
}
