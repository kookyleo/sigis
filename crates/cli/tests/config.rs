//! Exact assertions ported from pyHanko 0.38.1 `test_config.py` (MIT).
#[path = "common/mod.rs"]
mod common;

use sigis_cli::config::*;
use std::collections::BTreeSet;

fn cfg(s: &str) -> CliConfig {
    CliConfig::parse(s).unwrap()
}
fn vc(s: &str) -> CliConfig {
    cfg(&format!(
        "validation-contexts:\n  default:\n{}",
        s.lines().map(|s| format!("    {s}\n")).collect::<String>()
    ))
}
fn token(s: &str) -> CliConfig {
    cfg(&format!(
        "pkcs11-setups:\n  foo:\n    module-path: /path/to/libfoo.so\n{}",
        s.lines().map(|s| format!("    {s}\n")).collect::<String>()
    ))
}
fn set(v: &[&str]) -> Option<BTreeSet<String>> {
    Some(v.iter().map(|x| x.to_string()).collect())
}
fn data(p: &str) -> String {
    format!(
        "{}/../testdata/data/pyhanko/{p}",
        env!("CARGO_MANIFEST_DIR")
    )
}
fn ca(p: &str) -> String {
    data(&format!("crypto/testing-ca/{p}"))
}

#[test]
fn test_read_vc_kwargs() {
    for replace in [true, false] {
        let c = vc(&format!(
            "trust: '{}'\ntrust-replace: {replace}\nother-certs: '{}'",
            ca("root/root.cert.pem"),
            ca("ca-chain.cert.pem")
        ));
        let s = c.validation_settings(None).unwrap();
        assert_eq!(s.trust_roots.len(), 1);
        assert_eq!(s.other_certs.len(), 2);
        assert_eq!(s.trust_replace, replace);
        assert_eq!(s.key_usage.key_usage, None);
        assert_eq!(s.key_usage.extd_key_usage, None);
        assert!(c.validation_settings(Some("theresnosuchvc")).is_err());
    }
}
#[test]
fn test_os_trust_fallback_warning() {
    for (s, msg) in [
        (
            format!("trust: '{}'", ca("root/root.cert.pem")),
            "being combined with the operating system",
        ),
        ("other-certs: []".into(), "No trust roots were configured"),
    ] {
        assert!(vc(&format!("{s}\ntrust-replace: false"))
            .validation_settings(None)
            .unwrap()
            .warnings
            .iter()
            .any(|s| s.contains(msg)));
    }
}
#[test]
fn test_no_os_trust_fallback_warning_with_trust_replace() {
    assert!(vc(&format!(
        "trust: '{}'\ntrust-replace: true",
        ca("root/root.cert.pem")
    ))
    .validation_settings(None)
    .unwrap()
    .warnings
    .is_empty());
}

#[test]
fn test_read_bad_config() {
    assert!(
        cfg("stamp-styles:\n  default:\n    type: qr\n    blah: blah")
            .stamp_style(None)
            .is_err()
    );
}
#[test]
fn test_read_bad_background_config() {
    assert!(
        cfg("stamp-styles:\n  default:\n    type: text\n    background: 1234")
            .stamp_style(None)
            .unwrap_err()
            .contains("must be a string")
    );
}
#[test]
fn test_read_bad_config2() {
    for bad in ["5", "[1,2,3]"] {
        assert!(cfg(&format!("stamp-styles:\n  default: {bad}"))
            .stamp_style(None)
            .is_err());
    }
}
#[test]
fn test_empty_config() {
    assert!(cfg("").validation_settings(None).is_ok());
}

#[test]
fn test_read_logging_config() {
    let c=cfg("logging:\n  root-level: DEBUG\n  root-output: stdout\n  by-module:\n    example.test1:\n      level: 50\n      output: test.log\n    example.test2:\n      level: DEBUG\n    example.test3:\n      level: 10\n      output: stderr");
    assert_eq!(c.root_output(), "stdout");
    assert_eq!(c.log_config[0].1.level, LogLevel::Name("DEBUG".into()));
    assert_eq!(
        c.logger(Some("example.test1")).unwrap(),
        &LogConfig {
            level: LogLevel::Number(50),
            output: "test.log".into()
        }
    );
    assert_eq!(
        c.logger(Some("example.test2")).unwrap(),
        &LogConfig {
            level: LogLevel::Name("DEBUG".into()),
            output: "stderr".into()
        }
    );
    assert_eq!(
        c.logger(Some("example.test3")).unwrap(),
        &LogConfig {
            level: LogLevel::Number(10),
            output: "stderr".into()
        }
    );
}
#[test]
fn test_read_logging_config_defaults() {
    for (s, lev, out) in [
        (
            "logging:\n  root-level: DEBUG",
            LogLevel::Name("DEBUG".into()),
            "stderr",
        ),
        (
            "logging:\n  root-output: test.log",
            LogLevel::Number(20),
            "test.log",
        ),
        ("", LogLevel::Number(20), "stderr"),
    ] {
        let c = cfg(s);
        assert_eq!(
            c.log_config
                .iter()
                .map(|x| x.0.as_deref())
                .collect::<Vec<_>>(),
            vec![None, Some("signxml.processor"), Some("fontTools.subset")]
        );
        assert_eq!(c.log_config[0].1.level, lev);
        assert_eq!(c.root_output(), out);
    }
}
#[test]
fn test_read_logging_config_errors() {
    for s in [
        "logging: 5",
        "logging:\n  by-module: 1",
        "logging:\n  root-output: [1, 2]",
        "logging:\n  root-level: [2, 3]",
        "logging:\n  by-module:\n    test.example:\n      level: 10\n      output: 5",
        "logging:\n  by-module:\n    0:\n      level: 10",
        "logging:\n  by-module:\n    test.example:\n      output: abc.log",
    ] {
        assert!(CliConfig::parse(s).is_err(), "{s}");
    }
}

#[test]
fn test_read_key_usage() {
    for (lit, exp) in [
        ("non_repudiation", set(&["non_repudiation"])),
        (
            "[non_repudiation, digital_signature]",
            set(&["non_repudiation", "digital_signature"]),
        ),
        ("[]", set(&[])),
    ] {
        let p = vc(&format!("signer-key-usage: {lit}"))
            .key_usages(None)
            .unwrap();
        assert_eq!(p.key_usage, exp);
        assert_eq!(p.extd_key_usage, None);
    }
}
#[test]
fn test_read_extd_key_usage() {
    for (lit, exp) in [
        ("piv_content_signing", set(&["piv_content_signing"])),
        (
            "[piv_content_signing, code_signing]",
            set(&["piv_content_signing", "code_signing"]),
        ),
        ("[]", set(&[])),
        (
            "[2.16.840.1.101.3.6.7, code_signing]",
            set(&["piv_content_signing", "code_signing"]),
        ),
        (
            "[2.16.840.1.101.3.6.7, \"2.999\"]",
            set(&["piv_content_signing", "2.999"]),
        ),
        ("2.16.840.1.101.3.6.7", set(&["piv_content_signing"])),
        ("\"2.999\"", set(&["2.999"])),
    ] {
        let p = vc(&format!("signer-extd-key-usage: {lit}"))
            .key_usages(None)
            .unwrap();
        assert_eq!(p.key_usage, None);
        assert_eq!(p.extd_key_usage, exp);
        assert!(!p.match_all_key_usages);
    }
}
#[test]
fn test_read_key_usage_policy_1() {
    let p=vc("signer-key-usage-policy:\n  key-usage: [digital_signature, non_repudiation]\n  match-all-key-usages: true").key_usages(None).unwrap();
    assert_eq!(p.key_usage, set(&["digital_signature", "non_repudiation"]));
    assert_eq!(p.key_usage_forbidden, None);
    assert_eq!(p.extd_key_usage, None);
    assert!(p.match_all_key_usages);
}
#[test]
fn test_read_key_usage_policy_2() {
    let p=vc("signer-key-usage-policy:\n  key-usage: [digital_signature, non_repudiation]\n  extd-key-usage: '2.999'\n  explicit-extd-key-usage-required: true").key_usages(None).unwrap();
    assert_eq!(p.key_usage, set(&["digital_signature", "non_repudiation"]));
    assert_eq!(p.extd_key_usage, set(&["2.999"]));
    assert!(p.explicit_extd_key_usage_required);
}
#[test]
fn test_read_key_usage_policy_3() {
    let p=vc("signer-key-usage-policy:\n  key-usage: [digital_signature, non_repudiation]\n  key-usage-forbidden: data_encipherment").key_usages(None).unwrap();
    assert_eq!(p.key_usage, set(&["digital_signature", "non_repudiation"]));
    assert_eq!(p.key_usage_forbidden, set(&["data_encipherment"]));
    assert_eq!(p.extd_key_usage, None);
    assert!(!p.match_all_key_usages);
}
#[test]
fn test_extd_key_usage_errors() {
    for s in [
        "0",
        "[\"non_repudiation\", 2]",
        "[1, 2, 3]",
        "abcdef",
        "[\"no_such_key_usage\"]",
    ] {
        assert!(vc(&format!("signer-extd-key-usage: {s}"))
            .key_usages(None)
            .is_err());
    }
}
#[test]
fn test_key_usage_errors() {
    for s in [
        "0",
        "[\"non_repudiation\", 2]",
        "[1, 2, 3]",
        "abcdef",
        "[\"no_such_key_usage\"]",
    ] {
        assert!(vc(&format!("signer-key-usage: {s}"))
            .key_usages(None)
            .is_err());
    }
}
#[test]
fn test_read_time_tolerance() {
    for (global, local, exp) in [
        (Some(5), None, 5),
        (Some(5), Some(7), 7),
        (None, Some(7), 7),
        (None, None, 30),
    ] {
        let mut s = String::new();
        if let Some(g) = global {
            s.push_str(&format!("time-tolerance: {g}\n"));
        }
        s.push_str("validation-contexts:\n  default:\n    trust-replace: true\n");
        if let Some(l) = local {
            s.push_str(&format!("    time-tolerance: {l}\n"));
        }
        assert_eq!(
            cfg(&s).validation_settings(None).unwrap().time_tolerance,
            exp
        );
    }
}
#[test]
fn test_read_time_tolerance_input_issues() {
    for s in [
        "time-tolerance: this makes no sense",
        "validation-contexts:\n  default:\n    time-tolerance: this makes no sense",
    ] {
        let e = CliConfig::parse(s)
            .and_then(|c| c.validation_settings(None))
            .unwrap_err();
        assert!(e.contains("time-tolerance"));
    }
}
#[test]
fn test_read_retroactive_revinfo() {
    for (global, local, expected) in [
        (Some("true"), None, true),
        (Some("true"), Some("false"), false),
        (Some("false"), Some("true"), true),
        (None, Some("true"), true),
        (None, Some("\"yes\""), true),
        (None, None, false),
    ] {
        let mut text = global
            .map(|g| format!("retroactive-revinfo: {g}\n"))
            .unwrap_or_default();
        text.push_str("validation-contexts:\n  default:\n    trust-replace: true\n");
        if let Some(local) = local {
            text.push_str(&format!("    retroactive-revinfo: {local}\n"));
        }
        assert_eq!(
            cfg(&text)
                .validation_settings(None)
                .unwrap()
                .retroactive_revinfo,
            expected
        );
    }
}

#[test]
fn test_read_pkcs11_config() {
    let c=token(&format!("token-criteria:\n  label: testrsa\ncert-label: signer\nother-certs: '{}'\nonly-resident-certs: no",ca("ca-chain.cert.pem")));
    let s = c.pkcs11_setup("foo").unwrap();
    assert_eq!(s.token_criteria.unwrap().label.as_deref(), Some("testrsa"));
    assert_eq!(s.module_path, "/path/to/libfoo.so");
    assert!(!s.only_resident_certs);
    assert_eq!(s.other_certs.len(), 2);
    assert!(c.pkcs11_setup("bar").is_err());
}
#[test]
fn test_read_pkcs11_config_legacy() {
    let s = token("token-label: testrsa\ncert-label: signer")
        .pkcs11_setup("foo")
        .unwrap();
    assert_eq!(s.token_criteria.unwrap().label.as_deref(), Some("testrsa"));
    assert!(!s.only_resident_certs);
    assert!(s.warnings.iter().any(|s| s.contains("deprecated")));
}
#[test]
fn test_read_pkcs11_config_legacy_with_extra_criteria() {
    let s=token("token-label: testrsa\ntoken-criteria:\n  serial: deadbeef\ncert-label: signer\nonly-resident-certs: yes").pkcs11_setup("foo").unwrap();
    let t = s.token_criteria.unwrap();
    assert_eq!(t.label.as_deref(), Some("testrsa"));
    assert_eq!(t.serial, Some(vec![0xde, 0xad, 0xbe, 0xef]));
    assert!(s.only_resident_certs);
    assert!(!s.warnings.is_empty());
}
#[test]
fn test_read_pkcs11_config_slot_no() {
    let s = token(&format!(
        "slot-no: 0\ncert-label: signer\nother-certs: '{}'",
        ca("ca-chain.cert.pem")
    ))
    .pkcs11_setup("foo")
    .unwrap();
    assert_eq!(s.module_path, "/path/to/libfoo.so");
    assert_eq!(s.slot_no, Some(0));
    assert_eq!(s.other_certs.len(), 2);
}
#[test]
fn test_read_pkcs11_nothing_to_pull() {
    assert!(
        token("token-criteria:\n  label: testrsa\ncert-label: signer")
            .pkcs11_setup("foo")
            .unwrap()
            .other_certs
            .is_empty()
    );
}
#[test]
fn test_read_pkcs11_config_ids() {
    let s = token("slot-no: 0\ncert-id: 5\nkey-id: '74657374'")
        .pkcs11_setup("foo")
        .unwrap();
    assert_eq!(s.cert_id, Some(vec![5]));
    assert_eq!(s.key_id, Some(b"test".to_vec()));
}
#[test]
fn test_read_pkcs11_config_external_cert() {
    let s = token(&format!(
        "slot-no: 0\nkey-id: 10\nsigning-certificate: '{}'",
        ca("interm/signer1.cert.pem")
    ))
    .pkcs11_setup("foo")
    .unwrap();
    assert!(s.cert_id.is_none());
    assert!(s.cert_label.is_none());
    assert!(s.signing_certificate.is_some());
}
#[test]
fn test_read_pkcs11_config_bad_criteria_type() {
    assert!(token("token-criteria: bleh\ncert-label: signer")
        .pkcs11_setup("foo")
        .unwrap_err()
        .contains("TokenCriteria requires a dictionary"));
}
#[test]
fn test_read_pkcs11_config_bad_serial() {
    let e = token("token-criteria:\n  serial: bazz\ncert-label: signer")
        .pkcs11_setup("foo")
        .unwrap_err();
    assert!(e.contains("Failed to parse") && e.contains("hex"));
}
#[test]
fn test_read_pkcs11_config_no_cert_spec_or_key_spec() {
    assert!(token("slot-no: 0")
        .pkcs11_setup("foo")
        .unwrap_err()
        .contains("Either 'key_id'"));
}
#[test]
fn test_read_pkcs11_config_cert_label_from_key_label() {
    let s = token("slot-no: 0\nkey-label: signer")
        .pkcs11_setup("foo")
        .unwrap();
    assert_eq!((s.cert_label, s.cert_id), (Some("signer".into()), None));
}
#[test]
fn test_read_pkcs11_config_cert_id_from_key_id() {
    let s = token("slot-no: 0\nkey-id: deadbeef")
        .pkcs11_setup("foo")
        .unwrap();
    assert_eq!(
        (s.cert_label, s.cert_id),
        (None, Some(vec![0xde, 0xad, 0xbe, 0xef]))
    );
}
#[test]
fn test_read_pkcs11_config_key_id_from_cert_id() {
    let s = token("slot-no: 0\ncert-id: deadbeef")
        .pkcs11_setup("foo")
        .unwrap();
    assert_eq!(
        (s.key_label, s.key_id),
        (None, Some(vec![0xde, 0xad, 0xbe, 0xef]))
    );
}
#[test]
fn test_read_pkcs11_config_key_label_from_cert_label() {
    let s = token("slot-no: 0\ncert-label: signer")
        .pkcs11_setup("foo")
        .unwrap();
    assert_eq!((s.key_label, s.key_id), (Some("signer".into()), None));
}
#[test]
fn test_read_pkcs11_config_key_label_not_from_cert_label_if_key_id_defined() {
    let s = token("slot-no: 0\ncert-label: signer\nkey-id: deadbeef")
        .pkcs11_setup("foo")
        .unwrap();
    assert_eq!(
        (s.key_label, s.key_id),
        (None, Some(vec![0xde, 0xad, 0xbe, 0xef]))
    );
    assert_eq!((s.cert_label, s.cert_id), (Some("signer".into()), None));
}
#[test]
fn test_read_pkcs11_prompt_pin() {
    for (lit, exp) in [
        ("prompt", PinEntry::Prompt),
        ("skip", PinEntry::Skip),
        ("defer", PinEntry::Defer),
        ("true", PinEntry::Prompt),
        ("false", PinEntry::Skip),
        ("1", PinEntry::Prompt),
        ("0", PinEntry::Skip),
    ] {
        assert_eq!(
            token(&format!("cert-label: signer\nprompt-pin: {lit}"))
                .pkcs11_setup("foo")
                .unwrap()
                .prompt_pin,
            exp
        );
    }
}
#[test]
fn test_read_pkcs11_prompt_pin_default() {
    let s = token("cert-label: signer").pkcs11_setup("foo").unwrap();
    assert_eq!(s.prompt_pin, PinEntry::Prompt);
    assert_eq!(s.signing_pin_mode, SigningPinEntry::Skip);
}
#[test]
fn test_read_pkcs11_prompt_pin_invalid() {
    assert!(token("cert-label: signer\nprompt-pin: foobar")
        .pkcs11_setup("foo")
        .unwrap_err()
        .contains("Invalid"));
}
#[test]
fn test_read_pkcs11_signing_pin_mode() {
    for (lit, exp) in [
        ("prompt", SigningPinEntry::Prompt),
        ("reauthenticate", SigningPinEntry::Reauthenticate),
        ("skip", SigningPinEntry::Skip),
    ] {
        assert_eq!(
            token(&format!("cert-label: signer\nsigning-pin-mode: {lit}"))
                .pkcs11_setup("foo")
                .unwrap()
                .signing_pin_mode,
            exp
        );
    }
}
#[test]
fn test_read_pkcs11_signing_pin_invalid() {
    assert!(token("cert-label: signer\nsigning-pin-mode: foobar")
        .pkcs11_setup("foo")
        .unwrap_err()
        .contains("Invalid"));
}

fn key_cfg(kind: &str, extra: &str) -> CliConfig {
    let fields = if kind == "pkcs12" {
        format!("pfx-file: '{}'", ca("interm/signer1.pfx"))
    } else {
        format!(
            "key-file: '{}'\n    cert-file: '{}'",
            data("crypto/keys-rsa/signer.key.pem"),
            ca("interm/signer1.cert.pem")
        )
    };
    cfg(&format!(
        "{kind}-setups:\n  foo:\n    {fields}\n    {extra}"
    ))
}
fn sanity(s: sigis_pades_sign::SimpleSigner) {
    use sigis_pki_core::{algorithms::DigestAlgorithm, sign::KeySigner};
    let msg = b"Hello world!";
    let sig = s.sign_raw(msg, DigestAlgorithm::Sha256).unwrap();
    let cert = openssl::x509::X509::from_pem(
        std::fs::read(ca("interm/signer1.cert.pem"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let key = cert.public_key().unwrap();
    let mut v = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
    v.update(msg).unwrap();
    assert!(v.verify(&sig).unwrap());
}
#[test]
fn test_read_pkcs12_config() {
    let c = key_cfg(
        "pkcs12",
        &format!("other-certs: '{}'", ca("ca-chain.cert.pem")),
    );
    let s = c.pkcs12_setup("foo").unwrap();
    assert!(c.pkcs12_setup("bar").is_err());
    assert_eq!(s.other_certs.len(), 2);
    sanity(s.load_signer(None).unwrap());
}
#[test]
fn test_read_pkcs12_config_null_pw() {
    let s = key_cfg(
        "pkcs12",
        &format!(
            "other-certs: '{}'\n    pfx-passphrase: null",
            ca("ca-chain.cert.pem")
        ),
    )
    .pkcs12_setup("foo")
    .unwrap();
    assert_eq!(s.other_certs.len(), 2);
    sanity(s.load_signer(None).unwrap());
}
#[test]
fn test_read_pemder_config() {
    let c = key_cfg(
        "pemder",
        &format!(
            "other-certs: '{}'\n    key-passphrase: secret",
            ca("ca-chain.cert.pem")
        ),
    );
    let s = c.pemder_setup("foo").unwrap();
    assert!(c.pemder_setup("bar").is_err());
    assert_eq!(s.other_certs.len(), 2);
    sanity(s.load_signer(None).unwrap());
}
#[test]
fn test_read_pemder_config_wrong_passphrase() {
    assert!(
        key_cfg("pemder", "key-passphrase: this passphrase is wrong")
            .pemder_setup("foo")
            .unwrap()
            .load_signer(None)
            .is_err()
    );
}
#[test]
fn test_read_pemder_config_missing_passphrase() {
    let s = key_cfg("pemder", "").pemder_setup("foo").unwrap();
    assert!(s.load_signer(None).is_err());
    sanity(s.load_signer(Some(b"secret")).unwrap());
}
#[test]
fn test_read_pkcs12_config_wrong_passphrase() {
    assert!(
        key_cfg("pkcs12", "pfx-passphrase: this passphrase is wrong")
            .pkcs12_setup("foo")
            .unwrap()
            .load_signer(None)
            .is_err()
    );
}

#[test]
fn test_cache_dir_config() {
    let mut c = cfg("");
    assert!(!c.cache_dir().as_os_str().is_empty());
    c.cache_dir = Some("test".into());
    assert_eq!(c.cache_dir(), std::path::PathBuf::from("test"));
}

#[test]
fn test_read_qr_config() {
    use sigis_pades_sign::{
        content::Content,
        font::FontEngineFactory,
        layout::{AxisAlignment, Margins, SimpleBoxLayoutRule},
        stamp::{QrPosition, StampStyle},
    };
    let c=cfg(&format!("stamp-styles:\n  default:\n    text-box-style:\n      font: '{}'\n    type: qr\n    background: __stamp__\n    qr-position: right\n    inner-content-layout:\n      y-align: bottom\n      x-align: mid\n      margins:\n        left: 10\n        right: 10\n  alternative1:\n    text-box-style:\n      font: '{}'\n    background: '{}'\n    type: qr\n  alternative2:\n    type: qr\n    background: '{}'\n  alternative3:\n    type: text\n  wrong-position:\n    type: qr\n    qr-position: bleh",data("fonts/NotoSerifJP-Regular.otf"),data("fonts/NotoSerifJP-Regular.otf"),data("img/stamp-indexed.png"),data("pdf/pdf-background-test.pdf")));
    let StampStyle::Qr(s) = c.stamp_style(None).unwrap() else {
        panic!("expected QR style")
    };
    assert_eq!(
        format!("{:?}", s.text.base.background.as_ref().unwrap()),
        format!("{:?}", sigis_pades_sign::stamp::stamp_art_content())
    );
    assert!(matches!(
        s.text.text_box_style.font,
        FontEngineFactory::OpenType(_)
    ));
    assert_eq!(s.qr_position, QrPosition::RightOfText);
    let mut l = SimpleBoxLayoutRule::new(AxisAlignment::AlignMid, AxisAlignment::AlignMin);
    l.margins = Margins {
        left: 10.,
        right: 10.,
        top: 0.,
        bottom: 0.,
    };
    assert_eq!(s.text.inner_content_layout, Some(l));
    let StampStyle::Qr(s) = c.stamp_style(Some("alternative1")).unwrap() else {
        panic!("expected QR style")
    };
    assert!(matches!(s.text.base.background, Some(Content::Image(_))));
    assert!(matches!(
        s.text.text_box_style.font,
        FontEngineFactory::OpenType(_)
    ));
    assert_eq!(s.qr_position, QrPosition::LeftOfText);
    let StampStyle::Qr(s) = c.stamp_style(Some("alternative2")).unwrap() else {
        panic!("expected QR style")
    };
    assert!(matches!(
        s.text.base.background,
        Some(Content::ImportedPage(_))
    ));
    assert!(matches!(
        s.text.text_box_style.font,
        FontEngineFactory::Simple(_)
    ));
    let StampStyle::Text(s) = c.stamp_style(Some("alternative3")).unwrap() else {
        panic!("expected text style")
    };
    assert!(s.base.background.is_none());
    assert!(matches!(
        s.text_box_style.font,
        FontEngineFactory::Simple(_)
    ));
    assert!(c
        .stamp_style(Some("wrong-position"))
        .unwrap_err()
        .contains("not a valid QR position"));
    assert!(c.stamp_style(Some("theresnosuchstyle")).is_err());
}

#[test]
fn test_read_simple_layout_config() {
    use sigis_pades_sign::{
        layout::{AxisAlignment, InnerScaling},
        stamp::config::layout_rule_from_config,
    };
    for (yaml, x, y, margins, scale) in [
        (
            "x-align: left",
            AxisAlignment::AlignMin,
            AxisAlignment::AlignMid,
            [0., 0., 0., 0.],
            InnerScaling::ShrinkToFit,
        ),
        (
            "y-align: bottom",
            AxisAlignment::AlignMid,
            AxisAlignment::AlignMin,
            [0., 0., 0., 0.],
            InnerScaling::ShrinkToFit,
        ),
        (
            "y-align: bottom\nx-align: mid\nmargins:\n  left: 10\n  right: 10",
            AxisAlignment::AlignMid,
            AxisAlignment::AlignMin,
            [10., 10., 0., 0.],
            InnerScaling::ShrinkToFit,
        ),
        (
            "y-align: bottom\nx-align: mid\nmargins: [10,10,0,0]",
            AxisAlignment::AlignMid,
            AxisAlignment::AlignMin,
            [10., 10., 0., 0.],
            InnerScaling::ShrinkToFit,
        ),
        (
            "y-align: bottom\nx-align: mid\ninner-content-scaling: none",
            AxisAlignment::AlignMid,
            AxisAlignment::AlignMin,
            [0., 0., 0., 0.],
            InnerScaling::NoScaling,
        ),
        (
            "inner-content-scaling: stretch-to-fit",
            AxisAlignment::AlignMid,
            AxisAlignment::AlignMid,
            [0., 0., 0., 0.],
            InnerScaling::StretchToFit,
        ),
    ] {
        let v = serde_yaml::from_str(yaml).unwrap();
        let r = layout_rule_from_config(&v).unwrap();
        assert_eq!(r.x_align, x);
        assert_eq!(r.y_align, y);
        assert_eq!(
            [
                r.margins.left,
                r.margins.right,
                r.margins.top,
                r.margins.bottom
            ],
            margins
        );
        assert_eq!(r.inner_content_scaling, scale);
    }
}
#[test]
fn test_read_simple_layout_config_failures() {
    for (s, msg) in [
        ("x-align: bottom", "is not a valid horizontal"),
        ("y-align: right", "is not a valid vertical"),
        (
            "inner-content-scaling: foobar",
            "is not a valid inner scaling",
        ),
    ] {
        let v = serde_yaml::from_str(s).unwrap();
        assert!(sigis_pades_sign::stamp::config::layout_rule_from_config(&v)
            .unwrap_err()
            .to_string()
            .contains(msg));
    }
}

#[derive(Debug, serde::Deserialize, PartialEq)]
#[serde(untagged)]
enum TextOrInt {
    Text(String),
    Int(i64),
}
fn default_field5() -> TextOrInt {
    TextOrInt::Text("abc".into())
}
#[derive(Debug, serde::Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct DemoA {
    field1: i64,
    field2: Vec<i64>,
    #[serde(default)]
    field3: Option<i64>,
    #[serde(default)]
    field4: Option<Vec<i64>>,
    #[serde(default = "default_field5")]
    field5: TextOrInt,
    #[serde(default)]
    field6: Option<TextOrInt>,
}
#[derive(Debug, serde::Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct DemoB {
    #[serde(default)]
    some_field: Option<DemoA>,
}
fn demo(s: &str) -> Result<DemoB, String> {
    configurable(serde_yaml::from_str(s).unwrap())
}
#[test]
fn test_configurable_recurse() {
    for (s, exp) in [
        (
            "some_field:\n  field1: 1\n  field2: [1,2]",
            Some(DemoA {
                field1: 1,
                field2: vec![1, 2],
                field3: None,
                field4: None,
                field5: default_field5(),
                field6: None,
            }),
        ),
        (
            "some_field:\n  field1: 1\n  field2: [1,2]\n  field3: 5",
            Some(DemoA {
                field1: 1,
                field2: vec![1, 2],
                field3: Some(5),
                field4: None,
                field5: default_field5(),
                field6: None,
            }),
        ),
        (
            "some_field:\n  field1: 1\n  field2: [1,2]\n  field3: 5\n  field4: [6,7,8]",
            Some(DemoA {
                field1: 1,
                field2: vec![1, 2],
                field3: Some(5),
                field4: Some(vec![6, 7, 8]),
                field5: default_field5(),
                field6: None,
            }),
        ),
        (
            "some_field:\n  field1: 1\n  field2: [1,2]\n  field5: xyz",
            Some(DemoA {
                field1: 1,
                field2: vec![1, 2],
                field3: None,
                field4: None,
                field5: TextOrInt::Text("xyz".into()),
                field6: None,
            }),
        ),
        (
            "some_field:\n  field1: 1\n  field2: [1,2]\n  field5: 8\n  field6: xyz",
            Some(DemoA {
                field1: 1,
                field2: vec![1, 2],
                field3: None,
                field4: None,
                field5: TextOrInt::Int(8),
                field6: Some(TextOrInt::Text("xyz".into())),
            }),
        ),
        ("{}", None),
    ] {
        assert_eq!(demo(s).unwrap().some_field, exp);
    }
}
#[test]
fn test_enforce_required() {
    for s in [
        "field2: [1,2]\nfield3: 5",
        "field1: 1\nfield3: 5",
        "field3: 5",
        "{}",
    ] {
        assert!(configurable::<DemoA>(serde_yaml::from_str(s).unwrap())
            .unwrap_err()
            .contains("Missing required key"));
    }
}
#[test]
fn test_enforce_required_recursive() {
    assert!(demo("some_field:\n  field2: [1,2]")
        .unwrap_err()
        .contains("Error while processing configurable field"));
}
#[test]
fn test_configurable_recurse_optional_styles() {
    // Python's Optional[T], Union[T,None] and T | None all map to Rust Option<T>.
    for _annotation in ["Optional[T]", "Union[T,None]", "T | None"] {
        let r = demo("some_field:\n  field1: 1\n  field2: [1,2]").unwrap();
        assert_eq!(
            r.some_field,
            Some(DemoA {
                field1: 1,
                field2: vec![1, 2],
                field3: None,
                field4: None,
                field5: default_field5(),
                field6: None
            })
        );
    }
}
#[test]
fn test_default_stamp_style_fetch() {
    let s = vc(&format!(
        "trust: '{}'\nother-certs: '{}'",
        ca("root/root.cert.pem"),
        ca("ca-chain.cert.pem")
    ))
    .stamp_style(None)
    .unwrap();
    let expected = sigis_pades_sign::stamp::default_signing_stamp_style();
    assert_eq!(format!("{s:?}"), format!("{expected:?}"));
}

#[test]
fn test_fail_to_read_default_config() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("pyhanko.yml")).unwrap();
    let r = std::process::Command::new(common::cli())
        .current_dir(d.path())
        .args(["sign", "addsig", "--help"])
        .output()
        .unwrap();
    assert_eq!(r.status.code(), Some(1));
    let s = format!(
        "{}{}",
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&r.stderr)
    );
    assert!(s.contains("Failed to read pyhanko.yml"), "{s}");
}
#[test]
fn test_fail_to_read_nondefault_config() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("foo.yml")).unwrap();
    let r = std::process::Command::new(common::cli())
        .current_dir(d.path())
        .args(["--config", "foo.yml", "sign", "addsig", "--help"])
        .output()
        .unwrap();
    assert_eq!(r.status.code(), Some(1));
    let s = format!(
        "{}{}",
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&r.stderr)
    );
    assert!(s.contains("Failed to read configuration"), "{s}");
}

/// Seventeen fresh oracle cases; separate from unique upstream function counts.
#[test]
fn configuration_live_oracle_matrix() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let cases=["", "logging:\n  root-level: DEBUG\n  root-output: stdout", "logging:\n  root-output: test.log", "logging: 5", "logging:\n  by-module: 1", "logging:\n  root-output: [1,2]", "logging:\n  root-level: [2,3]", "time-tolerance: bad", "validation-contexts:\n  default:\n    signer-key-usage: non_repudiation", "validation-contexts:\n  default:\n    signer-key-usage: [non_repudiation, digital_signature]", "validation-contexts:\n  default:\n    signer-key-usage: []", "validation-contexts:\n  default:\n    signer-key-usage: abcdef", "validation-contexts:\n  default:\n    signer-extd-key-usage: piv_content_signing", "validation-contexts:\n  default:\n    signer-extd-key-usage: [2.16.840.1.101.3.6.7, code_signing]", "validation-contexts:\n  default:\n    signer-extd-key-usage: ['2.999']", "validation-contexts:\n  default:\n    signer-extd-key-usage: [non_repudiation, 2]", "validation-contexts:\n  default:\n    signer-key-usage-policy:\n      key-usage: digital_signature\n      match-all-key-usages: true"];
    let python = std::env::var("HANKO_ORACLE")
        .unwrap_or_else(|_| "/tmp/pyhanko-oracle/venv/bin/python".into());
    let mut child = Command::new(python)
        .args([
            "-c",
            include_str!("../../testdata/data/lanes/r3-c/config/oracle.py"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the pinned oracle is required for the live configuration matrix");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&cases).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for (case, oracle) in cases.iter().zip(expected) {
        let rust=CliConfig::parse(case).and_then(|c|{let p=c.key_usages(None)?;let root=c.logger(None).unwrap();let level=match &root.level{LogLevel::Number(n)=>serde_json::json!(n),LogLevel::Name(s)=>serde_json::json!(s)};Ok(serde_json::json!({"ok":true,"level":level,"output":root.output,"ku":p.key_usage,"eku":p.extd_key_usage,"all":p.match_all_key_usages,"explicit":p.explicit_extd_key_usage_required}))}).unwrap_or_else(|_|serde_json::json!({"ok":false}));
        assert_eq!(rust, oracle, "configuration: {case}");
    }
}

/// Default EKU enforcement must never become weaker than the pinned oracle.
#[test]
fn configuration_key_usage_default_requires_explicit_eku() {
    assert!(KeyUsagePolicy::default().explicit_extd_key_usage_required);
    assert!(
        cfg("")
            .key_usages(None)
            .unwrap()
            .explicit_extd_key_usage_required
    );
    let p=vc("signer-key-usage-policy:\n  extd-key-usage: code_signing\n  explicit-extd-key-usage-required: false").key_usages(None).unwrap();
    assert!(!p.explicit_extd_key_usage_required);
}

// Supplemental mandatory-policy schema checks, not additional upstream functions.
fn policy_schema_yaml(fragment: &str) -> String {
    format!(
        "validation-contexts:\n  default:\n{}",
        fragment
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect::<String>()
    )
}

fn policy_schema_oracle(cases: &[String]) -> Vec<serde_json::Value> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let script = r#"import json, sys
import pyhanko
pyhanko.__path__.append('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko')
from pyhanko.cli.config import parse_cli_config
results = []
for text in json.load(sys.stdin):
 try:
  p = parse_cli_config(text).config.get_signer_key_usages()
  results.append({'ok': True, 'all': bool(p.match_all_key_usages), 'explicit': bool(p.explicit_extd_key_usage_required)})
 except Exception as error:
  results.append({'ok': False, 'exception': type(error).__name__, 'error': str(error)})
json.dump(results, sys.stdout)
"#;
    let mut child = Command::new(sigis_testdata::oracle::python().unwrap())
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(cases).unwrap())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let results: Vec<serde_json::Value> = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(results.len(), cases.len());
    results
}

#[test]
fn configuration_policy_rejects_unknown_normalized_keys() {
    let mut cases = vec![];
    let mut keys = vec![];
    for (key, value) in [
        ("key-usage-forbiden", "non_repudiation"),
        ("require-qualified-signature", "true"),
        ("match-all-key-usage", "true"),
    ] {
        for underscore in [false, true] {
            let spelling = if underscore {
                key.replace('-', "_")
            } else {
                key.to_owned()
            };
            let prefix = if key == "match-all-key-usage" {
                "  key-usage: [non_repudiation, crl_sign]\n"
            } else {
                ""
            };
            cases.push(policy_schema_yaml(&format!(
                "signer-key-usage-policy:\n{prefix}  {spelling}: {value}"
            )));
            keys.push(key);
        }
    }
    for ((yaml, key), oracle) in cases.iter().zip(keys).zip(policy_schema_oracle(&cases)) {
        let expected = format!("Unexpected key in configuration for KeyUsageConstraints: {key}.");
        assert_eq!(oracle["ok"], false);
        assert_eq!(oracle["exception"], "ConfigurationError");
        assert_eq!(oracle["error"], expected);
        let native = CliConfig::parse(yaml).and_then(|config| config.key_usages(None));
        assert_eq!(native.unwrap_err(), expected, "{yaml}");
    }
}

#[test]
fn configuration_policy_rejects_malformed_shapes() {
    let cases: Vec<String> = [
        "null",
        "true",
        "0",
        "'text'",
        "[1, 2]",
        "{key-usage: {non_repudiation: true}}",
    ]
    .iter()
    .map(|literal| policy_schema_yaml(&format!("signer-key-usage-policy: {literal}")))
    .collect();
    for (yaml, oracle) in cases.iter().zip(policy_schema_oracle(&cases)) {
        assert_eq!(oracle["ok"], false, "{yaml}");
        assert!(
            CliConfig::parse(yaml)
                .and_then(|config| config.key_usages(None))
                .is_err(),
            "{yaml}"
        );
    }
}

#[test]
fn configuration_policy_rejects_conflicting_normalized_aliases() {
    let mut cases = vec![];
    for (key, left, right) in [
        ("key-usage", "non_repudiation", "digital_signature"),
        (
            "key-usage-forbidden",
            "non_repudiation",
            "digital_signature",
        ),
        ("extd-key-usage", "code_signing", "email_protection"),
        ("match-all-key-usages", "true", "false"),
        ("explicit-extd-key-usage-required", "true", "false"),
    ] {
        for reverse in [false, true] {
            let mut pairs = [(key.to_owned(), left), (key.replace('-', "_"), right)];
            if reverse {
                pairs.reverse();
            }
            let fragment: String = pairs
                .into_iter()
                .map(|(key, value)| format!("  {key}: {value}\n"))
                .collect();
            cases.push(policy_schema_yaml(&format!(
                "signer-key-usage-policy:\n{fragment}"
            )));
        }
    }
    for (key, left, right) in [
        (
            "signer-key-usage-policy",
            "{key-usage: non_repudiation}",
            "{key-usage: digital_signature}",
        ),
        ("signer-key-usage", "non_repudiation", "digital_signature"),
        ("signer-extd-key-usage", "code_signing", "email_protection"),
    ] {
        for reverse in [false, true] {
            let mut pairs = [(key.to_owned(), left), (key.replace('-', "_"), right)];
            if reverse {
                pairs.reverse();
            }
            let fragment: String = pairs
                .into_iter()
                .map(|(key, value)| format!("{key}: {value}\n"))
                .collect();
            cases.push(policy_schema_yaml(&fragment));
        }
    }
    for (key, left, right) in [
        (
            "validation-contexts",
            "{default: {signer-key-usage: non_repudiation}}",
            "{default: {signer-key-usage: digital_signature}}",
        ),
        ("default-validation-context", "default", "other"),
    ] {
        cases.push(format!(
            "{key}: {left}\n{}: {right}\n",
            key.replace('-', "_")
        ));
    }
    // Python's dict/normalization precedence accepts these ambiguous inputs.
    // Native rejection is intentionally stricter, not an oracle-parity claim.
    for (yaml, oracle) in cases.iter().zip(policy_schema_oracle(&cases)) {
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        assert!(
            CliConfig::parse(yaml)
                .and_then(|config| config.key_usages(None))
                .is_err(),
            "conflicting aliases were accepted: {yaml}"
        );
    }
}

#[test]
fn configuration_policy_boolean_truth_matches_python_objects() {
    let literals = [
        ("'no'", true),
        ("'off'", true),
        ("\"no\"", true),
        ("\"off\"", true),
        ("no", false),
        ("off", false),
        ("false", false),
        ("true", true),
        ("null", false),
    ];
    let mut cases = vec![];
    let mut expected = vec![];
    for field in ["match-all-key-usages", "explicit-extd-key-usage-required"] {
        for (literal, truth) in literals {
            cases.push(policy_schema_yaml(&format!(
                "signer-key-usage-policy:\n  {field}: {literal}"
            )));
            expected.push((field, truth));
        }
    }
    for ((yaml, (field, truth)), oracle) in
        cases.iter().zip(expected).zip(policy_schema_oracle(&cases))
    {
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        let oracle_field = if field == "match-all-key-usages" {
            "all"
        } else {
            "explicit"
        };
        assert_eq!(oracle[oracle_field], truth, "{yaml}");
        let policy = CliConfig::parse(yaml).unwrap().key_usages(None).unwrap();
        let native = if field == "match-all-key-usages" {
            policy.match_all_key_usages
        } else {
            policy.explicit_extd_key_usage_required
        };
        assert_eq!(
            native, truth,
            "policy object truth differs from pinned Python: {yaml}"
        );
    }
}

#[test]
fn configuration_policy_accepts_unambiguous_underscore_aliases() {
    let policy = vc("signer-key-usage-policy:\n  key_usage: non_repudiation\n  key_usage_forbidden: key_cert_sign\n  extd_key_usage: code_signing\n  match_all_key_usages: true\n  explicit_extd_key_usage_required: true").key_usages(None).unwrap();
    assert_eq!(policy.key_usage, set(&["non_repudiation"]));
    assert_eq!(policy.key_usage_forbidden, set(&["key_cert_sign"]));
    assert_eq!(policy.extd_key_usage, set(&["code_signing"]));
    assert!(policy.match_all_key_usages);
    assert!(policy.explicit_extd_key_usage_required);
}

#[test]
fn configuration_policy_nested_values_precede_legacy_fallbacks() {
    // Canonical nested settings have documented precedence over legacy fallback.
    let policy = vc("signer-key-usage-policy:\n  key-usage: non_repudiation\n  extd-key-usage: code_signing\nsigner-key-usage: digital_signature\nsigner-extd-key-usage: email_protection").key_usages(None).unwrap();
    assert_eq!(policy.key_usage, set(&["non_repudiation"]));
    assert_eq!(policy.extd_key_usage, set(&["code_signing"]));
    // Python normalizes nested underscore keys after inserting canonical legacy
    // fallbacks. Choosing the nested value here could be more trusting.
    for selector in ["signer-key-usage-policy", "signer_key_usage_policy"] {
        for underscore in [false, true] {
            if selector == "signer-key-usage-policy" && !underscore {
                continue;
            }
            let ku = if underscore { "key_usage" } else { "key-usage" };
            let eku = if underscore {
                "extd_key_usage"
            } else {
                "extd-key-usage"
            };
            let yaml = policy_schema_yaml(&format!("{selector}:\n  {ku}: non_repudiation\n  {eku}: code_signing\nsigner-key-usage: crl_sign\nsigner-extd-key-usage: email_protection"));
            assert!(
                CliConfig::parse(&yaml)
                    .and_then(|config| config.key_usages(None))
                    .is_err(),
                "ambiguous nested/legacy policy was accepted: {yaml}"
            );
        }
    }
}

#[test]
fn configuration_policy_rejects_unsupported_outer_underscore_selectors() {
    let cases: Vec<String> = [
        "signer_key_usage_policy: {key-usage: []}",
        "signer_key_usage: []",
        "signer_extd_key_usage: []",
    ]
    .iter()
    .map(|fragment| policy_schema_yaml(fragment))
    .collect();
    for (yaml, oracle) in cases.iter().zip(policy_schema_oracle(&cases)) {
        // The reference ignores these selectors; supporting a weaker policy
        // would bypass its default. Explicit native rejection is stricter.
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        assert!(
            CliConfig::parse(yaml)
                .and_then(|config| config.key_usages(None))
                .is_err(),
            "unsupported outer selector was accepted: {yaml}"
        );
    }
}

#[test]
fn configuration_yaml_policy_preserves_implicit_and_quoted_scalar_truth() {
    let mut cases = vec![];
    let mut expected = vec![];
    for (literal, truth) in [
        ("yes", true),
        ("Yes", true),
        ("YES", true),
        ("true", true),
        ("True", true),
        ("TRUE", true),
        ("on", true),
        ("On", true),
        ("ON", true),
        ("no", false),
        ("No", false),
        ("NO", false),
        ("false", false),
        ("False", false),
        ("FALSE", false),
        ("off", false),
        ("Off", false),
        ("OFF", false),
        ("nO", true),
        ("oFf", true),
        ("y", true),
        ("n", true),
        ("'no'", true),
        ("\"off\"", true),
        ("'NO'", true),
        ("|-\n  off", true),
        (">-\n  no", true),
    ] {
        cases.push(policy_schema_yaml(&format!(
            "signer-key-usage-policy:\n  match-all-key-usages: {}",
            literal.replace('\n', "\n  ")
        )));
        expected.push(truth);
    }
    for ((yaml, truth), oracle) in cases.iter().zip(expected).zip(policy_schema_oracle(&cases)) {
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        assert_eq!(oracle["all"], truth, "{yaml}");
        assert_eq!(
            CliConfig::parse(yaml)
                .unwrap()
                .key_usages(None)
                .unwrap()
                .match_all_key_usages,
            truth,
            "{yaml}"
        );
    }
}

#[test]
fn configuration_yaml_policy_resolves_plain_and_quoted_scalar_aliases() {
    let mut cases = vec![];
    let mut expected = vec![];
    for (literal, truth) in [
        ("no", false),
        ("off", false),
        ("'no'", true),
        ("\"off\"", true),
    ] {
        for decorated in [false, true] {
            let scalar = if decorated {
                format!("&flag !!str {literal}")
            } else {
                format!("&flag {literal}")
            };
            cases.push(format!(
                "shared: {scalar}\n{}",
                policy_schema_yaml("signer-key-usage-policy:\n  match-all-key-usages: *flag")
            ));
            expected.push(if decorated { true } else { truth });
        }
    }
    for ((yaml, truth), oracle) in cases.iter().zip(expected).zip(policy_schema_oracle(&cases)) {
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        assert_eq!(oracle["all"], truth, "{yaml}");
        assert_eq!(
            CliConfig::parse(yaml)
                .unwrap()
                .key_usages(None)
                .unwrap()
                .match_all_key_usages,
            truth,
            "{yaml}"
        );
    }
}

#[test]
fn configuration_yaml_policy_preserves_supported_explicit_tags() {
    let literals = [
        ("!!str no", true),
        ("!!str off", true),
        ("!!bool off", false),
        ("!!bool nO", false),
        ("!!bool true", true),
        ("!!bool false", false),
        ("!!bool 'true'", true),
        ("!!bool \"false\"", false),
        ("!<tag:yaml.org,2002:str> no", true),
        ("!<tag:yaml.org,2002:bool> off", false),
        ("! no", false),
    ];
    let mut cases: Vec<String> = literals
        .iter()
        .map(|(literal, _)| {
            policy_schema_yaml(&format!(
                "signer-key-usage-policy:\n  match-all-key-usages: {literal}"
            ))
        })
        .collect();
    let mut expected: Vec<bool> = literals.iter().map(|(_, truth)| *truth).collect();
    cases.push(format!(
        "%TAG !core! tag:yaml.org,2002:\n---\n{}",
        policy_schema_yaml("signer-key-usage-policy:\n  match-all-key-usages: !core!bool off")
    ));
    expected.push(false);
    for ((yaml, truth), oracle) in cases.iter().zip(expected).zip(policy_schema_oracle(&cases)) {
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        assert_eq!(oracle["all"], truth, "{yaml}");
        assert_eq!(
            CliConfig::parse(yaml)
                .unwrap()
                .key_usages(None)
                .unwrap()
                .match_all_key_usages,
            truth,
            "{yaml}"
        );
    }
}

#[test]
fn configuration_yaml_policy_rejects_unsupported_nonplain_legacy_bool() {
    let cases: Vec<String> = [
        "!!bool 'off'",
        "!!bool \"oFf\"",
        "!!bool \"o\\x66f\"",
        "!!bool |-\n    off",
    ]
    .iter()
    .map(|literal| {
        policy_schema_yaml(&format!(
            "signer-key-usage-policy:\n  match-all-key-usages: {}",
            literal.replace('\n', "\n  ")
        ))
    })
    .collect();
    for (yaml, oracle) in cases.iter().zip(policy_schema_oracle(&cases)) {
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        assert_eq!(oracle["all"], false, "{yaml}");
        // A bounded lexical frontend may reject these richer encodings; it must
        // never silently reinterpret their resolved false as a truthy string.
        assert!(
            CliConfig::parse(yaml)
                .and_then(|config| config.key_usages(None))
                .is_err(),
            "unsupported explicit bool accepted: {yaml}"
        );
    }
}

#[test]
fn configuration_yaml_policy_locates_booleans_after_unicode_and_line_breaks() {
    let long_text = "界🙂".repeat(4096);
    let cases = vec![
        format!("note: |-\n  {long_text}\n{}", policy_schema_yaml("signer-key-usage-policy:\n  match-all-key-usages: off")),
        "{note: 中文🙂, validation-contexts: {default: {signer-key-usage-policy: {match-all-key-usages: no}}}}\n".to_owned(),
        policy_schema_yaml("signer-key-usage-policy:\n  match-all-key-usages: no # 中文🙂").replace('\n', "\r\n"),
        policy_schema_yaml("signer-key-usage-policy:\n  match-all-key-usages: off # keep comment\n  explicit-extd-key-usage-required: true"),
    ];
    for (yaml, oracle) in cases.iter().zip(policy_schema_oracle(&cases)) {
        assert_eq!(oracle["ok"], true, "{oracle}");
        assert_eq!(oracle["all"], false);
        let policy = CliConfig::parse(yaml).unwrap().key_usages(None).unwrap();
        assert!(!policy.match_all_key_usages);
        assert!(policy.explicit_extd_key_usage_required);
    }
}

#[test]
fn configuration_yaml_policy_rejects_duplicate_anchors_and_keys() {
    let duplicate_anchor = format!(
        "first: &flag no\nsecond: &flag true\n{}",
        policy_schema_yaml("signer-key-usage-policy:\n  match-all-key-usages: *flag")
    );
    let oracle = policy_schema_oracle(std::slice::from_ref(&duplicate_anchor));
    assert_eq!(oracle[0]["ok"], false);
    assert!(CliConfig::parse(&duplicate_anchor).is_err());
    let duplicate_key = policy_schema_yaml(
        "signer-key-usage-policy:\n  match-all-key-usages: true\n  match-all-key-usages: false",
    );
    let oracle = policy_schema_oracle(std::slice::from_ref(&duplicate_key));
    // PyYAML keeps the last duplicate; native rejection is intentionally strict.
    assert_eq!(oracle[0]["ok"], true);
    assert_eq!(oracle[0]["all"], false);
    assert!(CliConfig::parse(&duplicate_key).is_err());
}

#[test]
fn configuration_yaml_policy_rejects_unknown_or_incompatible_explicit_tags() {
    let cases = vec![
        policy_schema_yaml("signer-key-usage-policy:\n  match-all-key-usages: !unknown off"),
        policy_schema_yaml("signer-key-usage-policy: !unknown {match-all-key-usages: false}"),
        policy_schema_yaml("signer-key-usage-policy:\n  match-all-key-usages: !!bool perhaps"),
        policy_schema_yaml("signer-key-usage-policy:\n  match-all-key-usages: !!bool [false]"),
    ];
    for (yaml, oracle) in cases.iter().zip(policy_schema_oracle(&cases)) {
        assert_eq!(oracle["ok"], false, "{yaml}: {oracle}");
        assert!(
            CliConfig::parse(yaml)
                .and_then(|config| config.key_usages(None))
                .is_err(),
            "unsupported tag was discarded: {yaml}"
        );
    }
}

#[test]
fn configuration_yaml_policy_applies_mature_merge_semantics() {
    let cases = vec![
        "policy: &policy {key-usage: non_repudiation, match-all-key-usages: no}\nvalidation-contexts:\n  default:\n    signer-key-usage-policy:\n      <<: *policy\n".to_owned(),
        "first: &first {match-all-key-usages: no}\nsecond: &second {match-all-key-usages: true}\nvalidation-contexts:\n  default:\n    signer-key-usage-policy:\n      <<: [*first, *second]\n".to_owned(),
        "policy: &policy {match-all-key-usages: true}\nvalidation-contexts:\n  default:\n    signer-key-usage-policy:\n      <<: *policy\n      match-all-key-usages: off\n".to_owned(),
    ];
    for (index, (yaml, oracle)) in cases.iter().zip(policy_schema_oracle(&cases)).enumerate() {
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        assert_eq!(oracle["all"], false);
        let policy = CliConfig::parse(yaml).unwrap().key_usages(None).unwrap();
        assert!(!policy.match_all_key_usages);
        if index == 0 {
            assert_eq!(policy.key_usage, set(&["non_repudiation"]));
        }
    }
    for merge in [
        "'<<': {match-all-key-usages: false}",
        "!!str <<: {match-all-key-usages: false}",
        "<<: false",
    ] {
        let yaml = policy_schema_yaml(&format!("signer-key-usage-policy:\n  {merge}"));
        // Quoted/string-tagged << is not a merge in Python and is an unknown
        // policy key. A malformed merge must likewise reject, not disappear.
        assert_eq!(
            policy_schema_oracle(std::slice::from_ref(&yaml))[0]["ok"],
            false
        );
        assert!(
            CliConfig::parse(&yaml)
                .and_then(|config| config.key_usages(None))
                .is_err(),
            "invalid/non-merge key was accepted: {yaml}"
        );
    }
}

#[test]
fn configuration_yaml_policy_rejects_trailing_document_and_invalid_aliases() {
    for yaml in [
        format!("{}---\nvalidation-contexts: {{}}\n", policy_schema_yaml("signer-key-usage-policy: {}")),
        policy_schema_yaml("signer-key-usage-policy: *missing"),
        "policy: &policy {self: *policy}\nvalidation-contexts: {default: {signer-key-usage-policy: *policy}}\n".to_owned(),
    ] {
        assert!(CliConfig::parse(&yaml).and_then(|config| config.key_usages(None)).is_err(), "invalid document/alias accepted: {yaml}");
    }
}

#[test]
fn configuration_policy_rejects_unsupported_alias_only_root_selectors() {
    for yaml in [
        "validation_contexts: {default: {signer-key-usage: []}}",
        "validation-contexts: {default: {}, custom: {signer-key-usage: []}}\ndefault_validation_context: custom",
    ] {
        assert!(CliConfig::parse(yaml).is_err(), "unsupported root trust selector was accepted: {yaml}");
    }
    // Equal aliases do not change the canonical interpretation.
    let policy = cfg("validation-contexts: {default: {signer-key-usage: non_repudiation}}\nvalidation_contexts: {default: {signer-key-usage: non_repudiation}}\ndefault-validation-context: default\ndefault_validation_context: default").key_usages(None).unwrap();
    assert_eq!(policy.key_usage, set(&["non_repudiation"]));
}

#[test]
fn configuration_yaml_policy_rejects_unsupported_numeric_encodings() {
    let mut cases = vec![];
    let mut expected = vec![];
    for field in ["match-all-key-usages", "explicit-extd-key-usage-required"] {
        for literal in [".nan", ".inf", "0o0", "0e0", "0E+0", "0.0e0"] {
            for underscore in [false, true] {
                let oracle_field = if field == "match-all-key-usages" {
                    "all"
                } else {
                    "explicit"
                };
                let field = if underscore {
                    field.replace('-', "_")
                } else {
                    field.to_owned()
                };
                cases.push(policy_schema_yaml(&format!(
                    "signer-key-usage-policy:\n  {field}: {literal}"
                )));
                cases.push(format!(
                    "shared: &number {literal}\n{}",
                    policy_schema_yaml(&format!("signer-key-usage-policy:\n  {field}: *number"))
                ));
                cases.push(format!(
                    "policy: &policy {{{field}: {literal}}}\n{}",
                    policy_schema_yaml("signer-key-usage-policy:\n  <<: *policy")
                ));
                expected.extend([oracle_field; 3]);
            }
        }
    }
    for ((yaml, field), oracle) in cases.iter().zip(expected).zip(policy_schema_oracle(&cases)) {
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        assert_eq!(oracle[field], true, "{yaml}");
        let error = CliConfig::parse(yaml)
            .and_then(|config| config.key_usages(None))
            .unwrap_err();
        assert!(error.contains("YAML"), "{yaml}: {error}");
    }
    for literal in ["!!float .nan", "!!float .inf", "!!int 0o0", "!!float 0e0"] {
        let yaml = policy_schema_yaml(&format!(
            "signer-key-usage-policy:\n  match-all-key-usages: {literal}"
        ));
        assert!(
            CliConfig::parse(&yaml).is_err(),
            "unsupported explicit YAML number was accepted: {yaml}"
        );
    }
    assert!(CliConfig::parse("unused: .nan\nvalidation-contexts: {default: {}}\n").is_err());
}

#[test]
fn configuration_yaml_policy_preserves_common_finite_numbers_and_pkcs11_hex_ids() {
    let mut cases = vec![];
    let mut expected = vec![];
    for field in ["match-all-key-usages", "explicit-extd-key-usage-required"] {
        for (literal, truth) in [
            ("0", false),
            ("1", true),
            ("-1", true),
            ("0.0", false),
            ("1.5", true),
            ("-2.0", true),
            ("0.0e+0", false),
            ("1.0e+2", true),
            ("0x0", false),
            ("0x10", true),
        ] {
            cases.push(policy_schema_yaml(&format!(
                "signer-key-usage-policy:\n  {field}: {literal}"
            )));
            expected.push((field, truth));
        }
    }
    for ((yaml, (field, truth)), oracle) in
        cases.iter().zip(expected).zip(policy_schema_oracle(&cases))
    {
        let policy = CliConfig::parse(yaml).unwrap().key_usages(None).unwrap();
        let (native, name) = if field == "match-all-key-usages" {
            (policy.match_all_key_usages, "all")
        } else {
            (policy.explicit_extd_key_usage_required, "explicit")
        };
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        assert_eq!(oracle[name], truth, "{yaml}");
        assert_eq!(native, truth, "{yaml}");
    }
    let setup = token("key-id: 0x10\ncert-id: 0x20")
        .pkcs11_setup("foo")
        .unwrap();
    assert_eq!(setup.key_id, Some(vec![0x10]));
    assert_eq!(setup.cert_id, Some(vec![0x20]));
}

#[test]
fn configuration_yaml_policy_resolves_nonspecific_tags_with_anchor_decorators() {
    let cases: Vec<String> = ["! &flag no", "&flag ! off"]
        .iter().map(|value| format!("shared: {value}\n{}", policy_schema_yaml("signer-key-usage-policy:\n  match-all-key-usages: *flag"))).chain(std::iter::once("{note: 中文🙂, validation-contexts: {default: {signer-key-usage-policy: {match-all-key-usages: ! no}}}}\n".to_owned())).collect();
    for (yaml, oracle) in cases.iter().zip(policy_schema_oracle(&cases)) {
        assert_eq!(oracle["ok"], true, "{yaml}: {oracle}");
        assert_eq!(oracle["all"], false, "{yaml}");
        assert!(
            !CliConfig::parse(yaml)
                .unwrap()
                .key_usages(None)
                .unwrap()
                .match_all_key_usages,
            "{yaml}"
        );
    }
}

#[test]
fn configuration_policy_raw_trust_aliases_require_canonical_spelling() {
    for key in ["time-tolerance", "retroactive-revinfo"] {
        let alias = key.replace('-', "_");
        let value = if key == "time-tolerance" {
            "30"
        } else {
            "false"
        };
        assert!(
            CliConfig::parse(&format!("{alias}: {value}\n")).is_err(),
            "{alias}"
        );
        assert!(
            CliConfig::parse(&format!("{key}: {value}\n{alias}: {value}\n")).is_ok(),
            "identical alias: {alias}"
        );
    }
    for (key, value) in [
        ("trust-replace", "true"),
        ("other-certs", "[]"),
        ("time-tolerance", "30"),
        ("retroactive-revinfo", "false"),
        ("eutl-force-redownload", "false"),
        ("eutl-lotl-url", "https://example.invalid/lotl.xml"),
        ("lotl-tlso-certs", "certificate.pem"),
        ("eutl-territories", "all"),
        ("revocation-policy", "require"),
    ] {
        let alias = key.replace('-', "_");
        assert!(
            CliConfig::parse(&policy_schema_yaml(&format!("{alias}: {value}"))).is_err(),
            "{alias}"
        );
        assert!(
            CliConfig::parse(&policy_schema_yaml(&format!(
                "{key}: {value}\n{alias}: {value}"
            )))
            .is_ok(),
            "identical alias: {alias}"
        );
    }
}

#[test]
fn configuration_yaml_mapping_keys_preserve_string_identity() {
    for yaml in [
        "validation-contexts: {default: {}, true: {}}",
        "validation-contexts: {default: {}, 7: {}}",
        "shared: &name true\nvalidation-contexts:\n  default: {}\n  *name : {}\n",
        "shared: &contexts {7: {}}\nvalidation-contexts:\n  <<: *contexts\n  default: {}\n",
        "unused: {false: value}\nvalidation-contexts: {default: {}}",
    ] {
        let error = CliConfig::parse(yaml).unwrap_err();
        assert!(error.contains("mapping keys"), "{yaml}: {error}");
    }
    for name in ["'true'", "'7'", "!!str 7"] {
        let config = CliConfig::parse(&format!(
            "validation-contexts: {{default: {{}}, {name}: {{}}}}\n"
        ))
        .unwrap();
        let key = if name == "'true'" { "true" } else { "7" };
        assert!(config.validation_contexts.contains_key(key));
    }
    let logger =
        CliConfig::parse("logging:\n  by-module:\n    0:\n      level: DEBUG\n").unwrap_err();
    assert_eq!(logger, "Logger names must be strings.");
}
