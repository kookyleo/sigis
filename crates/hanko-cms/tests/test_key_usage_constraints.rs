// Ported from pyHanko 0.38.1 `pkgs/pyhanko/tests/test_key_usage_constraints.py`
// (MIT, see LICENSE-pyHanko).

use std::collections::BTreeSet;

use hanko_cms::KeyUsageConstraints;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn ku(items: &[&str]) -> KeyUsageConstraints {
    KeyUsageConstraints::with_key_usage(items)
}

fn eku(items: &[&str]) -> KeyUsageConstraints {
    KeyUsageConstraints::with_extd_key_usage(items)
}

#[test]
fn test_ku_accept() {
    let none = BTreeSet::new();
    let cases: Vec<(KeyUsageConstraints, Option<BTreeSet<String>>)> = vec![
        (ku(&["non_repudiation"]), Some(set(&["non_repudiation"]))),
        (
            ku(&["non_repudiation", "digital_signature"]),
            Some(set(&["non_repudiation"])),
        ),
        (
            ku(&["non_repudiation"]),
            Some(set(&["non_repudiation", "digital_signature"])),
        ),
        (
            KeyUsageConstraints {
                match_all_key_usages: true,
                ..ku(&["non_repudiation"])
            },
            Some(set(&["non_repudiation", "digital_signature"])),
        ),
        (ku(&[]), Some(set(&["non_repudiation"]))),
        (KeyUsageConstraints::default(), Some(set(&["non_repudiation"]))),
        (KeyUsageConstraints::default(), None),
    ];
    for (cfg, cert_ku) in cases {
        cfg.validate_key_usage_extension(cert_ku.as_ref(), &none)
            .unwrap_or_else(|e| panic!("{cfg:?} {cert_ku:?}: {e}"));
    }
}

#[test]
fn test_ku_reject() {
    let none = BTreeSet::new();
    let cases = vec![
        (ku(&["non_repudiation"]), set(&["digital_signature"])),
        (
            KeyUsageConstraints {
                match_all_key_usages: true,
                ..ku(&["non_repudiation", "digital_signature"])
            },
            set(&["digital_signature"]),
        ),
        (
            KeyUsageConstraints {
                key_usage_forbidden: Some(set(&["key_agreement"])),
                ..ku(&["non_repudiation", "digital_signature"])
            },
            set(&["digital_signature", "key_agreement"]),
        ),
    ];
    for (cfg, cert_ku) in cases {
        assert!(
            cfg.validate_key_usage_extension(Some(&cert_ku), &none).is_err(),
            "{cfg:?} {cert_ku:?}"
        );
    }
}

#[test]
fn test_eku_accept() {
    let none = BTreeSet::new();
    let lenient = |items: &[&str]| KeyUsageConstraints {
        explicit_extd_key_usage_required: false,
        ..eku(items)
    };
    let cases: Vec<(KeyUsageConstraints, Option<BTreeSet<String>>)> = vec![
        (eku(&["time_stamping"]), Some(set(&["time_stamping"]))),
        (
            eku(&["time_stamping"]),
            Some(set(&["time_stamping", "microsoft_time_stamp_signing"])),
        ),
        (
            eku(&["time_stamping", "microsoft_time_stamp_signing"]),
            Some(set(&["time_stamping"])),
        ),
        (lenient(&["microsoft_document_signing"]), None),
        (KeyUsageConstraints::default(), Some(set(&["client_auth"]))),
        (
            lenient(&["microsoft_document_signing"]),
            Some(set(&["client_auth", "any_extended_key_usage"])),
        ),
        (
            lenient(&["microsoft_document_signing"]),
            Some(set(&["any_extended_key_usage"])),
        ),
    ];
    for (cfg, cert_eku) in cases {
        cfg.validate_extd_key_usage_extension(cert_eku.as_ref(), &none)
            .unwrap_or_else(|e| panic!("{cfg:?} {cert_eku:?}: {e}"));
    }
}

#[test]
fn test_eku_reject() {
    let none = BTreeSet::new();
    let lenient = |items: &[&str]| KeyUsageConstraints {
        explicit_extd_key_usage_required: false,
        ..eku(items)
    };
    let cases: Vec<(KeyUsageConstraints, Option<BTreeSet<String>>, &str)> = vec![
        (
            eku(&["time_stamping"]),
            None,
            "requires an extended key usage extension",
        ),
        (
            eku(&["microsoft_document_signing"]),
            Some(set(&["client_auth"])),
            "Relevant key purposes are microsoft document signing",
        ),
        (
            lenient(&["microsoft_document_signing"]),
            Some(set(&["client_auth"])),
            "Relevant key purposes are microsoft document signing",
        ),
        (
            eku(&["microsoft_document_signing"]),
            Some(set(&["client_auth", "any_extended_key_usage"])),
            "Relevant key purposes are microsoft document signing",
        ),
        (
            eku(&[]),
            Some(set(&["client_auth"])),
            "There are no acceptable extended key usages",
        ),
    ];
    for (cfg, cert_eku, err) in cases {
        let e = cfg
            .validate_extd_key_usage_extension(cert_eku.as_ref(), &none)
            .expect_err("reject");
        assert!(e.0.contains(err), "{e}");
    }
}
