// Port of `test_openssl_ocsp` in pyhanko-certvalidator `tests/test_validate.py`
// (MIT, see LICENSE-pyHanko). Test case definitions:
// `openssl-ocsp/openssl-ocsp.json`; test vectors from the OpenSSL test suite
// (Apache-2.0, see `openssl-ocsp/LICENSE`).

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::{load_cert, load_openssl_ors, moment, read};
use hanko_certvalidator::{build_paths, validate_path, ValidationContext};
use hanko_core::algorithms::DisallowWeakAlgorithmsPolicy;
use serde_json::Value;

/// Cases where this port's result differs from pyhanko-certvalidator's, with
/// the reason (see `pkits.rs` for how the list is enforced).
const KNOWN_DIVERGENCES: &[(&str, &str)] = &[];

#[test]
fn test_openssl_ocsp() {
    let cases: Value =
        serde_json::from_slice(&read(&["openssl-ocsp", "openssl-ocsp.json"])).expect("json");
    let cases = cases.as_array().expect("array");
    assert_eq!(cases.len(), 29);
    let known: BTreeMap<&str, &str> = KNOWN_DIVERGENCES.iter().copied().collect();
    let mut diverging = BTreeMap::new();
    let mut message_mismatches = 0;
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let strings = |key: &str| -> Vec<String> {
            case.get(key)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut builder = ValidationContext::builder()
            .trust_root(load_cert(&[
                "openssl-ocsp",
                case["root"].as_str().expect("root"),
            ]))
            .moment(moment(case["moment"].as_str().expect("moment")))
            .algorithm_policy(Arc::new(
                DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&["md2", "md5"]),
            ));
        for other in strings("other_certs") {
            builder = builder.other_cert(load_cert(&["openssl-ocsp", &other]));
        }
        for ors in strings("ocsps") {
            builder = builder.ocsp_response(load_openssl_ors(&ors));
        }
        let ctx = builder.build().expect("context");
        let cert = load_cert(&["openssl-ocsp", case["cert"].as_str().expect("cert")]);
        let paths = build_paths(&ctx, &cert).expect("paths");
        assert_eq!(paths.len(), 1, "{name}");
        assert_eq!(
            paths[0].len() as u64,
            case["path_len"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .or(case["path_len"].as_u64())
                .expect("path_len"),
            "{name}"
        );

        let result = validate_path(&ctx, &paths[0], None);
        let expected = case.get("error");
        let expected_class = expected.and_then(|e| e["class"].as_str()).unwrap_or("ok");
        let agrees = match &result {
            Ok(()) => expected_class == "ok",
            Err(e) => e.is_instance_of(expected_class),
        };
        if !agrees {
            diverging.insert(
                name.to_owned(),
                format!("{name}: expected {expected_class}, got {result:?}"),
            );
        } else if let (Err(e), Some(re)) = (&result, expected.and_then(|e| e["msg_regex"].as_str()))
        {
            if !regex::Regex::new(re)
                .expect("regex")
                .is_match(&e.to_string())
            {
                message_mismatches += 1;
                eprintln!("message differs for {name}: {e}");
            }
        }
    }
    for (name, detail) in &diverging {
        assert!(
            !detail.contains("got Ok"),
            "fail-open divergence {name}: {detail}"
        );
    }
    let unexpected: Vec<_> = diverging
        .iter()
        .filter(|(n, _)| !known.contains_key(n.as_str()))
        .map(|(_, d)| d.clone())
        .collect();
    let fixed: Vec<_> = known
        .keys()
        .filter(|n| !diverging.contains_key(**n))
        .collect();
    eprintln!(
        "openssl-ocsp: {} cases, {} diverge, {message_mismatches} message differences",
        cases.len(),
        diverging.len()
    );
    assert!(
        unexpected.is_empty(),
        "unexpected divergences:\n{}",
        unexpected.join("\n")
    );
    assert!(
        fixed.is_empty(),
        "listed divergences that now agree (remove them): {fixed:?}"
    );
}
