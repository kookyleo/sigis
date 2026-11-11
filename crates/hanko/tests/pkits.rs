// Port of `test_nist_pkits` in pyhanko-certvalidator `tests/test_validate.py`
// (MIT, see LICENSE-pyHanko). Test case definitions: `nist_pkits/pkits.json`.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::{load_nist_cert, load_nist_crl, pkits_moment, read};
use sigis_hanko::certvalidator::Cert;

fn try_load(name: &str) -> Result<Cert, ValidationError> {
    Cert::from_pem_or_der(&read(&["nist_pkits", "certs", name]))
}
use serde_json::Value;
use sigis_hanko::algorithms::DisallowWeakAlgorithmsPolicy;
use sigis_hanko::certvalidator::{
    build_paths, validate_path, PkixValidationParams, TrustAnchor, ValidationContext,
    ValidationPath,
};
use sigis_hanko::errors::ValidationError;

/// Cases where this port's result differs from pyhanko-certvalidator's, with
/// the reason. The test fails if a case diverges that is not listed here, and
/// also if a listed case starts to agree (so the list stays accurate).
///
/// Every entry fails closed: this port rejects (or reports insufficient
/// revocation information) where pyhanko-certvalidator accepts or reports
/// revocation. No entry accepts a path that pyhanko-certvalidator rejects.
const KNOWN_DIVERGENCES: &[(&str, &str)] = &[
    ("40104", "DSA signatures are not supported"),
    (
        "40105",
        "DSA signatures (with parameter inheritance) are not supported",
    ),
    (
        "40203",
        "UTCTime before 1970 (here 1950) cannot be decoded by the der crate",
    ),
    (
        "41418",
        "coverage across reason-partitioned (onlySomeReasons) CRLs is not accumulated",
    ),
    (
        "41419",
        "coverage across reason-partitioned (onlySomeReasons) CRLs is not accumulated",
    ),
    ("41422", "indirect CRLs are not supported"),
    ("41423", "indirect CRLs are not supported"),
    ("41424", "indirect CRLs are not supported"),
    ("41425", "indirect CRLs are not supported"),
    (
        "41428",
        "cRLIssuer distribution points (indirect CRLs) are not supported",
    ),
    (
        "41429",
        "cRLIssuer distribution points (indirect CRLs) are not supported",
    ),
    (
        "41430",
        "cRLIssuer distribution points (indirect CRLs) are not supported",
    ),
    (
        "41431",
        "cRLIssuer distribution points (indirect CRLs) are not supported",
    ),
    (
        "41432",
        "cRLIssuer distribution points (indirect CRLs) are not supported",
    ),
    (
        "41433",
        "cRLIssuer distribution points (indirect CRLs) are not supported",
    ),
    (
        "41434",
        "cRLIssuer distribution points (indirect CRLs) are not supported",
    ),
];

struct Case {
    id: String,
    name: String,
    json: Value,
}

fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn params(v: &Value) -> Option<PkixValidationParams> {
    let p = v.get("params")?;
    let flag = |k: &str| p.get(k).and_then(Value::as_bool).unwrap_or(false);
    Some(PkixValidationParams {
        user_initial_policy_set: strings(p, "user_initial_policy_set")
            .iter()
            .map(|s| const_oid::ObjectIdentifier::new(s).expect("policy OID"))
            .collect(),
        initial_policy_mapping_inhibit: flag("initial_policy_mapping_inhibit"),
        initial_explicit_policy: flag("initial_explicit_policy"),
        initial_any_policy_inhibit: flag("initial_any_policy_inhibit"),
    })
}

/// Outcome of a case, as a pyhanko-certvalidator class name ("ok" on success).
fn run_case(case: &Case) -> (String, Option<ValidationError>) {
    let v = &case.json;
    let root = load_nist_cert("TrustAnchorRootCertificate.crt");
    let check_revocation = v.get("revocation").and_then(Value::as_bool).unwrap_or(true);
    let mut builder = ValidationContext::builder()
        .trust_root(root.clone())
        .crl(load_nist_crl("TrustAnchorRootCRL.crl"))
        .moment(pkits_moment())
        .revocation_mode(if check_revocation {
            "require"
        } else {
            "hard-fail"
        })
        .algorithm_policy(Arc::new(
            DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&["md2", "md5"]),
        ));
    for crl in strings(v, "crls") {
        builder = builder.crl(load_nist_crl(&crl));
    }
    for cert in strings(v, "other_certs") {
        match try_load(&cert) {
            Ok(c) => builder = builder.other_cert(c),
            Err(e) => return (format!("load error: {}", e.class_name()), Some(e)),
        }
    }
    let ctx = match builder.build() {
        Ok(ctx) => ctx,
        Err(e) => return (format!("context error: {}", e.class_name()), Some(e)),
    };
    let leaf = match try_load(v["cert"].as_str().expect("cert")) {
        Ok(c) => c,
        Err(e) => return (format!("load error: {}", e.class_name()), Some(e)),
    };
    let path = if v.get("path_intermediates").is_some() {
        let interm = strings(v, "path_intermediates")
            .iter()
            .map(|c| load_nist_cert(c))
            .collect();
        ValidationPath::new(TrustAnchor::new(root), interm, Some(leaf))
    } else {
        match build_paths(&ctx, &leaf) {
            Ok(paths) if paths.len() == 1 => paths.into_iter().next().expect("one path"),
            Ok(paths) => return (format!("path count {}", paths.len()), None),
            Err(e) => return (format!("path building: {}", e.class_name()), Some(e)),
        }
    };
    let expected_len = v["path_len"].as_u64().expect("path_len") as usize;
    if path.len() != expected_len {
        return (format!("path length {}", path.len()), None);
    }
    match validate_path(&ctx, &path, params(v).as_ref()) {
        Ok(()) => ("ok".to_owned(), None),
        Err(e) => (e.class_name().to_owned(), Some(e)),
    }
}

fn load_cases() -> Vec<Case> {
    let json: Value =
        serde_json::from_slice(&read(&["nist_pkits", "pkits.json"])).expect("pkits.json");
    json.as_array()
        .expect("array")
        .iter()
        .map(|c| Case {
            id: c["id"].as_str().expect("id").to_owned(),
            name: c["name"].as_str().expect("name").to_owned(),
            json: c.clone(),
        })
        .collect()
}

#[test]
fn test_nist_pkits() {
    let cases = load_cases();
    assert_eq!(cases.len(), 246);
    let known: BTreeMap<&str, &str> = KNOWN_DIVERGENCES.iter().copied().collect();
    let mut diverging = BTreeMap::new();
    let mut message_mismatches = Vec::new();
    for case in &cases {
        let expected = case.json.get("error");
        let expected_class = expected.and_then(|e| e["class"].as_str()).unwrap_or("ok");
        let (outcome, err) = run_case(case);
        let agrees = match (&err, expected_class) {
            (None, "ok") => outcome == "ok",
            (Some(e), class) if outcome == e.class_name() => e.is_instance_of(class),
            _ => false,
        };
        if !agrees {
            let detail = err.as_ref().map(ToString::to_string).unwrap_or_default();
            diverging.insert(
                case.id.clone(),
                format!(
                    "{} [{}]: expected {expected_class}, got {outcome}: {detail}",
                    case.id, case.name
                ),
            );
        } else if let (Some(e), Some(re)) = (&err, expected.and_then(|e| e["msg_regex"].as_str())) {
            let re = regex::Regex::new(re).expect("regex");
            if !re.is_match(&e.to_string()) {
                message_mismatches.push(format!("{}: {}", case.id, e));
            }
        }
    }
    // Fail-closed check: no diverging case may succeed where an error was expected.
    for (id, detail) in &diverging {
        assert!(
            !detail.contains("got ok"),
            "fail-open divergence {id}: {detail}"
        );
    }
    let unexpected: Vec<_> = diverging
        .iter()
        .filter(|(id, _)| !known.contains_key(id.as_str()))
        .map(|(_, d)| d)
        .collect();
    let fixed: Vec<_> = known
        .keys()
        .filter(|id| !diverging.contains_key(**id))
        .collect();
    eprintln!(
        "PKITS: {} cases, {} agree, {} known divergences, {} agree on class but differ in message",
        cases.len(),
        cases.len() - diverging.len(),
        diverging.len() - unexpected.len(),
        message_mismatches.len()
    );
    if std::env::var_os("PKITS_VERBOSE").is_some() {
        for m in &message_mismatches {
            eprintln!("message: {m}");
        }
    }
    assert!(
        unexpected.is_empty(),
        "unexpected divergences:\n{}",
        unexpected
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        fixed.is_empty(),
        "listed divergences that now agree (remove them): {fixed:?}"
    );
}
