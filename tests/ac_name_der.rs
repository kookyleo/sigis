//! Signed AC issuer Name encoding must preserve pinned public validation outcomes.

use sigis_pki_certvalidator::ac::validate_ac;
use sigis_pki_certvalidator::{
    Cert, CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule, ValidationContext,
};
use sigis_pki_core::{algorithms::DigestAlgorithm, time::Moment};
use std::collections::BTreeMap;

fn hash(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn signed_name_encoding_variants_do_not_receive_more_trusting_verdicts() {
    let root = std::env::var_os("SIGIS_AC_NAME_FIXTURES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| sigis_testdata::path(&["lanes", "r3-s", "ac-name-der"]));
    let oracle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("results.json")).unwrap()).unwrap();
    let cases = oracle["records"].as_array().unwrap();
    assert_eq!(cases.len(), 8, "all frozen controls must execute");
    assert_eq!(
        cases.iter().filter(|c| c["accepted"] == true).count(),
        3,
        "retain the three successful controls and five rejections"
    );
    let files: BTreeMap<String, Vec<u8>> = std::fs::read_dir(&root)
        .unwrap()
        .map(Result::unwrap)
        .filter(|e| e.path().extension().is_some_and(|x| x == "der"))
        .map(|e| {
            let bytes = std::fs::read(e.path()).unwrap();
            (hash(&bytes), bytes)
        })
        .collect();
    let aa = Cert::from_der(&std::fs::read(root.join("aa.der")).unwrap()).unwrap();
    let mut records = Vec::new();
    let mut more_trusting = Vec::new();
    for case in cases {
        let name = case["case"].as_str().unwrap();
        let ac = &files[case["ac_sha256"].as_str().unwrap()];
        let holder = case["holder_sha256"]
            .as_str()
            .map(|h| Cert::from_der(&files[h]).unwrap());
        let mut builder = ValidationContext::builder()
            .trust_root(aa.clone())
            .other_cert(aa.clone())
            .moment(Moment::parse_rfc3339(oracle["validation_time"].as_str().unwrap()).unwrap())
            .revinfo_policy(CertRevTrustPolicy::new(RevocationCheckingPolicy {
                ee_certificate_rule: RevocationCheckingRule::OcspRequired,
                intermediate_ca_cert_rule: RevocationCheckingRule::OcspRequired,
            }));
        if let Some(h) = case["response_sha256"].as_str() {
            builder = builder.ocsp_response(files[h].clone());
        }
        let result = validate_ac(&builder.build().unwrap(), ac, holder.as_ref());
        let accepted = result.is_ok();
        let expected = case["accepted"].as_bool().unwrap();
        if accepted && !expected {
            more_trusting.push(name.to_owned());
        }
        if name.starts_with("base_") && expected {
            assert!(accepted, "positive {name}: {result:?}");
        }
        records.push(serde_json::json!({
            "case":name, "native_accepted":accepted, "oracle_accepted":expected,
            "ac_sha256":hash(ac), "response_sha256":case["response_sha256"],
            "error":result.err().map(|e| e.to_string()),
        }));
    }
    eprintln!(
        "AC_NAME_DER_NATIVE {}",
        serde_json::to_string(&records).unwrap()
    );
    assert!(
        more_trusting.is_empty(),
        "more trusting cases: {more_trusting:?}"
    );
    assert!(
        records
            .iter()
            .all(|r| r["native_accepted"] == r["oracle_accepted"]),
        "all eight exact verdicts must agree"
    );
}
