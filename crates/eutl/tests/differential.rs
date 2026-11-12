//! Differential test: trusted list verdicts of this crate against pyHanko's
//! (`oracle/tl_verdicts.py`) on every trusted list input, including
//! tampered variants. Skips when the oracle is not installed.

mod common;

use std::path::{Path, PathBuf};

use base64::Engine as _;
use common::*;
use serde_json::{json, Value};
use sigis_eutl::parse;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::time::Moment;

struct Case {
    name: String,
    xml: PathBuf,
    certs: Vec<Cert>,
    time: Option<Moment>,
}

fn pem(cert: &Cert) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(cert.der());
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

fn rust_verdict(case: &Case) -> Value {
    let xml = std::fs::read_to_string(&case.xml).unwrap();
    let mut v = json!({ "signature": null });
    let signed = if case.certs.is_empty() {
        xml
    } else {
        match parse::validate_and_extract_tl_data(&xml, &case.certs, case.time) {
            Ok(s) => {
                v["signature"] = json!("valid");
                s
            }
            Err(_) => {
                v["signature"] = json!("invalid");
                return v;
            }
        }
    };
    match parse::read_qualified_service_definitions(&signed) {
        Ok((sds, errors)) => {
            let cas = sds.iter().filter(|s| s.is_ca()).count();
            let (reg, _) = parse::trust_list_to_registry_unsafe(&signed, None).unwrap();
            v["cas"] = json!(cas);
            v["qtsts"] = json!(sds.len() - cas);
            v["errors"] = json!(errors.len());
            v["known_cas"] = json!(reg.known_certificate_authorities().len());
            v["known_tsas"] = json!(reg.known_timestamp_authorities().len());
        }
        Err(e) => {
            v["parse_error"] = json!(e.to_string());
        }
    }
    v
}

fn tampered(src: &Path, dir: &Path, name: &str, from: &str, to: &str) -> PathBuf {
    let xml = std::fs::read_to_string(src).unwrap();
    assert!(xml.contains(from), "{from} not in {}", src.display());
    let out = dir.join(name);
    std::fs::write(&out, xml.replacen(from, to, 1)).unwrap();
    out
}

#[test]
fn differential_trusted_list_verdicts() {
    let tmp = TempDir::new();
    let latest = sigis_eutl::parse::latest_known_lotl_tlso_certs();
    let pre_reanchor = sigis_eutl::util::load_certs_from_pemder(
        &std::fs::read(tl_path("pre-reanchor.cert.pem")).unwrap(),
    )
    .unwrap();
    let lotl = tl_file(TEST_REAL_LOTL);
    let be_ref = parse::parse_lotl_unsafe(&lotl)
        .unwrap()
        .references
        .into_iter()
        .find(|r| r.territory == "BE")
        .unwrap();
    let issued = |name: &str| {
        parse::parse_lotl_unsafe(&tl_file(name))
            .unwrap()
            .claimed_date_issued
    };
    let root = pki_cert("testing-ca-qualified", "root");
    let gen_lotl = data(&["lanes", "e", "tl", "certomancer-lotl.xml"]);
    let gen_tl = data(&["lanes", "e", "tl", "certomancer-qualified-tl.xml"]);
    let t_be = moment("2025-06-01T00:05:00Z");

    let mut cases = vec![
        Case {
            name: "be-old signed".into(),
            xml: tl_path(TEST_REAL_TL_BE_OLD),
            certs: vec![be_tlso_cert()],
            time: Some(t_be),
        },
        Case {
            name: "be-old unsigned".into(),
            xml: tl_path(TEST_REAL_TL_BE_OLD),
            certs: vec![],
            time: None,
        },
        Case {
            name: "ee wrong signer".into(),
            xml: tl_path(TEST_REAL_TL_EE),
            certs: vec![be_tlso_cert()],
            time: Some(t_be),
        },
        Case {
            name: "ee unsigned".into(),
            xml: tl_path(TEST_REAL_TL_EE),
            certs: vec![],
            time: None,
        },
        Case {
            name: "be-v6 via LOTL certs".into(),
            xml: tl_path(TEST_REAL_TL_BE),
            certs: be_ref.tlso_certs.clone(),
            time: Some(moment("2026-06-16T00:00:00Z")),
        },
        Case {
            name: "lotl".into(),
            xml: tl_path(TEST_REAL_LOTL),
            certs: latest.clone(),
            time: Some(issued(TEST_REAL_LOTL)),
        },
        Case {
            name: "lotl expired signer time".into(),
            xml: tl_path(TEST_REAL_LOTL),
            certs: latest.clone(),
            time: Some(moment("2050-01-01T00:00:00Z")),
        },
        Case {
            name: "lotl old".into(),
            xml: tl_path(TEST_REAL_LOTL_OLD),
            certs: pre_reanchor.clone(),
            time: Some(issued(TEST_REAL_LOTL_OLD)),
        },
        Case {
            name: "generated lotl".into(),
            xml: gen_lotl.clone(),
            certs: vec![root.clone()],
            time: None,
        },
        Case {
            name: "generated tl".into(),
            xml: gen_tl.clone(),
            certs: vec![root.clone()],
            time: None,
        },
        Case {
            name: "generated tl wrong signer".into(),
            xml: gen_tl.clone(),
            certs: vec![be_tlso_cert()],
            time: Some(t_be),
        },
    ];
    for p in [
        "eu-lotl-pivot-282.xml",
        "eu-lotl-pivot-300.xml",
        "eu-lotl-pivot-335.xml",
        "eu-lotl-pivot-341.xml",
    ] {
        let mut certs = sigis_eutl::parse::ojeu_bootstrap_lotl_tlso_certs(0);
        certs.extend(pre_reanchor.iter().cloned());
        cases.push(Case {
            name: format!("pivot {p}"),
            xml: tl_path(p),
            certs,
            time: Some(issued(p)),
        });
    }
    // Tampered inputs: both implementations must reject them.
    let t1 = tampered(
        &tl_path(TEST_REAL_TL_BE_OLD),
        tmp.path(),
        "be-tampered.xml",
        "<ServiceStatus>",
        "<ServiceStatus> ",
    );
    cases.push(Case {
        name: "be-old tampered content".into(),
        xml: t1,
        certs: vec![be_tlso_cert()],
        time: Some(t_be),
    });
    let t2 = tampered(
        &gen_tl,
        tmp.path(),
        "gen-tampered.xml",
        "TSA tsa-qualified",
        "TSA tsa-qua1ified",
    );
    cases.push(Case {
        name: "generated tl tampered".into(),
        xml: t2,
        certs: vec![root.clone()],
        time: None,
    });
    let t3 = tampered(
        &gen_lotl,
        tmp.path(),
        "gen-lotl-sigval.xml",
        "<ds:SignatureValue>",
        "<ds:SignatureValue>AAAA",
    );
    cases.push(Case {
        name: "generated lotl bad signature value".into(),
        xml: t3,
        certs: vec![root.clone()],
        time: None,
    });

    // These edits preserve the cryptographic payload. The oracle's XSD
    // validation must reject them before treating the signature as trusted.
    for (name, from, to) in [
        (
            "signature-value-attribute",
            "<ds:SignatureValue>",
            "<ds:SignatureValue bogus=\"1\">",
        ),
        (
            "signature-value-child",
            "</ds:SignatureValue>",
            "<ds:DigestValue/></ds:SignatureValue>",
        ),
        (
            "signature-text",
            "<ds:SignedInfo>",
            "invalid-schema-text<ds:SignedInfo>",
        ),
        ("object-attribute", "<ds:Object>", "<ds:Object bogus=\"1\">"),
    ] {
        let xml = tampered(&gen_tl, tmp.path(), &format!("{name}.xml"), from, to);
        cases.push(Case {
            name: name.into(),
            xml,
            certs: vec![root.clone()],
            time: None,
        });
    }

    // Write the case list for the oracle.
    let mut oracle_cases = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let mut cert_paths = Vec::new();
        for (j, cert) in c.certs.iter().enumerate() {
            let p = tmp.path().join(format!("c{i}-{j}.pem"));
            std::fs::write(&p, pem(cert)).unwrap();
            cert_paths.push(p.to_string_lossy().into_owned());
        }
        oracle_cases.push(json!({
            "xml": c.xml.to_string_lossy(),
            "certs": cert_paths,
            "time": c.time.map(|t| t.to_string()),
        }));
    }
    let cases_file = tmp.path().join("cases.json");
    std::fs::write(&cases_file, serde_json::to_string(&oracle_cases).unwrap()).unwrap();
    let script = sigis_testdata::manifest_dir().join("oracle/tl_verdicts.py");

    let rust: Vec<Value> = cases.iter().map(rust_verdict).collect();
    let Some(oracle) = sigis_testdata::oracle::run_json(&script, &[cases_file.to_str().unwrap()])
    else {
        return;
    };
    if let Some(reason) = oracle.get("skip") {
        eprintln!("skipping differential check: {reason}");
        return;
    }
    let oracle = oracle.as_array().unwrap();
    assert_eq!(oracle.len(), cases.len());
    let mut failures = Vec::new();
    for ((case, ours), theirs) in cases.iter().zip(&rust).zip(oracle) {
        // Never accept what pyHanko rejects.
        if theirs["signature"] == "invalid" && ours["signature"] == "valid" {
            failures.push(format!(
                "FAIL-OPEN {}: pyHanko {theirs} vs port {ours}",
                case.name
            ));
            continue;
        }
        let comparable = |v: &Value| {
            let mut v = v.clone();
            if let Some(o) = v.as_object_mut() {
                if o.remove("parse_error").is_some() {
                    o.insert("parse_error".into(), json!(true));
                }
            }
            v
        };
        if comparable(ours) != comparable(theirs) {
            failures.push(format!("{}: pyHanko {theirs} vs port {ours}", case.name));
        }
    }
    assert!(failures.is_empty(), "divergences:\n{}", failures.join("\n"));
    eprintln!("{} trusted list cases agree with pyHanko", cases.len());
}
