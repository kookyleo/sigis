//! Revocation acquisition must retain the caller's selected evidence policy.
//! These supplemental controls do not add unique upstream functions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sigis_pades_sign::ltv::{extended_context, fetch_revinfo, ValidationInfo};
use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner};
use sigis_pdf::decode_limits::DecodePurpose;
use sigis_pdf::{PdfFile, PdfHandlerExt};
use sigis_pki_certvalidator::policy::{
    CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule,
};
use sigis_pki_certvalidator::{CertificateValidator, ValidationContext};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{FetchError, FetchErrorKind, ValidationError};
use sigis_pki_core::fetch::{CrlFetcher, Fetchers, OcspFetcher};
use support::services::Services;

const ARCH: &str = "testing-ca-with-aa";
const TIME: &str = "2020-11-01T00:00:00Z";

#[derive(Debug)]
struct Evidence {
    available_ocsp: bool,
    available_crl: bool,
    delegate: Arc<Services>,
    ocsp_calls: Mutex<Vec<(Cert, Cert)>>,
    crl_calls: Mutex<Vec<Cert>>,
}

impl Evidence {
    fn new(available_ocsp: bool, available_crl: bool) -> Arc<Self> {
        Arc::new(Self {
            available_ocsp,
            available_crl,
            delegate: Services::new(&[ARCH], TIME),
            ocsp_calls: Mutex::new(Vec::new()),
            crl_calls: Mutex::new(Vec::new()),
        })
    }
}

impl OcspFetcher for Evidence {
    fn fetch_ocsp(&self, cert: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        self.ocsp_calls
            .lock()
            .unwrap()
            .push((cert.clone(), issuer.clone()));
        if self.available_ocsp {
            self.delegate.fetch_ocsp(cert, issuer)
        } else {
            Err(FetchError::new(
                FetchErrorKind::NotFound,
                "OCSP unavailable",
            ))
        }
    }
}

impl CrlFetcher for Evidence {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        self.crl_calls.lock().unwrap().push(cert.clone());
        if self.available_crl {
            self.delegate.fetch_crls(cert)
        } else {
            Err(FetchError::new(FetchErrorKind::NotFound, "CRL unavailable"))
        }
    }
}

fn context(rule: RevocationCheckingRule, evidence: &Arc<Evidence>) -> ValidationContext {
    let pki = support::pki(ARCH);
    ValidationContext::builder()
        .trust_root(pki.cert("root"))
        .other_cert(pki.cert("interm"))
        .moment(support::at(TIME))
        .revinfo_policy(CertRevTrustPolicy::new(RevocationCheckingPolicy {
            ee_certificate_rule: rule,
            intermediate_ca_cert_rule: RevocationCheckingRule::NoCheck,
        }))
        .fetchers(Fetchers {
            ocsp: Some(evidence.clone()),
            crl: Some(evidence.clone()),
            cert: None,
        })
        .build()
        .unwrap()
}

fn compare_fresh(mut cases: Vec<Value>) {
    let pki = support::pki(ARCH);
    let receipts = std::env::var_os("HANKO_P_POLICY_RECEIPTS").map(std::path::PathBuf::from);
    let prefix = if cases.iter().any(|case| case.get("pdf_path").is_some()) {
        "pdfs"
    } else {
        "matrix"
    };
    if let Some(directory) = &receipts {
        std::fs::create_dir_all(directory).unwrap();
        for case in &mut cases {
            if let Some(path) = case["pdf_path"].as_str() {
                let output = directory.join(format!("{}.pdf", case["name"].as_str().unwrap()));
                std::fs::copy(path, &output).unwrap();
                case["pdf_path"] = json!(output);
            }
        }
    }
    let manifest = json!({
        "leaf_path": pki.cert_path("signer1"),
        "intermediate_path": pki.cert_path("interm"),
        "root_path": pki.cert_path("root"),
        "native_certificates": {
            "leaf": pki.cert("signer1").der(),
            "intermediate": pki.cert("interm").der(),
            "root": pki.cert("root").der(),
        },
        "time": TIME, "cases": cases,
    });
    let encoded = serde_json::to_vec(&manifest).unwrap();
    let path = match &receipts {
        Some(directory) => {
            let path = directory.join(format!("{prefix}-manifest.json"));
            std::fs::write(&path, encoded).unwrap();
            path
        }
        None => support::temp_file("revinfo-policy-inputs.json", &encoded),
    };
    let oracle = support::oracle("check_revinfo_policy.py", &[support::path_str(&path)])
        .expect("fresh pinned validation of actual collected evidence/output is required");
    assert_eq!(
        oracle["cases"].as_array().unwrap().len(),
        manifest["cases"].as_array().unwrap().len()
    );
    for (native, python) in manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(oracle["cases"].as_array().unwrap())
    {
        assert_eq!(python["name"], native["name"]);
        assert_eq!(python["valid"], native["expected_valid"]);
    }
    eprintln!("fresh revocation policy oracle: {oracle}");
    if let Some(directory) = receipts {
        std::fs::write(
            directory.join(format!("{prefix}-oracle.json")),
            serde_json::to_vec_pretty(&oracle).unwrap(),
        )
        .unwrap();
    } else {
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn presign_acquisition_obeys_all_rules_with_missing_provider_controls() {
    use RevocationCheckingRule::*;

    // Columns are both available, OCSP missing, CRL missing, both missing.
    // Entries are expected OCSP calls, CRL calls, and offline native verdict.
    let rules = [
        (
            CrlRequired,
            [(0, 1, true), (0, 1, true), (0, 1, false), (0, 1, false)],
        ),
        (
            OcspRequired,
            [(1, 0, true), (1, 0, false), (1, 0, true), (1, 0, false)],
        ),
        (
            CrlAndOcspRequired,
            [(1, 1, true), (1, 1, false), (1, 1, false), (1, 1, false)],
        ),
        (
            CrlOrOcspRequired,
            [(1, 0, true), (1, 1, true), (1, 0, true), (1, 1, false)],
        ),
        (NoCheck, [(0, 0, true); 4]),
        (
            CheckIfDeclared,
            [(1, 0, true), (1, 1, true), (1, 0, true), (1, 1, false)],
        ),
        (
            CheckIfDeclaredSoft,
            [(1, 0, true), (1, 1, true), (1, 0, true), (1, 1, true)],
        ),
    ];
    let pki = support::pki(ARCH);
    let path = [pki.cert("signer1"), pki.cert("interm"), pki.cert("root")];
    assert!(path[0].declares_ocsp() && path[0].declares_crl());
    let mut cases = Vec::new();
    for (rule, expected) in rules {
        for ((ocsp, crl), (ocsp_calls, crl_calls, valid)) in
            [(true, true), (false, true), (true, false), (false, false)]
                .into_iter()
                .zip(expected)
        {
            let evidence = Evidence::new(ocsp, crl);
            let context = context(rule, &evidence);
            let mut info = ValidationInfo::default();
            fetch_revinfo(&context, &path, &mut info);
            let name = format!("{}-ocsp{ocsp}-crl{crl}", rule.value());
            assert_eq!(
                evidence.ocsp_calls.lock().unwrap().len(),
                ocsp_calls,
                "{name}"
            );
            assert_eq!(
                evidence.crl_calls.lock().unwrap().len(),
                crl_calls,
                "{name}"
            );
            assert!(evidence
                .ocsp_calls
                .lock()
                .unwrap()
                .iter()
                .all(|(cert, issuer)| cert == &path[0] && issuer == &path[1]));
            assert!(evidence
                .crl_calls
                .lock()
                .unwrap()
                .iter()
                .all(|cert| cert == &path[0]));
            assert_eq!(
                info.ocsps.len(),
                usize::from(ocsp && ocsp_calls > 0),
                "{name}"
            );
            assert_eq!(info.crls.len(), usize::from(crl && crl_calls > 0), "{name}");
            let offline = extended_context(&context, &path, &info)
                .unwrap()
                .with_fetchers(Fetchers::default());
            match CertificateValidator::new(&offline, path[0].clone()).validate() {
                Ok(validated) => {
                    assert!(valid, "{name}");
                    assert_eq!(validated.certs().len(), 3);
                }
                Err(error) => {
                    assert!(!valid, "{name}: {error}");
                    assert!(
                        matches!(error, ValidationError::InsufficientRevinfo(_)),
                        "{name}: {error}"
                    );
                }
            }
            cases.push(json!({
                "name": name, "ee_rule": rule.value(), "ca_rule": "nocheck",
                "ocsps": info.ocsps, "crls": info.crls, "expected_valid": valid,
            }));
        }
    }
    compare_fresh(cases);
}

fn dss_evidence(output: &[u8], key: &[u8]) -> Vec<Vec<u8>> {
    let reader = PdfFile::parse(output).unwrap();
    let root = reader.root().unwrap();
    let dss = reader.get_dict(&root, b"DSS").unwrap().unwrap();
    reader
        .get_array(&dss, key)
        .unwrap()
        .unwrap_or_default()
        .iter()
        .map(|object| {
            let stream = reader.resolve(object).unwrap();
            reader
                .read_stream_data(stream.as_stream().unwrap(), DecodePurpose::Generic, None)
                .unwrap()
        })
        .collect()
}

#[test]
fn real_pdf_signing_embeds_exactly_the_required_revocation_kinds() {
    use RevocationCheckingRule::{CrlAndOcspRequired, CrlRequired, OcspRequired};

    let pki = support::pki(ARCH);
    let mut cases = Vec::new();
    let mut paths = Vec::new();
    for (rule, ocsp_count, crl_count) in [
        (CrlRequired, 0, 1),
        (OcspRequired, 1, 0),
        (CrlAndOcspRequired, 1, 1),
    ] {
        let evidence = Evidence::new(true, true);
        let mut metadata = PdfSignatureMetadata::new("RequiredEvidence");
        metadata.validation_context = Some(Arc::new(context(rule, &evidence)));
        metadata.embed_validation_info = true;
        metadata.dss_settings = DssContentSettings {
            include_vri: false,
            placement: SigDssPlacement::TogetherWithSignature,
            ..Default::default()
        };
        let output = PdfSigner::new(metadata, Arc::new(pki.signer("signer1")))
            .at(support::at(TIME))
            .sign_pdf(&support::pdf("minimal.pdf"))
            .unwrap();
        let signatures = support::pdfcheck::embedded_signatures(&output);
        assert_eq!(signatures.len(), 1);
        support::pdfcheck::check_integrity(&output, &signatures[0]);
        let ocsps = dss_evidence(&output, b"OCSPs");
        let crls = dss_evidence(&output, b"CRLs");
        assert_eq!(ocsps.len(), ocsp_count, "{}", rule.value());
        assert_eq!(crls.len(), crl_count, "{}", rule.value());
        if ocsp_count == 0 {
            assert!(evidence.ocsp_calls.lock().unwrap().is_empty());
        }
        if crl_count == 0 {
            assert!(evidence.crl_calls.lock().unwrap().is_empty());
        }
        let path = support::temp_file("required-evidence.pdf", &output);
        cases.push(json!({
            "name": rule.value(), "ee_rule": rule.value(), "ca_rule": "nocheck",
            "ocsps": ocsps, "crls": crls, "expected_valid": true, "pdf_path": path,
        }));
        paths.push(path);
    }
    compare_fresh(cases);
    for path in paths {
        std::fs::remove_file(path).unwrap();
    }
}
