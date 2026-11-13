//! AC retrieval uses the configured AC methods, never the holder's PKC APIs.
//! Supplemental presign regressions; no unique upstream function credit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::{Arc, Mutex, OnceLock};

use der::{Decode, Encode};
use sigis_pades_sign::ltv::{validate_and_collect_attribute_certs, ValidationInfo};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{FetchError, FetchErrorKind, HankoError};
use sigis_pki_core::fetch::{CrlFetcher, Fetchers, OcspFetcher};
use support::services::Services;

const ARCH: &str = "testing-ca-with-aa";
const TIME: &str = "2020-11-01T00:00:00Z";

#[derive(Debug)]
struct DeferredAaCrls {
    calls: Mutex<Vec<Cert>>,
    services: Arc<Services>,
}

impl CrlFetcher for DeferredAaCrls {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        let mut calls = self.calls.lock().unwrap();
        calls.push(cert.clone());
        let count = calls.iter().filter(|requested| *requested == cert).count();
        drop(calls);
        if count == 1 {
            Err(FetchError::new(
                FetchErrorKind::Network,
                "prefetch unavailable",
            ))
        } else if count == 2 {
            self.services.fetch_crls(cert)
        } else {
            Err(FetchError::new(
                FetchErrorKind::TooLarge,
                "provider request allowance exhausted",
            ))
        }
    }
}

#[test]
fn native_aa_retrieval_outcomes_are_collected_without_reissuing_provider_calls() {
    let pki = support::pki(ARCH);
    let provider = Arc::new(DeferredAaCrls {
        calls: Mutex::new(Vec::new()),
        services: Services::new(&[ARCH], TIME),
    });
    // Only AC OCSP is supplied. AA path evidence is first obtained inside the
    // native validator after the collection prefetch's temporary failures.
    let context = ValidationContext::builder()
        .trust_root(pki.cert("root-aa"))
        .other_cert(pki.cert("interm-aa"))
        .other_cert(pki.cert("leaf-aa"))
        .moment(support::at(TIME))
        .revocation_mode("require")
        .ocsp_response(ac_file("ocsp-alice-role-with-rev.der"))
        .fetchers(Fetchers {
            crl: Some(provider.clone()),
            ..Default::default()
        })
        .build()
        .unwrap();
    let ac = ac_file("alice-role-with-rev.der");
    let mut info = ValidationInfo::default();
    let result = validate_and_collect_attribute_certs(
        &context,
        &pki.cert("signer1"),
        &[],
        std::slice::from_ref(&ac),
        &mut info,
    )
    .unwrap();
    assert!(result[0].approved_attributes.contains_key("role"));
    let calls = provider.calls.lock().unwrap();
    for name in ["leaf-aa", "interm-aa"] {
        let cert = pki.cert(name);
        assert_eq!(
            calls.iter().filter(|requested| **requested == cert).count(),
            2
        );
        for crl in provider.services.fetch_crls(&cert).unwrap() {
            assert!(
                info.crls.contains(&crl),
                "native-acquired CRL missing for {name}"
            );
        }
    }
    assert_eq!(info.crls.len(), 2);
    assert_eq!(info.ocsps, [ac_file("ocsp-alice-role-with-rev.der")]);
    assert_eq!(
        calls.len(),
        4,
        "no other provider targets or collector re-fetch"
    );
    drop(calls);
    assert_eq!(context.crls().count(), 0, "caller context stays unchanged");

    let output = sigis_pades_sign::pdf::dss::add_dss(
        &support::pdf("minimal.pdf"),
        &sigis_pades_sign::pdf::dss::DssContent {
            paths: info.paths.clone(),
            ocsps: info.ocsps.clone(),
            crls: info.crls.clone(),
            embed_roots: true,
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let reader = sigis_pdf::PdfFile::parse(&output).unwrap();
    let material = reader.dss().unwrap().unwrap().material;
    assert_eq!(material.certs.len(), 3);
    assert_eq!(material.crls, info.crls);
    assert_eq!(material.ocsps, info.ocsps);
    assert_eq!(provider.calls.lock().unwrap().len(), 4);
    let digest = |bytes: &[u8]| {
        sigis_pki_core::algorithms::DigestAlgorithm::Sha256
            .digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let payload = serde_json::json!({
        "ac": ac, "holder": pki.cert("signer1").der(), "root": pki.cert("root-aa").der(),
        "pdf": output, "pdf_sha256": digest(&output), "ac_sha256": digest(&ac),
        "certs": material.certs, "ocsps": material.ocsps, "crls": material.crls,
    });
    let mut child =
        std::process::Command::new(support::oracle_python().expect("pinned oracle required"))
            .args([
                "-I",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/oracle/check_native_ac_evidence.py"
                ),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
    std::io::Write::write_all(
        &mut child.stdin.take().unwrap(),
        &serde_json::to_vec(&payload).unwrap(),
    )
    .unwrap();
    let proof = child.wait_with_output().unwrap();
    assert!(
        proof.status.success(),
        "{}",
        String::from_utf8_lossy(&proof.stderr)
    );
    let proof: serde_json::Value = serde_json::from_slice(&proof.stdout).unwrap();
    assert_eq!(proof["approved"], true);
    assert_eq!(proof["empty_roots_approved"], false);
    eprintln!("fresh native-acquired DSS evidence oracle: {proof}");

    let failed_provider = Arc::new(DeferredAaCrls {
        calls: Mutex::new(Vec::new()),
        services: Services::new(&[ARCH], TIME),
    });
    let failed_context = context.with_fetchers(Fetchers {
        crl: Some(failed_provider.clone()),
        ..Default::default()
    });
    let mut rejected = ValidationInfo {
        paths: vec![vec![pki.cert("root")]],
        ..Default::default()
    };
    let before = rejected.paths.clone();
    assert!(validate_and_collect_attribute_certs(
        &failed_context,
        &pki.cert("signer1"),
        &[],
        &[ac, vec![0x30, 0]],
        &mut rejected,
    )
    .is_err());
    assert_eq!(
        failed_provider.calls.lock().unwrap().len(),
        4,
        "first AC actually validated"
    );
    assert_eq!(rejected.paths, before);
    assert!(
        rejected.crls.is_empty() && rejected.ocsps.is_empty(),
        "batch failure must not publish earlier downloads"
    );
}

fn ac_file(name: &str) -> Vec<u8> {
    std::fs::read(support::data_path(&["lanes", "r3-p", "ac", name])).unwrap()
}

#[derive(Debug)]
struct AcFetcher {
    case: &'static str,
    pkc: Arc<Services>,
    ocsp_calls: Mutex<Vec<(Vec<u8>, Cert)>>,
    crl_calls: Mutex<Vec<Vec<u8>>>,
    pkc_ocsp_calls: Mutex<Vec<Cert>>,
    pkc_crl_calls: Mutex<Vec<Cert>>,
}

impl AcFetcher {
    fn new(case: &'static str) -> Arc<Self> {
        Arc::new(Self {
            case,
            pkc: Services::new(&[ARCH], TIME),
            ocsp_calls: Mutex::new(Vec::new()),
            crl_calls: Mutex::new(Vec::new()),
            pkc_ocsp_calls: Mutex::new(Vec::new()),
            pkc_crl_calls: Mutex::new(Vec::new()),
        })
    }

    fn context(self: &Arc<Self>) -> ValidationContext {
        self.context_with_mode("require")
    }

    fn context_with_mode(self: &Arc<Self>, mode: &str) -> ValidationContext {
        let pki = support::pki(ARCH);
        ValidationContext::builder()
            .trust_root(pki.cert("root-aa"))
            .other_cert(pki.cert("interm-aa"))
            .other_cert(pki.cert("leaf-aa"))
            .moment(support::at(TIME))
            .revocation_mode(mode)
            .fetchers(Fetchers {
                ocsp: Some(self.clone()),
                crl: Some(self.clone()),
                cert: None,
            })
            .build()
            .unwrap()
    }
}

impl OcspFetcher for AcFetcher {
    fn fetch_ocsp(&self, cert: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        self.pkc_ocsp_calls.lock().unwrap().push(cert.clone());
        self.pkc.fetch_ocsp(cert, issuer)
    }

    fn fetch_ac_ocsp(&self, ac_der: &[u8], issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        self.ocsp_calls
            .lock()
            .unwrap()
            .push((ac_der.to_vec(), issuer.clone()));
        match self.case {
            "good_ocsp" => Ok(ac_file("ocsp-alice-role-with-rev.der")),
            "malformed_ocsp" => Ok(b"invalid DER OCSP response".to_vec()),
            "tampered_ocsp" => {
                let mut response =
                    x509_ocsp::OcspResponse::from_der(&ac_file("ocsp-alice-role-with-rev.der"))
                        .unwrap();
                let payload = response.response_bytes.as_mut().unwrap();
                let mut basic =
                    x509_ocsp::BasicOcspResponse::from_der(payload.response.as_bytes()).unwrap();
                let mut signature = basic.signature.as_bytes().unwrap().to_vec();
                signature[0] ^= 1;
                basic.signature = der::asn1::BitString::from_bytes(&signature).unwrap();
                payload.response = der::asn1::OctetString::new(basic.to_der().unwrap()).unwrap();
                Ok(response.to_der().unwrap())
            }
            "wrong_target_ocsp" => Ok(std::fs::read(support::data_path(&[
                "lanes",
                "d",
                "revinfo",
                ARCH,
                "2020-11-01",
                "ocsp-signer1.der",
            ]))
            .unwrap()),
            _ => Err(FetchError::new(
                FetchErrorKind::NotFound,
                "No AC OCSP response",
            )),
        }
    }
}

impl CrlFetcher for AcFetcher {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        self.pkc_crl_calls.lock().unwrap().push(cert.clone());
        self.pkc.fetch_crls(cert)
    }

    fn fetch_ac_crls(&self, ac_der: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        self.crl_calls.lock().unwrap().push(ac_der.to_vec());
        if matches!(
            self.case,
            "transport_crl_fallback" | "mixed_crl_batch" | "bad_signature_crl"
        ) {
            let good = std::fs::read(support::data_path(&[
                "lanes",
                "d",
                "revinfo",
                ARCH,
                "2020-11-01",
                "crl-leaf-aa.der",
            ]))
            .unwrap();
            if self.case == "bad_signature_crl" {
                let mut crl: x509_cert::crl::CertificateList =
                    x509_cert::crl::CertificateList::from_der(&good).unwrap();
                let mut signature = crl.signature.as_bytes().unwrap().to_vec();
                signature[0] ^= 1;
                crl.signature = der::asn1::BitString::from_bytes(&signature).unwrap();
                Ok(vec![crl.to_der().unwrap()])
            } else if self.case == "mixed_crl_batch" {
                Ok(vec![
                    good,
                    std::fs::read(support::data_path(&[
                        "lanes",
                        "d",
                        "revinfo",
                        ARCH,
                        "2020-11-01",
                        "crl-root.der",
                    ]))
                    .unwrap(),
                ])
            } else {
                Ok(vec![good])
            }
        } else {
            Err(FetchError::new(FetchErrorKind::NotFound, "No AC CRL"))
        }
    }
}

fn fresh_oracle() -> &'static serde_json::Value {
    static RESULT: OnceLock<serde_json::Value> = OnceLock::new();
    RESULT.get_or_init(|| oracle_for_mode("require"))
}

/// Reuse one configured handle while changing its backend between operations.
/// Cloning the selected backend before delegation keeps callbacks outside locks.
#[derive(Debug)]
struct ReusedAcProvider(Mutex<Arc<AcFetcher>>);

impl OcspFetcher for ReusedAcProvider {
    fn fetch_ocsp(&self, cert: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        let backend = self.0.lock().unwrap().clone();
        backend.fetch_ocsp(cert, issuer)
    }

    fn fetch_ac_ocsp(&self, ac: &[u8], issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        let backend = self.0.lock().unwrap().clone();
        backend.fetch_ac_ocsp(ac, issuer)
    }
}

impl CrlFetcher for ReusedAcProvider {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        let backend = self.0.lock().unwrap().clone();
        backend.fetch_crls(cert)
    }

    fn fetch_ac_crls(&self, ac: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        let backend = self.0.lock().unwrap().clone();
        backend.fetch_ac_crls(ac)
    }
}

#[test]
fn shared_provider_reuse_does_not_leak_evidence_or_suppress_later_operations() {
    let pki = support::pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    let initial = AcFetcher::new("good_ocsp");
    let provider = Arc::new(ReusedAcProvider(Mutex::new(initial.clone())));
    let context = initial.context().with_fetchers(Fetchers {
        ocsp: Some(provider.clone()),
        crl: Some(provider.clone()),
        cert: None,
    });
    assert_eq!(context.ocsps().count(), 0);
    assert_eq!(context.crls().count(), 0);

    let mut snapshots = Vec::new();
    for case in [
        "good_ocsp",
        "transport_crl_fallback",
        "missing_all",
        "good_ocsp",
    ] {
        let backend = AcFetcher::new(case);
        *provider.0.lock().unwrap() = backend.clone();
        let sentinel = vec![pki.cert("root")];
        let mut info = ValidationInfo {
            paths: vec![sentinel.clone()],
            ..Default::default()
        };
        let result = validate_and_collect_attribute_certs(
            &context,
            &pki.cert("signer1"),
            &[],
            std::slice::from_ref(&ac),
            &mut info,
        );
        assert_target(&backend, &ac);
        assert_eq!(backend.ocsp_calls.lock().unwrap().len(), 1, "{case}");
        assert_eq!(
            backend.crl_calls.lock().unwrap().len(),
            usize::from(case != "good_ocsp"),
            "{case}"
        );
        let accepted = result.is_ok();
        assert_eq!(accepted, case != "missing_all", "{case}: {result:?}");
        assert_eq!(fresh_oracle()[case]["accepted"], accepted);
        if let Ok(results) = result {
            assert_eq!(results.len(), 1);
            assert!(results[0].approved_attributes.contains_key("role"));
            assert_eq!(info.paths.len(), 2);
            assert_eq!(info.paths[0], sentinel);
            if case == "good_ocsp" {
                assert_eq!(info.ocsps, [ac_file("ocsp-alice-role-with-rev.der")]);
                assert_eq!(info.crls.len(), 2);
            } else {
                assert!(info.ocsps.is_empty(), "previous operation's OCSP leaked");
                assert_eq!(info.crls.len(), 3);
            }
            snapshots.push(info);
        } else {
            assert_eq!(info.paths, [sentinel]);
            assert!(info.ocsps.is_empty());
            assert!(info.crls.is_empty());
        }
        assert_eq!(context.ocsps().count(), 0);
        assert_eq!(context.crls().count(), 0);
    }
    // The intervening CRL/failure operations do not contaminate a new OCSP
    // result, and the first published value stays independent of later calls.
    assert_eq!(snapshots[0].paths, snapshots[2].paths);
    assert_eq!(snapshots[0].ocsps, snapshots[2].ocsps);
    assert_eq!(snapshots[0].crls, snapshots[2].crls);
    assert_eq!(initial.ocsp_calls.lock().unwrap().len(), 0);
    assert_eq!(initial.crl_calls.lock().unwrap().len(), 0);
}

fn oracle_for_mode(mode: &str) -> serde_json::Value {
    let output = std::process::Command::new(
        support::oracle_python().expect("the fresh pinned AC fetch oracle is required"),
    )
    .arg("-I")
    .arg(support::data_path(&[
        "lanes",
        "r3-p",
        "ac",
        "ac_fetch_assertions.py",
    ]))
    .arg(support::data_path(&[]))
    .arg(mode)
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decisions = serde_json::from_slice(&output.stdout).unwrap();
    eprintln!("fresh AC fetch oracle: {decisions}");
    decisions
}

fn assert_target(fetcher: &AcFetcher, ac: &[u8]) {
    let requests = fetcher.ocsp_calls.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "the real AC OCSP method must be called once"
    );
    assert_eq!(requests[0].0, ac);
    assert!(
        requests[0].1 == support::pki(ARCH).cert("leaf-aa"),
        "the issuer is the AA, never the signing holder"
    );
    assert!(fetcher
        .crl_calls
        .lock()
        .unwrap()
        .iter()
        .all(|request| request == ac));
}

#[test]
fn ac_presign_fetches_real_target_ocsp_and_falls_back_to_ac_crls() {
    let pki = support::pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    for case in ["good_ocsp", "transport_crl_fallback", "mixed_crl_batch"] {
        let fetcher = AcFetcher::new(case);
        let context = fetcher.context();
        assert_eq!(context.ocsps().count(), 0, "no AC evidence is preloaded");
        let mut info = ValidationInfo::default();
        let results = validate_and_collect_attribute_certs(
            &context,
            &pki.cert("signer1"),
            &[],
            std::slice::from_ref(&ac),
            &mut info,
        )
        .expect("mandatory AC evidence must be retrieved through the configured AC fetcher");
        assert_target(&fetcher, &ac);
        assert_eq!(results.len(), 1);
        assert!(results[0].approved_attributes.contains_key("role"));
        assert_eq!(
            info.paths,
            [vec![
                pki.cert("leaf-aa"),
                pki.cert("interm-aa"),
                pki.cert("root-aa")
            ]]
        );
        if case == "good_ocsp" {
            assert_eq!(info.ocsps, [ac_file("ocsp-alice-role-with-rev.der")]);
            assert_eq!(info.crls.len(), 2);
            assert!(fetcher.crl_calls.lock().unwrap().is_empty());
        } else {
            assert!(info.ocsps.is_empty());
            assert_eq!(
                info.crls.len(),
                if case == "mixed_crl_batch" { 4 } else { 3 }
            );
            assert_eq!(fetcher.crl_calls.lock().unwrap().len(), 1);
        }
        assert_eq!(fresh_oracle()[case]["accepted"], true);
        assert_eq!(fresh_oracle()[case]["ac_ocsp_calls"], 1);
    }
}

#[test]
fn ac_presign_rejects_unusable_fetched_evidence_without_publishing_it() {
    let pki = support::pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    for case in [
        "malformed_ocsp",
        "wrong_target_ocsp",
        "tampered_ocsp",
        "bad_signature_crl",
        "missing_all",
    ] {
        let fetcher = AcFetcher::new(case);
        let mut info = ValidationInfo {
            paths: vec![vec![pki.cert("root")]],
            ..Default::default()
        };
        let before = info.paths.clone();
        let error = validate_and_collect_attribute_certs(
            &fetcher.context(),
            &pki.cert("signer1"),
            &[],
            std::slice::from_ref(&ac),
            &mut info,
        )
        .unwrap_err();
        assert_target(&fetcher, &ac);
        assert!(matches!(error, HankoError::Signing(_)), "{error}");
        assert!(
            error
                .to_string()
                .contains("attribute certificate could not be validated"),
            "{error}"
        );
        if case == "bad_signature_crl" {
            assert!(
                error
                    .to_string()
                    .contains("CRL signature could not be verified"),
                "{error}"
            );
        }
        assert_eq!(info.paths, before);
        assert!(info.ocsps.is_empty());
        assert!(info.crls.is_empty());
        assert_eq!(fresh_oracle()[case]["accepted"], false);
        assert_eq!(
            fetcher.crl_calls.lock().unwrap().len(),
            usize::try_from(fresh_oracle()[case]["ac_crl_calls"].as_u64().unwrap()).unwrap(),
        );
    }
}

#[test]
fn ac_fetching_can_use_an_explicitly_anchored_attribute_authority() {
    let pki = support::pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    let fetcher = AcFetcher::new("good_ocsp");
    let context = ValidationContext::builder()
        .trust_root(pki.cert("leaf-aa"))
        .moment(support::at(TIME))
        .revocation_mode("require")
        .fetchers(Fetchers {
            ocsp: Some(fetcher.clone()),
            crl: Some(fetcher.clone()),
            cert: None,
        })
        .build()
        .unwrap();
    let mut info = ValidationInfo::default();
    let results = validate_and_collect_attribute_certs(
        &context,
        &pki.cert("signer1"),
        &[],
        std::slice::from_ref(&ac),
        &mut info,
    )
    .expect("an explicitly trusted AA is the AC issuer even without an AA path leaf");
    assert_target(&fetcher, &ac);
    assert_eq!(results.len(), 1);
    assert!(results[0].approved_attributes.contains_key("role"));
    assert!(results[0].aa_path.trust_anchor().cert() == &pki.cert("leaf-aa"));
    let validated_path: Vec<Cert> = results[0]
        .aa_path
        .certs()
        .into_iter()
        .rev()
        .cloned()
        .collect();
    assert_eq!(info.paths, [validated_path]);
    assert!(info.paths[0]
        .iter()
        .all(|cert| cert == &pki.cert("leaf-aa")));
    assert_eq!(info.ocsps, [ac_file("ocsp-alice-role-with-rev.der")]);
}

#[test]
fn ac_assertion_exemption_uses_whole_der_and_exact_validation_time() {
    use sigis_pki_certvalidator::policy::NonRevokedStatusAssertion;
    use sigis_pki_core::algorithms::DigestAlgorithm;
    use std::time::Duration;

    let pki = support::pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    let parsed = sigis_pki_certvalidator::ac::AttrCert::from_der(&ac).unwrap();
    let digest =
        |bytes: &[u8]| -> [u8; 32] { DigestAlgorithm::Sha256.digest(bytes).try_into().unwrap() };
    let time = support::at(TIME);
    for (label, hash, asserted_at, exempts) in [
        ("equal-time", digest(&ac), time, true),
        (
            "future-time",
            digest(&ac),
            time.plus(Duration::from_secs(1)),
            true,
        ),
        (
            "one-second-stale-despite-clock-tolerance",
            digest(&ac),
            time.minus(Duration::from_secs(1)),
            false,
        ),
        (
            "signed-info-is-not-whole-ac",
            digest(&parsed.info_der),
            time,
            false,
        ),
        (
            "holder-is-not-ac",
            digest(pki.cert("signer1").der()),
            time,
            false,
        ),
        (
            "aa-is-not-ac",
            digest(pki.cert("leaf-aa").der()),
            time,
            false,
        ),
        ("wrong-digest", [0; 32], time, false),
    ] {
        let fetcher = AcFetcher::new("good_ocsp");
        let context = ValidationContext::builder()
            .trust_root(pki.cert("root-aa"))
            .other_cert(pki.cert("interm-aa"))
            .other_cert(pki.cert("leaf-aa"))
            .moment(time)
            .revocation_mode("require")
            .assertion(NonRevokedStatusAssertion {
                cert_sha256: hash,
                at: asserted_at,
            })
            .fetchers(Fetchers {
                ocsp: Some(fetcher.clone()),
                crl: Some(fetcher.clone()),
                cert: None,
            })
            .build()
            .unwrap();
        let mut info = ValidationInfo::default();
        let results = validate_and_collect_attribute_certs(
            &context,
            &pki.cert("signer1"),
            &[],
            std::slice::from_ref(&ac),
            &mut info,
        )
        .unwrap();
        assert!(
            results[0].approved_attributes.contains_key("role"),
            "{label}"
        );
        assert!(fetcher.crl_calls.lock().unwrap().is_empty(), "{label}");
        if exempts {
            assert!(fetcher.ocsp_calls.lock().unwrap().is_empty(), "{label}");
            assert!(info.ocsps.is_empty(), "{label}");
        } else {
            assert_target(&fetcher, &ac);
            assert_eq!(
                info.ocsps,
                [ac_file("ocsp-alice-role-with-rev.der")],
                "{label}"
            );
        }
        assert_eq!(context.timing().validation_time, time);
        assert_eq!(context.ocsps().count(), 0, "{label}");

        // With unavailable evidence, only an exact active assertion may
        // settle the status; a stale or different digest cannot bypass require.
        let missing = AcFetcher::new("missing_all");
        let no_evidence = context.with_fetchers(Fetchers {
            ocsp: Some(missing.clone()),
            crl: Some(missing.clone()),
            cert: None,
        });
        let mut info = ValidationInfo::default();
        let result = validate_and_collect_attribute_certs(
            &no_evidence,
            &pki.cert("signer1"),
            &[],
            std::slice::from_ref(&ac),
            &mut info,
        );
        if exempts {
            assert!(result.unwrap()[0].approved_attributes.contains_key("role"));
            assert!(missing.ocsp_calls.lock().unwrap().is_empty(), "{label}");
            assert!(missing.crl_calls.lock().unwrap().is_empty(), "{label}");
        } else {
            assert!(matches!(result, Err(HankoError::Signing(_))), "{label}");
            assert_target(&missing, &ac);
            assert_eq!(missing.crl_calls.lock().unwrap().len(), 1, "{label}");
            assert!(info.paths.is_empty(), "{label}");
            assert!(info.ocsps.is_empty(), "{label}");
            assert!(info.crls.is_empty(), "{label}");
        }
    }
}

#[test]
fn successful_ac_validation_preserves_caller_assertions_without_fetching() {
    use sigis_pki_certvalidator::policy::NonRevokedStatusAssertion;
    use sigis_pki_core::algorithms::DigestAlgorithm;

    let pki = support::pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    for mode in ["require", "soft-fail"] {
        let fetcher = AcFetcher::new("good_ocsp");
        let context = ValidationContext::builder()
            .trust_root(pki.cert("root-aa"))
            .other_cert(pki.cert("interm-aa"))
            .other_cert(pki.cert("leaf-aa"))
            .moment(support::at(TIME))
            .revocation_mode(mode)
            .assertion(NonRevokedStatusAssertion {
                cert_sha256: DigestAlgorithm::Sha256.digest(&ac).try_into().unwrap(),
                at: support::at(TIME),
            })
            .fetchers(Fetchers {
                ocsp: Some(fetcher.clone()),
                crl: Some(fetcher.clone()),
                cert: None,
            })
            .build()
            .unwrap();
        let mut info = ValidationInfo::default();
        let results = validate_and_collect_attribute_certs(
            &context,
            &pki.cert("signer1"),
            &[],
            std::slice::from_ref(&ac),
            &mut info,
        )
        .unwrap();
        assert!(results[0].approved_attributes.contains_key("role"));
        assert!(
            fetcher.ocsp_calls.lock().unwrap().is_empty(),
            "a successful caller assertion must not contact AC retrieval"
        );
        assert!(fetcher.crl_calls.lock().unwrap().is_empty());
        assert!(info.ocsps.is_empty());
    }
}

#[test]
fn no_check_ac_presign_does_not_fetch_or_publish_revocation_evidence() {
    let pki = support::pki(ARCH);
    let fetcher = AcFetcher::new("good_ocsp");
    let mut info = ValidationInfo::default();
    let results = validate_and_collect_attribute_certs(
        &fetcher.context_with_mode("none"),
        &pki.cert("signer1"),
        &[],
        &[ac_file("alice-role-with-rev.der")],
        &mut info,
    )
    .unwrap();
    assert!(results[0].approved_attributes.contains_key("role"));
    assert!(fetcher.ocsp_calls.lock().unwrap().is_empty());
    assert!(fetcher.crl_calls.lock().unwrap().is_empty());
    assert!(fetcher.pkc_ocsp_calls.lock().unwrap().is_empty());
    assert!(fetcher.pkc_crl_calls.lock().unwrap().is_empty());
    assert!(info.ocsps.is_empty());
    assert!(
        info.crls.is_empty(),
        "NoCheck must not publish unused PKC revinfo either"
    );
    let oracle = oracle_for_mode("none");
    assert_eq!(oracle["good_ocsp"]["accepted"], true);
    for case in oracle.as_object().unwrap().values() {
        for key in [
            "ac_ocsp_calls",
            "ac_crl_calls",
            "pkc_ocsp_calls",
            "pkc_crl_calls",
        ] {
            assert_eq!(case[key], 0, "{key}: {case}");
        }
    }
}

#[test]
fn revinfo_acquisition_honours_no_check_at_each_path_position() {
    use sigis_pki_certvalidator::policy::{
        CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule,
    };
    use RevocationCheckingRule::{CheckIfDeclaredSoft, NoCheck};

    let pki = support::pki(ARCH);
    let path = [pki.cert("signer1"), pki.cert("interm"), pki.cert("root")];
    for (ee, ca, leaf_requests, ca_requests) in [
        (NoCheck, NoCheck, 0, 0),
        (NoCheck, CheckIfDeclaredSoft, 0, 1),
        (CheckIfDeclaredSoft, NoCheck, 1, 0),
        (CheckIfDeclaredSoft, CheckIfDeclaredSoft, 1, 1),
    ] {
        let fetcher = AcFetcher::new("good_ocsp");
        let context = ValidationContext::builder()
            .trust_root(path[2].clone())
            .other_cert(path[1].clone())
            .moment(support::at(TIME))
            .revinfo_policy(CertRevTrustPolicy::new(RevocationCheckingPolicy {
                ee_certificate_rule: ee,
                intermediate_ca_cert_rule: ca,
            }))
            .fetchers(Fetchers {
                ocsp: Some(fetcher.clone()),
                crl: Some(fetcher.clone()),
                cert: None,
            })
            .build()
            .unwrap();
        let mut info = ValidationInfo::default();
        sigis_pades_sign::ltv::fetch_revinfo(&context, &path, &mut info);
        let requested = fetcher.pkc_ocsp_calls.lock().unwrap();
        assert_eq!(requested.len(), leaf_requests);
        assert!(requested.iter().all(|cert| cert == &path[0]));
        let requested = fetcher.pkc_crl_calls.lock().unwrap();
        assert_eq!(requested.len(), ca_requests);
        assert!(requested.iter().all(|cert| cert == &path[1]));
        assert_eq!(info.ocsps.len(), leaf_requests);
        assert_eq!(info.crls.len(), ca_requests);
        let offline = sigis_pades_sign::ltv::extended_context(&context, &path, &info)
            .unwrap()
            .with_fetchers(Fetchers::default());
        let validated =
            sigis_pki_certvalidator::CertificateValidator::new(&offline, path[0].clone())
                .validate()
                .unwrap();
        assert_eq!(validated.certs().len(), 3);
    }
}

fn signed_issuer_form(form: &str) -> Vec<u8> {
    use sigis_pki_core::algorithms::{
        validate_signature, DigestAlgorithm, SignatureValidationContext,
    };
    use sigis_pki_core::asn1::tlv::{encode, Tlv};
    use sigis_pki_core::sign::KeySigner;

    let pki = support::pki(ARCH);
    let original = ac_file("alice-role-with-rev.der");
    let original = Tlv::parse_exact(&original).unwrap();
    let envelope = original.children().unwrap();
    let fields = envelope[0].children().unwrap();
    let aa = pki.cert("leaf-aa");
    let names = fields[2].children().unwrap()[0].raw.to_vec();
    let base = encode(
        0xa0,
        &[
            encode(0x30, &encode(0xa4, &aa.issuer().to_der().unwrap())),
            encode(0x02, aa.serial_bytes()),
        ]
        .concat(),
    );
    let issuer = match form {
        "v1_name" => names,
        "v2_name" => fields[2].raw.to_vec(),
        "v2_name_and_base" => encode(0xa0, &[names, base].concat()),
        "base_only" => encode(0xa0, &base),
        "dns_only" => encode(0xa0, &encode(0x30, &encode(0x82, b"aa.example.invalid"))),
        _ => panic!("unknown issuer form"),
    };
    let body = fields
        .iter()
        .enumerate()
        .flat_map(|(i, field)| {
            if i == 2 {
                issuer.clone()
            } else {
                field.raw.to_vec()
            }
        })
        .collect::<Vec<_>>();
    let info = encode(0x30, &body);
    let signer = pki.signer("leaf-aa");
    let algorithm = KeySigner::signature_algorithm(&signer, DigestAlgorithm::Sha256).unwrap();
    assert_eq!(algorithm.to_der().unwrap(), envelope[1].raw);
    let signature = KeySigner::sign_raw(&signer, &info, DigestAlgorithm::Sha256).unwrap();
    validate_signature(
        &signature,
        &info,
        &aa.public_key(),
        &algorithm,
        &SignatureValidationContext::default(),
    )
    .unwrap();
    encode(
        0x30,
        &[
            info,
            envelope[1].raw.to_vec(),
            der::asn1::BitString::from_bytes(&signature)
                .unwrap()
                .to_der()
                .unwrap(),
        ]
        .concat(),
    )
}

#[test]
fn ac_collection_requires_actual_issuer_directory_name_before_provider_io() {
    let pki = support::pki(ARCH);
    let mut cases = Vec::new();
    for (form, accepted) in [
        ("v1_name", true),
        ("v2_name", true),
        ("v2_name_and_base", true),
        ("base_only", false),
        ("dns_only", false),
    ] {
        let der = signed_issuer_form(form);
        let parsed = sigis_pki_certvalidator::ac::AttrCert::from_der(&der).unwrap();
        if form == "base_only" {
            assert!(parsed.issuer.names.is_none());
            let encoded_parent = parsed
                .issuer
                .base_certificate_id
                .as_ref()
                .unwrap()
                .issuer
                .iter()
                .find_map(|name| match name {
                    x509_cert::ext::pkix::name::GeneralName::DirectoryName(name) => Some(name),
                    _ => None,
                });
            assert_eq!(encoded_parent, Some(pki.cert("leaf-aa").issuer()));
            assert_ne!(encoded_parent, Some(pki.cert("leaf-aa").subject()));
        }
        let fetcher = AcFetcher::new("good_ocsp");
        let mut info = ValidationInfo {
            paths: vec![vec![pki.cert("root")]],
            ..Default::default()
        };
        let before = info.paths.clone();
        let result = validate_and_collect_attribute_certs(
            &fetcher.context(),
            &pki.cert("signer1"),
            &[],
            std::slice::from_ref(&der),
            &mut info,
        );
        if accepted {
            let result = result.unwrap();
            assert!(result[0].approved_attributes.contains_key("role"));
            assert_target(&fetcher, &der);
            assert_eq!(info.ocsps, [ac_file("ocsp-alice-role-with-rev.der")]);
        } else {
            assert!(fetcher.pkc_ocsp_calls.lock().unwrap().is_empty(), "{form}");
            assert!(fetcher.pkc_crl_calls.lock().unwrap().is_empty(), "{form}");
            assert!(fetcher.ocsp_calls.lock().unwrap().is_empty(), "{form}");
            assert!(fetcher.crl_calls.lock().unwrap().is_empty(), "{form}");
            let error = result.unwrap_err();
            assert!(matches!(error, HankoError::Signing(_)), "{error}");
            assert!(
                error.to_string().contains("issuer directoryName"),
                "{error}"
            );
            assert_eq!(info.paths, before);
            assert!(info.ocsps.is_empty() && info.crls.is_empty());
        }
        cases.push(serde_json::json!({"form": form, "accepted": accepted, "ac_der": der}));
    }
    let manifest = serde_json::json!({"aa_der": pki.cert("leaf-aa").der(), "cases": cases});
    let path = support::temp_file(
        "ac-issuer-forms.json",
        &serde_json::to_vec(&manifest).unwrap(),
    );
    let result = support::oracle("check_ac_collection_issuer.py", &[support::path_str(&path)])
        .expect("fresh pinned issuer identity and actual-AA signature checks are required");
    assert_eq!(result["cases"].as_array().unwrap().len(), 5);
    eprintln!("fresh AC collection issuer oracle: {result}");
    std::fs::remove_file(path).unwrap();
}

#[derive(Debug, Default)]
struct LegacyPkcOnly {
    ocsp_calls: std::sync::atomic::AtomicUsize,
    crl_calls: std::sync::atomic::AtomicUsize,
}

impl OcspFetcher for LegacyPkcOnly {
    fn fetch_ocsp(&self, _cert: &Cert, _issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        self.ocsp_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(ac_file("ocsp-alice-role-with-rev.der"))
    }
}

impl CrlFetcher for LegacyPkcOnly {
    fn fetch_crls(&self, _cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        self.crl_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(vec![std::fs::read(support::data_path(&[
            "lanes",
            "d",
            "revinfo",
            ARCH,
            "2020-11-01",
            "crl-leaf-aa.der",
        ]))
        .unwrap()])
    }
}

#[test]
fn legacy_pkc_only_fetchers_cannot_satisfy_mandatory_ac_collection() {
    use std::sync::atomic::Ordering;

    let pki = support::pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    let fetcher = Arc::new(LegacyPkcOnly::default());
    assert_eq!(
        fetcher
            .fetch_ac_ocsp(&ac, &pki.cert("leaf-aa"))
            .unwrap_err()
            .kind,
        FetchErrorKind::NotFound
    );
    assert_eq!(
        fetcher.fetch_ac_crls(&ac).unwrap_err().kind,
        FetchErrorKind::NotFound
    );
    let context = ValidationContext::builder()
        .trust_root(pki.cert("leaf-aa"))
        .moment(support::at(TIME))
        .revocation_mode("require")
        .fetchers(Fetchers {
            ocsp: Some(fetcher.clone()),
            crl: Some(fetcher.clone()),
            cert: None,
        })
        .build()
        .unwrap();
    let mut info = ValidationInfo::default();
    let error =
        validate_and_collect_attribute_certs(&context, &pki.cert("signer1"), &[], &[ac], &mut info)
            .unwrap_err();
    assert!(matches!(error, HankoError::Signing(_)), "{error}");
    assert!(
        error.to_string().contains("revocation information"),
        "{error}"
    );
    assert_eq!(fetcher.ocsp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fetcher.crl_calls.load(Ordering::SeqCst), 0);
    assert!(info.paths.is_empty() && info.ocsps.is_empty() && info.crls.is_empty());
}

fn soft_fail_collects_ac_evidence(case: &'static str) {
    let pki = support::pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    let fetcher = AcFetcher::new(case);
    let mut info = ValidationInfo::default();
    let results = validate_and_collect_attribute_certs(
        &fetcher.context_with_mode("soft-fail"),
        &pki.cert("signer1"),
        &[],
        std::slice::from_ref(&ac),
        &mut info,
    )
    .unwrap();
    assert!(results[0].approved_attributes.contains_key("role"));
    assert_target(&fetcher, &ac);
    if case == "good_ocsp" {
        assert_eq!(info.ocsps, [ac_file("ocsp-alice-role-with-rev.der")]);
        assert!(fetcher.crl_calls.lock().unwrap().is_empty());
    } else {
        let crl = std::fs::read(support::data_path(&[
            "lanes",
            "d",
            "revinfo",
            ARCH,
            "2020-11-01",
            "crl-leaf-aa.der",
        ]))
        .unwrap();
        assert!(info.crls.contains(&crl));
        assert_eq!(fetcher.crl_calls.lock().unwrap().len(), 1);
    }
}

#[test]
fn soft_fail_ac_presign_fetches_ocsp_before_publishing_success() {
    soft_fail_collects_ac_evidence("good_ocsp");
}

#[test]
fn soft_fail_ac_presign_fetches_crl_after_ocsp_transport_failure() {
    soft_fail_collects_ac_evidence("transport_crl_fallback");
}

#[test]
fn soft_fail_ac_presign_collects_applicable_crl_in_mixed_batch() {
    soft_fail_collects_ac_evidence("mixed_crl_batch");
}

#[test]
fn soft_fail_raw_outcomes_do_not_authenticate_evidence_or_poison_the_next_ac() {
    let pki = support::pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    let oracle = oracle_for_mode("soft-fail");
    for case in [
        "good_ocsp",
        "transport_crl_fallback",
        "mixed_crl_batch",
        "malformed_ocsp",
        "wrong_target_ocsp",
        "tampered_ocsp",
        "bad_signature_crl",
        "missing_all",
    ] {
        let fetcher = AcFetcher::new(case);
        let context = fetcher.context_with_mode("soft-fail");
        let mut info = ValidationInfo::default();
        let result = validate_and_collect_attribute_certs(
            &context,
            &pki.cert("signer1"),
            &[],
            &[ac.clone(), ac.clone()],
            &mut info,
        );
        assert_eq!(
            result.is_ok(),
            oracle[case]["accepted"].as_bool().unwrap(),
            "{case}: {result:?}"
        );
        let result = result.unwrap();
        assert_eq!(result.len(), 2);
        assert!(result
            .iter()
            .all(|r| r.approved_attributes.contains_key("role")));
        let requests = fetcher.ocsp_calls.lock().unwrap();
        assert_eq!(requests.len(), 2, "{case}: one call per actual AC check");
        for (actual_ac, actual_aa) in requests.iter() {
            assert_eq!(actual_ac, &ac);
            assert_eq!(actual_aa, &pki.cert("leaf-aa"));
        }
        assert_eq!(
            u64::try_from(fetcher.crl_calls.lock().unwrap().len()).unwrap(),
            2 * oracle[case]["ac_crl_calls"].as_u64().unwrap(),
            "{case}"
        );
        if case == "malformed_ocsp" {
            assert_eq!(info.ocsps, [b"invalid DER OCSP response".to_vec()]);
        } else if matches!(case, "bad_signature_crl" | "missing_all") {
            assert!(info.ocsps.is_empty(), "{case}");
        } else {
            // A returned blob is retained as raw transport output. Its
            // presence is not a successful standalone evidence validation.
            assert_eq!(
                info.ocsps.len(),
                usize::from(case != "transport_crl_fallback" && case != "mixed_crl_batch"),
                "{case}"
            );
        }
        assert_eq!(info.paths.len(), 1);
        assert_eq!(context.ocsps().count(), 0);
        assert_eq!(context.crls().count(), 0);
    }
}

#[test]
fn pdf_signing_embeds_ac_evidence_from_the_configured_ac_fetcher() {
    use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
    use sigis_pades_sign::{CadesSignedAttrSpec, PdfSignatureMetadata, PdfSigner, SignerAttrSpec};

    let pki = support::pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    let fetcher = AcFetcher::new("good_ocsp");
    let mut metadata = PdfSignatureMetadata::new("FetchedAcEvidence");
    metadata.validation_context = Some(Arc::new(support::services::live_testing_vc(
        ARCH,
        TIME,
        &[],
    )));
    metadata.ac_validation_context = Some(Arc::new(fetcher.context()));
    metadata.embed_validation_info = true;
    metadata.dss_settings = DssContentSettings {
        include_vri: false,
        placement: SigDssPlacement::TogetherWithSignature,
        ..Default::default()
    };
    metadata.cades_signed_attr_spec = Some(CadesSignedAttrSpec {
        signer_attributes: Some(SignerAttrSpec {
            claimed_attrs: Vec::new(),
            certified_attrs: vec![ac.clone()],
        }),
        ..Default::default()
    });
    let output = PdfSigner::new(metadata, Arc::new(pki.signer("signer1")))
        .at(support::at(TIME))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .expect("actual presign validation must fetch mandatory AC evidence");
    assert_target(&fetcher, &ac);
    let signatures = support::pdfcheck::embedded_signatures(&output);
    assert_eq!(signatures.len(), 1);
    support::pdfcheck::check_integrity(&output, &signatures[0]);
    let (certs, ocsps, crls, _) = support::pdfcheck::dss_counts(&output).unwrap();
    assert_eq!((certs, ocsps, crls), (7, 2, 3));
    let path = support::temp_file("ac-fetched-evidence.pdf", &output);
    let oracle = std::process::Command::new(
        support::oracle_python().expect("the fresh same-output oracle is required"),
    )
    .arg("-I")
    .arg(support::data_path(&[
        "lanes",
        "r3-p",
        "ac",
        "ac_issuer_assertions.py",
    ]))
    .arg(support::data_path(&[]))
    .arg(&path)
    .output()
    .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let decisions: serde_json::Value = serde_json::from_slice(&oracle.stdout).unwrap();
    assert_eq!(decisions["pdf_trusted"]["certified_attributes_valid"], true);
    assert_eq!(
        decisions["pdf_no_aa_root"]["certified_attributes_valid"],
        false
    );
    eprintln!("fresh fetched-evidence PDF oracle: {decisions}");
    let _ = std::fs::remove_file(path);
}
