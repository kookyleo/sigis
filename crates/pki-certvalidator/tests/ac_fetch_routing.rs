//! Supplemental AC transport routing controls; no upstream-function credit.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::moment;
use der::{Decode, Encode};
use sigis_pki_certvalidator::ac::{validate_ac, verify_ac_crl, verify_ac_ocsp, AttrCert};
use sigis_pki_certvalidator::{Cert, TrustAnchor, ValidationContext, ValidationPath};
use sigis_pki_core::errors::{FetchError, FetchErrorKind};
use sigis_pki_core::fetch::{CrlFetcher, Fetchers, OcspFetcher};
use std::io::Write;

fn opened(path: std::path::PathBuf) -> Vec<u8> {
    let path = path.canonicalize().unwrap();
    let data = std::fs::read(&path).unwrap();
    let digest: String = sigis_pki_core::algorithms::DigestAlgorithm::Sha256
        .digest(&data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let receipt = serde_json::json!({"opened_path":path,"sha256":digest,"length":data.len()});
    std::io::stderr()
        .write_all(format!("AC_ROUTING_INPUT {receipt}\n").as_bytes())
        .unwrap();
    data
}

fn input(parts: &[&str]) -> Vec<u8> {
    opened(sigis_testdata::certvalidator(parts))
}

fn aa(parts: &[&str]) -> Vec<u8> {
    let mut path = vec!["attribute-certs", "basic-aa"];
    path.extend_from_slice(parts);
    input(&path)
}

fn cert(parts: &[&str]) -> Cert {
    Cert::from_pem_or_der(&aa(parts)).unwrap()
}

fn authority() -> Cert {
    cert(&["interm", "role-aa.crt"])
}

fn ac() -> Vec<u8> {
    aa(&["aa", "alice-role-with-rev.attr.crt"])
}

fn path() -> ValidationPath {
    ValidationPath::new(
        TrustAnchor::new(cert(&["root", "root.crt"])),
        vec![cert(&["root", "interm-role.crt"])],
        Some(authority()),
    )
}

fn context(fetchers: Fetchers, at: &str) -> ValidationContext {
    ValidationContext::builder()
        .trust_root(cert(&["root", "root.crt"]))
        .other_cert(cert(&["root", "interm-role.crt"]))
        .other_cert(authority())
        .crl(aa(&["root", "root-all-good.crl"]))
        .crl(aa(&["interm", "interm-all-good.crl"]))
        .moment(moment(at))
        .revocation_mode("require")
        .fetchers(fetchers)
        .build()
        .unwrap()
}

#[derive(Debug, Default)]
struct RecordingAcFetcher {
    ocsp_response: Option<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    ac_ocsp: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    ac_crls: Mutex<Vec<Vec<u8>>>,
    pkc_calls: AtomicUsize,
    pkc_targets: Mutex<Vec<Vec<u8>>>,
}

impl OcspFetcher for RecordingAcFetcher {
    fn fetch_ocsp(&self, cert: &Cert, _: &Cert) -> Result<Vec<u8>, FetchError> {
        self.pkc_targets.lock().unwrap().push(cert.der().to_vec());
        self.pkc_calls.fetch_add(1, Ordering::SeqCst);
        Err(FetchError::new(
            FetchErrorKind::NotFound,
            "PKC is not the AC target",
        ))
    }

    fn fetch_ac_ocsp(&self, ac_der: &[u8], issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        self.ac_ocsp
            .lock()
            .unwrap()
            .push((ac_der.to_vec(), issuer.der().to_vec()));
        self.ocsp_response
            .clone()
            .ok_or_else(|| FetchError::new(FetchErrorKind::NotFound, "No attribute OCSP response"))
    }
}

impl CrlFetcher for RecordingAcFetcher {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        self.pkc_targets.lock().unwrap().push(cert.der().to_vec());
        self.pkc_calls.fetch_add(1, Ordering::SeqCst);
        Err(FetchError::new(
            FetchErrorKind::NotFound,
            "PKC is not the AC target",
        ))
    }

    fn fetch_ac_crls(&self, ac_der: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        self.ac_crls.lock().unwrap().push(ac_der.to_vec());
        Ok(self.crls.clone())
    }
}

fn ocsp_set(fetcher: Arc<RecordingAcFetcher>) -> Fetchers {
    Fetchers {
        ocsp: Some(fetcher),
        ..Fetchers::none()
    }
}

fn crl_set(fetcher: Arc<RecordingAcFetcher>) -> Fetchers {
    Fetchers {
        crl: Some(fetcher),
        ..Fetchers::none()
    }
}

#[test]
fn ac_ocsp_routing_uses_exact_der_and_actual_aa_without_pkc_substitution() {
    let fetcher = Arc::new(RecordingAcFetcher {
        ocsp_response: Some(aa(&["alice-all-good.ors"])),
        ..RecordingAcFetcher::default()
    });
    let ac_der = ac();
    let parsed = AttrCert::from_der(&ac_der).unwrap();
    let holder = cert(&["people-ca", "alice.crt"]);
    assert_ne!(parsed.serial.as_slice(), holder.serial_bytes());
    // The historical fixture happens to reuse the AA numeric serial; exact
    // DER routing still prevents substituting that certificate for the AC.
    let ctx = context(ocsp_set(fetcher.clone()), "2019-12-12T00:00:00Z");
    let result =
        validate_ac(&ctx, &ac_der, Some(&holder)).expect("HTTP-independent routing control");
    assert_eq!(result.aa_cert, authority());
    assert!(result.approved_attributes.contains_key("role"));
    assert_eq!(
        *fetcher.ac_ocsp.lock().unwrap(),
        vec![(ac_der, authority().der().to_vec())]
    );
    // The AA's AIA contains caIssuers, not an OCSP responder. Its supplied
    // CRL is sufficient, so every target retrieval here must be AC-specific.
    assert_eq!(fetcher.pkc_calls.load(Ordering::SeqCst), 0);
    assert!(fetcher.pkc_targets.lock().unwrap().is_empty());
}

#[test]
fn ac_crl_routing_fetches_actual_ac_only_after_supplied_evidence_is_incomplete() {
    let fetcher = Arc::new(RecordingAcFetcher {
        crls: vec![aa(&["role-aa-all-good.crl"])],
        ..RecordingAcFetcher::default()
    });
    let ac_der = ac();
    let ctx = context(crl_set(fetcher.clone()), "2019-12-12T00:00:00Z");
    validate_ac(&ctx, &ac_der, None).expect("fetched AC CRL completes mandatory evidence");
    assert_eq!(*fetcher.ac_crls.lock().unwrap(), vec![ac_der.clone()]);
    assert_eq!(fetcher.pkc_calls.load(Ordering::SeqCst), 0);

    let supplied = ValidationContext::builder()
        .trust_root(cert(&["root", "root.crt"]))
        .moment(moment("2019-12-12T00:00:00Z"))
        .crl(aa(&["role-aa-all-good.crl"]))
        .fetchers(crl_set(fetcher.clone()))
        .build()
        .unwrap();
    verify_ac_crl(&supplied, &ac_der, &path()).unwrap();
    assert_eq!(
        fetcher.ac_crls.lock().unwrap().len(),
        1,
        "complete supplied evidence avoids fetching"
    );
}

#[test]
fn fetched_ac_revoked_and_bad_signature_responses_cannot_gain_trust() {
    for (at, response, expected) in [
        (
            "2021-12-12T00:00:00Z",
            aa(&["alice-revoked.ors"]),
            "RevokedError",
        ),
        (
            "2019-12-12T00:00:00Z",
            {
                let mut response =
                    x509_ocsp::OcspResponse::from_der(&aa(&["alice-all-good.ors"])).unwrap();
                let body = response.response_bytes.as_mut().unwrap();
                let mut basic =
                    x509_ocsp::BasicOcspResponse::from_der(body.response.as_bytes()).unwrap();
                // Preserve signed TBS/CertID/status and embedded certificates.
                let mut signature = basic.signature.raw_bytes().to_vec();
                *signature.last_mut().unwrap() ^= 1;
                basic.signature = der::asn1::BitString::from_bytes(&signature).unwrap();
                body.response = der::asn1::OctetString::new(basic.to_der().unwrap()).unwrap();
                response.to_der().unwrap()
            },
            "InsufficientRevinfoError",
        ),
    ] {
        let fetcher = Arc::new(RecordingAcFetcher {
            ocsp_response: Some(response),
            ..RecordingAcFetcher::default()
        });
        let ctx = context(ocsp_set(fetcher.clone()), at);
        let error = verify_ac_ocsp(&ctx, &ac(), &path()).unwrap_err();
        assert!(error.is_instance_of(expected), "{error}");
        assert_eq!(fetcher.ac_ocsp.lock().unwrap().len(), 1);
        assert_eq!(fetcher.pkc_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn fetched_ac_revoked_stale_and_unrelated_crls_cannot_gain_trust() {
    for (at, response, expected) in [
        (
            "2021-12-12T00:00:00Z",
            aa(&["role-aa-some-revoked.crl"]),
            "RevokedError",
        ),
        (
            "2022-05-01T00:00:00Z",
            aa(&["role-aa-all-good.crl"]),
            "InsufficientRevinfoError",
        ),
        (
            "2019-12-12T00:00:00Z",
            aa(&["root", "root-all-good.crl"]),
            "InsufficientRevinfoError",
        ),
    ] {
        let fetcher = Arc::new(RecordingAcFetcher {
            crls: vec![response],
            ..RecordingAcFetcher::default()
        });
        let ctx = context(crl_set(fetcher.clone()), at);
        let error = verify_ac_crl(&ctx, &ac(), &path()).unwrap_err();
        assert!(error.is_instance_of(expected), "{error}");
        assert_eq!(fetcher.ac_crls.lock().unwrap().len(), 1);
        assert_eq!(fetcher.pkc_calls.load(Ordering::SeqCst), 0);
    }
}

#[derive(Debug, Default)]
struct LegacyFetcher(AtomicUsize);

impl OcspFetcher for LegacyFetcher {
    fn fetch_ocsp(&self, _: &Cert, _: &Cert) -> Result<Vec<u8>, FetchError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(aa(&["alice-all-good.ors"]))
    }
}

impl CrlFetcher for LegacyFetcher {
    fn fetch_crls(&self, _: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![aa(&["role-aa-all-good.crl"])])
    }
}

#[test]
fn legacy_defaults_cannot_substitute_pkc_evidence_for_mandatory_ac_checks() {
    let legacy = Arc::new(LegacyFetcher::default());
    let ctx = context(
        Fetchers {
            ocsp: Some(legacy.clone()),
            crl: Some(legacy.clone()),
            cert: None,
        },
        "2019-12-12T00:00:00Z",
    );
    let error = validate_ac(&ctx, &ac(), None).unwrap_err();
    assert!(error.is_instance_of("InsufficientRevinfoError"), "{error}");
    assert_eq!(
        legacy.0.load(Ordering::SeqCst),
        0,
        "AA supplied CRLs suffice"
    );
    legacy.0.store(0, Ordering::SeqCst);
    assert!(verify_ac_ocsp(&ctx, &ac(), &path())
        .unwrap_err()
        .is_instance_of("InsufficientRevinfoError"));
    assert!(verify_ac_crl(&ctx, &ac(), &path())
        .unwrap_err()
        .is_instance_of("InsufficientRevinfoError"));
    assert_eq!(
        legacy.0.load(Ordering::SeqCst),
        0,
        "default AC methods never delegate to PKC methods"
    );
}

#[test]
fn ac_holder_and_signature_rejections_happen_before_any_ac_fetch() {
    let fetcher = Arc::new(RecordingAcFetcher {
        ocsp_response: Some(aa(&["alice-all-good.ors"])),
        ..RecordingAcFetcher::default()
    });
    let ctx = context(ocsp_set(fetcher.clone()), "2019-12-12T00:00:00Z");
    let holder = cert(&["people-ca", "bob.crt"]);
    let mismatch = validate_ac(&ctx, &ac(), Some(&holder)).unwrap_err();
    assert!(
        mismatch.to_string().contains("Could not match"),
        "{mismatch}"
    );
    let badsig = validate_ac(&ctx, &aa(&["aa", "badsig.attr.crt"]), None).unwrap_err();
    assert!(
        badsig
            .to_string()
            .contains("signature could not be verified"),
        "{badsig}"
    );
    assert!(fetcher.ac_ocsp.lock().unwrap().is_empty());
    assert_eq!(fetcher.pkc_calls.load(Ordering::SeqCst), 0);
    assert!(fetcher.pkc_targets.lock().unwrap().is_empty());
}

#[test]
fn base_certificate_id_issuer_is_not_an_aa_fetch_identity() {
    let ac_der = input(&[
        "attribute-certs",
        "oneoff",
        "alice-v2form-only-base-cert-id.attr.crt",
    ]);
    let fetcher = Arc::new(RecordingAcFetcher::default());
    let ctx = context(
        Fetchers {
            ocsp: Some(fetcher.clone()),
            crl: Some(fetcher.clone()),
            cert: None,
        },
        "2022-05-01T00:00:00Z",
    );
    // This authenticated noRevAvail certificate remains supported for ordinary
    // offline validation. Its AA issuer DN must never stand in for AA subject.
    let offline = context(Fetchers::none(), "2022-05-01T00:00:00Z");
    // The require context's historical CRLs are intentionally not used here.
    let offline = ValidationContext::builder()
        .trust_root(cert(&["root", "root.crt"]))
        .other_cert(cert(&["root", "interm-role.crt"]))
        .other_cert(authority())
        .moment(offline.timing().validation_time)
        .build()
        .unwrap();
    validate_ac(&offline, &ac_der, Some(&cert(&["people-ca", "alice.crt"]))).unwrap();
    for error in [
        verify_ac_ocsp(&ctx, &ac_der, &path()).unwrap_err(),
        verify_ac_crl(&ctx, &ac_der, &path()).unwrap_err(),
    ] {
        assert_eq!(error.class_name(), "ValueError", "{error}");
        assert!(error.to_string().contains("AC issuer"), "{error}");
    }
    assert!(fetcher.ac_ocsp.lock().unwrap().is_empty());
    assert!(fetcher.ac_crls.lock().unwrap().is_empty());
    assert_eq!(fetcher.pkc_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn signed_unknown_ac_status_is_not_good_revocation_evidence() {
    let response = opened(sigis_testdata::path(&[
        "lanes",
        "r3-s",
        "ac-fetch",
        "unknown-signed.ors",
    ]));
    let parsed = x509_ocsp::OcspResponse::from_der(&response).unwrap();
    let basic =
        x509_ocsp::BasicOcspResponse::from_der(parsed.response_bytes.unwrap().response.as_bytes())
            .unwrap();
    assert!(matches!(
        basic.tbs_response_data.responses[0].cert_status,
        x509_ocsp::CertStatus::Unknown(_)
    ));
    let fetcher = Arc::new(RecordingAcFetcher {
        ocsp_response: Some(response),
        ..RecordingAcFetcher::default()
    });
    let ctx = context(ocsp_set(fetcher.clone()), "2019-12-12T00:00:00Z");
    let error = verify_ac_ocsp(&ctx, &ac(), &path()).unwrap_err();
    assert!(error.is_instance_of("InsufficientRevinfoError"), "{error}");
    assert_eq!(fetcher.ac_ocsp.lock().unwrap().len(), 1);
    assert_eq!(fetcher.pkc_calls.load(Ordering::SeqCst), 0);
}
