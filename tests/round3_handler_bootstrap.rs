//! Direct backend selection, exact lifecycle originals and real basic consumers.
//! Signed evidence below is committed-fixture replay, not fresh PKI generation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_cms::{SignedData, StandardCmsSignatureStatus, TrustProblem};
use sigis_pades::ades::{
    basic::{basic_validation, BasicValidationResult, QualificationSpec},
    policy::{
        basic_validation_with_handlers, basic_validation_with_handlers_and_options,
        HandlerFetchSelection, ValidationDataHandlers,
    },
    AdesValidationOptions,
};
use sigis_pades_sign::{
    keys::load_private_key_from_pemder_data, sign_general_data, DummyTimeStamper, SimpleSigner,
};
use sigis_pki_certvalidator::{
    context::ValidationContextBuilder,
    policy::{CertRevTrustPolicy, NonRevokedStatusAssertion, ValidationTimingParams},
    revinfo::freshness::{FreshnessJudge, RevinfoUsability, RevinfoUsabilityRating},
    ValidationContext,
};
use sigis_pki_core::{
    algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm},
    cert::Cert,
    errors::{FetchError, FetchErrorKind, ValidationError},
    fetch::{CertificateFetcher, CrlFetcher, FetcherBackend, Fetchers, OcspFetcher},
    key_usage::KeyUsageConstraints,
    sign::TimeStamper,
    time::Moment,
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Once,
    },
    time::Duration,
};

const TIME: &str = "2020-11-20T00:00:00Z";
const CONTENT: &[u8] = b"Direct bootstrap: real native CMS and mandatory evidence";

fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn at(value: &str) -> Moment {
    Moment::parse_rfc3339(value).unwrap()
}
fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}
fn read(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    eprintln!(
        "DIRECT_BOOTSTRAP_INPUT {}",
        serde_json::json!({"path":path.canonicalize().unwrap(),"length":bytes.len(),"sha256":sha(&bytes)})
    );
    bytes
}
fn runtime_identity() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let path = std::env::current_exe().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let source = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/round3_handler_bootstrap.rs"));
        eprintln!("DIRECT_BOOTSTRAP_EXECUTABLE {}", serde_json::json!({"path":path.canonicalize().unwrap(),"length":bytes.len(),"sha256":sha(&bytes),"test_source_sha256":sha(source)}));
    });
}
fn data(parts: &[&str]) -> PathBuf {
    sigis_testdata::path(parts)
}
struct Pki {
    directory: PathBuf,
    manifest: serde_json::Value,
}
impl Pki {
    fn new() -> Self {
        runtime_identity();
        let directory = data(&["lanes", "d", "pki", "testing-ca"]);
        let manifest = serde_json::from_slice(&read(&directory.join("manifest.json"))).unwrap();
        Self {
            directory,
            manifest,
        }
    }
    fn cert(&self, label: &str) -> Cert {
        let filename = self.manifest["certs"][label]["file"].as_str().unwrap();
        Cert::from_der(&read(&self.directory.join(filename))).unwrap()
    }
    fn key(&self, label: &str) -> sigis_pades_sign::keys::PrivateKey {
        let key_label = self.manifest["certs"][label]["subject_key"]
            .as_str()
            .unwrap();
        let entry = &self.manifest["keys"][key_label];
        let bytes = read(&data(&[
            "pyhanko",
            "crypto",
            entry["path"].as_str().unwrap(),
        ]));
        load_private_key_from_pemder_data(&bytes, entry["password"].as_str().map(str::as_bytes))
            .unwrap()
    }
    fn signer(&self, label: &str) -> SimpleSigner {
        // Leaf only forces a real issuer-provider path for selected fetchers.
        SimpleSigner::new(self.key(label), self.cert(label), vec![]).unwrap()
    }
    fn cms(&self, label: &str, timestamp: Option<&str>) -> Vec<u8> {
        let tsa = timestamp.map(|name| {
            DummyTimeStamper::new(
                self.cert(name),
                self.key(name),
                vec![self.cert("root"), self.cert("interm")],
            )
            .with_fixed_time(at(TIME))
        });
        sign_general_data(
            CONTENT,
            &self.signer(label),
            DigestAlgorithm::Sha256,
            true,
            tsa.as_ref().map(|value| value as &dyn TimeStamper),
        )
        .unwrap()
    }
}
fn evidence_bytes(day: &str, file: &str) -> Vec<u8> {
    read(&data(&["lanes", "d", "revinfo", "testing-ca", day, file]))
}

#[derive(Debug)]
struct Evidence {
    leaf: Cert,
    intermediate: Cert,
    ocsp: Vec<u8>,
    root_crl: Vec<u8>,
    intermediate_crl: Vec<u8>,
    cert_calls: AtomicUsize,
    ocsp_calls: AtomicUsize,
    crl_calls: AtomicUsize,
}
impl Evidence {
    fn new(pki: &Pki, label: &str, day: &str) -> Arc<Self> {
        Arc::new(Self {
            leaf: pki.cert(label),
            intermediate: pki.cert("interm"),
            ocsp: evidence_bytes(day, &format!("ocsp-{label}.der")),
            root_crl: evidence_bytes(day, "crl-root.der"),
            intermediate_crl: evidence_bytes(day, "crl-interm.der"),
            cert_calls: AtomicUsize::new(0),
            ocsp_calls: AtomicUsize::new(0),
            crl_calls: AtomicUsize::new(0),
        })
    }
    fn fetchers(self: &Arc<Self>) -> Fetchers {
        Fetchers {
            cert: Some(self.clone()),
            ocsp: Some(self.clone()),
            crl: Some(self.clone()),
        }
    }
    fn calls(&self) -> usize {
        self.cert_calls.load(Ordering::SeqCst)
            + self.ocsp_calls.load(Ordering::SeqCst)
            + self.crl_calls.load(Ordering::SeqCst)
    }
}
impl CertificateFetcher for Evidence {
    fn fetch_issuers(&self, target: &Cert) -> Result<Vec<Cert>, FetchError> {
        self.cert_calls.fetch_add(1, Ordering::SeqCst);
        if target == &self.leaf {
            Ok(vec![self.intermediate.clone()])
        } else {
            Err(FetchError::new(
                FetchErrorKind::NotFound,
                "no matching recorded issuer",
            ))
        }
    }
}
impl OcspFetcher for Evidence {
    fn fetch_ocsp(&self, target: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        self.ocsp_calls.fetch_add(1, Ordering::SeqCst);
        if target == &self.leaf && issuer == &self.intermediate {
            Ok(self.ocsp.clone())
        } else {
            Err(FetchError::new(
                FetchErrorKind::NotFound,
                "no matching recorded OCSP CertID",
            ))
        }
    }
}
impl CrlFetcher for Evidence {
    fn fetch_crls(&self, target: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        self.crl_calls.fetch_add(1, Ordering::SeqCst);
        if target == &self.leaf {
            Ok(vec![self.intermediate_crl.clone()])
        } else if target == &self.intermediate {
            Ok(vec![self.root_crl.clone()])
        } else {
            Err(FetchError::new(
                FetchErrorKind::NotFound,
                "no matching recorded CRL",
            ))
        }
    }
}
#[derive(Debug)]
struct Backend {
    evidence: Arc<Evidence>,
    factories: AtomicUsize,
    closes: AtomicUsize,
}
impl Backend {
    fn new(evidence: Arc<Evidence>) -> Arc<Self> {
        Arc::new(Self {
            evidence,
            factories: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
        })
    }
}
impl FetcherBackend for Backend {
    fn get_fetchers(&self) -> Fetchers {
        self.factories.fetch_add(1, Ordering::SeqCst);
        self.evidence.fetchers()
    }
    fn close(&self) -> Result<(), FetchError> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn builder(pki: &Pki, roots: bool, revocation: &str, time: &str) -> ValidationContextBuilder {
    let mut builder = ValidationContext::builder()
        .moment(at(time))
        .point_in_time_validation(false)
        .revocation_mode(revocation);
    if roots {
        builder = builder.trust_root(pki.cert("root"));
    }
    builder
}
fn local(
    builder: ValidationContextBuilder,
    pki: &Pki,
    day: &str,
    label: &str,
) -> ValidationContextBuilder {
    builder
        .other_cert(pki.cert("interm"))
        .crl(evidence_bytes(day, "crl-root.der"))
        .crl(evidence_bytes(day, "crl-interm.der"))
        .ocsp_response(evidence_bytes(day, &format!("ocsp-{label}.der")))
}
fn export(
    label: &str,
    bytes: &[u8],
    context: &ValidationContext,
    options: Option<&AdesValidationOptions>,
    material: Option<&Evidence>,
    result: &BasicValidationResult,
) {
    let Some(output) = std::env::var_os("HANKO_DIRECT_BOOTSTRAP_OUTPUT_DIR") else {
        return;
    };
    let mut certs: Vec<Vec<u8>> = context
        .other_certs()
        .iter()
        .map(|cert| cert.der().to_vec())
        .collect();
    let mut crls: Vec<Vec<u8>> = context.crls().map(<[u8]>::to_vec).collect();
    let mut ocsps: Vec<Vec<u8>> = context.ocsps().map(<[u8]>::to_vec).collect();
    if let Some(evidence) = material {
        certs.push(evidence.intermediate.der().to_vec());
        crls.extend([evidence.root_crl.clone(), evidence.intermediate_crl.clone()]);
        ocsps.push(evidence.ocsp.clone());
    }
    let b64 = |values: Vec<Vec<u8>>| {
        values
            .iter()
            .map(|bytes| openssl::base64::encode_block(bytes))
            .collect::<Vec<_>>()
    };
    let status = result.api_status.as_ref();
    let predicate = options.and_then(|value| value.exact_key_usage_settings.as_ref()).map(|policy| serde_json::json!({"key_usage":policy.key_usage,"key_usage_forbidden":policy.key_usage_forbidden,"extd_key_usage":policy.extd_key_usage,"explicit_extd_key_usage_required":policy.explicit_extd_key_usage_required,"match_all_key_usages":policy.match_all_key_usages}));
    let record = serde_json::json!({"label":label,"test":std::thread::current().name(),"cms_b64":openssl::base64::encode_block(bytes),"cms_sha256":sha(bytes),"content_b64":openssl::base64::encode_block(CONTENT),"content_sha256":sha(CONTENT),"roots_b64":b64(context.trust_anchors().iter().map(|anchor| anchor.cert().der().to_vec()).collect()),"other_certs_b64":b64(certs),"crls_b64":b64(crls),"ocsps_b64":b64(ocsps),"time":context.moment().to_string(),"point_in_time_validation":context.timing().point_in_time_validation,"time_tolerance_seconds":context.timing().time_tolerance.as_secs(),"revocation_mode":"require","profile":"ordinary-default-unless-explicit-predicate","predicate":predicate,"evidence_provenance":if material.is_some(){"committed signed material returned by selected actual fetcher; offline oracle receives equivalent bytes"}else{"context local signed evidence only; no selected network material"},"native":{"intact":status.map(|s|s.signature.intact),"valid":status.map(|s|s.signature.valid),"trusted":status.map(|s|s.signature.trusted()),"bottom_line":status.map(StandardCmsSignatureStatus::bottom_line),"subindication":result.ades_subindic.standard_name(),"trust_problem":status.map(|s|format!("{:?}",s.signature.trust_problem))}});
    let data = serde_json::to_vec_pretty(&record).unwrap();
    let output = PathBuf::from(output);
    std::fs::create_dir_all(&output).unwrap();
    let path = output.join(format!("{label}-{}.json", sha(&data)));
    std::fs::write(&path, &data).unwrap();
    eprintln!(
        "DIRECT_BOOTSTRAP_NATIVE_CASE {}",
        serde_json::json!({"path":path,"length":data.len(),"sha256":sha(&data),"cms_sha256":sha(bytes)})
    );
}
fn check(
    label: &str,
    bytes: &[u8],
    context: &ValidationContext,
    handlers: &ValidationDataHandlers,
    material: Option<&Evidence>,
) -> BasicValidationResult {
    let before = format!("{context:?}");
    let algorithm = context.algorithm_policy_arc();
    let result = basic_validation_with_handlers(
        bytes,
        Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
        context,
        &QualificationSpec::default(),
        handlers,
    )
    .unwrap();
    assert_eq!(before, format!("{context:?}"));
    assert!(Arc::ptr_eq(&algorithm, &context.algorithm_policy_arc()));
    export(label, bytes, context, None, material, &result);
    result
}
fn trusted(result: &BasicValidationResult) -> bool {
    result
        .api_status
        .as_ref()
        .is_some_and(|status| status.signature.trusted() && status.bottom_line())
}
fn intact_valid(result: &BasicValidationResult) {
    let status = result.api_status.as_ref().unwrap();
    assert!(status.signature.intact && status.signature.valid);
}

// Original CV assertions; paired real managed-HTTP consumer tests below establish
// actual default backend effects rather than treating construction as acceptance.
#[test]
fn test_bootstrap_owns_the_default_backend() {
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::default());
    assert!(handlers.owned_fetcher_backend.is_some());
    assert!(
        handlers.fetchers.cert.is_some()
            && handlers.fetchers.ocsp.is_some()
            && handlers.fetchers.crl.is_some()
    );
    handlers.close().unwrap();
    handlers.close().unwrap();
}
#[test]
fn test_bootstrap_owns_the_default_backend_explicitly() {
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::DefaultHttp);
    assert!(handlers.owned_fetcher_backend.is_some());
    handlers.close().unwrap();
}
#[test]
fn test_bootstrap_leaves_a_supplied_backend_alone() {
    let pki = Pki::new();
    let bytes = pki.cms("signer1", None);
    let evidence = Evidence::new(&pki, "signer1", "2020-11-20");
    let backend = Backend::new(evidence.clone());
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Borrowed(
        backend.clone(),
    ));
    assert!(handlers.owned_fetcher_backend.is_none());
    assert_eq!(backend.factories.load(Ordering::SeqCst), 1);
    let ctx = builder(&pki, true, "require", TIME).build().unwrap();
    let result = check(
        "borrowed-fetched-positive",
        &bytes,
        &ctx,
        &handlers,
        Some(&evidence),
    );
    assert!(trusted(&result), "{result:?}");
    assert!(evidence.cert_calls.load(Ordering::SeqCst) > 0);
    assert!(evidence.ocsp_calls.load(Ordering::SeqCst) > 0);
    assert!(evidence.crl_calls.load(Ordering::SeqCst) > 0);
    handlers.close().unwrap();
    handlers.close().unwrap();
    assert_eq!(backend.closes.load(Ordering::SeqCst), 0);
    assert_eq!(backend.factories.load(Ordering::SeqCst), 1);
}
#[test]
fn test_bootstrap_leaves_supplied_fetchers_alone() {
    let pki = Pki::new();
    let bytes = pki.cms("signer1", None);
    let evidence = Evidence::new(&pki, "signer1", "2020-11-20");
    let backend = Backend::new(evidence.clone());
    let supplied = backend.get_fetchers();
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Supplied(
        supplied.clone(),
    ));
    assert!(handlers.owned_fetcher_backend.is_none());
    assert!(Arc::ptr_eq(
        handlers.fetchers.cert.as_ref().unwrap(),
        supplied.cert.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        handlers.fetchers.ocsp.as_ref().unwrap(),
        supplied.ocsp.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        handlers.fetchers.crl.as_ref().unwrap(),
        supplied.crl.as_ref().unwrap()
    ));
    let ctx = builder(&pki, true, "require", TIME).build().unwrap();
    let result = check(
        "supplied-fetched-positive",
        &bytes,
        &ctx,
        &handlers,
        Some(&evidence),
    );
    assert!(trusted(&result), "{result:?}");
    assert!(evidence.cert_calls.load(Ordering::SeqCst) > 0);
    assert!(evidence.ocsp_calls.load(Ordering::SeqCst) > 0);
    assert!(evidence.crl_calls.load(Ordering::SeqCst) > 0);
    handlers.close().unwrap();
    assert_eq!(backend.closes.load(Ordering::SeqCst), 0);
    assert_eq!(backend.factories.load(Ordering::SeqCst), 1);
}
#[test]
fn empty_and_disabled_override_legacy_fetchers_but_keep_signed_local_evidence() {
    let pki = Pki::new();
    let bytes = pki.cms("signer1", None);
    for (name, selection) in [
        ("disabled", HandlerFetchSelection::Disabled),
        (
            "supplied-empty",
            HandlerFetchSelection::Supplied(Fetchers::none()),
        ),
    ] {
        let legacy = Evidence::new(&pki, "signer1", "2020-11-20");
        let ctx = builder(&pki, true, "require", TIME)
            .other_cert(pki.cert("interm"))
            .fetchers(legacy.fetchers())
            .build()
            .unwrap();
        let handlers = ValidationDataHandlers::from_fetch_selection(selection);
        assert!(handlers.owned_fetcher_backend.is_none());
        assert!(handlers.fetchers.is_empty());
        let denied = check(
            &format!("{name}-missing-evidence"),
            &bytes,
            &ctx,
            &handlers,
            None,
        );
        intact_valid(&denied);
        assert!(!trusted(&denied));
        assert_eq!(legacy.calls(), 0);
        let local_ctx = local(
            builder(&pki, true, "require", TIME),
            &pki,
            "2020-11-20",
            "signer1",
        )
        .fetchers(legacy.fetchers())
        .build()
        .unwrap();
        let accepted = check(
            &format!("{name}-local-positive"),
            &bytes,
            &local_ctx,
            &handlers,
            None,
        );
        assert!(trusted(&accepted), "{accepted:?}");
        assert_eq!(legacy.calls(), 0);
        handlers.close().unwrap();
    }
}
#[test]
fn selected_evidence_never_bypasses_roots_revocation_or_cms_integrity() {
    let pki = Pki::new();
    let bytes = pki.cms("signer1", None);
    let good = Evidence::new(&pki, "signer1", "2020-11-20");
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Supplied(
        good.fetchers(),
    ));
    let empty = builder(&pki, false, "require", TIME).build().unwrap();
    let denied = check("empty-roots", &bytes, &empty, &handlers, Some(&good));
    intact_valid(&denied);
    assert!(!trusted(&denied));
    let ctx = builder(&pki, true, "require", TIME).build().unwrap();
    let parsed = SignedData::from_der(&bytes).unwrap();
    let signature = &parsed.signer_infos[0].signature;
    let position = bytes
        .windows(signature.len())
        .position(|part| part == signature)
        .unwrap();
    let mut bad = bytes.clone();
    bad[position] ^= 1;
    let denied = check("tampered-signature", &bad, &ctx, &handlers, Some(&good));
    assert!(!denied.api_status.as_ref().unwrap().signature.valid);
    assert!(!trusted(&denied));
    let revoked_bytes = pki.cms("signer2", None);
    let revoked = Evidence::new(&pki, "signer2", "2020-12-01");
    let revoked_handlers = ValidationDataHandlers::from_fetch_selection(
        HandlerFetchSelection::Supplied(revoked.fetchers()),
    );
    let ctx = builder(&pki, true, "require", "2020-12-01T00:00:00Z")
        .build()
        .unwrap();
    let denied = check(
        "revoked-signer",
        &revoked_bytes,
        &ctx,
        &revoked_handlers,
        Some(&revoked),
    );
    intact_valid(&denied);
    assert!(denied.api_status.as_ref().unwrap().signature.revoked());
    assert!(!trusted(&denied));
    let malformed = basic_validation_with_handlers(
        b"not DER",
        None,
        &ctx,
        &QualificationSpec::default(),
        &handlers,
    );
    match malformed {
        Ok(result) => {
            assert!(!trusted(&result));
            assert_eq!(result.ades_subindic.standard_name(), "FORMAT_FAILURE");
        }
        Err(sigis_pki_core::errors::HankoError::Malformed(message)) => {
            assert!(!message.is_empty());
            eprintln!(
                "DIRECT_BOOTSTRAP_MALFORMED {}",
                serde_json::json!({"class":"Malformed","message":message})
            );
        }
        Err(other) => panic!("unexpected malformed-CMS error class: {other:?}"),
    }
}

#[derive(Debug)]
struct DenyAlgorithms(Option<Moment>, Moment);
impl AlgorithmUsagePolicy for DenyAlgorithms {
    fn digest_algorithm_allowed(
        &self,
        _: &const_oid::ObjectIdentifier,
        time: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        if time == Some(self.1) {
            AlgorithmUsageConstraint {
                allowed: false,
                not_allowed_after: self.0,
                failure_reason: Some(
                    "bounded direct handler best-signature-time digest denial".into(),
                ),
            }
        } else {
            AlgorithmUsageConstraint::allowed()
        }
    }
    fn signature_algorithm_allowed(
        &self,
        _: &AlgorithmIdentifierOwned,
        _: Option<Moment>,
        _: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::allowed()
    }
}
#[derive(Debug)]
struct RejectFreshness(Arc<AtomicUsize>);
impl FreshnessJudge for RejectFreshness {
    fn judge(
        &self,
        _: Option<Moment>,
        _: Option<Moment>,
        _: &CertRevTrustPolicy,
        _: &ValidationTimingParams,
    ) -> RevinfoUsability {
        self.0.fetch_add(1, Ordering::SeqCst);
        RevinfoUsability {
            rating: RevinfoUsabilityRating::Stale,
            last_usable_at: None,
            compared_to: None,
        }
    }
}
#[test]
fn complete_caller_algorithm_freshness_and_clock_constraints_survive() {
    let pki = Pki::new();
    let bytes = pki.cms("signer1", None);
    let evidence = Evidence::new(&pki, "signer1", "2020-11-20");
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Supplied(
        evidence.fetchers(),
    ));
    for cutoff in [None, Some(at("2020-11-19T00:00:00Z"))] {
        let ctx = builder(&pki, true, "require", TIME)
            .algorithm_policy(Arc::new(DenyAlgorithms(cutoff, at("2020-11-19T01:02:03Z"))))
            .time_tolerance(Duration::from_secs(71))
            .best_signature_time(at("2020-11-19T01:02:03Z"))
            .build()
            .unwrap();
        let result = basic_validation_with_handlers(
            &bytes,
            Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
            &ctx,
            &QualificationSpec::default(),
            &handlers,
        )
        .unwrap();
        intact_valid(&result);
        assert!(!trusted(&result));
        let status = result.api_status.as_ref().unwrap();
        assert_eq!(status.signature.error_time_horizon, cutoff);
        assert!(
            matches!(&status.signature.trust_problem,Some(TrustProblem::Path(ValidationError::DisallowedAlgorithm { banned_since,.. })) if banned_since.as_ref()==cutoff.as_ref())
        );
    }
    let seen = Arc::new(AtomicUsize::new(0));
    let ctx = builder(&pki, true, "require", TIME)
        .freshness_judge(Arc::new(RejectFreshness(seen.clone())))
        .build()
        .unwrap();
    let result = basic_validation_with_handlers(
        &bytes,
        Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
        &ctx,
        &QualificationSpec::default(),
        &handlers,
    )
    .unwrap();
    assert!(!trusted(&result));
    assert!(seen.load(Ordering::SeqCst) > 0);
    let expired = builder(&pki, true, "none", "2040-11-20T00:00:00Z")
        .build()
        .unwrap();
    let result = basic_validation_with_handlers(
        &bytes,
        Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
        &expired,
        &QualificationSpec::default(),
        &handlers,
    )
    .unwrap();
    intact_valid(&result);
    assert!(!trusted(&result));
}
#[test]
fn caller_nonrevocation_assertions_keep_exact_digest_and_time_predicates() {
    let pki = Pki::new();
    let bytes = pki.cms("signer1", None);
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Disabled);
    let leaf = pki.cert("signer1");
    for (hash, time, accepted) in [
        (leaf.sha256(), at(TIME), true),
        (leaf.sha256(), at("2020-11-19T00:00:00Z"), false),
        ([0u8; 32], at(TIME), false),
    ] {
        let ctx = builder(&pki, true, "require", TIME)
            .other_cert(pki.cert("interm"))
            .crl(evidence_bytes("2020-11-20", "crl-root.der"))
            .assertion(NonRevokedStatusAssertion {
                cert_sha256: hash,
                at: time,
            })
            .build()
            .unwrap();
        let before = ctx.non_revoked_status_assertions().to_vec();
        let result = basic_validation_with_handlers(
            &bytes,
            Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
            &ctx,
            &QualificationSpec::default(),
            &handlers,
        )
        .unwrap();
        intact_valid(&result);
        assert_eq!(trusted(&result), accepted, "{result:?}");
        assert_eq!(ctx.non_revoked_status_assertions(), before);
    }
}
fn ds_signer(pki: &Pki) -> SimpleSigner {
    let certificate = Cert::from_der(&read(&data(&[
        "lanes",
        "r3-v",
        "cms-exact-main",
        "digital-signature-only.der",
    ])))
    .unwrap();
    assert_eq!(
        sigis_pki_core::key_usage::cert_key_usages(&certificate),
        Some(names(&["digital_signature"]))
    );
    SimpleSigner::new(
        pki.key("signer1"),
        certificate,
        vec![pki.cert("interm"), pki.cert("root")],
    )
    .unwrap()
}
#[test]
fn all_five_exact_main_predicate_fields_and_fixed_tsa_purpose_reach_basic() {
    let pki = Pki::new();
    let bytes = sign_general_data(
        CONTENT,
        &ds_signer(&pki),
        DigestAlgorithm::Sha256,
        true,
        None,
    )
    .unwrap();
    let ctx = local(
        builder(&pki, true, "require", TIME),
        &pki,
        "2020-11-20",
        "signer1",
    )
    .build()
    .unwrap();
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Disabled);
    let ordinary = basic_validation_with_handlers(
        &bytes,
        Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
        &ctx,
        &QualificationSpec::default(),
        &handlers,
    )
    .unwrap();
    assert!(!trusted(&ordinary));
    for (index, (policy, accepted)) in [
        (KeyUsageConstraints::default(), true),
        (
            KeyUsageConstraints {
                key_usage: Some(BTreeSet::new()),
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature"])),
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation"])),
                ..Default::default()
            },
            false,
        ),
        (
            KeyUsageConstraints {
                key_usage: None,
                key_usage_forbidden: Some(names(&["digital_signature"])),
                ..Default::default()
            },
            false,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature", "non_repudiation"])),
                match_all_key_usages: false,
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature", "non_repudiation"])),
                match_all_key_usages: true,
                ..Default::default()
            },
            false,
        ),
        (
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["server_auth"])),
                explicit_extd_key_usage_required: false,
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["server_auth"])),
                explicit_extd_key_usage_required: true,
                ..Default::default()
            },
            false,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut options = AdesValidationOptions::default();
        options.exact_key_usage_settings = Some(policy.clone());
        let result = basic_validation_with_handlers_and_options(
            &bytes,
            Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
            &ctx,
            &QualificationSpec::default(),
            &handlers,
            &options,
        )
        .unwrap();
        intact_valid(&result);
        assert_eq!(trusted(&result), accepted, "policy {policy:?}: {result:?}");
        export(
            &format!("exact-policy-{index}"),
            &bytes,
            &ctx,
            Some(&options),
            None,
            &result,
        );
    }
    for (tsa_label, expected_trust) in [("tsa", true), ("signer1", false)] {
        let tsa = DummyTimeStamper::new(
            pki.cert(tsa_label),
            pki.key(tsa_label),
            vec![pki.cert("interm"), pki.cert("root")],
        )
        .with_fixed_time(at(TIME));
        let bytes = sign_general_data(
            CONTENT,
            &ds_signer(&pki),
            DigestAlgorithm::Sha256,
            true,
            Some(&tsa),
        )
        .unwrap();
        let ctx = local(
            builder(&pki, true, "none", TIME),
            &pki,
            "2020-11-20",
            "signer1",
        )
        .build()
        .unwrap();
        let mut options = AdesValidationOptions::default();
        options.exact_key_usage_settings = Some(KeyUsageConstraints::default());
        let result = basic_validation_with_handlers_and_options(
            &bytes,
            Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
            &ctx,
            &QualificationSpec::default(),
            &handlers,
            &options,
        )
        .unwrap();
        let status = result.api_status.as_ref().unwrap();
        assert!(status.signature.trusted());
        assert_eq!(
            status.timestamp_validity.as_ref().unwrap().trusted(),
            expected_trust
        );
    }
}
#[test]
fn default_consumer_delegates_without_altering_the_existing_basic_result() {
    let pki = Pki::new();
    let bytes = pki.cms("signer1", None);
    let ctx = local(
        builder(&pki, true, "require", TIME),
        &pki,
        "2020-11-20",
        "signer1",
    )
    .build()
    .unwrap();
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Disabled);
    let digest = DigestAlgorithm::Sha256.digest(CONTENT);
    let qualification = QualificationSpec::default();
    let old = basic_validation(&bytes, Some(&digest), &ctx, &qualification).unwrap();
    let current =
        basic_validation_with_handlers(&bytes, Some(&digest), &ctx, &qualification, &handlers)
            .unwrap();
    let explicit = basic_validation_with_handlers_and_options(
        &bytes,
        Some(&digest),
        &ctx,
        &qualification,
        &handlers,
        &AdesValidationOptions::default(),
    )
    .unwrap();
    assert!(trusted(&old));
    assert_eq!(format!("{old:?}"), format!("{current:?}"));
    assert_eq!(format!("{old:?}"), format!("{explicit:?}"));
}

// Supplemental real-default-pool and issued factory/shared-view controls.
mod real_default_http {
    use super::*;
    use der::{
        asn1::{Ia5String, OctetString},
        Decode, Encode,
    };
    use sigis_pki_fetch::{
        transport::HttpRequest, FetchKind, FetchLimits, FetcherSettings, HttpFetchers,
        HttpResponse, HttpTransport, TransportError,
    };
    use std::{
        io::{BufRead, Write},
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        thread,
        time::Duration,
    };
    use x509_cert::ext::{
        pkix::{name::GeneralName, AccessDescription, AuthorityInfoAccessSyntax},
        Extension,
    };

    const HTTP_CONTENT: &[u8] = b"Native direct default HTTP handler consumer";

    // Genuine re-signed leaf, using the existing mature certificate types and
    // the real fixture CA key. Only loopback AIA/serial are changed.
    fn leaf(url: &str, serial: u32) -> Cert {
        let pki = Pki::new();
        let original = pki.cert("signer1");
        let parsed = x509_cert::Certificate::from_der(original.der()).unwrap();
        let aia = AuthorityInfoAccessSyntax(vec![AccessDescription {
            access_method: "1.3.6.1.5.5.7.48.2".parse().unwrap(),
            access_location: GeneralName::UniformResourceIdentifier(Ia5String::new(url).unwrap()),
        }]);
        let mut extensions = parsed.tbs_certificate().extensions().unwrap().clone();
        extensions.retain(|ext| ext.extn_id.to_string() != "1.3.6.1.5.5.7.1.1");
        extensions.push(Extension {
            extn_id: "1.3.6.1.5.5.7.1.1".parse().unwrap(),
            critical: false,
            extn_value: OctetString::new(aia.to_der().unwrap()).unwrap(),
        });
        let original = openssl::x509::X509::from_der(original.der()).unwrap();
        let mut builder = openssl::x509::X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(
                &openssl::bn::BigNum::from_u32(serial)
                    .unwrap()
                    .to_asn1_integer()
                    .unwrap(),
            )
            .unwrap();
        builder.set_subject_name(original.subject_name()).unwrap();
        builder.set_issuer_name(original.issuer_name()).unwrap();
        builder.set_not_before(original.not_before()).unwrap();
        builder.set_not_after(original.not_after()).unwrap();
        builder.set_pubkey(&original.public_key().unwrap()).unwrap();
        for extension in extensions {
            builder
                .append_extension(
                    openssl::x509::X509Extension::new_from_der(
                        &openssl::asn1::Asn1Object::from_str(&extension.extn_id.to_string())
                            .unwrap(),
                        extension.critical,
                        &openssl::asn1::Asn1OctetString::new_from_bytes(
                            extension.extn_value.as_bytes(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let key = &pki.manifest["keys"]["interm"];
        let key_bytes = read(&data(&["pyhanko", "crypto", key["path"].as_str().unwrap()]));
        let ca_key = match key["password"].as_str() {
            Some(password) => openssl::pkey::PKey::private_key_from_pem_passphrase(
                &key_bytes,
                password.as_bytes(),
            )
            .unwrap(),
            None => openssl::pkey::PKey::private_key_from_pem(&key_bytes).unwrap(),
        };
        builder
            .sign(&ca_key, openssl::hash::MessageDigest::sha256())
            .unwrap();
        Cert::from_der(&builder.build().to_der().unwrap()).unwrap()
    }

    fn signed(leaf: &Cert) -> Vec<u8> {
        let pki = Pki::new();
        let signer =
            sigis_pades_sign::SimpleSigner::new(pki.key("signer1"), leaf.clone(), vec![]).unwrap();
        sigis_pades_sign::sign_general_data(
            HTTP_CONTENT,
            &signer,
            DigestAlgorithm::Sha256,
            true,
            None,
        )
        .unwrap()
    }

    fn ctx() -> ValidationContext {
        ValidationContext::builder()
            .trust_root(Pki::new().cert("root"))
            .moment(at("2020-11-20T00:00:00Z"))
            .revocation_mode("none")
            .build()
            .unwrap()
    }

    fn accepted(leaf: &Cert, handlers: &ValidationDataHandlers, label: &str) {
        let bytes = signed(leaf);
        let context = ctx();
        let before = format!("{context:?}");
        let digest = DigestAlgorithm::Sha256.digest(HTTP_CONTENT);
        let result = basic_validation_with_handlers(
            &bytes,
            Some(&digest),
            &context,
            &QualificationSpec::default(),
            handlers,
        )
        .unwrap();
        assert_eq!(result.ades_subindic.standard_name(), "OK");
        let status = result.api_status.as_ref().unwrap();
        assert!(status.signature.intact && status.signature.valid && status.signature.trusted());
        assert_eq!(status.signature.signing_cert.as_ref(), Some(leaf));
        assert_eq!(
            status.signature.validation_path.as_ref().unwrap().leaf(),
            Some(leaf)
        );
        assert_eq!(format!("{context:?}"), before);
        // Exact same newly produced bytes are available for a fresh offline
        // oracle using the actual issuer downloaded by the native consumer.
        if let Some(dir) = std::env::var_os("HANKO_DIRECT_BOOTSTRAP_OUTPUT_DIR") {
            let dir = std::path::PathBuf::from(dir);
            std::fs::create_dir_all(&dir).unwrap();
            let pki = Pki::new();
            let record = serde_json::json!({"label":label,"cms_b64":openssl::base64::encode_block(&bytes),
                "content_b64":openssl::base64::encode_block(HTTP_CONTENT),"time":"2020-11-20T00:00:00Z",
                "point_in_time_validation":true,"time_tolerance_seconds":1,"revocation_mode":"none","predicate":null,
                "roots_b64":[openssl::base64::encode_block(pki.cert("root").der())],
                "other_certs_b64":[openssl::base64::encode_block(pki.cert("interm").der())],
                "crls_b64":[],"ocsps_b64":[],
                "native":{"intact":true,"valid":true,"trusted":true,"revoked":false,"bottom_line":true,"subindication":"OK"},
                "evidence_mode":"fresh native re-signed leaf/CMS; actual default HTTP issuer; oracle explicit same issuer offline"});
            let data = serde_json::to_vec_pretty(&record).unwrap();
            let path = dir.join(format!("http-{label}.json"));
            std::fs::write(&path, &data).unwrap();
            eprintln!(
                "DIRECT_BOOTSTRAP_NATIVE_CASE {}",
                serde_json::json!({"path":path,"length":data.len(),"sha256":hex_sha(&data)})
            );
        }
    }

    fn hex_sha(bytes: &[u8]) -> String {
        DigestAlgorithm::Sha256
            .digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    struct KeepAlive {
        address: std::net::SocketAddr,
        requests: Arc<Mutex<Vec<String>>>,
        connections: Arc<AtomicUsize>,
        timeouts: Arc<AtomicUsize>,
        stopped: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }
    impl KeepAlive {
        fn new() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(vec![]));
            let connections = Arc::new(AtomicUsize::new(0));
            let stopped = Arc::new(AtomicBool::new(false));
            let timeouts = Arc::new(AtomicUsize::new(0));
            let worker = thread::spawn({
                let requests = requests.clone();
                let connections = connections.clone();
                let stopped = stopped.clone();
                let timeouts = timeouts.clone();
                let issuer = Pki::new().cert("interm").der().to_vec();
                move || {
                    while !stopped.load(Ordering::SeqCst) {
                        let (stream, _) = match listener.accept() {
                            Ok(s) => s,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(5));
                                continue;
                            }
                            Err(e) => panic!("accept: {e}"),
                        };
                        connections.fetch_add(1, Ordering::SeqCst);
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut reader = std::io::BufReader::new(stream);
                        loop {
                            if stopped.load(Ordering::SeqCst) {
                                return;
                            }
                            let mut line = String::new();
                            match reader.read_line(&mut line) {
                                Ok(0) => break,
                                Ok(_) => {}
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        std::io::ErrorKind::TimedOut
                                            | std::io::ErrorKind::WouldBlock
                                    ) =>
                                {
                                    if !stopped.load(Ordering::SeqCst) {
                                        timeouts.fetch_add(1, Ordering::SeqCst);
                                    }
                                    break;
                                }
                                Err(e) => panic!("read: {e}"),
                            }
                            let first = line.trim().to_owned();
                            let mut request_wire = line.as_bytes().to_vec();
                            assert!(first.starts_with("GET /issuer/"), "{first}");
                            loop {
                                line.clear();
                                assert!(reader.read_line(&mut line).unwrap() > 0);
                                request_wire.extend_from_slice(line.as_bytes());
                                assert!(request_wire.len() < 8192);
                                if line == "\r\n" {
                                    break;
                                }
                            }
                            requests.lock().unwrap().push(first);
                            let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-cert\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n", issuer.len());
                            let mut response_wire = header.into_bytes();
                            response_wire.extend_from_slice(&issuer);
                            reader.get_mut().write_all(&response_wire).unwrap();
                            reader.get_mut().flush().unwrap();
                            eprintln!(
                                "DIRECT_BOOTSTRAP_HTTP_EXCHANGE {}",
                                serde_json::json!({
                                    "request_b64": openssl::base64::encode_block(&request_wire),
                                    "request_length": request_wire.len(), "request_sha256": hex_sha(&request_wire),
                                    "response_b64": openssl::base64::encode_block(&response_wire),
                                    "response_length": response_wire.len(), "response_sha256": hex_sha(&response_wire),
                                    "body_length": issuer.len(), "body_sha256": hex_sha(&issuer),
                                    "connection": connections.load(Ordering::SeqCst)
                                })
                            );
                            if requests.lock().unwrap().len() == 2 {
                                return;
                            }
                        }
                    }
                }
            });
            Self {
                address,
                requests,
                connections,
                timeouts,
                stopped,
                worker: Some(worker),
            }
        }
        fn url(&self, suffix: &str) -> String {
            format!("http://{}/issuer/{suffix}", self.address)
        }
    }
    impl Drop for KeepAlive {
        fn drop(&mut self) {
            self.stopped.store(true, Ordering::SeqCst);
            self.worker.take().unwrap().join().unwrap();
        }
    }

    #[test]
    fn real_default_http_consumer_retains_factory_cache_and_closes_exact_pool() {
        let server = KeepAlive::new();
        let handlers =
            ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::DefaultHttp);
        let owner = handlers.owned_fetcher_backend.as_ref().unwrap();
        // The factory-issued set has a budget independent from the backend's
        // old shared view. No changed limits or substituted default transport.
        for _ in 0..owner.settings().limits.max_requests.unwrap() {
            owner.budget().charge(FetchKind::Crl).unwrap();
        }
        let first = leaf(&server.url("a"), 8101);
        let second = leaf(&server.url("b"), 8102);
        let old = owner.as_fetchers();
        assert_eq!(
            owner.fetch_certs(&server.url("a"), "aia").unwrap_err().kind,
            FetchErrorKind::Disabled
        );
        assert!(old
            .cert
            .as_ref()
            .unwrap()
            .fetch_issuers(&first)
            .unwrap()
            .is_empty());
        assert!(server.requests.lock().unwrap().is_empty());
        accepted(&first, &handlers, "default-first");
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        handlers.close().unwrap();
        accepted(&first, &handlers, "default-cache-after-close");
        assert_eq!(
            server.requests.lock().unwrap().len(),
            1,
            "issued cache survives close"
        );
        accepted(&second, &handlers, "default-new-session");
        assert_eq!(server.requests.lock().unwrap().len(), 2);
        assert_eq!(
            server.connections.load(Ordering::SeqCst),
            2,
            "managed close released the first idle reqwest connection"
        );
        assert_eq!(
            server.timeouts.load(Ordering::SeqCst),
            0,
            "server eviction cannot mimic close"
        );
        handlers.close().unwrap();
        handlers.close().unwrap();
        assert!(
            owner.budget().charge(FetchKind::Crl).is_err(),
            "owned old-view budget was not reset"
        );
        assert_eq!(
            owner.fetch_certs(&server.url("b"), "aia").unwrap_err().kind,
            FetchErrorKind::Disabled
        );
        assert!(old
            .cert
            .as_ref()
            .unwrap()
            .fetch_issuers(&second)
            .unwrap()
            .is_empty());
        eprintln!(
            "DIRECT_BOOTSTRAP_HTTP {}",
            serde_json::json!({"requests":server.requests.lock().unwrap().clone(),"connections":server.connections.load(Ordering::SeqCst),"timeouts":server.timeouts.load(Ordering::SeqCst)})
        );
    }

    #[derive(Debug)]
    struct CertificateTransport {
        body: Vec<u8>,
        requests: AtomicUsize,
    }
    impl HttpTransport for CertificateTransport {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, TransportError> {
            assert_eq!(request.method, "GET");
            self.requests.fetch_add(1, Ordering::SeqCst);
            Ok(HttpResponse {
                status: 200,
                content_type: Some("application/pkix-cert".into()),
                body: self.body.clone(),
            })
        }
    }

    #[test]
    fn direct_borrowed_factory_is_fresh_while_existing_policy_helper_keeps_shared_budget() {
        let transport = Arc::new(CertificateTransport {
            body: Pki::new().cert("interm").der().to_vec(),
            requests: AtomicUsize::new(0),
        });
        let backend = HttpFetchers::with_transport(
            transport.clone(),
            FetcherSettings {
                limits: FetchLimits {
                    max_requests: Some(1),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let first = leaf("http://direct.invalid/issuer/one", 8201);
        let second = leaf("http://direct.invalid/issuer/two", 8202);
        let one = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Borrowed(
            Arc::new(backend.clone()),
        ));
        accepted(&first, &one, "factory-one");
        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
        accepted(&first, &one, "factory-one-cache");
        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
        let deny = || {
            let bytes = signed(&second);
            let digest = DigestAlgorithm::Sha256.digest(HTTP_CONTENT);
            let result = basic_validation_with_handlers(
                &bytes,
                Some(&digest),
                &ctx(),
                &QualificationSpec::default(),
                &one,
            )
            .unwrap();
            assert!(!result.api_status.unwrap().signature.trusted());
        };
        deny();
        one.close().unwrap();
        deny();
        assert_eq!(
            transport.requests.load(Ordering::SeqCst),
            1,
            "close cannot replenish issued budget"
        );
        let two = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Borrowed(
            Arc::new(backend.clone()),
        ));
        accepted(&second, &two, "factory-two");
        assert_eq!(transport.requests.load(Ordering::SeqCst), 2);
        let spec = sigis_pades::ades::policy::RevocationInfoGatheringSpec {
            fetcher_backend: Some(backend),
            ..Default::default()
        };
        let old_one = sigis_pades::ades::policy::bootstrap_validation_data_handlers(&spec, false);
        let old_two = sigis_pades::ades::policy::bootstrap_validation_data_handlers(&spec, false);
        accepted(&first, &old_one, "legacy-shared-one");
        accepted(&first, &old_two, "legacy-shared-cache");
        assert_eq!(transport.requests.load(Ordering::SeqCst), 3);
        let bytes = signed(&second);
        let digest = DigestAlgorithm::Sha256.digest(HTTP_CONTENT);
        let result = basic_validation_with_handlers(
            &bytes,
            Some(&digest),
            &ctx(),
            &QualificationSpec::default(),
            &old_two,
        )
        .unwrap();
        assert!(!result.api_status.unwrap().signature.trusted());
        assert_eq!(transport.requests.load(Ordering::SeqCst), 3);
    }
}

#[derive(Debug)]
struct CallerTrustManager {
    root: sigis_pki_certvalidator::authority::TrustAnchor,
    calls: AtomicUsize,
}
impl sigis_pki_certvalidator::authority::TrustManager for CallerTrustManager {
    fn as_trust_anchor(
        &self,
        cert: &Cert,
    ) -> Option<sigis_pki_certvalidator::authority::TrustAnchor> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.root.cert() == cert).then(|| self.root.clone())
    }
    fn find_potential_issuers(
        &self,
        _: &Cert,
    ) -> Vec<sigis_pki_certvalidator::authority::TrustAnchor> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        vec![self.root.clone()]
    }
}

#[test]
fn real_caller_trust_manager_tolerance_and_qualification_constraints_are_consumed() {
    let pki = Pki::new();
    let bytes = pki.cms("signer1", None);
    let evidence = Evidence::new(&pki, "signer1", "2020-11-20");
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::Supplied(
        evidence.fetchers(),
    ));
    let manager = Arc::new(CallerTrustManager {
        root: sigis_pki_certvalidator::authority::TrustAnchor::new(pki.cert("root")),
        calls: AtomicUsize::new(0),
    });
    let context = builder(&pki, false, "none", TIME)
        .trust_manager(manager.clone())
        .build()
        .unwrap();
    let digest = DigestAlgorithm::Sha256.digest(CONTENT);
    let result = basic_validation_with_handlers(
        &bytes,
        Some(&digest),
        &context,
        &QualificationSpec::default(),
        &handlers,
    )
    .unwrap();
    assert!(trusted(&result), "{result:?}");
    assert!(manager.calls.load(Ordering::SeqCst) > 0);
    let required = QualificationSpec {
        requirements: Some(Default::default()),
        ..Default::default()
    };
    let result =
        basic_validation_with_handlers(&bytes, Some(&digest), &context, &required, &handlers)
            .unwrap();
    assert_ne!(
        result.ades_subindic.standard_name(),
        "OK",
        "qualification cannot disappear in delegation"
    );
    let beyond = pki.cert("signer1").not_after().plus(Duration::from_secs(2));
    for (seconds, accepted) in [(0, false), (3, true)] {
        let context = ValidationContext::builder()
            .trust_root(pki.cert("root"))
            .moment(beyond)
            .point_in_time_validation(false)
            .revocation_mode("none")
            .time_tolerance(Duration::from_secs(seconds))
            .build()
            .unwrap();
        let before = format!("{context:?}");
        let result = basic_validation_with_handlers(
            &bytes,
            Some(&digest),
            &context,
            &QualificationSpec::default(),
            &handlers,
        )
        .unwrap();
        intact_valid(&result);
        assert_eq!(
            trusted(&result),
            accepted,
            "actual validity/tolerance boundary: {result:?}"
        );
        assert_eq!(format!("{context:?}"), before);
    }
}
