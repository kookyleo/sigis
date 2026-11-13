//! Tests-first opt-in exact MAIN predicates through AdES entry points.
//! Existing recordings are retained reference inputs, not fresh oracle calls.
//! New assertions are supplemental; no additional upstream function credit.
mod common;

use common::*;
use serde_json::Value;
use sigis_cms::{SignatureStatus, StandardCmsSignatureStatus, TrustProblem};
use sigis_eutl::assess::QualificationRequirements;
use sigis_pades::ades::{
    basic::{basic_validation, basic_validation_with_options, QualificationSpec},
    lta::{
        lta_validation_with_ades_options, lta_validation_with_options,
        simulate_future_lta_validation, simulate_future_lta_validation_with_ades_options,
        LtaOptions, LtaValidationResult,
    },
    validate_pdf_ades, validate_pdf_ades_with_options,
    with_time::{with_time_validation, with_time_validation_with_options},
    AdesLevel, AdesValidationOptions,
};
use sigis_pdf::{EmbeddedSignature, PdfFile};
use sigis_pki_certvalidator::{
    ac::AcTargetDescription, authority::TrustManager, NonRevokedStatusAssertion, TrustAnchor,
    ValidationContext,
};
use sigis_pki_core::{
    algorithms::{
        AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm,
        DisallowWeakAlgorithmsPolicy,
    },
    cert::Cert,
    errors::FetchError,
    fetch::{FetcherBackend, Fetchers},
    key_usage::KeyUsageConstraints,
    time::Moment,
};
use std::{
    collections::BTreeSet,
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

const MODULE: &str = "test_ades_validation";
fn options(predicate: Option<KeyUsageConstraints>) -> AdesValidationOptions {
    let mut options = AdesValidationOptions::default();
    options.exact_key_usage_settings = predicate;
    options
}
fn empty() -> AdesValidationOptions {
    options(Some(KeyUsageConstraints::default()))
}
fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}
fn call(rec: &Recording, test: &str, function: &str) -> Call {
    rec.calls(MODULE, test)
        .into_iter()
        .find(|call| call.function() == function)
        .unwrap()
}
fn pdf(call: &Call) -> (PdfFile, EmbeddedSignature) {
    let (bytes, field) = call.pdf();
    let file = PdfFile::parse(&bytes).unwrap();
    let sig = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.field_name == field)
        .unwrap();
    (file, sig)
}
fn equal<T: fmt::Debug>(old: &T, new: &T, context: &str) {
    // Result structures include complete CMS/path/attributes/qualification and
    // timing. LTA POE uses a BTreeMap, so its complete Debug order is stable.
    assert_eq!(format!("{old:?}"), format!("{new:?}"), "{context}");
}
fn intact(status: &Option<StandardCmsSignatureStatus>) -> &StandardCmsSignatureStatus {
    let status = status.as_ref().unwrap();
    assert!(status.signature.intact && status.signature.valid);
    status
}
fn assert_ok(result: &LtaValidationResult) {
    assert_eq!(result.ades_subindic.standard_name(), "OK", "{result:?}");
    assert!(intact(&result.api_status).signature.trusted());
}
fn snapshot(ctx: &ValidationContext) -> String {
    format!("{ctx:?}")
}

#[test]
fn default_and_explicit_none_preserve_complete_basic_and_with_time_results() {
    let rec = Recording::load(MODULE);
    let basic = call(&rec, "test_pades_basic_happy_path", "ades_basic_validation");
    let timed = call(
        &rec,
        "test_embedded_cades_with_time_happy_path",
        "ades_with_time_validation",
    );
    for (input, is_time) in [(&basic, false), (&timed, true)] {
        let ctx = default_context(&rec, input);
        let before = snapshot(&ctx);
        let bytes = input.content_info();
        let raw = input.raw_digest();
        for opts in [AdesValidationOptions::default(), options(None)] {
            if is_time {
                let old = with_time_validation(
                    &bytes,
                    raw.as_deref(),
                    &ctx,
                    &QualificationSpec::default(),
                    None,
                )
                .unwrap();
                let new = with_time_validation_with_options(
                    &bytes,
                    raw.as_deref(),
                    &ctx,
                    &QualificationSpec::default(),
                    None,
                    &opts,
                )
                .unwrap();
                equal(&old, &new, "complete WithTime status/time/qualification");
                assert_eq!(new.ades_subindic.standard_name(), input.expected_subindic());
                assert!(intact(&new.api_status).signature.trusted());
            } else {
                let old =
                    basic_validation(&bytes, raw.as_deref(), &ctx, &QualificationSpec::default())
                        .unwrap();
                let new = basic_validation_with_options(
                    &bytes,
                    raw.as_deref(),
                    &ctx,
                    &QualificationSpec::default(),
                    &opts,
                )
                .unwrap();
                equal(&old, &new, "complete Basic status/path/qualification");
                assert_eq!(new.ades_subindic.standard_name(), input.expected_subindic());
            }
            assert_eq!(snapshot(&ctx), before);
        }
    }
}

#[test]
fn default_and_none_preserve_current_historical_lta_future_and_dispatcher_results() {
    let rec = Recording::load(MODULE);
    for test in [
        "test_pades_lta_happy_path_current_time",
        "test_pades_lta_happy_path_past_time",
        "test_pades_lta_happy_path_past_time_with_chain",
    ] {
        let input = call(&rec, test, "ades_lta_validation");
        let (file, sig) = pdf(&input);
        let ctx = default_context(&rec, &input);
        let before = snapshot(&ctx);
        let mut known =
            sigis_pki_certvalidator::ltv::poe::PoeManager::with_current_time(input.time());
        known.register(
            b"unrelated explicit caller proof",
            input.time(),
            sigis_pki_certvalidator::ltv::poe::PoeType::Provided,
        );
        let known_before = format!("{known:?}");
        let archival = LtaOptions {
            known_poes: Some(&known),
            ac_validation_context: Some(&ctx),
        };
        for opts in [AdesValidationOptions::default(), options(None)] {
            let old = lta_validation_with_options(
                &file,
                &sig,
                &ctx,
                &QualificationSpec::default(),
                &archival,
            )
            .unwrap();
            let new = lta_validation_with_ades_options(
                &file,
                &sig,
                &ctx,
                &QualificationSpec::default(),
                &archival,
                &opts,
            )
            .unwrap();
            equal(&old, &new, test);
            assert_eq!(new.ades_subindic.standard_name(), input.expected_subindic());
            assert_eq!(format!("{known:?}"), known_before);
            for level in [
                AdesLevel::Basic,
                AdesLevel::WithTimestamps,
                AdesLevel::LongTerm,
            ] {
                let old = validate_pdf_ades(&file, &sig, level, &ctx).unwrap();
                let new = validate_pdf_ades_with_options(&file, &sig, level, &ctx, &opts).unwrap();
                equal(
                    &old,
                    &new,
                    "dispatcher retains level-specific order/PDF guards",
                );
            }
            assert_eq!(snapshot(&ctx), before);
        }
    }
    for suffix in ["True", "False"] {
        let input = call(
            &rec,
            &format!("test_simulate_future_lta_happy_path[{suffix}]"),
            "simulate_future_ades_lta_validation",
        );
        let (file, sig) = pdf(&input);
        let ctx = default_context(&rec, &input);
        let before = snapshot(&ctx);
        let future = Moment::parse_rfc3339("2030-11-20T00:00:00Z").unwrap();
        for opts in [AdesValidationOptions::default(), options(None)] {
            let old = simulate_future_lta_validation(
                &file,
                &sig,
                &ctx,
                &QualificationSpec::default(),
                future,
            )
            .unwrap();
            let new = simulate_future_lta_validation_with_ades_options(
                &file,
                &sig,
                &ctx,
                &QualificationSpec::default(),
                future,
                &opts,
            )
            .unwrap();
            equal(&old, &new, "future whole result, POE and qualification");
            assert_eq!(new.ades_subindic.standard_name(), input.expected_subindic());
        }
        assert_eq!(snapshot(&ctx), before);
    }
}

#[test]
fn exact_main_does_not_waive_mandatory_qualification_or_timestamp_requirements() {
    let rec = Recording::load(MODULE);
    let input = call(
        &rec,
        "test_embedded_cades_with_time_happy_path",
        "ades_with_time_validation",
    );
    let ctx = default_context(&rec, &input);
    for (main, timestamp) in [
        (Some(QualificationRequirements::default()), None),
        (None, Some(QualificationRequirements::default())),
    ] {
        let qual = QualificationSpec {
            registry: None,
            requirements: main,
            ts_requirements: timestamp,
        };
        let result = with_time_validation_with_options(
            &input.content_info(),
            input.raw_digest().as_deref(),
            &ctx,
            &qual,
            None,
            &empty(),
        )
        .unwrap();
        assert_eq!(
            result.ades_subindic.standard_name(),
            "SIG_CONSTRAINTS_FAILURE"
        );
    }
}

#[test]
fn exact_empty_preserves_recorded_crypto_missing_poe_and_corrupt_chain_refusals() {
    let rec = Recording::load(MODULE);
    for (test, function, future) in [
        (
            "test_simulate_future_lta_no_revinfo_fail",
            "simulate_future_ades_lta_validation",
            Some("2030-11-20T00:00:00Z"),
        ),
        (
            "test_simulate_future_lta_with_broken_ts_chain",
            "simulate_future_ades_lta_validation",
            Some("2050-11-20T00:00:00Z"),
        ),
        (
            "test_nontraditional_hybrid_lta_with_failed_timestamp",
            "ades_lta_validation",
            None,
        ),
    ] {
        let input = call(&rec, test, function);
        let (file, sig) = pdf(&input);
        let ctx = default_context(&rec, &input);
        let before = snapshot(&ctx);
        let new = if let Some(at) = future {
            simulate_future_lta_validation_with_ades_options(
                &file,
                &sig,
                &ctx,
                &QualificationSpec::default(),
                Moment::parse_rfc3339(at).unwrap(),
                &empty(),
            )
        } else {
            lta_validation_with_ades_options(
                &file,
                &sig,
                &ctx,
                &QualificationSpec::default(),
                &LtaOptions::default(),
                &empty(),
            )
        }
        .unwrap();
        assert_eq!(
            new.ades_subindic.standard_name(),
            input.expected_subindic(),
            "{test}: {new:?}"
        );
        assert_ne!(new.ades_subindic.standard_name(), "OK");
        assert_eq!(snapshot(&ctx), before);
    }
    for test in [
        "test_embedded_cades_with_time_tampered_timestamp",
        "test_embedded_cades_with_time_sig_tampered_timestamp",
    ] {
        let input = call(&rec, test, "ades_with_time_validation");
        let result = with_time_validation_with_options(
            &input.content_info(),
            input.raw_digest().as_deref(),
            &default_context(&rec, &input),
            &QualificationSpec::default(),
            None,
            &empty(),
        )
        .unwrap();
        assert_eq!(
            result.ades_subindic.standard_name(),
            input.expected_subindic(),
            "{test}"
        );
        assert_ne!(result.ades_subindic.standard_name(), "OK");
    }
}

#[derive(Default)]
struct OwnerBackend {
    delegate: sigis_pki_fetch::HttpFetchers,
    close_calls: AtomicUsize,
    factory_calls: AtomicUsize,
}
impl fmt::Debug for OwnerBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExactOptionsOwnerBackend")
    }
}
impl FetcherBackend for OwnerBackend {
    fn get_fetchers(&self) -> Fetchers {
        self.factory_calls.fetch_add(1, Ordering::SeqCst);
        self.delegate.get_fetchers()
    }
    fn close(&self) -> Result<(), FetchError> {
        self.close_calls.fetch_add(1, Ordering::SeqCst);
        self.delegate.close()
    }
}
// Test-only observation around a real single-anchor lookup. The context has
// no static roots: this manager must actually supply the genuine recorded root.
struct RecordedAnchorManager {
    anchor: TrustAnchor,
    lookups: AtomicUsize,
}
impl fmt::Debug for RecordedAnchorManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordedAnchorManager")
            .field("anchor", &self.anchor)
            .finish()
    }
}
impl TrustManager for RecordedAnchorManager {
    fn as_trust_anchor(&self, certificate: &Cert) -> Option<TrustAnchor> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        (certificate == self.anchor.cert()).then(|| self.anchor.clone())
    }
    fn find_potential_issuers(&self, certificate: &Cert) -> Vec<TrustAnchor> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        if self.anchor.can_issue() && certificate.issuer() == self.anchor.cert().subject() {
            vec![self.anchor.clone()]
        } else {
            Vec::new()
        }
    }
}
#[derive(Default)]
struct ObservedPolicy {
    calls: Mutex<Vec<Option<Moment>>>,
}
impl fmt::Debug for ObservedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExactOptionsObservedDefaultPolicy")
    }
}
impl AlgorithmUsagePolicy for ObservedPolicy {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &const_oid::ObjectIdentifier,
        at: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        self.calls.lock().unwrap().push(at);
        DisallowWeakAlgorithmsPolicy::default().digest_algorithm_allowed(algorithm, at)
    }
    fn signature_algorithm_allowed(
        &self,
        algorithm: &spki::AlgorithmIdentifierOwned,
        at: Option<Moment>,
        key: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        self.calls.lock().unwrap().push(at);
        DisallowWeakAlgorithmsPolicy::default().signature_algorithm_allowed(algorithm, at, key)
    }
}
#[derive(Default)]
struct PhaseJudge {
    current: AtomicUsize,
    historical: AtomicUsize,
    reject_historical: bool,
}
impl fmt::Debug for PhaseJudge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExactOptionsPhaseJudge")
            .field("reject_historical", &self.reject_historical)
            .finish()
    }
}
impl sigis_pki_certvalidator::revinfo::freshness::FreshnessJudge for PhaseJudge {
    fn judge(
        &self,
        this: Option<Moment>,
        next: Option<Moment>,
        policy: &sigis_pki_certvalidator::policy::CertRevTrustPolicy,
        timing: &sigis_pki_certvalidator::policy::ValidationTimingParams,
    ) -> sigis_pki_certvalidator::revinfo::freshness::RevinfoUsability {
        use sigis_pki_certvalidator::revinfo::freshness::*;
        if timing.point_in_time_validation {
            self.historical.fetch_add(1, Ordering::SeqCst);
            if self.reject_historical {
                return RevinfoUsability {
                    rating: RevinfoUsabilityRating::Stale,
                    last_usable_at: Some(
                        timing
                            .validation_time
                            .minus(std::time::Duration::from_secs(86400)),
                    ),
                    compared_to: Some(timing.validation_time),
                };
            }
        } else {
            self.current.fetch_add(1, Ordering::SeqCst);
        }
        judge_revinfo(this, next, policy, timing)
    }
}

#[test]
fn options_preserve_complete_context_handles_owner_and_historical_freshness() {
    let rec = Recording::load(MODULE);
    let input = call(
        &rec,
        "test_pades_lta_happy_path_current_time",
        "ades_lta_validation",
    );
    let (file, sig) = pdf(&input);
    for reject in [false, true] {
        let backend = Arc::new(OwnerBackend::default());
        let policy: Arc<dyn AlgorithmUsagePolicy> = Arc::new(ObservedPolicy::default());
        let real_manager = Arc::new(RecordedAnchorManager {
            anchor: TrustAnchor::new(rec.cert("testing-ca", "root")),
            lookups: AtomicUsize::new(0),
        });
        let manager: Arc<dyn TrustManager> = real_manager.clone();
        let judge = Arc::new(PhaseJudge {
            reject_historical: reject,
            ..Default::default()
        });
        let ctx = ValidationContext::builder()
            .moment(input.time())
            .point_in_time_validation(false)
            .revinfo_policy(default_revinfo_policy())
            .time_tolerance(std::time::Duration::from_secs(1))
            .algorithm_policy(policy.clone())
            .trust_manager(manager.clone())
            .freshness_judge(judge.clone())
            .assertion(NonRevokedStatusAssertion {
                cert_sha256: [0xa5; 32],
                at: input.time(),
            })
            .acceptable_ac_targets(AcTargetDescription::default())
            .owned_fetcher_backend(backend.clone())
            // Real retained backend owns close authority; explicit recorded
            // providers win retrieval and must prevent factory invocation.
            .fetchers(input.fetchers())
            .build()
            .unwrap();
        assert_eq!(backend.factory_calls.load(Ordering::SeqCst), 0);
        assert!(ctx.trust_anchors().is_empty());
        let before = snapshot(&ctx);
        let result = lta_validation_with_ades_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            &LtaOptions::default(),
            &empty(),
        )
        .unwrap();
        if reject {
            assert_eq!(result.ades_subindic.standard_name(), "NO_POE");
        } else {
            assert_ok(&result);
        }
        assert!(judge.current.load(Ordering::SeqCst) > 0);
        assert!(judge.historical.load(Ordering::SeqCst) > 0);
        assert!(real_manager.lookups.load(Ordering::SeqCst) > 0);
        assert_eq!(backend.factory_calls.load(Ordering::SeqCst), 0);
        assert_eq!(snapshot(&ctx), before);
        assert!(Arc::ptr_eq(&policy, &ctx.algorithm_policy_arc()));
        assert!(Arc::ptr_eq(&manager, ctx.trust_manager().unwrap()));
        assert_eq!(ctx.non_revoked_status_assertions().len(), 1);
        assert_eq!(backend.close_calls.load(Ordering::SeqCst), 0);
        ctx.clone().close().unwrap();
        assert_eq!(backend.close_calls.load(Ordering::SeqCst), 1);
        ctx.with_timing(*ctx.timing())
            .with_fetchers(Fetchers::none())
            .close()
            .unwrap();
        assert_eq!(backend.close_calls.load(Ordering::SeqCst), 2);
    }
}

fn hash(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn fixture_manifest() -> (std::path::PathBuf, Value) {
    let dir = data(&["lanes", "r3-v", "ades-exact-options"]);
    let bytes = read_fixture(dir.join("manifest.json"));
    assert_eq!(
        hash(&bytes),
        "b0d4f18f3c32e07eba71c4bb28541466e82c7738527b1c1c0209244f568ce913"
    );
    let manifest: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(manifest["schema"], 1);
    assert_eq!(manifest["revocation_policy"], "REQUIRE_REVINFO");
    (dir, manifest)
}
fn new_fixture(name: &str, kind: &str) -> (Value, Value, PdfFile, EmbeddedSignature) {
    let (dir, manifest) = fixture_manifest();
    let row = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
        .clone();
    let asset = &row["files"][kind];
    let bytes = read_fixture(dir.join(asset["file"].as_str().unwrap()));
    assert_eq!(hash(&bytes), asset["sha256"].as_str().unwrap());
    assert_eq!(bytes.len() as u64, asset["length"].as_u64().unwrap());
    let file = PdfFile::parse(&bytes).unwrap();
    let all = file.embedded_signatures().unwrap();
    assert_eq!(
        all.iter()
            .filter(|sig| sig.kind == sigis_pdf::SignatureKind::DocTimeStamp)
            .count() as u64,
        asset["timestamp_count"].as_u64().unwrap()
    );
    let signature = all
        .into_iter()
        .find(|sig| sig.field_name == row["field_name"].as_str().unwrap())
        .unwrap();
    (manifest, row, file, signature)
}
fn fixture_context(manifest: &Value, file: &PdfFile, at: &str) -> ValidationContext {
    let ctx = ValidationContext::builder()
        .trust_root(Cert::from_der(&b64(manifest["root_der"].as_str().unwrap())).unwrap())
        .moment(Moment::parse_rfc3339(at).unwrap())
        .point_in_time_validation(false)
        .revinfo_policy(default_revinfo_policy())
        .build()
        .unwrap();
    let dss = file.dss().unwrap().unwrap_or_default();
    let certs: Vec<_> = dss
        .material
        .certs
        .iter()
        .map(|bytes| Cert::from_der(bytes).unwrap())
        .collect();
    let mut crls = dss.material.crls;
    for bytes in manifest["root_crls_by_time"][at]
        .as_array()
        .into_iter()
        .flatten()
    {
        crls.push(b64(bytes.as_str().unwrap()));
    }
    ctx.with_revinfo(
        &certs,
        crls.iter().map(Vec::as_slice),
        dss.material.ocsps.iter().map(Vec::as_slice),
    )
    .unwrap()
}
fn fixture_poes(manifest: &Value, now: Moment) -> sigis_pki_certvalidator::ltv::poe::PoeManager {
    use sigis_pki_certvalidator::ltv::poe::{PoeManager, PoeType};
    let mut known = PoeManager::with_current_time(now);
    for row in manifest["known_poes"].as_array().unwrap() {
        known.register_by_digest(
            b64(row["digest"].as_str().unwrap()),
            Moment::parse_rfc3339(row["time"].as_str().unwrap()).unwrap(),
            PoeType::Provided,
        );
    }
    known
}
fn signature_json(status: &SignatureStatus) -> Value {
    serde_json::json!({"intact":status.intact,"valid":status.valid,"trusted":status.trusted(),
        "validation_time":status.validation_time.map(|time|time.to_string()),
        "path":status.validation_path.as_ref().map(|path|path.certs().iter().map(|cert|hash(cert.der())).collect::<Vec<_>>()),
        "trust_problem":format!("{:?}",status.trust_problem),"subindication":status.trust_problem_indic.map(|value|value.standard_name()),
        "error_time_horizon":status.error_time_horizon.map(|time|time.to_string()),
        "signing_cert_sha256":status.signing_cert.as_ref().map(|cert|hash(cert.der()))})
}
fn export_fixture(
    labels: (&str, &str),
    file: &PdfFile,
    manifest: &Value,
    context_and_known: (
        &ValidationContext,
        Option<&sigis_pki_certvalidator::ltv::poe::PoeManager>,
    ),
    selected: &AdesValidationOptions,
    result: &LtaValidationResult,
    future: Option<Moment>,
) {
    export_fixture_with_policy_profile(
        labels,
        file,
        manifest,
        context_and_known,
        selected,
        result,
        (future, None),
    );
}
fn export_fixture_with_policy_profile(
    labels: (&str, &str),
    file: &PdfFile,
    manifest: &Value,
    context_and_known: (
        &ValidationContext,
        Option<&sigis_pki_certvalidator::ltv::poe::PoeManager>,
    ),
    selected: &AdesValidationOptions,
    result: &LtaValidationResult,
    temporal_and_policy: (Option<Moment>, Option<Value>),
) {
    let (entry, name) = labels;
    let (ctx, known) = context_and_known;
    let (future, policy_profile) = temporal_and_policy;
    use base64::Engine;
    let Some(directory) = std::env::var_os("HANKO_ADES_EXACT_OUTPUT_DIR") else {
        return;
    };
    let predicate = selected.exact_key_usage_settings.as_ref().map(|policy| serde_json::json!({
        "key_usage":policy.key_usage,"key_usage_forbidden":policy.key_usage_forbidden,"extd_key_usage":policy.extd_key_usage,
        "explicit_extd_key_usage_required":policy.explicit_extd_key_usage_required,"match_all_key_usages":policy.match_all_key_usages}));
    let row = serde_json::json!({"schema":1,"entry":entry,"case":name,
        "cohort":if policy_profile.is_some() { "custom_main_key_timed_algorithm_policy" } else { "exact_default_algorithm_local_required_revinfo_no_qualification" },
        "algorithm_policy_profile":policy_profile,"input_sha256":hash(file.bytes()),
        "context_crls_b64":ctx.crls().map(|bytes|base64::engine::general_purpose::STANDARD.encode(bytes)).collect::<Vec<_>>(),
        "context_ocsps_b64":ctx.ocsps().map(|bytes|base64::engine::general_purpose::STANDARD.encode(bytes)).collect::<Vec<_>>(),
        "context_other_certs_b64":ctx.other_certs().iter().map(|cert|base64::engine::general_purpose::STANDARD.encode(cert.der())).collect::<Vec<_>>(),
        "context_roots_b64":ctx.trust_anchors().iter().map(|anchor|base64::engine::general_purpose::STANDARD.encode(anchor.cert().der())).collect::<Vec<_>>(),
        "has_roots":!ctx.trust_anchors().is_empty(),"collection_time":ctx.moment().to_string(),"future_target_time":future.map(|time|time.to_string()),
        "known_poes":known.map(|manager|manager.iter().map(|poe|serde_json::json!({"digest":base64::engine::general_purpose::STANDARD.encode(poe.digest),"time":poe.poe_time.to_string(),"kind":format!("{:?}",poe.poe_type)})).collect::<Vec<_>>()),
        "context_revocation_policy":{"ee":format!("{:?}",ctx.revinfo_policy().revocation_checking_policy.ee_certificate_rule),"intermediate":format!("{:?}",ctx.revinfo_policy().revocation_checking_policy.intermediate_ca_cert_rule),
            "freshness_req_type":format!("{:?}",ctx.revinfo_policy().freshness_req_type),"freshness_seconds":ctx.revinfo_policy().freshness.map(|time|time.as_secs()),"retroactive_revinfo":ctx.revinfo_policy().retroactive_revinfo},
        "time_tolerance_seconds":ctx.timing().time_tolerance.as_secs(),
        "pdf_b64":base64::engine::general_purpose::STANDARD.encode(file.bytes()),"pdf_sha256":hash(file.bytes()),
        "root_b64":manifest["root_der"],"root_sha256":hash(&b64(manifest["root_der"].as_str().unwrap())),
        "predicate":predicate,"validation_time":ctx.moment().to_string(),"point_in_time_validation":ctx.timing().point_in_time_validation,
        "native":{"final_subindication":result.ades_subindic.standard_name(),"main":result.api_status.as_ref().map(|status|signature_json(&status.signature)),
            "api_bottom_line":result.api_status.as_ref().map(|status|status.bottom_line()),
            "timestamp":result.api_status.as_ref().and_then(|status|status.timestamp_validity.as_ref()).map(|ts|signature_json(&ts.signature)),
            "best_signature_time":result.best_signature_time.map(|time|time.to_string()),"qualification":format!("{:?}",result.qualification),
            "failure_msg":result.failure_msg,"poe":result.poe.iter().map(|poe|serde_json::json!({"digest":base64::engine::general_purpose::STANDARD.encode(poe.digest),"time":poe.poe_time.to_string(),"kind":format!("{:?}",poe.poe_type)})).collect::<Vec<_>>()}});
    let bytes = serde_json::to_vec_pretty(&row).unwrap();
    let directory = std::path::PathBuf::from(directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("{}.json", hash(&bytes)));
    std::fs::write(&path, &bytes).unwrap();
    eprintln!(
        "ADES_EXACT_NATIVE_EXPORT {}",
        serde_json::json!({"path":path,"sha256":hash(&bytes),"length":bytes.len(),"pdf_sha256":hash(file.bytes())})
    );
}

#[test]
fn genuine_digital_only_predicate_survives_final_historical_main_recheck() {
    use sigis_pki_core::errors::ValidationError;
    let (manifest, row, file, sig) = new_fixture("digital_signature_only", "archived");
    let leaf = Cert::from_der(&b64(row["signer_der"].as_str().unwrap())).unwrap();
    assert_eq!(
        sigis_pki_core::key_usage::cert_key_usages(&leaf).unwrap(),
        names(&["digital_signature"])
    );
    assert!(sigis_pki_core::key_usage::cert_extended_key_usages(&leaf).is_none());
    for time_key in ["validation_time", "future_validation_time"] {
        let at = manifest[time_key].as_str().unwrap();
        let ctx = fixture_context(&manifest, &file, at);
        let before = snapshot(&ctx);
        let known = fixture_poes(&manifest, ctx.moment());
        let archival = LtaOptions {
            known_poes: Some(&known),
            ..Default::default()
        };
        let predicates = vec![
            ("unrestricted", KeyUsageConstraints::default(), true),
            (
                "empty_ku",
                KeyUsageConstraints {
                    key_usage: Some(BTreeSet::new()),
                    ..Default::default()
                },
                true,
            ),
            (
                "all_five_matching",
                KeyUsageConstraints {
                    key_usage: Some(names(&["digital_signature"])),
                    key_usage_forbidden: Some(names(&["non_repudiation"])),
                    extd_key_usage: Some(names(&["server_auth"])),
                    explicit_extd_key_usage_required: false,
                    match_all_key_usages: true,
                },
                true,
            ),
            (
                "required_nr",
                KeyUsageConstraints {
                    key_usage: Some(names(&["non_repudiation"])),
                    ..Default::default()
                },
                false,
            ),
            (
                "forbidden_ds",
                KeyUsageConstraints {
                    key_usage_forbidden: Some(names(&["digital_signature"])),
                    ..Default::default()
                },
                false,
            ),
            (
                "match_all",
                KeyUsageConstraints {
                    key_usage: Some(names(&["digital_signature", "non_repudiation"])),
                    match_all_key_usages: true,
                    ..Default::default()
                },
                false,
            ),
            (
                "required_eku",
                KeyUsageConstraints {
                    extd_key_usage: Some(names(&["server_auth"])),
                    explicit_extd_key_usage_required: true,
                    ..Default::default()
                },
                false,
            ),
            (
                "empty_eku",
                KeyUsageConstraints {
                    extd_key_usage: Some(BTreeSet::new()),
                    ..Default::default()
                },
                false,
            ),
        ];
        for (name, predicate, permitted) in predicates {
            let initial_options = sigis_cms::CmsValidationOptions {
                validation_order: sigis_cms::CmsValidationOrder::SignerFirst,
                exact_key_usage_settings: Some(predicate.clone()),
                ..Default::default()
            };
            let initial = sigis_cms::validate_cms_signature_with(
                &sig.contents,
                sigis_cms::SignedContent::Data(&sig.signed_data(&file).unwrap()),
                &ctx,
                &initial_options,
            )
            .unwrap();
            assert!(initial.signature.intact && initial.signature.valid);
            // The late path fails validity BEFORE usage. A predicate failure
            // cannot satisfy this assertion in the initial stage.
            assert!(
                matches!(
                    initial.signature.trust_problem,
                    Some(TrustProblem::Path(ValidationError::Expired { .. }))
                ),
                "{name}: {:?}",
                initial.signature
            );
            let selected = options(Some(predicate));
            let result = lta_validation_with_ades_options(
                &file,
                &sig,
                &ctx,
                &QualificationSpec::default(),
                &archival,
                &selected,
            )
            .unwrap();
            let final_api = intact(&result.api_status);
            assert!(
                final_api.signature.validation_time.unwrap() < ctx.moment(),
                "must reach actual historical CMS recheck: {result:?}"
            );
            assert_eq!(
                result.best_signature_time,
                Some(Moment::parse_rfc3339(manifest["signed_at"].as_str().unwrap()).unwrap())
            );
            if permitted {
                assert_ok(&result);
            } else {
                assert_eq!(
                    result.ades_subindic.standard_name(),
                    "CHAIN_CONSTRAINTS_FAILURE",
                    "{name}: {result:?}"
                );
                assert!(matches!(
                    final_api.signature.trust_problem,
                    Some(TrustProblem::KeyUsage(_))
                ));
                assert!(!final_api.signature.trusted());
            }
            export_fixture(
                ("lta_validation_with_ades_options", name),
                &file,
                &manifest,
                (&ctx, Some(&known)),
                &selected,
                &result,
                None,
            );
            assert_eq!(snapshot(&ctx), before);
        }
    }
}

#[test]
fn future_simulation_rechecks_the_exact_predicate_at_its_actual_control_time() {
    let (manifest, _, file, sig) = new_fixture("digital_signature_only", "archived");
    // Use genuinely collected 2024 revocation evidence within its signed
    // validity window. This is a strict future simulation, without inventing
    // a future TSA nonrevocation assertion or a POE for context-only CRLs.
    let collected_at = manifest["validation_time"].as_str().unwrap();
    let ctx = fixture_context(&manifest, &file, collected_at);
    let before = snapshot(&ctx);
    let future = ctx.moment().plus(std::time::Duration::from_secs(86400));
    assert!(future > ctx.moment());
    let root_crl_der = b64(manifest["root_crls_by_time"][collected_at]
        .as_array()
        .unwrap()
        .first()
        .unwrap()
        .as_str()
        .unwrap());
    assert_eq!(
        hash(&root_crl_der),
        manifest["root_crls"][collected_at]["sha256"]
            .as_str()
            .unwrap()
    );
    let root_crl = sigis_pki_certvalidator::revinfo::CrlContainer::from_der(&root_crl_der).unwrap();
    assert!(root_crl.this_update() <= ctx.moment());
    assert!(future < root_crl.next_update().unwrap());
    let legacy =
        simulate_future_lta_validation(&file, &sig, &ctx, &QualificationSpec::default(), future)
            .unwrap();
    assert_eq!(
        legacy.ades_subindic.standard_name(),
        "CHAIN_CONSTRAINTS_FAILURE"
    );
    for selected in [AdesValidationOptions::default(), options(None)] {
        let unchanged = simulate_future_lta_validation_with_ades_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            future,
            &selected,
        )
        .unwrap();
        equal(
            &legacy,
            &unchanged,
            "DS-only near-future keeps ordinary NR default; exact None is not empty",
        );
    }
    for (predicate, accepted) in [
        (KeyUsageConstraints::default(), true),
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
    ] {
        let selected = options(Some(predicate));
        let result = simulate_future_lta_validation_with_ades_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            future,
            &selected,
        )
        .unwrap();
        let status = intact(&result.api_status);
        assert!(
            status.signature.validation_time.unwrap() < ctx.moment(),
            "must perform final recheck before evidence collection: {result:?}"
        );
        assert_eq!(
            result.best_signature_time,
            Some(Moment::parse_rfc3339(manifest["signed_at"].as_str().unwrap()).unwrap())
        );
        if accepted {
            assert_ok(&result);
        } else {
            assert_eq!(
                result.ades_subindic.standard_name(),
                "CHAIN_CONSTRAINTS_FAILURE"
            );
            assert!(matches!(
                status.signature.trust_problem,
                Some(TrustProblem::KeyUsage(_))
            ));
            assert!(!status.signature.trusted());
        }
        export_fixture(
            (
                "simulate_future_lta_validation_with_ades_options",
                "digital_signature_only",
            ),
            &file,
            &manifest,
            (&ctx, None),
            &selected,
            &result,
            Some(future),
        );
    }
    assert_eq!(snapshot(&ctx), before);
    assert!(simulate_future_lta_validation_with_ades_options(
        &file,
        &sig,
        &ctx,
        &QualificationSpec::default(),
        ctx.moment().minus(std::time::Duration::from_secs(1)),
        &empty()
    )
    .is_err());
}

#[test]
fn corrupt_document_imprint_cannot_create_material_poe_or_replace_explicit_knowledge() {
    use sigis_pki_certvalidator::ltv::poe::PoeType;
    for kind in ["archived", "no_poe", "corrupt_imprint"] {
        let (manifest, row, file, sig) = new_fixture("digital_signature_only", kind);
        let ctx = fixture_context(&manifest, &file, manifest["signed_at"].as_str().unwrap());
        let mut known = fixture_poes(&manifest, ctx.moment());
        known.register(
            b"independent provided evidence",
            ctx.moment(),
            PoeType::Provided,
        );
        let before = format!("{known:?}");
        if kind == "corrupt_imprint" {
            let timestamp = file
                .embedded_signatures()
                .unwrap()
                .into_iter()
                .find(|s| s.kind == sigis_pdf::SignatureKind::DocTimeStamp)
                .unwrap();
            let checked = sigis_pades::validate_pdf_timestamp(&file, &timestamp, &ctx).unwrap();
            assert!(
                checked.timestamp.signature.valid,
                "genuine TSA signature is separate from wrong imprint"
            );
            assert!(!checked.timestamp.signature.intact && !checked.timestamp.trusted());
        }
        let selected = empty();
        let result = lta_validation_with_ades_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            &LtaOptions {
                known_poes: Some(&known),
                ..Default::default()
            },
            &selected,
        )
        .unwrap();
        let leaf = b64(row["signer_der"].as_str().unwrap());
        assert_eq!(
            result.poe.get(&leaf).is_some(),
            kind == "archived",
            "{kind}: only authenticated enclosing material proves the leaf"
        );
        assert_eq!(
            result.poe.get(b"independent provided evidence"),
            Some((ctx.moment(), PoeType::Provided))
        );
        assert_eq!(format!("{known:?}"), before);
        // No-DTS and corrupt-DTS public reference inputs can retain a valid
        // current main signature. Assert POE structure, not an invented oracle
        // final refusal. Historical refusal originals remain separate above.
        export_fixture(
            ("lta_structural_poe_control", kind),
            &file,
            &manifest,
            (&ctx, Some(&known)),
            &selected,
            &result,
            None,
        );
    }
}

#[test]
fn exact_main_preserves_pdf_coverage_modification_and_mandatory_seed_guards() {
    let dir = data(&["lanes", "r3-v", "integrity"]);
    let manifest: Value = serde_json::from_slice(&read_fixture(dir.join("manifest.json"))).unwrap();
    let ctx = ValidationContext::builder()
        .trust_root(Cert::from_der(&b64(manifest["trust_root"].as_str().unwrap())).unwrap())
        .moment(Moment::parse_rfc3339(manifest["validation_time"].as_str().unwrap()).unwrap())
        .revocation_mode("soft-fail")
        .algorithm_policy(Arc::new(
            DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&[]),
        ))
        .build()
        .unwrap();
    for name in [
        "clean-signature.pdf",
        "page-modified.pdf",
        "tail-uncovered.pdf",
        "signature-gap-too-big.pdf",
        "one-byterange.pdf",
        "weird-byterange.pdf",
    ] {
        let anomalous = name != "clean-signature.pdf" && name != "page-modified.pdf";
        let path = if anomalous {
            data(&["pyhanko", "pdf", "coverage-anomalies", name])
        } else {
            dir.join(name)
        };
        let file = PdfFile::parse(&read_fixture(path)).unwrap();
        let sig = file.embedded_signatures().unwrap().remove(0);
        let selected_context = if anomalous {
            let sd = sigis_cms::SignedData::from_der(&sig.contents).unwrap();
            let signer = sigis_cms::signed_data::extract_certificate_info(&sd)
                .unwrap()
                .signer_cert;
            // Same explicit direct-signer trust as the accepted coverage guard:
            // the anomaly cannot be satisfied by the unrelated sample PKI.
            ValidationContext::builder()
                .trust_root(signer)
                .moment(ctx.moment())
                .revocation_mode("soft-fail")
                .algorithm_policy(Arc::new(
                    DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&[]),
                ))
                .build()
                .unwrap()
        } else {
            ctx.clone()
        };
        let before = snapshot(&selected_context);
        let raw = sigis_cms::validate_cms_signature_with(
            &sig.contents,
            sigis_cms::SignedContent::Data(&sig.signed_data(&file).unwrap()),
            &selected_context,
            &sigis_cms::CmsValidationOptions {
                exact_key_usage_settings: Some(KeyUsageConstraints::default()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            raw.signature.intact && raw.signature.valid && raw.signature.trusted(),
            "{name}"
        );
        let result = validate_pdf_ades_with_options(
            &file,
            &sig,
            AdesLevel::Basic,
            &selected_context,
            &empty(),
        )
        .unwrap();
        if name == "clean-signature.pdf" {
            assert_eq!(result.status, sigis_pades::ades::AdesStatus::Passed);
        } else {
            assert_ne!(
                result.status,
                sigis_pades::ades::AdesStatus::Passed,
                "{name}"
            );
        }
        assert_eq!(snapshot(&selected_context), before);
    }
    let dir = data(&["lanes", "r3-v", "seed"]);
    let manifest: Value = serde_json::from_slice(&read_fixture(dir.join("manifest.json"))).unwrap();
    let row = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "digest_required_sha1_reject")
        .unwrap();
    let file = PdfFile::parse(&read_fixture(dir.join(row["file"].as_str().unwrap()))).unwrap();
    let sig = file.embedded_signatures().unwrap().remove(0);
    let ctx = ValidationContext::builder()
        .trust_root(Cert::from_der(&b64(manifest["trust_root"].as_str().unwrap())).unwrap())
        .moment(Moment::parse_rfc3339(manifest["validation_time"].as_str().unwrap()).unwrap())
        .revocation_mode("soft-fail")
        .algorithm_policy(Arc::new(
            DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&[]),
        ))
        .build()
        .unwrap();
    let raw = sigis_cms::validate_cms_signature_with(
        &sig.contents,
        sigis_cms::SignedContent::Data(&sig.signed_data(&file).unwrap()),
        &ctx,
        &sigis_cms::CmsValidationOptions {
            exact_key_usage_settings: Some(KeyUsageConstraints::default()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(raw.signature.intact && raw.signature.valid && raw.signature.trusted());
    for level in [
        AdesLevel::Basic,
        AdesLevel::WithTimestamps,
        AdesLevel::LongTerm,
    ] {
        let result = validate_pdf_ades_with_options(&file, &sig, level, &ctx, &empty()).unwrap();
        assert_ne!(result.status, sigis_pades::ades::AdesStatus::Passed);
    }
}

#[test]
fn exact_main_never_turns_failed_attribute_authority_evidence_into_roles() {
    let dir = data(&["lanes", "r3-v", "adobe-ria"]);
    let manifest: Value = serde_json::from_slice(&read_fixture(dir.join("oracle.json"))).unwrap();
    let root = Cert::from_der(&read_fixture(dir.join("root.der"))).unwrap();
    let aa_root = Cert::from_der(&read_fixture(dir.join("root-aa.der"))).unwrap();
    for name in ["good", "forged-crl"] {
        let row = &manifest["cases"][name];
        let bytes = read_fixture(dir.join(row["pdf"].as_str().unwrap()));
        assert_eq!(hash(&bytes), row["sha256"].as_str().unwrap());
        let file = PdfFile::parse(&bytes).unwrap();
        let sig = file.embedded_signatures().unwrap().remove(0);
        let build = |anchor: Cert| {
            ValidationContext::builder()
                .trust_root(anchor)
                .moment(Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap())
                .revinfo_policy(default_revinfo_policy())
                .build()
                .unwrap()
        };
        let ctx = build(root.clone());
        let ac = build(aa_root.clone());
        let before = (snapshot(&ctx), snapshot(&ac));
        let archival = LtaOptions {
            ac_validation_context: Some(&ac),
            ..Default::default()
        };
        let old = lta_validation_with_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            &archival,
        )
        .unwrap();
        let new = lta_validation_with_ades_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            &archival,
            &empty(),
        )
        .unwrap();
        equal(
            &old,
            &new,
            "exact main predicate preserves actual AC trust result",
        );
        assert_eq!(
            new.ades_subindic.standard_name(),
            row["subindication"].as_str().unwrap()
        );
        let status = intact(&new.api_status);
        if name == "good" {
            assert!(status.ac_attrs.as_ref().unwrap().get("role").is_some());
        } else {
            assert!(status
                .ac_attrs
                .as_ref()
                .is_none_or(|attrs| attrs.get("role").is_none()));
            assert!(!status.ac_validation_errs.as_ref().unwrap().is_empty());
        }
        assert_eq!((snapshot(&ctx), snapshot(&ac)), before);
    }
}

#[test]
fn none_keeps_assessed_signer_and_timestamp_qualification_with_real_registry() {
    use sigis_eutl::{parse::trust_list_to_registry, tsp::TspTrustManager};
    let rec = Recording::load(MODULE);
    let id = "test_embedded_cades_with_time_happy_path_with_tl[True]";
    let input = call(&rec, id, "ades_with_time_validation");
    let tl = rec.0["generated_tls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["nodeid"].as_str().unwrap().ends_with(id))
        .unwrap();
    let registry = trust_list_to_registry(
        tl["xml"].as_str().unwrap(),
        &[rec.cert("testing-ca-qualified", "root")],
        None,
        None,
    )
    .unwrap()
    .0;
    let mut builder = ValidationContext::builder()
        .moment(input.time())
        .revinfo_policy(default_revinfo_policy())
        .fetchers(input.fetchers());
    for anchor in TspTrustManager::new(&registry).trust_anchors_at(input.time()) {
        builder = builder.trust_anchor(anchor);
    }
    let ctx = builder.build().unwrap();
    let before = snapshot(&ctx);
    let qual = QualificationSpec {
        registry: Some(&registry),
        requirements: Some(QualificationRequirements::default()),
        ts_requirements: Some(QualificationRequirements::default()),
    };
    let bytes = input.content_info();
    let raw = input.raw_digest();
    let old = with_time_validation(&bytes, raw.as_deref(), &ctx, &qual, None).unwrap();
    assert!(old.qualification.is_some() && old.timestamp_qualification.is_some());
    for opts in [AdesValidationOptions::default(), options(None)] {
        let new =
            with_time_validation_with_options(&bytes, raw.as_deref(), &ctx, &qual, None, &opts)
                .unwrap();
        equal(
            &old,
            &new,
            "assessed nonempty qualification and actual registry",
        );
        assert_eq!(new.ades_subindic.standard_name(), "OK");
        assert_eq!(snapshot(&ctx), before);
    }
}

#[derive(Debug)]
struct DeniedDigest {
    cutoff: Option<Moment>,
    only_sha512: bool,
}
impl AlgorithmUsagePolicy for DeniedDigest {
    fn digest_algorithm_allowed(
        &self,
        oid: &const_oid::ObjectIdentifier,
        at: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        if self.only_sha512 && *oid != DigestAlgorithm::Sha512.oid() {
            return DisallowWeakAlgorithmsPolicy::default().digest_algorithm_allowed(oid, at);
        }
        AlgorithmUsageConstraint {
            allowed: false,
            not_allowed_after: self.cutoff,
            failure_reason: Some("denied; diagnostic date 2099-01-01 is not policy".into()),
        }
    }
    fn signature_algorithm_allowed(
        &self,
        algorithm: &spki::AlgorithmIdentifierOwned,
        at: Option<Moment>,
        key: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        DisallowWeakAlgorithmsPolicy::default().signature_algorithm_allowed(algorithm, at, key)
    }
}

#[test]
fn exact_main_keeps_no_root_required_revinfo_and_typed_algorithm_refusals() {
    let rec = Recording::load(MODULE);
    let input = call(
        &rec,
        "test_pades_lta_happy_path_current_time",
        "ades_lta_validation",
    );
    let (file, sig) = pdf(&input);
    let baseline = default_context(&rec, &input);
    assert_ok(
        &lta_validation_with_ades_options(
            &file,
            &sig,
            &baseline,
            &QualificationSpec::default(),
            &LtaOptions::default(),
            &empty(),
        )
        .unwrap(),
    );
    let no_root = ValidationContext::builder()
        .moment(input.time())
        .revinfo_policy(default_revinfo_policy())
        .fetchers(input.fetchers())
        .build()
        .unwrap();
    let no_root_result = lta_validation_with_ades_options(
        &file,
        &sig,
        &no_root,
        &QualificationSpec::default(),
        &LtaOptions::default(),
        &empty(),
    )
    .unwrap();
    assert_ne!(no_root_result.ades_subindic.standard_name(), "OK");
    assert!(!intact(&no_root_result.api_status).signature.trusted());
    let missing = call(
        &rec,
        "test_simulate_future_lta_no_revinfo_fail",
        "simulate_future_ades_lta_validation",
    );
    let (missing_file, missing_sig) = pdf(&missing);
    assert!(missing_file.dss().unwrap().is_none());
    let require = ValidationContext::builder()
        .trust_root(rec.cert("testing-ca", "root"))
        .moment(input.time())
        .revinfo_policy(default_revinfo_policy())
        .build()
        .unwrap();
    let no_evidence = lta_validation_with_ades_options(
        &missing_file,
        &missing_sig,
        &require,
        &QualificationSpec::default(),
        &LtaOptions::default(),
        &empty(),
    )
    .unwrap();
    assert_ne!(no_evidence.ades_subindic.standard_name(), "OK");
    assert!(!intact(&no_evidence.api_status).signature.trusted());
    for cutoff in [
        None,
        Some(Moment::parse_rfc3339("2019-12-31T23:59:59Z").unwrap()),
    ] {
        let ctx = ValidationContext::builder()
            .trust_root(rec.cert("testing-ca", "root"))
            .moment(input.time())
            .revinfo_policy(default_revinfo_policy())
            .fetchers(input.fetchers())
            .algorithm_policy(Arc::new(DeniedDigest {
                cutoff,
                only_sha512: false,
            }))
            .build()
            .unwrap();
        let before = snapshot(&ctx);
        let result = lta_validation_with_ades_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            &LtaOptions::default(),
            &empty(),
        )
        .unwrap();
        let status = intact(&result.api_status);
        assert!(!status.signature.trusted());
        assert_eq!(status.signature.error_time_horizon, cutoff);
        assert!(
            matches!(&status.signature.trust_problem,Some(TrustProblem::Path(sigis_pki_core::errors::ValidationError::DisallowedAlgorithm{banned_since,..})) if *banned_since==cutoff)
        );
        assert_eq!(
            result.ades_subindic.standard_name(),
            if cutoff.is_some() {
                "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"
            } else {
                "CRYPTO_CONSTRAINTS_FAILURE"
            }
        );
        assert_eq!(snapshot(&ctx), before);
    }
}

#[test]
fn exact_main_does_not_turn_a_denied_timestamp_imprint_into_early_signature_poe() {
    use sigis_pki_certvalidator::ltv::poe::{PoeManager, PoeType};
    let dir = data(&["lanes", "r3-v", "poe-policy"]);
    let manifest: Value = serde_json::from_slice(&read_fixture(dir.join("manifest.json"))).unwrap();
    let bytes = read_fixture(dir.join(manifest["file"].as_str().unwrap()));
    assert_eq!(hash(&bytes), manifest["pdf_sha256"].as_str().unwrap());
    let file = PdfFile::parse(&bytes).unwrap();
    let sig = file.embedded_signatures().unwrap().remove(0);
    let now = Moment::parse_rfc3339(manifest["validation_time"].as_str().unwrap()).unwrap();
    let base = ValidationContext::builder()
        .trust_root(Cert::from_der(&b64(manifest["trust_root"].as_str().unwrap())).unwrap())
        .moment(now)
        .revinfo_policy(default_revinfo_policy())
        .algorithm_policy(Arc::new(DeniedDigest {
            cutoff: None,
            only_sha512: true,
        }))
        .build()
        .unwrap();
    let dss = file.dss().unwrap().unwrap();
    let certs: Vec<_> = dss
        .material
        .certs
        .iter()
        .map(|bytes| Cert::from_der(bytes).unwrap())
        .collect();
    let crls: Vec<_> = dss
        .material
        .crls
        .into_iter()
        .chain(
            manifest["current_crls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| b64(row.as_str().unwrap())),
        )
        .collect();
    let ocsps: Vec<_> = dss
        .material
        .ocsps
        .into_iter()
        .chain(
            manifest["current_ocsps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| b64(row.as_str().unwrap())),
        )
        .collect();
    let ctx = base
        .with_revinfo(
            &certs,
            crls.iter().map(Vec::as_slice),
            ocsps.iter().map(Vec::as_slice),
        )
        .unwrap();
    let case = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "default_policy")
        .unwrap();
    let mut known = PoeManager::with_current_time(now);
    for row in case["known_poes"].as_array().unwrap() {
        known.register_by_digest(
            b64(row["digest"].as_str().unwrap()),
            Moment::parse_rfc3339(row["time"].as_str().unwrap()).unwrap(),
            PoeType::Provided,
        );
    }
    let result = lta_validation_with_ades_options(
        &file,
        &sig,
        &ctx,
        &QualificationSpec::default(),
        &LtaOptions {
            known_poes: Some(&known),
            ..Default::default()
        },
        &empty(),
    )
    .unwrap();
    let cms = sigis_cms::SignedData::from_der(&sig.contents).unwrap();
    let signature = &cms.signer_infos[0].signature;
    assert_ne!(result.ades_subindic.standard_name(), "OK");
    assert_eq!(result.best_signature_time, Some(now));
    assert!(result.poe.get(signature).is_none());
    assert_eq!(result.poe.poe_time(signature), now);
}

#[test]
fn far_future_stale_timestamp_remains_an_explicit_refusal_with_exact_empty() {
    use sigis_pki_core::errors::ValidationError;
    let (manifest, _, file, sig) = new_fixture("digital_signature_only", "archived");
    let ctx = fixture_context(&manifest, &file, manifest["signed_at"].as_str().unwrap());
    let before = snapshot(&ctx);
    let future =
        Moment::parse_rfc3339(manifest["future_validation_time"].as_str().unwrap()).unwrap();
    let legacy =
        simulate_future_lta_validation(&file, &sig, &ctx, &QualificationSpec::default(), future)
            .unwrap();
    for selected in [AdesValidationOptions::default(), options(None), empty()] {
        let result = simulate_future_lta_validation_with_ades_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            future,
            &selected,
        )
        .unwrap();
        if selected.exact_key_usage_settings.is_none() {
            equal(
                &legacy,
                &result,
                "far-future old/default/None whole-result equality",
            );
        }
        assert_eq!(
            result.ades_subindic.standard_name(),
            "TRY_LATER",
            "{result:?}"
        );
        let status = intact(&result.api_status);
        assert_eq!(status.signature.validation_time, Some(future));
        let timestamp = status.timestamp_validity.as_ref().unwrap();
        assert!(timestamp.signature.intact && timestamp.signature.valid);
        assert!(!timestamp.signature.trusted());
        assert!(matches!(
            timestamp.signature.trust_problem,
            Some(TrustProblem::Path(ValidationError::StaleRevinfo { .. }))
        ));
        export_fixture(
            (
                "simulate_future_lta_validation_with_ades_options",
                "digital_signature_only_far_future_stale_timestamp",
            ),
            &file,
            &manifest,
            (&ctx, None),
            &selected,
            &result,
            Some(future),
        );
        assert_eq!(snapshot(&ctx), before);
    }
}

struct MainKeyTimedPolicy {
    main_key: spki::SubjectPublicKeyInfoOwned,
    cutoff: Moment,
    main_calls: Mutex<Vec<Option<Moment>>>,
}
impl fmt::Debug for MainKeyTimedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Observation is external to the validation context state.
        f.debug_struct("ExactOptionsMainKeyTimedPolicy")
            .field("cutoff", &self.cutoff)
            .finish()
    }
}
impl AlgorithmUsagePolicy for MainKeyTimedPolicy {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &const_oid::ObjectIdentifier,
        at: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        DisallowWeakAlgorithmsPolicy::default().digest_algorithm_allowed(algorithm, at)
    }
    fn signature_algorithm_allowed(
        &self,
        algorithm: &spki::AlgorithmIdentifierOwned,
        at: Option<Moment>,
        key: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        let baseline =
            DisallowWeakAlgorithmsPolicy::default().signature_algorithm_allowed(algorithm, at, key);
        if key == Some(&self.main_key) {
            self.main_calls.lock().unwrap().push(at);
            if baseline.allowed && at.is_some_and(|time| time > self.cutoff) {
                return AlgorithmUsageConstraint {
                    allowed: false,
                    failure_reason: Some("caller MAIN key cutoff".into()),
                    not_allowed_after: Some(self.cutoff),
                };
            }
        }
        baseline
    }
    fn min_rsa_key_size(&self) -> usize {
        DisallowWeakAlgorithmsPolicy::default().min_rsa_key_size()
    }
    fn digest_combination(
        &self,
        algorithm: &spki::AlgorithmIdentifierOwned,
        digest: &spki::AlgorithmIdentifierOwned,
        at: Option<Moment>,
    ) -> Option<AlgorithmUsageConstraint> {
        DisallowWeakAlgorithmsPolicy::default().digest_combination(algorithm, digest, at)
    }
}

#[test]
fn key_bounded_timed_denial_requires_exact_main_discovery_and_final_forwarding() {
    use sigis_pki_core::errors::ValidationError;
    let (manifest, row, file, sig) = new_fixture("digital_signature_only", "archived");
    let leaf = Cert::from_der(&b64(row["signer_der"].as_str().unwrap())).unwrap();
    assert_eq!(
        sigis_pki_core::key_usage::cert_key_usages(&leaf).unwrap(),
        names(&["digital_signature"])
    );
    let cutoff = Moment::parse_rfc3339("2021-01-01T00:00:00Z").unwrap();
    let signed_at = Moment::parse_rfc3339(manifest["signed_at"].as_str().unwrap()).unwrap();
    let base = fixture_context(
        &manifest,
        &file,
        manifest["validation_time"].as_str().unwrap(),
    );
    assert!(signed_at < cutoff && cutoff < base.moment());
    for predicate in [
        KeyUsageConstraints::default(),
        KeyUsageConstraints {
            key_usage: Some(names(&["digital_signature"])),
            ..Default::default()
        },
    ] {
        let policy = Arc::new(MainKeyTimedPolicy {
            main_key: leaf.public_key(),
            cutoff,
            main_calls: Mutex::new(Vec::new()),
        });
        // Reuse the actual frozen caller evidence, including the current root
        // CRL. Only this legitimate key-specific algorithm requirement differs.
        let ctx = ValidationContext::builder()
            .trust_root(Cert::from_der(&b64(manifest["root_der"].as_str().unwrap())).unwrap())
            .moment(base.moment())
            .point_in_time_validation(false)
            .revinfo_policy(default_revinfo_policy())
            .algorithm_policy(policy.clone())
            .build()
            .unwrap()
            .with_revinfo(base.other_certs(), base.crls(), base.ocsps())
            .unwrap();
        let before = snapshot(&ctx);
        let selected = options(Some(predicate.clone()));
        let initial_options = sigis_cms::CmsValidationOptions {
            validation_order: sigis_cms::CmsValidationOrder::SignerFirst,
            exact_key_usage_settings: Some(predicate),
            ..Default::default()
        };
        let initial = sigis_cms::validate_cms_signature_with(
            &sig.contents,
            sigis_cms::SignedContent::Data(&sig.signed_data(&file).unwrap()),
            &ctx,
            &initial_options,
        )
        .unwrap();
        assert!(initial.signature.intact && initial.signature.valid);
        assert!(initial.signature.validation_path.is_none());
        assert!(matches!(
            initial.signature.trust_problem.as_ref(),
            Some(TrustProblem::Path(ValidationError::DisallowedAlgorithm {
                banned_since: Some(value), ..
            })) if *value == cutoff
        ));
        assert_eq!(initial.signature.error_time_horizon, Some(cutoff));
        policy.main_calls.lock().unwrap().clear();
        let known = fixture_poes(&manifest, ctx.moment());
        let known_before = format!("{known:?}");
        let result = lta_validation_with_ades_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            &LtaOptions {
                known_poes: Some(&known),
                ..Default::default()
            },
            &selected,
        )
        .unwrap();
        assert_ok(&result);
        assert_eq!(result.best_signature_time, Some(signed_at));
        let status = intact(&result.api_status);
        let control = status.signature.validation_time.unwrap();
        assert!(signed_at <= control && control < cutoff);
        assert!(control < ctx.moment());
        assert!(status.signature.validation_path.is_some());
        let timestamp = status.timestamp_validity.as_ref().unwrap();
        assert!(timestamp.signature.trusted());
        assert_ne!(
            timestamp
                .signature
                .signing_cert
                .as_ref()
                .unwrap()
                .public_key(),
            policy.main_key
        );
        let observed = policy.main_calls.lock().unwrap().clone();
        assert!(observed.contains(&Some(ctx.moment())), "{observed:?}");
        // CMS algorithm policy uses best_signature_time for both discovery
        // and final revalidation. Path/status validation_time remains control.
        let historical_main_calls = observed
            .iter()
            .filter(|time| **time == Some(signed_at))
            .count();
        assert!(
            historical_main_calls >= 2,
            "discovery and final best-signature policy calls: {observed:?}"
        );
        eprintln!(
            "ADES_EXACT_MAIN_DISCOVERY_CALLS {}",
            serde_json::json!({"cutoff":cutoff.to_string(),"collection_time":ctx.moment().to_string(),
                "main_spki_debug":format!("{:?}",policy.main_key),
                "main_times":observed.iter().map(|time|time.map(|time|time.to_string())).collect::<Vec<_>>(),
                "final_control_time":control.to_string(),"best_signature_time":signed_at.to_string()})
        );
        use base64::Engine;
        use der::Encode;
        export_fixture_with_policy_profile(
            (
                "lta_validation_with_ades_options",
                "digital_signature_only_main_key_timed_discovery",
            ),
            &file,
            &manifest,
            (&ctx, Some(&known)),
            &selected,
            &result,
            (
                None,
                Some(serde_json::json!({
                    "kind":"main_spki_cutoff_default_elsewhere",
                    "main_spki_der_b64":base64::engine::general_purpose::STANDARD.encode(policy.main_key.to_der().unwrap()),
                    "cutoff":cutoff.to_string(),
                    "denied_when":"requested_time_strictly_after_cutoff_and_exact_main_spki",
                    "otherwise":"DisallowWeakAlgorithmsPolicy::default",
                    "observed_main_call_times":observed.iter().map(|time|time.map(|time|time.to_string())).collect::<Vec<_>>()
                })),
            ),
        );
        assert_eq!(format!("{known:?}"), known_before);
        assert_eq!(snapshot(&ctx), before);
    }
}
