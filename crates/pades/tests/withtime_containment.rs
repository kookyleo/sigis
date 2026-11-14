//! Tests-first containment of unchecked MAIN trust promotion; zero new original IDs.
mod common;
use common::{data, read_fixture};
use serde_json::{json, Value};
use sigis_cms::{
    CmsValidationOptions, CmsValidationOrder, SignedContent, StandardCmsSignatureStatus,
};
use sigis_pades::ades::{
    basic::QualificationSpec, with_time::with_time_validation_with_options, AdesValidationOptions,
};
use sigis_pki_certvalidator::{
    CertRevTrustPolicy, PkixValidationParams, ValidationContext, NO_REVOCATION, REQUIRE_REVINFO,
};
use sigis_pki_core::{
    algorithms::DigestAlgorithm, cert::Cert, key_usage::KeyUsageConstraints, time::Moment,
};
use std::path::PathBuf;
fn hash(b: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(b)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn time(v: &Value) -> Moment {
    Moment::parse_rfc3339(v.as_str().unwrap()).unwrap()
}
fn fixtures() -> (PathBuf, Value) {
    let p = data(&["lanes", "r3-v", "qualified-preliminary-completion"]);
    let m: Value = serde_json::from_slice(&read_fixture(p.join("manifest.json"))).unwrap();
    for r in m["files"].as_array().unwrap() {
        let b = read_fixture(p.join(r["file"].as_str().unwrap()));
        assert_eq!(hash(&b), r["sha256"].as_str().unwrap());
        assert_eq!(b.len() as u64, r["length"].as_u64().unwrap());
    }
    (p, m)
}
fn predicate() -> KeyUsageConstraints {
    KeyUsageConstraints {
        key_usage: Some(["non_repudiation".into()].into_iter().collect()),
        ..Default::default()
    }
}
fn options() -> AdesValidationOptions {
    let mut o = AdesValidationOptions::default();
    o.exact_key_usage_settings = Some(predicate());
    o
}
fn params(row: &Value) -> Option<PkixValidationParams> {
    row["required_policy"]
        .as_str()
        .map(|p| PkixValidationParams {
            initial_explicit_policy: true,
            user_initial_policy_constraint: Some([p.parse().unwrap()].into_iter().collect()),
            ..Default::default()
        })
}
fn context(dir: &std::path::Path, m: &Value, r: &Value) -> ValidationContext {
    let c = ValidationContext::builder()
        .trust_root(Cert::from_der(&read_fixture(dir.join(m["root"].as_str().unwrap()))).unwrap())
        .moment(time(&r["validation_time"]))
        .point_in_time_validation(true)
        .revinfo_policy(CertRevTrustPolicy::new(if r["revocation"] == "require" {
            REQUIRE_REVINFO
        } else {
            NO_REVOCATION
        }))
        .build()
        .unwrap();
    let crls = r["crls"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|n| read_fixture(dir.join(n.as_str().unwrap())))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    c.with_revinfo(
        &[],
        crls.iter().map(Vec::as_slice),
        std::iter::empty::<&[u8]>(),
    )
    .unwrap()
}
fn cms(
    bytes: &[u8],
    content: &[u8],
    ctx: &ValidationContext,
    r: &Value,
) -> StandardCmsSignatureStatus {
    sigis_cms::validate_cms_signature_with(
        bytes,
        SignedContent::Data(content),
        ctx,
        &CmsValidationOptions {
            validation_order: CmsValidationOrder::SignerFirst,
            exact_key_usage_settings: Some(predicate()),
            pkix_validation_params: params(r),
            ..Default::default()
        },
    )
    .unwrap()
}
fn status(s: &StandardCmsSignatureStatus) -> Value {
    json!({"intact":s.signature.intact,"valid":s.signature.valid,"trusted":s.signature.trusted(),"bottom_line":s.bottom_line(),"problem":format!("{:?}",s.signature.trust_problem),"subindic":s.signature.trust_problem_indic.map(|s|s.standard_name()),"validation_time":s.signature.validation_time.map(|t|t.to_string()),"horizon":s.signature.error_time_horizon.map(|t|t.to_string()),"path":s.signature.validation_path.as_ref().map(|p|p.certs().iter().map(|c|hash(c.der())).collect::<Vec<_>>()),"timestamp":s.timestamp_validity.as_ref().map(|t|json!({"trusted":t.trusted(),"intact":t.signature.intact,"valid":t.signature.valid,"time":t.timestamp.to_string(),"validation_time":t.signature.validation_time.map(|t|t.to_string()),"problem":format!("{:?}",t.signature.trust_problem)}))})
}
fn emit(label: &str, row: Value) {
    let b = std::fs::read("/proc/self/exe").unwrap();
    eprintln!(
        "CONTAINMENT_CASE {}",
        json!({"label":label,"data":row,"elf_sha256":hash(&b),"elf_length":b.len(),"host":std::fs::read_to_string("/etc/hostname").unwrap().trim(),"slot":std::env::var("RUST_SLOTS_HELD").ok()})
    );
}

fn require_contained(
    before: &StandardCmsSignatureStatus,
    result: &sigis_pades::ades::with_time::WithTimeValidationResult,
    label: &str,
) {
    assert!(
        !before.signature.trusted(),
        "failed MAIN precondition: {label}"
    );
    assert_ne!(
        result.ades_subindic.standard_name(),
        "OK",
        "{label}: {result:?}"
    );
    let after = result
        .api_status
        .as_ref()
        .expect("preserve available API status");
    assert!(
        !after.signature.trusted(),
        "unchecked trust promotion: {label}"
    );
    assert_eq!(
        format!("{:?}", before.signature),
        format!("{:?}", after.signature),
        "preserve complete original MAIN failure/path/clock/horizon: {label}"
    );
    assert!(
        result.qualification.is_none(),
        "do not qualify an incomplete error path"
    );
}

#[test]
fn pure_and_cms_withtime_preserve_failed_main_in_both_current_clock_profiles() {
    use sigis_pades::ades::with_time::{with_time_result, with_time_validation};
    let (dir, m) = fixtures();
    let content = read_fixture(dir.join(m["content"].as_str().unwrap()));
    for row in m["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["id"] != "policy_mismatch")
    {
        let bytes = read_fixture(dir.join(row["cms"].as_str().unwrap()));
        let ctx = context(&dir, &m, row);
        let source = format!("{ctx:?}");
        let first = cms(&bytes, &content, &ctx, row);
        assert!(first.signature.intact && first.signature.valid);
        let token = first.timestamp_validity.as_ref().unwrap();
        assert!(
            token.trusted(),
            "actual trusted TSA/signature/imprint precondition"
        );
        let mut timing = *ctx.timing();
        timing.best_signature_time = token.timestamp;
        let cloned = ctx.with_timing(timing);
        for (stage, current) in [("current", &ctx), ("current_best_authenticated", &cloned)] {
            let initial = cms(&bytes, &content, current, row);
            assert!(
                initial.signature.validation_path.is_some(),
                "real diagnostic path exists"
            );
            assert!(initial.signature.trust_problem.is_some());
            let pure = with_time_result(
                initial.clone(),
                &QualificationSpec::default(),
                None,
                None,
                current.moment(),
            );
            let raw = DigestAlgorithm::Sha256.digest(&content);
            let exact = with_time_validation_with_options(
                &bytes,
                Some(&raw),
                current,
                &QualificationSpec::default(),
                None,
                &options(),
            )
            .unwrap();
            let ordinary = with_time_validation(
                &bytes,
                Some(&raw),
                current,
                &QualificationSpec::default(),
                None,
            )
            .unwrap();
            for (entry, result) in [
                ("pure", pure),
                ("exact_cms", exact),
                ("ordinary_cms", ordinary),
            ] {
                let label = format!("{} {stage} {entry}", row["id"]);
                emit(
                    "failed_main_containment",
                    json!({"case":row["id"],"stage":stage,"entry":entry,
                    "cms_sha256":hash(&bytes),"before":status(&initial),"after":result.api_status.as_ref().map(status),
                    "subindic":result.ades_subindic.standard_name(),"best":result.best_signature_time.map(|t|t.to_string()),
                    "not_before":result.signature_not_before_time.map(|t|t.to_string())}),
                );
                require_contained(&initial, &result, &label);
                assert_eq!(
                    result.best_signature_time,
                    Some(token.timestamp),
                    "retain genuine bound"
                );
            }
        }
        assert_eq!(format!("{ctx:?}"), source, "source context is immutable");
    }
}

#[test]
fn fully_checked_current_cms_still_passes_and_real_mutations_and_empty_roots_refuse() {
    use sigis_pades::ades::with_time::{with_time_result, with_time_validation};
    let (dir, m) = fixtures();
    let row = m["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "good")
        .unwrap();
    let bytes = read_fixture(dir.join(row["cms"].as_str().unwrap()));
    let content = read_fixture(dir.join(m["content"].as_str().unwrap()));
    let base = context(&dir, &m, row);
    let mut timing = *base.timing();
    timing.validation_time = Moment::parse_rfc3339("2021-06-01T00:00:00Z").unwrap();
    timing.best_signature_time = timing.validation_time;
    let ctx = base.with_timing(timing);
    let initial = cms(&bytes, &content, &ctx, row);
    assert!(initial.signature.trusted());
    let raw = DigestAlgorithm::Sha256.digest(&content);
    for (entry, result) in [
        (
            "pure",
            with_time_result(
                initial.clone(),
                &QualificationSpec::default(),
                None,
                None,
                ctx.moment(),
            ),
        ),
        (
            "exact_cms",
            with_time_validation_with_options(
                &bytes,
                Some(&raw),
                &ctx,
                &QualificationSpec::default(),
                None,
                &options(),
            )
            .unwrap(),
        ),
        (
            "ordinary_cms",
            with_time_validation(
                &bytes,
                Some(&raw),
                &ctx,
                &QualificationSpec::default(),
                None,
            )
            .unwrap(),
        ),
    ] {
        emit(
            "fully_checked_positive",
            json!({"entry":entry,"cms_sha256":hash(&bytes),
            "subindic":result.ades_subindic.standard_name(),"api":result.api_status.as_ref().map(status)}),
        );
        assert_eq!(result.ades_subindic.standard_name(), "OK");
        assert!(result.api_status.as_ref().unwrap().bottom_line());
    }
    let no_roots = ValidationContext::builder()
        .moment(ctx.moment())
        .point_in_time_validation(true)
        .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
        .build()
        .unwrap();
    let denied = with_time_validation_with_options(
        &bytes,
        Some(&raw),
        &no_roots,
        &QualificationSpec::default(),
        None,
        &options(),
    )
    .unwrap();
    assert_ne!(denied.ades_subindic.standard_name(), "OK");
    assert!(!denied.api_status.as_ref().unwrap().signature.trusted());
    let mut wrong_digest = raw.clone();
    wrong_digest[0] ^= 1;
    let changed = with_time_validation_with_options(
        &bytes,
        Some(&wrong_digest),
        &ctx,
        &QualificationSpec::default(),
        None,
        &options(),
    )
    .unwrap();
    assert_eq!(changed.ades_subindic.standard_name(), "HASH_FAILURE");
    assert!(!changed.api_status.as_ref().unwrap().signature.intact);
    let sd = sigis_cms::SignedData::from_der(&bytes).unwrap();
    let signature = &sd.signer_infos[0].signature;
    let index = bytes
        .windows(signature.len())
        .position(|w| w == signature)
        .unwrap();
    let mut forged = bytes.clone();
    forged[index] ^= 1;
    let changed = with_time_validation_with_options(
        &forged,
        Some(&raw),
        &ctx,
        &QualificationSpec::default(),
        None,
        &options(),
    )
    .unwrap();
    assert_eq!(changed.ades_subindic.standard_name(), "SIG_CRYPTO_FAILURE");
    assert!(!changed.api_status.as_ref().unwrap().signature.valid);
    emit(
        "real_cms_denials",
        json!({"source_sha256":hash(&bytes),"forged_sha256":hash(&forged),
        "signature_xor_offset":index,"no_roots":denied.ades_subindic.standard_name(),
        "digest":"HASH_FAILURE","raw_signature":"SIG_CRYPTO_FAILURE"}),
    );
}

#[test]
fn actual_pdf_withtime_dispatcher_and_detailed_entry_cannot_bypass_main_guard() {
    use sigis_pades::ades::{validate_pdf_ades_with_options, AdesLevel, AdesStatus};
    let dir = data(&["lanes", "r3-v", "withtime-containment"]);
    let manifest: Value = serde_json::from_slice(&read_fixture(dir.join("manifest.json"))).unwrap();
    for input in manifest["files"].as_array().unwrap() {
        let bytes = read_fixture(dir.join(input["file"].as_str().unwrap()));
        assert_eq!(bytes.len() as u64, input["length"].as_u64().unwrap());
        assert_eq!(hash(&bytes), input["sha256"].as_str().unwrap());
    }
    for row in manifest["cases"].as_array().unwrap() {
        let bytes = read_fixture(dir.join(row["file"].as_str().unwrap()));
        let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
        let signature = file.embedded_signatures().unwrap().remove(0);
        for (stage, at, earlier_best) in [
            ("current", "current_validation_time", false),
            ("current", "current_validation_time", true),
            ("expired", "expired_validation_time", false),
            ("expired", "expired_validation_time", true),
        ] {
            let ctx = ValidationContext::builder()
                .trust_root(Cert::from_der(&read_fixture(dir.join("root.der"))).unwrap())
                .moment(time(&manifest[at]))
                .point_in_time_validation(true)
                .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
                .build()
                .unwrap();
            let mut timing = *ctx.timing();
            if earlier_best {
                timing.best_signature_time = time(&manifest["signed_at"]);
            }
            let ctx = ctx.with_timing(timing);
            let snapshot = format!("{ctx:?}");
            let cms = sigis_pades::validate_pdf_signature_with_options(
                &file,
                &signature,
                &ctx,
                Some(&sigis_pdf_diff::StandardDiffPolicy),
                &CmsValidationOptions {
                    validation_order: CmsValidationOrder::TimestampsFirst,
                    exact_key_usage_settings: Some(predicate()),
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(
                cms.cms.signature.intact && cms.cms.signature.valid,
                "actual main signature: {}",
                row["id"]
            );
            let expected = row["id"] == "good" && stage == "current";
            let result = validate_pdf_ades_with_options(
                &file,
                &signature,
                AdesLevel::WithTimestamps,
                &ctx,
                &options(),
            )
            .unwrap();
            let detailed = with_time_validation_with_options(
                &signature.contents,
                Some(&DigestAlgorithm::Sha256.digest(&signature.signed_data(&file).unwrap())),
                &ctx,
                &QualificationSpec::default(),
                None,
                &options(),
            )
            .unwrap();
            emit(
                "actual_pdf_withtime",
                json!({"case":row["id"],"stage":stage,"earlier_best":earlier_best,"pdf_sha256":hash(&bytes),
                "dispatcher":format!("{result:?}"),"initial":status(&cms.cms),
                "detailed_subindic":detailed.ades_subindic.standard_name(),"detailed":detailed.api_status.as_ref().map(status)}),
            );
            assert_eq!(
                result.status == AdesStatus::Passed,
                expected,
                "{} {stage}: {result:?}",
                row["id"]
            );
            assert_eq!(
                detailed.ades_subindic.standard_name() == "OK",
                expected,
                "{} {stage}: {detailed:?}",
                row["id"]
            );
            if expected {
                assert!(cms.bottom_line());
                assert!(detailed.api_status.as_ref().unwrap().bottom_line());
            } else if !cms.cms.signature.trusted() {
                assert!(!detailed.api_status.as_ref().unwrap().signature.trusted());
            }
            assert_eq!(format!("{ctx:?}"), snapshot);
        }
    }
}

#[test]
fn denied_tsa_policy_ordering_and_mandatory_qualification_still_refuse() {
    use der::Encode;
    use sigis_eutl::assess::QualificationRequirements;
    use sigis_pades::ades::with_time::with_time_result;
    use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
    use std::sync::Arc;
    #[derive(Debug)]
    struct DenyTsa(Vec<u8>);
    impl AlgorithmUsagePolicy for DenyTsa {
        fn digest_algorithm_allowed(
            &self,
            _: &const_oid::ObjectIdentifier,
            _: Option<Moment>,
        ) -> AlgorithmUsageConstraint {
            AlgorithmUsageConstraint::allowed()
        }
        fn signature_algorithm_allowed(
            &self,
            _: &spki::AlgorithmIdentifierOwned,
            _: Option<Moment>,
            key: Option<&spki::SubjectPublicKeyInfoOwned>,
        ) -> AlgorithmUsageConstraint {
            if key.is_some_and(|key| key.to_der().unwrap() == self.0) {
                AlgorithmUsageConstraint {
                    allowed: false,
                    failure_reason: Some("mandatory TSA refusal".into()),
                    not_allowed_after: None,
                }
            } else {
                AlgorithmUsageConstraint::allowed()
            }
        }
    }
    let (dir, m) = fixtures();
    let row = m["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "good")
        .unwrap();
    let bytes = read_fixture(dir.join("good.cms.der"));
    let content = read_fixture(dir.join("content.bin"));
    let root = Cert::from_der(&read_fixture(dir.join("root.der"))).unwrap();
    let tsa = Cert::from_der(&read_fixture(dir.join("tsa.der"))).unwrap();
    let builder = || {
        ValidationContext::builder()
            .trust_root(root.clone())
            .moment(Moment::parse_rfc3339("2021-06-01T00:00:00Z").unwrap())
            .point_in_time_validation(true)
            .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
    };
    let current = builder().build().unwrap();
    let denied = builder()
        .algorithm_policy(Arc::new(DenyTsa(tsa.public_key().to_der().unwrap())))
        .build()
        .unwrap();
    let actual = cms(&bytes, &content, &current, row);
    assert!(actual.signature.trusted());
    assert!(actual.timestamp_validity.as_ref().unwrap().trusted());
    let forbidden = with_time_validation_with_options(
        &bytes,
        Some(&DigestAlgorithm::Sha256.digest(&content)),
        &denied,
        &QualificationSpec::default(),
        None,
        &options(),
    )
    .unwrap();
    assert_eq!(
        forbidden.ades_subindic.standard_name(),
        "CRYPTO_CONSTRAINTS_FAILURE"
    );
    let order = with_time_result(
        actual.clone(),
        &QualificationSpec::default(),
        None,
        Some(Moment::parse_rfc3339("2020-08-02T00:00:00Z").unwrap()),
        current.moment(),
    );
    assert_eq!(
        order.ades_subindic.standard_name(),
        "TIMESTAMP_ORDER_FAILURE"
    );
    for signer in [false, true] {
        let q = if signer {
            QualificationSpec {
                requirements: Some(QualificationRequirements::default()),
                ..Default::default()
            }
        } else {
            QualificationSpec {
                ts_requirements: Some(QualificationRequirements::default()),
                ..Default::default()
            }
        };
        let result = with_time_result(actual.clone(), &q, None, None, current.moment());
        assert_eq!(
            result.ades_subindic.standard_name(),
            "SIG_CONSTRAINTS_FAILURE"
        );
        emit(
            "mandatory_qualification_denial",
            json!({"signer":signer,"subindic":result.ades_subindic.standard_name(),
            "api":result.api_status.as_ref().map(status)}),
        );
    }
    emit(
        "tsa_and_order_denials",
        json!({"cms_sha256":hash(&bytes),"tsa_sha256":hash(tsa.der()),
        "tsa":forbidden.ades_subindic.standard_name(),"ordering":order.ades_subindic.standard_name()}),
    );
}
