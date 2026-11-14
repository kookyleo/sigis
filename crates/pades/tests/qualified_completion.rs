//! Completion design diagnostics. Production is unchanged; zero original IDs.
mod common;
use common::{b64, data, read_fixture};
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
    eprintln!(
        "COMPLETION_DIAGNOSTIC {}",
        json!({"label": label, "data": row})
    );
}
#[test]
fn full_same_policy_current_timing_clone_does_not_complete_expired_or_revoked_pkix() {
    let (dir, m) = fixtures();
    let content = read_fixture(dir.join(m["content"].as_str().unwrap()));
    for r in m["cases"].as_array().unwrap() {
        let bytes = read_fixture(dir.join(r["cms"].as_str().unwrap()));
        let ctx = context(&dir, &m, r);
        let before = format!("{ctx:?}");
        let initial = cms(&bytes, &content, &ctx, r);
        assert!(
            initial.signature.intact && initial.signature.valid,
            "actual CMS crypto, {}",
            r["id"]
        );
        let ts = initial.timestamp_validity.as_ref().unwrap();
        assert!(
            ts.trusted(),
            "actual TSA/signature/imprint precondition: {}: {ts:?}",
            r["id"]
        );
        let best = ts.timestamp;
        assert_eq!(best, time(&r["signed_at"]));
        let mut timing = *ctx.timing();
        timing.best_signature_time = best;
        let same_policy = ctx.with_timing(timing);
        assert_eq!(same_policy.moment(), ctx.moment());
        let completed = cms(&bytes, &content, &same_policy, r);
        let mut historical_timing = timing;
        historical_timing.validation_time = best;
        let historical = ctx.with_timing(historical_timing);
        let historical_status = cms(&bytes, &content, &historical, r);
        let sd = sigis_cms::SignedData::from_der(&bytes).unwrap();
        let alg = DigestAlgorithm::from_oid(&sd.signer_infos.first().unwrap().digest_algorithm.oid)
            .unwrap();
        let raw = alg.digest(&content);
        let mut public = Vec::new();
        for (label, c) in [
            ("current", &ctx),
            ("current_best_authenticated", &same_policy),
            ("historical_control_not_current_completion", &historical),
        ] {
            // PhaseA public WithTime has no independent PKIX-params option. Record that
            // mismatch honestly; its policy_mismatch row is not a full same-policy call.
            let w = with_time_validation_with_options(
                &bytes,
                Some(&raw),
                c,
                &QualificationSpec::default(),
                None,
                &options(),
            )
            .unwrap();
            public.push(json!({"stage":label,"all_cms_pkix_params_carried":params(r).is_none(),"subindic":w.ades_subindic.standard_name(),"api":w.api_status.as_ref().map(status),"best":w.best_signature_time.map(|t|t.to_string()),"failure":w.failure_msg}));
        }
        emit(
            "same_policy_clone",
            json!({"case":r["id"],"cms_sha256":hash(&bytes),"content_sha256":hash(&content),"current":ctx.moment().to_string(),"authenticated_best":best.to_string(),"pkix_params":format!("{:?}",params(r)),"initial":status(&initial),"current_clone":status(&completed),"historical":status(&historical_status),"public_with_time":public}),
        );
        assert!(
            !completed.signature.trusted(),
            "full current same-policy retry cannot clear ordinary validity/revocation: {}",
            r["id"]
        );
        if r["id"] == "good" {
            assert!(
                historical_status.signature.trusted(),
                "genuine full-check positive"
            );
        }
        if matches!(
            r["id"].as_str().unwrap(),
            "name_constraints"
                | "unknown_critical"
                | "path_length"
                | "policy_mismatch"
                | "bad_cert_signature"
                | "ds_only"
        ) {
            assert!(
                !historical_status.signature.trusted(),
                "real historical control must expose the distinct mandatory constraint: {}",
                r["id"]
            );
        }
        assert_eq!(format!("{ctx:?}"), before);
    }
}
#[test]
fn public_with_time_must_not_promote_a_path_with_uncompleted_mandatory_checks() {
    let (dir, m) = fixtures();
    let content = read_fixture(dir.join(m["content"].as_str().unwrap()));
    let mut violations = Vec::new();
    for r in m["cases"].as_array().unwrap().iter().filter(|r| {
        matches!(
            r["id"].as_str().unwrap(),
            "name_constraints"
                | "unknown_critical"
                | "path_length"
                | "bad_cert_signature"
                | "ds_only"
                | "revoked_ds"
        )
    }) {
        let bytes = read_fixture(dir.join(r["cms"].as_str().unwrap()));
        let ctx = context(&dir, &m, r);
        let sd = sigis_cms::SignedData::from_der(&bytes).unwrap();
        let raw = DigestAlgorithm::from_oid(&sd.signer_infos.first().unwrap().digest_algorithm.oid)
            .unwrap()
            .digest(&content);
        let w = with_time_validation_with_options(
            &bytes,
            Some(&raw),
            &ctx,
            &QualificationSpec::default(),
            None,
            &options(),
        )
        .unwrap();
        let accepted = w.ades_subindic.standard_name() == "OK"
            && w.api_status.as_ref().is_some_and(|s| s.signature.trusted());
        emit(
            "hardening_required",
            json!({"case":r["id"],"cms_sha256":hash(&bytes),"public_subindic":w.ades_subindic.standard_name(),"api":w.api_status.as_ref().map(status),"accepted_uncompleted_mandatory":accepted}),
        );
        if accepted {
            violations.push(r["id"].as_str().unwrap().to_owned());
        }
    }
    assert!(
        violations.is_empty(),
        "public WithTime must fail closed independently of final LTA: {violations:?}"
    );
}
#[test]
fn final_lta_stays_refusing_missing_history_and_bad_purpose() {
    use sigis_pades::ades::lta::{lta_validation_with_ades_options, LtaOptions};
    let d = data(&["lanes", "r3-v", "ades-exact-options"]);
    let m: Value = serde_json::from_slice(&read_fixture(d.join("manifest.json"))).unwrap();
    let r = m["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "digital_signature_only")
        .unwrap();
    for kind in ["archived", "no_poe", "corrupt_imprint"] {
        let a = &r["files"][kind];
        let bytes = read_fixture(d.join(a["file"].as_str().unwrap()));
        assert_eq!(hash(&bytes), a["sha256"].as_str().unwrap());
        let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
        let sig = file.embedded_signatures().unwrap().remove(0);
        let ctx = ValidationContext::builder()
            .trust_root(Cert::from_der(&b64(m["root_der"].as_str().unwrap())).unwrap())
            .moment(Moment::parse_rfc3339("2025-03-01T22:00:00Z").unwrap())
            .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
            .build()
            .unwrap();
        let l = lta_validation_with_ades_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            &LtaOptions::default(),
            &options(),
        )
        .unwrap();
        emit(
            "final_lta_refusal",
            json!({"case":kind,"pdf_sha256":hash(&bytes),"subindic":l.ades_subindic.standard_name(),"api":l.api_status.as_ref().map(status),"failure":l.failure_msg,"best":l.best_signature_time.map(|t|t.to_string()),"poes":format!("{:?}",l.poe)}),
        );
        assert_ne!(l.ades_subindic.standard_name(), "OK");
        assert!(!l.api_status.as_ref().unwrap().signature.trusted());
    }
}
#[test]
fn timed_main_recheck_is_a_full_check_and_permanent_denial_never_recovers() {
    use der::Encode;
    use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
    use std::sync::Arc;
    #[derive(Debug)]
    struct TargetPolicy {
        key: Vec<u8>,
        cutoff: Moment,
        permanent: bool,
    }
    impl AlgorithmUsagePolicy for TargetPolicy {
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
            at: Option<Moment>,
            key: Option<&spki::SubjectPublicKeyInfoOwned>,
        ) -> AlgorithmUsageConstraint {
            if key.is_some_and(|k| k.to_der().unwrap() == self.key)
                && (self.permanent || at.is_none_or(|t| t > self.cutoff))
            {
                AlgorithmUsageConstraint {
                    allowed: false,
                    failure_reason: Some("actual target MAIN policy".into()),
                    not_allowed_after: (!self.permanent).then_some(self.cutoff),
                }
            } else {
                AlgorithmUsageConstraint::allowed()
            }
        }
    }
    let (dir, m) = fixtures();
    let content = read_fixture(dir.join(m["content"].as_str().unwrap()));
    for r in m["cases"].as_array().unwrap().iter().filter(|r| {
        matches!(
            r["id"].as_str().unwrap(),
            "good" | "name_constraints" | "unknown_critical" | "ds_only"
        )
    }) {
        let bytes = read_fixture(dir.join(r["cms"].as_str().unwrap()));
        let leaf = Cert::from_der(&read_fixture(dir.join(r["signer"].as_str().unwrap()))).unwrap();
        for permanent in [false, true] {
            let p = Arc::new(TargetPolicy {
                key: leaf.public_key().to_der().unwrap(),
                cutoff: Moment::parse_rfc3339("2020-12-01T00:00:00Z").unwrap(),
                permanent,
            });
            let ctx = ValidationContext::builder()
                .trust_root(Cert::from_der(&read_fixture(dir.join("root.der"))).unwrap())
                .moment(Moment::parse_rfc3339("2021-06-01T00:00:00Z").unwrap())
                .point_in_time_validation(true)
                .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
                .algorithm_policy(p)
                .build()
                .unwrap();
            let initial = cms(&bytes, &content, &ctx, r);
            assert!(initial.signature.intact && initial.signature.valid);
            assert!(!initial.signature.trusted());
            let ts = initial.timestamp_validity.as_ref().unwrap();
            assert!(
                ts.trusted(),
                "independent fixed-purpose TSA must authenticate before MAIN best selection"
            );
            let mut timing = *ctx.timing();
            timing.best_signature_time = ts.timestamp;
            let rechecked = cms(&bytes, &content, &ctx.with_timing(timing), r);
            emit(
                "full_main_algorithm_recheck",
                json!({"case":r["id"],"cms_sha256":hash(&bytes),"permanent":permanent,"validation_time":ctx.moment().to_string(),"authenticated_best":ts.timestamp.to_string(),"initial":status(&initial),"full_recheck":status(&rechecked),"full_lta_acceptance_claim":false}),
            );
            assert_eq!(rechecked.signature.trusted(),!permanent&&r["id"]=="good","a positive comes only from actual full current PKIX and exact predicate; never candidate presence");
        }
    }
}
#[test]
fn shared_tsa_clock_cannot_be_borrowed_from_an_unauthorized_token() {
    use der::Encode;
    use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
    use std::sync::Arc;
    #[derive(Debug)]
    struct TsaPolicy {
        key: Vec<u8>,
        cutoff: Moment,
    }
    impl AlgorithmUsagePolicy for TsaPolicy {
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
            at: Option<Moment>,
            key: Option<&spki::SubjectPublicKeyInfoOwned>,
        ) -> AlgorithmUsageConstraint {
            if key.is_some_and(|k| k.to_der().unwrap() == self.key)
                && at.is_none_or(|t| t > self.cutoff)
            {
                AlgorithmUsageConstraint {
                    allowed: false,
                    failure_reason: Some("fixed TSA policy time boundary".into()),
                    not_allowed_after: Some(self.cutoff),
                }
            } else {
                AlgorithmUsageConstraint::allowed()
            }
        }
    }
    let (dir, m) = fixtures();
    let r = m["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "good")
        .unwrap();
    let bytes = read_fixture(dir.join("good.cms.der"));
    let content = read_fixture(dir.join("content.bin"));
    let tsa = Cert::from_der(&read_fixture(dir.join("tsa.der"))).unwrap();
    let p = Arc::new(TsaPolicy {
        key: tsa.public_key().to_der().unwrap(),
        cutoff: Moment::parse_rfc3339("2020-12-01T00:00:00Z").unwrap(),
    });
    let ctx = ValidationContext::builder()
        .trust_root(Cert::from_der(&read_fixture(dir.join("root.der"))).unwrap())
        .moment(Moment::parse_rfc3339("2021-06-01T00:00:00Z").unwrap())
        .point_in_time_validation(true)
        .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
        .algorithm_policy(p)
        .build()
        .unwrap();
    let initial = cms(&bytes, &content, &ctx, r);
    assert!(initial.signature.trusted());
    let token = initial.timestamp_validity.as_ref().unwrap();
    assert!(!token.trusted());
    assert!(token.signature.intact && token.signature.valid);
    // Deliberately INELIGIBLE diagnostic: metadata from this denied token is not
    // authenticated best-time evidence. Nothing registers or publishes this time.
    let mut timing = *ctx.timing();
    timing.best_signature_time = token.timestamp;
    let unsafe_probe = cms(&bytes, &content, &ctx.with_timing(timing), r);
    emit(
        "ineligible_shared_tsa_clock_probe",
        json!({"case":"good","cms_sha256":hash(&bytes),"eligible_to_complete":false,"initial":status(&initial),"counterfactual_probe":status(&unsafe_probe),"reason":"initial TSA fails actual current policy; its genTime cannot authorize a best-time clone","source_of_probe_time":"untrusted metadata only, not POE"}),
    );
    assert!(unsafe_probe.timestamp_validity.as_ref().unwrap().trusted(),"demonstrates why a MAIN-only clock clone is not a role-preserving general completion proof");
}
