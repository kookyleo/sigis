//! Complete unchanged pre-revocation original closure using real native signing.
//! Tests-first recovery packet; zero new immutable upstream functions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/signing_integration.rs"]
mod support;

use sigis_cms::{CmsValidationOptions, CmsValidationOrder, SignedContent};
use sigis_pades::ades::{basic::QualificationSpec, with_time::with_time_validation};
use sigis_pades_sign::{
    cms::{CmsSigner, CmsSignerOptions},
    CmsSignedAttributes,
};
use sigis_pki_certvalidator::{
    validate_path, CertRevTrustPolicy, FreshnessReqType, TrustAnchor, ValidationContext,
    ValidationPath, REQUIRE_REVINFO,
};
use sigis_pki_core::{
    algorithms::DigestAlgorithm,
    cert::Cert,
    errors::{FetchError, FetchErrorKind},
    fetch::{CrlFetcher, Fetchers, OcspFetcher},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

const SIGNED_AT: &str = "2020-11-01T00:00:00Z";
const CURRENT: &str = "2020-12-25T00:00:00Z";
const CONTENT: &[u8] = b"Hello world!";

fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn read(path: PathBuf) -> Vec<u8> {
    let b = std::fs::read(&path).unwrap();
    eprintln!(
        "LEAF_COMPLETION_INPUT {}",
        serde_json::json!({"path":path.canonicalize().unwrap(),"length":b.len(),"sha256":sha(&b)})
    );
    b
}
fn fixture(date: &str, file: &str) -> Vec<u8> {
    read(support::data_path(&[
        "lanes",
        "r3-v",
        "leaf-revoked-completion",
        date,
        file,
    ]))
}
fn unavailable(msg: &str) -> FetchError {
    FetchError::new(FetchErrorKind::NotFound, msg)
}

/// Recorded signed Certomancer evidence, not a live HTTP implementation.
/// Full certificate and actual issuer bind every OCSP response selection.
#[derive(Debug)]
struct Evidence {
    date: &'static str,
    requests: Mutex<Vec<String>>,
}
impl Evidence {
    fn new(date: &'static str) -> Arc<Self> {
        Arc::new(Self {
            date,
            requests: Mutex::new(Vec::new()),
        })
    }
    fn fetchers(self: &Arc<Self>) -> Fetchers {
        Fetchers {
            ocsp: Some(self.clone()),
            crl: Some(self.clone()),
            cert: None,
        }
    }
}
impl OcspFetcher for Evidence {
    fn fetch_ocsp(&self, cert: &Cert, issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        let pki = support::pki("testing-ca");
        if cert.issuer() != issuer.subject() {
            return Err(unavailable("wrong actual issuer"));
        }
        for label in pki.labels() {
            if cert != &pki.cert(&label) {
                continue;
            }
            // The matched leaf bytes and actual known issuer must BOTH match.
            let issuer_known = pki.labels().iter().any(|l| pki.cert(l) == *issuer);
            if !issuer_known {
                return Err(unavailable("unknown actual issuer"));
            }
            self.requests.lock().unwrap().push(format!(
                "ocsp:{}:{label}:{}",
                self.date,
                sha(issuer.der())
            ));
            let path = support::data_path(&[
                "lanes",
                "r3-v",
                "leaf-revoked-completion",
                self.date,
                &format!("ocsp-{label}.der"),
            ]);
            if !path.exists() {
                return Err(unavailable("no recorded OCSP for this exact certificate"));
            }
            return Ok(read(path));
        }
        Err(unavailable("unknown complete certificate"))
    }
}
impl CrlFetcher for Evidence {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        let pki = support::pki("testing-ca");
        if !pki.labels().iter().any(|l| pki.cert(l) == *cert) {
            return Err(unavailable("unknown complete certificate"));
        }
        let issuer = if cert.issuer() == pki.cert("root").subject() {
            "root"
        } else if cert.issuer() == pki.cert("interm").subject() {
            "interm"
        } else {
            return Err(unavailable("unknown CRL issuer"));
        };
        self.requests.lock().unwrap().push(format!(
            "crl:{}:{issuer}:{}",
            self.date,
            sha(cert.der())
        ));
        Ok(vec![fixture(self.date, &format!("crl-{issuer}.der"))])
    }
}
fn context(at: &str, svc: &Arc<Evidence>) -> ValidationContext {
    let mut policy = CertRevTrustPolicy::new(REQUIRE_REVINFO);
    policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    ValidationContext::builder()
        .trust_root(support::pki("testing-ca").cert("root"))
        .moment(support::at(at))
        .point_in_time_validation(false)
        .revinfo_policy(policy)
        .fetchers(svc.fetchers())
        .build()
        .unwrap()
}
fn produce(signer_label: &str) -> Vec<u8> {
    produce_with(signer_label, Some("tsa"), SIGNED_AT, false)
}

fn temporal_input(name: &str) -> Vec<u8> {
    fixture("temporal-path-bounds", name)
}

fn temporal_context(intermediate: &Cert, anchor: TrustAnchor) -> ValidationContext {
    let mut policy = CertRevTrustPolicy::new(REQUIRE_REVINFO);
    policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    ValidationContext::builder()
        .trust_anchor(anchor)
        .other_cert(intermediate.clone())
        .moment(support::at(CURRENT))
        .point_in_time_validation(false)
        .revinfo_policy(policy)
        .crl(temporal_input("2020-12-25/crl-root.der"))
        .crl(temporal_input("2020-12-25/crl-interm.der"))
        .ocsp_response(temporal_input("2020-12-25/ocsp-signer2.der"))
        .build()
        .unwrap()
}

fn produce_temporal_cms(intermediate: &Cert, tsa_cert: &Cert, profile: &str) -> Vec<u8> {
    let pki = support::pki("testing-ca");
    let signer = sigis_pades_sign::SimpleSigner::new(
        pki.key(&pki.key_label_of("signer2")),
        pki.cert("signer2"),
        vec![pki.cert("root"), intermediate.clone()],
    )
    .unwrap();
    // The root-issued TSA needs ONLY Root. Do not register an alternative
    // original intermediate that could hide the selected path's time bound.
    let tsa = sigis_pades_sign::DummyTimeStamper::new(
        tsa_cert.clone(),
        pki.key(&pki.key_label_of("tsa")),
        vec![pki.cert("root")],
    )
    .with_fixed_time(support::at(SIGNED_AT));
    let options = CmsSignerOptions::default();
    let cms = CmsSigner {
        signer: &signer,
        options: &options,
    }
    .sign_general_data(
        CONTENT,
        DigestAlgorithm::Sha256,
        false,
        true,
        Some(&tsa),
        &CmsSignedAttributes {
            signing_time: Some(support::at(SIGNED_AT)),
            ..Default::default()
        },
    )
    .unwrap();
    let sd = sigis_cms::SignedData::from_content_info_der(&cms).unwrap();
    let si = sigis_cms::signed_data::extract_signer_info(&sd).unwrap();
    let tokens = sigis_cms::validate::extract_tst_data(si, false).unwrap();
    assert_eq!(tokens.len(), 1);
    let info = sigis_cms::validate::tst_info(&tokens[0]).unwrap();
    assert!(info.accuracy.is_none());
    assert_eq!(
        sigis_pki_core::time::Moment::from(info.gen_time.to_date_time()),
        support::at(SIGNED_AT)
    );
    if let Some(dir) = std::env::var_os("HANKO_LEAF_COMPLETION_OUTPUT_DIR") {
        let path = PathBuf::from(dir).join(format!("temporal-{profile}-{}.cms.der", sha(&cms)));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &cms).unwrap();
        eprintln!(
            "LEAF_COMPLETION_PRODUCER {}",
            serde_json::json!({"path":path,"length":cms.len(),"sha256":sha(&cms),"profile":profile,"content_sha256":sha(CONTENT),"signed_at":SIGNED_AT})
        );
    }
    cms
}

#[test]
fn temporal_resolution_checks_issuer_tsa_and_anchor_bounds_without_retiming() {
    use sigis_pki_certvalidator::{
        authority::TrustQualifiers, validate::find_current_leaf_revocation_evaluation,
    };
    let caller_manifest: serde_json::Value =
        serde_json::from_slice(&temporal_input("caller-inputs.json")).unwrap();
    for row in caller_manifest["files"].as_array().unwrap() {
        let bytes = temporal_input(row["file"].as_str().unwrap());
        assert_eq!(bytes.len() as u64, row["length"].as_u64().unwrap());
        assert_eq!(sha(&bytes), row["sha256"].as_str().unwrap());
    }
    let load = |name| Cert::from_der(&temporal_input(name)).unwrap();
    let root = load("cert-root-original.der");
    let original_intermediate = load("cert-interm-original.der");
    let original_tsa = load("cert-tsa-original.der");
    let late_intermediate = load("cert-interm-not-before-nov15.der");
    let late_tsa = load("cert-tsa-not-before-nov15.der");
    let profiles = [
        (
            "valid-full-path",
            original_intermediate.clone(),
            original_tsa.clone(),
            TrustAnchor::new(root.clone()),
            true,
        ),
        (
            "issuer-not-yet-valid-at-token",
            late_intermediate.clone(),
            original_tsa.clone(),
            TrustAnchor::new(root.clone()),
            false,
        ),
        (
            "tsa-not-yet-valid-at-token",
            original_intermediate.clone(),
            late_tsa.clone(),
            TrustAnchor::new(root.clone()),
            false,
        ),
        (
            "anchor-valid-from-not-started-at-token",
            original_intermediate.clone(),
            original_tsa.clone(),
            TrustAnchor::with_qualifiers(
                root,
                TrustQualifiers {
                    valid_from: Some(support::at("2020-11-15T00:00:00Z")),
                    ..Default::default()
                },
            ),
            false,
        ),
    ];
    for (profile, intermediate, tsa_cert, anchor, expected) in profiles {
        let cms = produce_temporal_cms(&intermediate, &tsa_cert, profile);
        let ctx = temporal_context(&intermediate, anchor.clone());
        // Test precondition only: this is never supplied as a witness to CMS.
        // Its own operation must discover/check its actual path independently.
        let checked = find_current_leaf_revocation_evaluation(
            &ctx,
            &support::pki("testing-ca").cert("signer2"),
            None,
        )
        .unwrap();
        assert_eq!(checked.leaf_events().len(), 1);
        assert!(checked.unresolved_failure().is_some());
        assert_eq!(
            checked.path().intermediates(),
            std::slice::from_ref(&intermediate)
        );
        assert_eq!(checked.path().trust_anchor(), &anchor);
        drop(checked);
        for order in [
            CmsValidationOrder::TimestampsFirst,
            CmsValidationOrder::SignerFirst,
        ] {
            let options = CmsValidationOptions {
                validation_order: order,
                ..Default::default()
            };
            let ordinary = sigis_cms::validate_cms_signature_with(
                &cms,
                SignedContent::Encapsulated,
                &ctx,
                &options,
            )
            .unwrap();
            assert!(ordinary.signature.intact && ordinary.signature.valid);
            assert!(ordinary.signature.revoked());
            assert_eq!(
                ordinary.signature.validation_time,
                Some(support::at(CURRENT))
            );
            let token = ordinary.timestamp_validity.as_ref().unwrap();
            assert!(token.trusted(), "real cryptography, fixed-purpose TSA and ORIGINAL current-reference checks must pass: {profile}, {order:?}: {token:#?}");
            assert_eq!(token.timestamp, support::at(SIGNED_AT));
            assert_eq!(token.signature.validation_time, Some(support::at(CURRENT)));
            let evaluated = sigis_cms::validate::evaluate_cms_leaf_revocation(
                &cms,
                SignedContent::Encapsulated,
                &ctx,
                &options,
            )
            .unwrap();
            let frozen = format!("{:#?}", evaluated.unresolved_status());
            assert_eq!(
                evaluated.eligible_signature_timestamp().is_some(),
                expected,
                "{profile}, {order:?}"
            );
            let resolved = evaluated.resolve_signature_timestamp();
            assert_eq!(
                resolved.signature.trusted(),
                expected,
                "{profile}, {order:?}: {resolved:#?}"
            );
            assert!(
                resolved.signature.revoked(),
                "resolution never means currently unrevoked"
            );
            assert_eq!(
                resolved.signature.validation_time,
                Some(support::at(CURRENT))
            );
            if !expected {
                assert_eq!(format!("{resolved:#?}"), frozen, "a temporal-bound refusal preserves its complete frozen error/path/API/time payload");
            }
        }
    }
}
#[derive(Debug)]
struct BoundTsa {
    actual: sigis_pades_sign::DummyTimeStamper,
    wrong_imprint: bool,
}
impl sigis_pki_core::sign::TimeStamper for BoundTsa {
    fn timestamp(
        &self,
        imprint: &[u8],
        digest: DigestAlgorithm,
    ) -> sigis_pki_core::errors::Result<Vec<u8>> {
        let mut bound = imprint.to_vec();
        if self.wrong_imprint {
            bound[0] ^= 1;
        }
        sigis_pki_core::sign::TimeStamper::timestamp(&self.actual, &bound, digest)
    }
}
fn produce_with(
    signer_label: &str,
    tsa_label: Option<&str>,
    token_at: &str,
    wrong_imprint: bool,
) -> Vec<u8> {
    let manifest_path =
        support::data_path(&["lanes", "r3-v", "leaf-revoked-completion", "manifest.json"]);
    let manifest: serde_json::Value = serde_json::from_slice(&read(manifest_path)).unwrap();
    for row in manifest["files"].as_array().unwrap() {
        let bytes = fixture("", row["relative_path"].as_str().unwrap());
        assert_eq!(bytes.len() as u64, row["length"].as_u64().unwrap());
        assert_eq!(sha(&bytes), row["sha256"].as_str().unwrap());
    }
    let pki = support::pki("testing-ca");
    let signer = pki.signer(signer_label);
    let tsa = tsa_label.map(|label| BoundTsa {
        actual: pki.tsa(label, support::at(token_at)),
        wrong_imprint,
    });
    let opts = CmsSignerOptions::default();
    let cms = CmsSigner {
        signer: &signer,
        options: &opts,
    }
    .sign_general_data(
        CONTENT,
        DigestAlgorithm::Sha256,
        false,
        true,
        tsa.as_ref()
            .map(|t| t as &dyn sigis_pki_core::sign::TimeStamper),
        &CmsSignedAttributes {
            signing_time: Some(support::at(SIGNED_AT)),
            ..Default::default()
        },
    )
    .unwrap();
    let sd = sigis_cms::SignedData::from_content_info_der(&cms).unwrap();
    let si = sigis_cms::signed_data::extract_signer_info(&sd).unwrap();
    let ts = sigis_cms::validate::extract_tst_data(si, false).unwrap();
    assert_eq!(ts.len(), usize::from(tsa_label.is_some()));
    if let Some(token) = ts.first() {
        let info = sigis_cms::validate::tst_info(token).unwrap();
        assert!(
            info.accuracy.is_none(),
            "initial recovery profile accepts no declared Accuracy"
        );
        assert_eq!(
            sigis_pki_core::time::Moment::from(info.gen_time.to_date_time()),
            support::at(token_at)
        );
    }
    if let Some(dir) = std::env::var_os("HANKO_LEAF_COMPLETION_OUTPUT_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{}-{signer_label}.cms.der", sha(&cms)));
        std::fs::write(&path, &cms).unwrap();
        eprintln!(
            "LEAF_COMPLETION_PRODUCER {}",
            serde_json::json!({"path":path,"length":cms.len(),"sha256":sha(&cms),"content_sha256":sha(CONTENT),"signer":signer_label,"signed_at":SIGNED_AT})
        );
    }
    cms
}
fn native_setup() {
    let pki = support::pki("testing-ca");
    let svc = Evidence::new("2020-11-01");
    let ctx = context(SIGNED_AT, &svc);
    let path = ValidationPath::new(
        TrustAnchor::new(pki.cert("root")),
        vec![pki.cert("interm")],
        Some(pki.cert("signer2")),
    );
    validate_path(&ctx, &path, None)
        .expect("original Nov1 async_validate_path precondition must really pass");
    assert!(
        !svc.requests.lock().unwrap().is_empty(),
        "actual revocation checks, not only structural path"
    );
    eprintln!(
        "LEAF_COMPLETION_SETUP {}",
        serde_json::json!({"time":SIGNED_AT,"path":path.certs().iter().map(|c|sha(c.der())).collect::<Vec<_>>(),"requests":*svc.requests.lock().unwrap(),"result":"full native validate_path success"})
    );
}
#[test]
fn original_pre_revoke_full_native_closure() {
    let bytes = produce("signer2");
    native_setup();
    let svc = Evidence::new("2020-12-25");
    let ctx = context(CURRENT, &svc);
    let before = format!(
        "{:?}{:?}{:?}{:?}{:?}",
        ctx.timing(),
        ctx.revinfo_policy(),
        ctx.trust_anchors(),
        ctx.other_certs(),
        ctx.non_revoked_status_assertions()
    );
    let policy = ctx.algorithm_policy_arc();
    let ocsp = ctx.fetchers().ocsp.as_ref().unwrap().clone();
    let crl = ctx.fetchers().crl.as_ref().unwrap().clone();
    let result =
        with_time_validation(&bytes, None, &ctx, &QualificationSpec::default(), None).unwrap();
    eprintln!(
        "LEAF_COMPLETION_RESULT {}",
        serde_json::json!({"input_sha256":sha(&bytes),"time":CURRENT,"result":format!("{result:#?}"),"requests":*svc.requests.lock().unwrap()})
    );
    assert_eq!(
        format!(
            "{:?}{:?}{:?}{:?}{:?}",
            ctx.timing(),
            ctx.revinfo_policy(),
            ctx.trust_anchors(),
            ctx.other_certs(),
            ctx.non_revoked_status_assertions()
        ),
        before,
        "keep original caller settings"
    );
    assert!(Arc::ptr_eq(&policy, &ctx.algorithm_policy_arc()));
    assert!(Arc::ptr_eq(&ocsp, ctx.fetchers().ocsp.as_ref().unwrap()));
    assert!(Arc::ptr_eq(&crl, ctx.fetchers().crl.as_ref().unwrap()));
    // Exact original final assertions. They must not be changed to denial.
    assert_eq!(result.ades_subindic.standard_name(), "OK", "{result:#?}");
    assert_eq!(result.best_signature_time, Some(support::at(SIGNED_AT)));
    let status = result
        .api_status
        .as_ref()
        .expect("temporal signature trust retains the actual CMS status");
    assert!(status.signature.trusted());
    assert!(
        status.signature.revoked(),
        "later authenticated leaf revocation remains a current fact"
    );
    assert_eq!(status.signature.validation_time, Some(support::at(CURRENT)));
    let event = status.signature.revocation_details.as_ref().unwrap();
    assert!(!event.ca_revoked);
    assert_eq!(
        event.revocation_date,
        Some(support::at("2020-12-01T00:00:00Z"))
    );
    assert_eq!(event.revocation_reason, Some("key_compromise"));
    assert_eq!(status.signature.error_time_horizon, event.revocation_date);
}
#[test]
fn currently_fully_checked_native_main_positive() {
    let bytes = produce("signer1");
    let svc = Evidence::new("2020-12-25");
    let ctx = context(CURRENT, &svc);
    let options = CmsValidationOptions {
        validation_order: CmsValidationOrder::SignerFirst,
        ..Default::default()
    };
    let status =
        sigis_cms::validate_cms_signature_with(&bytes, SignedContent::Encapsulated, &ctx, &options)
            .unwrap();
    assert!(
        status.signature.intact && status.signature.valid && status.signature.trusted(),
        "{status:#?}"
    );
    let result =
        with_time_validation(&bytes, None, &ctx, &QualificationSpec::default(), None).unwrap();
    assert_eq!(result.ades_subindic.standard_name(), "OK", "{result:#?}");
    assert!(result.api_status.unwrap().bottom_line());
}

#[test]
fn actual_failed_main_stays_refused_in_pure_status_transformer() {
    let bytes = produce("signer2");
    let svc = Evidence::new("2020-12-25");
    let ctx = context(CURRENT, &svc);
    let options = CmsValidationOptions {
        validation_order: CmsValidationOrder::SignerFirst,
        ..Default::default()
    };
    let status =
        sigis_cms::validate_cms_signature_with(&bytes, SignedContent::Encapsulated, &ctx, &options)
            .unwrap();
    assert!(!status.signature.trusted());
    assert!(status.timestamp_validity.as_ref().unwrap().trusted());
    let before = format!("{:?}", status.signature);
    let result = sigis_pades::ades::with_time::with_time_result(
        status,
        &QualificationSpec::default(),
        None,
        None,
        ctx.moment(),
    );
    assert_eq!(result.ades_subindic.standard_name(), "REVOKED_NO_POE");
    assert_eq!(
        format!("{:?}", result.api_status.as_ref().unwrap().signature),
        before
    );
    assert_eq!(result.best_signature_time, Some(support::at(SIGNED_AT)));
    assert!(result.qualification.is_none());
}
#[test]
fn timestamp_equality_after_revocation_and_future_never_resolve_leaf_obligation() {
    for time in [
        "2020-12-01T00:00:00Z",
        "2020-12-01T00:00:01Z",
        "2020-12-26T00:00:00Z",
    ] {
        let bytes = produce_with("signer2", Some("tsa"), time, false);
        let svc = Evidence::new("2020-12-25");
        let ctx = context(CURRENT, &svc);
        let result =
            with_time_validation(&bytes, None, &ctx, &QualificationSpec::default(), None).unwrap();
        assert_ne!(
            result.ades_subindic.standard_name(),
            "OK",
            "token at {time}: {result:#?}"
        );
        assert!(!result.api_status.unwrap().signature.trusted());
    }
}
#[test]
fn missing_wrong_purpose_and_authentically_wrong_imprint_timestamp_refuse() {
    for (tsa, wrong_imprint) in [(None, false), (Some("signer1"), false), (Some("tsa"), true)] {
        let bytes = produce_with("signer2", tsa, SIGNED_AT, wrong_imprint);
        let svc = Evidence::new("2020-12-25");
        let ctx = context(CURRENT, &svc);
        let result =
            with_time_validation(&bytes, None, &ctx, &QualificationSpec::default(), None).unwrap();
        assert_ne!(result.ades_subindic.standard_name(), "OK", "{result:#?}");
        assert!(!result.api_status.unwrap().signature.trusted());
    }
}
#[test]
fn every_exact_main_predicate_is_applied_before_context_bearing_recovery() {
    use sigis_pki_core::key_usage::KeyUsageConstraints as K;
    let values = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect();
    let profiles = [
        (
            "empty KU",
            K {
                key_usage: Some(values(&[])),
                ..Default::default()
            },
            true,
        ),
        (
            "required NR",
            K {
                key_usage: Some(values(&["non_repudiation"])),
                ..Default::default()
            },
            true,
        ),
        (
            "forbidden NR",
            K {
                key_usage_forbidden: Some(values(&["non_repudiation"])),
                ..Default::default()
            },
            false,
        ),
        (
            "any",
            K {
                key_usage: Some(values(&["non_repudiation", "key_agreement"])),
                match_all_key_usages: false,
                ..Default::default()
            },
            true,
        ),
        (
            "all",
            K {
                key_usage: Some(values(&["non_repudiation", "key_agreement"])),
                match_all_key_usages: true,
                ..Default::default()
            },
            false,
        ),
        (
            "explicit EKU",
            K {
                extd_key_usage: Some(values(&["time_stamping"])),
                explicit_extd_key_usage_required: true,
                ..Default::default()
            },
            false,
        ),
    ];
    let bytes = produce("signer2");
    for (name, predicate, expected) in profiles {
        let svc = Evidence::new("2020-12-25");
        let ctx = context(CURRENT, &svc);
        let mut options = sigis_pades::ades::AdesValidationOptions::default();
        options.exact_key_usage_settings = Some(predicate);
        let result = sigis_pades::ades::with_time::with_time_validation_with_options(
            &bytes,
            None,
            &ctx,
            &QualificationSpec::default(),
            None,
            &options,
        )
        .unwrap();
        assert_eq!(
            result.ades_subindic.standard_name() == "OK",
            expected,
            "{name}: {result:#?}"
        );
        assert_eq!(
            result.api_status.unwrap().signature.trusted(),
            expected,
            "{name}"
        );
    }
}

#[test]
fn external_time_and_noncurrent_policy_reference_cannot_replace_the_chosen_token() {
    let bytes = produce("signer2");
    let svc = Evidence::new("2020-12-25");
    let ctx = context(CURRENT, &svc);
    // This caller value is not an authenticated signature timestamp. It must
    // not create a successful bound or select a different qualification clock.
    let result = with_time_validation(
        &bytes,
        None,
        &ctx,
        &QualificationSpec::default(),
        Some(support::at("2020-10-01T00:00:00Z")),
    )
    .unwrap();
    assert_ne!(result.ades_subindic.standard_name(), "OK", "{result:#?}");
    assert!(!result.api_status.as_ref().unwrap().signature.trusted());
    assert!(result.api_status.as_ref().unwrap().signature.revoked());
    assert_eq!(
        result
            .api_status
            .as_ref()
            .unwrap()
            .signature
            .validation_time,
        Some(support::at(CURRENT))
    );

    let mut timing = *ctx.timing();
    timing.best_signature_time = support::at(SIGNED_AT);
    let noncurrent = ctx.with_timing(timing);
    let result = with_time_validation(
        &bytes,
        None,
        &noncurrent,
        &QualificationSpec::default(),
        None,
    )
    .unwrap();
    assert_ne!(result.ades_subindic.standard_name(), "OK", "{result:#?}");
    let status = result.api_status.as_ref().unwrap();
    assert!(!status.signature.trusted());
    assert!(status.signature.revoked());
    assert_eq!(status.signature.validation_time, Some(support::at(CURRENT)));
    assert_eq!(noncurrent.timing(), &timing);
}

#[test]
fn qualification_denial_keeps_the_frozen_current_revocation_payload() {
    let bytes = produce("signer2");
    let registry = Default::default();
    for (name, qualification) in [
        (
            "mandatory signer without registry",
            QualificationSpec {
                registry: None,
                requirements: Some(Default::default()),
                ts_requirements: None,
            },
        ),
        (
            "mandatory TSA without registry",
            QualificationSpec {
                registry: None,
                requirements: None,
                ts_requirements: Some(Default::default()),
            },
        ),
        (
            "mandatory unqualified signer and TSA",
            QualificationSpec {
                registry: Some(&registry),
                requirements: Some(Default::default()),
                ts_requirements: Some(Default::default()),
            },
        ),
    ] {
        let svc = Evidence::new("2020-12-25");
        let ctx = context(CURRENT, &svc);
        let options = CmsValidationOptions {
            validation_order: CmsValidationOrder::SignerFirst,
            ..Default::default()
        };
        let frozen = sigis_cms::validate::evaluate_cms_leaf_revocation(
            &bytes,
            SignedContent::Encapsulated,
            &ctx,
            &options,
        )
        .unwrap()
        .into_unresolved_status();
        assert!(frozen.signature.revoked());
        let result = with_time_validation(&bytes, None, &ctx, &qualification, None).unwrap();
        assert_ne!(
            result.ades_subindic.standard_name(),
            "OK",
            "{name}: {result:#?}"
        );
        let status = result.api_status.unwrap();
        assert!(!status.signature.trusted());
        assert_eq!(
            format!("{status:#?}"),
            format!("{frozen:#?}"),
            "{name}: qualification cannot erase/replace/retime the frozen revocation payload"
        );
    }
}

/// Produce a genuine content timestamp with a modified, freshly signed
/// TSTInfo. The signature timestamp still comes from the unchanged native TSA.
#[derive(Debug)]
struct ContentMetadataTsa {
    profile: &'static str,
}
impl sigis_pki_core::sign::TimeStamper for ContentMetadataTsa {
    fn timestamp(
        &self,
        imprint: &[u8],
        digest: DigestAlgorithm,
    ) -> sigis_pki_core::errors::Result<Vec<u8>> {
        use sigis_pki_core::asn1::{oids, tlv};
        let pki = support::pki("testing-ca");
        let ordinary = pki.tsa("tsa", support::at(SIGNED_AT));
        let token = sigis_pki_core::sign::TimeStamper::timestamp(&ordinary, imprint, digest)?;
        if imprint != DigestAlgorithm::Sha256.digest(CONTENT) {
            return Ok(token);
        }
        let sd = sigis_cms::SignedData::from_content_info_der(&token).unwrap();
        let info = tlv::Tlv::parse_exact(sd.econtent.as_deref().unwrap()).unwrap();
        let fields = info.children().unwrap();
        let mut body = Vec::new();
        for (index, field) in fields.iter().enumerate() {
            if index == 4 {
                let time = match self.profile {
                    "earlier" => b"20201031235959Z".as_slice(),
                    "fraction_after" => b"20201101000000.5Z".as_slice(),
                    _ => b"20201101000000Z".as_slice(),
                };
                body.extend(tlv::encode(0x18, time));
                if self.profile == "accuracy" {
                    // Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, ... }
                    body.extend(tlv::encode(0x30, &tlv::encode(0x02, &[1])));
                }
            } else {
                body.extend_from_slice(field.raw);
            }
        }
        let info = tlv::encode(0x30, &body);
        let signing_key = pki.signer("tsa");
        let options = CmsSignerOptions::default();
        CmsSigner {
            signer: &signing_key,
            options: &options,
        }
        .sign(
            &digest.digest(&info),
            digest,
            &CmsSignedAttributes {
                signing_time: Some(support::at(SIGNED_AT)),
                ..Default::default()
            },
            sigis_pades_sign::cms::AttrProfile::GenericCms,
            None,
            false,
            Some(cms::signed_data::EncapsulatedContentInfo {
                econtent_type: oids::CT_TST_INFO,
                econtent: Some(der::Any::encode_from(&der::asn1::OctetString::new(info)?)?),
            }),
        )
    }
}
fn check_content_timestamp_metadata(profile: &'static str, expected: bool) {
    let pki = support::pki("testing-ca");
    let signer = pki.signer("signer2");
    let options = CmsSignerOptions::default();
    let bytes = CmsSigner {
        signer: &signer,
        options: &options,
    }
    .sign_general_data(
        CONTENT,
        DigestAlgorithm::Sha256,
        false,
        true,
        Some(&ContentMetadataTsa { profile }),
        &CmsSignedAttributes {
            signing_time: Some(support::at(SIGNED_AT)),
            cades_signed_attrs: Some(sigis_pades_sign::CadesSignedAttrSpec {
                timestamp_content: true,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .unwrap();
    let svc = Evidence::new("2020-12-25");
    let ctx = context(CURRENT, &svc);
    let options = CmsValidationOptions {
        validation_order: CmsValidationOrder::SignerFirst,
        ..Default::default()
    };
    let evaluated = sigis_cms::validate::evaluate_cms_leaf_revocation(
        &bytes,
        SignedContent::Encapsulated,
        &ctx,
        &options,
    )
    .unwrap();
    let unresolved = evaluated.unresolved_status();
    assert!(unresolved.signature.intact && unresolved.signature.valid);
    assert!(unresolved.signature.revoked());
    assert!(unresolved.timestamp_validity.as_ref().unwrap().trusted());
    assert!(
        unresolved
            .content_timestamp_validity
            .as_ref()
            .unwrap()
            .trusted(),
        "this control requires a real, currently trusted CMS content token"
    );
    if let Some(dir) = std::env::var_os("HANKO_LEAF_COMPLETION_OUTPUT_DIR") {
        let path = PathBuf::from(dir).join(format!("content-{profile}-{}.cms.der", sha(&bytes)));
        std::fs::write(&path, &bytes).unwrap();
        eprintln!(
            "LEAF_COMPLETION_PRODUCER {}",
            serde_json::json!({
                "path":path,"sha256":sha(&bytes),"length":bytes.len(),"profile":profile,
                "content_sha256":sha(CONTENT),"signed_at":SIGNED_AT,
            })
        );
    }
    let eligible = evaluated.eligible_signature_timestamp().is_some();
    let resolved = evaluated.resolve_signature_timestamp();
    let result =
        with_time_validation(&bytes, None, &ctx, &QualificationSpec::default(), None).unwrap();
    eprintln!(
        "LEAF_CONTENT_METADATA_RESULT {}",
        serde_json::json!({
            "profile":profile,"input_sha256":sha(&bytes),"eligible":eligible,
            "cms_resolved_trusted":resolved.signature.trusted(),
            "with_time_subindic":result.ades_subindic.standard_name(),
            "with_time_trusted":result.api_status.as_ref().unwrap().signature.trusted(),
            "best_signature_time":result.best_signature_time.map(|t|t.to_string()),
            "validation_time":result.api_status.as_ref().unwrap().signature.validation_time.map(|t|t.to_string()),
            "revoked":result.api_status.as_ref().unwrap().signature.revoked(),
        })
    );
    assert_eq!(
        eligible, expected,
        "selected content metadata {profile} must not be truncated into proof"
    );
    assert_eq!(resolved.signature.trusted(), expected);
    assert_eq!(
        result.ades_subindic.standard_name() == "OK",
        expected,
        "{profile}: {result:#?}"
    );
    assert_eq!(result.api_status.unwrap().signature.trusted(), expected);
}
#[test]
fn canonical_content_timestamp_bounds_allow_real_completion() {
    check_content_timestamp_metadata("earlier", true);
    check_content_timestamp_metadata("equal", true);
}
#[test]
fn fractional_content_timestamp_cannot_hide_later_content_bound() {
    check_content_timestamp_metadata("fraction_after", false);
}
#[test]
fn declared_content_accuracy_cannot_authorize_the_initial_exact_bound_profile() {
    check_content_timestamp_metadata("accuracy", false);
}
