//! Tests-first exact main-signer predicate contract (zero upstream IDs).
//! L temporarily assigned this root integration target to V in shared-next.md.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/signing_integration.rs"]
mod support;

use sigis_cms::{
    validate::{ContentDigester, DataDigester},
    CmsError, CmsResult, CmsValidationOptions, CmsValidationOrder, SignedContent, SignedData,
    StandardCmsSignatureStatus, TrustProblem,
};
use sigis_pades_sign::{sign_general_data, SimpleSigner};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{
    ades::{AdesIndeterminate, AdesSubIndic},
    algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm},
    cert::Cert,
    errors::ValidationError,
    key_usage::KeyUsageConstraints,
    sign::KeySigner,
    time::Moment,
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

const TIME: &str = "2020-11-20T00:00:00Z";
const CONTENT: &[u8] = b"Exact main-signer predicate seam: genuine CMS controls";
const AMBIGUOUS: &str = "key_usage_settings and exact_key_usage_settings are mutually exclusive";

fn names(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn exact(policy: KeyUsageConstraints) -> CmsValidationOptions<'static> {
    CmsValidationOptions {
        exact_key_usage_settings: Some(policy),
        ..Default::default()
    }
}

fn context(roots: bool, revocation: &str) -> ValidationContext {
    let pki = support::pki("testing-ca");
    let mut builder = ValidationContext::builder()
        .moment(support::at(TIME))
        .point_in_time_validation(false)
        .revocation_mode(revocation);
    if roots {
        builder = builder.trust_root(pki.cert("root"));
    }
    builder.build().unwrap()
}

fn cms(signer: &dyn KeySigner, tsa: Option<&str>) -> Vec<u8> {
    let pki = support::pki("testing-ca");
    let timestamp = tsa.map(|label| pki.tsa(label, support::at(TIME)));
    sign_general_data(
        CONTENT,
        signer,
        DigestAlgorithm::Sha256,
        true,
        timestamp
            .as_ref()
            .map(|value| value as &dyn sigis_pki_core::sign::TimeStamper),
    )
    .unwrap()
}

fn validate(
    bytes: &[u8],
    context: &ValidationContext,
    options: &CmsValidationOptions<'_>,
) -> StandardCmsSignatureStatus {
    let before = format!("{context:?}");
    let policy = context.algorithm_policy_arc();
    let status = sigis_cms::validate_cms_signature_with(
        bytes,
        SignedContent::Data(CONTENT),
        context,
        options,
    )
    .unwrap();
    assert_eq!(
        format!("{context:?}"),
        before,
        "public context stays immutable"
    );
    assert!(Arc::ptr_eq(&policy, &context.algorithm_policy_arc()));
    export_case(bytes, context, options, &status);
    status
}

fn sha256(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_receipt(path: &std::path::Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    eprintln!(
        "CMS_EXACT_INPUT {}",
        serde_json::json!({
            "path": path.canonicalize().unwrap(), "length": bytes.len(), "sha256": sha256(&bytes)
        })
    );
    bytes
}

fn export_case(
    bytes: &[u8],
    ctx: &ValidationContext,
    options: &CmsValidationOptions<'_>,
    status: &StandardCmsSignatureStatus,
) {
    // Functional runtime output only, optional for normal regression runs.
    let Some(dir) = std::env::var_os("HANKO_CMS_EXACT_OUTPUT_DIR") else {
        return;
    };
    let predicate = options
        .exact_key_usage_settings
        .as_ref()
        .or(options.key_usage_settings.as_ref());
    let predicate = predicate.map(|p| {
        serde_json::json!({
            "key_usage": p.key_usage, "key_usage_forbidden": p.key_usage_forbidden,
            "extd_key_usage": p.extd_key_usage,
            "explicit_extd_key_usage_required": p.explicit_extd_key_usage_required,
            "match_all_key_usages": p.match_all_key_usages
        })
    });
    let root = support::pki("testing-ca").cert("root");
    let record = serde_json::json!({
        "test": std::thread::current().name(),
        "selector": if options.exact_key_usage_settings.is_some() { "exact" } else { "legacy" },
        "order": format!("{:?}", options.validation_order),
        "predicate": predicate,
        "validation_time": TIME,
        "has_roots": !ctx.trust_anchors().is_empty(),
        "context": format!("{ctx:?}"),
        "cms_b64": openssl::base64::encode_block(bytes), "cms_sha256": sha256(bytes),
        "content_b64": openssl::base64::encode_block(CONTENT), "content_sha256": sha256(CONTENT),
        "root_b64": openssl::base64::encode_block(root.der()), "root_sha256": sha256(root.der()),
        "native": { "intact": status.signature.intact, "valid": status.signature.valid,
            "trusted": status.signature.trusted(), "main_bottom_line": status.signature.bottom_line(),
            "overall_bottom_line": status.bottom_line(), "subindication": format!("{:?}", status.signature.trust_problem_indic),
            "trust_problem": format!("{:?}", status.signature.trust_problem),
            "timestamp_trusted": status.timestamp_validity.as_ref().map(|ts| ts.trusted()) }
    });
    let data = serde_json::to_vec_pretty(&record).unwrap();
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.json", sha256(&data)));
    std::fs::write(&path, &data).unwrap();
    eprintln!(
        "CMS_EXACT_NATIVE_CASE {}",
        serde_json::json!({"path":path,"length":data.len(),"sha256":sha256(&data),"cms_sha256":sha256(bytes)})
    );
}

fn assert_usage_rejection(status: &StandardCmsSignatureStatus) {
    assert!(status.signature.intact && status.signature.valid);
    assert!(!status.signature.trusted() && !status.bottom_line());
    assert!(matches!(
        status.signature.trust_problem,
        Some(TrustProblem::KeyUsage(_))
    ));
    assert_eq!(
        status.signature.trust_problem_indic,
        Some(AdesSubIndic::Indeterminate(
            AdesIndeterminate::CHAIN_CONSTRAINTS_FAILURE
        ))
    );
}

// This public certificate was genuinely issued with the existing fixture key.
// Its data/issuer signature are NOT generated by these unexecuted draft tests.
fn digital_only_signer() -> SimpleSigner {
    let dir = sigis_testdata::path(&["lanes", "r3-v", "cms-exact-main"]);
    let bytes = read_receipt(&dir.join("manifest.json"));
    assert_eq!(
        sha256(&bytes),
        "60f36a7996cb7aae8bb4a1cf50834b27d81fe2d29a073152ae0033f1629715b6"
    );
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let cert_bytes = read_receipt(&dir.join(manifest["certificate"]["file"].as_str().unwrap()));
    assert_eq!(
        cert_bytes.len(),
        manifest["certificate"]["length"].as_u64().unwrap() as usize
    );
    assert_eq!(
        sha256(&cert_bytes),
        manifest["certificate"]["sha256"].as_str().unwrap()
    );
    let leaf = Cert::from_der(&cert_bytes).unwrap();
    let pki = support::pki("testing-ca");
    assert_eq!(
        sigis_pki_core::key_usage::cert_key_usages(&leaf).unwrap(),
        names(&["digital_signature"])
    );
    assert_ne!(leaf.der(), pki.cert("signer1").der());
    assert_eq!(leaf.serial_bytes(), pki.cert("signer1").serial_bytes());
    assert_eq!(leaf.public_key(), pki.cert("signer1").public_key());
    SimpleSigner::new(
        pki.key(&pki.key_label_of("signer1")),
        leaf,
        vec![pki.cert("root"), pki.cert("interm")],
    )
    .unwrap()
}

#[test]
fn absent_exact_policy_preserves_ordinary_non_repudiation_default() {
    let ctx = context(true, "none");
    let normal = cms(&support::pki("testing-ca").signer("signer1"), Some("tsa"));
    let no_nr = cms(&digital_only_signer(), Some("tsa"));
    for options in [
        CmsValidationOptions::default(),
        CmsValidationOptions {
            exact_key_usage_settings: None,
            ..Default::default()
        },
    ] {
        assert!(validate(&normal, &ctx, &options).bottom_line());
        assert_usage_rejection(&validate(&no_nr, &ctx, &options));
    }
}

#[test]
fn an_explicit_empty_exact_predicate_omits_only_implicit_main_usage() {
    let bytes = cms(&digital_only_signer(), Some("tsa"));
    let ctx = context(true, "none");
    for order in [
        CmsValidationOrder::TimestampsFirst,
        CmsValidationOrder::SignerFirst,
    ] {
        let options = |policy| CmsValidationOptions {
            validation_order: order,
            ..exact(policy)
        };
        let ordinary = CmsValidationOptions {
            validation_order: order,
            ..Default::default()
        };
        assert_usage_rejection(&validate(&bytes, &ctx, &ordinary));
        assert!(validate(
            &bytes,
            &ctx,
            &options(KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature"])),
                ..Default::default()
            })
        )
        .bottom_line());
        assert_usage_rejection(&validate(
            &bytes,
            &ctx,
            &options(KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation"])),
                ..Default::default()
            }),
        ));
        for policy in [
            KeyUsageConstraints::default(),
            KeyUsageConstraints {
                key_usage: Some(BTreeSet::new()),
                ..Default::default()
            },
        ] {
            let accepted = validate(&bytes, &ctx, &options(policy));
            assert!(
                accepted.signature.intact && accepted.signature.valid && accepted.bottom_line()
            );
            assert!(accepted.timestamp_validity.as_ref().unwrap().trusted());
            assert!(
                accepted
                    .signature
                    .validation_path
                    .as_ref()
                    .unwrap()
                    .pkix_len()
                    > 0
            );
        }
    }
}

#[test]
fn exact_forbidden_usage_is_not_dropped_like_the_legacy_facade_setting() {
    let bytes = cms(&support::pki("testing-ca").signer("signer1"), None);
    let ctx = context(true, "none");
    for order in [
        CmsValidationOrder::TimestampsFirst,
        CmsValidationOrder::SignerFirst,
    ] {
        let exact = |policy| CmsValidationOptions {
            validation_order: order,
            ..exact(policy)
        };
        assert!(validate(
            &bytes,
            &ctx,
            &exact(KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation"])),
                ..Default::default()
            })
        )
        .bottom_line());
        assert_usage_rejection(&validate(
            &bytes,
            &ctx,
            &exact(KeyUsageConstraints {
                key_usage: Some(names(&["key_encipherment"])),
                ..Default::default()
            }),
        ));
        let predicate = KeyUsageConstraints {
            key_usage: Some(names(&["non_repudiation"])),
            key_usage_forbidden: Some(names(&["non_repudiation"])),
            ..Default::default()
        };
        let legacy = CmsValidationOptions {
            validation_order: order,
            key_usage_settings: Some(predicate.clone()),
            ..Default::default()
        };
        assert!(validate(&bytes, &ctx, &legacy).bottom_line());
        assert_usage_rejection(&validate(&bytes, &ctx, &exact(predicate)));
        // Preserve existing native Core forbidden-only behavior. Pinned Python
        // skips this check when positive KU is absent; do not claim global parity.
        assert_usage_rejection(&validate(
            &bytes,
            &ctx,
            &exact(KeyUsageConstraints {
                key_usage_forbidden: Some(names(&["non_repudiation"])),
                ..Default::default()
            }),
        ));
        assert!(validate(
            &bytes,
            &ctx,
            &exact(KeyUsageConstraints {
                key_usage_forbidden: Some(names(&["key_encipherment"])),
                ..Default::default()
            })
        )
        .bottom_line());
    }
}

#[test]
fn exact_match_all_flag_is_preserved_and_ordinary_normalization_is_unchanged() {
    let bytes = cms(&support::pki("testing-ca").signer("signer1"), None);
    let ctx = context(true, "none");
    let any = KeyUsageConstraints {
        key_usage: Some(names(&["non_repudiation", "key_encipherment"])),
        match_all_key_usages: false,
        ..Default::default()
    };
    let all = KeyUsageConstraints {
        match_all_key_usages: true,
        ..any.clone()
    };
    for order in [
        CmsValidationOrder::TimestampsFirst,
        CmsValidationOrder::SignerFirst,
    ] {
        let exact = |policy| CmsValidationOptions {
            validation_order: order,
            ..exact(policy)
        };
        assert!(validate(&bytes, &ctx, &exact(any.clone())).bottom_line());
        assert_usage_rejection(&validate(&bytes, &ctx, &exact(all.clone())));
        let legacy = CmsValidationOptions {
            validation_order: order,
            key_usage_settings: Some(all.clone()),
            ..Default::default()
        };
        assert!(validate(&bytes, &ctx, &legacy).bottom_line());
    }
}

#[test]
fn exact_optional_eku_flag_is_preserved_only_for_the_main_signer() {
    let pki = support::pki("testing-ca");
    assert!(sigis_pki_core::key_usage::cert_extended_key_usages(&pki.cert("signer1")).is_none());
    let bytes = cms(&pki.signer("signer1"), Some("tsa"));
    let ctx = context(true, "none");
    let optional = KeyUsageConstraints {
        key_usage: Some(names(&["non_repudiation"])),
        extd_key_usage: Some(names(&["server_auth"])),
        explicit_extd_key_usage_required: false,
        ..Default::default()
    };
    let accepted = validate(&bytes, &ctx, &exact(optional.clone()));
    assert!(accepted.bottom_line());
    assert!(accepted.timestamp_validity.as_ref().unwrap().trusted());
    let required = KeyUsageConstraints {
        explicit_extd_key_usage_required: true,
        ..optional.clone()
    };
    assert_usage_rejection(&validate(&bytes, &ctx, &exact(required)));
    let legacy = CmsValidationOptions {
        key_usage_settings: Some(optional),
        ..Default::default()
    };
    assert_usage_rejection(&validate(&bytes, &ctx, &legacy));
}

#[test]
fn exact_empty_eku_set_is_not_confused_with_no_eku_requirement() {
    let pki = support::pki("testing-ca");
    assert!(sigis_pki_core::key_usage::cert_extended_key_usages(&pki.cert("tsa")).is_some());
    // Using this issued certificate as an explicitly unrestricted MAIN signer
    // does not alter its meaning when separately used as a timestamp signer.
    let bytes = cms(&pki.signer("tsa"), None);
    let ctx = context(true, "none");
    assert!(validate(&bytes, &ctx, &exact(KeyUsageConstraints::default())).bottom_line());
    assert!(validate(
        &bytes,
        &ctx,
        &exact(KeyUsageConstraints {
            extd_key_usage: Some(names(&["time_stamping"])),
            ..Default::default()
        })
    )
    .bottom_line());
    assert_usage_rejection(&validate(
        &bytes,
        &ctx,
        &exact(KeyUsageConstraints {
            extd_key_usage: Some(names(&["server_auth"])),
            ..Default::default()
        }),
    ));
    assert_usage_rejection(&validate(
        &bytes,
        &ctx,
        &exact(KeyUsageConstraints {
            extd_key_usage: Some(BTreeSet::new()),
            ..Default::default()
        }),
    ));
}

struct DigestSentinel(AtomicUsize);
impl ContentDigester for DigestSentinel {
    fn digest(&self, _: &AlgorithmIdentifierOwned) -> CmsResult<Vec<u8>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CmsError::Malformed(
            "digest sentinel was reached before ambiguity rejection".into(),
        ))
    }
}

#[test]
fn both_selector_fields_reject_even_equal_values_before_digest_work() {
    let bytes = cms(&support::pki("testing-ca").signer("signer1"), None);
    let sd = SignedData::from_der(&bytes).unwrap();
    let ctx = context(true, "none");
    let before = format!("{ctx:?}");
    for exact_policy in [
        KeyUsageConstraints::default(),
        KeyUsageConstraints {
            key_usage: Some(names(&["key_encipherment"])),
            ..Default::default()
        },
    ] {
        for order in [
            CmsValidationOrder::TimestampsFirst,
            CmsValidationOrder::SignerFirst,
        ] {
            let digest = DigestSentinel(AtomicUsize::new(0));
            let options = CmsValidationOptions {
                validation_order: order,
                key_usage_settings: Some(KeyUsageConstraints::default()),
                exact_key_usage_settings: Some(exact_policy.clone()),
                ..Default::default()
            };
            let error = sigis_cms::validate::validate_detached_cms_with(
                &sd,
                &digest,
                false,
                Some(&ctx),
                &options,
            )
            .unwrap_err();
            assert!(matches!(&error, CmsError::Malformed(message) if message == AMBIGUOUS));
            assert_eq!(digest.0.load(Ordering::SeqCst), 0);
            assert_eq!(format!("{ctx:?}"), before);
            assert!(ctx.other_certs().is_empty());
        }
    }
}

#[test]
fn an_exact_empty_main_predicate_cannot_relax_fixed_timestamp_purpose() {
    let pki = support::pki("testing-ca");
    let ctx = context(true, "none");
    let good = cms(&pki.signer("signer1"), Some("tsa"));
    let wrong_purpose = cms(&pki.signer("signer1"), Some("signer1"));
    let options = exact(KeyUsageConstraints::default());
    let positive = validate(&good, &ctx, &options);
    assert!(positive.bottom_line());
    assert!(
        positive
            .timestamp_validity
            .as_ref()
            .unwrap()
            .signature
            .validation_path
            .as_ref()
            .unwrap()
            .pkix_len()
            > 0
    );
    let rejected = validate(&wrong_purpose, &ctx, &options);
    assert!(rejected.signature.intact && rejected.signature.valid && rejected.signature.trusted());
    let token = rejected.timestamp_validity.as_ref().unwrap();
    assert!(token.signature.intact && token.signature.valid);
    assert_eq!(
        token.signature.signing_cert.as_ref(),
        Some(&pki.cert("signer1"))
    );
    assert!(matches!(
        token.signature.trust_problem,
        Some(TrustProblem::KeyUsage(_))
    ));
    assert!(!token.trusted() && !rejected.bottom_line());
}

#[test]
fn exact_empty_never_waives_root_or_mandatory_revocation_requirements() {
    let bytes = cms(&support::pki("testing-ca").signer("signer1"), None);
    let options = exact(KeyUsageConstraints::default());
    assert!(validate(&bytes, &context(true, "none"), &options).bottom_line());
    for ctx in [context(false, "none"), context(true, "require")] {
        assert!(ctx.fetchers().is_empty());
        let rejected = validate(&bytes, &ctx, &options);
        assert!(rejected.signature.intact && rejected.signature.valid);
        assert!(!rejected.signature.trusted() && !rejected.bottom_line());
        assert!(matches!(
            rejected.signature.trust_problem,
            Some(TrustProblem::Path(_))
        ));
    }
}

#[derive(Debug)]
struct DenySha256(Option<Moment>);
impl AlgorithmUsagePolicy for DenySha256 {
    fn digest_algorithm_allowed(
        &self,
        _: &const_oid::ObjectIdentifier,
        _: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint {
            allowed: false,
            not_allowed_after: self.0,
            failure_reason: Some("deny with diagnostic date 2099-01-01".into()),
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

#[test]
fn exact_empty_preserves_typed_permanent_and_timed_algorithm_denials() {
    let pki = support::pki("testing-ca");
    let bytes = cms(&pki.signer("signer1"), None);
    for cutoff in [None, Some(support::at("2020-11-19T00:00:00Z"))] {
        let ctx = ValidationContext::builder()
            .trust_root(pki.cert("root"))
            .moment(support::at(TIME))
            .point_in_time_validation(false)
            .revocation_mode("none")
            .algorithm_policy(Arc::new(DenySha256(cutoff)))
            .build()
            .unwrap();
        let rejected = validate(&bytes, &ctx, &exact(KeyUsageConstraints::default()));
        assert!(rejected.signature.intact && rejected.signature.valid);
        assert!(!rejected.signature.trusted() && !rejected.bottom_line());
        assert_eq!(rejected.signature.error_time_horizon, cutoff);
        assert!(matches!(&rejected.signature.trust_problem,
            Some(TrustProblem::Path(ValidationError::DisallowedAlgorithm { banned_since, .. })) if *banned_since == cutoff));
        assert_eq!(
            rejected.signature.trust_problem_indic,
            Some(AdesSubIndic::Indeterminate(if cutoff.is_some() {
                AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE
            } else {
                AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE
            }))
        );
    }
}

#[test]
fn signer_first_integrity_failures_return_before_timestamp_statuses() {
    let bytes = cms(&support::pki("testing-ca").signer("signer1"), Some("tsa"));
    let mut sd = SignedData::from_der(&bytes).unwrap();
    assert_eq!(sd.signer_infos.len(), 1);
    assert!(!sd.signer_infos[0].signature.is_empty());
    let ctx = context(true, "none");
    let ac = context(true, "none");
    let options = CmsValidationOptions {
        validation_order: CmsValidationOrder::SignerFirst,
        ac_validation_context: Some(&ac),
        ..exact(KeyUsageConstraints::default())
    };
    assert!(validate(&bytes, &ctx, &options).bottom_line());
    // A meaningful stage-visit control: malformed supplied AC bytes yield an
    // actual parse error when visited, not an invented trusted attribute.
    sd.attribute_certificates.push(vec![0x30, 0]);
    let visited = sigis_cms::validate::validate_detached_cms_with(
        &sd,
        &DataDigester::new(CONTENT),
        false,
        Some(&ctx),
        &options,
    )
    .unwrap();
    assert!(visited.signature.intact && visited.signature.valid);
    assert_eq!(visited.ac_validation_errs.as_ref().unwrap().len(), 1);
    let token = sd.signer_infos[0]
        .unsigned_attrs
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|attribute| {
            attribute
                .oid
                .is(&sigis_pki_core::asn1::oids::AA_SIGNATURE_TIME_STAMP_TOKEN)
        })
        .unwrap();
    // Only the unsigned attribute changes. Reaching this later stage is a
    // genuine parse failure; an invalid outer signature must return first.
    token.values = vec![b"not a DER timestamp".to_vec()];
    for mutate_signature in [false, true] {
        let mut selected = sd.clone();
        let mut content = CONTENT.to_vec();
        if mutate_signature {
            selected.signer_infos[0].signature[0] ^= 1;
        } else {
            content[0] ^= 1;
        }
        let before = (format!("{ctx:?}"), format!("{ac:?}"));
        let rejected = sigis_cms::validate::validate_detached_cms_with(
            &selected,
            &DataDigester::new(&content),
            false,
            Some(&ctx),
            &options,
        )
        .unwrap();
        assert_eq!(rejected.signature.intact, mutate_signature);
        assert_eq!(rejected.signature.valid, !mutate_signature);
        assert!(!rejected.bottom_line());
        assert!(
            rejected.timestamp_validity.is_none() && rejected.content_timestamp_validity.is_none()
        );
        assert!(
            rejected.cades_signer_attrs.is_none()
                && rejected.ac_attrs.is_none()
                && rejected.ac_validation_errs.is_none()
        );
        assert_eq!((format!("{ctx:?}"), format!("{ac:?}")), before);
        let legacy_order = CmsValidationOptions {
            validation_order: CmsValidationOrder::TimestampsFirst,
            ..options.clone()
        };
        assert!(
            sigis_cms::validate::validate_detached_cms_with(
                &selected,
                &DataDigester::new(&content),
                false,
                Some(&ctx),
                &legacy_order,
            )
            .is_err(),
            "the malformed token is really reached in legacy order"
        );
    }
    // The private unit guards still supply callback/registration observations;
    // public output absence alone is weaker than a private zero-visit trace.
}

#[test]
fn exact_empty_does_not_bypass_signing_certificate_attribute_binding() {
    let pki = support::pki("testing-ca");
    let bytes = cms(&pki.signer("signer1"), None);
    let ctx = context(true, "none");
    let options = exact(KeyUsageConstraints::default());
    assert!(validate(&bytes, &ctx, &options).bottom_line());
    let mut sd = SignedData::from_der(&bytes).unwrap();
    assert!(
        sigis_cms::validate::get_signing_cert_attr(sd.signer_infos[0].signed_attr_list())
            .unwrap()
            .is_some()
    );
    let replacement = digital_only_signer().signing_cert().clone();
    let original = pki.cert("signer1");
    assert_eq!(original.serial_bytes(), replacement.serial_bytes());
    assert_eq!(original.public_key(), replacement.public_key());
    assert_ne!(original.der(), replacement.der());
    let mut changed = 0;
    for certificate in &mut sd.certificates {
        if certificate.as_slice() == original.der() {
            *certificate = replacement.der().to_vec();
            changed += 1;
        }
    }
    assert_eq!(changed, 1);
    let error = sigis_cms::validate::validate_detached_cms_with(
        &sd,
        &DataDigester::new(CONTENT),
        false,
        Some(&ctx),
        &options,
    )
    .unwrap_err();
    assert_eq!(
        error.ades_subindication(),
        AdesSubIndic::Indeterminate(AdesIndeterminate::NO_SIGNING_CERTIFICATE_FOUND)
    );
    assert!(error
        .to_string()
        .contains("Signing certificate attribute does not match"));
}
