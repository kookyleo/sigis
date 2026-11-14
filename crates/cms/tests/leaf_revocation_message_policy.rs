//! Tests first for the additive selected-message gate in the narrow producer.
//!
//! These are supplemental contract tests, not additional upstream function IDs.
//! The input manifests describe construction and prospective obligations only.
//! Public CMS operations, never a manually invoked policy, establish outcomes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use const_oid::ObjectIdentifier;
use der::Encode;
use sigis_cms::{
    policy::{default_policy, CmsAlgorithmUsagePolicy},
    signed_data::find_unique_cms_attribute,
    validate::{evaluate_cms_leaf_revocation, CmsLeafRevocationEvaluation},
    validate_cms_signature_with, CmsValidationOptions, CmsValidationOrder, SignedContent,
    SignedData, StandardCmsSignatureStatus, TrustProblem,
};
use sigis_pki_certvalidator::{
    CertRevTrustPolicy, FreshnessReqType, RevocationCheckingPolicy, RevocationCheckingRule,
    ValidationContext,
};
use sigis_pki_core::{
    algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm},
    asn1::oids,
    cert::Cert,
    errors::ValidationError,
    key_usage::KeyUsageConstraints,
    time::Moment,
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const BASE: &str = "lanes/r3-v/leaf-revoked-qualification-policy";
const V: &str = "2020-12-25T00:00:00Z";
const T: &str = "2020-11-01T00:00:00Z";
const C: &str = "2020-10-15T00:00:00Z";
const R: &str = "2020-12-01T00:00:00Z";
const SHA512_RSA_DER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00,
];

fn moment(value: &str) -> Moment {
    Moment::parse_rfc3339(value).unwrap()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn input(name: &str) -> Vec<u8> {
    let base = sigis_testdata::data_dir().join(BASE);
    let origin_path = base.join("origin.json");
    let origin_bytes = std::fs::read(&origin_path).unwrap();
    eprintln!(
        "LEAF_MESSAGE_CMS_INPUT {}",
        serde_json::json!({
            "path": origin_path.canonicalize().unwrap(), "length": origin_bytes.len(),
            "sha256": hex(&DigestAlgorithm::Sha256.digest(&origin_bytes))
        })
    );
    let manifest: serde_json::Value = serde_json::from_slice(&origin_bytes).unwrap();
    let relative = format!("messages/{name}");
    let rows: Vec<_> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["path"].as_str() == Some(relative.as_str()))
        .collect();
    assert_eq!(rows.len(), 1, "one finite origin binding for {relative}");
    let path = base.join(&relative);
    let value = std::fs::read(&path).unwrap();
    let digest = hex(&DigestAlgorithm::Sha256.digest(&value));
    assert_eq!(rows[0]["length"].as_u64(), Some(value.len() as u64));
    assert_eq!(rows[0]["sha256"].as_str(), Some(digest.as_str()));
    eprintln!(
        "LEAF_MESSAGE_CMS_INPUT {}",
        serde_json::json!({
            "path": path.canonicalize().unwrap(), "length": value.len(), "sha256": digest
        })
    );
    value
}

fn cert(role: &str) -> Cert {
    Cert::from_der(&input(&format!("certs/{role}.cert.der"))).unwrap()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PolicyCall {
    Signature {
        algorithm: Vec<u8>,
        key: Option<Vec<u8>>,
        reference: Option<Moment>,
    },
    Digest {
        algorithm: ObjectIdentifier,
        reference: Option<Moment>,
    },
    Combination {
        signature: Vec<u8>,
        digest: Vec<u8>,
        reference: Option<Moment>,
    },
}

#[derive(Debug)]
struct MessagePolicy {
    delegate: Arc<dyn CmsAlgorithmUsagePolicy>,
    expected_keys: Vec<Vec<u8>>,
    deny: bool,
    cutoff: Option<Moment>,
    calls: Mutex<Vec<PolicyCall>>,
    unexpected: Mutex<Vec<PolicyCall>>,
}

impl MessagePolicy {
    fn new(signers: &[&str], deny: bool, cutoff: Option<Moment>) -> Arc<Self> {
        Arc::new(Self {
            delegate: default_policy(),
            expected_keys: signers
                .iter()
                .map(|role| input(&format!("certs/{role}.spki.der")))
                .collect(),
            deny,
            cutoff,
            calls: Mutex::new(Vec::new()),
            unexpected: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<PolicyCall> {
        self.calls.lock().unwrap().clone()
    }

    fn message_calls(&self) -> Vec<PolicyCall> {
        self.calls()
            .into_iter()
            .filter(|call| {
                matches!(call,
                    PolicyCall::Signature { algorithm, .. } if algorithm == SHA512_RSA_DER
                )
            })
            .collect()
    }

    fn assert_bindings(&self) {
        assert!(
            self.unexpected.lock().unwrap().is_empty(),
            "unexpected discriminator bindings must refuse: {:?}",
            self.unexpected
        );
        for call in self.message_calls() {
            let PolicyCall::Signature {
                algorithm,
                key,
                reference,
            } = call
            else {
                unreachable!()
            };
            assert_eq!(algorithm, SHA512_RSA_DER);
            assert_eq!(
                reference,
                Some(moment(V)),
                "use original v, never token t or cutoff"
            );
            assert!(key.is_some_and(|key| self.expected_keys.contains(&key)));
        }
        let calls = self.calls();
        assert!(
            calls
                .iter()
                .any(|call| matches!(call, PolicyCall::Digest { .. })),
            "unrelated digest decisions remain delegated and logged"
        );
        assert!(
            calls.iter().any(|call| matches!(call,
                PolicyCall::Signature { algorithm, .. } if algorithm != SHA512_RSA_DER
            )),
            "certificate/MAIN/TSA decisions remain delegated and logged"
        );
    }
}

impl AlgorithmUsagePolicy for MessagePolicy {
    fn signature_algorithm_allowed(
        &self,
        algorithm: &AlgorithmIdentifierOwned,
        reference: Option<Moment>,
        key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        let call = PolicyCall::Signature {
            algorithm: algorithm.to_der().unwrap(),
            key: key.map(|key| key.to_der().unwrap()),
            reference,
        };
        self.calls.lock().unwrap().push(call.clone());
        // The OID only identifies discriminator calls. Permission depends on
        // the complete actual AlgorithmIdentifier, actual signer key and v.
        if algorithm.oid == oids::SHA512_WITH_RSA {
            let bound = algorithm.to_der().unwrap() == SHA512_RSA_DER
                && reference == Some(moment(V))
                && key.is_some_and(|key| self.expected_keys.contains(&key.to_der().unwrap()));
            if !bound {
                self.unexpected.lock().unwrap().push(call);
                return AlgorithmUsageConstraint::denied("unexpected selected-message binding");
            }
            if self.deny {
                return AlgorithmUsageConstraint {
                    not_allowed_after: self.cutoff,
                    ..AlgorithmUsageConstraint::denied("selected message policy denial")
                };
            }
        }
        self.delegate
            .signature_algorithm_allowed(algorithm, reference, key)
    }

    fn digest_algorithm_allowed(
        &self,
        algorithm: &ObjectIdentifier,
        reference: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        self.calls.lock().unwrap().push(PolicyCall::Digest {
            algorithm: *algorithm,
            reference,
        });
        self.delegate.digest_algorithm_allowed(algorithm, reference)
    }

    fn min_rsa_key_size(&self) -> usize {
        self.delegate.min_rsa_key_size()
    }

    fn digest_combination(
        &self,
        signature: &AlgorithmIdentifierOwned,
        digest: &AlgorithmIdentifierOwned,
        reference: Option<Moment>,
    ) -> Option<AlgorithmUsageConstraint> {
        Some(self.digest_combination_allowed(signature, digest, reference))
    }
}

impl CmsAlgorithmUsagePolicy for MessagePolicy {
    fn digest_combination_allowed(
        &self,
        signature: &AlgorithmIdentifierOwned,
        digest: &AlgorithmIdentifierOwned,
        reference: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        self.calls.lock().unwrap().push(PolicyCall::Combination {
            signature: signature.to_der().unwrap(),
            digest: digest.to_der().unwrap(),
            reference,
        });
        self.delegate
            .digest_combination_allowed(signature, digest, reference)
    }
}

#[derive(Clone, Copy, Debug)]
struct Profile {
    name: &'static str,
    rule: RevocationCheckingRule,
    leaf_ocsp: Option<&'static str>,
    leaf_crl: Option<&'static str>,
    ancestor_ocsp: &'static str,
    side_ocsp: Option<&'static str>,
    signers: &'static [&'static str],
    unique_discriminators: usize,
}

const DIRECT: Profile = Profile {
    name: "direct OCSP",
    rule: RevocationCheckingRule::OcspRequired,
    leaf_ocsp: Some("leaf-direct-revoked-sha512.der"),
    leaf_crl: None,
    ancestor_ocsp: "ancestor-good-sha256.der",
    side_ocsp: None,
    signers: &["issuing"],
    unique_discriminators: 1,
};

fn profiles() -> Vec<Profile> {
    vec![
        DIRECT,
        Profile {
            name: "direct CRL",
            rule: RevocationCheckingRule::CrlRequired,
            leaf_ocsp: None,
            leaf_crl: Some("leaf-revoked-sha512.der"),
            ..DIRECT
        },
        Profile {
            name: "delegated actual signer",
            leaf_ocsp: Some("leaf-delegated-revoked-sha512.der"),
            side_ocsp: Some("delegated-responder-good-sha256.der"),
            signers: &["responder_delegated"],
            ..DIRECT
        },
        Profile {
            name: "NoCheck responder actual signer",
            leaf_ocsp: Some("leaf-nocheck-revoked-sha512.der"),
            signers: &["responder_nocheck"],
            ..DIRECT
        },
        Profile {
            name: "selected ancestor Good",
            leaf_ocsp: Some("leaf-direct-revoked-sha256.der"),
            ancestor_ocsp: "ancestor-good-sha512.der",
            signers: &["root"],
            ..DIRECT
        },
        Profile {
            name: "selected delegated side-path Good",
            leaf_ocsp: Some("leaf-delegated-revoked-sha256.der"),
            side_ocsp: Some("delegated-responder-good-sha512.der"),
            ..DIRECT
        },
        Profile {
            name: "leaf and ancestor independent actual signers",
            ancestor_ocsp: "ancestor-good-sha512.der",
            signers: &["issuing", "root"],
            unique_discriminators: 2,
            ..DIRECT
        },
        Profile {
            name: "delegated leaf and side independent actual signers",
            leaf_ocsp: Some("leaf-delegated-revoked-sha512.der"),
            side_ocsp: Some("delegated-responder-good-sha512.der"),
            signers: &["responder_delegated", "issuing"],
            unique_discriminators: 2,
            ..DIRECT
        },
        Profile {
            name: "Both OCSP discriminator",
            rule: RevocationCheckingRule::CrlAndOcspRequired,
            leaf_crl: Some("leaf-revoked-sha256.der"),
            ..DIRECT
        },
        Profile {
            name: "Both CRL discriminator",
            rule: RevocationCheckingRule::CrlAndOcspRequired,
            leaf_ocsp: Some("leaf-direct-revoked-sha256.der"),
            leaf_crl: Some("leaf-revoked-sha512.der"),
            ..DIRECT
        },
        Profile {
            name: "Both distinct messages same algorithm and signer",
            rule: RevocationCheckingRule::CrlAndOcspRequired,
            leaf_crl: Some("leaf-revoked-sha512.der"),
            unique_discriminators: 2,
            ..DIRECT
        },
    ]
}

fn context(
    profile: Profile,
    policy: Arc<MessagePolicy>,
    roots: bool,
    evidence: bool,
) -> ValidationContext {
    let mut revocation = CertRevTrustPolicy::new(RevocationCheckingPolicy {
        ee_certificate_rule: profile.rule,
        intermediate_ca_cert_rule: profile.rule,
    });
    revocation.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    let mut builder = ValidationContext::builder()
        .moment(moment(V))
        .point_in_time_validation(false)
        .revinfo_policy(revocation)
        .algorithm_policy(policy);
    if roots {
        builder = builder.trust_root(cert("root"));
    }
    if evidence {
        builder = builder
            .ocsp_response(input(&format!("ocsp/{}", profile.ancestor_ocsp)))
            .ocsp_response(input("ocsp/content-tsa-good-sha256.der"))
            .ocsp_response(input("ocsp/signature-tsa-good-sha256.der"))
            .crl(input("crl/ancestor-good-sha256.der"));
        if let Some(name) = profile.leaf_ocsp {
            builder = builder.ocsp_response(input(&format!("ocsp/{name}")));
        }
        if let Some(name) = profile.leaf_crl {
            builder = builder.crl(input(&format!("crl/{name}")));
        }
        if let Some(name) = profile.side_ocsp {
            builder = builder.ocsp_response(input(&format!("ocsp/{name}")));
        }
    }
    // No certificate is supplied out of band: the original CMS role
    // registration and authenticated responder packaging must suffice.
    builder.build().unwrap()
}

fn orders() -> [CmsValidationOrder; 2] {
    [
        CmsValidationOrder::TimestampsFirst,
        CmsValidationOrder::SignerFirst,
    ]
}

fn assert_timestamps(status: &StandardCmsSignatureStatus) {
    let signature = status
        .timestamp_validity
        .as_ref()
        .expect("real signature TST");
    let content = status
        .content_timestamp_validity
        .as_ref()
        .expect("real content TST");
    for (timestamp, role, bound) in [(signature, "signature_tsa", T), (content, "content_tsa", C)] {
        assert!(timestamp.trusted(), "{role}: {timestamp:#?}");
        assert_eq!(timestamp.timestamp, moment(bound));
        assert_eq!(timestamp.signature.validation_time, Some(moment(V)));
        assert_eq!(timestamp.signature.signing_cert.as_ref(), Some(&cert(role)));
        assert!(timestamp.signature.validation_path.is_some());
    }
    assert_ne!(
        signature.signature.signing_cert,
        content.signature.signing_cert
    );
}

fn assert_ordinary_revoked(status: &StandardCmsSignatureStatus) {
    assert!(
        status.signature.intact && status.signature.valid,
        "{status:#?}"
    );
    assert!(!status.signature.trusted());
    assert!(matches!(
        status.signature.trust_problem,
        Some(TrustProblem::Path(ValidationError::Revoked { .. }))
    ));
    assert_eq!(status.signature.validation_time, Some(moment(V)));
    assert!(status.signature.validation_path.is_some());
    let event = status.signature.revocation_details.as_ref().unwrap();
    assert!(!event.ca_revoked);
    assert_eq!(event.revocation_date, Some(moment(R)));
    assert_eq!(event.revocation_reason, Some("key_compromise"));
    assert_eq!(status.signature.error_time_horizon, Some(moment(R)));
    assert_timestamps(status);
}

fn frozen_refusal(evaluated: CmsLeafRevocationEvaluation<'_, '_>, policy: &MessagePolicy) {
    assert!(evaluated.eligible_signature_timestamp().is_none());
    let frozen = format!("{:#?}", evaluated.unresolved_status());
    let calls = policy.calls();
    let resolved = evaluated.resolve_signature_timestamp();
    assert!(!resolved.signature.trusted());
    assert!(!resolved.bottom_line());
    assert_eq!(
        format!("{resolved:#?}"),
        frozen,
        "refusal moves the whole already-frozen payload, including typed errors and tokens"
    );
    assert_eq!(
        policy.calls(),
        calls,
        "resolution performs no new policy callbacks"
    );
}

fn allowed_control(profile: Profile, order: CmsValidationOrder) {
    let data = input("cms/main.cms.der");
    let policy = MessagePolicy::new(profile.signers, false, None);
    let ctx = context(profile, policy.clone(), true, true);
    let options = CmsValidationOptions {
        validation_order: order,
        ..Default::default()
    };
    let evaluated =
        evaluate_cms_leaf_revocation(&data, SignedContent::Encapsulated, &ctx, &options).unwrap();
    assert_ordinary_revoked(evaluated.unresolved_status());
    assert!(
        evaluated.eligible_signature_timestamp().is_some(),
        "{}, {order:?}",
        profile.name
    );
    let unresolved = evaluated.unresolved_status().clone();
    let calls = policy.calls();
    let result = evaluated.resolve_signature_timestamp();
    assert!(
        result.bottom_line(),
        "{}, {order:?}: {result:#?}",
        profile.name
    );
    assert!(result.signature.revoked());
    assert_eq!(
        result.signature.validation_path,
        unresolved.signature.validation_path
    );
    assert_eq!(
        result.signature.revocation_details,
        unresolved.signature.revocation_details
    );
    assert_eq!(result.signature.error_time_horizon, Some(moment(R)));
    assert_eq!(result.signature.validation_time, Some(moment(V)));
    assert_timestamps(&result);
    assert_eq!(policy.calls(), calls);
    policy.assert_bindings();
}

#[test]
fn genuine_allowed_message_profiles_complete_in_both_cms_orders() {
    for profile in profiles() {
        for order in orders() {
            allowed_control(profile, order);
        }
    }
}

#[test]
fn selected_messages_are_queried_once_per_operation_with_full_actual_bindings() {
    for profile in profiles() {
        for order in orders() {
            allowed_control(profile, order);
            let data = input("cms/main.cms.der");
            let policy = MessagePolicy::new(profile.signers, false, None);
            let ctx = context(profile, policy.clone(), true, true);
            let options = CmsValidationOptions {
                validation_order: order,
                ..Default::default()
            };
            for operation in 1..=2 {
                let evaluated = evaluate_cms_leaf_revocation(
                    &data,
                    SignedContent::Encapsulated,
                    &ctx,
                    &options,
                )
                .unwrap();
                assert_ordinary_revoked(evaluated.unresolved_status());
                let calls = policy.calls();
                let frozen = format!("{:#?}", evaluated.unresolved_status());
                let status = evaluated.into_unresolved_status();
                assert_eq!(format!("{status:#?}"), frozen);
                assert_eq!(policy.calls(), calls, "conversion never queries policy");
                assert_eq!(policy.message_calls().len(), profile.unique_discriminators * operation,
                    "{}, {order:?}: exact operation-local message identity; no cross-operation cache",
                    profile.name);
                policy.assert_bindings();
            }
        }
    }
}

#[test]
fn producer_message_denial_is_typed_before_cms_freeze_and_never_resolves() {
    for profile in profiles() {
        for order in orders() {
            allowed_control(profile, order);
            // t < cutoff < v deliberately remains a denial. Permanent denial
            // is separate; neither case permits a weaker retry at token time.
            for cutoff in [None, Some(moment("2020-11-15T00:00:00Z"))] {
                let data = input("cms/main.cms.der");
                let policy = MessagePolicy::new(profile.signers, true, cutoff);
                let ctx = context(profile, policy.clone(), true, true);
                let options = CmsValidationOptions {
                    validation_order: order,
                    ..Default::default()
                };
                // Ordinary validation intentionally retains its old Revoked
                // result. This new profile is stricter before status freeze.
                let ordinary =
                    validate_cms_signature_with(&data, SignedContent::Encapsulated, &ctx, &options)
                        .unwrap();
                assert_ordinary_revoked(&ordinary);
                assert!(
                    policy.message_calls().is_empty(),
                    "ordinary path gains no message gate"
                );
                let evaluated = evaluate_cms_leaf_revocation(
                    &data,
                    SignedContent::Encapsulated,
                    &ctx,
                    &options,
                )
                .unwrap();
                let status = evaluated.unresolved_status();
                assert!(status.signature.intact && status.signature.valid);
                assert_eq!(status.signature.validation_time, Some(moment(V)));
                assert_timestamps(status);
                match status.signature.trust_problem.as_ref() {
                    Some(TrustProblem::Path(ValidationError::DisallowedAlgorithm {
                        banned_since,
                        ..
                    })) => {
                        assert_eq!(*banned_since, cutoff);
                    }
                    other => panic!(
                        "real CV message denial must survive CMS mapping: {}, {order:?}: {other:?}",
                        profile.name
                    ),
                }
                assert_eq!(status.signature.error_time_horizon, cutoff);
                assert!(
                    status.signature.validation_path.is_some(),
                    "preserve actual failure path"
                );
                assert!(
                    status.signature.revocation_details.is_none(),
                    "do not forge the ordinary revoked payload after pre-freeze CV denial"
                );
                policy.assert_bindings();
                assert_eq!(policy.message_calls().len(), 1,
                    "only the new gate stops at its first denial; unrelated role calls may continue");
                frozen_refusal(evaluated, &policy);
            }
        }
    }
}

#[test]
fn exact_main_predicates_remain_mandatory_in_both_orders() {
    let names = |values: &[&str]| values.iter().map(|value| (*value).to_owned()).collect();
    let cases = [
        (
            "Some empty KU",
            KeyUsageConstraints {
                key_usage: Some(names(&[])),
                ..Default::default()
            },
            true,
        ),
        (
            "required NR",
            KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation"])),
                ..Default::default()
            },
            true,
        ),
        (
            "forbidden NR",
            KeyUsageConstraints {
                key_usage_forbidden: Some(names(&["non_repudiation"])),
                ..Default::default()
            },
            false,
        ),
        (
            "any KU",
            KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation", "key_agreement"])),
                match_all_key_usages: false,
                ..Default::default()
            },
            true,
        ),
        (
            "all KU",
            KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation", "key_agreement"])),
                match_all_key_usages: true,
                ..Default::default()
            },
            false,
        ),
        (
            "absent optional EKU",
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["time_stamping"])),
                explicit_extd_key_usage_required: false,
                ..Default::default()
            },
            true,
        ),
        (
            "absent mandatory EKU",
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["time_stamping"])),
                explicit_extd_key_usage_required: true,
                ..Default::default()
            },
            false,
        ),
        (
            "empty optional EKU",
            KeyUsageConstraints {
                extd_key_usage: Some(names(&[])),
                explicit_extd_key_usage_required: false,
                ..Default::default()
            },
            true,
        ),
        (
            "empty mandatory EKU",
            KeyUsageConstraints {
                extd_key_usage: Some(names(&[])),
                explicit_extd_key_usage_required: true,
                ..Default::default()
            },
            false,
        ),
    ];
    for order in orders() {
        allowed_control(DIRECT, order);
        for (label, predicate, allowed) in &cases {
            let data = input("cms/main.cms.der");
            let policy = MessagePolicy::new(DIRECT.signers, false, None);
            let ctx = context(DIRECT, policy.clone(), true, true);
            let options = CmsValidationOptions {
                validation_order: order,
                exact_key_usage_settings: Some(predicate.clone()),
                ..Default::default()
            };
            let evaluated =
                evaluate_cms_leaf_revocation(&data, SignedContent::Encapsulated, &ctx, &options)
                    .unwrap();
            assert_timestamps(evaluated.unresolved_status());
            if *allowed {
                assert!(
                    evaluated.resolve_signature_timestamp().bottom_line(),
                    "{label}, {order:?}"
                );
            } else {
                assert!(
                    matches!(
                        evaluated.unresolved_status().signature.trust_problem,
                        Some(TrustProblem::KeyUsage(_))
                    ),
                    "{label}, {order:?}"
                );
                frozen_refusal(evaluated, &policy);
            }
            policy.assert_bindings();
        }
    }
}

#[test]
fn no_event_and_configured_no_check_do_not_add_message_queries() {
    for order in orders() {
        allowed_control(DIRECT, order);
        for profile in [
            Profile {
                name: "current Good",
                leaf_ocsp: Some("leaf-direct-good-sha256.der"),
                leaf_crl: Some("leaf-good-sha256.der"),
                rule: RevocationCheckingRule::CrlAndOcspRequired,
                ..DIRECT
            },
            Profile {
                name: "configured NoCheck with unselected SHA512 stores",
                rule: RevocationCheckingRule::NoCheck,
                leaf_crl: Some("leaf-revoked-sha512.der"),
                ..DIRECT
            },
        ] {
            let data = input("cms/main.cms.der");
            let policy = MessagePolicy::new(DIRECT.signers, true, Some(moment(T)));
            let ctx = context(profile, policy.clone(), true, true);
            let options = CmsValidationOptions {
                validation_order: order,
                ..Default::default()
            };
            let ordinary =
                validate_cms_signature_with(&data, SignedContent::Encapsulated, &ctx, &options)
                    .unwrap();
            assert!(ordinary.bottom_line(), "{}: {ordinary:#?}", profile.name);
            let ordinary_calls = policy.calls();
            let evaluated =
                evaluate_cms_leaf_revocation(&data, SignedContent::Encapsulated, &ctx, &options)
                    .unwrap();
            assert!(evaluated.unresolved_status().bottom_line());
            assert_timestamps(evaluated.unresolved_status());
            assert!(evaluated.eligible_signature_timestamp().is_none());
            let frozen = format!("{:#?}", evaluated.unresolved_status());
            let calls = policy.calls();
            assert_eq!(
                &calls[ordinary_calls.len()..],
                ordinary_calls.as_slice(),
                "{} adds no selected-message signature query, including SHA256",
                profile.name
            );
            assert_eq!(
                format!("{:#?}", evaluated.resolve_signature_timestamp()),
                frozen
            );
            assert_eq!(policy.calls(), calls);
            assert!(policy.message_calls().is_empty(), "{}", profile.name);
            policy.assert_bindings();
        }
    }
}

#[test]
fn root_revinfo_and_independent_tsa_faults_keep_the_frozen_refusal() {
    for order in orders() {
        allowed_control(DIRECT, order);
        for (label, roots, evidence, bad_tsa) in [
            ("missing root", false, true, false),
            ("missing revinfo", true, false, false),
            ("independent TSA missing root", true, true, true),
        ] {
            let data = input("cms/main.cms.der");
            let policy = MessagePolicy::new(DIRECT.signers, false, None);
            let ctx = context(DIRECT, policy.clone(), roots, evidence);
            let tsa = context(DIRECT, policy.clone(), false, true);
            let options = CmsValidationOptions {
                validation_order: order,
                ts_validation_context: bad_tsa.then_some(&tsa),
                ..Default::default()
            };
            let evaluated =
                evaluate_cms_leaf_revocation(&data, SignedContent::Encapsulated, &ctx, &options)
                    .unwrap();
            assert_eq!(
                evaluated.unresolved_status().signature.validation_time,
                Some(moment(V)),
                "{label}"
            );
            if bad_tsa {
                assert!(!evaluated
                    .unresolved_status()
                    .timestamp_validity
                    .as_ref()
                    .unwrap()
                    .trusted());
                assert!(!evaluated
                    .unresolved_status()
                    .content_timestamp_validity
                    .as_ref()
                    .unwrap()
                    .trusted());
            }
            frozen_refusal(evaluated, &policy);
            policy.assert_bindings();
        }
    }
}

fn flip_unique(input: &[u8], needle: &[u8]) -> Vec<u8> {
    assert!(!needle.is_empty());
    let positions: Vec<_> = input
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, value)| (value == needle).then_some(index))
        .collect();
    assert_eq!(positions.len(), 1, "mutate only one actual signed field");
    let mut changed = input.to_vec();
    changed[positions[0]] ^= 1;
    changed
}

#[test]
fn raw_main_content_signature_and_signature_tsa_faults_cannot_promote() {
    for order in orders() {
        allowed_control(DIRECT, order);
        let original = input("cms/main.cms.der");
        let parsed = SignedData::from_der(&original).unwrap();
        let signer = &parsed.signer_infos[0];
        let token = find_unique_cms_attribute(
            signer.unsigned_attr_list(),
            oids::AA_SIGNATURE_TIME_STAMP_TOKEN,
        )
        .unwrap();
        let tsa = SignedData::from_der(token).unwrap();
        for (label, changed) in [
            (
                "MAIN signature and its TST imprint",
                flip_unique(&original, &signer.signature),
            ),
            (
                "encapsulated content digest",
                flip_unique(&original, parsed.econtent.as_ref().unwrap()),
            ),
            (
                "signature TSA raw signature",
                flip_unique(&original, &tsa.signer_infos[0].signature),
            ),
        ] {
            let policy = MessagePolicy::new(DIRECT.signers, false, None);
            let ctx = context(DIRECT, policy.clone(), true, true);
            let options = CmsValidationOptions {
                validation_order: order,
                ..Default::default()
            };
            let evaluated =
                evaluate_cms_leaf_revocation(&changed, SignedContent::Encapsulated, &ctx, &options)
                    .unwrap();
            match label {
                "MAIN signature and its TST imprint" => {
                    assert!(!evaluated.unresolved_status().signature.valid)
                }
                "encapsulated content digest" => {
                    assert!(!evaluated.unresolved_status().signature.intact)
                }
                _ => assert!(!evaluated
                    .unresolved_status()
                    .timestamp_validity
                    .as_ref()
                    .unwrap()
                    .trusted()),
            }
            frozen_refusal(evaluated, &policy);
            policy.assert_bindings();
        }
    }
}

#[test]
fn unauthenticated_revocation_messages_never_authorize_completion() {
    for order in orders() {
        allowed_control(DIRECT, order);
        for profile in [
            Profile {
                name: "OCSP signature tamper",
                leaf_ocsp: Some("leaf-direct-revoked-sha512-signature-tamper.der"),
                ..DIRECT
            },
            Profile {
                name: "CRL signature tamper",
                rule: RevocationCheckingRule::CrlRequired,
                leaf_ocsp: None,
                leaf_crl: Some("leaf-revoked-sha512-signature-tamper.der"),
                ..DIRECT
            },
        ] {
            let data = input("cms/main.cms.der");
            let policy = MessagePolicy::new(profile.signers, false, None);
            let ctx = context(profile, policy.clone(), true, true);
            let options = CmsValidationOptions {
                validation_order: order,
                ..Default::default()
            };
            let evaluated =
                evaluate_cms_leaf_revocation(&data, SignedContent::Encapsulated, &ctx, &options)
                    .unwrap();
            frozen_refusal(evaluated, &policy);
            assert!(
                policy.message_calls().is_empty(),
                "rejected candidates gain no new gate callback"
            );
            policy.assert_bindings();
        }
    }
}
