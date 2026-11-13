//! Supplemental raw CMS validation-order regressions; zero upstream IDs.
//! The detached bytes are read from fixed ranges of the SHA-pinned original
//! input, without adding a PDF or PAdES dependency to the CMS crate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
use spki::SubjectPublicKeyInfoOwned;
use std::sync::Mutex;

fn hash(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fixture(name: &str, expected: &str) -> Vec<u8> {
    let path = sigis_testdata::path(&["lanes", "r3-s", "mixed-context", name]);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(hash(&bytes), expected, "{}", path.display());
    bytes
}

fn detached_fixture() -> (SignedData, Vec<u8>) {
    let cms = fixture(
        "outer-signed-data.cms",
        "ad7f68c026e12e96ca08abf9ff43830bb46a8437ffd6504f4dcbc76328e01f66",
    );
    let pdf = fixture(
        "different-generation-reproducer.pdf",
        "29b0a8a97e32bb220c96ac34d9906bcadf2d38dc7a13eb77336b63eaa6cdc4b2",
    );
    // Original Sig's exact ByteRange, independently fixed by the input hash.
    // This is the detached signed content, not a digest copied from signedAttrs.
    assert_eq!(pdf.len(), 26_213);
    assert!(pdf
        .windows(b"/ByteRange [0 4380 25768 445]".len())
        .any(|window| window == b"/ByteRange [0 4380 25768 445]"));
    let mut content = pdf[..4380].to_vec();
    content.extend_from_slice(&pdf[25_768..]);
    (SignedData::from_der(&cms).unwrap(), content)
}

#[derive(Clone, Copy)]
enum Roots {
    Both,
    Ecc,
    Rsa,
}

fn context(historical: bool, roots: Roots) -> ValidationContext {
    let mut builder = ValidationContext::builder()
        .moment(Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap())
        .point_in_time_validation(historical)
        .revocation_mode("none");
    if !matches!(roots, Roots::Rsa) {
        let ecc = fixture(
            "testing-ca-ecdsa-root.der",
            "ccc409838b97b5c04b18f889fa39b9b123868ff685751f58956206fb86d5ba90",
        );
        builder = builder.trust_root(Cert::from_der(&ecc).unwrap());
    }
    if !matches!(roots, Roots::Ecc) {
        let rsa = fixture(
            "testing-ca-root.der",
            "2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa",
        );
        builder = builder.trust_root(Cert::from_der(&rsa).unwrap());
    }
    let context = builder.build().unwrap();
    assert!(context.other_certs().is_empty());
    assert!(context.fetchers().is_empty());
    context
}

#[derive(Debug)]
struct RecordingPolicy {
    signer_algorithm: ObjectIdentifier,
    signer_denial: Option<AlgorithmUsageConstraint>,
    calls: Mutex<Vec<ObjectIdentifier>>,
}

impl RecordingPolicy {
    fn new(sd: &SignedData, signer_denial: Option<AlgorithmUsageConstraint>) -> Self {
        Self {
            signer_algorithm: sd.signer_infos[0].signature_algorithm.oid,
            signer_denial,
            calls: Mutex::default(),
        }
    }
}

impl AlgorithmUsagePolicy for RecordingPolicy {
    fn signature_algorithm_allowed(
        &self,
        algorithm: &AlgorithmIdentifierOwned,
        _moment: Option<Moment>,
        _public_key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        self.calls.lock().unwrap().push(algorithm.oid);
        if algorithm.oid == self.signer_algorithm {
            if let Some(denial) = &self.signer_denial {
                return denial.clone();
            }
        }
        AlgorithmUsageConstraint::allowed()
    }

    fn digest_algorithm_allowed(
        &self,
        _algorithm: &ObjectIdentifier,
        _moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::allowed()
    }
}

impl CmsAlgorithmUsagePolicy for RecordingPolicy {}

fn algorithm_order(sd: &SignedData) -> [ObjectIdentifier; 2] {
    let signer = sd.signer_infos[0].signature_algorithm.oid;
    let tokens = extract_tst_data(&sd.signer_infos[0], false).unwrap();
    assert_eq!(tokens.len(), 1);
    let timestamp = tokens[0].signer_infos[0].signature_algorithm.oid;
    assert_ne!(signer, timestamp);
    [signer, timestamp]
}

#[test]
fn signer_first_is_explicit_and_default_legacy_role_identity_stays_unchanged() {
    assert_eq!(
        crate::CmsValidationOrder::default(),
        CmsValidationOrder::TimestampsFirst
    );
    assert_eq!(
        CmsValidationOptions::default().validation_order,
        CmsValidationOrder::TimestampsFirst
    );
    let (sd, content) = detached_fixture();
    for historical in [false, true] {
        for order in [
            CmsValidationOrder::TimestampsFirst,
            CmsValidationOrder::SignerFirst,
        ] {
            for role in [
                "implicit_shared",
                "explicit_shared",
                "equal_distinct",
                "separate_roots",
            ] {
                let separate = role == "separate_roots";
                let signer = context(historical, if separate { Roots::Ecc } else { Roots::Both });
                let equal = signer.clone();
                let timestamp = context(historical, Roots::Rsa);
                let before = [
                    format!("{signer:?}"),
                    format!("{equal:?}"),
                    format!("{timestamp:?}"),
                ];
                let policy = Arc::new(RecordingPolicy::new(&sd, None));
                let options = CmsValidationOptions {
                    validation_order: order,
                    ts_validation_context: match role {
                        "explicit_shared" => Some(&signer),
                        "equal_distinct" => Some(&equal),
                        "separate_roots" => Some(&timestamp),
                        _ => None,
                    },
                    algorithm_policy: Some(policy.clone()),
                    ..Default::default()
                };
                let status = validate_detached_cms_with(
                    &sd,
                    &DataDigester::new(&content),
                    false,
                    Some(&signer),
                    &options,
                )
                .unwrap();
                let expected = order == CmsValidationOrder::SignerFirst
                    || matches!(role, "equal_distinct" | "separate_roots");
                assert!(status.signature.intact && status.signature.valid);
                assert_eq!(
                    status.signature.trusted(),
                    expected,
                    "{historical}/{order:?}/{role}"
                );
                assert_eq!(
                    status.bottom_line(),
                    expected,
                    "{historical}/{order:?}/{role}"
                );
                let timestamp_status = status.timestamp_validity.as_ref().unwrap();
                assert!(timestamp_status.signature.intact && timestamp_status.signature.valid);
                assert!(timestamp_status.trusted());
                let mut expected_calls = algorithm_order(&sd);
                if order == CmsValidationOrder::TimestampsFirst {
                    expected_calls.reverse();
                }
                assert_eq!(*policy.calls.lock().unwrap(), expected_calls);
                assert_eq!(
                    [
                        format!("{signer:?}"),
                        format!("{equal:?}"),
                        format!("{timestamp:?}")
                    ],
                    before,
                    "only the private operation context may accumulate candidates"
                );
            }
        }
    }
}

#[test]
fn signer_first_invalid_outer_does_not_visit_timestamps_or_attribute_certificates() {
    let (original, content) = detached_fixture();
    for invalid_signature in [false, true] {
        let mut sd = original.clone();
        let mut detached = content.clone();
        if invalid_signature {
            sd.signer_infos[0].signature[0] ^= 1;
        } else {
            detached[0] ^= 1;
        }
        // This unsigned timestamp is malformed. A visited token is an error,
        // not a fake trusted result, while the outer integrity check is real.
        let timestamp = sd.signer_infos[0]
            .unsigned_attrs
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|attr| attr.oid.is(&oids::AA_SIGNATURE_TIME_STAMP_TOKEN))
            .unwrap();
        timestamp.values = vec![b"not a DER timestamp".to_vec()];
        assert!(extract_tst_data(&sd.signer_infos[0], false).is_err());
        sd.attribute_certificates.push(vec![0x30, 0]);
        let signer = context(false, Roots::Both);
        let ac = context(false, Roots::Both);
        let before = [format!("{signer:?}"), format!("{ac:?}")];
        // The AC is a meaningful negative: visiting it reports a real parse
        // failure. The early status must leave all authenticated attrs absent.
        let certs = extract_certificate_info(&sd).unwrap();
        let visited = collect_signer_attr_status(
            &certs.attribute_certs,
            &certs.signer_cert,
            &certs.other_certs,
            Some(&ac),
            sd.signer_infos[0].signed_attr_list(),
        )
        .unwrap();
        assert_eq!(visited.ac_validation_errs.as_ref().unwrap().len(), 1);
        let policy = Arc::new(RecordingPolicy::new(&sd, None));
        let options = CmsValidationOptions {
            validation_order: CmsValidationOrder::SignerFirst,
            algorithm_policy: Some(policy.clone()),
            ac_validation_context: Some(&ac),
            ..Default::default()
        };
        let status = validate_detached_cms_with(
            &sd,
            &DataDigester::new(&detached),
            false,
            Some(&signer),
            &options,
        )
        .expect("AdES outer integrity failure returns before malformed later stages");
        assert_eq!(status.signature.intact, invalid_signature);
        assert_eq!(status.signature.valid, !invalid_signature);
        assert!(!status.bottom_line());
        assert!(status.signer_reported_dt.is_none());
        assert!(status.timestamp_validity.is_none());
        assert!(status.content_timestamp_validity.is_none());
        assert!(status.cades_signer_attrs.is_none());
        assert!(status.ac_attrs.is_none());
        assert!(status.ac_validation_errs.is_none());
        assert_eq!(*policy.calls.lock().unwrap(), [policy.signer_algorithm]);
        assert_eq!([format!("{signer:?}"), format!("{ac:?}")], before);
        let legacy = CmsValidationOptions {
            validation_order: CmsValidationOrder::TimestampsFirst,
            ..options
        };
        assert!(
            validate_detached_cms_with(
                &sd,
                &DataDigester::new(&detached),
                false,
                Some(&signer),
                &legacy,
            )
            .is_err(),
            "the malformed timestamp is reached by the legacy order"
        );
    }
}

#[test]
fn signer_first_policy_denial_is_typed_unregistered_and_still_allows_timestamp_processing() {
    let (sd, content) = detached_fixture();
    for cutoff in [
        None,
        Some(Moment::parse_rfc3339("2020-10-31T00:00:00Z").unwrap()),
    ] {
        let signer = context(false, Roots::Both);
        let before = format!("{signer:?}");
        let policy = Arc::new(RecordingPolicy::new(
            &sd,
            Some(AlgorithmUsageConstraint {
                not_allowed_after: cutoff,
                ..AlgorithmUsageConstraint::denied("outer-only policy denial")
            }),
        ));
        let mut operation = signer.clone();
        let si = extract_signer_info(&sd).unwrap();
        let digest = DataDigester::new(&content)
            .digest(&si.digest_algorithm)
            .unwrap();
        let direct = cms_basic_validation_in_operation(
            &sd,
            Some(&digest),
            &mut operation,
            &StatusKind::Signature.default_usage_constraints(None),
            Some(policy.clone()),
            None,
            None,
        )
        .unwrap();
        assert!(direct.intact && direct.valid && !direct.trusted());
        assert!(operation.other_certs().is_empty());
        assert_eq!(format!("{operation:?}"), before);
        policy.calls.lock().unwrap().clear();
        let options = CmsValidationOptions {
            validation_order: CmsValidationOrder::SignerFirst,
            algorithm_policy: Some(policy.clone()),
            ..Default::default()
        };
        let status = validate_detached_cms_with(
            &sd,
            &DataDigester::new(&content),
            false,
            Some(&signer),
            &options,
        )
        .unwrap();
        assert!(status.signature.intact && status.signature.valid);
        assert!(!status.signature.trusted());
        assert!(status.signature.validation_path.is_none());
        assert_eq!(status.signature.error_time_horizon, cutoff);
        assert_eq!(
            status.signature.trust_problem_indic,
            Some(AdesSubIndic::Indeterminate(if cutoff.is_some() {
                AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE_NO_POE
            } else {
                AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE
            }))
        );
        let timestamp = status.timestamp_validity.as_ref().unwrap();
        assert!(timestamp.signature.intact && timestamp.signature.valid && timestamp.trusted());
        assert!(!status.bottom_line());
        assert_eq!(*policy.calls.lock().unwrap(), algorithm_order(&sd));
        assert_eq!(format!("{signer:?}"), before);
    }
}
