//! Supplemental private CMS operation-registration guards, zero upstream IDs.
//! Public inputs extracted from the actual retained 29b PDF; no verdict replay.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
use spki::SubjectPublicKeyInfoOwned;

const RSA_INTERMEDIATE: &str = "0e8fa78719fdd97ac8f9a531fa32929462d65306b9c58a63881ef21ca1a9509f";

fn hash(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn input(name: &str, expected: &str) -> Vec<u8> {
    let path = sigis_testdata::path(&["lanes", "r3-s", "mixed-context", name]);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(hash(&bytes), expected, "{}", path.display());
    bytes
}

fn real_timestamp() -> SignedData {
    let bytes = input(
        "timestamp.cms",
        "37183aa5a5aa3e0148831f13561100a9e0ec2a0866e28fc51deeed09a2d99af1",
    );
    SignedData::from_content_info_der(&bytes).unwrap()
}

fn operation() -> ValidationContext {
    let ecc = input(
        "testing-ca-ecdsa-root.der",
        "ccc409838b97b5c04b18f889fa39b9b123868ff685751f58956206fb86d5ba90",
    );
    let rsa = input(
        "testing-ca-root.der",
        "2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa",
    );
    ValidationContext::builder()
        .trust_root(Cert::from_der(&ecc).unwrap())
        .trust_root(Cert::from_der(&rsa).unwrap())
        .moment(Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap())
        .revocation_mode("none")
        .build()
        .unwrap()
}

fn actual_imprint(timestamp: &SignedData) -> Vec<u8> {
    tst_info(timestamp)
        .unwrap()
        .message_imprint
        .hashed_message
        .as_bytes()
        .to_vec()
}

fn assert_registered_actual_intermediate(operation: &ValidationContext) {
    let retained = operation
        .other_certs()
        .iter()
        .map(|cert| hash(cert.der()))
        .collect::<Vec<_>>();
    assert_eq!(retained, vec![RSA_INTERMEDIATE.to_owned()]);
    // Registry collision behavior must not delete either configured trust root.
    assert_eq!(operation.trust_anchors().len(), 2);
    assert_eq!(
        hash(operation.trust_anchors()[0].cert().der()),
        "ccc409838b97b5c04b18f889fa39b9b123868ff685751f58956206fb86d5ba90"
    );
    assert_eq!(
        hash(operation.trust_anchors()[1].cert().der()),
        "2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa"
    );
}

#[derive(Debug)]
struct DenyEveryAlgorithm;

impl AlgorithmUsagePolicy for DenyEveryAlgorithm {
    fn signature_algorithm_allowed(
        &self,
        _algorithm: &AlgorithmIdentifierOwned,
        _moment: Option<Moment>,
        _public_key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::denied("registration gate test rejects every algorithm")
    }

    fn digest_algorithm_allowed(
        &self,
        _algorithm: &ObjectIdentifier,
        _moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::denied("registration gate test rejects every algorithm")
    }
}
impl CmsAlgorithmUsagePolicy for DenyEveryAlgorithm {}

#[test]
fn raw_invalid_timestamp_does_not_register_its_candidates() {
    let mut timestamp = real_timestamp();
    let imprint = actual_imprint(&timestamp);
    let original_signature = timestamp.signer_infos[0].signature.clone();
    assert!(!original_signature.is_empty());
    timestamp.signer_infos[0].signature[0] ^= 1;
    let mut operation = operation();
    let before = format!("{operation:?}");
    let status = validate_tst_signed_data_in_operation(
        &timestamp,
        &mut operation,
        &|_| Ok(imprint.clone()),
        None,
    )
    .unwrap();
    assert!(
        status.signature.intact,
        "the unchanged signed digest still matches"
    );
    assert!(!status.signature.valid);
    assert!(!status.trusted());
    assert!(status.signature.validation_path.is_none());
    assert_eq!(format!("{operation:?}"), before);
    assert!(operation.other_certs().is_empty());
}

#[test]
fn algorithm_denied_raw_valid_timestamp_does_not_register_candidates() {
    let timestamp = real_timestamp();
    let imprint = actual_imprint(&timestamp);
    let mut operation = operation();
    let before = format!("{operation:?}");
    let status = validate_tst_signed_data_in_operation(
        &timestamp,
        &mut operation,
        &|_| Ok(imprint.clone()),
        Some(Arc::new(DenyEveryAlgorithm)),
    )
    .unwrap();
    assert!(status.signature.intact && status.signature.valid);
    assert!(!status.trusted());
    assert!(status.signature.validation_path.is_none());
    assert_eq!(
        status.signature.trust_problem_indic,
        Some(AdesSubIndic::Indeterminate(
            AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE
        ))
    );
    assert_eq!(status.signature.error_time_horizon, None);
    assert_eq!(format!("{operation:?}"), before);
    assert!(operation.other_certs().is_empty());
}

#[test]
fn raw_valid_wrong_imprint_registers_candidates_without_timestamp_trust() {
    let timestamp = real_timestamp();
    let mut wrong_imprint = actual_imprint(&timestamp);
    assert!(!wrong_imprint.is_empty());
    wrong_imprint[0] ^= 1;
    let mut operation = operation();
    let timing = format!("{:?}", operation.timing());
    let policy = operation.algorithm_policy_arc();
    let status = validate_tst_signed_data_in_operation(
        &timestamp,
        &mut operation,
        &|_| Ok(wrong_imprint.clone()),
        None,
    )
    .unwrap();
    assert!(
        status.signature.valid,
        "the actual CMS raw signature stays valid"
    );
    assert!(status.signature.validation_path.is_some());
    assert!(!status.signature.intact);
    assert!(
        !status.trusted(),
        "wrong imprint grants no trusted timestamp proof"
    );
    assert_registered_actual_intermediate(&operation);
    assert_eq!(format!("{:?}", operation.timing()), timing);
    assert!(Arc::ptr_eq(&policy, &operation.algorithm_policy_arc()));
    assert!(operation.fetchers().is_empty());
}

#[test]
fn a_later_unvisited_timestamp_does_not_register_its_extra_candidate() {
    let first_bytes = input(
        "timestamp.cms",
        "37183aa5a5aa3e0148831f13561100a9e0ec2a0866e28fc51deeed09a2d99af1",
    );
    let later_bytes = input(
        "unvisited-timestamp.cms",
        "ca9fad1c8a2fdc4141f447614c5f45785a4b6671ff45dd41326aab2afa89d899",
    );
    let later = SignedData::from_content_info_der(&later_bytes).unwrap();
    const MARKER: &str = "899920fac432386b36a5a0cbccd5c681a215df2accf35e0280560fef8749555a";
    assert!(later.certificates.iter().any(|cert| hash(cert) == MARKER));

    // The extra CertificateSet entry is outside the actual token's signature.
    // Positive control: if the later token IS visited, it is genuinely trusted
    // and its unique public candidate really enters operation registration.
    let mut direct_operation = operation();
    let imprint = actual_imprint(&later);
    let direct = validate_tst_signed_data_in_operation(
        &later,
        &mut direct_operation,
        &|_| Ok(imprint.clone()),
        None,
    )
    .unwrap();
    assert!(direct.signature.valid && direct.signature.intact && direct.trusted());
    assert!(direct_operation
        .other_certs()
        .iter()
        .any(|cert| hash(cert.der()) == MARKER));

    let outer_bytes = input(
        "outer-signed-data.cms",
        "ad7f68c026e12e96ca08abf9ff43830bb46a8437ffd6504f4dcbc76328e01f66",
    );
    let mut outer = SignedData::from_der(&outer_bytes).unwrap();
    assert_eq!(outer.signer_infos.len(), 1);
    let si = &mut outer.signer_infos[0];
    // This fixture has signature timestamps only; the external-content digest
    // is therefore not consulted. Preserve the original parent signature bytes.
    assert!(extract_tst_data(si, true).unwrap().is_empty());
    let timestamp_attributes = si
        .unsigned_attrs
        .as_mut()
        .unwrap()
        .iter_mut()
        .filter(|attribute| attribute.oid.is(&oids::AA_SIGNATURE_TIME_STAMP_TOKEN))
        .collect::<Vec<_>>();
    assert_eq!(timestamp_attributes.len(), 1);
    let timestamp_attribute = timestamp_attributes.into_iter().next().unwrap();
    assert_eq!(timestamp_attribute.values, vec![first_bytes]);
    timestamp_attribute.values.push(later_bytes);
    assert_eq!(extract_tst_data(si, false).unwrap().len(), 2);
    let mut operation = operation();
    let timing = collect_timing_info_in_operation(
        si,
        &mut operation,
        &DataDigester::new(b"unused: no content timestamps in this real fixture"),
        None,
    )
    .unwrap();
    let first = timing.timestamp_validity.unwrap();
    assert!(first.signature.valid && first.signature.intact && first.trusted());
    assert!(timing.content_timestamp_validity.is_none());
    assert_registered_actual_intermediate(&operation);
    assert!(operation
        .other_certs()
        .iter()
        .all(|cert| hash(cert.der()) != MARKER));
}
