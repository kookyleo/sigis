//! Tests-first exact main-signer seam: retained private-operation profiles.
//! Derived from accepted tests/round3_mixed_context_profiles.rs at a23bb342.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_cms::validate::{CmsValidationOptions, CmsValidationOrder};
use sigis_pdf::PdfFile;
use sigis_pki_certvalidator::{Cert, ValidationContext};
use sigis_pki_core::{algorithms::DigestAlgorithm, key_usage::KeyUsageConstraints, time::Moment};

const PDF_SHA256: &str = "29b0a8a97e32bb220c96ac34d9906bcadf2d38dc7a13eb77336b63eaa6cdc4b2";
const ECC_SHA256: &str = "ccc409838b97b5c04b18f889fa39b9b123868ff685751f58956206fb86d5ba90";
const RSA_SHA256: &str = "2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa";
const TIME: &str = "2020-11-01T00:00:00Z";
const ROLES: [&str; 4] = [
    "implicit_shared",
    "explicit_shared",
    "equal_distinct",
    "separate_roots",
];

fn hash(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct Inputs {
    pdf_path: std::path::PathBuf,
    bytes: Vec<u8>,
    ecc_der: Vec<u8>,
    rsa_der: Vec<u8>,
}

impl Inputs {
    fn frozen() -> Self {
        let dir = sigis_testdata::path(&["lanes", "r3-s", "mixed-context"]);
        let inputs = Self {
            pdf_path: dir.join("different-generation-reproducer.pdf"),
            bytes: std::fs::read(dir.join("different-generation-reproducer.pdf")).unwrap(),
            ecc_der: std::fs::read(dir.join("testing-ca-ecdsa-root.der")).unwrap(),
            rsa_der: std::fs::read(dir.join("testing-ca-root.der")).unwrap(),
        };
        inputs.assert_frozen();
        inputs
    }

    fn assert_frozen(&self) {
        assert_eq!(hash(&self.bytes), PDF_SHA256);
        assert_eq!(hash(&self.ecc_der), ECC_SHA256);
        assert_eq!(hash(&self.rsa_der), RSA_SHA256);
    }

    fn contexts(&self, historical: bool, separate: bool) -> (ValidationContext, ValidationContext) {
        let ecc = Cert::from_der(&self.ecc_der).unwrap();
        let rsa = Cert::from_der(&self.rsa_der).unwrap();
        let mut signer = ValidationContext::builder().trust_root(ecc);
        if !separate {
            signer = signer.trust_root(rsa.clone());
        }
        let signer = signer
            .moment(Moment::parse_rfc3339(TIME).unwrap())
            .point_in_time_validation(historical)
            .revocation_mode("none")
            .build()
            .unwrap();
        let timestamp = ValidationContext::builder()
            .trust_root(rsa)
            .moment(Moment::parse_rfc3339(TIME).unwrap())
            .point_in_time_validation(historical)
            .revocation_mode("none")
            .build()
            .unwrap();
        (signer, timestamp)
    }
}

fn empty_main_predicate() -> KeyUsageConstraints {
    // None means no KU/EKU predicate, not Some(empty EKU), which bans EKUs.
    // Under the proposed exact seam this object bypasses only the legacy
    // main-signer default merge. Timestamp purpose and PKIX rules stay fixed.
    let predicate = KeyUsageConstraints::default();
    assert!(predicate.key_usage.is_none());
    assert!(predicate.key_usage_forbidden.is_none());
    assert!(predicate.extd_key_usage.is_none());
    assert!(predicate.explicit_extd_key_usage_required);
    assert!(!predicate.match_all_key_usages);
    predicate
}

fn profile(inputs: &Inputs, historical: bool, role: &str, exact: bool) -> serde_json::Value {
    let separate = role == "separate_roots";
    let expected = separate || role == "equal_distinct";
    let file = PdfFile::parse(&inputs.bytes).unwrap();
    let auth = file.decrypt("secret").unwrap();
    assert_eq!(auth.mac_status, sigis_pdf::crypt::PdfMacStatus::Successful);
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|signature| signature.field_name == "Sig")
        .unwrap();
    let (context, timestamp_context) = inputs.contexts(historical, separate);
    let equal_context = context.clone();
    let before = (
        format!("{context:?}"),
        format!("{equal_context:?}"),
        format!("{timestamp_context:?}"),
    );
    // Preserve the original operation-registration test: seed only roots.
    // No main-certificate prevalidation or with_other_certs preseed is allowed.
    for source in [&context, &equal_context, &timestamp_context] {
        assert!(source.other_certs().is_empty());
        assert!(source.fetchers().is_empty());
        assert_eq!(source.timing().point_in_time_validation, historical);
        assert_eq!(source.timing().time_tolerance.as_secs(), 1);
    }
    let options = CmsValidationOptions {
        validation_order: CmsValidationOrder::TimestampsFirst,
        ts_validation_context: match role {
            "explicit_shared" => Some(&context),
            "equal_distinct" => Some(&equal_context),
            "separate_roots" => Some(&timestamp_context),
            "implicit_shared" => None,
            other => panic!("unknown frozen role profile {other}"),
        },
        key_usage_settings: None,
        exact_key_usage_settings: exact.then(empty_main_predicate),
        ..Default::default()
    };
    let status = sigis_pades::validate_pdf_signature_with_options(
        &file,
        &signature,
        &context,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
        &options,
    )
    .unwrap();
    assert_eq!(
        (
            format!("{context:?}"),
            format!("{equal_context:?}"),
            format!("{timestamp_context:?}")
        ),
        before,
        "all public caller role contexts must stay immutable"
    );
    for source in [&context, &equal_context, &timestamp_context] {
        assert!(
            source.other_certs().is_empty(),
            "registration is private to this operation"
        );
    }
    inputs.assert_frozen();
    assert!(status.cms.signature.intact && status.cms.signature.valid);
    assert_eq!(
        status.bottom_line(),
        expected,
        "historical={historical}, role={role}, exact={exact}"
    );
    let main_path: Vec<String> = status
        .cms
        .signature
        .validation_path
        .as_ref()
        .map(|path| path.certs().iter().map(|cert| hash(cert.der())).collect())
        .unwrap_or_default();
    let timestamp_path: Vec<String> = status
        .cms
        .timestamp_validity
        .as_ref()
        .and_then(|timestamp| timestamp.signature.validation_path.as_ref())
        .map(|path| path.certs().iter().map(|cert| hash(cert.der())).collect())
        .unwrap_or_default();
    serde_json::json!({
        "pdf_path": inputs.pdf_path,
        "pdf_sha256": hash(&inputs.bytes),
        "point_in_time_validation": historical,
        "role_identity": role,
        "separate_role_contexts": separate,
        "expected_Python_bottom_line": expected,
        "bottom_line": status.bottom_line(),
        "intact": status.cms.signature.intact,
        "valid": status.cms.signature.valid,
        "trusted": status.cms.signature.trusted(),
        "timestamp_intact": status.cms.timestamp_validity.as_ref().map(|timestamp| timestamp.signature.intact),
        "timestamp_valid": status.cms.timestamp_validity.as_ref().map(|timestamp| timestamp.signature.valid),
        "timestamp_trusted": status.cms.timestamp_validity.as_ref().map(|timestamp| timestamp.trusted()),
        "summary": status.summary(),
        "main_path_sha256": main_path,
        "timestamp_path_sha256": timestamp_path,
        "time": TIME,
        "tolerance_seconds": 1,
        "revocation": "none",
        "root_order": if separate { vec![ECC_SHA256] } else { vec![ECC_SHA256, RSA_SHA256] },
        "timestamp_roots": if separate { vec![RSA_SHA256] } else { vec![ECC_SHA256, RSA_SHA256] },
    })
}

#[test]
fn exact_main_predicate_preserves_frozen_timestamp_first_operation_profiles() {
    let inputs = Inputs::frozen();
    let mut records = Vec::new();
    for historical in [false, true] {
        for role in ROLES {
            // Reparse the same input and build fresh public contexts per call.
            // Exact evaluation cannot inherit candidates from the legacy call.
            let legacy = profile(&inputs, historical, role, false);
            let exact = profile(&inputs, historical, role, true);
            assert_eq!(
                exact, legacy,
                "the main predicate seam must not change registration/order/role outcomes"
            );
            records.push(serde_json::json!({"legacy_None": legacy, "exact_Some_empty": exact}));
        }
    }
    // Original eight profiles: shared roles refuse, distinct roles accept,
    // in both current and historical modes. Counts are test invariants only.
    assert_eq!(records.len(), 8);
    assert_eq!(
        records
            .iter()
            .filter(|row| row["exact_Some_empty"]["bottom_line"] == true)
            .count(),
        4
    );
    assert_eq!(
        records
            .iter()
            .filter(|row| row["exact_Some_empty"]["bottom_line"] == false)
            .count(),
        4
    );
    eprintln!(
        "EXACT_MAIN_OPERATION_PROFILES_JSON {}",
        serde_json::to_string(&records).unwrap()
    );
}

#[test]
fn exact_and_legacy_main_predicates_cannot_be_selected_together() {
    let inputs = Inputs::frozen();
    let file = PdfFile::parse(&inputs.bytes).unwrap();
    assert_eq!(
        file.decrypt("secret").unwrap().mac_status,
        sigis_pdf::crypt::PdfMacStatus::Successful
    );
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|signature| signature.field_name == "Sig")
        .unwrap();
    let (context, timestamp_context) = inputs.contexts(false, true);
    let before = (format!("{context:?}"), format!("{timestamp_context:?}"));
    let options = CmsValidationOptions {
        validation_order: CmsValidationOrder::TimestampsFirst,
        ts_validation_context: Some(&timestamp_context),
        key_usage_settings: Some(KeyUsageConstraints::default()),
        exact_key_usage_settings: Some(empty_main_predicate()),
        ..Default::default()
    };
    let result = sigis_pades::validate_pdf_signature_with_options(
        &file,
        &signature,
        &context,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
        &options,
    );
    assert!(
        result.is_err(),
        "ambiguous legacy+exact main predicates must reject explicitly"
    );
    assert_eq!(
        (format!("{context:?}"), format!("{timestamp_context:?}")),
        before
    );
    inputs.assert_frozen();
}
