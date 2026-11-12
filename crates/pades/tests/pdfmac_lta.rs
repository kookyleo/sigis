//! Native validation contribution to S-owned test_pdf_mac_pades (no V credit).
mod common;

use common::data;
use serde_json::Value;
use sigis_pades::ades::{basic::QualificationSpec, lta::lta_validation};
use sigis_pdf::crypt::{AuthStatus, PdfMacStatus};
use sigis_pdf::rw_common::PdfHandlerExt;
use sigis_pdf::{PdfFile, SignatureKind};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{cert::Cert, time::Moment};
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    std::env::var_os("HANKO_PDFMAC_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| data(&["lanes", "r3-v", "pdfmac"]))
}
fn context() -> ValidationContext {
    ValidationContext::builder()
        .trust_root(Cert::from_der(&common::read_fixture(fixtures().join("root.der"))).unwrap())
        .moment(Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap())
        .revocation_mode("none") // Exact upstream CertRevTrustPolicy(NO_REVOCATION).
        .build()
        .unwrap()
}
fn assert_iso_extension(file: &PdfFile) {
    let root = file.root().unwrap();
    let extensions = file.get_dict(&root, b"Extensions").unwrap().unwrap();
    let iso = file.get_array(&extensions, b"ISO_").unwrap().unwrap();
    assert!(iso.iter().any(|extension| {
        file.resolve(extension)
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"ExtensionLevel")
            .unwrap()
            .as_i64()
            .unwrap()
            == 32004
    }));
}
#[test]
fn test_pdf_mac_pades_native_lta() {
    let root = fixtures();
    let evidence: Value =
        serde_json::from_slice(&common::read_fixture(root.join("upstream-evidence.json"))).unwrap();
    assert_eq!(
        evidence["upstream_function"],
        "pyhanko/test_pdfmac.py::test_pdf_mac_pades"
    );
    assert_eq!(evidence["outcome"], "passed");
    let file = PdfFile::parse(&common::read_fixture(root.join("exact.pdf"))).unwrap();
    assert!(file.encrypted());
    let auth = file.decrypt("secret").unwrap();
    assert_ne!(auth.status, AuthStatus::Failed);
    assert_eq!(
        auth.mac_status,
        PdfMacStatus::Successful,
        "{:?}",
        auth.mac_failure_reason
    );
    assert_iso_extension(&file); // Exact pdf_mac_good decorator assertion.
    let decryptor = file.decryptor().unwrap();
    let limits = file.decode_context().limits;
    let strict = file.strict();
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.kind == SignatureKind::Signature)
        .unwrap();
    assert_eq!(signature.field_name, "Sig1");
    let result =
        lta_validation(&file, &signature, &context(), &QualificationSpec::default()).unwrap();
    let status = result.api_status.as_ref().unwrap();
    assert!(status.bottom_line(), "{:?}", result.failure_msg); // Exact upstream body assertion, using native archival output.
    let pdf = sigis_pades::validate_pdf_signature(
        &file,
        &signature,
        &context(),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    )
    .unwrap();
    assert!(pdf.bottom_line());
    assert_eq!(
        pdf.modification_level(),
        Some(sigis_pdf_diff::ModificationLevel::LtaUpdates)
    );
    let oracle = &evidence["lta_calls"][0];
    assert_eq!(
        result.ades_subindic.standard_name(),
        oracle["ades_subindic"].as_str().unwrap(),
        "failure={:?}",
        result.failure_msg
    );
    for (key, actual) in [
        ("intact", status.signature.intact),
        ("valid", status.signature.valid),
        ("trusted", status.signature.trusted()),
        ("bottom_line", status.bottom_line()),
    ] {
        assert_eq!(Some(actual), oracle[key].as_bool(), "{key}");
    }
    assert_eq!(file.strict(), strict);
    assert_eq!(file.decode_context().limits, limits);
    assert!(std::sync::Arc::ptr_eq(
        &decryptor,
        &file.decryptor().unwrap()
    ));
}

fn manifest() -> Value {
    let manifest: Value =
        serde_json::from_slice(&common::read_fixture(fixtures().join("manifest.json"))).unwrap();
    assert_eq!(manifest["pyhanko"], "0.38.1");
    assert_eq!(manifest["certvalidator"], "0.33.0");
    assert_eq!(manifest["cases"].as_array().unwrap().len(), 6);
    manifest
}
fn case<'a>(manifest: &'a Value, id: &str) -> &'a Value {
    manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == id)
        .unwrap()
}
fn open_case(case: &Value) -> PdfFile {
    PdfFile::parse(&common::read_fixture(
        fixtures().join(case["file"].as_str().unwrap()),
    ))
    .unwrap()
}
fn assert_auth(auth: &sigis_pdf::crypt::AuthResult, oracle: &Value) {
    let status = match auth.status {
        AuthStatus::Failed => "FAILED",
        AuthStatus::User => "USER",
        AuthStatus::Owner => "OWNER",
    };
    let mac = match auth.mac_status {
        PdfMacStatus::NotApplicable => "NOT_APPLICABLE",
        PdfMacStatus::Successful => "SUCCESSFUL",
        PdfMacStatus::Failed => "FAILED",
    };
    assert_eq!(Some(status), oracle["auth_status"].as_str());
    assert_eq!(Some(mac), oracle["mac_status"].as_str());
    assert_eq!(
        auth.mac_failure_reason.as_deref(),
        oracle["mac_failure_reason"].as_str()
    );
}
fn assert_native_lta(file: &PdfFile, oracle: &Value) {
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.field_name == "Sig1")
        .unwrap();
    let result =
        lta_validation(file, &signature, &context(), &QualificationSpec::default()).unwrap();
    let status = result.api_status.as_ref().unwrap();
    assert_eq!(
        Some(result.ades_subindic.standard_name()),
        oracle["ades_subindic"].as_str()
    );
    assert_eq!(
        result.best_signature_time,
        Some(Moment::parse_rfc3339(oracle["best_signature_time"].as_str().unwrap()).unwrap())
    );
    for (key, actual) in [
        ("intact", status.signature.intact),
        ("valid", status.signature.valid),
        ("trusted", status.signature.trusted()),
        ("bottom_line", status.bottom_line()),
    ] {
        assert_eq!(Some(actual), oracle[key].as_bool(), "{key}");
    }
    let timestamp = status.timestamp_validity.as_ref().unwrap();
    assert_eq!(
        Some(timestamp.signature.valid),
        oracle["signature_timestamp"]["valid"].as_bool()
    );
    assert_eq!(
        Some(timestamp.signature.trusted()),
        oracle["signature_timestamp"]["trusted"].as_bool()
    );
}
#[test]
fn pdfmac_wrong_password_and_authenticated_mutations_reject() {
    let manifest = manifest();
    // The same exact file is the paired successful authentication/LTA control.
    let positive = case(&manifest, "correct_password");
    let good = open_case(positive);
    assert_auth(&good.decrypt("secret").unwrap(), &positive["oracle"]);
    assert_native_lta(&good, &positive["oracle"]);
    for id in ["wrong_password", "mac_token_mutation", "document_mutation"] {
        let input = case(&manifest, id);
        assert_eq!(input["oracle"]["lta_attempted"], false);
        let file = open_case(input);
        let auth = file.decrypt(input["password"].as_str().unwrap()).unwrap();
        assert_auth(&auth, &input["oracle"]);
        assert_eq!(auth.status, AuthStatus::Failed, "{id}");
    }
}
#[test]
fn mac_token_mutation_preserves_cms_as_an_independent_control() {
    let manifest = manifest();
    let input = case(&manifest, "token_mutation_cms_control");
    assert_eq!(input["oracle"]["diagnostic_ignore_mac"], true);
    let file = open_case(input);
    // Diagnostic only: bypass MAC validation at the same low-level point as
    // the oracle's _validate_pdf_mac override. This is not accepted PDF auth.
    let sh = file.security_handler().unwrap().unwrap();
    let auth = sh
        .authenticate_password("secret", Some(&file.document_id().unwrap().0))
        .unwrap();
    assert_auth(&auth, &input["oracle"]);
    assert_native_lta(&file, &input["oracle"]);
}
#[test]
fn ignored_failed_auth_result_is_a_separate_compatibility_diagnostic() {
    let manifest = manifest();
    let input = case(&manifest, "post_failed_mac_lta_diagnostic");
    assert_eq!(input["oracle"]["continue_after_failed_mac"], true);
    let file = open_case(input);
    let auth = file.decrypt("secret").unwrap();
    assert_auth(&auth, &input["oracle"]);
    assert_eq!(auth.status, AuthStatus::Failed);
    // Both engines retain the key: callers MUST honor the failed AuthResult.
    // API CMS trust is deliberately not relabelled as successful PDF auth.
    assert_native_lta(&file, &input["oracle"]);
}
