// Exact validator assertions from pyHanko 0.38.1 test_diff_analysis.py.
// The two upstream functions belong to S; they do not add V function passes.

mod common;

use common::{b64, data};
use serde_json::Value;
use sigis_cms::{signed_data::extract_certificate_info, SignedContent};
use sigis_pades::ades::{validate_pdf_ades, AdesLevel, AdesStatus};
use sigis_pades::{
    validate_pdf_signature, validate_pdf_signature_with_options, PdfSignatureStatus,
    SignatureCoverageLevel,
};
use sigis_pdf::{EmbeddedSignature, PdfFile};
use sigis_pdf_diff::{ConfigurableDiffPolicy, DiffOutcome, DiffPolicy, ModificationLevel};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{algorithms::DisallowWeakAlgorithmsPolicy, cert::Cert, time::Moment};
use std::{path::PathBuf, sync::Arc};

fn fixtures() -> (PathBuf, Value) {
    let root = std::env::var_os("HANKO_INTEGRITY_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| data(&["lanes", "r3-v", "integrity"]));
    let manifest =
        serde_json::from_slice(&common::read_fixture(root.join("manifest.json"))).unwrap();
    (root, manifest)
}

fn context(manifest: &Value, trusted: bool) -> ValidationContext {
    let mut builder = ValidationContext::builder();
    if trusted {
        builder = builder
            .trust_root(Cert::from_der(&b64(manifest["trust_root"].as_str().unwrap())).unwrap());
    }
    builder
        .moment(Moment::parse_rfc3339(manifest["validation_time"].as_str().unwrap()).unwrap())
        .revocation_mode("soft-fail")
        .algorithm_policy(Arc::new(
            DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&[]),
        ))
        .build()
        .unwrap()
}

fn open(bytes: &[u8]) -> (PdfFile, EmbeddedSignature) {
    let file = PdfFile::parse(bytes).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    (file, signatures.into_iter().next().unwrap())
}

fn agree(status: &PdfSignatureStatus, oracle: &Value) {
    assert_eq!(
        status.cms.signature.valid,
        oracle["valid"].as_bool().unwrap()
    );
    assert_eq!(
        status.cms.signature.intact,
        oracle["intact"].as_bool().unwrap()
    );
    assert_eq!(
        status.cms.signature.trusted(),
        oracle["trusted"].as_bool().unwrap()
    );
    assert_eq!(
        status.bottom_line(),
        oracle["bottom_line"].as_bool().unwrap()
    );
    assert_eq!(
        status
            .modification_level()
            .map(|level| format!("{level:?}")),
        oracle["modification_level_rust"]
            .as_str()
            .map(str::to_owned)
    );
}

fn assert_basic_facade_rejects(
    file: &PdfFile,
    signature: &EmbeddedSignature,
    ctx: &ValidationContext,
) {
    // A guard failure must not be satisfied merely by untrusted or broken CMS.
    let cms = sigis_cms::validate_cms_signature(
        &signature.contents,
        SignedContent::Data(&signature.signed_data(file).unwrap()),
        ctx,
    )
    .unwrap();
    assert!(
        cms.signature.intact && cms.signature.valid && cms.signature.trusted(),
        "{cms:?}"
    );
    assert!(cms.bottom_line(), "{cms:?}");
    match validate_pdf_ades(file, signature, AdesLevel::Basic, ctx) {
        Ok(result) => assert_ne!(result.status, AdesStatus::Passed),
        Err(error) => assert!(!error.to_string().is_empty()),
    }
}

#[test]
fn test_tamper_sig_obj() {
    let (root, manifest) = fixtures();
    let bytes = common::read_fixture(root.join("tampered-signature.pdf"));
    let cases = manifest["tamper"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for (index, mode) in ["default", "no_changes", "skip_diff"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(cases[index]["mode"], mode);
        let (file, signature) = open(&bytes);
        let no_changes = ConfigurableDiffPolicy::no_changes();
        let policy: Option<&dyn DiffPolicy> = match mode {
            "default" => Some(&sigis_pdf_diff::StandardDiffPolicy),
            "no_changes" => Some(&no_changes),
            "skip_diff" => None,
            _ => unreachable!(),
        };
        let status =
            validate_pdf_signature(&file, &signature, &context(&manifest, false), policy).unwrap();
        if mode == "skip_diff" {
            assert!(status.diff_result.is_none());
        } else {
            assert!(matches!(
                status.diff_result.as_ref(),
                Some(DiffOutcome::Suspicious(_))
            ));
        }
        assert_eq!(
            status.coverage,
            SignatureCoverageLevel::ContiguousBlockFromStart
        );
        assert_eq!(status.modification_level(), Some(ModificationLevel::Other));
        agree(&status, &cases[index]);
        assert!(!status.bottom_line());
        assert_basic_facade_rejects(&file, &signature, &context(&manifest, true));
    }
}

fn anomalous_coverage_parameter(name: &str, expected: SignatureCoverageLevel) {
    let (_, manifest) = fixtures();
    let cases = manifest["anomalous"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let oracle = cases.iter().find(|case| case["name"] == name).unwrap();
    assert_eq!(oracle["name"], name);
    let bytes = common::read_fixture(data(&["pyhanko", "pdf", "coverage-anomalies", name]));
    let (file, signature) = open(&bytes);
    let expected_range: Vec<u64> = oracle["byte_range"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap())
        .collect();
    assert_eq!(signature.byte_range, expected_range, "{name}");
    let options = sigis_cms::CmsValidationOptions {
        key_usage_settings: Some(sigis_pades::settings::KeyUsageConstraints {
            key_usage: Some(Default::default()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let status = validate_pdf_signature_with_options(
        &file,
        &signature,
        &context(&manifest, true),
        Some(&sigis_pdf_diff::StandardDiffPolicy),
        &options,
    )
    .unwrap();
    assert!(status.cms.signature.valid, "{name}");
    assert!(status.cms.signature.intact, "{name}");
    assert!(!status.cms.signature.trusted(), "{name}");
    assert_eq!(status.coverage, expected, "{name}");
    assert!(!status.bottom_line(), "{name}");
    assert!(status.summary().contains("NONSTANDARD_COVERAGE"), "{name}");
    agree(&status, oracle);

    // Reports must preserve the actual range cardinality and ordering of
    // this real validation input, including the two-integer sample.
    let report = sigis_pades::ades::etsi_report::ReportInput::from_pdf(
        &file,
        &signature,
        &sigis_pades::ades::etsi_report::ReportValidation {
            validation_time: context(&manifest, true).moment(),
            best_signature_time: None,
            process: sigis_pades::ades::etsi_report::ValidationProcess::Basic,
            subindication: sigis_pades::ades::basic::basic_subindication(&status.cms.signature),
            status: &status.cms,
        },
    )
    .unwrap();
    assert_eq!(
        report.attributes.byte_range.as_slice(),
        signature.byte_range.as_slice()
    );
    let exact_range = signature
        .byte_range
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let xml = sigis_pades::ades::etsi_report::generate_report(&report).unwrap();
    assert!(
        xml.contains(&format!("<vr:ByteRange>{exact_range}</vr:ByteRange>")),
        "{name}"
    );
    assert!(
        !xml.contains("urn:etsi:019102:mainindication:total-passed"),
        "{name}"
    );

    // Grant this signer's key explicit trust so the facade guard cannot
    // pass only because the upstream sample uses an unrelated certificate.
    let cms = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
    let signer = extract_certificate_info(&cms).unwrap().signer_cert;
    let trusted_signer = ValidationContext::builder()
        .trust_root(signer)
        .moment(Moment::parse_rfc3339(manifest["validation_time"].as_str().unwrap()).unwrap())
        .revocation_mode("soft-fail")
        .algorithm_policy(Arc::new(
            DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&[]),
        ))
        .build()
        .unwrap();
    assert_basic_facade_rejects(&file, &signature, &trusted_signer);
}

#[test]
fn test_anomalous_coverage_tail_uncovered() {
    anomalous_coverage_parameter(
        "tail-uncovered.pdf",
        SignatureCoverageLevel::ContiguousBlockFromStart,
    );
}

#[test]
fn test_anomalous_coverage_signature_gap_too_big() {
    anomalous_coverage_parameter("signature-gap-too-big.pdf", SignatureCoverageLevel::Unclear);
}

#[test]
fn test_anomalous_coverage_one_byterange() {
    anomalous_coverage_parameter("one-byterange.pdf", SignatureCoverageLevel::Unclear);
}

#[test]
fn test_anomalous_coverage_weird_byterange() {
    anomalous_coverage_parameter("weird-byterange.pdf", SignatureCoverageLevel::Unclear);
}

#[test]
fn integrity_positive_controls_remain_accepted() {
    let (root, manifest) = fixtures();
    let bytes = common::read_fixture(root.join("clean-signature.pdf"));
    let (file, signature) = open(&bytes);
    let ctx = context(&manifest, true);
    let status = validate_pdf_signature(
        &file,
        &signature,
        &ctx,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    )
    .unwrap();
    assert_eq!(status.coverage, SignatureCoverageLevel::EntireFile);
    assert_eq!(status.modification_level(), Some(ModificationLevel::None));
    assert!(status.bottom_line());
    assert_eq!(
        validate_pdf_ades(&file, &signature, AdesLevel::Basic, &ctx)
            .unwrap()
            .status,
        AdesStatus::Passed
    );
    agree(&status, &manifest["clean_control"]);
}

#[test]
fn basic_facade_rejects_disallowed_modifications_with_valid_coverage() {
    let (root, manifest) = fixtures();
    let bytes = common::read_fixture(root.join("page-modified.pdf"));
    let (file, signature) = open(&bytes);
    let ctx = context(&manifest, true);
    let status = validate_pdf_signature(
        &file,
        &signature,
        &ctx,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    )
    .unwrap();
    assert_eq!(status.coverage, SignatureCoverageLevel::EntireRevision);
    assert_eq!(status.modification_level(), Some(ModificationLevel::Other));
    assert_eq!(status.docmdp_ok, Some(false));
    assert!(!status.bottom_line());
    agree(&status, &manifest["modification_control"]);
    assert_basic_facade_rejects(&file, &signature, &ctx);
}

#[test]
fn basic_facade_rejects_mandatory_seed_constraints_with_valid_cms() {
    // Reuse the exact seed validator inputs, rather than mutate signed bytes
    // and accidentally satisfy the guard through a CMS integrity failure.
    let root = data(&["lanes", "r3-v", "seed"]);
    let manifest: Value =
        serde_json::from_slice(&common::read_fixture(root.join("manifest.json"))).unwrap();
    let case = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "digest_required_sha1_reject")
        .unwrap();
    assert_eq!(case["oracle"]["seed_value_ok"], false);
    let bytes = common::read_fixture(root.join(case["file"].as_str().unwrap()));
    let (file, signature) = open(&bytes);
    let ctx = context(&manifest, true);
    let status = validate_pdf_signature(
        &file,
        &signature,
        &ctx,
        Some(&sigis_pdf_diff::StandardDiffPolicy),
    )
    .unwrap();
    assert_eq!(status.coverage, SignatureCoverageLevel::EntireFile);
    assert!(!status.seed_value_ok());
    assert!(!status.bottom_line());
    assert_basic_facade_rejects(&file, &signature, &ctx);
}
