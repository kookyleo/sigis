//! Validation-side seed-value regressions derived from pyHanko 0.38.1
//! `tests/test_seed_values.py`. These do not earn additional V function passes.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::{b64, data};
use serde_json::Value;
use sigis_pades::errors::SignatureValidationErrorKind;
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::DisallowWeakAlgorithmsPolicy;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::HankoError;

fn fixtures() -> (PathBuf, Value) {
    let root = std::env::var_os("HANKO_SEED_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| data(&["lanes", "r3-v", "seed"]));
    let manifest: Value =
        serde_json::from_slice(&common::read_fixture(root.join("manifest.json"))).unwrap();
    assert_eq!(manifest["cases"].as_array().unwrap().len(), 75);
    (root, manifest)
}

fn context(manifest: &Value, case: &Value) -> ValidationContext {
    // Mirrors upstream dummy_ocsp_vc(): the unrelated fixed OCSP response is
    // advisory under soft-fail, fetching is disabled, and SHA-1 is permitted.
    let mut builder = ValidationContext::builder();
    if case["trust_signer"].as_bool().unwrap_or(true) {
        builder = builder
            .trust_root(Cert::from_der(&b64(manifest["trust_root"].as_str().unwrap())).unwrap());
    }
    builder
        .moment(
            sigis_eutl::util::parse_xsd_datetime(manifest["validation_time"].as_str().unwrap())
                .unwrap(),
        )
        .revocation_mode("soft-fail")
        .algorithm_policy(Arc::new(
            DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&[]),
        ))
        .build()
        .unwrap()
}

fn run_group(group: &str) {
    let (root, manifest) = fixtures();
    assert_eq!(manifest["pyhanko"], "0.38.1");
    let cases: Vec<_> = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["group"] == group)
        .collect();
    let count = match group {
        "digest" => 7,
        "reasons" => 12,
        "timestamp" => 4,
        "subfilter" => 5,
        "mdp" => 17,
        "certificate" => 20,
        "unsupported" => 10,
        other => panic!("unknown fixture group {other}"),
    };
    assert_eq!(cases.len(), count, "incomplete fixture group {group}");
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let bytes = common::read_fixture(root.join(case["file"].as_str().unwrap()));
        let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
        let signatures = file.embedded_signatures().unwrap();
        assert_eq!(signatures.len(), 1, "{id}");
        let signature = &signatures[0];
        assert_eq!(signature.field_name, "Sig", "{id}");
        if case["expectation"] == "stricter" || case["oracle"]["outcome"] == "exception" {
            // Mandatory-guard rejection cannot be satisfied by a failure in
            // the underlying CMS or timestamp verifier.
            let cms = sigis_cms::validate_cms_signature(
                sigis_pades::cms_from_contents(&signature.contents).unwrap(),
                sigis_cms::SignedContent::Data(&signature.signed_data(&file).unwrap()),
                &context(&manifest, case),
            )
            .unwrap();
            assert!(
                cms.signature.intact && cms.signature.valid && cms.signature.trusted(),
                "{id}"
            );
            assert!(cms.bottom_line(), "{id}");
        }
        let result =
            sigis_pades::validate_pdf_signature(&file, signature, &context(&manifest, case), None);
        if case["expectation"] == "stricter" || case["oracle"]["outcome"] == "exception" {
            match result {
                Ok(status) => {
                    assert!(status.has_seed_values, "{id}");
                    assert!(!status.seed_value_ok(), "{id}: mandatory guard must reject");
                    assert!(!status.bottom_line(), "{id}: mandatory guard must reject");
                    assert_eq!(
                        status.seed_value_constraint_error.as_ref().unwrap().kind,
                        SignatureValidationErrorKind::SeedValue,
                        "{id}"
                    );
                }
                Err(
                    error @ (HankoError::NotImplemented(_)
                    | HankoError::Malformed(_)
                    | HankoError::SignatureValidation { .. }),
                ) => {
                    assert!(!error.to_string().is_empty(), "{id}");
                }
                Err(error) => panic!("{id}: unrelated error cannot satisfy a seed guard: {error}"),
            }
            if case["expectation"] == "stricter" {
                assert_eq!(case["oracle"]["seed_value_ok"], true, "{id}");
                assert_eq!(case["oracle"]["bottom_line"], true, "{id}");
                assert!(!case["divergence"].as_str().unwrap().is_empty(), "{id}");
            }
            continue;
        }
        let status = result.unwrap_or_else(|error| panic!("{id}: {error}"));
        let expected = &case["oracle"];
        assert_eq!(
            status.has_seed_values,
            expected["has_seed_values"].as_bool().unwrap(),
            "{id}"
        );
        assert_eq!(
            status.seed_value_ok(),
            expected["seed_value_ok"].as_bool().unwrap(),
            "{id}"
        );
        assert_eq!(
            status.bottom_line(),
            expected["bottom_line"].as_bool().unwrap(),
            "{id}"
        );
        assert_eq!(
            status.cms.signature.intact,
            expected["intact"].as_bool().unwrap(),
            "{id}"
        );
        assert_eq!(
            status.cms.signature.valid,
            expected["valid"].as_bool().unwrap(),
            "{id}"
        );
        assert_eq!(
            status.cms.signature.trusted(),
            expected["trusted"].as_bool().unwrap(),
            "{id}"
        );
        assert_eq!(
            status.cms.signature.md_algorithm_name,
            expected["md_algorithm"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            signature.sub_filter.as_deref(),
            expected["subfilter"]
                .as_str()
                .map(|value| value.trim_start_matches('/')),
            "{id}"
        );
        assert_eq!(
            status.docmdp_level.map(|value| value as u64),
            expected["docmdp_level"].as_u64(),
            "{id}"
        );
        let dictionary = file
            .object_in_revision(signature.sig_object, signature.signed_revision)
            .unwrap()
            .unwrap();
        let reason = match dictionary.as_dict().unwrap().get(b"Reason") {
            Ok(sigis_pdf::lopdf::Object::String(bytes, _)) => {
                Some(String::from_utf8(bytes.clone()).unwrap())
            }
            Err(_) => None,
            other => panic!("{id}: unexpected /Reason {other:?}"),
        };
        assert_eq!(reason.as_deref(), expected["reason"].as_str(), "{id}");
        if expected["error"].is_null() {
            assert!(status.seed_value_constraint_error.is_none(), "{id}");
        } else {
            let error = status
                .seed_value_constraint_error
                .as_ref()
                .unwrap_or_else(|| panic!("{id}: missing seed error"));
            assert_eq!(error.kind, SignatureValidationErrorKind::SeedValue, "{id}");
            assert!(!error.failure_message.is_empty(), "{id}");
            assert_eq!(
                expected["error"]["type"], "SigSeedValueValidationError",
                "{id}"
            );
        }
    }
}

#[test]
fn seed_digest_methods_required_and_hints() {
    run_group("digest");
}

#[test]
fn seed_reasons_required_and_all_prohibition_parameters() {
    run_group("reasons");
}

#[test]
fn seed_requires_a_trusted_timestamp() {
    run_group("timestamp");
}

#[test]
fn seed_subfilters_required_and_hints() {
    run_group("subfilter");
}

#[test]
fn seed_certification_mdp_and_lock_requirements() {
    run_group("mdp");
}

#[test]
fn seed_certificate_subject_issuer_and_key_usage() {
    run_group("certificate");
}

#[test]
fn seed_unsupported_mandatory_guards_reject_explicitly() {
    run_group("unsupported");
}

#[test]
fn optional_seed_filter_references_must_resolve() {
    let (root, manifest) = fixtures();
    let oracle: Value = serde_json::from_slice(&common::read_fixture(
        root.join("optional_filter_dangling.json"),
    ))
    .unwrap();
    assert_eq!(oracle["oracle"]["type"], "PdfStrictReadError");
    assert!(oracle["oracle"]["message"]
        .as_str()
        .unwrap()
        .contains("999999"));
    let bytes = common::read_fixture(root.join("optional_filter_dangling.pdf"));
    let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let signature = &signatures[0];
    let field = file
        .object_in_revision(signature.field_object, signature.signed_revision)
        .unwrap()
        .unwrap();
    let seed = sigis_pades::integrity::resolve(
        &file,
        field.as_dict().unwrap().get(b"SV").unwrap(),
        signature.signed_revision,
    )
    .unwrap();
    assert!(matches!(
        seed.as_dict().unwrap().get(b"Ff"),
        Ok(sigis_pdf::lopdf::Object::Integer(0))
    ));
    let context = context(&manifest, &Value::Null);
    let cms = sigis_cms::validate_cms_signature(
        sigis_pades::cms_from_contents(&signature.contents).unwrap(),
        sigis_cms::SignedContent::Data(&signature.signed_data(&file).unwrap()),
        &context,
    )
    .unwrap();
    assert!(cms.signature.intact && cms.signature.valid && cms.signature.trusted());
    assert!(cms.bottom_line());
    let error = sigis_pades::validate_pdf_signature(&file, signature, &context, None)
        .expect_err("optional seed /Filter must not hide an unresolved reference");
    assert!(matches!(error, HankoError::Malformed(_)), "{error}");
    assert!(error.to_string().contains("999999"), "{error}");
}
