//! Complete opt-in usage policies and supplemental legacy presign boundaries.
//! Supplemental zero-ID coverage; no higher-layer dev dependency or shared edit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use const_oid::ObjectIdentifier;
use der::Encode;
use serde_json::{json, Value};
use sigis_pades_sign::{
    DeferredSignatureValue, DeferredSigner, PdfSignatureMetadata, PdfSigner, SignOptions,
    SimpleSigner,
};
use sigis_pki_certvalidator::{CertificateValidator, ValidationContext};
use sigis_pki_core::algorithms::{
    validate_signature, AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm,
    SignatureValidationContext,
};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::HankoError;
use sigis_pki_core::key_usage::{cert_key_usages, KeyUsageConstraints};
use sigis_pki_core::time::Moment;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const TIME: &str = "2020-11-01T00:00:00Z";

fn hash(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn read_optional_set(value: &Value) -> Option<BTreeSet<String>> {
    if value.is_null() {
        return None;
    }
    let entries = value.as_array().expect("null or array is mandatory");
    let set: BTreeSet<_> = entries
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(set.len(), entries.len(), "duplicate policy values");
    Some(set)
}

fn full_policy(value: &Value) -> KeyUsageConstraints {
    let object = value.as_object().unwrap();
    assert_eq!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "key_usage",
            "key_usage_forbidden",
            "extd_key_usage",
            "explicit_extd_key_usage_required",
            "match_all_key_usages"
        ])
    );
    KeyUsageConstraints {
        key_usage: read_optional_set(&value["key_usage"]),
        key_usage_forbidden: read_optional_set(&value["key_usage_forbidden"]),
        extd_key_usage: read_optional_set(&value["extd_key_usage"]),
        explicit_extd_key_usage_required: value["explicit_extd_key_usage_required"]
            .as_bool()
            .unwrap(),
        match_all_key_usages: value["match_all_key_usages"].as_bool().unwrap(),
    }
}

fn oracle(mode: &str, input: &Value, directory: &Path) -> Value {
    let request = directory.join(format!("{mode}-request.json"));
    std::fs::write(&request, serde_json::to_vec_pretty(input).unwrap()).unwrap();
    let python = std::env::var_os("HANKO_ORACLE")
        .unwrap_or_else(|| "/tmp/pyhanko-oracle/venv/bin/python".into());
    let output = Command::new(python)
        .args([
            "-I",
            "-B",
            "-c",
            include_str!("../../testdata/data/lanes/r3-p/key-usage-policy/ku_policy_reference.py"),
            mode,
        ])
        .arg(&request)
        .output()
        .expect("fresh pinned reference is mandatory, never optional");
    std::fs::write(
        directory.join(format!("{mode}-stdout.json")),
        &output.stdout,
    )
    .unwrap();
    std::fs::write(directory.join(format!("{mode}-stderr.log")), &output.stderr).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["versions"],
        json!({"pyhanko": "0.38.1", "certvalidator": "0.33.0"})
    );
    // Verify every actual opened input, not a claimed path or a replayed receipt.
    let opened = value["opened_inputs"].as_array().unwrap();
    assert!(!opened.is_empty());
    for path in std::iter::once(request.as_path()).chain(
        ["leaf", "root", "intermediate", "pdf", "issuer_key"]
            .into_iter()
            .filter_map(|key| input[key].as_str().map(Path::new)),
    ) {
        let expected = path.canonicalize().unwrap();
        assert_eq!(
            opened
                .iter()
                .filter(|v| v["path"] == expected.to_str().unwrap())
                .count(),
            1,
            "missing/duplicated actual input: {}",
            expected.display()
        );
    }
    for record in opened {
        let path = PathBuf::from(record["path"].as_str().unwrap());
        assert!(path.is_absolute());
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(record["bytes"], bytes.len());
        assert_eq!(record["sha256"], hash(&bytes));
    }
    value
}

#[derive(Debug)]
struct DenyDocumentSha256;

impl AlgorithmUsagePolicy for DenyDocumentSha256 {
    fn digest_algorithm_allowed(
        &self,
        oid: &ObjectIdentifier,
        _: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        if *oid == DigestAlgorithm::Sha256.oid() {
            AlgorithmUsageConstraint::denied(
                "explicit usage bridge must preserve caller digest denial",
            )
        } else {
            AlgorithmUsageConstraint::allowed()
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

fn context(mode: &str, pki: &support::Pki) -> Option<Arc<ValidationContext>> {
    if mode == "none" {
        return None;
    }
    assert!([
        "valid",
        "empty-roots",
        "require-revinfo",
        "expired",
        "deny-digest"
    ]
    .contains(&mode));
    let mut builder = ValidationContext::builder()
        .other_cert(pki.cert("interm"))
        .moment(support::at(if mode == "expired" {
            "2050-11-01T00:00:00Z"
        } else {
            TIME
        }))
        .revocation_mode(if mode == "require-revinfo" {
            "require"
        } else {
            "soft-fail"
        });
    if mode != "empty-roots" {
        builder = builder.trust_root(pki.cert("root"));
    }
    if mode == "deny-digest" {
        builder = builder.algorithm_policy(Arc::new(DenyDocumentSha256));
    }
    Some(Arc::new(builder.build().unwrap()))
}

#[test]
fn complete_explicit_signer_usage_policy_and_legacy_controls() {
    let parent = PathBuf::from(
        std::env::var_os("HANKO_P_KU_EVIDENCE_DIR")
            .expect("new persistent evidence directory is mandatory"),
    );
    std::fs::create_dir_all(&parent).unwrap();
    let _marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(parent.join("ku-policy.started"))
        .unwrap();
    let pki = support::pki("testing-ca");
    let fixture_directory = parent.join("certificates");
    let preparation = oracle(
        "prepare",
        &json!({
            "leaf": pki.cert_path("signer1"), "intermediate": pki.cert_path("interm"),
            "root": pki.cert_path("root"),
            "issuer_key": support::data_path(&["pyhanko", "crypto", "keys-rsa", "intermediate_ca.key.pem"]),
            "directory": fixture_directory,
        }),
        &parent,
    );
    assert_eq!(
        preparation["variant_origin"],
        "REFERENCE_GENERATED_CERTIFICATES_NOT_NATIVE_PDFS"
    );
    let cases: Value = serde_json::from_str(include_str!(
        "../../testdata/data/lanes/r3-p/key-usage-policy/ku_policy_cases.json"
    ))
    .unwrap();
    let cases = cases.as_array().unwrap();
    assert_eq!(
        cases.len(),
        26,
        "retain the entire approved draft parameter matrix"
    );
    let expected_ids: BTreeSet<_> = [
        "attached-match-any",
        "attached-match-all",
        "forbidden-only-none",
        "forbidden-only-empty",
        "forbidden-with-positive",
        "missing-eku-required",
        "missing-eku-optional",
        "any-eku-required",
        "any-eku-optional",
        "exact-eku",
        "other-eku",
        "empty-eku-set",
        "legacy-default",
        "legacy-all",
        "legacy-missing-request",
        "legacy-empty",
        "legacy-no-context-default",
        "legacy-no-context-impossible",
        "explicit-no-context-match-any",
        "explicit-no-context-match-all",
        "missing-ku-explicit",
        "explicit-no-requirements",
        "guard-empty-roots",
        "guard-require-revinfo",
        "guard-expired",
        "guard-digest-policy",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        cases
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        expected_ids
    );
    let mut ids = BTreeSet::new();
    for case in cases {
        assert_eq!(
            case.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "id",
                "variant",
                "context",
                "legacy",
                "policy",
                "native_ok",
                "oracle_policy_ok",
                "core_policy_ok",
                "error_contains"
            ])
        );
        for key in ["native_ok", "oracle_policy_ok", "core_policy_ok"] {
            assert!(case[key].is_boolean());
        }
        assert!(["base", "any-eku", "exact-eku", "other-eku", "missing-ku"]
            .contains(&case["variant"].as_str().unwrap()));
        let name = case["id"].as_str().unwrap();
        assert!(ids.insert(name), "duplicate case: {name}");
        let directory = parent.join(name);
        std::fs::create_dir(&directory).unwrap();
        let leaf_path = PathBuf::from(
            preparation["variants"][case["variant"].as_str().unwrap()]["path"]
                .as_str()
                .unwrap(),
        );
        let leaf_bytes = std::fs::read(&leaf_path).unwrap();
        assert_eq!(
            preparation["variants"][case["variant"].as_str().unwrap()]["sha256"],
            hash(&leaf_bytes)
        );
        let cert = Cert::from_der(&leaf_bytes).unwrap();
        if case["variant"] != "missing-ku" {
            assert_eq!(
                cert_key_usages(&cert),
                Some(BTreeSet::from([
                    "digital_signature".into(),
                    "non_repudiation".into()
                ]))
            );
        }
        let ctx = context(case["context"].as_str().unwrap(), &pki);
        let mut metadata = PdfSignatureMetadata::pyhanko_defaults("Sig1");
        assert_eq!(metadata.signer_key_usage, ["non_repudiation"]);
        metadata.md_algorithm = Some(DigestAlgorithm::Sha256);
        metadata.validation_context = ctx.clone();
        metadata.signer_key_usage = case["legacy"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let key = pki.key(&pki.key_label_of("signer1"));
        let signer = SimpleSigner::new(
            key,
            cert.clone(),
            vec![pki.cert("root"), pki.cert("interm")],
        )
        .unwrap();
        let mut signer = PdfSigner::new(metadata, Arc::new(signer)).at(support::at(TIME));
        if !case["policy"].is_null() {
            let policy = full_policy(&case["policy"]);
            assert_eq!(
                policy.validate(&cert).is_ok(),
                case["core_policy_ok"].as_bool().unwrap()
            );
            // This exact missing method is the intentional initial API RED.
            // No helper silently translates ANY into the old metadata ALL Vec.
            signer = signer.with_signer_key_usage_policy(policy);
        }
        let input = support::pdf("minimal.pdf");
        let before = input.clone();
        let result = signer.sign_pdf(&input);
        assert_eq!(input, before);
        if let Some(ctx) = &ctx {
            assert!(Arc::ptr_eq(
                ctx,
                signer.metadata.validation_context.as_ref().unwrap()
            ));
        }
        let mut reference = json!({"case": case, "leaf": leaf_path,
            "root": pki.cert_path("root"), "intermediate": pki.cert_path("interm"), "pdf": null});
        if case["native_ok"].as_bool().unwrap() {
            let output = result.unwrap_or_else(|error| panic!("{name}: {error}"));
            let signatures = support::pdfcheck::embedded_signatures(&output);
            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].field_name, "Sig1");
            assert_eq!(
                support::pdfcheck::check_integrity(&output, &signatures[0]),
                cert
            );
            let cms = sigis_pades_sign::cms::decode_signed_data(&support::pdfcheck::cms_bytes(
                &signatures[0],
            ))
            .unwrap();
            assert_eq!(cms.signer_infos.0.len(), 1);
            let si = cms.signer_infos.0.iter().next().unwrap();
            assert_eq!(si.digest_alg.oid, DigestAlgorithm::Sha256.oid());
            assert_eq!(
                si.signature_algorithm.oid,
                sigis_pki_core::asn1::oids::SHA256_WITH_RSA
            );
            // No AlgorithmNotSupported=>skip path is acceptable for this
            // actual RSA/SHA256 fixture signature.
            validate_signature(
                si.signature.as_bytes(),
                &si.signed_attrs.as_ref().unwrap().to_der().unwrap(),
                &cert.public_key(),
                &si.signature_algorithm,
                &SignatureValidationContext::default(),
            )
            .unwrap();
            if let Some(ctx) = &ctx {
                let path = CertificateValidator::new(ctx, cert.clone())
                    .validate()
                    .unwrap();
                assert_eq!(path.certs().len(), 3);
            }
            let path = directory.join("native.pdf");
            std::fs::write(&path, &output).unwrap();
            reference["pdf"] = json!(path);
            let verdict = oracle("check", &reference, &directory);
            assert_eq!(verdict["full_native_pdf_checked"], true);
            assert_eq!(verdict["policy_ok"], true);
            let raw_trusted = !matches!(name, "missing-eku-optional" | "any-eku-optional");
            assert_eq!(verdict["raw_pdf_facade"]["trusted"], raw_trusted);
            assert_eq!(verdict["raw_pdf_facade"]["bottom_line"], raw_trusted);
            if !raw_trusted {
                assert_eq!(
                    verdict["raw_pdf_facade"]["trust_indication"],
                    "CHAIN_CONSTRAINTS_FAILURE"
                );
            }
            assert_eq!(verdict["pdf_sha256"], hash(&output));
            assert_eq!(verdict["signer_sha256"], hash(cert.der()));
            for key in ["intact", "valid", "trusted", "bottom_line"] {
                assert_eq!(verdict[key], true);
            }
            assert_eq!(verdict["path_len"], 3);
            assert_eq!(verdict["coverage"], "ENTIRE_FILE");
            assert_eq!(verdict["modification_level"], "NONE");
            assert!(verdict["opened_inputs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["path"] == path.canonicalize().unwrap().to_str().unwrap()));
            let executable = std::env::current_exe().unwrap();
            let elf = std::fs::read(&executable).unwrap();
            assert!(elf.starts_with(b"\x7fELF"));
            std::fs::write(directory.join("native-receipt.json"), serde_json::to_vec_pretty(&json!({
                "case":name, "pdf_bytes":output.len(), "pdf_sha256":hash(&output),
                "cert_sha256":hash(cert.der()), "elf_path":executable, "elf_bytes":elf.len(), "elf_sha256":hash(&elf),
                "source_provenance":"requires independent compiler-input audit; ELF/source coexistence is insufficient",
            })).unwrap()).unwrap();
        } else {
            let error = result.expect_err(name);
            assert!(matches!(error, HankoError::Signing(_)), "{name}: {error}");
            assert!(
                error
                    .to_string()
                    .to_lowercase()
                    .contains(case["error_contains"].as_str().unwrap()),
                "{name}: {error}"
            );
            std::fs::write(directory.join("native-error.txt"), error.to_string()).unwrap();
            let verdict = oracle("check", &reference, &directory);
            assert_eq!(verdict["full_native_pdf_checked"], false);
            assert_eq!(verdict["policy_ok"], case["oracle_policy_ok"]);
        }
    }
}

#[test]
fn explicit_policy_certificate_less_and_legacy_preparation_boundaries() {
    let positive_policy = KeyUsageConstraints::with_key_usage(["non_repudiation"], []);
    for attached in [false, true] {
        for explicit in [false, true] {
            let mut metadata = PdfSignatureMetadata::new("Sig1");
            metadata.md_algorithm = Some(DigestAlgorithm::Sha256);
            if attached {
                metadata.validation_context = context("valid", &support::pki("testing-ca"));
            }
            let provider = DeferredSigner::new(
                None,
                Vec::new(),
                DeferredSignatureValue::Size(256),
                Some(AlgorithmIdentifierOwned {
                    oid: sigis_pki_core::asn1::oids::SHA256_WITH_RSA,
                    parameters: None,
                }),
            );
            let mut signer = PdfSigner::with_signing_provider(metadata, Arc::new(provider));
            if explicit {
                signer = signer.with_signer_key_usage_policy(positive_policy.clone());
            }
            let result = signer.digest_doc_for_signing(
                &support::pdf("minimal.pdf"),
                &SignOptions {
                    bytes_reserved: Some(8192),
                    ..Default::default()
                },
            );
            if attached || explicit {
                let error =
                    result.expect_err("explicit policy or context requires an actual certificate");
                assert!(matches!(error, HankoError::Signing(_)), "{error}");
                assert!(
                    error.to_string().to_lowercase().contains("certificate"),
                    "{error}"
                );
            } else {
                assert_eq!(result.unwrap().md_algorithm, DigestAlgorithm::Sha256);
            }
        }
    }
}

/// A real compatibility rejection, not the opt-in policy composition contract.
/// Collect all native/reference evidence before asserting the legacy refusal.
#[test]
fn legacy_missing_key_usage_extension_preserves_original_refusal() {
    let parent = PathBuf::from(
        std::env::var_os("HANKO_P_LEGACY_KU_EVIDENCE_DIR")
            .expect("persistent evidence directory is mandatory"),
    );
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(parent.join("legacy-ku.started"))
        .unwrap();
    let pki = support::pki("testing-ca");
    let manifest_path = support::data_path(&["lanes", "d", "pki", "testing-ca", "manifest.json"]);
    let manifest: Value = serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
    let key_name = pki.key_label_of("signer1");
    let key_path = support::data_path(&[
        "pyhanko",
        "crypto",
        manifest["keys"][&key_name]["path"].as_str().unwrap(),
    ]);
    let preparation = oracle(
        "prepare",
        &json!({
            "leaf":pki.cert_path("signer1"), "intermediate":pki.cert_path("interm"), "root":pki.cert_path("root"),
            "issuer_key":support::data_path(&["pyhanko", "crypto", "keys-rsa", "intermediate_ca.key.pem"]),
            "directory":parent.join("certificates"),
        }),
        &parent,
    );
    let cases = [
        (
            "missing-ku-attached-default",
            true,
            true,
            vec!["non_repudiation"],
            false,
        ),
        ("missing-ku-attached-empty", true, true, vec![], true),
        (
            "missing-ku-no-context-default",
            true,
            false,
            vec!["non_repudiation"],
            true,
        ),
        ("missing-ku-no-context-empty", true, false, vec![], true),
        (
            "present-ku-attached-default",
            false,
            true,
            vec!["non_repudiation"],
            true,
        ),
        (
            "present-ku-attached-impossible",
            false,
            true,
            vec!["non_repudiation", "key_encipherment"],
            false,
        ),
    ];
    let mut disagreements = Vec::new();
    for (name, missing_ku, attached, legacy, expected_ok) in cases {
        let directory = parent.join(name);
        std::fs::create_dir(&directory).unwrap();
        let variant = if missing_ku { "missing-ku" } else { "base" };
        let leaf_path = PathBuf::from(preparation["variants"][variant]["path"].as_str().unwrap());
        let leaf_bytes = std::fs::read(&leaf_path).unwrap();
        assert_eq!(
            hash(&leaf_bytes),
            preparation["variants"][variant]["sha256"]
        );
        let cert = Cert::from_der(&leaf_bytes).unwrap();
        assert_eq!(cert.key_usage().is_none(), missing_ku);
        assert_eq!(
            !cert.has_extension(&sigis_pki_core::asn1::oids::CE_KEY_USAGE),
            missing_ku
        );
        let ctx = context(if attached { "valid" } else { "none" }, &pki);
        let mut metadata = PdfSignatureMetadata::pyhanko_defaults("Sig1");
        metadata.md_algorithm = Some(DigestAlgorithm::Sha256);
        metadata.validation_context = ctx.clone();
        metadata.signer_key_usage = legacy.iter().map(|v| (*v).to_owned()).collect();
        let signer = PdfSigner::new(
            metadata,
            Arc::new(
                SimpleSigner::new(
                    pki.key(&key_name),
                    cert.clone(),
                    vec![pki.cert("root"), pki.cert("interm")],
                )
                .unwrap(),
            ),
        )
        .at(support::at(TIME));
        let input = support::pdf("minimal.pdf");
        let before = input.clone();
        let result = signer.sign_pdf(&input);
        assert_eq!(input, before);
        if let Some(ctx) = &ctx {
            assert!(Arc::ptr_eq(
                ctx,
                signer.metadata.validation_context.as_ref().unwrap()
            ));
        }
        let native_ok = result.is_ok();
        let native_path = directory.join("native.pdf");
        if let Ok(output) = result {
            std::fs::write(&native_path, &output).unwrap();
            let signatures = support::pdfcheck::embedded_signatures(&output);
            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].field_name, "Sig1");
            assert_eq!(
                support::pdfcheck::check_integrity(&output, &signatures[0]),
                cert
            );
            let cms = sigis_pades_sign::cms::decode_signed_data(&support::pdfcheck::cms_bytes(
                &signatures[0],
            ))
            .unwrap();
            assert_eq!(cms.signer_infos.0.len(), 1);
            let si = cms.signer_infos.0.iter().next().unwrap();
            assert_eq!(si.digest_alg.oid, DigestAlgorithm::Sha256.oid());
            assert_eq!(
                si.signature_algorithm.oid,
                sigis_pki_core::asn1::oids::SHA256_WITH_RSA
            );
            validate_signature(
                si.signature.as_bytes(),
                &si.signed_attrs.as_ref().unwrap().to_der().unwrap(),
                &cert.public_key(),
                &si.signature_algorithm,
                &SignatureValidationContext::default(),
            )
            .unwrap();
            if let Some(ctx) = &ctx {
                assert_eq!(
                    CertificateValidator::new(ctx, cert.clone())
                        .validate()
                        .unwrap()
                        .certs()
                        .len(),
                    3
                );
            }
        } else if let Err(error) = result {
            assert!(matches!(error, HankoError::Signing(_)));
            assert!(error
                .to_string()
                .contains("key usage extension does not include"));
            std::fs::write(directory.join("native-error.txt"), error.to_string()).unwrap();
        }
        let request = json!({"case":name,"missing_ku":missing_ku,"attached":attached,"legacy":legacy,"expected_ok":expected_ok,
            "leaf":leaf_path,"root":pki.cert_path("root"),"intermediate":pki.cert_path("interm"),"signer_key":key_path,
            "input":support::data_path(&["pyhanko","pdf","minimal.pdf"]),"native_pdf":if native_ok {json!(native_path)} else {Value::Null},
            "reference_output":directory.join("reference.pdf")});
        let request_path = directory.join("request.json");
        std::fs::write(&request_path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();
        let python = std::env::var_os("HANKO_ORACLE")
            .unwrap_or_else(|| "/tmp/pyhanko-oracle/venv/bin/python".into());
        let output = Command::new(python)
            .args([
                "-I",
                "-B",
                "-c",
                include_str!(
                    "../../testdata/data/lanes/r3-p/key-usage-policy/legacy_ku_reference.py"
                ),
            ])
            .arg(&request_path)
            .output()
            .unwrap();
        std::fs::write(directory.join("reference-stdout.json"), &output.stdout).unwrap();
        std::fs::write(directory.join("reference-stderr.log"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reference: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(reference["original_signing_ok"], expected_ok);
        assert_eq!(
            reference["versions"],
            json!({"pyhanko":"0.38.1","certvalidator":"0.33.0"})
        );
        let opened_records = reference["opened_inputs"].as_array().unwrap();
        let mut expected_paths = vec![request_path.clone()];
        for key in ["leaf", "root", "intermediate", "signer_key", "input"] {
            expected_paths.push(PathBuf::from(request[key].as_str().unwrap()));
        }
        if native_ok {
            expected_paths.push(native_path.clone());
            assert_eq!(
                reference["same_native_output"]["pdf_sha256"],
                hash(&std::fs::read(&native_path).unwrap())
            );
            assert_eq!(reference["same_native_output"]["intact"], true);
            assert_eq!(reference["same_native_output"]["valid"], true);
            assert_eq!(reference["same_native_output"]["trusted"], expected_ok);
            assert_eq!(reference["same_native_output"]["bottom_line"], expected_ok);
        }
        if expected_ok {
            expected_paths.push(directory.join("reference.pdf"));
        }
        for path in expected_paths {
            let path = path.canonicalize().unwrap();
            assert_eq!(
                opened_records
                    .iter()
                    .filter(|r| r["path"] == path.to_str().unwrap())
                    .count(),
                1,
                "missing/duplicate actual read: {}",
                path.display()
            );
        }
        for opened in opened_records {
            let bytes = std::fs::read(opened["path"].as_str().unwrap()).unwrap();
            assert_eq!(opened["bytes"], bytes.len());
            assert_eq!(opened["sha256"], hash(&bytes));
        }
        let elf_path = std::env::current_exe().unwrap();
        let elf = std::fs::read(&elf_path).unwrap();
        std::fs::write(directory.join("native-receipt.json"),serde_json::to_vec_pretty(&json!({"case":name,"native_ok":native_ok,"expected_ok":expected_ok,"elf_path":elf_path,"elf_bytes":elf.len(),"elf_sha256":hash(&elf),"pdf_sha256":if native_ok {Some(hash(&std::fs::read(&native_path).unwrap()))} else {None}})).unwrap()).unwrap();
        if native_ok != expected_ok {
            disagreements.push(name);
        }
    }
    assert!(disagreements.is_empty(),"legacy presign differs from the original on {disagreements:?}; do not accept absent KU for a nonempty attached-context requirement");
}
