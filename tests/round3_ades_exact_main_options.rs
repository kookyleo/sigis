//! Tests-first real native signer callers for opt-in AdES MAIN usage.
//! Supplemental compatibility/security assertions; zero original-function credit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/signing_integration.rs"]
mod support;

use sigis_pades::ades::{
    basic::{basic_validation, basic_validation_with_options, QualificationSpec},
    etsi_report::{ReportInput, ReportValidation, ValidationProcess},
    lta::{lta_validation_with_ades_options, lta_validation_with_options, LtaOptions},
    validate_pdf_ades, validate_pdf_ades_with_options,
    with_time::{with_time_validation, with_time_validation_with_options},
    AdesLevel, AdesValidationOptions,
};
use sigis_pades_sign::{sign_general_data, PdfSignatureMetadata, PdfSigner, SimpleSigner};
use sigis_pdf::{PdfFile, SignatureKind};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{
    algorithms::DigestAlgorithm, cert::Cert, key_usage::KeyUsageConstraints, sign::KeySigner,
};
use std::{collections::BTreeSet, sync::Arc};

const TIME: &str = "2020-11-20T00:00:00Z";
const CONTENT: &[u8] = b"AdES exact opt-in MAIN profile: actual native signature bytes";
fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}
fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn exact(policy: KeyUsageConstraints) -> AdesValidationOptions {
    let mut options = AdesValidationOptions::default();
    options.exact_key_usage_settings = Some(policy);
    options
}
fn read(path: &std::path::Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    eprintln!(
        "ADES_EXACT_INPUT {}",
        serde_json::json!({"path":path.canonicalize().unwrap(),"length":bytes.len(),"sha256":sha(&bytes)})
    );
    bytes
}
fn ds_signer() -> SimpleSigner {
    // Existing accepted CMS fixture stays read-only; its exact certificate is
    // genuinely reissued with the same key/serial and a signed DS-only KU.
    let pki = support::pki("testing-ca");
    let bytes = read(&support::data_path(&[
        "lanes",
        "r3-v",
        "cms-exact-main",
        "digital-signature-only.der",
    ]));
    assert_eq!(
        sha(&bytes),
        "5053f3bcc821e7d82527b4f73247c34c36f5caef955945a3e8cf915f8dc0895c"
    );
    let leaf = Cert::from_der(&bytes).unwrap();
    assert_eq!(
        sigis_pki_core::key_usage::cert_key_usages(&leaf),
        Some(names(&["digital_signature"]))
    );
    assert_eq!(leaf.public_key(), pki.cert("signer1").public_key());
    SimpleSigner::new(
        pki.key(&pki.key_label_of("signer1")),
        leaf,
        vec![pki.cert("root"), pki.cert("interm")],
    )
    .unwrap()
}
fn ctx(roots: bool, required: bool, evidence: bool) -> ValidationContext {
    let pki = support::pki("testing-ca");
    let mut b = ValidationContext::builder()
        .moment(support::at(TIME))
        .point_in_time_validation(false)
        .revocation_mode(if required { "require" } else { "none" });
    if roots {
        b = b.trust_root(pki.cert("root"));
    }
    if evidence {
        // Explicit immutable signed evidence for these full-chain profile
        // tests. The original OCSP issuer+serial binds the reissued leaf too;
        // nothing substitutes the target certificate at validation time.
        for name in ["crl-root.der", "crl-interm.der"] {
            b = b.crl(read(&support::data_path(&[
                "lanes",
                "d",
                "revinfo",
                "testing-ca",
                "2020-11-20",
                name,
            ])));
        }
        b = b.ocsp_response(read(&support::data_path(&[
            "lanes",
            "d",
            "revinfo",
            "testing-ca",
            "2020-11-20",
            "ocsp-signer1.der",
        ])));
    }
    b.build().unwrap()
}
fn cms(signer: &dyn KeySigner, tsa: Option<&str>) -> Vec<u8> {
    let pki = support::pki("testing-ca");
    let ts = tsa.map(|label| pki.tsa(label, support::at(TIME)));
    let output = sign_general_data(
        CONTENT,
        signer,
        DigestAlgorithm::Sha256,
        true,
        ts.as_ref()
            .map(|t| t as &dyn sigis_pki_core::sign::TimeStamper),
    )
    .unwrap();
    persist_producer(&output, "cms.der");
    output
}
fn persist_producer(bytes: &[u8], kind: &str) {
    let Some(dir) = std::env::var_os("HANKO_ADES_EXACT_OUTPUT_DIR") else {
        return;
    };
    let path = std::path::PathBuf::from(dir).join("producer");
    std::fs::create_dir_all(&path).unwrap();
    let path = path.join(format!("{}.{}", sha(bytes), kind));
    std::fs::write(&path, bytes).unwrap();
    eprintln!(
        "ADES_EXACT_PRODUCER {}",
        serde_json::json!({"path":path,"length":bytes.len(),"sha256":sha(bytes),"kind":kind})
    );
}
fn export(
    input: &[u8],
    kind_and_entry: (&str, &str),
    options: &AdesValidationOptions,
    context: &ValidationContext,
    sub: &str,
    status: &sigis_cms::StandardCmsSignatureStatus,
    best: Option<sigis_pki_core::time::Moment>,
) {
    let (kind, entry) = kind_and_entry;
    let Some(dir) = std::env::var_os("HANKO_ADES_EXACT_OUTPUT_DIR") else {
        return;
    };
    let predicate=options.exact_key_usage_settings.as_ref().map(|p|serde_json::json!({
        "key_usage":p.key_usage,"key_usage_forbidden":p.key_usage_forbidden,"extd_key_usage":p.extd_key_usage,
        "explicit_extd_key_usage_required":p.explicit_extd_key_usage_required,"match_all_key_usages":p.match_all_key_usages}));
    let root = support::pki("testing-ca").cert("root");
    let row = serde_json::json!({"test":std::thread::current().name(),"entry":entry,"kind":kind,
        "input_b64":openssl::base64::encode_block(input),"input_sha256":sha(input),
        "content_b64":openssl::base64::encode_block(CONTENT),"content_sha256":sha(CONTENT),
        "root_b64":openssl::base64::encode_block(root.der()),"root_sha256":sha(root.der()),
        "predicate":predicate,"time":context.moment().to_string(),"point_in_time_validation":context.timing().point_in_time_validation,
        "revinfo_policy":format!("{:?}",context.revinfo_policy()),
        "crls_b64":context.crls().map(openssl::base64::encode_block).collect::<Vec<_>>(),
        "ocsps_b64":context.ocsps().map(openssl::base64::encode_block).collect::<Vec<_>>(),
        "other_certs_b64":context.other_certs().iter().map(|c|openssl::base64::encode_block(c.der())).collect::<Vec<_>>(),"has_roots":!context.trust_anchors().is_empty(),
        "native":{"subindication":sub,"intact":status.signature.intact,"valid":status.signature.valid,
            "trusted":status.signature.trusted(),"api_bottom_line":status.bottom_line(),"best_signature_time":best.map(|t|t.to_string()),
            "signature_time":status.signature.validation_time.map(|t|t.to_string()),"timestamp_trusted":status.timestamp_validity.as_ref().map(|t|t.trusted()),
            "full_status":format!("{status:#?}")}});
    let bytes = serde_json::to_vec_pretty(&row).unwrap();
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.json", sha(&bytes)));
    std::fs::write(&path, &bytes).unwrap();
    eprintln!(
        "ADES_EXACT_NATIVE_OUTPUT {}",
        serde_json::json!({"path":path,"length":bytes.len(),"sha256":sha(&bytes),"input_sha256":sha(input)})
    );
}
fn check_cms(bytes: &[u8], policy: KeyUsageConstraints, expected: bool) {
    let ctx = ctx(true, false, false);
    let before = format!("{ctx:?}");
    let alg = ctx.algorithm_policy_arc();
    let options = exact(policy);
    let digest = DigestAlgorithm::Sha256.digest(CONTENT);
    let qual = QualificationSpec::default();
    let basic = basic_validation_with_options(bytes, Some(&digest), &ctx, &qual, &options).unwrap();
    let timed =
        with_time_validation_with_options(bytes, Some(&digest), &ctx, &qual, None, &options)
            .unwrap();
    for (entry, sub, status, best) in [
        (
            "basic",
            basic.ades_subindic.standard_name(),
            basic.api_status.as_ref().unwrap(),
            None,
        ),
        (
            "with_time",
            timed.ades_subindic.standard_name(),
            timed.api_status.as_ref().unwrap(),
            timed.best_signature_time,
        ),
    ] {
        assert!(
            status.signature.intact && status.signature.valid,
            "{entry}: {status:?}"
        );
        assert_eq!(
            status.signature.trusted(),
            expected,
            "{entry} {options:?}: {status:?}"
        );
        let expected_sub = if !expected {
            "CHAIN_CONSTRAINTS_FAILURE"
        } else if entry == "with_time" && status.timestamp_validity.is_none() {
            // Existing WithTime requires a signature timestamp independently
            // of whether the exact MAIN predicate succeeds.
            "SIG_CONSTRAINTS_FAILURE"
        } else {
            "OK"
        };
        assert_eq!(sub, expected_sub);
        if let Some(ts) = &status.timestamp_validity {
            assert!(ts.trusted(), "MAIN must not alter actual TSA usage");
        }
        export(bytes, ("cms", entry), &options, &ctx, sub, status, best);
    }
    assert_eq!(format!("{ctx:?}"), before);
    assert!(Arc::ptr_eq(&alg, &ctx.algorithm_policy_arc()));
    assert!(ctx.other_certs().is_empty());
}

#[test]
fn genuine_native_cms_all_five_fields_reach_basic_and_with_time() {
    let pki = support::pki("testing-ca");
    let ds = cms(&ds_signer(), Some("tsa"));
    // A DS-only signer distinguishes preserved legacy NR defaults from a
    // silently unrestricted default. Equality on an NR signer alone cannot.
    let context = ctx(true, false, false);
    let qual = QualificationSpec::default();
    let digest = DigestAlgorithm::Sha256.digest(CONTENT);
    let old_basic = basic_validation(&ds, Some(&digest), &context, &qual).unwrap();
    let old_time = with_time_validation(&ds, Some(&digest), &context, &qual, None).unwrap();
    assert_eq!(
        old_basic.ades_subindic.standard_name(),
        "CHAIN_CONSTRAINTS_FAILURE"
    );
    assert_eq!(
        old_time.ades_subindic.standard_name(),
        "CHAIN_CONSTRAINTS_FAILURE"
    );
    let mut none = AdesValidationOptions::default();
    none.exact_key_usage_settings = None;
    for selected in [AdesValidationOptions::default(), none] {
        let basic =
            basic_validation_with_options(&ds, Some(&digest), &context, &qual, &selected).unwrap();
        let timed =
            with_time_validation_with_options(&ds, Some(&digest), &context, &qual, None, &selected)
                .unwrap();
        assert_eq!(format!("{basic:?}"), format!("{old_basic:?}"));
        assert_eq!(format!("{timed:?}"), format!("{old_time:?}"));
        for result in [
            basic.api_status.as_ref().unwrap(),
            timed.api_status.as_ref().unwrap(),
        ] {
            assert!(result.signature.intact && result.signature.valid);
            assert!(!result.signature.trusted());
        }
    }

    for (policy, accepted) in [
        (KeyUsageConstraints::default(), true),
        (
            KeyUsageConstraints {
                key_usage: Some(BTreeSet::new()),
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature"])),
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation"])),
                ..Default::default()
            },
            false,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature"])),
                key_usage_forbidden: Some(names(&["digital_signature"])),
                ..Default::default()
            },
            false,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature"])),
                key_usage_forbidden: Some(names(&["non_repudiation"])),
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature", "non_repudiation"])),
                match_all_key_usages: false,
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature", "non_repudiation"])),
                match_all_key_usages: true,
                ..Default::default()
            },
            false,
        ),
        (
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["server_auth"])),
                explicit_extd_key_usage_required: false,
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["server_auth"])),
                explicit_extd_key_usage_required: true,
                ..Default::default()
            },
            false,
        ),
    ] {
        check_cms(&ds, policy, accepted);
    }
    let tsa_main = cms(&pki.signer("tsa"), None);
    for (policy, accepted) in [
        (KeyUsageConstraints::default(), true),
        (
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["time_stamping"])),
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["server_auth"])),
                ..Default::default()
            },
            false,
        ),
        (
            KeyUsageConstraints {
                extd_key_usage: Some(BTreeSet::new()),
                ..Default::default()
            },
            false,
        ),
    ] {
        check_cms(&tsa_main, policy, accepted);
    }
}

fn native_pdf(lta: bool, tsa: &str) -> Vec<u8> {
    let pki = support::pki("testing-ca");
    let mut meta = PdfSignatureMetadata::new("ExactSig");
    let signing_context = ctx(true, lta, false);
    let signing_context = if lta {
        // Collect actual configured CRL evidence for the actual DS-only
        // certificate through its distribution points. No target substitute.
        signing_context
            .with_fetchers(support::services::Services::new(&["testing-ca"], TIME).fetchers())
    } else {
        signing_context
    };
    meta.validation_context = Some(Arc::new(signing_context));
    meta.embed_validation_info = lta;
    meta.use_pades_lta = lta;
    let output = PdfSigner::new(meta, Arc::new(ds_signer()))
        .with_signer_key_usage_policy(KeyUsageConstraints::default())
        .at(support::at(TIME))
        .with_timestamper(Arc::new(pki.tsa(tsa, support::at(TIME))))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .unwrap();
    persist_producer(&output, "pdf");
    output
}
#[test]
fn actual_native_pdf_opt_in_report_and_full_lta_keep_the_same_result() {
    for archive in [false, true] {
        let bytes = native_pdf(archive, "tsa");
        let file = PdfFile::parse(&bytes).unwrap();
        let signature = file
            .embedded_signatures()
            .unwrap()
            .into_iter()
            .find(|s| s.kind == SignatureKind::Signature)
            .unwrap();
        let context = ctx(true, archive, false);
        let qual = QualificationSpec::default();
        let before = format!("{context:?}");
        let dispatcher_context = if let Some(dss) = file.dss().unwrap() {
            assert!(
                !dss.material.crls.is_empty(),
                "actual fetch-and-collect must embed revocation evidence"
            );
            let certs = dss
                .material
                .certs
                .iter()
                .map(|d| Cert::from_der(d).unwrap())
                .collect::<Vec<_>>();
            context
                .with_revinfo(
                    &certs,
                    dss.material.crls.iter().map(Vec::as_slice),
                    dss.material.ocsps.iter().map(Vec::as_slice),
                )
                .unwrap()
        } else {
            context.clone()
        };
        let old_lta =
            lta_validation_with_options(&file, &signature, &context, &qual, &LtaOptions::default())
                .unwrap();
        assert_eq!(
            old_lta.ades_subindic.standard_name(),
            "CHAIN_CONSTRAINTS_FAILURE"
        );
        let mut none = AdesValidationOptions::default();
        none.exact_key_usage_settings = None;
        for selected in [AdesValidationOptions::default(), none] {
            let lta = lta_validation_with_ades_options(
                &file,
                &signature,
                &context,
                &qual,
                &LtaOptions::default(),
                &selected,
            )
            .unwrap();
            assert_eq!(format!("{lta:?}"), format!("{old_lta:?}"));
            for level in [
                AdesLevel::Basic,
                AdesLevel::WithTimestamps,
                AdesLevel::LongTerm,
            ] {
                let old = validate_pdf_ades(&file, &signature, level, &dispatcher_context).unwrap();
                let new = validate_pdf_ades_with_options(
                    &file,
                    &signature,
                    level,
                    &dispatcher_context,
                    &selected,
                )
                .unwrap();
                assert_eq!(new, old);
                assert_eq!(new.sub_indication.unwrap().0, "CHAIN_CONSTRAINTS_FAILURE");
            }
        }
        for (policy, allowed) in [
            (KeyUsageConstraints::default(), true),
            (
                KeyUsageConstraints {
                    key_usage: Some(BTreeSet::new()),
                    ..Default::default()
                },
                true,
            ),
            (
                KeyUsageConstraints {
                    key_usage: Some(names(&["digital_signature"])),
                    ..Default::default()
                },
                true,
            ),
            (
                KeyUsageConstraints {
                    key_usage: Some(names(&["non_repudiation"])),
                    ..Default::default()
                },
                false,
            ),
            (
                KeyUsageConstraints {
                    key_usage: Some(names(&["digital_signature"])),
                    key_usage_forbidden: Some(names(&["digital_signature"])),
                    ..Default::default()
                },
                false,
            ),
            (
                KeyUsageConstraints {
                    key_usage: Some(names(&["digital_signature", "non_repudiation"])),
                    match_all_key_usages: true,
                    ..Default::default()
                },
                false,
            ),
        ] {
            let options = exact(policy);
            for level in [AdesLevel::Basic, AdesLevel::WithTimestamps] {
                let r = validate_pdf_ades_with_options(
                    &file,
                    &signature,
                    level,
                    &dispatcher_context,
                    &options,
                )
                .unwrap();
                assert_eq!(r.sub_indication.is_none(), allowed, "{level:?}: {r:?}");
            }
            let r = lta_validation_with_ades_options(
                &file,
                &signature,
                &context,
                &qual,
                &LtaOptions::default(),
                &options,
            )
            .unwrap();
            let status = r.api_status.as_ref().unwrap();
            assert_eq!(status.signature.trusted(), allowed, "{r:#?}");
            if archive && allowed {
                assert_eq!(r.ades_subindic.standard_name(), "OK", "{r:#?}");
                assert!(status.bottom_line());
            }
            if !allowed {
                assert_eq!(r.ades_subindic.standard_name(), "CHAIN_CONSTRAINTS_FAILURE");
            }
            let input = ReportInput::from_pdf(
                &file,
                &signature,
                &ReportValidation {
                    validation_time: context.moment(),
                    best_signature_time: r.best_signature_time,
                    process: ValidationProcess::Lta,
                    subindication: r.ades_subindic,
                    status,
                },
            )
            .unwrap();
            assert_eq!(input.subindication, r.ades_subindic);
            assert_eq!(input.best_signature_time, r.best_signature_time);
            assert_eq!(input.attributes.byte_range, signature.byte_range);
            assert_eq!(
                input.signer_cert,
                status.signature.signing_cert.as_ref().unwrap().der()
            );
            let xml = sigis_pades::ades::etsi_report::generate_report(&input).unwrap();
            assert!(xml.contains(r.ades_subindic.standard_name()));
            export(
                &bytes,
                (
                    "pdf",
                    if archive {
                        "native_lta"
                    } else {
                        "native_no_dss"
                    },
                ),
                &options,
                &context,
                r.ades_subindic.standard_name(),
                status,
                r.best_signature_time,
            );
        }
        assert_eq!(format!("{context:?}"), before);
        assert_eq!(file.dss().unwrap().is_some(), archive);
    }
}

#[test]
fn unrestricted_main_cannot_authorize_wrong_purpose_tsa_or_bad_raw_crypto() {
    let pki = support::pki("testing-ca");
    let options = exact(KeyUsageConstraints::default());
    let context = ctx(true, false, false);
    let qual = QualificationSpec::default();
    for tsa in ["tsa", "signer1"] {
        let good = cms(&ds_signer(), Some(tsa));
        let digest = DigestAlgorithm::Sha256.digest(CONTENT);
        let result = with_time_validation_with_options(
            &good,
            Some(&digest),
            &context,
            &qual,
            None,
            &options,
        )
        .unwrap();
        let status = result.api_status.as_ref().unwrap();
        assert!(status.signature.trusted());
        let basic =
            basic_validation_with_options(&good, Some(&digest), &context, &qual, &options).unwrap();
        let raw = basic
            .api_status
            .as_ref()
            .unwrap()
            .timestamp_validity
            .as_ref()
            .unwrap();
        assert!(raw.signature.intact && raw.signature.valid);
        assert_eq!(raw.trusted(), tsa == "tsa");
        if tsa == "tsa" {
            assert!(status.timestamp_validity.as_ref().unwrap().trusted());
        } else {
            assert!(matches!(
                raw.signature.trust_problem,
                Some(sigis_cms::TrustProblem::KeyUsage(_))
            ));
            assert!(
                status.timestamp_validity.is_none(),
                "WithTime removes the failed token from retained evidence"
            );
            assert_eq!(
                result.ades_subindic.standard_name(),
                "CHAIN_CONSTRAINTS_FAILURE"
            );
        }
        assert_eq!(result.ades_subindic.standard_name() == "OK", tsa == "tsa");
        export(
            &good,
            ("cms", "with_time_tsa_purpose"),
            &options,
            &context,
            result.ades_subindic.standard_name(),
            status,
            result.best_signature_time,
        );
    }
    let good = cms(&pki.signer("signer1"), Some("tsa"));
    let parsed = sigis_cms::SignedData::from_der(&good).unwrap();
    let signature = &parsed.signer_infos[0].signature;
    let starts: Vec<_> = good
        .windows(signature.len())
        .enumerate()
        .filter_map(|(i, w)| (w == signature).then_some(i))
        .collect();
    assert_eq!(starts.len(), 1);
    let mut forged = good.clone();
    forged[starts[0]] ^= 1;
    let digest = DigestAlgorithm::Sha256.digest(CONTENT);
    let raw =
        basic_validation_with_options(&forged, Some(&digest), &context, &qual, &options).unwrap();
    assert_eq!(raw.ades_subindic.standard_name(), "SIG_CRYPTO_FAILURE");
    let raw_status = raw.api_status.as_ref().unwrap();
    assert!(!raw_status.signature.valid);
    assert!(raw_status.signature.intact);
    assert!(!raw_status.bottom_line());
    export(
        &forged,
        ("cms", "basic_signature_mutation"),
        &options,
        &context,
        raw.ades_subindic.standard_name(),
        raw_status,
        None,
    );
    let mut changed_content = CONTENT.to_vec();
    changed_content[0] ^= 1;
    let changed_digest = DigestAlgorithm::Sha256.digest(&changed_content);
    let result =
        basic_validation_with_options(&good, Some(&changed_digest), &context, &qual, &options)
            .unwrap();
    assert_eq!(result.ades_subindic.standard_name(), "HASH_FAILURE");
}
