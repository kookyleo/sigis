//! Signed Adobe RIA local evidence: supplemental S/CMS caller hardening.
//! The original function remains S-owned; these helpers earn no V function.
use sigis_cms::{SignedContent, SignedData};
use sigis_pades::ades::adobe_revinfo::with_signed_adobe_revinfo;
use sigis_pades::ades::{
    basic::QualificationSpec,
    lta::{lta_validation_with_options, LtaOptions, LtaValidationResult},
};
use sigis_pdf::PdfFile;
use sigis_pki_certvalidator::{CertRevTrustPolicy, ValidationContext, REQUIRE_REVINFO};
use sigis_pki_core::{
    algorithms::DigestAlgorithm,
    asn1::{oids, tlv::Tlv},
    cert::Cert,
    time::Moment,
};
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/data/lanes/r3-v/adobe-ria")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let (manifest_bytes, manifest_pin): (&[u8], &str) = if name.starts_with("additional/") {
        (
            include_bytes!("../../testdata/data/lanes/r3-v/adobe-ria/additional-oracle.json"),
            "84b7651c24d793234efb02c6b1632ba0fc4c51e650d208449fd45ddae39ca176",
        )
    } else {
        (
            include_bytes!("../../testdata/data/lanes/r3-v/adobe-ria/oracle.json"),
            "78597d5466c2a6f59a37fbc9c786d71e41a5cca4321ab10bd16b394d704e2ed5",
        )
    };
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(&DigestAlgorithm::Sha256.digest(manifest_bytes)),
        manifest_pin
    );
    let manifest: serde_json::Value = serde_json::from_slice(manifest_bytes).unwrap();
    let expected = &manifest["files"][name];
    assert_eq!(expected["length"].as_u64().unwrap(), bytes.len() as u64);
    assert_eq!(
        expected["sha256"].as_str().unwrap(),
        hex(&DigestAlgorithm::Sha256.digest(&bytes))
    );
    println!(
        "V_RIA_INPUT {}",
        serde_json::json!({
            "path": path.canonicalize().unwrap(), "length": bytes.len(),
            "sha256": DigestAlgorithm::Sha256.digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()
        })
    );
    bytes
}
fn context(ac: bool) -> ValidationContext {
    ValidationContext::builder()
        .trust_root(Cert::from_der(&fixture(if ac { "root-aa.der" } else { "root.der" })).unwrap())
        .moment(Moment::parse_rfc3339("2020-11-01T00:00:00Z").unwrap())
        .revinfo_policy(CertRevTrustPolicy::new(REQUIRE_REVINFO))
        .build()
        .unwrap()
}
fn lta(case: &str) -> sigis_pki_core::errors::Result<LtaValidationResult> {
    let bytes = fixture(&format!("cases/{case}.pdf"));
    let file = PdfFile::parse(&bytes).unwrap();
    assert!(file.dss().unwrap().is_none(), "RIA must work without a DSS");
    let signatures = file.embedded_signatures().unwrap();
    let ctx = context(false);
    let ac = context(true);
    assert!(ctx.fetchers().ocsp.is_none() && ctx.fetchers().crl.is_none());
    assert!(ac.fetchers().ocsp.is_none() && ac.fetchers().crl.is_none());
    assert_eq!(ctx.crls().count() + ctx.ocsps().count(), 0);
    assert_eq!(ac.crls().count() + ac.ocsps().count(), 0);
    lta_validation_with_options(
        &file,
        &signatures[0],
        &ctx,
        &QualificationSpec::default(),
        &LtaOptions {
            ac_validation_context: Some(&ac),
            ..Default::default()
        },
    )
}
#[test]
fn signed_ria_supplies_both_required_contexts_without_dss_or_fetchers() {
    let bytes = fixture("cases/good.pdf");
    let file = PdfFile::parse(&bytes).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    let sd = SignedData::from_der(&signatures[0].contents).unwrap();
    assert_eq!(sd.certificates.len(), 6, "five other PKCs and signer");
    assert_eq!(sd.attribute_certificates.len(), 1);
    sigis_cms::signed_data::find_unique_cms_attribute(
        sd.signer_infos[0].signed_attr_list(),
        oids::ADBE_REVOCATION_INFO_ARCHIVAL,
    )
    .unwrap();
    let result = lta("good").unwrap();
    assert_eq!(
        result.ades_subindic.standard_name(),
        "OK",
        "{:?}",
        result.failure_msg
    );
    let status = result.api_status.unwrap();
    assert!(status.bottom_line());
    let attrs = status.ac_attrs.unwrap();
    let role = attrs.get("role").unwrap();
    assert_eq!(role.attr_values.len(), 1);
    let role = Tlv::parse_exact(&role.attr_values[0]).unwrap();
    assert!(role.is_universal(16));
    let fields = role.children().unwrap();
    let names = fields
        .iter()
        .find(|v| v.is_context(1))
        .unwrap()
        .children()
        .unwrap();
    assert_eq!(names.len(), 1);
    assert!(names[0].is_context(1));
    assert_eq!(names[0].value, b"bigboss@example.com");
    assert!(status.ac_validation_errs.as_ref().is_none_or(Vec::is_empty));
}
#[test]
fn missing_ria_cannot_satisfy_require_revinfo() {
    let result = lta("missing").unwrap();
    assert_ne!(result.ades_subindic.standard_name(), "OK");
    assert!(!result.api_status.unwrap().bottom_line());
}
#[test]
fn signed_malformed_ria_rejects() {
    assert!(
        lta("malformed").is_err(),
        "authenticated malformed RIA must not be ignored"
    );
}
#[test]
fn outer_integrity_is_required_before_ria_can_help_validation() {
    for (case, expected) in [
        ("bad-signature", "SIG_CRYPTO_FAILURE"),
        ("tampered-content", "HASH_FAILURE"),
    ] {
        let result = lta(case).unwrap();
        assert_eq!(result.ades_subindic.standard_name(), expected);
        assert!(!result.api_status.unwrap().bottom_line());
    }
}
#[test]
fn forged_ria_revocation_signatures_are_not_authenticated_by_outer_signature() {
    let result = lta("forged-crl").unwrap();
    assert_ne!(result.ades_subindic.standard_name(), "OK");
    let status = result.api_status.unwrap();
    assert!(status.signature.intact && status.signature.valid);
    assert!(!status.bottom_line());
}

#[test]
fn public_adapter_adds_only_evidence_and_preserves_independent_contexts() {
    use sigis_pki_certvalidator::NonRevokedStatusAssertion;
    use std::sync::Arc;
    let content = fixture("good-content.bin");
    let cms = fixture("good.cms.der");
    for ac in [false, true] {
        let base = context(ac);
        let mut timing = *base.timing();
        timing.time_tolerance = std::time::Duration::from_secs(17);
        timing.best_signature_time = Moment::parse_rfc3339("2020-10-31T23:59:00Z").unwrap();
        let base = base.with_timing(timing);
        // A non-matching assertion is retained, never invented by ingestion.
        let assertion = NonRevokedStatusAssertion {
            cert_sha256: [42; 32],
            at: base.moment(),
        };
        let base = ValidationContext::builder()
            .trust_anchor(base.trust_anchors()[0].clone())
            .revinfo_policy(*base.revinfo_policy())
            .algorithm_policy(base.algorithm_policy_arc())
            .assertion(assertion.clone())
            .build()
            .unwrap()
            .with_timing(timing);
        let before_policy = base.algorithm_policy_arc();
        let augmented =
            with_signed_adobe_revinfo(&base, &cms, SignedContent::Data(&content)).unwrap();
        assert_eq!(augmented.crls().count(), 5);
        assert_eq!(augmented.ocsps().count(), 0);
        assert_eq!(base.crls().count(), 0, "source context stays immutable");
        assert_eq!(augmented.trust_anchors().len(), 1);
        assert_eq!(
            augmented.other_certs(),
            base.other_certs(),
            "RIA does not add issuer certificates"
        );
        assert_eq!(augmented.timing(), base.timing());
        assert_eq!(augmented.revinfo_policy(), base.revinfo_policy());
        assert_eq!(augmented.non_revoked_status_assertions(), &[assertion]);
        assert!(Arc::ptr_eq(
            &before_policy,
            &augmented.algorithm_policy_arc()
        ));
        assert!(augmented.fetchers().ocsp.is_none() && augmented.fetchers().crl.is_none());
        assert!(augmented.is_trust_anchor(
            &Cert::from_der(&fixture(if ac { "root-aa.der" } else { "root.der" })).unwrap()
        ));
        assert!(!augmented.is_trust_anchor(
            &Cert::from_der(&fixture(if ac { "root.der" } else { "root-aa.der" })).unwrap()
        ));
        let again =
            with_signed_adobe_revinfo(&augmented, &cms, SignedContent::Data(&content)).unwrap();
        assert_eq!(
            again.crls().collect::<Vec<_>>(),
            augmented.crls().collect::<Vec<_>>()
        );
        let digest = DigestAlgorithm::Sha256.digest(&content);
        let prehashed = with_signed_adobe_revinfo(
            &base,
            &cms,
            SignedContent::Digest(DigestAlgorithm::Sha256, &digest),
        )
        .unwrap();
        assert_eq!(
            prehashed.crls().collect::<Vec<_>>(),
            augmented.crls().collect::<Vec<_>>()
        );
    }
}
#[test]
fn absent_ambiguous_unsigned_or_invalid_ria_cannot_add_local_evidence() {
    for case in [
        "missing",
        "empty",
        "duplicate",
        "unsigned-only",
        "bad-signature",
        "tampered-content",
    ] {
        let bytes = fixture(&format!("cases/{case}.pdf"));
        let file = PdfFile::parse(&bytes).unwrap();
        let sig = file.embedded_signatures().unwrap().remove(0);
        let signed = sig.signed_data(&file).unwrap();
        let augmented =
            with_signed_adobe_revinfo(&context(false), &sig.contents, SignedContent::Data(&signed))
                .unwrap();
        assert_eq!(
            augmented.crls().count() + augmented.ocsps().count(),
            0,
            "{case}"
        );
        let result = lta(case).unwrap();
        assert_ne!(result.ades_subindic.standard_name(), "OK", "{case}");
        assert!(!result.api_status.unwrap().bottom_line());
    }
    let cms = fixture("good.cms.der");
    let wrong = with_signed_adobe_revinfo(
        &context(false),
        &cms,
        SignedContent::Digest(DigestAlgorithm::Sha256, &[0; 32]),
    )
    .unwrap();
    assert_eq!(wrong.crls().count() + wrong.ocsps().count(), 0);
    assert!(with_signed_adobe_revinfo(
        &context(false),
        &cms,
        SignedContent::Digest(DigestAlgorithm::Sha512, &[0; 64])
    )
    .is_err());
}
#[test]
fn signature_timestamp_does_not_create_ria_object_poes() {
    let result = lta("good").unwrap();
    assert_eq!(result.ades_subindic.standard_name(), "OK");
    let status = result.api_status.as_ref().unwrap();
    assert!(status
        .timestamp_validity
        .as_ref()
        .unwrap()
        .signature
        .trusted());
    for index in 0..5 {
        assert!(result
            .poe
            .get(&fixture(&format!("crl-{index}.der")))
            .is_none());
    }
}
#[test]
fn same_frozen_inputs_match_fresh_pinned_oracle_verdicts() {
    let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../testdata/data/lanes/r3-v/adobe-ria/oracle.json"
    ))
    .unwrap();
    for (name, expected) in manifest["cases"].as_object().unwrap() {
        if name == "malformed" {
            assert_eq!(expected["error_type"], "ValueError");
            assert!(lta(name).is_err());
            continue;
        }
        let result = lta(name).unwrap();
        let status = result.api_status.as_ref().unwrap();
        assert_eq!(
            result.ades_subindic.standard_name(),
            expected["subindication"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            status.bottom_line(),
            expected["bottom_line"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            status.signature.intact,
            expected["intact"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            status.signature.valid,
            expected["valid"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            status.signature.trusted(),
            expected["trusted"].as_bool().unwrap(),
            "{name}"
        );
        println!(
            "V_RIA_VERDICT {}",
            serde_json::json!({"case":name,"subindication":result.ades_subindic.standard_name(),"bottom_line":status.bottom_line(),"intact":status.signature.intact,"valid":status.signature.valid,"trusted":status.signature.trusted()})
        );
    }
}

#[test]
fn modifying_signed_ria_bytes_cannot_import_evidence() {
    let mut cms = fixture("good.cms.der");
    let content = fixture("good-content.bin");
    let crl = fixture("crl-0.der");
    let positions = cms
        .windows(crl.len())
        .enumerate()
        .filter_map(|(i, bytes)| (bytes == crl).then_some(i))
        .collect::<Vec<_>>();
    assert_eq!(positions.len(), 1);
    cms[positions[0] + crl.len() - 1] ^= 1;
    let context = context(false);
    let augmented =
        with_signed_adobe_revinfo(&context, &cms, SignedContent::Data(&content)).unwrap();
    assert_eq!(augmented.crls().count() + augmented.ocsps().count(), 0);
    let status =
        sigis_cms::validate_cms_signature(&cms, SignedContent::Data(&content), &augmented).unwrap();
    assert!(status.signature.intact);
    assert!(!status.signature.valid);
    assert!(!status.bottom_line());
}

#[derive(Debug)]
struct DigestBan(Option<Moment>);
impl sigis_pki_core::algorithms::AlgorithmUsagePolicy for DigestBan {
    fn digest_algorithm_allowed(
        &self,
        oid: &const_oid::ObjectIdentifier,
        at: Option<Moment>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, DisallowWeakAlgorithmsPolicy};
        if oid == &oids::SHA256 {
            AlgorithmUsageConstraint {
                allowed: false,
                not_allowed_after: self.0,
                failure_reason: Some("mandatory caller digest denial".into()),
            }
        } else {
            DisallowWeakAlgorithmsPolicy::default().digest_algorithm_allowed(oid, at)
        }
    }
    fn signature_algorithm_allowed(
        &self,
        algorithm: &spki::AlgorithmIdentifierOwned,
        at: Option<Moment>,
        key: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        use sigis_pki_core::algorithms::DisallowWeakAlgorithmsPolicy;
        DisallowWeakAlgorithmsPolicy::default().signature_algorithm_allowed(algorithm, at, key)
    }
}
#[test]
fn ria_cannot_erase_permanent_or_timed_algorithm_requirements() {
    use sigis_cms::TrustProblem;
    use sigis_pki_core::errors::ValidationError;
    use std::sync::Arc;
    let content = fixture("good-content.bin");
    let cms = fixture("good.cms.der");
    let bytes = fixture("cases/good.pdf");
    let file = PdfFile::parse(&bytes).unwrap();
    let signature = file.embedded_signatures().unwrap().remove(0);
    for cutoff in [
        None,
        Some(Moment::parse_rfc3339("2019-12-31T23:59:59Z").unwrap()),
    ] {
        let policy = Arc::new(DigestBan(cutoff));
        let base = ValidationContext::builder()
            .trust_root(Cert::from_der(&fixture("root.der")).unwrap())
            .moment(context(false).moment())
            .revinfo_policy(CertRevTrustPolicy::new(REQUIRE_REVINFO))
            .algorithm_policy(policy.clone())
            .build()
            .unwrap();
        let augmented =
            with_signed_adobe_revinfo(&base, &cms, SignedContent::Data(&content)).unwrap();
        assert_eq!(augmented.crls().count(), 5);
        let status =
            sigis_cms::validate_cms_signature(&cms, SignedContent::Data(&content), &augmented)
                .unwrap();
        assert!(status.signature.intact && status.signature.valid);
        match &status.signature.trust_problem {
            Some(TrustProblem::Path(ValidationError::DisallowedAlgorithm {
                banned_since, ..
            })) => assert_eq!(*banned_since, cutoff),
            other => panic!("lost caller algorithm denial: {other:?}"),
        }
        assert_eq!(status.signature.error_time_horizon, cutoff);
        let expected = if cutoff.is_some() {
            "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"
        } else {
            "CRYPTO_CONSTRAINTS_FAILURE"
        };
        assert_eq!(
            sigis_pades::ades::basic::basic_subindication(&status.signature).standard_name(),
            expected
        );
        let ac = context(true);
        let result = lta_validation_with_options(
            &file,
            &signature,
            &base,
            &QualificationSpec::default(),
            &LtaOptions {
                ac_validation_context: Some(&ac),
                ..Default::default()
            },
        )
        .unwrap();
        assert_ne!(result.ades_subindic.standard_name(), "OK");
        assert!(!result.api_status.unwrap().bottom_line());
        for i in 0..5 {
            assert!(result.poe.get(&fixture(&format!("crl-{i}.der"))).is_none());
        }
    }
}

#[test]
fn full_ocsp_response_ria_authenticates_ac_or_retains_its_crypto_refusal() {
    let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../testdata/data/lanes/r3-v/adobe-ria/additional-oracle.json"
    ))
    .unwrap();
    for (case, role_expected) in [("ocsp-good", true), ("ocsp-forged", false)] {
        let file = PdfFile::parse(&fixture(&format!("additional/{case}.pdf"))).unwrap();
        assert!(file.dss().unwrap().is_none());
        let signature = file.embedded_signatures().unwrap().remove(0);
        let ctx = context(false);
        let ac = context(true);
        let augmented = with_signed_adobe_revinfo(
            &ac,
            &signature.contents,
            SignedContent::Data(&signature.signed_data(&file).unwrap()),
        )
        .unwrap();
        assert_eq!(augmented.crls().count(), 4);
        assert_eq!(augmented.ocsps().count(), 1);
        assert_eq!(
            augmented.ocsps().next().unwrap(),
            fixture(if role_expected {
                "additional/ac-good.ocsp.der"
            } else {
                "additional/ac-forged.ocsp.der"
            })
        );
        let result = lta_validation_with_options(
            &file,
            &signature,
            &ctx,
            &QualificationSpec::default(),
            &LtaOptions {
                ac_validation_context: Some(&ac),
                ..Default::default()
            },
        )
        .unwrap();
        let status = result.api_status.unwrap();
        let expected = &manifest["cases"][case];
        assert_eq!(
            result.ades_subindic.standard_name(),
            expected["subindication"].as_str().unwrap()
        );
        assert_eq!(
            status.bottom_line(),
            expected["bottom_line"].as_bool().unwrap()
        );
        assert!(status.signature.intact && status.signature.valid && status.signature.trusted());
        let roles = status.ac_attrs.as_ref().and_then(|attrs| attrs.get("role"));
        assert_eq!(
            roles.is_some_and(|role| !role.attr_values.is_empty()),
            role_expected
        );
        if !role_expected {
            assert!(
                status
                    .ac_validation_errs
                    .as_ref()
                    .is_some_and(|errors| errors
                        .iter()
                        .any(|error| error.contains("Unable to verify OCSP response signature"))),
                "{:?}",
                status.ac_validation_errs
            );
        } else {
            assert_eq!(roles.unwrap().attr_values.len(), 1);
            assert!(status.ac_validation_errs.as_ref().is_none_or(Vec::is_empty));
        }
        println!(
            "V_RIA_AC_VERDICT {}",
            serde_json::json!({"case":case,"main_subindication":result.ades_subindic.standard_name(),"main_bottom_line":status.bottom_line(),"certified_role":role_expected,"ac_errors":status.ac_validation_errs})
        );
    }
}
#[test]
fn later_document_timestamp_proves_ria_atoms_atomically() {
    use sigis_pki_certvalidator::ltv::poe::{PoeManager, PoeType};
    let later = Moment::parse_rfc3339("2020-11-02T00:00:00Z").unwrap();
    let provided = Moment::parse_rfc3339("2020-10-31T23:00:00Z").unwrap();
    for (case, has_proof) in [("enclosing-good", true), ("enclosing-bad", false)] {
        let file = PdfFile::parse(&fixture(&format!("additional/{case}.pdf"))).unwrap();
        assert!(file.dss().unwrap().is_none());
        let signatures = file.embedded_signatures().unwrap();
        assert_eq!(signatures.len(), 2);
        let mut timing = *context(false).timing();
        timing.validation_time = later;
        timing.best_signature_time = later;
        let ctx = context(false).with_timing(timing);
        let ac = context(true).with_timing(timing);
        let mut known = PoeManager::with_current_time(later);
        known.register(b"independent caller knowledge", provided, PoeType::Provided);
        let result = lta_validation_with_options(
            &file,
            &signatures[0],
            &ctx,
            &QualificationSpec::default(),
            &LtaOptions {
                ac_validation_context: Some(&ac),
                known_poes: Some(&known),
            },
        )
        .unwrap();
        assert_eq!(
            result.poe.get(b"independent caller knowledge"),
            Some((provided, PoeType::Provided))
        );
        assert_eq!(known.iter().count(), 1, "caller POEs stay immutable");
        let mut observed = Vec::new();
        for i in 0..5 {
            let crl = fixture(&format!("crl-{i}.der"));
            let proof = result.poe.get(&crl);
            assert_eq!(
                proof,
                has_proof.then_some((later, PoeType::Timestamp)),
                "{case},crl{i}"
            );
            observed.push(proof.map(|(at, _)| at.to_string()));
        }
        assert_eq!(
            result.ades_subindic.standard_name(),
            "OK",
            "current valid main CMS may survive a failed evidence record"
        );
        assert!(result.api_status.unwrap().bottom_line());
        println!(
            "V_RIA_POE_VERDICT {}",
            serde_json::json!({"case":case,"ria_crl_poes":observed,"expected_proof":has_proof,"provided_poe_preserved":true})
        );
    }
}
