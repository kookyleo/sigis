//! Complete historical preliminary MAIN validation, distinct from final LTA proof.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use sigis_eutl::{
    parse,
    tsp::{Authority, TspRegistry},
};
use sigis_pades::ades::{
    basic::QualificationSpec,
    lta::{lta_validation_with_ades_options, LtaOptions},
    AdesValidationOptions,
};
use sigis_pdf::{PdfFile, SignatureKind};
use sigis_pki_certvalidator::{
    authority::{TrustManager, TrustQualifiers, TrustedServiceType},
    CertRevTrustPolicy, TrustAnchor, ValidationContext, NO_REVOCATION, REQUIRE_REVINFO,
};
use sigis_pki_core::{cert::Cert, key_usage::KeyUsageConstraints, time::Moment};
use std::sync::Arc;

fn at(s: &str) -> Moment {
    Moment::parse_rfc3339(s).unwrap()
}
fn data() -> std::path::PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "qualified-ades", "case-10"])
}
fn registry() -> Arc<TspRegistry> {
    let p = data();
    let cache = p.join("cache/eutl");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cache.join("index.json")).unwrap()).unwrap();
    let read = |url: &str| {
        std::fs::read_to_string(cache.join(index[url]["fname"].as_str().unwrap())).unwrap()
    };
    let observation = Moment::from_unix_secs(
        std::fs::read_to_string(p.join("moment.txt"))
            .unwrap()
            .trim()
            .parse()
            .unwrap(),
    );
    let tlso = Cert::from_pem_or_der(&std::fs::read(p.join("tlso.cert.pem")).unwrap()).unwrap();
    let lotl = parse::validate_and_parse_lotl(
        &read("http://pyhanko.tests/testing-ca-qualified/lotl.xml"),
        Some(&[tlso]),
        Some(observation),
    )
    .unwrap();
    assert!(lotl.errors.is_empty());
    let reference = lotl
        .references
        .iter()
        .find(|r| r.location_uri.ends_with("/tl/root.xml"))
        .unwrap();
    let (registry, errors) = parse::trust_list_to_registry(
        &read(&reference.location_uri),
        &reference.tlso_certs,
        None,
        Some(observation),
    )
    .unwrap();
    assert!(errors.is_empty());
    Arc::new(registry)
}
#[derive(Debug)]
struct Stale;
impl sigis_pki_certvalidator::revinfo::freshness::FreshnessJudge for Stale {
    fn judge(
        &self,
        _: Option<Moment>,
        _: Option<Moment>,
        _: &CertRevTrustPolicy,
        _: &sigis_pki_certvalidator::policy::ValidationTimingParams,
    ) -> sigis_pki_certvalidator::revinfo::freshness::RevinfoUsability {
        use sigis_pki_certvalidator::revinfo::freshness::*;
        RevinfoUsability {
            rating: RevinfoUsabilityRating::Stale,
            last_usable_at: None,
            compared_to: None,
        }
    }
}
#[derive(Debug)]
struct Registry(Arc<TspRegistry>);
impl TrustManager for Registry {
    fn as_trust_anchor(&self, cert: &Cert) -> Option<TrustAnchor> {
        let definitions = self
            .0
            .applicable_service_definitions(&Authority::of_cert(cert), None);
        if !definitions.iter().any(|s| {
            s.base_info
                .provider_certs
                .iter()
                .any(|c| c.der() == cert.der())
        }) {
            return None;
        }
        let sd = definitions.first()?;
        Some(TrustAnchor::with_qualifiers(
            cert.clone(),
            TrustQualifiers {
                valid_from: Some(sd.base_info.valid_from),
                valid_until: sd.base_info.valid_until,
                trusted_service_type: if sd.is_ca() {
                    TrustedServiceType::CertificateAuthority
                } else {
                    TrustedServiceType::TimeStampingAuthority
                },
                ..Default::default()
            },
        ))
    }
    fn find_potential_issuers(&self, cert: &Cert) -> Vec<TrustAnchor> {
        self.0
            .known_certificate_authorities()
            .into_iter()
            .filter(|a| a.is_potential_issuer_of(cert))
            .flat_map(|a| self.0.applicable_service_definitions(a, None))
            .filter(|s| s.is_ca())
            .flat_map(|s| &s.base_info.provider_certs)
            .filter_map(|c| self.as_trust_anchor(c))
            .collect()
    }
}
fn run(
    usage: KeyUsageConstraints,
    roots: bool,
    revinfo: bool,
) -> sigis_pades::ades::lta::LtaValidationResult {
    run_controlled(usage, roots, revinfo, "normal")
}
#[derive(Debug)]
struct CurrentDigestDenial;
impl sigis_pki_core::algorithms::AlgorithmUsagePolicy for CurrentDigestDenial {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &const_oid::ObjectIdentifier,
        moment: Option<Moment>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        let denied = algorithm.to_string() == "2.16.840.1.101.3.4.2.2"
            && moment.is_some_and(|t| t >= at("2024-01-01T00:00:00Z"));
        sigis_pki_core::algorithms::AlgorithmUsageConstraint {
            allowed: !denied,
            failure_reason: denied.then(|| "current digest refusal".into()),
            not_allowed_after: denied.then(|| at("2024-01-01T00:00:00Z")),
        }
    }
    fn signature_algorithm_allowed(
        &self,
        _: &spki::AlgorithmIdentifierOwned,
        _: Option<Moment>,
        _: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> sigis_pki_core::algorithms::AlgorithmUsageConstraint {
        sigis_pki_core::algorithms::AlgorithmUsageConstraint::allowed()
    }
}
fn run_controlled(
    usage: KeyUsageConstraints,
    roots: bool,
    revinfo: bool,
    control: &str,
) -> sigis_pades::ades::lta::LtaValidationResult {
    let registry = registry();
    let mut builder = ValidationContext::builder()
        .moment(at("2025-03-01T22:00:00Z"))
        .point_in_time_validation(true)
        .revinfo_policy(CertRevTrustPolicy::new(if revinfo {
            REQUIRE_REVINFO
        } else {
            NO_REVOCATION
        }));
    if control == "denied_algorithm" {
        builder = builder.algorithm_policy(Arc::new(CurrentDigestDenial));
    }
    if revinfo {
        builder = builder.freshness_judge(Arc::new(Stale));
    }
    if roots {
        builder = builder.trust_manager(Arc::new(Registry(registry.clone())));
    }
    let ctx = builder.build().unwrap();
    let before = format!("{ctx:?}");
    let mut bytes = std::fs::read(data().join("to-validate.pdf")).unwrap();
    if matches!(control, "corrupt_document_tst" | "bad_main_signature") {
        let parsed = PdfFile::parse(&bytes).unwrap();
        let selected_kind = if control == "corrupt_document_tst" {
            SignatureKind::DocTimeStamp
        } else {
            SignatureKind::Signature
        };
        let selected = parsed
            .embedded_signatures()
            .unwrap()
            .into_iter()
            .find(|s| s.kind == selected_kind)
            .unwrap();
        let sd = sigis_cms::SignedData::from_der(&selected.contents).unwrap();
        let value = &sigis_cms::signed_data::extract_signer_info(&sd)
            .unwrap()
            .signature;
        let pattern = value.iter().map(|b| format!("{b:02X}")).collect::<String>();
        let positions = bytes
            .windows(pattern.len())
            .enumerate()
            .filter_map(|(i, w)| w.eq_ignore_ascii_case(pattern.as_bytes()).then_some(i))
            .collect::<Vec<_>>();
        assert_eq!(positions.len(), 1);
        let last = positions[0] + pattern.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
    }
    let file = PdfFile::parse(&bytes).unwrap();
    let sig = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.kind == SignatureKind::Signature)
        .unwrap();
    let mut qualification = QualificationSpec {
        registry: Some(&registry),
        ..Default::default()
    };
    if control == "wrong_tsa_qualification" {
        qualification.ts_requirements = Some(sigis_eutl::assess::QualificationRequirements {
            require_service_type: Some(sigis_eutl::assess::RequiredServiceType::Uri(
                sigis_eutl::tsp::CA_QC_URI.into(),
            )),
            ..Default::default()
        });
    }
    if control == "wrong_signer_qualification" {
        qualification.requirements = Some(sigis_eutl::assess::QualificationRequirements {
            permit_cert_types: Some([sigis_eutl::tsp::QcCertType::QcEseal].into_iter().collect()),
            ..Default::default()
        });
    }
    let mut options = AdesValidationOptions::default();
    options.exact_key_usage_settings = Some(usage);
    let result = lta_validation_with_ades_options(
        &file,
        &sig,
        &ctx,
        &qualification,
        &LtaOptions::default(),
        &options,
    )
    .unwrap();
    assert_eq!(
        format!("{ctx:?}"),
        before,
        "original caller context is unchanged"
    );
    let status = result.api_status.as_ref().unwrap();
    if let Some(path) = &status.signature.validation_path {
        for cert in path.certs() {
            eprintln!(
                "certificate validity {}..{}; actual POE {:?}",
                cert.not_before(),
                cert.not_after(),
                result.poe.get(cert.der())
            );
        }
    }
    eprintln!(
        "final={} best={:?} trusted={} time={:?} failure={:?}",
        result.ades_subindic.standard_name(),
        result.best_signature_time,
        status.signature.trusted(),
        status.signature.validation_time,
        result.failure_msg
    );
    result
}
#[test]
fn no_revinfo_past_failure_retains_a_fully_checked_qualified_preliminary_main() {
    let result = run(KeyUsageConstraints::default(), true, false);
    assert_eq!(
        result.ades_subindic.standard_name(),
        "NO_POE",
        "archival proof still fails"
    );
    assert!(result
        .failure_msg
        .as_deref()
        .unwrap()
        .contains("control time"));
    let status = result.api_status.unwrap();
    assert!(status.signature.intact && status.signature.valid);
    let timestamp = status.timestamp_validity.unwrap();
    assert!(timestamp.trusted());
    assert_eq!(
        timestamp.signature.validation_time,
        Some(at("2025-03-01T22:00:00Z")),
        "do not retime TSA"
    );
    assert_eq!(result.best_signature_time, Some(at("2020-08-01T07:00:00Z")));
    assert!(
        status.signature.trusted(),
        "MAIN must actually pass full historical validation"
    );
    assert!(
        status
            .signature
            .validation_path
            .as_ref()
            .unwrap()
            .certs()
            .into_iter()
            .skip(1)
            .all(|cert| result
                .poe
                .get(cert.der())
                .is_some_and(|(time, _)| Some(time) <= result.best_signature_time)),
        "each historical MAIN certificate has actual authenticated POE"
    );
    assert_eq!(status.signature.validation_time, result.best_signature_time);
    let qualification = result.qualification.unwrap();
    assert!(qualification.status.qualified);
    assert_eq!(
        qualification.status.qc_type,
        sigis_eutl::tsp::QcCertType::QcEsign
    );
}
#[test]
fn historical_preliminary_never_waives_roots_required_revinfo_or_main_predicates() {
    let forbidden = KeyUsageConstraints {
        key_usage_forbidden: Some(["non_repudiation".into()].into_iter().collect()),
        ..Default::default()
    };
    let wrong_eku = KeyUsageConstraints {
        extd_key_usage: Some(["email_protection".into()].into_iter().collect()),
        ..Default::default()
    };
    for (usage, roots, revinfo) in [
        (KeyUsageConstraints::default(), false, false),
        (KeyUsageConstraints::default(), true, true),
        (forbidden, true, false),
        (wrong_eku, true, false),
    ] {
        let result = run(usage, roots, revinfo);
        assert!(!result.api_status.unwrap().signature.trusted());
        assert!(result.qualification.is_none());
    }
}

#[test]
fn corrupt_material_poe_and_bad_main_crypto_cannot_supply_historical_trust() {
    for control in ["corrupt_document_tst", "bad_main_signature"] {
        let result = run_controlled(KeyUsageConstraints::default(), true, false, control);
        assert!(
            !result.api_status.as_ref().unwrap().signature.trusted(),
            "{control}"
        );
        assert!(result.qualification.is_none());
        if control == "corrupt_document_tst" {
            let path = result
                .api_status
                .as_ref()
                .unwrap()
                .signature
                .validation_path
                .as_ref()
                .unwrap();
            assert!(
                path.certs()
                    .into_iter()
                    .skip(1)
                    .all(|cert| result.poe.get(cert.der()).is_none()),
                "invalid DocTS loses certificate POEs"
            );
        }
    }
}
#[test]
fn historical_payload_preserves_current_crypto_and_both_qualification_requirements() {
    for control in [
        "denied_algorithm",
        "wrong_tsa_qualification",
        "wrong_signer_qualification",
    ] {
        let result = run_controlled(KeyUsageConstraints::default(), true, false, control);
        assert!(
            !result.api_status.as_ref().unwrap().signature.trusted(),
            "{control}"
        );
        assert!(result.qualification.is_none());
    }
}

// S364f61b9: the same direct producer call, without CLI or EUTL setup.
#[test]
fn expired_leaf_lta_api_status_direct_reproducer() {
    use sigis_cms::signed_data::{extract_certificate_info, find_unique_cms_attribute};
    use sigis_pades::ades::{
        basic::QualificationSpec,
        lta::{lta_validation_with_ades_options, LtaOptions},
        AdesValidationOptions,
    };
    use sigis_pki_certvalidator::{
        policy::{CertRevTrustPolicy, NO_REVOCATION},
        ValidationContext,
    };
    use sigis_pki_core::{asn1::oids, cert::Cert, key_usage::KeyUsageConstraints};

    let directory = sigis_testdata::path(&["lanes", "r3-c", "qualified-ades", "case-10"]);
    let file =
        sigis_pdf::PdfFile::parse(&std::fs::read(directory.join("to-validate.pdf")).unwrap())
            .unwrap();
    let signature = file.embedded_signatures().unwrap().remove(0);
    let cms = sigis_cms::SignedData::from_der(
        sigis_pades::cms_from_contents(&signature.contents).unwrap(),
    )
    .unwrap();
    let token = find_unique_cms_attribute(
        cms.signer_infos[0].unsigned_attr_list(),
        oids::AA_SIGNATURE_TIME_STAMP_TOKEN,
    )
    .unwrap();
    let tsa = extract_certificate_info(&sigis_cms::SignedData::from_der(token).unwrap())
        .unwrap()
        .signer_cert;
    let ca =
        Cert::from_pem_or_der(&std::fs::read(directory.join("root.cert.pem")).unwrap()).unwrap();
    let context = ValidationContext::builder()
        .trust_root(ca)
        .trust_root(tsa)
        .moment(Moment::parse_rfc3339("2025-03-01T22:00:00Z").unwrap())
        .point_in_time_validation(true)
        .revinfo_policy(CertRevTrustPolicy::new(NO_REVOCATION))
        .build()
        .unwrap();
    let mut options = AdesValidationOptions::default();
    options.exact_key_usage_settings = Some(KeyUsageConstraints::default());
    let result = lta_validation_with_ades_options(
        &file,
        &signature,
        &context,
        &QualificationSpec::default(),
        &LtaOptions::default(),
        &options,
    )
    .unwrap();
    let status = result.api_status.as_ref().unwrap();
    assert!(status.signature.intact && status.signature.valid);
    assert!(status.timestamp_validity.as_ref().unwrap().trusted());
    assert!(
        status.bottom_line(),
        "sub={:?}; MAIN={:?}; typed_error={:?}; best={:?}; diagnostic={:?}",
        result.ades_subindic,
        status.signature.trust_problem_indic,
        status.signature.trust_problem,
        result.best_signature_time,
        result.failure_msg
    );
    assert_eq!(result.ades_subindic.standard_name(), "NO_POE");
    assert_eq!(result.best_signature_time, Some(at("2020-08-01T07:00:00Z")));
    assert_eq!(status.signature.validation_time, result.best_signature_time);
    assert_eq!(
        status
            .timestamp_validity
            .as_ref()
            .unwrap()
            .signature
            .validation_time,
        Some(at("2025-03-01T22:00:00Z"))
    );
    assert!(
        result.qualification.is_none(),
        "explicit anchors do not manufacture qualification"
    );
}
