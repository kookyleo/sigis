//! Complete historical preliminary MAIN validation, distinct from final LTA proof.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::sync::Arc;
use sigis_eutl::{parse, tsp::{Authority, TspRegistry}};
use sigis_pades::ades::{
    basic::QualificationSpec,
    lta::{lta_validation_with_ades_options, LtaOptions},
    AdesValidationOptions,
};
use sigis_pki_certvalidator::{
    authority::{TrustManager, TrustQualifiers, TrustedServiceType},
    CertRevTrustPolicy, TrustAnchor, ValidationContext, NO_REVOCATION, REQUIRE_REVINFO,
};
use sigis_pki_core::{cert::Cert, key_usage::KeyUsageConstraints, time::Moment};
use sigis_pdf::{PdfFile, SignatureKind};

fn at(s: &str) -> Moment { Moment::parse_rfc3339(s).unwrap() }
fn data() -> std::path::PathBuf {
    sigis_testdata::path(&["lanes", "r3-c", "qualified-ades", "case-10"])
}
fn registry() -> Arc<TspRegistry> {
    let p = data();
    let cache = p.join("cache/eutl");
    let index: serde_json::Value = serde_json::from_slice(&std::fs::read(cache.join("index.json")).unwrap()).unwrap();
    let read = |url: &str| std::fs::read_to_string(cache.join(index[url]["fname"].as_str().unwrap())).unwrap();
    let observation = Moment::from_unix_secs(std::fs::read_to_string(p.join("moment.txt")).unwrap().trim().parse().unwrap());
    let tlso = Cert::from_pem_or_der(&std::fs::read(p.join("tlso.cert.pem")).unwrap()).unwrap();
    let lotl = parse::validate_and_parse_lotl(&read("http://pyhanko.tests/testing-ca-qualified/lotl.xml"), Some(&[tlso]), Some(observation)).unwrap();
    assert!(lotl.errors.is_empty());
    let reference = lotl.references.iter().find(|r| r.location_uri.ends_with("/tl/root.xml")).unwrap();
    let (registry, errors) = parse::trust_list_to_registry(&read(&reference.location_uri), &reference.tlso_certs, None, Some(observation)).unwrap();
    assert!(errors.is_empty());
    Arc::new(registry)
}
#[derive(Debug)]
struct Registry(Arc<TspRegistry>);
impl TrustManager for Registry {
    fn as_trust_anchor(&self, cert: &Cert) -> Option<TrustAnchor> {
        let definitions = self.0.applicable_service_definitions(&Authority::of_cert(cert), None);
        if !definitions.iter().any(|s| s.base_info.provider_certs.iter().any(|c| c.der() == cert.der())) { return None; }
        let sd = definitions.first()?;
        Some(TrustAnchor::with_qualifiers(cert.clone(), TrustQualifiers {
            valid_from: Some(sd.base_info.valid_from), valid_until: sd.base_info.valid_until,
            trusted_service_type: if sd.is_ca() { TrustedServiceType::CertificateAuthority } else { TrustedServiceType::TimeStampingAuthority },
            ..Default::default()
        }))
    }
    fn find_potential_issuers(&self, cert: &Cert) -> Vec<TrustAnchor> {
        self.0.known_certificate_authorities().into_iter()
            .filter(|a| a.is_potential_issuer_of(cert))
            .flat_map(|a| self.0.applicable_service_definitions(a, None))
            .filter(|s| s.is_ca()).flat_map(|s| &s.base_info.provider_certs)
            .filter_map(|c| self.as_trust_anchor(c)).collect()
    }
}
fn run(usage: KeyUsageConstraints, roots: bool, revinfo: bool) -> sigis_pades::ades::lta::LtaValidationResult {
    let registry = registry();
    let mut builder = ValidationContext::builder()
        .moment(at("2025-03-01T22:00:00Z"))
        .point_in_time_validation(true)
        .revinfo_policy(CertRevTrustPolicy::new(if revinfo { REQUIRE_REVINFO } else { NO_REVOCATION }));
    if roots { builder = builder.trust_manager(Arc::new(Registry(registry.clone()))); }
    let ctx = builder.build().unwrap();
    let before = format!("{ctx:?}");
    let file = PdfFile::parse(&std::fs::read(data().join("to-validate.pdf")).unwrap()).unwrap();
    let sig = file.embedded_signatures().unwrap().into_iter().find(|s| s.kind == SignatureKind::Signature).unwrap();
    let qualification = QualificationSpec { registry: Some(&registry), ..Default::default() };
    let mut options = AdesValidationOptions::default();
    options.exact_key_usage_settings = Some(usage);
    let result = lta_validation_with_ades_options(&file, &sig, &ctx, &qualification, &LtaOptions::default(), &options).unwrap();
    assert_eq!(format!("{ctx:?}"), before, "original caller context is unchanged");
    let status = result.api_status.as_ref().unwrap();
    if let Some(path) = &status.signature.validation_path {
        for cert in path.certs() { eprintln!("certificate validity {}..{}; actual POE {:?}", cert.not_before(), cert.not_after(), result.poe.get(cert.der())); }
    }
    eprintln!("final={} best={:?} status={:?} q={:?} failure={:?}", result.ades_subindic.standard_name(), result.best_signature_time, status.signature, result.qualification, result.failure_msg);
    result
}
#[test]
fn no_revinfo_past_failure_retains_a_fully_checked_qualified_preliminary_main() {
    let result = run(KeyUsageConstraints::default(), true, false);
    assert_eq!(result.ades_subindic.standard_name(), "NO_POE", "archival proof still fails");
    assert!(result.failure_msg.as_deref().unwrap().contains("control time"));
    let status = result.api_status.unwrap();
    assert!(status.signature.intact && status.signature.valid);
    let timestamp = status.timestamp_validity.unwrap();
    assert!(timestamp.trusted());
    assert_eq!(timestamp.signature.validation_time, Some(at("2025-03-01T22:00:00Z")), "do not retime TSA");
    assert_eq!(result.best_signature_time, Some(at("2020-08-01T07:00:00Z")));
    assert!(status.signature.trusted(), "MAIN must actually pass full historical validation");
    assert_eq!(status.signature.validation_time, result.best_signature_time);
    assert!(result.qualification.unwrap().status.qualified);
}
#[test]
fn historical_preliminary_never_waives_roots_required_revinfo_or_main_predicates() {
    let forbidden = KeyUsageConstraints { key_usage_forbidden: Some(["non_repudiation".into()].into_iter().collect()), ..Default::default() };
    let wrong_eku = KeyUsageConstraints { extd_key_usage: Some(["email_protection".into()].into_iter().collect()), ..Default::default() };
    for (usage, roots, revinfo) in [(KeyUsageConstraints::default(), false, false), (KeyUsageConstraints::default(), true, true), (forbidden, true, false), (wrong_eku, true, false)] {
        let result = run(usage, roots, revinfo);
        assert!(!result.api_status.unwrap().signature.trusted());
        assert!(result.qualification.is_none());
    }
}
