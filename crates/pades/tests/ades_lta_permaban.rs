//! Permanent bans use the existing algorithm-policy API without a cutoff.
mod common;
use common::*;
use sigis_pki_core::{
    algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy},
    time::Moment,
};
use std::sync::Arc;
#[derive(Debug)]
struct BanAll;
impl AlgorithmUsagePolicy for BanAll {
    fn digest_algorithm_allowed(
        &self,
        _: &const_oid::ObjectIdentifier,
        _: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::denied("test permanent ban")
    }
    fn signature_algorithm_allowed(
        &self,
        _: &spki::AlgorithmIdentifierOwned,
        _: Option<Moment>,
        _: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::denied("test permanent ban")
    }
}
#[test]
fn test_pades_lta_algo_permaban() {
    let rec = Recording::load("test_ades_validation");
    let call = rec
        .calls("test_ades_validation", "test_pades_lta_algo_permaban")
        .into_iter()
        .find(|c| c.function() == "ades_lta_validation")
        .unwrap();
    let (bytes, name) = call.pdf();
    let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
    let sig = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.field_name == name)
        .unwrap();
    let ctx = sigis_pki_certvalidator::ValidationContext::builder()
        .trust_root(rec.cert("testing-ca", "root"))
        .moment(call.time())
        .revinfo_policy(default_revinfo_policy())
        .algorithm_policy(Arc::new(BanAll))
        .fetchers(call.fetchers())
        .build()
        .unwrap();
    let result = sigis_pades::ades::lta::lta_validation(
        &file,
        &sig,
        &ctx,
        &sigis_pades::ades::basic::QualificationSpec::default(),
    )
    .unwrap();
    assert_eq!(
        result.ades_subindic.standard_name(),
        "CRYPTO_CONSTRAINTS_FAILURE"
    );
    assert_eq!(
        result.ades_subindic.standard_name(),
        call.expected_subindic()
    );
    assert_eq!(result.best_signature_time, Some(call.time()));
    let signature = &result.api_status.as_ref().unwrap().signature;
    assert!(signature.intact && signature.valid);
    assert!(!signature.trusted());
    assert_eq!(signature.error_time_horizon, None);
    assert!(matches!(
        &signature.trust_problem,
        Some(sigis_cms::TrustProblem::Path(
            sigis_pki_core::errors::ValidationError::DisallowedAlgorithm {
                banned_since: None,
                ..
            }
        ))
    ));

    // Supplemental rejection: even explicit earlier signature/certificate
    // evidence must not make a permanent denial eligible for recovery.
    let early = Moment::parse_rfc3339("2020-11-20T00:00:00Z").unwrap();
    let mut poe = sigis_pki_certvalidator::ltv::poe::PoeManager::with_current_time(call.time());
    let cms = sigis_cms::SignedData::from_der(&sig.contents).unwrap();
    poe.register(
        cms.signer_infos.first().unwrap().signature.as_slice(),
        early,
        sigis_pki_certvalidator::ltv::poe::PoeType::Provided,
    );
    for certificate in cms.certificates {
        poe.register(
            &certificate,
            early,
            sigis_pki_certvalidator::ltv::poe::PoeType::Provided,
        );
    }
    let earlier = sigis_pades::ades::lta::lta_validation_with_options(
        &file,
        &sig,
        &ctx,
        &sigis_pades::ades::basic::QualificationSpec::default(),
        &sigis_pades::ades::lta::LtaOptions {
            known_poes: Some(&poe),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(earlier.best_signature_time, Some(early));
    assert_eq!(
        earlier.ades_subindic.standard_name(),
        "CRYPTO_CONSTRAINTS_FAILURE"
    );
    let signature = &earlier.api_status.as_ref().unwrap().signature;
    assert!(!signature.trusted());
    assert_eq!(signature.error_time_horizon, None);
    assert!(matches!(
        &signature.trust_problem,
        Some(sigis_cms::TrustProblem::Path(
            sigis_pki_core::errors::ValidationError::DisallowedAlgorithm {
                banned_since: None,
                ..
            }
        ))
    ));
}
