//! Exact time-dependent algorithm assertions using authenticated historical proofs.
mod common;
use common::*;
use sigis_pades::ades::{
    basic::QualificationSpec,
    lta::{lta_validation_with_options, LtaOptions},
};
use sigis_pdf::PdfFile;
use sigis_pki_certvalidator::{
    ltv::poe::{PoeManager, PoeType},
    ValidationContext,
};
use sigis_pki_core::{
    algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy},
    time::Moment,
};
use std::sync::Arc;
const MODULE: &str = "test_ades_validation";
#[derive(Debug)]
enum Policy {
    Sha512After(Moment),
    RsaAfter(Moment),
}
impl Policy {
    fn constraint(deny: bool, cutoff: Option<Moment>) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint {
            allowed: !deny,
            failure_reason: deny.then(|| "test algorithm policy".into()),
            not_allowed_after: if deny { cutoff } else { None },
        }
    }
}
impl AlgorithmUsagePolicy for Policy {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &const_oid::ObjectIdentifier,
        moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        match self {
            Self::Sha512After(cutoff) => Self::constraint(
                algorithm.to_string() == "2.16.840.1.101.3.4.2.3"
                    && moment.is_none_or(|m| m > *cutoff),
                Some(*cutoff),
            ),
            Self::RsaAfter(_) => AlgorithmUsageConstraint::allowed(),
        }
    }
    fn signature_algorithm_allowed(
        &self,
        algorithm: &spki::AlgorithmIdentifierOwned,
        moment: Option<Moment>,
        _: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        let oid = algorithm.oid.to_string();
        match self {
            Self::Sha512After(cutoff) => Self::constraint(
                matches!(
                    oid.as_str(),
                    "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4"
                ) && moment.is_none_or(|m| m > *cutoff),
                Some(*cutoff),
            ),
            Self::RsaAfter(cutoff) => Self::constraint(
                // Match the pinned policy's precedence, including its
                // unconditional denial when the evaluation time is unknown.
                moment.is_none_or(|m| m > *cutoff && oid.starts_with("1.2.840.113549.1.1.")),
                Some(*cutoff),
            ),
        }
    }
}
fn algorithm_case(
    test: &str,
    policy: Policy,
    local_dss_poe: bool,
    expected: &str,
    best: Option<Moment>,
) {
    let rec = Recording::load(MODULE);
    let call = rec
        .calls(MODULE, test)
        .into_iter()
        .find(|c| c.function() == "ades_lta_validation")
        .unwrap();
    let arch = if test.contains("hedge") {
        "testing-ca-ecdsa"
    } else {
        "testing-ca"
    };
    let cutoff = match &policy {
        Policy::Sha512After(cutoff) | Policy::RsaAfter(cutoff) => *cutoff,
    };
    let ctx = ValidationContext::builder()
        .trust_root(rec.cert(arch, "root"))
        .moment(call.time())
        .revinfo_policy(default_revinfo_policy())
        .algorithm_policy(Arc::new(policy))
        .fetchers(call.fetchers())
        .build()
        .unwrap();
    let (bytes, name) = call.pdf();
    let file = PdfFile::parse(&bytes).unwrap();
    let sig = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.field_name == name)
        .unwrap();
    let mut poe = PoeManager::with_current_time(call.time());
    if local_dss_poe {
        let dss = file.dss().unwrap().unwrap();
        let time = Moment::parse_rfc3339("2020-11-20").unwrap();
        for b in dss
            .material
            .certs
            .iter()
            .chain(&dss.material.crls)
            .chain(&dss.material.ocsps)
        {
            poe.register(b, time, PoeType::Provided);
        }
    } else if !test.contains("permaban") && !test.contains("hedge") {
        for label in ["root", "interm"] {
            let c = rec.cert("testing-ca", label);
            poe.register(c.der(), c.not_before(), PoeType::Provided);
        }
    }
    let result = lta_validation_with_options(
        &file,
        &sig,
        &ctx,
        &QualificationSpec::default(),
        &LtaOptions {
            known_poes: Some(&poe),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        result.ades_subindic.standard_name(),
        expected,
        "{test}: {:?}",
        result.failure_msg
    );
    if expected == "CRYPTO_CONSTRAINTS_FAILURE_NO_POE" {
        let signature = &result.api_status.as_ref().unwrap().signature;
        assert!(signature.intact && signature.valid);
        assert!(
            matches!(
                &signature.trust_problem,
                Some(sigis_cms::TrustProblem::Path(
                    sigis_pki_core::errors::ValidationError::DisallowedAlgorithm {
                        banned_since: Some(actual), ..
                    }
                )) if *actual == cutoff
            ),
            "{test}: retain the typed path error, not only the cached CMS sub-indication"
        );
        assert_eq!(
            result
                .api_status
                .as_ref()
                .unwrap()
                .signature
                .error_time_horizon,
            Some(cutoff),
            "{test}: preserve the exact typed policy horizon"
        );
        assert!(!signature.trusted());
        let cms = sigis_cms::SignedData::from_der(&sig.contents).unwrap();
        let signature_bytes = cms.signer_infos.first().unwrap().signature.as_slice();
        let (proven_at, _) = result.poe.get(signature_bytes).unwrap();
        assert!(
            proven_at > cutoff,
            "{test}: a policy cutoff must not fabricate earlier signature POE"
        );
    } else if expected == "OK" {
        let signature = &result.api_status.as_ref().unwrap().signature;
        assert!(signature.intact && signature.valid && signature.trusted());
        assert_eq!(signature.error_time_horizon, None);
    }
    if let Some(best) = best {
        assert_eq!(result.best_signature_time, Some(best));
    }
}
#[test]
fn test_pades_hash_algorithm_banned_but_poe_ok() {
    for place in ["in_sig", "in_cert", "both"] {
        algorithm_case(
            &format!("test_pades_hash_algorithm_banned_but_poe_ok[{place}]"),
            Policy::Sha512After(Moment::parse_rfc3339("2025-12-31T23:59:59Z").unwrap()),
            false,
            "OK",
            None,
        );
    }
}
#[test]
fn test_pades_lta_hash_algorithm_banned_and_no_poe() {
    for place in ["in_sig", "in_cert", "both"] {
        algorithm_case(
            &format!("test_pades_lta_hash_algorithm_banned_and_no_poe[{place}]"),
            Policy::Sha512After(Moment::parse_rfc3339("2019-12-31T23:59:59Z").unwrap()),
            false,
            "CRYPTO_CONSTRAINTS_FAILURE_NO_POE",
            None,
        );
    }
}
#[test]
fn test_pades_multi_sig_timestamp_algo_hedge_ok() {
    algorithm_case(
        "test_pades_multi_sig_timestamp_algo_hedge_ok",
        Policy::RsaAfter(Moment::parse_rfc3339("2025-12-31T23:59:59Z").unwrap()),
        true,
        "OK",
        Moment::parse_rfc3339("2020-11-20"),
    );
}
#[test]
fn test_pades_multi_doc_timestamp_algo_hedge_ok() {
    algorithm_case(
        "test_pades_multi_doc_timestamp_algo_hedge_ok",
        Policy::RsaAfter(Moment::parse_rfc3339("2025-12-31T23:59:59Z").unwrap()),
        false,
        "OK",
        Moment::parse_rfc3339("2020-11-20"),
    );
}
