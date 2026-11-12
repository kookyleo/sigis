//! Real corruption of a later evidence-record member must invalidate the chain.
//! Supplemental rejection for the owned LTA functions; no new upstream credit.
mod common;

use common::*;
use sigis_cms::{SignedContent, TrustProblem};
use sigis_pades::ades::{
    basic::QualificationSpec,
    lta::{lta_validation_with_options, LtaOptions},
};
use sigis_pki_certvalidator::{
    ltv::poe::{PoeManager, PoeType},
    ValidationContext,
};
use sigis_pki_core::{
    algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy},
    time::Moment,
};
use std::sync::Arc;

#[derive(Debug)]
struct Sha512Cutoff(Moment);
impl Sha512Cutoff {
    fn constraint(&self, relevant: bool, moment: Option<Moment>) -> AlgorithmUsageConstraint {
        let denied = relevant && moment.is_none_or(|at| at > self.0);
        AlgorithmUsageConstraint {
            allowed: !denied,
            failure_reason: denied.then(|| "independent chain test algorithm constraint".into()),
            not_allowed_after: denied.then_some(self.0),
        }
    }
}
impl AlgorithmUsagePolicy for Sha512Cutoff {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &const_oid::ObjectIdentifier,
        moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        self.constraint(algorithm.to_string() == "2.16.840.1.101.3.4.2.3", moment)
    }
    fn signature_algorithm_allowed(
        &self,
        algorithm: &spki::AlgorithmIdentifierOwned,
        moment: Option<Moment>,
        _: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        self.constraint(
            matches!(
                algorithm.oid.to_string().as_str(),
                "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4"
            ),
            moment,
        )
    }
}

fn run(case: &str) {
    let root = std::env::var_os("HANKO_POE_CHAIN_FIXTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| data(&["lanes", "r3-v", "poe-chain"]));
    let rec = Recording(serde_json::from_slice(&read_fixture(root.join("oracle.json"))).unwrap());
    let call = rec.calls("poe_chain", case).into_iter().next().unwrap();
    let (bytes, name) = call.pdf();
    assert_eq!(bytes, read_fixture(root.join(format!("{case}.pdf"))));
    let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 3);
    let signature = signatures.iter().find(|s| s.field_name == name).unwrap();
    let ctx = ValidationContext::builder()
        .trust_root(rec.cert("testing-ca", "root"))
        .moment(call.time())
        .revinfo_policy(default_revinfo_policy())
        .algorithm_policy(Arc::new(Sha512Cutoff(
            Moment::parse_rfc3339("2022-12-31T23:59:59Z").unwrap(),
        )))
        .fetchers(call.fetchers())
        .build()
        .unwrap();
    let mut poe = PoeManager::with_current_time(call.time());
    for label in ["root", "interm"] {
        let cert = rec.cert("testing-ca", label);
        poe.register(cert.der(), cert.not_before(), PoeType::Provided);
    }
    let dss = file.dss().unwrap().unwrap();
    let controls = ctx
        .with_revinfo(
            std::iter::empty::<&sigis_pki_core::cert::Cert>(),
            dss.material.crls.iter().map(Vec::as_slice),
            dss.material.ocsps.iter().map(Vec::as_slice),
        )
        .unwrap();
    // Both document imprints still match. Only the new member's CMS crypto
    // changes; the main signature and older trusted timestamp stay intact.
    let main = sigis_cms::validate_cms_signature(
        &signature.contents,
        SignedContent::Data(&signature.signed_data(&file).unwrap()),
        &controls,
    )
    .unwrap();
    assert!(main.signature.intact && main.signature.valid);
    assert!(matches!(
        main.signature.trust_problem,
        Some(TrustProblem::Path(_))
    ));
    for (index, timestamp) in signatures.iter().skip(1).enumerate() {
        let algorithm = sigis_pades::tst_imprint_algorithm(&timestamp.contents).unwrap();
        let checked = sigis_cms::validate_timestamp_token(
            &timestamp.contents,
            &algorithm.digest(&timestamp.signed_data(&file).unwrap()),
            &controls,
        )
        .unwrap();
        assert!(checked.signature.intact);
        assert_eq!(checked.signature.valid, case == "positive" || index == 0);
        if index == 0 || case == "positive" {
            assert!(checked.signature.trusted());
        }
    }
    let result = lta_validation_with_options(
        &file,
        signature,
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
        call.expected_subindic(),
        "{case}: {:?}",
        result.failure_msg
    );
    let status = &result.api_status.as_ref().unwrap().signature;
    assert!(status.intact && status.valid);
    assert_eq!(status.trusted(), case == "positive");
    if case == "positive" {
        assert_eq!(
            result.best_signature_time,
            Moment::parse_rfc3339("2020-11-20T00:00:00Z")
        );
    } else {
        let sd = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
        let cert = sigis_cms::signed_data::extract_certificate_info(&sd)
            .unwrap()
            .signer_cert;
        assert!(
            result.poe.get(cert.der()).is_none(),
            "A failed chain must retain no signer-certificate POE from a valid sibling"
        );
        assert_eq!(
            status.error_time_horizon,
            Moment::parse_rfc3339("2022-12-31T23:59:59Z")
        );
    }
}

#[test]
fn authentic_timestamp_chain_recovers_before_algorithm_cutoff() {
    run("positive");
}

#[test]
fn failed_document_timestamp_invalidates_archival_poe_chain() {
    run("corrupt");
}
