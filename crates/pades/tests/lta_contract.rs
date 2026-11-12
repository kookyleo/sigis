//! Public LTA contract for integration callers; no additional upstream credit.
mod common;
use common::*;
use sigis_pades::ades::{basic::QualificationSpec, lta::lta_validation, AdesPassed};
use sigis_pdf::{EmbeddedSignature, PdfFile};
use sigis_pdf_diff::{ModificationLevel, StandardDiffPolicy};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::fetch::Fetchers;

fn input(test: &str, function: &str) -> (Recording, Call, PdfFile, EmbeddedSignature) {
    let rec = Recording::load("test_ades_validation");
    let call = rec
        .calls("test_ades_validation", test)
        .into_iter()
        .find(|c| c.function() == function)
        .unwrap();
    let (bytes, name) = call.pdf();
    let file = PdfFile::parse(&bytes).unwrap();
    let sig = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.field_name == name)
        .unwrap();
    (rec, call, file, sig)
}

#[test]
fn archival_api_exposes_trust_and_exact_lta_updates() {
    let (rec, call, file, sig) = input(
        "test_pades_lta_happy_path_current_time",
        "ades_lta_validation",
    );
    let ctx = default_context(&rec, &call);
    let result = lta_validation(&file, &sig, &ctx, &QualificationSpec::default()).unwrap();
    assert_eq!(result.ades_subindic, AdesPassed::OK.into());
    let cms = result.api_status.unwrap();
    assert!(cms.signature.intact && cms.signature.valid && cms.signature.trusted());
    let pdf =
        sigis_pades::validate_pdf_signature(&file, &sig, &ctx, Some(&StandardDiffPolicy)).unwrap();
    assert_eq!(
        pdf.modification_level(),
        Some(ModificationLevel::LtaUpdates)
    );
    assert_eq!(
        pdf.coverage,
        sigis_pades::SignatureCoverageLevel::EntireRevision
    );
    assert_eq!(pdf.docmdp_ok, Some(true));
}

#[test]
fn required_revinfo_is_not_satisfied_by_cryptographic_validity() {
    let (rec, current, protected_file, _) = input(
        "test_pades_lta_happy_path_current_time",
        "ades_lta_validation",
    );
    let (_, _, file, sig) = input(
        "test_simulate_future_lta_no_revinfo_fail",
        "simulate_future_ades_lta_validation",
    );
    assert!(file.dss().unwrap().is_none());
    let ctx = default_context(&rec, &current);
    // Complete original current-time evidence includes the TSA's revocation
    // material as well as the main signer. Supplying raw DER does not confer
    // trust; native path/OCSP/CRL validation still authenticates it.
    let evidence = protected_file.dss().unwrap().unwrap();
    let positive_ctx = ctx
        .with_revinfo(
            std::iter::empty::<&sigis_pki_core::cert::Cert>(),
            evidence.material.crls.iter().map(Vec::as_slice),
            evidence.material.ocsps.iter().map(Vec::as_slice),
        )
        .unwrap();
    let positive =
        lta_validation(&file, &sig, &positive_ctx, &QualificationSpec::default()).unwrap();
    assert_eq!(positive.ades_subindic, AdesPassed::OK.into());
    assert!(positive.api_status.unwrap().signature.trusted());
    let offline = ctx.with_fetchers(Fetchers::none());
    let rejected = lta_validation(&file, &sig, &offline, &QualificationSpec::default()).unwrap();
    assert_ne!(rejected.ades_subindic, AdesPassed::OK.into());
    let status = rejected.api_status.unwrap();
    assert!(status.signature.intact && status.signature.valid);
    assert!(!status.signature.trusted());
}

#[test]
fn empty_trust_roots_cannot_accept_archival_evidence() {
    let (_, call, file, sig) = input(
        "test_pades_lta_happy_path_current_time",
        "ades_lta_validation",
    );
    let ctx = ValidationContext::builder()
        .moment(call.time())
        .revinfo_policy(default_revinfo_policy())
        .fetchers(call.fetchers())
        .build()
        .unwrap();
    let result = lta_validation(&file, &sig, &ctx, &QualificationSpec::default()).unwrap();
    assert_ne!(result.ades_subindic, AdesPassed::OK.into());
    let status = result.api_status.unwrap();
    assert!(status.signature.intact && status.signature.valid);
    assert!(!status.signature.trusted());
}

#[test]
fn corrupted_timestamp_cannot_borrow_document_timestamp_proof() {
    let (rec, call, file, sig) = input(
        "test_pades_lta_happy_path_current_time",
        "ades_lta_validation",
    );
    let ctx = default_context(&rec, &call);
    let original = lta_validation(&file, &sig, &ctx, &QualificationSpec::default()).unwrap();
    assert_eq!(original.ades_subindic, AdesPassed::OK.into());
    let sd = sigis_cms::SignedData::from_der(&sig.contents).unwrap();
    let token = sigis_cms::signed_data::find_cms_attribute_iter(
        sd.signer_infos[0].unsigned_attr_list(),
        sigis_pki_core::asn1::oids::AA_SIGNATURE_TIME_STAMP_TOKEN,
    )
    .next()
    .unwrap();
    let ts = sigis_cms::SignedData::from_der(token).unwrap();
    let ts_signature = &ts.signer_infos[0].signature;
    let mut bytes = file.bytes().to_vec();
    // /Contents is a PDF hex string. Change only the timestamp's signature,
    // preserving the main CMS signature and all signed byte-range offsets.
    let hex = ts_signature
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>();
    let offset = bytes
        .windows(hex.len())
        .position(|w| w.eq_ignore_ascii_case(hex.as_bytes()))
        .unwrap();
    bytes[offset] = if bytes[offset] == b'0' { b'1' } else { b'0' };
    let changed = PdfFile::parse(&bytes).unwrap();
    let changed_sig = changed
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.field_name == sig.field_name)
        .unwrap();
    let result =
        lta_validation(&changed, &changed_sig, &ctx, &QualificationSpec::default()).unwrap();
    assert_ne!(result.ades_subindic, AdesPassed::OK.into());
    let status = result.api_status.unwrap();
    assert!(status.signature.intact && status.signature.valid);
    assert!(!status.timestamp_validity.unwrap().signature.valid);
}

#[derive(Debug, Default)]
struct StaleOnlyInPast {
    current: std::sync::atomic::AtomicUsize,
    historical: std::sync::atomic::AtomicUsize,
}
impl sigis_pki_certvalidator::revinfo::freshness::FreshnessJudge for StaleOnlyInPast {
    fn judge(
        &self,
        this_update: Option<sigis_pki_core::time::Moment>,
        next_update: Option<sigis_pki_core::time::Moment>,
        policy: &sigis_pki_certvalidator::policy::CertRevTrustPolicy,
        timing: &sigis_pki_certvalidator::policy::ValidationTimingParams,
    ) -> sigis_pki_certvalidator::revinfo::freshness::RevinfoUsability {
        use sigis_pki_certvalidator::revinfo::freshness::{
            judge_revinfo, RevinfoUsability, RevinfoUsabilityRating,
        };
        use std::sync::atomic::Ordering;
        if timing.point_in_time_validation {
            self.historical.fetch_add(1, Ordering::Relaxed);
            RevinfoUsability {
                rating: RevinfoUsabilityRating::Stale,
                last_usable_at: Some(
                    timing
                        .validation_time
                        .minus(std::time::Duration::from_secs(86400)),
                ),
                compared_to: Some(timing.validation_time),
            }
        } else {
            self.current.fetch_add(1, Ordering::Relaxed);
            judge_revinfo(this_update, next_update, policy, timing)
        }
    }
}

#[test]
fn lta_preserves_caller_freshness_judge_during_past_validation() {
    use std::sync::{atomic::Ordering, Arc};
    let (rec, call, file, sig) = input(
        "test_pades_lta_happy_path_current_time",
        "ades_lta_validation",
    );
    let positive = ValidationContext::builder()
        .trust_root(rec.cert("testing-ca", "root"))
        .moment(call.time())
        .point_in_time_validation(false)
        .revinfo_policy(default_revinfo_policy())
        .build()
        .unwrap();
    let accepted = lta_validation(&file, &sig, &positive, &QualificationSpec::default()).unwrap();
    assert_eq!(accepted.ades_subindic, AdesPassed::OK.into());
    assert!(accepted.api_status.unwrap().signature.trusted());

    let judge = Arc::new(StaleOnlyInPast::default());
    let restricted = ValidationContext::builder()
        .trust_root(rec.cert("testing-ca", "root"))
        .moment(call.time())
        .point_in_time_validation(false)
        .revinfo_policy(default_revinfo_policy())
        .freshness_judge(judge.clone())
        .build()
        .unwrap();
    let rejected = lta_validation(&file, &sig, &restricted, &QualificationSpec::default()).unwrap();
    assert_eq!(
        rejected.ades_subindic,
        sigis_pades::ades::AdesIndeterminate::NO_POE.into()
    );
    let status = rejected.api_status.unwrap();
    // The custom restriction applies only in the historical phase; current
    // cryptographic validity/trust remains the paired positive control.
    assert!(status.signature.intact && status.signature.valid && status.signature.trusted());
    assert!(judge.current.load(Ordering::Relaxed) > 0);
    assert!(judge.historical.load(Ordering::Relaxed) > 0);
}
