//! Exact LTA result assertions from pyHanko 0.38.1.
mod common;
use common::*;
use sigis_pades::ades::basic::QualificationSpec;
use sigis_pades::ades::lta::{lta_validation, simulate_future_lta_validation};
use sigis_pdf::PdfFile;
const MODULE: &str = "test_ades_validation";
fn past_diagnostic(
    file: &PdfFile,
    ctx: &sigis_pki_certvalidator::ValidationContext,
    result: &sigis_pades::ades::lta::LtaValidationResult,
) -> String {
    let Some(path) = result
        .api_status
        .as_ref()
        .and_then(|s| s.signature.validation_path.as_ref())
    else {
        return "no path".into();
    };
    let dss = file.dss().unwrap().unwrap_or_default();
    let certs = dss
        .material
        .certs
        .iter()
        .map(|c| sigis_pki_core::cert::Cert::from_der(c).unwrap())
        .collect::<Vec<_>>();
    let ctx = ctx
        .with_revinfo(
            &certs,
            dss.material.crls.iter().map(Vec::as_slice),
            dss.material.ocsps.iter().map(Vec::as_slice),
        )
        .unwrap()
        .with_fetchers(sigis_pki_core::fetch::Fetchers::none());
    let control =
        sigis_pki_certvalidator::ltv::time_slide::time_slide(path, ctx.moment(), &ctx, &result.poe);
    let certificates = path
        .certs()
        .into_iter()
        .map(|c| {
            (
                sigis_pki_certvalidator::names::human_friendly(c.subject()),
                c.not_after(),
                result.poe.get(c.der()),
            )
        })
        .collect::<Vec<_>>();
    let crls = ctx
        .crls()
        .map(|c| {
            let crl = sigis_pki_certvalidator::revinfo::CrlContainer::from_der(c).unwrap();
            (crl.this_update(), crl.next_update(), result.poe.get(c))
        })
        .collect::<Vec<_>>();
    let ocsps = ctx
        .ocsps()
        .map(|o| {
            let responses = sigis_pki_certvalidator::revinfo::OcspContainer::load(o).unwrap();
            (
                responses[0].this_update(),
                responses[0].next_update(),
                result.poe.get(o),
            )
        })
        .collect::<Vec<_>>();
    format!("control={control:?}; certificates={certificates:?}; crls={crls:?}; ocsps={ocsps:?}")
}
fn run(test: &str, future: Option<&str>, best: Option<&str>) {
    let rec = Recording::load(MODULE);
    let calls: Vec<_> = rec
        .calls(MODULE, test)
        .into_iter()
        .filter(|c| {
            c.function()
                == if future.is_some() {
                    "simulate_future_ades_lta_validation"
                } else {
                    "ades_lta_validation"
                }
        })
        .collect();
    assert!(!calls.is_empty(), "missing LTA input: {test}");
    for call in calls {
        let (bytes, name) = call.pdf();
        let file = PdfFile::parse(&bytes).unwrap();
        let sig = file
            .embedded_signatures()
            .unwrap()
            .into_iter()
            .find(|s| s.field_name == name)
            .unwrap();
        let ctx = default_context(&rec, &call);
        let qual = QualificationSpec::default();
        let result = if let Some(t) = future {
            simulate_future_lta_validation(
                &file,
                &sig,
                &ctx,
                &qual,
                sigis_eutl::util::parse_xsd_datetime(t).unwrap(),
            )
        } else {
            lta_validation(&file, &sig, &ctx, &qual)
        }
        .unwrap();
        assert_eq!(
            result.ades_subindic.standard_name(),
            call.expected_subindic(),
            "{test}: {:?}; {}",
            result.failure_msg,
            if result.ades_subindic.standard_name() != call.expected_subindic() {
                past_diagnostic(&file, &ctx, &result)
            } else {
                String::new()
            }
        );
        if test == "test_nontraditional_hybrid_lta_with_failed_timestamp" {
            assert!(!result.api_status.as_ref().unwrap().signature.bottom_line());
            assert_eq!(
                sigis_pades::signature_coverage(&file, &sig).unwrap(),
                sigis_pades::SignatureCoverageLevel::EntireFile
            );
        }
        if let Some(t) = best {
            assert_eq!(
                result.best_signature_time,
                sigis_eutl::util::parse_xsd_datetime(t),
                "{test}"
            );
        }
    }
}
#[test]
fn test_pades_lta_happy_path_current_time() {
    run("test_pades_lta_happy_path_current_time", None, None);
}
#[test]
fn test_pades_lta_happy_path_past_time() {
    run(
        "test_pades_lta_happy_path_past_time",
        None,
        Some("2020-11-20T00:00:00Z"),
    );
}
#[test]
fn test_simulate_future_lta_happy_path() {
    for p in ["True", "False"] {
        run(
            &format!("test_simulate_future_lta_happy_path[{p}]"),
            Some("2030-11-20T00:00:00Z"),
            Some("2020-11-20T00:00:00Z"),
        );
    }
}
#[test]
fn test_simulate_future_lta_happy_path_with_ts_chain() {
    run(
        "test_simulate_future_lta_happy_path_with_ts_chain",
        Some("2050-11-20T00:00:00Z"),
        Some("2020-11-20T00:00:00Z"),
    );
}
#[test]
fn test_simulate_future_lta_no_revinfo_fail() {
    run(
        "test_simulate_future_lta_no_revinfo_fail",
        Some("2030-11-20T00:00:00Z"),
        None,
    );
}
#[test]
fn test_simulate_future_lta_with_broken_ts_chain() {
    run(
        "test_simulate_future_lta_with_broken_ts_chain",
        Some("2050-11-20T00:00:00Z"),
        None,
    );
}
#[test]
fn test_pades_lta_expired_timestamp() {
    for p in ["True", "False"] {
        run(
            &format!("test_pades_lta_expired_timestamp[{p}]"),
            None,
            None,
        );
    }
}
#[test]
fn test_pades_missing_dts() {
    run("test_pades_missing_dts", None, None);
}
#[test]
fn test_pades_lta_happy_path_past_time_with_chain() {
    run(
        "test_pades_lta_happy_path_past_time_with_chain",
        None,
        Some("2020-11-20T00:00:00Z"),
    );
}
#[test]
fn test_nontraditional_hybrid_lta_with_failed_timestamp() {
    run(
        "test_nontraditional_hybrid_lta_with_failed_timestamp",
        None,
        Some("2022-11-20T00:00:00Z"),
    );
}
#[test]
fn changed_pdf_data_cannot_inherit_archival_trust() {
    let rec = Recording::load(MODULE);
    let call = rec
        .calls(MODULE, "test_pades_lta_happy_path_current_time")
        .into_iter()
        .find(|c| c.function() == "ades_lta_validation")
        .unwrap();
    let (mut bytes, name) = call.pdf();
    let pos = bytes.windows(6).position(|w| w == b"/Media").unwrap();
    bytes[pos + 1] = b'X';
    let file = PdfFile::parse(&bytes).unwrap();
    let sig = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.field_name == name)
        .unwrap();
    let result = lta_validation(
        &file,
        &sig,
        &default_context(&rec, &call),
        &QualificationSpec::default(),
    )
    .unwrap();
    assert_ne!(result.ades_subindic.standard_name(), "OK");
}

use sigis_eutl::{assess::QualificationRequirements, tsp::TspTrustManager};
use sigis_pades::ades::lta::{lta_validation_with_options, LtaOptions};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{asn1::tlv::Tlv, time::Moment};
fn cases(rec: &Recording, stem: &str, expected: usize) -> Vec<String> {
    let ids: Vec<_> = rec.0["tests"]
        .as_object()
        .unwrap()
        .keys()
        .filter_map(|id| id.split_once("::").map(|(_, id)| id))
        .filter(|id| *id == stem || id.starts_with(&format!("{stem}[")))
        .map(str::to_owned)
        .collect();
    assert_eq!(ids.len(), expected, "all upstream parameters for {stem}");
    ids
}
fn registry(rec: &Recording, id: &str) -> sigis_eutl::tsp::TspRegistry {
    let xml = rec.0["generated_tls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tl| tl["nodeid"].as_str().unwrap().ends_with(id))
        .unwrap()["xml"]
        .as_str()
        .unwrap();
    sigis_eutl::parse::trust_list_to_registry(
        xml,
        &[rec.cert("testing-ca-qualified", "root")],
        None,
        None,
    )
    .unwrap()
    .0
}
#[test]
fn test_simulate_future_lta_happy_path_eseal() {
    let rec = Recording::load(MODULE);
    for id in cases(&rec, "test_simulate_future_lta_happy_path_eseal", 2) {
        let reg = registry(&rec, &id);
        let qual = QualificationSpec {
            registry: Some(&reg),
            requirements: if id.ends_with("[True]") {
                Some(QualificationRequirements::default())
            } else {
                None
            },
            ts_requirements: None,
        };
        let call = rec
            .calls(MODULE, &id)
            .into_iter()
            .find(|c| c.function() == "simulate_future_ades_lta_validation")
            .unwrap();
        let mut b = ValidationContext::builder()
            .moment(call.time())
            .revinfo_policy(default_revinfo_policy())
            .fetchers(call.fetchers());
        for a in TspTrustManager::new(&reg).trust_anchors_at(call.time()) {
            b = b.trust_anchor(a);
        }
        let ctx = b.build().unwrap();
        let (bytes, name) = call.pdf();
        let file = PdfFile::parse(&bytes).unwrap();
        let sig = file
            .embedded_signatures()
            .unwrap()
            .into_iter()
            .find(|s| s.field_name == name)
            .unwrap();
        let result = simulate_future_lta_validation(
            &file,
            &sig,
            &ctx,
            &qual,
            Moment::parse_rfc3339("2030-11-20").unwrap(),
        )
        .unwrap();
        assert_eq!(
            result.ades_subindic.standard_name(),
            "OK",
            "{id}: {:?}; {}",
            result.failure_msg,
            if result.ades_subindic.standard_name() != call.expected_subindic() {
                past_diagnostic(&file, &ctx, &result)
            } else {
                String::new()
            }
        );
        assert_eq!(
            result.best_signature_time,
            Moment::parse_rfc3339("2020-11-20")
        );
    }
}
#[test]
fn test_pades_lta_fail_qualification_requirements() {
    let rec = Recording::load(MODULE);
    for id in cases(&rec, "test_pades_lta_fail_qualification_requirements", 3) {
        let reg = registry(&rec, &id);
        let qual = QualificationSpec {
            registry: Some(&reg),
            requirements: Some(QualificationRequirements::default()),
            ts_requirements: if id.ends_with("-None]") {
                None
            } else {
                Some(QualificationRequirements::default())
            },
        };
        let call = rec
            .calls(MODULE, &id)
            .into_iter()
            .find(|c| c.function() == "simulate_future_ades_lta_validation")
            .unwrap();
        let mut b = ValidationContext::builder()
            .moment(call.time())
            .revinfo_policy(default_revinfo_policy())
            .fetchers(call.fetchers());
        for a in TspTrustManager::new(&reg).trust_anchors_at(call.time()) {
            b = b.trust_anchor(a);
        }
        let ctx = b.build().unwrap();
        let (bytes, name) = call.pdf();
        let file = PdfFile::parse(&bytes).unwrap();
        let sig = file
            .embedded_signatures()
            .unwrap()
            .into_iter()
            .find(|s| s.field_name == name)
            .unwrap();
        let result = simulate_future_lta_validation(
            &file,
            &sig,
            &ctx,
            &qual,
            Moment::parse_rfc3339("2030-11-20").unwrap(),
        )
        .unwrap();
        assert_eq!(
            result.ades_subindic.standard_name(),
            "SIG_CONSTRAINTS_FAILURE",
            "{id}"
        );
    }
}
#[test]
fn test_nontraditional_hybrid_lta() {
    let rec = Recording::load(MODULE);
    let call = rec
        .calls(MODULE, "test_nontraditional_hybrid_lta")
        .into_iter()
        .find(|c| c.function() == "ades_lta_validation")
        .unwrap();
    let ctx = ValidationContext::builder()
        .trust_root(rec.cert("testing-ca", "root"))
        .trust_root(rec.cert("unrelated-tsa", "root"))
        .moment(call.time())
        .revinfo_policy(default_revinfo_policy())
        .fetchers(call.fetchers())
        .build()
        .unwrap();
    let (bytes, name) = call.pdf();
    let file = PdfFile::parse(&bytes).unwrap();
    let sigs = file.embedded_signatures().unwrap();
    assert_eq!(sigs.len(), 1);
    assert!(file.dss().unwrap().is_none());
    let sig = sigs.iter().find(|s| s.field_name == name).unwrap();
    let result = lta_validation(&file, sig, &ctx, &QualificationSpec::default()).unwrap();
    assert_eq!(result.ades_subindic.standard_name(), "NO_POE");
}
fn aa_root(label: &str) -> sigis_pki_core::cert::Cert {
    sigis_pki_core::cert::Cert::from_pem_or_der(
        &std::fs::read(data(&[
            "lanes",
            "d",
            "pki",
            "testing-ca-with-aa",
            &format!("{label}.crt"),
        ]))
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn test_pades_lta_live_ac_validation() {
    let rec = Recording::load(MODULE);
    for id in cases(&rec, "test_pades_lta_live_ac_validation", 2) {
        let call = rec
            .calls(MODULE, &id)
            .into_iter()
            .find(|c| c.function() == "ades_lta_validation")
            .unwrap();
        let ctx = ValidationContext::builder()
            .trust_root(aa_root("root"))
            .moment(call.time())
            .revinfo_policy(default_revinfo_policy())
            .fetchers(call.fetchers())
            .build()
            .unwrap();
        let ac = ValidationContext::builder()
            .trust_root(aa_root("root-aa"))
            .moment(call.time())
            .revinfo_policy(default_revinfo_policy())
            .fetchers(call.fetchers())
            .build()
            .unwrap();
        let ac = call.with_recorded_revinfo(&ac);
        let (bytes, name) = call.pdf();
        let file = PdfFile::parse(&bytes).unwrap();
        let sig = file
            .embedded_signatures()
            .unwrap()
            .into_iter()
            .find(|s| s.field_name == name)
            .unwrap();
        let result = lta_validation_with_options(
            &file,
            &sig,
            &ctx,
            &QualificationSpec::default(),
            &LtaOptions {
                ac_validation_context: Some(&ac),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            result.ades_subindic.standard_name(),
            "OK",
            "{id}: {:?}; {}",
            result.failure_msg,
            if result.ades_subindic.standard_name() != call.expected_subindic() {
                past_diagnostic(&file, &ctx, &result)
            } else {
                String::new()
            }
        );
        let status = result.api_status.unwrap();
        let attrs = status.ac_attrs.expect("validated AC attributes");
        assert_eq!(attrs.0.len(), 1);
        let role = attrs.get("role").unwrap();
        assert_eq!(role.attr_values.len(), 1);
        let role = Tlv::parse_exact(&role.attr_values[0]).unwrap();
        assert!(role.is_universal(16));
        let fields = role.children().unwrap();
        let name = fields.iter().find(|v| v.is_context(1)).unwrap();
        let names = name.children().unwrap();
        assert_eq!(names.len(), 1);
        // The pinned RoleSyntax uses rfc822Name [1], confirmed against asn1crypto.
        assert!(names[0].is_context(1));
        assert_eq!(names[0].value, b"bigboss@example.com");
        assert!(status.ac_validation_errs.as_ref().is_none_or(Vec::is_empty));
    }
}
#[test]
fn test_pades_multi_sig_timestamp_with_unknown_digest() {
    let rec = Recording::load(MODULE);
    let call = rec
        .calls(MODULE, "test_pades_multi_sig_timestamp_with_unknown_digest")
        .into_iter()
        .find(|c| c.function() == "ades_lta_validation")
        .unwrap();
    let (bytes, name) = call.pdf();
    let file = PdfFile::parse(&bytes).unwrap();
    let sig = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.field_name == name)
        .unwrap();
    let ctx = ValidationContext::builder()
        .trust_root(rec.cert("testing-ca", "root"))
        .trust_root(rec.cert("testing-ca-ecdsa", "root"))
        .moment(call.time())
        .revinfo_policy(default_revinfo_policy())
        .fetchers(call.fetchers())
        .build()
        .unwrap();
    let err = lta_validation(&file, &sig, &ctx, &QualificationSpec::default()).unwrap_err();
    assert!(
        err.to_string().contains("TSTDigestNotAvailableError") && err.to_string().contains("2.999"),
        "unsupported timestamp digest must reject explicitly: {err}"
    );
}
