//! Authentic selected-evidence metadata must complete the bounded proof profile.
//! Supplemental tests-first coverage; zero immutable upstream function credit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sigis_pki_certvalidator::{
    validate::find_current_leaf_revocation_evaluation, CertRevTrustPolicy, FreshnessReqType,
    RevocationCheckingPolicy, RevocationCheckingRule, ValidationContext,
};
use sigis_pki_core::{
    algorithms::DigestAlgorithm, cert::Cert, errors::ValidationError, time::Moment,
};

const NOW: &str = "2020-12-25T00:00:00Z";

fn read(name: &str) -> Vec<u8> {
    let path = sigis_testdata::data_dir()
        .join("lanes/r3-v/leaf-revoked-completion")
        .join(name);
    let bytes = std::fs::read(&path).unwrap();
    eprintln!(
        "LEAF_COMPLETION_METADATA_INPUT {}",
        serde_json::json!({"path":path.canonicalize().unwrap(),"length":bytes.len(),
            "sha256":sha(&bytes)})
    );
    bytes
}

fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn cert(label: &str) -> Cert {
    Cert::from_der(&read(&format!("cert-{label}.der"))).unwrap()
}

fn manifest() -> serde_json::Value {
    let manifest: serde_json::Value =
        serde_json::from_slice(&read("metadata/manifest.json")).unwrap();
    assert_eq!(manifest["current_time"], NOW);
    for row in manifest["files"].as_array().unwrap() {
        let bytes = read(&format!("metadata/{}", row["file"].as_str().unwrap()));
        assert_eq!(bytes.len() as u64, row["length"].as_u64().unwrap());
        assert_eq!(sha(&bytes), row["sha256"].as_str().unwrap());
    }
    manifest
}

fn context_result(
    ee_rule: RevocationCheckingRule,
    root_crl: &str,
    ocsp: Option<&str>,
    crl: Option<&str>,
) -> Result<ValidationContext, ValidationError> {
    let mut policy = CertRevTrustPolicy::new(RevocationCheckingPolicy {
        ee_certificate_rule: ee_rule,
        intermediate_ca_cert_rule: RevocationCheckingRule::CrlRequired,
    });
    policy.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    let mut builder = ValidationContext::builder()
        .moment(Moment::parse_rfc3339(NOW).unwrap())
        .point_in_time_validation(false)
        .revinfo_policy(policy)
        .trust_root(cert("root"))
        .other_cert(cert("interm"))
        .crl(read(root_crl));
    if let Some(file) = ocsp {
        builder = builder.ocsp_response(read(file));
    }
    if let Some(file) = crl {
        builder = builder.crl(read(file));
    }
    builder.build()
}

fn context(
    ee_rule: RevocationCheckingRule,
    root_crl: &str,
    ocsp: Option<&str>,
    crl: Option<&str>,
) -> ValidationContext {
    context_result(ee_rule, root_crl, ocsp, crl).unwrap()
}

#[test]
fn explicit_key_compromise_keeps_actual_ocsp_and_crl_positive_controls() {
    manifest();
    for (rule, ocsp, crl) in [
        (
            RevocationCheckingRule::OcspRequired,
            Some("metadata/ocsp-key-compromise.der"),
            None,
        ),
        (
            RevocationCheckingRule::CrlRequired,
            None,
            Some("metadata/crl-key-compromise.der"),
        ),
    ] {
        let ctx = context(rule, "2020-12-25/crl-root.der", ocsp, crl);
        let leaf = cert("signer2");
        let checked = find_current_leaf_revocation_evaluation(&ctx, &leaf, None)
            .expect("full current checks + authentic explicit KeyCompromise are eligible facts");
        assert_eq!(checked.path().leaf(), Some(&leaf));
        assert!(
            checked.unresolved_failure().is_some(),
            "currently revoked stays unresolved"
        );
        assert_eq!(checked.leaf_events().len(), 1);
        assert_eq!(
            checked.leaf_events()[0].effective_time(),
            Moment::parse_rfc3339("2020-12-01T00:00:00Z").unwrap()
        );
    }
}

#[test]
fn unassigned_ocsp_reason_is_explicitly_refused_by_typed_builder_boundary() {
    manifest();
    let result = context_result(
        RevocationCheckingRule::OcspRequired,
        "2020-12-25/crl-root.der",
        Some("metadata/ocsp-reason-unassigned.der"),
        None,
    );
    match result {
        Err(ValidationError::Malformed(message)) => {
            eprintln!(
                "LEAF_COMPLETION_METADATA_CASE {}",
                serde_json::json!({
                    "id":"ocsp-reason-unassigned", "stage":"builder", "error_class":"Malformed", "message":message
                })
            );
        }
        Err(other) => {
            panic!("unassigned OCSP reason must retain explicit malformed input refusal: {other:?}")
        }
        Ok(_) => panic!("unassigned OCSP reason unexpectedly passed the typed builder boundary"),
    }
}

#[test]
fn authenticated_ocsp_metadata_refusals_are_not_error_relabelled_proofs() {
    let manifest = manifest();
    let leaf = cert("signer2");
    let mut failures = Vec::new();
    for row in manifest["cases"].as_array().unwrap().iter().filter(|row| {
        row["kind"] == "ocsp"
            && row["expected_proof"] == "reject"
            && row["id"] != "ocsp-reason-unassigned"
    }) {
        let name = row["id"].as_str().unwrap();
        let input = format!("metadata/{}", row["file"].as_str().unwrap());
        let ctx = match context_result(
            RevocationCheckingRule::OcspRequired,
            "2020-12-25/crl-root.der",
            Some(&input),
            None,
        ) {
            Ok(ctx) => ctx,
            Err(error) => {
                failures.push(format!(
                    "{name}: unexpected builder failure before full evaluation: {error:?}"
                ));
                continue;
            }
        };
        let rejected = find_current_leaf_revocation_evaluation(&ctx, &leaf, None).is_err();
        eprintln!(
            "LEAF_COMPLETION_METADATA_CASE {}",
            serde_json::json!({
                "id":name,"stage":"evaluation","rejected":rejected
            })
        );
        if !rejected {
            failures.push(format!(
                "selected authentic OCSP metadata was accepted: {name}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn authenticated_crl_metadata_and_incomplete_reasons_refuse_completion() {
    let manifest = manifest();
    let leaf = cert("signer2");
    let mut failures = Vec::new();
    for row in manifest["cases"].as_array().unwrap().iter().filter(|row| {
        row["kind"] == "crl"
            && row["target"] == "leaf"
            && row["expected_proof"] == "reject"
            && row["id"] != "crl-reason-remove"
    }) {
        let name = row["id"].as_str().unwrap();
        let input = format!("metadata/{}", row["file"].as_str().unwrap());
        let ctx = match context_result(
            RevocationCheckingRule::CrlRequired,
            "2020-12-25/crl-root.der",
            None,
            Some(&input),
        ) {
            Ok(ctx) => ctx,
            Err(error) => {
                failures.push(format!(
                    "{name}: unexpected builder failure before full evaluation: {error:?}"
                ));
                continue;
            }
        };
        let rejected = find_current_leaf_revocation_evaluation(&ctx, &leaf, None).is_err();
        eprintln!(
            "LEAF_COMPLETION_METADATA_CASE {}",
            serde_json::json!({
                "id":name,"stage":"evaluation","rejected":rejected
            })
        );
        if !rejected {
            failures.push(format!("selected authentic CRL metadata or incomplete reason coverage was accepted: {name}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn remove_from_crl_is_not_a_temporal_event_and_cannot_complete_required_both() {
    use sigis_pki_certvalidator::validate::find_valid_path;
    manifest();
    let leaf = cert("signer2");
    let ordinary_context = context(
        RevocationCheckingRule::CrlRequired,
        "2020-12-25/crl-root.der",
        None,
        Some("metadata/crl-reason-remove.der"),
    );
    let ordinary = find_valid_path(&ordinary_context, &leaf, None).unwrap();
    let current = find_current_leaf_revocation_evaluation(&ordinary_context, &leaf, None).unwrap();
    assert_eq!(current.path(), &ordinary);
    assert!(
        current.leaf_events().is_empty(),
        "removeFromCRL cannot mint a revocation proof"
    );
    assert!(current.unresolved_failure().is_none());

    // A real agreeing Both positive precedes the forbidden selected peer.
    let agreeing = context(
        RevocationCheckingRule::CrlAndOcspRequired,
        "2020-12-25/crl-root.der",
        Some("metadata/ocsp-key-compromise.der"),
        Some("metadata/crl-key-compromise.der"),
    );
    let complete = find_current_leaf_revocation_evaluation(&agreeing, &leaf, None).unwrap();
    assert_eq!(complete.leaf_events().len(), 2);
    assert!(complete.unresolved_failure().is_some());
    let unsupported = context(
        RevocationCheckingRule::CrlAndOcspRequired,
        "2020-12-25/crl-root.der",
        Some("metadata/ocsp-key-compromise.der"),
        Some("metadata/crl-reason-remove.der"),
    );
    assert!(
        find_current_leaf_revocation_evaluation(&unsupported, &leaf, None).is_err(),
        "a selected removeFromCRL peer must never authorize temporal completion"
    );
}

#[test]
fn every_selected_ancestor_dependency_is_inside_the_same_proof_boundary() {
    let manifest = manifest();
    let leaf = cert("signer2");
    for row in manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["target"] == "ancestor")
    {
        let name = row["id"].as_str().unwrap();
        let input = format!("metadata/{}", row["file"].as_str().unwrap());
        let ctx = context(
            RevocationCheckingRule::OcspRequired,
            &input,
            Some("metadata/ocsp-key-compromise.der"),
            None,
        );
        assert!(
            find_current_leaf_revocation_evaluation(&ctx, &leaf, None).is_err(),
            "clean leaf event cannot hide selected ancestor metadata: {name}"
        );
    }
}

#[test]
fn both_channels_refuse_signed_good_revoked_or_effective_event_conflicts() {
    manifest();
    let leaf = cert("signer2");
    for (ocsp, crl) in [
        ("ocsp-key-compromise.der", "crl-good.der"),
        ("ocsp-good.der", "crl-key-compromise.der"),
        ("ocsp-key-compromise.der", "crl-revocation-earlier.der"),
        ("ocsp-revocation-earlier.der", "crl-key-compromise.der"),
    ] {
        let ocsp_path = format!("metadata/{ocsp}");
        let crl_path = format!("metadata/{crl}");
        let ctx = context(
            RevocationCheckingRule::CrlAndOcspRequired,
            "2020-12-25/crl-root.der",
            Some(&ocsp_path),
            Some(&crl_path),
        );
        assert!(
            find_current_leaf_revocation_evaluation(&ctx, &leaf, None).is_err(),
            "Both requires nonconflicting selected authenticated channels: {ocsp}/{crl}"
        );
    }
}

#[test]
fn either_does_not_turn_an_unselected_optional_crl_into_a_required_channel() {
    manifest();
    let ctx = context(
        RevocationCheckingRule::CrlOrOcspRequired,
        "2020-12-25/crl-root.der",
        Some("metadata/ocsp-key-compromise.der"),
        Some("metadata/crl-unknown-critical.der"),
    );
    let checked = find_current_leaf_revocation_evaluation(&ctx, &cert("signer2"), None)
        .expect("Either retains selected OCSP; optional CRL is not fetched or selected");
    assert_eq!(checked.leaf_events().len(), 1);
    assert_eq!(
        checked.leaf_events()[0].evidence_der(),
        read("metadata/ocsp-key-compromise.der")
    );
}

#[test]
fn currently_valid_main_keeps_ordinary_path_success_despite_recovery_only_metadata_limits() {
    use sigis_pki_certvalidator::validate::find_valid_path;
    // This is the original genuine Good signer1 response. No favourable status,
    // response mutation or revoked-to-Good substitution is constructed here.
    let origin: serde_json::Value =
        serde_json::from_slice(&read("metadata/current-valid/origin.json")).unwrap();
    let leaf_bytes = read("metadata/current-valid/cert-signer1.der");
    assert_eq!(sha(&leaf_bytes), origin["source_sha256"].as_str().unwrap());
    assert_eq!(
        leaf_bytes.len() as u64,
        origin["source_length"].as_u64().unwrap()
    );
    let leaf = Cert::from_der(&leaf_bytes).unwrap();
    assert_eq!(
        sha(&read("2020-12-25/ocsp-signer1.der")),
        origin["original_genuine_good_ocsp"]["sha256"]
            .as_str()
            .unwrap()
    );
    for root in [
        "metadata/root-crl-duplicate-extension.der",
        "metadata/root-crl-this-update-fraction.der",
    ] {
        let ctx = context(
            RevocationCheckingRule::OcspRequired,
            root,
            Some("2020-12-25/ocsp-signer1.der"),
            None,
        );
        // Both independent operations must execute; ordinary success is a
        // substantive control, not inferred from the proposed producer result.
        let ordinary = find_valid_path(&ctx, &leaf, None)
            .expect("genuine currently-Good signer keeps ordinary current PKIX behaviour");
        let evaluated = find_current_leaf_revocation_evaluation(&ctx, &leaf, None).expect(
            "recovery-only metadata restrictions cannot reject an ordinary current-valid MAIN",
        );
        assert!(
            evaluated.unresolved_failure().is_none(),
            "no revoked leaf obligation: {root}"
        );
        assert!(
            evaluated.leaf_events().is_empty(),
            "Good leaf creates no revocation event: {root}"
        );
        assert_eq!(
            evaluated.path(),
            &ordinary,
            "same fully validated current path/policies: {root}"
        );
    }
}
