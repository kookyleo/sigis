//! Real timestamp-imprint policy consumer regressions; no new upstream credit.
//!
//! The pinned Python final LTA API accepts denied-imprint inputs. Rejection
//! below is an explicit stricter mandatory POE invariant, not a claim of
//! equivalent final oracle status. The corpus preserves both original API
//! behavior and the original helper's policy-gated registration observations.

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use common::{b64, data, default_revinfo_policy, read_fixture};
use serde_json::Value;
use sigis_cms::SignedContent;
use sigis_pades::ades::{
    basic::QualificationSpec,
    lta::{lta_validation_with_options, LtaOptions},
};
use sigis_pdf::{EmbeddedSignature, PdfFile};
use sigis_pki_certvalidator::{
    ltv::poe::{digest_for_poe, PoeManager, PoeType},
    ValidationContext,
};
use sigis_pki_core::{
    algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm},
    asn1::oids,
    cert::Cert,
    time::Moment,
};

#[derive(Debug)]
struct ImprintPolicy {
    mode: String,
    cutoff: Option<Moment>,
    queries: Mutex<Vec<(String, Option<Moment>, bool)>>,
}

impl AlgorithmUsagePolicy for ImprintPolicy {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &const_oid::ObjectIdentifier,
        moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        let oid = algorithm.to_string();
        let denied = oid == "2.16.840.1.101.3.4.2.3"
            && (self.mode == "permanent"
                || self.mode == "timed" && moment.is_none_or(|at| at > self.cutoff.unwrap()));
        self.queries.lock().unwrap().push((oid, moment, denied));
        AlgorithmUsageConstraint {
            allowed: !denied,
            failure_reason: denied.then(|| "timestamp imprint policy".into()),
            not_allowed_after: if denied { self.cutoff } else { None },
        }
    }

    fn signature_algorithm_allowed(
        &self,
        _: &spki::AlgorithmIdentifierOwned,
        _: Option<Moment>,
        _: Option<&spki::SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::allowed()
    }
}

fn moment(value: &Value) -> Moment {
    sigis_eutl::util::parse_xsd_datetime(value.as_str().unwrap()).unwrap()
}

fn fixtures() -> (PathBuf, Value) {
    let root = std::env::var_os("HANKO_POE_POLICY_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| data(&["lanes", "r3-v", "poe-policy"]));
    eprintln!("V_POE_POLICY_FIXTURE_DIR {}", root.display());
    let manifest: Value =
        serde_json::from_slice(&read_fixture(root.join("manifest.json"))).unwrap();
    assert_eq!(manifest["pyhanko"], "0.38.1");
    assert_eq!(manifest["certvalidator"], "0.33.0");
    assert_eq!(manifest["unique_upstream_credit"], 0);
    assert_eq!(manifest["cases"].as_array().unwrap().len(), 8);
    (root, manifest)
}

fn context(
    manifest: &Value,
    file: &PdfFile,
    at: Moment,
    policy: Option<Arc<ImprintPolicy>>,
) -> ValidationContext {
    let mut builder = ValidationContext::builder()
        .trust_root(Cert::from_der(&b64(manifest["trust_root"].as_str().unwrap())).unwrap())
        .moment(at)
        .revinfo_policy(default_revinfo_policy());
    if let Some(policy) = policy {
        builder = builder.algorithm_policy(policy);
    }
    let ctx = builder.build().unwrap();
    let dss = file.dss().unwrap().unwrap();
    let certs: Vec<_> = dss
        .material
        .certs
        .iter()
        .map(|der| Cert::from_der(der).unwrap())
        .collect();
    let mut crls = dss.material.crls;
    let mut ocsps = dss.material.ocsps;
    if at == moment(&manifest["validation_time"]) {
        crls.extend(
            manifest["current_crls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|der| b64(der.as_str().unwrap())),
        );
        ocsps.extend(
            manifest["current_ocsps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|der| b64(der.as_str().unwrap())),
        );
    }
    ctx.with_revinfo(
        &certs,
        crls.iter().map(Vec::as_slice),
        ocsps.iter().map(Vec::as_slice),
    )
    .unwrap()
}

fn cryptographic_controls(
    manifest: &Value,
    file: &PdfFile,
    signature: &EmbeddedSignature,
    ctx: &ValidationContext,
) -> Vec<u8> {
    let sd = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
    let si = sd.signer_infos.first().unwrap();
    assert_eq!(sd.signer_infos.len(), 1);
    assert_eq!(
        si.digest_algorithm.oid.to_string(),
        "2.16.840.1.101.3.4.2.1"
    );
    let tokens: Vec<_> = sigis_cms::signed_data::find_cms_attribute_iter(
        si.unsigned_attr_list(),
        oids::AA_SIGNATURE_TIME_STAMP_TOKEN,
    )
    .collect();
    assert_eq!(
        tokens.len(),
        1,
        "No alternate trusted timestamp can supply POE"
    );
    let ts = sigis_cms::SignedData::from_der(tokens[0]).unwrap();
    assert_eq!(
        ts.signer_infos
            .first()
            .unwrap()
            .digest_algorithm
            .oid
            .to_string(),
        manifest["timestamp_cms_digest_oid"].as_str().unwrap()
    );
    let info = sigis_cms::validate::tst_info(&ts).unwrap();
    assert_eq!(
        info.message_imprint.hash_algorithm.oid.to_string(),
        manifest["timestamp_imprint_digest_oid"].as_str().unwrap()
    );
    let expected = DigestAlgorithm::Sha512.digest(&si.signature);
    assert_eq!(info.message_imprint.hashed_message.as_bytes(), expected);
    // This token is trusted now under the actual strong revocation policy.
    // Its denied imprint is independent of valid CMS/path/usage verification.
    let timestamp = sigis_cms::validate_timestamp_token(tokens[0], &expected, ctx).unwrap();
    assert!(timestamp.signature.intact && timestamp.signature.valid);
    assert!(timestamp.signature.trusted(), "{timestamp:?}");
    assert_eq!(timestamp.timestamp, moment(&manifest["signed_at"]));

    // The target really was trusted when signed. Rejection cannot be supplied
    // by tampered bytes, an unrelated signer, or a permanently denied CMS hash.
    let signing_ctx = context(manifest, file, moment(&manifest["signed_at"]), None);
    let cms = sigis_cms::validate_cms_signature(
        &signature.contents,
        SignedContent::Data(&signature.signed_data(file).unwrap()),
        &signing_ctx,
    )
    .unwrap();
    assert!(cms.signature.intact && cms.signature.valid && cms.signature.trusted());
    assert!(cms.bottom_line());
    si.signature.clone()
}

fn run_case(identifier: &str) {
    let (root, manifest) = fixtures();
    let case = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == identifier)
        .unwrap();
    let bytes = read_fixture(root.join(manifest["file"].as_str().unwrap()));
    let hash = DigestAlgorithm::Sha256
        .digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(hash, manifest["pdf_sha256"].as_str().unwrap());
    let file = PdfFile::parse(&bytes).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(
        signatures.len(),
        1,
        "No document timestamp supplies alternate POE"
    );
    let signature = &signatures[0];
    assert_eq!(
        signature.field_name,
        manifest["field_name"].as_str().unwrap()
    );
    let policy = (case["mode"] != "default").then(|| {
        Arc::new(ImprintPolicy {
            mode: case["mode"].as_str().unwrap().into(),
            cutoff: case["cutoff"].as_str().map(|_| moment(&case["cutoff"])),
            queries: Mutex::new(Vec::new()),
        })
    });
    let now = moment(&manifest["validation_time"]);
    let ctx = context(&manifest, &file, now, policy.clone());
    let signature_bytes = cryptographic_controls(&manifest, &file, signature, &ctx);
    let signature_digest = digest_for_poe(&signature_bytes);
    let mut known = PoeManager::with_current_time(now);
    for entry in case["known_poes"].as_array().unwrap() {
        known.register_by_digest(
            b64(entry["digest"].as_str().unwrap()),
            moment(&entry["time"]),
            PoeType::Provided,
        );
    }
    let has_provided_signature = case["provided_signature_poe"].as_bool().unwrap();
    assert_eq!(
        known.iter().any(|entry| entry.digest == signature_digest),
        has_provided_signature,
        "Only the independent control may assert earlier signature POE"
    );
    let result = lta_validation_with_options(
        &file,
        signature,
        &ctx,
        &QualificationSpec::default(),
        &LtaOptions {
            known_poes: Some(&known),
            ..Default::default()
        },
    )
    .unwrap();
    let crypto = &result.api_status.as_ref().unwrap().signature;
    assert!(crypto.intact && crypto.valid, "{identifier}: {result:?}");
    match case["native_expectation"].as_str().unwrap() {
        "stricter_reject" => {
            assert_eq!(case["oracle"]["ades_subindic"], "OK");
            assert_eq!(case["oracle"]["api"]["trusted"], true);
            assert_eq!(case["oracle"]["api"]["bottom_line"], true);
            assert!(case["oracle_direct_register_calls"]
                .as_array()
                .unwrap()
                .is_empty());
            assert_ne!(
                result.ades_subindic.standard_name(),
                "OK",
                "{identifier}: a denied imprint must not create historical signature POE; this invariant is stricter than the original final Python API"
            );
            assert_eq!(result.best_signature_time, Some(now), "{identifier}");
            assert_eq!(result.poe.poe_time(&signature_bytes), now, "{identifier}");
            assert!(
                result.poe.get(&signature_bytes).is_none(),
                "{identifier}: current-time fallback is not timestamp evidence"
            );
            assert!(
                policy
                    .unwrap()
                    .queries
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(oid, time, denied)| {
                        oid == "2.16.840.1.101.3.4.2.3" && *time == Some(now) && *denied
                    }),
                "The actual imprint must be queried at the current validation reference time"
            );
        }
        "passed" => {
            assert_eq!(case["oracle"]["ades_subindic"], "OK");
            assert_eq!(
                result.ades_subindic.standard_name(),
                "OK",
                "{identifier}: {result:?}"
            );
            assert!(crypto.trusted(), "{identifier}");
            assert_eq!(
                result.best_signature_time,
                Some(moment(&manifest["signed_at"]))
            );
            assert_eq!(
                result.poe.poe_time(&signature_bytes),
                moment(&manifest["signed_at"])
            );
            if has_provided_signature {
                assert_eq!(
                    result.poe.get(&signature_bytes).unwrap().1,
                    PoeType::Provided
                );
            }
        }
        "rejected" => {
            assert_eq!(case["oracle"]["ades_subindic"], "NO_POE");
            assert_ne!(
                result.ades_subindic.standard_name(),
                "OK",
                "{identifier}: {result:?}"
            );
        }
        other => panic!("unknown native expectation {other}"),
    }
}

#[test]
fn timestamp_imprint_default_policy_positive() {
    run_case("default_policy");
    run_case("explicit_allow");
    run_case("imprint_after_2030");
}

#[test]
fn permanently_denied_timestamp_imprint_cannot_create_early_signature_poe() {
    run_case("imprint_permanent");
}

#[test]
fn timed_denied_timestamp_imprint_cannot_create_early_signature_poe() {
    run_case("imprint_after_2025");
}

#[test]
fn timestamp_imprint_banned_before_token_generation_cannot_create_signature_poe() {
    run_case("imprint_after_2019");
}

#[test]
fn denied_timestamp_imprint_preserves_independent_signature_poe() {
    run_case("independent_signature_poe");
}

#[test]
fn a_trusted_timestamp_alone_does_not_supply_certificate_and_revinfo_poe() {
    run_case("no_material_poe");
}
