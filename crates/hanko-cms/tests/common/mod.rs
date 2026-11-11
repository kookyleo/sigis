//! Replay of pyHanko validation calls recorded by `oracle/harvest_plugin.py`.
//!
//! Each recorded call carries the inputs pyHanko received (CMS bytes,
//! digests, the validation context's settings) and pyHanko's outcome. The
//! replay runs the same validation with hanko-cms and compares the outcome
//! field by field.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::large_enum_variant
)]

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use base64::Engine;
use const_oid::ObjectIdentifier;
use serde_json::Value;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use hanko_certvalidator::{
    CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule, ValidationContext,
};
use hanko_cms::policy::CmsAlgorithmUsagePolicy;
use hanko_cms::validate::{self, CmsValidationOptions, DataDigester, PrecomputedDigest};
use hanko_cms::{CmsError, SignedData, SignerInfo, StandardCmsSignatureStatus};
use hanko_core::algorithms::{
    AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm, DisallowWeakAlgorithmsPolicy,
};
use hanko_core::cert::Cert;
use hanko_core::time::Moment;

pub fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("base64")
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Path below `crates/hanko-testdata/data/lanes/a/`.
pub fn lane_data(parts: &[&str]) -> std::path::PathBuf {
    let mut all = vec!["lanes", "a"];
    all.extend_from_slice(parts);
    hanko_testdata::path(&all)
}

/// A harvested fixture file.
pub struct Harvest {
    pub calls: Vec<Value>,
    pub certs: BTreeMap<String, Cert>,
}

impl Harvest {
    pub fn load(module: &str) -> &'static Harvest {
        static CACHE: OnceLock<std::sync::Mutex<BTreeMap<String, &'static Harvest>>> =
            OnceLock::new();
        let cache = CACHE.get_or_init(Default::default);
        let mut guard = cache.lock().unwrap();
        if let Some(h) = guard.get(module) {
            return h;
        }
        let path = lane_data(&["harvest", &format!("{module}.json")]);
        let text = std::fs::read_to_string(&path).expect("read harvest");
        let v: Value = serde_json::from_str(&text).expect("json");
        let certs = v["certs"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, c)| {
                (
                    k.clone(),
                    Cert::from_der(&b64(c.as_str().unwrap())).expect("cert"),
                )
            })
            .collect();
        let calls = v["calls"].as_array().unwrap().clone();
        let h: &'static Harvest = Box::leak(Box::new(Harvest { calls, certs }));
        guard.insert(module.to_owned(), h);
        h
    }

    /// Calls recorded for `test` (exact node id, or every parametrization of
    /// the function when `test` has no `[`).
    pub fn calls_for(&self, test: &str) -> Vec<&Value> {
        self.calls
            .iter()
            .filter(|c| {
                let t = c["test"].as_str().unwrap();
                t == test || (!test.contains('[') && t.split('[').next() == Some(test))
            })
            .collect()
    }

    pub fn cert(&self, key: &str) -> Cert {
        self.certs
            .get(key)
            .unwrap_or_else(|| panic!("cert {key}"))
            .clone()
    }
}

/// Lenient policies used by individual tests.
#[derive(Debug)]
pub struct CustomPolicy {
    pub inner: Option<Arc<dyn AlgorithmUsagePolicy>>,
    pub allow_all: bool,
    pub allow_mismatch: bool,
    pub deny_digest: Option<String>,
}

impl AlgorithmUsagePolicy for CustomPolicy {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &ObjectIdentifier,
        moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        if let Some(r) = &self.deny_digest {
            return AlgorithmUsageConstraint::denied(r.clone());
        }
        match (&self.inner, self.allow_all) {
            (_, true) | (None, _) => AlgorithmUsageConstraint::allowed(),
            (Some(p), false) => p.digest_algorithm_allowed(algorithm, moment),
        }
    }

    fn signature_algorithm_allowed(
        &self,
        algorithm: &AlgorithmIdentifierOwned,
        moment: Option<Moment>,
        public_key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        match (&self.inner, self.allow_all) {
            (_, true) | (None, _) => AlgorithmUsageConstraint::allowed(),
            (Some(p), false) => p.signature_algorithm_allowed(algorithm, moment, public_key),
        }
    }

    fn digest_combination(
        &self,
        signature_algorithm: &AlgorithmIdentifierOwned,
        message_digest_algorithm: &AlgorithmIdentifierOwned,
        moment: Option<Moment>,
    ) -> Option<AlgorithmUsageConstraint> {
        Some(self.digest_combination_allowed(signature_algorithm, message_digest_algorithm, moment))
    }
}

impl CmsAlgorithmUsagePolicy for CustomPolicy {
    fn digest_combination_allowed(
        &self,
        signature_algorithm: &AlgorithmIdentifierOwned,
        message_digest_algorithm: &AlgorithmIdentifierOwned,
        moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        if self.allow_all || self.allow_mismatch {
            AlgorithmUsageConstraint::allowed()
        } else {
            let _ = moment;
            hanko_cms::policy::ensure_digest_match(signature_algorithm, message_digest_algorithm)
        }
    }
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|s| s.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

/// Rebuild a base algorithm policy from its recorded description.
pub fn base_policy(v: &Value) -> Arc<dyn AlgorithmUsagePolicy> {
    match v["class"].as_str().unwrap() {
        "DisallowWeakAlgorithmsPolicy" => Arc::new(DisallowWeakAlgorithmsPolicy {
            weak_hash_algos: str_list(&v["weak_hash_algos"]),
            weak_signature_algos: str_list(&v["weak_signature_algos"]),
            rsa_key_size_threshold: v["rsa_key_size_threshold"].as_u64().unwrap() as usize,
            dsa_key_size_threshold: v["dsa_key_size_threshold"].as_u64().unwrap() as usize,
        }),
        "_DefaultPolicyMixin" => base_policy(&v["inner"]),
        other => cms_policy(v).map_or_else(
            || panic!("unknown policy class {other}"),
            |p| p as Arc<dyn AlgorithmUsagePolicy>,
        ),
    }
}

/// Rebuild a CMS algorithm policy, if one was given.
pub fn cms_policy(v: &Value) -> Option<Arc<CustomPolicy>> {
    if v.is_null() {
        return None;
    }
    let class = v["class"].as_str().unwrap();
    let inner = (!v["inner"].is_null()).then(|| base_policy(&v["inner"]));
    Some(Arc::new(match class {
        "_AllowEverything" => CustomPolicy {
            inner: None,
            allow_all: true,
            allow_mismatch: true,
            deny_digest: None,
        },
        "_AllowMismatches" => CustomPolicy {
            inner,
            allow_all: false,
            allow_mismatch: true,
            deny_digest: None,
        },
        // `test_sign_weak_sig_digest_disallowed_by_custom_policy`.
        "Policy" => CustomPolicy {
            inner: None,
            allow_all: false,
            allow_mismatch: false,
            deny_digest: Some("Test reason".into()),
        },
        "_DefaultPolicyMixin" => CustomPolicy {
            inner,
            allow_all: false,
            allow_mismatch: false,
            deny_digest: None,
        },
        "DisallowWeakAlgorithmsPolicy" => CustomPolicy {
            inner: Some(base_policy(v)),
            allow_all: false,
            allow_mismatch: false,
            deny_digest: None,
        },
        other => panic!("unknown CMS policy class {other}"),
    }))
}

pub fn moment(v: &Value) -> Moment {
    Moment::parse_rfc3339(v.as_str().unwrap()).expect("moment")
}

/// Rebuild a validation context from its recorded description.
pub fn context(h: &Harvest, vc: &Value) -> Option<ValidationContext> {
    if vc.is_null() {
        return None;
    }
    let mut b = ValidationContext::builder();
    let roots = str_list(&vc["trust_roots"]);
    for r in &roots {
        b = b.trust_root(h.cert(r));
    }
    for c in str_list(&vc["other_certs"]) {
        if !roots.contains(&c) {
            b = b.other_cert(h.cert(&c));
        }
    }
    for c in vc["crls"].as_array().unwrap() {
        b = b.crl(b64(c.as_str().unwrap()));
    }
    for o in vc["ocsps"].as_array().unwrap() {
        b = b.ocsp_response(b64(o.as_str().unwrap()));
    }
    let rp = &vc["revinfo_policy"];
    let rule = |k: &str| RevocationCheckingRule::from_value(rp[k].as_str().unwrap()).unwrap();
    if let Some(pit) = vc["point_in_time_validation"].as_bool() {
        b = b.point_in_time_validation(pit);
    }
    b = b
        .moment(moment(&vc["moment"]))
        .best_signature_time(moment(&vc["best_signature_time"]))
        .time_tolerance(std::time::Duration::from_secs_f64(
            vc["time_tolerance"].as_f64().unwrap(),
        ))
        .revinfo_policy(CertRevTrustPolicy::new(RevocationCheckingPolicy {
            ee_certificate_rule: rule("ee"),
            intermediate_ca_cert_rule: rule("intermediate"),
        }))
        .algorithm_policy(base_policy(&vc["algorithm_policy"]));
    Some(b.build().expect("context"))
}

/// The outcome of a replayed call, in the recorded JSON shape.
pub fn status_json(st: &hanko_cms::SignatureStatus) -> Value {
    serde_json::json!({
        "summary": st.summary(),
        "intact": st.intact,
        "valid": st.valid,
        "trusted": st.trusted(),
        "revoked": st.revoked(),
        "trust_problem_indic": st.trust_problem_indic.map(|s| s.standard_name()),
        "md_algorithm": st.md_algorithm_name,
        "pkcs7_signature_mechanism": st.pkcs7_signature_mechanism,
        "validation_path_len": st.validation_path.as_ref().map(|p| p.len()),
    })
}

fn ts_json(ts: &Option<hanko_cms::TimestampSignatureStatus>) -> Value {
    match ts {
        None => Value::Null,
        Some(t) => {
            let mut v = status_json(&t.signature);
            v["timestamp"] = Value::String(hanko_cms::status::isoformat(t.timestamp));
            v
        }
    }
}

pub fn standard_json(st: &StandardCmsSignatureStatus) -> Value {
    let mut v = status_json(&st.signature);
    v["bottom_line"] = Value::Bool(st.bottom_line());
    v["summary"] = Value::String(st.summary());
    v["signer_reported_dt"] = st.signer_reported_dt.map_or(Value::Null, |m| {
        Value::String(hanko_cms::status::isoformat(m))
    });
    v["timestamp_validity"] = ts_json(&st.timestamp_validity);
    v["content_timestamp_validity"] = ts_json(&st.content_timestamp_validity);
    if let Some(ac) = &st.ac_attrs {
        v["ac_attrs"] = serde_json::json!(ac.0.keys().collect::<Vec<_>>());
    }
    if let Some(c) = &st.cades_signer_attrs {
        v["cades_signer_attrs"] = serde_json::json!({
            "claimed_attrs": c.claimed_attrs.0.keys().collect::<Vec<_>>(),
            "certified_attrs": c.certified_attrs.as_ref().map(|m| m.0.keys().collect::<Vec<_>>()),
            "valid": c.valid(),
            "unknown_attrs_present": c.unknown_attrs_present,
        });
    }
    v
}

pub fn error_json(e: &CmsError) -> Value {
    serde_json::json!({
        "error": e.class_name(),
        "message": e.to_string(),
        "ades_subindication": e.ades_subindication().standard_name(),
    })
}

/// Result of replaying one call.
#[derive(Debug)]
pub enum Replayed {
    Standard(StandardCmsSignatureStatus),
    Basic(hanko_cms::SignatureStatus),
    Integrity(bool, bool),
    /// Signer subject, number of other certificates and of ACs.
    Certs(String, usize, usize),
    Ok,
    Error(CmsError),
}

impl Replayed {
    pub fn to_json(&self) -> Value {
        match self {
            Self::Standard(s) => serde_json::json!({ "status": standard_json(s) }),
            Self::Basic(s) => serde_json::json!({ "status": status_json(s) }),
            Self::Integrity(i, v) => serde_json::json!({ "intact": i, "valid": v }),
            Self::Certs(_, n, a) => serde_json::json!({ "other_certs": n, "attribute_certs": a }),
            Self::Ok => serde_json::json!({ "ok": true }),
            Self::Error(e) => error_json(e),
        }
    }

    pub fn standard(&self) -> &StandardCmsSignatureStatus {
        match self {
            Self::Standard(s) => s,
            other => panic!("expected a standard status, got {other:?}"),
        }
    }

    pub fn basic(&self) -> &hanko_cms::SignatureStatus {
        match self {
            Self::Basic(s) => s,
            Self::Standard(s) => &s.signature,
            other => panic!("expected a status, got {other:?}"),
        }
    }

    pub fn error(&self) -> &CmsError {
        match self {
            Self::Error(e) => e,
            other => panic!("expected an error, got {other:?}"),
        }
    }
}

fn content_type_oid(name: &str) -> hanko_core::asn1::raw_oid::RawOid {
    match name {
        "data" => hanko_core::asn1::oids::CT_DATA,
        "signed_data" => hanko_core::asn1::oids::CT_SIGNED_DATA,
        "tst_info" => hanko_core::asn1::oids::CT_TST_INFO,
        other => other.parse::<ObjectIdentifier>().expect("content type"),
    }
    .into()
}

/// Replay one recorded call with hanko-cms.
pub fn replay(h: &Harvest, call: &Value) -> Replayed {
    let inputs = &call["inputs"];
    let r: Result<Replayed, CmsError> = (|| match call["fn"].as_str().unwrap() {
        "validate_sig_integrity" => {
            let si = SignerInfo::from_der(&b64(inputs["signer_info"].as_str().unwrap()))?;
            let cert = h.cert(inputs["cert"].as_str().unwrap());
            let ct = content_type_oid(inputs["expected_content_type"].as_str().unwrap());
            let digest = unhex(inputs["actual_digest"].as_str().unwrap());
            let (i, v) = validate::validate_sig_integrity(&si, &cert, &ct, &digest)?;
            Ok(Replayed::Integrity(i, v))
        }
        "async_validate_cms_signature" => {
            let sd = SignedData::from_der(&b64(inputs["signed_data"].as_str().unwrap()))?;
            let ctx = context(h, &inputs["vc"]);
            let raw = inputs["raw_digest"].as_str().map(unhex);
            let policy = cms_policy(&inputs["algorithm_policy"])
                .map(|p| p as Arc<dyn CmsAlgorithmUsagePolicy>);
            let st = validate::validate_cms_signature_basic(
                &sd,
                raw.as_deref(),
                ctx.as_ref(),
                None,
                policy,
            )?;
            Ok(Replayed::Basic(st))
        }
        "async_validate_detached_cms" => {
            let sd = SignedData::from_der(&b64(inputs["signed_data"].as_str().unwrap()))?;
            let data = b64(inputs["input_data"]["bytes"].as_str().unwrap());
            let ctx = context(h, &inputs["vc"]);
            let ts_ctx = context(h, &inputs["ts_vc"]);
            let ac_ctx = context(h, &inputs["ac_vc"]);
            let options = CmsValidationOptions {
                ts_validation_context: ts_ctx.as_ref(),
                ac_validation_context: ac_ctx.as_ref(),
                algorithm_policy: cms_policy(&inputs["algorithm_policy"])
                    .map(|p| p as Arc<dyn CmsAlgorithmUsagePolicy>),
                ..Default::default()
            };
            let st = validate::validate_detached_cms_with(
                &sd,
                &DataDigester::new(&data),
                false,
                ctx.as_ref(),
                &options,
            )?;
            Ok(Replayed::Standard(st))
        }
        "async_validate_pdf_signature" => {
            let sd = SignedData::from_der(&b64(inputs["signed_data"].as_str().unwrap()))?;
            let md = inputs["md_algorithm"].as_str().unwrap();
            let digest = unhex(inputs["document_digest"].as_str().unwrap());
            let Some(algorithm) = DigestAlgorithm::from_name(md) else {
                return Err(CmsError::validation_generic(format!(
                    "Unknown hash function '{md}'"
                )));
            };
            let ctx = context(h, &inputs["vc"]);
            let ts_ctx = context(h, &inputs["ts_vc"]);
            let ac_ctx = context(h, &inputs["ac_vc"]);
            let options = CmsValidationOptions {
                ts_validation_context: ts_ctx.as_ref(),
                ac_validation_context: ac_ctx.as_ref(),
                algorithm_policy: cms_policy(&inputs["algorithm_policy"])
                    .map(|p| p as Arc<dyn CmsAlgorithmUsagePolicy>),
                ..Default::default()
            };
            let st = validate::validate_detached_cms_with(
                &sd,
                &PrecomputedDigest { algorithm, digest },
                false,
                ctx.as_ref(),
                &options,
            )?;
            Ok(Replayed::Standard(st))
        }
        "extract_certs_for_validation" => {
            let sd = SignedData::from_der(&b64(inputs["signed_data"].as_str().unwrap()))?;
            let info = validate::extract_certs_for_validation(&sd)?;
            Ok(Replayed::Certs(
                hanko_cms::status::human_friendly(&info.signer_cert),
                info.other_certs.len(),
                info.attribute_certs.len(),
            ))
        }
        "extract_signer_info" => {
            let sd = SignedData::from_der(&b64(inputs["signed_data"].as_str().unwrap()))?;
            hanko_cms::signed_data::extract_signer_info(&sd)?;
            Ok(Replayed::Ok)
        }
        other => panic!("unknown recorded function {other}"),
    })();
    r.unwrap_or_else(Replayed::Error)
}

/// Fields compared per recorded function.
fn compared_fields(fn_name: &str) -> &'static [&'static str] {
    match fn_name {
        "async_validate_pdf_signature" => &[
            "intact",
            "valid",
            "trusted",
            "revoked",
            "trust_problem_indic",
            "md_algorithm",
            "pkcs7_signature_mechanism",
            "validation_path_len",
            "signer_reported_dt",
            "ac_attrs",
        ],
        _ => &[
            "intact",
            "valid",
            "trusted",
            "revoked",
            "trust_problem_indic",
            "md_algorithm",
            "pkcs7_signature_mechanism",
            "validation_path_len",
            "signer_reported_dt",
            "bottom_line",
            "summary",
            "ac_attrs",
            "cades_signer_attrs",
        ],
    }
}

/// Compare a replayed outcome with the recorded one; returns the
/// differences (empty if they agree).
pub fn diff(call: &Value, got: &Value) -> Vec<String> {
    let expected = &call["outcome"];
    let fn_name = call["fn"].as_str().unwrap();
    let mut out = Vec::new();
    if let Some(err) = expected.get("error") {
        if got.get("error").is_none() {
            out.push(format!("expected {err}, got {got}"));
            return out;
        }
        let mro = str_list(&expected["mro"]);
        let got_class = got["error"].as_str().unwrap();
        if !mro.iter().any(|c| c == got_class) {
            out.push(format!(
                "error class: expected {err} (mro {mro:?}), got {got_class}"
            ));
        }
        if expected["message"] != got["message"] {
            out.push(format!(
                "message: expected {}, got {}",
                expected["message"], got["message"]
            ));
        }
        let exp_sub = &expected["ades_subindication"];
        if !exp_sub.is_null() && *exp_sub != got["ades_subindication"] {
            out.push(format!(
                "sub-indication: expected {exp_sub}, got {}",
                got["ades_subindication"]
            ));
        }
        return out;
    }
    if got.get("error").is_some() {
        out.push(format!("expected success {expected}, got {got}"));
        return out;
    }
    if matches!(
        fn_name,
        "extract_certs_for_validation" | "extract_signer_info"
    ) {
        for k in ["other_certs", "attribute_certs", "ok"] {
            if expected.get(k).is_some() && expected[k] != got[k] {
                out.push(format!("{k}: expected {}, got {}", expected[k], got[k]));
            }
        }
        return out;
    }
    if fn_name == "validate_sig_integrity" {
        for k in ["intact", "valid"] {
            if expected[k] != got[k] {
                out.push(format!("{k}: expected {}, got {}", expected[k], got[k]));
            }
        }
        return out;
    }
    let (e, g) = (&expected["status"], &got["status"]);
    for k in compared_fields(fn_name) {
        // PDF validation falls back to the signature dictionary's /M entry
        // (lane E); only the CMS signingTime attribute is in scope here.
        if fn_name == "async_validate_pdf_signature"
            && *k == "signer_reported_dt"
            && g[*k].is_null()
        {
            continue;
        }
        if e.get(*k).is_some() && e[*k] != g[*k] {
            out.push(format!("{k}: expected {}, got {}", e[*k], g[*k]));
        }
    }
    for ts in ["timestamp_validity", "content_timestamp_validity"] {
        match (e.get(ts), g.get(ts)) {
            (Some(Value::Null) | None, Some(Value::Null) | None) => {}
            (Some(ev), Some(gv)) if !ev.is_null() && !gv.is_null() => {
                for k in [
                    "intact",
                    "valid",
                    "trusted",
                    "trust_problem_indic",
                    "md_algorithm",
                    "pkcs7_signature_mechanism",
                    "timestamp",
                    "validation_path_len",
                ] {
                    if ev[k] != gv[k] {
                        out.push(format!("{ts}.{k}: expected {}, got {}", ev[k], gv[k]));
                    }
                }
            }
            (ev, gv) => out.push(format!("{ts}: expected {ev:?}, got {gv:?}")),
        }
    }
    out
}

/// "Never accept what pyHanko rejects": the port's outcome must not be more
/// lenient than pyHanko's.
pub fn fail_open(call: &Value, got: &Value) -> Option<String> {
    let expected = &call["outcome"];
    if expected.get("error").is_some() {
        let accepted = got
            .get("status")
            .is_some_and(|s| s["trusted"] == Value::Bool(true))
            || (got["intact"] == Value::Bool(true) && got["valid"] == Value::Bool(true))
            || got.get("other_certs").is_some()
            || got.get("ok").is_some();
        return accepted.then(|| format!("pyHanko raised {}, port accepted", expected["error"]));
    }
    if matches!(
        call["fn"].as_str(),
        Some("extract_certs_for_validation" | "extract_signer_info")
    ) {
        return None;
    }
    if call["fn"] == "validate_sig_integrity" {
        for k in ["intact", "valid"] {
            if expected[k] == Value::Bool(false) && got[k] == Value::Bool(true) {
                return Some(format!("{k}: pyHanko false, port true"));
            }
        }
        return None;
    }
    let (e, g) = (&expected["status"], &got["status"]);
    if g.is_null() {
        return None;
    }
    for k in ["intact", "valid", "trusted", "bottom_line"] {
        if e[k] == Value::Bool(false) && g[k] == Value::Bool(true) {
            return Some(format!("{k}: pyHanko false, port true"));
        }
    }
    for ts in ["timestamp_validity", "content_timestamp_validity"] {
        let (ev, gv) = (&e[ts], &g[ts]);
        if ev.is_null() || gv.is_null() {
            continue;
        }
        for k in ["intact", "valid", "trusted"] {
            if ev[k] == Value::Bool(false) && gv[k] == Value::Bool(true) {
                return Some(format!("{ts}.{k}: pyHanko false, port true"));
            }
        }
    }
    None
}

/// Replay every call of `test`; panics on unlisted divergences, on listed
/// ones that now agree, and on fail-open divergences. Returns the replayed
/// outcomes in call order.
pub fn check(module: &str, test: &str, known: &[(&str, usize, &str)]) -> Vec<Replayed> {
    let h = Harvest::load(module);
    let calls = h.calls_for(test);
    assert!(!calls.is_empty(), "no recorded calls for {test}");
    let mut results = Vec::new();
    let mut problems = Vec::new();
    for call in calls {
        let id = call["test"].as_str().unwrap();
        let index = call["index"].as_u64().unwrap() as usize;
        let replayed = replay(h, call);
        let got = replayed.to_json();
        let d = diff(call, &got);
        let listed = known.iter().any(|(t, i, _)| *t == id && *i == index);
        if let Some(f) = fail_open(call, &got) {
            problems.push(format!("{id}#{index}: FAIL-OPEN divergence: {f}"));
        }
        match (d.is_empty(), listed) {
            (true, true) => problems.push(format!("{id}#{index}: listed divergence now agrees")),
            (false, false) => problems.push(format!("{id}#{index}: {}", d.join("; "))),
            _ => {}
        }
        results.push(replayed);
    }
    assert!(problems.is_empty(), "divergences:\n{}", problems.join("\n"));
    results
}
