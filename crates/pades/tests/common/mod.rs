//! Replay of the pyHanko AdES oracle recordings
//! (`crates/testdata/data/lanes/e/ades/*.json`, see
//! `oracle/record_plugin.py`).

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use serde_json::Value;
use sigis_pki_certvalidator::{
    CertRevTrustPolicy, FreshnessReqType, ValidationContext, REQUIRE_REVINFO,
};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{FetchError, FetchErrorKind};
use sigis_pki_core::fetch::{CertificateFetcher, CrlFetcher, Fetchers, OcspFetcher};
use sigis_pki_core::time::Moment;

/// Fixture path below `crates/testdata/data/`, from the run-time
/// `CARGO_MANIFEST_DIR` (request R-E9).
pub fn data(parts: &[&str]) -> PathBuf {
    let mut p = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .join("testdata")
        .join("data");
    p.extend(parts);
    p
}

pub fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// Read the actual native input and emit provenance after opening it.
/// Cargo's explicit `--config env` selection, rather than the launcher's
/// ambient environment, is required for scheduled worker fixture overrides.
pub fn read_fixture(path: impl AsRef<std::path::Path>) -> Vec<u8> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let digest = sigis_pki_core::algorithms::DigestAlgorithm::Sha256.digest(&bytes);
    let hash = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let selections: serde_json::Map<String, Value> = [
        "HANKO_ADES_RECORDING_DIR",
        "HANKO_SEED_FIXTURE_DIR",
        "HANKO_PDFMAC_FIXTURE_DIR",
        "HANKO_INTEGRITY_FIXTURE_DIR",
        "HANKO_POE_POLICY_FIXTURE_DIR",
        "HANKO_POE_CHAIN_FIXTURE_DIR",
    ]
    .into_iter()
    .filter_map(|key| {
        std::env::var(key)
            .ok()
            .map(|value| (key.into(), Value::String(value)))
    })
    .collect();
    // Render the complete record before printing: serde's streaming Display
    // can otherwise interleave with the test harness's independent stdout.
    let receipt = format!(
        "V_FIXTURE_OPEN {}",
        serde_json::json!({
            "path": std::fs::canonicalize(path).unwrap(),
            "sha256": hash,
            "length": bytes.len(),
            "host": std::fs::read_to_string("/etc/hostname").unwrap().trim(),
            "slot": std::env::var("RUST_SLOTS_HELD").ok(),
            "pid": std::process::id(),
            "selections": selections,
        })
    );
    eprintln!("{receipt}");
    bytes
}

/// One recorded module.
pub struct Recording(pub Value);

impl Recording {
    pub fn load(module: &str) -> Self {
        let p = std::env::var_os("HANKO_ADES_RECORDING_DIR")
            .map(|path| PathBuf::from(path).join(format!("{module}.json")))
            .unwrap_or_else(|| data(&["lanes", "e", "ades", &format!("{module}.json")]));
        Self(serde_json::from_slice(&read_fixture(p)).unwrap())
    }

    /// Certificate `label` of architecture `arch` in the recorded run.
    pub fn cert(&self, arch: &str, label: &str) -> Cert {
        Cert::from_der(&b64(self.0["pki"][arch][label].as_str().unwrap())).unwrap()
    }

    /// Recorded calls of a test case (pytest node id without the module
    /// path, e.g. `test_pades_basic_happy_path`).
    pub fn calls(&self, module: &str, test: &str) -> Vec<Call> {
        let id = format!("tests/{module}.py::{test}");
        let t = &self.0["tests"][&id];
        assert_eq!(t["outcome"], "passed", "{id} did not pass under pyHanko");
        let calls = t["calls"].as_array().unwrap();
        let case_http: Vec<Value> = calls
            .iter()
            .flat_map(|call| call["http"].as_array().into_iter().flatten().cloned())
            .collect();
        calls
            .iter()
            .map(|call| {
                let mut call = call.clone();
                call["case_http"] = Value::Array(case_http.clone());
                Call(call)
            })
            .collect()
    }
}

/// One recorded validation call.
#[derive(Clone)]
pub struct Call(pub Value);

impl Call {
    pub fn function(&self) -> &str {
        self.0["function"].as_str().unwrap()
    }

    pub fn time(&self) -> Moment {
        sigis_eutl::util::parse_xsd_datetime(self.0["time"].as_str().unwrap()).unwrap()
    }

    /// pyHanko's sub-indication (`OK`, `HASH_FAILURE`, ...).
    pub fn expected_subindic(&self) -> String {
        self.0["result"]["ades_subindic"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// DER `SignedData` of a CMS input, wrapped in a `ContentInfo`.
    pub fn content_info(&self) -> Vec<u8> {
        assert_eq!(self.0["input"]["kind"], "cms_signed_data");
        wrap_signed_data(&b64(self.0["input"]["der"].as_str().unwrap()))
    }

    pub fn raw_digest(&self) -> Option<Vec<u8>> {
        self.0.get("raw_digest").and_then(Value::as_str).map(b64)
    }

    pub fn pdf(&self) -> (Vec<u8>, String) {
        assert_eq!(self.0["input"]["kind"], "pdf_signature");
        (
            b64(self.0["input"]["pdf"].as_str().unwrap()),
            self.0["input"]["field_name"].as_str().unwrap().to_owned(),
        )
    }

    /// Replay current-time HTTP revocation evidence as raw local material.
    /// AC targets cannot use the Cert-only fetch trait yet; native validation
    /// still authenticates every supplied response under the caller's policy.
    pub fn with_recorded_revinfo(&self, ctx: &ValidationContext) -> ValidationContext {
        let http = self
            .0
            .get("case_http")
            .filter(|v| v.as_array().is_some_and(|a| !a.is_empty()))
            .unwrap_or(&self.0["http"]);
        let mut crls = Vec::new();
        let mut ocsps = Vec::new();
        for exchange in http
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| e["status"] == 200)
        {
            let mime = exchange["content_type"].as_str().unwrap_or("");
            if mime.starts_with("application/pkix-crl") {
                crls.push(b64(exchange["response_body"].as_str().unwrap()));
            }
            if mime.starts_with("application/ocsp-response") {
                ocsps.push(b64(exchange["response_body"].as_str().unwrap()));
            }
        }
        ctx.with_revinfo(
            std::iter::empty::<&Cert>(),
            crls.iter().map(Vec::as_slice),
            ocsps.iter().map(Vec::as_slice),
        )
        .unwrap()
    }

    pub fn fetchers(&self) -> Fetchers {
        let http = if self.0["http"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            &self.0["http"]
        } else {
            &self.0["case_http"]
        };
        let replay = Arc::new(Replay::new(http));
        Fetchers {
            ocsp: Some(replay.clone()),
            crl: Some(replay.clone()),
            cert: Some(replay),
        }
    }
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect();
        let mut v = vec![0x80 | bytes.len() as u8];
        v.extend(bytes);
        v
    }
}

/// `ContentInfo { id-signedData, [0] EXPLICIT SignedData }`.
pub fn wrap_signed_data(sd: &[u8]) -> Vec<u8> {
    let oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    // The recorder dumps the `content` field of the ContentInfo, which
    // asn1crypto serialises with its [0] EXPLICIT tag; plain SignedData
    // (a SEQUENCE) is wrapped here.
    let explicit = if sd.first() == Some(&0xa0) {
        sd.to_vec()
    } else {
        let mut explicit = vec![0xa0];
        explicit.extend(der_len(sd.len()));
        explicit.extend_from_slice(sd);
        explicit
    };
    let mut body = oid.to_vec();
    body.extend(explicit);
    let mut out = vec![0x30];
    out.extend(der_len(body.len()));
    out.extend(body);
    out
}

/// Fetchers that answer from the recorded HTTP exchanges, matching on the
/// URL path (the host of the Certomancer services is ignored).
#[derive(Debug)]
pub struct Replay {
    exchanges: Vec<(String, String, Vec<u8>)>, // (method, path, body)
}

impl Replay {
    pub fn new(http: &Value) -> Self {
        let exchanges = http
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|e| e["status"].as_u64() == Some(200))
                    .map(|e| {
                        (
                            e["method"].as_str().unwrap().to_owned(),
                            e["path"].as_str().unwrap().to_owned(),
                            b64(e["response_body"].as_str().unwrap()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { exchanges }
    }

    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let path = url.split_once("://").map_or(url, |(_, r)| r);
        let path = path.find('/').map_or("/", |i| &path[i..]);
        self.exchanges
            .iter()
            .find(|(_, p, _)| p == path)
            .map(|(_, _, b)| b.clone())
            .ok_or_else(|| {
                FetchError::new(
                    FetchErrorKind::NotFound,
                    format!("no recorded response for {url}"),
                )
            })
    }
}

fn uris_in(cert: &Cert, oid: const_oid::ObjectIdentifier) -> Vec<String> {
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
    match cert.extension::<AuthorityInfoAccessSyntax>() {
        Ok(Some((_, aia))) => aia
            .0
            .iter()
            .filter(|ad| ad.access_method == oid)
            .filter_map(|ad| match &ad.access_location {
                GeneralName::UniformResourceIdentifier(u) => Some(u.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

impl OcspFetcher for Replay {
    fn fetch_ocsp(&self, cert: &Cert, _issuer: &Cert) -> Result<Vec<u8>, FetchError> {
        let ocsp = const_oid::db::rfc5280::ID_AD_OCSP;
        for u in uris_in(cert, ocsp) {
            if let Ok(b) = self.get(&u) {
                return Ok(b);
            }
        }
        Err(FetchError::new(
            FetchErrorKind::NotFound,
            "no recorded OCSP response",
        ))
    }
}

impl CrlFetcher for Replay {
    fn fetch_crls(&self, cert: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
        let mut out = Vec::new();
        if let Some(dps) = cert.crl_distribution_points() {
            for dp in dps.0 {
                if let Some(DistributionPointName::FullName(names)) = dp.distribution_point {
                    for n in names {
                        if let GeneralName::UniformResourceIdentifier(u) = n {
                            if let Ok(b) = self.get(u.as_str()) {
                                out.push(b);
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }
}

impl CertificateFetcher for Replay {
    fn fetch_issuers(&self, cert: &Cert) -> Result<Vec<Cert>, FetchError> {
        let ca_issuers = const_oid::db::rfc5280::ID_AD_CA_ISSUERS;
        let mut out = Vec::new();
        for u in uris_in(cert, ca_issuers) {
            if let Ok(b) = self.get(&u) {
                if let Ok(c) = Cert::from_pem_or_der(&b) {
                    out.push(c);
                }
            }
        }
        Ok(out)
    }
}

/// `DEFAULT_REVINFO_POLICY` of `test_ades_validation.py`.
pub fn default_revinfo_policy() -> CertRevTrustPolicy {
    let mut p = CertRevTrustPolicy::new(REQUIRE_REVINFO);
    p.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
    p
}

/// `DEFAULT_SIG_VALIDATION_SPEC` (trust root: `testing-ca` root) at the
/// recorded time, fetching from the recording.
pub fn default_context(rec: &Recording, call: &Call) -> ValidationContext {
    ValidationContext::builder()
        .trust_root(rec.cert("testing-ca", "root"))
        .revinfo_policy(default_revinfo_policy())
        .moment(call.time())
        .fetchers(call.fetchers())
        .build()
        .unwrap()
}
