//! Exact default-context lifecycle original and genuine context consumers.
//! New leaf/CMS/HTTP CRL/nonce-correlated OCSP signatures are generated natively.
//! The root-issuer CRL and local-policy controls replay explicitly named fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use der::{
    asn1::{Ia5String, OctetString},
    Decode, Encode,
};
use sigis_cms::{SignedData, StandardCmsSignatureStatus, TrustProblem};
use sigis_pades::ades::{
    basic::{basic_validation_with_options, BasicValidationResult, QualificationSpec},
    policy::bootstrap_validation_context,
    AdesValidationOptions,
};
use sigis_pades_sign::{keys::load_private_key_from_pemder_data, sign_general_data, SimpleSigner};
use sigis_pki_certvalidator::{
    authority::{TrustAnchor, TrustManager, TrustQualifiers},
    context::ValidationContextBuilder,
    policy::{
        CertRevTrustPolicy, NonRevokedStatusAssertion, PkixValidationParams,
        RevocationCheckingPolicy, RevocationCheckingRule, ValidationTimingParams,
    },
    revinfo::freshness::{FreshnessJudge, RevinfoUsability, RevinfoUsabilityRating},
    ValidationContext,
};
use sigis_pki_core::{
    algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm},
    asn1::tlv::{encode, Tlv},
    cert::Cert,
    errors::ValidationError,
    fetch::Fetchers,
    key_usage::KeyUsageConstraints,
    time::Moment,
};
use sigis_pki_fetch::{FetchKind, FetchLimits, FetcherSettings, HttpFetchers};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::{
    collections::BTreeSet,
    io::{BufRead, Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, Once,
    },
    thread,
    time::Duration,
};
use x509_cert::ext::{
    pkix::{
        crl::dp::DistributionPoint,
        name::{DistributionPointName, GeneralName},
        AccessDescription, AuthorityInfoAccessSyntax, CrlDistributionPoints,
    },
    Extension,
};

const TIME: &str = "2020-11-20T00:00:00Z";
const CONTENT: &[u8] = b"Fetching-enabled context retains ownership and validation requirements";
fn at(s: &str) -> Moment {
    Moment::parse_rfc3339(s).unwrap()
}
fn sha(b: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(b)
        .iter()
        .map(|n| format!("{n:02x}"))
        .collect()
}
fn read(p: &Path) -> Vec<u8> {
    let b = std::fs::read(p).unwrap();
    eprintln!(
        "CONTEXT_DEFAULT_INPUT {}",
        serde_json::json!({"path":p.canonicalize().unwrap(),"length":b.len(),"sha256":sha(&b)})
    );
    b
}
fn data(parts: &[&str]) -> PathBuf {
    sigis_testdata::path(parts)
}
fn runtime_identity() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {let p=std::env::current_exe().unwrap();let b=std::fs::read(&p).unwrap();let source=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/round3_context_default_backend.rs"));eprintln!("CONTEXT_DEFAULT_EXECUTABLE {}",serde_json::json!({"path":p.canonicalize().unwrap(),"length":b.len(),"sha256":sha(&b),"test_source_sha256":sha(source)}));});
}
struct Pki {
    directory: PathBuf,
    manifest: serde_json::Value,
}
impl Pki {
    fn new() -> Self {
        runtime_identity();
        let directory = data(&["lanes", "d", "pki", "testing-ca"]);
        let manifest = serde_json::from_slice(&read(&directory.join("manifest.json"))).unwrap();
        Self {
            directory,
            manifest,
        }
    }
    fn cert(&self, name: &str) -> Cert {
        Cert::from_der(&read(
            &self
                .directory
                .join(self.manifest["certs"][name]["file"].as_str().unwrap()),
        ))
        .unwrap()
    }
    fn key_bytes(&self, name: &str) -> (Vec<u8>, Option<String>) {
        let key = self.manifest["certs"][name]["subject_key"]
            .as_str()
            .unwrap();
        let e = &self.manifest["keys"][key];
        (
            read(&data(&["pyhanko", "crypto", e["path"].as_str().unwrap()])),
            e["password"].as_str().map(str::to_owned),
        )
    }
    fn key(&self, name: &str) -> sigis_pades_sign::keys::PrivateKey {
        let (b, p) = self.key_bytes(name);
        load_private_key_from_pemder_data(&b, p.as_deref().map(str::as_bytes)).unwrap()
    }
    fn openssl_key(&self, name: &str) -> openssl::pkey::PKey<openssl::pkey::Private> {
        let (b, p) = self.key_bytes(name);
        match p {
            Some(p) => {
                openssl::pkey::PKey::private_key_from_pem_passphrase(&b, p.as_bytes()).unwrap()
            }
            None => openssl::pkey::PKey::private_key_from_pem(&b).unwrap(),
        }
    }
    fn cms(&self, leaf: &Cert) -> Vec<u8> {
        let signer = SimpleSigner::new(self.key("signer1"), leaf.clone(), vec![]).unwrap();
        sign_general_data(CONTENT, &signer, DigestAlgorithm::Sha256, true, None).unwrap()
    }
}
fn evidence(file: &str) -> Vec<u8> {
    read(&data(&[
        "lanes",
        "d",
        "revinfo",
        "testing-ca",
        "2020-11-20",
        file,
    ]))
}
fn seq(fields: &[Vec<u8>]) -> Vec<u8> {
    encode(0x30, &fields.concat())
}
fn fields(bytes: &[u8]) -> Vec<Vec<u8>> {
    Tlv::parse_exact(bytes)
        .unwrap()
        .children()
        .unwrap()
        .iter()
        .map(|v| v.raw.to_vec())
        .collect()
}
fn signature_algorithm() -> Vec<u8> {
    AlgorithmIdentifierOwned {
        oid: "1.2.840.113549.1.1.11".parse().unwrap(),
        parameters: Some(der::asn1::Null.into()),
    }
    .to_der()
    .unwrap()
}
fn sign_tbs(tbs: &[u8], key: &openssl::pkey::PKey<openssl::pkey::Private>) -> Vec<u8> {
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), key).unwrap();
    signer.update(tbs).unwrap();
    signer.sign_to_vec().unwrap()
}

// Use the mature certificate types and actual fixture CA key to change only
// signed distribution locations. Preserve serial/key/subject/validity/usages.
fn network_leaf(pki: &Pki, base: &str, suffix: &str) -> Cert {
    let original = pki.cert("signer1");
    let parsed = x509_cert::Certificate::from_der(original.der()).unwrap();
    let uri = |s: &str| GeneralName::UniformResourceIdentifier(Ia5String::new(s).unwrap());
    let aia = AuthorityInfoAccessSyntax(vec![
        AccessDescription {
            access_method: "1.3.6.1.5.5.7.48.2".parse().unwrap(),
            access_location: uri(&format!("{base}/issuer/{suffix}")),
        },
        AccessDescription {
            access_method: "1.3.6.1.5.5.7.48.1".parse().unwrap(),
            access_location: uri(&format!("{base}/ocsp")),
        },
    ]);
    let dps = CrlDistributionPoints(vec![DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(vec![uri(&format!(
            "{base}/crl"
        ))])),
        reasons: None,
        crl_issuer: None,
    }]);
    let mut extensions = parsed.tbs_certificate().extensions().unwrap().clone();
    extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    for (oid, value) in [
        ("1.3.6.1.5.5.7.1.1", aia.to_der().unwrap()),
        ("2.5.29.31", dps.to_der().unwrap()),
    ] {
        extensions.push(Extension {
            extn_id: oid.parse().unwrap(),
            critical: false,
            extn_value: OctetString::new(value).unwrap(),
        });
    }
    let old = openssl::x509::X509::from_der(original.der()).unwrap();
    let mut b = openssl::x509::X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(old.serial_number()).unwrap();
    b.set_subject_name(old.subject_name()).unwrap();
    b.set_issuer_name(old.issuer_name()).unwrap();
    b.set_not_before(old.not_before()).unwrap();
    b.set_not_after(old.not_after()).unwrap();
    b.set_pubkey(&old.public_key().unwrap()).unwrap();
    for e in extensions {
        b.append_extension(
            openssl::x509::X509Extension::new_from_der(
                &openssl::asn1::Asn1Object::from_str(&e.extn_id.to_string()).unwrap(),
                e.critical,
                &openssl::asn1::Asn1OctetString::new_from_bytes(e.extn_value.as_bytes()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    }
    b.sign(
        &pki.openssl_key("interm"),
        openssl::hash::MessageDigest::sha256(),
    )
    .unwrap();
    Cert::from_der(&b.build().to_der().unwrap()).unwrap()
}

fn fresh_crl(pki: &Pki) -> Vec<u8> {
    let mut outer = fields(&evidence("crl-interm.der"));
    let mut tbs = fields(&outer[0]);
    for item in &mut tbs {
        let t = Tlv::parse_exact(item).unwrap();
        if t.is_context(0) {
            let mut exts = fields(t.value);
            exts.retain(|e| {
                let f = fields(e);
                let oid: const_oid::ObjectIdentifier = der::Decode::from_der(&f[0]).unwrap();
                oid.to_string() != "2.5.29.28"
            });
            *item = encode(0xa0, &seq(&exts));
        }
    }
    outer[0] = seq(&tbs);
    outer[1] = signature_algorithm();
    let mut signature = vec![0];
    signature.extend(sign_tbs(&outer[0], &pki.openssl_key("interm")));
    outer[2] = encode(3, &signature);
    seq(&outer)
}
// Actual request CertID and nonce extensions are copied exactly, then the full
// ResponseData is freshly signed by the actual certificate issuer. No old token
// signature is reused or exempted. The production nonce/CMS/CV checks all run.
fn ocsp_for_request(pki: &Pki, request: &[u8]) -> Vec<u8> {
    let outer = fields(request);
    let tbs = fields(&outer[0]);
    let list = tbs
        .iter()
        .find(|b| Tlv::parse_exact(b).unwrap().is_universal(16))
        .unwrap();
    let requests = fields(list);
    assert_eq!(requests.len(), 1);
    let req = fields(&requests[0]);
    let cert_id = req[0].clone();
    let extensions = tbs
        .iter()
        .find(|b| Tlv::parse_exact(b).unwrap().is_context(2))
        .expect("default HTTP request includes nonce");
    let request_extensions = Tlv::parse_exact(extensions).unwrap();
    let ext_seq = fields(request_extensions.value);
    assert_eq!(ext_seq.len(), 1);
    let nonce_ext = fields(&ext_seq[0]);
    let nonce_oid: const_oid::ObjectIdentifier = der::Decode::from_der(&nonce_ext[0]).unwrap();
    assert_eq!(nonce_oid.to_string(), "1.3.6.1.5.5.7.48.1.2");
    let nonce = OctetString::from_der(&nonce_ext[1]).unwrap();
    let nonce = OctetString::from_der(nonce.as_bytes()).unwrap();
    assert_eq!(nonce.as_bytes().len(), 16);
    let time = encode(0x18, b"20201120000000Z");
    let next = encode(0xa0, &encode(0x18, b"20201121000000Z"));
    let single = seq(&[cert_id, encode(0x80, &[]), time.clone(), next]);
    let response_data = seq(&[
        encode(0xa1, &pki.cert("interm").subject_der().unwrap()),
        time,
        seq(&[single]),
        encode(0xa1, request_extensions.value),
    ]);
    let mut sig = vec![0];
    sig.extend(sign_tbs(&response_data, &pki.openssl_key("interm")));
    let basic = seq(&[response_data, signature_algorithm(), encode(3, &sig)]);
    seq(&[
        encode(0x0a, &[0]),
        encode(
            0xa0,
            &seq(&[
                "1.3.6.1.5.5.7.48.1.1"
                    .parse::<const_oid::ObjectIdentifier>()
                    .unwrap()
                    .to_der()
                    .unwrap(),
                encode(4, &basic),
            ]),
        ),
    ])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplyMode {
    Good,
    Missing,
    Malformed,
    ForgedCrl,
    ForgedOcsp,
}
struct Server {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    connections: Arc<AtomicUsize>,
    timeouts: Arc<AtomicUsize>,
    responses: Arc<Mutex<Vec<Vec<u8>>>>,
    crl_responses: Arc<Mutex<Vec<Vec<u8>>>>,
    stopped: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    issuer: Cert,
}
impl Server {
    fn new(mode: ReplyMode) -> Self {
        let pki = Pki::new();
        let issuer = pki.cert("interm");
        let crl = fresh_crl(&pki);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(vec![]));
        let connections = Arc::new(AtomicUsize::new(0));
        let timeouts = Arc::new(AtomicUsize::new(0));
        let responses = Arc::new(Mutex::new(vec![]));
        let crl_responses = Arc::new(Mutex::new(vec![]));
        let stopped = Arc::new(AtomicBool::new(false));
        let worker = thread::spawn({
            let requests = requests.clone();
            let connections = connections.clone();
            let timeouts = timeouts.clone();
            let responses = responses.clone();
            let crl_responses = crl_responses.clone();
            let stopped = stopped.clone();
            let crl = crl.clone();
            let issuer = issuer.clone();
            move || {
                while !stopped.load(Ordering::SeqCst) {
                    let (stream, _) = match listener.accept() {
                        Ok(v) => v,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(3));
                            continue;
                        }
                        Err(e) => panic!("accept: {e}"),
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut reader = std::io::BufReader::new(stream);
                    loop {
                        if stopped.load(Ordering::SeqCst) {
                            return;
                        }
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                                ) =>
                            {
                                if !stopped.load(Ordering::SeqCst) {
                                    timeouts.fetch_add(1, Ordering::SeqCst);
                                }
                                break;
                            }
                            Err(e) => panic!("read:{e}"),
                        };
                        let first = line.trim().to_owned();
                        let mut wire = line.as_bytes().to_vec();
                        let mut size = 0;
                        loop {
                            line.clear();
                            assert!(reader.read_line(&mut line).unwrap() > 0);
                            wire.extend_from_slice(line.as_bytes());
                            if line == "\r\n" {
                                break;
                            }
                            if let Some(v) =
                                line.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                size = v.trim().parse::<usize>().unwrap();
                            }
                            assert!(wire.len() < 16384);
                        }
                        assert!(size < 16384);
                        let mut request = vec![0; size];
                        reader.read_exact(&mut request).unwrap();
                        wire.extend_from_slice(&request);
                        let path = first.split_whitespace().nth(1).unwrap();
                        let is_ocsp = path == "/ocsp";
                        let (mut body, mime) = if path.starts_with("/issuer/") {
                            (issuer.der().to_vec(), "application/pkix-cert")
                        } else if path == "/crl" {
                            (crl.clone(), "application/pkix-crl")
                        } else {
                            assert!(is_ocsp, "{first}");
                            assert!(first.starts_with("POST "));
                            (
                                ocsp_for_request(&pki, &request),
                                "application/ocsp-response",
                            )
                        };
                        let mut status = "200 OK";
                        if mode == ReplyMode::Missing && !path.starts_with("/issuer/") {
                            body.clear();
                            status = "404 Missing";
                        }
                        if mode == ReplyMode::Malformed && !path.starts_with("/issuer/") {
                            body = b"malformed signed evidence".to_vec();
                        }
                        if (mode == ReplyMode::ForgedCrl && path == "/crl")
                            || (mode == ReplyMode::ForgedOcsp && is_ocsp)
                        {
                            *body.last_mut().unwrap() ^= 1;
                        }
                        requests.lock().unwrap().push(first.clone());
                        if status == "200 OK" {
                            if is_ocsp {
                                responses.lock().unwrap().push(body.clone());
                            } else if path == "/crl" {
                                crl_responses.lock().unwrap().push(body.clone());
                            }
                        }
                        let mut response=format!("HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",body.len()).into_bytes();
                        response.extend_from_slice(&body);
                        reader.get_mut().write_all(&response).unwrap();
                        reader.get_mut().flush().unwrap();
                        eprintln!(
                            "CONTEXT_DEFAULT_HTTP_EXCHANGE {}",
                            serde_json::json!({"request":first,"request_b64":openssl::base64::encode_block(&wire),"request_length":wire.len(),"request_sha256":sha(&wire),"response_b64":openssl::base64::encode_block(&response),"response_length":response.len(),"response_sha256":sha(&response),"body_sha256":sha(&body),"body_length":body.len(),"connection":connections.load(Ordering::SeqCst),"mode":format!("{mode:?}")})
                        );
                    }
                }
            }
        });
        Self {
            address,
            requests,
            connections,
            timeouts,
            responses,
            crl_responses,
            stopped,
            worker: Some(worker),
            issuer,
        }
    }
    fn base(&self) -> String {
        format!("http://{}", self.address)
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn builder(pki: &Pki, roots: bool) -> ValidationContextBuilder {
    let b = ValidationContext::builder()
        .moment(at(TIME))
        .point_in_time_validation(false);
    if roots {
        b.trust_root(pki.cert("root"))
    } else {
        b
    }
}
fn both_policy() -> CertRevTrustPolicy {
    CertRevTrustPolicy::new(RevocationCheckingPolicy {
        ee_certificate_rule: RevocationCheckingRule::CrlAndOcspRequired,
        intermediate_ca_cert_rule: RevocationCheckingRule::CrlRequired,
    })
}
fn local(pki: &Pki) -> ValidationContextBuilder {
    builder(pki, true)
        .other_cert(pki.cert("interm"))
        .crl(evidence("crl-root.der"))
        .crl(evidence("crl-interm.der"))
        .ocsp_response(evidence("ocsp-signer1.der"))
        .revocation_mode("require")
        .fetchers(Fetchers::none())
}
fn trusted(r: &BasicValidationResult) -> bool {
    r.api_status
        .as_ref()
        .is_some_and(|s| s.signature.trusted() && s.bottom_line())
}
fn intact_valid(r: &BasicValidationResult) {
    let s = r.api_status.as_ref().unwrap();
    assert!(s.signature.intact && s.signature.valid);
}
fn validate(
    bytes: &[u8],
    ctx: &ValidationContext,
    options: &AdesValidationOptions,
) -> BasicValidationResult {
    basic_validation_with_options(
        bytes,
        Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
        ctx,
        &QualificationSpec::default(),
        options,
    )
    .unwrap()
}
fn export(
    label: &str,
    bytes: &[u8],
    ctx: &ValidationContext,
    server: Option<&Server>,
    r: &BasicValidationResult,
) {
    let Some(dir) = std::env::var_os("HANKO_CONTEXT_DEFAULT_OUTPUT_DIR") else {
        return;
    };
    let certs: Vec<Vec<u8>> = ctx
        .other_certs()
        .iter()
        .map(|c| c.der().to_vec())
        .chain(server.map(|s| s.issuer.der().to_vec()))
        .collect();
    let mut crls: Vec<Vec<u8>> = ctx.crls().map(<[u8]>::to_vec).collect();
    if let Some(server) = server {
        crls.extend(server.crl_responses.lock().unwrap().clone());
    }
    let mut ocsps: Vec<Vec<u8>> = ctx.ocsps().map(<[u8]>::to_vec).collect();
    if let Some(server) = server {
        ocsps.extend(server.responses.lock().unwrap().clone());
    }
    let b64 = |v: Vec<Vec<u8>>| {
        v.iter()
            .map(|b| openssl::base64::encode_block(b))
            .collect::<Vec<_>>()
    };
    let s = r.api_status.as_ref();
    let policy = ctx.revinfo_policy().revocation_checking_policy;
    let row = serde_json::json!({"label":label,"cms_b64":openssl::base64::encode_block(bytes),"cms_sha256":sha(bytes),"content_b64":openssl::base64::encode_block(CONTENT),"content_sha256":sha(CONTENT),"roots_b64":b64(ctx.trust_anchors().iter().map(|a|a.cert().der().to_vec()).collect()),"other_certs_b64":b64(certs),"crls_b64":b64(crls),"ocsps_b64":b64(ocsps),"time":ctx.moment().to_string(),"best_signature_time":ctx.best_signature_time().to_string(),"point_in_time_validation":ctx.timing().point_in_time_validation,"time_tolerance_seconds":ctx.timing().time_tolerance.as_secs(),"revocation_policy":{"ee":policy.ee_certificate_rule.value(),"ca":policy.intermediate_ca_cert_rule.value()},"native":{"intact":s.map(|s|s.signature.intact),"valid":s.map(|s|s.signature.valid),"trusted":s.map(|s|s.signature.trusted()),"bottom_line":s.map(StandardCmsSignatureStatus::bottom_line),"subindication":r.ades_subindic.standard_name(),"trust_problem":s.map(|s|format!("{:?}",s.signature.trust_problem))},"evidence_origin":if server.is_some(){"native new leaf/CMS; arrays contain exact local and actually served candidate bytes, including forged/malformed 200 bodies; HTTP receipts identify transport errors; offline oracle is separate"}else{"explicit local committed fixture replay"}});
    let b = serde_json::to_vec_pretty(&row).unwrap();
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(format!("{label}-{}.json", sha(&b)));
    std::fs::write(&p, &b).unwrap();
    eprintln!(
        "CONTEXT_DEFAULT_NATIVE_CASE {}",
        serde_json::json!({"path":p,"length":b.len(),"sha256":sha(&b)})
    );
}

#[test]
fn test_context_provisions_and_owns_a_backend() {
    // Exact original: fetching-enabled construction with empty explicit roots,
    // real default backend components, and two harmless explicit close calls.
    let empty = bootstrap_validation_context(ValidationContext::builder()).unwrap();
    assert!(empty.trust_anchors().is_empty());
    assert!(empty.fetchers().cert.is_some());
    assert!(empty.fetchers().crl.is_some());
    assert!(empty.fetchers().ocsp.is_some());
    empty.close().unwrap();
    empty.close().unwrap();
    let pki = Pki::new();
    let server = Server::new(ReplyMode::Good);
    let leaf = network_leaf(&pki, &server.base(), "first");
    let bytes = pki.cms(&leaf);
    let ctx = bootstrap_validation_context(
        builder(&pki, true)
            .crl(evidence("crl-root.der"))
            .revinfo_policy(both_policy()),
    )
    .unwrap();
    let result = validate(&bytes, &ctx, &Default::default());
    intact_valid(&result);
    assert!(trusted(&result), "{result:?}");
    assert_eq!(result.ades_subindic.standard_name(), "OK");
    let paths = server.requests.lock().unwrap().clone();
    assert!(paths.iter().any(|p| p.starts_with("GET /issuer/")));
    assert!(paths.iter().any(|p| p.starts_with("GET /crl ")));
    assert!(paths.iter().any(|p| p.starts_with("POST /ocsp ")));
    assert_eq!(paths.len(), 3);
    export(
        "default-http-required-positive",
        &bytes,
        &ctx,
        Some(&server),
        &result,
    );
    let outer_error = basic_validation_with_options(
        b"not DER",
        Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
        &ctx,
        &QualificationSpec::default(),
        &Default::default(),
    )
    .unwrap_err();
    match outer_error {
        sigis_pki_core::errors::HankoError::Malformed(message) => {
            assert!(!message.is_empty());
            eprintln!(
                "CONTEXT_DEFAULT_OUTER_ERROR {}",
                serde_json::json!({"class":"Malformed","message":message,"context_still_owned_by_caller":true})
            );
        }
        other => panic!("wrong outer malformed-CMS error class: {other:?}"),
    }
    // The same caller-held context remains explicitly closeable and its actual
    // issued caches still validate the original after the genuine outer Err.
    ctx.close().unwrap();
    let after = validate(&bytes, &ctx, &Default::default());
    assert!(trusted(&after));
    assert_eq!(
        server.count(),
        3,
        "issued successful issuer/CRL/OCSP caches survive close"
    );
    ctx.close().unwrap();
    let second = network_leaf(&pki, &server.base(), "second");
    let next = pki.cms(&second);
    let result = validate(&next, &ctx, &Default::default());
    assert!(trusted(&result), "{result:?}");
    assert_eq!(
        server.count(),
        4,
        "new URL needs issuer retrieval while serial-bound CRL/OCSP remain cached"
    );
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        2,
        "context close releases exact real managed session"
    );
    assert_eq!(
        server.timeouts.load(Ordering::SeqCst),
        0,
        "server eviction cannot explain reconnect"
    );
    ctx.close().unwrap();
    ctx.close().unwrap();
    eprintln!(
        "CONTEXT_DEFAULT_LIFECYCLE {}",
        serde_json::json!({"first_requests":3,"cached_after_close_requests":3,"new_url_requests":server.count(),"connections":server.connections.load(Ordering::SeqCst),"timeouts":server.timeouts.load(Ordering::SeqCst),"close_calls":4})
    );
}

#[test]
fn fetched_forged_missing_malformed_and_wrong_root_evidence_cannot_grant_trust() {
    let pki = Pki::new();
    for mode in [
        ReplyMode::Missing,
        ReplyMode::Malformed,
        ReplyMode::ForgedCrl,
        ReplyMode::ForgedOcsp,
    ] {
        let server = Server::new(mode);
        let leaf = network_leaf(&pki, &server.base(), "negative");
        let bytes = pki.cms(&leaf);
        let ctx = bootstrap_validation_context(
            builder(&pki, true)
                .crl(evidence("crl-root.der"))
                .revinfo_policy(both_policy()),
        )
        .unwrap();
        let r = validate(&bytes, &ctx, &Default::default());
        intact_valid(&r);
        assert!(!trusted(&r), "{mode:?}: {r:?}");
        assert!(server.count() >= 2);
        export(
            &format!("http-negative-{mode:?}"),
            &bytes,
            &ctx,
            Some(&server),
            &r,
        );
        ctx.close().unwrap();
        let count = server.count();
        let r = validate(&bytes, &ctx, &Default::default());
        assert!(!trusted(&r));
        assert_eq!(
            server.count(),
            count,
            "issued failure responses/errors survive close"
        );
        ctx.close().unwrap();
    }
    let server = Server::new(ReplyMode::Good);
    let leaf = network_leaf(&pki, &server.base(), "wrong-root");
    let bytes = pki.cms(&leaf);
    // This is an UNTRUSTED candidate, never a trust anchor. Knowing it
    // prevents the fixture intermediate's original external AIA from being used;
    // the leaf's actual issuer still comes from our real loopback HTTP provider.
    let untrusted_root = pki.cert("root");
    assert!(sigis_pki_fetch::common::gather_aia_issuer_urls(&untrusted_root).is_empty());
    let ctx = bootstrap_validation_context(
        builder(&pki, false)
            .other_cert(untrusted_root)
            .revocation_mode("none"),
    )
    .unwrap();
    assert!(ctx.trust_anchors().is_empty());
    let r = validate(&bytes, &ctx, &Default::default());
    intact_valid(&r);
    assert!(!trusted(&r));
    assert_eq!(
        server.count(),
        1,
        "only the loopback leaf issuer was retrieved"
    );
    export("default-empty-roots", &bytes, &ctx, Some(&server), &r);
    ctx.close().unwrap();
    let parsed = SignedData::from_der(&bytes).unwrap();
    let sig = &parsed.signer_infos[0].signature;
    let pos = bytes.windows(sig.len()).position(|p| p == sig).unwrap();
    let mut bad = bytes.clone();
    bad[pos] ^= 1;
    let ctx = bootstrap_validation_context(builder(&pki, true).revocation_mode("none")).unwrap();
    let r = validate(&bad, &ctx, &Default::default());
    assert!(!r.api_status.as_ref().unwrap().signature.valid);
    assert!(!trusted(&r));
    export("default-cms-signature-forged", &bad, &ctx, None, &r);
    ctx.close().unwrap();
}

#[test]
fn independent_default_contexts_have_independent_pools_and_issued_caches() {
    let pki = Pki::new();
    let server = Server::new(ReplyMode::Good);
    let leaf = network_leaf(&pki, &server.base(), "independent");
    let bytes = pki.cms(&leaf);
    let a = bootstrap_validation_context(builder(&pki, true).revocation_mode("none")).unwrap();
    let b = bootstrap_validation_context(builder(&pki, true).revocation_mode("none")).unwrap();
    assert!(!Arc::ptr_eq(
        a.fetchers().cert.as_ref().unwrap(),
        b.fetchers().cert.as_ref().unwrap()
    ));
    assert!(trusted(&validate(&bytes, &a, &Default::default())));
    a.close().unwrap();
    assert!(trusted(&validate(&bytes, &b, &Default::default())));
    assert_eq!(server.count(), 2);
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
    b.close().unwrap();
    assert!(trusted(&validate(&bytes, &a, &Default::default())));
    assert_eq!(
        server.count(),
        2,
        "first issued cache remains independent and retained"
    );
    a.close().unwrap();
}

#[derive(Debug)]
struct DenyAtBest {
    at: Moment,
    cutoff: Option<Moment>,
}
impl AlgorithmUsagePolicy for DenyAtBest {
    fn digest_algorithm_allowed(
        &self,
        _: &const_oid::ObjectIdentifier,
        time: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        if time == Some(self.at) {
            AlgorithmUsageConstraint {
                allowed: false,
                not_allowed_after: self.cutoff,
                failure_reason: Some("context-default exact caller-clock rejection".into()),
            }
        } else {
            AlgorithmUsageConstraint::allowed()
        }
    }
    fn signature_algorithm_allowed(
        &self,
        _: &AlgorithmIdentifierOwned,
        _: Option<Moment>,
        _: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::allowed()
    }
}
#[derive(Debug)]
struct RejectFreshness(Arc<AtomicUsize>);
impl FreshnessJudge for RejectFreshness {
    fn judge(
        &self,
        _: Option<Moment>,
        _: Option<Moment>,
        _: &CertRevTrustPolicy,
        _: &ValidationTimingParams,
    ) -> RevinfoUsability {
        self.0.fetch_add(1, Ordering::SeqCst);
        RevinfoUsability {
            rating: RevinfoUsabilityRating::Stale,
            last_usable_at: None,
            compared_to: None,
        }
    }
}
#[derive(Debug)]
struct OneRoot {
    root: TrustAnchor,
    calls: AtomicUsize,
}
impl TrustManager for OneRoot {
    fn as_trust_anchor(&self, cert: &Cert) -> Option<TrustAnchor> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.root.cert() == cert).then(|| self.root.clone())
    }
    fn find_potential_issuers(&self, _: &Cert) -> Vec<TrustAnchor> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        vec![self.root.clone()]
    }
}

#[test]
fn caller_clock_tolerance_algorithm_freshness_and_assertions_remain_effective() {
    let pki = Pki::new();
    let leaf = pki.cert("signer1");
    let bytes = pki.cms(&leaf);
    let positive = bootstrap_validation_context(local(&pki)).unwrap();
    assert!(
        positive.fetchers().is_empty(),
        "explicit empty suppresses real default construction"
    );
    let r = validate(&bytes, &positive, &Default::default());
    assert!(trusted(&r));
    export("explicit-local-positive", &bytes, &positive, None, &r);
    positive.close().unwrap();
    for cutoff in [None, Some(at("2020-11-19T00:00:00Z"))] {
        let policy = Arc::new(DenyAtBest {
            at: at("2020-11-19T01:02:03Z"),
            cutoff,
        });
        let erased: Arc<dyn AlgorithmUsagePolicy> = policy;
        let ctx = bootstrap_validation_context(
            local(&pki)
                .algorithm_policy(erased.clone())
                .best_signature_time(at("2020-11-19T01:02:03Z"))
                .time_tolerance(Duration::from_secs(71)),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&erased, &ctx.algorithm_policy_arc()));
        assert_eq!(ctx.timing().time_tolerance, Duration::from_secs(71));
        assert_eq!(ctx.best_signature_time(), at("2020-11-19T01:02:03Z"));
        let before = format!("{ctx:?}");
        let r = validate(&bytes, &ctx, &Default::default());
        intact_valid(&r);
        assert!(!trusted(&r));
        let status = r.api_status.as_ref().unwrap();
        assert_eq!(status.signature.error_time_horizon, cutoff);
        assert!(
            matches!(&status.signature.trust_problem,Some(TrustProblem::Path(ValidationError::DisallowedAlgorithm{banned_since,..}))if banned_since.as_ref()==cutoff.as_ref())
        );
        assert_eq!(before, format!("{ctx:?}"));
        ctx.close().unwrap();
    }
    let seen = Arc::new(AtomicUsize::new(0));
    let ctx = bootstrap_validation_context(
        local(&pki).freshness_judge(Arc::new(RejectFreshness(seen.clone()))),
    )
    .unwrap();
    let r = validate(&bytes, &ctx, &Default::default());
    assert!(!trusted(&r));
    assert!(seen.load(Ordering::SeqCst) > 0);
    ctx.close().unwrap();
    let beyond = leaf.not_after().plus(Duration::from_secs(2));
    for (seconds, allow) in [(0, false), (3, true)] {
        let ctx = bootstrap_validation_context(
            builder(&pki, true)
                .other_cert(pki.cert("interm"))
                .moment(beyond)
                .point_in_time_validation(false)
                .time_tolerance(Duration::from_secs(seconds))
                .revocation_mode("none")
                .fetchers(Fetchers::none()),
        )
        .unwrap();
        let r = validate(&bytes, &ctx, &Default::default());
        intact_valid(&r);
        assert_eq!(
            trusted(&r),
            allow,
            "actual duplicate validity tolerance:{r:?}"
        );
        ctx.close().unwrap();
    }
    for (digest, time, allow) in [
        (leaf.sha256(), at(TIME), true),
        (leaf.sha256(), at("2020-11-19T00:00:00Z"), false),
        ([0; 32], at(TIME), false),
    ] {
        let assertion = NonRevokedStatusAssertion {
            cert_sha256: digest,
            at: time,
        };
        let ctx = bootstrap_validation_context(
            builder(&pki, true)
                .other_cert(pki.cert("interm"))
                .crl(evidence("crl-root.der"))
                .revocation_mode("require")
                .fetchers(Fetchers::none())
                .assertion(assertion.clone()),
        )
        .unwrap();
        assert_eq!(ctx.non_revoked_status_assertions(), &[assertion]);
        let r = validate(&bytes, &ctx, &Default::default());
        intact_valid(&r);
        assert_eq!(trusted(&r), allow, "assertion exact digest/time:{r:?}");
        ctx.close().unwrap();
    }
}

#[test]
fn actual_trust_manager_anchor_qualifiers_pkix_and_qualification_are_not_dropped() {
    let pki = Pki::new();
    let bytes = pki.cms(&pki.cert("signer1"));
    let manager = Arc::new(OneRoot {
        root: TrustAnchor::new(pki.cert("root")),
        calls: AtomicUsize::new(0),
    });
    let erased: Arc<dyn TrustManager> = manager.clone();
    let ctx = bootstrap_validation_context(
        builder(&pki, false)
            .trust_manager(erased.clone())
            .other_cert(pki.cert("interm"))
            .revocation_mode("none")
            .fetchers(Fetchers::none()),
    )
    .unwrap();
    assert!(Arc::ptr_eq(ctx.trust_manager().unwrap(), &erased));
    let r = validate(&bytes, &ctx, &Default::default());
    assert!(trusted(&r));
    assert!(manager.calls.load(Ordering::SeqCst) > 0);
    let required = QualificationSpec {
        requirements: Some(Default::default()),
        ..Default::default()
    };
    let result = basic_validation_with_options(
        &bytes,
        Some(&DigestAlgorithm::Sha256.digest(CONTENT)),
        &ctx,
        &required,
        &Default::default(),
    )
    .unwrap();
    assert_ne!(result.ades_subindic.standard_name(), "OK");
    ctx.close().unwrap();
    for quals in [
        TrustQualifiers {
            max_path_length: Some(0),
            ..Default::default()
        },
        TrustQualifiers {
            valid_until: Some(at("2020-11-19T00:00:00Z")),
            ..Default::default()
        },
        TrustQualifiers {
            standard_parameters: Some(PkixValidationParams {
                initial_explicit_policy: true,
                user_initial_policy_constraint: Some(BTreeSet::new()),
                ..Default::default()
            }),
            ..Default::default()
        },
    ] {
        let anchor = TrustAnchor::with_qualifiers(pki.cert("root"), quals.clone());
        let ctx = bootstrap_validation_context(
            ValidationContext::builder()
                .trust_anchor(anchor.clone())
                .other_cert(pki.cert("interm"))
                .moment(at(TIME))
                .point_in_time_validation(false)
                .revocation_mode("none")
                .fetchers(Fetchers::none()),
        )
        .unwrap();
        assert_eq!(ctx.trust_anchors(), &[anchor]);
        let r = validate(&bytes, &ctx, &Default::default());
        intact_valid(&r);
        assert!(
            !trusted(&r),
            "actual anchor/PKIX restriction:{quals:?} {r:?}"
        );
        ctx.close().unwrap();
    }
    let ctx = bootstrap_validation_context(
        builder(&pki, true)
            .other_cert(pki.cert("interm"))
            .revocation_mode("none")
            .fetchers(Fetchers::none()),
    )
    .unwrap();
    assert!(trusted(&validate(&bytes, &ctx, &Default::default())));
    ctx.close().unwrap();
}

#[test]
fn actual_targeted_ac_consumes_preserved_target_restrictions() {
    use sigis_pki_certvalidator::ac::{validate_ac, AcTargetDescription};
    use std::str::FromStr;
    let aa = |parts: &[&str]| {
        let mut full = vec!["attribute-certs", "basic-aa"];
        full.extend_from_slice(parts);
        read(&sigis_testdata::certvalidator(&full))
    };
    let cert = |parts: &[&str]| Cert::from_pem_or_der(&aa(parts)).unwrap();
    let ac = aa(&["aa", "alice-norev-targeted.attr.crt"]);
    for (name, allow) in [
        (
            "CN=Validator,OU=Validators,O=Testing Attribute Authority,C=XX",
            true,
        ),
        (
            "CN=Not Validator,OU=Validators,O=Testing Attribute Authority,C=XX",
            false,
        ),
    ] {
        let ctx = bootstrap_validation_context(
            ValidationContext::builder()
                .trust_root(cert(&["root", "root.crt"]))
                .other_cert(cert(&["root", "interm-unrestricted.crt"]))
                .other_cert(cert(&["interm", "aa-unrestricted.crt"]))
                .moment(at("2022-05-01T00:00:00Z"))
                .revocation_mode("none")
                .acceptable_ac_targets(AcTargetDescription {
                    validator_names: vec![GeneralName::DirectoryName(
                        x509_cert::name::Name::from_str(name).unwrap(),
                    )],
                    group_memberships: vec![],
                })
                .fetchers(Fetchers::none()),
        )
        .unwrap();
        let result = validate_ac(&ctx, &ac, None);
        if allow {
            let r = result.unwrap();
            assert_eq!(r.aa_path.len(), 3);
            assert!(r.approved_attributes.contains_key("role"));
        } else {
            let e = result.unwrap_err();
            assert!(e.is_instance_of("InvalidCertificateError"));
            assert!(e.to_string().contains("AC targeting"));
        }
        ctx.close().unwrap();
    }
}

#[test]
fn explicit_adopted_shared_view_budget_and_caches_survive_context_close() {
    let pki = Pki::new();
    let server = Server::new(ReplyMode::Good);
    let first = network_leaf(&pki, &server.base(), "budget-one");
    let second = network_leaf(&pki, &server.base(), "budget-two");
    let backend = Arc::new(HttpFetchers::new(FetcherSettings {
        limits: FetchLimits {
            max_requests: Some(1),
            ..Default::default()
        },
        ..Default::default()
    }));
    let supplied = backend.as_fetchers();
    let ctx = bootstrap_validation_context(
        builder(&pki, true)
            .revocation_mode("none")
            .fetchers(supplied.clone())
            .owned_fetcher_backend(backend.clone()),
    )
    .unwrap();
    assert!(Arc::ptr_eq(
        ctx.fetchers().cert.as_ref().unwrap(),
        supplied.cert.as_ref().unwrap()
    ));
    let bytes = pki.cms(&first);
    assert!(trusted(&validate(&bytes, &ctx, &Default::default())));
    assert_eq!(server.count(), 1);
    assert_eq!(
        backend.budget().charge(FetchKind::Cert).unwrap_err().kind,
        FetchKind::Cert
    );
    ctx.close().unwrap();
    assert!(trusted(&validate(&bytes, &ctx, &Default::default())));
    assert_eq!(server.count(), 1);
    assert!(
        backend.budget().charge(FetchKind::Cert).is_err(),
        "closing the exact adopted pool never refills issued request budget"
    );
    let other = pki.cms(&second);
    let r = validate(&other, &ctx, &Default::default());
    intact_valid(&r);
    assert!(!trusted(&r));
    assert_eq!(server.count(), 1);
    ctx.close().unwrap();
}

fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}
#[test]
fn all_five_exact_main_fields_and_default_none_survive_new_context_construction() {
    let pki = Pki::new();
    let ds = Cert::from_der(&read(&data(&[
        "lanes",
        "r3-v",
        "cms-exact-main",
        "digital-signature-only.der",
    ])))
    .unwrap();
    assert_eq!(
        sigis_pki_core::key_usage::cert_key_usages(&ds),
        Some(names(&["digital_signature"]))
    );
    let signer = SimpleSigner::new(pki.key("signer1"), ds, vec![]).unwrap();
    let bytes = sign_general_data(CONTENT, &signer, DigestAlgorithm::Sha256, true, None).unwrap();
    let ctx = bootstrap_validation_context(local(&pki)).unwrap();
    assert!(
        !trusted(&validate(&bytes, &ctx, &Default::default())),
        "ordinary None still requires NR"
    );
    for (policy, allow) in [
        (KeyUsageConstraints::default(), true),
        (
            KeyUsageConstraints {
                key_usage: Some(BTreeSet::new()),
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature"])),
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["non_repudiation"])),
                ..Default::default()
            },
            false,
        ),
        (
            KeyUsageConstraints {
                key_usage: None,
                key_usage_forbidden: Some(names(&["digital_signature"])),
                ..Default::default()
            },
            false,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature", "non_repudiation"])),
                match_all_key_usages: false,
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                key_usage: Some(names(&["digital_signature", "non_repudiation"])),
                match_all_key_usages: true,
                ..Default::default()
            },
            false,
        ),
        (
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["server_auth"])),
                explicit_extd_key_usage_required: false,
                ..Default::default()
            },
            true,
        ),
        (
            KeyUsageConstraints {
                extd_key_usage: Some(names(&["server_auth"])),
                explicit_extd_key_usage_required: true,
                ..Default::default()
            },
            false,
        ),
    ] {
        let mut options = AdesValidationOptions::default();
        options.exact_key_usage_settings = Some(policy.clone());
        let r = validate(&bytes, &ctx, &options);
        intact_valid(&r);
        assert_eq!(
            trusted(&r),
            allow,
            "exact complete predicate:{policy:?} {r:?}"
        );
    }
    ctx.close().unwrap();
}
