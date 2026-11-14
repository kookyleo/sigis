//! Three exact lifecycle originals under the approved limited capability mapping.
//! Empty external C/R fixture maps to explicit absent retrieval components only.
//! General mutable source graphs and independent nonempty stores are not modelled.
//! Real L2 concrete HTTP owners retain their pool and issued state through Basic.
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
    policy::{
        bootstrap_validation_context, build_validation_context_with_handlers,
        HandlerFetchSelection, ValidationDataHandlers,
    },
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
    fetch::{FetcherBackend, Fetchers},
    key_usage::KeyUsageConstraints,
    time::Moment,
};
use sigis_pki_fetch::{FetchLimits, FetcherSettings, HttpFetchers};
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
        "FETCH_REMAINING_INPUT {}",
        serde_json::json!({"path":p.canonicalize().unwrap(),"length":b.len(),"sha256":sha(&b)})
    );
    b
}
fn data(parts: &[&str]) -> PathBuf {
    sigis_testdata::path(parts)
}
fn runtime_identity() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {let p=std::env::current_exe().unwrap();let b=std::fs::read(&p).unwrap();let source=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/tests/round3_fetch_lifecycle_remaining.rs"));eprintln!("FETCH_REMAINING_EXECUTABLE {}",serde_json::json!({"path":p.canonicalize().unwrap(),"length":b.len(),"sha256":sha(&b),"test_source_sha256":sha(source)}));});
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

fn fresh_crl(pki: &Pki, revoked: bool) -> Vec<u8> {
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
    if revoked {
        let serial = x509_cert::Certificate::from_der(pki.cert("signer1").der())
            .unwrap()
            .tbs_certificate()
            .serial_number()
            .to_der()
            .unwrap();
        let revoked_entries = seq(&[seq(&[serial, encode(0x17, b"201119000000Z")])]);
        let position = tbs
            .iter()
            .rposition(|item| {
                let t = Tlv::parse_exact(item).unwrap();
                t.is_universal(23) || t.is_universal(24)
            })
            .unwrap()
            + 1;
        if tbs
            .get(position)
            .is_some_and(|item| Tlv::parse_exact(item).unwrap().is_universal(16))
        {
            tbs[position] = revoked_entries;
        } else {
            tbs.insert(position, revoked_entries);
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
fn ocsp_for_request(pki: &Pki, request: &[u8], revoked: bool) -> Vec<u8> {
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
    let status = if revoked {
        encode(0xa1, &encode(0x18, b"20201119000000Z"))
    } else {
        encode(0x80, &[])
    };
    let single = seq(&[cert_id, status, time.clone(), next]);
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
    RevokedCrl,
    RevokedOcsp,
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
        let crl = fresh_crl(&pki, mode == ReplyMode::RevokedCrl);
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
                                ocsp_for_request(&pki, &request, mode == ReplyMode::RevokedOcsp),
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
                            "FETCH_REMAINING_HTTP_EXCHANGE {}",
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
    let Some(dir) = std::env::var_os("HANKO_FETCH_REMAINING_OUTPUT_DIR") else {
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
    let row = serde_json::json!({"label":label,"cms_b64":openssl::base64::encode_block(bytes),"cms_sha256":sha(bytes),"content_b64":openssl::base64::encode_block(CONTENT),"content_sha256":sha(CONTENT),"roots_b64":b64(ctx.trust_anchors().iter().map(|a|a.cert().der().to_vec()).collect()),"other_certs_b64":b64(certs),"crls_b64":b64(crls),"ocsps_b64":b64(ocsps),"time":ctx.moment().to_string(),"best_signature_time":ctx.best_signature_time().to_string(),"point_in_time_validation":ctx.timing().point_in_time_validation,"time_tolerance_seconds":ctx.timing().time_tolerance.as_secs(),"revocation_policy":{"ee":policy.ee_certificate_rule.value(),"ca":policy.intermediate_ca_cert_rule.value()},"native":{"intact":s.map(|s|s.signature.intact),"valid":s.map(|s|s.signature.valid),"trusted":s.map(|s|s.signature.trusted()),"bottom_line":s.map(StandardCmsSignatureStatus::bottom_line),"subindication":r.ades_subindic.standard_name(),"trust_problem":s.map(|s|format!("{:?}",s.signature.trust_problem))},"evidence_origin":if server.is_some(){"native new leaf/CMS; arrays contain exact local and actually served candidate bytes, including forged/malformed 200 bodies; HTTP receipts identify transport errors; offline oracle is separate"}else{"new native signed CMS; exact committed local certificates/revocation replay, except explicitly network-resigned leaf in unreachable-* profiles; no HTTP performed for this profile"}});
    let b = serde_json::to_vec_pretty(&row).unwrap();
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(format!("{label}-{}.json", sha(&b)));
    std::fs::write(&p, &b).unwrap();
    eprintln!(
        "FETCH_REMAINING_NATIVE_CASE {}",
        serde_json::json!({"path":p,"length":b.len(),"sha256":sha(&b)})
    );
}

// Keep the actual fetching-enabled construction route in every reachability
// companion. Explicit None is a retrieval-capability choice, never inferred
// from empty evidence. No source/registry manager is fabricated.
fn http_handoff_context(
    builder: ValidationContextBuilder,
) -> Result<ValidationContext, ValidationError> {
    bootstrap_validation_context(builder)
}
fn local_handoff_context(
    builder: ValidationContextBuilder,
) -> Result<ValidationContext, ValidationError> {
    bootstrap_validation_context(builder.fetchers(Fetchers::none()))
}
// Exercise the complete caller constraints through BOTH actual producers.
// This helper is test-only; no public context is rebuilt from getters.
fn local_context_route(
    route: bool,
    builder: ValidationContextBuilder,
) -> Result<ValidationContext, ValidationError> {
    if route {
        build_validation_context_with_handlers(builder, None)
    } else {
        local_handoff_context(builder)
    }
}
fn same_components(actual: &Fetchers, expected: &Fetchers) {
    assert!(Arc::ptr_eq(
        actual.cert.as_ref().unwrap(),
        expected.cert.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        actual.crl.as_ref().unwrap(),
        expected.crl.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        actual.ocsp.as_ref().unwrap(),
        expected.ocsp.as_ref().unwrap()
    ));
}

#[test]
fn concrete_http_pool_alias_close_reconnect_and_issued_cache_companion() {
    // Exact original's wrapper/count obligations are additionally asserted with
    // the SAME generic CV primitive in context_tests.rs. Public L2 retains its
    // existing concrete HttpFetchers type; no generic owner field is invented.
    // Empty issued components still carry a real owned close capability.
    // This supplementary alias control first ISSUES DefaultHttp and then
    // replaces components: it is NOT the reachability factory-zero proof.
    // The two exact reachability tests below start genuinely unissued.
    let mut empty_handlers =
        ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::DefaultHttp);
    empty_handlers.fetchers = Fetchers::none();
    let empty =
        build_validation_context_with_handlers(ValidationContext::builder(), Some(&empty_handlers))
            .unwrap();
    assert!(empty.trust_anchors().is_empty());
    assert!(empty.fetchers().is_empty());
    empty.close().unwrap();
    empty_handlers.close().unwrap();
    empty.close().unwrap();

    let pki = Pki::new();
    let server = Server::new(ReplyMode::Good);
    let leaf = network_leaf(&pki, &server.base(), "first");
    let bytes = pki.cms(&leaf);
    let handlers = ValidationDataHandlers::from_fetch_selection(HandlerFetchSelection::DefaultHttp);
    let ctx = build_validation_context_with_handlers(
        builder(&pki, true)
            .crl(evidence("crl-root.der"))
            .revinfo_policy(both_policy()),
        Some(&handlers),
    )
    .unwrap();
    same_components(ctx.fetchers(), &handlers.fetchers);
    let result = validate(&bytes, &ctx, &Default::default());
    intact_valid(&result);
    assert!(trusted(&result), "{result:?}");
    assert_eq!(result.ades_subindic.standard_name(), "OK");
    let paths = server.requests.lock().unwrap().clone();
    assert!(paths.iter().any(|p| p.starts_with("GET /issuer/")));
    assert!(paths.iter().any(|p| p.starts_with("GET /crl ")));
    assert!(paths.iter().any(|p| p.starts_with("POST /ocsp ")));
    assert_eq!(paths.len(), 3);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    export(
        "policy-owned-http-required-positive",
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
    assert!(matches!(
        outer_error,
        sigis_pki_core::errors::HankoError::Malformed(_)
    ));
    // Both the original handler alias and returned context remain closeable;
    // errors never trigger hidden cleanup or remove caller-held authority.
    ctx.close().unwrap();
    let after = validate(&bytes, &ctx, &Default::default());
    assert!(trusted(&after));
    assert_eq!(server.count(), 3, "issued caches survive context close");
    same_components(ctx.fetchers(), &handlers.fetchers);

    let second = network_leaf(&pki, &server.base(), "second");
    let next = pki.cms(&second);
    assert!(trusted(&validate(&next, &ctx, &Default::default())));
    assert_eq!(server.count(), 4);
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        2,
        "closing the handed owner releases the handler's actual shared pool"
    );
    assert_eq!(server.timeouts.load(Ordering::SeqCst), 0);
    // Exercise the handler alias separately: its close alone must end the
    // exact same currently live pool that the handed context used above.
    handlers.close().unwrap();
    let third = network_leaf(&pki, &server.base(), "third");
    assert!(trusted(&validate(
        &pki.cms(&third),
        &ctx,
        &Default::default()
    )));
    assert_eq!(server.count(), 5);
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        3,
        "old handler alias still closes the actual shared pool"
    );
    // The context retains its capability independently of the handler value.
    drop(handlers);
    ctx.close().unwrap();
    let fourth = network_leaf(&pki, &server.base(), "fourth");
    assert!(trusted(&validate(
        &pki.cms(&fourth),
        &ctx,
        &Default::default()
    )));
    assert_eq!(server.count(), 6);
    assert_eq!(server.connections.load(Ordering::SeqCst), 4);
    assert_eq!(server.timeouts.load(Ordering::SeqCst), 0);
    ctx.close().unwrap();
    ctx.close().unwrap();
    eprintln!(
        "FETCH_REMAINING_LIFECYCLE {}",
        serde_json::json!({
            "first_requests":3,"cached_after_context_close_requests":3,
            "second_url_requests":4,"third_url_after_handler_close_requests":5,
            "context_after_handler_drop_requests":6,
            "connections":server.connections.load(Ordering::SeqCst),
            "timeouts":server.timeouts.load(Ordering::SeqCst),
            "old_handler_close_calls":1,"context_close_calls":4,
            "same_issued_component_arcs":true,"original_generic_count_proof":"CV private same primitive"
        })
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
        ReplyMode::RevokedCrl,
        ReplyMode::RevokedOcsp,
    ] {
        let server = Server::new(mode);
        let leaf = network_leaf(&pki, &server.base(), "negative");
        let bytes = pki.cms(&leaf);
        let ctx = http_handoff_context(
            builder(&pki, true)
                .crl(evidence("crl-root.der"))
                .revinfo_policy(both_policy()),
        )
        .unwrap();
        let r = validate(&bytes, &ctx, &Default::default());
        intact_valid(&r);
        assert!(!trusted(&r), "{mode:?}: {r:?}");
        if matches!(mode, ReplyMode::RevokedCrl | ReplyMode::RevokedOcsp) {
            let Some(TrustProblem::Path(ValidationError::Revoked {
                revocation_time, ..
            })) = r
                .api_status
                .as_ref()
                .unwrap()
                .signature
                .trust_problem
                .as_ref()
            else {
                panic!("authenticated revoked evidence must produce a typed revocation: {mode:?}: {r:?}");
            };
            assert_eq!(revocation_time.as_ref(), Some(&at("2020-11-19T00:00:00Z")));
            assert_eq!(r.ades_subindic.standard_name(), "REVOKED_NO_POE");
        }
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
    let ctx = http_handoff_context(
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
    export("policy-empty-roots", &bytes, &ctx, Some(&server), &r);
    ctx.close().unwrap();
    {
        let wrong_server = Server::new(ReplyMode::Good);
        let wrong_leaf = network_leaf(&pki, &wrong_server.base(), "nonempty-wrong-root");
        let wrong_bytes = pki.cms(&wrong_leaf);
        let unrelated_anchor = pki.cert("signer2");
        let real_root = pki.cert("root");
        let wrong_ctx = http_handoff_context(
            builder(&pki, false)
                .trust_root(unrelated_anchor.clone())
                .other_cert(real_root.clone())
                .revocation_mode("none"),
        )
        .unwrap();
        assert_eq!(wrong_ctx.trust_anchors().len(), 1);
        assert_eq!(wrong_ctx.trust_anchors()[0].cert(), &unrelated_anchor);
        assert!(!wrong_ctx.is_trust_anchor(&real_root));
        let denied = validate(&wrong_bytes, &wrong_ctx, &Default::default());
        intact_valid(&denied);
        assert!(
            !trusted(&denied),
            "nonempty unrelated roots cannot authorize actual issuer:{denied:?}"
        );
        assert_eq!(
            wrong_server.count(),
            1,
            "actual intermediate comes only from loopback AIA"
        );
        export(
            "policy-nonempty-wrong-root",
            &wrong_bytes,
            &wrong_ctx,
            Some(&wrong_server),
            &denied,
        );
        wrong_ctx.close().unwrap();
    }
    let parsed = SignedData::from_der(&bytes).unwrap();
    let sig = &parsed.signer_infos[0].signature;
    let pos = bytes.windows(sig.len()).position(|p| p == sig).unwrap();
    let mut bad = bytes.clone();
    bad[pos] ^= 1;
    let ctx = http_handoff_context(builder(&pki, true).revocation_mode("none")).unwrap();
    let r = validate(&bad, &ctx, &Default::default());
    assert!(!r.api_status.as_ref().unwrap().signature.valid);
    assert!(!trusted(&r));
    export("policy-cms-signature-forged", &bad, &ctx, None, &r);
    ctx.close().unwrap();
}

#[test]
fn independent_handler_contexts_have_independent_pools_and_issued_caches() {
    let pki = Pki::new();
    let server = Server::new(ReplyMode::Good);
    let leaf = network_leaf(&pki, &server.base(), "independent");
    let bytes = pki.cms(&leaf);
    let a = http_handoff_context(builder(&pki, true).revocation_mode("none")).unwrap();
    let b = http_handoff_context(builder(&pki, true).revocation_mode("none")).unwrap();
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
                failure_reason: Some("remaining-lifecycle exact caller-clock rejection".into()),
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
    for route in [false, true] {
        let pki = Pki::new();
        let leaf = pki.cert("signer1");
        let bytes = pki.cms(&leaf);
        let positive = local_context_route(route, local(&pki)).unwrap();
        assert!(
            positive.fetchers().is_empty(),
            "explicit absent retrieval components suppress bootstrap provisioning"
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
            let ctx = local_context_route(
                route,
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
        let ctx = local_context_route(
            route,
            local(&pki).freshness_judge(Arc::new(RejectFreshness(seen.clone()))),
        )
        .unwrap();
        let r = validate(&bytes, &ctx, &Default::default());
        assert!(!trusted(&r));
        assert!(seen.load(Ordering::SeqCst) > 0);
        ctx.close().unwrap();
        let beyond = leaf.not_after().plus(Duration::from_secs(2));
        for (seconds, allow) in [(0, false), (3, true)] {
            let ctx = local_context_route(
                route,
                builder(&pki, true)
                    .other_cert(pki.cert("interm"))
                    .moment(beyond)
                    .point_in_time_validation(false)
                    .time_tolerance(Duration::from_secs(seconds))
                    .revocation_mode("none"),
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
            let ctx = local_context_route(
                route,
                builder(&pki, true)
                    .other_cert(pki.cert("interm"))
                    .crl(evidence("crl-root.der"))
                    .revocation_mode("require")
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
}

#[test]
fn actual_trust_manager_anchor_qualifiers_pkix_and_qualification_are_not_dropped() {
    for route in [false, true] {
        let pki = Pki::new();
        let bytes = pki.cms(&pki.cert("signer1"));
        let manager = Arc::new(OneRoot {
            root: TrustAnchor::new(pki.cert("root")),
            calls: AtomicUsize::new(0),
        });
        let erased: Arc<dyn TrustManager> = manager.clone();
        let ctx = local_context_route(
            route,
            builder(&pki, false)
                .trust_manager(erased.clone())
                .other_cert(pki.cert("interm"))
                .revocation_mode("none"),
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
            let ctx = local_context_route(
                route,
                ValidationContext::builder()
                    .trust_anchor(anchor.clone())
                    .other_cert(pki.cert("interm"))
                    .moment(at(TIME))
                    .point_in_time_validation(false)
                    .revocation_mode("none"),
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
        let ctx = local_context_route(
            route,
            builder(&pki, true)
                .other_cert(pki.cert("interm"))
                .revocation_mode("none"),
        )
        .unwrap();
        assert!(trusted(&validate(&bytes, &ctx, &Default::default())));
        ctx.close().unwrap();
    }
}

#[test]
fn actual_targeted_ac_consumes_preserved_target_restrictions() {
    for route in [false, true] {
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
            let ctx = local_context_route(
                route,
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
                    }),
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
}

#[test]
fn exact_issued_factory_budget_and_caches_survive_context_and_handler_close() {
    let pki = Pki::new();
    let server = Server::new(ReplyMode::Good);
    let first = network_leaf(&pki, &server.base(), "budget-one");
    let second = network_leaf(&pki, &server.base(), "budget-two");
    let backend = HttpFetchers::new(FetcherSettings {
        limits: FetchLimits {
            max_requests: Some(1),
            ..Default::default()
        },
        ..Default::default()
    });
    // Factory-issued set has independent state from backend.as_fetchers().
    // Observe the ISSUED component's actual requests/refusals; never inspect
    // owner.budget() as a proxy for this separate set's remaining allowance.
    let issued = backend.get_fetchers();
    let handlers = ValidationDataHandlers {
        fetchers: issued.clone(),
        owned_fetcher_backend: Some(backend),
    };
    let ctx = build_validation_context_with_handlers(
        builder(&pki, true).revocation_mode("none"),
        Some(&handlers),
    )
    .unwrap();
    same_components(ctx.fetchers(), &issued);
    let bytes = pki.cms(&first);
    assert!(trusted(&validate(&bytes, &ctx, &Default::default())));
    assert_eq!(server.count(), 1);
    handlers.close().unwrap();
    ctx.close().unwrap();
    assert!(trusted(&validate(&bytes, &ctx, &Default::default())));
    assert_eq!(
        server.count(),
        1,
        "exact issued successful cache survives close"
    );
    let other = pki.cms(&second);
    let r = validate(&other, &ctx, &Default::default());
    intact_valid(&r);
    assert!(
        !trusted(&r),
        "new URL cannot refill spent issued budget:{r:?}"
    );
    assert_eq!(
        server.count(),
        1,
        "no new request after issued max_requests=1"
    );
    same_components(ctx.fetchers(), &issued);
    ctx.close().unwrap();
    handlers.close().unwrap();
}

fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}
#[test]
fn all_five_exact_main_fields_and_default_none_survive_new_context_construction() {
    for route in [false, true] {
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
        let bytes =
            sign_general_data(CONTENT, &signer, DigestAlgorithm::Sha256, true, None).unwrap();
        let ctx = local_context_route(route, local(&pki)).unwrap();
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
}

#[derive(Debug)]
struct FactoryProbe {
    backend: HttpFetchers,
    calls: AtomicUsize,
    closes: AtomicUsize,
}
impl FactoryProbe {
    fn new() -> Self {
        Self {
            backend: HttpFetchers::default(),
            calls: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
        }
    }
}
impl FetcherBackend for FactoryProbe {
    fn get_fetchers(&self) -> Fetchers {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.backend.get_fetchers()
    }
    fn close(&self) -> Result<(), sigis_pki_core::errors::FetchError> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        self.backend.close()
    }
}

#[test]
fn absent_handlers_preserve_ordinary_explicit_factory_and_close_semantics() {
    let pki = Pki::new();
    let server = Server::new(ReplyMode::Good);
    // None means no ADDED owner/default; an existing explicit backend still
    // issues once under ordinary build unless an explicit set suppresses it.
    for owned in [false, true] {
        for explicit_set in [false, true] {
            let backend = Arc::new(FactoryProbe::new());
            let mut b = builder(&pki, true).revocation_mode("none");
            b = if owned {
                b.owned_fetcher_backend(backend.clone())
            } else {
                b.fetcher_backend(backend.clone())
            };
            let supplied_backend = HttpFetchers::default();
            let supplied = supplied_backend.get_fetchers();
            if explicit_set {
                b = b.fetchers(supplied.clone());
            }
            let ctx = build_validation_context_with_handlers(b, None).unwrap();
            assert_eq!(
                backend.calls.load(Ordering::SeqCst),
                usize::from(!explicit_set)
            );
            if explicit_set {
                same_components(ctx.fetchers(), &supplied);
            }
            let suffix = format!("ordinary-{owned}-{explicit_set}");
            let leaf = network_leaf(&pki, &server.base(), &suffix);
            assert!(trusted(&validate(
                &pki.cms(&leaf),
                &ctx,
                &Default::default()
            )));
            ctx.close().unwrap();
            ctx.close().unwrap();
            assert_eq!(
                backend.closes.load(Ordering::SeqCst),
                if owned { 2 } else { 0 }
            );
            assert_eq!(
                backend.calls.load(Ordering::SeqCst),
                usize::from(!explicit_set)
            );
            backend.backend.close().unwrap();
            supplied_backend.close().unwrap();
        }
    }
    assert_eq!(server.count(), 4);
}

#[test]
fn test_policy_without_handlers_hands_over_nothing() {
    let pki = Pki::new();
    let bytes = pki.cms(&pki.cert("signer1"));
    let empty = build_validation_context_with_handlers(
        ValidationContext::builder()
            .revocation_mode("soft-fail")
            .moment(Moment::now()),
        None,
    )
    .unwrap();
    assert!(empty.fetchers().is_empty());
    empty.close().unwrap();
    empty.close().unwrap();
    let positive = build_validation_context_with_handlers(local(&pki), None).unwrap();
    assert!(positive.fetchers().is_empty());
    let r = validate(&bytes, &positive, &Default::default());
    intact_valid(&r);
    assert!(trusted(&r));
    export("policy-none-local-positive", &bytes, &positive, None, &r);
    positive.close().unwrap();
    let missing = build_validation_context_with_handlers(
        builder(&pki, true)
            .other_cert(pki.cert("interm"))
            .crl(evidence("crl-root.der"))
            .revocation_mode("require"),
        None,
    )
    .unwrap();
    assert!(missing.fetchers().is_empty());
    let r = validate(&bytes, &missing, &Default::default());
    intact_valid(&r);
    assert!(
        !trusted(&r),
        "missing mandatory evidence cannot create a default:{r:?}"
    );
    export("policy-none-missing-mandatory", &bytes, &missing, None, &r);
    missing.close().unwrap();
}

// These are the two whole, unparameterized reachability originals. Private CV
// assertions separately inspect the exact owned field/fallback invocation.
#[test]
fn test_no_backend_when_fetchers_are_unreachable() {
    unreachable_empty_fixture(false);
}
#[test]
fn test_unreachable_fetchers_still_adopt_an_owned_backend() {
    unreachable_empty_fixture(true);
}
fn unreachable_empty_fixture(owned: bool) {
    let pki = Pki::new();
    let server = Server::new(ReplyMode::Good);
    let backend = Arc::new(FactoryProbe::new()); // genuinely unissued/unprewarmed
    let alias = backend.clone();
    let empty_builder = ValidationContext::builder().fetchers(Fetchers::none());
    let empty_builder = if owned {
        empty_builder.owned_fetcher_backend(backend.clone())
    } else {
        empty_builder
    };
    let empty = bootstrap_validation_context(empty_builder).unwrap();
    assert!(empty.trust_anchors().is_empty());
    assert!(empty.other_certs().is_empty());
    assert_eq!(empty.crls().count(), 0);
    assert_eq!(empty.ocsps().count(), 0);
    assert!(empty.fetchers().is_empty());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.closes.load(Ordering::SeqCst), 0);
    empty.close().unwrap();
    assert_eq!(backend.closes.load(Ordering::SeqCst), usize::from(owned));
    empty.close().unwrap();
    assert_eq!(alias.closes.load(Ordering::SeqCst), 2 * usize::from(owned));
    drop(empty);
    assert_eq!(alias.closes.load(Ordering::SeqCst), 2 * usize::from(owned));

    let leaf = network_leaf(&pki, &server.base(), "unreachable");
    let bytes = pki.cms(&leaf);
    let selected = builder(&pki, true)
        .revocation_mode("require")
        .fetchers(Fetchers::none());
    let selected = if owned {
        selected.owned_fetcher_backend(backend.clone())
    } else {
        selected
    };
    let ctx = bootstrap_validation_context(selected).unwrap();
    let before = format!("{ctx:?}");
    let failed = validate(&bytes, &ctx, &Default::default());
    intact_valid(&failed);
    assert!(
        !trusted(&failed),
        "no missing issuer fetch is reachable: {failed:?}"
    );
    assert_eq!(server.count(), 0);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(before, format!("{ctx:?}"));
    export(
        &format!("unreachable-{owned}-missing-intermediate"),
        &bytes,
        &ctx,
        None,
        &failed,
    );
    ctx.close().unwrap();

    // Retain independently supplied native local material. It is not treated
    // as an external manager alias or as evidence of implicit unreachability.
    let selected = local(&pki).fetchers(Fetchers::none());
    let selected = if owned {
        selected.owned_fetcher_backend(backend.clone())
    } else {
        selected
    };
    let local_ctx = bootstrap_validation_context(selected).unwrap();
    assert_eq!(local_ctx.other_certs(), &[pki.cert("interm")]);
    assert_eq!(local_ctx.crls().count(), 2);
    assert_eq!(local_ctx.ocsps().count(), 1);
    let positive = validate(&bytes, &local_ctx, &Default::default());
    intact_valid(&positive);
    assert!(
        trusted(&positive),
        "signed local chain/evidence remains usable: {positive:?}"
    );
    assert_eq!(server.count(), 0);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    export(
        &format!("unreachable-{owned}-local-positive"),
        &bytes,
        &local_ctx,
        None,
        &positive,
    );
    local_ctx.close().unwrap();
    alias.close().unwrap(); // caller-held authority survives contexts
    assert_eq!(
        alias.closes.load(Ordering::SeqCst),
        1 + 4 * usize::from(owned)
    );
    assert_eq!(alias.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unset_fetching_enabled_bootstrap_really_fetches_missing_intermediate() {
    let pki = Pki::new();
    let server = Server::new(ReplyMode::Good);
    let leaf = network_leaf(&pki, &server.base(), "real-default");
    let bytes = pki.cms(&leaf);
    let ctx = bootstrap_validation_context(
        builder(&pki, true)
            .crl(evidence("crl-root.der"))
            .revinfo_policy(both_policy()),
    )
    .unwrap();
    assert!(!ctx.fetchers().is_empty());
    let result = validate(&bytes, &ctx, &Default::default());
    intact_valid(&result);
    assert!(trusted(&result), "{result:?}");
    let paths = server.requests.lock().unwrap().clone();
    assert_eq!(paths.len(), 3);
    assert!(paths.iter().any(|p| p.starts_with("GET /issuer/")));
    assert!(paths.iter().any(|p| p.starts_with("GET /crl ")));
    assert!(paths.iter().any(|p| p.starts_with("POST /ocsp ")));
    export(
        "unset-real-http-positive",
        &bytes,
        &ctx,
        Some(&server),
        &result,
    );
    ctx.close().unwrap();
    assert!(trusted(&validate(&bytes, &ctx, &Default::default())));
    assert_eq!(server.count(), 3);
    ctx.close().unwrap();
}
