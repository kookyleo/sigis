//! Tests-first selected-message contract for the additive current-leaf producer.
//! Supplemental controls only; no upstream-function credit or execution claim.
//! Input expectations are never treated as committed selection receipts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use sigis_pki_certvalidator::{
    validate::{find_current_leaf_revocation_evaluation, find_valid_path, LeafRevocationChannel},
    CertRevTrustPolicy, FreshnessReqType, NonRevokedStatusAssertion, PathFailure,
    RevocationCheckingPolicy, RevocationCheckingRule, ValidationContext, ValidationPath,
};
use sigis_pki_core::{
    algorithms::{
        validate_signature, AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm,
        DisallowWeakAlgorithmsPolicy, SignatureValidationContext,
    },
    asn1::tlv::Tlv,
    cert::Cert,
    errors::ValidationError,
    time::Moment,
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::{certificate::Raw, crl::CertificateList};
use x509_ocsp::{BasicOcspResponse, OcspResponse};

const ROOT: &str = "lanes/r3-v/leaf-revoked-qualification-policy";
const V: &str = "2020-12-25T00:00:00Z";
const R: &str = "2020-12-01T00:00:00Z";
const T: &str = "2020-11-01T00:00:00Z";
const CUTOFF: &str = "2020-12-10T00:00:00Z";
const SHA256_RSA: &str = "300d06092a864886f70d01010b0500";
const SHA512_RSA: &str = "300d06092a864886f70d01010d0500";
const DENIAL: &str = "exact selected-message test policy denial";

fn moment(value: &str) -> Moment {
    Moment::parse_rfc3339(value).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&DigestAlgorithm::Sha256.digest(bytes))
}

fn opened(relative: &str) -> Vec<u8> {
    let path = sigis_testdata::data_dir().join(ROOT).join(relative);
    let bytes = std::fs::read(&path).expect("finite imported fixture must exist");
    eprintln!(
        "LEAF_MESSAGE_POLICY_INPUT {}",
        serde_json::json!({"path":path.canonicalize().unwrap(),
            "length":bytes.len(),"sha256":sha256(&bytes)})
    );
    bytes
}

fn input(relative: &str) -> Vec<u8> {
    assert!(!relative.starts_with('/'));
    assert!(!relative.split('/').any(|part| part == ".."));
    let origin: serde_json::Value = serde_json::from_slice(&opened("origin.json")).unwrap();
    assert_eq!(origin["message_clocks"]["v"], V);
    assert_eq!(origin["message_clocks"]["r"], R);
    assert_eq!(origin["message_clocks"]["t"], T);
    let rows: Vec<_> = origin["files"].as_array().unwrap().iter()
        .filter(|row| row["path"].as_str() == Some(relative)).collect();
    assert_eq!(rows.len(), 1, "exactly one finite origin entry: {relative}");
    let bytes = opened(relative);
    assert_eq!(rows[0]["length"].as_u64(), Some(bytes.len() as u64));
    assert_eq!(rows[0]["sha256"].as_str(), Some(sha256(&bytes).as_str()));
    bytes
}

fn cert(name: &str) -> Cert {
    let certificate = Cert::from_der(&input(&format!("messages/certs/{name}.cert.der"))).unwrap();
    assert_eq!(hex(&certificate.decoded().signature_algorithm().to_der().unwrap()), SHA256_RSA,
        "certificate signatures must not share the message discriminator");
    assert_eq!(certificate.public_key().to_der().unwrap(),
        input(&format!("messages/certs/{name}.spki.der")));
    certificate
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    algorithm_der: Vec<u8>,
    signer_spki_der: Option<Vec<u8>>,
    reference: Option<Moment>,
}

#[derive(Debug)]
struct Message {
    original: Vec<u8>,
    algorithm: AlgorithmIdentifierOwned,
    signer: SubjectPublicKeyInfoOwned,
    signed: Vec<u8>,
    signature: Vec<u8>,
}

impl Message {
    fn binding(&self) -> Binding {
        Binding {
            algorithm_der: self.algorithm.to_der().unwrap(),
            signer_spki_der: Some(self.signer.to_der().unwrap()),
            reference: Some(moment(V)),
        }
    }

    fn raw_signature_valid(&self) -> bool {
        validate_signature(&self.signature, &self.signed, &self.signer, &self.algorithm,
            &SignatureValidationContext::default()).is_ok()
    }
}

fn message(relative: &str) -> Message {
    let bindings: serde_json::Value = serde_json::from_slice(
        &input("messages/expected-bindings-input-only.json")).unwrap();
    let row = bindings.as_array().unwrap().iter()
        .find(|row| row["path"].as_str() == Some(relative))
        .expect("binding is an input expectation, never a selection receipt");
    let original = input(&format!("messages/{relative}"));
    assert_eq!(row["sha256"].as_str(), Some(sha256(&original).as_str()));
    assert_eq!(row["length"].as_u64(), Some(original.len() as u64));
    assert_eq!(row["original_validation_reference"], V);
    let signer_bytes = input(&format!("messages/{}", row["actual_signer_spki"].as_str().unwrap()));
    assert_eq!(row["actual_signer_spki_sha256"].as_str(), Some(sha256(&signer_bytes).as_str()));
    let signer = SubjectPublicKeyInfoOwned::from_der(&signer_bytes).unwrap();
    assert_eq!(signer, cert(row["actual_signer"].as_str().unwrap()).public_key());
    let (algorithm, signed, signature) = match row["channel"].as_str().unwrap() {
        "OCSP" => {
            let response = OcspResponse::from_der(&original).unwrap();
            let body = response.response_bytes.unwrap();
            let basic = BasicOcspResponse::from_der(body.response.as_bytes()).unwrap();
            for single in &basic.tbs_response_data.responses {
                assert_eq!(single.cert_id.hash_algorithm.oid,
                    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
                    "CertID SHA256 is independent of the message signature algorithm");
            }
            let signed = Tlv::parse_exact(body.response.as_bytes()).unwrap()
                .children().unwrap()[0].raw.to_vec();
            (basic.signature_algorithm, signed, basic.signature.raw_bytes().to_vec())
        }
        "CRL" => {
            let crl = CertificateList::<Raw>::from_der(&original).unwrap();
            assert_eq!(crl.signature_algorithm, crl.tbs_cert_list.signature);
            let signed = Tlv::parse_exact(&original).unwrap().children().unwrap()[0].raw.to_vec();
            (crl.signature_algorithm, signed, crl.signature.raw_bytes().to_vec())
        }
        other => panic!("unsupported finite channel: {other}"),
    };
    assert_eq!(row["signature_algorithm_der_hex"].as_str(),
        Some(hex(&algorithm.to_der().unwrap()).as_str()));
    Message { original, algorithm, signer, signed, signature }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Signature(Binding),
    Digest(ObjectIdentifier, Option<Moment>),
    Combination(Vec<u8>, Vec<u8>, Option<Moment>),
    MinimumRsa,
}

#[derive(Debug)]
struct MessagePolicy {
    expected: Vec<Binding>,
    deny: bool,
    cutoff: Option<Moment>,
    calls: Mutex<Vec<Call>>,
    unexpected: Mutex<Vec<Binding>>,
    delegate: DisallowWeakAlgorithmsPolicy,
}

impl MessagePolicy {
    fn new(paths: &[&str], deny: bool, cutoff: Option<Moment>) -> Arc<Self> {
        Arc::new(Self {
            expected: paths.iter().map(|path| {
                let m = message(path);
                assert_eq!(hex(&m.algorithm.to_der().unwrap()), SHA512_RSA);
                m.binding()
            }).collect(),
            deny, cutoff, calls: Mutex::new(Vec::new()), unexpected: Mutex::new(Vec::new()),
            delegate: DisallowWeakAlgorithmsPolicy::default(),
        })
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn discriminator_calls(&self) -> Vec<Binding> {
        self.calls().into_iter().filter_map(|call| match call {
            Call::Signature(binding) if hex(&binding.algorithm_der) == SHA512_RSA => Some(binding),
            _ => None,
        }).collect()
    }

    fn assert_bindings(&self) {
        assert!(self.unexpected.lock().unwrap().is_empty(),
            "an unexpected full algorithm/key/reference binding must fail the test");
        for binding in self.discriminator_calls() {
            assert!(self.expected.contains(&binding));
        }
    }
}

impl AlgorithmUsagePolicy for MessagePolicy {
    fn signature_algorithm_allowed(&self, algorithm: &AlgorithmIdentifierOwned,
        at: Option<Moment>, key: Option<&SubjectPublicKeyInfoOwned>) -> AlgorithmUsageConstraint {
        let actual = Binding {
            algorithm_der: algorithm.to_der().unwrap(),
            signer_spki_der: key.map(|key| key.to_der().unwrap()), reference: at,
        };
        self.calls.lock().unwrap().push(Call::Signature(actual.clone()));
        if algorithm.oid != ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13") {
            return self.delegate.signature_algorithm_allowed(algorithm, at, key);
        }
        if !self.expected.contains(&actual) {
            self.unexpected.lock().unwrap().push(actual);
            return AlgorithmUsageConstraint::denied("unexpected full message binding");
        }
        if !self.deny {
            return self.delegate.signature_algorithm_allowed(algorithm, at, key);
        }
        let mut denied = AlgorithmUsageConstraint::denied(DENIAL);
        denied.not_allowed_after = self.cutoff;
        denied
    }

    fn digest_algorithm_allowed(&self, oid: &ObjectIdentifier, at: Option<Moment>)
        -> AlgorithmUsageConstraint {
        self.calls.lock().unwrap().push(Call::Digest(*oid, at));
        self.delegate.digest_algorithm_allowed(oid, at)
    }

    fn digest_combination(&self, signature: &AlgorithmIdentifierOwned,
        digest: &AlgorithmIdentifierOwned, at: Option<Moment>) -> Option<AlgorithmUsageConstraint> {
        self.calls.lock().unwrap().push(Call::Combination(
            signature.to_der().unwrap(), digest.to_der().unwrap(), at));
        self.delegate.digest_combination(signature, digest, at)
    }

    fn min_rsa_key_size(&self) -> usize {
        self.calls.lock().unwrap().push(Call::MinimumRsa);
        self.delegate.min_rsa_key_size()
    }
}

#[derive(Clone)]
struct Inputs {
    ee: RevocationCheckingRule,
    ca: RevocationCheckingRule,
    ocsp: Vec<&'static str>,
    crl: Vec<&'static str>,
    trusted: bool,
    asserted: bool,
}

impl Inputs {
    fn direct(ee: RevocationCheckingRule, ocsp: &[&'static str], crl: &[&'static str]) -> Self {
        Self { ee, ca: RevocationCheckingRule::CrlRequired, ocsp: ocsp.to_vec(),
            crl: std::iter::once("crl/ancestor-good-sha256.der").chain(crl.iter().copied()).collect(),
            trusted: true, asserted: false }
    }

    fn context(&self, policy: Arc<MessagePolicy>) -> ValidationContext {
        let mut revocation = CertRevTrustPolicy::new(RevocationCheckingPolicy {
            ee_certificate_rule: self.ee, intermediate_ca_cert_rule: self.ca,
        });
        revocation.freshness_req_type = FreshnessReqType::MaxDiffRevocationValidation;
        let mut builder = ValidationContext::builder().other_cert(cert("issuing"))
            .other_cert(cert("responder_delegated")).other_cert(cert("responder_nocheck"))
            .moment(moment(V)).point_in_time_validation(false)
            .revinfo_policy(revocation).algorithm_policy(policy);
        if self.trusted { builder = builder.trust_root(cert("root")); }
        for path in &self.ocsp { builder = builder.ocsp_response(input(&format!("messages/{path}"))); }
        for path in &self.crl { builder = builder.crl(input(&format!("messages/{path}"))); }
        if self.asserted {
            for name in ["main", "issuing"] {
                builder = builder.assertion(NonRevokedStatusAssertion {
                    cert_sha256: cert(name).sha256(), at: moment(V),
                });
            }
        }
        builder.build().unwrap()
    }
}

fn assert_path(path: &ValidationPath, leaf: &str) {
    assert_eq!(path.trust_anchor().cert(), &cert("root"));
    assert_eq!(path.leaf(), Some(&cert(leaf)));
    if leaf == "issuing" {
        assert!(path.intermediates().is_empty());
    } else {
        assert_eq!(path.intermediates(), &[cert("issuing")]);
    }
}

fn assert_revoked(failure: &PathFailure) {
    match &failure.error {
        ValidationError::Revoked { revocation_time, reason, .. } => {
            assert_eq!(*revocation_time, Some(moment(R)));
            assert_eq!(*reason, Some("key_compromise"));
        }
        other => panic!("expected the real ordinary KeyCompromise refusal, got {other:?}"),
    }
    assert_path(failure.path.as_ref().expect("actual failed path"), "main");
    assert!(failure.is_ee_cert);
    assert!(!failure.is_side_validation);
    assert_eq!(failure.time_horizon, Some(moment(R)));
    assert!(!failure.invalid_certificate);
}

fn allowed_event(inputs: &Inputs, discriminators: &[&str], count: usize) -> ValidationPath {
    let policy = MessagePolicy::new(discriminators, false, None);
    let ctx = inputs.context(policy.clone());
    assert_eq!(ctx.timing().validation_time, moment(V));
    let leaf = cert("main");
    let ordinary = find_valid_path(&ctx, &leaf, None).expect_err("ordinary current leaf is revoked");
    assert_revoked(&ordinary);
    let checked = find_current_leaf_revocation_evaluation(&ctx, &leaf, None)
        .expect("genuine complete allowed KeyCompromise premise must pass before denial");
    assert_path(checked.path(), "main");
    assert_revoked(checked.unresolved_failure().expect("revocation stays unresolved"));
    assert_eq!(checked.leaf_events().len(), count);
    for event in checked.leaf_events() {
        assert_eq!(event.target(), &leaf);
        assert_eq!(event.issuer(), &cert("issuing"));
        assert_eq!(event.effective_time(), moment(R));
        assert_eq!(event.rule(), inputs.ee);
        assert_eq!(event.selected_index(), 0, "these finite leaf fixtures select their first entry");
        let supplied = match event.channel() {
            LeafRevocationChannel::Ocsp => &inputs.ocsp,
            LeafRevocationChannel::Crl => &inputs.crl,
        };
        assert!(supplied.iter().any(|path| input(&format!("messages/{path}")) == event.evidence_der()));
    }
    if inputs.ee == RevocationCheckingRule::CrlAndOcspRequired {
        let channels: Vec<_> = checked.leaf_events().iter().map(|event| event.channel()).collect();
        assert_eq!(channels.len(), 2);
        assert!(channels.contains(&LeafRevocationChannel::Ocsp));
        assert!(channels.contains(&LeafRevocationChannel::Crl));
    }
    policy.assert_bindings();
    let path = checked.path().clone();
    let before = policy.calls();
    let facts = checked.into_owned_facts();
    assert_eq!(facts.path(), &path);
    assert_revoked(facts.unresolved_failure().unwrap());
    assert_eq!(facts.leaf_events().len(), count);
    assert_eq!(policy.calls(), before, "conversion and getters perform no policy work");
    path
}

fn denied_event(inputs: &Inputs, discriminators: &[&str], cutoff: Option<Moment>,
    origin_leaf: &str, is_ee: bool, side: bool) {
    let policy = MessagePolicy::new(discriminators, true, cutoff);
    let ctx = inputs.context(policy.clone());
    assert_eq!(ctx.timing().validation_time, moment(V));
    let failure = find_current_leaf_revocation_evaluation(&ctx, &cert("main"), None)
        .expect_err("selected message denial must block completion facts");
    policy.assert_bindings();
    let calls = policy.discriminator_calls();
    assert_eq!(calls.len(), 1, "the first selected denied discriminator stops the new gate");
    assert!(policy.expected.contains(&calls[0]));
    assert_eq!(calls[0].reference, Some(moment(V)));
    match &failure.error {
        ValidationError::DisallowedAlgorithm { banned_since, .. } => assert_eq!(*banned_since, cutoff),
        other => panic!("producer must return typed message denial, got {other:?}"),
    }
    assert_eq!(failure.time_horizon, cutoff);
    assert_eq!(failure.is_ee_cert, is_ee);
    assert_eq!(failure.is_side_validation, side);
    assert!(!failure.invalid_certificate);
    assert_path(failure.path.as_ref().expect("actual originating message path"), origin_leaf);
}

#[test]
fn m0_real_sha512_messages_verify_and_signature_only_tampering_fails() {
    for path in ["ocsp/leaf-direct-revoked-sha512.der", "crl/leaf-revoked-sha512.der"] {
        let genuine = message(path);
        let tampered = message(&path.replace(".der", "-signature-tamper.der"));
        assert_eq!(hex(&genuine.algorithm.to_der().unwrap()), SHA512_RSA);
        assert_eq!(genuine.algorithm, tampered.algorithm);
        assert_eq!(genuine.signer, tampered.signer);
        assert_eq!(genuine.signed, tampered.signed);
        assert_eq!(genuine.original.len(), tampered.original.len());
        assert!(genuine.raw_signature_valid());
        assert!(!tampered.raw_signature_valid());
    }
}

#[test]
fn m1_ordinary_good_current_ancestor_does_not_inherit_the_new_message_gate() {
    let mut inputs = Inputs::direct(RevocationCheckingRule::OcspRequired,
        &["ocsp/ancestor-good-sha512.der"], &[]);
    inputs.ca = RevocationCheckingRule::OcspRequired;
    let policy = MessagePolicy::new(&["ocsp/ancestor-good-sha512.der"], true, None);
    let ctx = inputs.context(policy.clone());
    let ordinary = find_valid_path(&ctx, &cert("issuing"), None).expect("genuine current Good issuer");
    assert_path(&ordinary, "issuing");
    assert!(policy.discriminator_calls().is_empty(), "ordinary raw response policy remains separate");
    let checked = find_current_leaf_revocation_evaluation(&ctx, &cert("issuing"), None)
        .expect("current success adds no message gate");
    assert_eq!(checked.path(), &ordinary);
    assert!(checked.leaf_events().is_empty());
    assert!(checked.unresolved_failure().is_none());
    assert!(policy.discriminator_calls().is_empty());
    policy.assert_bindings();
}

#[test]
fn m2_direct_ocsp_and_crl_message_denials_are_additive_typed_failures() {
    for (rule, ocsp, crl, discriminator) in [
        (RevocationCheckingRule::OcspRequired,
            vec!["ocsp/leaf-direct-revoked-sha512.der"], vec![], "ocsp/leaf-direct-revoked-sha512.der"),
        (RevocationCheckingRule::CrlRequired,
            vec![], vec!["crl/leaf-revoked-sha512.der"], "crl/leaf-revoked-sha512.der"),
    ] {
        let inputs = Inputs::direct(rule, &ocsp, &crl);
        allowed_event(&inputs, &[discriminator], 1);
        let ordinary_policy = MessagePolicy::new(&[discriminator], true, None);
        let ordinary_ctx = inputs.context(ordinary_policy.clone());
        assert_revoked(&find_valid_path(&ordinary_ctx, &cert("main"), None).unwrap_err());
        assert!(ordinary_policy.discriminator_calls().is_empty());
        ordinary_policy.assert_bindings();
        denied_event(&inputs, &[discriminator], None, "main", true, false);
    }
}

#[test]
fn m3_timed_denial_keeps_cutoff_without_rewinding_before_the_signature_bound() {
    assert!(moment(T) < moment(CUTOFF) && moment(CUTOFF) < moment(V));
    let inputs = Inputs::direct(RevocationCheckingRule::OcspRequired,
        &["ocsp/leaf-direct-revoked-sha512.der"], &[]);
    allowed_event(&inputs, &["ocsp/leaf-direct-revoked-sha512.der"], 1);
    denied_event(&inputs, &["ocsp/leaf-direct-revoked-sha512.der"],
        Some(moment(CUTOFF)), "main", true, false);
}

#[test]
fn m4_required_both_checks_each_agreeing_peer_after_authentication() {
    for (ocsp, crl, denied) in [
        ("ocsp/leaf-direct-revoked-sha512.der", "crl/leaf-revoked-sha256.der",
            "ocsp/leaf-direct-revoked-sha512.der"),
        ("ocsp/leaf-direct-revoked-sha256.der", "crl/leaf-revoked-sha512.der",
            "crl/leaf-revoked-sha512.der"),
    ] {
        let inputs = Inputs::direct(RevocationCheckingRule::CrlAndOcspRequired, &[ocsp], &[crl]);
        allowed_event(&inputs, &[denied], 2);
        denied_event(&inputs, &[denied], None, "main", true, false);
    }
}

#[test]
fn m5_either_does_not_query_the_optional_denied_crl() {
    let inputs = Inputs::direct(RevocationCheckingRule::CrlOrOcspRequired,
        &["ocsp/leaf-direct-revoked-sha256.der"], &["crl/leaf-revoked-sha512.der"]);
    allowed_event(&inputs, &["crl/leaf-revoked-sha512.der"], 1);
    let policy = MessagePolicy::new(&["crl/leaf-revoked-sha512.der"], true, None);
    let ctx = inputs.context(policy.clone());
    let checked = find_current_leaf_revocation_evaluation(&ctx, &cert("main"), None).unwrap();
    assert_revoked(checked.unresolved_failure().unwrap());
    assert_eq!(checked.leaf_events().len(), 1);
    assert_eq!(checked.leaf_events()[0].channel(), LeafRevocationChannel::Ocsp);
    assert_eq!(checked.leaf_events()[0].evidence_der(),
        input("messages/ocsp/leaf-direct-revoked-sha256.der"));
    assert!(policy.discriminator_calls().is_empty());
    policy.assert_bindings();
}

#[test]
fn m6_delegated_and_nocheck_response_keys_are_bound_independently_of_the_issuer() {
    assert!(!cert("responder_delegated").has_extension(&sigis_pki_core::asn1::oids::OCSP_NOCHECK));
    assert!(cert("responder_nocheck").has_extension(&sigis_pki_core::asn1::oids::OCSP_NOCHECK));
    for path in ["ocsp/leaf-delegated-revoked-sha512.der", "ocsp/leaf-nocheck-revoked-sha512.der"] {
        assert_ne!(message(path).signer, cert("issuing").public_key());
        let inputs = Inputs::direct(RevocationCheckingRule::OcspRequired,
            &[path, "ocsp/delegated-responder-good-sha256.der"],
            &["crl/delegated-responder-good-sha256.der"]);
        allowed_event(&inputs, &[path], 1);
        denied_event(&inputs, &[path], None, "main", true, false);
    }
}

#[test]
fn m6_nocheck_responder_does_not_select_supplied_side_revocation_evidence() {
    let discriminator = "ocsp/nocheck-responder-good-sha512.der";
    let inputs = Inputs::direct(RevocationCheckingRule::OcspRequired,
        &["ocsp/leaf-nocheck-revoked-sha256.der", discriminator], &[]);
    allowed_event(&inputs, &[discriminator], 1);
    let policy = MessagePolicy::new(&[discriminator], true, None);
    let ctx = inputs.context(policy.clone());
    let checked = find_current_leaf_revocation_evaluation(&ctx, &cert("main"), None).unwrap();
    assert_revoked(checked.unresolved_failure().unwrap());
    assert_eq!(checked.leaf_events().len(), 1);
    assert_eq!(checked.leaf_events()[0].evidence_der(),
        input("messages/ocsp/leaf-nocheck-revoked-sha256.der"));
    assert!(policy.discriminator_calls().is_empty());
    policy.assert_bindings();
}

#[test]
fn m7_tamper_missing_and_untrusted_controls_never_mint_completion_facts() {
    let genuine = Inputs::direct(RevocationCheckingRule::OcspRequired,
        &["ocsp/leaf-direct-revoked-sha512.der"], &[]);
    allowed_event(&genuine, &["ocsp/leaf-direct-revoked-sha512.der"], 1);
    allowed_event(&Inputs::direct(RevocationCheckingRule::CrlRequired, &[],
        &["crl/leaf-revoked-sha512.der"]), &["crl/leaf-revoked-sha512.der"], 1);
    let mut untrusted = genuine.clone();
    untrusted.trusted = false;
    for inputs in [untrusted,
        Inputs::direct(RevocationCheckingRule::OcspRequired, &[], &[]),
        Inputs::direct(RevocationCheckingRule::OcspRequired,
            &["ocsp/leaf-direct-revoked-sha512-signature-tamper.der"], &[]),
        Inputs::direct(RevocationCheckingRule::CrlRequired, &[],
            &["crl/leaf-revoked-sha512-signature-tamper.der"]),
    ] {
        let policy = MessagePolicy::new(&[], true, None);
        let ctx = inputs.context(policy.clone());
        assert!(find_valid_path(&ctx, &cert("main"), None).is_err());
        assert!(find_current_leaf_revocation_evaluation(&ctx, &cert("main"), None).is_err());
        policy.assert_bindings();
        assert!(policy.discriminator_calls().is_empty(), "no gate before collector completeness");
    }
}

#[test]
fn m7_wrong_full_algorithm_key_or_reference_binding_is_never_accepted_as_enforcement() {
    let path = "ocsp/leaf-direct-revoked-sha512.der";
    let inputs = Inputs::direct(RevocationCheckingRule::OcspRequired, &[path], &[]);
    allowed_event(&inputs, &[path], 1);
    let actual = message(path).binding();
    for mutation in 0..3 {
        let mut policy = MessagePolicy::new(&[path], true, None);
        let expected = &mut Arc::get_mut(&mut policy).unwrap().expected[0];
        match mutation {
            0 => {
                // Omit explicit NULL only in the test's expected input. The
                // producer must still pass the genuine original algorithm DER.
                expected.algorithm_der.truncate(expected.algorithm_der.len() - 2);
                expected.algorithm_der[1] -= 2;
            }
            1 => expected.signer_spki_der = Some(cert("root").public_key().to_der().unwrap()),
            2 => expected.reference = Some(moment(T)),
            _ => unreachable!(),
        }
        let ctx = inputs.context(policy.clone());
        let failure = find_current_leaf_revocation_evaluation(&ctx, &cert("main"), None)
            .expect_err("an unexpected binding must refuse, even for a denial policy");
        assert!(matches!(failure.error,
            ValidationError::DisallowedAlgorithm { banned_since: None, .. }));
        assert_eq!(policy.discriminator_calls(), vec![actual.clone()]);
        assert_eq!(*policy.unexpected.lock().unwrap(), vec![actual.clone()]);
        assert!(std::panic::catch_unwind(|| policy.assert_bindings()).is_err(),
            "the common assertion must reject this wrong-binding observation");
    }
}

#[test]
fn m8_historical_timeslide_refuses_without_authenticated_earlier_existence_evidence() {
    use sigis_pki_certvalidator::ltv::{poe::PoeManager, time_slide_with, LtvError, TimeSlideOptions};

    let path_name = "ocsp/leaf-direct-revoked-sha512.der";
    let inputs = Inputs::direct(RevocationCheckingRule::OcspRequired, &[path_name], &[]);
    let path = allowed_event(&inputs, &[path_name], 1);
    let origin: serde_json::Value = serde_json::from_slice(&opened("origin.json")).unwrap();
    let observed = moment(origin["message_clocks"]["conservative_observation_reference"].as_str().unwrap());
    assert!(observed > moment(V), "construction observation is not historical POE");
    let poe = PoeManager::with_current_time(observed);
    assert!(poe.iter().next().is_none(), "no authenticated earlier POE is imported");
    assert_eq!(poe.poe_time(cert("main").der()), observed);
    assert_eq!(poe.poe_time(&message(path_name).original), observed);

    let denied = MessagePolicy::new(&[path_name], true, Some(moment(CUTOFF)));
    let ctx = inputs.context(denied.clone());
    let error = time_slide_with(&path, moment(V), &ctx, &poe, TimeSlideOptions::default())
        .expect_err("construction and current validation cannot create earlier existence evidence");
    // The production source checks certificate POE before its missing-revinfo
    // branch. Do not seed certificate POE merely to reach a different error.
    assert!(matches!(error, LtvError::InsufficientPoe(_)), "{error:?}");
    denied.assert_bindings();
    assert!(denied.discriminator_calls().is_empty(), "no message-policy rewind is reached");
    // Positive historical cutoff behavior requires authentic earlier POE and
    // remains separate pending coverage, not a premise supplied by these inputs.
}

#[test]
fn m9_ancestor_and_delegated_side_good_messages_are_required_gate_obligations() {
    let mut ancestor = Inputs::direct(RevocationCheckingRule::OcspRequired,
        &["ocsp/ancestor-good-sha512.der", "ocsp/leaf-direct-revoked-sha256.der"], &[]);
    ancestor.ca = RevocationCheckingRule::OcspRequired;
    allowed_event(&ancestor, &["ocsp/ancestor-good-sha512.der"], 1);
    denied_event(&ancestor, &["ocsp/ancestor-good-sha512.der"], Some(moment(CUTOFF)),
        "main", false, false);

    let mut side = Inputs::direct(RevocationCheckingRule::OcspRequired,
        &["ocsp/ancestor-good-sha256.der", "ocsp/delegated-responder-good-sha512.der",
            "ocsp/leaf-delegated-revoked-sha256.der"], &[]);
    side.ca = RevocationCheckingRule::OcspRequired;
    allowed_event(&side, &["ocsp/delegated-responder-good-sha512.der"], 1);
    denied_event(&side, &["ocsp/delegated-responder-good-sha512.der"], Some(moment(CUTOFF)),
        "responder_delegated", true, true);
}

#[test]
fn m10_no_event_nocheck_and_assertion_settlement_add_no_message_queries() {
    let mut no_check = Inputs::direct(RevocationCheckingRule::NoCheck,
        &["ocsp/leaf-direct-revoked-sha512.der"], &["crl/leaf-revoked-sha512.der"]);
    no_check.ca = RevocationCheckingRule::NoCheck;
    let mut asserted = Inputs::direct(RevocationCheckingRule::CrlAndOcspRequired,
        &["ocsp/leaf-direct-revoked-sha512.der"], &["crl/leaf-revoked-sha512.der"]);
    asserted.asserted = true;
    let no_event = Inputs::direct(RevocationCheckingRule::CrlAndOcspRequired,
        &["ocsp/leaf-direct-good-sha256.der", "ocsp/leaf-nocheck-revoked-sha512.der"],
        &["crl/leaf-good-sha256.der"]);
    for inputs in [no_check, asserted, no_event] {
        let policy = MessagePolicy::new(&[], true, None);
        let ctx = inputs.context(policy.clone());
        let ordinary = find_valid_path(&ctx, &cert("main"), None)
            .expect("genuine no-event current-success premise");
        let checked = find_current_leaf_revocation_evaluation(&ctx, &cert("main"), None).unwrap();
        assert_eq!(checked.path(), &ordinary);
        assert!(checked.unresolved_failure().is_none());
        assert!(checked.leaf_events().is_empty());
        assert!(policy.discriminator_calls().is_empty());
        policy.assert_bindings();
    }
}
