//! Exact S-owned decode-limit operation callers for ROOT integration.
//! Derived from pyHanko 0.38.1 tests/test_decode_limits.py (MIT).
//! Keep at root so the P/V integration does not introduce crate dev cycles.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/signing_integration.rs"]
mod support;

#[path = "support/round3_s_pdf_inputs.rs"]
mod provenance;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use lopdf::{Dictionary, Object, Stream};
use sigis_pades_sign::pdf::dss::{add_dss, add_dss_with_state, DssContent};
use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
use sigis_pades_sign::pdf::timestamp::PdfTimeStamper;
use sigis_pades_sign::pdf::writer::{PdfOperationResult, PdfReopenState, PdfUpdate};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SignOptions, SubFilter};
use sigis_pdf::crypt::AuthStatus;
use sigis_pdf::decode_limits::{DecodeLimits, DecodePurpose, DocumentDecodeBudget};
use sigis_pdf::{PdfFile, ReaderOptions, SignatureKind};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};

const TIME: &str = "2020-11-01T00:00:00Z";
const OVERSIZED_HASH: &str = "71dce67bc7edf17664bea023b47ac34834a0bb77c1d14c77098e412d3473bc8f";
const SIGNER_HASH: &str = "449ecb59122767b13cbfbb6e75feb98bac90a4e1f782b4da43c071af94329aa5";

fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    eprintln!(
        "S_PDF_CALLER_INPUT {}",
        serde_json::json!({
            "path":std::fs::canonicalize(path).unwrap(), "sha256":sha(&bytes),
            "length":bytes.len(), "host":std::fs::read_to_string("/etc/hostname").unwrap().trim(),
            "slot":std::env::var("RUST_SLOTS_HELD").ok(),
            "build_manifest":env!("CARGO_MANIFEST_DIR"),
            "testdata_selection":std::env::var("HANKO_TESTDATA").ok(),
        })
    );
    bytes
}

fn oversized() -> Vec<u8> {
    let input = read(&sigis_testdata::path(&[
        "lanes",
        "r3-s",
        "decode-preflight",
        "oversized-objstm.pdf",
    ]));
    assert_eq!(sha(&input), OVERSIZED_HASH);
    input
}

fn original_signer() -> Cert {
    let bytes = read(&sigis_testdata::path(&[
        "lanes",
        "r3-s",
        "decode-preflight",
        "from-ca-signer.der",
    ]));
    assert_eq!(sha(&bytes), SIGNER_HASH);
    let cert = Cert::from_der(&bytes).unwrap();
    assert_eq!(cert, support::pki("testing-ca").cert("signer1"));
    cert
}

fn trusted(input: &[u8]) -> PdfReopenState {
    PdfReopenState::from_reader(
        PdfFile::parse_with(
            input,
            ReaderOptions {
                decode_limits: DecodeLimits::for_trusted_input(),
                ..Default::default()
            },
        )
        .unwrap(),
    )
}

fn tsa() -> PdfTimeStamper {
    PdfTimeStamper::new(Arc::new(
        support::pki("testing-ca").tsa("tsa", support::at(TIME)),
    ))
}

fn pades_signer(placement: SigDssPlacement, field: &str) -> PdfSigner {
    provenance::trace_pki("testing-ca");
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults(field);
    metadata.subfilter = Some(SubFilter::Pades);
    metadata.embed_validation_info = true;
    metadata.use_pades_lta = true;
    metadata.dss_settings = DssContentSettings {
        placement,
        ..Default::default()
    };
    // The existing exported Certomancer revinfo service is a committed-evidence
    // replay backend. It still performs real presign and TSA path validation;
    // it is not described as freshly generated HTTP revocation evidence.
    metadata.validation_context = Some(Arc::new(support::services::live_testing_vc(
        "testing-ca",
        TIME,
        &[],
    )));
    PdfSigner::new(
        metadata,
        Arc::new(support::pki("testing-ca").signer("signer1")),
    )
    .at(support::at(TIME))
    .with_timestamper(Arc::new(
        support::pki("testing-ca").tsa("tsa", support::at(TIME)),
    ))
}

fn persist(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::var_os("SIGIS_S_PDF_CALLER_OUTPUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("sigis-s-pdf-callers-{}", std::process::id()))
        });
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    eprintln!(
        "S_PDF_CALLER_OUTPUT {}",
        serde_json::json!({
            "path":path, "sha256":sha(bytes), "length":bytes.len(),
        })
    );
    path
}

fn assert_bound_state(output: &PdfOperationResult, selected: &DecodeLimits) {
    assert_eq!(output.state.reader().bytes(), output.pdf);
    assert_eq!(&output.state.decode_context().limits, selected);
}

fn count_timestamps(reader: &PdfFile) -> usize {
    reader
        .embedded_signatures()
        .unwrap()
        .iter()
        .filter(|s| s.kind == SignatureKind::DocTimeStamp)
        .count()
}

fn post_sign(placement: SigDssPlacement, name: &str) {
    let input = oversized();
    let output = pades_signer(placement, "Sig1")
        .sign_pdf_with_state(
            &input,
            &SignOptions {
                decode_limits: DecodeLimits::for_trusted_input(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_bound_state(&output, &DecodeLimits::for_trusted_input());
    let reader = trusted(&output.pdf);
    // Exact upstream assertion, after the actual PAdES/LTA signing operation.
    assert_eq!(count_timestamps(reader.reader()), 1);
    let signatures = reader.reader().embedded_signatures().unwrap();
    let signature = signatures
        .iter()
        .find(|s| s.kind == SignatureKind::Signature)
        .unwrap();
    assert_eq!(signature.field_name, "Sig1");
    assert_eq!(signature.sub_filter.as_deref(), Some("ETSI.CAdES.detached"));
    let dss = reader.reader().dss().unwrap().unwrap();
    assert!(!dss.material.certs.is_empty());
    assert!(!dss.material.ocsps.is_empty() || !dss.material.crls.is_empty());
    persist(name, &output.pdf);
}

#[test]
fn test_post_sign_reopen_keeps_limits_together_with_next_ts() {
    post_sign(
        SigDssPlacement::TogetherWithNextTs,
        "decode-post-sign-together.pdf",
    );
}

#[test]
fn test_post_sign_reopen_keeps_limits_separate_revision() {
    post_sign(
        SigDssPlacement::SeparateRevision,
        "decode-post-sign-separate.pdf",
    );
}

#[test]
fn test_archival_timestamp_update_keeps_limits() {
    let input = oversized();
    let context = support::services::live_testing_vc("testing-ca", TIME, &[]);
    // Exact in_place=False equivalent: the borrowed input remains unchanged.
    let before = input.clone();
    let output = tsa()
        .update_archival_timestamp_chain_with_state(
            &input,
            &context,
            DigestAlgorithm::Sha256,
            trusted(&input),
        )
        .unwrap();
    assert_eq!(input, before);
    assert_bound_state(&output, &DecodeLimits::for_trusted_input());
    assert_eq!(count_timestamps(trusted(&output.pdf).reader()), 1);
    persist("decode-archival.pdf", &output.pdf);
}

#[test]
fn test_add_dss_keeps_limits() {
    let input = oversized();
    let signer = original_signer();
    let content = DssContent {
        sig_contents: None,
        certs: vec![signer.clone()],
        ..Default::default()
    };
    let output = add_dss_with_state(&input, &content, false, trusted(&input)).unwrap();
    assert_bound_state(&output, &DecodeLimits::for_trusted_input());
    let reader = trusted(&output.pdf);
    let dss = reader.reader().dss().unwrap().unwrap();
    // Exact original nonempty certificate assertion, plus actual signer identity.
    assert!(!dss.material.certs.is_empty());
    assert_eq!(dss.material.certs, vec![signer.der().to_vec()]);
    assert!(
        dss.vri.is_empty(),
        "sig_contents=None must not invent a VRI"
    );
    persist("decode-dss.pdf", &output.pdf);
}

fn assert_limit<T: std::fmt::Debug>(result: Result<T>, operation: &str) {
    let error = result.unwrap_err();
    assert!(
        matches!(&error,HankoError::Malformed(message)
        if message.starts_with("PdfDecodeLimitError: ")),
        "{operation}: {error}"
    );
    eprintln!(
        "S_PDF_CALLER_LIMIT {}",
        serde_json::json!({
            "operation":operation,"wrapper_class":"Malformed","pdf_class":"PdfDecodeLimitError",
            "message":error.to_string(),
        })
    );
}

#[test]
fn real_operations_reject_default_limits_on_the_same_object_stream() {
    let input = oversized();
    let content = DssContent {
        certs: vec![original_signer()],
        ..Default::default()
    };
    let context = support::services::live_testing_vc("testing-ca", TIME, &[]);
    // No external reader/preflight may reject instead of the actual operation.
    assert_limit(
        pades_signer(SigDssPlacement::TogetherWithNextTs, "Sig1").sign_pdf(&input),
        "sign",
    );
    assert_limit(
        tsa().update_archival_timestamp_chain(&input, &context, DigestAlgorithm::Sha256),
        "archival",
    );
    assert_limit(add_dss(&input, &content, false), "DSS");
}

#[test]
fn real_operations_reject_the_inherited_finite_budget_without_resetting_it() {
    let input = oversized();
    let limits = DecodeLimits {
        document_budget: Some(DocumentDecodeBudget {
            base_allowance: 1024,
            max_ratio: 0.0,
        }),
        ..DecodeLimits::for_trusted_input()
    };
    let state = || {
        PdfReopenState::from_reader(
            PdfFile::parse_with(
                &input,
                ReaderOptions {
                    decode_limits: limits.clone(),
                    ..Default::default()
                },
            )
            .unwrap(),
        )
    };
    let content = DssContent {
        certs: vec![original_signer()],
        ..Default::default()
    };
    let context = support::services::live_testing_vc("testing-ca", TIME, &[]);
    assert_limit(
        pades_signer(SigDssPlacement::TogetherWithNextTs, "Sig1").sign_pdf_with_state(
            &input,
            &SignOptions {
                // Defaults would allow a much larger budget; the inherited state wins.
                reopen_state: Some(state()),
                ..Default::default()
            },
        ),
        "sign inherited budget",
    );
    assert_limit(
        tsa().update_archival_timestamp_chain_with_state(
            &input,
            &context,
            DigestAlgorithm::Sha256,
            state(),
        ),
        "archival inherited budget",
    );
    assert_limit(
        add_dss_with_state(&input, &content, false, state()),
        "DSS inherited budget",
    );
}

fn assert_continuation(output: &PdfOperationResult, limits: &DecodeLimits, maximum: i64) -> i64 {
    assert_bound_state(output, limits);
    assert!(!output.state.strict());
    assert!(output.state.reader().encrypted());
    assert!(output.state.reader().decryptor().is_some());
    assert!(output
        .state
        .reader()
        .security_handler()
        .unwrap()
        .unwrap()
        .is_authenticated());
    assert_eq!(
        output.state.reader().get_object_at((999, 0), None).unwrap(),
        Object::Null
    );
    let remaining = output.state.decode_context().remaining_budget().unwrap();
    assert!(
        remaining <= maximum,
        "operation reset spent document budget: {remaining}>{maximum}"
    );
    remaining
}

#[test]
fn sign_archive_dss_keep_spent_budget_authentication_and_lenient_reader_policy() {
    let input = read(&sigis_testdata::pyhanko(&[
        "pdf",
        "minimal-with-field-aes256.pdf",
    ]));
    let mut update = PdfUpdate::with_password(&input, b"usersecret").unwrap();
    let mut stream = Stream::new(Dictionary::new(), vec![0; 800_000]);
    stream.compress().unwrap();
    let spare = update.add(Object::Stream(stream));
    update.root_mut().unwrap().set("Spare", spare);
    let input = update.write().unwrap().0;
    let limits = DecodeLimits {
        document_budget: Some(DocumentDecodeBudget {
            base_allowance: 1_000_000,
            max_ratio: 0.0,
        }),
        ..DecodeLimits::for_trusted_input()
    };
    let reader = PdfFile::parse_with(
        &input,
        ReaderOptions {
            strict: false,
            decode_limits: limits.clone(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_ne!(
        reader.decrypt("usersecret").unwrap().status,
        AuthStatus::Failed
    );
    let object = reader.get_object_at(spare, None).unwrap();
    let initial = reader.decode_context().remaining_budget().unwrap();
    assert_eq!(
        reader
            .read_stream_data(object.as_stream().unwrap(), DecodePurpose::Generic, None)
            .unwrap(),
        vec![0; 800_000]
    );
    let spent = reader.decode_context().remaining_budget().unwrap();
    assert_eq!(initial - spent, 800_000);
    let signed = pades_signer(SigDssPlacement::TogetherWithNextTs, "BudgetSig")
        .sign_pdf_with_state(
            &input,
            &SignOptions {
                reopen_state: Some(PdfReopenState::from_reader(reader)),
                ..Default::default()
            },
        )
        .unwrap();
    let after_sign = assert_continuation(&signed, &limits, spent);
    let context = support::services::live_testing_vc("testing-ca", TIME, &[]);
    let archived = tsa()
        .update_archival_timestamp_chain_with_state(
            &signed.pdf,
            &context,
            DigestAlgorithm::Sha256,
            signed.state,
        )
        .unwrap();
    let after_archival = assert_continuation(&archived, &limits, after_sign);
    let content = DssContent {
        certs: vec![original_signer()],
        ..Default::default()
    };
    let final_output = add_dss_with_state(&archived.pdf, &content, true, archived.state).unwrap();
    let after_dss = assert_continuation(&final_output, &limits, after_archival);
    let object = final_output
        .state
        .reader()
        .get_object_at(spare, None)
        .unwrap();
    let rejected = final_output.state.reader().read_stream_data(
        object.as_stream().unwrap(),
        DecodePurpose::Generic,
        None,
    );
    assert!(matches!(
        rejected.unwrap_err(),
        sigis_pdf::PdfError::DecodeLimit(_)
    ));
    eprintln!(
        "S_PDF_CALLER_BUDGET {}",
        serde_json::json!({
            "initial":initial,"after_spending":spent,"after_sign":after_sign,
            "after_archival":after_archival,"after_dss":after_dss,
            "authenticated":true,"strict":false,"final_large_decode_rejected":true,
        })
    );
    persist("decode-state-chain-encrypted.pdf", &final_output.pdf);
}
