//! Borrowed-buffer assistance for S-owned test_direct_pdfcmsembedder_usage.
//! These tests earn no additional lane P upstream-function credit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use lopdf::{dictionary, Dictionary, Object, ObjectId, Stream};
use sigis_pades_sign::cms::{AttrProfile, CmsSigner, CmsSignerOptions};
use sigis_pades_sign::pdf::dss::{add_dss_in_place, add_dss_in_place_with_state, DssContent};
use sigis_pades_sign::pdf::fields::{ensure_sig_flags, prepare_sig_field, NewFieldSettings};
use sigis_pades_sign::pdf::signer::{
    read_certification_level, write_and_digest_in_place, SigMdpSetup, SignatureObjectSpec,
};
use sigis_pades_sign::pdf::writer::{PdfReopenState, PdfUpdate};
use sigis_pades_sign::CmsSignedAttributes;
use sigis_pdf::crypt::AuthStatus;
use sigis_pdf::decode_limits::{DecodeLimits, DecodePurpose, DocumentDecodeBudget};
use sigis_pdf::{MdpPerm, PdfFile, ReaderOptions};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::sign::KeySigner;

const TIME: &str = "2020-11-01T00:00:00Z";
const RESERVED: usize = 8192;

fn certification(mut update: PdfUpdate) -> (PdfUpdate, ObjectId) {
    let (created, field_id) = prepare_sig_field(
        &mut update,
        "Signature",
        false,
        &NewFieldSettings::default(),
    )
    .unwrap();
    assert!(created);
    assert_eq!(
        update
            .get_dict(field_id)
            .unwrap()
            .get(b"T")
            .unwrap()
            .as_str()
            .unwrap(),
        b"Signature"
    );
    ensure_sig_flags(&mut update, true).unwrap();
    let mut dictionary = SignatureObjectSpec {
        timestamp: Some(support::at(TIME)),
        ..Default::default()
    }
    .to_dict(false);
    let signature_id = update.add(Object::Null);
    SigMdpSetup {
        certify: true,
        field_lock: None,
        docmdp_perms: Some(MdpPerm::NoChanges),
    }
    .apply(&mut update, &mut dictionary, signature_id)
    .unwrap();
    update.update(signature_id, Object::Dictionary(dictionary));
    update
        .get_dict_mut(field_id)
        .unwrap()
        .set("V", signature_id);
    (update, signature_id)
}

fn cms_for_digest(digest: &[u8]) -> Vec<u8> {
    let signer = support::pki("testing-ca").signer("signer1");
    CmsSigner {
        signer: &signer,
        options: &CmsSignerOptions::default(),
    }
    .sign(
        digest,
        DigestAlgorithm::Sha256,
        &CmsSignedAttributes {
            signing_time: Some(support::at(TIME)),
            ..Default::default()
        },
        AttrProfile::GenericPdf,
        None,
        false,
        None,
    )
    .unwrap()
}

fn exact_live_oracle(output: &[u8], extended: bool) {
    let python = support::oracle_python().expect("the pinned live oracle is mandatory");
    let path = support::temp_file("borrowed-direct-embedder.pdf", output);
    let result = std::process::Command::new(python)
        .args(["-I", "-c", EXACT_DIRECT_ASSERTIONS])
        .arg(&path)
        .arg(if extended { "true" } else { "false" })
        .output()
        .unwrap();
    let _ = std::fs::remove_file(path);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(status["bottom_line"], true, "{status}");
    eprintln!("live borrowed direct embedder extended={extended}: {status}");
}

#[test]
fn direct_cms_signing_and_dss_return_the_same_caller_vec_object() {
    let mut caller = support::pdf("minimal.pdf");
    // Capture the Vec object address, never its reallocatable heap allocation.
    // No output Vec is assigned back to this binding at any point.
    let caller_identity: *const Vec<u8> = std::ptr::from_ref(&caller);
    let original = caller.clone();
    let (mut update, signature_id) = certification(PdfUpdate::new(&caller).unwrap());
    let prepared = write_and_digest_in_place(
        &mut caller,
        &mut update,
        signature_id,
        RESERVED,
        DigestAlgorithm::Sha256,
    )
    .unwrap();
    assert!(prepared.output().starts_with(&original));
    assert_eq!(prepared.md_algorithm, DigestAlgorithm::Sha256);
    assert_eq!(
        prepared.reserved_region_end - prepared.reserved_region_start,
        RESERVED + 2
    );
    assert_eq!(
        prepared.byte_range,
        [
            0,
            prepared.reserved_region_start,
            prepared.reserved_region_end,
            prepared.output().len() - prepared.reserved_region_end,
        ]
    );
    let mut signed_bytes = prepared.output()[..prepared.reserved_region_start].to_vec();
    signed_bytes.extend_from_slice(&prepared.output()[prepared.reserved_region_end..]);
    assert_eq!(
        prepared.document_digest,
        DigestAlgorithm::Sha256.digest(&signed_bytes)
    );
    let cms = cms_for_digest(&prepared.document_digest);
    let same_caller = prepared.fill_with_cms(&cms).unwrap();
    assert!(std::ptr::eq(
        caller_identity,
        std::ptr::from_ref(&*same_caller)
    ));
    let before_dss = same_caller.clone(); // A comparison snapshot, not an output replacement.
    let signed_end = same_caller.len();
    let signature = support::pdfcheck::embedded_signatures(same_caller).remove(0);
    assert_eq!(signature.field_name, "Signature");
    assert_eq!(
        signature.byte_range[2] - signature.byte_range[1],
        (RESERVED + 2) as i64
    );
    support::pdfcheck::check_integrity(same_caller, &signature);
    assert_eq!(
        read_certification_level(&PdfUpdate::new(same_caller).unwrap()).unwrap(),
        Some(MdpPerm::NoChanges)
    );
    assert!(support::pdfcheck::dss_counts(same_caller).is_none());
    exact_live_oracle(same_caller, false);

    let signer = support::pki("testing-ca").signer("signer1");
    let same_caller = add_dss_in_place(
        same_caller,
        &DssContent {
            sig_contents: Some(&signature.contents),
            certs: signer.cert_chain().to_vec(),
            ocsps: vec![support::pyhanko_data(&["crypto", "ocsp.resp.der"])],
            ..Default::default()
        },
        false,
    )
    .unwrap();
    assert!(std::ptr::eq(
        caller_identity,
        std::ptr::from_ref(&*same_caller)
    ));
    assert!(same_caller.starts_with(&before_dss));
    let updated_signature = support::pdfcheck::embedded_signatures(same_caller).remove(0);
    assert_eq!(updated_signature.contents, signature.contents);
    assert_eq!(updated_signature.byte_range, signature.byte_range);
    assert_eq!(
        usize::try_from(updated_signature.byte_range[2] + updated_signature.byte_range[3]).unwrap(),
        signed_end
    );
    support::pdfcheck::check_integrity(same_caller, &updated_signature);
    let (certificates, ocsps, _, _) = support::pdfcheck::dss_counts(same_caller).unwrap();
    assert_eq!(certificates, 3);
    assert_eq!(ocsps, 1);
    exact_live_oracle(same_caller, true);
    assert!(std::ptr::eq(caller_identity, std::ptr::from_ref(&caller)));
}

#[test]
fn preparation_errors_leave_the_caller_bytes_unchanged() {
    for failure in ["odd reservation", "missing signature", "different base"] {
        let mut caller = support::pdf("minimal.pdf");
        let caller_identity: *const Vec<u8> = std::ptr::from_ref(&caller);
        let (mut update, signature_id) = certification(PdfUpdate::new(&caller).unwrap());
        if failure == "different base" {
            caller.push(b'\n');
        }
        let before = caller.clone();
        let id = if failure == "missing signature" {
            (u32::MAX, 0)
        } else {
            signature_id
        };
        let reserve = if failure == "odd reservation" {
            RESERVED - 1
        } else {
            RESERVED
        };
        assert!(
            write_and_digest_in_place(
                &mut caller,
                &mut update,
                id,
                reserve,
                DigestAlgorithm::Sha256
            )
            .is_err(),
            "{failure}"
        );
        assert_eq!(caller, before, "{failure}");
        assert!(std::ptr::eq(caller_identity, std::ptr::from_ref(&caller)));
    }
}

#[test]
fn oversized_cms_leaves_prepared_caller_bytes_unchanged() {
    let mut caller = support::pdf("minimal.pdf");
    let (mut update, signature_id) = certification(PdfUpdate::new(&caller).unwrap());
    let prepared = write_and_digest_in_place(
        &mut caller,
        &mut update,
        signature_id,
        RESERVED,
        DigestAlgorithm::Sha256,
    )
    .unwrap();
    let prepared_bytes = prepared.output().to_vec();
    assert!(prepared.fill_with_cms(&vec![0; RESERVED / 2 + 1]).is_err());
    assert_eq!(caller, prepared_bytes);
}

fn dss_input(corrupt: bool) -> (Vec<u8>, ObjectId) {
    let mut update = PdfUpdate::new(&support::pdf("minimal.pdf")).unwrap();
    let cert = support::pki("testing-ca").cert("signer1");
    let cert_stream = if corrupt {
        Stream::new(
            dictionary! { "Filter" => "FlateDecode" },
            b"invalid zlib".to_vec(),
        )
    } else {
        let mut stream = Stream::new(Dictionary::new(), cert.der().to_vec());
        stream.compress().unwrap();
        stream
    };
    let cert_id = update.add(Object::Stream(cert_stream));
    let dss = update.add(Object::Dictionary(
        dictionary! { "Certs" => vec![Object::Reference(cert_id)] },
    ));
    update.root_mut().unwrap().set("DSS", dss);
    let mut preload = Stream::new(Dictionary::new(), vec![0; 800]);
    preload.compress().unwrap();
    let preload_id = update.add(Object::Stream(preload));
    (update.write().unwrap().0, preload_id)
}

#[test]
fn failed_dss_decode_preserves_caller_bytes() {
    let (mut caller, _) = dss_input(true);
    let before = caller.clone();
    let identity: *const Vec<u8> = std::ptr::from_ref(&caller);
    let error = add_dss_in_place(&mut caller, &DssContent::default(), false)
        .err()
        .unwrap();
    assert!(error.to_string().contains("decompress"), "{error}");
    assert_eq!(caller, before);
    assert!(std::ptr::eq(identity, std::ptr::from_ref(&caller)));
}

#[test]
fn failed_dss_budget_preserves_caller_bytes_without_refreshing_allowance() {
    let (mut caller, preload_id) = dss_input(false);
    let limits = DecodeLimits {
        document_budget: Some(DocumentDecodeBudget {
            base_allowance: 1000,
            max_ratio: 0.0,
        }),
        ..Default::default()
    };
    let reader = PdfFile::parse_with(
        &caller,
        ReaderOptions {
            decode_limits: limits,
            strict: false,
            ..Default::default()
        },
    )
    .unwrap();
    let preload = reader.get_object_at(preload_id, None).unwrap();
    reader
        .read_stream_data(preload.as_stream().unwrap(), DecodePurpose::Generic, None)
        .unwrap();
    assert_eq!(reader.remaining_decode_budget(), Some(200));
    let before = caller.clone();
    let error = add_dss_in_place_with_state(
        &mut caller,
        &DssContent::default(),
        true,
        PdfReopenState::from_reader(reader),
    )
    .map(|_| ())
    .expect_err("the inherited DSS decoding budget must reject");
    assert!(error.to_string().contains("limit"), "{error}");
    assert_eq!(caller, before);
}

#[test]
fn authenticated_trusted_state_survives_borrowed_completion_and_dss() {
    let mut caller = support::pdf("minimal-with-field-aes256.pdf");
    let original = caller.clone();
    let identity: *const Vec<u8> = std::ptr::from_ref(&caller);
    let unauthenticated = PdfFile::parse(&caller).unwrap();
    assert!(add_dss_in_place_with_state(
        &mut caller,
        &DssContent::default(),
        true,
        PdfReopenState::from_reader(unauthenticated)
    )
    .is_err());
    assert_eq!(caller, original);
    let reader = PdfFile::parse_with(
        &caller,
        ReaderOptions {
            decode_limits: DecodeLimits::for_trusted_input(),
            strict: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert_ne!(
        reader.decrypt("usersecret").unwrap().status,
        AuthStatus::Failed
    );
    let (mut update, signature_id) = certification(
        PdfUpdate::open_with_state(&caller, PdfReopenState::from_reader(reader)).unwrap(),
    );
    let prepared = write_and_digest_in_place(
        &mut caller,
        &mut update,
        signature_id,
        RESERVED,
        DigestAlgorithm::Sha256,
    )
    .unwrap();
    assert!(!prepared.reopen_state.strict());
    assert_eq!(
        prepared.reopen_state.decode_context().limits,
        DecodeLimits::for_trusted_input()
    );
    let cms = cms_for_digest(&prepared.document_digest);
    let (same_caller, state) = prepared.fill_with_cms_with_state(&cms).unwrap();
    assert!(std::ptr::eq(identity, std::ptr::from_ref(&*same_caller)));
    assert!(state.reader().bytes() == same_caller.as_slice());
    assert!(state.reader().encrypted());
    assert!(!state.strict());
    let (same_caller, state) = add_dss_in_place_with_state(
        same_caller,
        &DssContent {
            certs: vec![support::pki("testing-ca").cert("root")],
            ..Default::default()
        },
        true,
        state,
    )
    .unwrap();
    assert!(std::ptr::eq(identity, std::ptr::from_ref(&*same_caller)));
    assert!(state.reader().bytes() == same_caller.as_slice());
    assert!(state.reader().encrypted());
    assert!(state
        .reader()
        .security_handler()
        .unwrap()
        .unwrap()
        .is_authenticated());
    assert!(!state.strict());
    assert_eq!(
        state.decode_context().limits,
        DecodeLimits::for_trusted_input()
    );
}

// Invoke the exact upstream val_trusted helper on both fresh Rust outputs.
// Additional no-root and altered-digest controls are independent evidence.
const EXACT_DIRECT_ASSERTIONS: &str = r#"
import importlib.metadata
import json
import sys
from io import BytesIO
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import DocumentSecurityStore, validate_pdf_signature
from pyhanko.sign.validation.generic_cms import validate_sig_integrity
from pyhanko_testing_commons.test_utils.signing_commons import FROM_CA, notrust_v_context, val_trusted
assert importlib.metadata.version('pyhanko') == '0.38.1'
with freeze_time('2020-11-01'):
    extended = sys.argv[2] == 'true'
    reader = PdfFileReader(BytesIO(open(sys.argv[1], 'rb').read()))
    signature = reader.embedded_signatures[0]
    assert signature.field_name == 'Signature'
    assert signature.docmdp_level.value == 1
    byte_range = signature.sig_object['/ByteRange']
    assert byte_range[2] - byte_range[1] == 8194
    status = val_trusted(signature, extd=extended)
    assert status.intact and status.valid and status.trusted and status.bottom_line
    assert status.pretty_print_details()
    assert status.coverage.name == ('ENTIRE_REVISION' if extended else 'ENTIRE_FILE')
    if extended:
        assert status.modification_level.name == 'LTA_UPDATES'
        dss = DocumentSecurityStore.read_dss(reader)
        assert dss is not None
        assert len(dss.certs) == 3
        assert len(dss.ocsps) == 1
    else:
        assert status.modification_level.name == 'NONE'
        assert '/DSS' not in reader.root
    untrusted = validate_pdf_signature(signature, notrust_v_context(), skip_diff=True)
    assert untrusted.intact and untrusted.valid and not untrusted.trusted
    digest = bytearray(signature.compute_digest())
    digest[0] ^= 1
    intact, valid = validate_sig_integrity(signature.signer_info, FROM_CA.signing_cert, 'data', bytes(digest))
    assert not intact and valid
    print(json.dumps({'bottom_line': status.bottom_line, 'coverage': status.coverage.name, 'modification_level': status.modification_level.name, 'details': status.pretty_print_details()}))
"#;

#[test]
fn failed_completion_reopen_preserves_prepared_bytes_and_remaining_budget() {
    use sigis_pdf::PdfFileWriter;

    let mut source = PdfFileWriter::new(true, true).unwrap();
    source
        .insert_page(
            dictionary! {
                "Type" => "Page", "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
                "Resources" => Dictionary::new(),
            },
            None,
        )
        .unwrap();
    let mut preload = Stream::new(Dictionary::new(), vec![0; 800]);
    preload.compress().unwrap();
    let preload = source.add_object(Object::Stream(preload)).unwrap();
    let mut caller = source.write().unwrap();
    let probe_limits = DecodeLimits {
        document_budget: Some(DocumentDecodeBudget {
            base_allowance: 10_000,
            max_ratio: 0.0,
        }),
        ..Default::default()
    };
    let probe = PdfFile::parse_with(
        &caller,
        ReaderOptions {
            decode_limits: probe_limits,
            ..Default::default()
        },
    )
    .unwrap();
    let eager_spent = 10_000 - probe.remaining_decode_budget().unwrap();
    assert!(
        eager_spent > 0,
        "the source uses actual xref stream decoding"
    );
    let limits = DecodeLimits {
        document_budget: Some(DocumentDecodeBudget {
            base_allowance: u64::try_from(eager_spent + 800).unwrap(),
            max_ratio: 0.0,
        }),
        ..Default::default()
    };
    let reader = PdfFile::parse_with(
        &caller,
        ReaderOptions {
            decode_limits: limits,
            ..Default::default()
        },
    )
    .unwrap();
    let stream = reader.get_object_at(preload, None).unwrap();
    reader
        .read_stream_data(stream.as_stream().unwrap(), DecodePurpose::Generic, None)
        .unwrap();
    assert_eq!(reader.remaining_decode_budget(), Some(0));
    let (mut update, signature_id) = certification(
        PdfUpdate::open_with_state(&caller, PdfReopenState::from_reader(reader)).unwrap(),
    );
    let prepared = write_and_digest_in_place(
        &mut caller,
        &mut update,
        signature_id,
        RESERVED,
        DigestAlgorithm::Sha256,
    )
    .unwrap();
    assert_eq!(
        prepared.reopen_state.decode_context().remaining_budget(),
        Some(0)
    );
    let prepared_bytes = prepared.output().to_vec();
    let cms = cms_for_digest(&prepared.document_digest);
    let error = prepared
        .fill_with_cms_with_state(&cms)
        .map(|_| ())
        .expect_err("completion cannot reopen a new xref stream with exhausted allowance");
    assert!(error.to_string().contains("limit"), "{error}");
    assert_eq!(caller, prepared_bytes);
}

#[test]
fn borrowed_mac_completion_and_dss_keep_document_session_and_buffer_identity() {
    use sigis_pades_sign::pdf::mac::PdfMacSessions;
    use sigis_pdf::crypt::{PdfMacStatus, StandardEncryptOptions};
    use sigis_pdf::PdfFileWriter;

    let mut source = PdfFileWriter::new(false, true).unwrap();
    source
        .insert_page(
            dictionary! {
                "Type" => "Page", "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
                "Resources" => Dictionary::new(),
            },
            None,
        )
        .unwrap();
    source
        .encrypt_with("secret", None, StandardEncryptOptions::default())
        .unwrap();
    let mut caller = source.write().unwrap();
    let identity: *const Vec<u8> = std::ptr::from_ref(&caller);
    let (mut update, signature_id) =
        certification(PdfUpdate::with_password(&caller, b"secret").unwrap());
    let registry = PdfMacSessions::default();
    let handler = update.security_handler().unwrap().clone();
    let session = registry.begin(&handler, "sha256").unwrap().unwrap();
    update.set_auth_code(Object::Dictionary(dictionary! {
        "MACLocation" => "AttachedToSig", "SigObjRef" => signature_id,
    }));
    let mut prepared = write_and_digest_in_place(
        &mut caller,
        &mut update,
        signature_id,
        // Additional ISO 32004 attributes need space beyond the exact
        // plaintext upstream case, which still reserves precisely 8192.
        RESERVED * 2,
        DigestAlgorithm::Sha256,
    )
    .unwrap();
    prepared.mac_session = Some(session);
    assert!(registry.begin(&handler, "sha256").is_err());
    let cms = cms_for_digest(&prepared.document_digest);
    let (same_caller, state) = prepared.fill_with_cms_with_state(&cms).unwrap();
    assert!(std::ptr::eq(identity, std::ptr::from_ref(&*same_caller)));
    assert_eq!(
        state.reader().decrypt("secret").unwrap().mac_status,
        PdfMacStatus::Successful
    );
    assert!(registry.begin(&handler, "sha256").unwrap().is_some());
    let (same_caller, state) = add_dss_in_place_with_state(
        same_caller,
        &DssContent {
            certs: vec![support::pki("testing-ca").cert("root")],
            ..Default::default()
        },
        true,
        state,
    )
    .unwrap();
    assert!(std::ptr::eq(identity, std::ptr::from_ref(&*same_caller)));
    assert_eq!(
        state.reader().decrypt("secret").unwrap().mac_status,
        PdfMacStatus::Successful
    );
    assert!(state.reader().bytes() == same_caller.as_slice());
}
