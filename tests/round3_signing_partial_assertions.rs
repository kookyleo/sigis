//! Missing assertions and direct Rust checks for inherited upstream ports.
//!
//! The two test_cms.py functions remain S-owned and earn no P function counts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/signing_integration.rs"]
mod support;

use std::sync::Arc;

use sigis_pades::SignatureCoverageLevel;
use sigis_pades_sign::cms::{AttrProfile, CmsSigner, CmsSignerOptions};
use sigis_pades_sign::pdf::dss::{add_dss, DssContent};
use sigis_pades_sign::pdf::signer::{
    write_and_digest, DssContentSettings, SigDssPlacement, SigMdpSetup, SignatureObjectSpec,
};
use sigis_pades_sign::pdf::timestamp::TimestampDssSettings;
use sigis_pades_sign::{
    CmsSignedAttributes, PdfSignatureMetadata, PdfSigner, SignOptions, SimpleSigner,
};
use sigis_pdf::MdpPerm;
use sigis_pdf_diff::{DiffOutcome, ModificationLevel, StandardDiffPolicy};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::errors::HankoError;
use sigis_pki_core::sign::KeySigner;

const TIME: &str = "2020-11-01T00:00:00Z";

fn rust_status(output: &[u8], trusted: bool, extended: bool) -> sigis_pades::PdfSignatureStatus {
    let file = sigis_pdf::PdfFile::parse(output).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    let context = if trusted {
        support::services::live_testing_vc("testing-ca", TIME, &[])
    } else {
        sigis_pki_certvalidator::ValidationContext::builder()
            .moment(support::at(TIME))
            .build()
            .unwrap()
    };
    sigis_pades::validate_pdf_signature(
        &file,
        &signatures[0],
        &context,
        extended.then_some(&StandardDiffPolicy as &dyn sigis_pdf_diff::DiffPolicy),
    )
    .unwrap()
}

fn oracle_status(output: &[u8], trusted: bool, extended: bool) -> serde_json::Value {
    let root = support::pki("testing-ca").cert_path("root");
    let trust = if trusted {
        vec![root.as_path()]
    } else {
        Vec::new()
    };
    let extra = if extended { vec!["--extd"] } else { Vec::new() };
    support::pdfcheck::oracle_verdicts(output, &trust, TIME, &extra)
        .expect("the pinned live oracle is required to accept these assertions")
        .remove(0)
}

fn assert_trusted(output: &[u8], extended: bool) {
    let status = rust_status(output, true, extended);
    assert!(status.cms.signature.intact && status.cms.signature.valid);
    assert!(status.cms.signature.trusted());
    assert!(status.cms.summary().contains("INTACT"));
    assert!(status.cms.summary().contains("TRUSTED"));
    assert!(!status.cms.pretty_print_details().is_empty());
    assert!(status.bottom_line(), "{status:?}");
    if extended {
        assert_eq!(status.coverage, SignatureCoverageLevel::EntireRevision);
        let Some(DiffOutcome::Reviewed(review)) = status.diff_result else {
            panic!("the DSS update must pass an actual difference review");
        };
        assert!(review.modification_level <= ModificationLevel::FormFilling);
    } else {
        assert_eq!(status.coverage, SignatureCoverageLevel::EntireFile);
    }
    let oracle = oracle_status(output, true, extended);
    assert_eq!(oracle["intact"], true, "{oracle}");
    assert_eq!(oracle["valid"], true, "{oracle}");
    assert_eq!(oracle["trusted"], true, "{oracle}");
    assert_eq!(oracle["bottom_line"], true, "{oracle}");
    assert!(oracle["summary"].as_str().unwrap().contains("INTACT"));
    assert!(oracle["summary"].as_str().unwrap().contains("TRUSTED"));
    assert_eq!(
        oracle["coverage"],
        if extended {
            "ENTIRE_REVISION"
        } else {
            "ENTIRE_FILE"
        },
        "{oracle}"
    );
    let level = oracle["modification_level"].as_str().unwrap();
    if extended {
        assert!(["NONE", "LTA_UPDATES", "FORM_FILLING"].contains(&level));
    } else {
        assert_eq!(level, "NONE");
    }
    eprintln!("live oracle trusted extended={extended}: {oracle}");
}

/// S-owned: restore the signer-refusal half omitted by the CMS replay test.
#[test]
fn test_overspecify_cms_digest_algo() {
    let signer = SimpleSigner::load(
        &support::pyhanko_data(&["crypto", "selfsigned.key.pem"]),
        &support::pyhanko_data(&["crypto", "selfsigned.cert.pem"]),
        Some(b"secret"),
        vec![
            sigis_pades_sign::keys::load_cert_from_pemder_data(&support::pyhanko_data(&[
                "crypto",
                "selfsigned.cert.pem",
            ]))
            .unwrap(),
        ],
    )
    .unwrap()
    .with_signature_mechanism(spki::AlgorithmIdentifierOwned {
        oid: sigis_pki_core::asn1::oids::SHA256_WITH_RSA,
        parameters: None,
    });
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults("Sig1");
    metadata.md_algorithm = Some(DigestAlgorithm::Sha256);
    let output = PdfSigner::new(metadata.clone(), Arc::new(signer.clone()))
        .at(support::at(TIME))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .unwrap();
    let status = rust_status(&output, false, false);
    assert!(status.cms.signature.intact && status.cms.signature.valid);
    assert!(!status.cms.signature.trusted());
    assert_eq!(status.coverage, SignatureCoverageLevel::EntireFile);
    assert!(status.cms.summary().contains("INTACT"));
    assert!(!status.cms.pretty_print_details().is_empty());
    let oracle = oracle_status(&output, false, false);
    assert_eq!(oracle["intact"], true, "{oracle}");
    assert_eq!(oracle["valid"], true, "{oracle}");
    assert_eq!(oracle["coverage"], "ENTIRE_FILE", "{oracle}");
    assert_eq!(oracle["modification_level"], "NONE", "{oracle}");
    assert!(oracle["summary"].as_str().unwrap().contains("INTACT"));
    metadata.md_algorithm = Some(DigestAlgorithm::Sha512);
    let error = PdfSigner::new(metadata, Arc::new(signer))
        .at(support::at(TIME))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .unwrap_err();
    assert!(matches!(error, HankoError::Signing(_)), "{error}");
    eprintln!("Rust overspecified mechanism refused: {error}; oracle matching digest: {oracle}");
}

/// S-owned: complete low-level certification, validation, DSS update and revalidation.
#[test]
fn test_direct_pdfcmsembedder_usage() {
    let input = support::pdf("minimal.pdf");
    let mut update = sigis_pades_sign::pdf::writer::PdfUpdate::new(&input).unwrap();
    let (_, field) = sigis_pades_sign::pdf::fields::prepare_sig_field(
        &mut update,
        "Signature",
        false,
        &Default::default(),
    )
    .unwrap();
    let field_object = update.get_dict(field).unwrap();
    let lopdf::Object::String(name, _) = field_object.get(b"T").unwrap() else {
        panic!("the prepared signature field must have a string name");
    };
    assert_eq!(
        sigis_pades_sign::pdf::util::decode_text_string(name),
        "Signature"
    );
    sigis_pades_sign::pdf::fields::ensure_sig_flags(&mut update, true).unwrap();
    let mut dictionary = SignatureObjectSpec {
        timestamp: Some(support::at(TIME)),
        ..Default::default()
    }
    .to_dict(false);
    let signature_id = update.add(lopdf::Object::Null);
    SigMdpSetup {
        certify: true,
        field_lock: None,
        docmdp_perms: Some(MdpPerm::NoChanges),
    }
    .apply(&mut update, &mut dictionary, signature_id)
    .unwrap();
    update.update(signature_id, lopdf::Object::Dictionary(dictionary));
    update
        .get_dict_mut(field)
        .unwrap()
        .set("V", lopdf::Object::Reference(signature_id));
    let prepared =
        write_and_digest(&mut update, signature_id, 8192, DigestAlgorithm::Sha256).unwrap();
    let signer = support::pki("testing-ca").signer("signer1");
    let cms = CmsSigner {
        signer: &signer,
        options: &CmsSignerOptions::default(),
    }
    .sign(
        &prepared.document_digest,
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
    .unwrap();
    let output = prepared.fill_with_cms(&cms).unwrap();
    // Rust returns owned bytes. This proves incremental prefix preservation;
    // the upstream caller-buffer identity assertion remains unported.
    assert!(output.starts_with(&input));
    assert_trusted(&output, false);
    let signature = &support::pdfcheck::embedded_signatures(&output)[0];
    let updated = add_dss(
        &output,
        &DssContent {
            sig_contents: Some(&signature.contents),
            certs: signer.cert_chain().to_vec(),
            ocsps: vec![support::pyhanko_data(&["crypto", "ocsp.resp.der"])],
            ..Default::default()
        },
        false,
    )
    .unwrap();
    assert_trusted(&updated, true);
    let (certificates, ocsps, _, _) =
        support::pdfcheck::dss_counts(&updated).expect("DSS required");
    assert_eq!(certificates, 3);
    assert_eq!(ocsps, 1);
}

fn sign_pades(settings: DssContentSettings, lta: bool) -> Vec<u8> {
    let mut metadata = PdfSignatureMetadata::new("Sig1");
    metadata.dss_settings = settings;
    metadata.embed_validation_info = true;
    metadata.use_pades_lta = lta;
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
    .sign_pdf_with(
        &support::pdf("minimal-with-field.pdf"),
        &SignOptions {
            fresh_document: true,
            ..Default::default()
        },
    )
    .unwrap()
}

fn assert_pades_two_revisions(output: &[u8], case: usize) {
    let file = sigis_pdf::PdfFile::parse(output).unwrap();
    assert_eq!(file.total_revisions(), 2, "case {case}");
    let status = rust_status(output, true, true);
    assert!(status.bottom_line(), "case {case}: {status:?}");
    let root = support::pki("testing-ca").cert_path("root");
    let oracle = support::pdfcheck::ades_lta(output, &[&root], TIME, false)
        .expect("the pinned oracle must execute the upstream LTA check");
    assert_eq!(oracle[0]["bottom_line"], true, "case {case}: {}", oracle[0]);
    eprintln!("live oracle DSS settings case {case}: {}", oracle[0]);
}

#[test]
fn test_pades_two_revisions() {
    for (case, settings) in [
        DssContentSettings {
            placement: SigDssPlacement::SeparateRevision,
            ..Default::default()
        },
        DssContentSettings {
            placement: SigDssPlacement::TogetherWithNextTs,
            ..Default::default()
        },
        DssContentSettings::default(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_pades_two_revisions(&sign_pades(settings, false), case);
    }
}

#[test]
fn test_pades_lta_two_revisions() {
    let before = TimestampDssSettings {
        update_before_ts: true,
        include_vri: false,
        ..Default::default()
    };
    for (case, settings) in [
        DssContentSettings {
            placement: SigDssPlacement::TogetherWithNextTs,
            next_ts_settings: Some(before),
            ..Default::default()
        },
        DssContentSettings {
            placement: SigDssPlacement::TogetherWithSignature,
            include_vri: false,
            next_ts_settings: Some(before),
            ..Default::default()
        },
        DssContentSettings {
            placement: SigDssPlacement::TogetherWithSignature,
            include_vri: false,
            ..Default::default()
        },
        DssContentSettings {
            placement: SigDssPlacement::TogetherWithNextTs,
            include_vri: false,
            ..Default::default()
        },
    ]
    .into_iter()
    .enumerate()
    {
        assert_pades_two_revisions(&sign_pades(settings, true), case);
    }
}

#[test]
fn test_dss_setting_validation() {
    let bad = TimestampDssSettings {
        include_vri: true,
        update_before_ts: true,
        ..Default::default()
    };
    assert!(matches!(
        bad.assert_viable().unwrap_err(),
        HankoError::Signing(_)
    ));
    assert!(matches!(
        DssContentSettings {
            include_vri: true,
            placement: SigDssPlacement::TogetherWithSignature,
            ..Default::default()
        }
        .assert_viable()
        .unwrap_err(),
        HankoError::Signing(_)
    ));
    DssContentSettings {
        include_vri: true,
        placement: SigDssPlacement::TogetherWithNextTs,
        ..Default::default()
    }
    .assert_viable()
    .unwrap();
    DssContentSettings {
        include_vri: false,
        placement: SigDssPlacement::TogetherWithSignature,
        ..Default::default()
    }
    .assert_viable()
    .unwrap();
    assert!(matches!(
        DssContentSettings {
            include_vri: false,
            placement: SigDssPlacement::TogetherWithSignature,
            next_ts_settings: Some(bad),
            ..Default::default()
        }
        .assert_viable()
        .unwrap_err(),
        HankoError::Signing(_)
    ));
}
