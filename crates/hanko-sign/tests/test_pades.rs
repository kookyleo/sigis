//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_pades.py`.
//!
//! The AdES checks (`_simple_pades_check`, `ades_lta_validation`) run in
//! pyHanko through the oracle until lane E's `sigis-pades` lands.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pades_sign::pdf::timestamp::{PdfTimeStamper, TimestampOptions};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SubFilter};
use support::pdfcheck::*;
use support::services::*;
use support::*;

const T: &str = "2020-11-01T00:00:00+00:00";

fn ca() -> Pki {
    pki("testing-ca")
}

fn pades_meta(field: &str) -> PdfSignatureMetadata {
    let mut m = PdfSignatureMetadata::pyhanko_defaults(field);
    m.subfilter = Some(SubFilter::Pades);
    m
}

fn signer_at(meta: PdfSignatureMetadata, time: &str) -> PdfSigner {
    PdfSigner::new(meta, Arc::new(ca().signer("signer1"))).at(at(time))
}

fn dummy_ts(time: &str) -> Arc<sigis_pades_sign::DummyTimeStamper> {
    Arc::new(ca().tsa("tsa", at(time)))
}

fn one_field() -> Vec<u8> {
    pdf("minimal-with-field.pdf")
}

fn trust_root() -> std::path::PathBuf {
    ca().cert_path("root")
}

/// `_simple_pades_check(TRUST_ROOTS, sig)` at `time`.
fn pades_check(pdf: &[u8], ix: usize, time: &str) -> Option<serde_json::Value> {
    let root = trust_root();
    ades_lta(pdf, &[&root], time, false).map(|v| v[ix].clone())
}

fn lta_meta(time: &str) -> PdfSignatureMetadata {
    let mut m = pades_meta("Sig1");
    m.validation_context = Some(Arc::new(live_testing_vc("testing-ca", time, &[])));
    m.embed_validation_info = true;
    m.use_pades_lta = true;
    m
}

#[test]
fn test_pades_flag() {
    let out = signer_at(pades_meta("Sig1"), T).sign_pdf(&one_field()).unwrap();
    let s = &embedded_signatures(&out)[0];
    assert_eq!(s.field_name, "Sig1");
    assert_eq!(s.subfilter(), "ETSI.CAdES.detached");
    let doc = load(&out);
    let Some(lopdf::Object::Dictionary(ext)) = dict_get(&doc, root(&doc), b"Extensions") else {
        panic!("no /Extensions")
    };
    assert!(ext.get(b"ESIC").is_ok());
    assert!(out.starts_with(b"%PDF-1.7"));
}

#[test]
fn test_pades_pdf2() {
    // pyHanko raises the version in the signing revision; we do it in a
    // preceding update, which is equivalent for this check
    let mut w = sigis_pades_sign::pdf::writer::PdfUpdate::new(&one_field()).unwrap();
    sigis_pades_sign::pdf::signer::ensure_output_version(&mut w, (2, 0)).unwrap();
    let (bytes, _) = w.write().unwrap();
    let out = signer_at(pades_meta("Sig1"), T).sign_pdf(&bytes).unwrap();
    let s = &embedded_signatures(&out)[0];
    assert_eq!(s.subfilter(), "ETSI.CAdES.detached");
    let doc = load(&out);
    assert!(dict_get(&doc, root(&doc), b"Extensions").is_none());
}

#[test]
fn test_pades_revinfo_nodata() {
    let mut m = pades_meta("Sig1");
    m.embed_validation_info = true;
    let err = signer_at(m, T).sign_pdf(&one_field()).unwrap_err();
    assert!(err.to_string().contains("validation context must be provided"), "{err}");
}

#[test]
fn test_pades_revinfo_live_no_timestamp() {
    let mut m = pades_meta("Sig1");
    m.validation_context = Some(Arc::new(live_testing_vc("testing-ca", T, &[])));
    m.embed_validation_info = true;
    let out = signer_at(m, T).sign_pdf(&one_field()).unwrap();
    if let Ok(p) = std::env::var("HANKO_DUMP") {
        std::fs::write(p, &out).unwrap();
    }
    check_integrity(&out, &embedded_signatures(&out)[0]);
    if let Some(s) = pades_check(&out, 0, T) {
        assert_eq!(s["bottom_line"], true, "{s}");
    }
}

#[test]
fn test_pades_dss_content() {
    let mut m = pades_meta("Sig1");
    m.validation_context = Some(Arc::new(live_testing_vc("testing-ca", T, &[])));
    m.embed_validation_info = true;
    let out = signer_at(m, T).with_timestamper(dummy_ts(T)).sign_pdf(&one_field()).unwrap();
    let (certs, ocsps, crls, vri) = dss_counts(&out).unwrap();
    assert_eq!(vri, 1);
    assert_eq!(certs, 5);
    assert_eq!(ocsps, 1);
    assert_eq!(crls, 1);
}

#[test]
fn test_pades_revinfo_live() {
    let mut m = pades_meta("Sig1");
    m.validation_context = Some(Arc::new(live_testing_vc("testing-ca", T, &[])));
    m.embed_validation_info = true;
    let out = signer_at(m, T).with_timestamper(dummy_ts(T)).sign_pdf(&one_field()).unwrap();
    if let Some(s) = pades_check(&out, 0, T) {
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
        assert_eq!(s["modification_level"], "LTA_UPDATES", "{s}");
    }
    if let Some(s) = pades_check(&out, 0, "2025-11-01T00:00:00+00:00") {
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
    }
    if let Some(s) = pades_check(&out, 0, "2040-11-01T00:00:00+00:00") {
        assert_eq!(s["trusted"], false, "{s}");
        assert_eq!(s["ades_subindic"], "NO_POE", "{s}");
    }
}

#[test]
fn test_pades_revinfo_live_update() {
    let out = signer_at(lta_meta(T), T).with_timestamper(dummy_ts(T)).sign_pdf(&one_field()).unwrap();
    let vc = live_testing_vc("testing-ca", T, &[]);
    let out = PdfTimeStamper::new(dummy_ts(T))
        .update_archival_timestamp_chain(&out, &vc, DigestAlgorithm::Sha256)
        .unwrap();
    assert_eq!(sig_kinds(&out), (1, 2));
    if let Some(s) = pades_check(&out, 0, T) {
        assert_eq!(s["bottom_line"], true, "{s}");
        assert_eq!(s["modification_level"], "LTA_UPDATES", "{s}");
    }
}

#[test]
fn test_update_no_timestamps() {
    let vc = simple_vc("testing-ca", T);
    let out = PdfTimeStamper::new(dummy_ts(T))
        .update_archival_timestamp_chain(&pdf("minimal.pdf"), &vc, DigestAlgorithm::Sha256)
        .unwrap();
    let sigs = embedded_signatures(&out);
    assert_eq!(sigs[0].sig_type(), "DocTimeStamp");
    assert_eq!(
        sigs[0].field.get(b"TU").unwrap(),
        &lopdf::Object::string_literal("Timestamp")
    );
    let root = trust_root();
    if let Some(v) = oracle_verdicts(&out, &[&root], T, &[]) {
        assert_eq!(v[0]["valid"], true, "{}", v[0]);
        assert_eq!(v[0]["trusted"], true, "{}", v[0]);
    }
}

/// `_test_pades_revinfo_live_lta_validate`.
fn lta_validate(out: &[u8], no_write: bool, has_more_sigs: bool) {
    let expected_mod = if has_more_sigs { "FORM_FILLING" } else { "LTA_UPDATES" };
    if !has_more_sigs {
        let (certs, ocsps, crls, vri) = dss_counts(out).unwrap();
        assert_eq!((vri, certs, ocsps, crls), (2, 5, 1, 1));
    }
    let sigs = embedded_signatures(out);
    assert_eq!(sigs[1].sig_type(), "DocTimeStamp");
    if let Some(s) = pades_check(out, 0, T) {
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
        assert_eq!(s["modification_level"], expected_mod, "{s}");
    }
    if let Some(s) = pades_check(out, 0, "2025-11-01T00:00:00+00:00") {
        assert_eq!(s["trusted"], true, "{s}");
    }
    if let Some(s) = pades_check(out, 0, "2035-11-01T00:00:00+00:00") {
        assert_eq!(s["trusted"], false, "{s}");
        assert_eq!(s["ades_subindic"], "NO_POE", "{s}");
    }
    if no_write {
        return;
    }
    let t2 = "2028-12-01T00:00:00+00:00";
    let vc = live_testing_vc("testing-ca", t2, &[]);
    let ts2 = Arc::new(ca().tsa("tsa2", at(t2)));
    let out = PdfTimeStamper::new(ts2)
        .update_archival_timestamp_chain(out, &vc, DigestAlgorithm::Sha256)
        .unwrap();
    if let Some(s) = pades_check(&out, 0, t2) {
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
        assert_eq!(s["modification_level"], expected_mod, "{s}");
    }
    if let Some(s) = pades_check(&out, 0, "2035-11-01T00:00:00+00:00") {
        assert_eq!(s["trusted"], true, "{s}");
    }
    if let Some(s) = pades_check(&out, 0, "2040-11-01T00:00:00+00:00") {
        assert_eq!(s["trusted"], false, "{s}");
        assert_eq!(s["ades_subindic"], "NO_POE", "{s}");
    }
}

#[test]
fn test_pades_revinfo_live_lta() {
    let out = signer_at(lta_meta(T), T).with_timestamper(dummy_ts(T)).sign_pdf(&one_field()).unwrap();
    lta_validate(&out, false, false);
}

#[test]
fn test_pades_lta_sign_twice() {
    let t1 = "2020-10-01T00:00:00+00:00";
    let mut m1 = lta_meta(t1);
    m1.field_name = "Sig1".into();
    let out = signer_at(m1, t1)
        .with_timestamper(dummy_ts(t1))
        .sign_pdf(&pdf("minimal-two-fields.pdf"))
        .unwrap();
    let mut m2 = lta_meta(T);
    m2.field_name = "Sig2".into();
    let out = signer_at(m2, T).with_timestamper(dummy_ts(T)).sign_pdf(&out).unwrap();
    lta_validate(&out, true, true);
    if let Some(s) = pades_check(&out, 2, "2025-12-01T00:00:00+00:00") {
        assert_eq!(s["bottom_line"], true, "{s}");
    }
}

#[test]
fn test_pades_lta_sign_twice_post_expiry() {
    let t1 = "2020-10-01T00:00:00+00:00";
    let out = signer_at(lta_meta(t1), t1)
        .with_timestamper(dummy_ts(t1))
        .sign_pdf(&pdf("minimal-two-fields.pdf"))
        .unwrap();
    let t2 = "2020-10-10T00:00:00+00:00";
    let mut m2 = lta_meta(t2);
    m2.field_name = "Sig2".into();
    m2.validation_context = Some(Arc::new(simple_vc("testing-ca-ecdsa", t2)));
    let err = PdfSigner::new(m2, Arc::new(pki("testing-ca-ecdsa").signer("signer1")))
        .at(at(t2))
        .with_timestamper(dummy_ts(t2))
        .sign_pdf(&out)
        .unwrap_err();
    assert!(err.to_string().contains("most recent timestamp"), "{err}");
}

#[test]
fn test_standalone_document_timestamp() {
    let vc = live_testing_vc("testing-ca", T, &[]);
    let mut opts = TimestampOptions::new(DigestAlgorithm::Sha256);
    opts.validation_context = Some(&vc);
    let out = PdfTimeStamper::new(dummy_ts(T)).timestamp_pdf(&one_field(), &opts).unwrap();
    let root = trust_root();
    if let Some(v) = oracle_verdicts(&out, &[&root], T, &[]) {
        let s = &v[0];
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
        assert_eq!(s["coverage"], "ENTIRE_REVISION", "{s}");
        assert_eq!(s["modification_level"], "LTA_UPDATES", "{s}");
    }
    let mut tampered = out.clone();
    tampered[0x9D] = b'4';
    if let Some(v) = oracle_verdicts(&tampered, &[&root], T, &[]) {
        assert_eq!(v[0]["intact"], false, "{}", v[0]);
        assert_eq!(v[0]["valid"], true, "{}", v[0]);
    }
}

fn add_revinfo_later(with_vri: bool) {
    let out = PdfSigner::new(PdfSignatureMetadata::pyhanko_defaults("Sig1"), Arc::new(ca().signer("signer1")))
        .at(at(T))
        .with_timestamper(dummy_ts(T))
        .sign_pdf(&pdf("minimal.pdf"))
        .unwrap();
    let t2 = "2020-12-01T00:00:00+00:00";
    let vc = live_testing_vc("testing-ca", t2, &[]);
    let w = sigis_pades_sign::pdf::writer::PdfUpdate::new(&out).unwrap();
    let sig = sigis_pades_sign::pdf::embedded::embedded_signatures(&w).unwrap().remove(0);
    let out = sigis_pades_sign::pdf::timestamp::add_validation_info_for(&out, &sig, &vc, true, with_vri, false).unwrap();
    if let Some(s) = pades_check(&out, 0, t2) {
        assert_eq!(s["bottom_line"], true, "{s}");
    }
}

#[test]
fn test_add_revinfo_later_with_vri() {
    add_revinfo_later(true);
}

#[test]
fn test_add_revinfo_later_without_vri() {
    add_revinfo_later(false);
}

#[test]
fn test_add_revinfo_and_timestamp() {
    let out = PdfSigner::new(PdfSignatureMetadata::pyhanko_defaults("Sig1"), Arc::new(ca().signer("signer1")))
        .at(at(T))
        .sign_pdf(&pdf("minimal.pdf"))
        .unwrap();
    let t2 = "2020-12-01T00:00:00+00:00";
    let vc = live_testing_vc("testing-ca", t2, &[]);
    let w = sigis_pades_sign::pdf::writer::PdfUpdate::new(&out).unwrap();
    let sig = sigis_pades_sign::pdf::embedded::embedded_signatures(&w).unwrap().remove(0);
    let out = sigis_pades_sign::pdf::timestamp::add_validation_info_for(&out, &sig, &vc, true, true, false).unwrap();
    let mut opts = TimestampOptions::new(DigestAlgorithm::Sha256);
    opts.validation_context = Some(&vc);
    let out = PdfTimeStamper::new(dummy_ts(t2)).timestamp_pdf(&out, &opts).unwrap();
    if let Some(s) = pades_check(&out, 0, t2) {
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
    }
}

#[test]
fn test_sign_with_commitment() {
    use sigis_pki_core::asn1::commitment::CommitmentType;
    let mut m = pades_meta("Sig1");
    m.cades_signed_attr_spec = Some(sigis_pades_sign::CadesSignedAttrSpec {
        commitment_type: Some(sigis_pades_sign::attributes::commitment_indication(
            CommitmentType::ProofOfOrigin,
        )),
        ..Default::default()
    });
    let out = signer_at(m, T).sign_pdf(&pdf("minimal.pdf")).unwrap();
    assert_eq!(embedded_signatures(&out)[0].field_name, "Sig1");
    val_trusted(&out, 0, &ca(), T, false);
    let attr = signed_attr(&out, sigis_pki_core::asn1::oids::AA_ETS_COMMITMENT_TYPE).unwrap();
    let ind: sigis_pki_core::asn1::commitment::CommitmentTypeIndication = attr.decode_as().unwrap();
    assert_eq!(ind.commitment_type_id, sigis_pki_core::asn1::oids::CTI_PROOF_OF_ORIGIN);
}

/// The first value of signed attribute `oid` of the first signature.
fn signed_attr(pdf: &[u8], oid: const_oid::ObjectIdentifier) -> Option<der::Any> {
    let sig = &embedded_signatures(pdf)[0];
    let sd = sigis_pades_sign::cms::decode_signed_data(&cms_bytes(sig)).unwrap();
    let si = sd.signer_infos.0.iter().next().unwrap().clone();
    let attrs = si.signed_attrs?;
    let a = attrs.iter().find(|a| a.oid == oid)?;
    a.values.iter().next().cloned()
}

#[test]
fn test_sign_with_content_sig() {
    let mut m = pades_meta("Sig1");
    m.cades_signed_attr_spec = Some(sigis_pades_sign::CadesSignedAttrSpec {
        timestamp_content: true,
        ..Default::default()
    });
    let out = signer_at(m, T).with_timestamper(dummy_ts(T)).sign_pdf(&pdf("minimal.pdf")).unwrap();
    if let Some(s) = val_trusted(&out, 0, &ca(), T, false) {
        let c = &s["content_timestamp_validity"];
        assert_eq!(c["intact"], true, "{s}");
        assert_eq!(c["valid"], true, "{s}");
        assert_eq!(c["trusted"], true, "{s}");
    }
    let tok = signed_attr(&out, sigis_pades_sign::attributes::CONTENT_TIME_STAMP).unwrap();
    let info = sigis_pades_sign::timestamps::tst_info(&der::Encode::to_der(&tok).unwrap()).unwrap();
    assert_eq!(info.version, x509_tsp::TspVersion::V1);
}

#[test]
fn test_sign_with_wrong_content_sig() {
    // pyHanko installs a custom signed attribute provider that timestamps
    // the wrong data; we build the same attribute set with the low-level API
    use sigis_pades_sign::cms::{AttrProfile, CmsSigner, CmsSignerOptions};
    let m = pades_meta("Sig1");
    let signer = ca().signer("signer1");
    let ts = dummy_ts(T);
    let pdf_signer = PdfSigner::new(m, Arc::new(signer.clone())).at(at(T));
    // the extra attribute does not take part in the size estimate
    let tbs = pdf_signer
        .digest_doc_for_signing(&pdf("minimal.pdf"), &sigis_pades_sign::SignOptions { bytes_reserved: Some(32768), ..Default::default() })
        .unwrap();
    let opts = CmsSignerOptions::default();
    let cs = CmsSigner { signer: &signer, options: &opts };
    let mut attrs = cs
        .signed_attrs(
            &tbs.prepared.document_digest,
            DigestAlgorithm::Sha256,
            &tbs.signed_attr_settings,
            AttrProfile::Cades { is_pades: true },
            sigis_pades_sign::attributes::ID_DATA,
            None,
            false,
        )
        .unwrap();
    use sigis_pki_core::sign::TimeStamper;
    let wrong = ts.timestamp(&DigestAlgorithm::Sha256.digest(b"\xde\xad\xbe\xef"), DigestAlgorithm::Sha256).unwrap();
    attrs.push(sigis_pades_sign::attributes::raw_attribute(sigis_pades_sign::attributes::CONTENT_TIME_STAMP, &wrong).unwrap());
    let cms = cs
        .sign_prescribed_attributes(DigestAlgorithm::Sha256, attrs, cms::content_info::CmsVersion::V1, Some(ts.as_ref()), false, None)
        .unwrap();
    let out = sigis_pades_sign::pdf::signer::PdfTbsDocument::finish_signing(tbs.prepared, &cms, None, None).unwrap();
    let root = trust_root();
    if let Some(v) = oracle_verdicts(&out, &[&root], T, &[]) {
        let s = &v[0];
        assert_eq!(s["bottom_line"], false, "{s}");
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["intact"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
        let c = &s["content_timestamp_validity"];
        assert_eq!(c["intact"], false, "{s}");
        assert_eq!(c["valid"], true, "{s}");
        assert_eq!(c["trusted"], false, "{s}");
        let t = &s["timestamp_validity"];
        assert_eq!(t["intact"], true, "{s}");
        assert_eq!(t["valid"], true, "{s}");
        assert_eq!(t["trusted"], true, "{s}");
    }
}

fn interrupted_pades_lta(different_tsa: bool) {
    use sigis_pades_sign::cms::{AttrProfile, CmsSigner, CmsSignerOptions};
    use sigis_pades_sign::pdf::signer::{DssContentSettings, PdfTbsDocument, PostSignInstructions};
    let signer_cert = ca().cert("signer1");
    let chain = vec![ca().cert("root"), ca().cert("interm")];
    let mech = sigis_pades_sign::signer::default_signature_mechanism(&signer_cert, DigestAlgorithm::Sha256, false).unwrap();
    let ext = |v: Vec<u8>| sigis_pades_sign::ExternalSigner::new(signer_cert.clone(), chain.clone(), mech.clone(), v);
    let mut m = pades_meta("SigNew");
    m.embed_validation_info = true;
    m.use_pades_lta = true;
    m.validation_context = Some(Arc::new(live_testing_vc("testing-ca", T, &[])));
    m.md_algorithm = Some(DigestAlgorithm::Sha256);
    m.dss_settings = DssContentSettings { include_vri: false, ..Default::default() };
    let ts = dummy_ts(T);
    let tbs = PdfSigner::new(m, Arc::new(ext(vec![0; 256])))
        .at(at(T))
        .with_timestamper(ts.clone())
        .digest_doc_for_signing(&pdf("minimal.pdf"), &Default::default())
        .unwrap();
    let psi = tbs.post_sign_instructions.clone().unwrap();
    let opts = CmsSignerOptions::default();
    let placeholder = ext(vec![0; 256]);
    let attrs = CmsSigner { signer: &placeholder, options: &opts }
        .signed_attrs(
            &tbs.prepared.document_digest,
            DigestAlgorithm::Sha256,
            &tbs.signed_attr_settings,
            AttrProfile::Cades { is_pades: true },
            sigis_pades_sign::attributes::ID_DATA,
            None,
            false,
        )
        .unwrap();
    // the "remote" signature over the signed attributes
    let to_sign = der::Encode::to_der(&sigis_pades_sign::cms::attrs_to_set(attrs.clone()).unwrap()).unwrap();
    use sigis_pki_core::sign::KeySigner;
    let sig_value = ca().signer("signer1").sign_raw(&to_sign, DigestAlgorithm::Sha256).unwrap();
    let real = ext(sig_value);
    let cms = CmsSigner { signer: &real, options: &opts }
        .sign_prescribed_attributes(DigestAlgorithm::Sha256, attrs, cms::content_info::CmsVersion::V1, Some(ts.as_ref()), false, None)
        .unwrap();
    let (vc, docts): (_, Arc<dyn sigis_pki_core::sign::TimeStamper>) = if different_tsa {
        (
            live_testing_vc("testing-ca", T, &["unrelated-tsa"]),
            Arc::new(pki("unrelated-tsa").tsa("tsa", at(T))),
        )
    } else {
        (live_testing_vc("testing-ca", T, &[]), ts.clone())
    };
    let new_psi = PostSignInstructions { timestamper: Some(docts), ..psi };
    let out = PdfTbsDocument::finish_signing(tbs.prepared, &cms, Some(&new_psi), Some(&vc)).unwrap();
    let (certs, ocsps, crls, _) = dss_counts(&out).unwrap();
    let trust_unrel = pki("unrelated-tsa").cert_path("root");
    let root = trust_root();
    let mut trust: Vec<&std::path::Path> = vec![&root];
    if different_tsa {
        assert_eq!((certs, ocsps, crls), (7, 1, 2));
        assert_eq!(revision_count(&out), 4);
        trust.push(&trust_unrel);
    } else {
        assert_eq!((certs, ocsps, crls), (5, 1, 1));
        assert_eq!(revision_count(&out), 3);
    }
    assert_eq!(sig_kinds(&out), (1, 1));
    let live: Vec<&str> = if different_tsa { vec!["testing-ca", "unrelated-tsa"] } else { vec!["testing-ca"] };
    if let Some(v) = ades_lta_live(&out, &trust, T, false, &live) {
        let s = &v[0];
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
        assert_eq!(s["modification_level"], "LTA_UPDATES", "{s}");
    }
}

#[test]
fn test_interrupted_pades_lta_signature_same_tsa() {
    interrupted_pades_lta(false);
}

#[test]
fn test_interrupted_pades_lta_signature_different_tsa() {
    interrupted_pades_lta(true);
}

#[test]
fn test_dss_setting_validation() {
    use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
    use sigis_pades_sign::pdf::timestamp::TimestampDssSettings;
    let bad = TimestampDssSettings { include_vri: true, update_before_ts: true, skip_if_unneeded: true };
    assert!(bad.assert_viable().is_err());
    assert!(DssContentSettings { include_vri: true, placement: SigDssPlacement::TogetherWithSignature, ..Default::default() }
        .assert_viable()
        .is_err());
    DssContentSettings { include_vri: true, placement: SigDssPlacement::TogetherWithNextTs, ..Default::default() }
        .assert_viable()
        .unwrap();
    DssContentSettings { include_vri: false, placement: SigDssPlacement::TogetherWithSignature, ..Default::default() }
        .assert_viable()
        .unwrap();
    assert!(DssContentSettings {
        include_vri: false,
        placement: SigDssPlacement::TogetherWithSignature,
        next_ts_settings: Some(bad),
        ..Default::default()
    }
    .assert_viable()
    .is_err());
}

fn fresh_sign(m: PdfSignatureMetadata) -> Vec<u8> {
    signer_at(m, T)
        .with_timestamper(dummy_ts(T))
        .sign_pdf_with(&one_field(), &sigis_pades_sign::SignOptions { fresh_document: true, ..Default::default() })
        .unwrap()
}

fn total_revisions(pdf: &[u8]) -> usize {
    match inspect(pdf) {
        Some(v) => v["total_revisions"].as_u64().unwrap() as usize,
        None => revision_count(pdf),
    }
}

#[test]
fn test_pades_two_revisions() {
    use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
    for dss in [
        DssContentSettings { placement: SigDssPlacement::SeparateRevision, ..Default::default() },
        DssContentSettings { placement: SigDssPlacement::TogetherWithNextTs, ..Default::default() },
        DssContentSettings::default(),
    ] {
        let placement = dss.placement;
        let mut m = pades_meta("Sig1");
        m.dss_settings = dss;
        m.validation_context = Some(Arc::new(live_testing_vc("testing-ca", T, &[])));
        m.embed_validation_info = true;
        let out = fresh_sign(m);
        assert_eq!(total_revisions(&out), 2, "{placement:?}");
        if let Some(s) = pades_check(&out, 0, T) {
            assert_eq!(s["bottom_line"], true, "{s}");
        }
    }
}

#[test]
fn test_pades_lta_two_revisions() {
    use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
    use sigis_pades_sign::pdf::timestamp::TimestampDssSettings;
    let before_ts = TimestampDssSettings { update_before_ts: true, include_vri: false, skip_if_unneeded: true };
    let cases = [
        DssContentSettings { placement: SigDssPlacement::TogetherWithNextTs, next_ts_settings: Some(before_ts), ..Default::default() },
        DssContentSettings { placement: SigDssPlacement::TogetherWithSignature, include_vri: false, next_ts_settings: Some(before_ts), ..Default::default() },
        DssContentSettings { placement: SigDssPlacement::TogetherWithSignature, include_vri: false, ..Default::default() },
        DssContentSettings { placement: SigDssPlacement::TogetherWithNextTs, include_vri: false, ..Default::default() },
    ];
    for dss in cases {
        let mut m = lta_meta(T);
        m.dss_settings = dss;
        let out = fresh_sign(m);
        assert_eq!(total_revisions(&out), 2, "{dss:?}");
        if let Some(s) = pades_check(&out, 0, T) {
            assert_eq!(s["bottom_line"], true, "{s}");
        }
    }
}

#[test]
fn test_pades_lta_noskip() {
    use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
    let mut m = lta_meta(T);
    m.dss_settings = DssContentSettings {
        placement: SigDssPlacement::SeparateRevision,
        include_vri: false,
        skip_if_unneeded: false,
        ..Default::default()
    };
    let out = fresh_sign(m);
    assert_eq!(total_revisions(&out), 4);
    if let Some(s) = pades_check(&out, 0, T) {
        assert_eq!(s["bottom_line"], true, "{s}");
    }
}

fn dss_last_change(pdf: &[u8]) -> Option<u64> {
    inspect(pdf).map(|v| v["dss_last_change"].as_u64().unwrap())
}

#[test]
fn test_pades_post_ts_autosuppress() {
    use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
    let mut m = lta_meta(T);
    m.dss_settings = DssContentSettings { placement: SigDssPlacement::TogetherWithNextTs, include_vri: false, ..Default::default() };
    let out = fresh_sign(m);
    assert_eq!(total_revisions(&out), 2);
    if let Some(r) = dss_last_change(&out) {
        assert_eq!(r, 1);
    }
    if let Some(s) = pades_check(&out, 0, T) {
        assert_eq!(s["bottom_line"], true, "{s}");
    }
}

#[test]
fn test_pades_max_autosuppress() {
    use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
    let mut m = lta_meta(T);
    m.dss_settings = DssContentSettings { placement: SigDssPlacement::TogetherWithSignature, include_vri: false, ..Default::default() };
    let out = fresh_sign(m);
    assert_eq!(total_revisions(&out), 2);
    if let Some(r) = dss_last_change(&out) {
        assert_eq!(r, 0);
    }
    if let Some(s) = pades_check(&out, 0, T) {
        assert_eq!(s["bottom_line"], true, "{s}");
    }
}

#[test]
fn test_pades_independent_tsa() {
    let mut m = pades_meta("Sig1");
    m.validation_context = Some(Arc::new(live_testing_vc("testing-ca", T, &["unrelated-tsa"])));
    m.embed_validation_info = true;
    let out = signer_at(m, T)
        .with_timestamper(Arc::new(pki("unrelated-tsa").tsa("tsa", at(T))))
        .sign_pdf_with(&one_field(), &sigis_pades_sign::SignOptions { fresh_document: true, ..Default::default() })
        .unwrap();
    let (certs, ocsps, crls, _) = dss_counts(&out).unwrap();
    assert_eq!((crls, ocsps, certs), (2, 1, 6));
    assert_eq!(total_revisions(&out), 2);
    let root = trust_root();
    let unrel = pki("unrelated-tsa").cert_path("root");
    if let Some(v) = ades_lta_live(&out, &[&root, &unrel], T, false, &["testing-ca", "unrelated-tsa"]) {
        assert_eq!(v[0]["bottom_line"], true, "{}", v[0]);
    }
}

/// pyHanko uses the policy OID 2.999; `const-oid` cannot encode a first
/// subidentifier above 127 (see `docs/lanes/d.md`, divergences), so the
/// port uses another example OID. The signer treats it as opaque either way.
const POLICY_OID: &str = "1.3.6.1.4.1.99999.1";

#[test]
fn test_sign_with_policy() {
    use sigis_pki_core::asn1::sig_policy::{SignaturePolicyId, SignaturePolicyIdentifier};
    let policy = SignaturePolicyIdentifier::SignaturePolicyId(SignaturePolicyId {
        sig_policy_id: const_oid::ObjectIdentifier::new_unwrap(POLICY_OID),
        sig_policy_hash: sigis_pki_core::asn1::OtherHashAlgAndValue {
            hash_algorithm: sigis_pades_sign::signer::digest_algorithm_id(DigestAlgorithm::Sha256),
            hash_value: der::asn1::OctetString::new(DigestAlgorithm::Sha256.digest(b"")).unwrap(),
        },
        sig_policy_qualifiers: None,
    });
    let mut m = pades_meta("Sig1");
    m.cades_signed_attr_spec = Some(sigis_pades_sign::CadesSignedAttrSpec {
        signature_policy_identifier: Some(policy),
        ..Default::default()
    });
    let out = signer_at(m, T).sign_pdf(&pdf("minimal.pdf")).unwrap();
    val_trusted(&out, 0, &ca(), T, false);
    let attr = signed_attr(&out, sigis_pki_core::asn1::oids::AA_ETS_SIG_POLICY_ID).unwrap();
    let spi: SignaturePolicyIdentifier = attr.decode_as().unwrap();
    let SignaturePolicyIdentifier::SignaturePolicyId(id) = spi else { panic!() };
    assert_eq!(id.sig_policy_id.to_string(), POLICY_OID);
}

#[test]
fn test_pades_lta_no_embed_root() {
    let mut m = lta_meta(T);
    m.field_name = "Sig1".into();
    let mut s = signer_at(m, T).with_timestamper(dummy_ts(T));
    s.cms_options.embed_roots = false;
    let out = s.sign_pdf(&pdf("minimal.pdf")).unwrap();
    let sig = &embedded_signatures(&out)[0];
    assert_eq!(sig.field_name, "Sig1");
    assert!(sig.field.get(b"AP").is_err());
    let sd = sigis_pades_sign::cms::decode_signed_data(&cms_bytes(sig)).unwrap();
    assert_eq!(sd.certificates.unwrap().0.len(), 2);
    let (certs, ..) = dss_counts(&out).unwrap();
    assert_eq!(certs, 4);
    if let Some(s) = pades_check(&out, 0, T) {
        assert_eq!(s["bottom_line"], true, "{s}");
    }
}

#[test]
fn test_interrupted_nonstrict_with_psi() {
    use sigis_pades_sign::pdf::signer::PdfTbsDocument;
    let mut m = pades_meta("SigNew");
    m.embed_validation_info = true;
    m.validation_context = Some(Arc::new(simple_vc("testing-ca", T)));
    let tbs = signer_at(m, T)
        .with_timestamper(dummy_ts(T))
        .digest_doc_for_signing(&pdf("minimal-startxref-obo2.pdf"), &sigis_pades_sign::SignOptions { strict: false, ..Default::default() })
        .unwrap();
    assert!(tbs.post_sign_instructions.is_some());
    let signer = ca().signer("signer1");
    let cms = sigis_pades_sign::cms::CmsSigner { signer: &signer, options: &Default::default() }
        .sign(
            &tbs.prepared.document_digest,
            tbs.md_algorithm,
            &sigis_pades_sign::CmsSignedAttributes::default(),
            sigis_pades_sign::cms::AttrProfile::GenericCms,
            None,
            false,
            None,
        )
        .unwrap();
    let out = PdfTbsDocument::finish_signing(tbs.prepared, &cms, tbs.post_sign_instructions.as_ref(), None).unwrap();
    let root = trust_root();
    if let Some(v) = oracle_verdicts(&out, &[&root], T, &["--extd", "--lenient"]) {
        let s = &v[0];
        assert_eq!(s["intact"], true, "{s}");
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
        assert_eq!(s["coverage"], "ENTIRE_REVISION", "{s}");
        assert_eq!(s["bottom_line"], true, "{s}");
    }
}

#[test]
fn test_brazilian_pades() {
    let mut w = sigis_pades_sign::pdf::writer::PdfUpdate::new(&one_field()).unwrap();
    sigis_pades_sign::pdf::signer::ensure_output_version(&mut w, (2, 0)).unwrap();
    let (bytes, _) = w.write().unwrap();
    let mut m = pades_meta("Sig1");
    m.subfilter = Some(SubFilter::PbadPades);
    let out = signer_at(m, T).sign_pdf(&bytes).unwrap();
    let s = &embedded_signatures(&out)[0];
    assert_eq!(s.field_name, "Sig1");
    assert_eq!(s.subfilter(), "PBAD.PAdES");
    val_trusted(&out, 0, &ca(), T, false);
}

#[test]
fn test_pades_revinfo_dummydata() {
    let mut m = pades_meta("Sig1");
    m.validation_context = Some(Arc::new(dummy_ocsp_vc(T)));
    m.embed_validation_info = true;
    let out = signer_at(m, T).sign_pdf(&one_field()).unwrap();
    let s = &embedded_signatures(&out)[0];
    assert_eq!(s.field_name, "Sig1");
    assert_eq!(s.subfilter(), "ETSI.CAdES.detached");
    let (certs, ocsps, ..) = dss_counts(&out).unwrap();
    assert_eq!((certs, ocsps), (4, 1));
}

#[test]
fn test_pades_revinfo_ts_dummydata() {
    let mut m = pades_meta("Sig1");
    m.validation_context = Some(Arc::new(dummy_ocsp_vc(T)));
    m.embed_validation_info = true;
    let out = signer_at(m, T).with_timestamper(dummy_ts(T)).sign_pdf(&one_field()).unwrap();
    assert_eq!(embedded_signatures(&out)[0].subfilter(), "ETSI.CAdES.detached");
    let (certs, ocsps, ..) = dss_counts(&out).unwrap();
    assert_eq!((certs, ocsps), (5, 1));
}

#[test]
fn test_pades_revinfo_live_update_to_disk() {
    let out = signer_at(lta_meta(T), T).with_timestamper(dummy_ts(T)).sign_pdf(&one_field()).unwrap();
    let vc = live_testing_vc("testing-ca", T, &[]);
    let updated = PdfTimeStamper::new(dummy_ts(T))
        .update_archival_timestamp_chain(&out, &vc, DigestAlgorithm::Sha256)
        .unwrap();
    let path = temp_file("lta-update.pdf", &updated);
    let from_disk = std::fs::read(&path).unwrap();
    assert_eq!(sig_kinds(&from_disk), (1, 2));
    if let Some(s) = pades_check(&from_disk, 0, T) {
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
        assert_eq!(s["modification_level"], "LTA_UPDATES", "{s}");
    }
}

/// pyHanko's in-place / direct-flush variants differ only in their I/O
/// handles; the port's API takes and returns bytes, so these run the same
/// flow through a file on disk.
fn lta_via_file(validate: bool) {
    let input = temp_file("lta-in.pdf", &one_field());
    let bytes = std::fs::read(&input).unwrap();
    let out = signer_at(lta_meta(T), T).with_timestamper(dummy_ts(T)).sign_pdf(&bytes).unwrap();
    std::fs::write(&input, &out).unwrap();
    let out = std::fs::read(&input).unwrap();
    lta_validate(&out, !validate, false);
}

#[test]
fn test_pades_revinfo_live_lta_in_place() {
    lta_via_file(true);
}

#[test]
fn test_pades_revinfo_live_lta_direct_flush() {
    lta_via_file(true);
}

#[test]
fn test_pades_revinfo_live_lta_direct_flush_newfile() {
    lta_via_file(false);
}

#[test]
fn test_pades_lta_dss_indirect_arrs() {
    // a pyHanko-produced file whose DSS uses indirect arrays: it validates,
    // and the DSS writer can extend it
    let input = pdf("pades-lta-dss-indirect-arrs-test.pdf");
    let root = trust_root();
    if let Some(v) = ades_lta(&input, &[&root], T, true) {
        assert_eq!(v[0]["bottom_line"], true, "{}", v[0]);
    }
    let before = dss_counts(&input).unwrap();
    let extra = ca().cert("tsa2");
    let out = sigis_pades_sign::pdf::dss::add_dss(
        &input,
        &sigis_pades_sign::pdf::dss::DssContent { certs: vec![extra], embed_roots: true, ..Default::default() },
        false,
    )
    .unwrap();
    let after = dss_counts(&out).unwrap();
    assert_eq!(after.0, before.0 + 1);
    assert_eq!((after.1, after.2), (before.1, before.2));
}

fn fix_incomplete_revinfo_later(with_vri: bool) {
    // trust the intermediate CA and the TSA absolutely
    let incomplete = sigis_pki_certvalidator::ValidationContext::builder()
        .trust_root(ca().cert("interm"))
        .trust_root(ca().cert("tsa"))
        .moment(at(T))
        .fetchers(Services::new(&["testing-ca"], T).fetchers())
        .build()
        .unwrap();
    let mut m = pades_meta("Sig1");
    m.validation_context = Some(Arc::new(incomplete));
    m.embed_validation_info = true;
    let out = signer_at(m, T).with_timestamper(dummy_ts(T)).sign_pdf(&pdf("minimal.pdf")).unwrap();
    let t2 = "2020-12-01T00:00:00+00:00";
    let vc = live_testing_vc("testing-ca", t2, &[]);
    let w = sigis_pades_sign::pdf::writer::PdfUpdate::new(&out).unwrap();
    let sig = sigis_pades_sign::pdf::embedded::embedded_signatures(&w).unwrap().remove(0);
    let out = sigis_pades_sign::pdf::timestamp::add_validation_info_for(&out, &sig, &vc, true, with_vri, false).unwrap();
    if let Some(s) = pades_check(&out, 0, t2) {
        assert_eq!(s["bottom_line"], true, "{s}");
    }
}

#[test]
fn test_fix_incomplete_revinfo_later_with_vri() {
    fix_incomplete_revinfo_later(true);
}

#[test]
fn test_fix_incomplete_revinfo_later_without_vri() {
    fix_incomplete_revinfo_later(false);
}

/// `SAMPLE_GROUP_ATTR`: the `group` attribute (RFC 5755) with the values
/// "Employees" and "Executives", DER-encoded.
fn sample_group_attr() -> Vec<u8> {
    use der::asn1::{SetOfVec, Utf8StringRef};
    use der::{Any, Encode};
    let values: Vec<Any> = ["Employees", "Executives"]
        .iter()
        .map(|v| Any::encode_from(&Utf8StringRef::new(v).unwrap()).unwrap())
        .collect();
    #[derive(der::Sequence)]
    struct IetfAttrSyntax {
        values: Vec<Any>,
    }
    let mut set = SetOfVec::new();
    set.insert(Any::encode_from(&IetfAttrSyntax { values }).unwrap()).unwrap();
    x509_cert::attr::Attribute {
        oid: const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.10.4"),
        values: set,
    }
    .to_der()
    .unwrap()
}

fn check_claimed_only(out: &[u8], pass_ac_vc: bool, unknown: bool) {
    let root = trust_root();
    let mut extra = vec!["--live", "testing-ca"];
    if pass_ac_vc {
        extra.push("--ac-vc");
    }
    if let Some(v) = oracle_verdicts(out, &[&root], T, &extra) {
        let s = &v[0];
        assert_eq!(s["bottom_line"], true, "{s}");
        assert_eq!(s["ac_attrs_len"], 0, "{s}");
        if !pass_ac_vc {
            assert_eq!(s["ac_attrs_is_none"], true, "{s}");
        }
        let c = &s["cades_signer_attrs"];
        assert_eq!(c["claimed_count"], 1, "{s}");
        assert_eq!(c["certified_count"], 0, "{s}");
        if !pass_ac_vc {
            assert_eq!(c["certified_is_none"], true, "{s}");
        }
        assert_eq!(c["unknown_attrs_present"], unknown, "{s}");
        assert_eq!(c["groups"], serde_json::json!(["Employees", "Executives"]), "{s}");
    }
}

#[test]
fn test_cades_signer_attrs_claimed_only() {
    use sigis_pki_core::asn1::commitment::CommitmentType;
    for pass_ac_vc in [true, false] {
        let mut m = pades_meta("Sig1");
        m.cades_signed_attr_spec = Some(sigis_pades_sign::CadesSignedAttrSpec {
            commitment_type: Some(sigis_pades_sign::attributes::commitment_indication(CommitmentType::ProofOfApproval)),
            signer_attributes: Some(sigis_pades_sign::SignerAttrSpec {
                claimed_attrs: vec![sample_group_attr()],
                certified_attrs: vec![],
            }),
            ..Default::default()
        });
        let out = signer_at(m, T).sign_pdf(&pdf("minimal.pdf")).unwrap();
        check_claimed_only(&out, pass_ac_vc, false);
    }
}

/// Sign with extra signed attributes appended by `extra` (pyHanko's custom
/// attribute providers / overridden `signed_attrs`).
fn sign_with_extra_attrs(extra: impl Fn(&mut Vec<x509_cert::attr::Attribute>)) -> Vec<u8> {
    use sigis_pades_sign::cms::{CmsSigner, CmsSignerOptions};
    let signer = ca().signer("signer1");
    let tbs = signer_at(pades_meta("Sig1"), T)
        .digest_doc_for_signing(&pdf("minimal.pdf"), &Default::default())
        .unwrap();
    let opts = CmsSignerOptions::default();
    let cs = CmsSigner { signer: &signer, options: &opts };
    let mut attrs = cs
        .signed_attrs(
            &tbs.prepared.document_digest,
            tbs.md_algorithm,
            &tbs.signed_attr_settings,
            tbs.attr_profile,
            sigis_pades_sign::attributes::ID_DATA,
            None,
            false,
        )
        .unwrap();
    extra(&mut attrs);
    let set = sigis_pades_sign::cms::attrs_to_set(attrs).unwrap();
    let cms = cs
        .sign_prescribed_attributes(tbs.md_algorithm, set.into_vec(), cms::content_info::CmsVersion::V1, None, false, None)
        .unwrap();
    sigis_pades_sign::pdf::signer::PdfTbsDocument::finish_signing(tbs.prepared, &cms, None, None).unwrap()
}

#[test]
fn test_cades_signer_attrs_unknown_attrs() {
    use der::{Any, Decode, Encode};
    // OID 2.999 (as in pyHanko), encoded by hand: const-oid cannot build it
    let oid_2_999 = Any::from_der(&[0x06, 0x02, 0x88, 0x37]).unwrap();
    let value = Any::encode_from(&der::asn1::OctetString::new(vec![0xde, 0xad, 0xbe, 0xef]).unwrap()).unwrap();
    for (as_signed_assertions, pass_ac_vc) in [(true, true), (true, false), (false, true), (false, false)] {
        let out = sign_with_extra_attrs(|attrs| {
            let claimed = Some(vec![Any::from_der(&sample_group_attr()).unwrap()]);
            #[derive(der::Sequence)]
            struct Pair {
                id: Any,
                value: Any,
            }
            let pair = Any::encode_from(&Pair { id: oid_2_999.clone(), value: value.clone() }).unwrap();
            let mut v = sigis_pades_sign::attributes::SignerAttributesV2 { claimed_attributes: claimed, ..Default::default() };
            if as_signed_assertions {
                v.signed_assertions = Some(vec![pair]);
            } else {
                // other_attr_cert [1] EXPLICIT
                let tagged = der::asn1::ContextSpecific {
                    tag_number: der::TagNumber(1),
                    tag_mode: der::TagMode::Explicit,
                    value: pair,
                };
                v.certified_attributes_v2 = Some(vec![Any::encode_from(&tagged).unwrap()]);
            }
            attrs.push(sigis_pades_sign::attributes::simple_attribute(sigis_pades_sign::attributes::SIGNER_ATTRIBUTES_V2, &v).unwrap());
        });
        assert!(Any::from_der(&value.to_der().unwrap()).is_ok());
        check_claimed_only(&out, pass_ac_vc, true);
    }
}

// `test_cades_signer_attrs_multivalued` is skipped: it signs a
// `signer-attributes-v2` attribute with two identical values, which the
// `der` SET OF types (and hence the signing API) cannot represent. It tests
// the validator's rejection of that input (lane E).
