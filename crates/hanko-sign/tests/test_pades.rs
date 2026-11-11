//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_pades.py`.
//!
//! The AdES checks (`_simple_pades_check`, `ades_lta_validation`) run in
//! pyHanko through the oracle until lane E's `hanko-ades` lands.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use hanko_core::algorithms::DigestAlgorithm;
use hanko_sign::pdf::timestamp::{PdfTimeStamper, TimestampOptions};
use hanko_sign::{PdfSignatureMetadata, PdfSigner, SubFilter};
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

fn dummy_ts(time: &str) -> Arc<hanko_sign::DummyTimeStamper> {
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
    let mut w = hanko_sign::pdf::writer::PdfUpdate::new(&one_field()).unwrap();
    hanko_sign::pdf::signer::ensure_output_version(&mut w, (2, 0)).unwrap();
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
    let w = hanko_sign::pdf::writer::PdfUpdate::new(&out).unwrap();
    let sig = hanko_sign::pdf::embedded::embedded_signatures(&w).unwrap().remove(0);
    let out = hanko_sign::pdf::timestamp::add_validation_info_for(&out, &sig, &vc, true, with_vri, false).unwrap();
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
    let w = hanko_sign::pdf::writer::PdfUpdate::new(&out).unwrap();
    let sig = hanko_sign::pdf::embedded::embedded_signatures(&w).unwrap().remove(0);
    let out = hanko_sign::pdf::timestamp::add_validation_info_for(&out, &sig, &vc, true, true, false).unwrap();
    let mut opts = TimestampOptions::new(DigestAlgorithm::Sha256);
    opts.validation_context = Some(&vc);
    let out = PdfTimeStamper::new(dummy_ts(t2)).timestamp_pdf(&out, &opts).unwrap();
    if let Some(s) = pades_check(&out, 0, t2) {
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["trusted"], true, "{s}");
    }
}
