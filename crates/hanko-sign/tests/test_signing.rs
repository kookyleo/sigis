//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_signing.py`.
//!
//! Validation uses the Rust-side integrity check plus pyHanko's verdict
//! through the oracle (`oracle/validate_pdf.py`), until lane E lands.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use hanko_core::algorithms::DigestAlgorithm;
use hanko_core::sign::KeySigner;
use hanko_pdf::MdpPerm;
use hanko_sign::keys::{load_cert_from_pemder_data, load_certs_from_pemder_data};
use hanko_sign::{PdfSignatureMetadata, PdfSigner, SigFieldSpec, SimpleSigner};
use support::pdfcheck::*;
use support::*;

const T_2020_11_01: &str = "2020-11-01T00:00:00+00:00";

fn self_sign() -> SimpleSigner {
    SimpleSigner::load(
        &pyhanko_data(&["crypto", "selfsigned.key.pem"]),
        &pyhanko_data(&["crypto", "selfsigned.cert.pem"]),
        Some(b"secret"),
        vec![],
    )
    .unwrap()
}

fn from_ca() -> SimpleSigner {
    pki("testing-ca").signer("signer1")
}

fn minimal() -> Vec<u8> {
    pdf("minimal.pdf")
}

fn meta(field: &str) -> PdfSignatureMetadata {
    PdfSignatureMetadata::pyhanko_defaults(field)
}

fn sign(pdf_in: &[u8], meta: PdfSignatureMetadata, signer: SimpleSigner, at_time: &str) -> Vec<u8> {
    PdfSigner::new(meta, Arc::new(signer))
        .at(at(at_time))
        .sign_pdf(pdf_in)
        .unwrap()
}

fn sign_err(pdf_in: &[u8], meta: PdfSignatureMetadata, signer: SimpleSigner) -> String {
    PdfSigner::new(meta, Arc::new(signer))
        .at(at(T_2020_11_01))
        .sign_pdf(pdf_in)
        .unwrap_err()
        .to_string()
}

#[test]
fn test_der_detect() {
    let s = self_sign();
    let der = s.signing_cert().der().to_vec();
    let c = load_cert_from_pemder_data(&der).unwrap();
    assert_eq!(c.der(), der.as_slice());
}

#[test]
fn test_enforce_one_cert() {
    let data = pyhanko_data(&["crypto", "some-chain.cert.pem"]);
    assert_eq!(load_certs_from_pemder_data(&data).unwrap().len(), 2);
    assert!(load_cert_from_pemder_data(&data).is_err());
}

#[test]
fn test_simple_sign() {
    let out = sign(&minimal(), meta("Sig1"), self_sign(), T_2020_11_01);
    let sigs = embedded_signatures(&out);
    assert_eq!(sigs[0].field_name, "Sig1");
    val_untrusted(&out, 0, T_2020_11_01, false);
}

#[test]
fn test_simple_sign_tamper() {
    let mut out = sign(&minimal(), meta("Sig1"), self_sign(), T_2020_11_01);
    val_untrusted(&out, 0, T_2020_11_01, false);
    // change the size of the media box (offset 0x9D in minimal.pdf)
    assert_ne!(out[0x9D], b'4');
    out[0x9D] = b'4';
    let sigs = embedded_signatures(&out);
    let r = std::panic::catch_unwind(|| check_integrity(&out, &sigs[0]));
    assert!(r.is_err(), "tampered document must not verify");
    let root = pki("testing-ca").cert_path("root");
    if let Some(v) = oracle_verdicts(&out, &[&root], T_2020_11_01, &[]) {
        assert_eq!(v[0]["intact"], false, "{}", v[0]);
        assert_eq!(v[0]["valid"], true, "{}", v[0]);
        assert_eq!(v[0]["summary"], "INVALID", "{}", v[0]);
    }
}

#[test]
fn test_simple_sign_120mb_file() {
    // pyHanko adds a 120 MiB stream object before signing; we append it
    // as an incremental update first.
    let mut w = hanko_sign::pdf::writer::PdfUpdate::new(&minimal()).unwrap();
    let big = lopdf::Stream::new(lopdf::Dictionary::new(), vec![0u8; 120 * 1024 * 1024]);
    let id = w.add(lopdf::Object::Stream(big));
    w.root_mut().unwrap().set("YugeObject", lopdf::Object::Reference(id));
    let (bytes, _) = w.write().unwrap();
    let out = sign(&bytes, meta("Sig1"), self_sign(), T_2020_11_01);
    let sigs = embedded_signatures(&out);
    assert_eq!(sigs[0].field_name, "Sig1");
    check_integrity(&out, &sigs[0]);
    let v = oracle_verdicts(&out, &[], T_2020_11_01, &[]);
    if let Some(v) = v {
        assert_eq!(v[0]["intact"], true, "{}", v[0]);
        assert_eq!(v[0]["valid"], true, "{}", v[0]);
    }
}

#[test]
fn test_append_sigfield_tu_on_signing() {
    let mut spec = SigFieldSpec::new("Sig1");
    spec.empty_field_appearance = true;
    spec.readable_field_name = Some("Test test".into());
    let out = PdfSigner::new(meta("Sig1"), Arc::new(self_sign()))
        .with_field_spec(spec)
        .at(at(T_2020_11_01))
        .sign_pdf(&minimal())
        .unwrap();
    let doc = load(&out);
    let r = root(&doc);
    let Some(lopdf::Object::Dictionary(form)) = dict_get(&doc, r, b"AcroForm") else {
        panic!()
    };
    let Some(lopdf::Object::Array(fields)) = dict_get(&doc, form, b"Fields") else {
        panic!()
    };
    let lopdf::Object::Dictionary(f0) = resolve(&doc, &fields[0]) else {
        panic!()
    };
    assert_eq!(
        dict_get(&doc, f0, b"TU"),
        Some(&lopdf::Object::string_literal("Test test"))
    );
}

#[test]
fn test_sign_with_trust() {
    let out = sign(&minimal(), meta("Sig1"), from_ca(), T_2020_11_01);
    let sigs = embedded_signatures(&out);
    assert_eq!(sigs[0].field_name, "Sig1");
    assert!(sigs[0].field.get(b"AP").is_err());
    if let Some(s) = val_untrusted(&out, 0, T_2020_11_01, false) {
        assert_eq!(s["trusted"], false);
    }
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
}

#[test]
fn test_sign_with_trust_pkcs12() {
    let pfx = pyhanko_data(&["crypto", "testing-ca", "interm", "signer1.pfx"]);
    let signer = SimpleSigner::from_pkcs12(&pfx, None).unwrap();
    let out = sign(&minimal(), meta("Sig1"), signer, T_2020_11_01);
    let sigs = embedded_signatures(&out);
    assert_eq!(sigs[0].field_name, "Sig1");
    if let Some(s) = val_untrusted(&out, 0, T_2020_11_01, false) {
        assert_eq!(s["trusted"], false);
    }
    // the PKCS#12 file belongs to the legacy OpenSSL test CA in
    // `crypto/testing-ca/`, whose root is shipped as PEM
    let root = hanko_testdata_root("testing-ca/root/root.cert.pem");
    let v = oracle_verdicts(&out, &[&root], T_2020_11_01, &[]);
    if let Some(v) = v {
        assert_eq!(v[0]["trusted"], true, "{}", v[0]);
        assert_eq!(v[0]["bottom_line"], true, "{}", v[0]);
    }
}

fn hanko_testdata_root(rel: &str) -> std::path::PathBuf {
    let mut p = data_path(&["pyhanko", "crypto"]);
    p.push(rel);
    p
}

#[test]
fn test_enumerate_empty() {
    let w = hanko_sign::pdf::writer::PdfUpdate::new(&minimal()).unwrap();
    assert!(hanko_sign::pdf::fields::enumerate_sig_fields(&w, None, None)
        .unwrap()
        .is_empty());
}

#[test]
fn test_certify_blank() {
    let w = hanko_sign::pdf::writer::PdfUpdate::new(&minimal()).unwrap();
    assert_eq!(hanko_sign::pdf::signer::read_certification_level(&w).unwrap(), None);
}

#[test]
fn test_certify() {
    let mut m = meta("Sig1");
    m.certify = Some(MdpPerm::NoChanges);
    let out = sign(&minimal(), m, from_ca(), T_2020_11_01);
    let sigs = embedded_signatures(&out);
    let refs = sigs[0].sig.get(b"Reference").unwrap().as_array().unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(sigs[0].field_name, "Sig1");
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
    let w = hanko_sign::pdf::writer::PdfUpdate::new(&out).unwrap();
    assert_eq!(
        hanko_sign::pdf::signer::read_certification_level(&w).unwrap(),
        Some(MdpPerm::NoChanges)
    );
    // with NO_CHANGES, we shouldn't be able to append an approval signature
    let err = sign_err(&out, meta("Sig2"), from_ca());
    assert!(err.contains("forbids all changes"), "{err}");
}

#[test]
fn test_no_certify_after_sign() {
    let out = sign(&minimal(), meta("Sig1"), from_ca(), T_2020_11_01);
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
    let mut m = meta("Sig2");
    m.certify = Some(MdpPerm::FillForms);
    let err = sign_err(&out, m, from_ca());
    assert!(err.contains("must be the first"), "{err}");
}

#[test]
fn test_approval_sig() {
    let mut m = meta("Sig1");
    m.certify = Some(MdpPerm::FillForms);
    let out = sign(&minimal(), m, from_ca(), T_2020_11_01);
    let out = sign(&out, meta("Sig2"), from_ca(), T_2020_11_01);
    let sigs = embedded_signatures(&out);
    assert_eq!(sigs[0].field_name, "Sig1");
    let p = pki("testing-ca");
    val_trusted(&out, 0, &p, T_2020_11_01, true);
    let w = hanko_sign::pdf::writer::PdfUpdate::new(&out).unwrap();
    assert_eq!(
        hanko_sign::pdf::signer::read_certification_level(&w).unwrap(),
        Some(MdpPerm::FillForms)
    );
    assert_eq!(sigs[1].field_name, "Sig2");
    val_trusted(&out, 1, &p, T_2020_11_01, false);
}

#[test]
fn test_bytes_reserved_even() {
    let r = PdfSigner::new(meta("Sig1"), Arc::new(from_ca())).sign_pdf_with(
        &minimal(),
        &hanko_sign::SignOptions {
            bytes_reserved: Some(7),
            ..Default::default()
        },
    );
    assert!(r.unwrap_err().to_string().contains("must be even"));
}

#[test]
fn test_rsa_with_sha384() {
    let mut m = meta("Sig1");
    m.md_algorithm = Some(DigestAlgorithm::Sha384);
    let out = sign(&minimal(), m, from_ca(), T_2020_11_01);
    if let Some(s) = val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false) {
        assert_eq!(s["md_algorithm"], "sha384");
    }
}
