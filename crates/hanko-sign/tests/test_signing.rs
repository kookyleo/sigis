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

fn one_field() -> Vec<u8> {
    pdf("minimal-with-field.pdf")
}

fn verdicts(out: &[u8], trust: bool, extra: &[&str]) -> Option<Vec<serde_json::Value>> {
    let root = pki("testing-ca").cert_path("root");
    if trust {
        oracle_verdicts(out, &[&root], T_2020_11_01, extra)
    } else {
        oracle_verdicts(out, &[], T_2020_11_01, extra)
    }
}

#[test]
fn test_simple_sign_fresh_doc() {
    let out = PdfSigner::new(meta("Sig1"), Arc::new(self_sign()))
        .at(at(T_2020_11_01))
        .sign_pdf_with(&minimal(), &hanko_sign::SignOptions { fresh_document: true, ..Default::default() })
        .unwrap();
    assert_eq!(revision_count(&out), 1);
    assert_eq!(embedded_signatures(&out)[0].field_name, "Sig1");
    val_untrusted(&out, 0, T_2020_11_01, false);
}

#[test]
fn test_diff_fallback_ok() {
    let out = sign(&minimal(), meta("Sig1"), self_sign(), T_2020_11_01);
    for (policy, skip_diff) in [(None, false), (Some("no-changes"), false), (None, true)] {
        let mut extra = Vec::new();
        if !skip_diff {
            extra.push("--extd");
        }
        if let Some(p) = policy {
            extra.push("--diff-policy");
            extra.push(p);
        }
        if let Some(v) = verdicts(&out, false, &extra) {
            let s = &v[0];
            assert_eq!(s["diff_result_is_none"], skip_diff, "{s}");
            assert_eq!(s["docmdp_ok"], true, "{s}");
            assert_eq!(s["modification_level"], "NONE", "{s}");
        }
    }
}

#[test]
fn test_no_diff_summary() {
    let out = sign(&minimal(), meta("Sig1"), self_sign(), T_2020_11_01);
    let out = hanko_sign::pdf::dss::add_dss(
        &out,
        &hanko_sign::pdf::dss::DssContent { certs: vec![self_sign().signing_cert().clone()], embed_roots: true, ..Default::default() },
        false,
    )
    .unwrap();
    if let Some(v) = verdicts(&out, false, &[]) {
        let s = &v[0];
        assert_eq!(s["diff_result_is_none"], true, "{s}");
        assert_eq!(s["modification_level"], serde_json::Value::Null, "{s}");
        // pyHanko: `assert not status.docmdp_ok` (None or False)
        assert!(s["docmdp_ok"].is_null() || s["docmdp_ok"] == false, "{s}");
        assert_eq!(s["coverage"], "ENTIRE_REVISION", "{s}");
        assert!(s["summary"].as_str().unwrap().contains("EXTENDED"), "{s}");
    }
}

#[test]
fn test_sign_with_trust_async() {
    // the Rust API is synchronous; same flow as test_sign_with_trust
    let out = sign(&minimal(), meta("Sig1"), from_ca(), T_2020_11_01);
    assert!(embedded_signatures(&out)[0].field.get(b"AP").is_err());
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
}

fn revoked_signer() -> SimpleSigner {
    pki("testing-ca").signer("signer2")
}

fn check_revoked(out: &[u8], time: &str) {
    let root = pki("testing-ca").cert_path("root");
    if let Some(v) = oracle_verdicts(out, &[&root], time, &["--live", "testing-ca"]) {
        let s = &v[0];
        assert_eq!(s["intact"], true, "{s}");
        assert_eq!(s["valid"], true, "{s}");
        assert_eq!(s["revoked"], true, "{s}");
        assert_eq!(s["trusted"], false, "{s}");
        let summ = s["summary"].as_str().unwrap();
        assert!(summ.contains("INTACT") && summ.contains("REVOKED"), "{s}");
        assert_eq!(s["coverage"], "ENTIRE_FILE", "{s}");
        assert_eq!(s["modification_level"], "NONE", "{s}");
        assert_eq!(s["bottom_line"], false, "{s}");
    }
}

#[test]
fn test_sign_with_revoked() {
    let t = "2020-12-05T00:00:00+00:00";
    let out = sign(&minimal(), meta("Sig1"), revoked_signer(), t);
    check_revoked(&out, t);
    // should refuse to sign with a known revoked cert
    let mut m = meta("Sig1");
    m.validation_context = Some(Arc::new(support::services::live_testing_vc("testing-ca", t, &[])));
    let err = PdfSigner::new(m, Arc::new(revoked_signer())).at(at(t)).sign_pdf(&minimal()).unwrap_err();
    assert!(matches!(err, hanko_core::errors::HankoError::Signing(_)), "{err}");
}

#[test]
fn test_sign_with_later_revoked_nots() {
    let out = sign(&minimal(), meta("Sig1"), revoked_signer(), "2020-01-20T00:00:00+00:00");
    check_revoked(&out, "2020-12-05T00:00:00+00:00");
}

#[test]
fn test_ocsp_embed() {
    let mut m = meta("Sig1");
    m.validation_context = Some(Arc::new(support::services::dummy_ocsp_vc(T_2020_11_01)));
    m.embed_validation_info = true;
    let out = sign(&one_field(), m, from_ca(), T_2020_11_01);
    assert_eq!(embedded_signatures(&out)[0].field_name, "Sig1");
    if let Some(s) = val_untrusted(&out, 0, T_2020_11_01, false) {
        assert_eq!(s["trusted"], false);
    }
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
    let ria = adobe_revinfo(&out);
    assert_eq!(ria.ocsp.map(|o| o.len()), Some(1));
}

fn adobe_revinfo(out: &[u8]) -> hanko_sign::attributes::RevocationInfoArchival {
    let sig = &embedded_signatures(out)[0];
    let sd = hanko_sign::cms::decode_signed_data(&cms_bytes(sig)).unwrap();
    let si = sd.signer_infos.0.iter().next().unwrap().clone();
    let attrs = si.signed_attrs.unwrap();
    let a = attrs
        .iter()
        .find(|a| a.oid == hanko_sign::attributes::ADOBE_REVOCATION_INFO_ARCHIVAL)
        .expect("adobe_revocation_info_archival attribute");
    a.values.iter().next().unwrap().decode_as().unwrap()
}

#[test]
fn test_ocsp_without_nextupdate_embed() {
    let p = pki("testing-ca-ocsp-no-nextupdate");
    let vc = support::services::live_testing_vc("testing-ca-ocsp-no-nextupdate", T_2020_11_01, &[]);
    let key = p.key("signer1");
    let signer = SimpleSigner::new(key, p.cert("signer-special"), vec![p.cert("root"), p.cert("interm")]).unwrap();
    let mut m = meta("Sig1");
    m.validation_context = Some(Arc::new(vc));
    m.embed_validation_info = true;
    let out = sign(&one_field(), m, signer, T_2020_11_01);
    let ria = adobe_revinfo(&out);
    assert_eq!(ria.ocsp.as_ref().map(|o| o.len()), Some(1));
    assert_eq!(ria.crl.as_ref().map(|o| o.len()), Some(1));
    let ocsp_der = der::Encode::to_der(&ria.ocsp.unwrap()[0]).unwrap();
    let resp: x509_ocsp::OcspResponse = der::Decode::from_der(&ocsp_der).unwrap();
    let basic: x509_ocsp::BasicOcspResponse =
        der::Decode::from_der(resp.response_bytes.unwrap().response.as_bytes()).unwrap();
    assert!(basic.tbs_response_data.responses[0].next_update.is_none());
}

#[test]
fn test_meta_tsa_verify() {
    // the TSA certificate does not validate against an unrelated OCSP
    // response in hard-fail mode
    let vc = hanko_certvalidator::ValidationContext::builder()
        .trust_root(pki("testing-ca").cert("root"))
        .ocsp_response(pyhanko_data(&["crypto", "ocsp.resp.der"]))
        .revocation_mode("hard-fail")
        .moment(at(T_2020_11_01))
        .build()
        .unwrap();
    let r = hanko_certvalidator::CertificateValidator::new(&vc, pki("testing-ca").cert("tsa")).validate();
    let err = r.unwrap_err();
    assert!(err.is_path_validation_error(), "{err:?}");
}

#[test]
fn test_name_location() {
    let mut m = meta("Sig1");
    m.name = Some("Bleh".into());
    m.location = Some("Bluh".into());
    let out = sign(&minimal(), m, self_sign(), T_2020_11_01);
    let s = &embedded_signatures(&out)[0];
    assert_eq!(s.field_name, "Sig1");
    val_untrusted(&out, 0, T_2020_11_01, false);
    assert_eq!(s.sig.get(b"Name").unwrap(), &lopdf::Object::string_literal("Bleh"));
    assert_eq!(s.sig.get(b"Location").unwrap(), &lopdf::Object::string_literal("Bluh"));
}

/// `_tamper_with_sig_obj`: embed a CMS signature through the low-level
/// API after `tamper` modified the signature dictionary.
fn tamper_with_sig_obj(
    tamper: impl Fn(&mut hanko_sign::pdf::writer::PdfUpdate, &mut lopdf::Dictionary),
) -> Vec<u8> {
    use hanko_sign::pdf::{fields, signer as ps, writer::PdfUpdate};
    let mut w = PdfUpdate::new(&minimal()).unwrap();
    let (_, field_id) = fields::prepare_sig_field(&mut w, "Signature", false, &Default::default()).unwrap();
    fields::ensure_sig_flags(&mut w, true).unwrap();
    let mut d = ps::SignatureObjectSpec::default().to_dict(false);
    tamper(&mut w, &mut d);
    let sig_id = w.add(lopdf::Object::Dictionary(d));
    w.get_dict_mut(field_id).unwrap().set("V", lopdf::Object::Reference(sig_id));
    let prepared = ps::write_and_digest(&mut w, sig_id, 8192, DigestAlgorithm::Sha256).unwrap();
    let base = from_ca();
    let signer = SimpleSigner::new(base.key().clone(), base.signing_cert().clone(), base.cert_chain().to_vec())
        .unwrap()
        .with_signature_mechanism(spki::AlgorithmIdentifierOwned {
            oid: hanko_core::asn1::oids::RSA_ENCRYPTION,
            parameters: Some(der::Any::encode_from(&der::asn1::Null).unwrap()),
        });
    let cms = hanko_sign::cms::CmsSigner { signer: &signer, options: &Default::default() }
        .sign(
            &prepared.document_digest,
            DigestAlgorithm::Sha256,
            &Default::default(),
            hanko_sign::cms::AttrProfile::GenericPdf,
            None,
            false,
            None,
        )
        .unwrap();
    prepared.fill_with_cms(&cms).unwrap()
}

#[test]
fn test_sig_delete_type() {
    let out = tamper_with_sig_obj(|_, d| {
        d.remove(b"Type");
    });
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
    if let Some(v) = verdicts(&out, true, &["--as-timestamp"]) {
        assert!(v[0]["error"].as_str().unwrap().contains("must be /DocTimeStamp"), "{}", v[0]);
    }
}

#[test]
fn test_timestamp_wrong_type() {
    let out = sign(&minimal(), meta("Sig1"), self_sign(), T_2020_11_01);
    if let Some(v) = verdicts(&out, true, &["--as-timestamp"]) {
        assert!(v[0]["error"].as_str().unwrap().contains("must be /DocTimeStamp"), "{}", v[0]);
    }
}

#[test]
fn test_sig_wrong_subfilter() {
    for wrong in [Some(lopdf::Object::Name(b"abcde".to_vec())), Some(lopdf::Object::Name(b"ETSI.RFC3161".to_vec())), None, Some(lopdf::Object::Null)] {
        let out = tamper_with_sig_obj(|_, d| match &wrong {
            Some(o) => d.set("SubFilter", o.clone()),
            None => {
                d.remove(b"SubFilter");
            }
        });
        if let Some(v) = verdicts(&out, true, &["--from-fields"]) {
            let e = v[0]["error"].as_str().unwrap_or_default();
            assert!(e.starts_with("SignatureValidationError") || e.contains("SignatureValidationError"), "{:?}: {}", wrong, v[0]);
        }
    }
}

#[test]
fn test_sig_wrong_subfilter_at_enum_time() {
    for wrong in [Some(lopdf::Object::Name(b"abcde".to_vec())), None, Some(lopdf::Object::Null)] {
        let out = tamper_with_sig_obj(|_, d| match &wrong {
            Some(o) => d.set("SubFilter", o.clone()),
            None => {
                d.remove(b"SubFilter");
            }
        });
        if let Some(v) = verdicts(&out, true, &["--count-only"]) {
            assert_eq!(v[0]["count"], 0, "{:?}", wrong);
        }
    }
}

fn contents_tamper_reader_error(f: impl Fn(&mut hanko_sign::pdf::writer::PdfUpdate, &mut lopdf::Dictionary), needle: &str) {
    let out = tamper_with_sig_obj(f);
    if let Some(v) = verdicts(&out, true, &[]) {
        let e = v[0]["reader_error"].as_str().unwrap_or_default();
        assert!(e.contains(needle), "{}", v[0]);
    }
}

#[test]
fn test_sig_no_contents() {
    contents_tamper_reader_error(
        |_, d| {
            let c = d.get(b"Contents").unwrap().clone();
            d.set("FakeContents", c);
            d.remove(b"Contents");
        },
        "Could not read /Contents",
    );
}

#[test]
fn test_sig_null_contents() {
    contents_tamper_reader_error(
        |_, d| {
            let c = d.get(b"Contents").unwrap().clone();
            d.set("FakeContents", c);
            d.set("Contents", lopdf::Object::Null);
        },
        "string-like",
    );
}

#[test]
fn test_sig_indirect_contents() {
    contents_tamper_reader_error(
        |w, d| {
            let c = d.get(b"Contents").unwrap().clone();
            let id = w.add(c);
            d.set("Contents", lopdf::Object::Reference(id));
        },
        "be string-like",
    );
}

#[test]
fn test_timestamp_with_different_digest() {
    let p = pki("testing-ca");
    let mut ts = p.tsa("tsa", at(T_2020_11_01));
    ts.override_md = Some(DigestAlgorithm::Sha512);
    let mut m = meta("");
    m.md_algorithm = Some(DigestAlgorithm::Sha256);
    let out = PdfSigner::new(m, Arc::new(from_ca()))
        .at(at(T_2020_11_01))
        .with_timestamper(Arc::new(ts))
        .sign_pdf_with(&one_field(), &hanko_sign::SignOptions { existing_fields_only: true, ..Default::default() })
        .unwrap();
    assert_eq!(embedded_signatures(&out)[0].field_name, "Sig1");
    if let Some(s) = val_trusted(&out, 0, &p, T_2020_11_01, false) {
        assert_eq!(s["timestamp_validity"]["trusted"], true, "{s}");
    }
}

fn bogus_tsa_sign() -> Vec<u8> {
    let p = pki("testing-ca");
    let ts = hanko_sign::DummyTimeStamper::new(p.cert("interm-ocsp"), p.key("interm-ocsp"), vec![p.cert("root"), p.cert("interm")])
        .with_fixed_time(at(T_2020_11_01));
    let mut m = meta("");
    m.md_algorithm = Some(DigestAlgorithm::Sha256);
    PdfSigner::new(m, Arc::new(from_ca()))
        .at(at(T_2020_11_01))
        .with_timestamper(Arc::new(ts))
        .sign_pdf_with(&one_field(), &hanko_sign::SignOptions { existing_fields_only: true, ..Default::default() })
        .unwrap()
}

fn bogus_tsa_verdict(out: &[u8], anchor: Option<&str>) -> Option<serde_json::Value> {
    let p = pki("testing-ca");
    let root = p.cert_path("root");
    let bogus = p.cert_path("interm-ocsp");
    let spec = anchor.map(|k| if k.is_empty() { bogus.display().to_string() } else { format!("{}:{k}", bogus.display()) });
    let mut extra: Vec<&str> = Vec::new();
    if let Some(s) = &spec {
        extra.push("--ts-anchor");
        extra.push(s);
    }
    oracle_verdicts(out, &[&root], T_2020_11_01, &extra).map(|v| v[0].clone())
}

#[test]
fn test_timestamp_with_nonsense_key_usage_rejection_scenarios() {
    let out = bogus_tsa_sign();
    for anchor in [None, Some("UNSUPPORTED"), Some("CERTIFICATE_AUTHORITY")] {
        if let Some(s) = bogus_tsa_verdict(&out, anchor) {
            assert_eq!(s["timestamp_validity"]["trusted"], false, "{anchor:?}: {s}");
        }
    }
}

#[test]
fn test_timestamp_with_nonsense_key_usage_acceptance_scenarios() {
    let out = bogus_tsa_sign();
    for anchor in [Some("TIME_STAMPING_AUTHORITY"), Some("UNSPECIFIED"), Some("")] {
        if let Some(s) = bogus_tsa_verdict(&out, anchor) {
            assert_eq!(s["timestamp_validity"]["trusted"], true, "{anchor:?}: {s}");
        }
    }
}

#[test]
fn test_sign_with_empty_kids() {
    use hanko_sign::pdf::{fields, writer::PdfUpdate};
    let mut w = PdfUpdate::new(&minimal()).unwrap();
    let mut spec = SigFieldSpec::new("Sig1").with_box((20.0, 20.0, 80.0, 40.0));
    spec.combine_annotation = false;
    let fid = fields::append_signature_field(&mut w, &spec).unwrap();
    w.get_dict_mut(fid).unwrap().set("Kids", lopdf::Object::Array(vec![]));
    let (bytes, _) = w.write().unwrap();
    let err = sign_err(&bytes, meta("Sig1"), from_ca());
    assert!(err.contains("Failed to access") && err.contains("annot"), "{err}");
}

#[test]
fn test_sign_without_annot() {
    let out = sign(&pdf("minimal-annotless.pdf"), meta("Sig1"), from_ca(), T_2020_11_01);
    let s = &embedded_signatures(&out)[0];
    assert_eq!(s.field_name, "Sig1");
    for k in [b"AP".as_slice(), b"Rect", b"Kids", b"Type"] {
        assert!(s.field.get(k).is_err(), "{}", String::from_utf8_lossy(k));
    }
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
}

#[test]
fn test_no_revinfo_to_be_added() {
    for _in_place in [true, false] {
        let vc = support::services::live_testing_vc("testing-ca", T_2020_11_01, &[]);
        let mut m = meta("Sig1");
        m.embed_validation_info = true;
        m.validation_context = Some(Arc::new(vc.clone()));
        m.subfilter = Some(hanko_sign::SubFilter::Pades);
        let out = PdfSigner::new(m, Arc::new(from_ca()))
            .at(at(T_2020_11_01))
            .with_timestamper(Arc::new(pki("testing-ca").tsa("tsa", at(T_2020_11_01))))
            .sign_pdf(&minimal())
            .unwrap();
        let (_, ocsps, crls, _) = dss_counts(&out).unwrap();
        assert_eq!((ocsps, crls), (1, 1));
        let w = hanko_sign::pdf::writer::PdfUpdate::new(&out).unwrap();
        let sig = hanko_sign::pdf::embedded::embedded_signatures(&w).unwrap().remove(0);
        let again = hanko_sign::pdf::timestamp::add_validation_info_for(&out, &sig, &vc, true, false, false).unwrap();
        assert_eq!(again.len(), out.len());
        let (_, ocsps, crls, _) = dss_counts(&again).unwrap();
        assert_eq!((ocsps, crls), (1, 1));
    }
}

#[test]
fn test_simple_interrupted_signature() {
    use hanko_sign::pdf::signer::PdfTbsDocument;
    let signer = from_ca();
    let tbs = PdfSigner::new(meta("SigNew"), Arc::new(signer.clone()))
        .at(at(T_2020_11_01))
        .digest_doc_for_signing(&minimal(), &Default::default())
        .unwrap();
    assert!(tbs.post_sign_instructions.is_none());
    // copy the output, to make the point that only the bytes matter
    let prepared = tbs.prepared.clone();
    let cms = hanko_sign::cms::CmsSigner { signer: &signer, options: &Default::default() }
        .sign(
            &prepared.document_digest,
            tbs.md_algorithm,
            &Default::default(),
            hanko_sign::cms::AttrProfile::GenericPdf,
            None,
            false,
            None,
        )
        .unwrap();
    let out = PdfTbsDocument::finish_signing(prepared, &cms, None, None).unwrap();
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
}

#[test]
fn test_sign_prescribed_attrs() {
    // pyHanko timestamps through its HTTP client against the mocked TSA;
    // the port uses the local TSA (HTTP client: lane A).
    let signer = from_ca();
    let digest = DigestAlgorithm::Sha256.digest(b"Hello world!");
    let opts = hanko_sign::CmsSignerOptions::default();
    let cs = hanko_sign::cms::CmsSigner { signer: &signer, options: &opts };
    let attrs = cs
        .signed_attrs(&digest, DigestAlgorithm::Sha256, &Default::default(), hanko_sign::cms::AttrProfile::GenericPdf, hanko_sign::attributes::ID_DATA, None, false)
        .unwrap();
    let ts = pki("testing-ca").tsa("tsa", at(T_2020_11_01));
    let cms = cs
        .sign_prescribed_attributes(DigestAlgorithm::Sha256, attrs, cms::content_info::CmsVersion::V1, Some(&ts), false, None)
        .unwrap();
    let cms_path = temp_file("prescribed.p7s", &cms);
    let data = temp_file("data.bin", b"Hello world!");
    let root = pki("testing-ca").cert_path("root");
    if let Some(v) = oracle(
        "validate_cms.py",
        &["--cms", path_str(&cms_path), "--data", path_str(&data), "--trust", path_str(&root), "--time", T_2020_11_01],
    ) {
        for k in ["valid", "intact", "trusted"] {
            assert_eq!(v[k], true, "{v}");
            assert_eq!(v["timestamp_validity"][k], true, "{v}");
        }
    }
}

fn assert_tight(out: &[u8], ix: usize) {
    let s = &embedded_signatures(out)[ix];
    let tight = cms_bytes(s);
    assert_eq!(tight.len(), s.contents.len(), "contents must not be padded");
}

#[test]
fn test_sign_tight_container() {
    let mut m = meta("Sig1");
    m.tight_size_estimates = true;
    let out = sign(&minimal(), m, self_sign(), T_2020_11_01);
    assert_eq!(embedded_signatures(&out)[0].field_name, "Sig1");
    val_untrusted(&out, 0, T_2020_11_01, false);
    assert_tight(&out, 0);
}

fn tsa_no_nonce() -> Arc<hanko_sign::DummyTimeStamper> {
    let mut ts = pki("testing-ca").tsa("tsa", at(T_2020_11_01));
    ts.include_nonce = false;
    Arc::new(ts)
}

#[test]
fn test_sign_tight_container_with_ts() {
    let mut m = meta("Sig1");
    m.tight_size_estimates = true;
    m.md_algorithm = Some(DigestAlgorithm::Sha256);
    let out = PdfSigner::new(m, Arc::new(self_sign()))
        .at(at(T_2020_11_01))
        .with_timestamper(tsa_no_nonce())
        .sign_pdf(&minimal())
        .unwrap();
    val_untrusted(&out, 0, T_2020_11_01, false);
    assert_tight(&out, 0);
}

#[test]
fn test_sign_tight_container_with_lta() {
    let mut m = meta("Sig1");
    m.tight_size_estimates = true;
    m.subfilter = Some(hanko_sign::SubFilter::Pades);
    m.use_pades_lta = true;
    m.embed_validation_info = true;
    m.validation_context = Some(Arc::new(support::services::live_testing_vc("testing-ca", T_2020_11_01, &[])));
    let out = PdfSigner::new(m, Arc::new(from_ca()))
        .at(at(T_2020_11_01))
        .with_timestamper(tsa_no_nonce())
        .sign_pdf(&minimal())
        .unwrap();
    assert_tight(&out, 0);
    assert_tight(&out, 1);
}

/// `LegacyRSASigner`: a signer implemented outside the crate.
#[derive(Debug)]
struct LegacyRsaSigner(SimpleSigner);

impl KeySigner for LegacyRsaSigner {
    fn signing_cert(&self) -> &hanko_core::cert::Cert {
        self.0.signing_cert()
    }
    fn cert_chain(&self) -> &[hanko_core::cert::Cert] {
        self.0.cert_chain()
    }
    fn signature_algorithm(&self, digest: DigestAlgorithm) -> hanko_core::errors::Result<spki::AlgorithmIdentifierOwned> {
        hanko_sign::signer::default_signature_mechanism(self.signing_cert(), digest, false)
    }
    fn sign_raw(&self, data: &[u8], digest: DigestAlgorithm) -> hanko_core::errors::Result<Vec<u8>> {
        let mech = self.signature_algorithm(digest)?;
        hanko_sign::signer::sign_with_key(self.0.key(), &mech, data, digest)
    }
}

#[test]
fn test_simple_sign_legacy_signer_upgrade() {
    let out = PdfSigner::new(meta("Sig1"), Arc::new(LegacyRsaSigner(self_sign())))
        .at(at(T_2020_11_01))
        .sign_pdf(&minimal())
        .unwrap();
    assert_eq!(embedded_signatures(&out)[0].field_name, "Sig1");
    val_untrusted(&out, 0, T_2020_11_01, false);
}

#[test]
fn test_disallow_hybrid_sign() {
    let err = sign_err(&pdf("minimal-hybrid-xref.pdf"), meta("Sig1"), self_sign());
    assert!(err.contains("hybrid xrefs are disabled"), "{err}");
}

fn hybrid_signed(signer: SimpleSigner) -> Vec<u8> {
    PdfSigner::new(meta("Sig1"), Arc::new(signer))
        .at(at(T_2020_11_01))
        .sign_pdf_with(&pdf("minimal-hybrid-xref.pdf"), &hanko_sign::SignOptions { strict: false, ..Default::default() })
        .unwrap()
}

#[test]
fn test_allow_hybrid_sign() {
    hybrid_signed(self_sign());
}

#[test]
fn test_allow_hybrid_sign_validate_fail() {
    let out = hybrid_signed(from_ca());
    if let Some(v) = verdicts(&out, true, &[]) {
        let e = v[0]["error"].as_str().or(v[0]["reader_error"].as_str()).unwrap_or_default();
        assert!(e.contains("do not permit") && e.contains("hybrid"), "{}", v[0]);
    }
}

#[test]
fn test_allow_hybrid_sign_validate_allow() {
    let out = hybrid_signed(from_ca());
    if let Some(v) = verdicts(&out, true, &["--lenient"]) {
        assert_eq!(v[0]["bottom_line"], true, "{}", v[0]);
    }
}

fn extensions_levels(out: &[u8]) -> Vec<i64> {
    let doc = load(out);
    let Some(lopdf::Object::Dictionary(ext)) = dict_get(&doc, root(&doc), b"Extensions") else {
        return vec![];
    };
    match dict_get(&doc, ext, b"ISO_") {
        Some(lopdf::Object::Array(a)) => a
            .iter()
            .map(|e| resolve(&doc, e).as_dict().unwrap().get(b"ExtensionLevel").unwrap().as_i64().unwrap())
            .collect(),
        _ => vec![],
    }
}

#[test]
fn test_ed25519() {
    let out = sign(&minimal(), meta("Sig1"), pki("testing-ca-ed25519").signer("signer1"), T_2020_11_01);
    if let Some(s) = val_untrusted(&out, 0, T_2020_11_01, false) {
        assert_eq!(s["md_algorithm"], "sha512");
    }
    assert_eq!(extensions_levels(&out), vec![32002]);
}

#[test]
fn test_ed25519_trust() {
    let p = pki("testing-ca-ed25519");
    let out = sign(&minimal(), meta("Sig1"), p.signer("signer1"), T_2020_11_01);
    val_trusted(&out, 0, &p, T_2020_11_01, false);
}

#[test]
fn test_ecdsa_with_sha256() {
    let mut m = meta("Sig1");
    m.md_algorithm = Some(DigestAlgorithm::Sha256);
    let out = sign(&minimal(), m, pki("testing-ca-ecdsa").signer("signer1"), T_2020_11_01);
    if let Some(s) = val_untrusted(&out, 0, T_2020_11_01, false) {
        assert_eq!(s["md_algorithm"], "sha256");
    }
    assert_eq!(extensions_levels(&out), vec![32002]);
}

fn sig_dict_of(out: &[u8]) -> lopdf::Dictionary {
    embedded_signatures(out)[0].sig.clone()
}

#[test]
fn test_sign_with_build_props_app_name() {
    let mut m = meta("Sig1");
    m.app_build_props = Some(hanko_sign::BuildProps { name: "Test Application".into(), revision: None });
    let out = sign(&minimal(), m, from_ca(), T_2020_11_01);
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
    let d = sig_dict_of(&out);
    let app = d.get(b"Prop_Build").unwrap().as_dict().unwrap().get(b"App").unwrap().as_dict().unwrap();
    assert_eq!(app.get(b"Name").unwrap(), &lopdf::Object::Name(b"Test Application".to_vec()));
    assert!(app.get(b"REx").is_err());
}

#[test]
fn test_sign_with_build_props_versioned_app_name() {
    let mut m = meta("Sig1");
    m.app_build_props = Some(hanko_sign::BuildProps { name: "Test Application".into(), revision: Some("1.2.3".into()) });
    let out = sign(&minimal(), m, from_ca(), T_2020_11_01);
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
    let d = sig_dict_of(&out);
    let app = d.get(b"Prop_Build").unwrap().as_dict().unwrap().get(b"App").unwrap().as_dict().unwrap();
    assert_eq!(app.get(b"Name").unwrap(), &lopdf::Object::Name(b"Test Application".to_vec()));
    assert_eq!(app.get(b"REx").unwrap(), &lopdf::Object::string_literal("1.2.3"));
}

#[test]
fn test_signature_dict_with_prop_auth_time() {
    let mut m = meta("Sig1");
    m.prop_auth_time = Some(512);
    let out = sign(&minimal(), m, from_ca(), T_2020_11_01);
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
    assert_eq!(sig_dict_of(&out).get(b"Prop_AuthTime").unwrap(), &lopdf::Object::Integer(512));
}

#[test]
fn test_signature_dict_with_contact_info() {
    let mut m = meta("Sig1");
    m.contact_info = Some("+55 99 99999-9999".into());
    let out = sign(&minimal(), m, from_ca(), T_2020_11_01);
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
    assert_eq!(
        sig_dict_of(&out).get(b"ContactInfo").unwrap(),
        &lopdf::Object::string_literal("+55 99 99999-9999")
    );
}

#[test]
fn test_signature_dict_with_prop_auth_type() {
    let mut m = meta("Sig1");
    m.prop_auth_type = Some(hanko_sign::SigAuthType::Password);
    let out = sign(&minimal(), m, from_ca(), T_2020_11_01);
    val_trusted(&out, 0, &pki("testing-ca"), T_2020_11_01, false);
    // pyHanko compares with the string 'Password' (`pdf_string`)
    assert_eq!(
        sig_dict_of(&out).get(b"Prop_AuthType").unwrap(),
        &lopdf::Object::string_literal("Password")
    );
}

#[test]
fn test_do_not_enforce_key_usage_if_signer_is_root() {
    let signer = SimpleSigner::load(
        &pyhanko_data(&["crypto", "keys-rsa", "signer.key.pem"]),
        &pyhanko_data(&["crypto", "testing-ca", "interm", "decrypter1.cert.pem"]),
        Some(b"secret"),
        vec![],
    )
    .unwrap();
    let cert_path = data_path(&["pyhanko", "crypto", "testing-ca", "interm", "decrypter1.cert.pem"]);
    let out = sign(&minimal(), meta("Sig1"), signer, T_2020_11_01);
    assert_eq!(embedded_signatures(&out)[0].field_name, "Sig1");
    if let Some(v) = oracle_verdicts(&out, &[&cert_path], T_2020_11_01, &[]) {
        assert_eq!(v[0]["bottom_line"], true, "{}", v[0]);
        assert_eq!(v[0]["trusted"], true, "{}", v[0]);
    }
}

#[test]
fn test_mldsa44() {
    let p = pki("testing-ca-mldsa");
    for label in ["signer1", "signer1_65", "signer1_87"] {
        let signer = SimpleSigner::new(
            p.key(&p.key_label_of(label)),
            p.cert(label),
            vec![p.cert("root"), p.cert("interm")],
        )
        .unwrap();
        let out = sign(&minimal(), meta("Sig1"), signer, T_2020_11_01);
        if let Some(s) = val_untrusted(&out, 0, T_2020_11_01, false) {
            assert_eq!(s["md_algorithm"], "sha256", "{label}: {s}");
        }
    }
}

fn ed448_signer() -> SimpleSigner {
    pki("testing-ca-ed448").signer("signer1")
}

#[test]
fn test_ed448() {
    let out = sign(&minimal(), meta("Sig1"), ed448_signer(), T_2020_11_01);
    if let Some(s) = val_untrusted(&out, 0, T_2020_11_01, false) {
        assert_eq!(s["md_algorithm"], "shake256_len", "{s}");
    }
    let mut levels = extensions_levels(&out);
    levels.sort();
    assert_eq!(levels, vec![32001, 32002]);
    // the document digest is SHAKE256 with 64 bytes of output
    let sig = &embedded_signatures(&out)[0];
    let sd = hanko_sign::cms::decode_signed_data(&cms_bytes(sig)).unwrap();
    let si = sd.signer_infos.0.iter().next().unwrap();
    let md = si.signed_attrs.as_ref().unwrap().iter().find(|a| a.oid == hanko_core::asn1::oids::MESSAGE_DIGEST).unwrap();
    let d: der::asn1::OctetString = md.values.iter().next().unwrap().decode_as().unwrap();
    assert_eq!(d.as_bytes().len(), 64);
}

#[test]
fn test_ed448_trust() {
    let out = sign(&minimal(), meta("Sig1"), ed448_signer(), T_2020_11_01);
    val_trusted(&out, 0, &pki("testing-ca-ed448"), T_2020_11_01, false);
}

#[test]
fn test_ed448_invalid_hash_algo() {
    let mut m = meta("Sig1");
    m.md_algorithm = Some(DigestAlgorithm::Sha256);
    let err = sign_err(&minimal(), m, ed448_signer());
    assert!(err.contains("specifies") && err.contains("shake256"), "{err}");
}

#[test]
fn test_ecdsa_with_sha3() {
    let mut m = meta("Sig1");
    m.md_algorithm = Some(DigestAlgorithm::Sha3_256);
    let out = sign(&minimal(), m, pki("testing-ca-ecdsa").signer("signer1"), T_2020_11_01);
    if let Some(s) = val_untrusted(&out, 0, T_2020_11_01, false) {
        assert_eq!(s["md_algorithm"], "sha3_256", "{s}");
    }
    let mut levels = extensions_levels(&out);
    levels.sort();
    assert_eq!(levels, vec![32001, 32002]);
}

#[test]
fn test_rsa_with_sha3() {
    // the generic rsaEncryption mechanism, as pyHanko's test uses
    let base = from_ca();
    let signer = SimpleSigner::new(base.key().clone(), base.signing_cert().clone(), base.cert_chain().to_vec())
        .unwrap()
        .with_signature_mechanism(spki::AlgorithmIdentifierOwned {
            oid: hanko_core::asn1::oids::RSA_ENCRYPTION,
            parameters: Some(der::Any::encode_from(&der::asn1::Null).unwrap()),
        });
    let mut m = meta("Sig1");
    m.md_algorithm = Some(DigestAlgorithm::Sha3_256);
    let out = sign(&minimal(), m, signer, T_2020_11_01);
    if let Some(s) = val_untrusted(&out, 0, T_2020_11_01, false) {
        assert_eq!(s["md_algorithm"], "sha3_256", "{s}");
    }
    assert_eq!(extensions_levels(&out), vec![32001]);
}
