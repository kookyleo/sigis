//! Port of pyHanko 0.38.1 `pkgs/pyhanko/tests/test_sign_encrypted.py`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use hanko_sign::{PdfSignatureMetadata, PdfSigner, SignOptions, SubFilter};
use support::pdfcheck::*;
use support::*;

const T: &str = "2020-11-01T00:00:00+00:00";

fn signer() -> Arc<hanko_sign::SimpleSigner> {
    Arc::new(pki("testing-ca").signer("signer1"))
}

fn sign(input: &[u8], field: &str, password: &[u8], existing_only: bool) -> Vec<u8> {
    PdfSigner::new(PdfSignatureMetadata::pyhanko_defaults(field), signer())
        .at(at(T))
        .sign_pdf_with(input, &SignOptions { existing_fields_only: existing_only, password: Some(password.to_vec()), ..Default::default() })
        .unwrap()
}

/// `val_trusted` on a document opened with `password`.
fn val_trusted_pw(out: &[u8], password: &str, extd: bool) -> Option<serde_json::Value> {
    let root = pki("testing-ca").cert_path("root");
    let mut extra = vec!["--password", password];
    if extd {
        extra.push("--extd");
    }
    let v = oracle_verdicts(out, &[&root], T, &extra)?;
    let s = v[0].clone();
    assert!(s.get("error").is_none() && s.get("reader_error").is_none(), "{s}");
    for k in ["intact", "valid", "trusted", "bottom_line"] {
        assert_eq!(s[k], true, "{k}: {s}");
    }
    if extd {
        assert_eq!(s["coverage"], "ENTIRE_REVISION", "{s}");
    } else {
        assert_eq!(s["coverage"], "ENTIRE_FILE", "{s}");
        assert_eq!(s["modification_level"], "NONE", "{s}");
    }
    Some(s)
}

#[test]
fn test_sign_crypt_rc4() {
    for pw in ["usersecret", "ownersecret"] {
        let out = sign(&pdf("minimal-with-field-rc4.pdf"), "", pw.as_bytes(), true);
        val_trusted_pw(&out, pw, false);
    }
}

#[test]
fn test_sign_crypt_aes256() {
    for pw in ["usersecret", "ownersecret"] {
        let out = sign(&pdf("minimal-with-field-aes256.pdf"), "", pw.as_bytes(), true);
        val_trusted_pw(&out, pw, false);
    }
}

fn lane_d(name: &str) -> Vec<u8> {
    std::fs::read(data_path(&["lanes", "d", "encrypted", name])).unwrap()
}

#[test]
fn test_sign_crypt_empty_user_pass() {
    let out = sign(&lane_d("minimal-with-field-owner-only.pdf"), "", b"", true);
    val_trusted_pw(&out, "", false);
}

#[test]
fn test_sign_encrypted_with_extensions() {
    let p = pki("testing-ca-ed25519");
    let out = PdfSigner::new(PdfSignatureMetadata::pyhanko_defaults(""), Arc::new(p.signer("signer1")))
        .at(at(T))
        .sign_pdf_with(
            &lane_d("minimal-with-field-secret.pdf"),
            &SignOptions { existing_fields_only: true, password: Some(b"secret".to_vec()), ..Default::default() },
        )
        .unwrap();
    let root = p.cert_path("root");
    if let Some(v) = oracle_verdicts(&out, &[&root], T, &["--password", "secret"]) {
        assert_eq!(v[0]["bottom_line"], true, "{}", v[0]);
    }
}

const NEW_PARAMS: [(&str, usize); 4] = [("usersecret", 0), ("usersecret", 1), ("ownersecret", 0), ("ownersecret", 1)];

#[test]
fn test_sign_crypt_rc4_new() {
    let files = ["minimal-rc4.pdf", "minimal-with-field-rc4.pdf"];
    for (pw, f) in NEW_PARAMS {
        let out = sign(&pdf(files[f]), "SigNew", pw.as_bytes(), false);
        val_trusted_pw(&out, pw, false);
    }
}

#[test]
fn test_sign_crypt_aes256_new() {
    let files = ["minimal-aes256.pdf", "minimal-with-field-aes256.pdf"];
    for (pw, f) in NEW_PARAMS {
        let out = sign(&pdf(files[f]), "SigNew", pw.as_bytes(), false);
        val_trusted_pw(&out, pw, false);
    }
}

#[test]
fn test_sign_encrypted_with_post_sign() {
    use hanko_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
    let files = ["minimal-aes256.pdf", "minimal-with-field-aes256.pdf"];
    for (pw, f) in NEW_PARAMS {
        let mut m = PdfSignatureMetadata::pyhanko_defaults("Sig1");
        m.validation_context = Some(Arc::new(support::services::live_testing_vc("testing-ca", T, &[])));
        m.subfilter = Some(SubFilter::Pades);
        m.embed_validation_info = true;
        m.dss_settings = DssContentSettings { placement: SigDssPlacement::SeparateRevision, ..Default::default() };
        m.use_pades_lta = true;
        let out = PdfSigner::new(m, signer())
            .at(at(T))
            .with_timestamper(Arc::new(pki("testing-ca").tsa("tsa", at(T))))
            .sign_pdf_with(&pdf(files[f]), &SignOptions { password: Some(pw.as_bytes().to_vec()), ..Default::default() })
            .unwrap();
        if let Some(s) = val_trusted_pw(&out, pw, true) {
            assert_eq!(s["modification_level"], "LTA_UPDATES", "{s}");
        }
        if let Some(v) = oracle_verdicts(&out, &[], T, &["--password", pw]) {
            let kinds: Vec<&str> = v.iter().map(|e| e["type"].as_str().unwrap()).collect();
            assert_eq!(kinds, ["/Sig", "/DocTimeStamp"]);
        }
    }
}

#[test]
fn test_copy_encrypted_signed_file() {
    let out = sign(&pdf("minimal-with-field-aes256.pdf"), "", b"ownersecret", true);
    // copy_into_new_writer of the decrypted document: a fresh, unencrypted
    // single-revision file whose signature no longer matches
    let copied = fresh_copy_decrypted(&out, b"ownersecret");
    let root = pki("testing-ca").cert_path("root");
    if let Some(v) = oracle_verdicts(&copied, &[&root], T, &[]) {
        assert_eq!(v[0]["intact"], false, "{}", v[0]);
    }
}

/// Rewrite the decrypted contents of an encrypted file as a new document.
fn fresh_copy_decrypted(pdf_in: &[u8], password: &[u8]) -> Vec<u8> {
    let mut doc = lopdf::Document::load_mem_with_options(
        pdf_in,
        lopdf::LoadOptions::with_password(std::str::from_utf8(password).unwrap()),
    )
    .unwrap();
    doc.encryption_state = None;
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}
