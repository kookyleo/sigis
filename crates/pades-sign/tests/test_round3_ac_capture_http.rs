//! Operation-local collection and actual HTTP AC material in DSS/signed RIA.
//! Supplemental producer proof; no P7 or S Adobe whole-function credit.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/ac_capture_http.rs"]
mod ac_http;
mod support;

use std::sync::Arc;

use der::{Decode, Encode};
use sigis_pades_sign::attributes::RevocationInfoArchival;
use sigis_pades_sign::ltv::{validate_and_collect_attribute_certs, ValidationInfo};
use sigis_pades_sign::{DummyTimeStamper, PdfSignatureMetadata, PdfSigner, SimpleSigner};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext};
use sigis_pki_core::asn1::{oids, tlv::Tlv};
use sigis_pki_core::cert::Cert;
use support::*;

const ARCH: &str = "testing-ca-with-aa";
const TIME: &str = "2020-11-01T00:00:00Z";

fn ac_file(name: &str) -> Vec<u8> {
    std::fs::read(data_path(&["lanes", "r3-p", "ac", name])).unwrap()
}

fn authorities() -> Vec<Cert> {
    let p = pki(ARCH);
    ["root", "interm", "root-aa", "interm-aa", "leaf-aa"]
        .map(|label| p.cert(label))
        .to_vec()
}

fn context(ac: bool, http: &ac_http::HttpPki) -> ValidationContext {
    let p = pki(ARCH);
    let mut builder = ValidationContext::builder()
        .trust_root(p.cert(if ac { "root-aa" } else { "root" }))
        .moment(at(TIME))
        .revocation_mode("require")
        .fetchers(http.http.as_fetchers());
    for cert in authorities() {
        builder = builder.other_cert(cert);
    }
    let ctx = builder.build().unwrap();
    assert_eq!(ctx.ocsps().count(), 0, "no fixture-preloaded AC evidence");
    assert_eq!(ctx.crls().count(), 0);
    ctx
}

fn assert_unchanged(actual: &ValidationInfo, expected: &ValidationInfo) {
    assert_eq!(actual.paths, expected.paths);
    assert_eq!(actual.ocsps, expected.ocsps);
    assert_eq!(actual.crls, expected.crls);
}

fn sentinel() -> ValidationInfo {
    ValidationInfo {
        paths: vec![vec![pki(ARCH).cert("root")]],
        ocsps: vec![std::fs::read(data_path(&[
            "lanes",
            "d",
            "revinfo",
            ARCH,
            "2020-11-01",
            "ocsp-signer1.der",
        ]))
        .unwrap()],
        crls: vec![std::fs::read(data_path(&[
            "lanes",
            "d",
            "revinfo",
            ARCH,
            "2020-11-01",
            "crl-root.der",
        ]))
        .unwrap()],
    }
}

fn actual_ac_response(http: &ac_http::HttpPki) -> Vec<u8> {
    let trace = http.trace();
    let entries: Vec<_> = trace
        .iter()
        .filter(|row| row["path"] == "/testing-ca-with-aa/ocsp/leaf-aa" && row["status"] == 200)
        .collect();
    assert_eq!(entries.len(), 1, "one actual HTTP AC OCSP exchange");
    let bytes: Vec<u8> = serde_json::from_value(entries[0]["response_der"].clone()).unwrap();
    assert_eq!(bytes, ac_file("ocsp-alice-role-with-rev.der"));
    bytes
}

fn sign(kind: &str, http: &ac_http::HttpPki) -> Vec<u8> {
    let p = pki(ARCH);
    let signer = SimpleSigner::new(
        p.key(&p.key_label_of("signer1")),
        p.cert("signer1"),
        authorities(),
    )
    .unwrap();
    let mut meta = if kind == "adobe" {
        PdfSignatureMetadata::pyhanko_defaults("Sig1")
    } else {
        PdfSignatureMetadata::new("Sig1")
    };
    meta.embed_validation_info = true;
    // No preceding collection/probe is allowed to populate these provider caches.
    meta.validation_context = Some(Arc::new(context(false, http)));
    meta.ac_validation_context = Some(Arc::new(context(true, http)));
    let timestamp = DummyTimeStamper::new(
        p.cert("tsa"),
        p.key(&p.key_label_of("tsa")),
        vec![p.cert("root")],
    )
    .with_fixed_time(at(TIME));
    let mut signer = PdfSigner::new(meta, Arc::new(signer))
        .at(at(TIME))
        .with_timestamper(Arc::new(timestamp));
    signer.cms_options.attribute_certs = vec![ac_file("alice-role-with-rev.der")];
    signer.sign_pdf(&pdf("minimal.pdf")).unwrap()
}

/// Verify the original detached CMS and signed attributes without removing ACs.
fn signed_ria(output: &[u8]) -> Option<RevocationInfoArchival> {
    let sig = support::pdfcheck::embedded_signatures(output).remove(0);
    let cms = support::pdfcheck::cms_bytes(&sig);
    let ci = Tlv::parse_exact(&cms).unwrap().children().unwrap();
    let sd = Tlv::parse_exact(ci[1].value).unwrap().children().unwrap();
    let infos = sd.last().unwrap().children().unwrap();
    assert_eq!(infos.len(), 1);
    let si = cms::signed_data::SignerInfo::from_der(infos[0].raw).unwrap();
    let attrs = si.signed_attrs.as_ref().unwrap();
    let md = DigestAlgorithm::from_oid(&si.digest_alg.oid).unwrap();
    let digest = attrs
        .iter()
        .find(|attr| attr.oid == oids::MESSAGE_DIGEST)
        .unwrap();
    let digest = digest
        .values
        .iter()
        .next()
        .unwrap()
        .decode_as::<der::asn1::OctetString>()
        .unwrap();
    let br = &sig.byte_range;
    assert_eq!(br.len(), 4);
    let mut signed = output[..usize::try_from(br[1]).unwrap()].to_vec();
    let start = usize::try_from(br[2]).unwrap();
    signed.extend_from_slice(&output[start..start + usize::try_from(br[3]).unwrap()]);
    assert_eq!(digest.as_bytes(), md.digest(&signed));
    validate_signature(
        si.signature.as_bytes(),
        &attrs.to_der().unwrap(),
        &pki(ARCH).cert("signer1").public_key(),
        &si.signature_algorithm,
        &SignatureValidationContext {
            contextual_digest: Some(md),
            prehashed: false,
        },
    )
    .unwrap();
    attrs
        .iter()
        .find(|attr| attr.oid == oids::ADBE_REVOCATION_INFO_ARCHIVAL)
        .map(|attr| {
            RevocationInfoArchival::from_der(&attr.values.iter().next().unwrap().to_der().unwrap())
                .unwrap()
        })
}

fn retain_and_compare(kind: &str, output: &[u8], http: &ac_http::HttpPki) {
    static RECEIPT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let receipt_guard = RECEIPT_LOCK.lock().unwrap();
    let directory = std::env::temp_dir().join(format!("sigis-p-ac-capture-{}", std::process::id()));
    let path = directory.join(kind);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("output.pdf"), output).unwrap();
    let p = pki(ARCH);
    let record = serde_json::json!({
        "kind": kind, "pdf_sha256": ac_http::hash(output), "pdf_length": output.len(),
        "root": p.cert("root").der(), "aa_root": p.cert("root-aa").der(),
        "ac": ac_file("alice-role-with-rev.der"), "ac_ocsp": actual_ac_response(http),
        "http": http.trace(),
    });
    std::fs::write(
        path.join("receipt.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    let exe = std::env::current_exe().unwrap();
    std::fs::copy(&exe, directory.join("native-test.elf")).unwrap();
    let sources = [
        ("src/ltv.rs", include_bytes!("../src/ltv.rs").as_slice()),
        (
            "src/ltv/capture.rs",
            include_bytes!("../src/ltv/capture.rs").as_slice(),
        ),
        (
            "tests/test_round3_ac_capture_http.rs",
            include_bytes!("test_round3_ac_capture_http.rs").as_slice(),
        ),
        (
            "tests/support/ac_capture_http.rs",
            include_bytes!("support/ac_capture_http.rs").as_slice(),
        ),
    ];
    let mut hashes = serde_json::Map::new();
    for (relative, compiled) in sources {
        let actual = std::fs::read(sigis_testdata::manifest_dir().join(relative)).unwrap();
        assert_eq!(
            actual, compiled,
            "compiled/opened source mismatch: {relative}"
        );
        let saved = directory.join("source").join(relative);
        std::fs::create_dir_all(saved.parent().unwrap()).unwrap();
        std::fs::write(saved, &actual).unwrap();
        hashes.insert(
            relative.to_owned(),
            serde_json::json!(ac_http::hash(&actual)),
        );
    }
    let proof = serde_json::json!({"executable": exe, "elf_sha256": ac_http::hash(&std::fs::read(&exe).unwrap()), "sources": hashes});
    std::fs::write(
        directory.join("runtime.json"),
        serde_json::to_vec_pretty(&proof).unwrap(),
    )
    .unwrap();
    drop(receipt_guard);
    let script = sigis_testdata::manifest_dir().join("oracle/check_ac_capture_embedding.py");
    let oracle = std::process::Command::new(oracle_python().expect("mandatory pinned oracle"))
        .arg("-I")
        .arg(script)
        .arg(&path)
        .arg(data_dir())
        .output()
        .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    eprintln!(
        "AC_CAPTURE_PROOF {} {}",
        path.display(),
        String::from_utf8_lossy(&oracle.stdout).trim()
    );
}

#[test]
fn http_fetched_ac_ocsp_is_embedded_in_dss() {
    let http = ac_http::HttpPki::start("good");
    let output = sign("pades", &http);
    let material = sigis_pdf::PdfFile::parse(&output)
        .unwrap()
        .dss()
        .unwrap()
        .unwrap()
        .material;
    assert!(
        material.ocsps.contains(&actual_ac_response(&http)),
        "actual HTTP AC OCSP must reach DSS"
    );
    assert!(signed_ria(&output).is_none());
    retain_and_compare("pades", &output, &http);
}

#[test]
fn http_fetched_ac_ocsp_is_embedded_in_adobe_signed_ria() {
    let http = ac_http::HttpPki::start("good");
    let output = sign("adobe", &http);
    let ria = signed_ria(&output).expect("actual signed Adobe RIA");
    let ocsps: Vec<_> = ria
        .ocsp
        .unwrap()
        .iter()
        .map(|entry| entry.to_der().unwrap())
        .collect();
    assert!(
        ocsps.contains(&actual_ac_response(&http)),
        "actual HTTP AC OCSP must reach signed RIA"
    );
    assert!(sigis_pdf::PdfFile::parse(&output)
        .unwrap()
        .dss()
        .unwrap()
        .is_none());
    retain_and_compare("adobe", &output, &http);
}

#[test]
fn http_capture_is_per_operation_even_when_provider_cache_is_reused() {
    let http = ac_http::HttpPki::start("good");
    let ctx = context(true, &http);
    let original = ctx.fetchers().clone();
    let p = pki(ARCH);
    let ac = ac_file("alice-role-with-rev.der");
    for _ in 0..2 {
        let mut info = sentinel();
        validate_and_collect_attribute_certs(
            &ctx,
            &p.cert("signer1"),
            &[],
            std::slice::from_ref(&ac),
            &mut info,
        )
        .unwrap();
        assert!(info.ocsps.contains(&actual_ac_response(&http)));
        assert_eq!(ctx.ocsps().count(), 0);
        assert_eq!(ctx.crls().count(), 0);
        assert!(Arc::ptr_eq(
            ctx.fetchers().ocsp.as_ref().unwrap(),
            original.ocsp.as_ref().unwrap()
        ));
    }
    assert_eq!(
        http.trace()
            .iter()
            .filter(|row| row["path"] == "/testing-ca-with-aa/ocsp/leaf-aa")
            .count(),
        1,
        "second operation observes the provider's cache, but still publishes its own raw outcome"
    );
    let mut bad = ac.clone();
    *bad.last_mut().unwrap() ^= 1;
    let initial = sentinel();
    let mut info = initial.clone();
    assert!(validate_and_collect_attribute_certs(
        &ctx,
        &p.cert("signer1"),
        &[],
        &[ac, bad],
        &mut info
    )
    .is_err());
    assert_unchanged(&info, &initial);
}

#[test]
fn http_capture_preserves_required_denial_fallback_and_sentinels() {
    let p = pki(ARCH);
    for case in ["crl_fallback", "missing", "tampered_ocsp", "forged_crl"] {
        let http = ac_http::HttpPki::start(case);
        let ctx = context(true, &http);
        let initial = sentinel();
        let mut info = initial.clone();
        let result = validate_and_collect_attribute_certs(
            &ctx,
            &p.cert("signer1"),
            &[],
            &[ac_file("alice-role-with-rev.der")],
            &mut info,
        );
        assert_eq!(result.is_ok(), case == "crl_fallback", "{case}: {result:?}");
        http.assert_ac_requested();
        if let Err(error) = &result {
            assert_unchanged(&info, &initial);
            if case == "forged_crl" {
                assert!(error
                    .to_string()
                    .contains("CRL signature could not be verified"));
            }
        } else {
            let ac_crl = std::fs::read(data_path(&[
                "lanes",
                "d",
                "revinfo",
                ARCH,
                "2020-11-01",
                "crl-leaf-aa.der",
            ]))
            .unwrap();
            assert!(info.crls.contains(&ac_crl));
            assert_eq!(info.ocsps, initial.ocsps);
            assert!(info.paths.starts_with(&initial.paths));
        }
        assert_eq!(ctx.ocsps().count(), 0);
        assert_eq!(ctx.crls().count(), 0);
        let receipt = serde_json::json!({
            "case": case, "native_accepted": result.is_ok(),
            "native_error": result.as_ref().err().map(|error| error.to_string()),
            "ac": ac_file("alice-role-with-rev.der"), "holder": p.cert("signer1").der(),
            "root": p.cert("root-aa").der(),
            "authorities": authorities().iter().map(|cert| cert.der().to_vec()).collect::<Vec<_>>(),
            "http": http.trace(),
        });
        let path = temp_file(
            &format!("capture-{case}.json"),
            &serde_json::to_vec_pretty(&receipt).unwrap(),
        );
        let script = sigis_testdata::manifest_dir().join("oracle/check_ac_http_control.py");
        let oracle =
            std::process::Command::new(oracle_python().expect("mandatory required-mode oracle"))
                .arg("-I")
                .arg(script)
                .arg(&path)
                .output()
                .unwrap();
        assert!(
            oracle.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&oracle.stderr)
        );
        eprintln!(
            "AC_CAPTURE_CONTROL {} {}",
            path.display(),
            String::from_utf8_lossy(&oracle.stdout).trim()
        );
    }
}
