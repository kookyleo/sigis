//! Supplemental replay of two frozen PRE-RIA native Adobe outputs; zero IDs.
//! No signing, metadata rewrite or new PDF production occurs in this test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/signing_integration.rs"]
mod support;

use der::{Decode, Encode};
use sigis_cms::attributes::RoleSyntax;
use sigis_cms::signed_data::{extract_certificate_info, find_unique_cms_attribute};
use sigis_pades::ades::{
    basic::QualificationSpec,
    lta::{lta_validation_with_options, LtaOptions, LtaValidationResult},
};
use sigis_pades_sign::attributes::RevocationInfoArchival;
use sigis_pdf::{PdfFile, SignatureKind};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{algorithms::DigestAlgorithm, asn1::oids, cert::Cert, fetch::Fetchers};
use std::path::Path;
use x509_cert::ext::pkix::name::GeneralName;

const TIME: &str = "2020-11-01T00:00:00Z";
const ARCH: &str = "testing-ca-with-aa";

fn sha(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn read_pinned(path: &Path, expected: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    eprintln!(
        "ADOBE_OLD_INPUT {}",
        serde_json::json!({
            "path":path,"length":bytes.len(),"sha256":sha(&bytes)
        })
    );
    assert_eq!(sha(&bytes), expected, "{}", path.display());
    bytes
}
fn context(root: Cert, fetchers: Fetchers) -> ValidationContext {
    // Exactly the existing Adobe validation_context's timing/policy path:
    // no explicit point-in-time override, no other certs/revinfo/POE preload.
    let ctx = ValidationContext::builder()
        .trust_root(root)
        .moment(support::at(TIME))
        .revocation_mode("require")
        .fetchers(fetchers)
        .build()
        .unwrap();
    assert!(ctx.other_certs().is_empty());
    assert_eq!(ctx.crls().count() + ctx.ocsps().count(), 0);
    assert!(ctx.fetchers().ocsp.is_some() && ctx.fetchers().crl.is_some());
    ctx
}
fn normalize(result: sigis_pki_core::errors::Result<LtaValidationResult>) -> serde_json::Value {
    match result {
        Err(error) => serde_json::json!({
            "error":format!("{error:?}"),"has_role_entry":false,"authenticated_role":false
        }),
        Ok(result) => {
            let status = result.api_status.as_ref();
            let attrs = status.and_then(|s| s.ac_attrs.as_ref());
            let values = attrs
                .and_then(|a| a.get("role"))
                .map(|a| a.attr_values.as_slice())
                .unwrap_or_default();
            let parsed = values.first().and_then(|b| RoleSyntax::from_der(b).ok());
            let role_name = parsed.as_ref().and_then(|r| match &r.role_name {
                GeneralName::Rfc822Name(name) => Some(name.as_str().to_owned()),
                _ => None,
            });
            serde_json::json!({
                "error":null,"ades_subindic":result.ades_subindic.standard_name(),
                "failure_msg":result.failure_msg,"best_signature_time":result.best_signature_time.map(|t|t.to_string()),
                "api_present":status.is_some(),"bottom_line":status.map(|s|s.bottom_line()),
                "intact":status.map(|s|s.signature.intact),"valid":status.map(|s|s.signature.valid),
                "trusted":status.map(|s|s.signature.trusted()),
                "has_role_entry":attrs.is_some_and(|a|a.contains("role")),
                "authenticated_role":!values.is_empty(),"role_count":values.len(),
                "typed_role":parsed.is_some(),"rfc822_role_name":role_name,
                "ac_errors":status.and_then(|s|s.ac_validation_errs.as_ref()),
                "main_path_sha256":status.and_then(|s|s.signature.validation_path.as_ref()).map(|p|p.certs().iter().map(|c|sha(c.der())).collect::<Vec<_>>()),
                "timestamp_path_sha256":status.and_then(|s|s.timestamp_validity.as_ref()).and_then(|t|t.signature.validation_path.as_ref()).map(|p|p.certs().iter().map(|c|sha(c.der())).collect::<Vec<_>>()),
                "full_status_debug":format!("{result:#?}")
            })
        }
    }
}

#[test]
fn frozen_pre_ria_native_adobe_bytes_match_original_public_lta() {
    // Copy artifact fixtures/ to this dedicated public testdata directory.
    let dir = sigis_testdata::path(&["lanes", "r3-v", "adobe-old-native"]);
    let aa_bytes = read_pinned(
        &dir.join("aa.der"),
        "f99a3526088b5fd5aec2e6cc48ced611ef77de337b11c782f0363de4359d7e8b",
    );
    let mut rows = Vec::new();
    for (backend, pdf_sha) in [
        (
            "requests",
            "c61dfabab6dea0e83f924e41cb95a2ae14e530ea7d759d285c9ebfa77566f97f",
        ),
        (
            "aiohttp",
            "fb38975943cd7c71c7ac5bbec500f33da1b827bb641795c168f75d82ff796a96",
        ),
    ] {
        let case = dir.join(backend);
        // Verify every retained public input before parsing this case.
        let pdf = read_pinned(&case.join("cms-adobe.pdf"), pdf_sha);
        let root_bytes = read_pinned(
            &case.join("root.der"),
            "8de3a2712e46d0ea6e9b5f234457aee5e9c7bed69fdf7feed0c5a98649688a3c",
        );
        let aa_root_bytes = read_pinned(
            &case.join("root-aa.der"),
            "57b9e80c61bdb208e67f02a4949d251e0552564728c9262f6cbea66520830b06",
        );
        let ac = read_pinned(
            &case.join("attribute-certificate.der"),
            "b650abefb4270855a7bb3aba8879044c64d52ef1969178ed66d9073f4c150909",
        );
        let ocsp = read_pinned(
            &case.join("ac-ocsp.der"),
            "0a2f1f902b1db9794e9df41c30c242b7be980986db21b5f33252feeb32de070d",
        );
        let root = Cert::from_der(&root_bytes).unwrap();
        let aa_root = Cert::from_der(&aa_root_bytes).unwrap();
        let aa = Cert::from_der(&aa_bytes).unwrap();
        let file = PdfFile::parse(&pdf).unwrap();
        assert!(
            !file.encrypted(),
            "plain Adobe input: MAC/decryption is inapplicable"
        );
        assert!(file.dss().unwrap().is_none(), "no DSS substitute");
        let signatures = file.embedded_signatures().unwrap();
        assert_eq!(signatures.len(), 1);
        let signature = signatures
            .iter()
            .find(|s| s.kind == SignatureKind::Signature)
            .unwrap();
        assert_eq!(signature.field_name, "Sig1");
        assert_eq!(signature.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
        let sd = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
        let certificates = extract_certificate_info(&sd).unwrap();
        assert_eq!(certificates.other_certs.len(), 5);
        assert_eq!(certificates.attribute_certs, vec![ac.clone()]);
        assert_eq!(sd.certificates.len() + sd.attribute_certificates.len(), 7);
        let encoded = find_unique_cms_attribute(
            sd.signer_infos[0].signed_attr_list(),
            oids::ADBE_REVOCATION_INFO_ARCHIVAL,
        )
        .unwrap();
        assert_eq!(
            sha(encoded),
            "c928027ba88d621e89290fc1d96632a809c6de38cbfb7dad9c1dc6d88c064e75"
        );
        let ria = RevocationInfoArchival::from_der(encoded).unwrap();
        assert!(ria.crl.as_ref().is_some_and(|v| !v.is_empty()));
        assert!(ria
            .ocsp
            .as_ref()
            .unwrap()
            .iter()
            .any(|v| v.to_der().unwrap() == ocsp));
        // This is the same recorded provider used by the existing original
        // caller; it is retrieval capability, not context-preloaded evidence.
        // Full AC bytes plus actual AA bind the explicit AC response route.
        let fetchers =
            support::services::Services::new(&[ARCH], TIME).fetchers_with_ac_ocsp(ac, aa, ocsp);
        let main = context(root.clone(), fetchers.clone());
        let authority = context(aa_root, fetchers.clone());
        let wrong_authority = context(root, fetchers);
        let before = [
            format!("{main:?}"),
            format!("{authority:?}"),
            format!("{wrong_authority:?}"),
        ];
        let correct = normalize(lta_validation_with_options(
            &file,
            signature,
            &main,
            &QualificationSpec::default(),
            &LtaOptions {
                ac_validation_context: Some(&authority),
                ..Default::default()
            },
        ));
        let wrong = normalize(lta_validation_with_options(
            &file,
            signature,
            &main,
            &QualificationSpec::default(),
            &LtaOptions {
                ac_validation_context: Some(&wrong_authority),
                ..Default::default()
            },
        ));
        assert_eq!(
            [
                format!("{main:?}"),
                format!("{authority:?}"),
                format!("{wrong_authority:?}")
            ],
            before
        );
        // Existing unchanged helper, exact original current-online policy.
        let script =
            sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/cms_adobe_verdict.py");
        let oracle = sigis_testdata::oracle::run_json(
            &script,
            &[
                case.join("cms-adobe.pdf").to_str().unwrap(),
                case.join("root.der").to_str().unwrap(),
                case.join("root-aa.der").to_str().unwrap(),
                case.join("attribute-certificate.der").to_str().unwrap(),
                case.join("ac-ocsp.der").to_str().unwrap(),
                backend,
                TIME,
            ],
        )
        .expect("mandatory fresh same-OLD-byte public LTA oracle");
        rows.push(serde_json::json!({"backend_label":backend,"pdf_sha256":pdf_sha,
            "mac_applicable":false,"no_dss":true,"native_timing":format!("{:?}",main.timing()),
            "profile":"original REQUIRE current-online; separate main/AA roots; no preload/provided POE",
            "native":correct,"native_wrong_AA":wrong,"oracle":oracle}));
    }
    // Preserve both actual old-byte results before the parity assertions.
    eprintln!(
        "ADOBE_OLD_NATIVE_RESULTS {}",
        serde_json::to_string(&rows).unwrap()
    );
    for row in &rows {
        let native = &row["native"];
        let oracle = &row["oracle"];
        assert!(native["error"].is_null(), "{row}");
        assert_eq!(oracle["pyhanko"], "0.38.1");
        assert_eq!(oracle["certvalidator"], "0.33.0");
        assert_eq!(oracle["pdf_sha256"], row["pdf_sha256"]);
        assert_eq!(native["ades_subindic"], "OK", "{row}");
        assert_eq!(
            native["ades_subindic"], oracle["correct"]["ades_subindic"],
            "{row}"
        );
        for key in [
            "bottom_line",
            "intact",
            "valid",
            "trusted",
            "authenticated_role",
        ] {
            assert_eq!(native[key], true, "{key}: {row}");
            assert_eq!(native[key], oracle["correct"][key], "{key}: {row}");
        }
        assert_eq!(native["typed_role"], true);
        assert_eq!(native["role_count"], 1);
        assert_eq!(native["rfc822_role_name"], "bigboss@example.com");
        assert_eq!(oracle["correct"]["role_type"], "RoleSyntax");
        assert_eq!(oracle["correct"]["role_name"], "bigboss@example.com");
        assert_eq!(row["native_wrong_AA"]["has_role_entry"], false, "{row}");
        assert_eq!(oracle["wrong_ac_root"]["authenticated_role"], false);
    }
}
