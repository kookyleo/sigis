// Ported from pyHanko 0.38.1 tests/test_cms.py (MIT).
//! Exact Adobe AC revinfo caller; original default current-time fetching remains enabled.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/signing_integration.rs"]
mod support;

use std::sync::Arc;

use der::{Decode, Encode};
use sigis_cms::attributes::RoleSyntax;
use sigis_cms::signed_data::{extract_certificate_info, find_unique_cms_attribute};
use sigis_pades::ades::{
    basic::QualificationSpec,
    lta::{lta_validation_with_options, LtaOptions},
};
use sigis_pades_sign::attributes::RevocationInfoArchival;
use sigis_pades_sign::ltv::{validate_and_collect_attribute_certs, ValidationInfo};
use sigis_pades_sign::{DummyTimeStamper, PdfSignatureMetadata, PdfSigner, SimpleSigner};
use sigis_pdf::{PdfFile, SignatureKind};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{algorithms::DigestAlgorithm, asn1::oids, cert::Cert, fetch::Fetchers};
use x509_cert::ext::pkix::name::GeneralName;

const TIME: &str = "2020-11-01T00:00:00Z";
const ARCH: &str = "testing-ca-with-aa";
const FUNCTION: &str = "test_embed_ac_revinfo_adobe_style";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(support::data_path(&["lanes", "r3-p", "ac", name])).unwrap()
}

fn authorities() -> Vec<Cert> {
    let pki = support::pki(ARCH);
    ["root", "interm", "root-aa", "interm-aa", "leaf-aa"]
        .into_iter()
        .map(|label| pki.cert(label))
        .collect()
}

fn services() -> Fetchers {
    let pki = support::pki(ARCH);
    // Existing explicit opt-in fixture provider, bound to the full AC bytes
    // and actual AA. Production validators still authenticate all responses.
    // These are recorded PKI responses, not fresh HTTP evidence.
    support::services::Services::new(&[ARCH], TIME).fetchers_with_ac_ocsp(
        fixture("alice-role-with-rev.der"),
        pki.cert("leaf-aa"),
        fixture("ocsp-alice-role-with-rev.der"),
    )
}

fn signing_context(ac: bool, fetchers: Fetchers) -> ValidationContext {
    let pki = support::pki(ARCH);
    let mut builder = ValidationContext::builder()
        .trust_root(pki.cert(if ac { "root-aa" } else { "root" }))
        .moment(support::at(TIME))
        .revocation_mode("require")
        .fetchers(fetchers);
    for cert in authorities() {
        builder = builder.other_cert(cert);
    }
    builder.build().unwrap()
}

fn validation_context(ac: bool, fetchers: Fetchers, wrong_ac_root: bool) -> ValidationContext {
    let pki = support::pki(ARCH);
    let context = ValidationContext::builder()
        .trust_root(pki.cert(if ac && !wrong_ac_root {
            "root-aa"
        } else {
            "root"
        }))
        .moment(support::at(TIME))
        .revocation_mode("require")
        .fetchers(fetchers)
        .build()
        .unwrap();
    assert!(context.other_certs().is_empty());
    context
}

fn sign_adobe_case() -> Vec<u8> {
    let pki = support::pki(ARCH);
    let signer = SimpleSigner::new(
        pki.key(&pki.key_label_of("signer1")),
        pki.cert("signer1"),
        authorities(),
    )
    .unwrap();
    // Upstream leaves subfilter unspecified: Adobe GenericPdf, not PAdES.
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults("Sig1");
    metadata.embed_validation_info = true;
    let fetchers = services();
    metadata.validation_context = Some(Arc::new(signing_context(false, fetchers.clone())));
    metadata.ac_validation_context = Some(Arc::new(signing_context(true, fetchers)));
    let timestamp = DummyTimeStamper::new(
        pki.cert("tsa"),
        pki.key(&pki.key_label_of("tsa")),
        vec![pki.cert("root")],
    )
    .with_fixed_time(support::at(TIME));
    let mut pdf_signer = PdfSigner::new(metadata, Arc::new(signer))
        .at(support::at(TIME))
        .with_timestamper(Arc::new(timestamp));
    pdf_signer.cms_options.attribute_certs = vec![fixture("alice-role-with-rev.der")];
    pdf_signer.sign_pdf(&support::pdf("minimal.pdf")).unwrap()
}

fn assert_role(status: &sigis_cms::StandardCmsSignatureStatus) {
    assert!(status.bottom_line(), "{status:?}");
    let attrs = status
        .ac_attrs
        .as_ref()
        .expect("authenticated AC attributes");
    let roles = &attrs.get("role").expect("authenticated role").attr_values;
    let role = RoleSyntax::from_der(roles.first().expect("one RoleSyntax value")).unwrap();
    let GeneralName::Rfc822Name(name) = role.role_name else {
        panic!("the exact upstream role must use rfc822Name");
    };
    assert_eq!(name.as_str(), "bigboss@example.com");
    assert!(status.ac_validation_errs.as_ref().is_none_or(Vec::is_empty));
}

fn sha256(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn test_embed_ac_revinfo_adobe_style() {
    // Exact conftest fixture matrix: one immutable function, two backend cases.
    // Rust consolidates backend implementations behind Fetchers; Services is
    // its configured evidence adapter in both cases. Neither label claims a
    // separate native requests/aiohttp implementation or live HTTP exchange.
    for backend in ["requests", "aiohttp"] {
        let output = sign_adobe_case();
        let file = PdfFile::parse(&output).unwrap();
        let signature = file
            .embedded_signatures()
            .unwrap()
            .into_iter()
            .find(|signature| signature.kind == SignatureKind::Signature)
            .unwrap();
        assert_eq!(signature.field_name, "Sig1");
        assert_eq!(signature.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
        let sd = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
        let embedded = extract_certificate_info(&sd).unwrap();
        // Exact original assertions. Public-key cert count excludes the signer.
        assert_eq!(embedded.other_certs.len(), 5);
        assert_eq!(embedded.attribute_certs.len(), 1);
        // Supplemental structural/material controls: all seven actual choices,
        // the original AC DER, and the actual signed Adobe evidence attribute.
        assert_eq!(sd.certificates.len() + sd.attribute_certificates.len(), 7);
        assert_eq!(
            embedded.attribute_certs[0],
            fixture("alice-role-with-rev.der")
        );
        assert_eq!(embedded.signer_cert, support::pki(ARCH).cert("signer1"));
        let encoded = find_unique_cms_attribute(
            sd.signer_infos[0].signed_attr_list(),
            oids::ADBE_REVOCATION_INFO_ARCHIVAL,
        )
        .expect("real Adobe revocationInfoArchival must be signed");
        let ria = RevocationInfoArchival::from_der(encoded).unwrap();
        assert!(ria.crl.as_ref().is_some_and(|entries| !entries.is_empty()));
        let ocsp = ria.ocsp.as_ref().expect("actual embedded OCSP responses");
        assert!(!ocsp.is_empty());
        let ac_response = fixture("ocsp-alice-role-with-rev.der");
        assert!(ocsp
            .iter()
            .any(|entry| entry.to_der().unwrap() == ac_response));
        assert!(
            file.dss().unwrap().is_none(),
            "this is Adobe CMS evidence, not a DSS substitute"
        );

        // Match the ORIGINAL current-time/default online capability. Native
        // Services is configured retrieval, not preloaded context revinfo.
        // No manual extraction of RIA into either validation context is allowed.
        let validation_fetchers = services();
        let main = validation_context(false, validation_fetchers.clone(), false);
        let ac = validation_context(true, validation_fetchers.clone(), false);
        let result = lta_validation_with_options(
            &file,
            &signature,
            &main,
            &QualificationSpec::default(),
            &LtaOptions {
                ac_validation_context: Some(&ac),
                ..Default::default()
            },
        )
        .expect("run the real V AdES LTA API over actual P Adobe output");
        let subindication = result.ades_subindic.standard_name();
        let status = result.api_status.expect("original LTA API status");
        assert_role(&status);
        // Original tests api_status.bottom_line, not final archival OK. Keep
        // the actual final subindication visible instead of silently upgrading it.

        // Supplemental untrusted-AA control: main signer trust does not grant
        // authority to authenticate an AC under the unrelated main PKI root.
        let wrong_ac = validation_context(true, validation_fetchers, true);
        if let Ok(rejected) = lta_validation_with_options(
            &file,
            &signature,
            &main,
            &QualificationSpec::default(),
            &LtaOptions {
                ac_validation_context: Some(&wrong_ac),
                ..Default::default()
            },
        ) {
            if let Some(rejected) = rejected.api_status {
                assert!(rejected
                    .ac_attrs
                    .as_ref()
                    .is_none_or(|attrs| !attrs.contains("role")));
                assert!(rejected
                    .ac_validation_errs
                    .as_ref()
                    .is_some_and(|errors| !errors.is_empty()));
            }
        }
        // Existing P transactional holder guard is checked using a genuine,
        // differently identified holder, not by corrupting the AC signature.
        let mut rejected_info = ValidationInfo::default();
        let error = validate_and_collect_attribute_certs(
            &signing_context(true, services()),
            &support::pki(ARCH).cert("signer2"),
            &authorities(),
            &[fixture("alice-role-with-rev.der")],
            &mut rejected_info,
        )
        .unwrap_err();
        assert!(error.to_string().contains("holder"), "{error}");
        assert!(rejected_info.paths.is_empty());
        assert!(rejected_info.ocsps.is_empty());
        assert!(rejected_info.crls.is_empty());

        let directory = tempfile::tempdir().unwrap();
        let pdf_path = directory.path().join("cms-adobe.pdf");
        let root_path = directory.path().join("root.der");
        let aa_root_path = directory.path().join("root-aa.der");
        let ac_path = directory.path().join("attribute-certificate.der");
        let ac_ocsp_path = directory.path().join("ac-ocsp.der");
        std::fs::write(&pdf_path, &output).unwrap();
        std::fs::write(&root_path, support::pki(ARCH).cert("root").der()).unwrap();
        std::fs::write(&aa_root_path, support::pki(ARCH).cert("root-aa").der()).unwrap();
        std::fs::write(&ac_path, fixture("alice-role-with-rev.der")).unwrap();
        std::fs::write(&ac_ocsp_path, &ac_response).unwrap();
        if let Some(retained) = std::env::var_os("SIGIS_CMS_ADOBE_ARTIFACT_DIR") {
            let retained = std::path::PathBuf::from(retained).join(backend);
            std::fs::create_dir_all(&retained).unwrap();
            for (source, name) in [
                (&pdf_path, "cms-adobe.pdf"),
                (&root_path, "root.der"),
                (&aa_root_path, "root-aa.der"),
                (&ac_path, "attribute-certificate.der"),
                (&ac_ocsp_path, "ac-ocsp.der"),
            ] {
                std::fs::copy(source, retained.join(name)).unwrap();
            }
        }
        let script = std::env::var_os("SIGIS_CMS_ADOBE_ORACLE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/cms_adobe_verdict.py")
            });
        let oracle = sigis_testdata::oracle::run_json(
            &script,
            &[
                pdf_path.to_str().unwrap(),
                root_path.to_str().unwrap(),
                aa_root_path.to_str().unwrap(),
                ac_path.to_str().unwrap(),
                ac_ocsp_path.to_str().unwrap(),
                backend,
                TIME,
            ],
        )
        .expect("mandatory fresh pinned Python LTA/RoleSyntax over the same actual PDF");
        assert_eq!(oracle["pyhanko"], "0.38.1");
        assert_eq!(oracle["certvalidator"], "0.33.0");
        assert_eq!(oracle["pdf_sha256"], sha256(&output));
        assert_eq!(
            oracle["root_sha256"],
            sha256(support::pki(ARCH).cert("root").der())
        );
        assert_eq!(
            oracle["aa_root_sha256"],
            sha256(support::pki(ARCH).cert("root-aa").der())
        );
        assert_eq!(
            oracle["ac_sha256"],
            sha256(&fixture("alice-role-with-rev.der"))
        );
        assert_eq!(oracle["adobe_revinfo_sha256"], sha256(encoded));
        assert_eq!(oracle["backend_case"], backend);
        assert_eq!(oracle["other_certificates"], 5);
        assert_eq!(oracle["attribute_certificates"], 1);
        assert_eq!(oracle["total_certificates"], 7);
        assert_eq!(oracle["correct"]["bottom_line"], true);
        assert_eq!(oracle["correct"]["role_type"], "RoleSyntax");
        assert_eq!(oracle["correct"]["role_name"], "bigboss@example.com");
        assert_eq!(oracle["wrong_ac_root"]["authenticated_role"], false);
        eprintln!(
            "CMS_ADOBE_AC {}",
            serde_json::json!({
                "upstream_id": format!("pyhanko/test_cms.py::{FUNCTION}"),
                "backend_case": backend,
                "native_fetch_adapter": "shared Services with explicit AC-bound OCSP opt-in",
                "native_subindication": subindication,
                "native_bottom_line": status.bottom_line(),
                "pdf_sha256": sha256(&output),
                "adobe_revinfo_sha256": sha256(encoded),
                "oracle": oracle,
            })
        );
    }
}
