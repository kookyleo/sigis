// Ported from pyHanko0.38.1 test_pades.py (MIT).
//! Tests-first ROOT caller: seven immutable functions, nine actual output cases.
//! Backend labels retain the Python fixture matrix; Rust uses one Fetchers API.
//! Install as tests/round3_p_ac_complete.rs, not inside the signing crate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/p7_native_tail.rs"]
mod native_tail;
#[path = "support/signing_integration.rs"]
mod support;

use sigis_cms::signed_data::extract_signer_info;
use sigis_pades_sign::attributes::{commitment_indication, GenericCommitment};
use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
use sigis_pades_sign::{
    CadesSignedAttrSpec, DummyTimeStamper, PdfSignatureMetadata, PdfSigner, SignOptions,
    SignerAttrSpec, SimpleSigner, SubFilter,
};
use sigis_pdf::{PdfFile, SignatureKind};
use sigis_pki_certvalidator::{CertRevTrustPolicy, ValidationContext, REQUIRE_REVINFO};
use sigis_pki_core::{algorithms::DigestAlgorithm, asn1::oids, cert::Cert, fetch::Fetchers};
use std::sync::Arc;

const ARCH: &str = "testing-ca-with-aa";
const SIGN_TIME: &str = "2020-11-01T00:00:00Z";
const LTA_TIME: &str = "2028-02-01T00:00:00Z";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(support::data_path(&["lanes", "r3-p", "ac", name])).unwrap()
}

fn hash(bytes: &[u8]) -> String {
    DigestAlgorithm::Sha256
        .digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn authorities() -> Vec<Cert> {
    let p = support::pki(ARCH);
    ["root", "interm", "root-aa", "interm-aa", "leaf-aa"]
        .into_iter()
        .map(|label| p.cert(label))
        .collect()
}

fn service_fetchers(time: &str) -> Fetchers {
    // Explicit fixture retrieval, bound to actual full AC DER + actual AA.
    // The raw response is NOT supplied as context revinfo. No live HTTP claim.
    let (response, expected) = match time {
        SIGN_TIME => (
            fixture("ocsp-alice-role-with-rev.der"),
            "0a2f1f902b1db9794e9df41c30c242b7be980986db21b5f33252feeb32de070d",
        ),
        LTA_TIME => (
            fixture("ocsp-alice-role-with-rev-2028-02-01.der"),
            "d30e61620a051faa16c4385a856e2c212befd1ae388ab7dfe761fac3d7fed1a4",
        ),
        _ => panic!("no pinned current AC response for {time}"),
    };
    assert_eq!(hash(&response), expected);
    eprintln!(
        "P7_AC_PROVIDER {}",
        serde_json::json!({"validation_time":time,"response_sha256":expected})
    );
    support::services::Services::new(&[ARCH], time).fetchers_with_ac_ocsp(
        fixture("alice-role-with-rev.der"),
        support::pki(ARCH).cert("leaf-aa"),
        response,
    )
}

fn signing_context(ac: bool, presign_case: bool, fetchers: Fetchers) -> ValidationContext {
    let p = support::pki(ARCH);
    let mut builder = ValidationContext::builder()
        .trust_root(p.cert(if ac { "root-aa" } else { "root" }))
        .moment(support::at(SIGN_TIME))
        // Original contexts have no explicit moment; freezegun sets the clock.
        .point_in_time_validation(false)
        .fetchers(fetchers);
    if presign_case {
        builder = builder.revocation_mode("require");
        for cert in authorities() {
            builder = builder.other_cert(cert);
        }
    } else {
        // Exact live_ac_vcs(with_authorities=True), DEFAULT soft-fail policy.
        for label in ["interm", "interm-aa", "leaf-aa"] {
            builder = builder.other_cert(p.cert(label));
        }
    }
    let context = builder.build().unwrap();
    assert!(context.crls().next().is_none());
    assert!(context.ocsps().next().is_none());
    if presign_case {
        assert_eq!(context.other_certs().len(), 5);
        assert_eq!(
            context.revinfo_policy().revocation_checking_policy,
            REQUIRE_REVINFO
        );
    } else {
        assert_eq!(context.other_certs().len(), 3);
        assert_eq!(context.revinfo_policy(), &CertRevTrustPolicy::default());
    }
    context
}

fn validation_context(ac: bool, live: bool, time: &str) -> ValidationContext {
    let p = support::pki(ARCH);
    let mut builder = ValidationContext::builder()
        .trust_root(p.cert(if ac { "root-aa" } else { "root" }))
        .moment(support::at(time))
        .point_in_time_validation(false)
        .fetchers(service_fetchers(time));
    if live {
        builder = builder.revinfo_policy(CertRevTrustPolicy::new(REQUIRE_REVINFO));
    }
    // No other_certs or response preloads: only this output may supply material.
    builder.build().unwrap()
}

struct ActualOutput {
    pdf: Vec<u8>,
    root: Vec<u8>,
    aa_root: Vec<u8>,
    aa: Vec<u8>,
    ac: Vec<u8>,
    ac_ocsp: Vec<u8>,
    signer: Cert,
}

fn sign_original_case(name: &str) -> ActualOutput {
    let presign = name.contains("live_ac_presign_validation");
    let lta = name == "test_pades_lta_live_ac_presign_validation";
    let autofill = name == "test_cades_signer_attrs_autofill_dss";
    let no_claimed = name == "test_cades_signer_attrs_validate_acs_no_claimed";
    let p = support::pki(ARCH);
    let signer = SimpleSigner::new(
        p.key(&p.key_label_of("signer1")),
        p.cert("signer1"),
        if autofill { Vec::new() } else { authorities() },
    )
    .unwrap();
    use sigis_pki_core::sign::KeySigner;
    assert_eq!(signer.cert_chain().is_empty(), autofill);
    let (main_fetchers, ac_fetchers) = if presign {
        // Original fixture shares its configured fetchers across both contexts.
        let shared = service_fetchers(SIGN_TIME);
        (shared.clone(), shared)
    } else {
        // live_ac_vcs creates independent default contexts over the same PKI.
        (service_fetchers(SIGN_TIME), service_fetchers(SIGN_TIME))
    };
    let mut metadata = PdfSignatureMetadata::new(if presign { "" } else { "Sig1" });
    metadata.subfilter = Some(SubFilter::Pades);
    metadata.validation_context = Some(Arc::new(signing_context(false, presign, main_fetchers)));
    metadata.ac_validation_context = Some(Arc::new(signing_context(true, presign, ac_fetchers)));
    metadata.embed_validation_info = true;
    metadata.use_pades_lta = lta;
    if presign && !lta {
        metadata.dss_settings = DssContentSettings {
            include_vri: false,
            placement: SigDssPlacement::TogetherWithSignature,
            ..Default::default()
        };
    }
    if !presign {
        metadata.cades_signed_attr_spec = Some(CadesSignedAttrSpec {
            commitment_type: (!no_claimed)
                .then(|| commitment_indication(GenericCommitment::ProofOfApproval)),
            signer_attributes: Some(SignerAttrSpec {
                claimed_attrs: if no_claimed {
                    Vec::new()
                } else {
                    vec![fixture("claimed-group.der")]
                },
                certified_attrs: vec![fixture("alice-role-with-rev.der")],
            }),
            ..Default::default()
        });
    }
    let mut pdf_signer = PdfSigner::new(metadata, Arc::new(signer)).at(support::at(SIGN_TIME));
    if presign {
        pdf_signer.cms_options.attribute_certs = vec![fixture("alice-role-with-rev.der")];
        pdf_signer = pdf_signer.with_timestamper(Arc::new(
            DummyTimeStamper::new(
                p.cert("tsa"),
                p.key(&p.key_label_of("tsa")),
                vec![p.cert("root")],
            )
            .with_fixed_time(support::at(SIGN_TIME)),
        ));
    }
    let input = support::pdf(if presign {
        "minimal-with-field.pdf"
    } else {
        "minimal.pdf"
    });
    let output = pdf_signer
        .sign_pdf_with(
            &input,
            &SignOptions {
                existing_fields_only: presign,
                ..Default::default()
            },
        )
        .expect(
            "actual original P signing setup; do not accept a presign error as a status negative",
        );
    ActualOutput {
        pdf: output,
        root: p.cert("root").der().to_vec(),
        aa_root: p.cert("root-aa").der().to_vec(),
        aa: p.cert("leaf-aa").der().to_vec(),
        ac: fixture("alice-role-with-rev.der"),
        ac_ocsp: fixture("ocsp-alice-role-with-rev.der"),
        signer: p.cert("signer1"),
    }
}

fn assert_actual_signature(output: &ActualOutput) {
    // Supplemental loaded-signer CMS integrity, without trust shortcuts. Ensures
    // even missing-VC/autofill cases validate real signed bytes, not fake status.
    let file = PdfFile::parse(&output.pdf).unwrap();
    let signature = file
        .embedded_signatures()
        .unwrap()
        .into_iter()
        .find(|s| s.kind == SignatureKind::Signature)
        .unwrap();
    let sd = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
    let si = extract_signer_info(&sd).unwrap();
    let digest = si
        .digest()
        .unwrap()
        .digest(&signature.signed_data(&file).unwrap());
    let (intact, valid) = sigis_cms::validate::validate_sig_integrity(
        si,
        &output.signer,
        &oids::CT_DATA.into(),
        &digest,
    )
    .unwrap();
    assert!(intact && valid);
}

fn run_original_case(name: &str, backend: &str) {
    let output = sign_original_case(name);
    let directory = tempfile::tempdir().unwrap();
    let files: Vec<(&str, &[u8])> = vec![
        ("document.pdf", &output.pdf),
        ("root.der", &output.root),
        ("root-aa.der", &output.aa_root),
        ("aa.der", &output.aa),
        ("ac.der", &output.ac),
        ("ac-ocsp.der", &output.ac_ocsp),
        ("signer.der", output.signer.der()),
    ];
    // Preserve generated bytes BEFORE either native or Python validation. An
    // explicitly selected retained directory keeps a failing case reviewable.
    let retained = std::env::var_os("SIGIS_P7_ARTIFACT_DIR")
        .map(|base| std::path::PathBuf::from(base).join(format!("{name}-{backend}")));
    if let Some(path) = &retained {
        std::fs::create_dir_all(path).unwrap();
    }
    let mut receipts = Vec::new();
    for (name, bytes) in files {
        std::fs::write(directory.path().join(name), bytes).unwrap();
        if let Some(path) = &retained {
            std::fs::write(path.join(name), bytes).unwrap();
        }
        receipts.push(serde_json::json!({"file":name,"bytes":bytes.len(),"sha256":hash(bytes)}));
    }
    eprintln!(
        "P7_OUTPUT_OPEN {}",
        serde_json::json!({"case":name,"backend_label":backend,"inputs":receipts})
    );
    assert_actual_signature(&output);
    let live = name.contains("live_ac_presign_validation");
    let validation_time = if name == "test_pades_lta_live_ac_presign_validation" {
        LTA_TIME
    } else {
        SIGN_TIME
    };
    let main = validation_context(false, live, validation_time);
    let ac = validation_context(true, live, validation_time);

    let helper = std::env::var_os("SIGIS_P7_ORACLE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            sigis_testdata::manifest_dir().join("tools/pyhanko-oracle/p7_same_output.py")
        });
    let assertions = support::data_path(&["lanes", "r3-p", "ac", "ac_assertions.py"]);
    let path = |name: &str| directory.path().join(name).to_str().unwrap().to_owned();
    let verdict = sigis_testdata::oracle::run_json(
        &helper,
        &[
            "--case",
            name,
            "--backend",
            backend,
            "--pdf",
            &path("document.pdf"),
            "--root",
            &path("root.der"),
            "--aa-root",
            &path("root-aa.der"),
            "--ac",
            &path("ac.der"),
            "--assertions-script",
            assertions.to_str().unwrap(),
        ],
    )
    .expect("all original same-output assertions require fresh pinned Python; never skip");
    assert_eq!(verdict["case"], name);
    assert_eq!(verdict["backend_label"], backend);
    assert_eq!(verdict["opened"]["pdf"]["sha256"], hash(&output.pdf));
    assert_eq!(verdict["assertion_tail_passed"], true);
    assert_eq!(verdict["native_count_credit"], 0);
    if let Some(path) = &retained {
        std::fs::write(
            path.join("same-output-oracle.json"),
            serde_json::to_vec_pretty(&verdict).unwrap(),
        )
        .unwrap();
    }
    // Run the complete native tail after retaining fresh same-byte reference:
    // a native assertion failure still leaves a meaningful expected verdict.
    native_tail::assert_p7_native_tail(name, &output.pdf, &main, &ac);
    if name == "test_pades_lta_live_ac_presign_validation" {
        // Same 2028 PKC services, but deliberately stale 2020 AC evidence.
        // This test adapter provides no alternative AC CRL. Mandatory AC
        // validation must refuse the role, without changing the clock/policy.
        let stale_fetchers = support::services::Services::new(&[ARCH], LTA_TIME)
            .fetchers_with_ac_ocsp(
                fixture("alice-role-with-rev.der"),
                support::pki(ARCH).cert("leaf-aa"),
                fixture("ocsp-alice-role-with-rev.der"),
            );
        let stale_ac = ac.with_fetchers(stale_fetchers);
        native_tail::assert_stale_current_ac_response_not_authenticated(
            &output.pdf,
            &main,
            &stale_ac,
        );
    }
    eprintln!(
        "P7_COMPLETE_CASE {}",
        serde_json::json!({"case":name,"backend_label":backend,"pdf_sha256":hash(&output.pdf),"same_output":verdict})
    );
}

#[test]
fn test_pades_live_ac_presign_validation() {
    for backend in ["requests", "aiohttp"] {
        run_original_case("test_pades_live_ac_presign_validation", backend);
    }
}
#[test]
fn test_pades_lta_live_ac_presign_validation() {
    for backend in ["requests", "aiohttp"] {
        run_original_case("test_pades_lta_live_ac_presign_validation", backend);
    }
}
#[test]
fn test_cades_signer_attrs_autofill_dss() {
    run_original_case("test_cades_signer_attrs_autofill_dss", "requests");
}
#[test]
fn test_cades_signer_attrs_validate_acs() {
    run_original_case("test_cades_signer_attrs_validate_acs", "requests");
}
#[test]
fn test_cades_signer_attrs_validate_acs_no_claimed() {
    run_original_case(
        "test_cades_signer_attrs_validate_acs_no_claimed",
        "requests",
    );
}
#[test]
fn test_cades_signer_attrs_validate_acs_wrong_vc() {
    run_original_case("test_cades_signer_attrs_validate_acs_wrong_vc", "requests");
}
#[test]
fn test_cades_signer_attrs_validate_acs_missing_vc() {
    run_original_case(
        "test_cades_signer_attrs_validate_acs_missing_vc",
        "requests",
    );
}
