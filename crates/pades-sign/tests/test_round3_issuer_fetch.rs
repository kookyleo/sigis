//! Behavioral regressions for fetching missing issuers before PDF signing.
//!
//! These tests add no unique upstream function claims or HTTP AIA coverage.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::{Arc, Mutex};

use const_oid::ObjectIdentifier;
use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement};
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SimpleSigner};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{FetchError, HankoError};
use sigis_pki_core::fetch::{CertificateFetcher, Fetchers};
use sigis_pki_core::time::Moment;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const TIME: &str = "2020-11-01T00:00:00Z";
const DENIAL: &str = "Fetched issuer certificate is forbidden by caller policy";

#[derive(Debug)]
struct FixedIssuers {
    issuers: Vec<Cert>,
    requested: Mutex<Vec<Cert>>,
    max_calls: Option<usize>,
}

impl FixedIssuers {
    fn new(issuers: Vec<Cert>) -> Arc<Self> {
        Arc::new(Self {
            issuers,
            requested: Mutex::new(Vec::new()),
            max_calls: None,
        })
    }

    fn once(issuers: Vec<Cert>) -> Arc<Self> {
        Arc::new(Self {
            issuers,
            requested: Mutex::new(Vec::new()),
            max_calls: Some(1),
        })
    }
}

impl CertificateFetcher for FixedIssuers {
    fn fetch_issuers(&self, cert: &Cert) -> Result<Vec<Cert>, FetchError> {
        let mut requested = self.requested.lock().unwrap();
        requested.push(cert.clone());
        if self.max_calls.is_some_and(|limit| requested.len() > limit) {
            return Err(FetchError::new(
                sigis_pki_core::errors::FetchErrorKind::Disabled,
                "Test certificate-fetch allowance exhausted",
            ));
        }
        Ok(self.issuers.clone())
    }
}

#[derive(Debug)]
struct DenyFetchedIssuerSignature {
    root_key: SubjectPublicKeyInfoOwned,
}

impl AlgorithmUsagePolicy for DenyFetchedIssuerSignature {
    fn digest_algorithm_allowed(
        &self,
        _algorithm: &ObjectIdentifier,
        _moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        AlgorithmUsageConstraint::allowed()
    }

    fn signature_algorithm_allowed(
        &self,
        _algorithm: &AlgorithmIdentifierOwned,
        _moment: Option<Moment>,
        public_key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        if public_key == Some(&self.root_key) {
            AlgorithmUsageConstraint::denied(DENIAL)
        } else {
            AlgorithmUsageConstraint::allowed()
        }
    }
}

fn context(fetcher: Option<Arc<FixedIssuers>>, forbid_issuer: bool) -> ValidationContext {
    let pki = support::pki("testing-ca");
    let mut builder = ValidationContext::builder()
        .trust_root(pki.cert("root"))
        .moment(support::at(TIME))
        .revocation_mode("soft-fail");
    if let Some(fetcher) = fetcher {
        builder = builder.fetchers(Fetchers {
            cert: Some(fetcher),
            ..Default::default()
        });
    }
    if forbid_issuer {
        builder = builder.algorithm_policy(Arc::new(DenyFetchedIssuerSignature {
            root_key: pki.cert("root").public_key(),
        }));
    }
    builder.build().unwrap()
}

fn leaf_only_signer(context: ValidationContext) -> PdfSigner {
    let pki = support::pki("testing-ca");
    let signer = SimpleSigner::new(
        pki.key(&pki.key_label_of("signer1")),
        pki.cert("signer1"),
        Vec::new(),
    )
    .unwrap();
    let mut metadata = PdfSignatureMetadata::new("FetchedIssuer");
    metadata.validation_context = Some(Arc::new(context));
    metadata.embed_validation_info = true;
    metadata.dss_settings = DssContentSettings {
        include_vri: false,
        placement: SigDssPlacement::TogetherWithSignature,
        ..Default::default()
    };
    PdfSigner::new(metadata, Arc::new(signer)).at(support::at(TIME))
}

fn assert_signing_error(error: HankoError, expected: &str) {
    assert!(matches!(error, HankoError::Signing(_)), "{error}");
    assert!(error.to_string().contains(expected), "{error}");
}

#[test]
fn leaf_only_pdf_signing_fetches_issuer_and_embeds_validated_path() {
    let pki = support::pki("testing-ca");
    let fetcher = FixedIssuers::new(vec![pki.cert("interm")]);
    let output = leaf_only_signer(context(Some(fetcher.clone()), false))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .unwrap();
    assert_eq!(*fetcher.requested.lock().unwrap(), [pki.cert("signer1")]);
    let signatures = support::pdfcheck::embedded_signatures(&output);
    assert_eq!(signatures.len(), 1);
    support::pdfcheck::check_integrity(&output, &signatures[0]);
    assert_eq!(support::pdfcheck::dss_counts(&output).unwrap().0, 3);
    let root = pki.cert_path("root");
    // Basic PDF validation does not automatically import DSS certificates.
    // Read the actual emitted DSS, rather than preloading a fixture issuer.
    let path = support::temp_file("fetched-issuer.pdf", &output);
    let oracle = std::process::Command::new(
        support::oracle_python().expect("the fresh pinned pyHanko oracle is required"),
    )
    .args([
        "-I",
        "-c",
        r#"
import importlib.metadata, sys
from datetime import datetime
from freezegun import freeze_time
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.dss import DocumentSecurityStore
assert importlib.metadata.version('pyhanko') == '0.38.1'
assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
with freeze_time(sys.argv[3]), open(sys.argv[1], 'rb') as file:
    reader = PdfFileReader(file)
    dss = DocumentSecurityStore.read_dss(reader)
    assert len(dss.certs) == 3
    for roots, expected in [([load_cert_from_pemder(sys.argv[2])], True), ([], False)]:
        context = dss.as_validation_context(dict(
            trust_roots=roots, allow_fetching=False,
            moment=datetime.fromisoformat(sys.argv[3]), revocation_mode='soft-fail',
        ))
        status = validate_pdf_signature(reader.embedded_signatures[0], context)
        assert status.intact and status.valid
        assert status.trusted == expected
        assert status.bottom_line == expected
        assert status.coverage.name == 'ENTIRE_FILE'
print('PASS fresh DSS issuer trust and empty-root rejection')
"#,
    ])
    .args([support::path_str(&path), support::path_str(&root), TIME])
    .output()
    .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    assert!(String::from_utf8_lossy(&oracle.stdout).contains("PASS fresh DSS issuer trust"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn leaf_only_pdf_signing_without_issuer_fetcher_rejects() {
    let error = leaf_only_signer(context(None, false))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .unwrap_err();
    assert_signing_error(error, "Unable to build a validation path");
}

#[test]
fn leaf_only_pdf_signing_rejects_unrelated_fetched_issuer() {
    let pki = support::pki("testing-ca");
    // The leaf itself creates a cycle if fetched candidates are not filtered.
    // The root is trusted, but cannot directly issue this leaf.
    let fetcher = FixedIssuers::new(vec![pki.cert("signer1"), pki.cert("root")]);
    let error = leaf_only_signer(context(Some(fetcher.clone()), false))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .unwrap_err();
    assert_signing_error(error, "Unable to build a validation path");
    assert_eq!(*fetcher.requested.lock().unwrap(), [pki.cert("signer1")]);
}

#[test]
fn leaf_only_pdf_signing_does_not_trust_fetched_root() {
    let pki = support::pki("testing-ca");
    let fetcher = FixedIssuers::new(vec![pki.cert("interm"), pki.cert("root")]);
    let context = ValidationContext::builder()
        .trust_root(support::pki("testing-ca-ecdsa").cert("root"))
        .moment(support::at(TIME))
        .revocation_mode("soft-fail")
        .fetchers(Fetchers {
            cert: Some(fetcher.clone()),
            ..Default::default()
        })
        .build()
        .unwrap();
    let error = leaf_only_signer(context)
        .sign_pdf(&support::pdf("minimal.pdf"))
        .unwrap_err();
    assert_signing_error(error, "Unable to build a validation path");
    assert_eq!(
        *fetcher.requested.lock().unwrap(),
        [pki.cert("signer1"), pki.cert("interm"), pki.cert("root")],
        "a fetched self-signed root must not become trusted or cause a fetch loop"
    );
}

#[test]
fn leaf_only_pdf_signing_rejects_policy_forbidden_fetched_issuer() {
    let pki = support::pki("testing-ca");
    let fetcher = FixedIssuers::new(vec![pki.cert("interm")]);
    let error = leaf_only_signer(context(Some(fetcher.clone()), true))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .unwrap_err();
    assert_signing_error(error, DENIAL);
    assert_eq!(*fetcher.requested.lock().unwrap(), [pki.cert("signer1")]);
}

#[test]
fn rejected_fetched_path_does_not_publish_partial_validation_info() {
    use sigis_pades_sign::ltv::{validate_and_collect, ValidationInfo};

    let pki = support::pki("testing-ca");
    let fetcher = FixedIssuers::new(vec![pki.cert("interm")]);
    let context = context(Some(fetcher), true);
    let mut fetchers = context.fetchers().clone();
    assert!(pki.cert("signer1").declares_ocsp());
    let ocsp = std::fs::read(support::data_path(&[
        "lanes",
        "d",
        "revinfo",
        "testing-ca",
        "2020-11-01",
        "ocsp-signer1.der",
    ]))
    .unwrap();
    fetchers.ocsp = Some(Arc::new(support::services::FixedOcsp(ocsp)));
    let context = context.with_fetchers(fetchers);
    let mut info = ValidationInfo {
        paths: vec![vec![pki.cert("root")]],
        ..Default::default()
    };
    let original_paths = info.paths.clone();
    let error = validate_and_collect(&context, &pki.cert("signer1"), &[], &mut info).unwrap_err();
    assert!(error.to_string().contains(DENIAL), "{error}");
    assert_eq!(info.paths, original_paths);
    assert!(info.ocsps.is_empty());
    assert!(info.crls.is_empty());
}

fn ac_context(fetcher: Arc<FixedIssuers>, forbid_issuer: bool) -> ValidationContext {
    let pki = support::pki("testing-ca-with-aa");
    let mut fetchers = support::services::Services::new(&["testing-ca-with-aa"], TIME).fetchers();
    fetchers.cert = Some(fetcher);
    let mut builder = ValidationContext::builder()
        .trust_root(pki.cert("root-aa"))
        .other_cert(pki.cert("leaf-aa"))
        .moment(support::at(TIME))
        .revocation_mode("require")
        .fetchers(fetchers)
        .ocsp_response(
            std::fs::read(support::data_path(&[
                "lanes",
                "r3-p",
                "ac",
                "ocsp-alice-role-with-rev.der",
            ]))
            .unwrap(),
        );
    if forbid_issuer {
        builder = builder.algorithm_policy(Arc::new(DenyFetchedIssuerSignature {
            root_key: pki.cert("root-aa").public_key(),
        }));
    }
    builder.build().unwrap()
}

#[test]
fn ac_presign_uses_fetched_aa_intermediate_for_native_validation_and_collection() {
    use sigis_pades_sign::ltv::{validate_and_collect_attribute_certs, ValidationInfo};

    let pki = support::pki("testing-ca-with-aa");
    let fetcher = FixedIssuers::once(vec![pki.cert("interm-aa")]);
    let context = ac_context(fetcher.clone(), false);
    assert!(!context.other_certs().contains(&pki.cert("interm-aa")));
    let ac = std::fs::read(support::data_path(&[
        "lanes",
        "r3-p",
        "ac",
        "alice-role-with-rev.der",
    ]))
    .unwrap();
    let mut info = ValidationInfo::default();
    let results =
        validate_and_collect_attribute_certs(&context, &pki.cert("signer1"), &[], &[ac], &mut info)
            .expect("fetched AA intermediate must participate in native AC validation");
    assert_eq!(*fetcher.requested.lock().unwrap(), [pki.cert("leaf-aa")]);
    assert_eq!(results.len(), 1);
    assert!(results[0].approved_attributes.contains_key("role"));
    assert_eq!(
        info.paths,
        [vec![
            pki.cert("leaf-aa"),
            pki.cert("interm-aa"),
            pki.cert("root-aa"),
        ]]
    );
    assert_eq!(info.ocsps.len(), 1);
    assert_eq!(info.crls.len(), 2);
    // Fetching candidates must not mutate the source policy/context.
    assert!(!context.other_certs().contains(&pki.cert("interm-aa")));

    let oracle = std::process::Command::new(
        support::oracle_python().expect("the fresh pinned AC issuer oracle is required"),
    )
    .arg("-I")
    .arg(support::data_path(&[
        "lanes",
        "r3-p",
        "ac",
        "ac_issuer_assertions.py",
    ]))
    .arg(support::data_path(&[]))
    .output()
    .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let decisions: serde_json::Value = serde_json::from_slice(&oracle.stdout).unwrap();
    assert_eq!(decisions["allowed"]["accepted"], true);
    assert_eq!(decisions["allowed"]["issuer_calls"], 1);
    for case in ["policy", "holder", "untrusted"] {
        assert_eq!(decisions[case]["accepted"], false, "{decisions}");
    }
    eprintln!("fresh AC issuer oracle: {decisions}");
}

#[test]
fn ac_presign_fetched_aa_keeps_holder_policy_and_atomic_collection() {
    use sigis_pades_sign::ltv::{validate_and_collect_attribute_certs, ValidationInfo};

    let pki = support::pki("testing-ca-with-aa");
    let ac = std::fs::read(support::data_path(&[
        "lanes",
        "r3-p",
        "ac",
        "alice-role-with-rev.der",
    ]))
    .unwrap();
    for (forbid_issuer, holder) in [(true, pki.cert("signer1")), (false, pki.cert("signer2"))] {
        let fetcher = FixedIssuers::once(vec![pki.cert("interm-aa")]);
        let context = ac_context(fetcher.clone(), forbid_issuer);
        let mut info = ValidationInfo {
            paths: vec![vec![pki.cert("root")]],
            ..Default::default()
        };
        let original_paths = info.paths.clone();
        let error = validate_and_collect_attribute_certs(
            &context,
            &holder,
            &[],
            std::slice::from_ref(&ac),
            &mut info,
        )
        .unwrap_err();
        assert!(matches!(error, HankoError::Signing(_)), "{error}");
        if forbid_issuer {
            assert!(error.to_string().contains(DENIAL), "{error}");
        } else {
            assert!(error.to_string().contains("holder"), "{error}");
        }
        assert_eq!(*fetcher.requested.lock().unwrap(), [pki.cert("leaf-aa")]);
        assert_eq!(info.paths, original_paths);
        assert!(info.ocsps.is_empty());
        assert!(info.crls.is_empty());
    }
}

#[test]
fn ac_presign_does_not_trust_a_fetched_aa_root() {
    use sigis_pades_sign::ltv::{validate_and_collect_attribute_certs, ValidationInfo};

    let pki = support::pki("testing-ca-with-aa");
    let fetcher = FixedIssuers::new(vec![pki.cert("interm-aa"), pki.cert("root-aa")]);
    let mut fetchers = support::services::Services::new(&["testing-ca-with-aa"], TIME).fetchers();
    fetchers.cert = Some(fetcher.clone());
    // A fetched self-signed AA root is a candidate, never an added anchor.
    let context = ValidationContext::builder()
        .trust_root(pki.cert("root"))
        .other_cert(pki.cert("leaf-aa"))
        .moment(support::at(TIME))
        .revocation_mode("require")
        .fetchers(fetchers)
        .build()
        .unwrap();
    let ac = std::fs::read(support::data_path(&[
        "lanes",
        "r3-p",
        "ac",
        "alice-role-with-rev.der",
    ]))
    .unwrap();
    let mut info = ValidationInfo::default();
    let error =
        validate_and_collect_attribute_certs(&context, &pki.cert("signer1"), &[], &[ac], &mut info)
            .unwrap_err();
    assert!(matches!(error, HankoError::Signing(_)), "{error}");
    assert!(error.to_string().contains("validation path"), "{error}");
    assert!(info.paths.is_empty());
    assert!(info.ocsps.is_empty());
    assert!(info.crls.is_empty());
    let requested = fetcher.requested.lock().unwrap();
    assert!(!requested.is_empty() && requested.len() < 10);
}

#[test]
fn pdf_signing_embeds_the_once_fetched_aa_path_in_dss() {
    use sigis_pades_sign::{CadesSignedAttrSpec, SignerAttrSpec};

    let pki = support::pki("testing-ca-with-aa");
    let fetcher = FixedIssuers::once(vec![pki.cert("interm-aa")]);
    let mut metadata = PdfSignatureMetadata::new("FetchedAaIssuer");
    metadata.validation_context = Some(Arc::new(support::services::live_testing_vc(
        "testing-ca-with-aa",
        TIME,
        &[],
    )));
    metadata.ac_validation_context = Some(Arc::new(ac_context(fetcher.clone(), false)));
    metadata.embed_validation_info = true;
    metadata.dss_settings = DssContentSettings {
        include_vri: false,
        placement: SigDssPlacement::TogetherWithSignature,
        ..Default::default()
    };
    metadata.cades_signed_attr_spec = Some(CadesSignedAttrSpec {
        signer_attributes: Some(SignerAttrSpec {
            claimed_attrs: Vec::new(),
            certified_attrs: vec![std::fs::read(support::data_path(&[
                "lanes",
                "r3-p",
                "ac",
                "alice-role-with-rev.der",
            ]))
            .unwrap()],
        }),
        ..Default::default()
    });
    let output = PdfSigner::new(metadata, Arc::new(pki.signer("signer1")))
        .at(support::at(TIME))
        .sign_pdf(&support::pdf("minimal.pdf"))
        .expect("actual signing/DSS must retain the once-fetched AA path");
    assert_eq!(*fetcher.requested.lock().unwrap(), [pki.cert("leaf-aa")]);
    let signatures = support::pdfcheck::embedded_signatures(&output);
    assert_eq!(signatures.len(), 1);
    support::pdfcheck::check_integrity(&output, &signatures[0]);
    let (certs, ocsps, crls, _) = support::pdfcheck::dss_counts(&output).unwrap();
    assert_eq!((certs, ocsps, crls), (7, 2, 3));

    let parsed = sigis_pades_sign::pdf::writer::PdfUpdate::new(&output).unwrap();
    let dss = parsed
        .dict_get(parsed.root().unwrap(), b"DSS")
        .unwrap()
        .unwrap()
        .as_dict()
        .unwrap();
    let certificates = parsed
        .dict_get(dss, b"Certs")
        .unwrap()
        .unwrap()
        .as_array()
        .unwrap();
    let encoded_certificates: Vec<Vec<u8>> = certificates
        .iter()
        .map(|reference| {
            let stream = parsed.resolve(reference).unwrap().as_stream().unwrap();
            parsed
                .read_stream_data(stream, sigis_pdf::decode_limits::DecodePurpose::Certificate)
                .unwrap()
        })
        .collect();
    for label in ["leaf-aa", "interm-aa", "root-aa"] {
        assert!(
            encoded_certificates
                .iter()
                .any(|der| der == pki.cert(label).der()),
            "DSS must contain the exact validated {label} certificate"
        );
    }

    // Import AA material from the actual DSS, not from a fixture registry.
    // Basic Python PDF validation does not automatically import DSS entries.
    let path = support::temp_file("fetched-aa-issuer.pdf", &output);
    let oracle = std::process::Command::new(
        support::oracle_python().expect("the fresh output AC oracle is required"),
    )
    .arg("-I")
    .arg(support::data_path(&[
        "lanes",
        "r3-p",
        "ac",
        "ac_issuer_assertions.py",
    ]))
    .arg(support::data_path(&[]))
    .arg(&path)
    .output()
    .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let decisions: serde_json::Value = serde_json::from_slice(&oracle.stdout).unwrap();
    assert_eq!(decisions["pdf_trusted"]["certified_attributes_valid"], true);
    assert_eq!(
        decisions["pdf_no_aa_root"]["certified_attributes_valid"],
        false
    );
    eprintln!("fresh output AC oracle: {decisions}");
    let _ = std::fs::remove_file(path);
}
