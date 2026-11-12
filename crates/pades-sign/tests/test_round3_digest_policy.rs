//! The exact weak-digest presign refusal and caller-policy ordering regressions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use const_oid::ObjectIdentifier;
use sigis_pades_sign::signer::SigningProvider;
use sigis_pades_sign::{
    DeferredSignatureValue, DeferredSigner, PdfSignatureMetadata, PdfSigner, SignOptions,
    SimpleSigner,
};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::{AlgorithmUsageConstraint, AlgorithmUsagePolicy, DigestAlgorithm};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};
use sigis_pki_core::time::Moment;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const SIGNING_TIME: &str = "2020-11-01T00:00:00Z";

#[derive(Debug)]
struct DigestPolicy {
    deny_sha256: bool,
    moments: Arc<Mutex<Vec<Option<Moment>>>>,
}

impl AlgorithmUsagePolicy for DigestPolicy {
    fn digest_algorithm_allowed(
        &self,
        algorithm: &ObjectIdentifier,
        moment: Option<Moment>,
    ) -> AlgorithmUsageConstraint {
        self.moments.lock().unwrap().push(moment);
        if self.deny_sha256 && *algorithm == DigestAlgorithm::Sha256.oid() {
            AlgorithmUsageConstraint::denied("Caller explicitly forbids SHA-256")
        } else {
            AlgorithmUsageConstraint::allowed()
        }
    }

    fn signature_algorithm_allowed(
        &self,
        _algorithm: &AlgorithmIdentifierOwned,
        _moment: Option<Moment>,
        _public_key: Option<&SubjectPublicKeyInfoOwned>,
    ) -> AlgorithmUsageConstraint {
        // This adversarial policy forbids only the document digest. Certificate
        // signature policy validation cannot stand in for the missing check.
        AlgorithmUsageConstraint::allowed()
    }
}

#[derive(Debug)]
struct MechanismSpy {
    delegate: SimpleSigner,
    calls: Arc<AtomicUsize>,
}

impl SigningProvider for MechanismSpy {
    fn signing_cert(&self) -> Option<&Cert> {
        SigningProvider::signing_cert(&self.delegate)
    }

    fn cert_chain(&self) -> &[Cert] {
        SigningProvider::cert_chain(&self.delegate)
    }

    fn signature_algorithm(&self, digest: DigestAlgorithm) -> Result<AlgorithmIdentifierOwned> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        SigningProvider::signature_algorithm(&self.delegate, digest)
    }

    fn sign_raw(&self, data: &[u8], digest: DigestAlgorithm) -> Result<Vec<u8>> {
        SigningProvider::sign_raw(&self.delegate, data, digest)
    }
}

fn assert_policy_error(error: HankoError, digest: &str) {
    assert!(matches!(error, HankoError::Signing(_)), "{error}");
    let message = error.to_string();
    assert!(
        message.contains(&format!("{digest} is not allowed")),
        "{message}"
    );
    assert!(
        message.contains("specified validation context"),
        "{message}"
    );
}

fn assert_current_moments(moments: &Mutex<Vec<Option<Moment>>>, before: Moment, after: Moment) {
    let moments = moments.lock().unwrap();
    assert!(
        !moments.is_empty(),
        "the document digest policy must be consulted"
    );
    for moment in moments.iter() {
        let moment = moment.expect("the document digest policy requires an actual current time");
        assert!(
            before.unix_secs() <= moment.unix_secs() && moment.unix_secs() <= after.unix_secs(),
            "policy time {moment} must be current, independently of signing/validation time"
        );
    }
}

fn fresh_oracle() -> &'static serde_json::Value {
    static ORACLE: OnceLock<serde_json::Value> = OnceLock::new();
    ORACLE.get_or_init(|| {
        let python = support::oracle_python().expect("the fresh pinned oracle is required");
        let output = std::process::Command::new(python)
            .args(["-I", "-c", DIGEST_POLICY_ORACLE])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "digest policy oracle failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result = serde_json::from_slice(&output.stdout).unwrap();
        eprintln!("fresh digest policy oracle: {result}");
        result
    })
}

/// Exact upstream function: pyhanko/test_cms.py::test_sign_weak_digest_prevention.
#[test]
fn test_sign_weak_digest_prevention() {
    let oracle = fresh_oracle();
    assert_eq!(oracle["md5"]["error_type"], "SigningError");
    assert!(oracle["md5"]["message"]
        .as_str()
        .unwrap()
        .contains("md5 is not allowed"));
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults("Sig1");
    metadata.md_algorithm = Some(DigestAlgorithm::Md5);
    metadata.validation_context = Some(Arc::new(support::services::simple_vc(
        "testing-ca",
        SIGNING_TIME,
    )));
    let error = PdfSigner::new(
        metadata,
        Arc::new(support::pki("testing-ca").signer("signer1")),
    )
    .at(support::at(SIGNING_TIME))
    .sign_pdf(&support::pdf("minimal.pdf"))
    .map(|_| ())
    .expect_err("the caller validation context must forbid MD5 before mechanism selection");
    assert_policy_error(error, "md5");
}

#[test]
fn explicit_digest_policy_refuses_before_mechanism_introspection_at_current_time() {
    let oracle = fresh_oracle();
    assert_eq!(oracle["sha256"]["operation_mechanism_calls"], 0);
    assert!(oracle["sha256"]["message"]
        .as_str()
        .unwrap()
        .contains("DigestPolicy"));
    let pki = support::pki("testing-ca");
    let moments = Arc::new(Mutex::new(Vec::new()));
    let context = ValidationContext::builder()
        .trust_root(pki.cert("root"))
        .moment(support::at("2010-01-01T00:00:00Z"))
        .algorithm_policy(Arc::new(DigestPolicy {
            deny_sha256: true,
            moments: moments.clone(),
        }))
        .build()
        .unwrap();
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults("Denied");
    // An explicit digest avoids any need to ask the provider for a default.
    metadata.md_algorithm = Some(DigestAlgorithm::Sha256);
    metadata.validation_context = Some(Arc::new(context));
    let calls = Arc::new(AtomicUsize::new(0));
    let signer = PdfSigner::with_signing_provider(
        metadata,
        Arc::new(MechanismSpy {
            delegate: pki.signer("signer1"),
            calls: calls.clone(),
        }),
    )
    .at(support::at(SIGNING_TIME));
    let before = Moment::now();
    let result = signer.sign_pdf(&support::pdf("minimal.pdf"));
    let after = Moment::now();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "deny before consulting the mechanism"
    );
    assert_policy_error(
        result
            .map(|_| ())
            .expect_err("the explicit digest must be refused"),
        "sha256",
    );
    assert_current_moments(&moments, before, after);
}

#[test]
fn explicit_allowed_digest_produces_an_intact_native_signature() {
    assert_eq!(fresh_oracle()["sha256_allow"]["bottom_line"], true);
    let pki = support::pki("testing-ca");
    let moments = Arc::new(Mutex::new(Vec::new()));
    let context = ValidationContext::builder()
        .trust_root(pki.cert("root"))
        .moment(support::at(SIGNING_TIME))
        .algorithm_policy(Arc::new(DigestPolicy {
            deny_sha256: false,
            moments: moments.clone(),
        }))
        .build()
        .unwrap();
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults("Allowed");
    metadata.md_algorithm = Some(DigestAlgorithm::Sha256);
    metadata.validation_context = Some(Arc::new(context));
    let calls = Arc::new(AtomicUsize::new(0));
    let signer = PdfSigner::with_signing_provider(
        metadata,
        Arc::new(MechanismSpy {
            delegate: pki.signer("signer1"),
            calls: calls.clone(),
        }),
    )
    .at(support::at(SIGNING_TIME));
    let before = Moment::now();
    let output = signer.sign_pdf(&support::pdf("minimal.pdf")).unwrap();
    let after = Moment::now();
    assert!(calls.load(Ordering::SeqCst) > 0);
    assert_current_moments(&moments, before, after);
    let signatures = support::pdfcheck::embedded_signatures(&output);
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0].field_name, "Allowed");
    support::pdfcheck::check_integrity(&output, &signatures[0]);
}

#[test]
fn no_validation_context_preserves_explicit_md5_interrupted_preparation() {
    assert_eq!(fresh_oracle()["md5_without_vc"]["prepared"], true);
    let pki = support::pki("testing-ca");
    let provider = DeferredSigner::new(
        Some(pki.cert("signer1")),
        vec![pki.cert("interm"), pki.cert("root")],
        DeferredSignatureValue::Size(256),
        Some(AlgorithmIdentifierOwned {
            oid: sigis_pki_core::asn1::oids::MD5_WITH_RSA,
            parameters: None,
        }),
    );
    let mut metadata = PdfSignatureMetadata::pyhanko_defaults("Unvalidated");
    metadata.md_algorithm = Some(DigestAlgorithm::Md5);
    let prepared = PdfSigner::with_signing_provider(metadata, Arc::new(provider))
        .at(support::at(SIGNING_TIME))
        .digest_doc_for_signing(
            &support::pdf("minimal.pdf"),
            &SignOptions {
                bytes_reserved: Some(8192),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(prepared.md_algorithm, DigestAlgorithm::Md5);
    assert_eq!(prepared.prepared.document_digest.len(), 16);
    assert!(prepared.post_sign_instructions.is_none());
}

const DIGEST_POLICY_ORACLE: &str = r#"
import asyncio
import importlib.metadata
import json
from io import BytesIO

from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.general import SigningError
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.policy_decl import AlgorithmUsageConstraint, AlgorithmUsagePolicy
from pyhanko_testing_commons.test_data.samples import MINIMAL
from pyhanko_testing_commons.test_utils.signing_commons import FROM_CA, TRUST_ROOTS


class DigestPolicy(AlgorithmUsagePolicy):
    def __init__(self, deny_sha256):
        self.deny_sha256 = deny_sha256
        self.moments = []

    def digest_algorithm_allowed(self, algo, moment):
        self.moments.append(moment.isoformat() if moment else None)
        denied = self.deny_sha256 and algo['algorithm'].native == 'sha256'
        return AlgorithmUsageConstraint(
            allowed=not denied,
            failure_reason='Caller explicitly forbids SHA-256' if denied else None,
        )

    def signature_algorithm_allowed(self, algo, moment, public_key):
        return AlgorithmUsageConstraint(allowed=True)


class MechanismSpy(signers.SimpleSigner):
    def __init__(self):
        self.mechanism_calls = 0
        super().__init__(
            signing_cert=FROM_CA.signing_cert,
            signing_key=FROM_CA.signing_key,
            cert_registry=FROM_CA.cert_registry,
        )

    def get_signature_mechanism_for_digest(self, digest_algorithm):
        self.mechanism_calls += 1
        return super().get_signature_mechanism_for_digest(digest_algorithm)


async def main():
    assert importlib.metadata.version('pyhanko') == '0.38.1'
    assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
    results = {}
    for md, custom in [('md5', None), ('sha256', DigestPolicy(True))]:
        signer = MechanismSpy()
        context = ValidationContext(
            trust_roots=TRUST_ROOTS,
            algorithm_usage_policy=custom,
        )
        pdf_signer = signers.PdfSigner(
            signers.PdfSignatureMetadata(
                field_name='Sig1', md_algorithm=md, validation_context=context
            ),
            signer=signer,
        )
        # Python probes once in PdfSigner.__init__; compare operation calls.
        before = signer.mechanism_calls
        try:
            await pdf_signer.async_sign_pdf(IncrementalPdfFileWriter(BytesIO(MINIMAL)))
        except SigningError as error:
            message = str(error)
            assert f'{md} is not allowed' in message
            assert 'specified validation context' in message
            if custom is not None:
                assert 'DigestPolicy' in message
                assert custom.moments == ['2020-11-01T00:00:00+00:00']
            assert signer.mechanism_calls == before
            results[md] = {
                'error_type': type(error).__name__,
                'message': message,
                'operation_mechanism_calls': signer.mechanism_calls - before,
                'policy_moments': custom.moments if custom else None,
            }
        else:
            raise AssertionError(f'{md} was not refused')

    signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(
            field_name='Allowed',
            md_algorithm='sha256',
            validation_context=ValidationContext(
                trust_roots=TRUST_ROOTS,
                algorithm_usage_policy=DigestPolicy(False),
            ),
        ),
        signer=FROM_CA,
    )
    output = await signer.async_sign_pdf(IncrementalPdfFileWriter(BytesIO(MINIMAL)))
    reader = PdfFileReader(output)
    status = await async_validate_pdf_signature(
        reader.embedded_signatures[0],
        signer_validation_context=ValidationContext(trust_roots=TRUST_ROOTS),
    )
    assert status.bottom_line
    results['sha256_allow'] = {'bottom_line': status.bottom_line}

    signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name='Unvalidated', md_algorithm='md5'),
        signer=FROM_CA,
    )
    prepared, tbs, output = await signer.async_digest_doc_for_signing(
        IncrementalPdfFileWriter(BytesIO(MINIMAL)), bytes_reserved=8192
    )
    assert tbs.md_algorithm == 'md5'
    assert len(prepared.document_digest) == 16
    results['md5_without_vc'] = {'prepared': True, 'digest_length': 16}
    print(json.dumps(results, sort_keys=True))


with freeze_time('2020-11-01'):
    asyncio.run(main())

"#;
