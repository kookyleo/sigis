//! Supplemental deterministic CSC batch-identity regression; no upstream IDs.

use super::{
    base64_digest, http_client, Batch, CscAuthorizationInfo, CscAuthorizationManager,
    CscCredentialInfo, CscServiceSessionInfo, CscSigner, CscSignerOptions,
};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};
use std::sync::Arc;

#[derive(Debug)]
struct NeverAuthorize {
    session: CscServiceSessionInfo,
    credential: CscCredentialInfo,
}

impl CscAuthorizationManager for NeverAuthorize {
    fn session_info(&self) -> &CscServiceSessionInfo {
        &self.session
    }

    fn credential_info(&self) -> &CscCredentialInfo {
        &self.credential
    }

    fn authorize_signature(&self, _: &[String]) -> Result<CscAuthorizationInfo> {
        panic!("an old batch's auto-commit must never authorize the new current batch")
    }
}

fn signer() -> CscSigner {
    let cert = Cert::from_pem_or_der(
        &std::fs::read(sigis_testdata::certvalidator(&[
            "nist_pkits",
            "certs",
            "TrustAnchorRootCertificate.crt",
        ]))
        .expect("known public RSA certificate"),
    )
    .expect("actual RSA credential certificate");
    let authorization = NeverAuthorize {
        session: CscServiceSessionInfo::new("http://127.0.0.1:1", "unused-credential"),
        credential: CscCredentialInfo {
            signing_cert: cert,
            chain: Vec::new(),
            supported_mechanisms: ["sha256_rsa".to_owned()].into_iter().collect(),
            max_batch_size: 10,
            hash_pinning_required: false,
            response_data: serde_json::json!({}),
        },
    };
    CscSigner::new(
        http_client().expect("client construction makes no request"),
        Arc::new(authorization),
        CscSignerOptions {
            batch_size: 3,
            ..Default::default()
        },
    )
}

#[test]
fn completed_batch_commit_cannot_authorize_or_modify_a_new_current_batch() {
    const A: u64 = 1;
    const B: u64 = 2;
    for old_succeeded in [true, false] {
        let signer = signer();
        let new_hash = base64_digest(b"new current batch", DigestAlgorithm::Sha256);
        {
            let mut state = signer.lock();
            state.current = Some(B);
            state.next_id = 3;
            state.batches.insert(
                A,
                Batch {
                    md: DigestAlgorithm::Sha256,
                    hashes: [b"old one".as_slice(), b"old two", b"old three"]
                        .into_iter()
                        .map(|data| base64_digest(data, DigestAlgorithm::Sha256))
                        .collect(),
                    initiated: true,
                    done: true,
                    results: old_succeeded.then(|| vec![vec![1], vec![2], vec![3]]),
                    error: (!old_succeeded).then(|| "old batch failed".to_owned()),
                    // The delayed auto-committing signer still needs A's result.
                    waiters: 1,
                },
            );
            state.batches.insert(
                B,
                Batch {
                    md: DigestAlgorithm::Sha256,
                    hashes: vec![new_hash.clone()],
                    initiated: false,
                    done: false,
                    results: None,
                    error: None,
                    waiters: 1,
                },
            );
        }
        let outcome = signer.commit_batch(Some(A));
        if old_succeeded {
            outcome.expect("a completed old successful batch remains successful");
        } else {
            assert!(
                matches!(outcome, Err(HankoError::Signing(ref error)) if error.contains("Commit failed")),
                "the old failure must remain associated with A: {outcome:?}"
            );
        }
        let state = signer.lock();
        assert_eq!(state.current, Some(B));
        assert_eq!(state.next_id, 3);
        let current = state.batches.get(&B).expect("new batch retained");
        assert_eq!(current.hashes, vec![new_hash]);
        assert_eq!(current.md, DigestAlgorithm::Sha256);
        assert!(!current.initiated && !current.done);
        assert!(current.results.is_none() && current.error.is_none());
        assert_eq!(current.waiters, 1);
        let completed = state.batches.get(&A).expect("old waiter retains A");
        assert_eq!(completed.waiters, 1);
        assert_eq!(completed.results.is_some(), old_succeeded);
        assert!(completed.initiated && completed.done);
    }
}
