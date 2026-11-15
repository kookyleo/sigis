//! Injectable clock and certificate retrieval services for command execution.
use sigis_pki_core::{fetch::Fetchers, time::Moment};
use std::sync::Arc;

/// A dedicated USER-PIN request did not produce a credential.
///
/// These errors carry no caller-controlled diagnostic text or PIN value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pkcs11UserPinPromptError {
    /// The caller cannot supply a token USER PIN.
    Unavailable,
    /// The caller cancelled this token USER-PIN request.
    Cancelled,
}

type UserPinCallback =
    dyn Fn(&'static str) -> Result<String, Pkcs11UserPinPromptError> + Send + Sync + 'static;

/// Explicit programmatic authority to answer the token USER-PIN prompt.
///
/// This capability cannot answer a document-password, software-key passphrase
/// or context-specific signing-PIN prompt. It installs no terminal or stdin
/// fallback. Clones share the callback, never a cached returned PIN. Caller
/// callback logging, panics, blocking and capture zeroization are not controlled
/// by this wrapper.
#[derive(Clone)]
pub struct Pkcs11UserPinPrompt {
    callback: Arc<UserPinCallback>,
}

impl std::fmt::Debug for Pkcs11UserPinPrompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pkcs11UserPinPrompt(<redacted>)")
    }
}

impl Pkcs11UserPinPrompt {
    /// Supply a callback dedicated to the USER-PIN request for this runtime.
    ///
    /// The callback receives only `PKCS#11 user PIN: `. Its response is not
    /// trimmed or logged by the adapter. An empty response retains the existing
    /// PKCS11 CLI fallback semantics; it is distinct from cancellation.
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(&'static str) -> Result<String, Pkcs11UserPinPromptError> + Send + Sync + 'static,
    {
        Self {
            callback: Arc::new(callback),
        }
    }

    pub(crate) fn request_user_pin(&self) -> Result<String, Pkcs11UserPinPromptError> {
        (self.callback)("PKCS#11 user PIN: ")
    }
}

/// A context-specific signing-PIN request did not produce a credential.
///
/// Errors contain neither caller-controlled messages nor credential values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pkcs11SigningPinPromptError {
    /// The caller cannot supply a signing PIN for this operation.
    Unavailable,
    /// The caller cancelled this signing-PIN request.
    Cancelled,
}

type SigningPinCallback =
    dyn Fn(&'static str) -> Result<String, Pkcs11SigningPinPromptError> + Send + Sync + 'static;

/// Explicit authority to answer context-specific token signing-PIN requests.
///
/// This capability cannot authorize USER login or document decryption. It
/// installs no terminal fallback and caches no returned PIN. Clones retain the
/// callback identity. Callers control callback concurrency, blocking, logging
/// and captured data, as with the separate USER-PIN capability.
#[derive(Clone)]
pub struct Pkcs11SigningPinPrompt {
    callback: Arc<SigningPinCallback>,
}

impl std::fmt::Debug for Pkcs11SigningPinPrompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pkcs11SigningPinPrompt(<redacted>)")
    }
}

impl Pkcs11SigningPinPrompt {
    /// Supply the callback for the fixed `PKCS#11 signing PIN: ` request.
    ///
    /// The response is not trimmed or cached, and is never used for USER login.
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(&'static str) -> Result<String, Pkcs11SigningPinPromptError> + Send + Sync + 'static,
    {
        Self {
            callback: Arc::new(callback),
        }
    }

    pub(crate) fn request_signing_pin(&self) -> Result<String, Pkcs11SigningPinPromptError> {
        (self.callback)("PKCS#11 signing PIN: ")
    }
}

/// Runtime services corresponding to the upstream CLI context.
#[derive(Clone, Debug)]
pub struct ValidationRuntime {
    /// The current time. Claimed signature times do not override this implicitly.
    pub now: Moment,
    /// Issuer, revocation and OCSP retrieval services.
    pub fetchers: Fetchers,
    /// Password supplied by an injected CLI password prompter.
    pub password: Option<String>,
    /// Optional, explicitly supplied token USER-PIN prompt capability.
    ///
    /// `None` preserves the existing unsupported-prompt refusal; `password` is
    /// never substituted for it. External exhaustive runtime literals must
    /// include this field or use `..Default::default()`.
    pub pkcs11_user_pin_prompt: Option<Pkcs11UserPinPrompt>,
    /// Optional, separate context-specific signing-PIN authority.
    ///
    /// `None` keeps prompt requests unsupported. Neither `password` nor the
    /// USER-PIN callback substitutes for this capability. External exhaustive
    /// literals must add this field or use `..Default::default()`.
    pub pkcs11_signing_pin_prompt: Option<Pkcs11SigningPinPrompt>,
    /// Optional trusted-list HTTP provider; None uses the bounded production transport.
    pub trusted_list_transport: Option<std::sync::Arc<dyn sigis_pki_fetch::HttpTransport>>,
}
impl Default for ValidationRuntime {
    fn default() -> Self {
        Self {
            password: None,
            pkcs11_user_pin_prompt: None,
            pkcs11_signing_pin_prompt: None,
            trusted_list_transport: None,
            now: Moment::now(),
            fetchers: sigis_pki_fetch::HttpFetchers::default().as_fetchers(),
        }
    }
}

#[cfg(test)]
mod user_pin_tests {
    use super::{Pkcs11UserPinPrompt, Pkcs11UserPinPromptError, ValidationRuntime};
    use sigis_pki_core::time::Moment;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn user_pin_capability_is_explicit_and_debug_is_redacted() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let secret = "CAPTURED_TOKEN_SECRET_MUST_NOT_BE_DEBUGGED";
        let prompt = Pkcs11UserPinPrompt::new(move |label| {
            assert_eq!(label, "PKCS#11 user PIN: ");
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(secret.to_owned())
        });
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!format!("{prompt:?}").contains(secret));
        let runtime = ValidationRuntime {
            pkcs11_user_pin_prompt: Some(prompt),
            ..Default::default()
        };
        assert!(!format!("{runtime:?}").contains(secret));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let answer = runtime
            .pkcs11_user_pin_prompt
            .as_ref()
            .unwrap()
            .request_user_pin()
            .unwrap();
        assert!(answer == secret, "The dedicated callback response changed");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(ValidationRuntime::default()
            .pkcs11_user_pin_prompt
            .is_none());
    }

    #[derive(Debug)]
    struct NoTransportIo;
    impl sigis_pki_fetch::HttpTransport for NoTransportIo {
        fn send(
            &self,
            _: &sigis_pki_fetch::transport::HttpRequest<'_>,
        ) -> Result<sigis_pki_fetch::HttpResponse, sigis_pki_fetch::TransportError> {
            panic!("Cloning runtime services must not perform transport I/O")
        }
    }

    #[test]
    fn runtime_clone_preserves_callback_identity_and_all_existing_services() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let runtime = ValidationRuntime {
            pkcs11_user_pin_prompt: Some(Pkcs11UserPinPrompt::new(move |_| {
                let next = observed.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(format!("response-{next}"))
            })),
            now: Moment::from_unix_secs(1_604_188_800),
            fetchers: sigis_pki_fetch::HttpFetchers::default().as_fetchers(),
            password: Some("document-role-only".into()),
            pkcs11_signing_pin_prompt: Some(super::Pkcs11SigningPinPrompt::new(|_| {
                Ok("separate-signing-response".into())
            })),
            trusted_list_transport: Some(Arc::new(NoTransportIo)),
        };
        let clone = runtime.clone();
        assert_eq!(clone.now, runtime.now);
        assert_eq!(clone.password, runtime.password);
        assert!(Arc::ptr_eq(
            clone.fetchers.cert.as_ref().unwrap(),
            runtime.fetchers.cert.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            clone.fetchers.ocsp.as_ref().unwrap(),
            runtime.fetchers.ocsp.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            clone.fetchers.crl.as_ref().unwrap(),
            runtime.fetchers.crl.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            clone.trusted_list_transport.as_ref().unwrap(),
            runtime.trusted_list_transport.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            &runtime.pkcs11_signing_pin_prompt.as_ref().unwrap().callback,
            &clone.pkcs11_signing_pin_prompt.as_ref().unwrap().callback,
        ));
        let first = runtime.pkcs11_user_pin_prompt.as_ref().unwrap();
        let second = clone.pkcs11_user_pin_prompt.as_ref().unwrap();
        assert!(Arc::ptr_eq(&first.callback, &second.callback));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(first.request_user_pin().unwrap(), "response-1");
        assert_eq!(second.request_user_pin().unwrap(), "response-2");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn closure_capture_drops_only_after_the_last_capability_clone() {
        struct Capture(Arc<AtomicUsize>);
        impl Drop for Capture {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let capture = Capture(drops.clone());
        let runtime = ValidationRuntime {
            pkcs11_user_pin_prompt: Some(Pkcs11UserPinPrompt::new(move |_| {
                let _keep_capture_alive = &capture;
                Ok("fixture-response".into())
            })),
            ..Default::default()
        };
        let clone = runtime.clone();
        let last = clone.pkcs11_user_pin_prompt.clone();
        drop(runtime);
        drop(clone);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(last);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn distinct_capabilities_keep_counters_and_responses_separate() {
        let a = Arc::new(AtomicUsize::new(0));
        let b = Arc::new(AtomicUsize::new(0));
        let make = |counter: Arc<AtomicUsize>, response: &'static str| {
            Pkcs11UserPinPrompt::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(response.into())
            })
        };
        let first = make(a.clone(), "first-role");
        let second = make(b.clone(), "second-role");
        assert_eq!(first.request_user_pin().unwrap(), "first-role");
        assert_eq!(first.clone().request_user_pin().unwrap(), "first-role");
        assert_eq!(second.request_user_pin().unwrap(), "second-role");
        assert_eq!(a.load(Ordering::SeqCst), 2);
        assert_eq!(b.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn typed_errors_have_no_arbitrary_credential_payload() {
        for error in [
            Pkcs11UserPinPromptError::Unavailable,
            Pkcs11UserPinPromptError::Cancelled,
        ] {
            let prompt = Pkcs11UserPinPrompt::new(move |_| Err(error));
            assert_eq!(prompt.request_user_pin(), Err(error));
            assert!(matches!(
                format!("{error:?}").as_str(),
                "Unavailable" | "Cancelled"
            ));
        }
    }

    #[test]
    fn runtime_and_prompt_keep_send_and_sync_contracts() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Pkcs11UserPinPrompt>();
        assert_send_sync::<ValidationRuntime>();
    }
}

#[cfg(test)]
mod signing_pin_tests {
    use super::{Pkcs11SigningPinPrompt, Pkcs11SigningPinPromptError, ValidationRuntime};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn signing_capability_is_separate_redacted_and_does_not_cache_responses() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let prompt = Pkcs11SigningPinPrompt::new(move |label| {
            assert_eq!(label, "PKCS#11 signing PIN: ");
            let index = observed.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(format!("  signing-secret-{index}  "))
        });
        let runtime = ValidationRuntime {
            pkcs11_signing_pin_prompt: Some(prompt.clone()),
            ..Default::default()
        };
        let cloned = runtime.clone();
        assert!(runtime.pkcs11_user_pin_prompt.is_none());
        assert!(!format!("{runtime:?}").contains("signing-secret"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let clone = cloned.pkcs11_signing_pin_prompt.as_ref().unwrap();
        assert!(Arc::ptr_eq(&prompt.callback, &clone.callback));
        assert_eq!(
            prompt.request_signing_pin().unwrap(),
            "  signing-secret-1  "
        );
        assert_eq!(clone.request_signing_pin().unwrap(), "  signing-secret-2  ");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(ValidationRuntime::default()
            .pkcs11_signing_pin_prompt
            .is_none());
    }

    #[test]
    fn signing_capability_preserves_typed_refusals_without_freeform_diagnostics() {
        for refusal in [
            Pkcs11SigningPinPromptError::Unavailable,
            Pkcs11SigningPinPromptError::Cancelled,
        ] {
            let prompt = Pkcs11SigningPinPrompt::new(move |_| Err(refusal));
            assert_eq!(prompt.request_signing_pin(), Err(refusal));
        }
    }
}
