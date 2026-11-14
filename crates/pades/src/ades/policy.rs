// Derived from pyHanko 0.38.1 sign/validation/policy_decl.py (MIT).

//! Online material gathering policy for AdES validation.

use std::sync::Arc;

use super::{
    basic::{basic_validation_with_options, BasicValidationResult, QualificationSpec},
    AdesValidationOptions,
};
use sigis_pki_certvalidator::{context::ValidationContextBuilder, ValidationContext};
use sigis_pki_core::{
    errors::{FetchError, HankoError, ValidationError},
    fetch::{FetcherBackend, Fetchers},
};
use sigis_pki_fetch::HttpFetchers;

/// When online revocation information may be retrieved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RevinfoOnlineFetchingRule {
    /// Permit online retrieval during current and historical validation.
    AlwaysFetch,
    /// Permit online retrieval only during current validation.
    #[default]
    NoHistoricalFetch,
    /// Use only material supplied locally.
    LocalOnly,
}

/// Whether issuer certificates may be retrieved from AIA URLs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CertificateFetchingRule {
    /// Permit certificate retrieval when online revocation retrieval is allowed.
    #[default]
    FollowOnlineRule,
    /// Disable certificate retrieval while retaining permitted revocation retrieval.
    NeverFetch,
}

/// Policy and optional caller-owned backend for gathering validation material.
#[derive(Clone, Debug, Default)]
pub struct RevocationInfoGatheringSpec {
    /// Rule for online OCSP and CRL retrieval.
    pub online_fetching_rule: RevinfoOnlineFetchingRule,
    /// Rule for certificate retrieval.
    pub certificate_fetching_rule: CertificateFetchingRule,
    /// Backend whose caches and request budget may be shared across operations.
    /// If absent, a backend is created for each online validation operation.
    pub fetcher_backend: Option<HttpFetchers>,
}

/// Explicit provider selection for a direct validation operation.
///
/// This does not change the gathering-policy helper's shared cache/budget
/// semantics or provision a backend in an existing validation context.
#[derive(Clone, Debug, Default)]
pub enum HandlerFetchSelection {
    /// Disable online retrieval, including any context's previous fetchers.
    Disabled,
    /// Provision a real HTTP backend and issue one fresh fetcher set.
    #[default]
    DefaultHttp,
    /// Issue one set from a backend whose caller retains close authority.
    Borrowed(Arc<dyn FetcherBackend>),
    /// Use these exact components, including an explicitly empty set.
    Supplied(Fetchers),
}

/// Fetchers prepared for one validation operation.
#[derive(Clone, Debug)]
pub struct ValidationDataHandlers {
    /// Fetchers to install on the validation context.
    pub fetchers: Fetchers,
    /// Backend provisioned for this operation, if the caller did not supply one.
    /// Dropping the handlers and their fetchers releases its HTTP resources.
    pub owned_fetcher_backend: Option<HttpFetchers>,
}

impl ValidationDataHandlers {
    /// Select the actual fetchers for one direct validation operation.
    ///
    /// Factories are called exactly once for default and borrowed backends.
    /// Supplied and disabled selections never fall back to another backend.
    pub fn from_fetch_selection(selection: HandlerFetchSelection) -> Self {
        match selection {
            HandlerFetchSelection::Disabled => Self {
                fetchers: Fetchers::none(),
                owned_fetcher_backend: None,
            },
            HandlerFetchSelection::DefaultHttp => {
                let backend = HttpFetchers::default();
                let fetchers = backend.get_fetchers();
                Self {
                    fetchers,
                    owned_fetcher_backend: Some(backend),
                }
            }
            HandlerFetchSelection::Borrowed(backend) => Self {
                fetchers: backend.get_fetchers(),
                owned_fetcher_backend: None,
            },
            HandlerFetchSelection::Supplied(fetchers) => Self {
                fetchers,
                owned_fetcher_backend: None,
            },
        }
    }

    /// Close only this handler's retained owned HTTP backend.
    ///
    /// Every explicit call delegates without clearing ownership or resetting
    /// issued caches/budgets. Borrowed and supplied providers remain external.
    pub fn close(&self) -> Result<(), FetchError> {
        match &self.owned_fetcher_backend {
            Some(backend) => backend.close(),
            None => Ok(()),
        }
    }

    /// Whether this operation may retrieve revocation information online.
    pub fn fetching_allowed(&self) -> bool {
        self.fetchers.ocsp.is_some() || self.fetchers.crl.is_some()
    }
}

/// Construct a fetching-enabled context for actual validation operations.
///
/// A real default HTTP backend is created and adopted only if neither fetchers
/// nor a backend was explicitly selected. The complete builder is validated
/// before that factory runs. Ordinary context construction stays offline.
/// The caller retains the returned context through validation and explicit
/// repeated close; this constructor performs no certificate/signature validation or automatic close.
pub fn bootstrap_validation_context(
    builder: ValidationContextBuilder,
) -> Result<ValidationContext, ValidationError> {
    builder.build_with_backend_fallback(|| Arc::new(HttpFetchers::default()))
}

/// Build a context with a handler's exact issued components and close capability.
///
/// Handlers remain borrowed and retain their own explicit close authority. A
/// concrete HTTP owner clone shares the same pool; its new outer Arc is not a
/// generic backend identity supplied by the caller. No issued set is recreated.
/// Existing explicit builder retrieval/backend choices conflict rather than
/// being overwritten. With no handlers, ordinary build preserves those choices
/// and adds no default backend. The caller retains the resulting context through
/// validation, errors and repeated explicit close; construction performs no cleanup.
pub fn build_validation_context_with_handlers(
    builder: ValidationContextBuilder,
    handlers: Option<&ValidationDataHandlers>,
) -> Result<ValidationContext, ValidationError> {
    match handlers {
        Some(handlers) => builder.build_with_fetcher_handoff(
            handlers.fetchers.clone(),
            handlers
                .owned_fetcher_backend
                .as_ref()
                .map(|backend| Arc::new(backend.clone()) as Arc<dyn FetcherBackend>),
        ),
        None => builder.build(),
    }
}

/// Run basic AdES validation with this handler's exact fetcher components.
///
/// The complete caller context is cloned; local evidence, trust, policies and
/// close authority are preserved. This does not adopt or close any backend.
pub fn basic_validation_with_handlers(
    content_info: &[u8],
    raw_digest: Option<&[u8]>,
    ctx: &ValidationContext,
    qualification: &QualificationSpec<'_>,
    handlers: &ValidationDataHandlers,
) -> Result<BasicValidationResult, HankoError> {
    basic_validation_with_handlers_and_options(
        content_info,
        raw_digest,
        ctx,
        qualification,
        handlers,
        &AdesValidationOptions::default(),
    )
}

/// Run basic AdES validation with selected fetchers and exact main options.
///
/// Only retrieval components change. All caller requirements, signer-first
/// order and fixed timestamp purpose remain those of the existing validator.
pub fn basic_validation_with_handlers_and_options(
    content_info: &[u8],
    raw_digest: Option<&[u8]>,
    ctx: &ValidationContext,
    qualification: &QualificationSpec<'_>,
    handlers: &ValidationDataHandlers,
    options: &AdesValidationOptions,
) -> Result<BasicValidationResult, HankoError> {
    let context = ctx.with_fetchers(handlers.fetchers.clone());
    basic_validation_with_options(content_info, raw_digest, &context, qualification, options)
}

/// Prepare validation fetchers, applying the historical and certificate rules.
///
/// The historical flag describes the validation operation rather than the
/// existence of an archival timestamp. Callers pass `true` for past-validation
/// evaluations and `false` for the present-time validation phase.
pub fn bootstrap_validation_data_handlers(
    spec: &RevocationInfoGatheringSpec,
    is_historical: bool,
) -> ValidationDataHandlers {
    let permit_online = match spec.online_fetching_rule {
        RevinfoOnlineFetchingRule::AlwaysFetch => true,
        RevinfoOnlineFetchingRule::NoHistoricalFetch => !is_historical,
        RevinfoOnlineFetchingRule::LocalOnly => false,
    };
    if !permit_online {
        return ValidationDataHandlers {
            fetchers: Fetchers::none(),
            owned_fetcher_backend: None,
        };
    }

    let owned_fetcher_backend = spec.fetcher_backend.is_none().then(HttpFetchers::default);
    let backend = spec
        .fetcher_backend
        .as_ref()
        .or(owned_fetcher_backend.as_ref());
    let mut fetchers = backend.map(HttpFetchers::as_fetchers).unwrap_or_default();
    if spec.certificate_fetching_rule == CertificateFetchingRule::NeverFetch {
        fetchers.cert = None;
    }
    ValidationDataHandlers {
        fetchers,
        owned_fetcher_backend,
    }
}

#[cfg(test)]
mod direct_selection_tests {
    use super::*;
    use sigis_pki_core::errors::{FetchError, FetchErrorKind};
    use sigis_pki_core::fetch::FetcherBackend;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Debug)]
    struct RecordingBackend {
        issued: Fetchers,
        factories: AtomicUsize,
        closes: AtomicUsize,
    }

    impl RecordingBackend {
        fn new() -> Self {
            Self {
                issued: HttpFetchers::default().get_fetchers(),
                factories: AtomicUsize::new(0),
                closes: AtomicUsize::new(0),
            }
        }
    }

    impl FetcherBackend for RecordingBackend {
        fn get_fetchers(&self) -> Fetchers {
            self.factories.fetch_add(1, Ordering::SeqCst);
            self.issued.clone()
        }

        fn close(&self) -> Result<(), FetchError> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Err(FetchError::new(
                FetchErrorKind::Timeout,
                "caller-owned backend must not be closed by handlers",
            ))
        }
    }

    fn assert_same_components(actual: &Fetchers, expected: &Fetchers) {
        assert!(Arc::ptr_eq(
            actual.cert.as_ref().unwrap(),
            expected.cert.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            actual.crl.as_ref().unwrap(),
            expected.crl.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            actual.ocsp.as_ref().unwrap(),
            expected.ocsp.as_ref().unwrap()
        ));
    }

    #[test]
    fn default_and_explicit_default_keep_a_real_owned_http_backend() {
        for selection in [
            HandlerFetchSelection::default(),
            HandlerFetchSelection::DefaultHttp,
        ] {
            let handlers = ValidationDataHandlers::from_fetch_selection(selection);
            let owner: &HttpFetchers = handlers.owned_fetcher_backend.as_ref().unwrap();
            assert!(handlers.fetchers.cert.is_some());
            assert!(handlers.fetchers.crl.is_some());
            assert!(handlers.fetchers.ocsp.is_some());
            let old_view = owner.as_fetchers();
            assert!(!Arc::ptr_eq(
                old_view.crl.as_ref().unwrap(),
                handlers.fetchers.crl.as_ref().unwrap()
            ));
            let before = owner.settings().clone();
            handlers.close().unwrap();
            handlers.close().unwrap();
            assert_eq!(
                handlers.owned_fetcher_backend.as_ref().unwrap().settings(),
                &before
            );
            assert!(handlers.fetching_allowed());
        }
    }

    #[test]
    fn borrowed_backend_factory_runs_once_and_close_authority_stays_with_caller() {
        let backend = Arc::new(RecordingBackend::new());
        let handlers = ValidationDataHandlers::from_fetch_selection(
            HandlerFetchSelection::Borrowed(backend.clone()),
        );
        assert!(handlers.owned_fetcher_backend.is_none());
        assert_same_components(&handlers.fetchers, &backend.issued);
        handlers.close().unwrap();
        handlers.clone().close().unwrap();
        assert_eq!(backend.factories.load(Ordering::SeqCst), 1);
        assert_eq!(backend.closes.load(Ordering::SeqCst), 0);
        // This error is a REAL caller operation, never an invented owned-HTTP
        // close failure. Handlers did not consume it or call this method.
        assert_eq!(backend.close().unwrap_err().kind, FetchErrorKind::Timeout);
        assert_eq!(backend.closes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn supplied_exact_components_and_disabled_empty_never_provision_a_backend() {
        let backend = RecordingBackend::new();
        let set = backend.get_fetchers();
        let handlers = ValidationDataHandlers::from_fetch_selection(
            HandlerFetchSelection::Supplied(set.clone()),
        );
        assert_same_components(&handlers.fetchers, &set);
        assert!(handlers.owned_fetcher_backend.is_none());
        handlers.close().unwrap();
        assert_eq!(backend.factories.load(Ordering::SeqCst), 1);
        assert_eq!(backend.closes.load(Ordering::SeqCst), 0);
        for selection in [
            HandlerFetchSelection::Disabled,
            HandlerFetchSelection::Supplied(Fetchers::none()),
        ] {
            let empty = ValidationDataHandlers::from_fetch_selection(selection);
            assert!(empty.fetchers.is_empty());
            assert!(empty.owned_fetcher_backend.is_none());
            assert!(!empty.fetching_allowed());
            empty.close().unwrap();
            empty.close().unwrap();
        }
    }
}
