// Derived from pyHanko 0.38.1 sign/validation/policy_decl.py (MIT).

//! Online material gathering policy for AdES validation.

use sigis_pki_core::fetch::Fetchers;
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
    /// Whether this operation may retrieve revocation information online.
    pub fn fetching_allowed(&self) -> bool {
        self.fetchers.ocsp.is_some() || self.fetchers.crl.is_some()
    }
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
