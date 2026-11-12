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
