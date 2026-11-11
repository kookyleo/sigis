// Derived from pyhanko-certvalidator `fetchers/common_utils.py` (`FetchBudget`,
// `cap_aia_urls`) and `fetchers/api.py` (`FetchLimits`) (MIT, see LICENSE-pyHanko).

//! Bounds on fetching: a single hostile certificate must not trigger an
//! arbitrary amount of network activity.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Limits applied by the fetchers (`FetchLimits` plus transport limits).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchLimits {
    /// Per-request timeout.
    pub timeout: Duration,
    /// Maximum response size in bytes.
    pub max_response_bytes: usize,
    /// Maximum number of network requests of any type (`None`: unlimited).
    pub max_requests: Option<usize>,
    /// Maximum number of issuer certificate requests (also counted in
    /// `max_requests`).
    pub max_cert_requests: Option<usize>,
    /// Maximum number of `caIssuers` URLs followed per certificate or CRL.
    pub max_aia_urls_per_object: Option<usize>,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_response_bytes: 10 * 1024 * 1024,
            max_requests: Some(1000),
            max_cert_requests: Some(200),
            max_aia_urls_per_object: Some(10),
        }
    }
}

impl FetchLimits {
    /// No request-count limits (`FetchLimits(None, None, None)`), default
    /// transport limits.
    pub fn unlimited() -> Self {
        Self {
            max_requests: None,
            max_cert_requests: None,
            max_aia_urls_per_object: None,
            ..Self::default()
        }
    }
}

/// The kind of a fetch (`FetchKind`), which selects the error raised when
/// the budget is exhausted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FetchKind {
    /// Issuer certificates.
    Cert,
    /// CRLs.
    Crl,
    /// OCSP responses.
    Ocsp,
}

/// Why a request was refused (the message of the fetch error).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetExhausted {
    /// The kind of request refused.
    pub kind: FetchKind,
    /// `Fetch limit of ... reached.`
    pub message: String,
}

/// Request counters enforcing a [`FetchLimits`] (`FetchBudget`). Shared by
/// the fetchers of one [`crate::HttpFetchers`].
#[derive(Debug)]
pub struct FetchBudget {
    limits: FetchLimits,
    counts: Mutex<(usize, usize)>,
    exhausted_logged: AtomicBool,
}

impl FetchBudget {
    /// A fresh budget.
    pub fn new(limits: FetchLimits) -> Self {
        Self {
            limits,
            counts: Mutex::new((0, 0)),
            exhausted_logged: AtomicBool::new(false),
        }
    }

    /// The limits.
    pub fn limits(&self) -> &FetchLimits {
        &self.limits
    }

    /// `true` once a request has been refused (pyHanko logs a warning the
    /// first time, then at debug level).
    pub fn exhaustion_reported(&self) -> bool {
        self.exhausted_logged.load(Ordering::Relaxed)
    }

    /// Account for one request about to be made (`charge`).
    pub fn charge(&self, kind: FetchKind) -> Result<(), BudgetExhausted> {
        let mut guard = match self.counts.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let (requests, cert_requests) = &mut *guard;
        if let Some(max) = self.limits.max_requests {
            if *requests >= max {
                return Err(self.refuse(kind, format!("{max} requests")));
            }
        }
        if kind == FetchKind::Cert {
            if let Some(max) = self.limits.max_cert_requests {
                if *cert_requests >= max {
                    return Err(self.refuse(kind, format!("{max} certificate requests")));
                }
            }
            *cert_requests += 1;
        }
        *requests += 1;
        Ok(())
    }

    fn refuse(&self, kind: FetchKind, what: String) -> BudgetExhausted {
        self.exhausted_logged.store(true, Ordering::Relaxed);
        BudgetExhausted {
            kind,
            message: format!("Fetch limit of {what} reached."),
        }
    }
}

/// `cap_aia_urls`: keep at most `max_aia_urls_per_object` URLs.
pub fn cap_aia_urls(budget: Option<&FetchBudget>, urls: Vec<String>) -> Vec<String> {
    match budget.and_then(|b| b.limits.max_aia_urls_per_object) {
        Some(limit) if urls.len() > limit => urls.into_iter().take(limit).collect(),
        _ => urls,
    }
}
