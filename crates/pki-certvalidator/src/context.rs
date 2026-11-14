// Partly derived from pyhanko-certvalidator `context.py` (MIT, see LICENSE-pyHanko).

//! Validation context: trust anchors, other certificates, revocation
//! information, the time of interest and policies.

use core::time::Duration;
use std::sync::Arc;

use super::authority::{Cert, TrustAnchor, TrustManager};
use super::policy::{
    CertRevTrustPolicy, NonRevokedStatusAssertion, RevocationCheckingPolicy, ValidationTimingParams,
};
use super::revinfo::freshness::{DefaultFreshnessJudge, FreshnessJudge};
use super::revinfo::{CrlContainer, OcspContainer};
use sigis_pki_core::algorithms::{AlgorithmUsagePolicy, DisallowWeakAlgorithmsPolicy};
use sigis_pki_core::errors::{FetchError, ValidationError};
use sigis_pki_core::fetch::{FetcherBackend, Fetchers};
use sigis_pki_core::time::Moment;

/// Default allowed clock drift.
pub const DEFAULT_TIME_TOLERANCE: Duration = Duration::from_secs(1);

/// Everything a validation needs besides the certificate itself.
///
/// All material is supplied up front; this phase performs no network access.
#[derive(Clone, Debug)]
pub struct ValidationContext {
    pub(crate) trust_anchors: Vec<TrustAnchor>,
    pub(crate) other_certs: Vec<Cert>,
    pub(crate) crls: Vec<CrlContainer>,
    pub(crate) ocsps: Vec<OcspContainer>,
    pub(crate) timing: ValidationTimingParams,
    pub(crate) revinfo_policy: CertRevTrustPolicy,
    pub(crate) algorithm_policy: Arc<dyn AlgorithmUsagePolicy>,
    pub(crate) freshness_judge: Arc<dyn FreshnessJudge>,
    pub(crate) assertions: Vec<NonRevokedStatusAssertion>,
    pub(crate) fetchers: Fetchers,
    owned_fetcher_backend: Option<Arc<dyn FetcherBackend>>,
    pub(crate) acceptable_ac_targets: Option<crate::ac::AcTargetDescription>,
    pub(crate) trust_manager: Option<Arc<dyn TrustManager>>,
}

impl ValidationContext {
    /// Start building a context.
    pub fn builder() -> ValidationContextBuilder {
        ValidationContextBuilder::default()
    }

    /// Trust anchors.
    pub fn trust_anchors(&self) -> &[TrustAnchor] {
        &self.trust_anchors
    }

    /// Additional certificates available for path building.
    pub fn other_certs(&self) -> &[Cert] {
        &self.other_certs
    }

    /// Timing parameters.
    pub fn timing(&self) -> &ValidationTimingParams {
        &self.timing
    }

    /// Clone this context, replacing only its timing parameters.
    ///
    /// Caller-supplied policies, freshness checks, assertions and attribute
    /// certificate target restrictions are preserved for historical validation.
    pub fn with_timing(&self, timing: ValidationTimingParams) -> Self {
        let mut context = self.clone();
        context.timing = timing;
        context
    }

    /// Revocation information trust policy.
    pub fn revinfo_policy(&self) -> &CertRevTrustPolicy {
        &self.revinfo_policy
    }

    /// Explicit caller-supplied non-revocation assertions, in builder order.
    ///
    /// This is a borrowed view of configured state, not a status inferred from
    /// successful validation or a tolerated missing response. Matching still
    /// requires the exact target DER SHA-256 and an assertion time at least the
    /// validation time. Trust and signature checks remain separate.
    ///
    /// The returned slice cannot be mutated:
    ///
    /// ```compile_fail
    /// use sigis_pki_certvalidator::{NonRevokedStatusAssertion, ValidationContext};
    /// let context = ValidationContext::builder().build().unwrap();
    /// let _: &mut [NonRevokedStatusAssertion] = context.non_revoked_status_assertions();
    /// ```
    ///
    /// The borrow cannot outlive its context:
    ///
    /// ```compile_fail
    /// use sigis_pki_certvalidator::ValidationContext;
    /// let assertions = {
    ///     let context = ValidationContext::builder().build().unwrap();
    ///     context.non_revoked_status_assertions()
    /// };
    /// assert!(assertions.is_empty());
    /// ```
    pub fn non_revoked_status_assertions(&self) -> &[NonRevokedStatusAssertion] {
        &self.assertions
    }

    /// Configured fetchers (none by default).
    pub fn fetchers(&self) -> &Fetchers {
        &self.fetchers
    }

    /// Close only the backend explicitly adopted by this context.
    ///
    /// Borrowed backends and supplied fetchers are left alone. Every explicit
    /// call delegates to the same adopted backend and propagates its error;
    /// the owner is retained, and issued caches/budgets are not reset. Clones
    /// retain this authority. Dropping a context does not call this method.
    pub fn close(&self) -> Result<(), FetchError> {
        match &self.owned_fetcher_backend {
            Some(backend) => backend.close(),
            None => Ok(()),
        }
    }

    /// Clone this context, replacing only its fetchers.
    ///
    /// All caller-supplied validation requirements remain in effect.
    pub fn with_fetchers(&self, fetchers: Fetchers) -> Self {
        let mut context = self.clone();
        context.fetchers = fetchers;
        context
    }

    /// Algorithm usage policy.
    pub fn algorithm_policy(&self) -> &dyn AlgorithmUsagePolicy {
        self.algorithm_policy.as_ref()
    }

    /// Algorithm usage policy, shared.
    pub fn algorithm_policy_arc(&self) -> Arc<dyn AlgorithmUsagePolicy> {
        self.algorithm_policy.clone()
    }

    /// The trust manager, if one was configured.
    pub fn trust_manager(&self) -> Option<&Arc<dyn TrustManager>> {
        self.trust_manager.as_ref()
    }

    /// `cert` as a trust anchor: a supplied anchor with this certificate, or
    /// the trust manager's answer.
    pub fn as_trust_anchor(&self, cert: &Cert) -> Option<TrustAnchor> {
        self.trust_anchors
            .iter()
            .find(|a| a.cert() == cert)
            .cloned()
            .or_else(|| self.trust_manager.as_ref()?.as_trust_anchor(cert))
    }

    /// Is `cert` a trust anchor ([`Self::as_trust_anchor`])?
    pub fn is_trust_anchor(&self, cert: &Cert) -> bool {
        self.as_trust_anchor(cert).is_some()
    }

    /// Trust anchors that may have issued `cert`: the supplied ones, then
    /// the trust manager's `find_potential_issuers` (duplicates removed).
    /// Callers still check names and key identifiers.
    pub fn potential_issuing_anchors(&self, cert: &Cert) -> Vec<TrustAnchor> {
        let mut out = self.trust_anchors.clone();
        if let Some(manager) = &self.trust_manager {
            for anchor in manager.find_potential_issuers(cert) {
                if !out.iter().any(|a| a.cert() == anchor.cert()) {
                    out.push(anchor);
                }
            }
        }
        out
    }

    /// The CRLs supplied to the context, DER-encoded (`crls`).
    pub fn crls(&self) -> impl Iterator<Item = &[u8]> {
        self.crls.iter().map(CrlContainer::der)
    }

    /// The OCSP responses supplied to the context, DER-encoded (`ocsps`).
    /// A response with several single responses appears once.
    pub fn ocsps(&self) -> impl Iterator<Item = &[u8]> {
        let mut seen: Vec<&[u8]> = Vec::new();
        self.ocsps.iter().filter_map(move |o| {
            let der = o.der();
            if seen.contains(&der) {
                None
            } else {
                seen.push(der);
                Some(der)
            }
        })
    }

    /// A copy of this context extended with validation material from a
    /// document, for example a PDF DSS: certificates for path building,
    /// CRLs and OCSP responses. Duplicates are ignored. Proofs of existence
    /// are kept separately in a
    /// [`PoeManager`](crate::ltv::poe::PoeManager).
    pub fn with_revinfo<'a>(
        &self,
        certs: impl IntoIterator<Item = &'a Cert>,
        crls: impl IntoIterator<Item = &'a [u8]>,
        ocsps: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, ValidationError> {
        let mut out = self.with_other_certs(certs);
        for der in crls {
            if !out.crls.iter().any(|c| c.der() == der) {
                out.crls.push(CrlContainer::from_der(der)?);
            }
        }
        for der in ocsps {
            if !out.ocsps.iter().any(|o| o.der() == der) {
                out.ocsps.extend(OcspContainer::load(der)?);
            }
        }
        Ok(out)
    }

    /// A copy of this context with additional certificates available for
    /// path building (`certificate_registry.register_multiple`). Duplicates
    /// are ignored.
    pub fn with_other_certs<'a>(&self, certs: impl IntoIterator<Item = &'a Cert>) -> Self {
        let mut out = self.clone();
        for c in certs {
            if !out.other_certs.contains(c) && !out.is_trust_anchor(c) {
                out.other_certs.push(c.clone());
            }
        }
        out
    }

    /// A copy with operation-local certificate registration, retaining the
    /// first certificate with each issuer/serial identity. This models
    /// `certificate_registry.register_multiple` without mutating the caller.
    ///
    /// Candidate certificates are registered before explicit root certificates,
    /// as when a validation context is constructed, followed by `certs` in order.
    /// All trust anchors and security requirements remain unchanged: registry
    /// collisions never delete or add trust anchors. This does not import state
    /// from another validation context or change general `with_other_certs`.
    pub fn with_registered_other_certs<'a>(
        &self,
        certs: impl IntoIterator<Item = &'a Cert>,
    ) -> Self {
        let mut registry =
            crate::registry::CertificateRegistry::build(self.other_certs.iter().cloned());
        for anchor in &self.trust_anchors {
            registry.register(anchor.cert().clone());
        }
        for cert in certs {
            registry.register(cert.clone());
        }
        let mut out = self.clone();
        out.other_certs = registry
            .certs()
            .iter()
            .filter(|cert| !self.is_trust_anchor(cert))
            .cloned()
            .collect();
        out
    }

    /// Every CRL the context knows for `cert`: the supplied ones, plus
    /// those the CRL fetcher returns (`async_retrieve_crls`). Fetch
    /// failures yield the supplied CRLs only.
    pub fn retrieve_crls(&self, cert: &Cert) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self.crls.iter().map(|c| c.der().to_vec()).collect();
        if let Some(fetcher) = &self.fetchers.crl {
            if let Ok(fetched) = fetcher.fetch_crls(cert) {
                for c in fetched {
                    if !out.contains(&c) {
                        out.push(c);
                    }
                }
            }
        }
        out
    }

    /// The time of interest (`moment`).
    pub fn moment(&self) -> Moment {
        self.timing.validation_time
    }

    /// The best known signature time (`best_signature_time`).
    pub fn best_signature_time(&self) -> Moment {
        self.timing.best_signature_time
    }

    /// Every certificate known to the context: anchors, then other certificates.
    pub(crate) fn known_certs(&self) -> impl Iterator<Item = &Cert> {
        self.trust_anchors
            .iter()
            .map(TrustAnchor::cert)
            .chain(self.other_certs.iter())
    }
}

/// Builder for [`ValidationContext`].
#[derive(Debug, Default)]
pub struct ValidationContextBuilder {
    trust_anchors: Vec<TrustAnchor>,
    other_certs: Vec<Cert>,
    crls: Vec<Vec<u8>>,
    ocsps: Vec<Vec<u8>>,
    moment: Option<Moment>,
    point_in_time_validation: Option<bool>,
    best_signature_time: Option<Moment>,
    time_tolerance: Option<Duration>,
    revinfo_policy: Option<CertRevTrustPolicy>,
    revocation_mode: Option<String>,
    algorithm_policy: Option<Arc<dyn AlgorithmUsagePolicy>>,
    freshness_judge: Option<Arc<dyn FreshnessJudge>>,
    assertions: Vec<NonRevokedStatusAssertion>,
    fetchers: Option<Fetchers>,
    fetcher_backend: Option<(Arc<dyn FetcherBackend>, bool)>,
    acceptable_ac_targets: Option<crate::ac::AcTargetDescription>,
    trust_manager: Option<Arc<dyn TrustManager>>,
}

impl ValidationContextBuilder {
    /// Consult `manager` for trust anchors in addition to the supplied ones
    /// (pyhanko-certvalidator `trust_manager`).
    pub fn trust_manager(mut self, manager: Arc<dyn TrustManager>) -> Self {
        self.trust_manager = Some(manager);
        self
    }

    /// Targets this validator accepts for targeted attribute certificates
    /// (`acceptable_ac_targets`).
    pub fn acceptable_ac_targets(mut self, targets: crate::ac::AcTargetDescription) -> Self {
        self.acceptable_ac_targets = Some(targets);
        self
    }

    /// Add a trust root (validity period not enforced).
    pub fn trust_root(mut self, cert: Cert) -> Self {
        self.trust_anchors.push(TrustAnchor::new(cert));
        self
    }

    /// Add a trust anchor.
    pub fn trust_anchor(mut self, anchor: TrustAnchor) -> Self {
        self.trust_anchors.push(anchor);
        self
    }

    /// Add a certificate available for path building.
    pub fn other_cert(mut self, cert: Cert) -> Self {
        self.other_certs.push(cert);
        self
    }

    /// Add a DER-encoded CRL.
    pub fn crl(mut self, der: impl Into<Vec<u8>>) -> Self {
        self.crls.push(der.into());
        self
    }

    /// Add a DER-encoded `OCSPResponse`.
    pub fn ocsp_response(mut self, der: impl Into<Vec<u8>>) -> Self {
        self.ocsps.push(der.into());
        self
    }

    /// Set the time of interest. Defaults to the current time.
    pub fn moment(mut self, moment: Moment) -> Self {
        self.moment = Some(moment);
        self
    }

    /// Override whether only revocations before the time of interest count
    /// (`point_in_time_validation`). Defaults to `true` iff a moment was set,
    /// as in pyhanko-certvalidator.
    pub fn point_in_time_validation(mut self, value: bool) -> Self {
        self.point_in_time_validation = Some(value);
        self
    }

    /// Set the best known signature time. Defaults to the time of interest.
    pub fn best_signature_time(mut self, moment: Moment) -> Self {
        self.best_signature_time = Some(moment);
        self
    }

    /// Set the allowed clock drift. Defaults to [`DEFAULT_TIME_TOLERANCE`].
    pub fn time_tolerance(mut self, tolerance: Duration) -> Self {
        self.time_tolerance = Some(tolerance);
        self
    }

    /// Use a legacy revocation mode: `none`, `soft-fail` (default),
    /// `hard-fail` or `require`. Ignored if [`Self::revinfo_policy`] is set.
    pub fn revocation_mode(mut self, mode: &str) -> Self {
        self.revocation_mode = Some(mode.to_owned());
        self
    }

    /// Set the revocation information trust policy.
    pub fn revinfo_policy(mut self, policy: CertRevTrustPolicy) -> Self {
        self.revinfo_policy = Some(policy);
        self
    }

    /// Set the algorithm usage policy. Defaults to
    /// [`DisallowWeakAlgorithmsPolicy::default`].
    pub fn algorithm_policy(mut self, policy: Arc<dyn AlgorithmUsagePolicy>) -> Self {
        self.algorithm_policy = Some(policy);
        self
    }

    /// Replace the freshness rules for revocation information.
    pub fn freshness_judge(mut self, judge: Arc<dyn FreshnessJudge>) -> Self {
        self.freshness_judge = Some(judge);
        self
    }

    /// Assert that a certificate was not revoked at some moment.
    pub fn assertion(mut self, assertion: NonRevokedStatusAssertion) -> Self {
        self.assertions.push(assertion);
        self
    }

    /// Allow retrieving revocation information and certificates with these
    /// fetchers. The default is [`Fetchers::none`]: nothing is fetched.
    pub fn fetchers(mut self, fetchers: Fetchers) -> Self {
        self.fetchers = Some(fetchers);
        self
    }

    /// Select a borrowed backend. The caller retains authority to close it.
    ///
    /// The last backend setter selects its backend and close mode. Explicit
    /// [`Self::fetchers`] takes precedence in either setter order, including
    /// explicit [`Fetchers::none`]. No default HTTP backend is provisioned.
    pub fn fetcher_backend(mut self, backend: Arc<dyn FetcherBackend>) -> Self {
        self.fetcher_backend = Some((backend, false));
        self
    }

    /// Adopt a backend, retaining the exact supplied handle for explicit close.
    ///
    /// The backend is retained even when explicit [`Self::fetchers`] wins
    /// retrieval. Its factory runs at most once, only after builder validation
    /// succeeds and only when no explicit fetcher set was supplied.
    pub fn owned_fetcher_backend(mut self, backend: Arc<dyn FetcherBackend>) -> Self {
        self.fetcher_backend = Some((backend, true));
        self
    }

    /// Parse the revocation information and build the context.
    ///
    /// No default backend is provisioned by this ordinary construction path.
    pub fn build(self) -> Result<ValidationContext, ValidationError> {
        self.build_with_optional_backend_fallback(None::<fn() -> Arc<dyn FetcherBackend>>)
    }

    /// Build with a default backend only when neither retrieval choice was set.
    ///
    /// Policy and revocation DER validation precede the fallback. Explicit
    /// fetchers, including an empty set, suppress it. An explicit backend keeps
    /// its selected borrowed/adopted close authority. The fallback backend is
    /// adopted by its exact handle and issues one fetcher set; explicit close
    /// retains that handle and the issued caches and request budget.
    pub fn build_with_backend_fallback<F>(
        self,
        fallback: F,
    ) -> Result<ValidationContext, ValidationError>
    where
        F: FnOnce() -> Arc<dyn FetcherBackend>,
    {
        self.build_with_optional_backend_fallback(Some(fallback))
    }

    fn build_with_optional_backend_fallback<F>(
        mut self,
        fallback: Option<F>,
    ) -> Result<ValidationContext, ValidationError>
    where
        F: FnOnce() -> Arc<dyn FetcherBackend>,
    {
        let revinfo_policy = match (self.revinfo_policy, self.revocation_mode) {
            (Some(policy), _) => policy,
            (None, Some(mode)) => CertRevTrustPolicy::new(
                RevocationCheckingPolicy::from_legacy(&mode).ok_or_else(|| {
                    ValidationError::Malformed(format!("'{mode}' is not a valid revocation mode"))
                })?,
            ),
            (None, None) => CertRevTrustPolicy::default(),
        };
        let validation_time = self.moment.unwrap_or_else(Moment::now);
        let crls = self
            .crls
            .iter()
            .map(|der| CrlContainer::from_der(der))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ocsps = Vec::new();
        for der in &self.ocsps {
            ocsps.extend(OcspContainer::load(der)?);
        }
        // Factories may allocate transport resources: resolve the selection
        // only after all fallible builder validation above has succeeded.
        if self.fetchers.is_none() && self.fetcher_backend.is_none() {
            self.fetcher_backend = fallback.map(|create| (create(), true));
        }
        let fetchers = self.fetchers.unwrap_or_else(|| {
            self.fetcher_backend
                .as_ref()
                .map(|(backend, _)| backend.get_fetchers())
                .unwrap_or_default()
        });
        let owned_fetcher_backend = self
            .fetcher_backend
            .and_then(|(backend, owned)| owned.then_some(backend));
        Ok(ValidationContext {
            trust_anchors: self.trust_anchors,
            other_certs: self.other_certs,
            crls,
            ocsps,
            timing: ValidationTimingParams {
                point_in_time_validation: self
                    .point_in_time_validation
                    .unwrap_or(self.moment.is_some()),
                validation_time,
                best_signature_time: self.best_signature_time.unwrap_or(validation_time),
                time_tolerance: self.time_tolerance.unwrap_or(DEFAULT_TIME_TOLERANCE),
            },
            revinfo_policy,
            algorithm_policy: self
                .algorithm_policy
                .unwrap_or_else(|| Arc::new(DisallowWeakAlgorithmsPolicy::default())),
            freshness_judge: self
                .freshness_judge
                .unwrap_or_else(|| Arc::new(DefaultFreshnessJudge)),
            assertions: self.assertions,
            fetchers,
            owned_fetcher_backend,
            acceptable_ac_targets: self.acceptable_ac_targets,
            trust_manager: self.trust_manager,
        })
    }
}

#[cfg(test)]
#[path = "context_tests.rs"]
mod tests;
