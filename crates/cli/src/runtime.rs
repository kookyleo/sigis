//! Injectable clock and certificate retrieval services for command execution.
use sigis_pki_core::{fetch::Fetchers, time::Moment};
/// Runtime services corresponding to the upstream CLI context.
#[derive(Clone, Debug)]
pub struct ValidationRuntime {
    /// The current time. Claimed signature times do not override this implicitly.
    pub now: Moment,
    /// Issuer, revocation and OCSP retrieval services.
    pub fetchers: Fetchers,
    /// Password supplied by an injected CLI password prompter.
    pub password: Option<String>,
    /// Optional trusted-list HTTP provider; None uses the bounded production transport.
    pub trusted_list_transport: Option<std::sync::Arc<dyn sigis_pki_fetch::HttpTransport>>,
}
impl Default for ValidationRuntime {
    fn default() -> Self {
        Self {
            password: None,
            trusted_list_transport: None,
            now: Moment::now(),
            fetchers: sigis_pki_fetch::HttpFetchers::default().as_fetchers(),
        }
    }
}
