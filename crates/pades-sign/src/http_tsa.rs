//! Select a timestamp client from explicit configuration or PDF seed values.

use std::sync::Arc;

use sigis_pki_core::sign::TimeStamper;

use crate::pdf::seed::SigSeedValueSpec;

/// Preserve an explicit TSA, or use a required seed timestamp URL.
///
/// The HTTP client retains the fetch layer's default limits and nonce checks.
/// A required timestamp without a URL remains unresolved so that the signing
/// session can reject it together with its other seed-value requirements.
pub fn resolve_timestamper(
    explicit: Option<Arc<dyn TimeStamper>>,
    seed: Option<&SigSeedValueSpec>,
) -> Option<Arc<dyn TimeStamper>> {
    explicit.or_else(|| {
        seed.filter(|value| value.timestamp_required)
            .and_then(|value| value.timestamp_server_url.as_ref())
            .filter(|url| !url.is_empty())
            .map(|url| Arc::new(sigis_pki_fetch::HttpTimeStamper::new(url)) as Arc<dyn TimeStamper>)
    })
}
