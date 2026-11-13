//! Opt-in main-signer certificate usage for AdES validation.

use sigis_cms::{CmsValidationOptions, CmsValidationOrder};
use sigis_pki_core::key_usage::KeyUsageConstraints;

/// Additional main-signer validation requirements, without changing defaults.
///
/// Existing entry points use [`Default`]. To request the complete native
/// predicate, set [`Self::exact_key_usage_settings`] on a default value. This
/// does not configure timestamp purpose, trust roots, qualification or POE.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AdesValidationOptions {
    /// Exact main-signer usage predicate, with every native field preserved.
    ///
    /// `None` keeps the entry point's ordinary facade behavior. `Some` retains
    /// intentional empty values without adding non-repudiation or normalizing
    /// KU/EKU flags. Timestamp certificate purpose and all other caller
    /// requirements remain unchanged.
    pub exact_key_usage_settings: Option<KeyUsageConstraints>,
}

impl AdesValidationOptions {
    pub(crate) fn main_cms_options(
        &self,
        validation_order: CmsValidationOrder,
    ) -> CmsValidationOptions<'static> {
        CmsValidationOptions {
            validation_order,
            exact_key_usage_settings: self.exact_key_usage_settings.clone(),
            ..Default::default()
        }
    }
}
