//! Shared conversion of CLI certificate usage requirements.

/// Preserve every configured requirement when invoking native validation.
pub fn key_usage_constraints(
    policy: &crate::config::KeyUsagePolicy,
) -> sigis_pki_core::key_usage::KeyUsageConstraints {
    sigis_pki_core::key_usage::KeyUsageConstraints {
        key_usage: policy.key_usage.clone(),
        key_usage_forbidden: policy.key_usage_forbidden.clone(),
        extd_key_usage: policy.extd_key_usage.clone(),
        match_all_key_usages: policy.match_all_key_usages,
        explicit_extd_key_usage_required: policy.explicit_extd_key_usage_required,
    }
}
