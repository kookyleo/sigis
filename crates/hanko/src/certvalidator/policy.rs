// Derived from pyhanko-certvalidator `policy_decl.py` (MIT, see LICENSE-pyHanko).

//! Validation policy declarations: revocation checking rules, revocation
//! information trust (freshness) policies and PKIX parameters.

use core::time::Duration;

use const_oid::ObjectIdentifier;

use crate::time::Moment;

/// Default freshness window for revocation information without `nextUpdate`
/// under [`FreshnessReqType::Default`] (`FRESHNESS_FALLBACK_VALIDITY_DEFAULT`).
pub const FRESHNESS_FALLBACK_VALIDITY_DEFAULT: Duration = Duration::from_secs(30 * 60);

/// When revocation information has to be checked, and what kind
/// (ETSI TS 119 172 check types plus two legacy certvalidator modes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevocationCheckingRule {
    /// Check CRLs (`clrcheck`).
    CrlRequired,
    /// Check OCSP (`ocspcheck`).
    OcspRequired,
    /// Check CRL and OCSP (`bothcheck`).
    CrlAndOcspRequired,
    /// Check CRL or OCSP (`eithercheck`).
    CrlOrOcspRequired,
    /// Do not check (`nocheck`).
    NoCheck,
    /// Check revocation information if the certificate declares it
    /// (legacy `hard-fail`).
    CheckIfDeclared,
    /// Check revocation information if declared, but do not fail if the check
    /// cannot be completed (legacy `soft-fail`).
    CheckIfDeclaredSoft,
}

impl RevocationCheckingRule {
    /// Revocation information is always expected.
    pub fn strict(self) -> bool {
        !matches!(
            self,
            Self::CheckIfDeclared | Self::CheckIfDeclaredSoft | Self::NoCheck
        )
    }

    /// Failures to obtain revocation information are tolerated.
    pub fn tolerant(self) -> bool {
        matches!(self, Self::CheckIfDeclaredSoft | Self::NoCheck)
    }

    /// A CRL check is mandatory.
    pub fn crl_mandatory(self) -> bool {
        matches!(self, Self::CrlRequired | Self::CrlAndOcspRequired)
    }

    /// CRLs are taken into account.
    pub fn crl_relevant(self) -> bool {
        !matches!(self, Self::NoCheck | Self::OcspRequired)
    }

    /// An OCSP check is mandatory.
    pub fn ocsp_mandatory(self) -> bool {
        matches!(self, Self::OcspRequired | Self::CrlAndOcspRequired)
    }

    /// OCSP responses are taken into account.
    pub fn ocsp_relevant(self) -> bool {
        !matches!(self, Self::NoCheck | Self::CrlRequired)
    }
}

/// Revocation checking rules for end-entity and CA certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RevocationCheckingPolicy {
    /// Rule for the end-entity certificate.
    pub ee_certificate_rule: RevocationCheckingRule,
    /// Rule for intermediate CA certificates.
    pub intermediate_ca_cert_rule: RevocationCheckingRule,
}

/// Revocation information is always required; CRL or OCSP is acceptable.
pub const REQUIRE_REVINFO: RevocationCheckingPolicy = RevocationCheckingPolicy {
    ee_certificate_rule: RevocationCheckingRule::CrlOrOcspRequired,
    intermediate_ca_cert_rule: RevocationCheckingRule::CrlOrOcspRequired,
};

/// Revocation information is never required.
pub const NO_REVOCATION: RevocationCheckingPolicy = RevocationCheckingPolicy {
    ee_certificate_rule: RevocationCheckingRule::NoCheck,
    intermediate_ca_cert_rule: RevocationCheckingRule::NoCheck,
};

impl RevocationCheckingPolicy {
    /// Map a legacy certvalidator revocation mode (`none`, `soft-fail`,
    /// `hard-fail`, `require`) to a policy.
    pub fn from_legacy(mode: &str) -> Option<Self> {
        let both = |rule| Self {
            ee_certificate_rule: rule,
            intermediate_ca_cert_rule: rule,
        };
        match mode {
            "none" => Some(NO_REVOCATION),
            "soft-fail" => Some(both(RevocationCheckingRule::CheckIfDeclaredSoft)),
            "hard-fail" => Some(both(RevocationCheckingRule::CheckIfDeclared)),
            "require" => Some(REQUIRE_REVINFO),
            _ => None,
        }
    }

    /// Revocation checking is essential (not merely best effort).
    pub fn essential(self) -> bool {
        !(self.ee_certificate_rule.tolerant() && self.intermediate_ca_cert_rule.tolerant())
    }
}

/// How the freshness of revocation information is evaluated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum FreshnessReqType {
    /// Legacy certvalidator policy: usable between `thisUpdate` and `nextUpdate`.
    #[default]
    Default,
    /// The validation time must be close enough to `thisUpdate`
    /// (ETSI EN 319 102-1 §5.2.5.4).
    MaxDiffRevocationValidation,
    /// The revocation information must be issued a "cooldown period" after the
    /// signature time.
    TimeAfterSignature,
}

/// Conditions for trusting revocation information (`CertRevTrustPolicy`,
/// based on `CertificateRevTrust` in ETSI TS 119 172-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CertRevTrustPolicy {
    /// Revocation checking requirements.
    pub revocation_checking_policy: RevocationCheckingPolicy,
    /// Freshness interval. Defaults to `nextUpdate - thisUpdate`.
    pub freshness: Option<Duration>,
    /// Freshness evaluation method.
    pub freshness_req_type: FreshnessReqType,
    /// How long the CA supplies status information after a certificate expires.
    pub expected_post_expiry_revinfo_time: Option<Duration>,
    /// Ignore `thisUpdate` under [`FreshnessReqType::Default`].
    pub retroactive_revinfo: bool,
}

impl CertRevTrustPolicy {
    /// A policy with the given checking rules and default freshness settings.
    pub fn new(revocation_checking_policy: RevocationCheckingPolicy) -> Self {
        Self {
            revocation_checking_policy,
            freshness: None,
            freshness_req_type: FreshnessReqType::Default,
            expected_post_expiry_revinfo_time: None,
            retroactive_revinfo: false,
        }
    }
}

impl Default for CertRevTrustPolicy {
    /// The pyhanko-certvalidator default: legacy `soft-fail`.
    fn default() -> Self {
        Self::new(RevocationCheckingPolicy::from_legacy("soft-fail").unwrap_or(NO_REVOCATION))
    }
}

/// Assertion that a certificate was not revoked at some moment
/// (`NonRevokedStatusAssertion`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NonRevokedStatusAssertion {
    /// SHA-256 digest of the certificate.
    pub cert_sha256: [u8; 32],
    /// The moment the assertion applies to.
    pub at: Moment,
}

/// Initial inputs of the RFC 5280 path validation algorithm
/// (`PKIXValidationParams`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PkixValidationParams {
    /// `user-initial-policy-set`; empty means `anyPolicy`.
    pub user_initial_policy_set: Vec<ObjectIdentifier>,
    /// `initial-policy-mapping-inhibit`.
    pub initial_policy_mapping_inhibit: bool,
    /// `initial-explicit-policy`.
    pub initial_explicit_policy: bool,
    /// `initial-any-policy-inhibit`.
    pub initial_any_policy_inhibit: bool,
}

/// Timing parameters for one validation (`ValidationTimingParams`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidationTimingParams {
    /// The time of interest.
    pub validation_time: Moment,
    /// Best known signature time (for [`FreshnessReqType::TimeAfterSignature`]).
    pub best_signature_time: Moment,
    /// Allowed clock drift.
    pub time_tolerance: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_modes() {
        let soft = RevocationCheckingPolicy::from_legacy("soft-fail").expect("soft-fail");
        assert!(soft.ee_certificate_rule.tolerant());
        assert!(!soft.essential());
        let hard = RevocationCheckingPolicy::from_legacy("hard-fail").expect("hard-fail");
        assert!(!hard.ee_certificate_rule.strict());
        assert!(hard.essential());
        assert_eq!(
            RevocationCheckingPolicy::from_legacy("require"),
            Some(REQUIRE_REVINFO)
        );
        assert_eq!(RevocationCheckingPolicy::from_legacy("bogus"), None);
    }
}
