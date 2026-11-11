// Derived from pyhanko-certvalidator `policy_decl.py` (MIT, see LICENSE-pyHanko).

//! Validation policy declarations: revocation checking rules, revocation
//! information trust (freshness) policies and PKIX parameters.

use core::time::Duration;

use const_oid::ObjectIdentifier;
use x509_cert::ext::pkix::constraints::name::GeneralSubtree;

use hanko_core::time::Moment;

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
    /// The pyhanko-certvalidator enum value (`clrcheck`, ...).
    pub fn value(self) -> &'static str {
        match self {
            Self::CrlRequired => "clrcheck",
            Self::OcspRequired => "ocspcheck",
            Self::CrlAndOcspRequired => "bothcheck",
            Self::CrlOrOcspRequired => "eithercheck",
            Self::NoCheck => "nocheck",
            Self::CheckIfDeclared => "ifdeclaredcheck",
            Self::CheckIfDeclaredSoft => "ifdeclaredsoftcheck",
        }
    }

    /// Parse a pyhanko-certvalidator enum value (see [`Self::value`]).
    pub fn from_value(value: &str) -> Option<Self> {
        [
            Self::CrlRequired,
            Self::OcspRequired,
            Self::CrlAndOcspRequired,
            Self::CrlOrOcspRequired,
            Self::NoCheck,
            Self::CheckIfDeclared,
            Self::CheckIfDeclaredSoft,
        ]
        .into_iter()
        .find(|r| r.value() == value)
    }

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
    /// `initial-permitted-subtrees`; `None` means unconstrained.
    pub initial_permitted_subtrees: Option<Vec<GeneralSubtree>>,
    /// `initial-excluded-subtrees`; `None` means none.
    pub initial_excluded_subtrees: Option<Vec<GeneralSubtree>>,
    /// Upper bound on the size of the policy graph (`max_policy_graph_nodes`).
    pub max_policy_graph_nodes: Option<usize>,
}

/// `stricter_limit`.
pub fn stricter_limit(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (None, b) => b,
        (a, None) => a,
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

impl PkixValidationParams {
    /// `merge`: combine two parameter sets as pyhanko-certvalidator does
    /// (policy sets intersected unless one is `anyPolicy`, flags combined
    /// with "and", the stricter policy graph limit; subtrees are not kept).
    pub fn merge(&self, other: &Self) -> Self {
        let any = const_oid::db::rfc5280::ANY_POLICY;
        let is_any = |p: &Vec<ObjectIdentifier>| p.is_empty() || p.contains(&any);
        let user_initial_policy_set = if is_any(&self.user_initial_policy_set) {
            other.user_initial_policy_set.clone()
        } else if is_any(&other.user_initial_policy_set) {
            self.user_initial_policy_set.clone()
        } else {
            self.user_initial_policy_set
                .iter()
                .filter(|p| other.user_initial_policy_set.contains(p))
                .copied()
                .collect()
        };
        Self {
            user_initial_policy_set,
            initial_any_policy_inhibit: self.initial_any_policy_inhibit
                && other.initial_any_policy_inhibit,
            initial_explicit_policy: self.initial_explicit_policy && other.initial_explicit_policy,
            initial_policy_mapping_inhibit: self.initial_policy_mapping_inhibit
                && other.initial_policy_mapping_inhibit,
            initial_permitted_subtrees: None,
            initial_excluded_subtrees: None,
            max_policy_graph_nodes: stricter_limit(
                self.max_policy_graph_nodes,
                other.max_policy_graph_nodes,
            ),
        }
    }

    /// Combine the parameters of a trust anchor with the caller's
    /// (`_PathValidationState.init_pkix_validation_state`): policy sets
    /// intersected, flags combined with "or", permitted subtrees
    /// intersected (here: both lists apply), excluded subtrees united,
    /// the stricter policy graph limit.
    pub fn combine_with_anchor(&self, anchor: &Self) -> Self {
        let any = const_oid::db::rfc5280::ANY_POLICY;
        let is_any = |p: &Vec<ObjectIdentifier>| p.is_empty() || p.contains(&any);
        let user_initial_policy_set = if is_any(&self.user_initial_policy_set) {
            anchor.user_initial_policy_set.clone()
        } else if is_any(&anchor.user_initial_policy_set) {
            self.user_initial_policy_set.clone()
        } else {
            self.user_initial_policy_set
                .iter()
                .filter(|p| anchor.user_initial_policy_set.contains(p))
                .copied()
                .collect()
        };
        let concat = |a: &Option<Vec<GeneralSubtree>>, b: &Option<Vec<GeneralSubtree>>| match (a, b)
        {
            (None, None) => None,
            (a, b) => Some(
                a.iter()
                    .flatten()
                    .chain(b.iter().flatten())
                    .cloned()
                    .collect(),
            ),
        };
        Self {
            user_initial_policy_set,
            initial_any_policy_inhibit: self.initial_any_policy_inhibit
                || anchor.initial_any_policy_inhibit,
            initial_explicit_policy: self.initial_explicit_policy || anchor.initial_explicit_policy,
            initial_policy_mapping_inhibit: self.initial_policy_mapping_inhibit
                || anchor.initial_policy_mapping_inhibit,
            initial_permitted_subtrees: concat(
                &self.initial_permitted_subtrees,
                &anchor.initial_permitted_subtrees,
            ),
            initial_excluded_subtrees: concat(
                &self.initial_excluded_subtrees,
                &anchor.initial_excluded_subtrees,
            ),
            max_policy_graph_nodes: stricter_limit(
                self.max_policy_graph_nodes,
                anchor.max_policy_graph_nodes,
            ),
        }
    }
}

/// `derive_quals_from_cert`: trust qualifiers from a certificate's name
/// constraints, certificate policies, path length and CA flag.
pub fn derive_quals_from_cert(cert: &crate::authority::Cert) -> crate::authority::TrustQualifiers {
    use x509_cert::ext::pkix::{BasicConstraints, CertificatePolicies, NameConstraints};
    let any = const_oid::db::rfc5280::ANY_POLICY;
    let mut ext_found = false;
    let (mut permitted, mut excluded) = (None, None);
    if let Ok(Some((_, nc))) = cert.extension::<NameConstraints>() {
        ext_found = true;
        permitted = nc.permitted_subtrees;
        excluded = nc.excluded_subtrees;
    }
    let mut acceptable: Option<Vec<ObjectIdentifier>> = None;
    if let Ok(Some((_, cps))) = cert.extension::<CertificatePolicies>() {
        ext_found = true;
        acceptable = Some(
            cps.0
                .iter()
                .map(|p| p.policy_identifier)
                .filter(|p| *p != any)
                .collect(),
        );
    }
    let standard_parameters = ext_found.then(|| PkixValidationParams {
        user_initial_policy_set: acceptable
            .clone()
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| vec![any]),
        initial_explicit_policy: acceptable.is_some(),
        initial_permitted_subtrees: permitted,
        initial_excluded_subtrees: excluded,
        ..PkixValidationParams::default()
    });
    let bc = cert
        .extension::<BasicConstraints>()
        .ok()
        .flatten()
        .map(|(_, bc)| bc);
    crate::authority::TrustQualifiers {
        standard_parameters,
        max_path_length: bc
            .as_ref()
            .and_then(|b| b.path_len_constraint)
            .map(usize::from),
        max_aa_path_length: None,
        trusted_service_type: if bc.is_some_and(|b| b.ca) {
            crate::authority::TrustedServiceType::CertificateAuthority
        } else {
            crate::authority::TrustedServiceType::Unsupported
        },
    }
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
    /// The time of interest was given explicitly (`point_in_time_validation`):
    /// only revocations before it count. Otherwise any revocation counts.
    pub point_in_time_validation: bool,
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
