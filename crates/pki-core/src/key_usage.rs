// Derived from pyHanko `sign/validation/settings.py` (MIT, see LICENSE-pyHanko).

//! Key usage constraints for signer certificates
//! (`pyhanko.sign.validation.settings`).
//!
//! Shared by `sigis-cms` (lane A) and `sigis-pades` / `sigis-eutl` (lane E);
//! owned by lane A. `sigis_cms` and `sigis_pades::settings` re-export this
//! module.
//!
//! Key usages and extended key usages are named as in asn1crypto
//! (`non_repudiation`, `time_stamping`, ...); unknown extended key usages
//! are named by their dotted OID.

use std::collections::BTreeSet;

use crate::cert::Cert;
use x509_cert::ext::pkix::KeyUsages;

/// Error raised when a certificate does not meet a key usage policy
/// (`InvalidCertificateError` in pyhanko-certvalidator).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidCertificateError(pub String);

/// Names of the key usage bits, as asn1crypto spells them, in bit order.
pub const KEY_USAGE_NAMES: [&str; 9] = [
    "digital_signature",
    "non_repudiation",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
];

/// The key usage bits of `cert` by name, `None` if the extension is absent.
/// A malformed extension counts as asserting nothing.
pub fn cert_key_usages(cert: &Cert) -> Option<BTreeSet<String>> {
    if !cert.has_extension(&crate::asn1::oids::CE_KEY_USAGE) {
        return None;
    }
    let Some(ku) = cert.key_usage() else {
        return Some(BTreeSet::new());
    };
    let flags = [
        KeyUsages::DigitalSignature,
        KeyUsages::NonRepudiation,
        KeyUsages::KeyEncipherment,
        KeyUsages::DataEncipherment,
        KeyUsages::KeyAgreement,
        KeyUsages::KeyCertSign,
        KeyUsages::CRLSign,
        KeyUsages::EncipherOnly,
        KeyUsages::DecipherOnly,
    ];
    Some(
        flags
            .iter()
            .zip(KEY_USAGE_NAMES)
            .filter(|(flag, _)| ku.0.contains(**flag))
            .map(|(_, name)| name.to_owned())
            .collect(),
    )
}

/// The key usage bits of `cert` by name (empty if the extension is absent).
pub fn key_usage_names(cert: &Cert) -> BTreeSet<String> {
    cert_key_usages(cert).unwrap_or_default()
}

/// asn1crypto's names for well-known key purpose IDs (`KeyPurposeId._map`,
/// asn1crypto 1.5.1). Unknown OIDs are rendered in dotted form, as asn1crypto
/// does.
pub const KEY_PURPOSE_NAMES: &[(&str, &str)] = &[
    ("2.5.29.37.0", "any_extended_key_usage"),
    ("1.3.6.1.5.5.7.3.1", "server_auth"),
    ("1.3.6.1.5.5.7.3.2", "client_auth"),
    ("1.3.6.1.5.5.7.3.3", "code_signing"),
    ("1.3.6.1.5.5.7.3.4", "email_protection"),
    ("1.3.6.1.5.5.7.3.5", "ipsec_end_system"),
    ("1.3.6.1.5.5.7.3.6", "ipsec_tunnel"),
    ("1.3.6.1.5.5.7.3.7", "ipsec_user"),
    ("1.3.6.1.5.5.7.3.8", "time_stamping"),
    ("1.3.6.1.5.5.7.3.9", "ocsp_signing"),
    ("1.3.6.1.5.5.7.3.10", "dvcs"),
    ("1.3.6.1.5.5.7.3.13", "eap_over_ppp"),
    ("1.3.6.1.5.5.7.3.14", "eap_over_lan"),
    ("1.3.6.1.5.5.7.3.15", "scvp_server"),
    ("1.3.6.1.5.5.7.3.16", "scvp_client"),
    ("1.3.6.1.5.5.7.3.17", "ipsec_ike"),
    ("1.3.6.1.5.5.7.3.18", "capwap_ac"),
    ("1.3.6.1.5.5.7.3.19", "capwap_wtp"),
    ("1.3.6.1.5.5.7.3.20", "sip_domain"),
    ("1.3.6.1.5.5.7.3.21", "secure_shell_client"),
    ("1.3.6.1.5.5.7.3.22", "secure_shell_server"),
    ("1.3.6.1.5.5.7.3.23", "send_router"),
    ("1.3.6.1.5.5.7.3.24", "send_proxied_router"),
    ("1.3.6.1.5.5.7.3.25", "send_owner"),
    ("1.3.6.1.5.5.7.3.26", "send_proxied_owner"),
    ("1.3.6.1.5.5.7.3.27", "cmc_ca"),
    ("1.3.6.1.5.5.7.3.28", "cmc_ra"),
    ("1.3.6.1.5.5.7.3.29", "cmc_archive"),
    ("1.3.6.1.5.5.7.3.30", "bgpspec_router"),
    ("1.3.6.1.5.5.8.2.2", "ike_intermediate"),
    ("1.3.6.1.4.1.311.10.3.1", "microsoft_trust_list_signing"),
    ("1.3.6.1.4.1.311.10.3.2", "microsoft_time_stamp_signing"),
    ("1.3.6.1.4.1.311.10.3.3", "microsoft_server_gated"),
    ("1.3.6.1.4.1.311.10.3.3.1", "microsoft_serialized"),
    ("1.3.6.1.4.1.311.10.3.4", "microsoft_efs"),
    ("1.3.6.1.4.1.311.10.3.4.1", "microsoft_efs_recovery"),
    ("1.3.6.1.4.1.311.10.3.5", "microsoft_whql"),
    ("1.3.6.1.4.1.311.10.3.6", "microsoft_nt5"),
    ("1.3.6.1.4.1.311.10.3.7", "microsoft_oem_whql"),
    ("1.3.6.1.4.1.311.10.3.8", "microsoft_embedded_nt"),
    ("1.3.6.1.4.1.311.10.3.9", "microsoft_root_list_signer"),
    (
        "1.3.6.1.4.1.311.10.3.10",
        "microsoft_qualified_subordination",
    ),
    ("1.3.6.1.4.1.311.10.3.11", "microsoft_key_recovery"),
    ("1.3.6.1.4.1.311.10.3.12", "microsoft_document_signing"),
    ("1.3.6.1.4.1.311.10.3.13", "microsoft_lifetime_signing"),
    (
        "1.3.6.1.4.1.311.10.3.14",
        "microsoft_mobile_device_software",
    ),
    ("1.3.6.1.4.1.311.20.2.2", "microsoft_smart_card_logon"),
    ("1.2.840.113635.100.1.2", "apple_x509_basic"),
    ("1.2.840.113635.100.1.3", "apple_ssl"),
    ("1.2.840.113635.100.1.4", "apple_local_cert_gen"),
    ("1.2.840.113635.100.1.5", "apple_csr_gen"),
    ("1.2.840.113635.100.1.6", "apple_revocation_crl"),
    ("1.2.840.113635.100.1.7", "apple_revocation_ocsp"),
    ("1.2.840.113635.100.1.8", "apple_smime"),
    ("1.2.840.113635.100.1.9", "apple_eap"),
    ("1.2.840.113635.100.1.10", "apple_software_update_signing"),
    ("1.2.840.113635.100.1.11", "apple_ipsec"),
    ("1.2.840.113635.100.1.12", "apple_ichat"),
    ("1.2.840.113635.100.1.13", "apple_resource_signing"),
    ("1.2.840.113635.100.1.14", "apple_pkinit_client"),
    ("1.2.840.113635.100.1.15", "apple_pkinit_server"),
    ("1.2.840.113635.100.1.16", "apple_code_signing"),
    ("1.2.840.113635.100.1.17", "apple_package_signing"),
    ("1.2.840.113635.100.1.18", "apple_id_validation"),
    ("1.2.840.113635.100.1.20", "apple_time_stamping"),
    ("1.2.840.113635.100.1.21", "apple_revocation"),
    ("1.2.840.113635.100.1.22", "apple_passbook_signing"),
    ("1.2.840.113635.100.1.23", "apple_mobile_store"),
    ("1.2.840.113635.100.1.24", "apple_escrow_service"),
    ("1.2.840.113635.100.1.25", "apple_profile_signer"),
    ("1.2.840.113635.100.1.26", "apple_qa_profile_signer"),
    ("1.2.840.113635.100.1.27", "apple_test_mobile_store"),
    ("1.2.840.113635.100.1.28", "apple_otapki_signer"),
    ("1.2.840.113635.100.1.29", "apple_test_otapki_signer"),
    (
        "1.2.840.113625.100.1.30",
        "apple_id_validation_record_signing_policy",
    ),
    ("1.2.840.113625.100.1.31", "apple_smp_encryption"),
    ("1.2.840.113625.100.1.32", "apple_test_smp_encryption"),
    ("1.2.840.113635.100.1.33", "apple_server_authentication"),
    ("1.2.840.113635.100.1.34", "apple_pcs_escrow_service"),
    ("2.16.840.1.101.3.6.8", "piv_card_authentication"),
    ("2.16.840.1.101.3.6.7", "piv_content_signing"),
    ("1.3.6.1.5.2.3.4", "pkinit_kpclientauth"),
    ("1.3.6.1.5.2.3.5", "pkinit_kpkdc"),
    ("1.2.840.113583.1.1.5", "adobe_authentic_documents_trust"),
    ("2.16.840.1.101.3.8.7", "fpki_pivi_content_signing"),
];

/// asn1crypto's name of a key purpose ID (the dotted OID if unnamed).
pub fn key_purpose_name(oid: &str) -> String {
    KEY_PURPOSE_NAMES
        .iter()
        .find(|(dotted, _)| *dotted == oid)
        .map_or_else(|| oid.to_owned(), |(_, name)| (*name).to_owned())
}

/// The extended key usages of `cert` by name, `None` if the extension is
/// absent. A malformed extension counts as asserting nothing.
pub fn cert_extended_key_usages(cert: &Cert) -> Option<BTreeSet<String>> {
    if !cert.has_extension(&crate::asn1::oids::CE_EXT_KEY_USAGE) {
        return None;
    }
    Some(
        cert.extended_key_usage()
            .unwrap_or_default()
            .iter()
            .map(|oid| key_purpose_name(&oid.to_string()))
            .collect(),
    )
}

/// The extended key usages of `cert`, named as asn1crypto names them.
pub fn extended_key_usage_names(cert: &Cert) -> Option<BTreeSet<String>> {
    cert_extended_key_usages(cert)
}

fn match_usages(required: &BTreeSet<String>, present: &BTreeSet<String>, need_all: bool) -> bool {
    if need_all {
        required.is_subset(present)
    } else {
        !required.is_disjoint(present)
    }
}

fn rephrase<'a>(it: impl Iterator<Item = &'a String>) -> String {
    it.map(|s| s.replace('_', " "))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Key usage requirements (`KeyUsageConstraints`).
///
/// Key usages use the asn1crypto names (see [`KEY_USAGE_NAMES`]); extended
/// key usages use asn1crypto key purpose names or dotted OIDs (see
/// [`key_purpose_name`]). [`Default`] equals [`KeyUsageConstraints::new`]
/// (pyHanko's defaults, `explicit_extd_key_usage_required=True`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyUsageConstraints {
    /// All or some (see `match_all_key_usages`) of these key usages must be
    /// present. `None` or empty: any key usage is acceptable.
    pub key_usage: Option<BTreeSet<String>>,
    /// These key usages must not be present (ISO 32000 seed values), even
    /// when `key_usage` is `None` or empty.
    pub key_usage_forbidden: Option<BTreeSet<String>>,
    /// Acceptable extended key usages. `None`: all are acceptable. An empty
    /// set bans all extended key usages.
    pub extd_key_usage: Option<BTreeSet<String>>,
    /// Require an extended key usage extension with a listed purpose when
    /// `extd_key_usage` is set; `anyExtendedKeyUsage` then does not count
    /// (default `true`).
    pub explicit_extd_key_usage_required: bool,
    /// All key usages in `key_usage` must be present (default `false`).
    pub match_all_key_usages: bool,
}

impl Default for KeyUsageConstraints {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyUsageConstraints {
    /// Constraints with pyHanko's defaults (no requirements).
    pub fn new() -> Self {
        Self {
            key_usage: None,
            key_usage_forbidden: None,
            extd_key_usage: None,
            explicit_extd_key_usage_required: true,
            match_all_key_usages: false,
        }
    }

    /// Require one of the given key usages, ban others.
    pub fn with_key_usage<'a>(
        key_usage: impl IntoIterator<Item = &'a str>,
        forbidden: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let forbidden: BTreeSet<String> = forbidden.into_iter().map(str::to_owned).collect();
        Self {
            key_usage: Some(key_usage.into_iter().map(str::to_owned).collect()),
            key_usage_forbidden: (!forbidden.is_empty()).then_some(forbidden),
            ..Self::new()
        }
    }

    /// Require one of the given extended key usages.
    pub fn with_extd_key_usage<'a>(extd: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            extd_key_usage: Some(extd.into_iter().map(str::to_owned).collect()),
            ..Self::new()
        }
    }

    /// Validate `cert` (`validate`).
    pub fn validate(&self, cert: &Cert) -> Result<(), InvalidCertificateError> {
        self.validate_with_extra(cert, &BTreeSet::new(), &BTreeSet::new())
    }

    /// Validate `cert`, treating the extra usages as asserted as well (for
    /// example the service type of a trusted list entry).
    pub fn validate_with_extra(
        &self,
        cert: &Cert,
        extra_key_usages: &BTreeSet<String>,
        extra_extd_key_usages: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        self.validate_key_usage_extension(cert_key_usages(cert).as_ref(), extra_key_usages)?;
        self.validate_extd_key_usage_extension(
            cert_extended_key_usages(cert).as_ref(),
            extra_extd_key_usages,
        )
    }

    /// Check a key usage extension value (`None`: extension absent) plus
    /// extra asserted key usages.
    pub fn validate_key_usage_extension(
        &self,
        cert_ku: Option<&BTreeSet<String>>,
        extra: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let mut asserted = cert_ku.cloned().unwrap_or_default();
        asserted.extend(extra.iter().cloned());
        self.validate_asserted_key_usage(&asserted)
    }

    /// Check an extended key usage extension value (`None`: extension
    /// absent) plus extra asserted extended key usages.
    pub fn validate_extd_key_usage_extension(
        &self,
        cert_eku: Option<&BTreeSet<String>>,
        extra: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let mut asserted = cert_eku.cloned().unwrap_or_default();
        asserted.extend(extra.iter().cloned());
        self.validate_asserted_extended_key_usage(&asserted)
    }

    /// Check a set of asserted key usages (`validate_asserted_key_usage`).
    pub fn validate_asserted_key_usage(
        &self,
        asserted: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let empty = BTreeSet::new();
        let forbidden = self.key_usage_forbidden.as_ref().unwrap_or(&empty);
        let banned: BTreeSet<String> = asserted.intersection(forbidden).cloned().collect();
        if !banned.is_empty() {
            return Err(InvalidCertificateError(format!(
                "The active key usage policy explicitly bans certificates used for {}.",
                rephrase(banned.iter())
            )));
        }
        let key_usage = match &self.key_usage {
            Some(ku) if !ku.is_empty() => ku,
            _ => return Ok(()),
        };
        let need_all = self.match_all_key_usages;
        if !match_usages(key_usage, asserted, need_all) {
            return Err(InvalidCertificateError(format!(
                "The active key usage policy requires {}the key usage extensions {} to be present.",
                if need_all { "" } else { "at least one of " },
                rephrase(key_usage.iter())
            )));
        }
        Ok(())
    }

    /// Check a set of asserted extended key usages
    /// (`validate_asserted_extended_key_usage`).
    pub fn validate_asserted_extended_key_usage(
        &self,
        asserted: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let Some(extd) = &self.extd_key_usage else {
            return Ok(());
        };
        if asserted.is_empty() {
            if self.explicit_extd_key_usage_required {
                return Err(InvalidCertificateError(
                    "The active key usage policy requires an extended key usage extension."
                        .to_owned(),
                ));
            }
            return Ok(());
        }
        if asserted.contains("any_extended_key_usage") && !self.explicit_extd_key_usage_required {
            return Ok(());
        }
        if !match_usages(extd, asserted, false) {
            let ok_list = if extd.is_empty() {
                "There are no acceptable extended key usages.".to_owned()
            } else {
                format!("Relevant key purposes are {}.", rephrase(extd.iter()))
            };
            return Err(InvalidCertificateError(format!(
                "The extended key usages for which this certificate is valid do not match the active key usage policy. {ok_list}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_pyhanko() {
        let d = KeyUsageConstraints::default();
        assert!(d.explicit_extd_key_usage_required);
        assert!(!d.match_all_key_usages);
        assert_eq!(d, KeyUsageConstraints::new());
    }

    #[test]
    fn key_purpose_names_follow_asn1crypto() {
        assert_eq!(key_purpose_name("1.3.6.1.5.5.7.3.8"), "time_stamping");
        assert_eq!(
            key_purpose_name("1.2.840.113583.1.1.5"),
            "adobe_authentic_documents_trust"
        );
        assert_eq!(key_purpose_name("2.999"), "2.999");
    }

    fn usages(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn signer_certificate() -> Cert {
        Cert::from_pem_or_der(include_bytes!(
            "../../testdata/data/pyhanko-certvalidator/testing-ca-ed25519/signer.cert.pem"
        ))
        .unwrap()
    }

    #[test]
    fn forbidden_key_usages_reject_without_positive_requirements() {
        let cert = signer_certificate();
        assert_eq!(
            cert_key_usages(&cert),
            Some(usages(&["digital_signature", "non_repudiation"]))
        );
        for key_usage in [None, Some(BTreeSet::new())] {
            for match_all_key_usages in [false, true] {
                let constraints = KeyUsageConstraints {
                    key_usage: key_usage.clone(),
                    key_usage_forbidden: Some(usages(&["non_repudiation"])),
                    match_all_key_usages,
                    ..KeyUsageConstraints::default()
                };
                assert_eq!(
                    constraints.validate(&cert).unwrap_err().0,
                    "The active key usage policy explicitly bans certificates used for non repudiation."
                );
                let permitted = KeyUsageConstraints {
                    key_usage_forbidden: Some(usages(&["key_cert_sign"])),
                    ..constraints
                };
                permitted.validate(&cert).unwrap();
            }
        }
    }

    #[test]
    fn forbidden_key_usages_include_extra_assertions() {
        let cert = signer_certificate();
        for key_usage in [None, Some(BTreeSet::new())] {
            let constraints = KeyUsageConstraints {
                key_usage,
                key_usage_forbidden: Some(usages(&["key_agreement"])),
                ..KeyUsageConstraints::default()
            };
            constraints.validate(&cert).unwrap();
            let extra = usages(&["key_agreement"]);
            let expected =
                "The active key usage policy explicitly bans certificates used for key agreement.";
            assert_eq!(
                constraints
                    .validate_with_extra(&cert, &extra, &BTreeSet::new())
                    .unwrap_err()
                    .0,
                expected
            );
            assert_eq!(
                constraints
                    .validate_key_usage_extension(None, &extra)
                    .unwrap_err()
                    .0,
                expected
            );
            constraints
                .validate_key_usage_extension(None, &BTreeSet::new())
                .unwrap();
        }
    }

    #[test]
    fn forbidden_key_usages_precede_positive_requirements() {
        let constraints =
            KeyUsageConstraints::with_key_usage(["key_cert_sign"], ["non_repudiation"]);
        assert_eq!(
            constraints.validate(&signer_certificate()).unwrap_err().0,
            "The active key usage policy explicitly bans certificates used for non repudiation."
        );
        assert!(constraints
            .validate_asserted_key_usage(&usages(&["digital_signature"]))
            .unwrap_err()
            .0
            .contains("requires at least one of the key usage extensions key cert sign"));
    }

    #[test]
    fn unrestricted_key_usages_preserve_none_and_empty() {
        let default = KeyUsageConstraints::default();
        assert_eq!(default.key_usage, None);
        assert_eq!(default.key_usage_forbidden, None);
        assert_eq!(default.extd_key_usage, None);
        let explicit_empty = KeyUsageConstraints::with_key_usage([], []);
        assert_eq!(explicit_empty.key_usage, Some(BTreeSet::new()));
        assert_eq!(explicit_empty.key_usage_forbidden, None);
        for constraints in [default, explicit_empty] {
            constraints.validate(&signer_certificate()).unwrap();
            constraints
                .validate_key_usage_extension(None, &BTreeSet::new())
                .unwrap();
            let empty_forbidden = KeyUsageConstraints {
                key_usage_forbidden: Some(BTreeSet::new()),
                ..constraints
            };
            empty_forbidden.validate(&signer_certificate()).unwrap();
        }
    }

    #[test]
    fn extended_key_usages_preserve_none_and_empty() {
        for explicit_extd_key_usage_required in [false, true] {
            let unrestricted = KeyUsageConstraints {
                explicit_extd_key_usage_required,
                ..KeyUsageConstraints::default()
            };
            let empty = KeyUsageConstraints {
                extd_key_usage: Some(BTreeSet::new()),
                ..unrestricted.clone()
            };
            let client_auth = usages(&["client_auth"]);
            unrestricted
                .validate_asserted_extended_key_usage(&client_auth)
                .unwrap();
            assert_eq!(
                empty
                    .validate_asserted_extended_key_usage(&client_auth)
                    .unwrap_err()
                    .0,
                "The extended key usages for which this certificate is valid do not match the active key usage policy. There are no acceptable extended key usages."
            );
            // Absence and anyExtendedKeyUsage retain the explicitness policy.
            for asserted in [BTreeSet::new(), usages(&["any_extended_key_usage"])] {
                unrestricted
                    .validate_asserted_extended_key_usage(&asserted)
                    .unwrap();
                assert_eq!(
                    empty
                        .validate_asserted_extended_key_usage(&asserted)
                        .is_err(),
                    explicit_extd_key_usage_required
                );
            }
        }
    }
}
