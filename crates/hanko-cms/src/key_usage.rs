// Derived from pyHanko `sign/validation/settings.py` (MIT, see LICENSE-pyHanko).

//! Key usage requirements for signer certificates (`KeyUsageConstraints`).
//!
//! Key usages and extended key usages are named as in asn1crypto
//! (`non_repudiation`, `time_stamping`, ...); unknown extended key usages
//! are named by their dotted OID.

use std::collections::BTreeSet;

use const_oid::ObjectIdentifier;
use x509_cert::ext::pkix::KeyUsages;

use hanko_core::cert::Cert;

/// A key usage requirement failed (`InvalidCertificateError`).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidCertificateError(pub String);

/// Key usage requirements (`KeyUsageConstraints`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyUsageConstraints {
    /// All or some (see [`Self::match_all_key_usages`]) of these key usages
    /// must be present. `None` or empty: no requirement.
    pub key_usage: Option<BTreeSet<String>>,
    /// Key usages that must not be present (ISO 32000 seed values).
    pub key_usage_forbidden: Option<BTreeSet<String>>,
    /// Acceptable extended key usages. `None`: no requirement. An empty set
    /// bans every extended key usage.
    pub extd_key_usage: Option<BTreeSet<String>>,
    /// Require an EKU extension with a listed purpose when
    /// [`Self::extd_key_usage`] is set (`anyExtendedKeyUsage` then does not count).
    pub explicit_extd_key_usage_required: bool,
    /// All listed key usages must be present, instead of one.
    pub match_all_key_usages: bool,
}

impl Default for KeyUsageConstraints {
    fn default() -> Self {
        Self {
            key_usage: None,
            key_usage_forbidden: None,
            extd_key_usage: None,
            explicit_extd_key_usage_required: true,
            match_all_key_usages: false,
        }
    }
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

impl KeyUsageConstraints {
    /// Constraints with the given required key usages.
    pub fn with_key_usage(items: &[&str]) -> Self {
        Self {
            key_usage: Some(set(items)),
            ..Self::default()
        }
    }

    /// Constraints with the given acceptable extended key usages.
    pub fn with_extd_key_usage(items: &[&str]) -> Self {
        Self {
            extd_key_usage: Some(set(items)),
            ..Self::default()
        }
    }

    /// Check `cert`, with additional key usages asserted by context (for
    /// example the service type of a trusted list entry).
    pub fn validate(
        &self,
        cert: &Cert,
        extra_asserted_key_usages: &BTreeSet<String>,
        extra_asserted_extd_key_usages: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let ku = cert_key_usages(cert);
        self.validate_key_usage_extension(ku.as_ref(), extra_asserted_key_usages)?;
        let eku = cert_extended_key_usages(cert);
        self.validate_extd_key_usage_extension(eku.as_ref(), extra_asserted_extd_key_usages)
    }

    /// Check a key usage extension value (`None`: extension absent).
    pub fn validate_key_usage_extension(
        &self,
        cert_ku: Option<&BTreeSet<String>>,
        extra: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let mut asserted = cert_ku.cloned().unwrap_or_default();
        asserted.extend(extra.iter().cloned());
        self.validate_asserted_key_usage(&asserted)
    }

    /// `validate_asserted_key_usage`.
    pub fn validate_asserted_key_usage(
        &self,
        asserted: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let Some(key_usage) = self.key_usage.as_ref().filter(|k| !k.is_empty()) else {
            return Ok(());
        };
        let forbidden: Vec<String> = self
            .key_usage_forbidden
            .iter()
            .flatten()
            .filter(|f| asserted.contains(*f))
            .map(|s| s.replace('_', " "))
            .collect();
        if !forbidden.is_empty() {
            return Err(InvalidCertificateError(format!(
                "The active key usage policy explicitly bans certificates used for {}.",
                forbidden.join(", ")
            )));
        }
        let need_all = self.match_all_key_usages;
        if !match_usages(key_usage, asserted, need_all) {
            let rephrased: Vec<String> = key_usage.iter().map(|s| s.replace('_', " ")).collect();
            return Err(InvalidCertificateError(format!(
                "The active key usage policy requires {}the key usage extensions {} to be present.",
                if need_all { "" } else { "at least one of " },
                rephrased.join(", ")
            )));
        }
        Ok(())
    }

    /// Check an extended key usage extension value (`None`: extension absent).
    pub fn validate_extd_key_usage_extension(
        &self,
        cert_eku: Option<&BTreeSet<String>>,
        extra: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let mut asserted = cert_eku.cloned().unwrap_or_default();
        asserted.extend(extra.iter().cloned());
        self.validate_asserted_extended_key_usage(&asserted)
    }

    /// `validate_asserted_extended_key_usage`.
    pub fn validate_asserted_extended_key_usage(
        &self,
        asserted: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let Some(extd_key_usage) = &self.extd_key_usage else {
            return Ok(());
        };
        if asserted.is_empty() {
            if self.explicit_extd_key_usage_required {
                return Err(InvalidCertificateError(
                    "The active key usage policy requires an extended key usage extension."
                        .into(),
                ));
            }
            return Ok(());
        }
        if asserted.contains("any_extended_key_usage") && !self.explicit_extd_key_usage_required {
            return Ok(());
        }
        if !match_usages(extd_key_usage, asserted, false) {
            let ok_list = if extd_key_usage.is_empty() {
                "There are no acceptable extended key usages.".to_owned()
            } else {
                let rephrased: Vec<String> =
                    extd_key_usage.iter().map(|s| s.replace('_', " ")).collect();
                format!("Relevant key purposes are {}.", rephrased.join(", "))
            };
            return Err(InvalidCertificateError(format!(
                "The extended key usages for which this certificate is valid do not match the active key usage policy. {ok_list}"
            )));
        }
        Ok(())
    }
}

fn match_usages(required: &BTreeSet<String>, present: &BTreeSet<String>, need_all: bool) -> bool {
    if need_all {
        required.is_subset(present)
    } else {
        required.iter().any(|r| present.contains(r))
    }
}

/// asn1crypto names of key usage bits, in bit order.
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

/// The key usages of `cert` by name, `None` if the extension is absent.
/// A malformed extension counts as asserting nothing.
pub fn cert_key_usages(cert: &Cert) -> Option<BTreeSet<String>> {
    if !cert.has_extension(&hanko_core::asn1::oids::CE_KEY_USAGE) {
        return None;
    }
    let ku = cert.key_usage()?;
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
            .filter(|(f, _)| ku.0.contains(**f))
            .map(|(_, n)| n.to_owned())
            .collect(),
    )
}

/// The extended key usages of `cert` by name, `None` if the extension is
/// absent.
pub fn cert_extended_key_usages(cert: &Cert) -> Option<BTreeSet<String>> {
    if !cert.has_extension(&hanko_core::asn1::oids::CE_EXT_KEY_USAGE) {
        return None;
    }
    Some(
        cert.extended_key_usage()
            .unwrap_or_default()
            .iter()
            .map(key_purpose_name)
            .collect(),
    )
}

/// The asn1crypto name of a key purpose OID, or its dotted form.
pub fn key_purpose_name(oid: &ObjectIdentifier) -> String {
    let dotted = oid.to_string();
    KEY_PURPOSE_NAMES
        .iter()
        .find(|(o, _)| *o == dotted)
        .map_or(dotted, |(_, n)| (*n).to_owned())
}

/// Key purpose names known to asn1crypto (`KeyPurposeId._map`).
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
    ("1.3.6.1.4.1.311.10.3.10", "microsoft_qualified_subordination"),
    ("1.3.6.1.4.1.311.10.3.11", "microsoft_key_recovery"),
    ("1.3.6.1.4.1.311.10.3.12", "microsoft_document_signing"),
    ("1.3.6.1.4.1.311.10.3.13", "microsoft_lifetime_signing"),
    ("1.3.6.1.4.1.311.10.3.14", "microsoft_mobile_device_software"),
    ("1.3.6.1.4.1.311.20.2.2", "microsoft_smart_card_logon"),
    ("2.16.840.1.101.3.6.8", "piv_card_authentication"),
    ("2.16.840.1.101.3.6.7", "piv_content_signing"),
    ("1.3.6.1.5.2.3.4", "pkinit_kpclientauth"),
    ("1.3.6.1.5.2.3.5", "pkinit_kpkdc"),
    ("1.2.840.113583.1.1.5", "adobe_authentic_documents_trust"),
    ("2.16.840.1.101.3.8.7", "fpki_pivi_content_signing"),
];
