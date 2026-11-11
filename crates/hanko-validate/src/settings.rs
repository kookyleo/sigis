// Derived from pyHanko `sign/validation/settings.py` (MIT, see LICENSE-pyHanko).

//! Validation settings (`pyhanko.sign.validation.settings`).

use std::collections::BTreeSet;

use hanko_core::cert::Cert;
use x509_cert::ext::pkix::KeyUsages;

/// Error raised when a certificate does not meet a key usage policy
/// (`InvalidCertificateError` in pyhanko-certvalidator).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidCertificateError(pub String);

/// Names of the key usage bits, as asn1crypto spells them.
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

/// The key usage bits of `cert`, named as asn1crypto names them.
pub fn key_usage_names(cert: &Cert) -> BTreeSet<String> {
    let Some(ku) = cert.key_usage() else {
        return BTreeSet::new();
    };
    let flags = [
        (KeyUsages::DigitalSignature, "digital_signature"),
        (KeyUsages::NonRepudiation, "non_repudiation"),
        (KeyUsages::KeyEncipherment, "key_encipherment"),
        (KeyUsages::DataEncipherment, "data_encipherment"),
        (KeyUsages::KeyAgreement, "key_agreement"),
        (KeyUsages::KeyCertSign, "key_cert_sign"),
        (KeyUsages::CRLSign, "crl_sign"),
        (KeyUsages::EncipherOnly, "encipher_only"),
        (KeyUsages::DecipherOnly, "decipher_only"),
    ];
    flags
        .iter()
        .filter(|(flag, _)| ku.0.contains(*flag))
        .map(|(_, name)| (*name).to_owned())
        .collect()
}

/// asn1crypto's names for well-known key purpose IDs (`KeyPurposeId._map`).
/// Unknown OIDs are rendered in dotted form, as asn1crypto does.
const KEY_PURPOSE_NAMES: &[(&str, &str)] = &[
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
    ("2.16.840.1.113730.4.1", "netscape_server_gated_crypto"),
    ("1.3.6.1.5.5.8.2.2", "ike_intermediate"),
    ("1.2.840.113583.1.1.5", "pdf_signing"),
    ("0.4.0.2231.3.0", "tsl_signing"),
];

/// asn1crypto's name of a key purpose ID (the dotted OID if unnamed).
pub fn key_purpose_name(oid: &str) -> String {
    KEY_PURPOSE_NAMES
        .iter()
        .find(|(dotted, _)| *dotted == oid)
        .map_or_else(|| oid.to_owned(), |(_, name)| (*name).to_owned())
}

/// The extended key usages of `cert`, named as asn1crypto names them.
pub fn extended_key_usage_names(cert: &Cert) -> Option<BTreeSet<String>> {
    cert.extended_key_usage().map(|ekus| {
        ekus.iter()
            .map(|oid| key_purpose_name(&oid.to_string()))
            .collect()
    })
}

fn match_usages(required: &BTreeSet<String>, present: &BTreeSet<String>, need_all: bool) -> bool {
    if need_all {
        required.is_subset(present)
    } else {
        !required.is_disjoint(present)
    }
}

fn rephrase<'a>(it: impl Iterator<Item = &'a String>) -> String {
    it.map(|s| s.replace('_', " ")).collect::<Vec<_>>().join(", ")
}

/// Key usage requirements (`KeyUsageConstraints`).
///
/// Key usages use the asn1crypto names (see [`KEY_USAGE_NAMES`]); extended
/// key usages use asn1crypto key purpose names or dotted OIDs (see
/// [`key_purpose_name`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct KeyUsageConstraints {
    /// All or some (see `match_all_key_usages`) of these key usages must be
    /// present. `None` or empty: any key usage is acceptable.
    pub key_usage: Option<BTreeSet<String>>,
    /// These key usages must not be present.
    pub key_usage_forbidden: Option<BTreeSet<String>>,
    /// Acceptable extended key usages. `None`: all are acceptable. An empty
    /// set bans all extended key usages.
    pub extd_key_usage: Option<BTreeSet<String>>,
    /// Require an extended key usage extension when `extd_key_usage` is set
    /// (default `true`).
    pub explicit_extd_key_usage_required: bool,
    /// All key usages in `key_usage` must be present (default `false`).
    pub match_all_key_usages: bool,
}

impl KeyUsageConstraints {
    /// Constraints with pyHanko's defaults (no requirements).
    pub fn new() -> Self {
        Self {
            explicit_extd_key_usage_required: true,
            ..Self::default()
        }
    }

    /// Require one of the given key usages, ban others.
    pub fn with_key_usage<'a>(
        key_usage: impl IntoIterator<Item = &'a str>,
        forbidden: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        Self {
            key_usage: Some(key_usage.into_iter().map(str::to_owned).collect()),
            key_usage_forbidden: Some(forbidden.into_iter().map(str::to_owned).collect()),
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

    /// Validate `cert`, treating the extra usages as asserted as well.
    pub fn validate_with_extra(
        &self,
        cert: &Cert,
        extra_key_usages: &BTreeSet<String>,
        extra_extd_key_usages: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let mut ku = key_usage_names(cert);
        ku.extend(extra_key_usages.iter().cloned());
        self.validate_asserted_key_usage(&ku)?;
        let mut eku = extended_key_usage_names(cert).unwrap_or_default();
        eku.extend(extra_extd_key_usages.iter().cloned());
        self.validate_asserted_extended_key_usage(&eku)
    }

    /// Check a set of asserted key usages (`validate_asserted_key_usage`).
    pub fn validate_asserted_key_usage(
        &self,
        asserted: &BTreeSet<String>,
    ) -> Result<(), InvalidCertificateError> {
        let key_usage = match &self.key_usage {
            Some(ku) if !ku.is_empty() => ku,
            _ => return Ok(()),
        };
        let empty = BTreeSet::new();
        let forbidden = self.key_usage_forbidden.as_ref().unwrap_or(&empty);
        let banned: BTreeSet<String> = asserted.intersection(forbidden).cloned().collect();
        if !banned.is_empty() {
            return Err(InvalidCertificateError(format!(
                "The active key usage policy explicitly bans certificates used for {}.",
                rephrase(banned.iter())
            )));
        }
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
