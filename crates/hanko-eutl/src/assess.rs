// Derived from pyHanko `sign/validation/qualified/assess.py` and the
// `QualificationRequirements` part of `sign/validation/policy_decl.py`
// (MIT, see LICENSE-pyHanko).

//! Qualification assessment (`pyhanko.sign.validation.qualified.assess`).

use std::collections::BTreeSet;

use hanko_certvalidator::ValidationPath;
use hanko_core::cert::Cert;
use hanko_core::time::Moment;
use hanko_validate::errors::SignatureValidationError;
use hanko_validate::report::AdesIndeterminate;
use x509_cert::ext::pkix::{InhibitAnyPolicy, PolicyConstraints, PolicyMappings};

use crate::q_status::{QcPrivateKeyManagementType, QualificationResult, QualifiedStatus};
use crate::qc_statements::{self, QcStatementsError};
use crate::tsp::{
    BaseServiceInformation, QcCertType, Qualification, QualifiedServiceInformation, Qualifier,
    TrustedServiceType, TspRegistry,
};

/// Start of eIDAS: 2016-07-01T00:00:00 Europe/Brussels (CEST, UTC+2).
pub const EIDAS_START_DATE: Moment = Moment::from_unix_secs(1_467_324_000);
/// Pre-eIDAS QCP policy OID.
pub const PRE_EIDAS_QCP_POLICY: &str = "0.4.0.1456.1.1";
/// Pre-eIDAS QCP+ policy OID.
pub const PRE_EIDAS_QCP_PLUS_POLICY: &str = "0.4.0.1456.1.2";
const ANY_POLICY: &str = "2.5.29.32.0";

/// The default status of a certificate that is not qualified
/// (`UNQUALIFIED`).
pub const UNQUALIFIED: QualifiedStatus = QualifiedStatus {
    qualified: false,
    qc_type: QcCertType::QcEsign,
    qc_key_security: QcPrivateKeyManagementType::Unknown,
};

/// Errors of the qualification assessment.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QualificationError {
    /// Malformed QC statements.
    #[error(transparent)]
    QcStatements(#[from] QcStatementsError),
    /// A case pyHanko does not support (raises `NotImplementedError`).
    #[error("not supported: {0}")]
    NotSupported(String),
}

/// Requirements imposed by a qualification policy
/// (`QualificationRequirements`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualificationRequirements {
    /// Permitted key management types (`None`: no restriction).
    pub permit_key_mgmt_types: Option<BTreeSet<QcPrivateKeyManagementType>>,
    /// Permitted certificate types (`None`: no restriction). Defaults to
    /// eSign and eSeal.
    pub permit_cert_types: Option<BTreeSet<QcCertType>>,
    /// Require the end entity to be directly listed as a service of this
    /// type.
    pub require_service_type: Option<RequiredServiceType>,
}

impl Default for QualificationRequirements {
    fn default() -> Self {
        Self {
            permit_key_mgmt_types: None,
            permit_cert_types: Some(
                [QcCertType::QcEsign, QcCertType::QcEseal]
                    .into_iter()
                    .collect(),
            ),
            require_service_type: None,
        }
    }
}

/// Required service type: a trusted service type or a raw URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequiredServiceType {
    /// A trusted service type.
    Type(TrustedServiceType),
    /// A service type URI.
    Uri(String),
}

/// User-domain policies on `path` (`ValidationPath.qualified_policies`).
///
/// `hanko-certvalidator` does not expose the RFC 5280 valid policy tree yet,
/// so this computes a subset of it: a policy qualifies if the end-entity
/// certificate asserts it and every intermediate asserts it (or
/// `anyPolicy`, unless a policy constraint or `inhibitAnyPolicy` extension is
/// present on the path). Paths with policy mappings yield `None`. Being a
/// subset, it can only make fewer certificates qualified than pyHanko does.
pub fn path_qualified_policies(path: &ValidationPath) -> Option<BTreeSet<String>> {
    let mut certs: Vec<&Cert> = path.intermediates().iter().collect();
    let leaf = path.leaf().filter(|l| *l != path.trust_anchor().cert())?;
    certs.push(leaf);
    let mut restrictive = false;
    for c in &certs {
        if matches!(c.extension::<PolicyMappings>(), Ok(Some(_)) | Err(_)) {
            return None;
        }
        if !matches!(c.extension::<PolicyConstraints>(), Ok(None))
            || !matches!(c.extension::<InhibitAnyPolicy>(), Ok(None))
        {
            restrictive = true;
        }
    }
    let policies =
        |c: &Cert| -> Option<BTreeSet<String>> { crate::util::certificate_policy_oids(c) };
    let mut result = policies(leaf)?;
    result.remove(ANY_POLICY);
    for c in &certs[..certs.len() - 1] {
        let p = policies(c)?;
        if !restrictive && p.contains(ANY_POLICY) {
            continue;
        }
        result.retain(|oid| p.contains(oid));
    }
    Some(result)
}

/// Assess qualification against a registry (`QualificationAssessor`).
#[derive(Clone, Debug)]
pub struct QualificationAssessor<'a> {
    registry: &'a TspRegistry,
}

impl<'a> QualificationAssessor<'a> {
    /// New assessor.
    pub fn new(registry: &'a TspRegistry) -> Self {
        Self { registry }
    }

    /// Preliminary status from the certificate's QC statements
    /// (`_process_qc_statements`).
    pub fn process_qc_statements(cert: &Cert) -> Result<QualifiedStatus, QualificationError> {
        let mut qualified = false;
        let mut key_secure = false;
        let mut qc_type = QcCertType::QcEsign;
        for st in qc_statements::qc_statements(cert)? {
            if st.statement_id == qc_statements::QC_COMPLIANCE {
                qualified = true;
            } else if st.statement_id == qc_statements::QC_SSCD {
                key_secure = true;
            } else if st.statement_id == qc_statements::QC_TYPE {
                let types = qc_statements::qc_types(&st)?;
                if types.len() != 1 {
                    return Err(QualificationError::NotSupported(
                        "only support exactly 1 qc_type".into(),
                    ));
                }
                qc_type = match types[0] {
                    qc_statements::QCT_ESIGN => QcCertType::QcEsign,
                    qc_statements::QCT_ESEAL => QcCertType::QcEseal,
                    qc_statements::QCT_WEB => QcCertType::QcWeb,
                    other => {
                        return Err(QualificationError::NotSupported(format!(
                            "'{other}' is not a valid QcCertType"
                        )))
                    }
                };
            }
        }
        Ok(QualifiedStatus {
            qualified,
            qc_type,
            qc_key_security: if key_secure && qualified {
                QcPrivateKeyManagementType::Qscd
            } else {
                QcPrivateKeyManagementType::Unknown
            },
        })
    }

    /// `_check_cd_applicable`.
    pub fn check_cd_applicable(sd: &BaseServiceInformation, putative: &QualifiedStatus) -> bool {
        sd.additional_info_certificate_type.is_empty()
            || sd
                .additional_info_certificate_type
                .contains(&putative.qc_type)
    }

    /// `_apply_sd_qualifications`.
    pub fn apply_sd_qualifications(
        cert: &Cert,
        prelim: QualifiedStatus,
        qualifications: &[Qualification],
    ) -> QualifiedStatus {
        let mut applicable = BTreeSet::new();
        for q in qualifications {
            if q.criteria_list.matches(cert) {
                applicable.extend(q.qualifiers.iter().copied());
            }
        }
        Self::final_status(prelim, &applicable)
    }

    /// Apply qualifiers to a preliminary status (`_final_status`).
    pub fn final_status(prelim: QualifiedStatus, quals: &BTreeSet<Qualifier>) -> QualifiedStatus {
        let qualified = if quals.contains(&Qualifier::NotQualified)
            || quals.contains(&Qualifier::LegalPerson)
        {
            false
        } else if quals.contains(&Qualifier::QcStatement) {
            true
        } else {
            prelim.qualified
        };
        let qc_type = if quals.contains(&Qualifier::ForWsa) {
            QcCertType::QcWeb
        } else if quals.contains(&Qualifier::ForEsig) {
            QcCertType::QcEsign
        } else if quals.contains(&Qualifier::ForEseal) {
            QcCertType::QcEseal
        } else {
            prelim.qc_type
        };
        let key = if !qualified
            || quals.contains(&Qualifier::NoSscd)
            || quals.contains(&Qualifier::NoQscd)
        {
            QcPrivateKeyManagementType::Unknown
        } else if quals.contains(&Qualifier::QscdManagedOnBehalf) {
            QcPrivateKeyManagementType::QscdDelegated
        } else if quals.contains(&Qualifier::WithSscd) || quals.contains(&Qualifier::WithQscd) {
            QcPrivateKeyManagementType::Qscd
        } else {
            prelim.qc_key_security
        };
        QualifiedStatus {
            qualified,
            qc_type,
            qc_key_security: key,
        }
    }

    /// Qualified status of the end-entity certificate of `path`, against the
    /// service definitions valid at `moment` (now if `None`)
    /// (`check_entity_cert_qualified`).
    pub fn check_entity_cert_qualified(
        &self,
        path: &ValidationPath,
        moment: Option<Moment>,
    ) -> Result<QualificationResult, QualificationError> {
        let cert = path.leaf().unwrap_or(path.trust_anchor().cert());
        let mut prelim = Self::process_qc_statements(cert)?;
        let reference_time = moment.unwrap_or_else(Moment::now);
        if reference_time < EIDAS_START_DATE {
            if let Some(policies) = path_qualified_policies(path).filter(|p| !p.is_empty()) {
                if policies.contains(PRE_EIDAS_QCP_PLUS_POLICY) {
                    prelim.qualified = true;
                    if !prelim.qc_key_security.is_qscd() {
                        prelim.qc_key_security = QcPrivateKeyManagementType::QscdByPolicy;
                    }
                } else if policies.contains(PRE_EIDAS_QCP_POLICY) {
                    prelim.qualified = true;
                }
            }
        }
        let mut found: Vec<(&QualifiedServiceInformation, QualifiedStatus)> = Vec::new();
        for sd in self
            .registry
            .applicable_tsps_on_path(path, Some(reference_time))
        {
            let putative = Self::apply_sd_qualifications(cert, prelim, &sd.qualifications);
            if Self::check_cd_applicable(&sd.base_info, &putative) {
                found.push((sd, putative));
            }
        }
        let uniq: BTreeSet<QualifiedStatus> = found.iter().map(|(_, s)| *s).collect();
        if found.len() == 1 || uniq.len() == 1 {
            let (sd, st) = &found[0];
            Ok(QualificationResult {
                status: *st,
                service_definition: Some((*sd).clone()),
            })
        } else {
            Ok(QualificationResult {
                status: UNQUALIFIED,
                service_definition: None,
            })
        }
    }
}

/// Error raised by a qualification policy violation
/// (`QualificationPolicyError`, a `SignatureValidationError`).
pub type QualificationPolicyError = SignatureValidationError;

fn human_friendly(cert: &Cert) -> String {
    cert.subject().to_string()
}

/// Enforce `requirements` on a qualification result (`enforce_requirements`).
pub fn enforce_requirements(
    requirements: &QualificationRequirements,
    result: &QualificationResult,
    path: &ValidationPath,
) -> Result<(), QualificationPolicyError> {
    let cert = path.leaf().unwrap_or(path.trust_anchor().cert());
    let status = result.status;
    if !status.qualified {
        return Err(SignatureValidationError::with(
            format!("Certificate for {} is not qualified", human_friendly(cert)),
            AdesIndeterminate::SIG_CONSTRAINTS_FAILURE,
        ));
    }
    let sd = result.service_definition.as_ref().ok_or_else(|| {
        SignatureValidationError::with(
            "Qualified status without service definition",
            AdesIndeterminate::SIG_CONSTRAINTS_FAILURE,
        )
    })?;
    let mut errs: Vec<String> = Vec::new();
    if let Some(req) = &requirements.require_service_type {
        let uri = &sd.base_info.service_type;
        let ok = match req {
            RequiredServiceType::Uri(u) => u == uri,
            RequiredServiceType::Type(t) => *t == TrustedServiceType::from_service_type_uri(uri),
        };
        let pkix_len = path.len() - 1;
        if !ok || pkix_len > 0 {
            errs.push(format!(
                "Certificate {} is not directly trusted as a service of type {req:?}.",
                human_friendly(cert)
            ));
        }
    }
    if let Some(types) = &requirements.permit_cert_types {
        if !types.contains(&status.qc_type) {
            errs.push(format!(
                "Certificate for {} is qualified,but the type {} is not permitted by the requirements. Must be one of {}.",
                human_friendly(cert),
                status.qc_type.name(),
                types.iter().map(|t| t.name()).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    if let Some(types) = &requirements.permit_key_mgmt_types {
        if !types.contains(&status.qc_key_security) {
            errs.push(format!(
                "Certificate for {} is qualified,but the key management type {} is not permitted by the requirements. Must be one of {}.",
                human_friendly(cert),
                status.qc_key_security.name(),
                types.iter().map(|t| t.name()).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(SignatureValidationError::with(
            errs.join("; "),
            AdesIndeterminate::SIG_CONSTRAINTS_FAILURE,
        ))
    }
}
