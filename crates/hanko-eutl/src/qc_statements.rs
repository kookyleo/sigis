// Derived from pyHanko `sign/ades/qualified_asn1.py` (MIT, see LICENSE-pyHanko).

//! ETSI EN 319 412-5 `QCStatements` (`pyhanko.sign.ades.qualified_asn1`).

use const_oid::ObjectIdentifier;
use der::asn1::Any;
use der::{Decode, Sequence};
use hanko_core::cert::Cert;

/// `id-pe-qcStatements`.
pub const QC_STATEMENTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.3");
/// `id-etsi-qcs-QcCompliance`.
pub const QC_COMPLIANCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.1");
/// `id-etsi-qcs-QcLimitValue`.
pub const QC_LIMIT_VALUE: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.2");
/// `id-etsi-qcs-QcRetentionPeriod`.
pub const QC_RETENTION_PERIOD: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.3");
/// `id-etsi-qcs-QcSSCD`.
pub const QC_SSCD: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.4");
/// `id-etsi-qcs-QcPDS`.
pub const QC_PDS: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.5");
/// `id-etsi-qcs-QcType`.
pub const QC_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.6");
/// `id-etsi-qcs-QcCClegislation`.
pub const QC_CC_LEGISLATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.7");
/// `id-etsi-qct-esign`.
pub const QCT_ESIGN: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.6.1");
/// `id-etsi-qct-eseal`.
pub const QCT_ESEAL: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.6.2");
/// `id-etsi-qct-web`.
pub const QCT_WEB: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1862.1.6.3");

/// One `QCStatement`.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct QcStatement {
    /// `statementId`.
    pub statement_id: ObjectIdentifier,
    /// `statementInfo`.
    pub statement_info: Option<Any>,
}

/// Error decoding QC statements.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed QC statements: {0}")]
pub struct QcStatementsError(pub String);

/// The QC statements of `cert` (empty if the extension is absent)
/// (`get_qc_statements`).
pub fn qc_statements(cert: &Cert) -> Result<Vec<QcStatement>, QcStatementsError> {
    let Some(exts) = cert.decoded().tbs_certificate().extensions() else {
        return Ok(Vec::new());
    };
    for ext in exts.iter() {
        if ext.extn_id != QC_STATEMENTS {
            continue;
        }
        return Vec::<QcStatement>::from_der(ext.extn_value.as_bytes())
            .map_err(|e| QcStatementsError(e.to_string()));
    }
    Ok(Vec::new())
}

/// Decode the `statementInfo` of a `QcType` statement.
pub fn qc_types(statement: &QcStatement) -> Result<Vec<ObjectIdentifier>, QcStatementsError> {
    match &statement.statement_info {
        Some(any) => any
            .decode_as::<Vec<ObjectIdentifier>>()
            .map_err(|e| QcStatementsError(e.to_string())),
        None => Err(QcStatementsError(
            "QcType statement without statementInfo".into(),
        )),
    }
}
