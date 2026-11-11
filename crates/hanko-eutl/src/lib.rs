// Derived from pyHanko `sign/validation/qualified/` (MIT, see LICENSE-pyHanko).

//! EU trusted lists (ETSI TS 119 612) and qualified status of signatures and
//! timestamps (`pyhanko.sign.validation.qualified`).
//!
//! | pyHanko module | Rust module |
//! | --- | --- |
//! | `qualified/tsp.py` | [`tsp`] |
//! | `qualified/q_status.py` | [`q_status`] |
//! | `qualified/assess.py` | [`assess`] |
//! | `qualified/eutl_parse.py` | [`parse`] |
//! | `qualified/eutl_fetch.py` | [`fetch`] |
//! | `sign/ades/qualified_asn1.py` | [`qc_statements`] |
//! | (signxml, lxml C14N) | [`xml`] |
//!
//! Owned by lane E (see `docs/hanko-lanes.md`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod assess;
pub mod fetch;
pub mod parse;
pub mod q_status;
pub mod qc_statements;
pub mod tsp;
pub mod util;
pub mod xml;

use hanko_certvalidator::ValidationPath;
use hanko_core::cert::Cert;
use hanko_core::errors::{HankoError, Result};
use hanko_core::time::Moment;

/// A parsed and signature-checked trusted list (`TrustedServiceProvider` set).
#[derive(Clone, Debug, Default)]
pub struct TrustedList {
    /// Service certificates with their qualification data.
    pub services: Vec<TrustService>,
}

/// One trust service entry.
#[derive(Clone, Debug)]
pub struct TrustService {
    /// Service digital identity.
    pub certs: Vec<Cert>,
    /// Service type URI.
    pub service_type: String,
}

/// Qualification of a certificate at a moment (`QualificationResult`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualificationResult {
    /// The certificate is qualified.
    pub qualified: bool,
    /// The key resides in a QSCD.
    pub qscd: Option<bool>,
}

/// Parse a trusted list and verify its XAdES signature against `signers`
/// (at the current time).
///
/// This is the simple interface; [`parse::trust_list_to_registry`] keeps the
/// full service definitions.
pub fn parse_trusted_list(xml: &[u8], signers: &[Cert]) -> Result<TrustedList> {
    let text = std::str::from_utf8(xml).map_err(|e| HankoError::Malformed(format!("trusted list: {e}")))?;
    let signed = parse::validate_and_extract_tl_data(text, signers, None)
        .map_err(|e| HankoError::Malformed(e.to_string()))?;
    let (sds, _errors) =
        parse::read_qualified_service_definitions(&signed).map_err(|e| HankoError::Malformed(e.to_string()))?;
    Ok(TrustedList {
        services: sds
            .into_iter()
            .map(|sd| TrustService {
                certs: sd.base_info.provider_certs,
                service_type: sd.base_info.service_type,
            })
            .collect(),
    })
}

/// Determine the qualified status of `cert` at `at` against the current
/// service definitions in `tl`.
///
/// The certificate counts as issued under a listed service if it is itself
/// listed (QTST) or was issued by a listed certificate (a one-step path, no
/// revocation checking); use [`assess::QualificationAssessor`] with a fully
/// validated path otherwise.
pub fn qualification(tl: &TrustedList, cert: &Cert, at: Moment) -> Result<QualificationResult> {
    let mut registry = tsp::TspRegistry::new();
    for svc in &tl.services {
        let base = tsp::BaseServiceInformation {
            service_type: svc.service_type.clone(),
            service_name: String::new(),
            valid_from: Moment::from_unix_secs(i64::MIN / 2),
            valid_until: None,
            provider_certs: svc.certs.clone(),
            additional_info_certificate_type: Default::default(),
            other_additional_info: Default::default(),
        };
        let sd = if svc.service_type == tsp::QTST_URI {
            tsp::QualifiedServiceInformation::qtst(base, [])
        } else {
            tsp::QualifiedServiceInformation::ca(base, [], None)
        };
        registry.register(sd);
    }
    let anchor_path = tl
        .services
        .iter()
        .flat_map(|s| s.certs.iter())
        .find_map(|ca| {
            if ca == cert {
                return Some(ValidationPath::new(
                    hanko_certvalidator::TrustAnchor::new(ca.clone()),
                    vec![],
                    Some(cert.clone()),
                ));
            }
            let auth = tsp::Authority::of_cert(ca);
            let issued = auth.is_potential_issuer_of(cert)
                && hanko_core::algorithms::validate_signature(
                    cert.decoded().signature().raw_bytes(),
                    &der::Encode::to_der(cert.decoded().tbs_certificate()).ok()?,
                    &ca.public_key(),
                    cert.decoded().signature_algorithm(),
                    &Default::default(),
                )
                .is_ok();
            issued.then(|| {
                ValidationPath::new(
                    hanko_certvalidator::TrustAnchor::new(ca.clone()),
                    vec![],
                    Some(cert.clone()),
                )
            })
        });
    let Some(path) = anchor_path else {
        return Ok(QualificationResult {
            qualified: false,
            qscd: None,
        });
    };
    let result = assess::QualificationAssessor::new(&registry)
        .check_entity_cert_qualified(&path, Some(at))
        .map_err(|e| HankoError::Unsupported(e.to_string()))?;
    Ok(QualificationResult {
        qualified: result.status.qualified,
        qscd: result
            .status
            .qualified
            .then(|| result.status.qc_key_security.is_qscd()),
    })
}
