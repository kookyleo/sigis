// Derived from pyHanko `sign/signers/pdf_signer.py`
// (`perform_presign_validation`, `PreSignValidationStatus`),
// `sign/timestamps/api.py` (`TimeStamper.validation_paths`) and
// `sign/validation/dss.py` (`collect_validation_info`) (MIT, see
// LICENSE-pyHanko).

//! Collection of validation information (certificates, OCSP responses,
//! CRLs) for long-term validation (PAdES B-LT / B-LTA).
//!
//! pyHanko lets the certificate validator fetch revocation information and
//! records what it fetched in the `ValidationContext`. The Rust validator
//! (`sigis-pki-certvalidator`) performs no network access during validation, so
//! this module fetches first, with the context's fetchers (OCSP first, CRLs
//! when no OCSP response is available, as pyHanko's default policy does),
//! and then validates against a context extended with the fetched data.

use sigis_pki_certvalidator::{CertificateValidator, ValidationContext};
use sigis_pki_core::algorithms::{validate_signature, SignatureValidationContext};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};
use der::Encode;

/// Validation information collected before or after signing
/// (`PreSignValidationStatus`).
#[derive(Clone, Debug, Default)]
pub struct ValidationInfo {
    /// Validation paths (leaf first, trust anchor last).
    pub paths: Vec<Vec<Cert>>,
    /// DER OCSP responses.
    pub ocsps: Vec<Vec<u8>>,
    /// DER CRLs.
    pub crls: Vec<Vec<u8>>,
}

impl ValidationInfo {
    /// Merge `other` into `self`, removing duplicates.
    pub fn extend(&mut self, other: ValidationInfo) {
        for p in other.paths {
            if !self.paths.contains(&p) {
                self.paths.push(p);
            }
        }
        for o in other.ocsps {
            if !self.ocsps.contains(&o) {
                self.ocsps.push(o);
            }
        }
        for c in other.crls {
            if !self.crls.contains(&c) {
                self.crls.push(c);
            }
        }
    }
}

fn issued_by(cert: &Cert, issuer: &Cert) -> bool {
    if cert.issuer() != issuer.subject() {
        return false;
    }
    let tbs = match cert.decoded().tbs_certificate().to_der() {
        Ok(t) => t,
        Err(_) => return false,
    };
    validate_signature(
        cert.decoded().signature().raw_bytes(),
        &tbs,
        &issuer.public_key(),
        cert.decoded().signature_algorithm(),
        &SignatureValidationContext::default(),
    )
    .is_ok()
}

/// Build a path from `cert` to a trust anchor of `ctx`, using `pool` and
/// the context's other certificates. Returns the path leaf first.
pub fn build_path(ctx: &ValidationContext, cert: &Cert, pool: &[Cert]) -> Option<Vec<Cert>> {
    let anchors: Vec<Cert> = ctx.trust_anchors().iter().map(|a| a.cert().clone()).collect();
    let mut candidates: Vec<Cert> = pool.to_vec();
    candidates.extend(ctx.other_certs().iter().cloned());
    let mut path = vec![cert.clone()];
    for _ in 0..16 {
        let cur = path.last()?.clone();
        if anchors.contains(&cur) {
            return Some(path);
        }
        if let Some(a) = anchors.iter().find(|a| issued_by(&cur, a)) {
            path.push(a.clone());
            return Some(path);
        }
        let next = candidates
            .iter()
            .find(|c| !path.contains(c) && issued_by(&cur, c))?
            .clone();
        path.push(next);
    }
    None
}

/// Fetch revocation information for every certificate of `path` except
/// the trust anchor: an OCSP response if the certificate names a
/// responder and one can be fetched, CRLs otherwise.
pub fn fetch_revinfo(ctx: &ValidationContext, path: &[Cert], info: &mut ValidationInfo) {
    let fetchers = ctx.fetchers();
    for (i, cert) in path.iter().enumerate() {
        let Some(issuer) = path.get(i + 1) else {
            break;
        };
        if cert.is_self_issued() {
            continue;
        }
        let mut have_ocsp = false;
        if cert.declares_ocsp() {
            if let Some(f) = &fetchers.ocsp {
                if let Ok(resp) = f.fetch_ocsp(cert, issuer) {
                    if !info.ocsps.contains(&resp) {
                        info.ocsps.push(resp);
                    }
                    have_ocsp = true;
                }
            }
        }
        if !have_ocsp && cert.declares_crl() {
            if let Some(f) = &fetchers.crl {
                if let Ok(crls) = f.fetch_crls(cert) {
                    for c in crls {
                        if !info.crls.contains(&c) {
                            info.crls.push(c);
                        }
                    }
                }
            }
        }
    }
}

/// Extend `ctx` with extra certificates and revocation information.
pub fn extended_context(
    ctx: &ValidationContext,
    certs: &[Cert],
    info: &ValidationInfo,
) -> Result<ValidationContext> {
    let timing = ctx.timing();
    let mut b = ValidationContext::builder()
        .moment(timing.validation_time)
        .best_signature_time(timing.best_signature_time)
        .time_tolerance(timing.time_tolerance)
        .revinfo_policy(*ctx.revinfo_policy())
        .fetchers(ctx.fetchers().clone());
    for a in ctx.trust_anchors() {
        b = b.trust_anchor(a.clone());
    }
    for c in ctx.other_certs().iter().chain(certs) {
        b = b.other_cert(c.clone());
    }
    for o in &info.ocsps {
        b = b.ocsp_response(o.clone());
    }
    for c in &info.crls {
        b = b.crl(c.clone());
    }
    Ok(b.build()?)
}

/// Validate `cert` (with candidate intermediates `pool`), collecting the
/// revocation information needed along the way. Returns the path (leaf
/// first) and adds it and its revocation information to `info`.
pub fn validate_and_collect(
    ctx: &ValidationContext,
    cert: &Cert,
    pool: &[Cert],
    info: &mut ValidationInfo,
) -> Result<Vec<Cert>> {
    let path = build_path(ctx, cert, pool).ok_or_else(|| {
        HankoError::Validation(sigis_pki_core::errors::ValidationError::PathBuilding(
            "Unable to build a validation path for the certificate".into(),
        ))
    })?;
    fetch_revinfo(ctx, &path, info);
    let ext = extended_context(ctx, pool, info)?;
    CertificateValidator::new(&ext, cert.clone()).validate()?;
    if !info.paths.contains(&path) {
        info.paths.push(path.clone());
    }
    Ok(path)
}

/// Certificates embedded in a DER `OCSPResponse` (`enumerate_ocsp_certs`).
pub fn ocsp_certs(der_resp: &[u8]) -> Vec<Cert> {
    use der::Decode;
    let Ok(resp) = x509_ocsp::OcspResponse::from_der(der_resp) else {
        return Vec::new();
    };
    let Some(bytes) = resp.response_bytes else {
        return Vec::new();
    };
    let Ok(basic) = x509_ocsp::BasicOcspResponse::from_der(bytes.response.as_bytes()) else {
        return Vec::new();
    };
    basic
        .certs
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c.to_der().ok())
        .filter_map(|d| Cert::from_der(&d).ok())
        .collect()
}
