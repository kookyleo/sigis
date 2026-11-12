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

use der::Encode;
use sigis_pki_certvalidator::{CertificateValidator, ValidationContext};
use sigis_pki_core::algorithms::{validate_signature, SignatureValidationContext};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};

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

/// Build a path from `cert` to a trust anchor of `ctx`, using local candidates
/// first and fetching missing issuers if necessary. Returns the path leaf first.
pub fn build_path(ctx: &ValidationContext, cert: &Cert, pool: &[Cert]) -> Option<Vec<Cert>> {
    build_local_path(ctx, cert, pool).or_else(|| fetch_missing_issuer_path(ctx, cert, pool))
}

fn build_local_path(ctx: &ValidationContext, cert: &Cert, pool: &[Cert]) -> Option<Vec<Cert>> {
    let anchors: Vec<Cert> = ctx
        .trust_anchors()
        .iter()
        .map(|a| a.cert().clone())
        .collect();
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

/// Fetch only after local path construction fails. Candidate issuers must
/// actually verify the child's signature; fetched certificates never become
/// trust anchors. Full certificate policy validation remains a separate step.
fn fetch_missing_issuer_path(
    ctx: &ValidationContext,
    cert: &Cert,
    pool: &[Cert],
) -> Option<Vec<Cert>> {
    const MAX_DEPTH: usize = 16;
    const MAX_NODES: usize = 128;
    const MAX_FETCHED_CERTIFICATES: usize = 256;

    let fetcher = ctx.fetchers().cert.as_ref()?;
    let anchors: Vec<Cert> = ctx
        .trust_anchors()
        .iter()
        .map(|anchor| anchor.cert().clone())
        .collect();
    let mut candidates = pool.to_vec();
    candidates.extend(ctx.other_certs().iter().cloned());
    let mut scheduled = vec![cert.clone()];
    let mut pending = std::collections::VecDeque::from([vec![cert.clone()]]);
    let mut fetched_count = 0;
    while let Some(path) = pending.pop_front() {
        let current = path.last()?;
        if anchors.contains(current) {
            return Some(path);
        }
        if path.len() >= MAX_DEPTH {
            continue;
        }
        if let Some(anchor) = anchors.iter().find(|anchor| issued_by(current, anchor)) {
            let mut completed = path;
            completed.push(anchor.clone());
            return Some(completed);
        }
        if fetched_count < MAX_FETCHED_CERTIFICATES {
            if let Ok(issuers) = fetcher.fetch_issuers(current) {
                for issuer in issuers
                    .into_iter()
                    .take(MAX_FETCHED_CERTIFICATES - fetched_count)
                {
                    fetched_count += 1;
                    if !candidates.contains(&issuer) {
                        candidates.push(issuer);
                    }
                }
            }
        }
        for issuer in &candidates {
            if scheduled.len() >= MAX_NODES {
                break;
            }
            if !scheduled.contains(issuer) && issued_by(current, issuer) {
                scheduled.push(issuer.clone());
                let mut next = path.clone();
                next.push(issuer.clone());
                pending.push_back(next);
            }
        }
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
    // Clone the caller's complete policy: rebuilding with a builder loses
    // algorithm/freshness policies, trust managers, AC targets and assertions.
    Ok(ctx.with_revinfo(
        certs,
        info.crls.iter().map(Vec::as_slice),
        info.ocsps.iter().map(Vec::as_slice),
    )?)
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
    let mut staged = info.clone();
    fetch_revinfo(ctx, &path, &mut staged);
    // Fetched issuers are candidate intermediates in the cloned context, not
    // anchors. Preserve all caller policies and let the native validator decide.
    let mut candidates = pool.to_vec();
    candidates.extend(path.iter().cloned());
    let ext = extended_context(ctx, &candidates, &staged)?;
    let validated = CertificateValidator::new(&ext, cert.clone()).validate()?;
    let path: Vec<Cert> = validated.certs().into_iter().rev().cloned().collect();
    if !staged.paths.contains(&path) {
        staged.paths.push(path.clone());
    }
    *info = staged;
    Ok(path)
}

/// Validate the attribute certificates embedded in a CMS certificate set
/// or in `signer-attributes-v2`, collecting their AA paths and revocation
/// information for the DSS (`_perform_presign_ac_validation`).
///
/// `holder` is the signing certificate and must match every AC. The
/// context supplies the AA trust policy independently of the signer's PKI.
/// Results and collected information are committed only if every AC
/// validates, so a rejected AC cannot contribute trusted DSS material.
///
/// The current fetcher traits accept X.509 certificates only. AA path
/// revocation information is fetched normally; AC-specific responses must
/// already be supplied in `ctx`. Missing mandatory AC revocation evidence
/// is rejected by the lower validator rather than treated as valid.
pub fn validate_and_collect_attribute_certs(
    ctx: &ValidationContext,
    holder: &Cert,
    pool: &[Cert],
    attribute_certs: &[Vec<u8>],
    info: &mut ValidationInfo,
) -> Result<Vec<sigis_pki_certvalidator::ac::AcValidationResult>> {
    use sigis_pki_certvalidator::ac::{validate_ac, AttrCert};

    if attribute_certs.is_empty() {
        return Ok(Vec::new());
    }
    let mut staged = info.clone();
    for response in ctx.ocsps() {
        if !staged.ocsps.iter().any(|existing| existing == response) {
            staged.ocsps.push(response.to_vec());
        }
    }
    for crl in ctx.crls() {
        if !staged.crls.iter().any(|existing| existing == crl) {
            staged.crls.push(crl.to_vec());
        }
    }
    let ctx = ctx.with_other_certs(pool);
    let mut candidates = pool.to_vec();
    let mut results = Vec::new();
    for der in attribute_certs {
        let ac = AttrCert::from_der(der).map_err(|error| {
            HankoError::Signing(format!(
                "An attribute certificate could not be validated: {error}"
            ))
        })?;
        // Fetch evidence for candidate AA paths before asking validate_ac
        // to enforce the holder, AA usage/controls, signature and AC policy.
        // Selection and trust decisions remain with the lower validator.
        if let Some(issuer_name) = ac.issuer_name() {
            for issuer in ctx
                .other_certs()
                .iter()
                .filter(|cert| cert.subject() == &issuer_name)
            {
                if let Some(path) = build_path(&ctx, issuer, &candidates) {
                    fetch_revinfo(&ctx, &path, &mut staged);
                    // Keep fetched AA intermediates available to native AC
                    // validation. Fetching them twice can exhaust the caller's
                    // shared request budget, and does not grant them trust.
                    for cert in path {
                        if !candidates.contains(&cert) {
                            candidates.push(cert);
                        }
                    }
                }
            }
        }
        let extended = extended_context(&ctx, &candidates, &staged)?;
        let result = validate_ac(&extended, der, Some(holder)).map_err(|error| {
            HankoError::Signing(format!(
                "An attribute certificate could not be validated: {error}"
            ))
        })?;
        let path: Vec<Cert> = result.aa_path.certs().into_iter().rev().cloned().collect();
        if !staged.paths.contains(&path) {
            staged.paths.push(path);
        }
        results.push(result);
    }
    *info = staged;
    Ok(results)
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
