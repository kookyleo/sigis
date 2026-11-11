// Partly derived from pyhanko-certvalidator `validate.py` and `__init__.py`
// (MIT, see LICENSE-pyHanko).

//! Path building and validation.
//!
//! Paths are built here by name chaining, as pyhanko-certvalidator does. RFC
//! 5280 path validation is delegated to `certval`, with its own revocation
//! checking and network access turned off. This module adds what
//! pyhanko-certvalidator layers on top: validity reporting per certificate,
//! the algorithm usage policy, and offline revocation checking under the
//! configured revocation and freshness policies.

use certval::{
    validate_path_rfc5280, CertFile, CertVector, CertificationPath, CertificationPathResults,
    CertificationPathSettings, ExtensionProcessing, ObjectIdentifierSet, PDVCertificate,
    PDVTrustAnchorChoice, PathValidationStatus, PkiEnvironment, TaSource, TimeOfInterest,
    EXTS_OF_INTEREST,
};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};

use super::authority::{Cert, TrustAnchor};
use super::context::ValidationContext;
use super::path::ValidationPath;
use super::policy::PkixValidationParams;
use super::revinfo;
use hanko_core::errors::ValidationError;

fn cv_err(context: &str, e: certval::Error) -> ValidationError {
    ValidationError::PathValidation(format!("{context}: {e:?}"))
}

fn settings(
    ctx: &ValidationContext,
    time_of_interest: TimeOfInterest,
    enforce_ta_validity: bool,
    params: Option<&PkixValidationParams>,
) -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(time_of_interest);
    // Revocation is handled by `revinfo`; nothing is fetched.
    cps.set_check_revocation_status(false);
    cps.set_check_ocsp_from_aia(false);
    cps.set_retrieve_from_aia_sia_http(false);
    cps.set_check_crldp_http(false);
    cps.set_enforce_trust_anchor_validity(enforce_ta_validity);
    cps.set_min_rsa_modulus_bits(
        u16::try_from(ctx.algorithm_policy.min_rsa_key_size()).unwrap_or(u16::MAX),
    );
    if let Some(p) = params {
        cps.set_initial_explicit_policy_indicator(p.initial_explicit_policy);
        cps.set_initial_policy_mapping_inhibit_indicator(p.initial_policy_mapping_inhibit);
        cps.set_initial_inhibit_any_policy_indicator(p.initial_any_policy_inhibit);
        if !p.user_initial_policy_set.is_empty() {
            let set: ObjectIdentifierSet = p.user_initial_policy_set.iter().copied().collect();
            cps.set_initial_policy_set_from_oid_set(set);
        }
    }
    cps
}

fn environment(ctx: &ValidationContext) -> Result<PkiEnvironment, ValidationError> {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut tas = TaSource::new();
    for anchor in &ctx.trust_anchors {
        tas.push(CertFile {
            filename: String::new(),
            bytes: anchor.cert().der().to_vec(),
        });
    }
    tas.initialize().map_err(|e| cv_err("trust anchors", e))?;
    pe.add_trust_anchor_source(Box::new(tas));
    Ok(pe)
}

fn pdv_cert(cert: &Cert) -> Result<PDVCertificate, ValidationError> {
    let mut pdv = PDVCertificate::try_from(cert.der())
        .map_err(|e| ValidationError::Malformed(format!("certificate: {e}")))?;
    pdv.parse_extensions(EXTS_OF_INTEREST);
    Ok(pdv)
}

/// The authority key identifier of `cert`, if present.
pub(crate) fn authority_key_id(cert: &Cert) -> Option<Vec<u8>> {
    cert.extension::<AuthorityKeyIdentifier>()
        .ok()
        .flatten()
        .and_then(|(_, aki)| aki.key_identifier)
        .map(|k| k.as_bytes().to_vec())
}

/// The subject key identifier of `cert`, if present.
pub(crate) fn subject_key_id(cert: &Cert) -> Option<Vec<u8>> {
    cert.extension::<SubjectKeyIdentifier>()
        .ok()
        .flatten()
        .map(|(_, ski)| ski.0.as_bytes().to_vec())
}

/// Could `issuer` have issued `cert`? Names must chain (RFC 5280 name
/// comparison); if both key identifiers are present they must agree.
fn may_have_issued(issuer: &Cert, cert: &Cert) -> bool {
    if !certval::compare_names(issuer.subject(), cert.issuer()) {
        return false;
    }
    let aki = cert
        .extension::<AuthorityKeyIdentifier>()
        .ok()
        .flatten()
        .and_then(|(_, aki)| aki.key_identifier);
    let ski = issuer
        .extension::<SubjectKeyIdentifier>()
        .ok()
        .flatten()
        .map(|(_, ski)| ski.0);
    match (aki, ski) {
        (Some(a), Some(s)) => a == s,
        _ => true,
    }
}

const MAX_PATH_DEPTH: usize = 16;
const MAX_PATHS: usize = 64;

struct PathSearch<'a> {
    ctx: &'a ValidationContext,
    leaf: &'a Cert,
    /// Certificates available for chaining: the context's, plus fetched ones.
    pool: Vec<Cert>,
    /// Certificates whose AIA issuers were already fetched.
    fetched_for: Vec<Cert>,
}

impl PathSearch<'_> {
    fn has_issuer(&self, current: &Cert) -> bool {
        self.ctx
            .trust_anchors
            .iter()
            .any(|a| a.cert() != current && may_have_issued(a.cert(), current))
            || self
                .pool
                .iter()
                .any(|c| c != current && may_have_issued(c, current))
    }

    /// Fetch issuer certificates through AIA when none is known
    /// (`fetch_missing_potential_issuers`). Fetch failures are ignored.
    fn fetch_missing(&mut self, current: &Cert) {
        let Some(fetcher) = self.ctx.fetchers.cert.as_ref() else {
            return;
        };
        if self.fetched_for.contains(current) || self.has_issuer(current) {
            return;
        }
        self.fetched_for.push(current.clone());
        if let Ok(certs) = fetcher.fetch_issuers(current) {
            for c in certs {
                if !self.pool.contains(&c) {
                    self.pool.push(c);
                }
            }
        }
    }

    fn extend(&mut self, current: &Cert, chain: &mut Vec<Cert>, out: &mut Vec<ValidationPath>) {
        if out.len() >= MAX_PATHS {
            return;
        }
        self.fetch_missing(current);
        for anchor in &self.ctx.trust_anchors {
            if anchor.cert() != current && may_have_issued(anchor.cert(), current) {
                let intermediates = chain.iter().rev().cloned().collect();
                out.push(ValidationPath::new(
                    anchor.clone(),
                    intermediates,
                    Some(self.leaf.clone()),
                ));
            }
        }
        if chain.len() >= MAX_PATH_DEPTH {
            return;
        }
        let candidates: Vec<Cert> = self
            .pool
            .iter()
            .filter(|candidate| {
                // asn1crypto cannot index a certificate whose subject fails
                // string preparation.
                crate::names::check_name(candidate.subject()).is_ok()
                    && *candidate != self.leaf
                    && !chain.contains(candidate)
                    && !self.ctx.trust_anchors.iter().any(|a| a.cert() == *candidate)
                    && may_have_issued(candidate, current)
            })
            .cloned()
            .collect();
        for candidate in candidates {
            chain.push(candidate.clone());
            self.extend(&candidate, chain, out);
            chain.pop();
        }
    }
}

/// Build candidate paths from `leaf` to the context's trust anchors
/// (`CertificationPathBuilder` in pyhanko-certvalidator).
///
/// Paths are built by name chaining, checking key identifiers when present.
/// Signatures, validity and constraints are checked by [`validate_path`], so
/// that a broken path is reported as a validation error, as in pyHanko.
pub fn build_paths(
    ctx: &ValidationContext,
    leaf: &Cert,
) -> Result<Vec<ValidationPath>, ValidationError> {
    if let Some(anchor) = ctx.trust_anchors.iter().find(|a| a.cert() == leaf) {
        return Ok(vec![ValidationPath::new(
            anchor.clone(),
            Vec::new(),
            Some(leaf.clone()),
        )]);
    }
    let mut paths = Vec::new();
    let mut search = PathSearch {
        ctx,
        leaf,
        pool: ctx.other_certs.clone(),
        fetched_for: Vec::new(),
    };
    search.extend(leaf, &mut Vec::new(), &mut paths);
    if paths.is_empty() {
        return Err(ValidationError::PathBuilding(format!(
            "Unable to build a validation path for the certificate \"{}\" - no issuer matching \"{}\" was found",
            certval::name_to_string(leaf.subject()),
            certval::name_to_string(leaf.issuer()),
        )));
    }
    Ok(paths)
}

fn check_validity(
    ctx: &ValidationContext,
    cert: &Cert,
    description: &str,
) -> Result<(), ValidationError> {
    let t = ctx.timing.validation_time;
    let tol = ctx.timing.time_tolerance;
    if t.minus(tol) > cert.not_after() {
        return Err(ValidationError::Expired {
            msg: format!(
                "The path could not be validated because {description} expired {}",
                cert.not_after()
            ),
        });
    }
    if t.plus(tol) < cert.not_before() {
        return Err(ValidationError::NotYetValid {
            msg: format!(
                "The path could not be validated because {description} is not valid until {}",
                cert.not_before()
            ),
        });
    }
    Ok(())
}

fn map_status(status: PathValidationStatus) -> ValidationError {
    use PathValidationStatus as S;
    let msg = |what: &str| format!("The path could not be validated because {what}");
    match status {
        S::InvalidNotAfterDate => ValidationError::Expired {
            msg: msg("a certificate in the path expired"),
        },
        S::InvalidNotBeforeDate => ValidationError::NotYetValid {
            msg: msg("a certificate in the path is not yet valid"),
        },
        S::NoPathsFound | S::MissingTrustAnchor | S::MissingTrustAnchorName => {
            ValidationError::PathBuilding(msg("no path to a trust anchor was found"))
        }
        S::SignatureVerificationFailure => {
            ValidationError::PathValidation(msg("a signature in the path could not be verified"))
        }
        other => ValidationError::PathValidation(msg(&format!(
            "RFC 5280 path validation failed ({other:?})"
        ))),
    }
}

/// A failed path validation with the context pyHanko attaches to its
/// exceptions (`original_path`, `is_ee_cert`, `is_side_validation`,
/// `expired_dt` / `revocation_dt`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathFailure {
    /// The error.
    pub error: ValidationError,
    /// The path on which validation failed, if any.
    pub path: Option<ValidationPath>,
    /// The failing certificate is the end-entity certificate of the path.
    pub is_ee_cert: bool,
    /// The failure happened while validating revocation information signers.
    pub is_side_validation: bool,
    /// Expiry or revocation time, if relevant.
    pub time_horizon: Option<hanko_core::time::Moment>,
    /// The certificate itself is unsuitable (`InvalidCertificateError`), for
    /// example self-signed but not trusted.
    pub invalid_certificate: bool,
}

impl PathFailure {
    fn plain(error: ValidationError, path: Option<ValidationPath>) -> Self {
        Self {
            error,
            path,
            is_ee_cert: false,
            is_side_validation: false,
            time_horizon: None,
            invalid_certificate: false,
        }
    }
}

/// Port of `find_valid_path`: build paths for `cert` and return the first
/// that validates. On failure, report the error pyhanko-certvalidator would
/// raise: a single candidate's error, else the last error that is not about
/// a signature, else the first error. If no path can be built and the
/// certificate is self-issued, the failure is an `InvalidCertificateError`.
pub fn find_valid_path(
    ctx: &ValidationContext,
    cert: &Cert,
    params: Option<&PkixValidationParams>,
) -> Result<ValidationPath, Box<PathFailure>> {
    // asn1crypto cannot compare names that fail string preparation, so
    // pyhanko-certvalidator fails with a `ValueError` on such certificates.
    for name in [cert.subject(), cert.issuer()] {
        if let Err(e) = crate::names::check_name(name) {
            return Err(Box::new(PathFailure::plain(ValidationError::Malformed(e), None)));
        }
    }
    let paths = match build_paths(ctx, cert) {
        Ok(p) => p,
        Err(e) => {
            if cert.is_self_issued() {
                let mut f = PathFailure::plain(
                    ValidationError::PathValidation(format!(
                        "The X.509 certificate provided is self-signed - \"{}\"",
                        certval::name_to_string(cert.subject())
                    )),
                    None,
                );
                f.invalid_certificate = true;
                return Err(Box::new(f));
            }
            return Err(Box::new(PathFailure::plain(e, None)));
        }
    };
    let mut failures = Vec::new();
    for path in paths {
        match validate_path_qualified(ctx, &path, params) {
            Ok(p) => return Ok(p),
            Err(f) => failures.push(f),
        }
    }
    if failures.len() > 1 {
        if let Some(pos) = failures
            .iter()
            .rposition(|f| !f.error.to_string().contains("signature"))
        {
            return Err(failures.swap_remove(pos));
        }
    }
    let mut it = failures.into_iter();
    Err(it.next().unwrap_or_else(|| {
        Box::new(PathFailure::plain(
            ValidationError::PathBuilding("no candidate paths".into()),
            None,
        ))
    }))
}

/// Validate `path` at the context's time of interest (port of `validate_path`).
///
/// This covers RFC 5280 validation, the algorithm usage policy, and revocation
/// checking with the supplied CRLs and OCSP responses.
pub fn validate_path(
    ctx: &ValidationContext,
    path: &ValidationPath,
    params: Option<&PkixValidationParams>,
) -> Result<(), ValidationError> {
    validate_path_at_depth(ctx, path, params, &[])
}

/// Maximum nesting of CRL signer path validations.
pub(crate) const MAX_REVINFO_DEPTH: u8 = 3;

/// Validate `path` inside the validations of revocation information signers
/// for the certificates in `stack` (the leaves of the enclosing paths).
pub(crate) fn validate_path_at_depth(
    ctx: &ValidationContext,
    path: &ValidationPath,
    params: Option<&PkixValidationParams>,
    stack: &[Cert],
) -> Result<(), ValidationError> {
    validate_path_in_stack(ctx, path, params, stack)
        .map(|_| ())
        .map_err(|f| f.error)
}

/// [`validate_path`] with the failure details of [`PathFailure`].
pub fn validate_path_detailed(
    ctx: &ValidationContext,
    path: &ValidationPath,
    params: Option<&PkixValidationParams>,
) -> Result<(), Box<PathFailure>> {
    validate_path_in_stack(ctx, path, params, &[]).map(|_| ())
}

/// [`validate_path_detailed`], returning the path with its qualified
/// policies set (`ValidationPath.qualified_policies()`).
pub fn validate_path_qualified(
    ctx: &ValidationContext,
    path: &ValidationPath,
    params: Option<&PkixValidationParams>,
) -> Result<ValidationPath, Box<PathFailure>> {
    let policies = validate_path_in_stack(ctx, path, params, &[])?;
    let mut p = path.clone();
    p.set_qualified_policies(policies);
    Ok(p)
}

/// Decode `SEQUENCE OF PolicyQualifierInfo` leniently (the strict decoder
/// rejects some PKITS user notices).
fn decode_qualifiers(der: &[u8]) -> Vec<x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo> {
    use der::Decode;
    use hanko_core::asn1::tlv::Tlv;
    let Ok(seq) = Tlv::parse_exact(der) else {
        return Vec::new();
    };
    seq.children()
        .unwrap_or_default()
        .iter()
        .filter_map(|q| {
            let parts = q.children().ok()?;
            let id = const_oid::ObjectIdentifier::from_der(parts.first()?.raw).ok()?;
            let qualifier = match parts.get(1) {
                Some(t) => Some(der::Any::from_der(t.raw).ok()?),
                None => None,
            };
            Some(x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo {
                policy_qualifier_id: id,
                qualifier,
            })
        })
        .collect()
}

/// `user_constrained_policies` (RFC 5280 §6.1.5 (g) as replaced by RFC 9618
/// §5.5), computed over certval's final policy graph. Edges are
/// reconstructed from the expected policy sets: a node's parents are the
/// nodes one level up that expect its policy, else the anyPolicy node.
fn qualified_policies(
    results: &CertificationPathResults,
    params: Option<&PkixValidationParams>,
) -> Vec<crate::path::QualifiedPolicy> {
    use std::collections::{BTreeMap, BTreeSet};
    use x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo;
    let any = const_oid::db::rfc5280::ANY_POLICY;
    let Some(tree) = results.get_final_valid_policy_graph() else {
        return Vec::new();
    };
    let n = tree.len().saturating_sub(1);
    if n == 0 {
        return Vec::new();
    }
    // parents[d][i]: indices into tree[d - 1].
    let mut parents: Vec<Vec<Vec<usize>>> = vec![Vec::new(); tree.len()];
    for d in 1..tree.len() {
        for node in &tree[d] {
            let up = &tree[d - 1];
            let mut ps: Vec<usize> = up
                .iter()
                .enumerate()
                .filter(|(_, p)| p.valid_policy != any && p.expected_policy_set.contains(&node.valid_policy))
                .map(|(i, _)| i)
                .collect();
            if ps.is_empty() {
                ps = up
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.valid_policy == any)
                    .map(|(i, _)| i)
                    .collect();
            }
            parents[d].push(ps);
        }
    }
    let ancestors = |d: usize, i: usize| -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut frontier = vec![(d, i)];
        while let Some((dd, ii)) = frontier.pop() {
            if dd == 0 {
                continue;
            }
            for &p in &parents[dd][ii] {
                if !out.contains(&(dd - 1, p)) {
                    out.push((dd - 1, p));
                    frontier.push((dd - 1, p));
                }
            }
        }
        out
    };
    let descendants = |d: usize, i: usize| -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut frontier = vec![(d, i)];
        while let Some((dd, ii)) = frontier.pop() {
            if dd + 1 >= tree.len() {
                continue;
            }
            for (ci, ps) in parents[dd + 1].iter().enumerate() {
                if ps.contains(&ii) && !out.contains(&(dd + 1, ci)) {
                    out.push((dd + 1, ci));
                    frontier.push((dd + 1, ci));
                }
            }
        }
        out
    };
    // Step (g)(2) and (3): nodes branching off anyPolicy, and a final anyPolicy.
    let mut node_set = Vec::new();
    for d in 1..=n {
        for (i, node) in tree[d].iter().enumerate() {
            if node.valid_policy == any || parents[d][i].len() != 1 {
                continue;
            }
            if tree[d - 1][parents[d][i][0]].valid_policy == any {
                node_set.push((d, i));
            }
        }
    }
    if let Some(i) = tree[n].iter().position(|x| x.valid_policy == any) {
        node_set.push((n, i));
    }
    // Step (g)(4).
    let mut quals: BTreeMap<const_oid::ObjectIdentifier, Vec<PolicyQualifierInfo>> = BTreeMap::new();
    let mut leaves: BTreeMap<const_oid::ObjectIdentifier, BTreeSet<const_oid::ObjectIdentifier>> =
        BTreeMap::new();
    for (d, i) in node_set {
        let node = &tree[d][i];
        let entry = quals.entry(node.valid_policy).or_default();
        let mut relatives = vec![(d, i)];
        relatives.extend(ancestors(d, i));
        let desc = descendants(d, i);
        relatives.extend(desc.iter().copied());
        for (rd, ri) in relatives {
            for q in tree[rd][ri].qualifier_set.as_deref().map(decode_qualifiers).unwrap_or_default() {
                if !entry.contains(&q) {
                    entry.push(q);
                }
            }
        }
        let l = leaves.entry(node.valid_policy).or_default();
        if d == n {
            l.insert(node.valid_policy);
        }
        for (dd, di) in desc {
            if dd == n {
                l.insert(tree[dd][di].valid_policy);
            }
        }
    }
    let qualified = |p: &const_oid::ObjectIdentifier| -> Vec<crate::path::QualifiedPolicy> {
        leaves[p]
            .iter()
            .map(|issuer| crate::path::QualifiedPolicy {
                user_domain_policy_id: *p,
                issuer_domain_policy_id: *issuer,
                qualifiers: quals[p].clone(),
            })
            .collect()
    };
    let user_set: Vec<const_oid::ObjectIdentifier> = params
        .map(|p| p.user_initial_policy_set.clone())
        .filter(|v: &Vec<_>| !v.is_empty())
        .unwrap_or_else(|| vec![any]);
    if user_set.contains(&any) {
        return leaves.keys().flat_map(&qualified).collect();
    }
    let mut out: Vec<crate::path::QualifiedPolicy> = leaves
        .keys()
        .filter(|p| user_set.contains(p))
        .flat_map(&qualified)
        .collect();
    if leaves.contains_key(&any) {
        let accounted: Vec<_> = out.iter().map(|q| q.user_domain_policy_id).collect();
        for p in user_set.iter().filter(|p| !accounted.contains(p)) {
            out.push(crate::path::QualifiedPolicy {
                user_domain_policy_id: *p,
                issuer_domain_policy_id: *p,
                qualifiers: quals[&any].clone(),
            });
        }
    }
    out
}

fn validate_path_in_stack(
    ctx: &ValidationContext,
    path: &ValidationPath,
    params: Option<&PkixValidationParams>,
    outer: &[Cert],
) -> Result<Vec<crate::path::QualifiedPolicy>, Box<PathFailure>> {
    let fail = |error: ValidationError| Box::new(PathFailure::plain(error, Some(path.clone())));
    let anchor: &TrustAnchor = path.trust_anchor();
    if anchor.enforce_validity() {
        check_validity(ctx, anchor.cert(), "the trust anchor").map_err(|e| {
            let mut f = fail(e);
            f.time_horizon = Some(anchor.cert().not_after());
            f
        })?;
    }
    let issued = path.issued_certs();
    if issued.is_empty() {
        // Only the trust anchor itself: every policy is acceptable.
        let any = const_oid::db::rfc5280::ANY_POLICY;
        return Ok(vec![crate::path::QualifiedPolicy {
            user_domain_policy_id: any,
            issuer_domain_policy_id: any,
            qualifiers: Vec::new(),
        }]);
    }
    let total = issued.len();
    for (index, (cert, _)) in issued.iter().enumerate() {
        check_validity(ctx, cert, &path.describe(index, total)).map_err(|e| {
            let mut f = fail(e);
            f.is_ee_cert = index + 1 == total && path.leaf().is_some();
            if matches!(f.error, ValidationError::Expired { .. }) {
                f.time_horizon = Some(cert.not_after());
            }
            f
        })?;
    }

    let toi = ctx
        .timing
        .validation_time
        .to_der_datetime()
        .map(TimeOfInterest)
        .ok_or_else(|| fail(ValidationError::Malformed("time of interest out of range".into())))?;
    let cps = settings(ctx, toi, anchor.enforce_validity(), params);
    let pe = environment(ctx).map_err(fail)?;

    let ta = PDVTrustAnchorChoice::try_from(anchor.cert().der())
        .map_err(|e| fail(ValidationError::Malformed(format!("trust anchor: {e}"))))?;
    let mut chain: Vec<PDVCertificate> = issued
        .iter()
        .map(|(c, _)| pdv_cert(c))
        .collect::<Result<_, _>>()
        .map_err(fail)?;
    let Some(target) = chain.pop() else {
        return Ok(Vec::new());
    };
    let cv_path = CertificationPath::new(ta, chain, target);
    let mut results = CertificationPathResults::new();
    match validate_path_rfc5280(&pe, &cps, &cv_path, &mut results) {
        Ok(()) => {}
        Err(certval::Error::PathValidation(status)) => return Err(fail(map_status(status))),
        Err(e) => return Err(fail(cv_err("The path could not be validated", e))),
    }

    // Algorithm usage policy on every certificate signature in the path.
    for (index, (cert, issuer)) in issued.iter().enumerate() {
        let issuer_key = issuer.public_key();
        let allowed = ctx.algorithm_policy.signature_algorithm_allowed(
            cert.decoded().signature_algorithm(),
            Some(ctx.timing.validation_time),
            Some(&issuer_key),
        );
        if !allowed.allowed {
            return Err(fail(ValidationError::DisallowedAlgorithm(format!(
                "The path could not be validated because the signature of {} uses a disallowed algorithm: {}",
                path.describe(index, total),
                allowed.failure_reason.unwrap_or_default()
            ))));
        }
    }

    if outer.len() > usize::from(MAX_REVINFO_DEPTH) {
        return Err(fail(ValidationError::InsufficientRevinfo(
            "The path could not be validated because revocation information signers are nested too deeply".into(),
        )));
    }
    let mut stack = outer.to_vec();
    stack.push(path.leaf().unwrap_or(anchor.cert()).clone());
    revinfo::check_path_revocation_detailed(ctx, path, &stack)?;
    Ok(qualified_policies(&results, params))
}

/// Validates one certificate against a [`ValidationContext`]
/// (`CertificateValidator`).
#[derive(Debug)]
pub struct CertificateValidator<'a> {
    ctx: &'a ValidationContext,
    cert: Cert,
    params: Option<PkixValidationParams>,
}

impl<'a> CertificateValidator<'a> {
    /// Validator for `cert`.
    pub fn new(ctx: &'a ValidationContext, cert: Cert) -> Self {
        Self {
            ctx,
            cert,
            params: None,
        }
    }

    /// Set the RFC 5280 initial inputs.
    pub fn with_params(mut self, params: PkixValidationParams) -> Self {
        self.params = Some(params);
        self
    }

    /// Build paths and return the first one that validates. If none does,
    /// return the error of the first candidate path.
    pub fn validate(&self) -> Result<ValidationPath, ValidationError> {
        let paths = build_paths(self.ctx, &self.cert)?;
        let mut first_error = None;
        for path in paths {
            match validate_path_qualified(self.ctx, &path, self.params.as_ref()) {
                Ok(p) => return Ok(p),
                Err(e) => {
                    first_error.get_or_insert(e.error);
                }
            }
        }
        Err(first_error
            .unwrap_or_else(|| ValidationError::PathBuilding("no candidate paths".into())))
    }
}
