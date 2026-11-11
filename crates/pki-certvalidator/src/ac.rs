// Derived from pyhanko-certvalidator `validate.py` (`async_validate_ac`,
// `ACValidationResult`, `check_ac_holder_match`, `_candidate_ac_issuers`,
// `validate_aa_usage`, `_check_ac_signature`, `_validate_ac_targeting`,
// `_check_aa_controls`), `path.py` (`aa_attr_in_scope`) and `asn1_types.py`
// (`AAControls`) (MIT, see LICENSE-pyHanko).

//! Attribute certificate validation (RFC 5755).

use std::collections::BTreeMap;

use const_oid::ObjectIdentifier;
use der::Decode;
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, CrlDistributionPoints,
};
use x509_cert::ext::Extension;
use x509_cert::name::Name;

use sigis_pki_core::algorithms::{validate_signature, SignatureValidationContext};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::asn1::raw_oid::RawOid;
use sigis_pki_core::asn1::tlv::{tag, Class, Tlv};
use sigis_pki_core::errors::ValidationError;
use sigis_pki_core::time::Moment;

use crate::authority::Cert;
use crate::context::ValidationContext;
use crate::path::ValidationPath;
use crate::revinfo::{check_revocation, Subject, Target};

/// `id-pe-aaControls`.
const PE_AA_CONTROLS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.6");
/// `id-ce-targetInformation`.
const CE_TARGET_INFORMATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.55");
/// `id-ce-noRevAvail`.
const CE_NO_REV_AVAIL: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.56");
/// `id-pe-ac-auditIdentity`.
const PE_AUDIT_IDENTITY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.4");
/// `id-ce-subjectKeyIdentifier` (`key_identifier` in asn1crypto).
const CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// Failure of attribute certificate validation, with pyhanko-certvalidator's
/// error classes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AcError {
    /// `InvalidCertificateError`.
    #[error("{0}")]
    InvalidCertificate(String),
    /// `InvalidAttrCertificateError` (a subclass of the above).
    #[error("{0}")]
    InvalidAttrCertificate(String),
    /// A path building or validation error of the AA path or of the AC's
    /// revocation status.
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

impl AcError {
    /// The pyhanko-certvalidator class name.
    pub fn class_name(&self) -> &'static str {
        match self {
            Self::InvalidCertificate(_) => "InvalidCertificateError",
            Self::InvalidAttrCertificate(_) => "InvalidAttrCertificateError",
            Self::Validation(e) => e.class_name(),
        }
    }

    /// `isinstance` with pyhanko-certvalidator's hierarchy.
    pub fn is_instance_of(&self, class: &str) -> bool {
        match self {
            Self::InvalidCertificate(_) => class == "InvalidCertificateError",
            Self::InvalidAttrCertificate(_) => {
                matches!(
                    class,
                    "InvalidAttrCertificateError" | "InvalidCertificateError"
                )
            }
            Self::Validation(e) => e.is_instance_of(class),
        }
    }
}

/// `IssuerSerial` of RFC 5755.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcIssuerSerial {
    /// `issuer`.
    pub issuer: Vec<GeneralName>,
    /// Serial number contents octets.
    pub serial: Vec<u8>,
}

/// `Holder`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Holder {
    /// `baseCertificateID`.
    pub base_certificate_id: Option<AcIssuerSerial>,
    /// `entityName`.
    pub entity_name: Option<Vec<GeneralName>>,
    /// `objectDigestInfo` is present (not supported).
    pub object_digest_info: bool,
}

/// `AttCertIssuer`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcIssuer {
    /// `issuerName` (v2Form) or the v1Form names.
    pub names: Option<Vec<GeneralName>>,
    /// `baseCertificateID` (v2Form).
    pub base_certificate_id: Option<AcIssuerSerial>,
    /// `objectDigestInfo` (v2Form) is present (not supported).
    pub object_digest_info: bool,
}

/// A parsed `AttributeCertificate` (v2).
#[derive(Clone, Debug)]
pub struct AttrCert {
    /// DER of the whole certificate.
    pub der: Vec<u8>,
    /// DER of `acinfo` (the signed part).
    pub info_der: Vec<u8>,
    /// `holder`.
    pub holder: Holder,
    /// `issuer`.
    pub issuer: AcIssuer,
    /// `signature` inside `acinfo`.
    pub inner_signature_algorithm: AlgorithmIdentifierOwned,
    /// Serial number contents octets.
    pub serial: Vec<u8>,
    /// `notBeforeTime`.
    pub not_before: Moment,
    /// `notAfterTime`.
    pub not_after: Moment,
    /// Attributes: type and DER of the `Attribute`.
    pub attributes: Vec<(RawOid, Vec<u8>)>,
    /// Extensions.
    pub extensions: Vec<Extension>,
    /// `signatureAlgorithm` on the envelope.
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// Signature value.
    pub signature: Vec<u8>,
}

fn malformed(what: &str) -> AcError {
    AcError::Validation(ValidationError::Malformed(format!(
        "attribute certificate: {what}"
    )))
}

fn general_names(t: &Tlv<'_>) -> Result<Vec<GeneralName>, AcError> {
    // `t` is a GeneralNames SEQUENCE, possibly implicitly tagged.
    let seq = sigis_pki_core::asn1::tlv::encode(0x30, t.value);
    Vec::<GeneralName>::from_der(&seq).map_err(|e| malformed(&e.to_string()))
}

fn issuer_serial(t: &Tlv<'_>) -> Result<AcIssuerSerial, AcError> {
    let mut parts = t.children().map_err(|e| malformed(&e.to_string()))?;
    // asn1crypto tags V2Form's baseCertificateID explicitly: unwrap a
    // single inner IssuerSerial SEQUENCE.
    if let [inner] = parts.as_slice() {
        if inner.is_universal(tag::SEQUENCE)
            && inner
                .children()
                .is_ok_and(|c| c.get(1).is_some_and(|s| s.is_universal(tag::INTEGER)))
        {
            parts = inner.children().map_err(|e| malformed(&e.to_string()))?;
        }
    }
    let issuer = parts.first().ok_or_else(|| malformed("IssuerSerial"))?;
    let serial = parts
        .get(1)
        .filter(|s| s.is_universal(tag::INTEGER))
        .ok_or_else(|| malformed("IssuerSerial"))?;
    Ok(AcIssuerSerial {
        issuer: general_names(issuer)?,
        serial: serial.value.to_vec(),
    })
}

fn generalized_time(t: &Tlv<'_>) -> Result<Moment, AcError> {
    der::asn1::GeneralizedTime::from_der(t.raw)
        .map(|g| Moment::from(g.to_date_time()))
        .map_err(|e| malformed(&e.to_string()))
}

impl AttrCert {
    /// Parse a DER `AttributeCertificate`.
    pub fn from_der(der: &[u8]) -> Result<Self, AcError> {
        let m = |e: sigis_pki_core::asn1::tlv::TlvError| malformed(&e.to_string());
        let outer = Tlv::parse_exact(der).map_err(m)?;
        let parts = outer.children().map_err(m)?;
        let [info, sig_alg, sig] = parts.as_slice() else {
            return Err(malformed("expected three fields"));
        };
        let fields = info.children().map_err(m)?;
        let mut it = fields.iter().peekable();
        let mut next = || it.next().ok_or_else(|| malformed("truncated acinfo"));
        let _version = next()?;
        let holder_tlv = next()?;
        let mut holder = Holder::default();
        for h in holder_tlv.children().map_err(m)? {
            match (h.class, h.number) {
                (Class::ContextSpecific, 0) => {
                    holder.base_certificate_id = Some(issuer_serial(&h)?)
                }
                (Class::ContextSpecific, 1) => holder.entity_name = Some(general_names(&h)?),
                (Class::ContextSpecific, 2) => holder.object_digest_info = true,
                _ => return Err(malformed("holder")),
            }
        }
        let issuer_tlv = next()?;
        let mut issuer = AcIssuer::default();
        if issuer_tlv.is_context(0) {
            for f in issuer_tlv.children().map_err(m)? {
                match (f.class, f.number) {
                    (Class::Universal, 16) => issuer.names = Some(general_names(&f)?),
                    (Class::ContextSpecific, 0) => {
                        issuer.base_certificate_id = Some(issuer_serial(&f)?)
                    }
                    (Class::ContextSpecific, 1) => issuer.object_digest_info = true,
                    _ => return Err(malformed("issuer")),
                }
            }
        } else {
            issuer.names = Some(general_names(issuer_tlv)?);
        }
        let inner_signature_algorithm = AlgorithmIdentifierOwned::from_der(next()?.raw)
            .map_err(|e| malformed(&e.to_string()))?;
        let serial = next()?.value.to_vec();
        let validity = next()?.children().map_err(m)?;
        let [nb, na] = validity.as_slice() else {
            return Err(malformed("validity"));
        };
        let (not_before, not_after) = (generalized_time(nb)?, generalized_time(na)?);
        let mut attributes = Vec::new();
        for a in next()?.children().map_err(m)? {
            let ty = a.children().map_err(m)?;
            let oid =
                RawOid::from_tlv(ty.first().ok_or_else(|| malformed("attribute"))?).map_err(m)?;
            attributes.push((oid, a.raw.to_vec()));
        }
        let mut extensions = Vec::new();
        for rest in it {
            if rest.is_universal(tag::SEQUENCE) {
                extensions =
                    Vec::<Extension>::from_der(rest.raw).map_err(|e| malformed(&e.to_string()))?;
            }
        }
        let signature_algorithm = AlgorithmIdentifierOwned::from_der(sig_alg.raw)
            .map_err(|e| malformed(&e.to_string()))?;
        if !sig.is_universal(tag::BIT_STRING) {
            return Err(malformed("signature"));
        }
        Ok(Self {
            der: der.to_vec(),
            info_der: info.raw.to_vec(),
            holder,
            issuer,
            inner_signature_algorithm,
            serial,
            not_before,
            not_after,
            attributes,
            extensions,
            signature_algorithm,
            signature: sig.value.get(1..).unwrap_or_default().to_vec(),
        })
    }

    fn extension(&self, oid: &ObjectIdentifier) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.extn_id == *oid)
    }

    /// The issuer's directory name (`get_issuer_dn`).
    pub fn issuer_name(&self) -> Option<Name> {
        let names = self.issuer.names.as_ref().or(self
            .issuer
            .base_certificate_id
            .as_ref()
            .map(|b| &b.issuer))?;
        dir_name(names)
    }

    pub(crate) fn target(&self) -> Option<Target> {
        let dps: Vec<DistributionPoint> = self
            .extension(&oids::CE_CRL_DISTRIBUTION_POINTS)
            .and_then(|e| CrlDistributionPoints::from_der(e.extn_value.as_bytes()).ok())
            .map(|d| d.0)
            .unwrap_or_default();
        let declares_ocsp = self
            .extension(&oids::PE_AUTHORITY_INFO_ACCESS)
            .and_then(|e| AuthorityInfoAccessSyntax::from_der(e.extn_value.as_bytes()).ok())
            .is_some_and(|aia| aia.0.iter().any(|ad| ad.access_method == oids::AD_OCSP));
        Some(Target {
            der: self.der.clone(),
            serial: self.serial.clone(),
            issuer: self.issuer_name()?,
            declares_crl: self.extension(&oids::CE_CRL_DISTRIBUTION_POINTS).is_some(),
            dps,
            is_ca: false,
            is_ac: true,
            declares_ocsp,
            x509: None,
            display_name: String::new(),
        })
    }
}

/// `extract_dir_name`: the single directory name of a `GeneralNames`.
fn dir_name(names: &[GeneralName]) -> Option<Name> {
    match names {
        [GeneralName::DirectoryName(n)] => Some(n.clone()),
        _ => names.iter().find_map(|n| match n {
            GeneralName::DirectoryName(n) => Some(n.clone()),
            _ => None,
        }),
    }
}

fn normalize_int(b: &[u8]) -> &[u8] {
    let mut b = b;
    while b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
        b = &b[1..];
    }
    b
}

fn matches_issuer_serial(is: &AcIssuerSerial, cert: &Cert) -> bool {
    dir_name(&is.issuer).is_some_and(|n| certval::compare_names(&n, cert.issuer()))
        && normalize_int(&is.serial) == normalize_int(cert.serial_bytes())
}

/// `check_ac_holder_match`: the parts of the holder entry that do not
/// match `holder_cert` (`base_certificate_id`, `entity_name`).
pub fn check_ac_holder_match(
    holder_cert: &Cert,
    holder: &Holder,
) -> Result<Vec<&'static str>, AcError> {
    let mut mismatches = Vec::new();
    if let Some(base) = &holder.base_certificate_id {
        if !matches_issuer_serial(base, holder_cert) {
            mismatches.push("base_certificate_id");
        }
    }
    if let Some(names) = &holder.entity_name {
        let dn = dir_name(names).ok_or_else(|| malformed("Could not identify AC holder DN"))?;
        if !certval::compare_names(&dn, holder_cert.subject()) {
            mismatches.push("entity_name");
        }
    }
    if holder.object_digest_info {
        return Err(AcError::InvalidAttrCertificate(
            "Object digest info is currently not supported".into(),
        ));
    }
    Ok(mismatches)
}

/// Acceptable AC targets (`ACTargetDescription`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcTargetDescription {
    /// `validator_names`.
    pub validator_names: Vec<GeneralName>,
    /// `group_memberships`.
    pub group_memberships: Vec<GeneralName>,
}

fn gn_eq(a: &GeneralName, b: &GeneralName) -> bool {
    match (a, b) {
        (GeneralName::DirectoryName(x), GeneralName::DirectoryName(y)) => {
            certval::compare_names(x, y)
        }
        _ => a == b,
    }
}

/// `_validate_ac_targeting`.
fn validate_targeting(ac: &AttrCert, targets: &AcTargetDescription) -> Result<(), AcError> {
    let Some(ext) = ac.extension(&CE_TARGET_INFORMATION) else {
        return Ok(());
    };
    let m = |e: sigis_pki_core::asn1::tlv::TlvError| malformed(&e.to_string());
    // SEQUENCE OF Targets; Targets ::= SEQUENCE OF Target;
    // Target ::= CHOICE { targetName [0], targetGroup [1], targetCert [2] }
    let outer = Tlv::parse_exact(ext.extn_value.as_bytes()).map_err(m)?;
    for targets_seq in outer.children().map_err(m)? {
        for target in targets_seq.children().map_err(m)? {
            let valid = match target.number {
                0 => &targets.validator_names,
                1 => &targets.group_memberships,
                _ => continue,
            };
            // The target's contents is an explicitly tagged GeneralName.
            let gn = GeneralName::from_der(target.value).map_err(|e| malformed(&e.to_string()))?;
            if valid.iter().any(|v| gn_eq(&gn, v)) {
                return Ok(());
            }
        }
    }
    Err(AcError::InvalidAttrCertificate(
        "AC targeting check failed".into(),
    ))
}

/// `AAControls`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AaControls {
    path_len_constraint: Option<u32>,
    permitted: Option<Vec<ObjectIdentifier>>,
    excluded: Option<Vec<ObjectIdentifier>>,
    permit_unspecified: bool,
}

impl AaControls {
    fn read(cert: &Cert) -> Option<Self> {
        let ext = cert
            .decoded()
            .tbs_certificate()
            .extensions()?
            .iter()
            .find(|e| e.extn_id == PE_AA_CONTROLS)?;
        let t = Tlv::parse_exact(ext.extn_value.as_bytes()).ok()?;
        let mut out = Self {
            permit_unspecified: true,
            ..Self::default()
        };
        let oids = |t: &Tlv<'_>| -> Vec<ObjectIdentifier> {
            t.children()
                .unwrap_or_default()
                .iter()
                .filter_map(|o| ObjectIdentifier::from_der(o.raw).ok())
                .collect()
        };
        for f in t.children().ok()? {
            match (f.class, f.number) {
                (Class::Universal, 2) => {
                    out.path_len_constraint = f.value.iter().try_fold(0u32, |acc, b| {
                        acc.checked_mul(256)
                            .and_then(|v| v.checked_add(u32::from(*b)))
                    })
                }
                (Class::ContextSpecific, 0) => out.permitted = Some(oids(&f)),
                (Class::ContextSpecific, 1) => out.excluded = Some(oids(&f)),
                (Class::Universal, 1) => {
                    out.permit_unspecified = f.value.first().is_some_and(|b| *b != 0)
                }
                _ => {}
            }
        }
        Some(out)
    }

    fn accept(&self, attr: &RawOid) -> bool {
        let is = |list: &Option<Vec<ObjectIdentifier>>| {
            list.as_ref().is_some_and(|l| l.iter().any(|o| attr.is(o)))
        };
        if is(&self.excluded) {
            return false;
        }
        if is(&self.permitted) {
            return true;
        }
        self.permit_unspecified
    }
}

/// `_check_aa_controls` and the AA path length (`max_aa_path_length`)
/// for an AA certificate path (`EECertProfile.ATTRIBUTE_AUTHORITY`).
fn check_aa_path(path: &ValidationPath) -> Result<(), AcError> {
    let issued: Vec<&Cert> = path.certs().into_iter().skip(1).collect();
    let n = issued.len();
    let mut max_aa = n;
    let mut used = false;
    for (pos, cert) in issued.iter().enumerate() {
        let index = pos + 1;
        let describe = if index == n {
            "the end-entity certificate".to_owned()
        } else {
            format!("intermediate certificate {index}")
        };
        if index < n && !cert.is_self_issued() {
            if max_aa == 0 {
                return Err(ValidationError::PathValidation(
                    "The path could not be validated because it exceeds the maximum path length for an AA certificate".into(),
                )
                .into());
            }
            max_aa -= 1;
        }
        match AaControls::read(cert) {
            Some(c) => {
                if !used && index > 1 {
                    return Err(ValidationError::PathValidation(format!(
                        "AA controls extension only present on part of the certificate chain: {describe} has AA controls while preceding certificates do not. "
                    ))
                    .into());
                }
                used = true;
                if let Some(l) = c.path_len_constraint {
                    max_aa = max_aa.min(l as usize);
                }
            }
            None if used => {
                return Err(ValidationError::PathValidation(format!(
                    "AA controls extension only present on part of the certificate chain: {describe} has no AA controls "
                ))
                .into());
            }
            None => {}
        }
    }
    Ok(())
}

/// `aa_attr_in_scope`.
fn aa_attr_in_scope(path: &ValidationPath, attr: &RawOid) -> bool {
    let controls: Vec<AaControls> = path
        .certs()
        .into_iter()
        .filter_map(AaControls::read)
        .collect();
    controls.is_empty() || controls.iter().all(|c| c.accept(attr))
}

/// `validate_aa_usage`: digital signature key usage, not a CA.
fn validate_aa_usage(cert: &Cert) -> Result<(), AcError> {
    if !cert.key_usage().is_some_and(|ku| ku.digital_signature()) {
        return Err(AcError::InvalidCertificate(
            "The X.509 certificate provided is not valid for the purpose of digital signature"
                .into(),
        ));
    }
    if cert.is_ca() {
        return Err(AcError::InvalidCertificate(
            "The X.509 certificate provided is a CA certificate, so it cannot be used to validate attribute certificates.".into(),
        ));
    }
    Ok(())
}

/// `_candidate_ac_issuers`.
fn candidate_issuers(ctx: &ValidationContext, ac: &AttrCert) -> Result<Vec<Cert>, AcError> {
    if ac.issuer.object_digest_info {
        return Err(AcError::InvalidAttrCertificate(
            "Could not identify AA; objectDigestInfo is not supported.".into(),
        ));
    }
    let mut aa_iss_serial = ac.issuer.base_certificate_id.clone();
    let mut aki = None;
    if let Some(ext) = ac.extension(&oids::CE_AUTHORITY_KEY_IDENTIFIER) {
        let v = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
            .map_err(|e| malformed(&e.to_string()))?;
        aki = v.key_identifier.map(|k| k.as_bytes().to_vec());
        if let (Some(iss), Some(ser)) = (&v.authority_cert_issuer, &v.authority_cert_serial_number)
        {
            let from_aki = AcIssuerSerial {
                issuer: iss.clone(),
                serial: ser.as_bytes().to_vec(),
            };
            match &aa_iss_serial {
                Some(existing)
                    if !(dir_name(&existing.issuer)
                        .zip(dir_name(&from_aki.issuer))
                        .is_some_and(|(a, b)| certval::compare_names(&a, &b))
                        && normalize_int(&existing.serial) == normalize_int(&from_aki.serial)) =>
                {
                    return Err(AcError::InvalidAttrCertificate(
                        "AC's AKI extension and issuer include conflicting identifying information for the issuing AA".into(),
                    ));
                }
                _ => aa_iss_serial = Some(from_aki),
            }
        }
    }
    let aa_name = ac.issuer.names.as_deref().and_then(dir_name);
    let known: Vec<&Cert> = ctx.known_certs().collect();
    let candidates: Vec<Cert> = if let Some(is) = &aa_iss_serial {
        known
            .into_iter()
            .filter(|c| matches_issuer_serial(is, c))
            .take(1)
            .cloned()
            .collect()
    } else if let Some(name) = &aa_name {
        known
            .into_iter()
            .filter(|c| certval::compare_names(c.subject(), name))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    Ok(candidates
        .into_iter()
        .filter(|c| {
            aa_name
                .as_ref()
                .is_none_or(|n| certval::compare_names(c.subject(), n))
        })
        .filter(|c| {
            aki.as_ref().is_none_or(|k| {
                c.decoded()
                    .tbs_certificate()
                    .extensions()
                    .and_then(|exts| exts.iter().find(|e| e.extn_id == CE_SUBJECT_KEY_IDENTIFIER))
                    .and_then(|e| der::asn1::OctetString::from_der(e.extn_value.as_bytes()).ok())
                    .is_some_and(|ski| ski.as_bytes() == k.as_slice())
            })
        })
        .collect())
}

/// Result of a successful attribute certificate validation
/// (`ACValidationResult`).
#[derive(Clone, Debug)]
pub struct AcValidationResult {
    /// DER of the attribute certificate.
    pub attr_cert: Vec<u8>,
    /// The attribute authority's certificate.
    pub aa_cert: Cert,
    /// Path of the attribute authority's certificate.
    pub aa_path: ValidationPath,
    /// Approved attributes by type name (DER of each `Attribute`), filtered
    /// by AA controls.
    pub approved_attributes: BTreeMap<String, Vec<u8>>,
}

const SUPPORTED_AC_EXTENSIONS: [ObjectIdentifier; 8] = [
    oids::PE_AUTHORITY_INFO_ACCESS,
    oids::CE_AUTHORITY_KEY_IDENTIFIER,
    oids::CE_CRL_DISTRIBUTION_POINTS,
    oids::CE_FRESHEST_CRL,
    CE_SUBJECT_KEY_IDENTIFIER,
    CE_NO_REV_AVAIL,
    CE_TARGET_INFORMATION,
    PE_AUDIT_IDENTITY,
];

/// Validate an attribute certificate (`async_validate_ac`). `holder`, if
/// given, must match the AC's holder entry.
pub fn validate_ac(
    ctx: &ValidationContext,
    attr_cert: &[u8],
    holder: Option<&Cert>,
) -> Result<AcValidationResult, AcError> {
    let ac = AttrCert::from_der(attr_cert)?;
    let mut unsupported: Vec<String> = ac
        .extensions
        .iter()
        .filter(|e| e.critical && !SUPPORTED_AC_EXTENSIONS.contains(&e.extn_id))
        .map(|e| e.extn_id.to_string())
        .collect();
    if !unsupported.is_empty() {
        unsupported.sort();
        return Err(AcError::InvalidCertificate(format!(
            "The AC could not be validated because it contains the following unsupported critical extension{}: {}.",
            if unsupported.len() == 1 { "" } else { "s" },
            unsupported.join(", ")
        )));
    }
    if ac.extension(&CE_TARGET_INFORMATION).is_some() {
        let Some(targets) = ctx.acceptable_ac_targets.as_ref() else {
            return Err(AcError::InvalidAttrCertificate(
                "The attribute certificate is targeted, but no targeting information is available in the validation context.".into(),
            ));
        };
        validate_targeting(&ac, targets)?;
    }
    if ac.holder == Holder::default() {
        return Err(AcError::InvalidAttrCertificate(
            "AC holder entry is empty".into(),
        ));
    }
    if let Some(h) = holder {
        let mismatches = check_ac_holder_match(h, &ac.holder)?;
        if !mismatches.is_empty() {
            return Err(AcError::InvalidAttrCertificate(format!(
                "Could not match AC holder entry against supplied holder certificate; mismatched entries: {}",
                mismatches.join(", ")
            )));
        }
    }

    let mut errors: Vec<AcError> = Vec::new();
    let mut aa_path = None;
    'candidates: for cand in candidate_issuers(ctx, &ac)? {
        if let Err(e) = validate_aa_usage(&cand) {
            errors.push(e);
            continue;
        }
        let paths = match crate::validate::build_paths(ctx, &cand) {
            Ok(p) => p,
            Err(e) => {
                errors.push(e.into());
                continue;
            }
        };
        for p in paths {
            let r = crate::validate::validate_path(ctx, &p, None)
                .map_err(AcError::from)
                .and_then(|()| check_aa_path(&p));
            match r {
                Ok(()) => {
                    aa_path = Some(p);
                    break 'candidates;
                }
                Err(e) => errors.push(e),
            }
        }
    }
    let Some(aa_path) = aa_path else {
        return Err(errors.into_iter().next().unwrap_or_else(|| {
            ValidationError::PathBuilding(
                "Could not find a suitable AA for the attribute certificate".into(),
            )
            .into()
        }));
    };
    let aa_cert = aa_path
        .leaf()
        .cloned()
        .unwrap_or_else(|| aa_path.trust_anchor().cert().clone());

    // `_check_ac_signature`.
    if ac.signature_algorithm != ac.inner_signature_algorithm {
        return Err(AcError::InvalidAttrCertificate(
            "Signature algorithm declaration in signed portion of AC does not match the signature algorithm declaration on the envelope.".into(),
        ));
    }
    let allowed = ctx.algorithm_policy.signature_algorithm_allowed(
        &ac.signature_algorithm,
        Some(ctx.timing.best_signature_time),
        Some(&aa_cert.public_key()),
    );
    if !allowed.allowed {
        return Err(ValidationError::DisallowedAlgorithm(format!(
            "The attribute certificate could not be validated because the signature uses the disallowed signature algorithm {}. ",
            ac.signature_algorithm.oid
        ))
        .into());
    }
    match validate_signature(
        &ac.signature,
        &ac.info_der,
        &aa_cert.public_key(),
        &ac.signature_algorithm,
        &SignatureValidationContext::default(),
    ) {
        Ok(()) => {}
        Err(sigis_pki_core::errors::SignatureError::PssParameterMismatch) => {
            return Err(AcError::InvalidAttrCertificate(
                "The signature parameters for the attribute certificate do not match the constraints on the public key. ".into(),
            ))
        }
        Err(_) => {
            return Err(AcError::InvalidAttrCertificate(
                "The attribute certificate could not be validated because the signature could not be verified.".into(),
            ))
        }
    }

    // Validity of the AC itself.
    let t = ctx.timing.validation_time;
    let tol = ctx.timing.time_tolerance;
    if t.minus(tol) > ac.not_after {
        return Err(ValidationError::Expired {
            msg: format!(
                "The path could not be validated because the attribute certificate expired {}",
                crate::validate::py_time(ac.not_after)
            ),
        }
        .into());
    }
    if t.plus(tol) < ac.not_before {
        return Err(ValidationError::NotYetValid {
            msg: format!(
                "The path could not be validated because the attribute certificate is not valid until {}",
                crate::validate::py_time(ac.not_before)
            ),
        }
        .into());
    }

    if ac.extension(&CE_NO_REV_AVAIL).is_none() {
        with_ac_subject(&ac, &aa_path, |subject| check_revocation(ctx, subject))?;
    }

    let approved_attributes = ac
        .attributes
        .iter()
        .filter(|(oid, _)| aa_attr_in_scope(&aa_path, oid))
        .map(|(oid, der)| (attribute_type_name(oid), der.clone()))
        .collect();
    Ok(AcValidationResult {
        attr_cert: attr_cert.to_vec(),
        aa_cert,
        aa_path,
        approved_attributes,
    })
}

/// Run `f` on the revocation subject of `ac`, whose AA path is `aa_path`
/// (`ac_path = aa_path.copy_and_append(attr_cert)` in pyHanko).
fn with_ac_subject<T>(
    ac: &AttrCert,
    aa_path: &ValidationPath,
    f: impl FnOnce(&Subject<'_>) -> Result<T, ValidationError>,
) -> Result<T, AcError> {
    let target = ac
        .target()
        .ok_or_else(|| malformed("Could not identify the AC issuer"))?;
    let aa_cert = aa_path
        .leaf()
        .cloned()
        .unwrap_or_else(|| aa_path.trust_anchor().cert().clone());
    // The AA must be an authority of the path the CRL and OCSP checks see.
    let mut authorities = aa_path.intermediates().to_vec();
    if aa_path.leaf().is_some() {
        authorities.push(aa_cert.clone());
    }
    let path = ValidationPath::new(aa_path.trust_anchor().clone(), authorities, None);
    let stack = [aa_cert.clone()];
    let subject = Subject {
        cert: &target,
        issuer: &aa_cert,
        path: &path,
        description: "the attribute certificate".into(),
        description_definite: "the attribute certificate".into(),
        is_ee: true,
        stack: &stack,
    };
    Ok(f(&subject)?)
}

fn outcome_to_result(
    outcome: crate::revinfo::CheckOutcome,
    kind: &str,
) -> Result<(), ValidationError> {
    use crate::revinfo::CheckOutcome;
    match outcome {
        CheckOutcome::Good => Ok(()),
        CheckOutcome::NoMatches => Err(ValidationError::InsufficientRevinfo(format!(
            "No {kind} issued for the attribute certificate"
        ))),
        CheckOutcome::Indeterminate { failures, .. } => Err(ValidationError::InsufficientRevinfo(format!(
            "Unable to determine if the attribute certificate is revoked due to insufficient information from known {kind}s: {}",
            failures.join("; ")
        ))),
        CheckOutcome::FetchFailed(m) => Err(ValidationError::InsufficientRevinfo(m)),
    }
}

/// `verify_crl(attr_cert, ac_path, ...)`: check an attribute certificate
/// against the context's CRLs only.
pub fn verify_ac_crl(
    ctx: &ValidationContext,
    attr_cert: &[u8],
    aa_path: &ValidationPath,
) -> Result<(), AcError> {
    let ac = AttrCert::from_der(attr_cert)?;
    with_ac_subject(&ac, aa_path, |s| {
        outcome_to_result(crate::revinfo::crl::verify_crl(ctx, s)?, "CRL")
    })
}

/// `verify_ocsp_response(attr_cert, ac_path, ...)`: check an attribute
/// certificate against the context's OCSP responses only.
pub fn verify_ac_ocsp(
    ctx: &ValidationContext,
    attr_cert: &[u8],
    aa_path: &ValidationPath,
) -> Result<(), AcError> {
    let ac = AttrCert::from_der(attr_cert)?;
    with_ac_subject(&ac, aa_path, |s| {
        outcome_to_result(crate::revinfo::ocsp::verify_ocsp(ctx, s)?, "OCSP response")
    })
}

/// The asn1crypto name of an attribute certificate attribute type.
pub fn attribute_type_name(oid: &RawOid) -> String {
    match oid.dotted().as_str() {
        "1.3.6.1.5.5.7.10.1" => "authentication_info".into(),
        "1.3.6.1.5.5.7.10.2" => "access_identity".into(),
        "1.3.6.1.5.5.7.10.3" => "charging_identity".into(),
        "1.3.6.1.5.5.7.10.4" => "group".into(),
        "2.5.4.72" => "role".into(),
        "2.5.4.55" => "clearance".into(),
        other => other.into(),
    }
}
