// Derived from pyHanko `sign/validation/qualified/tsp.py` (MIT, see LICENSE-pyHanko).

//! Trusted service providers: service definitions, qualifiers, criteria and
//! the TSP registry (`pyhanko.sign.validation.qualified.tsp`).

use std::collections::BTreeSet;

use der::Encode;
use hanko_certvalidator::{TrustAnchor, ValidationPath};
use hanko_core::cert::Cert;
use hanko_core::time::Moment;
use hanko_validate::settings::KeyUsageConstraints;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};

/// Service type URI of a qualified CA (`CA_QC_URI`).
pub const CA_QC_URI: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
/// Service type URI of a qualified TSA (`QTST_URI`).
pub const QTST_URI: &str = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";
/// Base URI of trusted list identifiers.
pub const TRUSTEDLIST_URI_BASE: &str = "http://uri.etsi.org/TrstSvc/TrustedList";
/// Base URI of service information extension identifiers.
pub const SVCINFOEXT_URI_BASE: &str = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt";

/// Error while interpreting a trusted list (`TSPServiceParsingError`).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TspServiceParsingError(pub String);

/// Additional service information (`AdditionalServiceInformation`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdditionalServiceInformation {
    /// Identifier URI.
    pub uri: String,
    /// Criticality of the enclosing extension.
    pub critical: bool,
    /// Textual information, if any.
    pub textual_info: Option<String>,
}

/// Type of qualified certificate (`QcCertType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QcCertType {
    /// Qualified for electronic signatures (`qct_esign`).
    QcEsign,
    /// Qualified for electronic seals (`qct_eseal`).
    QcEseal,
    /// Qualified website authentication certificate (`qct_web`).
    QcWeb,
}

impl QcCertType {
    /// pyHanko enum value.
    pub fn value(self) -> &'static str {
        match self {
            Self::QcEsign => "qct_esign",
            Self::QcEseal => "qct_eseal",
            Self::QcWeb => "qct_web",
        }
    }

    /// pyHanko enum member name.
    pub fn name(self) -> &'static str {
        match self {
            Self::QcEsign => "QC_ESIGN",
            Self::QcEseal => "QC_ESEAL",
            Self::QcWeb => "QC_WEB",
        }
    }
}

/// Common information about a trusted service (`BaseServiceInformation`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseServiceInformation {
    /// Service type URI (`ServiceTypeIdentifier`).
    pub service_type: String,
    /// Service name.
    pub service_name: String,
    /// Start of the validity window of the service definition.
    pub valid_from: Moment,
    /// End of the validity window, if any.
    pub valid_until: Option<Moment>,
    /// Certificates of the service.
    pub provider_certs: Vec<Cert>,
    /// If non-empty, narrows the service to these certificate types.
    pub additional_info_certificate_type: BTreeSet<QcCertType>,
    /// Other additional information.
    pub other_additional_info: BTreeSet<AdditionalServiceInformation>,
}

/// Qualifier (ETSI TS 119 612, 5.5.9.2) (`Qualifier`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(missing_docs)]
pub enum Qualifier {
    WithSscd,
    NoSscd,
    SscdAsInCert,
    WithQscd,
    NoQscd,
    QscdAsInCert,
    QscdManagedOnBehalf,
    LegalPerson,
    ForEsig,
    ForEseal,
    ForWsa,
    NotQualified,
    QcStatement,
}

impl Qualifier {
    /// All qualifiers.
    pub const ALL: [Qualifier; 13] = [
        Self::WithSscd,
        Self::NoSscd,
        Self::SscdAsInCert,
        Self::WithQscd,
        Self::NoQscd,
        Self::QscdAsInCert,
        Self::QscdManagedOnBehalf,
        Self::LegalPerson,
        Self::ForEsig,
        Self::ForEseal,
        Self::ForWsa,
        Self::NotQualified,
        Self::QcStatement,
    ];

    /// The qualifier's name in the URI.
    pub fn value(self) -> &'static str {
        match self {
            Self::WithSscd => "QCWithSSCD",
            Self::NoSscd => "QCNoSSCD",
            Self::SscdAsInCert => "QCSSCDStatusAsInCert",
            Self::WithQscd => "QCWithQSCD",
            Self::NoQscd => "QCNoQSCD",
            Self::QscdAsInCert => "QCQSCDStatusAsInCert",
            Self::QscdManagedOnBehalf => "QCQSCDManagedOnBehalf",
            Self::LegalPerson => "QCForLegalPerson",
            Self::ForEsig => "QCForESig",
            Self::ForEseal => "QCForESeal",
            Self::ForWsa => "QCForWSA",
            Self::NotQualified => "NotQualified",
            Self::QcStatement => "QCStatement",
        }
    }

    /// The qualifier URI.
    pub fn uri(self) -> String {
        format!("{SVCINFOEXT_URI_BASE}/{}", self.value())
    }

    /// Look up a qualifier by URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|q| q.uri() == uri)
    }
}

/// How to combine sub-criteria (`CriteriaCombination`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CriteriaCombination {
    /// All must match (`all`).
    All,
    /// At least one must match (`atLeastOne`).
    AtLeastOne,
    /// None may match (`none`).
    None,
}

impl CriteriaCombination {
    /// Parse the `assert` attribute value.
    pub fn from_value(v: &str) -> Option<Self> {
        match v {
            "all" => Some(Self::All),
            "atLeastOne" => Some(Self::AtLeastOne),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// A criterion for a qualifier to apply to a certificate (`Criterion`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Criterion {
    /// Key usage constraints must hold (`KeyUsageCriterion`).
    KeyUsage(KeyUsageConstraints),
    /// All of these policy OIDs must be asserted (`PolicySetCriterion`).
    PolicySet(BTreeSet<String>),
    /// The subject DN must contain attributes of all these types
    /// (`CertSubjectDNCriterion`).
    CertSubjectDn(BTreeSet<String>),
    /// A nested list (`CriteriaList`).
    List(CriteriaList),
}

/// Policy OIDs (dotted) asserted in the certificate policies extension.
///
/// Decoded without `const-oid`, which rejects arcs such as `2.999`.
pub fn cert_policy_oids(cert: &Cert) -> BTreeSet<String> {
    crate::util::certificate_policy_oids(cert).unwrap_or_default()
}

impl Criterion {
    /// Evaluate the criterion (`matches`).
    pub fn matches(&self, cert: &Cert) -> bool {
        match self {
            Self::KeyUsage(ku) => ku.validate(cert).is_ok(),
            Self::PolicySet(required) => required.is_subset(&cert_policy_oids(cert)),
            Self::CertSubjectDn(required) => {
                let found: BTreeSet<String> = cert
                    .subject()
                    .iter()
                    .map(|atv| atv.oid.to_string())
                    .collect();
                required.is_subset(&found)
            }
            Self::List(list) => list.matches(cert),
        }
    }
}

/// A combination of criteria (`CriteriaList`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CriteriaList {
    /// Combination rule.
    pub combine_as: CriteriaCombination,
    /// Sub-criteria (a set: duplicates are removed on construction).
    pub criteria: Vec<Criterion>,
}

impl CriteriaList {
    /// Build a list, removing duplicate criteria (pyHanko uses a frozenset).
    pub fn new(combine_as: CriteriaCombination, criteria: impl IntoIterator<Item = Criterion>) -> Self {
        let mut uniq: Vec<Criterion> = Vec::new();
        for c in criteria {
            if !uniq.contains(&c) {
                uniq.push(c);
            }
        }
        Self {
            combine_as,
            criteria: uniq,
        }
    }

    /// Evaluate the list (`matches`).
    pub fn matches(&self, cert: &Cert) -> bool {
        match self.combine_as {
            CriteriaCombination::All => self.criteria.iter().all(|c| c.matches(cert)),
            CriteriaCombination::AtLeastOne => self.criteria.iter().any(|c| c.matches(cert)),
            CriteriaCombination::None => !self.criteria.iter().any(|c| c.matches(cert)),
        }
    }
}

/// A qualification (ETSI TS 119 612, 5.5.9.2) (`Qualification`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Qualification {
    /// Qualifiers applying to matching certificates.
    pub qualifiers: BTreeSet<Qualifier>,
    /// Criteria.
    pub criteria_list: CriteriaList,
}

/// Kind of qualified service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceKind {
    /// Qualified CA (`CAServiceInformation`).
    Ca {
        /// `ExpiredCertsRevocationInfo` cut-off (not yet used in validation,
        /// as in pyHanko).
        expired_certs_revocation_info: Option<Moment>,
    },
    /// Qualified TSA (`QTSTServiceInformation`).
    Qtst,
}

/// A service with conditional qualifiers (`QualifiedServiceInformation`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualifiedServiceInformation {
    /// Basic information.
    pub base_info: BaseServiceInformation,
    /// Qualifications (a set).
    pub qualifications: Vec<Qualification>,
    /// CA or TSA.
    pub kind: ServiceKind,
}

impl QualifiedServiceInformation {
    /// A CA service definition.
    pub fn ca(
        base_info: BaseServiceInformation,
        qualifications: impl IntoIterator<Item = Qualification>,
        expired_certs_revocation_info: Option<Moment>,
    ) -> Self {
        Self {
            base_info,
            qualifications: dedup(qualifications),
            kind: ServiceKind::Ca {
                expired_certs_revocation_info,
            },
        }
    }

    /// A QTST service definition.
    pub fn qtst(base_info: BaseServiceInformation, qualifications: impl IntoIterator<Item = Qualification>) -> Self {
        Self {
            base_info,
            qualifications: dedup(qualifications),
            kind: ServiceKind::Qtst,
        }
    }

    /// `true` for CA service definitions.
    pub fn is_ca(&self) -> bool {
        matches!(self.kind, ServiceKind::Ca { .. })
    }

    /// `ExpiredCertsRevocationInfo`, for CA services.
    pub fn expired_certs_revocation_info(&self) -> Option<Moment> {
        match self.kind {
            ServiceKind::Ca {
                expired_certs_revocation_info,
            } => expired_certs_revocation_info,
            ServiceKind::Qtst => None,
        }
    }
}

fn dedup<T: PartialEq>(it: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();
    for x in it {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

/// A named key (`Authority`): equality is by subject name and public key,
/// as in pyhanko-certvalidator (`AuthorityWithCert` / `NamedKeyAuthority`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Authority {
    name_der: Vec<u8>,
    key_der: Vec<u8>,
    key_id: Option<Vec<u8>>,
}

impl Authority {
    /// The authority of a certificate (`AuthorityWithCert`).
    pub fn of_cert(cert: &Cert) -> Self {
        let key_id = match cert.extension::<SubjectKeyIdentifier>() {
            Ok(Some((_, ski))) => Some(ski.0.as_bytes().to_vec()),
            _ => None,
        };
        Self {
            name_der: cert.subject_der().unwrap_or_default(),
            key_der: cert.public_key().to_der().unwrap_or_default(),
            key_id,
        }
    }

    /// A named key without certificate (`NamedKeyAuthority`).
    pub fn named_key(name: &x509_cert::name::Name, key: &spki::SubjectPublicKeyInfoOwned) -> Self {
        Self {
            name_der: name.to_der().unwrap_or_default(),
            key_der: key.to_der().unwrap_or_default(),
            key_id: None,
        }
    }

    fn hashable(&self) -> (&[u8], &[u8]) {
        (&self.name_der, &self.key_der)
    }

    /// `true` if this authority could have issued `cert`
    /// (`is_potential_issuer_of`).
    pub fn is_potential_issuer_of(&self, cert: &Cert) -> bool {
        if cert.issuer().to_der().ok().as_deref() != Some(self.name_der.as_slice()) {
            return false;
        }
        let aki = match cert.extension::<AuthorityKeyIdentifier>() {
            Ok(Some((_, aki))) => aki.key_identifier.map(|k| k.as_bytes().to_vec()),
            _ => None,
        };
        !matches!((aki, &self.key_id), (Some(a), Some(k)) if a != *k)
    }
}

fn same_authority(a: &Authority, b: &Authority) -> bool {
    a.hashable() == b.hashable()
}

fn service_sort_key(si: &QualifiedServiceInformation) -> (u8, Option<Moment>) {
    match si.base_info.valid_until {
        None => (1, None),
        Some(u) => (0, Some(u)),
    }
}

/// Registry of trusted service providers (`TSPRegistry`).
#[derive(Clone, Debug, Default)]
pub struct TspRegistry {
    ca: Vec<(Authority, Vec<QualifiedServiceInformation>)>,
    tst: Vec<(Authority, Vec<QualifiedServiceInformation>)>,
}

fn register(
    map: &mut Vec<(Authority, Vec<QualifiedServiceInformation>)>,
    sd: &QualifiedServiceInformation,
) {
    for cert in &sd.base_info.provider_certs {
        let auth = Authority::of_cert(cert);
        let entry = match map.iter().position(|(a, _)| same_authority(a, &auth)) {
            Some(i) => &mut map[i].1,
            None => {
                map.push((auth, Vec::new()));
                let last = map.len() - 1;
                &mut map[last].1
            }
        };
        if !entry.contains(sd) {
            entry.push(sd.clone());
        }
    }
}

impl TspRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a qualified CA (`register_ca`).
    pub fn register_ca(&mut self, sd: QualifiedServiceInformation) {
        register(&mut self.ca, &sd);
    }

    /// Register a qualified TSA (`register_tst`).
    pub fn register_tst(&mut self, sd: QualifiedServiceInformation) {
        register(&mut self.tst, &sd);
    }

    /// Register by kind.
    pub fn register(&mut self, sd: QualifiedServiceInformation) {
        if sd.is_ca() {
            self.register_ca(sd);
        } else {
            self.register_tst(sd);
        }
    }

    /// Service definitions under which `authority` may act at `moment` (all
    /// of them if `moment` is `None`), most recent first
    /// (`applicable_service_definitions`).
    pub fn applicable_service_definitions(
        &self,
        authority: &Authority,
        moment: Option<Moment>,
    ) -> Vec<&QualifiedServiceInformation> {
        let lookup = |map: &'_ [(Authority, Vec<QualifiedServiceInformation>)]| -> Vec<usize> {
            map.iter()
                .enumerate()
                .filter(|(_, (a, _))| same_authority(a, authority))
                .map(|(i, _)| i)
                .collect()
        };
        let mut all: Vec<&QualifiedServiceInformation> = Vec::new();
        for i in lookup(&self.ca) {
            all.extend(self.ca[i].1.iter());
        }
        for i in lookup(&self.tst) {
            all.extend(self.tst[i].1.iter());
        }
        // Stable sort, descending (Python's sorted(reverse=True) is stable).
        all.sort_by_key(|sd| std::cmp::Reverse(service_sort_key(sd)));
        all.into_iter()
            .filter(|sd| match moment {
                None => true,
                Some(m) => {
                    sd.base_info.valid_from <= m && sd.base_info.valid_until.is_none_or(|u| u >= m)
                }
            })
            .collect()
    }

    /// Known qualified CAs (`known_certificate_authorities`).
    pub fn known_certificate_authorities(&self) -> Vec<&Authority> {
        self.ca.iter().filter(|(_, sds)| !sds.is_empty()).map(|(a, _)| a).collect()
    }

    /// Known qualified TSAs (`known_timestamp_authorities`).
    pub fn known_timestamp_authorities(&self) -> Vec<&Authority> {
        self.tst.iter().filter(|(_, sds)| !sds.is_empty()).map(|(a, _)| a).collect()
    }

    /// Service definitions of the authorities on `path`
    /// (`applicable_tsps_on_path`).
    pub fn applicable_tsps_on_path(
        &self,
        path: &ValidationPath,
        moment: Option<Moment>,
    ) -> Vec<&QualifiedServiceInformation> {
        let mut out = Vec::new();
        for auth in path_authorities(path) {
            out.extend(self.applicable_service_definitions(&auth, moment));
        }
        out
    }

    /// The certificate registered for `authority`, if any.
    fn cert_for(&self, authority: &Authority) -> Option<&Cert> {
        self.ca
            .iter()
            .chain(self.tst.iter())
            .filter(|(a, _)| same_authority(a, authority))
            .flat_map(|(_, sds)| sds.iter())
            .flat_map(|sd| sd.base_info.provider_certs.iter())
            .find(|c| same_authority(&Authority::of_cert(c), authority))
    }
}

/// Authorities on a path: the trust anchor, then the intermediates
/// (`ValidationPath.iter_authorities`).
pub fn path_authorities(path: &ValidationPath) -> Vec<Authority> {
    let mut out = vec![Authority::of_cert(path.trust_anchor().cert())];
    out.extend(path.intermediates().iter().map(Authority::of_cert));
    out
}

/// Trusted service type of a trust anchor (`TrustedServiceType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrustedServiceType {
    /// Trusted for any purpose.
    Unspecified,
    /// Unsupported service type.
    Unsupported,
    /// Certificate authority.
    CertificateAuthority,
    /// Time-stamping authority.
    TimeStampingAuthority,
}

impl TrustedServiceType {
    /// Map a service type URI.
    pub fn from_service_type_uri(uri: &str) -> Self {
        match uri {
            CA_QC_URI => Self::CertificateAuthority,
            QTST_URI => Self::TimeStampingAuthority,
            _ => Self::Unsupported,
        }
    }
}

/// A trust anchor derived from a registry, with its trust qualifiers
/// (`TSPTrustManager.as_trust_anchor`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualifiedTrustAnchor {
    /// The anchor.
    pub anchor: TrustAnchor,
    /// Service type of the most recent service definition.
    pub trusted_service_type: TrustedServiceType,
    /// Validity window start.
    pub valid_from: Moment,
    /// Validity window end.
    pub valid_until: Option<Moment>,
}

/// Trust manager backed by a [`TspRegistry`] (`TSPTrustManager`).
#[derive(Clone, Debug)]
pub struct TspTrustManager<'a> {
    /// The registry.
    pub registry: &'a TspRegistry,
}

impl<'a> TspTrustManager<'a> {
    /// Wrap a registry.
    pub fn new(registry: &'a TspRegistry) -> Self {
        Self { registry }
    }

    /// The anchor for `authority`, qualified by its most recent service
    /// definition (`as_trust_anchor`).
    pub fn as_trust_anchor(&self, authority: &Authority) -> Option<QualifiedTrustAnchor> {
        let sd = *self.registry.applicable_service_definitions(authority, None).first()?;
        let cert = self.registry.cert_for(authority)?;
        Some(QualifiedTrustAnchor {
            anchor: TrustAnchor::new(cert.clone()),
            trusted_service_type: TrustedServiceType::from_service_type_uri(&sd.base_info.service_type),
            valid_from: sd.base_info.valid_from,
            valid_until: sd.base_info.valid_until,
        })
    }

    /// All anchors (CAs and TSAs) whose trust qualifiers admit validation
    /// at `at`.
    ///
    /// pyhanko-certvalidator enforces the `valid_from` / `valid_until`
    /// qualifiers of an anchor during path validation. `hanko-certvalidator`
    /// does not support trust qualifiers yet, so anchors outside their window
    /// are left out here instead; the outcome is the same.
    pub fn trust_anchors_at(&self, at: Moment) -> Vec<TrustAnchor> {
        let mut out: Vec<TrustAnchor> = Vec::new();
        let auths = self
            .registry
            .known_certificate_authorities()
            .into_iter()
            .chain(self.registry.known_timestamp_authorities());
        for auth in auths {
            if let Some(q) = self.as_trust_anchor(auth) {
                let inside = q.valid_from <= at && q.valid_until.is_none_or(|u| u >= at);
                if inside && !out.contains(&q.anchor) {
                    out.push(q.anchor);
                }
            }
        }
        out
    }

    /// Potential issuers of `cert` among the known CAs
    /// (`find_potential_issuers`).
    pub fn find_potential_issuers(&self, cert: &Cert) -> Vec<QualifiedTrustAnchor> {
        self.registry
            .known_certificate_authorities()
            .into_iter()
            .filter(|a| a.is_potential_issuer_of(cert))
            .filter_map(|a| self.as_trust_anchor(a))
            .collect()
    }
}
