// Derived from pyHanko `sign/fields.py` (`SigSeedValueSpec`,
// `SigCertConstraints`, `SigCertKeyUsage`, `SigSeedValFlags`,
// `SigCertConstraintFlags`, `SeedSignatureType`, `SeedLockDocument`,
// `SigSeedSubFilter`, `SeedValueDictVersion`) (MIT, see LICENSE-pyHanko).

//! Seed value dictionaries (`/SV`) of signature fields.

use const_oid::ObjectIdentifier as Oid;
use hanko_core::cert::Cert;
use hanko_core::errors::{HankoError, Result};
use hanko_pdf::MdpPerm;
use lopdf::{Dictionary, Object, StringFormat};

use crate::pdf::util::{decode_text_string, name, text_string};
use crate::pdf::writer::PdfUpdate;
use crate::signer::directory_string;

fn signing_error(msg: impl Into<String>) -> HankoError {
    HankoError::Signing(msg.into())
}

/// `/SubFilter` values (`SigSeedSubFilter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigSeedSubFilter {
    /// `adbe.pkcs7.detached`.
    AdobePkcs7Detached,
    /// `ETSI.CAdES.detached`.
    Pades,
    /// `ETSI.RFC3161`.
    EtsiRfc3161,
    /// `PBAD.PAdES`.
    PbadPades,
}

impl SigSeedSubFilter {
    /// The PDF name without the slash.
    pub fn pdf_name(self) -> &'static str {
        match self {
            Self::AdobePkcs7Detached => "adbe.pkcs7.detached",
            Self::Pades => "ETSI.CAdES.detached",
            Self::EtsiRfc3161 => "ETSI.RFC3161",
            Self::PbadPades => "PBAD.PAdES",
        }
    }

    /// Parse a PDF name (without slash).
    pub fn from_name(n: &[u8]) -> Option<Self> {
        Some(match n {
            b"adbe.pkcs7.detached" => Self::AdobePkcs7Detached,
            b"ETSI.CAdES.detached" => Self::Pades,
            b"ETSI.RFC3161" => Self::EtsiRfc3161,
            b"PBAD.PAdES" => Self::PbadPades,
            _ => return None,
        })
    }
}

/// `/Ff` flags of a seed value dictionary (`SigSeedValFlags`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SigSeedValFlags(pub u32);

impl SigSeedValFlags {
    /// `/Filter` mandatory.
    pub const FILTER: Self = Self(1);
    /// `/SubFilter` mandatory.
    pub const SUBFILTER: Self = Self(2);
    /// `/V` mandatory.
    pub const V: Self = Self(4);
    /// `/Reasons` mandatory.
    pub const REASONS: Self = Self(8);
    /// `/LegalAttestation` mandatory.
    pub const LEGAL_ATTESTATION: Self = Self(16);
    /// `/AddRevInfo` mandatory.
    pub const ADD_REV_INFO: Self = Self(32);
    /// `/DigestMethod` mandatory.
    pub const DIGEST_METHOD: Self = Self(64);
    /// `/LockDocument` mandatory.
    pub const LOCK_DOCUMENT: Self = Self(128);
    /// `/AppearanceFilter` mandatory.
    pub const APPEARANCE_FILTER: Self = Self(256);

    /// Whether `other` is set.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0 && other.0 != 0
    }
}

impl std::ops::BitOr for SigSeedValFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// `/Ff` flags of a certificate seed value dictionary
/// (`SigCertConstraintFlags`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SigCertConstraintFlags(pub u32);

impl SigCertConstraintFlags {
    /// `/Subject`.
    pub const SUBJECT: Self = Self(1);
    /// `/Issuer`.
    pub const ISSUER: Self = Self(2);
    /// `/OID` (unsupported).
    pub const OID: Self = Self(4);
    /// `/SubjectDN`.
    pub const SUBJECT_DN: Self = Self(8);
    /// Reserved (unsupported).
    pub const RESERVED: Self = Self(16);
    /// `/KeyUsage`.
    pub const KEY_USAGE: Self = Self(32);
    /// `/URL`.
    pub const URL: Self = Self(64);
    /// Unsupported constraints.
    pub const UNSUPPORTED: Self = Self(16 | 4);

    /// Whether any bit of `other` is set.
    pub fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl std::ops::BitOr for SigCertConstraintFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Key usage bit names in asn1crypto order (RFC 5280 bit numbers).
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

/// Key usage requirements (`SigCertKeyUsage`), as sets of bit names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigCertKeyUsage {
    /// Bits that must be set.
    pub must_have: std::collections::BTreeSet<String>,
    /// Bits that must not be set.
    pub forbidden: std::collections::BTreeSet<String>,
}

impl SigCertKeyUsage {
    /// Build from sets of names (`from_sets`).
    pub fn from_sets(must_have: &[&str], forbidden: &[&str]) -> Self {
        Self {
            must_have: must_have.iter().map(|s| (*s).to_owned()).collect(),
            forbidden: forbidden.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// Encode as the 9-character PDF string (`encode_to_sv_string`).
    pub fn encode_to_sv_string(&self) -> String {
        KEY_USAGE_NAMES
            .iter()
            .map(|n| {
                if self.must_have.contains(*n) {
                    '1'
                } else if self.forbidden.contains(*n) {
                    '0'
                } else {
                    'X'
                }
            })
            .collect()
    }

    /// Parse the PDF string (`read_from_sv_string`).
    pub fn read_from_sv_string(s: &str) -> Self {
        let mut out = Self::default();
        for (c, n) in s.chars().take(9).zip(KEY_USAGE_NAMES) {
            match c {
                '1' => {
                    out.must_have.insert(n.to_owned());
                }
                '0' => {
                    out.forbidden.insert(n.to_owned());
                }
                _ => {}
            }
        }
        out
    }
}

/// Names of the key usage bits set on `cert` (empty if no extension).
pub fn cert_key_usage_names(cert: &Cert) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    if let Some(ku) = cert.key_usage() {
        let bits = ku.0.bits();
        for (i, n) in KEY_USAGE_NAMES.iter().enumerate() {
            if bits & (1 << i) != 0 {
                out.insert((*n).to_owned());
            }
        }
    }
    out
}

const NAME_ABBREVS: [(&str, &str); 7] = [
    ("2.5.4.3", "CN"),
    ("2.5.4.5", "SerialNumber"),
    ("2.5.4.6", "C"),
    ("2.5.4.7", "L"),
    ("2.5.4.8", "ST"),
    ("2.5.4.10", "O"),
    ("2.5.4.11", "OU"),
];

/// `(oid, value)` pairs of a name (`x509_name_keyval_pairs`).
pub fn name_keyval_pairs(name: &x509_cert::name::Name) -> Vec<(String, String)> {
    name.iter()
        .map(|atv| {
            (
                atv.oid.to_string(),
                directory_string(&atv.value).unwrap_or_default(),
            )
        })
        .collect()
}

/// Certificate constraints (`SigCertConstraints`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigCertConstraints {
    /// Enforcement flags.
    pub flags: SigCertConstraintFlags,
    /// Allowed signer certificates.
    pub subjects: Option<Vec<Cert>>,
    /// Required subject attributes, as `(oid, value)` pairs.
    pub subject_dn: Option<Vec<(String, String)>>,
    /// Allowed issuers (anywhere in the path).
    pub issuers: Option<Vec<Cert>>,
    /// Informational URL.
    pub info_url: Option<String>,
    /// URL type (default `Browser`).
    pub url_type: String,
    /// Allowed key usage profiles.
    pub key_usage: Option<Vec<SigCertKeyUsage>>,
}

impl SigCertConstraints {
    /// Empty constraints.
    pub fn new() -> Self {
        Self {
            url_type: "Browser".into(),
            ..Self::default()
        }
    }

    /// Render as PDF (`as_pdf_object`).
    pub fn as_pdf_object(&self) -> Dictionary {
        let mut d = Dictionary::new();
        d.set("Type", name("SVCert"));
        d.set("Ff", Object::Integer(i64::from(self.flags.0)));
        let certs = |cs: &[Cert]| {
            Object::Array(
                cs.iter()
                    .map(|c| Object::String(c.der().to_vec(), StringFormat::Hexadecimal))
                    .collect(),
            )
        };
        if let Some(s) = &self.subjects {
            d.set("Subject", certs(s));
        }
        if let Some(dn) = &self.subject_dn {
            if !dn.is_empty() {
                let mut entry = Dictionary::new();
                for (k, v) in dn {
                    let key = NAME_ABBREVS
                        .iter()
                        .find(|(oid, _)| oid == k)
                        .map_or(k.as_str(), |(_, a)| a);
                    entry.set(key.as_bytes().to_vec(), text_string(v));
                }
                d.set("SubjectDN", Object::Array(vec![Object::Dictionary(entry)]));
            }
        }
        if let Some(s) = &self.issuers {
            d.set("Issuer", certs(s));
        }
        if let Some(url) = &self.info_url {
            d.set("URL", text_string(url));
            d.set("URLType", name(&self.url_type));
        }
        if let Some(kus) = &self.key_usage {
            d.set(
                "KeyUsage",
                Object::Array(kus.iter().map(|k| text_string(&k.encode_to_sv_string())).collect()),
            );
        }
        d
    }

    /// Read from PDF (`from_pdf_object`).
    pub fn from_pdf_object(update: &PdfUpdate, d: &Dictionary) -> Result<Self> {
        let mut out = Self::new();
        out.flags = SigCertConstraintFlags(
            update
                .dict_get(d, b"Ff")?
                .and_then(|o| o.as_i64().ok())
                .and_then(|i| u32::try_from(i).ok())
                .unwrap_or(0),
        );
        let read_certs = |key: &[u8]| -> Result<Vec<Cert>> {
            let mut v = Vec::new();
            if let Some(Object::Array(a)) = update.dict_get(d, key)? {
                for o in a {
                    if let Object::String(b, _) = update.resolve(o)? {
                        v.push(Cert::from_der(b)?);
                    }
                }
            }
            Ok(v)
        };
        let subjects = read_certs(b"Subject")?;
        let issuers = read_certs(b"Issuer")?;
        out.subjects = (!subjects.is_empty()).then_some(subjects);
        out.issuers = (!issuers.is_empty()).then_some(issuers);
        let mut dn = Vec::new();
        if let Some(Object::Array(a)) = update.dict_get(d, b"SubjectDN")? {
            for entry in a {
                if let Object::Dictionary(e) = update.resolve(entry)? {
                    for (k, v) in e.iter() {
                        let key = String::from_utf8_lossy(k).to_string();
                        let oid = NAME_ABBREVS
                            .iter()
                            .find(|(_, a)| a.eq_ignore_ascii_case(&key))
                            .map_or(key.clone(), |(o, _)| (*o).to_owned());
                        if let Object::String(s, _) = update.resolve(v)? {
                            dn.push((oid, decode_text_string(s)));
                        }
                    }
                }
            }
        }
        out.subject_dn = (!dn.is_empty()).then_some(dn);
        if let Some(Object::Array(a)) = update.dict_get(d, b"KeyUsage")? {
            let mut kus = Vec::new();
            for o in a {
                if let Object::String(s, _) = update.resolve(o)? {
                    kus.push(SigCertKeyUsage::read_from_sv_string(&decode_text_string(s)));
                }
            }
            out.key_usage = Some(kus);
        }
        let url = match update.dict_get(d, b"URL")? {
            Some(Object::String(s, _)) => Some(decode_text_string(s)),
            _ => None,
        };
        if url.is_some() {
            if let Some(Object::Name(n)) = update.dict_get(d, b"URLType")? {
                out.url_type = String::from_utf8_lossy(n).into_owned();
            }
        }
        out.info_url = url;
        Ok(out)
    }

    /// Check the signer certificate against the constraints
    /// (`satisfied_by`); `path_issuers` are the issuer certificates of the
    /// signer's validation path, if known.
    pub fn satisfied_by(&self, signer: &Cert, path_issuers: Option<&[Cert]>) -> Result<()> {
        let flags = self.flags;
        if flags.intersects(SigCertConstraintFlags::UNSUPPORTED) {
            return Err(HankoError::Unsupported(
                "Certificate constraint flags include mandatory constraints that are not supported."
                    .into(),
            ));
        }
        let unacceptable = |m: &str| HankoError::Signing(format!("UnacceptableSignerError: {m}"));
        let issuer_serial = |c: &Cert| (c.issuer().clone(), c.serial_bytes().to_vec());
        if flags.intersects(SigCertConstraintFlags::SUBJECT) {
            if let Some(subjects) = &self.subjects {
                let me = issuer_serial(signer);
                if !subjects.iter().any(|s| issuer_serial(s) == me) {
                    return Err(unacceptable("Signer certificate not on SVCert whitelist."));
                }
            }
        }
        if flags.intersects(SigCertConstraintFlags::ISSUER) {
            if let Some(issuers) = &self.issuers {
                let Some(path) = path_issuers else {
                    return Err(unacceptable("Validation path not provided."));
                };
                let in_path: Vec<_> = path.iter().map(issuer_serial).collect();
                if !issuers.iter().any(|i| in_path.contains(&issuer_serial(i))) {
                    return Err(unacceptable(
                        "Signer certificate cannot be traced back to approved issuer.",
                    ));
                }
            }
        }
        if flags.intersects(SigCertConstraintFlags::SUBJECT_DN) {
            if let Some(dn) = &self.subject_dn {
                let subject = name_keyval_pairs(signer.subject());
                if !dn.iter().all(|attr| subject.contains(attr)) {
                    return Err(unacceptable(
                        "Subject does not have some of the following required attributes",
                    ));
                }
            }
        }
        if flags.intersects(SigCertConstraintFlags::KEY_USAGE) {
            if let Some(kus) = &self.key_usage {
                let have = cert_key_usage_names(signer);
                let ok = kus.iter().any(|ku| {
                    ku.must_have.iter().all(|b| have.contains(b))
                        && !ku.forbidden.iter().any(|b| have.contains(b))
                });
                if !ok {
                    return Err(unacceptable(
                        "The signer satisfies none of the key usage extension profiles specified in the seed value dictionary.",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// `/LockDocument` (`SeedLockDocument`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SeedLockDocument {
    /// `/true`.
    Lock,
    /// `/false`.
    DoNotLock,
    /// `/auto`.
    SignerDiscretion,
}

/// Seed value dictionary version (`SeedValueDictVersion`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SeedValueDictVersion {
    /// PDF 1.5.
    Pdf15 = 1,
    /// PDF 1.7.
    Pdf17 = 2,
    /// PDF 2.0.
    Pdf20 = 3,
}

/// A seed value dictionary (`SigSeedValueSpec`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigSeedValueSpec {
    /// Enforcement flags.
    pub flags: SigSeedValFlags,
    /// Acceptable reasons.
    pub reasons: Option<Vec<String>>,
    /// Timestamp server URL.
    pub timestamp_server_url: Option<String>,
    /// A timestamp is required.
    pub timestamp_required: bool,
    /// Certificate constraints.
    pub cert: Option<SigCertConstraints>,
    /// Acceptable subfilters.
    pub subfilters: Option<Vec<SigSeedSubFilter>>,
    /// Acceptable digest methods (lower case).
    pub digest_methods: Option<Vec<String>>,
    /// Adobe-style revocation info requirement.
    pub add_rev_info: Option<bool>,
    /// `/MDP`: `Some(None)` = approval signature, `Some(Some(p))` =
    /// certification with `p`.
    pub seed_signature_type: Option<Option<MdpPerm>>,
    /// `/V` (explicit).
    pub sv_dict_version: Option<u32>,
    /// Legal attestations.
    pub legal_attestations: Option<Vec<String>>,
    /// `/LockDocument`.
    pub lock_document: Option<SeedLockDocument>,
    /// Named appearance.
    pub appearance: Option<String>,
}

impl SigSeedValueSpec {
    /// Render as a PDF dictionary (`as_pdf_object`).
    pub fn as_pdf_object(&self, _update: &PdfUpdate) -> Result<Dictionary> {
        let mut min_version = SeedValueDictVersion::Pdf15;
        let mut d = Dictionary::new();
        d.set("Type", name("SV"));
        d.set("Ff", Object::Integer(i64::from(self.flags.0)));
        if let Some(sfs) = &self.subfilters {
            d.set(
                "SubFilter",
                Object::Array(sfs.iter().map(|s| name(s.pdf_name())).collect()),
            );
        }
        if let Some(b) = self.add_rev_info {
            min_version = SeedValueDictVersion::Pdf17;
            d.set("AddRevInfo", Object::Boolean(b));
        }
        if let Some(dm) = &self.digest_methods {
            min_version = SeedValueDictVersion::Pdf17;
            d.set("DigestMethod", Object::Array(dm.iter().map(|s| text_string(s)).collect()));
        }
        if let Some(r) = &self.reasons {
            d.set("Reasons", Object::Array(r.iter().map(|s| text_string(s)).collect()));
        }
        if let Some(url) = &self.timestamp_server_url {
            min_version = SeedValueDictVersion::Pdf17;
            let mut ts = Dictionary::new();
            ts.set("URL", text_string(url));
            ts.set("Ff", Object::Integer(i64::from(self.timestamp_required)));
            d.set("TimeStamp", Object::Dictionary(ts));
        }
        if let Some(c) = &self.cert {
            d.set("Cert", Object::Dictionary(c.as_pdf_object()));
        }
        if let Some(st) = &self.seed_signature_type {
            let mut mdp = Dictionary::new();
            mdp.set("P", Object::Integer(st.map_or(0, |p| p as i64)));
            d.set("MDP", Object::Dictionary(mdp));
        }
        if let Some(la) = &self.legal_attestations {
            d.set("LegalAttestation", Object::Array(la.iter().map(|s| text_string(s)).collect()));
        }
        if let Some(ld) = self.lock_document {
            min_version = SeedValueDictVersion::Pdf20;
            d.set(
                "LockDocument",
                name(match ld {
                    SeedLockDocument::Lock => "true",
                    SeedLockDocument::DoNotLock => "false",
                    SeedLockDocument::SignerDiscretion => "auto",
                }),
            );
        }
        if let Some(a) = &self.appearance {
            d.set("AppearanceFilter", text_string(a));
        }
        d.set(
            "V",
            Object::Integer(i64::from(self.sv_dict_version.unwrap_or(min_version as u32))),
        );
        Ok(d)
    }

    /// Read a seed value dictionary (`from_pdf_object`).
    pub fn from_pdf_object(update: &PdfUpdate, d: &Dictionary) -> Result<Self> {
        let mut out = Self::default();
        let int = |o: Option<&Object>| o.and_then(|o| o.as_i64().ok());
        out.flags = SigSeedValFlags(
            int(update.dict_get(d, b"Ff")?)
                .and_then(|i| u32::try_from(i).ok())
                .unwrap_or(0),
        );
        if let Some(Object::Name(f)) = update.dict_get(d, b"Filter")? {
            if out.flags.contains(SigSeedValFlags::FILTER) && f != b"Adobe.PPKLite" {
                return Err(signing_error(format!(
                    "Signature handler '/{}' is not available, only the default /Adobe.PPKLite is supported.",
                    String::from_utf8_lossy(f)
                )));
            }
        }
        if let Some(v) = int(update.dict_get(d, b"V")?) {
            if out.flags.contains(SigSeedValFlags::V) && v > SeedValueDictVersion::Pdf20 as i64 {
                return Err(signing_error(format!(
                    "Seed value dictionary version {v} not supported."
                )));
            }
            out.sv_dict_version = u32::try_from(v).ok();
        }
        if let Some(o) = update.dict_get(d, b"AddRevInfo")? {
            out.add_rev_info = Some(matches!(o, Object::Boolean(true)));
        }
        if let Some(Object::Array(a)) = update.dict_get(d, b"SubFilter")? {
            out.subfilters = Some(
                a.iter()
                    .filter_map(|o| update.resolve(o).ok())
                    .filter_map(|o| o.as_name().ok())
                    .filter_map(SigSeedSubFilter::from_name)
                    .collect(),
            );
        }
        let strings = |o: Option<&Object>| -> Option<Vec<String>> {
            match o {
                Some(Object::Array(a)) => Some(
                    a.iter()
                        .filter_map(|x| update.resolve(x).ok())
                        .filter_map(|x| match x {
                            Object::String(s, _) => Some(decode_text_string(s)),
                            Object::Name(n) => Some(String::from_utf8_lossy(n).into_owned()),
                            _ => None,
                        })
                        .collect(),
                ),
                _ => None,
            }
        };
        out.digest_methods = strings(update.dict_get(d, b"DigestMethod")?)
            .map(|v| v.into_iter().map(|s| s.to_lowercase()).collect());
        out.reasons = strings(update.dict_get(d, b"Reasons")?);
        out.legal_attestations = strings(update.dict_get(d, b"LegalAttestation")?);
        if let Some(mdp) = update.dict_get(d, b"MDP")? {
            let bad = || {
                signing_error("/MDP entry in seed value dictionary is not correctly formatted.")
            };
            let Object::Dictionary(mdp) = mdp else {
                return Err(bad());
            };
            let p = int(update.dict_get(mdp, b"P")?).ok_or_else(bad)?;
            out.seed_signature_type = Some(match p {
                0 => None,
                1 => Some(MdpPerm::NoChanges),
                2 => Some(MdpPerm::FillForms),
                3 => Some(MdpPerm::Annotate),
                _ => return Err(bad()),
            });
        }
        if let Some(o) = update.dict_get(d, b"LockDocument")? {
            out.lock_document = Some(match o {
                Object::Name(n) if n == b"true" => SeedLockDocument::Lock,
                Object::Name(n) if n == b"false" => SeedLockDocument::DoNotLock,
                Object::Name(n) if n == b"auto" => SeedLockDocument::SignerDiscretion,
                _ => return Err(signing_error("/LockDocument entry is invalid.")),
            });
        }
        if let Some(Object::String(s, _)) = update.dict_get(d, b"AppearanceFilter")? {
            out.appearance = Some(decode_text_string(s));
        }
        if let Some(Object::Dictionary(ts)) = update.dict_get(d, b"TimeStamp")? {
            if let Some(Object::String(s, _)) = update.dict_get(ts, b"URL")? {
                out.timestamp_server_url = Some(decode_text_string(s));
            }
            out.timestamp_required = int(update.dict_get(ts, b"Ff")?).unwrap_or(0) != 0;
        }
        if let Some(Object::Dictionary(c)) = update.dict_get(d, b"Cert")? {
            out.cert = Some(SigCertConstraints::from_pdf_object(update, c)?);
        }
        Ok(out)
    }
}

#[doc(hidden)]
pub fn _oid(s: &str) -> Option<Oid> {
    Oid::new(s).ok()
}
