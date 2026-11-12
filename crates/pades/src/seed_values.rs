// Derived from pyHanko 0.38.1 `sign/validation/pdf_embedded.py`
// (`_validate_sv_constraints`) and `sign/fields.py` (MIT).

//! Validation of seed constraints from the signed revision of a PDF field.

use std::cell::Cell;
use std::collections::BTreeSet;

use der::Decode;
use sigis_cms::StandardCmsSignatureStatus;
use sigis_pdf::lopdf::{Dictionary, Object};
use sigis_pdf::{EmbeddedSignature, MdpPerm, PdfFile};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{HankoError, Result};
use sigis_pki_core::key_usage::{cert_key_usages, KeyUsageConstraints, KEY_USAGE_NAMES};

use crate::errors::{SignatureValidationError, SignatureValidationErrorKind};
use crate::integrity::{resolve, SUBFILTERS};

const FILTER: u64 = 1;
const SUBFILTER: u64 = 2;
const REASONS: u64 = 8;
const LEGAL_ATTESTATION: u64 = 16;
const ADD_REV_INFO: u64 = 32;
const DIGEST_METHOD: u64 = 64;
const LOCK_DOCUMENT: u64 = 128;
const APPEARANCE_FILTER: u64 = 256;
const KNOWN_SEED_FLAGS: u64 = 511;
const SUBJECT: u64 = 1;
const ISSUER: u64 = 2;
const SUBJECT_DN: u64 = 8;
const KEY_USAGE: u64 = 32;
const KNOWN_CERT_FLAGS: u64 = 127;
const UNSUPPORTED_CERT_FLAGS: u64 = 4 | 16;

fn malformed(message: impl Into<String>) -> HankoError {
    HankoError::Malformed(message.into())
}

/// Every object is resolved through the authenticated historical reader.
/// The local budget also bounds repeated lookups and seed list processing.
struct Reader<'a> {
    file: &'a PdfFile,
    revision: usize,
    remaining: Cell<usize>,
}

impl Reader<'_> {
    fn object(&self, object: &Object) -> Result<Object> {
        let remaining = self
            .remaining
            .get()
            .checked_sub(1)
            .ok_or_else(|| malformed("Seed value object budget exceeded"))?;
        self.remaining.set(remaining);
        resolve(self.file, object, self.revision)
    }

    fn entry(&self, dictionary: &Dictionary, key: &[u8]) -> Result<Option<Object>> {
        dictionary
            .get(key)
            .ok()
            .map(|value| self.object(value))
            .transpose()
    }

    fn dictionary(&self, object: &Object) -> Result<Dictionary> {
        match self.object(object)? {
            Object::Dictionary(dictionary) => Ok(dictionary),
            _ => Err(malformed("Seed value entry must be a dictionary")),
        }
    }

    fn array(&self, object: &Object) -> Result<Vec<Object>> {
        match self.object(object)? {
            Object::Array(values) if values.len() <= 1024 => Ok(values),
            Object::Array(_) => Err(malformed("Seed value array exceeds validation budget")),
            _ => Err(malformed("Seed value entry must be an array")),
        }
    }

    fn text(&self, object: &Object) -> Result<String> {
        match self.object(object)? {
            Object::String(bytes, _) => sigis_pdf::generic::decode_text(&bytes)
                .ok_or_else(|| malformed("Seed value string has invalid text encoding")),
            _ => Err(malformed("Seed value entry must be a text string")),
        }
    }

    fn name(&self, object: &Object) -> Result<String> {
        match self.object(object)? {
            Object::Name(bytes) => {
                String::from_utf8(bytes).map_err(|_| malformed("Seed value name is not UTF-8"))
            }
            _ => Err(malformed("Seed value entry must be a name")),
        }
    }

    fn integer_entry(&self, dictionary: &Dictionary, key: &[u8]) -> Result<Option<i64>> {
        self.entry(dictionary, key)?
            .map(|value| match value {
                Object::Integer(value) => Ok(value),
                _ => Err(malformed("Seed value entry must be an integer")),
            })
            .transpose()
    }

    fn flags(&self, dictionary: &Dictionary) -> Result<u64> {
        self.integer_entry(dictionary, b"Ff")?
            .unwrap_or(0)
            .try_into()
            .map_err(|_| malformed("Seed value flags must not be negative"))
    }

    fn text_entry(&self, dictionary: &Dictionary, key: &[u8]) -> Result<Option<String>> {
        self.entry(dictionary, key)?
            .map(|value| self.text(&value))
            .transpose()
    }

    fn names_entry(&self, dictionary: &Dictionary, key: &[u8]) -> Result<Option<Vec<String>>> {
        self.entry(dictionary, key)?
            .map(|value| {
                self.array(&value)?
                    .iter()
                    .map(|item| self.name(item))
                    .collect()
            })
            .transpose()
    }

    fn texts_entry(&self, dictionary: &Dictionary, key: &[u8]) -> Result<Option<Vec<String>>> {
        self.entry(dictionary, key)?
            .map(|value| {
                self.array(&value)?
                    .iter()
                    .map(|item| self.text(item))
                    .collect()
            })
            .transpose()
    }

    fn certs_entry(&self, dictionary: &Dictionary, key: &[u8]) -> Result<Option<Vec<Cert>>> {
        let Some(value) = self.entry(dictionary, key)? else {
            return Ok(None);
        };
        let mut certificates = Vec::new();
        for item in self.array(&value)? {
            let Object::String(bytes, _) = self.object(&item)? else {
                return Err(malformed("Seed certificate must be a DER byte string"));
            };
            certificates.push(
                Cert::from_der(&bytes)
                    .map_err(|error| malformed(format!("Invalid seed certificate: {error}")))?,
            );
        }
        // pyHanko normalises an empty /Subject or /Issuer list to None.
        Ok((!certificates.is_empty()).then_some(certificates))
    }

    fn check_type(&self, dictionary: &Dictionary, expected: &str) -> Result<()> {
        if let Some(value) = self.entry(dictionary, b"Type")? {
            if self.name(&value)? != expected {
                return Err(malformed(format!(
                    "Seed dictionary /Type must be /{expected}"
                )));
            }
        }
        Ok(())
    }

    fn was_certified(&self, signature: &EmbeddedSignature) -> Result<bool> {
        let trailer = self.file.trailer_in_revision(self.revision)?;
        let Some(root) = self.entry(&trailer, b"Root")? else {
            return Ok(false);
        };
        let root = self.dictionary(&root)?;
        let Some(permissions) = self.entry(&root, b"Perms")? else {
            return Ok(false);
        };
        let permissions = self.dictionary(&permissions)?;
        let Ok(pointer) = permissions.get(b"DocMDP") else {
            return Ok(false);
        };
        // Resolve to verify authentication and reference validity, but retain
        // the identity of the reference for the certification comparison.
        self.object(pointer)?;
        Ok(matches!(pointer, Object::Reference(id) if *id == signature.sig_object))
    }
}

fn same_issuer_serial(left: &Cert, right: &Cert) -> bool {
    left.serial_bytes() == right.serial_bytes() && left.issuer() == right.issuer()
}

fn attribute_oid(key: &[u8]) -> Result<String> {
    let key =
        std::str::from_utf8(key).map_err(|_| malformed("SubjectDN attribute key is not UTF-8"))?;
    let oid = match key.to_ascii_uppercase().as_str() {
        "CN" => "2.5.4.3",
        "C" => "2.5.4.6",
        "L" => "2.5.4.7",
        "ST" => "2.5.4.8",
        "O" => "2.5.4.10",
        "OU" => "2.5.4.11",
        // The pinned oracle does not accept its mixed-case SerialNumber
        // alias on import. Its dotted OID remains fully supported.
        _ => {
            der::asn1::ObjectIdentifier::new(key)
                .map_err(|_| malformed(format!("Unsupported SubjectDN attribute {key}")))?;
            key
        }
    };
    Ok(oid.to_owned())
}

fn key_usage_matches(certificate: &Cert, profiles: &[String]) -> bool {
    let asserted = cert_key_usages(certificate).unwrap_or_default();
    profiles.iter().any(|profile| {
        let mut required = BTreeSet::new();
        let mut forbidden = BTreeSet::new();
        for (bit, character) in profile.chars().take(9).enumerate() {
            match character {
                '1' => {
                    required.insert(KEY_USAGE_NAMES[bit].to_owned());
                }
                '0' => {
                    forbidden.insert(KEY_USAGE_NAMES[bit].to_owned());
                }
                _ => {}
            }
        }
        // The shared API returns early when required is empty. Seed values
        // still have to enforce a forbidden-only profile explicitly.
        if !asserted.is_disjoint(&forbidden) {
            return false;
        }
        KeyUsageConstraints {
            key_usage: Some(required),
            key_usage_forbidden: Some(forbidden),
            match_all_key_usages: true,
            ..Default::default()
        }
        .validate(certificate)
        .is_ok()
    })
}

fn check_certificate(
    reader: &Reader<'_>,
    dictionary: &Dictionary,
    cms: &StandardCmsSignatureStatus,
) -> Result<Option<String>> {
    reader.check_type(dictionary, "SVCert")?;
    let flags = reader.flags(dictionary)?;
    if flags & (!KNOWN_CERT_FLAGS | UNSUPPORTED_CERT_FLAGS) != 0 {
        return Err(HankoError::NotImplemented(
            "Certificate constraint flags include mandatory constraints that are not supported.",
        ));
    }
    let subjects = reader.certs_entry(dictionary, b"Subject")?;
    let issuers = reader.certs_entry(dictionary, b"Issuer")?;
    let usages = reader.texts_entry(dictionary, b"KeyUsage")?;
    let mut distinguished_name = Vec::new();
    if let Some(value) = reader.entry(dictionary, b"SubjectDN")? {
        for entry in reader.array(&value)? {
            for (key, value) in reader.dictionary(&entry)?.iter() {
                distinguished_name.push((attribute_oid(key)?, reader.text(value)?));
            }
        }
    }
    let Some(signer) = cms.signature.signing_cert.as_ref() else {
        return Ok(Some(
            "Signer certificate unavailable for seed value constraints.".into(),
        ));
    };
    if flags & SUBJECT != 0 {
        if let Some(subjects) = subjects {
            if !subjects
                .iter()
                .any(|candidate| same_issuer_serial(candidate, signer))
            {
                return Ok(Some("Signer certificate not on SVCert whitelist.".into()));
            }
        }
    }
    if flags & ISSUER != 0 {
        if let Some(issuers) = issuers {
            let Some(path) = cms
                .signature
                .validation_path
                .as_ref()
                .filter(|_| cms.signature.trusted())
            else {
                return Ok(Some("Validation path not provided.".into()));
            };
            if !issuers.iter().any(|approved| {
                path.authorities()
                    .iter()
                    .any(|authority| same_issuer_serial(approved, authority))
            }) {
                return Ok(Some(
                    "Signer certificate cannot be traced back to approved issuer.".into(),
                ));
            }
        }
    }
    if flags & SUBJECT_DN != 0 && !distinguished_name.is_empty() {
        let subject: Vec<_> = signer
            .subject()
            .iter()
            .filter_map(|attribute| {
                sigis_pki_certvalidator::names::attribute_string(attribute)
                    .map(|value| (attribute.oid.to_string(), value))
            })
            .collect();
        if !distinguished_name
            .iter()
            .all(|attribute| subject.contains(attribute))
        {
            return Ok(Some(
                "Subject does not have some of the required attributes.".into(),
            ));
        }
    }
    if flags & KEY_USAGE != 0 {
        if let Some(profiles) = usages {
            if !key_usage_matches(signer, &profiles) {
                return Ok(Some("The signer satisfies none of the key usage extension profiles specified in the seed value dictionary.".into()));
            }
        }
    }
    Ok(None)
}

fn adobe_revinfo_present(signature: &EmbeddedSignature) -> Result<bool> {
    let bytes = crate::cms_from_contents(&signature.contents)?;
    let content = cms::content_info::ContentInfo::from_der(bytes)
        .map_err(|error| malformed(error.to_string()))?;
    let signed_data: cms::signed_data::SignedData = content
        .content
        .decode_as()
        .map_err(|error: der::Error| malformed(error.to_string()))?;
    let signer = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| malformed("Missing CMS SignerInfo"))?;
    let mut matches = signer
        .signed_attrs
        .iter()
        .flat_map(|attributes| attributes.iter())
        .filter(|attribute| attribute.oid.to_string() == "1.2.840.113583.1.1.8");
    let Some(attribute) = matches.next() else {
        return Ok(false);
    };
    Ok(attribute.values.len() == 1 && matches.next().is_none())
}

fn check_seed(
    reader: &Reader<'_>,
    signature: &EmbeddedSignature,
    seed: &Dictionary,
    sig_dict: &Dictionary,
    cms: &StandardCmsSignatureStatus,
    docmdp: Option<MdpPerm>,
) -> Result<Option<String>> {
    reader.check_type(seed, "SV")?;
    let flags = reader.flags(seed)?;
    if flags & !KNOWN_SEED_FLAGS != 0 {
        return Err(HankoError::NotImplemented(
            "Unknown mandatory seed value flags",
        ));
    }
    // The oracle reads /Filter even when it is only a hint. An optional
    // constraint must not conceal a dangling or unauthenticated reference.
    let filter = reader.entry(seed, b"Filter")?;
    if flags & FILTER != 0 {
        if let Some(filter) = filter {
            if reader.name(&filter)? != "Adobe.PPKLite" {
                return Err(HankoError::NotImplemented(
                    "Unsupported mandatory signature handler",
                ));
            }
        }
    }
    if let Some(version) = reader.integer_entry(seed, b"V")? {
        if !(1..=3).contains(&version) {
            return Err(HankoError::NotImplemented(
                "Unsupported seed value dictionary version",
            ));
        }
    }
    let reasons = reader.texts_entry(seed, b"Reasons")?;
    let subfilters = reader.names_entry(seed, b"SubFilter")?;
    let digests = reader.texts_entry(seed, b"DigestMethod")?;
    reader.text_entry(seed, b"AppearanceFilter")?;
    reader.texts_entry(seed, b"LegalAttestation")?;
    let lock = reader
        .entry(seed, b"LockDocument")?
        .map(|value| reader.name(&value))
        .transpose()?;
    if lock
        .as_ref()
        .is_some_and(|value| !["true", "false", "auto"].contains(&value.as_str()))
    {
        return Err(malformed("Invalid /LockDocument seed value"));
    }
    let add_revinfo = reader
        .entry(seed, b"AddRevInfo")?
        .map(|value| match value {
            Object::Boolean(value) => Ok(value),
            _ => Err(malformed("/AddRevInfo must be a boolean")),
        })
        .transpose()?;

    // Certificate constraints, timestamp requirements and signature type do
    // not depend on the enforcement flags of the enclosing /SV dictionary.
    if let Some(value) = reader.entry(seed, b"Cert")? {
        if let Some(error) = check_certificate(reader, &reader.dictionary(&value)?, cms)? {
            return Ok(Some(error));
        }
    }
    if let Some(value) = reader.entry(seed, b"TimeStamp")? {
        let timestamp = reader.dictionary(&value)?;
        reader.text_entry(&timestamp, b"URL")?;
        let required = reader.flags(&timestamp)?;
        if required > 1 {
            return Err(HankoError::NotImplemented(
                "Unknown mandatory timestamp seed flags",
            ));
        }
        if required != 0
            && !cms.timestamp_validity.as_ref().is_some_and(|status| {
                status.signature.intact && status.signature.valid && status.trusted()
            })
        {
            return Ok(Some("The seed value dictionary requires a trusted timestamp, but none was found, or the timestamp did not validate.".into()));
        }
    }
    if let Some(value) = reader.entry(seed, b"MDP")? {
        let mdp = reader.dictionary(&value)?;
        let permission = reader
            .integer_entry(&mdp, b"P")?
            .filter(|value| (0..=3).contains(value))
            .ok_or_else(|| malformed("Seed /MDP must contain a /P integer from 0 through 3"))?;
        let certified = reader.was_certified(signature)?;
        if (permission != 0) != certified {
            return Ok(Some(
                "The seed value dictionary's /MDP entry specifies a different signature type."
                    .into(),
            ));
        }
        if certified && docmdp.map(|value| value as i64) != Some(permission) {
            return Ok(Some(
                "The seed value dictionary specified a different certification MDP policy.".into(),
            ));
        }
    }
    if flags & SUBFILTER != 0 {
        if let Some(subfilters) = subfilters {
            let mandated = subfilters.iter().find(|candidate| SUBFILTERS.contains(&candidate.as_str()))
                .ok_or(HankoError::NotImplemented("The signature encodings mandated by the seed value dictionary are not supported."))?;
            if signature.sub_filter.as_ref() != Some(mandated) {
                return Ok(Some(format!(
                    "The seed value dictionary mandates subfilter '/{mandated}'."
                )));
            }
        }
    }
    if flags & APPEARANCE_FILTER != 0 {
        return Ok(Some(
            "The mandatory named appearance constraint cannot be validated.".into(),
        ));
    }
    if flags & LEGAL_ATTESTATION != 0 {
        return Err(HankoError::NotImplemented(
            "Mandatory legal attestations cannot be validated",
        ));
    }
    if flags & LOCK_DOCUMENT != 0 {
        if lock.as_deref() == Some("true") && docmdp != Some(MdpPerm::NoChanges) {
            return Ok(Some(
                "Document must be locked, but some changes are still allowed.".into(),
            ));
        }
        if lock.as_deref() == Some("false") && docmdp == Some(MdpPerm::NoChanges) {
            return Ok(Some(
                "Document must not be locked, but the DocMDP level is set to NO_CHANGES.".into(),
            ));
        }
    }
    if flags & ADD_REV_INFO != 0 {
        if let Some(required) = add_revinfo {
            if required != adobe_revinfo_present(signature)? {
                return Ok(Some("Embedded Adobe revocation information does not satisfy the seed value requirement.".into()));
            }
            if required && signature.sub_filter.as_deref() != Some("adbe.pkcs7.detached") {
                return Ok(Some(
                    "Adobe-style revocation information requires /adbe.pkcs7.detached.".into(),
                ));
            }
        }
    }
    if flags & DIGEST_METHOD != 0 {
        if let Some(digests) = digests {
            let selected = cms
                .signature
                .md_algorithm
                .map(|algorithm| algorithm.name().to_owned())
                .unwrap_or_else(|| cms.signature.md_algorithm_name.clone())
                .to_ascii_lowercase();
            if !digests
                .iter()
                .any(|digest| digest.to_ascii_lowercase() == selected)
            {
                return Ok(Some(format!("The selected message digest {selected} is not allowed by the seed value dictionary.")));
            }
        }
    }
    if flags & REASONS != 0 {
        let reasons = reasons.unwrap_or_default();
        let must_omit = reasons.is_empty() || reasons.as_slice() == ["."];
        let reason = reader.text_entry(sig_dict, b"Reason")?;
        if must_omit && reason.is_some() {
            return Ok(Some(
                "The seed value dictionary prohibits giving a reason for signing.".into(),
            ));
        }
        if !must_omit
            && reason
                .as_ref()
                .is_none_or(|reason| !reasons.contains(reason))
        {
            return Ok(Some(
                "The reason for signing is not accepted by the seed value dictionary.".into(),
            ));
        }
    }
    Ok(None)
}

/// Validate seed values recorded with the signature, never a later field state.
pub(crate) fn validate(
    file: &PdfFile,
    signature: &EmbeddedSignature,
    sig_dict: &Dictionary,
    cms: &StandardCmsSignatureStatus,
    docmdp: Option<MdpPerm>,
) -> Result<(bool, Option<SignatureValidationError>)> {
    let reader = Reader {
        file,
        revision: signature.signed_revision,
        remaining: Cell::new(4096),
    };
    let field = reader.dictionary(&Object::Reference(signature.field_object))?;
    let Some(seed) = reader.entry(&field, b"SV")? else {
        return Ok((false, None));
    };
    let seed = reader.dictionary(&seed)?;
    let error = check_seed(&reader, signature, &seed, sig_dict, cms, docmdp)?.map(|message| {
        SignatureValidationError::new(message, None)
            .with_kind(SignatureValidationErrorKind::SeedValue)
    });
    Ok((true, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_only_seed_key_usage_is_enforced() {
        let certificate = Cert::from_pem_or_der(include_bytes!(
            "../../testdata/data/lanes/e/pki/testing-ca/signer1.cert.pem"
        ))
        .unwrap();
        assert!(cert_key_usages(&certificate)
            .unwrap()
            .contains("non_repudiation"));
        assert!(!key_usage_matches(&certificate, &["X0XXXXXXX".into()]));
        assert!(key_usage_matches(
            &certificate,
            &["X0XXXXXXX".into(), "11XXXXXX0".into()]
        ));
    }
}
