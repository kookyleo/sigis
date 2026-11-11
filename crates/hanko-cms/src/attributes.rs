// Derived from pyHanko `sign/validation/generic_cms.py`
// (`collect_signer_attr_status`) and `sign/validation/status.py`
// (`ClaimedAttributes`, `CertifiedAttributes`) (MIT, see LICENSE-pyHanko).

//! Signer attributes: CAdES `signer-attrs-v2` (claimed and certified
//! attributes) and attribute certificates embedded in the `SignedData`.

use std::collections::BTreeMap;

use const_oid::ObjectIdentifier;
use der::asn1::{OctetString, Utf8StringRef};
use der::{Choice, Decode, Sequence};
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};

use hanko_certvalidator::ac::{validate_ac, AcValidationResult};
use hanko_certvalidator::ValidationContext;
use hanko_core::asn1::oids;
use hanko_core::asn1::tlv::{tag, Tlv};
use hanko_core::cert::Cert;

use crate::errors::{CmsError, CmsResult};
use crate::signed_data::{find_unique_cms_attribute, AttributeLookupError, CmsAttribute};
use crate::status::{AttributeInfo, AttributeMap, CadesSignerAttributeAssertions};
use hanko_core::ades::{AdesFailure, AdesSubIndic};

/// `RoleSyntax` (RFC 5755).
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct RoleSyntax {
    /// `roleAuthority`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub role_authority: Option<GeneralNames>,
    /// `roleName`.
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    pub role_name: GeneralName,
}

/// One value of `IetfAttrSyntax` (RFC 5755).
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
pub enum IetfAttrValue<'a> {
    /// `octets`.
    Octets(OctetString),
    /// `oid`.
    Oid(ObjectIdentifier),
    /// `string`.
    String(Utf8StringRef<'a>),
}

/// `IetfAttrSyntax` (RFC 5755).
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct IetfAttrSyntax<'a> {
    /// `policyAuthority`.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub policy_authority: Option<GeneralNames>,
    /// `values`.
    pub values: Vec<IetfAttrValue<'a>>,
}

/// `SvceAuthInfo` (RFC 5755).
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct SvceAuthInfo {
    /// `service`.
    pub service: GeneralName,
    /// `ident`.
    pub ident: GeneralName,
    /// `authInfo`.
    #[asn1(optional = "true")]
    pub auth_info: Option<OctetString>,
}

/// asn1crypto name of an attribute certificate attribute type
/// (`AttCertAttributeType`), or the dotted OID.
pub fn att_cert_attribute_name(oid: &ObjectIdentifier) -> String {
    match oid.to_string().as_str() {
        "1.3.6.1.5.5.7.10.1" => "authentication_info".to_owned(),
        "1.3.6.1.5.5.7.10.2" => "access_identity".to_owned(),
        "1.3.6.1.5.5.7.10.3" => "charging_identity".to_owned(),
        "1.3.6.1.5.5.7.10.4" => "group".to_owned(),
        "2.5.4.72" => "role".to_owned(),
        "2.5.4.55" => "clearance".to_owned(),
        other => other.to_owned(),
    }
}

/// Surface-level parse of one value, as asn1crypto's `list(attr['values'])`
/// does for the attribute types it knows.
fn parse_value(attr_type: &str, value: &[u8]) -> Result<(), String> {
    let r = match attr_type {
        "role" => RoleSyntax::from_der(value).map(|_| ()),
        "charging_identity" | "group" => IetfAttrSyntax::from_der(value).map(|_| ()),
        "authentication_info" | "access_identity" => SvceAuthInfo::from_der(value).map(|_| ()),
        _ => return Ok(()),
    };
    r.map_err(|e| e.to_string())
}

/// A parsed `Attribute` (type, value encodings).
type RawAttr = (String, Vec<Vec<u8>>);

/// Parse one `Attribute` of an AC or of `claimedAttributes`.
fn parse_attribute(der: &[u8]) -> Result<RawAttr, (Option<String>, String)> {
    let t = Tlv::parse_exact(der).map_err(|e| (None, e.to_string()))?;
    let parts = t.children().map_err(|e| (None, e.to_string()))?;
    let [ty, values] = parts.as_slice() else {
        return Err((None, "attribute must have two fields".into()));
    };
    if !ty.is_universal(tag::OID) {
        return Err((None, "attribute type is not an OBJECT IDENTIFIER".into()));
    }
    let oid = ObjectIdentifier::from_der(ty.raw).map_err(|e| (None, e.to_string()))?;
    let name = att_cert_attribute_name(&oid);
    if !values.is_universal(tag::SET) {
        return Err((Some(name), "attribute values are not a SET".into()));
    }
    let vals: Vec<Vec<u8>> = values
        .children()
        .map_err(|e| (Some(name.clone()), e.to_string()))?
        .into_iter()
        .map(|v| v.raw.to_vec())
        .collect();
    for v in &vals {
        parse_value(&name, v).map_err(|e| (Some(name.clone()), e))?;
    }
    Ok((name, vals))
}

/// `_handle_attr_err`.
fn attr_error(attr_type: Option<&str>, kind: &str, err: &str, fatal: bool) -> CmsResult<()> {
    let ty = match attr_type {
        None | Some("") => "unknown type".to_owned(),
        Some(t) => format!("type '{t}'"),
    };
    if fatal {
        return Err(CmsError::validation(
            format!("Failed to parse {kind} of {ty}: {err}"),
            AdesSubIndic::Failure(AdesFailure::FORMAT_FAILURE),
        ));
    }
    Ok(())
}

/// `ClaimedAttributes.from_iterable`: group attribute values by type,
/// skipping (or, if `parse_error_fatal`, rejecting) malformed attributes.
pub fn claimed_attributes_from(
    attrs: &[Vec<u8>],
    parse_error_fatal: bool,
) -> CmsResult<AttributeMap> {
    let mut by_type: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
    for der in attrs {
        match parse_attribute(der) {
            Ok((name, values)) => by_type.entry(name).or_default().extend(values),
            Err((ty, e)) => attr_error(ty.as_deref(), "claimed attribute", &e, parse_error_fatal)?,
        }
    }
    Ok(AttributeMap(
        by_type
            .into_iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    AttributeInfo {
                        attr_type: k,
                        attr_values: v,
                        validation_results: Vec::new(),
                    },
                )
            })
            .collect(),
    ))
}

/// `CertifiedAttributes.from_results`: attributes approved by valid ACs,
/// grouped by type. Malformed attributes are skipped.
pub fn certified_attributes_from(results: &[AcValidationResult]) -> AttributeMap {
    let mut map: BTreeMap<String, AttributeInfo> = BTreeMap::new();
    for (index, r) in results.iter().enumerate() {
        for der in r.approved_attributes.values() {
            let Ok((name, values)) = parse_attribute(der) else {
                continue;
            };
            let entry = map.entry(name.clone()).or_insert_with(|| AttributeInfo {
                attr_type: name,
                attr_values: Vec::new(),
                validation_results: Vec::new(),
            });
            entry.attr_values.extend(values);
            entry.validation_results.push(index);
        }
    }
    AttributeMap(map)
}

/// Results of [`collect_signer_attr_status`].
#[derive(Clone, Debug, Default)]
pub struct SignerAttrStatus {
    /// `cades_signer_attrs`.
    pub cades_signer_attrs: Option<CadesSignerAttributeAssertions>,
    /// `ac_attrs`.
    pub ac_attrs: Option<AttributeMap>,
    /// `ac_validation_errs`.
    pub ac_validation_errs: Option<Vec<String>>,
}

/// `process_certified_attrs`: validate ACs for `holder`.
fn process_certified_attrs(
    acs: &[Vec<u8>],
    holder: &Cert,
    other_certs: &[Cert],
    ctx: &ValidationContext,
) -> (Vec<AcValidationResult>, Vec<String>) {
    let ctx = ctx.with_other_certs(other_certs);
    let mut results = Vec::new();
    let mut errors = Vec::new();
    for ac in acs {
        match validate_ac(&ctx, ac, Some(holder)) {
            Ok(r) => results.push(r),
            Err(e) => errors.push(e.to_string()),
        }
    }
    (results, errors)
}

/// `collect_signer_attr_status`.
pub fn collect_signer_attr_status(
    sd_attr_certificates: &[Vec<u8>],
    signer_cert: &Cert,
    other_certs: &[Cert],
    ctx: Option<&ValidationContext>,
    signed_attrs: Option<&[CmsAttribute]>,
) -> CmsResult<SignerAttrStatus> {
    let signer_attrs = match find_unique_cms_attribute(signed_attrs, oids::AA_SIGNER_ATTRIBUTES_V2)
    {
        Ok(v) => Some(v),
        Err(AttributeLookupError::Nonexistent(_)) => None,
        Err(e @ AttributeLookupError::Multivalued(_)) => {
            return Err(CmsError::validation(
                e.to_string(),
                AdesSubIndic::Failure(AdesFailure::FORMAT_FAILURE),
            ))
        }
    };
    let mut out = SignerAttrStatus::default();
    let mut cades_results: Option<Vec<AcValidationResult>> = None;
    let mut cades_errors: Option<Vec<String>> = None;
    if let Some(value) = signer_attrs {
        let malformed =
            |e: &dyn std::fmt::Display| CmsError::Malformed(format!("signer-attrs-v2: {e}"));
        let seq = Tlv::parse_exact(value).map_err(|e| malformed(&e))?;
        if !seq.is_universal(tag::SEQUENCE) {
            return Err(malformed(&"not a SEQUENCE"));
        }
        let mut claimed_raw = Vec::new();
        let mut certified_acs = Vec::new();
        let mut unknown_cert_attrs = false;
        let mut signed_assertions = false;
        for field in seq.children().map_err(|e| malformed(&e))? {
            let inner = || -> CmsResult<Tlv<'_>> { Ok(Tlv::parse_exact(field.value)?) };
            match (field.class, field.number) {
                (hanko_core::asn1::tlv::Class::ContextSpecific, 0) => {
                    for a in inner()?.children()? {
                        claimed_raw.push(a.raw.to_vec());
                    }
                }
                (hanko_core::asn1::tlv::Class::ContextSpecific, 1) => {
                    for choice in inner()?.children()? {
                        if choice.is_context(0) && choice.constructed {
                            certified_acs.push(Tlv::parse_exact(choice.value)?.raw.to_vec());
                        } else {
                            unknown_cert_attrs = true;
                        }
                    }
                }
                (hanko_core::asn1::tlv::Class::ContextSpecific, 2) => signed_assertions = true,
                _ => return Err(malformed(&"unexpected field")),
            }
        }
        let claimed = claimed_attributes_from(&claimed_raw, false)?;
        if let Some(ctx) = ctx {
            let (r, e) = process_certified_attrs(&certified_acs, signer_cert, other_certs, ctx);
            cades_results = Some(r);
            cades_errors = Some(e);
        }
        let certified = cades_results.as_deref().map(certified_attributes_from);
        out.cades_signer_attrs = Some(CadesSignerAttributeAssertions {
            claimed_attrs: claimed,
            certified_attrs: certified,
            ac_validation_errs: cades_errors.clone(),
            unknown_attrs_present: unknown_cert_attrs || signed_assertions,
        });
    }
    if let Some(ctx) = ctx {
        let (mut results, mut errors) =
            process_certified_attrs(sd_attr_certificates, signer_cert, other_certs, ctx);
        if let Some(r) = cades_results {
            results.extend(r);
        }
        if let Some(e) = cades_errors {
            errors.extend(e);
        }
        out.ac_attrs = Some(certified_attributes_from(&results));
        out.ac_validation_errs = Some(errors);
    }
    Ok(out)
}
