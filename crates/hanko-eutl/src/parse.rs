// Derived from pyHanko `sign/validation/qualified/eutl_parse.py` (MIT, see LICENSE-pyHanko).

//! Parsing and validation of EU trusted lists and the list of the lists
//! (`pyhanko.sign.validation.qualified.eutl_parse`).
//!
//! pyHanko binds the ETSI TS 119 612 schema with xsdata; this port reads the
//! few elements it needs from a `roxmltree` DOM. As with xsdata's lenient
//! configuration, unknown elements and attributes are ignored, and missing
//! required elements are reported where pyHanko reports them.

use std::collections::BTreeSet;

use base64::Engine as _;
use hanko_core::cert::Cert;
use hanko_core::time::Moment;
use hanko_validate::errors::SignatureValidationError;
use hanko_validate::report::{AdesFailure, AdesIndeterminate};
use hanko_validate::settings::KeyUsageConstraints;
use roxmltree::Node;

use crate::tsp::{
    AdditionalServiceInformation, BaseServiceInformation, CriteriaCombination, CriteriaList,
    Criterion, QcCertType, Qualification, QualifiedServiceInformation, Qualifier, TspRegistry,
    TspServiceParsingError, CA_QC_URI, QTST_URI, SVCINFOEXT_URI_BASE,
};
use crate::util::{load_certs_from_pemder, parse_xsd_datetime};
use crate::xml::dsig::verify_xades;
use crate::xml::{
    self, child, children, collapsed_text, element_children, is, text_content, TSL_ADDTYPES_NS, TSL_NS,
    TSL_SIE_NS, XADES_NS, XML_NS,
};

/// `Svcstatus/granted`.
pub const STATUS_GRANTED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
/// Scheme rule of the EU list of the lists.
pub const LOTL_RULE: &str = "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUlistofthelists";
/// MIME type of an ETSI trusted list.
pub const ETSI_TSL_MIME_TYPE: &str = "application/vnd.etsi.tsl+xml";
/// Preferred language for names.
pub const PREFERRED_LANGUAGE: &str = "en";
/// URLs at which the LOTL was re-anchored by the OJEU.
pub const KNOWN_OJEU_REANCHOR_URLS: &[&str] = &["https://eur-lex.europa.eu/eli/C/2026/1944/oj"];

const LOTL_LATEST: &[u8] = include_bytes!("../lotl-certs/latest.cert.pem");
const LOTL_BOOTSTRAP_0: &[u8] = include_bytes!("../lotl-certs/bootstrap-0.cert.pem");
const LOTL_BOOTSTRAP_1: &[u8] = include_bytes!("../lotl-certs/bootstrap-1.cert.pem");

/// Errors of trusted list processing.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EutlError {
    /// Malformed XML.
    #[error(transparent)]
    Xml(#[from] xml::XmlError),
    /// Trusted list content could not be interpreted.
    #[error(transparent)]
    Parsing(#[from] TspServiceParsingError),
    /// The signature on a list could not be validated.
    #[error(transparent)]
    Signature(#[from] SignatureValidationError),
}

fn perr(msg: impl Into<String>) -> TspServiceParsingError {
    TspServiceParsingError(msg.into())
}

fn required<T>(v: Option<T>, descr: &str) -> Result<T, TspServiceParsingError> {
    v.ok_or_else(|| perr(format!("{descr} must be provided")))
}

fn uri_text(node: Node<'_, '_>) -> String {
    collapsed_text(node)
}

fn xsd_bool(node: Node<'_, '_>) -> Option<bool> {
    match collapsed_text(node).as_str() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

fn attr_bool(node: Node<'_, '_>, name: &str) -> Option<bool> {
    match node.attribute(name).map(str::trim) {
        Some("true" | "1") => Some(true),
        Some("false" | "0") => Some(false),
        _ => None,
    }
}

/// `_extract_from_intl_string`: the English value, else the first one.
fn intl_string(names: &[Node<'_, '_>]) -> Result<String, TspServiceParsingError> {
    let first = names.first().ok_or_else(|| perr("Empty internationalised string"))?;
    for n in names {
        if n.attribute((XML_NS, "lang")) == Some(PREFERRED_LANGUAGE) {
            return Ok(text_content(*n));
        }
    }
    Ok(text_content(*first))
}

/// `_service_name_from_intl_string`.
fn service_name(info: Node<'_, '_>) -> Result<String, TspServiceParsingError> {
    match child(info, TSL_NS, "ServiceName") {
        Some(sn) => intl_string(&children(sn, TSL_NS, "Name").collect::<Vec<_>>()),
        None => Ok("unknown".to_owned()),
    }
}

fn b64_cert(node: Node<'_, '_>) -> Result<Cert, TspServiceParsingError> {
    let b64: String = text_content(node).chars().filter(|c| !c.is_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| perr(format!("Invalid base64 certificate: {e}")))?;
    Cert::from_der(&der).map_err(|e| perr(format!("Invalid certificate: {e}")))
}

/// `_as_certs`: certificates in a `ServiceDigitalIdentity`.
fn as_certs(sdi: Node<'_, '_>) -> Result<Vec<Cert>, TspServiceParsingError> {
    let mut out = Vec::new();
    for did in children(sdi, TSL_NS, "DigitalId") {
        for c in children(did, TSL_NS, "X509Certificate") {
            out.push(b64_cert(c)?);
        }
    }
    Ok(out)
}

/// `_parse_xades_oid`.
fn xades_oid(node: Node<'_, '_>) -> Result<String, TspServiceParsingError> {
    Ok(uri_text(required(child(node, XADES_NS, "Identifier"), "Identifier tag in OID")?))
}

/// `KeyUsageBitType` names as pyHanko derives them (`bit.name.name.lower()`).
fn key_usage_bit_name(xml_name: &str) -> Option<&'static str> {
    Some(match xml_name {
        "digitalSignature" => "digital_signature",
        "nonRepudiation" => "non_repudiation",
        "keyEncipherment" => "key_encipherment",
        "dataEncipherment" => "data_encipherment",
        "keyAgreement" => "key_agreement",
        "keyCertSign" => "key_cert_sign",
        "crlSign" => "crl_sign",
        "encipherOnly" => "encipher_only",
        "decipherOnly" => "decipher_only",
        _ => return None,
    })
}

/// `_process_criteria_list`.
fn process_criteria_list(criteria: Option<Node<'_, '_>>) -> Result<CriteriaList, TspServiceParsingError> {
    let entries = process_criteria_list_entries(criteria)?;
    let Some(criteria) = criteria.filter(|_| !entries.is_empty()) else {
        return Err(perr("No criteria"));
    };
    let assertion = required(criteria.attribute("assert"), "Criteria assertion type")?;
    let combine = CriteriaCombination::from_value(assertion.trim())
        .ok_or_else(|| perr(format!("'{assertion}' is not a valid CriteriaCombination")))?;
    Ok(CriteriaList::new(combine, entries))
}

/// `_process_criteria_list_entries`.
fn process_criteria_list_entries(list: Option<Node<'_, '_>>) -> Result<Vec<Criterion>, TspServiceParsingError> {
    let Some(list) = list else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for ps in children(list, TSL_SIE_NS, "PolicySet") {
        let oids = children(ps, TSL_SIE_NS, "PolicyIdentifier")
            .map(xades_oid)
            .collect::<Result<BTreeSet<_>, _>>()?;
        out.push(Criterion::PolicySet(oids));
    }
    for ku in children(list, TSL_SIE_NS, "KeyUsage") {
        let mut must = BTreeSet::new();
        let mut forbidden = BTreeSet::new();
        for bit in children(ku, TSL_SIE_NS, "KeyUsageBit") {
            let name = required(bit.attribute("name"), "Key usage bit type name")?;
            let name = key_usage_bit_name(name.trim())
                .ok_or_else(|| perr(format!("Unknown key usage bit {name}")))?
                .to_owned();
            match xsd_bool(bit) {
                Some(true) => {
                    must.insert(name);
                }
                Some(false) => {
                    forbidden.insert(name);
                }
                None => {}
            }
        }
        out.push(Criterion::KeyUsage(KeyUsageConstraints {
            key_usage: Some(must),
            key_usage_forbidden: Some(forbidden),
            ..KeyUsageConstraints::new()
        }));
    }
    for sub in children(list, TSL_SIE_NS, "CriteriaList") {
        out.push(Criterion::List(process_criteria_list(Some(sub))?));
    }
    if let Some(other) = child(list, TSL_SIE_NS, "otherCriteriaList") {
        for el in element_children(other) {
            if is(el, TSL_ADDTYPES_NS, "CertSubjectDNAttribute") {
                let oids = children(el, TSL_ADDTYPES_NS, "AttributeOID")
                    .map(xades_oid)
                    .collect::<Result<BTreeSet<_>, _>>()?;
                out.push(Criterion::CertSubjectDn(oids));
            } else if is(el, TSL_ADDTYPES_NS, "ExtendedKeyUsage") {
                let kpids = children(el, TSL_ADDTYPES_NS, "KeyPurposeId")
                    .map(xades_oid)
                    .collect::<Result<BTreeSet<_>, _>>()?;
                out.push(Criterion::KeyUsage(KeyUsageConstraints {
                    extd_key_usage: Some(kpids),
                    ..KeyUsageConstraints::new()
                }));
            } else {
                return Err(perr(format!(
                    "Unknown criterion {} in qualifier definition",
                    el.tag_name().name()
                )));
            }
        }
    }
    Ok(out)
}

/// `_get_qualifications`.
fn get_qualifications(quals: Node<'_, '_>) -> Result<Vec<Qualification>, TspServiceParsingError> {
    let mut out = Vec::new();
    for qe in children(quals, TSL_SIE_NS, "QualificationElement") {
        let Some(qx) = child(qe, TSL_SIE_NS, "Qualifiers") else {
            continue;
        };
        let qualifiers: BTreeSet<Qualifier> = children(qx, TSL_SIE_NS, "Qualifier")
            .filter_map(|q| q.attribute("uri").and_then(|u| Qualifier::from_uri(u.trim())))
            .collect();
        let criteria = process_criteria_list(child(qe, TSL_SIE_NS, "CriteriaList"))?;
        if !qualifiers.is_empty() {
            out.push(Qualification {
                qualifiers,
                criteria_list: criteria,
            });
        }
    }
    Ok(out)
}

fn certificate_type_by_uri(uri: &str) -> Option<QcCertType> {
    let frag = uri.strip_prefix(SVCINFOEXT_URI_BASE)?.strip_prefix('/')?;
    match frag {
        "ForeSignatures" => Some(QcCertType::QcEsign),
        "ForeSeals" => Some(QcCertType::QcEseal),
        "ForWebSiteAuthentication" => Some(QcCertType::QcWeb),
        _ => None,
    }
}

/// Which kind of service to interpret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceInterpreter {
    /// `_interpret_historical_service_info_for_ca`.
    Ca,
    /// `_interpret_historical_service_info_for_qtst`.
    Qtst,
}

/// Interpret a `ServiceInformation` or `ServiceHistoryInstance` element
/// (`_interpret_historical_service_info_for_ca` / `..._for_qtst`).
pub fn interpret_service_info(
    info: Node<'_, '_>,
    next_update_at: Option<Moment>,
    interpreter: ServiceInterpreter,
) -> Result<QualifiedServiceInformation, TspServiceParsingError> {
    let certs = as_certs(required(
        child(info, TSL_NS, "ServiceDigitalIdentity"),
        "Service digital identity",
    )?)?;
    let name = service_name(info)?;
    let mut qualifications = Vec::new();
    let mut expired_revinfo = None;
    let mut additional_info = BTreeSet::new();
    let mut asi_qc_type = BTreeSet::new();
    if let Some(exts) = child(info, TSL_NS, "ServiceInformationExtensions") {
        for ext in children(exts, TSL_NS, "Extension") {
            let critical = attr_bool(ext, "Critical").unwrap_or(false);
            for content in element_children(ext) {
                if is(content, TSL_SIE_NS, "Qualifications") {
                    qualifications = get_qualifications(content)?;
                } else if interpreter == ServiceInterpreter::Ca && is(content, TSL_NS, "ExpiredCertsRevocationInfo") {
                    let txt = collapsed_text(content);
                    expired_revinfo = Some(
                        parse_xsd_datetime(&txt)
                            .ok_or_else(|| perr("Date in expired certs revocation info cutoff must be provided"))?,
                    );
                } else if interpreter == ServiceInterpreter::Ca && is(content, TSL_NS, "AdditionalServiceInformation") {
                    let uri = uri_text(required(child(content, TSL_NS, "URI"), "Additional service info URI")?);
                    let textual = child(content, TSL_NS, "InformationValue").map(text_content);
                    match certificate_type_by_uri(&uri) {
                        Some(t) => {
                            asi_qc_type.insert(t);
                        }
                        None => {
                            additional_info.insert(AdditionalServiceInformation {
                                uri,
                                critical,
                                textual_info: textual,
                            });
                        }
                    }
                } else if critical {
                    return Err(perr(format!(
                        "Cannot process a critical extension in service named '{name}'.\nContent: {}",
                        content.tag_name().name()
                    )));
                }
            }
        }
    }
    let valid_from = match child(info, TSL_NS, "StatusStartingTime") {
        Some(n) => parse_xsd_datetime(&collapsed_text(n))
            .ok_or_else(|| perr(format!("Invalid status starting time in service named {name}")))?,
        None => {
            return Err(perr(format!(
                "The validity start of the status of the the service named {name} is not known. This is an error."
            )))
        }
    };
    let service_type = uri_text(required(child(info, TSL_NS, "ServiceTypeIdentifier"), "Service type identifier")?);
    let base = BaseServiceInformation {
        service_type,
        service_name: name,
        valid_from,
        valid_until: next_update_at,
        provider_certs: certs,
        additional_info_certificate_type: asi_qc_type,
        other_additional_info: additional_info,
    };
    Ok(match interpreter {
        ServiceInterpreter::Ca => QualifiedServiceInformation::ca(base, qualifications, expired_revinfo),
        ServiceInterpreter::Qtst => QualifiedServiceInformation::qtst(base, qualifications),
    })
}

/// Interpret the current information of a `TSPService` element
/// (`_interpret_service_info_for_ca` and friends).
pub fn interpret_service(
    service: Node<'_, '_>,
    interpreter: ServiceInterpreter,
) -> Result<QualifiedServiceInformation, TspServiceParsingError> {
    let info = required(child(service, TSL_NS, "ServiceInformation"), "Service information")?;
    interpret_service_info(info, None, interpreter)
}

fn status_granted(info: Node<'_, '_>) -> bool {
    child(info, TSL_NS, "ServiceStatus").is_some_and(|s| uri_text(s) == STATUS_GRANTED)
}

fn start_time(info: Node<'_, '_>) -> Option<Moment> {
    child(info, TSL_NS, "StatusStartingTime").and_then(|n| parse_xsd_datetime(&collapsed_text(n)))
}

/// Service definitions (current and historical) of the given type in the
/// `TSPService` elements, plus the errors encountered
/// (`_interpret_service_info_for_tsps`).
pub fn interpret_service_info_for_tsps<'a, 'i: 'a>(
    services: impl IntoIterator<Item = Node<'a, 'i>>,
    service_type: &str,
    interpreter: ServiceInterpreter,
) -> (Vec<QualifiedServiceInformation>, Vec<TspServiceParsingError>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for service in services {
        let Some(info) = child(service, TSL_NS, "ServiceInformation") else {
            continue;
        };
        if child(info, TSL_NS, "ServiceTypeIdentifier").map(uri_text).as_deref() != Some(service_type) {
            continue;
        }
        if status_granted(info) {
            match interpret_service_info(info, None, interpreter) {
                Ok(sd) => out.push(sd),
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            }
        }
        let Some(validity_start) = start_time(info) else {
            continue;
        };
        let Some(history) = child(service, TSL_NS, "ServiceHistory") else {
            continue;
        };
        let items: Vec<Node<'_, '_>> = children(history, TSL_NS, "ServiceHistoryInstance").collect();
        // Items with a start time, latest first; each ends where the next
        // later one (or the current status) starts.
        let mut dated: Vec<(usize, Moment)> = items
            .iter()
            .enumerate()
            .filter_map(|(i, it)| start_time(*it).map(|t| (i, t)))
            .collect();
        dated.sort_by_key(|d| std::cmp::Reverse(d.1));
        let mut ends: Vec<(usize, Moment)> = Vec::new();
        let mut next_start = validity_start;
        for (ix, start) in &dated {
            ends.push((*ix, next_start));
            next_start = *start;
        }
        // Python dict keyed by original index, insertion order = sorted order.
        for (ix, end) in ends {
            let item = items[ix];
            if !status_granted(item) {
                continue;
            }
            match interpret_service_info(item, Some(end), interpreter) {
                Ok(sd) => out.push(sd),
                Err(e) => errors.push(e),
            }
        }
    }
    (out, errors)
}

/// Qualified service definitions in a trusted list, without signature
/// validation (`read_qualified_service_definitions`).
pub fn read_qualified_service_definitions(
    tl_xml: &str,
) -> Result<(Vec<QualifiedServiceInformation>, Vec<TspServiceParsingError>), EutlError> {
    let doc = xml::parse(tl_xml)?;
    let root = doc.root_element();
    let tspl = required(child(root, TSL_NS, "TrustServiceProviderList"), "TSP list")?;
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for tsp in children(tspl, TSL_NS, "TrustServiceProvider") {
        let services = required(child(tsp, TSL_NS, "TSPServices"), "TSP services (CA)")?;
        let svc: Vec<_> = children(services, TSL_NS, "TSPService").collect();
        let (sds, errs) = interpret_service_info_for_tsps(svc.iter().copied(), CA_QC_URI, ServiceInterpreter::Ca);
        out.extend(sds);
        errors.extend(errs);
        let (sds, errs) = interpret_service_info_for_tsps(svc.iter().copied(), QTST_URI, ServiceInterpreter::Qtst);
        out.extend(sds);
        errors.extend(errs);
    }
    Ok((out, errors))
}

/// Parse a trusted list into a registry without validating its signature
/// (`trust_list_to_registry_unsafe`).
pub fn trust_list_to_registry_unsafe(
    tl_xml: &str,
    registry: Option<TspRegistry>,
) -> Result<(TspRegistry, Vec<TspServiceParsingError>), EutlError> {
    let mut registry = registry.unwrap_or_default();
    let (sds, errors) = read_qualified_service_definitions(tl_xml)?;
    for sd in sds {
        registry.register(sd);
    }
    Ok((registry, errors))
}

fn human_friendly(cert: &Cert) -> String {
    cert.subject().to_string()
}

/// Verify the list signature with one certificate and return the signed
/// trusted list XML (`_validate_and_extract_tl_data`).
fn validate_and_extract_one(tl_xml: &str, cert: &Cert, at: Moment) -> Result<String, SignatureValidationError> {
    let refs = verify_xades(tl_xml, cert, at).map_err(|e| {
        SignatureValidationError::with(
            format!("Invalid XML signature on trusted list: [{}] {e}", e.class_name()),
            AdesIndeterminate::GENERIC,
        )
    })?;
    for r in refs {
        if r
            .signed_root
            .as_ref()
            .is_some_and(|(ns, n)| ns.as_deref() == Some(TSL_NS) && n == "TrustServiceStatusList")
        {
            return String::from_utf8(r.signed_data).map_err(|e| {
                SignatureValidationError::with(e.to_string(), AdesFailure::FORMAT_FAILURE)
            });
        }
    }
    Err(SignatureValidationError::with(
        "Failed to identify trusted list in signed data",
        AdesFailure::FORMAT_FAILURE,
    ))
}

/// Try each candidate certificate, newest first
/// (`_validate_and_extract_tl_data_multiple_certs`).
pub fn validate_and_extract_tl_data(
    tl_xml: &str,
    candidates: &[Cert],
    at: Option<Moment>,
) -> Result<String, SignatureValidationError> {
    let at = at.unwrap_or_else(Moment::now);
    let mut sorted: Vec<&Cert> = candidates.iter().collect();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.not_before()));
    let mut errors = Vec::new();
    for c in sorted {
        match validate_and_extract_one(tl_xml, c, at) {
            Ok(s) => return Ok(s),
            Err(e) => errors.push(format!(
                "<{}|{}> {}",
                serial_decimal(c),
                human_friendly(c),
                e.failure_message
            )),
        }
    }
    let sep = "\n - ";
    Err(SignatureValidationError::with(
        format!(
            "None of the candidate TLSO certs could be used to validate the TL signature:{sep}{}",
            errors.join(sep)
        ),
        AdesIndeterminate::GENERIC,
    ))
}

fn serial_decimal(cert: &Cert) -> String {
    // Decimal rendering of a big-endian unsigned integer.
    let mut digits: Vec<u8> = vec![0];
    for &byte in cert.serial_bytes() {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            let v = u32::from(*d) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| char::from(b'0' + d)).collect()
}

/// Validate and parse a trusted list into a registry
/// (`trust_list_to_registry`). The signature is checked at `at` (now if
/// `None`, as in pyHanko).
pub fn trust_list_to_registry(
    tl_xml: &str,
    tlso_certs: &[Cert],
    registry: Option<TspRegistry>,
    at: Option<Moment>,
) -> Result<(TspRegistry, Vec<TspServiceParsingError>), EutlError> {
    let signed = validate_and_extract_tl_data(tl_xml, tlso_certs, at)?;
    trust_list_to_registry_unsafe(&signed, registry)
}

/// Reference to a trusted list in a LOTL (`TLReference`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlReference {
    /// Location of the list.
    pub location_uri: String,
    /// Territory.
    pub territory: String,
    /// Certificates that may sign the list.
    pub tlso_certs: Vec<Cert>,
    /// Scheme rules.
    pub scheme_rules: BTreeSet<String>,
}

/// Result of parsing a LOTL (`LOTLParseResult`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotlParseResult {
    /// References to trusted lists.
    pub references: Vec<TlReference>,
    /// Errors.
    pub errors: Vec<TspServiceParsingError>,
    /// URLs of pivot LOTLs.
    pub pivot_urls: Vec<String>,
    /// Claimed issuance date.
    pub claimed_date_issued: Moment,
}

/// Parse a LOTL without validating its signature (`parse_lotl_unsafe`).
pub fn parse_lotl_unsafe(lotl_xml: &str) -> Result<LotlParseResult, EutlError> {
    let doc = xml::parse(lotl_xml)?;
    let root = doc.root_element();
    let scheme = required(child(root, TSL_NS, "SchemeInformation"), "LOTL scheme information")?;
    let pointers = required(child(scheme, TSL_NS, "PointersToOtherTSL"), "pointers to other TSLs")?;
    let info_uris = required(child(scheme, TSL_NS, "SchemeInformationURI"), "scheme information URIs")?;
    let issued = required(child(scheme, TSL_NS, "ListIssueDateTime"), "LotL issuance date")?;
    let claimed_date_issued =
        parse_xsd_datetime(&collapsed_text(issued)).ok_or_else(|| perr("LotL issuance date must be provided"))?;

    let mut references = Vec::new();
    let mut errors = Vec::new();
    for pointer in children(pointers, TSL_NS, "OtherTSLPointer") {
        let additional = required(
            child(pointer, TSL_NS, "AdditionalInformation"),
            "TSL pointer additional information",
        )?;
        let mut rules = BTreeSet::new();
        let mut territory = None;
        let mut list_type = None;
        for oi in children(additional, TSL_NS, "OtherInformation") {
            for item in element_children(oi) {
                if is(item, TSL_NS, "SchemeTypeCommunityRules") {
                    for u in children(item, TSL_NS, "URI") {
                        rules.insert(uri_text(u));
                    }
                } else if is(item, TSL_NS, "SchemeTerritory") {
                    territory = Some(collapsed_text(item));
                } else if is(item, TSL_ADDTYPES_NS, "MimeType") {
                    list_type = Some(collapsed_text(item));
                }
            }
        }
        let location = child(pointer, TSL_NS, "TSLLocation").map(uri_text);
        let sdis = child(pointer, TSL_NS, "ServiceDigitalIdentities");
        let (Some(location), Some(territory), Some(sdis)) = (location, territory, sdis) else {
            continue;
        };
        if list_type.as_deref() != Some(ETSI_TSL_MIME_TYPE) {
            continue;
        }
        let mut certs = Vec::new();
        for sdi in children(sdis, TSL_NS, "ServiceDigitalIdentity") {
            for did in children(sdi, TSL_NS, "DigitalId") {
                for c in children(did, TSL_NS, "X509Certificate") {
                    match b64_cert(c) {
                        Ok(cert) => certs.push(cert),
                        Err(e) => errors.push(perr(format!(
                            "Failed to load certificate for {territory} ({location}): {e}"
                        ))),
                    }
                }
            }
        }
        references.push(TlReference {
            location_uri: location,
            territory,
            tlso_certs: certs,
            scheme_rules: rules,
        });
    }
    let mut pivot_urls = Vec::new();
    for u in children(info_uris, TSL_NS, "URI") {
        let v = uri_text(u);
        if v.ends_with(".xml") {
            pivot_urls.push(v);
        } else if KNOWN_OJEU_REANCHOR_URLS.contains(&v.as_str()) {
            break;
        }
    }
    Ok(LotlParseResult {
        references,
        errors,
        pivot_urls,
        claimed_date_issued,
    })
}

fn bundled(data: &[u8]) -> Vec<Cert> {
    load_certs_from_pemder(data).unwrap_or_default()
}

/// The LOTL signer certificates known at the time of the pyHanko release
/// (`latest_known_lotl_tlso_certs`).
pub fn latest_known_lotl_tlso_certs() -> Vec<Cert> {
    bundled(LOTL_LATEST)
}

/// The LOTL signer certificates published in the OJEU for anchor `anchor`
/// (0: OJ C 276, 16.8.2019; 1: OJ C/2026/1944)
/// (`ojeu_bootstrap_lotl_tlso_certs`).
pub fn ojeu_bootstrap_lotl_tlso_certs(anchor: u32) -> Vec<Cert> {
    match anchor {
        0 => bundled(LOTL_BOOTSTRAP_0),
        1 => bundled(LOTL_BOOTSTRAP_1),
        _ => Vec::new(),
    }
}

/// Validate and parse a LOTL (`validate_and_parse_lotl`). Without
/// certificates, the latest known LOTL signers are used.
pub fn validate_and_parse_lotl(
    lotl_xml: &str,
    lotl_tlso_certs: Option<&[Cert]>,
    validation_time: Option<Moment>,
) -> Result<LotlParseResult, EutlError> {
    let latest;
    let certs = match lotl_tlso_certs {
        Some(c) if !c.is_empty() => c,
        _ => {
            latest = latest_known_lotl_tlso_certs();
            &latest
        }
    };
    let validated = validate_and_extract_tl_data(lotl_xml, certs, validation_time)?;
    parse_lotl_unsafe(&validated)
}
