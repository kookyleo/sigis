// Derived from pyHanko `sign/validation/report/tools.py` and the
// validation object helpers of `sign/validation/ades.py`
// (MIT, see LICENSE-pyHanko).

//! ETSI TS 119 102-2 validation reports (`pyhanko.sign.validation.report`).
//!
//! pyHanko serialises xsdata bindings generated from the schema; this module
//! writes the subset of elements pyHanko fills, in schema order, with
//! `quick-xml`.

use std::io::Cursor;

use base64::Engine as _;
use der::{Decode, Encode};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use sigis_pades::report::{AdesStatus, AdesSubIndic};
use sigis_pki_certvalidator::ltv::poe::digest_for_poe;
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::ess::{SigningCertificate, SigningCertificateV2};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::asn1::raw_oid::RawOid;
use sigis_pki_core::asn1::tlv::{tag, Tlv};
use sigis_pki_core::errors::{HankoError, Result as HankoResult};
use sigis_pki_core::time::Moment;

/// Namespace of TS 119 102-2 reports.
pub const VR_NS: &str = "http://uri.etsi.org/19102/v1.2.1#";
/// XAdES namespace.
pub const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
/// XMLDSig namespace.
pub const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Kind of validation object (`ValidationObjectType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValidationObjectType {
    /// `certificate`.
    Certificate,
    /// `CRL`.
    Crl,
    /// `OCSPResponse`.
    OcspResponse,
    /// `timestamp`.
    Timestamp,
    /// `signedData`.
    SignedData,
}

impl ValidationObjectType {
    /// Enum value.
    pub fn value(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::Crl => "CRL",
            Self::OcspResponse => "OCSPResponse",
            Self::Timestamp => "timestamp",
            Self::SignedData => "signedData",
        }
    }

    /// `urn:etsi:019102:validationObject:...`.
    pub fn urn(self) -> String {
        format!("urn:etsi:019102:validationObject:{}", self.value())
    }
}

/// A validation object with its binary representation
/// (`derive_validation_object_binary_data`: the DER of certificates, CRLs and
/// OCSP responses, the signature value of signed data and timestamps).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationObject {
    /// Type.
    pub object_type: ValidationObjectType,
    /// Binary data.
    pub data: Vec<u8>,
}

impl ValidationObject {
    /// `derive_validation_object_identifier`.
    pub fn identifier(&self) -> String {
        let marker: String = digest_for_poe(&self.data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("vo-{}-{marker}", self.object_type.value())
    }
}

/// Validation process (`SignatureValidationProcessID`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationProcess {
    /// Basic validation.
    Basic,
    /// Validation with time (`LTVM`).
    WithTime,
    /// Long-term validation with archival data (`LTA`).
    Lta,
}

impl ValidationProcess {
    fn id(self) -> &'static str {
        match self {
            Self::Basic => "Basic",
            Self::WithTime => "LTVM",
            Self::Lta => "LTA",
        }
    }
}

/// One `SigningCertificate(V2)` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertIdRef {
    /// Digest algorithm (SHA-1 for `ESSCertID`).
    pub digest_algorithm: DigestAlgorithm,
    /// Certificate hash.
    pub digest: Vec<u8>,
    /// DER of the `IssuerSerial`, if present.
    pub issuer_serial: Option<Vec<u8>>,
}

/// Signature attributes reported (`_summarise_attrs`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignatureAttributes {
    /// Claimed signing time (`/M` or signature timestamp time).
    pub signing_time: Option<Moment>,
    /// Signing certificate references.
    pub signing_certificate: Option<Vec<CertIdRef>>,
    /// Commitment type OID (dotted).
    pub commitment_type: Option<String>,
    /// Content timestamp time.
    pub content_timestamp: Option<Moment>,
    /// Signature policy OIDs (dotted).
    pub policy_oids: Vec<String>,
    /// `/Location`.
    pub location: Option<String>,
    /// Signer roles: (certified, description).
    pub signer_roles: Vec<(bool, String)>,
    /// Signature timestamp time.
    pub signature_timestamp: Option<Moment>,
    /// `messageDigest` attribute.
    pub message_digest: Vec<u8>,
    /// `/Reason`.
    pub reason: Option<String>,
    /// `/Name`.
    pub name: Option<String>,
    /// `/ContactInfo`.
    pub contact_info: Option<String>,
    /// `/SubFilter` without the slash.
    pub sub_filter: String,
    /// Complete `/ByteRange` offset-length pairs, in their original order.
    pub byte_range: Vec<u64>,
    /// `/Filter` without the slash.
    pub filter: String,
}

/// Data needed for one signature validation report (`_generate_report`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportInput {
    /// Signature value of the `SignerInfo`.
    pub signature_value: Vec<u8>,
    /// Message digest algorithm.
    pub md_algorithm: DigestAlgorithm,
    /// Original `[0] IMPLICIT` encoding of the signed attributes. The pinned
    /// report hashes this encoding; CMS verification uses a universal SET.
    pub signed_attrs_der: Vec<u8>,
    /// Digest of the signed document (byte range digest).
    pub document_digest: Vec<u8>,
    /// Validation time.
    pub validation_time: Moment,
    /// Best signature time (validation with time and LTA).
    pub best_signature_time: Option<Moment>,
    /// Process.
    pub process: ValidationProcess,
    /// Result.
    pub subindication: AdesSubIndic,
    /// Signer certificate DER.
    pub signer_cert: Vec<u8>,
    /// Signature attributes.
    pub attributes: SignatureAttributes,
    /// Validation objects.
    pub validation_objects: Vec<ValidationObject>,
}

/// Validation evidence consumed by the report input builders.
///
/// Certified signer roles are taken exclusively from successfully validated
/// attribute-certificate results in `status`.
pub struct ReportValidation<'a> {
    /// Time at which validation was requested.
    pub validation_time: Moment,
    /// Proven upper bound on the signature time, if established.
    pub best_signature_time: Option<Moment>,
    /// Validation procedure that produced the result.
    pub process: ValidationProcess,
    /// Result of that procedure.
    pub subindication: AdesSubIndic,
    /// CMS validation result, including timestamp and attribute evidence.
    pub status: &'a sigis_cms::StandardCmsSignatureStatus,
}

fn report_error(error: impl std::fmt::Display) -> HankoError {
    HankoError::Malformed(format!("cannot construct validation report: {error}"))
}

fn unique_attribute(
    signer: &sigis_cms::SignerInfo,
    oid: der::asn1::ObjectIdentifier,
) -> HankoResult<Option<&[u8]>> {
    use sigis_cms::signed_data::{find_unique_cms_attribute, AttributeLookupError};
    match find_unique_cms_attribute(signer.signed_attr_list(), oid) {
        Ok(value) => Ok(Some(value)),
        Err(AttributeLookupError::Nonexistent(_)) => Ok(None),
        Err(error) => Err(report_error(error)),
    }
}

fn first_oid(value: &[u8]) -> HankoResult<String> {
    let sequence = Tlv::parse_exact(value).map_err(report_error)?;
    if !sequence.is_universal(tag::SEQUENCE) {
        return Err(report_error("attribute value must be a SEQUENCE"));
    }
    let children = sequence.children().map_err(report_error)?;
    let oid = children
        .first()
        .ok_or_else(|| report_error("attribute value has no identifier"))?;
    Ok(RawOid::from_tlv(oid).map_err(report_error)?.dotted())
}

fn role_description(info: &sigis_cms::status::AttributeInfo, certified: bool) -> String {
    let values = info
        .attr_values
        .iter()
        .map(|value| match Tlv::parse_exact(value) {
            Ok(value) if [12, 19, 22].iter().any(|tag| value.is_universal(*tag)) => {
                String::from_utf8_lossy(value.value).into_owned()
            }
            _ => format!("DER:{}", b64(value)),
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "{}{} {values}",
        info.attr_type,
        if certified { "" } else { ":" }
    )
}

impl ReportInput {
    /// Construct a report from the original CMS encoding and a Rust validation
    /// result. `document_digest` is the digest of the actual detached content.
    pub fn from_cms(
        content_info: &[u8],
        document_digest: &[u8],
        validation: &ReportValidation<'_>,
    ) -> HankoResult<Self> {
        let signed_data = sigis_cms::SignedData::from_der(content_info)?;
        let signer = sigis_cms::signed_data::extract_signer_info(&signed_data)?;
        let md_algorithm = signer
            .digest()
            .ok_or_else(|| report_error("unsupported signer digest algorithm"))?;
        let signed_attrs = signer
            .signed_attrs
            .as_ref()
            .ok_or_else(|| report_error("signed attributes are required"))?;
        let signer_cert = sigis_cms::signed_data::extract_certificate_info(&signed_data)?
            .signer_cert
            .der()
            .to_vec();
        let status = validation.status;
        let mut attributes = SignatureAttributes {
            signing_time: status
                .signer_reported_dt
                .or_else(|| status.timestamp_validity.as_ref().map(|t| t.timestamp)),
            content_timestamp: status
                .content_timestamp_validity
                .as_ref()
                .map(|t| t.timestamp),
            signature_timestamp: status.timestamp_validity.as_ref().map(|t| t.timestamp),
            ..Default::default()
        };
        let message_digest = unique_attribute(signer, oids::MESSAGE_DIGEST)?
            .ok_or_else(|| report_error("required messageDigest attribute is missing"))?;
        attributes.message_digest = der::asn1::OctetString::from_der(message_digest)
            .map_err(report_error)?
            .as_bytes()
            .to_vec();
        if let Some(value) = unique_attribute(signer, oids::AA_ETS_COMMITMENT_TYPE)? {
            attributes.commitment_type = Some(first_oid(value)?);
        }
        for value in sigis_cms::signed_data::find_cms_attribute_iter(
            signer.signed_attr_list(),
            oids::AA_ETS_SIG_POLICY_ID,
        ) {
            // The NULL alternative means an implied policy, with no OID.
            if !Tlv::parse_exact(value)
                .map_err(report_error)?
                .is_universal(5)
            {
                attributes.policy_oids.push(first_oid(value)?);
            }
        }
        if let Some(value) = unique_attribute(signer, oids::AA_SIGNING_CERTIFICATE)? {
            let certificate = SigningCertificate::from_der(value).map_err(report_error)?;
            attributes.signing_certificate = Some(
                certificate
                    .certs
                    .into_iter()
                    .map(|id| {
                        Ok(CertIdRef {
                            digest_algorithm: DigestAlgorithm::Sha1,
                            digest: id.cert_hash.as_bytes().to_vec(),
                            issuer_serial: id
                                .issuer_serial
                                .map(|s| s.to_der())
                                .transpose()
                                .map_err(report_error)?,
                        })
                    })
                    .collect::<HankoResult<Vec<_>>>()?,
            );
        } else if let Some(value) = unique_attribute(signer, oids::AA_SIGNING_CERTIFICATE_V2)? {
            let certificate = SigningCertificateV2::from_der(value).map_err(report_error)?;
            attributes.signing_certificate = Some(
                certificate
                    .certs
                    .into_iter()
                    .map(|id| {
                        Ok(CertIdRef {
                            digest_algorithm: id
                                .digest_algorithm()
                                .ok_or_else(|| report_error("unsupported certificate digest"))?,
                            digest: id.cert_hash.as_bytes().to_vec(),
                            issuer_serial: id
                                .issuer_serial
                                .map(|s| s.to_der())
                                .transpose()
                                .map_err(report_error)?,
                        })
                    })
                    .collect::<HankoResult<Vec<_>>>()?,
            );
        }
        if let Some(roles) = &status.cades_signer_attrs {
            attributes.signer_roles.extend(
                roles
                    .claimed_attrs
                    .0
                    .values()
                    .map(|info| (false, role_description(info, false))),
            );
            if let Some(certified) = &roles.certified_attrs {
                attributes.signer_roles.extend(
                    certified
                        .0
                        .values()
                        .map(|info| (true, role_description(info, true))),
                );
            }
        }
        let validation_objects = signed_data
            .certificates
            .iter()
            .map(|data| ValidationObject {
                object_type: ValidationObjectType::Certificate,
                data: data.clone(),
            })
            .collect();
        Ok(Self {
            signature_value: signer.signature.clone(),
            md_algorithm,
            signed_attrs_der: sigis_pki_core::asn1::tlv::encode(0xa0, &signed_attrs.contents),
            document_digest: document_digest.to_vec(),
            validation_time: validation.validation_time,
            best_signature_time: validation.best_signature_time,
            process: validation.process,
            subindication: validation.subindication,
            signer_cert,
            attributes,
            validation_objects,
        })
    }

    /// Construct a report using the actual PDF byte range and signature
    /// dictionary, preserving metadata from the signed revision.
    pub fn from_pdf(
        file: &sigis_pdf::PdfFile,
        signature: &sigis_pdf::EmbeddedSignature,
        validation: &ReportValidation<'_>,
    ) -> HankoResult<Self> {
        use sigis_pdf::lopdf::Object;
        let signed_data = sigis_cms::SignedData::from_der(&signature.contents)?;
        let signer = sigis_cms::signed_data::extract_signer_info(&signed_data)?;
        let algorithm = signer
            .digest()
            .ok_or_else(|| report_error("unsupported signer digest"))?;
        let digest = algorithm.digest(&signature.signed_data(file)?);
        let mut input = Self::from_cms(&signature.contents, &digest, validation)?;
        let Some(Object::Dictionary(dictionary)) =
            file.object_in_revision(signature.sig_object, signature.signed_revision)?
        else {
            return Err(report_error("signature dictionary is unavailable"));
        };
        let text = |key: &[u8]| {
            dictionary
                .get(key)
                .ok()
                .and_then(sigis_pdf::signatures::text_of)
        };
        input.attributes.name = text(b"Name");
        input.attributes.reason = text(b"Reason");
        input.attributes.contact_info = text(b"ContactInfo");
        input.attributes.location = text(b"Location");
        if validation.status.signer_reported_dt.is_none() {
            if let Ok(date) = dictionary.get(b"M") {
                let date = sigis_pdf::generic::parse_pdf_date_obj(date, file.strict())
                    .map_err(report_error)?;
                input.attributes.signing_time = Some(Moment::from_unix_secs(date.unix_timestamp()));
            }
        }
        input.attributes.sub_filter = signature.sub_filter.clone().unwrap_or_default();
        input.attributes.byte_range = signature.byte_range.clone();
        input.attributes.filter = dictionary
            .get(b"Filter")
            .ok()
            .and_then(|o| o.as_name().ok())
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .unwrap_or_default();
        if let Some(dss) = file.dss()? {
            for (object_type, objects) in [
                (ValidationObjectType::Certificate, dss.material.certs),
                (ValidationObjectType::OcspResponse, dss.material.ocsps),
                (ValidationObjectType::Crl, dss.material.crls),
            ] {
                for data in objects {
                    let object = ValidationObject { object_type, data };
                    if !input.validation_objects.contains(&object) {
                        input.validation_objects.push(object);
                    }
                }
            }
        }
        Ok(input)
    }
}

/// XML Signature URI of a digest algorithm (`DIGEST_ALGO_URIS`); `None`
/// where pyHanko's `_digest_algo_uri` raises `NotImplementedError`.
pub fn digest_algo_uri(algo: DigestAlgorithm) -> Option<&'static str> {
    match algo {
        DigestAlgorithm::Sha1 => Some("http://www.w3.org/2000/09/xmldsig#sha1"),
        DigestAlgorithm::Sha224 => Some("http://www.w3.org/2001/04/xmldsig-more#sha224"),
        DigestAlgorithm::Sha256 => Some("http://www.w3.org/2001/04/xmlenc#sha256"),
        DigestAlgorithm::Sha384 => Some("http://www.w3.org/2001/04/xmldsig-more#sha384"),
        DigestAlgorithm::Sha512 => Some("http://www.w3.org/2001/04/xmlenc#sha512"),
        _ => None,
    }
}

/// [`digest_algo_uri`] or pyHanko's error for digests without XML syntax.
fn digest_uri(algo: DigestAlgorithm) -> Result<&'static str, quick_xml::Error> {
    digest_algo_uri(algo).ok_or_else(|| {
        quick_xml::Error::Io(std::sync::Arc::new(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "No XML signature syntax available for digest algo '{}'",
                algo.name()
            ),
        )))
    })
}

/// Main indication URI.
pub fn main_indication_uri(status: AdesStatus) -> &'static str {
    match status {
        AdesStatus::Passed => "urn:etsi:019102:mainindication:total-passed",
        AdesStatus::Failed => "urn:etsi:019102:mainindication:total-failed",
        AdesStatus::Indeterminate => "urn:etsi:019102:mainindication:indeterminate",
    }
}

fn xml_time(m: Moment) -> String {
    m.to_string()
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

struct W {
    w: Writer<Cursor<Vec<u8>>>,
}

type XmlResult = Result<(), quick_xml::Error>;

impl W {
    fn start(&mut self, name: &str, attrs: &[(&str, &str)]) -> XmlResult {
        let mut s = BytesStart::new(name);
        for (k, v) in attrs {
            s.push_attribute((*k, *v));
        }
        self.w
            .write_event(Event::Start(s))
            .map_err(quick_xml::Error::from)
    }

    fn end(&mut self, name: &str) -> XmlResult {
        self.w
            .write_event(Event::End(BytesEnd::new(name)))
            .map_err(quick_xml::Error::from)
    }

    fn leaf(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) -> XmlResult {
        self.start(name, attrs)?;
        self.w
            .write_event(Event::Text(BytesText::new(text)))
            .map_err(quick_xml::Error::from)?;
        self.end(name)
    }

    fn empty(&mut self, name: &str, attrs: &[(&str, &str)]) -> XmlResult {
        let mut s = BytesStart::new(name);
        for (k, v) in attrs {
            s.push_attribute((*k, *v));
        }
        self.w
            .write_event(Event::Empty(s))
            .map_err(quick_xml::Error::from)
    }

    fn digest(&mut self, wrapper: &str, algo: DigestAlgorithm, value: &[u8]) -> XmlResult {
        self.start(wrapper, &[])?;
        self.empty("ds:DigestMethod", &[("Algorithm", digest_uri(algo)?)])?;
        self.leaf("ds:DigestValue", &[], &b64(value))?;
        self.end(wrapper)
    }
}

fn write_attributes(w: &mut W, a: &SignatureAttributes) -> XmlResult {
    let signed = [("Signed", "true")];
    w.start("vr:SignatureAttributes", &[])?;
    if let Some(t) = a.signing_time {
        w.start("vr:SigningTime", &signed)?;
        w.leaf("vr:Time", &[], &xml_time(t))?;
        w.end("vr:SigningTime")?;
    }
    if let Some(ids) = &a.signing_certificate {
        w.start("vr:SigningCertificate", &signed)?;
        for id in ids {
            w.start("vr:CertID", &[])?;
            if let Some(is) = &id.issuer_serial {
                w.leaf("vr:X509IssuerSerial", &[], &b64(is))?;
            }
            w.empty(
                "ds:DigestMethod",
                &[("Algorithm", digest_uri(id.digest_algorithm)?)],
            )?;
            w.leaf("ds:DigestValue", &[], &b64(&id.digest))?;
            w.end("vr:CertID")?;
        }
        w.end("vr:SigningCertificate")?;
    }
    if let Some(oid) = &a.commitment_type {
        w.start("vr:CommitmentTypeIndication", &signed)?;
        w.leaf(
            "vr:CommitmentTypeIdentifier",
            &[],
            &format!("urn:oid:{oid}"),
        )?;
        w.end("vr:CommitmentTypeIndication")?;
    }
    if let Some(t) = a.content_timestamp {
        w.start("vr:AllDataObjectsTimeStamp", &signed)?;
        w.leaf("vr:TimeStampValue", &[], &xml_time(t))?;
        w.end("vr:AllDataObjectsTimeStamp")?;
    }
    for oid in &a.policy_oids {
        w.start("vr:SigPolicyIdentifier", &signed)?;
        w.leaf("vr:SigPolicyId", &[], &format!("urn:oid:{oid}"))?;
        w.end("vr:SigPolicyIdentifier")?;
    }
    if let Some(loc) = &a.location {
        w.start("vr:SignatureProductionPlace", &signed)?;
        w.leaf("vr:AddressString", &[], loc)?;
        w.end("vr:SignatureProductionPlace")?;
    }
    if !a.signer_roles.is_empty() {
        w.start("vr:SignerRole", &signed)?;
        for (certified, role) in &a.signer_roles {
            w.start("vr:RoleDetails", &[])?;
            w.leaf("vr:Role", &[], role)?;
            w.leaf(
                "vr:EndorsementType",
                &[],
                if *certified { "certified" } else { "claimed" },
            )?;
            w.end("vr:RoleDetails")?;
        }
        w.end("vr:SignerRole")?;
    }
    if let Some(t) = a.signature_timestamp {
        w.start("vr:SignatureTimeStamp", &[("Signed", "false")])?;
        w.leaf("vr:TimeStampValue", &[], &xml_time(t))?;
        w.end("vr:SignatureTimeStamp")?;
    }
    w.start("vr:MessageDigest", &signed)?;
    w.leaf("vr:Digest", &[], &b64(&a.message_digest))?;
    w.end("vr:MessageDigest")?;
    if let Some(r) = &a.reason {
        w.start("vr:Reason", &signed)?;
        w.leaf("vr:ReasonElement", &[], r)?;
        w.end("vr:Reason")?;
    }
    if let Some(n) = &a.name {
        w.start("vr:Name", &signed)?;
        w.leaf("vr:NameElement", &[], n)?;
        w.end("vr:Name")?;
    }
    if let Some(c) = &a.contact_info {
        w.start("vr:ContactInfo", &signed)?;
        w.leaf("vr:ContactInfoElement", &[], c)?;
        w.end("vr:ContactInfo")?;
    }
    w.start("vr:SubFilter", &signed)?;
    w.leaf("vr:SubFilterElement", &[], &a.sub_filter)?;
    w.end("vr:SubFilter")?;
    let br: Vec<String> = a.byte_range.iter().map(u64::to_string).collect();
    w.leaf("vr:ByteRange", &[], &br.join(" "))?;
    w.start("vr:Filter", &[])?;
    w.leaf("vr:Filter", &[], &a.filter)?;
    w.end("vr:Filter")?;
    w.end("vr:SignatureAttributes")
}

/// Generate the XML validation report (`generate_report`).
pub fn generate_report(input: &ReportInput) -> Result<String, quick_xml::Error> {
    let mut w = W {
        w: Writer::new_with_indent(Cursor::new(Vec::new()), b' ', 2),
    };
    w.w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .map_err(quick_xml::Error::from)?;
    w.start(
        "vr:ValidationReport",
        &[
            ("xmlns:vr", VR_NS),
            ("xmlns:XAdES", XADES_NS),
            ("xmlns:ds", DS_NS),
            ("xmlns:xs", "http://www.w3.org/2001/XMLSchema"),
        ],
    )?;
    w.start("vr:SignatureValidationReport", &[])?;
    // SignatureIdentifier
    w.start("vr:SignatureIdentifier", &[])?;
    let dtbsr = input.md_algorithm.digest(&input.signed_attrs_der);
    w.digest("vr:DigestAlgAndValue", input.md_algorithm, &dtbsr)?;
    w.leaf("ds:SignatureValue", &[], &b64(&input.signature_value))?;
    w.leaf("vr:HashOnly", &[], "false")?;
    w.leaf("vr:DocHashOnly", &[], "false")?;
    w.end("vr:SignatureIdentifier")?;
    // ValidationTimeInfo
    w.start("vr:ValidationTimeInfo", &[])?;
    w.leaf("vr:ValidationTime", &[], &xml_time(input.validation_time))?;
    if let Some(t) = input.best_signature_time {
        w.start("vr:BestSignatureTime", &[])?;
        w.leaf("vr:POETime", &[], &xml_time(t))?;
        w.leaf("vr:TypeOfProof", &[], "urn:etsi:019102:poetype:validation")?;
        w.end("vr:BestSignatureTime")?;
    }
    w.end("vr:ValidationTimeInfo")?;
    // SignersDocument
    w.start("vr:SignersDocument", &[])?;
    w.digest(
        "vr:DigestAlgAndValue",
        input.md_algorithm,
        &input.document_digest,
    )?;
    w.end("vr:SignersDocument")?;
    write_attributes(&mut w, &input.attributes)?;
    // SignerInformation
    let signer_vo = ValidationObject {
        object_type: ValidationObjectType::Certificate,
        data: input.signer_cert.clone(),
    };
    w.start("vr:SignerInformation", &[])?;
    w.empty(
        "vr:SignerCertificate",
        &[("VOReference", &signer_vo.identifier())],
    )?;
    w.end("vr:SignerInformation")?;
    // SignatureValidationProcess
    w.start("vr:SignatureValidationProcess", &[])?;
    w.leaf(
        "vr:SignatureValidationProcessID",
        &[],
        &format!("urn:etsi:019102:validationprocess:{}", input.process.id()),
    )?;
    w.end("vr:SignatureValidationProcess")?;
    // SignatureValidationStatus
    w.start("vr:SignatureValidationStatus", &[])?;
    w.leaf(
        "vr:MainIndication",
        &[],
        main_indication_uri(input.subindication.status()),
    )?;
    w.leaf(
        "vr:SubIndication",
        &[],
        &format!(
            "urn:etsi:019102:subindication:{}",
            input.subindication.standard_name()
        ),
    )?;
    w.end("vr:SignatureValidationStatus")?;
    w.end("vr:SignatureValidationReport")?;
    // Validation objects
    w.start("vr:SignatureValidationObjects", &[])?;
    for vo in &input.validation_objects {
        w.start("vr:ValidationObject", &[("id", &vo.identifier())])?;
        w.leaf("vr:ObjectType", &[], &vo.object_type.urn())?;
        w.start("vr:ValidationObjectRepresentation", &[])?;
        w.leaf("vr:base64", &[], &b64(&vo.data))?;
        w.end("vr:ValidationObjectRepresentation")?;
        w.end("vr:ValidationObject")?;
    }
    w.end("vr:SignatureValidationObjects")?;
    w.end("vr:ValidationReport")?;
    String::from_utf8(w.w.into_inner().into_inner())
        .map_err(|e| quick_xml::Error::Io(std::sync::Arc::new(std::io::Error::other(e))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigis_pades::report::{AdesFailure, AdesPassed};

    fn input(sub: AdesSubIndic, process: ValidationProcess) -> ReportInput {
        ReportInput {
            signature_value: vec![1, 2, 3],
            md_algorithm: DigestAlgorithm::Sha256,
            signed_attrs_der: vec![0x31, 0x00],
            document_digest: vec![9; 32],
            validation_time: Moment::from_unix_secs(1_606_262_400),
            best_signature_time: (process != ValidationProcess::Basic)
                .then(|| Moment::from_unix_secs(1_605_830_400)),
            process,
            subindication: sub,
            signer_cert: vec![0x30, 0x00],
            attributes: SignatureAttributes {
                message_digest: vec![7; 32],
                sub_filter: "ETSI.CAdES.detached".into(),
                byte_range: vec![0, 10, 20, 30],
                filter: "Adobe.PPKLite".into(),
                reason: Some("a < b & c".into()),
                ..Default::default()
            },
            validation_objects: vec![ValidationObject {
                object_type: ValidationObjectType::Certificate,
                data: vec![0x30, 0x00],
            }],
        }
    }

    #[test]
    fn report_indications() {
        let ok = generate_report(&input(AdesPassed::OK.into(), ValidationProcess::Basic)).unwrap();
        assert!(ok.contains("urn:etsi:019102:mainindication:total-passed"));
        assert!(ok.contains("urn:etsi:019102:validationprocess:Basic"));
        assert!(ok.contains("a &lt; b &amp; c"));
        let failed = generate_report(&input(
            AdesFailure::HASH_FAILURE.into(),
            ValidationProcess::Lta,
        ))
        .unwrap();
        assert!(failed.contains("urn:etsi:019102:mainindication:total-failed"));
        assert!(failed.contains("urn:etsi:019102:subindication:HASH_FAILURE"));
        assert!(failed.contains("urn:etsi:019102:validationprocess:LTA"));
        assert!(failed.contains("<vr:POETime>2020-11-20T00:00:00Z</vr:POETime>"));
        let vo_id = ValidationObject {
            object_type: ValidationObjectType::Certificate,
            data: vec![0x30, 0x00],
        }
        .identifier();
        assert!(vo_id.starts_with("vo-certificate-"));
        assert_eq!(failed.matches(&vo_id).count(), 2);
    }
}
