//! XMLDSig / XAdES signature verification against a known signer
//! certificate, matching the checks pyHanko performs through signxml's
//! `XAdESVerifier` (`eutl_parse._verify_xml`).
//!
//! Original code; behaviour follows signxml 4.x as used by pyHanko 0.38.1:
//!
//! * the first `ds:Signature` element in document order is verified;
//! * SHA-1 based signature and reference digest algorithms are rejected
//!   (signxml's default `SignatureConfiguration`);
//! * the signer certificate must be valid at the verification time;
//! * a `KeyValue` / `DEREncodedKeyValue` must match the certificate key;
//! * every reference digest must match; unknown transforms are ignored, as
//!   signxml does; XPointer and external references are rejected;
//! * one reference must point to `xades:SignedProperties`, whose
//!   `SigningCertificate(V2)` digests must match the certificates in
//!   `KeyInfo` and the first one the signer certificate.

use base64::Engine as _;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use roxmltree::{Document, Node};
use sigis_pki_core::algorithms::{
    validate_signature, DigestAlgorithm, RsaPssParams, SignatureValidationContext,
};
use sigis_pki_core::asn1::oids;
use sigis_pki_core::cert::Cert;
use sigis_pki_core::time::Moment;
use spki::AlgorithmIdentifierOwned;

use super::c14n::{canonicalize, C14nMethod, C14nParams};
use super::{child, children, element_children, is, parse, text_content, DSIG_NS, XADES_NS};

const DSIG11_NS: &str = "http://www.w3.org/2009/xmldsig11#";
const EC_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Failure to verify an XML signature (signxml's `SignXMLException` family).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DsigError {
    /// The input does not have the expected structure (`InvalidInput`).
    #[error("{0}")]
    InvalidInput(String),
    /// The signature value does not verify (`InvalidSignature`).
    #[error("{0}")]
    InvalidSignature(String),
    /// A reference or certificate digest does not match (`InvalidDigest`).
    #[error("{0}")]
    InvalidDigest(String),
    /// The signer certificate is not usable (`InvalidCertificate`).
    #[error("{0}")]
    InvalidCertificate(String),
}

impl DsigError {
    /// signxml's exception class name.
    pub fn class_name(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "InvalidInput",
            Self::InvalidSignature(_) => "InvalidSignature",
            Self::InvalidDigest(_) => "InvalidDigest",
            Self::InvalidCertificate(_) => "InvalidCertificate",
        }
    }
}

fn invalid(msg: impl Into<String>) -> DsigError {
    DsigError::InvalidInput(msg.into())
}

/// One verified reference (`VerifyResult`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReference {
    /// The `URI` attribute of the reference.
    pub uri: String,
    /// The data as it was digested (after transforms).
    pub signed_data: Vec<u8>,
    /// Namespace and local name of the root element of `signed_data`, if it
    /// parses as XML.
    pub signed_root: Option<(Option<String>, String)>,
}

#[derive(Clone, Copy, Debug)]
enum SigAlg {
    RsaPkcs1(DigestAlgorithm),
    RsaPss(DigestAlgorithm),
    Ecdsa(DigestAlgorithm),
}

/// Resolve a `SignatureMethod` URI. SHA-1 methods are rejected, as by
/// signxml's default configuration; SHA-3, DSA and HMAC are unsupported.
fn signature_method(uri: &str) -> Result<SigAlg, DsigError> {
    use DigestAlgorithm::*;
    const MORE: &str = "http://www.w3.org/2001/04/xmldsig-more#";
    const MORE07: &str = "http://www.w3.org/2007/05/xmldsig-more#";
    let alg = if let Some(frag) = uri.strip_prefix(MORE) {
        match frag {
            "rsa-sha224" => SigAlg::RsaPkcs1(Sha224),
            "rsa-sha256" => SigAlg::RsaPkcs1(Sha256),
            "rsa-sha384" => SigAlg::RsaPkcs1(Sha384),
            "rsa-sha512" => SigAlg::RsaPkcs1(Sha512),
            "ecdsa-sha224" => SigAlg::Ecdsa(Sha224),
            "ecdsa-sha256" => SigAlg::Ecdsa(Sha256),
            "ecdsa-sha384" => SigAlg::Ecdsa(Sha384),
            "ecdsa-sha512" => SigAlg::Ecdsa(Sha512),
            "ecdsa-sha1" => {
                return Err(invalid(
                    "Signature method ECDSA_SHA1 forbidden by configuration",
                ))
            }
            _ => return Err(invalid(format!("Unsupported signature method {uri}"))),
        }
    } else if let Some(frag) = uri.strip_prefix(MORE07) {
        match frag {
            "sha224-rsa-MGF1" => SigAlg::RsaPss(Sha224),
            "sha256-rsa-MGF1" => SigAlg::RsaPss(Sha256),
            "sha384-rsa-MGF1" => SigAlg::RsaPss(Sha384),
            "sha512-rsa-MGF1" => SigAlg::RsaPss(Sha512),
            "sha1-rsa-MGF1" => {
                return Err(invalid(
                    "Signature method SHA1_RSA_MGF1 forbidden by configuration",
                ))
            }
            _ => return Err(invalid(format!("Unsupported signature method {uri}"))),
        }
    } else if uri == "http://www.w3.org/2000/09/xmldsig#rsa-sha1" {
        return Err(invalid(
            "Signature method RSA_SHA1 forbidden by configuration",
        ));
    } else {
        return Err(invalid(format!("Unsupported signature method {uri}")));
    };
    Ok(alg)
}

/// Resolve a `DigestMethod` URI for reference digests (SHA-1 forbidden).
fn reference_digest(uri: &str) -> Result<DigestAlgorithm, DsigError> {
    match any_digest(uri)? {
        DigestAlgorithm::Sha1 => Err(invalid("Digest algorithm SHA1 forbidden by configuration")),
        d => Ok(d),
    }
}

/// Resolve any `DigestMethod` URI (certificate digests may use SHA-1).
fn any_digest(uri: &str) -> Result<DigestAlgorithm, DsigError> {
    Ok(match uri {
        "http://www.w3.org/2000/09/xmldsig#sha1" => DigestAlgorithm::Sha1,
        "http://www.w3.org/2001/04/xmldsig-more#sha224" => DigestAlgorithm::Sha224,
        "http://www.w3.org/2001/04/xmlenc#sha256" => DigestAlgorithm::Sha256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => DigestAlgorithm::Sha384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => DigestAlgorithm::Sha512,
        other => return Err(invalid(format!("Unsupported digest algorithm {other}"))),
    })
}

fn b64(node: Node<'_, '_>) -> Result<Vec<u8>, DsigError> {
    let text: String = text_content(node)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(text.as_bytes())
        .map_err(|e| invalid(format!("invalid base64 in {}: {e}", node.tag_name().name())))
}

fn require<'a, 'i>(node: Node<'a, 'i>, ns: &str, name: &str) -> Result<Node<'a, 'i>, DsigError> {
    child(node, ns, name).ok_or_else(|| {
        invalid(format!(
            "Expected to find XML element {name} in {}",
            node.tag_name().name()
        ))
    })
}

fn c14n_params(method_node: Node<'_, '_>) -> Result<C14nParams, DsigError> {
    let alg = method_node.attribute("Algorithm").unwrap_or("");
    let mut params = C14nParams::from_uri(alg)
        .ok_or_else(|| invalid(format!("Unsupported canonicalization method {alg}")))?;
    // signxml renders "C14N 1.1" with lxml's C14N 1.0 serializer.
    if params.method == C14nMethod::Inclusive11 {
        params.method = C14nMethod::Inclusive10;
    }
    if let Some(inc) = child(method_node, EC_NS, "InclusiveNamespaces") {
        if let Some(list) = inc.attribute("PrefixList") {
            params.inclusive_prefixes = list.split(' ').map(str::to_owned).collect();
        }
    }
    Ok(params)
}

/// Enforce a deliberately narrow XMLDSig/XAdES schema profile before any
/// cryptographic checks. Unsupported schema extensions fail closed. This is
/// not a general XSD processor; the supported grammar covers trusted lists,
/// certificate key values and the signed properties consumed below.
fn check_structure(sig: Node<'_, '_>) -> Result<(), DsigError> {
    use std::collections::BTreeSet;

    fn xml_space(c: char) -> bool {
        matches!(c, ' ' | '\t' | '\r' | '\n')
    }
    fn sequence(node: Node<'_, '_>, ns: &str, spec: &[(&str, usize, usize)]) -> bool {
        let kids: Vec<_> = element_children(node).collect();
        let mut pos = 0;
        for &(name, min, max) in spec {
            let start = pos;
            while pos < kids.len() && is(kids[pos], ns, name) && pos - start < max {
                pos += 1;
            }
            if pos - start < min {
                return false;
            }
        }
        pos == kids.len()
    }
    fn id_valid(id: &str) -> bool {
        // An ASCII subset of xsd:ID/NCName; Unicode IDs are unsupported.
        let mut chars = id.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    }

    let mut ids = BTreeSet::new();
    for node in sig.descendants().filter(|n| n.is_element()) {
        let name = node.tag_name().name();
        let ns = node.tag_name().namespace();
        let mut attrs: &[&str] = &[];
        let mut required: &[&str] = &[];
        let mut scalar = false;
        let mut binary = false;
        let structure = match (ns, name) {
            (Some(DSIG_NS), "Signature") => {
                attrs = &["Id"];
                sequence(
                    node,
                    DSIG_NS,
                    &[
                        ("SignedInfo", 1, 1),
                        ("SignatureValue", 1, 1),
                        ("KeyInfo", 0, 1),
                        ("Object", 0, usize::MAX),
                    ],
                )
            }
            (Some(DSIG_NS), "SignedInfo") => {
                attrs = &["Id"];
                sequence(
                    node,
                    DSIG_NS,
                    &[
                        ("CanonicalizationMethod", 1, 1),
                        ("SignatureMethod", 1, 1),
                        ("Reference", 1, usize::MAX),
                    ],
                )
            }
            (Some(DSIG_NS), "Reference") => {
                attrs = &["Id", "URI", "Type"];
                sequence(
                    node,
                    DSIG_NS,
                    &[
                        ("Transforms", 0, 1),
                        ("DigestMethod", 1, 1),
                        ("DigestValue", 1, 1),
                    ],
                )
            }
            (Some(DSIG_NS), "Transforms") => {
                sequence(node, DSIG_NS, &[("Transform", 1, usize::MAX)])
            }
            (Some(DSIG_NS), "CanonicalizationMethod" | "Transform") => {
                attrs = &["Algorithm"];
                required = attrs;
                // Only the canonicalization parameter supported by this verifier.
                sequence(node, EC_NS, &[("InclusiveNamespaces", 0, 1)])
            }
            (Some(DSIG_NS), "SignatureMethod" | "DigestMethod") => {
                attrs = &["Algorithm"];
                required = attrs;
                element_children(node).next().is_none()
            }
            (Some(DSIG_NS), "SignatureValue") => {
                attrs = &["Id"];
                scalar = true;
                binary = true;
                true
            }
            (
                Some(DSIG_NS),
                "DigestValue" | "X509Certificate" | "X509SKI" | "X509CRL" | "Modulus" | "Exponent",
            ) => {
                scalar = true;
                binary = true;
                true
            }
            (Some(DSIG_NS), "KeyInfo") => {
                attrs = &["Id"];
                element_children(node).next().is_some()
                    && element_children(node).all(|k| {
                        is(k, DSIG_NS, "X509Data")
                            || is(k, DSIG_NS, "KeyValue")
                            || is(k, DSIG11_NS, "DEREncodedKeyValue")
                    })
            }
            (Some(DSIG_NS), "KeyValue") => {
                let kids: Vec<_> = element_children(node).collect();
                kids.len() == 1
                    && (is(kids[0], DSIG_NS, "RSAKeyValue") || is(kids[0], DSIG11_NS, "ECKeyValue"))
            }
            (Some(DSIG_NS), "RSAKeyValue") => {
                sequence(node, DSIG_NS, &[("Modulus", 1, 1), ("Exponent", 1, 1)])
            }
            (Some(DSIG_NS), "X509Data") => {
                element_children(node).next().is_some()
                    && element_children(node).all(|k| {
                        k.tag_name().namespace() == Some(DSIG_NS)
                            && matches!(
                                k.tag_name().name(),
                                "X509IssuerSerial"
                                    | "X509SKI"
                                    | "X509SubjectName"
                                    | "X509Certificate"
                                    | "X509CRL"
                            )
                    })
            }
            (Some(DSIG_NS), "X509IssuerSerial") | (Some(XADES_NS), "IssuerSerial") => sequence(
                node,
                DSIG_NS,
                &[("X509IssuerName", 1, 1), ("X509SerialNumber", 1, 1)],
            ),
            (Some(DSIG_NS), "X509IssuerName" | "X509SubjectName" | "X509SerialNumber") => {
                scalar = true;
                if name == "X509SerialNumber" {
                    let text = text_content(node);
                    let value = text.trim_matches(xml_space);
                    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
                    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
                } else {
                    true
                }
            }
            (Some(DSIG_NS), "Object") => {
                attrs = &["Id", "MimeType", "Encoding"];
                // No unchecked arbitrary XML extensions inside a trusted signature.
                sequence(node, XADES_NS, &[("QualifyingProperties", 1, 1)])
            }
            (Some(DSIG11_NS), "ECKeyValue") => {
                attrs = &["Id"];
                sequence(
                    node,
                    DSIG11_NS,
                    &[("NamedCurve", 1, 1), ("PublicKey", 1, 1)],
                )
            }
            (Some(DSIG11_NS), "NamedCurve") => {
                attrs = &["URI"];
                required = attrs;
                element_children(node).next().is_none()
            }
            (Some(DSIG11_NS), "PublicKey" | "DEREncodedKeyValue") => {
                if name == "DEREncodedKeyValue" {
                    attrs = &["Id"];
                }
                scalar = true;
                binary = true;
                true
            }
            (Some(EC_NS), "InclusiveNamespaces") => {
                attrs = &["PrefixList"];
                required = attrs;
                element_children(node).next().is_none()
            }
            (Some(XADES_NS), "QualifyingProperties") => {
                attrs = &["Id", "Target"];
                required = &["Target"];
                sequence(node, XADES_NS, &[("SignedProperties", 1, 1)])
            }
            (Some(XADES_NS), "SignedProperties") => {
                attrs = &["Id"];
                sequence(
                    node,
                    XADES_NS,
                    &[
                        ("SignedSignatureProperties", 1, 1),
                        ("SignedDataObjectProperties", 0, 1),
                    ],
                )
            }
            (Some(XADES_NS), "SignedSignatureProperties") => {
                attrs = &["Id"];
                sequence(
                    node,
                    XADES_NS,
                    &[
                        ("SigningTime", 0, 1),
                        ("SigningCertificate", 0, 1),
                        ("SigningCertificateV2", 0, 1),
                    ],
                )
            }
            (Some(XADES_NS), "SigningCertificate" | "SigningCertificateV2") => {
                sequence(node, XADES_NS, &[("Cert", 1, usize::MAX)])
            }
            (Some(XADES_NS), "Cert") => {
                attrs = &["URI"];
                let v2 = node
                    .parent()
                    .is_some_and(|p| is(p, XADES_NS, "SigningCertificateV2"));
                sequence(
                    node,
                    XADES_NS,
                    &[
                        ("CertDigest", 1, 1),
                        (
                            if v2 { "IssuerSerialV2" } else { "IssuerSerial" },
                            usize::from(!v2),
                            1,
                        ),
                    ],
                )
            }
            (Some(XADES_NS), "CertDigest") => sequence(
                node,
                DSIG_NS,
                &[("DigestMethod", 1, 1), ("DigestValue", 1, 1)],
            ),
            (Some(XADES_NS), "IssuerSerialV2") => {
                scalar = true;
                binary = true;
                true
            }
            (Some(XADES_NS), "SigningTime" | "Description" | "MimeType" | "Encoding") => {
                scalar = true;
                if name == "SigningTime" {
                    Moment::parse_xsd_datetime(text_content(node).trim_matches(xml_space)).is_some()
                } else {
                    true
                }
            }
            (Some(XADES_NS), "SignedDataObjectProperties") => {
                attrs = &["Id"];
                sequence(node, XADES_NS, &[("DataObjectFormat", 0, usize::MAX)])
            }
            (Some(XADES_NS), "DataObjectFormat") => {
                attrs = &["ObjectReference"];
                required = attrs;
                sequence(
                    node,
                    XADES_NS,
                    &[
                        ("Description", 0, 1),
                        ("MimeType", 0, 1),
                        ("Encoding", 0, 1),
                    ],
                )
            }
            _ => false,
        };
        let bad_attr = node
            .attributes()
            .any(|a| a.namespace().is_some() || !attrs.contains(&a.name()));
        let missing_attr = required.iter().any(|a| node.attribute(*a).is_none());
        let bad_content = if scalar {
            element_children(node).next().is_some()
        } else {
            node.children()
                .filter(|c| c.is_text())
                .any(|c| !c.text().unwrap_or("").chars().all(xml_space))
        };
        if !structure || bad_attr || missing_attr || bad_content {
            return Err(invalid(format!(
                "Unsupported or invalid XML signature schema content in {name}"
            )));
        }
        if let Some(id) = node.attribute("Id") {
            if !id_valid(id) || !ids.insert(id.to_owned()) {
                return Err(invalid("Invalid or duplicate XML signature ID"));
            }
        }
        if binary {
            // xsd:base64Binary permits XML whitespace, not arbitrary Unicode whitespace.
            let text = text_content(node);
            let compact: String = text.chars().filter(|c| !xml_space(*c)).collect();
            base64::engine::general_purpose::STANDARD
                .decode(compact.as_bytes())
                .map_err(|_| invalid(format!("Invalid base64 schema content in {name}")))?;
        }
    }
    Ok(())
}

fn ecdsa_raw_to_der(raw: &[u8], key_bits: usize) -> Result<Vec<u8>, DsigError> {
    let want = key_bits.div_ceil(8) * 2;
    if raw.len() != want {
        return Err(DsigError::InvalidSignature(format!(
            "Expected {want} byte SignatureValue, got {}",
            raw.len()
        )));
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    let uint = |b: &[u8]| -> Result<der::asn1::Uint, DsigError> {
        der::asn1::Uint::new(b).map_err(|e| DsigError::InvalidSignature(e.to_string()))
    };
    #[derive(der::Sequence)]
    struct EcSig {
        r: der::asn1::Uint,
        s: der::asn1::Uint,
    }
    EcSig {
        r: uint(r)?,
        s: uint(s)?,
    }
    .to_der()
    .map_err(|e| DsigError::InvalidSignature(e.to_string()))
}

fn ec_key_bits(cert: &Cert) -> Option<usize> {
    let spki = cert.public_key();
    if spki.algorithm.oid != oids::EC_PUBLIC_KEY {
        return None;
    }
    let curve: ObjectIdentifier = spki.algorithm.parameters.as_ref()?.decode_as().ok()?;
    match curve {
        oids::SECP256R1 => Some(256),
        oids::SECP384R1 => Some(384),
        oids::SECP521R1 => Some(521),
        _ => None,
    }
}

fn verify_signature_value(
    alg: SigAlg,
    cert: &Cert,
    signed_info: &[u8],
    raw_sig: &[u8],
) -> Result<(), DsigError> {
    let spki = cert.public_key();
    let is_rsa =
        spki.algorithm.oid == oids::RSA_ENCRYPTION || spki.algorithm.oid == oids::RSASSA_PSS;
    let (sig, algorithm) = match alg {
        SigAlg::RsaPkcs1(d) | SigAlg::RsaPss(d) if !is_rsa => {
            let _ = d;
            return Err(invalid(
                "DER encoded key value does not match specified signature algorithm",
            ));
        }
        SigAlg::RsaPkcs1(d) => {
            let oid = match d {
                DigestAlgorithm::Sha224 => oids::SHA224_WITH_RSA,
                DigestAlgorithm::Sha256 => oids::SHA256_WITH_RSA,
                DigestAlgorithm::Sha384 => oids::SHA384_WITH_RSA,
                DigestAlgorithm::Sha512 => oids::SHA512_WITH_RSA,
                DigestAlgorithm::Sha1 => oids::SHA1_WITH_RSA,
                // XML-DSig here uses SHA-1 / SHA-2 only.
                other => {
                    return Err(invalid(format!(
                        "unsupported digest algorithm {}",
                        other.name()
                    )))
                }
            };
            (
                raw_sig.to_vec(),
                AlgorithmIdentifierOwned {
                    oid,
                    parameters: None,
                },
            )
        }
        SigAlg::RsaPss(d) => {
            let mgf = AlgorithmIdentifierOwned {
                oid: oids::MGF1,
                parameters: Some(
                    der::Any::encode_from(&d.algorithm_identifier())
                        .map_err(|e| invalid(e.to_string()))?,
                ),
            };
            let params = RsaPssParams {
                hash_algorithm: Some(d.algorithm_identifier()),
                mask_gen_algorithm: Some(mgf),
                salt_length: u32::try_from(d.output_len()).ok(),
                trailer_field: None,
            };
            let any = der::Any::encode_from(&params).map_err(|e| invalid(e.to_string()))?;
            (
                raw_sig.to_vec(),
                AlgorithmIdentifierOwned {
                    oid: oids::RSASSA_PSS,
                    parameters: Some(any),
                },
            )
        }
        SigAlg::Ecdsa(d) => {
            let bits = ec_key_bits(cert).ok_or_else(|| {
                invalid("DER encoded key value does not match specified signature algorithm")
            })?;
            let oid = match d {
                DigestAlgorithm::Sha224 => oids::ECDSA_WITH_SHA224,
                DigestAlgorithm::Sha256 => oids::ECDSA_WITH_SHA256,
                DigestAlgorithm::Sha384 => oids::ECDSA_WITH_SHA384,
                DigestAlgorithm::Sha512 => oids::ECDSA_WITH_SHA512,
                DigestAlgorithm::Sha1 => oids::ECDSA_WITH_SHA1,
                // XML-DSig here uses SHA-1 / SHA-2 only.
                other => {
                    return Err(invalid(format!(
                        "unsupported digest algorithm {}",
                        other.name()
                    )))
                }
            };
            (
                ecdsa_raw_to_der(raw_sig, bits)?,
                AlgorithmIdentifierOwned {
                    oid,
                    parameters: None,
                },
            )
        }
    };
    validate_signature(
        &sig,
        signed_info,
        &spki,
        &algorithm,
        &SignatureValidationContext::default(),
    )
    .map_err(|e| DsigError::InvalidSignature(format!("Signature verification failed: {e}")))
}

/// Compare a `ds:KeyValue` with the certificate key. Unrecognised or
/// mismatching key values are errors (signxml raises in both cases).
fn match_key_value(key_value: Node<'_, '_>, cert: &Cert) -> Result<(), DsigError> {
    let spki = cert.public_key();
    let mismatch = || {
        invalid(
            "Both X509Data and KeyValue found and they represent different public keys. \
             Use verify(ignore_ambiguous_key_info=True) to ignore KeyValue and validate \
             using X509Data only.",
        )
    };
    if let Some(rsa) = child(key_value, DSIG_NS, "RSAKeyValue") {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::traits::PublicKeyParts;
        let key = rsa::RsaPublicKey::from_pkcs1_der(spki.subject_public_key.raw_bytes())
            .map_err(|_| mismatch())?;
        let n = b64(require(rsa, DSIG_NS, "Modulus")?)?;
        let e = b64(require(rsa, DSIG_NS, "Exponent")?)?;
        let strip = |v: Vec<u8>| -> Vec<u8> {
            let i = v.iter().position(|b| *b != 0).unwrap_or(v.len());
            v[i..].to_vec()
        };
        if strip(n) == key.n().to_be_bytes_trimmed_vartime().to_vec()
            && strip(e) == key.e().to_be_bytes_trimmed_vartime().to_vec()
        {
            return Ok(());
        }
        return Err(mismatch());
    }
    if let Some(ec) = child(key_value, DSIG11_NS, "ECKeyValue") {
        let point = b64(require(ec, DSIG11_NS, "PublicKey")?)?;
        let curve = require(ec, DSIG11_NS, "NamedCurve")?
            .attribute("URI")
            .ok_or_else(mismatch)?
            .to_owned();
        let key_curve: Option<ObjectIdentifier> = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as().ok());
        let same_curve = key_curve.is_some_and(|c| curve == format!("urn:oid:{c}"));
        if same_curve && point == spki.subject_public_key.raw_bytes() {
            return Ok(());
        }
        return Err(mismatch());
    }
    Err(mismatch())
}

fn match_der_key_value(node: Node<'_, '_>, cert: &Cert) -> Result<(), DsigError> {
    let der = b64(node)?;
    let theirs = spki::SubjectPublicKeyInfoOwned::from_der(&der)
        .map_err(|e| invalid(format!("DEREncodedKeyValue: {e}")))?;
    let ours = cert.public_key();
    if theirs.subject_public_key == ours.subject_public_key
        && theirs.algorithm.oid == ours.algorithm.oid
    {
        Ok(())
    } else {
        Err(invalid(
            "Both X509Data and DEREncodedKeyValue found and they represent different public keys.",
        ))
    }
}

/// Elements whose `Id`, `ID`, `id` (or `xml:id`) attribute equals `id`.
fn resolve_id<'a, 'i>(doc: &'a Document<'i>, id: &str) -> Result<Node<'a, 'i>, DsigError> {
    for attr_name in ["Id", "ID", "id"] {
        let hits: Vec<_> = doc
            .descendants()
            .filter(|n| n.is_element())
            .filter(|n| {
                n.attributes()
                    .any(|a| a.name() == attr_name && a.value() == id)
            })
            .collect();
        match hits.len() {
            0 => continue,
            1 => return Ok(hits[0]),
            k => {
                return Err(invalid(format!(
                    "Ambiguous reference URI #{id} resolved to {k} nodes"
                )))
            }
        }
    }
    Err(invalid(format!("Unable to resolve reference URI: #{id}")))
}

fn root_name(data: &[u8]) -> Option<(Option<String>, String)> {
    let s = std::str::from_utf8(data).ok()?;
    let doc = parse(s).ok()?;
    let r = doc.root_element();
    Some((
        r.tag_name().namespace().map(str::to_owned),
        r.tag_name().name().to_owned(),
    ))
}

fn verify_reference(
    doc: &Document<'_>,
    signature: Node<'_, '_>,
    reference: Node<'_, '_>,
    index: usize,
) -> Result<VerifiedReference, DsigError> {
    let uri = reference
        .attribute("URI")
        .ok_or_else(|| invalid("References without URIs are not supported"))?;
    let payload = if uri.is_empty() {
        doc.root_element()
    } else if uri.starts_with("#xpointer(") {
        return Err(invalid("XPointer references are not supported"));
    } else if let Some(id) = uri.strip_prefix('#') {
        resolve_id(doc, id)?
    } else {
        return Err(invalid(format!(
            "External URI dereferencing is not configured: {uri}"
        )));
    };
    let transforms: Vec<Node<'_, '_>> = child(reference, DSIG_NS, "Transforms")
        .map(|t| children(t, DSIG_NS, "Transform").collect())
        .unwrap_or_default();
    let enveloped = transforms
        .iter()
        .any(|t| t.attribute("Algorithm") == Some(ENVELOPED));
    if transforms
        .iter()
        .any(|t| t.attribute("Algorithm") == Some("http://www.w3.org/2000/09/xmldsig#base64"))
    {
        return Err(invalid("base64 transforms are not supported"));
    }
    let exclude = enveloped.then(|| signature.id());
    let mut data: Option<Vec<u8>> = None;
    for t in &transforms {
        let alg = t.attribute("Algorithm").unwrap_or("");
        if C14nParams::from_uri(alg).is_none() {
            continue;
        }
        let params = c14n_params(*t)?;
        data = Some(match data {
            None => canonicalize(doc, payload, exclude, &params).map_err(|e| invalid(e.0))?,
            Some(prev) => {
                let s = String::from_utf8(prev).map_err(|e| invalid(e.to_string()))?;
                let d2 = parse(&s).map_err(|e| invalid(e.0))?;
                canonicalize(&d2, d2.root_element(), None, &params).map_err(|e| invalid(e.0))?
            }
        });
    }
    let data = match data {
        Some(d) => d,
        None => {
            let params = C14nParams {
                method: C14nMethod::Inclusive10,
                with_comments: false,
                inclusive_prefixes: Vec::new(),
            };
            canonicalize(doc, payload, exclude, &params).map_err(|e| invalid(e.0))?
        }
    };
    let dm = require(reference, DSIG_NS, "DigestMethod")?;
    let digest_alg = reference_digest(dm.attribute("Algorithm").unwrap_or(""))?;
    let expected = b64(require(reference, DSIG_NS, "DigestValue")?)?;
    if digest_alg.digest(&data) != expected {
        return Err(DsigError::InvalidDigest(format!(
            "Digest mismatch for reference {index} ({uri})"
        )));
    }
    Ok(VerifiedReference {
        uri: uri.to_owned(),
        signed_root: root_name(&data),
        signed_data: data,
    })
}

/// Verify the XAdES signature on `xml` with the signer certificate `cert`
/// at time `at`, returning the verified references.
pub fn verify_xades(
    xml: &str,
    cert: &Cert,
    at: Moment,
) -> Result<Vec<VerifiedReference>, DsigError> {
    let doc = parse(xml).map_err(|e| invalid(e.0))?;
    let root = doc.root_element();
    let signature = if is(root, DSIG_NS, "Signature") {
        root
    } else {
        root.descendants()
            .skip(1)
            .find(|n| is(*n, DSIG_NS, "Signature"))
            .ok_or_else(|| invalid("Expected to find XML element Signature"))?
    };
    check_structure(signature)?;
    let signed_info = require(signature, DSIG_NS, "SignedInfo")?;
    let c14n = c14n_params(require(signed_info, DSIG_NS, "CanonicalizationMethod")?)?;
    let sig_alg = signature_method(
        require(signed_info, DSIG_NS, "SignatureMethod")?
            .attribute("Algorithm")
            .unwrap_or(""),
    )?;
    let raw_sig = b64(require(signature, DSIG_NS, "SignatureValue")?)?;
    let key_info = child(signature, DSIG_NS, "KeyInfo");
    let key_value = key_info.and_then(|k| child(k, DSIG_NS, "KeyValue"));
    let der_key_value = key_info.and_then(|k| child(k, DSIG11_NS, "DEREncodedKeyValue"));
    let si_c14n = canonicalize(&doc, signed_info, None, &c14n).map_err(|e| invalid(e.0))?;

    if at < cert.not_before() {
        return Err(DsigError::InvalidCertificate(format!(
            "provided x509_cert: certificate is not yet valid at validation time {at}"
        )));
    }
    if at > cert.not_after() {
        return Err(DsigError::InvalidCertificate(format!(
            "provided x509_cert: certificate has expired at validation time {at}"
        )));
    }
    verify_signature_value(sig_alg, cert, &si_c14n, &raw_sig)?;
    if let Some(kv) = key_value {
        match_key_value(kv, cert)?;
    }
    if let Some(dkv) = der_key_value {
        match_der_key_value(dkv, cert)?;
    }

    // Read the references from the signed (canonical) SignedInfo.
    let si_text = String::from_utf8(si_c14n).map_err(|e| invalid(e.to_string()))?;
    let si_doc = parse(&si_text).map_err(|e| invalid(e.0))?;
    let mut results = Vec::new();
    for (idx, reference) in children(si_doc.root_element(), DSIG_NS, "Reference").enumerate() {
        results.push(verify_reference(&doc, signature, reference, idx)?);
    }

    // XAdES: SignedProperties must be among the references.
    let props = results
        .iter()
        .find(|r| {
            r.signed_root
                .as_ref()
                .is_some_and(|(ns, n)| ns.as_deref() == Some(XADES_NS) && n == "SignedProperties")
        })
        .ok_or_else(|| invalid("Expected to find a xades:SignedProperties element"))?;
    verify_cert_digests(signature, &props.signed_data, cert)?;
    Ok(results)
}

fn verify_cert_digests(
    signature: Node<'_, '_>,
    signed_props: &[u8],
    signer: &Cert,
) -> Result<(), DsigError> {
    let mut certs: Vec<Vec<u8>> = Vec::new();
    if let Some(ki) = child(signature, DSIG_NS, "KeyInfo") {
        for xd in children(ki, DSIG_NS, "X509Data") {
            for c in children(xd, DSIG_NS, "X509Certificate") {
                let der = b64(c)?;
                Cert::from_der(&der).map_err(|e| invalid(format!("X509Certificate: {e}")))?;
                certs.push(der);
            }
        }
    }
    if !certs.iter().any(|c| c.as_slice() == signer.der()) {
        certs.push(signer.der().to_vec());
    }
    let text = std::str::from_utf8(signed_props).map_err(|e| invalid(e.to_string()))?;
    let doc = parse(text).map_err(|e| invalid(e.0))?;
    let ssp = require(doc.root_element(), XADES_NS, "SignedSignatureProperties")?;
    let v1 = child(ssp, XADES_NS, "SigningCertificate");
    let v2 = child(ssp, XADES_NS, "SigningCertificateV2");
    let node = match (v1, v2) {
        (None, None) => {
            return Err(invalid(
                "Expected to find XML element xades:SigningCertificate or xades:SigningCertificateV2",
            ))
        }
        (Some(_), Some(_)) => {
            return Err(invalid(
                "Expected to find exactly one of xades:SigningCertificate or xades:SigningCertificateV2",
            ))
        }
        (Some(n), None) | (None, Some(n)) => n,
    };
    for (idx, c) in children(node, XADES_NS, "Cert").enumerate() {
        let cd = require(c, XADES_NS, "CertDigest")?;
        let alg = any_digest(
            require(cd, DSIG_NS, "DigestMethod")?
                .attribute("Algorithm")
                .unwrap_or(""),
        )?;
        let value = b64(require(cd, DSIG_NS, "DigestValue")?)?;
        if !certs.iter().any(|der| alg.digest(der) == value) {
            return Err(DsigError::InvalidDigest(
                "Digest mismatch for certificate digest".into(),
            ));
        }
        if idx == 0 && alg.digest(signer.der()) != value {
            return Err(DsigError::InvalidDigest(
                "Digest mismatch for signing certificate digest".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod schema_tests {
    use super::*;

    const VALID: &str = r##"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="sig">
<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<Reference URI="#payload"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<DigestValue>AA==</DigestValue></Reference></SignedInfo>
<SignatureValue>AA==</SignatureValue></Signature>"##;

    #[test]
    fn supported_schema_profile_rejects_ignored_invalid_content() {
        let doc = parse(VALID).unwrap();
        check_structure(doc.root_element()).unwrap();
        for (from, to) in [
            ("<SignatureValue>", "<SignatureValue bogus=\"1\">"),
            ("<SignatureValue>", "<SignatureValue xml:lang=\"en\">"),
            ("</SignatureValue>", "<DigestValue/></SignatureValue>"),
            ("<SignedInfo>", "unexpected<SignedInfo>"),
            ("<DigestValue>", "<DigestValue Id=\"x\">"),
            ("<DigestValue>AA==", "<DigestValue>AA\u{a0}=="),
            ("<Reference URI=", "<Reference Id=\"sig\" URI="),
            ("Id=\"sig\"", "Id=\"1-invalid-id\""),
            ("<DigestMethod Algorithm=", "<DigestMethod Unexpected="),
            ("<DigestMethod", "<Transforms/><DigestMethod"),
            ("</Signature>", "<KeyInfo/><KeyInfo/></Signature>"),
            ("</Signature>", "<Object><unknown/></Object></Signature>"),
            ("</SignatureValue>", "</SignatureValue><unknown/>"),
        ] {
            assert!(VALID.contains(from));
            let xml = VALID.replacen(from, to, 1);
            let doc = parse(&xml).unwrap();
            assert!(
                check_structure(doc.root_element()).is_err(),
                "accepted {to}"
            );
        }
    }
}
