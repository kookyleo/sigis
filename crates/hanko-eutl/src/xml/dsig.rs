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
use hanko_core::algorithms::{
    validate_signature, DigestAlgorithm, RsaPssParams, SignatureValidationContext,
};
use hanko_core::asn1::oids;
use hanko_core::cert::Cert;
use hanko_core::time::Moment;
use roxmltree::{Document, Node};
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

/// Check the structure of a `ds:Signature` element against the XMLDSig
/// schema (the parts signxml's schema validation would reject).
fn check_structure(sig: Node<'_, '_>) -> Result<(), DsigError> {
    let kids: Vec<_> = element_children(sig).collect();
    let names: Vec<_> = kids
        .iter()
        .map(|k| (k.tag_name().namespace(), k.tag_name().name()))
        .collect();
    let ok = names.len() >= 2
        && names[0] == (Some(DSIG_NS), "SignedInfo")
        && names[1] == (Some(DSIG_NS), "SignatureValue")
        && names[2..].iter().enumerate().all(|(i, n)| {
            *n == (Some(DSIG_NS), "Object") || (i == 0 && *n == (Some(DSIG_NS), "KeyInfo"))
        });
    if !ok {
        return Err(invalid(
            "Signature element does not match the XMLDSig schema",
        ));
    }
    let si = kids[0];
    let si_names: Vec<_> = element_children(si)
        .map(|k| (k.tag_name().namespace(), k.tag_name().name()))
        .collect();
    let ok = si_names.len() >= 3
        && si_names[0] == (Some(DSIG_NS), "CanonicalizationMethod")
        && si_names[1] == (Some(DSIG_NS), "SignatureMethod")
        && si_names[2..]
            .iter()
            .all(|n| *n == (Some(DSIG_NS), "Reference"));
    if !ok {
        return Err(invalid(
            "SignedInfo element does not match the XMLDSig schema",
        ));
    }
    for r in children(si, DSIG_NS, "Reference") {
        let rn: Vec<_> = element_children(r)
            .map(|k| (k.tag_name().namespace(), k.tag_name().name()))
            .collect();
        let ok = matches!(
            rn.as_slice(),
            [
                (Some(DSIG_NS), "Transforms"),
                (Some(DSIG_NS), "DigestMethod"),
                (Some(DSIG_NS), "DigestValue")
            ] | [
                (Some(DSIG_NS), "DigestMethod"),
                (Some(DSIG_NS), "DigestValue")
            ]
        );
        if !ok {
            return Err(invalid(
                "Reference element does not match the XMLDSig schema",
            ));
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
