//! Exact rejection ports and boundary regressions from the round-3 skip audit.
//!
//! The PDF rejection cases preserve the upstream assertions. The DSA boundary
//! regressions isolate existing capabilities and remaining token-signing
//! blockers without claiming a complete HSM signing port.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/signing_integration.rs"]
mod support;

use der::{Any, Decode, Encode};
use sigis_pades_sign::attributes::{simple_attribute, SignerAttributesV2, SIGNER_ATTRIBUTES_V2};
use sigis_pades_sign::pkcs11::{self, Pkcs11Mechanism, PostSignTransform, PreSignTransform};
use sigis_pki_core::algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext};

const VALIDATION_TIME: &str = "2020-11-01T00:00:00Z";

/// The exact upstream adversary inserts two identical values in one
/// signer-attributes-v2 attribute. The current CMS builder preserves both
/// values; the inherited claim that it cannot represent duplicates is stale.
#[test]
fn signer_attributes_v2_duplicate_values_survive_cms_assembly() {
    let signer_attrs = sample_signer_attributes();
    let value = Any::encode_from(&signer_attrs).unwrap();
    let mut values = der::asn1::SetOfVec::new();
    values.insert(value.clone()).unwrap();
    values.insert(value.clone()).unwrap();
    assert_eq!(values.len(), 2);
    let attribute = x509_cert::attr::Attribute {
        oid: SIGNER_ATTRIBUTES_V2,
        values,
    };
    let decoded = x509_cert::attr::Attribute::from_der(&attribute.to_der().unwrap()).unwrap();
    assert_eq!(decoded.values.len(), 2);
    assert!(decoded.values.iter().all(|entry| entry == &value));

    let attr = simple_attribute(SIGNER_ATTRIBUTES_V2, &signer_attrs).unwrap();
    let merged = sigis_pades_sign::cms::attrs_to_set(vec![attr.clone(), attr]).unwrap();
    assert_eq!(merged.len(), 1);
    let merged = merged.iter().next().unwrap();
    assert_eq!(merged.values.len(), 2);
    assert!(merged.values.iter().all(|entry| entry == &value));
}

fn sample_signer_attributes() -> SignerAttributesV2 {
    use der::asn1::Utf8StringRef;

    #[derive(der::Sequence)]
    struct IetfAttrSyntax {
        values: Vec<Any>,
    }

    let group_values = ["Employees", "Executives"]
        .iter()
        .map(|value| Any::encode_from(&Utf8StringRef::new(value).unwrap()).unwrap())
        .collect();
    let group = simple_attribute(
        const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.10.4"),
        &IetfAttrSyntax {
            values: group_values,
        },
    )
    .unwrap();
    SignerAttributesV2 {
        claimed_attributes: Some(vec![Any::encode_from(&group).unwrap()]),
        ..Default::default()
    }
}

/// SHA-256 raw DSA keeps its hash/DER transforms and translates through the
/// safe cryptoki adapter with the standard null, zero-length parameters.
#[test]
fn raw_dsa_sha256_selects_hash_and_signature_transforms() {
    let cert = support::pki("testing-ca-dsa").cert("signer1");
    let mechanism =
        pkcs11::signature_mechanism_for_key(&cert, DigestAlgorithm::Sha256, false).unwrap();
    assert_eq!(mechanism.oid.to_string(), "2.16.840.1.101.3.4.3.2");
    let operation =
        pkcs11::select_pkcs11_signing_params(&mechanism, DigestAlgorithm::Sha256, true, None)
            .unwrap();
    assert_eq!(operation.mechanism, Pkcs11Mechanism::Dsa);
    assert_eq!(
        operation.pre_sign_transform,
        Some(PreSignTransform::HashFully {
            digest: DigestAlgorithm::Sha256,
            wrap_digest_info: false,
        })
    );
    assert_eq!(
        operation.post_sign_transform,
        Some(PostSignTransform::EncodeDsa)
    );
    assert_eq!(operation.mechanism.mechanism_type(), 0x11);
    use pkcs11::cryptoki::mechanism::{
        vendor_defined::VendorDefinedMechanism, Mechanism, MechanismType,
    };

    let mechanism_type = MechanismType::try_from(operation.mechanism.mechanism_type())
        .expect("the standard CKM_DSA mechanism must be usable");
    let mechanism = Mechanism::VendorDefined(VendorDefinedMechanism::new::<()>(
        mechanism_type,
        None,
    ));
    let raw: cryptoki_sys::CK_MECHANISM = (&mechanism).into();
    assert_eq!(raw.mechanism, 0x11);
    assert!(raw.pParameter.is_null());
    assert_eq!(raw.ulParameterLen, 0);
}

/// Recognising a standard mechanism is not a claim that a token implements it.
/// Keep numeric inputs so the unpatched dependency fails at runtime conversion,
/// rather than failing to compile because the new named constants are absent.
#[test]
fn standard_dsa_mechanisms_preserve_ids_and_empty_parameters() {
    use pkcs11::cryptoki::mechanism::{
        vendor_defined::VendorDefinedMechanism, Mechanism, MechanismType,
    };

    let signing_ids: [cryptoki_sys::CK_MECHANISM_TYPE; 6] = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    for value in signing_ids {
        let mechanism_type = MechanismType::try_from(value)
            .expect("standard DSA mechanisms must survive conversion and slot enumeration");
        assert_eq!(*mechanism_type, value);
        assert!(MechanismType::new_vendor_defined(value).is_err());
        let mechanism = Mechanism::VendorDefined(VendorDefinedMechanism::new::<()>(
            mechanism_type,
            None,
        ));
        assert_eq!(mechanism.mechanism_type(), mechanism_type);
        let raw: cryptoki_sys::CK_MECHANISM = (&mechanism).into();
        assert_eq!(raw.mechanism, value);
        assert!(raw.pParameter.is_null());
        assert_eq!(raw.ulParameterLen, 0);
    }
    // This bounded patch deliberately does not add DSA key-generation/SHA-3.
    let unpatched_ids: [cryptoki_sys::CK_MECHANISM_TYPE; 5] = [0x10, 0x18, 0x19, 0x1a, 0x1b];
    for value in unpatched_ids {
        assert!(MechanismType::try_from(value).is_err());
    }
}

/// This fixture uses DSA-with-SHA256, the digest required by the inherited
/// raw-DSA signing case. Verify its real signature and reject a modified TBS.
#[test]
fn dsa_sha256_certificate_signature_verifies_and_rejects_modified_data() {
    let pki = support::pki("testing-ca-dsa");
    let cert = pki.cert("signer1");
    let issuer = pki.cert("interm");
    let decoded = cert.decoded();
    assert_eq!(
        decoded.signature_algorithm().oid.to_string(),
        "2.16.840.1.101.3.4.3.2"
    );
    let signature = decoded.signature().as_bytes().unwrap();
    let mut signed_data = decoded.tbs_certificate().to_der().unwrap();
    let public_key = issuer.public_key();
    let context = SignatureValidationContext::default();
    validate_signature(
        signature,
        &signed_data,
        &public_key,
        decoded.signature_algorithm(),
        &context,
    )
    .unwrap();
    signed_data.push(b'!');
    assert!(validate_signature(
        signature,
        &signed_data,
        &public_key,
        decoded.signature_algorithm(),
        &context,
    )
    .is_err());
}

/// Build the exact malformed attribute through the current DER/CMS APIs,
/// sign it and keep a complete PDF envelope.
fn sign_multivalued_signer_attributes() -> Vec<u8> {
    use sigis_pades_sign::cms::{AttrProfile, CmsSigner, CmsSignerOptions};

    let signer = support::pki("testing-ca").signer("signer1");
    let tbs = sigis_pades_sign::PdfSigner::new(
        sigis_pades_sign::PdfSignatureMetadata::new("Sig1"),
        std::sync::Arc::new(signer.clone()),
    )
    .at(support::at(VALIDATION_TIME))
    .digest_doc_for_signing(&support::pdf("minimal.pdf"), &Default::default())
    .unwrap();
    let options = CmsSignerOptions::default();
    let cms_signer = CmsSigner {
        signer: &signer,
        options: &options,
    };
    let mut attrs = cms_signer
        .signed_attrs(
            &tbs.prepared.document_digest,
            tbs.md_algorithm,
            &Default::default(),
            AttrProfile::Cades { is_pades: true },
            sigis_pades_sign::attributes::ID_DATA,
            None,
            false,
        )
        .unwrap();
    let value = Any::encode_from(&sample_signer_attributes()).unwrap();
    let mut values = der::asn1::SetOfVec::new();
    values.insert(value.clone()).unwrap();
    values.insert(value).unwrap();
    attrs.push(x509_cert::attr::Attribute {
        oid: SIGNER_ATTRIBUTES_V2,
        values,
    });
    let malicious = cms_signer
        .sign_prescribed_attributes(
            tbs.md_algorithm,
            attrs,
            cms::content_info::CmsVersion::V1,
            None,
            false,
            None,
        )
        .unwrap();
    sigis_pades_sign::pdf::signer::PdfTbsDocument::finish_signing(
        tbs.prepared,
        &malicious,
        None,
        None,
    )
    .unwrap()
}

fn validation_context() -> sigis_pki_certvalidator::ValidationContext {
    let pki = support::pki("testing-ca");
    sigis_pki_certvalidator::ValidationContext::builder()
        .trust_root(pki.cert("root"))
        .other_cert(pki.cert("interm"))
        .moment(support::at(VALIDATION_TIME))
        .build()
        .unwrap()
}

/// Exact upstream function: pyhanko/test_pades.py::test_cades_signer_attrs_multivalued.
#[test]
fn test_cades_signer_attrs_multivalued() {
    let output = sign_multivalued_signer_attributes();
    let file = sigis_pdf::PdfFile::parse(&output).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    let signature = &signatures[0];
    let sd = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
    assert!(sd.attribute_certificates.is_empty());
    let attr = sd.signer_infos[0]
        .signed_attr_list()
        .unwrap()
        .iter()
        .find(|attr| attr.oid.is(&SIGNER_ATTRIBUTES_V2))
        .unwrap();
    assert_eq!(attr.values.len(), 2);
    assert_eq!(attr.values[0], attr.values[1]);
    let ctx = validation_context();
    let digest = DigestAlgorithm::Sha256.digest(&signature.signed_data(&file).unwrap());
    let signer = support::pki("testing-ca").cert("signer1");
    assert_eq!(
        sigis_cms::validate::validate_sig_integrity(
            &sd.signer_infos[0],
            &signer,
            &sd.econtent_type,
            &digest,
        )
        .unwrap(),
        (true, true),
        "the rejection must concern the duplicate values in an otherwise intact signature"
    );
    for pass_ac_vc in [true, false] {
        // The PDF facade currently has no AC-context parameter. Its complete
        // PDF path and the CMS option-bearing entry point must both reject.
        let error = sigis_pades::validate_pdf_signature(&file, signature, &ctx, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Expected single"), "{error}");
        let options = sigis_cms::CmsValidationOptions {
            ac_validation_context: pass_ac_vc.then_some(&ctx),
            ..Default::default()
        };
        let signed_data = signature.signed_data(&file).unwrap();
        let error = sigis_cms::validate_cms_signature_with(
            &signature.contents,
            sigis_cms::SignedContent::Data(&signed_data),
            &ctx,
            &options,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("Expected single"), "{pass_ac_vc}: {error}");
        let root = support::pki("testing-ca").cert_path("root");
        let mut extra = vec!["--live", "testing-ca"];
        if pass_ac_vc {
            extra.push("--ac-vc");
        }
        let verdicts =
            support::pdfcheck::oracle_verdicts(&output, &[&root], VALIDATION_TIME, &extra)
                .expect("the pinned pyHanko oracle is required for this exact port");
        let error = verdicts[0]["error"].as_str().unwrap();
        assert!(error.contains("SignatureValidationError"), "{error}");
        assert!(error.contains("Expected single"), "{error}");
        eprintln!("live oracle multivalued pass_ac_vc={pass_ac_vc}: {error}");
    }
}

/// Exact upstream function: pyhanko/test_signing.py::test_sign_reject_econtent_if_detached.
#[test]
fn test_sign_reject_econtent_if_detached() {
    let input = support::pdf("pdf-sig-with-econtent.pdf");
    let file = sigis_pdf::PdfFile::parse(&input).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    let signature = &signatures[0];
    let sd = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
    assert!(sd.econtent.is_some());
    let error = sigis_pades::validate_pdf_signature(&file, signature, &validation_context(), None)
        .unwrap_err()
        .to_string();
    assert!(error.contains("detached"), "{error}");
    assert!(error.contains("encapsulated"), "{error}");
    let verdicts = support::pdfcheck::oracle_verdicts(&input, &[], VALIDATION_TIME, &[])
        .expect("the pinned pyHanko oracle is required for this exact port");
    let error = verdicts[0]["error"].as_str().unwrap();
    assert!(error.contains("SignatureValidationError"), "{error}");
    assert!(error.contains("detached"), "{error}");
    assert!(error.contains("encapsulated"), "{error}");
    eprintln!("live oracle detached econtent: {error}");
}
