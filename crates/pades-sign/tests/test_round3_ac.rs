//! Exact assertion ports of the seven AC presign/DSS cases in pyHanko 0.38.1.
//! Rust signs and performs AC presign checks; the pinned Python validator
//! executes original status assertions against each newly generated Rust PDF.
//! Python status assertions do not establish Rust validation-status parity.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use der::{Decode, Encode};

use sigis_pades_sign::attributes::{
    commitment_indication, GenericCommitment, SignerAttributesV2, ID_DATA, ID_SIGNED_DATA,
    SIGNER_ATTRIBUTES_V2,
};
use sigis_pades_sign::ltv::{validate_and_collect_attribute_certs, ValidationInfo};
use sigis_pades_sign::pdf::signer::{DssContentSettings, SigDssPlacement, SignOptions};
use sigis_pades_sign::{CadesSignedAttrSpec, PdfSignatureMetadata, PdfSigner, SignerAttrSpec};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext};
use sigis_pki_core::asn1::{
    oids,
    tlv::{self, tag, Tlv},
};
use sigis_pki_core::cert::Cert;
use support::pdfcheck::{cms_bytes, dss_counts, embedded_signatures, FoundSig};
use support::services::Services;
use support::*;

const T: &str = "2020-11-01T00:00:00+00:00";
const ARCH: &str = "testing-ca-with-aa";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(data_path(&["lanes", "r3-p", "ac", name])).unwrap()
}

fn authorities() -> Vec<sigis_pki_core::cert::Cert> {
    let p = pki(ARCH);
    ["root", "interm", "root-aa", "interm-aa", "leaf-aa"]
        .iter()
        .map(|name| p.cert(name))
        .collect()
}

fn context(ac: bool) -> ValidationContext {
    let p = pki(ARCH);
    let services = Services::new(&[ARCH], T);
    let fetchers = if ac {
        services.fetchers_with_ac_ocsp(
            fixture("alice-role-with-rev.der"),
            p.cert("leaf-aa"),
            fixture("ocsp-alice-role-with-rev.der"),
        )
    } else {
        services.fetchers()
    };
    let mut builder = ValidationContext::builder()
        .trust_root(p.cert(if ac { "root-aa" } else { "root" }))
        .moment(at(T))
        .revocation_mode("require")
        .fetchers(fetchers);
    for cert in authorities() {
        builder = builder.other_cert(cert);
    }
    if ac {
        // Keep the same explicit raw fixture for DSS collection. Configured
        // fetching now also supplies it through the bound AC method above;
        // native validation still authenticates it under this caller policy.
        builder = builder.ocsp_response(fixture("ocsp-alice-role-with-rev.der"));
    }
    builder.build().unwrap()
}

/// Verify the original CMS without forcing its certificate choices through the
/// CMS crate's X.509-only enum. In particular, retain every [2] AC in place.
fn check_ac_integrity(pdf: &[u8], signature: &FoundSig, embedded_ac: bool) -> Cert {
    let range = &signature.byte_range;
    assert_eq!(range.len(), 4, "ByteRange");
    assert_eq!(range[0], 0);
    let gap_start = usize::try_from(range[1]).unwrap();
    let gap_end = usize::try_from(range[2]).unwrap();
    let suffix_len = usize::try_from(range[3]).unwrap();
    let revision_end = gap_end.checked_add(suffix_len).unwrap();
    assert!(gap_start < gap_end && revision_end <= pdf.len());
    assert_eq!(pdf[gap_start], b'<');
    assert_eq!(pdf[gap_end - 1], b'>');
    let mut signed_bytes = pdf[..gap_start].to_vec();
    signed_bytes.extend_from_slice(&pdf[gap_end..revision_end]);

    let encoded = cms_bytes(signature);
    let content_info = Tlv::parse_exact(&encoded).unwrap().children().unwrap();
    assert_eq!(
        const_oid::ObjectIdentifier::from_der(content_info[0].raw).unwrap(),
        ID_SIGNED_DATA
    );
    assert!(content_info[1].is_context(0));
    let signed_data = Tlv::parse_exact(content_info[1].value).unwrap();
    let fields = signed_data.children().unwrap();
    let encapsulated = cms::signed_data::EncapsulatedContentInfo::from_der(fields[2].raw).unwrap();
    assert_eq!(encapsulated.econtent_type, ID_DATA);
    assert!(
        encapsulated.econtent.is_none(),
        "PDF signatures are detached"
    );
    let certificates = fields.iter().find(|field| field.is_context(0)).unwrap();
    let mut public_key_certs = Vec::new();
    let mut attribute_certs = Vec::new();
    for certificate in certificates.children().unwrap() {
        if certificate.is_universal(tag::SEQUENCE) {
            public_key_certs.push(Cert::from_der(certificate.raw).unwrap());
        } else if certificate.is_context(2) {
            // v2AttrCert [2] is IMPLICIT: restore only its outer SEQUENCE tag
            // for exact fixture comparison, without modifying the CMS input.
            attribute_certs.push(tlv::retag(&certificate, 0x30));
        } else {
            panic!("unexpected certificate choice in this AC fixture");
        }
    }
    assert_eq!(attribute_certs.len(), usize::from(embedded_ac));
    if embedded_ac {
        assert_eq!(attribute_certs[0], fixture("alice-role-with-rev.der"));
    }

    let signer_infos = fields.last().unwrap();
    assert!(signer_infos.is_universal(tag::SET));
    let signer_infos = signer_infos.children().unwrap();
    assert_eq!(signer_infos.len(), 1);
    let signer_info = cms::signed_data::SignerInfo::from_der(signer_infos[0].raw).unwrap();
    let cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(identity) = &signer_info.sid
    else {
        panic!("the exact fixture uses issuer and serial number")
    };
    let signer = public_key_certs
        .into_iter()
        .find(|cert| {
            cert.issuer() == &identity.issuer
                && cert.serial_bytes() == identity.serial_number.as_bytes()
        })
        .expect("the signer certificate must remain embedded");
    let md = DigestAlgorithm::from_oid(&signer_info.digest_alg.oid).unwrap();
    let attrs = signer_info.signed_attrs.as_ref().unwrap();
    let digest = attrs
        .iter()
        .find(|attr| attr.oid == oids::MESSAGE_DIGEST)
        .unwrap();
    assert_eq!(digest.values.len(), 1);
    let digest = digest
        .values
        .iter()
        .next()
        .unwrap()
        .decode_as::<der::asn1::OctetString>()
        .unwrap();
    assert_eq!(
        digest.as_bytes(),
        md.digest(&signed_bytes),
        "document digest"
    );

    let raw_signer_fields = signer_infos[0].children().unwrap();
    let raw_attrs = raw_signer_fields
        .iter()
        .find(|field| field.is_context(0))
        .unwrap();
    let raw_signed_attrs = tlv::retag(raw_attrs, 0x31);
    assert_eq!(attrs.to_der().unwrap(), raw_signed_attrs);
    validate_signature(
        signer_info.signature.as_bytes(),
        &raw_signed_attrs,
        &signer.public_key(),
        &signer_info.signature_algorithm,
        &SignatureValidationContext {
            contextual_digest: Some(md),
            prehashed: false,
        },
    )
    .expect("the original CMS signature must verify without exclusions");

    let signer_attrs = attrs.iter().find(|attr| attr.oid == SIGNER_ATTRIBUTES_V2);
    if embedded_ac {
        assert!(signer_attrs.is_none());
    } else {
        let signer_attrs = signer_attrs.unwrap();
        assert_eq!(signer_attrs.values.len(), 1);
        let value = signer_attrs
            .values
            .iter()
            .next()
            .unwrap()
            .decode_as::<SignerAttributesV2>()
            .unwrap();
        let certified = value.certified_attributes_v2.unwrap();
        assert_eq!(certified.len(), 1);
        let choice = certified[0].to_der().unwrap();
        let choice = Tlv::parse_exact(&choice).unwrap();
        assert!(choice.is_context(0));
        assert_eq!(choice.value, fixture("alice-role-with-rev.der"));
    }
    signer
}

fn sign_case(name: &str) -> Vec<u8> {
    let live = name.contains("live_ac_presign_validation");
    let lta = name == "test_pades_lta_live_ac_presign_validation";
    let autofill = name == "test_cades_signer_attrs_autofill_dss";
    let no_claimed = name == "test_cades_signer_attrs_validate_acs_no_claimed";
    let p = pki(ARCH);
    let signer = sigis_pades_sign::SimpleSigner::new(
        p.key(&p.key_label_of("signer1")),
        p.cert("signer1"),
        if autofill { Vec::new() } else { authorities() },
    )
    .unwrap();
    let mut metadata = PdfSignatureMetadata::new(if live { "" } else { "Sig1" });
    metadata.validation_context = Some(Arc::new(context(false)));
    metadata.ac_validation_context = Some(Arc::new(context(true)));
    metadata.embed_validation_info = true;
    metadata.use_pades_lta = lta;
    if live && !lta {
        metadata.dss_settings = DssContentSettings {
            include_vri: false,
            placement: SigDssPlacement::TogetherWithSignature,
            ..Default::default()
        };
    }
    if !live {
        metadata.cades_signed_attr_spec = Some(CadesSignedAttrSpec {
            commitment_type: (!no_claimed)
                .then(|| commitment_indication(GenericCommitment::ProofOfApproval)),
            signer_attributes: Some(SignerAttrSpec {
                claimed_attrs: if no_claimed {
                    Vec::new()
                } else {
                    vec![fixture("claimed-group.der")]
                },
                certified_attrs: vec![fixture("alice-role-with-rev.der")],
            }),
            ..Default::default()
        });
    }
    let mut pdf_signer = PdfSigner::new(metadata, Arc::new(signer)).at(at(T));
    if live {
        pdf_signer.cms_options.attribute_certs = vec![fixture("alice-role-with-rev.der")];
        // Match upstream's TSA registry: only the PKI root is embedded.
        let ts = sigis_pades_sign::DummyTimeStamper::new(
            p.cert("tsa"),
            p.key(&p.key_label_of("tsa")),
            vec![p.cert("root")],
        )
        .with_fixed_time(at(T));
        pdf_signer = pdf_signer.with_timestamper(Arc::new(ts));
    }
    let base = pdf(if live {
        "minimal-with-field.pdf"
    } else {
        "minimal.pdf"
    });
    let out = pdf_signer
        .sign_pdf_with(
            &base,
            &SignOptions {
                existing_fields_only: live,
                ..Default::default()
            },
        )
        .unwrap();
    check_ac_integrity(&out, &embedded_signatures(&out)[0], live);
    if live && !lta {
        let (certs, ocsps, crls, _) = dss_counts(&out).unwrap();
        assert_eq!(certs, 8);
        assert_eq!(ocsps, 2);
        assert_eq!(crls, 3);
    } else if autofill {
        assert_eq!(dss_counts(&out).unwrap().0, 7);
    }
    out
}

fn exact_upstream_assertions(name: &str, backend: &str) {
    let out = sign_case(name);
    let output = temp_file(&format!("{name}-{backend}.pdf"), &out);
    let python = oracle_python().expect("these exact AC status ports require the pinned oracle");
    let script = data_path(&["lanes", "r3-p", "ac", "ac_assertions.py"]);
    let result = std::process::Command::new(python)
        .arg("-I")
        .arg(script)
        .arg(name)
        .arg(output)
        .arg(backend)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{name}/{backend}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("PASS exact upstream assertions"),
        "oracle did not finish the exact assertion tail"
    );
}

#[test]
fn opaque_ac_cms_check_rejects_document_and_attribute_certificate_tampering() {
    let original = sign_case("test_pades_live_ac_presign_validation");
    let signature = embedded_signatures(&original).remove(0);
    let mut changed_document = original.clone();
    // Retain the parsed signature: a change to the signed PDF bytes must fail
    // the real message-digest assertion independently of CMS certificate APIs.
    changed_document[0] ^= 1;
    assert!(std::panic::catch_unwind(|| {
        check_ac_integrity(&changed_document, &signature, true);
    })
    .is_err());

    let ac = fixture("alice-role-with-rev.der");
    let implicit_ac = tlv::retag(&Tlv::parse_exact(&ac).unwrap(), 0xa2);
    let cms = cms_bytes(&signature);
    let ac_start = cms
        .windows(implicit_ac.len())
        .position(|part| part == implicit_ac)
        .unwrap();
    let altered_byte = ac_start + implicit_ac.len() - 1;
    let mut changed_ac = original;
    let hex_offset = usize::try_from(signature.byte_range[1]).unwrap() + 1 + 2 * altered_byte;
    assert!(changed_ac[hex_offset].is_ascii_hexdigit());
    changed_ac[hex_offset] = if changed_ac[hex_offset] == b'0' {
        b'1'
    } else {
        b'0'
    };
    // CertificateSet bytes are outside the document digest and CMS signature.
    // The local helper must still retain and compare the complete raw AC.
    let altered_signature = embedded_signatures(&changed_ac).remove(0);
    assert!(std::panic::catch_unwind(|| {
        check_ac_integrity(&changed_ac, &altered_signature, true);
    })
    .is_err());
}

#[test]
fn test_pades_live_ac_presign_validation() {
    for backend in ["requests", "aiohttp"] {
        exact_upstream_assertions("test_pades_live_ac_presign_validation", backend);
    }
}

#[test]
fn test_pades_lta_live_ac_presign_validation() {
    for backend in ["requests", "aiohttp"] {
        exact_upstream_assertions("test_pades_lta_live_ac_presign_validation", backend);
    }
}

#[test]
fn test_cades_signer_attrs_autofill_dss() {
    exact_upstream_assertions("test_cades_signer_attrs_autofill_dss", "requests");
}

#[test]
fn test_cades_signer_attrs_validate_acs() {
    exact_upstream_assertions("test_cades_signer_attrs_validate_acs", "requests");
}

#[test]
fn test_cades_signer_attrs_validate_acs_no_claimed() {
    exact_upstream_assertions(
        "test_cades_signer_attrs_validate_acs_no_claimed",
        "requests",
    );
}

#[test]
fn test_cades_signer_attrs_validate_acs_wrong_vc() {
    exact_upstream_assertions("test_cades_signer_attrs_validate_acs_wrong_vc", "requests");
}

#[test]
fn test_cades_signer_attrs_validate_acs_missing_vc() {
    exact_upstream_assertions(
        "test_cades_signer_attrs_validate_acs_missing_vc",
        "requests",
    );
}

#[test]
fn ac_presign_validation_rejects_wrong_authority_and_holder() {
    let ac = fixture("alice-role-with-rev.der");
    let p = pki(ARCH);
    let mut info = ValidationInfo::default();
    let results = validate_and_collect_attribute_certs(
        &context(true),
        &p.cert("signer1"),
        &authorities(),
        std::slice::from_ref(&ac),
        &mut info,
    )
    .unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].approved_attributes.contains_key("role"));
    assert_eq!(info.paths.len(), 1);
    assert_eq!(info.ocsps.len(), 1);
    assert_eq!(info.crls.len(), 2);
    for (ctx, holder) in [
        (context(false), p.cert("signer1")),
        (context(true), p.cert("signer2")),
    ] {
        let mut rejected_info = ValidationInfo::default();
        assert!(validate_and_collect_attribute_certs(
            &ctx,
            &holder,
            &authorities(),
            std::slice::from_ref(&ac),
            &mut rejected_info,
        )
        .is_err());
        assert!(rejected_info.paths.is_empty());
        assert!(rejected_info.ocsps.is_empty());
        assert!(rejected_info.crls.is_empty());
    }
}

#[test]
fn ac_presign_validation_preserves_algorithm_policy() {
    let p = pki(ARCH);
    let mut builder = ValidationContext::builder()
        .trust_root(p.cert("root-aa"))
        .moment(at(T))
        .revocation_mode("require")
        .fetchers(Services::new(&[ARCH], T).fetchers())
        .ocsp_response(fixture("ocsp-alice-role-with-rev.der"))
        .algorithm_policy(Arc::new(
            sigis_pki_core::algorithms::DisallowWeakAlgorithmsPolicy::with_weak_hash_algos(&[
                "sha256",
            ]),
        ));
    for cert in authorities() {
        builder = builder.other_cert(cert);
    }
    let mut info = ValidationInfo::default();
    assert!(validate_and_collect_attribute_certs(
        &builder.build().unwrap(),
        &p.cert("signer1"),
        &authorities(),
        &[fixture("alice-role-with-rev.der")],
        &mut info,
    )
    .is_err());
    assert!(info.paths.is_empty());
}

#[test]
fn ac_presign_validation_requires_ac_revocation_evidence() {
    let p = pki(ARCH);
    let mut builder = ValidationContext::builder()
        .trust_root(p.cert("root-aa"))
        .moment(at(T))
        .revocation_mode("require")
        .fetchers(Services::new(&[ARCH], T).fetchers());
    for cert in authorities() {
        builder = builder.other_cert(cert);
    }
    let mut info = ValidationInfo::default();
    assert!(validate_and_collect_attribute_certs(
        &builder.build().unwrap(),
        &p.cert("signer1"),
        &authorities(),
        &[fixture("alice-role-with-rev.der")],
        &mut info,
    )
    .is_err());
    assert!(info.paths.is_empty());
    assert!(info.ocsps.is_empty());
    assert!(info.crls.is_empty());
}
