//! CMS framing regressions: zero-valued DER bytes belong to the signature.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cms::{
    content_info::ContentInfo,
    signed_data::{SignedData, SignerInfos},
};
use der::{
    asn1::{OctetString, SetOfVec},
    Any, Decode, Encode,
};
use lopdf::{dictionary, Document, Object};
use underskrift::{
    trust::{TrustStore, TrustStoreSet},
    verify::{extractor, report::CryptoValidity, SignatureVerifier},
    PdfSigner, SigningOptions, SoftwareSigner,
};
use x509_cert::attr::Attribute;

fn document(contents: &[u8]) -> Vec<u8> {
    let mut doc = Document::new();
    let signature = doc.add_object(dictionary! {
        "ByteRange" => vec![Object::Integer(0), Object::Integer(10), Object::Integer(20), Object::Integer(30)],
        "Contents" => Object::String(contents.to_vec(), lopdf::StringFormat::Hexadecimal),
        "SubFilter" => "ETSI.CAdES.detached",
    });
    let field = doc.add_object(
        dictionary! {"FT" => "Sig", "T" => Object::string_literal("Sig1"), "V" => signature},
    );
    let form = doc.add_object(dictionary! {"Fields" => vec![Object::Reference(field)]});
    let catalog = doc.add_object(dictionary! {"Type" => "Catalog", "AcroForm" => form});
    doc.trailer.set("Root", catalog);
    let mut pdf = Vec::new();
    doc.save_to(&mut pdf).unwrap();
    pdf
}

#[test]
fn extraction_keeps_zero_inside_short_and_long_der_sequences() {
    let short = vec![0x30, 0x03, 0x04, 0x01, 0x00];
    let mut long = vec![0x30, 0x81, 0x80, 0x04, 0x7e];
    long.extend([0; 126]);
    for der in [short, long] {
        for padding in [0, 32] {
            let mut contents = der.clone();
            contents.extend(vec![0; padding]);
            let doc = document(&contents);
            assert_eq!(
                extractor::extract_signatures(&doc).unwrap()[0].cms_bytes,
                der
            );
        }
    }
}

#[test]
fn invalid_or_nonzero_trailing_contents_are_not_hidden_as_padding() {
    for contents in [
        vec![0x30, 0x05, 0x04, 0x01, 0x00], // Truncated outer sequence.
        vec![0x30, 0x80, 0x00, 0x00],       // Indefinite length is not DER.
        vec![0x30, 0x03, 0x04, 0x01, 0x00, 0x01, 0x00], // Nonzero suffix.
    ] {
        let doc = document(&contents);
        let extracted = extractor::extract_signatures(&doc).unwrap();
        assert_eq!(extracted[0].cms_bytes, contents);
        assert!(ContentInfo::from_der(&extracted[0].cms_bytes).is_err());
    }
    let placeholder = document(&[0; 32]);
    assert!(extractor::extract_signatures(&placeholder)
        .unwrap()
        .is_empty());
}

fn signer() -> (SoftwareSigner, Vec<u8>) {
    use openssl::{
        asn1::{Asn1Integer, Asn1Time},
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{
            extension::{BasicConstraints, KeyUsage},
            X509NameBuilder, X509,
        },
    };
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "CMS zero-byte regression")
        .unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    cert.set_not_before(&Asn1Time::from_unix(now - 60).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::from_unix(now + 86400).unwrap())
        .unwrap();
    cert.append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap(),
    )
    .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = cert.build().to_der().unwrap();
    let signer =
        SoftwareSigner::from_rsa_der(&key.private_key_to_pkcs8().unwrap(), vec![cert.clone()])
            .unwrap();
    (signer, cert)
}

#[tokio::test]
async fn real_signed_pdf_with_zero_terminated_cms_remains_trusted() {
    let (signer, certificate) = signer();
    let input = std::fs::read(sigis_testdata::pyhanko(&["pdf", "minimal.pdf"])).unwrap();
    let mut output = PdfSigner::new()
        .options(SigningOptions {
            content_size: 16 * 1024,
            ..Default::default()
        })
        .sign(&input, &signer)
        .await
        .unwrap();
    let extracted = extractor::extract_signatures(&output).unwrap();
    let original = &extracted[0];
    let content = ContentInfo::from_der(&original.cms_bytes).unwrap();
    let mut signed_data = SignedData::from_der(&content.content.to_der().unwrap()).unwrap();
    let mut infos = signed_data.signer_infos.0.into_vec();
    // An unknown unsigned attribute does not change the signed attributes or
    // PDF digest. Its zero-valued payload makes the complete CMS end in zero.
    infos[0].unsigned_attrs = Some(
        SetOfVec::try_from(vec![Attribute {
            oid: const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5"),
            values: SetOfVec::try_from(vec![Any::encode_from(
                &OctetString::new(vec![0; 4096]).unwrap(),
            )
            .unwrap()])
            .unwrap(),
        }])
        .unwrap(),
    );
    signed_data.signer_infos = SignerInfos(SetOfVec::try_from(infos).unwrap());
    let cms = ContentInfo {
        content_type: content.content_type,
        content: Any::encode_from(&signed_data).unwrap(),
    }
    .to_der()
    .unwrap();
    assert_eq!(cms.last(), Some(&0));
    let range = original.byte_range;
    let region = &mut output[range[1] + 1..range[2] - 1];
    assert!(cms.len() * 2 <= region.len());
    region.fill(b'0');
    for (pair, byte) in region.as_chunks_mut::<2>().0.iter_mut().zip(&cms) {
        let digits = b"0123456789ABCDEF";
        pair[0] = digits[(byte >> 4) as usize];
        pair[1] = digits[(byte & 15) as usize];
    }
    let mut roots = TrustStore::new();
    roots.add_der_certificate(&certificate).unwrap();
    let stores = TrustStoreSet::new().with_sig_store(roots);
    let verifier = SignatureVerifier::new(&stores);
    let report = verifier.verify_pdf(&output).unwrap();
    let signature = &report.signatures[0];
    assert_eq!(
        signature.cryptographic_validity,
        CryptoValidity::Valid,
        "{signature:?}"
    );
    assert!(
        signature.digest_matches && signature.integrity_ok && signature.chain_trusted,
        "{signature:?}"
    );
    assert_eq!(
        extractor::extract_signatures(&output).unwrap()[0].cms_bytes,
        cms
    );
    // Alter a signed byte without changing the PDF syntax or reserved region.
    assert_eq!(&output[..5], b"%PDF-");
    output[7] = if output[7] == b'7' { b'6' } else { b'7' };
    let changed = verifier.verify_pdf(&output).unwrap();
    assert!(!changed.signatures[0].digest_matches);
}
