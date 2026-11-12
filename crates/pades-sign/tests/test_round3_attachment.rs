//! Port of pyHanko 0.38.1 `test_signing.py::test_embed_signed_attachment`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use lopdf::Object;
use sigis_pades_sign::attributes::CmsSignedAttributes;
use sigis_pades_sign::cms::{decode_signed_data, CmsSigner, CmsSignerOptions};
use sigis_pades_sign::pdf::attachment::{embed_payload_with_cms, SignedAttachmentOptions};
use sigis_pdf::decode_limits::DecodePurpose;
use sigis_pdf::embed::{embedded_file_object, EmbeddedFileParams};
use sigis_pdf::generic::{decode_text, parse_pdf_date};
use sigis_pdf::{IncrementalWriter, PdfFile, PdfHandler, PdfHandlerExt};
use sigis_pki_core::algorithms::DigestAlgorithm;
use sigis_pki_core::asn1::oids;
use support::*;

fn text(object: &Object) -> String {
    decode_text(object.as_str().unwrap()).unwrap()
}

#[test]
fn test_embed_signed_attachment() {
    let dt = at("2020-11-01T05:00:00+00:00");
    let payload = pdf("scribble.pdf"); // Upstream VECTOR_IMAGE_PDF.
    let p = pki("testing-ca");
    let signer = p.signer("signer1"); // Upstream FROM_CA.
    let signature = CmsSigner {
        signer: &signer,
        options: &CmsSignerOptions::default(),
    }
    .sign_general_data(
        &payload,
        DigestAlgorithm::Sha256,
        true,
        false,
        None,
        &CmsSignedAttributes {
            signing_time: Some(dt),
            ..Default::default()
        },
    )
    .unwrap();

    // Check that the setup is the original detached SHA-256 signature at dt.
    let signed_data = decode_signed_data(&signature).unwrap();
    assert!(signed_data.encap_content_info.econtent.is_none());
    let signer_info = signed_data.signer_infos.0.iter().next().unwrap();
    assert_eq!(signer_info.digest_alg.oid, oids::SHA256);
    let signing_time = signer_info
        .signed_attrs
        .as_ref()
        .unwrap()
        .iter()
        .find(|attr| attr.oid == oids::SIGNING_TIME)
        .unwrap()
        .values
        .iter()
        .next()
        .unwrap()
        .decode_as::<x509_cert::time::Time>()
        .unwrap();
    assert_eq!(
        signing_time.to_unix_duration().as_secs(),
        u64::try_from(dt.unix_secs()).unwrap()
    );

    let base = pdf("minimal.pdf");
    let mut w = IncrementalWriter::try_new(PdfFile::parse(&base).unwrap()).unwrap();
    let pdf_dt = parse_pdf_date("D:20201101050000Z", true).unwrap();
    let payload_ref = embedded_file_object(
        &mut w,
        &payload,
        true,
        Some(&EmbeddedFileParams {
            creation_date: Some(pdf_dt),
            modification_date: Some(pdf_dt),
            ..Default::default()
        }),
        Some("application/pdf"),
    )
    .unwrap();
    embed_payload_with_cms(
        &mut w,
        "attachment.pdf",
        payload_ref,
        &signature,
        &SignedAttachmentOptions {
            file_name: Some("添付ファイル.pdf".into()),
            description: Some("Signed attachment test".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let out = w.write().unwrap();

    let r = PdfFile::parse(&out).unwrap();
    let root = r.root().unwrap();
    let names = r.get_dict(&root, b"Names").unwrap().unwrap();
    let embedded_files = r.get_dict(&names, b"EmbeddedFiles").unwrap().unwrap();
    let Object::Array(emb_lst) = r.get_required(&embedded_files, b"Names").unwrap() else {
        panic!("EmbeddedFiles/Names must be an array");
    };
    assert_eq!(emb_lst.len(), 4);
    assert_eq!(text(&emb_lst[0]), "attachment.pdf");
    let spec_obj = r.resolve(&emb_lst[1]).unwrap();
    let spec_obj = spec_obj.as_dict().unwrap();
    assert_eq!(text(spec_obj.get(b"UF").unwrap()), "添付ファイル.pdf");
    let ef = r.get_dict(spec_obj, b"EF").unwrap().unwrap();
    let stream = r.get_required(&ef, b"F").unwrap();
    assert_eq!(
        r.decode_stream(stream.as_stream().unwrap(), DecodePurpose::Generic)
            .unwrap(),
        payload
    );
    let rf = r.get_dict(spec_obj, b"RF").unwrap().unwrap();
    let related_f = r.get_required(&rf, b"F").unwrap();
    let related_f = related_f.as_array().unwrap();
    assert_eq!(text(&related_f[0]), "attachment.sig");
    let related_uf = r.get_required(&rf, b"UF").unwrap();
    let related_uf = related_uf.as_array().unwrap();
    assert_eq!(text(&related_uf[0]), "添付ファイル.sig");
    let rel_file_ref = related_f[1].as_reference().unwrap();

    assert_eq!(text(&emb_lst[2]), "attachment.sig");
    let spec_obj = r.resolve(&emb_lst[3]).unwrap();
    let spec_obj = spec_obj.as_dict().unwrap();
    assert_eq!(text(spec_obj.get(b"UF").unwrap()), "添付ファイル.sig");
    let ef = r.get_dict(spec_obj, b"EF").unwrap().unwrap();
    let cms_ref = ef.get(b"F").unwrap().as_reference().unwrap();
    let stream = r.get_required(&ef, b"F").unwrap();
    assert_eq!(
        r.decode_stream(stream.as_stream().unwrap(), DecodePurpose::Generic)
            .unwrap(),
        signature
    );
    assert_eq!(cms_ref, rel_file_ref);
    // Both related-file name variants must share the standalone CMS stream.
    assert_eq!(related_uf[1].as_reference().unwrap(), cms_ref);
    assert_eq!(ef.get(b"UF").unwrap().as_reference().unwrap(), cms_ref);

    // Repeat the original structural assertions with the pinned Python reader.
    {
        let py = oracle_python().expect("the pinned oracle is required for this exact port");
        let output_file = temp_file("signed-attachment.pdf", &out);
        let payload_file = temp_file("attachment-payload.pdf", &payload);
        let cms_file = temp_file("attachment.sig", &signature);
        let result = std::process::Command::new(py)
            .args(["-I", "-c", ATTACHMENT_ORACLE])
            .arg(output_file)
            .arg(payload_file)
            .arg(cms_file)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "attachment oracle failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        eprintln!("{}", String::from_utf8_lossy(&result.stdout));
    }
}

const ATTACHMENT_ORACLE: &str = r#"
import importlib.metadata
import sys
from datetime import datetime
from io import BytesIO
from pathlib import Path
from asn1crypto import cms
from pyhanko.pdf_utils.reader import PdfFileReader
assert importlib.metadata.version('pyhanko') == '0.38.1'
data, payload, signature = [Path(p).read_bytes() for p in sys.argv[1:]]
r = PdfFileReader(BytesIO(data))
emb_lst = r.root['/Names']['/EmbeddedFiles']['/Names']
assert len(emb_lst) == 4
assert emb_lst[0] == 'attachment.pdf'
spec_obj = emb_lst[1]
assert spec_obj['/UF'] == '添付ファイル.pdf'
stream = spec_obj['/EF']['/F']
assert stream.data == payload
assert spec_obj['/RF']['/F'][0] == 'attachment.sig'
assert spec_obj['/RF']['/UF'][0] == '添付ファイル.sig'
rel_file_ref = spec_obj['/RF']['/F'].raw_get(1).reference
assert spec_obj['/RF']['/UF'].raw_get(1).reference == rel_file_ref
assert emb_lst[2] == 'attachment.sig'
spec_obj = emb_lst[3]
assert spec_obj['/UF'] == '添付ファイル.sig'
stream = spec_obj['/EF']['/F']
assert stream.data == signature
assert stream.container_ref == rel_file_ref
sd = cms.ContentInfo.load(signature)['content']
assert sd['encap_content_info']['content'].native is None
si = sd['signer_infos'][0]
assert si['digest_algorithm']['algorithm'].native == 'sha256'
attrs = {a['type'].native: a['values'][0].native for a in si['signed_attrs']}
assert attrs['signing_time'] == datetime.fromisoformat('2020-11-01T05:00:00+00:00')
print('PASS signed attachment: exact upstream structure and CMS setup')
"#;
