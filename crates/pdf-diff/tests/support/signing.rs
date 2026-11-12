// Derived from pyHanko test_diff_analysis.py (v0.38.1, MIT).
//! Signing-only cases that became runnable after lane D integration.

use std::sync::Arc;

use lopdf::Object;
use sigis_pades_sign::{PdfSignatureMetadata, PdfSigner, SigFieldSpec, SignOptions, SimpleSigner};
use sigis_pki_certvalidator::ValidationContext;
use sigis_pki_core::{cert::Cert, time::Moment};

const TIME: &str = "2020-11-01T00:00:00Z";
const GROUPS: &[&str] = &[
    "minimal-with-textfield-group.pdf",
    "minimal-with-textfield-group-var.pdf",
];

fn cert(label: &str) -> Cert {
    Cert::from_der(&sigis_testdata::read(&[
        "lanes",
        "d",
        "pki",
        "testing-ca",
        &format!("{label}.crt"),
    ]))
    .unwrap()
}

fn signer() -> PdfSigner {
    let key = sigis_pades_sign::keys::load_private_key_from_pemder_data(
        &sigis_testdata::read(&["pyhanko", "crypto", "keys-rsa", "signer.key.pem"]),
        Some(b"secret"),
    )
    .unwrap();
    let signer =
        SimpleSigner::new(key, cert("signer1"), vec![cert("interm"), cert("root")]).unwrap();
    PdfSigner::new(PdfSignatureMetadata::new(""), Arc::new(signer))
        .at(Moment::parse_rfc3339(TIME).unwrap())
}

fn input(name: &str) -> Vec<u8> {
    sigis_testdata::read(&["pyhanko", "pdf", name])
}

fn validate(bytes: &[u8], field: &str) {
    let file = sigis_pdf::PdfFile::parse(bytes).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0].field_name, field);
    let ctx = ValidationContext::builder()
        .trust_root(cert("root"))
        .moment(Moment::parse_rfc3339(TIME).unwrap())
        .revocation_mode("soft-fail")
        .build()
        .unwrap();
    let status = sigis_pades::validate_pdf_signature(&file, &signatures[0], &ctx, None).unwrap();
    assert!(status.bottom_line(), "{status:?}");

    let dir = tempfile::tempdir().unwrap();
    let pdf = dir.path().join("signed.pdf");
    std::fs::write(&pdf, bytes).unwrap();
    let root = sigis_testdata::path(&["lanes", "d", "pki", "testing-ca", "root.crt"]);
    let script = sigis_testdata::manifest_dir().join("../pades-sign/oracle/validate_pdf.py");
    if let Some(verdicts) = sigis_testdata::oracle::run_json(
        &script,
        &[
            "--pdf",
            pdf.to_str().unwrap(),
            "--trust",
            root.to_str().unwrap(),
            "--time",
            TIME,
        ],
    ) {
        assert_eq!(verdicts[0]["bottom_line"], true, "{verdicts}");
    }
}

pub fn create_deep_fields(multiple: bool) {
    let name = if multiple {
        "TextInput.Sigs.Blah.NewSig"
    } else {
        "TextInput.NewSig"
    };
    let mut inputs = GROUPS.to_vec();
    if multiple {
        inputs.push("minimal.pdf");
    }
    for source in inputs {
        let mut signing = signer();
        signing.metadata.field_name = name.into();
        validate(&signing.sign_pdf(&input(source)).unwrap(), name);
    }
}

pub fn reject_non_signature_fields() {
    for source in GROUPS {
        for existing_fields_only in [true, false] {
            let mut signing = signer();
            signing.metadata.field_name = "TextInput.TextField1".into();
            let error = signing
                .sign_pdf_with(
                    &input(source),
                    &SignOptions {
                        existing_fields_only,
                        ..Default::default()
                    },
                )
                .unwrap_err();
            assert!(error.to_string().contains("not a Sig field"), "{error}");
        }
    }
}

pub fn separate_annotation() {
    let mut signing = signer();
    signing.metadata.field_name = "Sig1".into();
    let mut spec = SigFieldSpec::new("Sig1").with_box((20.0, 20.0, 80.0, 40.0));
    spec.combine_annotation = false;
    let out = signing
        .with_field_spec(spec)
        .sign_pdf(&input("minimal.pdf"))
        .unwrap();
    validate(&out, "Sig1");
    let file = sigis_pdf::PdfFile::parse(&out).unwrap();
    let signatures = file.embedded_signatures().unwrap();
    let doc = lopdf::Document::load_mem(&out).unwrap();
    let field = doc.get_dictionary(signatures[0].field_object).unwrap();
    assert!(field.get(b"AP").is_err());
    let kid = field.get(b"Kids").unwrap().as_array().unwrap()[0]
        .as_reference()
        .unwrap();
    assert!(matches!(
        doc.get_dictionary(kid).unwrap().get(b"AP"),
        Ok(Object::Dictionary(_))
    ));
}
