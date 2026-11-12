//! Supplemental AC recording transport identity guards; no upstream ID credit.
mod common;
use common::*;
use sigis_pki_core::asn1::tlv::{encode, Tlv};
use sigis_pki_core::fetch::OcspFetcher;

#[test]
fn recorded_ac_retrieval_keeps_target_serial_and_authority_binding() {
    let rec = Recording::load("test_ades_validation");
    for provider in ["aiohttp", "requests"] {
        let id = format!("test_pades_lta_live_ac_validation[{provider}]");
        let call = rec
            .calls("test_ades_validation", &id)
            .into_iter()
            .find(|call| call.function() == "ades_lta_validation")
            .unwrap();
        let (bytes, name) = call.pdf();
        let file = sigis_pdf::PdfFile::parse(&bytes).unwrap();
        let signature = file
            .embedded_signatures()
            .unwrap()
            .into_iter()
            .find(|signature| signature.field_name == name)
            .unwrap();
        let signed = sigis_cms::SignedData::from_der(&signature.contents).unwrap();
        assert_eq!(signed.attribute_certificates.len(), 1);
        let ac = &signed.attribute_certificates[0];
        let aa = rec.cert("testing-ca-with-aa", "leaf-aa");
        let http = &call.0["case_http"];
        let expected = http
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| {
                entry["method"] == "POST"
                    && entry["path"] == "/testing-ca-with-aa/ocsp/leaf-aa"
                    && entry["status"] == 200
            })
            .unwrap();
        let replay = Replay::new(http);
        let response = replay.fetch_ac_ocsp(ac, &aa).unwrap();
        assert_eq!(response, b64(expected["response_body"].as_str().unwrap()));

        // Retrieval-only metadata mutation, never signature/trust evidence.
        let fields = |der: &[u8]| {
            Tlv::parse_exact(der)
                .unwrap()
                .children()
                .unwrap()
                .iter()
                .map(|part| part.raw.to_vec())
                .collect::<Vec<_>>()
        };
        let mut envelope = fields(ac);
        let mut info = fields(&envelope[0]);
        let wrong_serial = encode(0x02, &[0x7f]);
        assert_ne!(info[4], wrong_serial);
        info[4] = wrong_serial;
        envelope[0] = encode(0x30, &info.concat());
        let wrong_ac = encode(0x30, &envelope.concat());
        assert!(replay.fetch_ac_ocsp(&wrong_ac, &aa).is_err());
        let other_authority = rec.cert("testing-ca-with-aa", "root-aa");
        assert_ne!(aa.public_key(), other_authority.public_key());
        assert!(replay.fetch_ac_ocsp(ac, &other_authority).is_err());
    }
}
