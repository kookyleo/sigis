//! Genuine NoRevAvail exempts AC revocation only, never authentication.
//! Supplemental P collection controls; no unique upstream-function credit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::{Arc, Mutex};

use der::{Decode, Encode};
use sigis_pades_sign::ltv::{validate_and_collect_attribute_certs, ValidationInfo};
use sigis_pki_certvalidator::{ac::AttrCert, ValidationContext};
use sigis_pki_core::algorithms::{validate_signature, DigestAlgorithm, SignatureValidationContext};
use sigis_pki_core::asn1::tlv::{encode, Tlv};
use sigis_pki_core::cert::Cert;
use sigis_pki_core::errors::{FetchError, FetchErrorKind};
use sigis_pki_core::fetch::{CrlFetcher, Fetchers, OcspFetcher};
use sigis_pki_core::sign::KeySigner;

const ARCH: &str = "testing-ca-with-aa";
const TIME: &str = "2020-11-01T00:00:00Z";

#[derive(Debug, Default)]
struct Unavailable(Mutex<Vec<&'static str>>);

impl Unavailable {
    fn deny(&self, kind: &'static str) -> FetchError {
        self.0.lock().unwrap().push(kind);
        FetchError::new(FetchErrorKind::NotFound, "No revocation evidence supplied")
    }
}

impl OcspFetcher for Unavailable {
    fn fetch_ocsp(&self, _: &Cert, _: &Cert) -> Result<Vec<u8>, FetchError> {
        Err(self.deny("pkc-ocsp"))
    }

    fn fetch_ac_ocsp(&self, _: &[u8], _: &Cert) -> Result<Vec<u8>, FetchError> {
        Err(self.deny("ac-ocsp"))
    }
}

impl CrlFetcher for Unavailable {
    fn fetch_crls(&self, _: &Cert) -> Result<Vec<Vec<u8>>, FetchError> {
        Err(self.deny("pkc-crl"))
    }

    fn fetch_ac_crls(&self, _: &[u8]) -> Result<Vec<Vec<u8>>, FetchError> {
        Err(self.deny("ac-crl"))
    }
}

fn with_no_rev_avail(original: &[u8]) -> Vec<u8> {
    let outer = Tlv::parse_exact(original).unwrap().children().unwrap();
    let info = outer[0].children().unwrap();
    let mut extensions = x509_cert::ext::Extensions::from_der(info.last().unwrap().raw).unwrap();
    extensions.retain(|ext| {
        !matches!(
            ext.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31" | "2.5.29.46" | "2.5.29.56"
        )
    });
    extensions.push(x509_cert::ext::Extension {
        extn_id: const_oid::ObjectIdentifier::new_unwrap("2.5.29.56"),
        critical: false,
        extn_value: der::asn1::OctetString::new([5, 0]).unwrap(),
    });
    let info = encode(
        0x30,
        &[
            info[..info.len() - 1]
                .iter()
                .flat_map(|part| part.raw.iter().copied())
                .collect::<Vec<_>>(),
            extensions.to_der().unwrap(),
        ]
        .concat(),
    );
    let pki = support::pki(ARCH);
    let signer = pki.signer("leaf-aa");
    let algorithm = KeySigner::signature_algorithm(&signer, DigestAlgorithm::Sha256).unwrap();
    assert_eq!(algorithm.to_der().unwrap(), outer[1].raw);
    let signature = KeySigner::sign_raw(&signer, &info, DigestAlgorithm::Sha256).unwrap();
    encode(
        0x30,
        &[
            info,
            outer[1].raw.to_vec(),
            der::asn1::BitString::from_bytes(&signature)
                .unwrap()
                .to_der()
                .unwrap(),
        ]
        .concat(),
    )
}

#[test]
fn no_rev_avail_preserves_holder_signature_trust_and_required_evidence_checks() {
    let pki = support::pki(ARCH);
    let aa = pki.cert("leaf-aa");
    let holder = pki.cert("signer1");
    let wrong_holder = pki.cert("signer2");
    let original = std::fs::read(support::data_path(&[
        "lanes",
        "r3-p",
        "ac",
        "alice-role-with-rev.der",
    ]))
    .unwrap();
    let valid = with_no_rev_avail(&original);
    let mut bad = valid.clone();
    *bad.last_mut().unwrap() ^= 1;
    for (bytes, signature_valid) in [(&valid, true), (&bad, false)] {
        let parsed = AttrCert::from_der(bytes).unwrap();
        assert_eq!(
            validate_signature(
                &parsed.signature,
                &parsed.info_der,
                &aa.public_key(),
                &parsed.signature_algorithm,
                &SignatureValidationContext::default(),
            )
            .is_ok(),
            signature_valid
        );
    }
    let expected_role = AttrCert::from_der(&valid).unwrap().attributes;
    let mut rows = Vec::new();
    for mode in ["require", "soft-fail"] {
        for (case, ac, selected_holder, trusted, accepted) in [
            ("genuine", &valid, &holder, true, true),
            ("bad-signature", &bad, &holder, true, false),
            ("wrong-holder", &valid, &wrong_holder, true, false),
            ("untrusted-aa", &valid, &holder, false, false),
        ] {
            let provider = Arc::new(Unavailable::default());
            // Explicit AA anchoring isolates the AC exemption from AA-chain
            // PKC revocation obligations. No AC evidence or assertions exist.
            let mut builder = ValidationContext::builder()
                .other_cert(aa.clone())
                .moment(support::at(TIME))
                .revocation_mode(mode)
                .fetchers(Fetchers {
                    ocsp: Some(provider.clone()),
                    crl: Some(provider.clone()),
                    cert: None,
                });
            if trusted {
                builder = builder.trust_root(aa.clone());
            }
            let context = builder.build().unwrap();
            let mut info = ValidationInfo::default();
            let result = validate_and_collect_attribute_certs(
                &context,
                selected_holder,
                &[],
                std::slice::from_ref(ac),
                &mut info,
            );
            assert_eq!(result.is_ok(), accepted, "{mode}/{case}: {result:?}");
            let native_error = result.as_ref().err().map(ToString::to_string);
            if let Some(error) = &native_error {
                let expected = match case {
                    "bad-signature" => "signature could not be verified",
                    "wrong-holder" => "Could not match AC holder entry",
                    "untrusted-aa" => "Unable to build a validation path",
                    _ => panic!("unexpected native refusal: {mode}/{case}: {error}"),
                };
                assert!(error.contains(expected), "{mode}/{case}: {error}");
            }
            assert!(provider.0.lock().unwrap().is_empty(), "{mode}/{case}");
            assert!(info.ocsps.is_empty() && info.crls.is_empty());
            if let Ok(result) = result {
                assert_eq!(result.len(), 1);
                assert_eq!(result[0].attr_cert, *ac);
                assert_eq!(result[0].aa_cert, aa);
                assert_eq!(result[0].aa_path.certs().len(), 1);
                assert_eq!(result[0].approved_attributes.len(), 1);
                let role = &result[0].approved_attributes["role"];
                assert!(expected_role.iter().any(|(_, value)| value == role));
                assert!(role
                    .windows(b"bigboss@example.com".len())
                    .any(|part| part == b"bigboss@example.com"));
                assert_eq!(info.paths, [vec![aa.clone()]]);
            } else {
                assert!(info.paths.is_empty());
            }
            assert_eq!(context.ocsps().count(), 0);
            assert_eq!(context.crls().count(), 0);
            rows.push(serde_json::json!({
                "case": case, "mode": mode, "ac": ac, "holder": selected_holder.der(),
                "trusted": trusted, "accepted": accepted, "native_error": native_error,
            }));
        }
    }
    // The same require policy with an ordinary AC still demands evidence.
    let context = ValidationContext::builder()
        .trust_root(aa.clone())
        .moment(support::at(TIME))
        .revocation_mode("require")
        .build()
        .unwrap();
    let mut info = ValidationInfo::default();
    let original_result = validate_and_collect_attribute_certs(
        &context,
        &holder,
        &[],
        std::slice::from_ref(&original),
        &mut info,
    );
    assert!(original_result.is_err());
    let original_error = original_result.unwrap_err().to_string();
    assert!(
        original_error.contains("revocation information"),
        "{original_error}"
    );
    assert!(info.paths.is_empty() && info.ocsps.is_empty() && info.crls.is_empty());
    rows.push(serde_json::json!({
        "case": "ordinary-missing-evidence", "mode": "require", "ac": original,
        "holder": holder.der(), "trusted": true, "accepted": false,
        "native_error": original_error,
    }));
    let manifest = support::temp_file(
        "no-rev-avail.json",
        &serde_json::to_vec(&serde_json::json!({
            "aa": aa.der(), "time": TIME, "cases": rows,
        }))
        .unwrap(),
    );
    let output =
        std::process::Command::new(support::oracle_python().expect("pinned oracle required"))
            .args([
                "-I",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/oracle/check_ac_no_rev_avail.py"
                ),
            ])
            .arg(&manifest)
            .output()
            .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let proof: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(proof["agreements"], 9);
    eprintln!("fresh NoRevAvail public AC oracle: {proof}");
}
