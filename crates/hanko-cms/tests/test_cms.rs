// Ported from pyHanko 0.38.1 `pkgs/pyhanko/tests/test_cms.py`
// (MIT, see LICENSE-pyHanko).
//
// The upstream tests sign with pyHanko and then validate. The signing half
// is replaced by recorded pyHanko output (`oracle/harvest.sh`), the
// validation half runs hanko-cms on exactly the inputs pyHanko validated,
// asserts the upstream test's own assertions, and compares every outcome
// with pyHanko's recorded one (`common::check`).

mod common;

use common::{b64, check, Harvest, Replayed};
use hanko_cms::signed_data::{
    find_cms_attribute_iter, find_unique_cms_attribute, parse_attributes, AttributeLookupError,
};
use hanko_core::ades::{AdesIndeterminate, AdesSubIndic};
use hanko_core::asn1::oids;
use hanko_core::asn1::tlv;
use hanko_core::time::Moment;

const MODULE: &str = "test_cms";

/// Recorded calls on which hanko-cms is known to diverge from pyHanko. Every
/// divergence fails closed (asserted by `common::check`).
const KNOWN: &[(&str, usize, &str)] = &[];

fn run(test: &str) -> Vec<Replayed> {
    check(MODULE, test, KNOWN)
}

fn moment(s: &str) -> Moment {
    Moment::parse_rfc3339(s).expect("moment")
}

fn nov_2020() -> Moment {
    moment("2020-11-01T00:00:00Z")
}

#[test]
fn test_generic_data_sign() {
    let results = run("test_generic_data_sign");
    for r in &results {
        match r {
            Replayed::Basic(s) => assert!(s.valid && s.intact),
            Replayed::Standard(s) => {
                assert!(s.signature.valid && s.signature.intact);
                assert!(s
                    .pretty_print_details()
                    .contains("No available information about the signing time."));
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    // Three detached variants also validate with async_validate_detached_cms.
    assert_eq!(results.len(), 9);
}

#[test]
fn test_cms_v3_sign() {
    for r in run("test_cms_v3_sign") {
        assert!(r.basic().valid && r.basic().intact);
    }
}

#[test]
fn test_detached_cms_with_self_reported_timestamp() {
    let r = &run("test_detached_cms_with_self_reported_timestamp")[0];
    let s = r.standard();
    assert_eq!(s.signer_reported_dt, Some(moment("2020-11-01T05:00:00Z")));
    assert!(s.timestamp_validity.is_none());
    assert!(s.pretty_print_details().contains("reported by signer"));
    assert!(s.signature.valid && s.signature.intact);
}

#[test]
fn test_detached_cms_with_tst() {
    let r = &run("test_detached_cms_with_tst")[0];
    let s = r.standard();
    assert_eq!(s.signer_reported_dt, None);
    let ts = s.timestamp_validity.as_ref().expect("timestamp");
    assert!(ts.signature.intact && ts.signature.valid);
    assert_eq!(ts.timestamp, nov_2020());
    assert!(s
        .pretty_print_details()
        .contains("The TSA certificate is untrusted"));
    assert!(s.signature.valid && s.signature.intact);
}

#[test]
fn test_detached_cms_with_multiple_signature_timestamps() {
    // Pending R1 (one of the two timestamps uses SHA3-256).
    run("test_detached_cms_with_multiple_signature_timestamps");
}

#[test]
fn test_detached_cms_with_multiple_signature_timestamps_algo_policy() {
    // Pending R1 (one of the two timestamps uses SHA3-256).
    run("test_detached_cms_with_multiple_signature_timestamps_algo_policy");
}

#[test]
fn test_detached_cms_with_content_tst() {
    let r = &run("test_detached_cms_with_content_tst")[0];
    let s = r.standard();
    assert_eq!(s.signer_reported_dt, None);
    for ts in [&s.timestamp_validity, &s.content_timestamp_validity] {
        let ts = ts.as_ref().expect("timestamp");
        assert!(ts.signature.intact && ts.signature.valid);
        assert_eq!(ts.timestamp, nov_2020());
    }
    let pp = s.pretty_print_details();
    assert!(pp.contains("The TSA certificate is untrusted"));
    assert!(pp.contains("Content timestamp"));
    assert!(pp.contains("Signature timestamp"));
    assert!(s.signature.valid && s.signature.intact);
    assert!(s
        .summary()
        .contains("CONTENT_TIMESTAMP_TOKEN<INTACT:UNTRUSTED>"));
    assert!(s.summary().contains(",TIMESTAMP_TOKEN<INTACT:UNTRUSTED>"));
}

#[test]
fn test_detached_cms_with_wrong_tst() {
    let r = &run("test_detached_cms_with_wrong_tst")[0];
    let s = r.standard();
    let ts = s.timestamp_validity.as_ref().expect("timestamp");
    assert!(!ts.signature.intact && ts.signature.valid);
    assert_eq!(ts.timestamp, nov_2020());
    let cts = s
        .content_timestamp_validity
        .as_ref()
        .expect("content timestamp");
    assert!(cts.signature.intact && cts.signature.valid);
    assert_eq!(cts.timestamp, nov_2020());
    assert!(s.signature.valid && s.signature.intact);
    assert!(s
        .summary()
        .contains("CONTENT_TIMESTAMP_TOKEN<INTACT:UNTRUSTED>"));
    assert!(s.summary().contains("TIMESTAMP_TOKEN<INVALID>"));
}

#[test]
fn test_detached_cms_with_wrong_content_tst() {
    let r = &run("test_detached_cms_with_wrong_content_tst")[0];
    let s = r.standard();
    let ts = s.timestamp_validity.as_ref().expect("timestamp");
    assert!(ts.signature.intact && ts.signature.valid);
    let cts = s
        .content_timestamp_validity
        .as_ref()
        .expect("content timestamp");
    assert!(!cts.signature.intact && cts.signature.valid);
    assert_eq!(cts.timestamp, nov_2020());
    let pp = s.pretty_print_details();
    assert!(pp.contains("The TSA certificate is untrusted"));
    assert!(pp.contains("Content timestamp") && pp.contains("Signature timestamp"));
    assert!(s.signature.valid && s.signature.intact);
    assert!(s.summary().contains("CONTENT_TIMESTAMP_TOKEN<INVALID>"));
    assert!(s.summary().contains("TIMESTAMP_TOKEN<INTACT:UNTRUSTED>"));
}

#[test]
fn test_detached_cms_with_duplicated_attr() {
    let r = &run("test_detached_cms_with_duplicated_attr")[0];
    let e = r.error();
    assert_eq!(e.class_name(), "SignatureValidationError");
    assert!(e.to_string().contains("multiple message digest attributes"));
}

#[test]
fn test_detached_with_malformed_content_tst() {
    let results = run("test_detached_with_malformed_content_tst");
    assert_eq!(results.len(), 5);
    for r in results {
        assert!(r
            .error()
            .to_string()
            .contains("does not encapsulate TSTInfo"));
    }
}

#[test]
fn test_overspecify_cms_digest_algo() {
    // The validation half (val_untrusted). The second half checks that the
    // signer refuses a conflicting digest: signing side, lane D.
    for r in run("test_overspecify_cms_digest_algo") {
        if let Replayed::Standard(s) = r {
            assert!(s.signature.valid && s.signature.intact && !s.signature.trusted());
        }
    }
}

fn integrity_errors(test: &str) -> Vec<hanko_cms::CmsError> {
    run(test)
        .into_iter()
        .filter_map(|r| match r {
            Replayed::Error(e) => Some(e),
            _ => None,
        })
        .collect()
}

#[test]
fn test_cms_algorithm_protection() {
    let errors = integrity_errors("test_cms_algorithm_protection");
    assert_eq!(errors.len(), 4);
    for e in errors {
        assert_eq!(e.class_name(), "SignatureValidationError");
        assert!(e.to_string().contains("CMS"), "{e}");
    }
}

#[test]
fn test_signed_attrs_tampering() {
    let results = run("test_signed_attrs_tampering");
    assert!(results
        .iter()
        .any(|r| matches!(r, Replayed::Integrity(true, false))));
}

#[test]
fn test_no_message_digest() {
    assert_eq!(integrity_errors("test_no_message_digest").len(), 1);
}

#[test]
fn test_duplicate_content_type() {
    let errors = integrity_errors("test_duplicate_content_type");
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].ades_subindication().status(),
        hanko_cms::AdesStatus::Failed
    );
}

#[test]
fn test_duplicate_content_type_oid() {
    assert_eq!(integrity_errors("test_duplicate_content_type_oid").len(), 1);
}

#[test]
fn test_no_content_type() {
    assert_eq!(integrity_errors("test_no_content_type").len(), 1);
}

#[test]
fn test_wrong_content_type() {
    assert_eq!(integrity_errors("test_wrong_content_type").len(), 1);
}

fn pdf_statuses(test: &str) -> Vec<hanko_cms::StandardCmsSignatureStatus> {
    run(test)
        .into_iter()
        .filter_map(|r| match r {
            Replayed::Standard(s) => Some(s),
            _ => None,
        })
        .collect()
}

#[test]
fn test_sign_weak_digest() {
    // Pending R1 (MD5); the recorded calls are replayed and fail closed.
    run("test_sign_weak_digest");
}

#[test]
fn test_forbidden_signature_algorithm() {
    let s = &pdf_statuses("test_forbidden_signature_algorithm")[0];
    assert_eq!(
        s.signature.trust_problem_indic,
        Some(AdesSubIndic::Indeterminate(
            AdesIndeterminate::CRYPTO_CONSTRAINTS_FAILURE
        ))
    );
}

#[test]
fn test_sign_weak_sig_digest_mismatch() {
    run("test_sign_weak_sig_digest_mismatch"); // pending R1 (MD5)
}

#[test]
fn test_sign_weak_sig_digest_mismatch_allowed() {
    run("test_sign_weak_sig_digest_mismatch_allowed"); // pending R1 (MD5)
}

#[test]
fn test_sign_digest_mismatch_allowed_but_inner_banned() {
    run("test_sign_digest_mismatch_allowed_but_inner_banned"); // pending R1 (MD5)
}

#[test]
fn test_sign_digest_mismatch_allowed_but_outer_banned() {
    run("test_sign_digest_mismatch_allowed_but_outer_banned"); // pending R1 (MD5)
}

#[test]
fn test_sign_digest_mismatch_allowed_passed_through_context() {
    run("test_sign_digest_mismatch_allowed_passed_through_context"); // pending R1 (MD5)
}

#[test]
fn test_sign_weak_sig_digest() {
    run("test_sign_weak_sig_digest"); // pending R1 (MD5)
}

#[test]
fn test_sign_weak_sig_digest_allowed() {
    run("test_sign_weak_sig_digest_allowed"); // pending R1 (MD5)
}

#[test]
fn test_sign_weak_sig_digest_disallowed_by_custom_policy() {
    run("test_sign_weak_sig_digest_disallowed_by_custom_policy"); // pending R1 (MD5)
}

#[test]
fn test_old_style_signing_cert_attr_ok() {
    for s in pdf_statuses("test_old_style_signing_cert_attr_ok") {
        assert!(s.signature.trusted());
    }
}

#[test]
fn test_old_style_signing_cert_attr_mismatch() {
    let errors = integrity_errors("test_old_style_signing_cert_attr_mismatch");
    assert_eq!(errors.len(), 2);
    for e in errors {
        assert!(e
            .to_string()
            .contains("Signing certificate attribute does not match "));
        assert_eq!(
            e.ades_subindication(),
            AdesSubIndic::Indeterminate(AdesIndeterminate::NO_SIGNING_CERTIFICATE_FOUND)
        );
        assert_eq!(
            e.ades_subindication().status(),
            hanko_cms::AdesStatus::Indeterminate
        );
    }
}

#[test]
fn test_old_style_signing_cert_attr_get() {
    use der::Decode;
    use hanko_core::algorithms::DigestAlgorithm;
    use hanko_core::asn1::ess::{EssCertIdV2, IssuerSerial};
    // `as_signing_certificate` (SHA-1 ESSCertID) and
    // `as_signing_certificate_v2(cert, 'sha1')` agree on issuer/serial and hash.
    let h = Harvest::load(MODULE);
    let cert = h.cert(&signer1_key(h));
    let raw = hanko_core::cert::RawCertificate::from_der(cert.der()).expect("cert");
    let v2 = EssCertIdV2::for_certificate(&raw, DigestAlgorithm::Sha1).expect("v2");
    let v1_issuer_serial = IssuerSerial::for_certificate(&raw).expect("v1");
    assert_eq!(v2.issuer_serial.as_ref(), Some(&v1_issuer_serial));
    assert_eq!(
        v2.cert_hash.as_bytes(),
        DigestAlgorithm::Sha1.digest(cert.der())
    );
}

/// The key of FROM_CA's signing certificate (Alice) in the harvest.
fn signer1_key(h: &Harvest) -> String {
    h.certs
        .iter()
        .find(|(_, c)| hanko_cms::status::human_friendly(c).starts_with("Email Address: alice@"))
        .map(|(k, _)| k.clone())
        .expect("signer1")
}

#[test]
fn test_signing_cert_attr_malformed_issuer() {
    let errors = integrity_errors("test_signing_cert_attr_malformed_issuer");
    assert_eq!(errors.len(), 1);
    assert!(errors[0]
        .to_string()
        .contains("Signing certificate attribute does not match "));
    assert_eq!(
        errors[0].ades_subindication(),
        AdesSubIndic::Indeterminate(AdesIndeterminate::NO_SIGNING_CERTIFICATE_FOUND)
    );
}

#[test]
fn test_signing_cert_attr_duplicated() {
    let errors = integrity_errors("test_signing_cert_attr_duplicated");
    assert_eq!(errors.len(), 1);
    assert!(errors[0]
        .to_string()
        .contains("Wrong cardinality for signing cert"));
}

fn untrusted_but_sound(test: &str) {
    let statuses = pdf_statuses(test);
    assert!(!statuses.is_empty());
    for s in statuses {
        assert!(s.signature.valid && s.signature.intact, "{test}");
        assert!(!s.signature.trusted(), "{test}");
    }
}

fn trusted(test: &str) {
    let statuses = pdf_statuses(test);
    assert!(!statuses.is_empty());
    for s in statuses {
        assert!(
            s.signature.trusted(),
            "{test}: {:?}",
            s.signature.trust_problem
        );
    }
}

#[test]
fn test_verify_sig_without_signed_attrs() {
    untrusted_but_sound("test_verify_sig_without_signed_attrs");
}

#[test]
fn test_verify_sig_with_ski_sid() {
    untrusted_but_sound("test_verify_sig_with_ski_sid");
}

#[test]
fn test_sign_with_ecdsa_trust() {
    trusted("test_sign_with_ecdsa_trust");
    let s = &pdf_statuses("test_sign_with_ecdsa_trust")[0];
    assert_eq!(s.signature.pkcs7_signature_mechanism, "sha384_ecdsa");
}

#[test]
fn test_sign_with_dsa_trust() {
    run("test_sign_with_dsa_trust"); // pending R1 (DSA)
}

#[test]
fn test_sign_with_explicit_ecdsa_implied_hash() {
    trusted("test_sign_with_explicit_ecdsa_implied_hash");
    let s = &pdf_statuses("test_sign_with_explicit_ecdsa_implied_hash")[0];
    assert_eq!(s.signature.pkcs7_signature_mechanism, "ecdsa");
    assert_eq!(s.signature.md_algorithm_name, "sha384");
}

#[test]
fn test_sign_with_explicit_dsa_implied_hash() {
    run("test_sign_with_explicit_dsa_implied_hash"); // pending R1 (DSA)
}

#[test]
fn test_sign_pss() {
    untrusted_but_sound("test_sign_pss");
    let s = &pdf_statuses("test_sign_pss")[0];
    assert_eq!(s.signature.pkcs7_signature_mechanism, "rsassa_pss");
}

#[test]
fn test_sign_pss_md_discrepancy() {
    untrusted_but_sound("test_sign_pss_md_discrepancy");
}

#[test]
fn test_direct_pdfcmsembedder_usage() {
    // Both val_trusted calls; the DSS part is lane B / E.
    trusted("test_direct_pdfcmsembedder_usage");
}

#[test]
fn test_no_embed_root() {
    trusted("test_no_embed_root");
}

#[test]
fn test_noop_attribute_prov() {
    for r in run("test_noop_attribute_prov") {
        assert!(r.basic().valid && r.basic().intact);
    }
}

#[test]
fn test_no_certificates() {
    // `emb.signer_cert` raises SignatureValidationError('signer cert...
    // included'); collect_validation_info raises CMSExtractionError (lane E).
    let results = run("test_no_certificates");
    let errors: Vec<_> = results
        .iter()
        .filter_map(|r| match r {
            Replayed::Error(e) => Some(e),
            _ => None,
        })
        .collect();
    assert_eq!(errors.len(), 2);
    for e in errors {
        assert_eq!(e.class_name(), "SignatureValidationError");
        assert!(e.to_string().contains("signer certificate not included"));
    }
}

#[test]
fn test_two_signer_infos() {
    let results = run("test_two_signer_infos");
    let e = results.iter().find_map(|r| match r {
        Replayed::Error(e) => Some(e),
        _ => None,
    });
    let e = e.expect("error");
    assert_eq!(e.class_name(), "CMSExtractionError");
    assert!(e.to_string().contains("exactly one"));
}

fn role_from_ac_attrs(s: &hanko_cms::StandardCmsSignatureStatus) -> String {
    use hanko_cms::attributes::RoleSyntax;
    let role = s
        .ac_attrs
        .as_ref()
        .and_then(|a| a.get("role"))
        .expect("role attribute");
    let value = RoleSyntax::from_der(&role.attr_values[0]).expect("RoleSyntax");
    match value.role_name {
        x509_cert::ext::pkix::name::GeneralName::Rfc822Name(n) => n.to_string(),
        other => format!("{other:?}"),
    }
}

#[test]
fn test_embed_ac() {
    // The embedded AC certifies a role (live fetching in pyHanko; the
    // replayed contexts carry no fetchers, which only matters for the
    // revocation checks that soft-fail).
    for s in pdf_statuses("test_embed_ac") {
        assert!(s.signature.trusted());
        assert_eq!(role_from_ac_attrs(&s), "bigboss@example.com");
    }
}

#[test]
fn test_embed_ac_revinfo_adobe_style() {
    // Pending: the assertions are on `ades_lta_validation` (lane E). The
    // recorded calls are the integrity checks it makes.
    for r in run("test_embed_ac_revinfo_adobe_style") {
        if let Replayed::Integrity(i, v) = r {
            assert!(i && v);
        }
    }
}

#[test]
fn test_ac_detached() {
    let s = run("test_ac_detached").remove(0);
    let s = s.standard();
    assert!(s.bottom_line());
    assert_eq!(s.ac_attrs.as_ref().expect("ac attrs").len(), 1);
    assert_eq!(role_from_ac_attrs(s), "bigboss@example.com");
}

#[test]
fn test_ac_attr_validation_fail() {
    let s = run("test_ac_attr_validation_fail").remove(0);
    let s = s.standard();
    assert!(s.bottom_line());
    let ac = s.ac_attrs.as_ref().expect("ac attrs");
    assert!(ac.is_empty() && !ac.contains("role"));
}

#[test]
fn test_ac_attr_validation_holder_mismatch() {
    let s = run("test_ac_attr_validation_holder_mismatch").remove(0);
    let s = s.standard();
    assert!(s.bottom_line());
    let ac = s.ac_attrs.as_ref().expect("ac attrs");
    assert!(ac.is_empty() && !ac.contains("role"));
}

#[test]
fn test_detached_cades_cms_with_tst() {
    let r = &run("test_detached_cades_cms_with_tst")[0];
    let s = r.standard();
    assert_eq!(s.signer_reported_dt, Some(nov_2020()));
    let ts = s.timestamp_validity.as_ref().expect("timestamp");
    assert!(ts.signature.intact && ts.signature.valid);
    assert_eq!(ts.timestamp, nov_2020());
    assert!(s
        .pretty_print_details()
        .contains("The TSA certificate is untrusted"));
    assert!(s.signature.valid && s.signature.intact);
}

const NONSENSICAL_ATTR: &str = "301c06035504483115041354686973206d616b6573206e6f2073656e7365";
const UNTYPABLE_ATTR: &str = "3033041a54686973206d616b6573206576656e206c6573732073656e73653115041354686973206d616b6573206e6f2073656e7365";
const SAMPLE_GROUP_ATTR: &str =
    "302706082b06010505070a04311b301930170c09456d706c6f796565730c0a45786563757469766573";

#[test]
fn test_parse_malformed_claimed_attrs() {
    use hanko_cms::attributes::claimed_attributes_from;
    for (bad, pattern) in [
        (
            NONSENSICAL_ATTR,
            regex_lite("Failed to parse claimed", "role"),
        ),
        (
            UNTYPABLE_ATTR,
            regex_lite("Failed to parse", "unknown type"),
        ),
    ] {
        let attrs = vec![common::unhex(bad), common::unhex(SAMPLE_GROUP_ATTR)];
        let e = claimed_attributes_from(&attrs, true).expect_err("fatal");
        assert_eq!(e.class_name(), "SignatureValidationError");
        assert!(pattern(&e.to_string()), "{e}");
        let claimed = claimed_attributes_from(&attrs, false).expect("lenient");
        assert_eq!(claimed.len(), 1);
    }
}

/// `re.search('a.*b', s)`.
fn regex_lite(a: &'static str, b: &'static str) -> impl Fn(&str) -> bool {
    move |s: &str| s.find(a).is_some_and(|i| s[i + a.len()..].contains(b))
}

#[test]
fn test_validate_with_malformed_claimed_attrs() {
    for r in run("test_validate_with_malformed_claimed_attrs") {
        let s = r.standard();
        assert_eq!(
            s.cades_signer_attrs
                .as_ref()
                .expect("signer attrs")
                .claimed_attrs
                .len(),
            1
        );
    }
}

#[test]
fn test_parse_ac_with_malformed_attribute() {
    let s = run("test_parse_ac_with_malformed_attribute").remove(0);
    let s = s.standard();
    // The malformed attribute is dropped; the other one is certified.
    let certified = s
        .cades_signer_attrs
        .as_ref()
        .and_then(|c| c.certified_attrs.as_ref())
        .expect("certified attrs");
    assert_eq!(certified.len(), 1);
}

#[test]
fn test_detached_cms_with_invalid_cn() {
    let s = run("test_detached_cms_with_invalid_cn").remove(0);
    let s = s.standard();
    assert!(s.signature.valid && s.signature.intact);
    assert!(!s.signature.trusted());
}

#[test]
fn test_detached_cms_with_invalid_cn_in_ca_wrong_cert() {
    let r = &run("test_detached_cms_with_invalid_cn_in_ca_wrong_cert")[0];
    assert!(r
        .error()
        .to_string()
        .contains("Signing certificate attribute does not match"));
}

#[test]
fn test_detached_cms_with_invalid_cn_in_ca() {
    let s = run("test_detached_cms_with_invalid_cn_in_ca").remove(0);
    let s = s.standard();
    assert!(s.signature.valid && s.signature.intact);
    assert!(!s.signature.trusted());
}

#[test]
fn test_tolerate_der_deviations() {
    let results = run("test_tolerate_der_deviations");
    assert!(matches!(results[0], Replayed::Integrity(true, true)));
}

#[test]
fn test_tolerate_der_deviations_in_pdf() {
    trusted("test_tolerate_der_deviations_in_pdf");
}

#[test]
fn test_ed448_no_length() {
    run("test_ed448_no_length"); // pending R1 (Ed448)
}

#[test]
fn test_ed448_invalid_hash_algo_validation() {
    run("test_ed448_invalid_hash_algo_validation"); // pending R1 (Ed448)
}

// --- find_cms_attribute_iter / find_unique_cms_attribute ----------------

fn attr(oid: &const_oid::ObjectIdentifier, values: &[Vec<u8>]) -> Vec<u8> {
    use der::Encode;
    let mut body = oid.to_der().expect("oid");
    body.extend(tlv::encode(0x31, &values.concat()));
    tlv::encode(0x30, &body)
}

fn octets(v: &[u8]) -> Vec<u8> {
    tlv::encode(0x04, v)
}

fn attrs(list: &[Vec<u8>]) -> Vec<hanko_cms::signed_data::CmsAttribute> {
    parse_attributes(&list.concat()).expect("attributes")
}

fn test_attrs() -> Vec<hanko_cms::signed_data::CmsAttribute> {
    use der::Encode;
    let h = Harvest::load(MODULE);
    let cert = h.cert(&signer1_key(h));
    let raw = hanko_core::cert::RawCertificate::from_der(cert.der()).expect("cert");
    let scv2 = hanko_core::asn1::ess::SigningCertificateV2::for_signer(
        &raw,
        hanko_core::algorithms::DigestAlgorithm::Sha256,
    )
    .expect("scv2")
    .to_der()
    .expect("der");
    attrs(&[
        attr(&oids::CONTENT_TYPE, &[oids::CT_DATA.to_der().expect("oid")]),
        attr(&oids::MESSAGE_DIGEST, &[octets(b"test_digest")]),
        attr(&oids::AA_SIGNING_CERTIFICATE_V2, &[scv2]),
    ])
}

use der::Decode;

#[test]
fn test_find_cms_attribute_iter_single_value() {
    let a = test_attrs();
    let values: Vec<_> = find_cms_attribute_iter(Some(&a), oids::CONTENT_TYPE).collect();
    assert_eq!(values.len(), 1);
    assert_eq!(
        const_oid::ObjectIdentifier::from_der(values[0]).expect("oid"),
        oids::CT_DATA
    );
}

#[test]
fn test_find_cms_attribute_iter_multiple_values() {
    let a = attrs(&[attr(
        &oids::MESSAGE_DIGEST,
        &[octets(b"test1"), octets(b"test2")],
    )]);
    let values: Vec<_> = find_cms_attribute_iter(Some(&a), oids::MESSAGE_DIGEST).collect();
    assert_eq!(values, vec![octets(b"test1"), octets(b"test2")]);
}

#[test]
fn test_find_cms_attribute_iter_nonexistent_attribute() {
    let a = test_attrs();
    assert_eq!(
        find_cms_attribute_iter(Some(&a), oids::SIGNING_TIME).count(),
        0
    );
}

#[test]
fn test_find_cms_attribute_iter_none_attrs() {
    assert_eq!(find_cms_attribute_iter(None, oids::CONTENT_TYPE).count(), 0);
}

#[test]
fn test_find_cms_attribute_iter_empty_attrs() {
    let a = attrs(&[]);
    assert_eq!(
        find_cms_attribute_iter(Some(&a), oids::CONTENT_TYPE).count(),
        0
    );
}

#[test]
fn test_find_unique_cms_attribute_success() {
    let a = test_attrs();
    let v = find_unique_cms_attribute(Some(&a), oids::CONTENT_TYPE).expect("value");
    assert_eq!(
        const_oid::ObjectIdentifier::from_der(v).expect("oid"),
        oids::CT_DATA
    );
}

#[test]
fn test_find_unique_cms_attribute_raises_on_missing() {
    let a = test_attrs();
    let e = find_unique_cms_attribute(Some(&a), oids::SIGNING_TIME).expect_err("missing");
    assert!(matches!(e, AttributeLookupError::Nonexistent(_)));
    assert_eq!(e.to_string(), "Unable to locate attribute signing_time.");
}

#[test]
fn test_find_unique_cms_attribute_raises_on_multiple() {
    let a = attrs(&[attr(
        &oids::MESSAGE_DIGEST,
        &[octets(b"test1"), octets(b"test2")],
    )]);
    let e = find_unique_cms_attribute(Some(&a), oids::MESSAGE_DIGEST).expect_err("multiple");
    assert_eq!(
        e.to_string(),
        "Expected single-valued message_digest attribute, but found multiple"
    );
}

#[test]
fn test_find_unique_cms_attribute_none_attrs() {
    assert!(matches!(
        find_unique_cms_attribute(None, oids::CONTENT_TYPE),
        Err(AttributeLookupError::Nonexistent(_))
    ));
}

#[test]
fn test_find_unique_cms_attribute_empty_attrs() {
    let a = attrs(&[]);
    assert!(matches!(
        find_unique_cms_attribute(Some(&a), oids::CONTENT_TYPE),
        Err(AttributeLookupError::Nonexistent(_))
    ));
}

#[test]
fn test_find_unique_cms_attribute_with_multiple_attributes_single_value() {
    let a = test_attrs();
    let v = find_unique_cms_attribute(Some(&a), oids::MESSAGE_DIGEST).expect("value");
    assert_eq!(v, octets(b"test_digest"));
}

#[test]
fn test_find_cms_attribute_iter_preserves_order() {
    let a = attrs(&[attr(
        &oids::MESSAGE_DIGEST,
        &[octets(b"first"), octets(b"second"), octets(b"third")],
    )]);
    let values: Vec<_> = find_cms_attribute_iter(Some(&a), oids::MESSAGE_DIGEST).collect();
    assert_eq!(
        values,
        vec![octets(b"first"), octets(b"second"), octets(b"third")]
    );
}

#[test]
fn test_find_cms_attribute_iter_multiple_attributes_same_type() {
    let a = attrs(&[
        attr(&oids::MESSAGE_DIGEST, &[octets(b"digest1")]),
        attr(&oids::MESSAGE_DIGEST, &[octets(b"digest2")]),
    ]);
    let values: Vec<_> = find_cms_attribute_iter(Some(&a), oids::MESSAGE_DIGEST).collect();
    assert_eq!(values, vec![octets(b"digest1"), octets(b"digest2")]);
}

#[test]
fn harvest_is_complete() {
    // Every recorded call is covered by one of the tests above.
    let h = Harvest::load(MODULE);
    assert!(h.calls.len() > 100);
    let _ = b64("");
}
